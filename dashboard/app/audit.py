"""Audit log for the dashboard (More > Audit log, #/audit), stored in Elasticsearch in DAILY indices
`logs-netmon.YYYY.MM.DD` (UTC day of each entry's @timestamp) so retention can delete whole days by index name
(an ILM / DLM / curator rule on `logs-netmon.*`). The dot, not a hyphen, keeps the name outside Security Onion's
`logs-*-*` data-stream templates. Reads cover `logs-netmon`, `logs-netmon.*` (and the stray `logs-netmon-*`).

Two kinds of entries (ECS field names, so they also read well in Kibana / Security Onion Hunt):
  event.dataset = netmon.audit   every user action: sign-in / sign-out, every POST (check-offs, notes, chat,
                                 settings, users, AI verdicts...), page views, report downloads, denied requests
  event.dataset = netmon.review  one entry per correlation review pass that did work or failed, and per finished
                                 review-job run (reviewlog.py; AI pipeline monitoring > Review log card)
  event.dataset = netmon.llm     every conversation between the app and an LLM: Ask AI chat turns, the
                                 event reviewer, the review job's and event research's
                                 results coming back in (enrich.py put). Prompt, system prompt, answer, model,
                                 tokens, seconds, outcome.
Secrets never reach the log: any parameter whose name looks like a password / key / token is replaced by
"[redacted]" before it is queued.

Writing is asynchronous (a daemon thread bulk-indexes every ~2 s) so a slow or unreachable Elasticsearch never
delays a request. When ES is down or no key is configured yet, entries are appended to /state/audit_spool.jsonl
(capped) and sent once ES works again. The key (integrations.json "audit", set on the Audit log page) only
needs create_doc + read on logs-netmon: the dashboard can add audit entries and read them, never change or
delete them.
"""
import atexit, json, os, queue, re, signal, ssl, sys, threading, time, urllib.error, urllib.request, uuid
from datetime import datetime, timezone

STATE = os.environ.get("STATE_DIR", "/state")
_ROOT = os.environ.get("NETMON_DIR", "/netmon")
if _ROOT not in sys.path:
    sys.path.append(_ROOT)
if os.path.isdir(STATE):
    os.environ.setdefault("NETMON_INTEGRATIONS", os.path.join(STATE, "integrations.json"))
import integrations  # noqa: E402  /netmon/integrations.py (Elasticsearch URL + the audit key)

SPOOL = os.path.join(STATE, "audit_spool.jsonl")
DEAD = os.path.join(STATE, "audit_rejected.jsonl")   # entries Elasticsearch refused as malformed (kept, not resent)
SPOOL_MAX = 4 * 1024 ** 3        # spool may grow to 4 GB while Elasticsearch is down or backed up ...
SPOOL_MIN_FREE = 2 * 1024 ** 3   # ... as long as 2 GB of disk stay free; only then are entries dropped
BULK_DOCS, BULK_BYTES, BULK_TIMEOUT = 500, 8 * 1024 * 1024, 60
MAX_TEXT = 32000          # characters kept per prompt / answer
MAX_PARAM = 4000          # characters kept per request parameter
_q = queue.Queue(maxsize=20000)
_lock = threading.Lock()
_spool_lock = threading.Lock()
STATUS = {"sent": 0, "spooled": 0, "dropped": 0, "last_ok": None, "last_error": "", "started": False}
SECRET_RE = re.compile(r"pass(word)?|secret|token|api_?key|^key$|^current$|cookie|auth|p256dh|credential|private", re.I)
_ctx = ssl._create_unverified_context()  # Security Onion's own CA (same as the collectors)


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def clean(v, depth=0):
    """Request parameters as stored: secrets redacted, long strings / lists cut, nesting bounded."""
    if depth > 4:
        return "…"
    if isinstance(v, dict):
        return {str(k)[:80]: ("[redacted]" if SECRET_RE.search(str(k)) and v[k] not in (None, "", False) else clean(v[k], depth + 1))
                for k in list(v)[:60]}
    if isinstance(v, list):
        return [clean(x, depth + 1) for x in v[:50]]
    if isinstance(v, str):
        return v if len(v) <= MAX_PARAM else v[:MAX_PARAM] + f"… [{len(v)} chars]"
    return v


def _cut(s, n=MAX_TEXT):
    s = "" if s is None else str(s)
    return s if len(s) <= n else s[:n] + f"\n… [truncated, {len(s)} chars]"


ACTORS = {"netmon (event reviewer)": "reviewer", "netmon (review log)": "reviewer", "netmon (background reviewer)": "reviewer", "netmon (review job)": "reviewer", "netmon (event research)": "researcher",
          "netmon (research job)": "researcher"}  # last one: entries spooled before the review / research split


def emit(doc):
    who = ACTORS.get((doc.get("user") or {}).get("name"))
    if who and not integrations.audit_send(who):  # switched off on the Audit log page (Send event reviewer / researcher events)
        STATUS["skipped"] = STATUS.get("skipped", 0) + 1
        return
    doc.setdefault("@timestamp", _now())
    doc.setdefault("event", {}).setdefault("id", uuid.uuid4().hex)
    doc["event"].update(kind="event", module="netmon")
    try:
        _q.put_nowait(doc)
    except queue.Full:  # writer is behind (ES slow / backed up): straight to the disk spool, never dropped
        _spool([doc])
    # the server's writer thread (start()) sends it; short-lived CLI processes call flush(drain=False) instead


def action(user, act, *, role=None, ip=None, outcome="success", method=None, path=None, status=None, params=None,
           target=None, message=None, category="web", ua=None):
    """One user action."""
    doc = {"event": {"dataset": "netmon.audit", "category": [category], "type": ["access" if method == "GET" else "change"] if method else ["info"],
                     "action": act, "outcome": outcome},
           "user": {"name": str(user or "-")[:80], **({"roles": [role]} if role else {})},
           "message": message or f"{user or '-'} {act} ({outcome})"}
    if ip:
        doc["source"] = {"ip": ip}
    if ua:
        doc["user_agent"] = {"original": str(ua)[:512]}
    if method or status:
        doc["http"] = {"request": {"method": method}, "response": {"status_code": status}}
    if path:
        doc["url"] = {"path": str(path)[:300]}
    nm = {}
    if params:
        nm["params"] = clean(params)
    if target:
        nm["target"] = str(target)[:1024]
    if nm:
        doc["netmon"] = nm
    emit(doc)


def llm(purpose, provider, model, *, user="netmon", system=None, prompt=None, response=None, usage=None, seconds=None,
        error=None, session=None, tools=None, status=None, message=None):
    """One request/answer between the app and an LLM."""
    usage = usage or {}
    tin = usage.get("prompt", usage.get("input_tokens", usage.get("prompt_tokens")))
    tout = usage.get("completion", usage.get("output_tokens", usage.get("completion_tokens")))
    out = "failure" if error or status in ("failed", "cancelled") else "success"
    doc = {"event": {"dataset": "netmon.llm", "category": ["process"], "type": ["info"], "action": "llm." + purpose, "outcome": out},
           "user": {"name": str(user or "netmon")[:80]},
           "gen_ai": {"system": provider or "", "operation": {"name": "chat"}, "request": {"model": model or ""},
                      "prompt": _cut(prompt), "completion": _cut(response)},
           "netmon": {"llm": {"purpose": purpose}},
           "message": message or f"{purpose}: {provider}/{model} for {user}" + (f" - {str(error)[:120]}" if error else "")}
    if seconds is not None:
        doc["event"]["duration"] = int(float(seconds) * 1e9)
    if tin is not None or tout is not None:
        doc["gen_ai"]["usage"] = {"input_tokens": int(tin or 0), "output_tokens": int(tout or 0)}
    L = doc["netmon"]["llm"]
    if system:
        L["system_prompt"] = _cut(system, 12000)
    if session:
        L["session_id"] = str(session)[:128]
    if tools:
        L["tools"] = [str(t)[:80] for t in tools][:50]
    if error:
        L["error"] = str(error)[:2000]
    if status:
        L["status"] = str(status)[:40]
    emit(doc)


# ---------------------------------------------------------------- Elasticsearch
def index():
    """Base name (Audit log settings, default logs-netmon). Entries go to <base>.YYYY.MM.DD, see index_for()."""
    return integrations.audit_index()


def index_for(doc):
    """Daily write index from the entry's own @timestamp (UTC), e.g. logs-netmon.2026.10.31 - spooled entries land in
    the day they happened, not the day they were sent."""
    ts = str(doc.get("@timestamp") or _now())
    day = ts[:10].replace("-", ".") if re.match(r"^\d{4}-\d\d-\d\d", ts) else datetime.now(timezone.utc).strftime("%Y.%m.%d")
    return f"{index()}.{day}"  # "." not "-": logs-netmon-<day> would match Security Onion's logs-*-* data-stream template


def read_pattern():
    """Everything readable: the daily indices plus the single index used before the daily split."""
    return f"{index()},{index()}.*,{index()}-*"  # -*: entries written for a few minutes as a data stream before the "." naming


RQ = "ignore_unavailable=true&allow_no_indices=true"
TEMPLATE = os.path.join(_ROOT, "docs", "audit_index_template.json")


def ensure_template():
    """Install / update the index template (fixed mapping) for <base> and <base>.* so every new daily index gets it.
    Needs manage_index_templates on the audit key; without it the template from docs/audit_index_template.json must be
    installed by hand (docs/AUDIT_LOG.md). Never raises."""
    try:
        t = json.load(open(TEMPLATE))
        t["index_patterns"] = [index(), index() + ".*"]
        for k in [k for k in t if k.startswith(("created_date", "modified_date"))]:  # system-managed: rejected on PUT
            t.pop(k)
        _es("PUT", "/_index_template/netmon-audit?master_timeout=120s", t, timeout=180)  # cluster-state updates can be slow
        STATUS["template"] = "ok"
    except Exception as e:  # noqa: BLE001
        STATUS["template"] = f"not updated: {str(getattr(e, 'reason', e))[:150]}"
        print(f"audit: index template not updated ({STATUS['template']})", file=sys.stderr)


def _es(method, path, body=None, ndjson=False, timeout=15, key=None):
    url, key = integrations.es_url(), key or integrations.audit_key()
    if not url or not key:
        raise RuntimeError("audit log: Elasticsearch URL or audit API key not configured")
    if not url.startswith(("https://", "http://")):
        raise RuntimeError("audit log: bad Elasticsearch URL")
    data = None
    if body is not None:
        data = body.encode() if isinstance(body, str) else json.dumps(body).encode()
    req = urllib.request.Request(url + path, data=data, method=method,
                                 headers={"Authorization": f"ApiKey {key}",
                                          "Content-Type": "application/x-ndjson" if ndjson else "application/json"})
    with urllib.request.urlopen(req, context=_ctx if url.startswith("https://") else None, timeout=timeout) as r:  # noqa: S310 - http(s) checked
        return json.load(r)


class Retry(Exception):
    """A bulk request where Elasticsearch accepted some entries and asked for the rest to be sent again later
    (429 / 503 / shard not ready / timeout...). .sent = entries stored, .docs = entries still to send."""

    def __init__(self, sent, docs, reason):
        super().__init__(reason)
        self.sent, self.docs, self.reason = sent, docs, reason


# per-item errors that are permanent: the entry itself does not fit the index (mapping / parse). Everything else
# (429 overloaded, 5xx, unavailable shards, cluster blocks, timeouts, auth) is retried, never thrown away.
PERMANENT = re.compile(r"mapper_parsing|document_parsing|illegal_argument|strict_dynamic_mapping|parse_exception|x_content_parse", re.I)


def _action(d):
    a = {"_index": index_for(d)}
    eid = (d.get("event") or {}).get("id") if isinstance(d.get("event"), dict) else None
    if eid and re.fullmatch(r"[A-Za-z0-9_-]{1,64}", str(eid)):
        a["_id"] = str(eid)  # idempotent: a re-send after a timeout answers 409 instead of storing a duplicate
    return {"create": a}


def _bulk(docs):
    """Send one chunk. Returns the number stored (409 = stored earlier counts as stored). Entries that are
    permanently malformed go to the dead-letter file; retryable failures raise Retry with those entries."""
    body = "".join(json.dumps(_action(d)) + "\n" + json.dumps(d, default=str) + "\n" for d in docs)
    r = _es("POST", "/_bulk", body, ndjson=True, timeout=BULK_TIMEOUT)
    if not r.get("errors"):
        return len(docs)
    retry, dead, why = [], [], ""
    for d, it in zip(docs, r.get("items", [])):
        res = it.get("create") or next(iter(it.values()), {})
        err, st = res.get("error"), res.get("status", 0)
        if not err or st == 409:  # 409 version_conflict on our own _id: already stored by an earlier attempt
            continue
        etxt = json.dumps(err)[:300] if isinstance(err, dict) else str(err)[:300]
        if st in (0, 400) and PERMANENT.search(etxt):
            dead.append((d, etxt))
        else:
            retry.append(d)
            why = why or f"{st} {etxt}"
    if len(r.get("items", [])) < len(docs):  # malformed answer: resend what it did not report on
        retry.extend(docs[len(r.get("items", [])):])
    if dead:
        STATUS["rejected"] = STATUS.get("rejected", 0) + len(dead)
        STATUS["last_reject"] = dead[0][1]
        _dead_letter(dead)
        print(f"audit: {len(dead)} entries rejected (kept in {os.path.basename(DEAD)}): {STATUS['last_reject']}", file=sys.stderr)
    sent = len(docs) - len(retry) - len(dead)
    if retry:
        STATUS["retried"] = STATUS.get("retried", 0) + len(retry)
        raise Retry(sent, retry, f"Elasticsearch deferred {len(retry)} entries: {why[:200]}")
    return sent


def _chunks(docs):
    """Bulk-sized chunks: at most BULK_DOCS entries and about BULK_BYTES each (LLM entries are up to ~80 KB)."""
    out, size = [], 0
    for d in docs:
        n = len(json.dumps(d, default=str))
        if out and (len(out) >= BULK_DOCS or size + n > BULK_BYTES):
            yield out
            out, size = [], 0
        out.append(d)
        size += n
    if out:
        yield out


def _dead_letter(items):
    try:
        fd = os.open(DEAD, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a") as f:
            for d, err in items:
                f.write(json.dumps({"error": err, "doc": d}, default=str) + "\n")
    except OSError as e:
        print(f"audit: dead-letter write failed: {e}", file=sys.stderr)


def _spool_full():
    """True only when disk space really runs out: the spool may grow to SPOOL_MAX and must leave SPOOL_MIN_FREE free."""
    try:
        if os.path.exists(SPOOL) and os.path.getsize(SPOOL) > SPOOL_MAX:
            return True
        st = os.statvfs(os.path.dirname(SPOOL) or ".")
        return st.f_bavail * st.f_frsize < SPOOL_MIN_FREE
    except OSError:
        return False


def _spool(docs):
    """Keep entries on disk until Elasticsearch takes them. Dropping is the very last resort (disk full / unwritable)."""
    if not docs:
        return
    with _spool_lock:
        try:
            if _spool_full():
                STATUS["dropped"] += len(docs)
                print(f"audit: spool full / disk low - {len(docs)} entries DROPPED", file=sys.stderr)
                return
            fd = os.open(SPOOL, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            with os.fdopen(fd, "a") as f:
                f.write("".join(json.dumps(d, default=str) + "\n" for d in docs))
                f.flush()
                os.fsync(f.fileno())
            STATUS["spooled"] += len(docs)
        except OSError as e:
            STATUS["dropped"] += len(docs)
            print(f"audit: spool failed: {e}", file=sys.stderr)


def _read_chunk(f):
    """Next bulk-sized chunk of spooled entries from an open file (unparseable lines go to the dead-letter file)."""
    out, size = [], 0
    while len(out) < BULK_DOCS and size < BULK_BYTES:
        line = f.readline()
        if not line:
            break
        if not line.strip():
            continue
        try:
            out.append(json.loads(line))
            size += len(line)
        except ValueError:
            _dead_letter([({"raw": line[:MAX_TEXT]}, "unreadable spool line")])
    return out


def _drain_spool():
    """Send what was spooled while ES was unreachable or busy: oldest first, streamed in bulk-sized chunks, so a
    large spool never sits in memory. On a failure the unsent rest (incl. deferred entries) stays for the retry."""
    work = SPOOL + ".sending"
    with _spool_lock:
        if not os.path.exists(work):
            if not os.path.exists(SPOOL) or not os.path.getsize(SPOOL):
                return
            os.replace(SPOOL, work)
    with open(work) as f:
        while True:
            chunk = _read_chunk(f)
            if not chunk:
                break
            try:
                STATUS["sent"] += _bulk(chunk)
            except Exception as e:
                left = e.docs if isinstance(e, Retry) else chunk
                if isinstance(e, Retry):
                    STATUS["sent"] += e.sent
                with open(work + ".tmp", "w") as t:  # keep only what was not stored yet
                    t.writelines(json.dumps(d, default=str) + "\n" for d in left)
                    while True:
                        b = f.read(1 << 20)
                        if not b:
                            break
                        t.write(b)
                os.replace(work + ".tmp", work)
                raise
    os.remove(work)
    STATUS["spooled"] = 0


def flush(batch=None, drain=True):
    """Write queued entries now. Short-lived CLI processes call flush(drain=False) before they exit: only the
    server's writer thread sends the spool, so two processes never send the same spooled entries.
    Nothing is lost on a failure: whatever Elasticsearch did not store is spooled to disk."""
    docs = list(batch or [])
    while True:
        try:
            docs.append(_q.get_nowait())
        except queue.Empty:
            break
    if not docs and not os.path.exists(SPOOL) and not os.path.exists(SPOOL + ".sending"):
        return 0
    with _lock:
        n, chunks, i = 0, [], 0
        try:
            if drain:
                _drain_spool()
            chunks = list(_chunks(docs))
            for i, c in enumerate(chunks):
                n += _bulk(c)
            STATUS.update(sent=STATUS["sent"] + n, last_ok=time.time(), last_error="")
            return n
        except Exception as e:  # noqa: BLE001 - ES down / busy / no key: keep every unsent entry on disk
            if chunks:  # failed while sending the new entries: chunk i not (fully) stored, later chunks not tried
                left = (e.docs if isinstance(e, Retry) else chunks[i]) + [d for c in chunks[i + 1:] for d in c]
            else:  # failed while draining the spool (which keeps its own rest): none of the new entries were sent
                left = docs
            n += e.sent if isinstance(e, Retry) and chunks else 0
            STATUS["sent"] += n
            STATUS["last_error"] = f"{type(e).__name__}: {str(getattr(e, 'reason', e))[:200]}"
            _spool(left)
            return n


def _save_queue():
    """On shutdown: whatever is still in memory goes to the spool, so a restart / redeploy loses nothing."""
    left = []
    while True:
        try:
            left.append(_q.get_nowait())
        except queue.Empty:
            break
    _spool(left)


def _loop():
    backoff = 2
    while True:
        try:
            first = _q.get(timeout=30)
        except queue.Empty:
            first = None
        time.sleep(2)  # gather a batch
        batch = [first] if first else []
        try:
            flush(batch)
            backoff = 2 if not STATUS["last_error"] else min(backoff * 2, 120)
        except Exception as e:  # noqa: BLE001 - the writer thread must never die
            print(f"audit writer: {e}", file=sys.stderr)
        if STATUS["last_error"]:
            time.sleep(backoff)


def start():
    with _lock:
        if STATUS["started"]:
            return
        STATUS["started"] = True
    threading.Thread(target=ensure_template, name="audit-template", daemon=True).start()
    threading.Thread(target=_loop, name="audit-writer", daemon=True).start()
    atexit.register(_save_queue)
    try:  # docker stop sends SIGTERM: exit normally so atexit spools the in-memory queue
        if threading.current_thread() is threading.main_thread() and signal.getsignal(signal.SIGTERM) in (signal.SIG_DFL, None):
            signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    except (ValueError, OSError):
        pass


# ---------------------------------------------------------------- reading (the Audit log page)
RANGES = {"1h": "now-1h", "24h": "now-24h", "7d": "now-7d", "30d": "now-30d", "90d": "now-90d"}
BIG = ("gen_ai.prompt", "gen_ai.completion", "netmon.llm.system_prompt")


def search(p):
    """p: kind (all|action|llm), range, user, action, outcome, model, q, page. Newest first, 50 per page."""
    size, page = 50, max(0, min(int(p.get("page") or 0), 190))
    flt = []
    iso = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d(:\d\d(\.\d+)?)?(Z|[+-]\d\d:\d\d)$")
    if p.get("start") or p.get("end"):  # explicit time range (start / end, ISO with offset)
        r = {}
        for k, op in (("start", "gte"), ("end", "lte")):
            v = str(p.get(k) or "")
            if v:
                if not iso.match(v):
                    raise ValueError(f"bad {k} time")
                r[op] = v
        flt.append({"range": {"@timestamp": r}})
    else:
        rng = RANGES.get(p.get("range") or "24h")
        if rng:
            flt.append({"range": {"@timestamp": {"gte": rng}}})
    kind = p.get("kind") or "all"
    if kind in ("action", "llm"):
        flt.append({"term": {"event.dataset": "netmon.audit" if kind == "action" else "netmon.llm"}})
    for f, field in (("user", "user.name"), ("action", "event.action"), ("outcome", "event.outcome"), ("model", "gen_ai.request.model")):
        if p.get(f):
            flt.append({"term": {field: str(p[f])[:200]}})
    must = []
    if (p.get("q") or "").strip():
        must.append({"simple_query_string": {"query": str(p["q"])[:300], "default_operator": "and", "lenient": True,
                                             "fields": ["message", "gen_ai.prompt", "gen_ai.completion", "netmon.target", "netmon.params",
                                                        "url.path", "user.name", "event.action", "gen_ai.request.model", "netmon.llm.error"]}})
    body = {"size": size, "from": page * size, "track_total_hits": True, "sort": [{"@timestamp": "desc"}],
            "query": {"bool": {"filter": flt, "must": must}},
            "_source": {"excludes": list(BIG)},
            "aggs": {"users": {"terms": {"field": "user.name", "size": 50}},
                     "actions": {"terms": {"field": "event.action", "size": 200}},
                     "models": {"terms": {"field": "gen_ai.request.model", "size": 50}},
                     "outcomes": {"terms": {"field": "event.outcome", "size": 5}},
                     "kinds": {"terms": {"field": "event.dataset", "size": 5}},
                     "tin": {"sum": {"field": "gen_ai.usage.input_tokens"}}, "tout": {"sum": {"field": "gen_ai.usage.output_tokens"}},
                     "over_time": {"auto_date_histogram": {"field": "@timestamp", "buckets": 48},
                                   "aggs": {"kind": {"terms": {"field": "event.dataset", "size": 3}}}}}}
    r = _es("POST", f"/{read_pattern()}/_search?{RQ}", body)
    A = r.get("aggregations") or {}
    tb = lambda k: [{"key": b["key"], "n": b["doc_count"]} for b in (A.get(k) or {}).get("buckets", [])]  # noqa: E731
    rows = []
    for h in (r.get("hits") or {}).get("hits", []):
        s = h["_source"]
        rows.append({"id": h["_id"], "ts": s.get("@timestamp"), "kind": "llm" if (s.get("event") or {}).get("dataset") == "netmon.llm" else "action",
                     "user": (s.get("user") or {}).get("name"), "role": ((s.get("user") or {}).get("roles") or [""])[0],
                     "action": (s.get("event") or {}).get("action"), "outcome": (s.get("event") or {}).get("outcome"),
                     "message": s.get("message"), "ip": (s.get("source") or {}).get("ip"),
                     "status": ((s.get("http") or {}).get("response") or {}).get("status_code"),
                     "model": ((s.get("gen_ai") or {}).get("request") or {}).get("model"), "provider": (s.get("gen_ai") or {}).get("system"),
                     "tokens": (s.get("gen_ai") or {}).get("usage"), "seconds": round(((s.get("event") or {}).get("duration") or 0) / 1e9, 2) or None,
                     "target": (s.get("netmon") or {}).get("target")})
    hist = [{"t": b["key_as_string"] if "key_as_string" in b else b["key"], "ms": b["key"],
             **{x["key"]: x["doc_count"] for x in b.get("kind", {}).get("buckets", [])}}
            for b in (A.get("over_time") or {}).get("buckets", [])]
    return {"total": ((r.get("hits") or {}).get("total") or {}).get("value", 0), "page": page, "size": size, "rows": rows,
            "users": tb("users"), "actions": tb("actions"), "models": tb("models"), "outcomes": tb("outcomes"), "kinds": tb("kinds"),
            "tokens": {"in": int((A.get("tin") or {}).get("value") or 0), "out": int((A.get("tout") or {}).get("value") or 0)},
            "interval": (A.get("over_time") or {}).get("interval"), "histogram": hist}


def review_entries(hours=24, size=200):
    """netmon.review entries (AI pipeline monitoring > Review log card), newest first, with counts per kind / outcome."""
    body = {"size": size, "sort": [{"@timestamp": "desc"}], "track_total_hits": True,
            "query": {"bool": {"filter": [{"term": {"event.dataset": "netmon.review"}}, {"range": {"@timestamp": {"gte": f"now-{int(hours)}h"}}}]}},
            "aggs": {"kind": {"terms": {"field": "event.action", "size": 10}, "aggs": {"out": {"terms": {"field": "event.outcome", "size": 5}}}}}}
    r = _es("POST", f"/{read_pattern()}/_search?{RQ}", body)
    return [h["_source"] for h in (r.get("hits") or {}).get("hits", [])], ((r.get("hits") or {}).get("total") or {}).get("value", 0)


def doc(doc_id):
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", doc_id or ""):
        raise ValueError("bad id")
    r = _es("POST", f"/{read_pattern()}/_search?{RQ}", {"size": 1, "query": {"ids": {"values": [doc_id]}}})
    hits = (r.get("hits") or {}).get("hits") or []
    return hits[0]["_source"] if hits else None


def status():
    out = {k: STATUS.get(k) for k in ("sent", "spooled", "dropped", "rejected", "retried", "last_reject", "last_ok", "last_error")}
    out.update(send_reviewer=integrations.audit_send("reviewer"), send_researcher=integrations.audit_send("researcher"), skipped=STATUS.get("skipped", 0), index=index_for({}), index_pattern=index() + ".*", template=STATUS.get("template"), es_url_set=bool(integrations.es_url()), key_set=bool(integrations.audit_key()), queued=_q.qsize())
    try:
        out["spool_bytes"] = sum(os.path.getsize(p) for p in (SPOOL, SPOOL + ".sending") if os.path.exists(p))
        out["rejected_bytes"] = os.path.getsize(DEAD) if os.path.exists(DEAD) else 0
    except OSError:
        out["spool_bytes"] = 0
    try:
        c = _es("GET", f"/{read_pattern()}/_count?{RQ}", timeout=8)
        out.update(connected=True, docs=c.get("count"))
    except Exception as e:  # noqa: BLE001
        out.update(connected=False, error=integrations._err(e) if isinstance(e, urllib.error.HTTPError) else str(e)[:200])
    return out
