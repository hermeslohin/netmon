"""Audit log for the dashboard (More > Audit log, #/audit), stored in Elasticsearch index `logs-netmon`.

Two kinds of entries (ECS field names, so they also read well in Kibana / Security Onion Hunt):
  event.dataset = netmon.audit   every user action: sign-in / sign-out, every POST (check-offs, notes, chat,
                                 settings, users, AI verdicts...), page views, report downloads, denied requests
  event.dataset = netmon.llm     every conversation between the app and an LLM: Ask AI chat turns, the
                                 correlation reviewer, model comparisons, item comparisons and the research job's
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
import json, os, queue, re, ssl, sys, threading, time, urllib.error, urllib.request, uuid
from datetime import datetime, timezone

STATE = os.environ.get("STATE_DIR", "/state")
_ROOT = os.environ.get("NETMON_DIR", "/netmon")
if _ROOT not in sys.path:
    sys.path.append(_ROOT)
if os.path.isdir(STATE):
    os.environ.setdefault("NETMON_INTEGRATIONS", os.path.join(STATE, "integrations.json"))
import integrations  # noqa: E402  /netmon/integrations.py (Elasticsearch URL + the audit key)

SPOOL = os.path.join(STATE, "audit_spool.jsonl")
SPOOL_MAX = 50 * 1024 * 1024
MAX_TEXT = 32000          # characters kept per prompt / answer
MAX_PARAM = 4000          # characters kept per request parameter
_q = queue.Queue(maxsize=20000)
_lock = threading.Lock()
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


def emit(doc):
    doc.setdefault("@timestamp", _now())
    doc.setdefault("event", {}).setdefault("id", uuid.uuid4().hex)
    doc["event"].update(kind="event", module="netmon")
    try:
        _q.put_nowait(doc)
    except queue.Full:
        STATUS["dropped"] += 1
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
    return integrations.audit_index()


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


def _bulk(docs):
    ix = index()
    body = "".join(json.dumps({"create": {"_index": ix}}) + "\n" + json.dumps(d, default=str) + "\n" for d in docs)
    r = _es("POST", "/_bulk", body, ndjson=True, timeout=30)
    bad = [i["create"] for i in r.get("items", []) if i.get("create", {}).get("error")] if r.get("errors") else []
    if bad:  # a mapping problem on single entries must not block the rest forever: report it, keep going
        STATUS["rejected"] = STATUS.get("rejected", 0) + len(bad)
        STATUS["last_reject"] = str(bad[0].get("error"))[:300]
        print(f"audit: {len(bad)} entries rejected: {STATUS['last_reject']}", file=sys.stderr)
    return len(docs) - len(bad)


def _spool(docs):
    try:
        if os.path.exists(SPOOL) and os.path.getsize(SPOOL) > SPOOL_MAX:
            STATUS["dropped"] += len(docs)
            return
        fd = os.open(SPOOL, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a") as f:
            for d in docs:
                f.write(json.dumps(d, default=str) + "\n")
        STATUS["spooled"] += len(docs)
    except OSError as e:
        STATUS["dropped"] += len(docs)
        print(f"audit: spool failed: {e}", file=sys.stderr)


def _drain_spool():
    """Send what was spooled while ES was unreachable (oldest first, in chunks)."""
    if not os.path.exists(SPOOL) or not os.path.getsize(SPOOL):
        return
    work = SPOOL + ".sending"
    if not os.path.exists(work):
        os.replace(SPOOL, work)
    with open(work) as f:
        docs = [json.loads(l) for l in f if l.strip()]
    for i in range(0, len(docs), 500):
        try:
            STATUS["sent"] += _bulk(docs[i:i + 500])
        except Exception:
            with open(work + ".tmp", "w") as f:  # keep only what was not sent yet (no duplicates on the retry)
                f.writelines(json.dumps(d, default=str) + "\n" for d in docs[i:])
            os.replace(work + ".tmp", work)
            raise
    os.remove(work)
    STATUS["spooled"] = 0


def flush(batch=None, drain=True):
    """Write queued entries now. Short-lived CLI processes call flush(drain=False) before they exit: only the
    server's writer thread sends the spool, so two processes never send the same spooled entries."""
    docs = list(batch or [])
    while True:
        try:
            docs.append(_q.get_nowait())
        except queue.Empty:
            break
    if not docs and not os.path.exists(SPOOL) and not os.path.exists(SPOOL + ".sending"):
        return 0
    with _lock:
        try:
            if drain:
                _drain_spool()
            n = _bulk(docs) if docs else 0
            STATUS.update(sent=STATUS["sent"] + n, last_ok=time.time(), last_error="")
            return n
        except Exception as e:  # noqa: BLE001 - ES down / no key: keep the entries on disk
            STATUS["last_error"] = f"{type(e).__name__}: {str(getattr(e, 'reason', e))[:200]}"
            _spool(docs)
            return 0


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
    threading.Thread(target=_loop, name="audit-writer", daemon=True).start()


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
    r = _es("POST", f"/{index()}/_search", body)
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


def doc(doc_id):
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", doc_id or ""):
        raise ValueError("bad id")
    r = _es("POST", f"/{index()}/_search", {"size": 1, "query": {"ids": {"values": [doc_id]}}})
    hits = (r.get("hits") or {}).get("hits") or []
    return hits[0]["_source"] if hits else None


def status():
    out = {k: STATUS.get(k) for k in ("sent", "spooled", "dropped", "rejected", "last_reject", "last_ok", "last_error")}
    out.update(index=index(), es_url_set=bool(integrations.es_url()), key_set=bool(integrations.audit_key()), queued=_q.qsize())
    try:
        out["spool_bytes"] = os.path.getsize(SPOOL) if os.path.exists(SPOOL) else 0
    except OSError:
        out["spool_bytes"] = 0
    try:
        c = _es("GET", f"/{index()}/_count", timeout=8)
        out.update(connected=True, docs=c.get("count"))
    except Exception as e:  # noqa: BLE001
        out.update(connected=False, error=integrations._err(e) if isinstance(e, urllib.error.HTTPError) else str(e)[:200])
    return out
