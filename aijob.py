#!/usr/bin/env python3
"""Shared machinery of netmon's AI jobs (review.py, research.py): read-only tools, budget, conversation logs, snapshot load.

The AI works through narrow, read-only tools (Elasticsearch search, netmon data, notes, optionally web search / fetch);
each job adds its own submit_* tool that writes through enrich.sh (dashboard container).
"""
import datetime as dt, glob, json, os, re, subprocess, sys, time  # noqa: F401,E401

NM = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, NM)
sys.path.insert(1, os.path.join(NM, "dashboard", "app"))
import agent  # noqa: E402
import esk  # noqa: E402  (dashboard/app) Elasticsearch search -> Kibana artifact
import store  # noqa: E402
import webtools  # noqa: E402

DATA = os.path.join(NM, "data")
PY = os.environ.get("NETMON_PYTHON") or "/usr/bin/python3"
STATE = os.environ.get("STATE_DIR") or ("/state" if os.path.isdir("/state") else os.path.join(NM, "dashboard", "state"))
BATCH = 8
STAMP_RE = re.compile(r"/(\d{4}-\d\d-\d\dT\d{4}Z)\.json$")


def prompt(name):
    return open(os.path.join(NM, "prompts", name + ".md")).read()


# ------------------------------------------------------------------ helpers
def sh(argv, timeout=3600, inp=None):
    p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, cwd=NM, input=inp)  # noqa: S603 - fixed argv
    return p.returncode, p.stdout, p.stderr


def latest_snapshot():
    snaps = sorted(p for p in store.jglob(DATA, "*.json") if STAMP_RE.search(p))
    return snaps[-1] if snaps else None


def jload(p, default=None):
    return store.jload(p, default)


def _walk(obj, path):
    for part in [p for p in str(path or "").split("/") if p != ""]:
        if isinstance(obj, list):
            try:
                obj = obj[int(part)]
            except (ValueError, IndexError):
                raise KeyError(f"no index {part!r} (list of {len(obj)})") from None
        elif isinstance(obj, dict):
            if part not in obj:
                close = [k for k in obj if part.lower() in str(k).lower()][:20]
                raise KeyError(f"no key {part!r}" + (f"; similar: {close}" if close else f"; keys: {list(obj)[:40]}"))
            obj = obj[part]
        else:
            raise KeyError(f"{part!r}: not a container")
    return obj


def _overview(v, limit):
    s = json.dumps(v, default=str, ensure_ascii=False)
    if len(s) <= limit:
        return v
    if isinstance(v, dict):
        return {"_note": f"too big to show whole ({len(s):,} chars); read a sub-path. Keys with sizes:",
                "keys": {str(k): len(json.dumps(x, default=str)) for k, x in list(v.items())[:300]}}
    if isinstance(v, list):
        return {"_note": f"list of {len(v)} items ({len(s):,} chars); read items by index, e.g. path/0. First items:",
                "first": json.loads(json.dumps(v[:5], default=str))[:5]}
    return s[:limit]



# ------------------------------------------------------------------ the job
class Job:
    """One AI job run: the tools its model may call, a token/cost budget and saved conversations.
    Subclasses (review.py Review, research.py Research) set LOGDIR (conversation logs), LABEL and SOURCE (es_queries log)."""
    LOGDIR, LABEL, SOURCE = os.path.join(NM, "logs", "ai"), "AI run", "ai"

    def __init__(self, target, args, budget, web=False, es=True, max_searches=0):
        self.target, self.args, self.budget = target, args, budget
        self.web, self.es, self.max_searches = bool(web), bool(es), max_searches
        self.fetched, self.errors, self.counts = set(), [], {}
        self.es_found = []  # Elasticsearch searches of the current batch (esk descriptors)
        self.snap = self.stem = None
        self.raw, self.ana = {}, {}
        os.makedirs(self.LOGDIR, mode=0o700, exist_ok=True)
        os.chmod(self.LOGDIR, 0o700)

    # ---- citations
    def ledger_path(self):
        return self.stem + ".sources.json"

    def ledger(self):
        d = jload(self.ledger_path(), {"version": 1, "sources": []})
        return d if isinstance(d, dict) else {"version": 1, "sources": d}

    def known_urls(self):
        urls = set(self.fetched)
        for f in sorted(store.jglob(DATA, "*.sources.json"))[-30:]:
            d = jload(f, {})
            urls |= {s.get("url") for s in (d.get("sources") if isinstance(d, dict) else d) or [] if isinstance(s, dict)}
        return urls

    # ---- tools
    def t_es(self, a):
        import esq
        idx = str(a.get("index") or "")
        if not re.fullmatch(r"[A-Za-z0-9*._,\-]{1,200}", idx) or idx.startswith(("_", "-")):
            raise ValueError("index: an index name or pattern such as logs-zeek-so or logs-endpoint.events.process-*")
        body = a.get("body") if isinstance(a.get("body"), dict) else json.loads(a.get("body") or "{}")
        if re.search(r'"(script|script_fields|runtime_mappings)"', json.dumps(body)):
            raise ValueError("scripts are not allowed in searches")
        for_ids = [str(x) for x in (a.get("for_ids") or []) if isinstance(x, (str, int))][:20] if isinstance(a.get("for_ids"), list) else []
        body["size"] = max(0, min(int(body.get("size", 10)), 50))
        body.setdefault("timeout", "60s")
        t0, err, r = time.time(), None, {}
        try:
            r = esq.q(idx, body)
        except Exception as e:
            err = f"{type(e).__name__}: {e}"[:300]
            raise
        finally:
            self.log_es(idx, body, r, time.time() - t0, err)
        hits = r.get("hits") or {}
        tot = (hits.get("total") or {}).get("value") if isinstance(hits.get("total"), dict) else hits.get("total")
        try:  # kept as a Kibana-openable artifact of the notes/links of this batch (dashboard: esk.py)
            d = esk.from_dsl(idx, body, tot)
            d["for_ids"] = for_ids
            self.es_found.append(d)
        except Exception as e:  # noqa: BLE001 - artifacts are a convenience, never fail the search
            print(f"es artifact failed: {e}", file=sys.stderr)
        out = {"total": tot,
               "hits": [json.dumps(h.get("_source"), ensure_ascii=False)[:1500] for h in hits.get("hits") or []]}
        if r.get("aggregations"):
            out["aggregations"] = r["aggregations"]
        return out

    def log_es(self, idx, body, r, secs, err):
        """Keep every Elasticsearch search of this job in corr_llm.db (AI review, tagged with the job's SOURCE)."""
        try:
            import sqlite3
            h = r.get("hits") or {}
            tot = (h.get("total") or {}).get("value") if isinstance(h.get("total"), dict) else h.get("total")
            c = sqlite3.connect(os.path.join(STATE, "corr_llm.db"), timeout=10)
            try:
                c.execute("ALTER TABLE es_queries ADD COLUMN source TEXT DEFAULT 'reviewer'")
            except sqlite3.OperationalError:
                pass
            with c:
                c.execute("INSERT INTO es_queries (ts, anchor, candidates, model, query, total, seconds, error, source) VALUES (?,?,?,?,?,?,?,?,?)",
                          (time.time(), f"{self.LABEL} " + os.path.basename(self.stem or ""), "[]", self.target.get("model"),
                           json.dumps({"index": idx, "body": body}, default=str)[:4000], tot, round(secs, 2), err, self.SOURCE))
            c.close()
        except Exception as e:
            print(f"es log failed: {e}", file=sys.stderr)

    def files(self):
        return {"snapshot": self.raw, "analysis": self.ana, "known_benign": jload(os.path.join(NM, "known_benign.json"), {}),
                "policy": jload(os.path.join(NM, "policy.json"), {})}

    def t_read(self, a):
        f = self.files()
        name = a.get("file") or "snapshot"
        if name not in f:
            raise ValueError(f"file must be one of {list(f)}")
        lim = max(1000, min(int(a.get("max_chars") or 10000), 20000))
        return _overview(_walk(f[name], a.get("path")), lim)

    def t_device(self, a):
        import netmon_mcp
        return netmon_mcp.device({"query": str(a.get("query") or "")})

    def t_kb(self, a):
        rc, out, err = sh([os.path.join(NM, "enrich.sh"), "kb", str(a.get("filter") or "")[:100]], timeout=120)
        if rc:
            raise RuntimeError(err[-300:])
        return out

    def t_search(self, a):
        return webtools.search(a.get("query"), a.get("n") or 6)

    def t_fetch(self, a):
        r = webtools.fetch(str(a.get("url") or ""), a.get("max_chars") or 8000)
        self.fetched.add(r["url"])
        self.fetched.add(str(a.get("url")))
        return r

    def t_cite(self, a):
        url, title = str(a.get("url") or "").strip(), str(a.get("title") or "").strip()[:200]
        led = self.ledger()
        for s in led["sources"]:
            if s.get("url") == url:
                return {"id": s["id"]}
        if url not in self.known_urls():
            raise ValueError("fetch the page with web_fetch first - only pages you read can be cited")
        sid = max([int(s.get("id") or 0) for s in led["sources"]] or [0]) + 1
        led["sources"].append({"id": sid, "url": url, "title": title or url, "accessed": time.strftime("%Y-%m-%d", time.gmtime())})
        store.jdump(led, self.ledger_path())
        return {"id": sid}

    def _links(self, links, where):
        out = []
        urls = self.known_urls()
        for l in links or []:
            if not isinstance(l, dict) or not str(l.get("url") or "").startswith(("http://", "https://")):
                continue
            if l["url"] not in urls:
                raise ValueError(f"{where}: link {l['url'][:100]} was not fetched - only link pages you read")
            out.append({"title": str(l.get("title") or l["url"])[:200], "url": l["url"][:500]})
        return out

    def queries_for(self, *item_ids):
        """Searches of this batch that concern one of the items (tagged with for_ids) or were not tagged at all."""
        want = set(item_ids)
        out = [{k: v for k, v in d.items() if k != "for_ids"} for d in self.es_found if not d.get("for_ids") or want & set(d["for_ids"])]
        return out[:12]


    NOWEB = "\n\nWeb access is switched off for this run: you have no web_search, web_fetch or cite tools. Work from the local data only, do not cite sources or add links, and say so in a note when a verdict would need outside information."

    def tools(self, batch=None):
        T = {
            "es_search": (self.t_es, "Read-only Elasticsearch search (query DSL). Keep size small (<= 50) and use aggregations for counts.",
                          {"index": {"type": "string", "description": "index or pattern, e.g. logs-zeek-so"},
                           "body": {"type": "object", "description": "search body: query, aggs, size, sort, _source"},
                           "for_ids": {"type": "array", "items": {"type": "string"}, "description": "ids of the work items this search is about; each search is attached to those notes as a Kibana link"}}, ["index", "body"]),
            "read_data": (self.t_read, "Read netmon data by path. Files: snapshot (full collected data), analysis (findings vs baseline), "
                          "known_benign, policy. path uses '/' between keys, e.g. devices/192.168.1.20 or "
                          "alerts/signatures/0. Big objects come back as a key list with sizes.",
                          {"file": {"type": "string"}, "path": {"type": "string"}, "max_chars": {"type": "integer"}}, ["file"]),
            "device_lookup": (self.t_device, "Everything netmon knows about one device (traffic, destinations, services, findings, notes).",
                              {"query": {"type": "string", "description": "IP, MAC or name"}}, ["query"]),
            "notes_kb": (self.t_kb, "Notes knowledge base: host notes (AI and owner) per device and the owner's notes on events.",
                         {"filter": {"type": "string", "description": "optional IP / MAC / host / text filter"}}),
            "web_search": (self.t_search, "Search the web. Returns titles, URLs and snippets.",
                           {"query": {"type": "string"}, "n": {"type": "integer"}}, ["query"]),
            "web_fetch": (self.t_fetch, "Read a public web page as text (needed before citing or linking it).",
                          {"url": {"type": "string"}, "max_chars": {"type": "integer"}}, ["url"]),
            "cite": (self.t_cite, "Register a page you fetched as a source; returns its id for [n] citations.",
                     {"url": {"type": "string"}, "title": {"type": "string"}}, ["url", "title"]),
        }
        if not self.es:
            T.pop("es_search")
        if batch and self.web and self.max_searches and "web_search" in T:
            left, fn, cap = [self.max_searches * len(batch)], T["web_search"][0], self.max_searches * len(batch)
            def capped(a, _fn=fn, _left=left, _cap=cap):
                if _left[0] <= 0:
                    raise ValueError(f"web search limit reached ({self.max_searches} per event, {_cap} for this batch): use web_fetch on pages you already found, or finish with what you have")
                _left[0] -= 1
                return _fn(a)
            T["web_search"] = (capped,) + tuple(T["web_search"][1:])
        if not self.web:  # web access off for this job
            for k in ("web_search", "web_fetch", "cite"):
                T.pop(k, None)
        return T

    def converse(self, name, system, user, tools, stop, **kw):
        log = {"name": name, "model": self.target, "started": time.time(), "system": system, "user": user}
        try:
            r = agent.run(self.target, system, user, tools, budget=self.budget, stop_tools=stop, **kw)
            log.update(result={k: r[k] for k in ("text", "turns", "tool_calls", "stopped")}, messages=r["messages"])
            return r
        except Exception as e:
            log["error"] = f"{type(e).__name__}: {e}"
            raise
        finally:
            log["usage"] = self.budget.summary()
            fn = os.path.join(self.LOGDIR, f"{time.strftime('%Y%m%dT%H%M%S', time.gmtime())}-{name}.json")
            fd = os.open(fn, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)  # transcripts hold log data: owner-only
            with os.fdopen(fd, "w") as f:
                f.write(agent.redact(json.dumps(log, indent=1, default=str, ensure_ascii=False)))
            for old in sorted(glob.glob(os.path.join(self.LOGDIR, "*.json")))[:-60]:
                os.remove(old)


    # ---- snapshot
    def collect(self):
        """Collect + analyze a new snapshot (unless args.skip_collect), then load the newest one."""
        if not self.args.skip_collect:
            rc, out, err = sh([PY, os.path.join(NM, "collect.py"), "24" if getattr(self, "daily", False) else "auto"], timeout=3600)
            if rc:
                raise RuntimeError(f"collect.py failed: {(err or out)[-400:]}")
            rc, out, err = sh([PY, os.path.join(NM, "analyze.py")], timeout=3600)
            if rc:
                raise RuntimeError(f"analyze.py failed: {(err or out)[-400:]}")
            self.analyze_out = out + err
            if "store backup FAILED" in self.analyze_out or re.search(r"integrity[^\n]*(?<!ok)$", self.analyze_out, re.M) and "integrity: ok" not in self.analyze_out:
                self.errors.append("analyze: store backup or integrity check problem (see analyze output)")
        self.snap = latest_snapshot()
        if not self.snap:
            raise RuntimeError("no snapshot in data/")
        self.stem = self.snap[:-5]
        self.raw, self.ana = jload(self.snap, {}), jload(self.stem + ".analysis.json", {})
        if self.raw.get("extras_errors"):
            self.errors.append(f"collector errors: {json.dumps(self.raw['extras_errors'])[:300]}")
        if not store.jexists(self.ledger_path()):
            store.jdump({"version": 1, "sources": []}, self.ledger_path())

