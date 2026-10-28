#!/usr/bin/env python3
"""netmon research job: collect -> analyze [-> reviewer]; no AI call is ever made unless a person asks for it.

Started by scheduler.py on the grid set on the dashboard (research_cfg.py), or by hand:
    review.py [--trigger manual|schedule] [--skip-collect] [--max-batches N] [--event ID]
Scheduled runs (--trigger schedule) only collect + analyze and queue work items: no AI model is called.
The reviewer runs only on a person's Run now (--trigger manual); events are researched only on Send to research (--event).
The daily run is the first run at or after 05:00 UTC each day; it covers 24 h of logs so the device baseline stays daily.
Other runs cover the lookback window set on the AI review page.

The AI works through narrow, read-only tools (Elasticsearch search, netmon data, web search / fetch) and writes only
through validated submit_* tools: research notes via enrich.sh
(dashboard container), known_benign additions. Sources it cites are kept in data/<stamp>.sources.json.
Run state, token use and cost go to <state>/research_job.json (AI review page). Conversations are saved under
logs/research/ for review (git-ignored; the newest 60 are kept).
"""
import argparse, datetime as dt, fcntl, glob, json, os, re, subprocess, sys, time, traceback

NM = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, NM)
sys.path.insert(1, os.path.join(NM, "dashboard", "app"))
import agent  # noqa: E402
import esk  # noqa: E402  (dashboard/app) Elasticsearch search -> Kibana artifact
import llm_providers as LP  # noqa: E402
import research_cfg as RC  # noqa: E402
import store  # noqa: E402
import site_cfg as SITE  # noqa: E402
import webtools  # noqa: E402

DATA = os.path.join(NM, "data")
PY = os.environ.get("NETMON_PYTHON") or "/usr/bin/python3"
LOGDIR = os.path.join(NM, "logs", "research")
VIA = "netmon research"
BATCH = 8
VERDICTS = ("malicious", "suspicious", "needs-review", "benign", "expected")
PRIOS = ("Investigate", "Review", "Info")
STAMP_RE = re.compile(r"/(\d{4}-\d\d-\d\dT\d{4}Z)\.json$")


def prompt(name):
    return open(os.path.join(NM, "prompts", name + ".md")).read()


# ------------------------------------------------------------------ run state (AI review page)
class EventStatus:
    """Status of a single-event run: leaves the main run's state alone, only adds its token use to the day's cost."""
    def __init__(self, target):
        self.target, self.t0 = target, time.time()

    def phase(self, p):
        pass

    def finish(self, status, error, budget, summary, daily):
        d, u = RC.status() or {}, budget.summary()
        d["usage"] = ((d.get("usage") or []) + [{"at": time.time(), "prompt": u["prompt"], "completion": u["completion"], "total": u["total"],
                                                  "duration_s": round(time.time() - self.t0), "model": self.target["model"], "provider": self.target["provider"],
                                                  "error": status != "completed", "daily_run": False, "fresh": u["prompt"] - u["cache_read"] - u["cache_write"],
                                                  "cache_read": u["cache_read"], "cache_write": u["cache_write"], "cost_usd": u["cost_usd"], "calls": u["calls"],
                                                  "event_run": True}])[-600:]
        d["researched"] = ((d.get("researched") or []) + (getattr(self, "researched", None) or []))[-500:]
        RC.write_status(d)


class Status:
    def __init__(self, target, trigger, daily):
        self.d = RC.status() or {}
        self.d.setdefault("runs", [])
        self.d.setdefault("usage", [])
        self.run = {"status": "running", "trigger": trigger, "started": time.time(), "finished": None, "progress": time.time(),
                    "duration_s": None, "error": None, "daily_run": daily, "ai": trigger != "schedule", "phase": "starting", "model": target["model"], "provider": target["provider"]}
        self.d["runs"] = [self.run] + [r for r in self.d["runs"] if r.get("status") != "running"][:29]
        self.d["running"] = {"started": self.run["started"], "progress": self.run["progress"], "phase": "starting"}
        self.save()

    def phase(self, p):
        self.run.update(phase=p, progress=time.time())
        self.d["running"] = {"started": self.run["started"], "progress": time.time(), "phase": p}
        self.save()

    def finish(self, status, error, budget, summary, daily):
        now = time.time()
        self.run.update(status=status, finished=now, duration_s=round(now - self.run["started"]), error=(error or "")[:300] or None, phase=None)
        self.d["running"] = None
        u = budget.summary()
        self.d["usage"] = (self.d["usage"] + [{"at": now, "prompt": u["prompt"], "completion": u["completion"], "total": u["total"],
                                                "duration_s": self.run["duration_s"], "model": self.run["model"], "provider": self.run["provider"],
                                                "error": status != "completed", "daily_run": daily, "fresh": u["prompt"] - u["cache_read"] - u["cache_write"],
                                                "cache_read": u["cache_read"], "cache_write": u["cache_write"], "cost_usd": u["cost_usd"],
                                                "calls": u["calls"]}])[-600:]
        self.d["researched"] = ((self.d.get("researched") or []) + (getattr(self, "researched", None) or []))[-500:]
        self.d["summary"] = {"at": now, "text": summary, "model": self.run["model"]}
        self.d["last_status"] = "ok" if status == "completed" else status
        self.d["last_error"] = self.run["error"]
        self.d["failure_streak"] = 0 if status == "completed" else int(self.d.get("failure_streak") or 0) + 1
        self.d["last_run"] = self.run["started"]
        self.save()

    def save(self):
        self.d["exported"] = time.time()
        RC.write_status(self.d)


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


# ------------------------------------------------------------------ the run
class Run:
    def __init__(self, target, daily, args):
        self.target, self.daily, self.args = target, daily, args
        cfg = RC.get()
        self.budget = agent.Budget(target["provider"], target["model"], cfg["max_run_tokens"] or None, cfg["max_run_usd"] or None)
        self.max_searches = cfg.get("max_searches", 3)
        self.web = bool(cfg.get("web_research", True))
        self.es = bool(cfg.get("es_search", True))  # AI Research job may search Elasticsearch (AI review > Models)
        self.max_batches = args.max_batches if args.max_batches is not None else cfg["max_batches"]
        self.fetched, self.notes_out, self.errors, self.counts = set(), [], [], {}
        self.es_found = []  # Elasticsearch searches of the current research batch (esk descriptors)
        self.researched = []  # one record per researched event (tokens + cost; a batch's use is split evenly over its events)
        self.snap = self.stem = None
        self.raw, self.ana = {}, {}
        os.makedirs(LOGDIR, mode=0o700, exist_ok=True)
        os.chmod(LOGDIR, 0o700)

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
        """Keep every research-side Elasticsearch search in corr_llm.db (shown on AI review > Research AI searches)."""
        try:
            import sqlite3
            h = r.get("hits") or {}
            tot = (h.get("total") or {}).get("value") if isinstance(h.get("total"), dict) else h.get("total")
            c = sqlite3.connect(os.path.join(RC.STATE, "corr_llm.db"), timeout=10)
            try:
                c.execute("ALTER TABLE es_queries ADD COLUMN source TEXT DEFAULT 'reviewer'")
            except sqlite3.OperationalError:
                pass
            with c:
                c.execute("INSERT INTO es_queries (ts, anchor, candidates, model, query, total, seconds, error, source) VALUES (?,?,?,?,?,?,?,?,?)",
                          (time.time(), "Research run " + os.path.basename(self.stem or ""), "[]", self.target.get("model"),
                           json.dumps({"index": idx, "body": body}, default=str)[:4000], tot, round(secs, 2), err, "research"))
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

    def t_notes_factory(self, batch):
        self.es_found = []  # a new batch starts here
        ids = set()
        for it in batch:
            ids.add(it["id"])
            ids.update(it.get("other_ids") or [])
            ids.update(r.get("id") for r in it.get("related") or [] if isinstance(r, dict) and r.get("id"))

        def submit(a):
            notes = []
            for i, n in enumerate(a.get("notes") or []):
                if not isinstance(n, dict) or n.get("id") not in ids:
                    raise ValueError(f"notes[{i}]: id must be one of this batch's ids")
                if n.get("verdict") not in VERDICTS or n.get("priority") not in PRIOS:
                    raise ValueError(f"notes[{i}]: verdict {VERDICTS} and priority {PRIOS} are required")
                notes.append({"id": n["id"], "verdict": n["verdict"], "priority": n["priority"], "summary": str(n.get("summary") or "")[:600],
                              "research": str(n.get("research") or "")[:4000], "links": self._links(n.get("links"), f"notes[{i}]"),
                              "queries": self.queries_for(n["id"])})
            links = [{**l, "queries": self.queries_for(l["a"], l["b"])} for l in a.get("links") or [] if isinstance(l, dict) and l.get("a") and l.get("b")]
            doc = {"model": self.target["model"], "via": VIA, "snapshot": os.path.basename(self.stem), "notes": notes, "links": links,
                   "host_notes": [h for h in a.get("host_notes") or [] if isinstance(h, dict)],
                   "host_notes_delete": [x for x in a.get("host_notes_delete") or [] if isinstance(x, (int, str))]}
            rc, out, err = sh([os.path.join(NM, "enrich.sh"), "put", "-"], timeout=300, inp=json.dumps(doc))
            if rc:
                raise RuntimeError((err or out)[-400:])
            res = {"output": out[-600:]}
            for line in reversed(out.splitlines()):
                if line.startswith("{"):
                    try:
                        res = json.loads(line)
                        break
                    except ValueError:
                        pass
            for k in ("notes", "links", "host_notes_added", "host_notes_updated"):
                if isinstance(res.get(k), int):
                    self.counts[k] = self.counts.get(k, 0) + res[k]
            if res.get("rejected_ids"):
                return f"error: stored the rest, but these ids were rejected - fix and resubmit only those: {res['rejected_ids']}"
            return res
        return submit

    NOWEB = "\n\nWeb research is switched off for this run: you have no web_search, web_fetch or cite tools. Work from the local data only, do not cite sources or add links, and say so in a note when a verdict would need outside information."

    def tools(self, kind, batch=None):
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
        if kind == "enrich":
            T["submit_notes"] = (self.t_notes_factory(batch), "Store research notes, link verdicts and host notes for this batch.",
                                 {"notes": {"type": "array", "items": {"type": "object"}}, "links": {"type": "array", "items": {"type": "object"}},
                                  "host_notes": {"type": "array", "items": {"type": "object"}},
                                  "host_notes_delete": {"type": "array", "items": {"type": "integer"}}}, ["notes"])
        if kind == "enrich" and batch and self.web and self.max_searches and "web_search" in T:
            left, fn, cap = [self.max_searches * len(batch)], T["web_search"][0], self.max_searches * len(batch)
            def capped(a, _fn=fn, _left=left, _cap=cap):
                if _left[0] <= 0:
                    raise ValueError(f"web search limit reached ({self.max_searches} per event, {_cap} for this batch): use web_fetch on pages you already found, or finish with what you have")
                _left[0] -= 1
                return _fn(a)
            T["web_search"] = (capped,) + tuple(T["web_search"][1:])
        if not self.web:  # admin turned web research off (AI review > Research job limits)
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
            fn = os.path.join(LOGDIR, f"{time.strftime('%Y%m%dT%H%M%S', time.gmtime())}-{name}.json")
            fd = os.open(fn, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)  # transcripts hold log data: owner-only
            with os.fdopen(fd, "w") as f:
                f.write(agent.redact(json.dumps(log, indent=1, default=str, ensure_ascii=False)))
            for old in sorted(glob.glob(os.path.join(LOGDIR, "*.json")))[:-60]:
                os.remove(old)

    # ---- phases
    def collect(self):
        if not self.args.skip_collect:
            rc, out, err = sh([PY, os.path.join(NM, "collect.py"), "24" if self.daily else "auto"], timeout=3600)
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

    def enrich(self):
        out = self.stem + ".work.json"
        one = getattr(self.args, "event", None)  # only a person's "Send to research" click researches events; scheduled runs never do
        for attempt in range(3):  # the dashboard container may be restarting (deploy): retry instead of losing the run
            rc, o, err = sh([os.path.join(NM, "enrich.sh"), "events", out] + (["--only", one] if one else []), timeout=600)
            if not rc:
                break
            time.sleep(20)
        if rc:
            raise RuntimeError(f"enrich.sh events failed: {(err or o)[-300:]}")
        d = jload(out, {})
        os.remove(out)
        items = d.get("events") or []
        # review-mode items: the reviewer compares them with earlier research and either copies a prior note or sends them to research
        review = [x for x in items if x.get("mode") == "review"]
        self.counts["review_only"], self.counts["review_covered"] = d.get("review_only", 0), d.get("review_covered", 0)
        items = [x for x in items if x.get("mode") not in ("review", "test")]  # test-mode items are only listed on the dashboard
        if review and getattr(self.args, "trigger", "") == "schedule":  # scheduled run: no AI call at all; everything waits in the queue
            self.counts["review_to_research"] = len([x for x in review if not x.get("note")])
            review = []
        if review:
            self.status.phase("reviewer")
            items += self.review_items([x for x in review if not x.get("note")])
        if not one:  # scheduled run: the reviewer's copies are stored; whatever it sent back waits in the queue for a click on Send to research
            self.counts["work_items"], self.counts["without_note"] = len(items), sum(1 for x in items if not x.get("note"))
            return
        todo = [x for x in items if not x.get("note")] + [x for x in items if x.get("note") and str(x.get("id", "")).split("|")[0] in ("ids", "gw", "hf")]
        self.counts["work_items"], self.counts["without_note"] = len(items), sum(1 for x in items if not x.get("note"))
        sysmsg = prompt("analyst") + "\n\n" + prompt("enrich")
        for b in range(0, min(len(todo), self.max_batches * BATCH), BATCH):
            batch = todo[b:b + BATCH]
            self.status.phase(f"event research {b // BATCH + 1}/{min(-(-len(todo) // BATCH), self.max_batches)}")
            user = (f"Snapshot {os.path.basename(self.stem)}. Batch of {len(batch)} work items"
                    f"{' (these already have notes: only rewrite a note if this run contradicts it)' if all(x.get('note') for x in batch) else ''}:\n"
                    f"<work_items>\n{json.dumps(batch, ensure_ascii=False)[:60000]}\n</work_items>{self.NOWEB if not self.web else ''}")
            before = self.budget.summary()
            try:
                self.converse(f"enrich{b // BATCH + 1}", sysmsg, user, self.tools("enrich", batch), ("submit_notes",), max_turns=40, max_tokens=8000)
                self.counts["batches"] = self.counts.get("batches", 0) + 1
            except agent.BudgetExceeded:
                raise
            except Exception as e:  # noqa: BLE001 - one bad batch must not stop the others
                self.errors.append(f"event research batch {b // BATCH + 1}: {str(e)[:200]}")
            finally:
                self.record_batch(batch, before)

    def record_batch(self, batch, before):
        """Tokens and cost of one research batch, split evenly over its events (exact when one event is researched)."""
        after, n = self.budget.summary(), max(1, len(batch))
        d = {k: after[k] - before[k] for k in ("prompt", "completion", "cache_read", "cache_write")}
        usd = None if after["cost_usd"] is None else round(after["cost_usd"] - (before["cost_usd"] or 0), 4)
        now = time.time()
        for it in batch:
            self.researched.append({"at": now, "id": it.get("id"), "label": str(it.get("label") or it.get("id") or "")[:200], "type": it.get("type"),
                                    "model": self.target["model"], "provider": self.target["provider"], "batch": n,
                                    "prompt": round(d["prompt"] / n), "completion": round(d["completion"] / n),
                                    "cache_read": round(d["cache_read"] / n), "cache_write": round(d["cache_write"] / n),
                                    "total": round((d["prompt"] + d["completion"]) / n), "cost_usd": None if usd is None else round(usd / n, 4)})

    def review_items(self, review):
        """Reviewer: for each review-mode item without a note, copy the most similar prior note (marked as copied) or send it back
        to research. Returns the items that go to research. Any failure sends everything back (nothing is silently dropped)."""
        if not review:
            return []
        decided, copies = {}, []
        for b in range(0, len(review), BATCH * 2):
            batch = review[b:b + BATCH * 2]
            ids = {x["id"]: x for x in batch}

            def submit(a, ids=ids):
                n = 0
                for i, dcs in enumerate(a.get("decisions") or []):
                    if not isinstance(dcs, dict) or dcs.get("id") not in ids or dcs.get("action") not in ("copy", "research"):
                        raise ValueError(f"decisions[{i}]: id must be one of the batch ids, action copy|research")
                    if dcs["action"] == "copy":
                        if dcs.get("from") not in {p["id"] for p in ids[dcs["id"]].get("prior") or []}:
                            raise ValueError(f"decisions[{i}]: 'from' must be the id of one of that item's prior notes")
                        decided[dcs["id"]] = dict(id=dcs["id"], **{"from": dcs["from"]}, reason=str(dcs.get("reason") or "")[:400])
                    else:
                        decided[dcs["id"]] = None
                    n += 1
                missing = [i for i in ids if i not in decided]
                return {"ok": True, "decided": n} if not missing else f"error: stored, but no decision yet for: {missing}"
            cand = [x for x in batch if x.get("prior")]
            for x in batch:
                if not x.get("prior"):
                    decided[x["id"]] = None  # nothing earlier to compare with
            if not cand:
                continue
            ids = {x["id"]: x for x in cand}
            user = (f"Snapshot {os.path.basename(self.stem)}. {len(cand)} items to review against earlier research:\n"
                    f"<work_items>\n{json.dumps(cand, ensure_ascii=False)[:60000]}\n</work_items>")
            T = self.tools("enrich", cand)
            T = {k: T[k] for k in ("es_search", "device_lookup", "notes_kb") if k in T}
            T["submit_review"] = (submit, "Store the copy / research decision for every item (call once).",
                                  {"decisions": {"type": "array", "items": {"type": "object"}}}, ["decisions"])
            try:
                self.converse(f"review{b // (BATCH * 2) + 1}", prompt("analyst") + "\n\n" + prompt("reviewer"), user, T, ("submit_review",),
                              max_turns=20, max_tokens=6000)
            except agent.BudgetExceeded:
                raise
            except Exception as e:  # noqa: BLE001
                self.errors.append(f"reviewer batch {b // (BATCH * 2) + 1}: {str(e)[:200]}")
        copies = [v for v in decided.values() if v]
        if copies:
            rc, out, err = sh([os.path.join(NM, "enrich.sh"), "copy", "-"], timeout=300,
                              inp=json.dumps({"model": self.target["model"], "snapshot": os.path.basename(self.stem), "copies": copies}))
            if rc:
                self.errors.append(f"reviewer copy failed: {(err or out)[-200:]}")
                copies = []
            else:
                self.counts["review_copied"] = len(copies)
        done = {c["id"] for c in copies}
        back = [x for x in review if x["id"] not in done]
        self.counts["review_to_research"] = len(back)
        return back

    def go(self, status):
        self.status, self.started = status, time.time()
        fatal = None
        steps = [("collect + analyze", self.collect, True), ("queue" if getattr(self.args, "trigger", "") == "schedule" else "reviewer", self.enrich, False)]
        if getattr(self.args, "event", None):  # one event on request: no new snapshot
            steps = [("collect + analyze", self.collect, True), ("event research", self.enrich, False)]
        for name, fn, must in steps:
            if fatal:
                continue
            status.phase(name)
            try:
                fn()
            except agent.BudgetExceeded as e:
                self.errors.append(f"{name}: stopped - {e}")
                fatal = fatal or str(e)
            except Exception as e:  # noqa: BLE001
                traceback.print_exc()
                self.errors.append(f"{name}: {str(e)[:300]}")
                if must:
                    fatal = str(e)
                    break
        return fatal

    def summary(self):
        c, u = self.counts, self.budget.summary()
        ai = getattr(self.args, "event", None) or getattr(self.args, "trigger", "") != "schedule"
        parts = [f"{'Daily run (24 h)' if self.daily else 'Review run'} on {os.path.basename(self.stem or '?')}"
                 + (f" with {self.target['model']}." if ai else " (scheduled: no AI calls).")]
        parts.append(f"Research notes stored: {c.get('notes', 0)}, "
                     f"link verdicts: {c.get('links', 0)}, host notes added/updated: {c.get('host_notes_added', 0)}/{c.get('host_notes_updated', 0)}, "
                     f"work items without a note at start: {c.get('without_note', 0)}. Reviewer: {c.get('review_copied', 0)} earlier notes copied, {c.get('review_to_research', 0)} left queued for Send to research.")
        parts.append(f"Tokens: {u['total']:,} in {u['calls']} calls" + (f", est. ${u['cost_usd']:.2f}" if u["cost_usd"] is not None else "") + ".")
        if self.errors:
            parts.append("Problems: " + "; ".join(self.errors)[:800])
        return " ".join(parts)


def daily_due():
    """First run at or after 05:00 UTC each day is the daily run (24 h window, feeds the device baseline)."""
    now = dt.datetime.now(dt.timezone.utc)
    if now.hour < RC.DAILY_HOUR:
        return False
    today = now.strftime("%Y-%m-%d")
    for r in (RC.status().get("runs") or []):
        if (r.get("daily_run") or r.get("pdf_run")) and r.get("status") == "completed" and time.strftime("%Y-%m-%d", time.gmtime(r.get("started") or 0)) == today:
            return False
    return True


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--daily", action="store_true", help="force the 24 h daily window")
    ap.add_argument("--no-daily", action="store_true")
    ap.add_argument("--trigger", default="manual")
    ap.add_argument("--skip-collect", action="store_true", help="use the newest existing snapshot")
    ap.add_argument("--max-batches", type=int)
    ap.add_argument("--event", help="research just this event id now (started from the dashboard's Send to research button)")
    args = ap.parse_args()
    cfg = RC.get()
    target = {"provider": cfg["provider"], "model": cfg["model"]}
    if (args.event or args.trigger != "schedule") and not LP.allowed(target["provider"], target["model"]):
        print(f"research model not configured or unavailable ({target}); set it on the dashboard's AI review page", file=sys.stderr)
        return 2
    lock = open(os.path.join(RC.STATE, ".research-event.lock" if args.event else ".research.lock"), "w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        print("another research run is in progress", file=sys.stderr)
        return 3
    if cfg["max_day_usd"] and RC.spent_today() >= cfg["max_day_usd"]:
        print(f"daily cost cap reached (${RC.spent_today():.2f} of ${cfg['max_day_usd']:.2f}); not starting", file=sys.stderr)
        return 4
    daily = False if args.event else (args.daily or (not args.no_daily and daily_due()))
    if args.event:
        args.skip_collect = True
    run = Run(target, daily, args)
    st = EventStatus(target) if args.event else Status(target, args.trigger, daily)
    fatal = None
    try:
        fatal = run.go(st)
    except BaseException as e:  # noqa: BLE001 - record the failure even on Ctrl-C / kill
        fatal = f"{type(e).__name__}: {e}"
        run.errors.append(fatal)
        raise
    finally:
        s = run.summary()
        st.researched = run.researched
        failed = fatal
        st.finish("failed" if failed else "completed", fatal or ("; ".join(run.errors)[:300] if run.errors else None), run.budget, s, daily)
        print(s)
    return 1 if fatal else 0


if __name__ == "__main__":
    sys.exit(main())
