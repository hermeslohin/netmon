#!/usr/bin/env python3
"""netmon research job: collect -> analyze -> AI triage -> AI event research -> (daily) briefing + PDF report.

Started by scheduler.py on the grid set on the dashboard (research_cfg.py), or by hand:
    review.py [--pdf | --no-pdf] [--trigger manual|schedule] [--skip-collect] [--max-batches N]
The PDF run is the first run at or after 05:00 UTC each day (or --pdf); it always covers 24 h of logs, writes the news
briefing and renders the report. Other runs cover the lookback window set on the AI review page.

The AI works through narrow, read-only tools (Elasticsearch search, netmon data, web search / fetch) and writes only
through validated submit_* tools: data/<stamp>.triage.json, data/<stamp>.briefing.json, research notes via enrich.sh
(dashboard container), known_benign.json additions. Sources it cites are kept in data/<stamp>.sources.json.
Run state, token use and cost go to <state>/research_job.json (AI review page). Conversations are saved under
logs/research/ for review (git-ignored; the newest 60 are kept).
"""
import argparse, datetime as dt, fcntl, glob, json, os, re, subprocess, sys, time, traceback

NM = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, NM)
sys.path.insert(1, os.path.join(NM, "dashboard", "app"))
import agent  # noqa: E402
import llm_providers as LP  # noqa: E402
import research_cfg as RC  # noqa: E402
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
class Status:
    def __init__(self, target, trigger, pdf):
        self.d = RC.status() or {}
        self.d.setdefault("runs", [])
        self.d.setdefault("usage", [])
        self.run = {"status": "running", "trigger": trigger, "started": time.time(), "finished": None, "progress": time.time(),
                    "duration_s": None, "error": None, "pdf_run": pdf, "phase": "starting", "model": target["model"], "provider": target["provider"]}
        self.d["runs"] = [self.run] + [r for r in self.d["runs"] if r.get("status") != "running"][:29]
        self.d["running"] = {"started": self.run["started"], "progress": self.run["progress"], "phase": "starting"}
        self.save()

    def phase(self, p):
        self.run.update(phase=p, progress=time.time())
        self.d["running"] = {"started": self.run["started"], "progress": time.time(), "phase": p}
        self.save()

    def finish(self, status, error, budget, summary, pdf):
        now = time.time()
        self.run.update(status=status, finished=now, duration_s=round(now - self.run["started"]), error=(error or "")[:300] or None, phase=None)
        self.d["running"] = None
        u = budget.summary()
        self.d["usage"] = (self.d["usage"] + [{"at": now, "prompt": u["prompt"], "completion": u["completion"], "total": u["total"],
                                                "duration_s": self.run["duration_s"], "model": self.run["model"], "provider": self.run["provider"],
                                                "error": status != "completed", "pdf_run": pdf, "fresh": u["prompt"] - u["cache_read"] - u["cache_write"],
                                                "cache_read": u["cache_read"], "cache_write": u["cache_write"], "cost_usd": u["cost_usd"],
                                                "calls": u["calls"]}])[-60:]
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
    snaps = sorted(p for p in glob.glob(os.path.join(DATA, "*.json")) if STAMP_RE.search(p))
    return snaps[-1] if snaps else None


def jload(p, default=None):
    try:
        return json.load(open(p))
    except (OSError, ValueError):
        return default


def triage_files(stem):
    """(previous triage, triage ~24 h earlier) for comparison."""
    me = os.path.basename(stem)
    files = sorted(f for f in glob.glob(os.path.join(DATA, "*.triage.json")) if os.path.basename(f) < me + ".triage.json")
    prev = files[-1] if files else None
    t0 = dt.datetime.strptime(me, "%Y-%m-%dT%H%MZ") - dt.timedelta(hours=24)
    day = None
    for f in files:
        try:
            if dt.datetime.strptime(os.path.basename(f)[:16], "%Y-%m-%dT%H%MZ") <= t0:
                day = f
        except ValueError:
            pass
    return prev, day


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
    def __init__(self, target, pdf, args):
        self.target, self.pdf, self.args = target, pdf, args
        cfg = RC.get()
        self.budget = agent.Budget(target["provider"], target["model"], cfg["max_run_tokens"] or None, cfg["max_run_usd"] or None)
        self.max_batches = args.max_batches if args.max_batches is not None else cfg["max_batches"]
        self.fetched, self.notes_out, self.errors, self.counts = set(), [], [], {}
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
        for f in sorted(glob.glob(os.path.join(DATA, "*.sources.json")))[-30:]:
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
        body["size"] = max(0, min(int(body.get("size", 10)), 50))
        body.setdefault("timeout", "60s")
        r = esq.q(idx, body)
        hits = r.get("hits") or {}
        out = {"total": (hits.get("total") or {}).get("value") if isinstance(hits.get("total"), dict) else hits.get("total"),
               "hits": [json.dumps(h.get("_source"), ensure_ascii=False)[:1500] for h in hits.get("hits") or []]}
        if r.get("aggregations"):
            out["aggregations"] = r["aggregations"]
        return out

    def files(self):
        prev, day = triage_files(self.stem)
        return {"snapshot": self.raw, "analysis": self.ana, "previous_triage": jload(prev, {}) if prev else {},
                "day_ago_triage": jload(day, {}) if day else {}, "known_benign": jload(os.path.join(NM, "known_benign.json"), {}),
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
        json.dump(led, open(self.ledger_path(), "w"), indent=2)
        return {"id": sid}

    def t_benign(self, a):
        sec, key, why = str(a.get("section") or ""), str(a.get("value") or "").strip()[:200], str(a.get("reason") or "").strip()[:300]
        p = os.path.join(NM, "known_benign.json")
        kb = jload(p, {})
        if sec not in ("signatures", "names", "dns_domains", "beacon_domains") or not key or not why:
            raise ValueError("section: signatures | names | dns_domains | beacon_domains; value and reason are required")
        if sec in ("signatures", "names"):
            kb.setdefault(sec, {})[key] = why
        elif key not in kb.setdefault(sec, []):
            kb[sec].append(key)
        tmp = p + ".tmp"
        json.dump(kb, open(tmp, "w"), indent=1, ensure_ascii=False)
        os.replace(tmp, p)
        self.counts["known_benign_added"] = self.counts.get("known_benign_added", 0) + 1
        return {"ok": True}

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

    def t_triage(self, a):
        alarms = []
        for i, x in enumerate(a.get("alarms") or []):
            if not isinstance(x, dict) or x.get("priority") not in PRIOS or not x.get("title"):
                raise ValueError(f"alarms[{i}]: needs priority (Investigate|Review|Info) and title")
            al = {k: str(x.get(k) or "")[:3000] for k in ("priority", "title", "who", "evidence", "why", "next", "context") if x.get(k)}
            if x.get("links"):
                al["links"] = self._links(x["links"], f"alarms[{i}]")
            alarms.append(al)
        rn = a.get("research_notes") or []
        if isinstance(rn, str):
            rn = [rn]
        dn = a.get("device_notes") or {}
        if not isinstance(dn, dict):
            raise ValueError("device_notes must be an object {ip: note}")
        doc = {"generated_by": {"model": self.target["model"], "via": VIA, "provider": LP.name(self.target["provider"])},
               "summary": str(a.get("summary") or "")[:6000], "alarms": alarms,
               "research_notes": [str(x)[:3000] for x in rn if x], "device_notes": {str(k): str(v)[:2000] for k, v in dn.items()}}
        if not doc["summary"]:
            raise ValueError("summary is required")
        json.dump(doc, open(self.stem + ".triage.json", "w"), indent=1, ensure_ascii=False)
        self.counts["alarms"] = len(alarms)
        self.counts["investigate"] = sum(1 for x in alarms if x["priority"] == "Investigate")
        self.triage_summary = doc["summary"]
        return {"ok": True, "stored": len(alarms)}

    def t_briefing(self, a):
        items = []
        for i, x in enumerate(a.get("items") or []):
            if not isinstance(x, dict) or not x.get("title") or not x.get("url"):
                raise ValueError(f"items[{i}]: needs category, title, summary and url")
            if x["url"] not in self.known_urls():
                raise ValueError(f"items[{i}]: fetch {x['url'][:100]} with web_fetch before using it")
            items.append({k: str(x.get(k) or "")[:1500] for k in ("category", "title", "summary", "url")})
        json.dump({"generated_by": {"model": self.target["model"], "via": VIA}, "items": items},
                  open(self.stem + ".briefing.json", "w"), indent=1, ensure_ascii=False)
        self.counts["briefing_items"] = len(items)
        return {"ok": True, "stored": len(items)}

    def t_notes_factory(self, batch):
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
                              "research": str(n.get("research") or "")[:4000], "links": self._links(n.get("links"), f"notes[{i}]")})
            links = [l for l in a.get("links") or [] if isinstance(l, dict) and l.get("a") and l.get("b")]
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

    def tools(self, kind, batch=None):
        T = {
            "es_search": (self.t_es, "Read-only Elasticsearch search (query DSL). Keep size small (<= 50) and use aggregations for counts.",
                          {"index": {"type": "string", "description": "index or pattern, e.g. logs-zeek-so"},
                           "body": {"type": "object", "description": "search body: query, aggs, size, sort, _source"}}, ["index", "body"]),
            "read_data": (self.t_read, "Read netmon data by path. Files: snapshot (full collected data), analysis (findings vs baseline), "
                          "previous_triage, day_ago_triage, known_benign, policy. path uses '/' between keys, e.g. devices/192.168.1.20 or "
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
        if kind == "triage":
            T["add_known_benign"] = (self.t_benign, "Record a conclusively benign item so later runs do not raise it again.",
                                     {"section": {"type": "string", "enum": ["signatures", "names", "dns_domains", "beacon_domains"]},
                                      "value": {"type": "string"}, "reason": {"type": "string"}}, ["section", "value", "reason"])
            T["submit_triage"] = (self.t_triage, "Store the triage (call once at the end).",
                                  {"summary": {"type": "string"}, "alarms": {"type": "array", "items": {"type": "object"}},
                                   "research_notes": {"type": "array", "items": {"type": "string"}},
                                   "device_notes": {"type": "object"}}, ["summary", "alarms"])
        elif kind == "enrich":
            T["submit_notes"] = (self.t_notes_factory(batch), "Store research notes, link verdicts and host notes for this batch.",
                                 {"notes": {"type": "array", "items": {"type": "object"}}, "links": {"type": "array", "items": {"type": "object"}},
                                  "host_notes": {"type": "array", "items": {"type": "object"}},
                                  "host_notes_delete": {"type": "array", "items": {"type": "integer"}}}, ["notes"])
        elif kind == "briefing":
            T = {k: T[k] for k in ("web_search", "web_fetch")}
            T["submit_briefing"] = (self.t_briefing, "Store the briefing items (call once at the end).",
                                    {"items": {"type": "array", "items": {"type": "object"}}}, ["items"])
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
            rc, out, err = sh([PY, os.path.join(NM, "collect.py"), "24" if self.pdf else "auto"], timeout=3600)
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
        if not os.path.exists(self.ledger_path()):
            json.dump({"version": 1, "sources": []}, open(self.ledger_path(), "w"))

    def triage(self):
        rc, kb, _ = sh([os.path.join(NM, "enrich.sh"), "kb"], timeout=120)
        prev, day = triage_files(self.stem)
        ana = json.dumps(self.ana, ensure_ascii=False)
        user = (f"Snapshot {os.path.basename(self.stem)} covering {self.raw.get('hours')} h of logs "
                f"({'daily PDF run' if self.pdf else 'enrichment run'}); generated {self.raw.get('generated')}.\n"
                f"Collector errors: {json.dumps(self.raw.get('extras_errors') or {})}\n"
                f"Previous triage: {os.path.basename(prev) if prev else 'none'}; about 24 h ago: {os.path.basename(day) if day else 'none'}.\n\n"
                f"<notes_kb>\n{(kb if rc == 0 else '{}')[:30000]}\n</notes_kb>\n\n"
                f"<analysis>\n{ana[:60000]}{' …[truncated - read_data analysis for the rest]' if len(ana) > 60000 else ''}\n</analysis>\n\n"
                f"Snapshot top-level keys: {list(self.raw.keys())}")
        r = self.converse("triage", prompt("analyst") + "\n\n" + prompt("triage"), user, self.tools("triage"), ("submit_triage",),
                          max_turns=60, max_tokens=8000)
        if not os.path.exists(self.stem + ".triage.json") or os.path.getmtime(self.stem + ".triage.json") < self.started:
            raise RuntimeError(f"the model ended without submitting a triage ({r.get('stopped') or 'no submit_triage call'})")

    def enrich(self):
        out = self.stem + ".work.json"
        rc, o, err = sh([os.path.join(NM, "enrich.sh"), "events", out], timeout=600)
        if rc:
            raise RuntimeError(f"enrich.sh events failed: {(err or o)[-300:]}")
        d = jload(out, {})
        os.remove(out)
        items = d.get("events") or []
        todo = [x for x in items if not x.get("note")] + [x for x in items if x.get("note") and str(x.get("id", "")).split("|")[0] in ("ids", "gw", "hf")]
        self.counts["work_items"], self.counts["without_note"] = len(items), sum(1 for x in items if not x.get("note"))
        sysmsg = prompt("analyst") + "\n\n" + prompt("enrich")
        for b in range(0, min(len(todo), self.max_batches * BATCH), BATCH):
            batch = todo[b:b + BATCH]
            self.status.phase(f"event research {b // BATCH + 1}/{min(-(-len(todo) // BATCH), self.max_batches)}")
            user = (f"Snapshot {os.path.basename(self.stem)}. Batch of {len(batch)} work items"
                    f"{' (these already have notes: only rewrite a note if this run contradicts it)' if all(x.get('note') for x in batch) else ''}:\n"
                    f"<work_items>\n{json.dumps(batch, ensure_ascii=False)[:60000]}\n</work_items>")
            try:
                self.converse(f"enrich{b // BATCH + 1}", sysmsg, user, self.tools("enrich", batch), ("submit_notes",), max_turns=40, max_tokens=8000)
                self.counts["batches"] = self.counts.get("batches", 0) + 1
            except agent.BudgetExceeded:
                raise
            except Exception as e:  # noqa: BLE001 - one bad batch must not stop the others
                self.errors.append(f"event research batch {b // BATCH + 1}: {str(e)[:200]}")

    def briefing(self):
        topics = SITE.get("briefing_topics") or [{"category": "Security", "count": 3, "about": "high-impact computer security news"}]
        want = "\n".join(f"- {t.get('category')}: {t.get('count', 1)} stor{'y' if t.get('count', 1) == 1 else 'ies'} about {t.get('about') or t.get('category')}"
                         for t in topics)
        self.converse("briefing", prompt("briefing"), f"Today is {time.strftime('%Y-%m-%d', time.gmtime())}. Categories:\n{want}",
                      self.tools("briefing"), ("submit_briefing",), max_turns=40, max_tokens=6000)

    def report(self):
        rc, out, err = sh([PY, os.path.join(NM, "report.py")], timeout=1800)
        m = re.findall(r"(/\S+\.pdf)", out + err)
        if rc or not m or not os.path.exists(m[-1]) or os.path.getsize(m[-1]) == 0:
            raise RuntimeError(f"report.py failed: {(err or out)[-300:]}")
        self.counts["pdf"] = m[-1]

    def go(self, status):
        self.status, self.started = status, time.time()
        fatal = None
        steps = [("collect + analyze", self.collect, True), ("triage", self.triage, False), ("event research", self.enrich, False)]
        if self.pdf:
            steps += [("briefing", self.briefing, False), ("report", self.report, False)]
        for name, fn, must in steps:
            if fatal and name != "report":
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
        parts = [f"{'PDF run' if self.pdf else 'Enrichment run'} on {os.path.basename(self.stem or '?')} with {self.target['model']}."]
        if getattr(self, "triage_summary", None):
            parts.append(self.triage_summary[:900])
        parts.append(f"Alarms: {c.get('alarms', 0)} ({c.get('investigate', 0)} Investigate). Research notes stored: {c.get('notes', 0)}, "
                     f"link verdicts: {c.get('links', 0)}, host notes added/updated: {c.get('host_notes_added', 0)}/{c.get('host_notes_updated', 0)}, "
                     f"work items without a note at start: {c.get('without_note', 0)}.")
        if c.get("pdf"):
            parts.append(f"Report: {c['pdf']}.")
        parts.append(f"Tokens: {u['total']:,} in {u['calls']} calls" + (f", est. ${u['cost_usd']:.2f}" if u["cost_usd"] is not None else "") + ".")
        if self.errors:
            parts.append("Problems: " + "; ".join(self.errors)[:800])
        return " ".join(parts)


def pdf_due():
    """First run at or after 05:00 UTC each day renders the PDF (the report file name carries the snapshot stamp)."""
    now = dt.datetime.now(dt.timezone.utc)
    if now.hour < RC.PDF_HOUR:
        return False
    today = now.strftime("%Y-%m-%d")
    for r in (RC.status().get("runs") or []):
        if r.get("pdf_run") and r.get("status") == "completed" and time.strftime("%Y-%m-%d", time.gmtime(r.get("started") or 0)) == today:
            return False
    return True


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--pdf", action="store_true")
    ap.add_argument("--no-pdf", action="store_true")
    ap.add_argument("--trigger", default="manual")
    ap.add_argument("--skip-collect", action="store_true", help="use the newest existing snapshot")
    ap.add_argument("--max-batches", type=int)
    args = ap.parse_args()
    cfg = RC.get()
    target = {"provider": cfg["provider"], "model": cfg["model"]}
    if not LP.allowed(target["provider"], target["model"]):
        print(f"research model not configured or unavailable ({target}); set it on the dashboard's AI review page", file=sys.stderr)
        return 2
    lock = open(os.path.join(RC.STATE, ".research.lock"), "w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        print("another research run is in progress", file=sys.stderr)
        return 3
    if cfg["max_day_usd"] and RC.spent_today() >= cfg["max_day_usd"]:
        print(f"daily cost cap reached (${RC.spent_today():.2f} of ${cfg['max_day_usd']:.2f}); not starting", file=sys.stderr)
        return 4
    pdf = args.pdf or (not args.no_pdf and pdf_due())
    run = Run(target, pdf, args)
    st = Status(target, args.trigger, pdf)
    fatal = None
    try:
        fatal = run.go(st)
    except BaseException as e:  # noqa: BLE001 - record the failure even on Ctrl-C / kill
        fatal = f"{type(e).__name__}: {e}"
        run.errors.append(fatal)
        raise
    finally:
        s = run.summary()
        failed = fatal or any(e.startswith("triage:") for e in run.errors)
        st.finish("failed" if failed else "completed", fatal or ("; ".join(run.errors)[:300] if run.errors else None), run.budget, s, pdf)
        print(s)
    return 1 if (fatal or any(e.startswith("triage:") for e in run.errors)) else 0


if __name__ == "__main__":
    sys.exit(main())
