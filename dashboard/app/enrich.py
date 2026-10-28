"""AI notes on dashboard events: the review job's work list and copied notes, and event research results.

The review job (review.py on the host, scheduled) asks here for the work list of the newest snapshot (_events); its
reviewer copies earlier notes onto matching events (copy_notes). Everything else waits in the queue (queue_items) until
a person clicks Send to research (request_research -> host broker -> research.py). Event research writes:
  - a note per event (verdict, summary, research text, links it actually read), shown by related.js
    as a "✨ notes" button next to the event's Related column;
  - correlation verdicts for candidate links (corr_llm.db, same table the correlation reviewer uses). Research
    verdicts replace the reviewer's; manual verdicts (model "manual:<user>") are never overwritten, and
    the reviewer only asks about undecided pairs, so it never overwrites research.

Notes are keyed by a stable event key so they carry over to later snapshots: finding ids embed the detail text
(numbers change every run), so the key masks the numbers in the detail; watcher alerts are stored per alert
family (first 3 parts of the alert key, e.g. host|hnet-interp|<host>), so one note covers repeats of the same alert.

CLI (runs inside the dashboard container; host wrapper: netmon/enrich.sh):
  enrich.py events [--sid ID] [--all] [--max N] [--hosts N] [--ids N] [--gw N]   work list: host findings, Suricata sev 1-2, gateway events, then other events
  enrich.py put -                       read {"model", "notes": [...], "links": [...], "host_notes": [...], "host_notes_delete": [...]}
                                        from stdin and store it (host_notes: see kb.py)
Each work item carries the owner's event notes (`user_notes`, authoritative guidance) and the host notes of the
internal hosts involved (`host_notes`, {ip: [...]}) so the run decides with what earlier runs and the owner know.
"""
import json, os, re, sqlite3, sys, time

import esk

DB = os.path.join(os.environ.get("STATE_DIR", "/state"), "enrich.db")
VERDICTS = ("malicious", "suspicious", "needs-review", "benign", "expected")
PRIORITIES = ("Investigate", "Review", "Info")
_NUM = re.compile(r"\d+(?:[.,:]\d+)*")
_URL = re.compile(r"^https?://[^\s\"'<>]+$", re.I)


def _db():
    c = sqlite3.connect(DB, timeout=10)
    c.execute("""CREATE TABLE IF NOT EXISTS notes (skey TEXT PRIMARY KEY, eid TEXT, label TEXT, verdict TEXT, priority TEXT,
                 summary TEXT, research TEXT, links TEXT, model TEXT, via TEXT, ts REAL, snapshot TEXT)""")
    c.execute("CREATE TABLE IF NOT EXISTS note_queries (skey TEXT, kql TEXT, meta TEXT, ts REAL, PRIMARY KEY (skey, kql))")  # Elasticsearch searches behind a note (esk.py descriptors)
    c.execute("""CREATE TABLE IF NOT EXISTS runs (id INTEGER PRIMARY KEY, snapshot TEXT, started REAL, listed INTEGER, todo INTEGER,
                 note_keys INTEGER, stored REAL, notes INTEGER, links INTEGER, rejected INTEGER, model TEXT)""")
    c.execute("PRAGMA temp_store=MEMORY")
    return c


def _alert_keys():
    try:
        import store
        return {str(a["id"]): a.get("key") or "" for a in store.alerts_recent(2000, suppressed=True)}
    except Exception:  # noqa: BLE001
        return {}


def skey(eid, akeys=None):
    p = str(eid).split("|")
    if p[0] == "f":  # same finding in a later run: numbers in the detail (MB, counts, ratios) are masked
        return _NUM.sub("#", str(eid))
    if p[0] == "gw" and len(p) >= 5:  # gateway events: one note per type + destination (a scanner wave = one note)
        return f"gwfam|{p[2]}|{p[4] or _NUM.sub('#', p[3])}"
    if p[0] == "alert" and akeys is not None and akeys.get(p[1] if len(p) > 1 else ""):
        return "alertfam|" + "|".join(akeys[p[1]].split("|")[:3])
    return str(eid)


def load(eids):
    eids, ak = list(eids), _alert_keys()
    keys = {}
    for e in eids:
        keys.setdefault(skey(e, ak), []).append(e)
    out = {}
    if not keys:
        return out
    with _db() as c:
        ks = list(keys)
        for i in range(0, len(ks), 500):
            ch = ks[i:i + 500]
            for r in c.execute(f"SELECT skey, eid, verdict, priority, summary, research, links, model, via, ts, snapshot FROM notes "
                               f"WHERE skey IN ({','.join('?' * len(ch))})", ch):
                for eid in keys[r[0]]:
                    out[eid] = {"verdict": r[2], "priority": r[3], "summary": r[4], "research": r[5], "links": json.loads(r[6] or "[]"),
                                "model": r[7], "via": r[8], "at": r[9], "snapshot": r[10], "same_event": r[1] == eid}
            qs = {}
            for sk, meta in c.execute(f"SELECT skey, meta FROM note_queries WHERE skey IN ({','.join('?' * len(ch))}) ORDER BY ts", ch):
                try:
                    d = esk.clean(json.loads(meta))
                except ValueError:
                    d = None
                if d:
                    qs.setdefault(sk, []).append(d)
            for sk, eids_ in keys.items():
                for eid in eids_:
                    if eid in out and qs.get(sk):
                        out[eid]["queries"] = qs[sk]
    return out


def for_acks(acks):
    """Research notes for checked-off items, whether or not their event is still in a snapshot: {"type|key": note}.
    host / alarm / issue / gateway items map to the note's key directly; baseline findings by their label (kind: detail)."""
    out, want, fl = {}, {}, {}
    for typ, m in (acks or {}).items():
        for key, a in (m or {}).items():
            sk = {"host": "hf|" + key, "alarm": "alarm|" + key, "issue": "iss|" + key, "gw": key}.get(typ)
            if sk:
                want.setdefault(sk, []).append(f"{typ}|{key}")
            elif typ == "finding" and (a or {}).get("label"):
                fl[f"{typ}|{key}"] = _NUM.sub("#", str(a["label"]))
    with _db() as c:
        cols = "skey, eid, verdict, priority, summary, research, links, model, via, ts, snapshot, label"
        def note(r, same):
            return {"verdict": r[2], "priority": r[3], "summary": r[4], "research": r[5], "links": json.loads(r[6] or "[]"),
                    "model": r[7], "via": r[8], "at": r[9], "snapshot": r[10], "same_event": same, "label": r[11]}
        ks = list(want)
        for i in range(0, len(ks), 500):
            ch = ks[i:i + 500]
            for r in c.execute(f"SELECT {cols} FROM notes WHERE skey IN ({','.join('?' * len(ch))})", ch):
                for k in want[r[0]]:
                    out[k] = note(r, True)
        if fl:  # labels are normalised once per note (not once per note x checked finding), then matched by kind
            rows, bykind = [], {}
            for r in c.execute(f"SELECT {cols} FROM notes WHERE skey LIKE 'f|%' ORDER BY ts DESC"):
                nl = _NUM.sub("#", str(r[11] or ""))
                rows.append((nl, r))
                kd, sep, _ = nl.partition(": ")
                if sep:
                    bykind.setdefault(kd, []).append((nl, r))
            for k, lab in fl.items():
                kind, sep, detail = lab.partition(": ")
                cand = bykind.get(kind, ()) if sep else rows  # labels without "kind: " (rare): scan them all, as before
                for nl, r in cand:  # newest first, as before
                    if nl == lab or (nl.startswith(kind + ": ") and nl.endswith(" - " + detail)):
                        out[k] = note(r, False)
                        break
    return out


def apply(res):
    """Attach notes for the events of a correlation result (new dict; the cached base stays untouched)."""
    if not res or res.get("error"):
        return res
    try:
        return {**res, "notes": load((res.get("events") or {}).keys())}
    except Exception as e:  # noqa: BLE001 - notes are optional
        print(f"enrich notes unavailable: {e}", file=sys.stderr)
        return res


def adopt_note(eid, verdict, priority, summary, reasoning, model, user):
    """A person picked another model's assessment in a comparison: it replaces the note's verdict/priority/summary;
    the original research text and links are kept below it."""
    ak = _alert_keys()
    k = skey(eid, ak)
    v = str(verdict or "").lower()
    with _db() as c:
        old = c.execute("SELECT research, links, label, snapshot FROM notes WHERE skey=?", (k,)).fetchone()
        research = f"[{model} - chosen by {user} in a model comparison] {str(reasoning or '')[:1500]}"
        if old and old[0]:
            research += "\n\nEarlier research: " + old[0]
        c.execute("INSERT OR REPLACE INTO notes VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                  (k, eid, old[2] if old else "", v if v in VERDICTS else "needs-review", priority if priority in PRIORITIES else "Review",
                   str(summary or "")[:600], research[:4000], old[1] if old else "[]", f"{str(model)[:60]} (chosen by {user})",
                   "model comparison", time.time(), old[3] if old else ""))


def _clean_links(links):
    out = []
    for l in links or []:
        u = str((l or {}).get("url", "")).strip()
        if _URL.match(u):
            out.append({"title": str(l.get("title") or u)[:200], "url": u[:1000]})
    return out[:12]


def put(doc, events=None):
    """Store notes + correlation verdicts. events = current {eid: event} (labels; unknown ids are rejected)."""
    model = str(doc.get("model") or "unknown")[:80]
    via = str(doc.get("via") or "netmon research")[:80]
    sid = str(doc.get("snapshot") or "")[:40]
    now, rows, bad, ak = time.time(), [], [], _alert_keys()
    for n in doc.get("notes") or []:
        eid = str(n.get("id") or "")
        if not eid or (events is not None and eid not in events):
            bad.append(eid); continue
        v = str(n.get("verdict") or "needs-review").lower()
        rows.append((skey(eid, ak), eid, (events or {}).get(eid, {}).get("label", "")[:200], v if v in VERDICTS else "needs-review",
                     n.get("priority") if n.get("priority") in PRIORITIES else "Info", str(n.get("summary") or "")[:600],
                     str(n.get("research") or "")[:4000], json.dumps(_clean_links(n.get("links"))), model, via, now, sid))
    with _db() as c:
        c.executemany("INSERT OR REPLACE INTO notes VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", rows)
        for n in doc.get("notes") or []:  # the Elasticsearch searches the research AI ran for this note: Kibana artifacts of the note
            if str(n.get("id") or "") and isinstance(n.get("queries"), list):
                sk = skey(str(n["id"]), ak)
                c.execute("DELETE FROM note_queries WHERE skey=?", (sk,))
                c.executemany("INSERT OR REPLACE INTO note_queries VALUES (?,?,?,?)",
                              [(sk, d["kql"], esk.dumps(d), now) for d in map(esk.clean, n["queries"][:12]) if d and d["kql"]])
    import corr_llm
    lrows, kept = [], 0
    with corr_llm._db() as c:
        manual = {p for (p,) in c.execute("SELECT pair FROM verdicts WHERE model LIKE 'manual:%'")}
        for l in doc.get("links") or []:
            a, b = str(l.get("a") or ""), str(l.get("b") or "")
            if not a or not b or a == b or (events is not None and (a not in events or b not in events)):
                bad.append(f"{a} <-> {b}"); continue
            p = corr_llm.pair(a, b)
            if p in manual:
                kept += 1; continue
            lrows.append((p, 1 if l.get("related") else 0, max(0.0, min(1.0, float(l.get("confidence") or 0))),
                          str(l.get("reason") or "")[:300], model, now))
        c.executemany("INSERT OR REPLACE INTO verdicts (pair, related, confidence, reason, model, ts) VALUES (?,?,?,?,?,?)", lrows)
        for l in doc.get("links") or []:  # searches behind a related link become its Kibana artifacts
            a, b = str(l.get("a") or ""), str(l.get("b") or "")
            if l.get("related") and isinstance(l.get("queries"), list) and corr_llm.pair(a, b) not in manual and a and b and a != b and (events is None or (a in events and b in events)):
                corr_llm.set_query_artifacts(c, corr_llm.pair(a, b), l["queries"], model, now)
    with _db() as c:  # close the newest open run of this snapshot (opened by `events`), else log a standalone one
        r = c.execute("SELECT id FROM runs WHERE snapshot=? AND stored IS NULL ORDER BY id DESC LIMIT 1", (sid,)).fetchone()
        if r:
            c.execute("UPDATE runs SET stored=?, notes=?, links=?, rejected=?, model=? WHERE id=?", (now, len(rows), len(lrows), len(bad), model, r[0]))
        else:
            c.execute("INSERT INTO runs (snapshot, started, stored, notes, links, rejected, model) VALUES (?,?,?,?,?,?,?)",
                      (sid, now, now, len(rows), len(lrows), len(bad), model))
    out = {"notes": len(rows), "links": len(lrows), "manual_kept": kept, "rejected_ids": bad[:50]}
    if doc.get("host_notes") or doc.get("host_notes_delete"):  # what the run learned about devices (kb.py)
        import kb
        out.update(kb.put({**doc, "model": model, "via": via}))
    return out


def job():
    """The review job as one record for the AI review page: settings (review_cfg) + run state (review_job.json), plus the
    token use of event research (research_job.json) for the usage chart."""
    import review_cfg as VC, research_cfg as RC, corr_llm
    cfg, st, rs = VC.get(), VC.status(), RC.status()
    runs = st.get("runs") or []
    last = next((r for r in runs if r.get("status") != "running"), {})
    try:
        tgt = corr_llm._target()
    except Exception:  # noqa: BLE001 - shown as "no reviewer model"
        tgt = {}
    return {"id": "review", "name": "Review job: collect + analyze, reviewer",
            "model": tgt.get("model"), "provider": tgt.get("provider"), "enabled": cfg.get("enabled"),
            "interval_minutes": cfg.get("interval_minutes"), "next_run": VC.next_run(),
            "severities": cfg.get("severities"), "severity_options": cfg.get("severity_options"),
            "requested": VC.pending_request(), "last_run": st.get("last_run"), "last_status": st.get("last_status"),
            "last_error": st.get("last_error"), "failure_streak": st.get("failure_streak") or 0,
            "running": st.get("running"), "runs": runs[:12], "usage": st.get("usage") or [], "research_usage": [u for u in rs.get("usage") or [] if u.get("event_run")],
            "chat_usage": _chat_usage(), "researched": rs.get("researched") or [], "summary": st.get("summary"),
            "last": last, "exported": st.get("exported")}


def _chat_usage():
    try:
        import chat
        return chat.chat_usage()
    except Exception as e:  # noqa: BLE001
        print(f"chat usage unavailable: {e}", file=sys.stderr)
        return []


def status(event_ids=()):
    """Review job status for the AI review page: job state, the note-run log, note coverage of the current
    snapshot and the correlation verdicts written with notes."""
    import corr_llm
    try:
        j = job()
        jobs = {"jobs": [j], "exported": j.get("exported")}
    except Exception as e:  # noqa: BLE001
        jobs = {"jobs": [], "exported": None, "error": str(e)[:200]}
    now = time.time()
    with _db() as c:
        runs = [dict(zip(("snapshot", "started", "listed", "todo", "note_keys", "stored", "notes", "links", "rejected", "model"), r))
                for r in c.execute("SELECT snapshot, started, listed, todo, note_keys, stored, notes, links, rejected, model FROM runs ORDER BY id DESC LIMIT 20")]
        n_total, n_24 = c.execute("SELECT count(*), sum(ts > ?) FROM notes", (now - 86400,)).fetchone()
        verd = dict(c.execute("SELECT verdict, count(*) FROM notes GROUP BY verdict").fetchall())
        models = sorted({m for (m,) in c.execute("SELECT DISTINCT model FROM runs WHERE model IS NOT NULL")} | {"-"})
    with corr_llm._db() as c:  # verdicts written by the enrichment runs' model(s)
        cv = c.execute(f"SELECT count(*), sum(related), sum(ts > ?), max(ts), group_concat(DISTINCT model) FROM verdicts "
                       f"WHERE model IN ({','.join('?' * len(models))})", (now - 86400, *models)).fetchone()
    queue = None
    try:  # events waiting in the queue: no note yet, not dismissed (cached briefly: it is a full work-list build)
        if time.time() - _QCACHE.get("t", 0) > 30:
            r = _events_cached()
            _QCACHE.update(t=time.time(), v=None if r.get("error") else {"count": r["queued"], "testing": r["testing"], "review_only": r["review_only"],
                                                                   "review_covered": r["review_covered"]})
        queue = _QCACHE.get("v")
    except Exception as e:  # noqa: BLE001
        print(f"queue: {e}", file=sys.stderr)
    ids = list(event_ids)
    covered = len(load(ids)) if ids else 0
    return {"jobs": jobs.get("jobs") or [], "exported": jobs.get("exported"), "runs": runs,
            "queue": queue,
            "notes": {"total": n_total or 0, "last_24h": n_24 or 0, "by_verdict": verd,
                      "current_events": len(ids), "current_with_note": covered},
            "links": {"total": cv[0] or 0, "related": cv[1] or 0, "last_24h": cv[2] or 0, "last": cv[3], "models": (cv[4] or "").split(",") if cv[4] else []}}


RANK = {"critical": 0, "high": 1, "investigate": 1, "medium": 2, "urgent": 3, "low": 4}


def _sigs(sid):
    """Suricata signatures of the snapshot by name: severity (1 = high, 2 = medium, 3 = low), count, hosts, ports."""
    try:
        import server
        raw = (server.snapshot(sid) or {}).get("raw") or {}
    except Exception:  # noqa: BLE001
        raw = {}
    return {x.get("name"): x for x in ((raw.get("alerts") or {}).get("signatures") or [])}


def _events(sid=None, everything=False, limit=40, hosts=60, idsq_max=40, gw_max=30, only=None):
    """Work list for the enrichment run: one entry per note key (alert families and repeat findings collapse),
    events without a note first, most severe first, capped at `limit` (0 = no cap). Endpoint host findings
    (hf|..., the Posture "Host findings" box) are always included, whatever their severity, in their own
    quota of `hosts` items on top of `limit`, so they are listed every run instead of losing to network events.
    Suricata severity 1 and 2 signatures (ids|...) get the same treatment with their own quota of `idsq_max` items,
    and so do UniFi gateway events (gw|..., the Posture "Gateway events" card; quota `gw_max`, any severity)."""
    import server, corr_llm, research_cfg as RC, review_cfg as VC
    sid = sid or (server.snapshots() or [{"id": ""}])[-1]["id"]
    res = corr_llm.apply(server.correlation(sid))
    if not res or res.get("error"):
        return {"snapshot": sid, "error": "no correlation for snapshot"}
    modes = VC.get()["modes"]  # admin-chosen review / queue / test / skip per event category (AI review page)
    E, notes, ak = res["events"], load(res["events"].keys()), _alert_keys()
    groups = {}
    rules = corr_llm.limits()["rules"]  # suppression rules (AI review > Review limits) that cover the review job
    forced = _requested(E, notes, ak)  # note keys a person asked to have researched (not researched yet)
    if only:  # event research (research.py --event): just that event's family, whatever its category or rules
        forced = {skey(only, ak)} if only in E else set()
        E = {i: e for i, e in E.items() if skey(i, ak) in forced}
        notes = {i: n for i, n in notes.items() if i in E}
    for eid, e in E.items():
        if skey(eid, ak) in forced:
            groups.setdefault(skey(eid, ak), []).append(eid)
            continue
        if not everything and ((rules and corr_llm.suppressed(rules, "queue", eid, e))):
            continue
        # host findings, gateway events, threat intel and store alarms are categories of their own; the rest is gated
        # on its severity (Suricata sev 1-2 is split off below, once the signature detail is known)
        if not everything and e["type"] not in ("ti", "host", "gw", "alert") and corr_llm.etype(eid, e) != "seg" and modes.get(e.get("sev"), "skip") == "skip" \
                and e["type"] != "ids":
            continue
        groups.setdefault(skey(eid, ak), []).append(eid)
    if not everything:  # queue cleared by an admin (clear_queue): those note keys stay out of the queue until reset
        dismissed = set(RC._meta("research_dismissed").get("keys") or [])
        groups = {k: v for k, v in groups.items() if k not in dismissed or k in forced}
    out = []
    for k, ids in groups.items():
        ids.sort(key=lambda i: -(E[i].get("t0") or 0))
        eid, e, n = ids[0], E[ids[0]], notes.get(ids[0])
        rel = res["related"].get(eid) or []
        out.append({"id": eid, "type": e["type"], "sev": e.get("sev"), "label": e["label"], "link": e.get("link"),
                    "when": time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(e["t0"])) if e.get("t0") else "ongoing",
                    "repeats": len(ids), "other_ids": ids[1:6],
                    "note": ({k2: n[k2] for k2 in ("verdict", "priority", "summary", "model", "snapshot")}
                             | {"age_h": round((time.time() - n["at"]) / 3600, 1)}) if n else None,
                    "related": [{"id": r["id"], "label": (E.get(r["id"]) or {}).get("label", "")[:120], "why": r["why"],
                                 "verdict": r.get("llm"), "by": r.get("llm_model"), "reason": r.get("llm_reason")} for r in rel[:8]]})
    out.sort(key=lambda x: (x["note"] is not None, RANK.get(x["sev"], 5) - (1 if x["type"] in ("ti", "ids") else 0), -x["repeats"]))
    sigs = _sigs(sid)
    for x in out:  # Suricata detail so the researcher sees severity, volume, hosts and ports without a lookup
        g = sigs.get(x["id"][4:]) if x["type"] == "ids" else None
        if g:
            x["suricata"] = {"severity": g.get("severity"), "count": g.get("count"), "category": g.get("category"),
                             "src": g.get("src"), "dst": g.get("dst"), "dport": g.get("dport"), "first": g.get("first"), "last": g.get("last")}
    sev12 = lambda x: x["type"] == "ids" and (x.get("suricata") or {}).get("severity") in (1, 2)  # noqa: E731
    cat = lambda x: x["type"] if x["type"] in ("host", "gw", "ti", "alert") else ("seg_" + (x.get("sev") if x.get("sev") in ("high", "medium") else "low") if corr_llm.etype(x["id"], x) == "seg" else "ids12" if sev12(x) else x.get("sev"))  # noqa: E731
    if not everything:  # drop the categories set to skip (Suricata sev 3 falls through to its severity)
        out = [x for x in out if modes.get(cat(x), "skip") != "skip" or skey(x["id"], ak) in forced]
    for x in out:
        m = modes.get(cat(x)) if skey(x["id"], ak) not in forced else "queue"
        x["mode"] = m if m in ("review", "test") else "queue"
        x["requested"] = skey(x["id"], ak) in forced
    todo = sum(1 for x in out if not x["note"])
    hostq = [x for x in out if x["type"] == "host"]
    idsq = [x for x in out if sev12(x)]
    gwq = [x for x in out if x["type"] == "gw"]
    rest = [x for x in out if x["type"] not in ("host", "gw") and not sev12(x)]
    pick = ((hostq[:hosts] if hosts else hostq) + (idsq[:idsq_max] if idsq_max else idsq) + (gwq[:gw_max] if gw_max else gwq)
            + (rest[:limit] if limit else rest))
    pick.sort(key=lambda x: (x["note"] is not None, not (x["type"] in ("host", "gw") or sev12(x))))
    _prior(pick, E, res, notes)
    hn_count = 0
    try:  # the owner's event notes (authoritative guidance) and what earlier runs learned about the hosts involved
        import kb
        reg = kb._registry()
        un = kb.event_notes([x["id"] for x in pick], ai=True)  # approved notes only (User notes need defender approval)
        hn_cache = {}
        for x in pick:
            if un.get(x["id"]):
                x["user_notes"] = [{"by": n["author"], "at": time.strftime("%Y-%m-%d", time.gmtime(n["ts"])), "text": n["text"]} for n in un[x["id"]]]
            hn = {}
            for ip in (E.get(x["id"]) or {}).get("ips") or []:
                if ip not in hn_cache:
                    hn_cache[ip] = [{"id": n["id"], "subject": n["subject"], "category": n["category"], "by": n["author"], "authoritative": n.get("status") == "approved" or str(n["author"]).startswith("user:"), "text": n["text"]}
                                    for n in kb.host_notes(kb.subjects_for_ip(ip, reg), ai=True)]
                if hn_cache[ip]:
                    hn[ip] = hn_cache[ip]
            if hn:
                x["host_notes"] = hn
            inn = {}  # notes on the external IPs the event involves (Network > Internet notes)
            for ip in kb.external_ips(E.get(x["id"]) or {}):
                if ip not in hn_cache:
                    hn_cache[ip] = [{"id": n["id"], "subject": n["subject"], "category": n["category"], "by": n["author"], "authoritative": n.get("status") == "approved" or str(n["author"]).startswith("user:"), "text": n["text"]}
                                    for n in kb.host_notes([f"ip:{ip}", f"art:ip:{ip}"], ai=True)]
                if hn_cache[ip]:
                    inn[ip] = hn_cache[ip]
            if inn:
                x["internet_notes"] = inn
            dn = [{"id": n["id"], "domain": d, "applies_to": nm, "by": n["author"], "authoritative": n.get("status") == "approved" or str(n["author"]).startswith("user:"), "text": n["text"]}  # DNS notes (a domain's note covers its subdomains)
                  for nm, d, n, _ex in kb.dns_notes_for(kb.dns_names(E.get(x["id"]) or {}), 6)]
            if dn:
                x["dns_notes"] = dn
        hn_count = sum(1 for v in hn_cache.values() if v)
    except Exception as e:  # noqa: BLE001 - the work list must not depend on the notes store
        print(f"kb notes unavailable: {e}", file=sys.stderr)
    return {"snapshot": sid, "total_events": len(E), "note_keys": len(out), "without_note": todo,
            "host_findings": len(hostq), "host_without_note": sum(1 for x in hostq if not x["note"]),
            "review_only": sum(1 for x in pick if x.get("mode") == "review"),
            "review_covered": sum(1 for x in pick if x.get("mode") == "review" and x.get("researched")),
            "queued": sum(1 for x in out if x["mode"] in ("queue", "review") and not x["note"]),
            "testing": sum(1 for x in out if x["mode"] == "test" and not x["note"]),
            "ids_sev12": len(idsq), "ids_sev12_without_note": sum(1 for x in idsq if not x["note"]),
            "gateway": len(gwq), "gateway_without_note": sum(1 for x in gwq if not x["note"]),
            "events_with_user_notes": sum(1 for x in pick if x.get("user_notes")), "hosts_with_notes": hn_count,
            "listed": len(pick), "llm": {k: res.get("llm", {}).get(k) for k in ("model", "confirmed", "rejected", "pending")},
            "events": pick}


_QCACHE = {}


def _events_cached(ttl=30):
    """_events() shared by the AI-review status, the queue list and the test-mode ids for `ttl` seconds: the
    work-list build (difflib similarity over earlier notes) costs ~0.5 s and all three read the same result.
    _QCACHE.clear() (settings changes, research requests) drops it."""
    if time.time() - _QCACHE.get("ev_t", 0) > ttl or "ev" not in _QCACHE:
        _QCACHE.update(ev=_events(), ev_t=time.time())
    return _QCACHE["ev"]


def _requested(E, notes, ak):
    """Note keys with a pending 'send to research' request whose event has no note yet; satisfied requests are dropped."""
    import research_cfg as RC
    reqs = RC._meta("research_requests").get("items") or {}
    if not reqs:
        return set()
    have = {skey(eid, ak) for eid in E if notes.get(eid)}
    live = {k: v for k, v in reqs.items() if k not in have}
    if len(live) != len(reqs):
        RC._meta_put("research_requests", {"items": live})
    return {k for k in live if any(skey(eid, ak) == k for eid in E)}


def _testing_ids():
    """Ids of events currently held in test mode (queued and tagged, never sent); cached with the queue numbers."""
    try:
        if time.time() - _QCACHE.get("ti_t", 0) > 30:
            _QCACHE.update(ti_t=time.time(), ti={i for x in _events_cached()["events"] if x.get("mode") == "test" and not x["note"] for i in [x["id"]] + x["other_ids"]})
        return _QCACHE.get("ti") or set()
    except Exception:  # noqa: BLE001
        return set()


def request_research(eid, user, send=True):
    """A person asks for one event to be researched. State: researched (a note exists), queued (requested or already due),
    idle. Research starts at once on the host (research.py); when the research model is busy the click waits and the
    host scheduler starts it as soon as the running research ends."""
    import research_cfg as RC
    ak = _alert_keys()
    k = skey(eid, ak)
    if load([eid]).get(eid):
        return {"state": "researched"}
    reqs = dict(RC._meta("research_requests").get("items") or {})
    if k in reqs:
        st = reqs[k].get("started")
        return {"state": "running" if st and time.time() - st < 1800 else "queued", "by": reqs[k].get("by")}
    if not send:
        return {"state": "idle", "testing": eid in _testing_ids()}
    if len(reqs) >= 200:
        raise ValueError("too many pending research requests (200)")
    reqs[k] = {"eid": eid[:300], "by": str(user)[:64], "at": time.time()}
    RC._meta_put("research_requests", {"items": reqs})
    _QCACHE.clear()
    try:  # start the research now on the host (research.py); if that fails the request stays queued
        import corr_llm
        r = corr_llm.broker("/research-event", {"eid": eid, "user": str(user)[:64]}, timeout=20)
        if r.get("started"):
            reqs[k].update(started=time.time(), tries=1)
            RC._meta_put("research_requests", {"items": reqs})
            return {"state": "running", "by": reqs[k]["by"]}
        return {"state": "queued", "by": reqs[k]["by"], "note": r.get("reason") or "another research run is in progress"}
    except Exception as e:  # noqa: BLE001
        print(f"research now: {e}", file=sys.stderr)
        return {"state": "queued", "by": reqs[k]["by"], "note": "could not start right away"}


def queue_items():
    """Events waiting for a person (no note yet, not dismissed or suppressed); Send to research researches one."""
    r = _events_cached()
    if r.get("error"):
        return {"error": r["error"], "items": []}
    items = [{"id": x["id"], "type": x["type"], "sev": x.get("sev"), "label": x["label"], "link": x.get("link"), "when": x["when"],
              "repeats": x["repeats"], "requested": x.get("requested"), "testing": x.get("mode") == "test"}
             for x in r["events"] if x.get("mode") in ("queue", "review", "test") and not x["note"]]
    return {"snapshot": r["snapshot"], "count": sum(1 for x in items if not x["testing"]), "testing": sum(1 for x in items if x["testing"]), "items": items}


def _similar(x, skeys, limit=4, min_ratio=0.6):
    """Earlier notes on events of the same type whose label (numbers masked) looks like this item's: [(ratio, row)]."""
    import difflib
    me = _NUM.sub("#", x.get("label") or "")
    if not me:
        return []
    out = []
    with _db() as c:
        for r in c.execute("SELECT skey, eid, label, verdict, priority, summary, research, model, ts FROM notes WHERE eid LIKE ?",
                           (x["id"].split("|")[0] + "|%",)):
            if r[0] in skeys or not r[2]:
                continue
            q = difflib.SequenceMatcher(None, me, _NUM.sub("#", r[2])).ratio()
            if q >= min_ratio:
                out.append((q, r))
    out.sort(key=lambda t: -t[0])
    return out[:limit]


def _prior(pick, E, res, notes):
    """Review-mode items: what was researched before. Own note (same family), the notes of correlated events and notes on
    events with a similar label. Sets x["prior"] (list of {id, how, verdict, priority, summary, research, label, age_h}) and
    x["researched"]; queue-mode items are untouched. The review job's reviewer (review.py) decides from these whether
    an item can reuse a prior note (copy_notes) or stays in the queue."""
    rel_ids = {r["id"] for x in pick if x.get("mode") == "review" and not x["note"] for r in (res["related"].get(x["id"]) or [])}
    rn = load(rel_ids) if rel_ids else {}
    ak = _alert_keys()
    for x in pick:
        if x.get("mode") != "review":
            continue
        prior = []
        if x["note"]:
            prior.append({"id": x["id"], "how": "same event family", "verdict": x["note"]["verdict"], "summary": x["note"]["summary"],
                          "age_h": x["note"]["age_h"]})
        else:
            seen = {skey(x["id"], ak)}
            for r in (res["related"].get(x["id"]) or [])[:8]:
                n = rn.get(r["id"])
                if n and skey(r["id"], ak) not in seen:
                    seen.add(skey(r["id"], ak))
                    prior.append({"id": r["id"], "how": "correlated: " + str(r.get("why") or "")[:80], "label": (E.get(r["id"]) or {}).get("label", "")[:160],
                                  "verdict": n["verdict"], "priority": n["priority"], "summary": n["summary"],
                                  "research": (n.get("research") or "")[:800], "age_h": round((time.time() - n["at"]) / 3600, 1)})
            try:
                for q, r in _similar(x, seen):
                    prior.append({"id": r[1], "how": f"similar event (label match {q:.0%})", "label": r[2][:160], "verdict": r[3], "priority": r[4],
                                  "summary": r[5], "research": (r[6] or "")[:800], "age_h": round((time.time() - r[8]) / 3600, 1)})
            except Exception as e:  # noqa: BLE001 - similar-event lookup is optional
                print(f"similar notes unavailable: {e}", file=sys.stderr)
        x["prior"], x["researched"] = prior, bool(prior)


def copy_notes(doc, events=None):
    """The review job's reviewer judged an event the same as one researched before: store the earlier note for it, with a
    line saying it was copied. doc = {model, snapshot, copies: [{id, from, reason}]} -> {copied, rejected_ids}."""
    model = str(doc.get("model") or "unknown")[:80]
    sid = str(doc.get("snapshot") or "")[:40]
    ak, now, bad, rows = _alert_keys(), time.time(), [], []
    for cp in doc.get("copies") or []:
        eid, src = str(cp.get("id") or ""), str(cp.get("from") or "")
        if not eid or not src or (events is not None and eid not in events):
            bad.append(eid); continue
        old = load([src]).get(src)
        if not old:
            bad.append(eid); continue
        label = (events or {}).get(eid, {}).get("label", "")[:200]
        when = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(old["at"]))
        head = (f"[Copied by the reviewer ({model}) from the note on {src} ({when}, researched by {old.get('model')}): "
                f"{str(cp.get('reason') or 'judged the same activity')[:400]}. Not re-researched.]")
        rows.append((skey(eid, ak), eid, label, old["verdict"], old["priority"], old["summary"][:600], (head + "\n\n" + (old["research"] or ""))[:4000],
                     json.dumps(old["links"]), old.get("model") or model, "reviewer (copied note)", now, sid))
    if rows:
        with _db() as c:
            c.executemany("INSERT OR REPLACE INTO notes VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", rows)
    return {"copied": len(rows), "rejected_ids": bad}


def clear_queue(user, wipe=False):
    """Start fresh: every event family in the current snapshot is dismissed from the queue (new events and new
    note keys are queued as usual); wipe=True also deletes all event notes and the model's correlation verdicts
    (manual verdicts are kept). Databases are copied to <state>/backup-<ts>/ first."""
    import server, corr_llm, research_cfg as RC, shutil
    sid = (server.snapshots() or [{"id": ""}])[-1]["id"]
    res = server.correlation(sid)
    if not res or res.get("error"):
        return {"error": "no correlation for snapshot"}
    ak = _alert_keys()
    keys = sorted({skey(eid, ak) for eid in res["events"]})
    out = {"snapshot": sid, "dismissed": len(keys)}
    if wipe:
        bk = os.path.join(os.path.dirname(DB), "backup-" + time.strftime("%Y%m%d-%H%M%S"))
        os.makedirs(bk)
        for src in (DB, corr_llm.DB):
            d = sqlite3.connect(src); b = sqlite3.connect(os.path.join(bk, os.path.basename(src))); d.backup(b); b.close(); d.close()
        with _db() as c:
            out["notes_deleted"] = c.execute("DELETE FROM notes").rowcount
        with corr_llm._db() as c:
            out["verdicts_deleted"] = c.execute("DELETE FROM verdicts WHERE model NOT LIKE 'manual:%'").rowcount
        out["backup"] = bk
    keys = sorted(set(keys) | set(RC._meta("research_dismissed").get("keys") or []))
    RC._meta_put("research_dismissed", {"keys": keys, "by": str(user)[:64], "at": time.time(), "snapshot": sid})
    return out


def _audit(purpose, model, message, prompt=None, response=None, error=None):
    """The review job (review.py) and event research (research.py) read work items and store results here: log what goes in and comes back."""
    job = "event research" if purpose.startswith("research") else "review job"
    try:
        import audit
        audit.llm(purpose, job, model, user=f"netmon ({job})", prompt=prompt, response=response, error=error, message=message)
        audit.flush(drain=False)
    except Exception as e:  # noqa: BLE001 - the job must not fail because the audit log is down (entries spool)
        print(f"audit: {e}", file=sys.stderr)


def main(argv):
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    if argv[:1] == ["events"]:
        sid = argv[argv.index("--sid") + 1] if "--sid" in argv else None
        lim = int(argv[argv.index("--max") + 1]) if "--max" in argv else 40
        hq = int(argv[argv.index("--hosts") + 1]) if "--hosts" in argv else 60
        iq = int(argv[argv.index("--ids") + 1]) if "--ids" in argv else 40
        gq = int(argv[argv.index("--gw") + 1]) if "--gw" in argv else 30
        res = _events(sid, "--all" in argv, lim, hq, iq, gq, argv[argv.index("--only") + 1] if "--only" in argv else None)
        _audit("research-input" if "--only" in argv else "review-input", "", f"{'event research' if '--only' in argv else 'review job'}: work list ({res.get('listed')} events, snapshot {res.get('snapshot')})",
               prompt=json.dumps(res, default=str), error=res.get("error"))
        print(json.dumps(res, indent=1, default=str))
    elif argv[:1] == ["clear-queue"]:
        print(json.dumps(clear_queue("cli", "--wipe" in argv), default=str))
    elif argv[:1] == ["clear-review"]:
        import server, corr_llm
        sids = [x["id"] for x in (server.snapshots() or [])][-3:]
        print(json.dumps(corr_llm.clear_pending(sids, "cli")))
    elif argv[:1] == ["copy"]:
        doc = json.load(sys.stdin if argv[1:2] in (["-"], []) else open(argv[1]))
        import server
        sid = doc.get("snapshot") or (server.snapshots() or [{"id": ""}])[-1]["id"]
        out = copy_notes({**doc, "snapshot": sid}, (server.correlation(sid) or {}).get("events") or {})
        _audit("review-copy", str(doc.get("model") or ""), f"review job reviewer: {out['copied']} earlier notes reused", response=json.dumps(doc, default=str))
        print(json.dumps(out))
    elif argv[:1] == ["put"]:
        doc = json.load(sys.stdin if argv[1:2] in (["-"], []) else open(argv[1]))
        import server
        sid = doc.get("snapshot") or (server.snapshots() or [{"id": ""}])[-1]["id"]
        res = server.correlation(sid)
        out = put({**doc, "snapshot": sid}, (res or {}).get("events") or {})
        _audit("research-result", str(doc.get("model") or ""), f"event research: LLM results stored ({len(doc.get('notes') or [])} notes, "
               f"{len(doc.get('links') or [])} links) -> {json.dumps(out, default=str)[:200]}", response=json.dumps(doc, default=str))
        print(json.dumps(out))
    else:
        print(__doc__)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
