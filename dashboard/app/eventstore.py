"""Persistent event store (sqlite table `events`): every correlation event stays here until it is checked off.

The time picker only decides what a snapshot/range *shows*; an event that nobody has checked off is still open, however
old. Fix-list items (`iss|`) are the exception: their lifecycle is the issue's own (fixed -> resolved), so they close
when the issue is no longer open.

Ack identity: events with a check-off list reuse their existing ack keys (alarm / finding / host / issue / gw / admin);
events without one (IDS signatures, threat-intel hits, alerts) use the generic ack type "event" with the eid as key.
"""
import json, os, re, sys, threading

_ROOT = os.environ.get("NETMON_DIR", "/netmon")
if os.path.isdir(_ROOT) and _ROOT not in sys.path:
    sys.path.append(_ROOT)
import store

_lock = threading.Lock()
SEV_RANK = {"critical": 0, "high": 0, "urgent": 0, "medium": 1, "low": 2, "info": 3}
DDL = """CREATE TABLE IF NOT EXISTS events (
  eid TEXT PRIMARY KEY, type TEXT NOT NULL, label TEXT NOT NULL DEFAULT '', sev TEXT DEFAULT '', link TEXT DEFAULT '',
  t0 REAL, t1 REAL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, last_sid TEXT, n INTEGER NOT NULL DEFAULT 1,
  resolved INTEGER NOT NULL DEFAULT 0, doc TEXT NOT NULL DEFAULT '{}');
CREATE INDEX IF NOT EXISTS events_open ON events(resolved, type);"""


def _c():
    return store.tl_conn("eventstore", lambda c: c.executescript(DDL))


def ack_refs(eid):
    """[(ack type, key)] under which a check-off of this event is stored; the first is the one the UI writes."""
    import corr_llm
    p = str(eid).split("|")
    if p[0] == "adm" and len(p) >= 4:
        return [("admin", "|".join(p[1:]))]
    refs = list(corr_llm._ack_keys(eid))
    return refs or [("event", str(eid))]


def _slim(x, depth=0):
    """The source row kept with an event (for Ask AI, Kibana pivots, display): sizes capped."""
    if isinstance(x, dict):
        it = list(x.items())[:40]
        return {str(k): _slim(v, depth + 1) for k, v in it} if depth < 4 else str(x)[:300]
    if isinstance(x, (list, tuple, set)):
        return [_slim(v, depth + 1) for v in list(x)[:25]] if depth < 4 else str(x)[:300]
    if isinstance(x, str):
        return x[:1500]
    return x if isinstance(x, (int, float, bool)) or x is None else str(x)[:300]


def upsert(E, sid, gen_iso=None, items=None):
    """Record the events of one snapshot. Idempotent per (eid, sid): the seen counter moves once per snapshot.
    An older snapshot never overwrites what a newer one stored."""
    if not E or not sid:
        return 0
    now = gen_iso or store.now_iso()
    rows = []
    for eid, ev in E.items():
        doc = {k: ev.get(k) for k in ("arts", "ips", "host_ips", "dst_ips") if ev.get(k)}
        if items and items.get(eid) is not None:
            doc["item"] = _slim(items[eid])
        rows.append((eid, ev.get("type") or "", (ev.get("label") or "")[:300], ev.get("sev") or "", ev.get("link") or "",
                     ev.get("t0"), ev.get("t1"), now, now, sid, json.dumps(doc, default=str)))
    newer = "COALESCE(excluded.t1,0) >= COALESCE(events.t1,0)"
    with _lock:
        c = _c()
        with store.tx(c):
            c.executemany(
                "INSERT INTO events (eid,type,label,sev,link,t0,t1,first_seen,last_seen,last_sid,n,doc) VALUES (?,?,?,?,?,?,?,?,?,?,1,?) "
                "ON CONFLICT(eid) DO UPDATE SET "
                f"label=CASE WHEN {newer} THEN excluded.label ELSE events.label END, sev=CASE WHEN {newer} THEN excluded.sev ELSE events.sev END, "
                f"link=CASE WHEN {newer} THEN excluded.link ELSE events.link END, doc=CASE WHEN {newer} THEN excluded.doc ELSE events.doc END, "
                "t0=MIN(COALESCE(events.t0,excluded.t0), COALESCE(excluded.t0,events.t0)), t1=MAX(COALESCE(events.t1,excluded.t1), COALESCE(excluded.t1,events.t1)), "
                "first_seen=MIN(events.first_seen, excluded.first_seen), last_seen=MAX(events.last_seen, excluded.last_seen), "
                "n=events.n + (CASE WHEN COALESCE(events.last_sid,'')!=excluded.last_sid THEN 1 ELSE 0 END), "
                "last_sid=excluded.last_sid, resolved=CASE WHEN events.type='vuln' THEN 0 ELSE events.resolved END", rows)
    return len(rows)


def sync_vulns(E, latest):
    """Fix-list items live as long as the issue is open: close stored ones the newest snapshot no longer lists."""
    if not latest:
        return
    live = [e for e, v in E.items() if v.get("type") == "vuln"]
    with _lock:
        c = _c()
        with store.tx(c):
            c.execute("UPDATE events SET resolved=1 WHERE type='vuln'")
            c.executemany("UPDATE events SET resolved=0 WHERE eid=?", [(e,) for e in live])


_KEEP = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b|\bport \d+|\b\d+/(?:tcp|udp)\b|\b[0-9a-f]{2}(?::[0-9a-f]{2}){5}\b", re.I)


def _norm(text):
    """Volatile counts ("145 conns", "3,983 queries", "every ~180s") become #; IPs, ports and MACs are kept."""
    out, last = [], 0
    for m in _KEEP.finditer(text):
        out.append(re.sub(r"\d[\d,.]*", "#", text[last:m.start()])); out.append(m.group(0)); last = m.end()
    out.append(re.sub(r"\d[\d,.]*", "#", text[last:]))
    return "".join(out)


def gkey(eid):
    """Logical identity of an event. A finding's id embeds its volatile detail, so one condition shows up as a new id every
    snapshot; group those. Segmentation findings group by their flow (the key the flow is cleared under)."""
    p = str(eid).split("|")
    if p[0] == "f" and len(p) >= 4:
        if p[1] == "segmentation":
            import risk
            k = risk.seg_key_finding({"device": p[2], "kind": "segmentation", "detail": "|".join(p[3:])})
            if k:
                return "seg|" + k
        return "f|" + p[1] + "|" + p[2] + "|" + _norm("|".join(p[3:]))
    return str(eid)


def open_events(types=None, sev=None, q=None, limit=2000):
    """Unchecked, unresolved events (any age), most severe then newest first. Repeats of one condition are one row."""
    c = _c()
    acks = store.acks_load(c)
    alert_ok = {r[0] for r in c.execute("SELECT id FROM alerts WHERE cleared=0 AND held=0 AND source!='review'")}
    groups = {}
    for r in c.execute("SELECT * FROM events WHERE resolved=0 ORDER BY COALESCE(t1,0), last_seen"):  # oldest -> newest
        eid = r["eid"]
        if eid.startswith("alert|"):
            try:
                if int(eid.split("|")[1]) not in alert_ok:
                    continue
            except ValueError:
                continue
        g = groups.setdefault(gkey(eid), {"members": [], "first": r["first_seen"], "n": 0})
        g["members"].append(r); g["n"] += r["n"]; g["first"] = min(g["first"], r["first_seen"])
    out, counts = [], {}
    for gk, g in groups.items():
        newest = g["members"][-1]
        refs = ack_refs(newest["eid"])
        grp = gk != newest["eid"]
        grp_ref = ("seg", gk[4:]) if gk.startswith("seg|") else ("event", "grp|" + gk)
        if grp and k_in(acks, grp_ref):
            continue
        if any(k_in(acks, ref) for ref in refs):
            continue
        counts[newest["type"]] = counts.get(newest["type"], 0) + 1
        if types and newest["type"] not in types:
            continue
        if sev and (newest["sev"] or "").lower() != sev:
            continue
        if q and q.lower() not in (newest["label"] or "").lower():
            continue
        d = json.loads(newest["doc"] or "{}")
        t0s = [m["t0"] for m in g["members"] if m["t0"] is not None]
        # what a check-off writes: the group's own ack, plus each member's usual ack so the per-page lists agree
        todo = [refs[0]] + ([grp_ref] if grp else [])  # the newest variant's own ack first (suppress rules work on it)
        for m in g["members"][-50:]:
            todo += [x for x in ack_refs(m["eid"])[:1] if not (grp and x[0] == "event")]
        out.append({"eid": newest["eid"], "type": newest["type"], "label": newest["label"], "sev": newest["sev"], "link": newest["link"],
                    "t0": newest["t0"], "t1": newest["t1"], "item": d.get("item"), "members": [m["eid"] for m in g["members"][-12:]], "first_seen": g["first"], "last_seen": newest["last_seen"], "n": g["n"],
                    "repeats": len(g["members"]), "ips": d.get("ips") or [], "acks": [{"type": t, "key": k} for t, k in dict.fromkeys(todo)]})
    out.sort(key=lambda e: (SEV_RANK.get((e["sev"] or "").lower(), 2), -(e["t1"] or 0), e["eid"]))
    shown = out[:limit]
    return {"events": shown, "total": sum(counts.values()), "counts": counts, "shown": len(shown), "extra": extras(shown) if shown else {}}


def extras(rows):
    """AI notes (verdicts), reviewer classifications, people's notes and times seen for the rows, keyed by each row's event id.
    A grouped row takes the newest variant that has one."""
    out = {"notes": {}, "classes": {}, "unotes": {}, "seen": {}}
    allids = [m for r in rows for m in r["members"]]
    try:
        import enrich, corr_llm, kb
        N, C, U = enrich.load(allids), corr_llm.classes(allids), kb.event_notes(allids)
    except Exception as e:  # noqa: BLE001 - the page works without them
        print(f"eventstore extras: {e}", file=sys.stderr)
        N = C = U = {}
    for r in rows:
        for m in reversed(r["members"]):
            for src, dst in ((N, "notes"), (C, "classes"), (U, "unotes")):
                if m in src and r["eid"] not in out[dst]:
                    out[dst][r["eid"]] = src[m]
        out["seen"][r["eid"]] = {"n": r["n"], "first": r["first_seen"], "last": r["last_seen"]}
    return out


def k_in(acks, ref):
    return ref[1] in (acks.get(ref[0]) or {})



