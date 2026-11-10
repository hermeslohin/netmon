"""Persistent event store (sqlite table `events`): every correlation event stays here until it is checked off.

The time picker only decides what a snapshot/range *shows*; an event that nobody has checked off is still open, however
old. Fix-list items (`iss|`) are the exception: their lifecycle is the issue's own (fixed -> resolved), so they close
when the issue is no longer open.

Ack identity: events with a check-off list reuse their existing ack keys (alarm / finding / host / issue / gw / admin);
events without one (IDS signatures, threat-intel hits, alerts) use the generic ack type "event" with the eid as key.
"""
import json, os, re, sys, threading, time

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
CREATE INDEX IF NOT EXISTS events_open ON events(resolved, type);
CREATE TABLE IF NOT EXISTS event_fires (
  eid TEXT NOT NULL, sid TEXT NOT NULL, seen TEXT NOT NULL, t0 REAL, t1 REAL, label TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (eid, sid)) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS event_fires_seen ON event_fires(seen);"""
FIRE_KEEP_DAYS = 400


# A "firing" is an occurrence of the event in Elasticsearch data (Zeek / Suricata / endpoint / syslog), not a report that
# merely lists it. Only ES-sourced events fire: IDS signatures, host findings, threat-intel hits and the Zeek-derived
# baseline findings. Inventory findings, vulnerabilities, gateway/UniFi events, admin-protocol and code-scan alerts never do.
ES_TYPES = {"ids", "host", "ti", "finding"}
NON_ES_FINDINGS = {"outdated-software", "new-software", "new-device", "new-device-dhcp", "inbound-exposure", "segmentation"}


def es_sourced(eid, typ):
    p = str(eid).split("|")
    if typ == "finding" or p[0] == "f":
        return len(p) > 1 and p[1] not in NON_ES_FINDINGS
    return typ in ES_TYPES


def _plan_fires(c, rows, sid, now, fresh=None):
    """Decide which rows are new firings. Window events (findings / host / threat intel carry the report's analysis window
    as t0..t1): a window overlapping the previous firing of the same condition is the same occurrence, so that firing is
    extended instead of repeated. IDS signatures carry real alert times: a firing per new last-alert time.
    -> (new fire rows, [(t1, eid, sid)] extensions). `fresh` = in-memory last fire per group, for replays."""
    new, ext, last = [], [], fresh if fresh is not None else {}
    for r in rows:
        eid, typ, label, t0, t1 = r[0], r[1], r[2], r[5], r[6]
        if not es_sourced(eid, typ) or t1 is None:
            continue
        g = gkey(eid)
        prev = last.get(g)
        if prev is None and fresh is None:
            p = str(eid).split("|")
            pre = "|".join(p[:3]) + "|" if p[0] == "f" and len(p) >= 4 else str(eid)
            for o in c.execute("SELECT eid,sid,t0,t1 FROM event_fires WHERE eid >= ? AND eid < ? ORDER BY COALESCE(t1,0) DESC", (pre, pre + "\uffff")):
                if gkey(o["eid"]) == g:
                    prev = (o["eid"], o["sid"], o["t0"], o["t1"]); break
        if prev is not None and prev[1] == sid and prev[0] == eid:
            continue  # already recorded for this snapshot
        if typ == "ids":
            same = prev is not None and t1 <= prev[3] + 1
        else:
            same = prev is not None and (t0 if t0 is not None else t1) <= prev[3]
        if same:
            if t1 > prev[3]:
                ext.append((t1, prev[0], prev[1])); last[g] = (prev[0], prev[1], prev[2], t1)
            continue
        new.append((eid, sid, now, t0, t1, label)); last[g] = (eid, sid, t0, t1)
    return new, ext


def _init(c):
    c.executescript(DDL)
    # when the activity happened (Elasticsearch record times, filled by evtime.py on the host): et0/et1 first/last record,
    # et_upto the window end already looked up
    for t in ("events", "event_fires"):
        have = {r[1] for r in c.execute(f"PRAGMA table_info({t})")}
        for col in ("et0", "et1", "et_upto"):
            if col not in have:
                try:
                    c.execute(f"ALTER TABLE {t} ADD COLUMN {col} REAL")
                except Exception as e:  # noqa: BLE001 - another process added it first
                    if "duplicate column" not in str(e):
                        raise
    c.execute("CREATE TABLE IF NOT EXISTS event_times (eid TEXT NOT NULL, w0 INTEGER NOT NULL, w1 INTEGER NOT NULL, et0 REAL, et1 REAL, "
              "at REAL NOT NULL, PRIMARY KEY (eid, w0, w1)) WITHOUT ROWID")


def _c():
    return store.tl_conn("eventstore", _init)


def _emin(rows, k="et0"):
    v = [r[k] for r in rows if r[k] is not None]
    return min(v) if v else None


def _emax(rows, k="et1"):
    v = [r[k] for r in rows if r[k] is not None]
    return max(v) if v else None


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
            fires, ext = _plan_fires(c, rows, sid, now)
            c.executemany(
                "INSERT INTO events (eid,type,label,sev,link,t0,t1,first_seen,last_seen,last_sid,n,doc) VALUES (?,?,?,?,?,?,?,?,?,?,1,?) "
                "ON CONFLICT(eid) DO UPDATE SET "
                f"label=CASE WHEN {newer} THEN excluded.label ELSE events.label END, sev=CASE WHEN {newer} THEN excluded.sev ELSE events.sev END, "
                f"link=CASE WHEN {newer} THEN excluded.link ELSE events.link END, doc=CASE WHEN {newer} THEN excluded.doc ELSE events.doc END, "
                "t0=MIN(COALESCE(events.t0,excluded.t0), COALESCE(excluded.t0,events.t0)), t1=MAX(COALESCE(events.t1,excluded.t1), COALESCE(excluded.t1,events.t1)), "
                "first_seen=MIN(events.first_seen, excluded.first_seen), last_seen=MAX(events.last_seen, excluded.last_seen), "
                "n=events.n + (CASE WHEN COALESCE(events.last_sid,'')!=excluded.last_sid THEN 1 ELSE 0 END), "
                "last_sid=excluded.last_sid, resolved=CASE WHEN events.type='vuln' THEN 0 ELSE events.resolved END", rows)
            c.executemany("INSERT OR IGNORE INTO event_fires (eid,sid,seen,t0,t1,label) VALUES (?,?,?,?,?,?)", fires)
            c.executemany("UPDATE event_fires SET t1=? WHERE eid=? AND sid=?", ext)
            c.execute("DELETE FROM event_fires WHERE seen < ?", (time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - FIRE_KEEP_DAYS * 86400)),))
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


def open_events(types=None, sev=None, q=None, limit=2000, merge=False, exclude=None, ids_only=False):
    """Unchecked, unresolved events (any age), most severe then newest first. Repeats of one condition are one row.
    exclude: event types left out entirely (rows, counts and total), e.g. {'vuln'} for the Open events page, whose
    Fix-list items live on the Fix list page instead.
    ids_only: just [{"eid", "members", "last_sid"}] of every row (the event reviewer's work list, corr_llm.open_rows)."""
    c = _c()
    acks = store.acks_load(c)
    alert_ok = {r[0] for r in c.execute("SELECT id FROM alerts WHERE cleared=0 AND held=0 AND source!='review'")}
    groups = {}
    for r in c.execute("SELECT * FROM events WHERE resolved=0 ORDER BY COALESCE(t1,0), last_seen"):  # oldest -> newest
        eid = r["eid"]
        if exclude and r["type"] in exclude:
            continue
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
                    "et0": _emin(g["members"]), "et1": _emax(g["members"]), "repeats": len(g["members"]), "last_sid": newest["last_sid"], "ips": d.get("ips") or [], "acks": [{"type": t, "key": k} for t, k in dict.fromkeys(todo)]})
    if ids_only:
        return [{"eid": x["eid"], "members": x["members"], "last_sid": x["last_sid"]} for x in out]
    if merge:
        out = merge_flows(out)
    out.sort(key=lambda e: (SEV_RANK.get((e["sev"] or "").lower(), 2), -(e["t1"] or 0), e["eid"]))
    shown = out[:limit]
    return {"events": shown, "total": sum(counts.values()), "counts": counts, "shown": len(shown), "extra": extras(shown) if shown else {}}


_FLOW = re.compile(r"^(?P<pre>.*?)->\s*(?P<dst>.*?)\s*(?:\((?P<ip>[0-9a-f.:]+)\))?\s+(?P<rest>\d+/(?:tcp|udp).*)$", re.I)


_VARIANT_KINDS = ("hnet-proc", "hnet-in", "net-new")  # host findings: hf|<kind>|<host>|<process>|<remote variant>


def _merge_variants(rows):
    """Host findings of one process on one system (same kind, host and executable) that differ only in the remote
    side (destination IPs/names, source IPs) become one row \"... (N variants)\"; the variants ride along in `children`."""
    buckets, out = {}, []
    for r in rows:
        p = str(r["eid"]).split("|")
        if r["type"] == "host" and p[0] == "hf" and len(p) >= 5 and p[1] in _VARIANT_KINDS:
            buckets.setdefault(tuple(p[1:4]), []).append((r, "|".join(p[4:])))
        else:
            out.append(r)
    for (kind, host, proc), L in buckets.items():
        if len(L) < 2:
            out.append(L[0][0]); continue
        L.sort(key=lambda t: (t[0]["t1"] or 0, t[0]["last_seen"] or 0))  # oldest -> newest
        top = dict(L[-1][0])
        kids = [{"eid": r["eid"], "dst": v, "ip": v, "ips": [], "detail": r["label"], "sev": r["sev"], "first_seen": r["first_seen"],
                 "last_seen": r["last_seen"], "t0": r["t0"], "t1": r["t1"], "et0": r.get("et0"), "et1": r.get("et1"), "n": r["n"]} for r, v in reversed(L)]
        txt = f"{host}: {proc} - {kind} - {len(L)} variants"
        it = dict(top.get("item") or {}); it["text"] = txt
        top["item"] = it; top["label"] = txt
        top["ips"] = list(dict.fromkeys(ip for r, _ in reversed(L) for ip in r["ips"]))
        top["acks"] = [{"type": t, "key": k} for t, k in dict.fromkeys((a["type"], a["key"]) for r, _ in reversed(L) for a in r["acks"])]
        top["members"] = list(dict.fromkeys(e for r, _ in reversed(L) for e in r["members"]))[:40]
        top["n"] = sum(r["n"] for r, _ in L); top["repeats"] = sum(r["repeats"] for r, _ in L)
        top["first_seen"] = min(r["first_seen"] for r, _ in L); top["last_seen"] = max(r["last_seen"] for r, _ in L)
        top["et0"] = min((r.get("et0") for r, _ in L if r.get("et0") is not None), default=None)
        top["et1"] = max((r.get("et1") for r, _ in L if r.get("et1") is not None), default=None)
        top["children"] = kids
        out.append(top)
    return out


def merge_flows(rows):
    """Display grouping for the Open events page: segmentation findings of one device and one flow type ("10.0.0.1 -
    lateral-movement/admin port 22 (tcp) ...: -> A", "... -> B") become one row "... -> multiple devices (N)"; the instances
    (each destination with its own IPs) ride along in `children` for the detail window. Check-off covers every instance."""
    buckets, out = {}, []
    rows = _merge_variants(rows)
    for r in rows:
        if r.get("children"):
            out.append(r); continue
        it = r.get("item") or {}
        m = _FLOW.match(it.get("detail") or "") if r["type"] == "finding" and it.get("kind") == "segmentation" else None
        if not m:
            out.append(r); continue
        buckets.setdefault((it.get("device"), m["pre"].strip()), []).append((r, m))
    for (dev, pre), L in buckets.items():
        if len(L) < 2:
            out.append(L[0][0]); continue
        L.sort(key=lambda t: (t[0]["t1"] or 0, t[0]["last_seen"] or 0))  # oldest -> newest
        top = dict(L[-1][0])
        kids = [{"eid": r["eid"], "dst": m["dst"], "ip": m["ip"] or "", "ips": r["ips"], "detail": (r.get("item") or {}).get("detail") or r["label"],
                 "sev": r["sev"], "first_seen": r["first_seen"], "last_seen": r["last_seen"], "t0": r["t0"], "t1": r["t1"], "et0": r.get("et0"), "et1": r.get("et1"), "n": r["n"]} for r, m in reversed(L)]
        dsts = {k["ip"] or k["dst"] for k in kids}
        txt = f"{pre} -> multiple devices ({len(dsts)})"
        it = dict(top.get("item") or {}); it["detail"] = txt
        top["item"] = it
        top["label"] = f"segmentation: {it.get('name') or dev} - {txt}"
        top["ips"] = list(dict.fromkeys(ip for r, _ in reversed(L) for ip in r["ips"]))
        top["acks"] = [{"type": t, "key": k} for t, k in dict.fromkeys((a["type"], a["key"]) for r, _ in reversed(L) for a in r["acks"])]
        top["members"] = list(dict.fromkeys(e for r, _ in reversed(L) for e in r["members"]))[:40]
        top["n"] = sum(r["n"] for r, _ in L); top["repeats"] = sum(r["repeats"] for r, _ in L)
        top["first_seen"] = min(r["first_seen"] for r, _ in L); top["last_seen"] = max(r["last_seen"] for r, _ in L)
        top["et0"] = min((r.get("et0") for r, _ in L if r.get("et0") is not None), default=None)
        top["et1"] = max((r.get("et1") for r, _ in L if r.get("et1") is not None), default=None)
        top["children"] = kids
        out.append(top)
    return out


def extras(rows):
    """AI notes (verdicts), event reviewer classifications, people's notes and times seen for the rows, keyed by each row's event id.
    A grouped row takes the newest variant that has one."""
    out = {"notes": {}, "classes": {}, "unotes": {}, "seen": {}}
    allids = [m for r in rows for m in r["members"]]
    try:
        import enrich, corr_llm, kb
        N, C, U = enrich.load(allids), corr_llm.classes(allids, pending=True), kb.event_notes(allids)
    except Exception as e:  # noqa: BLE001 - the page works without them
        print(f"eventstore extras: {e}", file=sys.stderr)
        N = C = U = {}
    for r in rows:
        for m in reversed(r["members"]):
            for src, dst in ((N, "notes"), (C, "classes"), (U, "unotes")):
                if m in src and r["eid"] not in out[dst]:
                    out[dst][r["eid"]] = src[m]
        out["seen"][r["eid"]] = {"n": r["n"], "first": r["first_seen"], "last": r["last_seen"]}
    # related events from the stored (decision model / event reviewer) verdicts, so rows older than the loaded snapshot
    # still get their Related count, the linked events, their artifacts and the decision model's confidence
    try:
        import corr_llm
        R, _ = corr_llm.related_view({r["eid"]: set(r["members"]) | {r["eid"]} for r in rows}, detail=False)
        out["related_n"] = {k: len(v) for k, v in R.items()}
    except Exception as e:  # noqa: BLE001 - the page works without them
        print(f"eventstore related: {e}", file=sys.stderr)
    return out


def related(eid, members):
    """Related popover of one Open events row: linked events (stored verdicts), artifacts, decision model confidence."""
    import corr_llm
    ms = [*members, eid]  # oldest -> newest
    R, partners = corr_llm.related_view({eid: set(ms)})
    return {"related": R.get(eid, []), "events": _ev_view(partners | {eid})}


def detail(eid):
    """Open events modal: every stored occurrence of one event (all variants of the grouped condition, newest first)
    and its related events, one line per related condition (their own repeats are counted, not listed)."""
    c = _c()
    gk = gkey(eid)
    p = str(eid).split("|")
    pre = "|".join(p[:3]) + "|" if p[0] == "f" and len(p) >= 4 else str(eid)
    occ = []
    for r in c.execute("SELECT eid,label,sev,link,t0,t1,et0,et1,first_seen,last_seen,n,resolved FROM events WHERE eid >= ? AND eid < ? ORDER BY COALESCE(t1,0) DESC, last_seen DESC",
                       (pre, pre + "\uffff")):
        if r["resolved"] == 0 and gkey(r["eid"]) == gk or r["eid"] == eid:
            occ.append({k: r[k] for k in ("eid", "label", "sev", "link", "t0", "t1", "et0", "et1", "first_seen", "last_seen", "n")})
    if not occ:
        return {"occurrences": [], "related": [], "events": {}}
    members = [o["eid"] for o in occ][:300]
    ch = members
    fires = [dict(r) for r in c.execute(f"SELECT eid,sid,seen,t0,t1,et0,et1,label FROM event_fires WHERE eid IN ({','.join('?' * len(ch))}) "
                                        "ORDER BY seen DESC, COALESCE(t1,0) DESC LIMIT 1000", ch)]
    r0 = c.execute("SELECT MIN(seen) FROM event_fires").fetchone()
    since = r0[0] if r0 else None
    # related events of each distinct event id that fired (one line per related condition, its repeats merged), with the
    # artifacts and Elasticsearch queries of those links; the window nests them under each firing
    import corr_llm
    fe = list(dict.fromkeys([f["eid"] for f in fires] or members[:1]))[:60]
    R, partners = corr_llm.related_view({e: {e} for e in fe})
    DI = corr_llm.decision_inputs_view(fe)  # the events passed in to each determination (the firings show the ones in their span)
    ev = _ev_view(partners | set(fe) | {x["id"] for L in DI.values() for d in L for x in d["inputs"]})
    by = {}
    for e in fe:
        seen = {}
        for r in R.get(e, []):
            g = gkey(r["id"])
            x = seen.setdefault(g, {**{k: v for k, v in r.items() if k != "llm_artifacts"}, "variants": 0, "llm_artifacts": []})
            if r.get("llm_at"):
                x.setdefault("llm_ats", []).append(r["llm_at"])  # review time of each merged link (picks the firing it belongs to)
            have = {(a["kind"], a["value"]) for a in x["llm_artifacts"]}
            for a in r.get("llm_artifacts") or []:
                if (a["kind"], a["value"]) not in have:
                    have.add((a["kind"], a["value"])); x["llm_artifacts"].append(a)
            x["variants"] += 1
            if (r.get("llm_conf") or 0) > (x.get("llm_conf") or 0):
                x.update({k: v for k, v in r.items() if k not in ("llm_artifacts", "llm_ats")})
        by[e] = sorted(seen.values(), key=lambda x: -(x.get("llm_conf") or 0))[:40]
    return {"fires": fires, "fires_since": since, "occurrences": occ[:500], "n_occurrences": len(occ), "by_event": by, "events": ev,
            "decisions": DI,
            "inputs_since": corr_llm.decision_inputs_since()}


def decision_inputs(eid):
    """Posture / Alerts classification pop-up: the events passed in to this event's determinations, with their records."""
    import corr_llm
    DI = corr_llm.decision_inputs_view([eid]).get(eid, [])
    return {"decisions": DI, "events": _ev_view({x["id"] for d in DI for x in d["inputs"]})}


def artifact_event(eid):
    """One stored event as {label, host_ips, dst_ips, ips, arts} for kb.event_artifact_keys (the verdict scope picker)."""
    r = _c().execute("SELECT label, doc FROM events WHERE eid=?", (str(eid),)).fetchone()
    if not r:
        return {}
    try:
        dd = json.loads(r["doc"] or "{}")
    except ValueError:
        dd = {}
    return {"label": r["label"] or "", "host_ips": dd.get("host_ips") or [], "dst_ips": dd.get("dst_ips") or [], "ips": dd.get("ips") or [],
            "arts": dd.get("arts") or [], "item": {"key": (dd.get("item") or {}).get("key") or ""}}


def _ev_view(eids):
    """Minimal event records (type, label, link, time, host IPs) for the Related popover."""
    eids, out = list(eids), {}
    c = _c()
    for i in range(0, len(eids), 500):
        ch = eids[i:i + 500]
        for r in c.execute(f"SELECT eid, type, label, sev, link, t0, t1, doc FROM events WHERE eid IN ({','.join('?' * len(ch))})", ch):
            try:
                dd = json.loads(r["doc"] or "{}")
            except ValueError:
                dd = {}
            out[r["eid"]] = {"type": r["type"], "label": r["label"], "sev": r["sev"], "link": r["link"] or "", "t0": r["t0"], "t1": r["t1"],
                             "host_ips": (dd.get("host_ips") or dd.get("ips") or [])[:6], "dst_ips": (dd.get("dst_ips") or [])[:6], "arts": (dd.get("arts") or [])[:20]}
    for e in eids:  # partner gone from the store (pruned): still list it by id
        out.setdefault(e, {"type": e.split("|")[0], "label": e, "link": "", "t0": None, "t1": None})
    return out


def k_in(acks, ref):
    return ref[1] in (acks.get(ref[0]) or {})





VERDICTS = ("suspicious", "expected", "benign")


def alert_ref(a):
    """The event an alert row is about: a review alarm (key ev|<eid>) carries the reviewed event's id, where its AI
    classification, research and notes are stored; a watcher detection is its own event alert|<id>."""
    k = str(a.get("key") or "")
    return k[3:] if k.startswith("ev|") and len(k) > 3 else f"alert|{a['id']}"


def alert_verdict(ref, X):
    """(verdict, source) of one alert: a person's verdict wins, then the event reviewer's classification, then the
    decision model, else unreviewed."""
    for n in reversed((X.get("unotes") or {}).get(ref) or []):
        if n.get("verdict") in VERDICTS and n.get("status", "approved") != "rejected":
            return n["verdict"], "person"
    c = (X.get("classes") or {}).get(ref)
    if c and c.get("label") in VERDICTS:
        return c["label"], "ai"
    if c and c.get("pending"):  # its correlated group has not settled yet: the event reviewer labels it then
        return "pending", "ai"
    return "unreviewed", ""


def web_research(eids, per=12):
    """Web searches and page reads the AI ran while reviewing these events (corr_llm.db web_queries), newest first:
    {eid: [{ts, kind, query, why, results, urls, error, model, cached, own}]}. own=False: the event was a candidate
    while the AI reviewed a related event (anchor)."""
    eids, out = set(eids), {}
    if not eids:
        return out
    import corr_llm
    with corr_llm._db() as c:
        ch = list(eids)
        rows = []
        for i in range(0, len(ch), 500):
            rows += c.execute("SELECT ts, anchor, candidates, model, kind, query, why, results, urls, error, cached FROM web_queries "
                              "WHERE anchor IN (SELECT value FROM json_each(?)) AND COALESCE(purpose,'') != 'manual-test'", (json.dumps(ch[i:i + 500]),)).fetchall()
        q = [json.dumps(e) for e in ch]
        for r in c.execute("SELECT ts, anchor, candidates, model, kind, query, why, results, urls, error, cached FROM web_queries "
                           "WHERE ts > ? AND COALESCE(purpose,'') != 'manual-test' AND candidates != '[]'", (time.time() - 31 * 86400,)):
            if any(x in (r[2] or "") for x in q):
                rows.append(r)
    for ts, anchor, cands, model, kind, query, why, n, urls, err, cached in sorted(set(rows), key=lambda r: -r[0]):
        try:
            U = [u for u in json.loads(urls or "[]") if isinstance(u, dict) and str(u.get("url", "")).startswith(("http://", "https://"))][:8]
        except ValueError:
            U = []
        try:
            C = set(json.loads(cands or "[]"))
        except ValueError:
            C = set()
        for e in ({anchor} | C) & eids:
            L = out.setdefault(e, [])
            if len(L) < per:
                L.append({"ts": ts, "kind": kind, "query": str(query or "")[:300], "why": str(why or "")[:400], "results": n, "error": str(err or "")[:200] or None,
                          "urls": [{"url": u["url"], "title": str(u.get("title") or "")[:140]} for u in U], "model": model, "cached": bool(cached),
                          "own": e == anchor, "anchor": "" if e == anchor else anchor})
    return out


def alert_view(alerts, related=True, art_limit=6):
    """Alerts page: each alert's verdict, the research done on it (AI classification + web sources, research note,
    decision model), people's notes and notes on its artifacts. Returns (rows with eid/verdict/vsrc set, extra keyed by eid)."""
    if not alerts:
        return alerts, {}
    for a in alerts:
        a["eid"] = alert_ref(a)
    rows, seen = [], set()
    for a in alerts:
        if a["eid"] in seen:
            continue
        seen.add(a["eid"])
        ms = list(dict.fromkeys([f"alert|{a['id']}", a["eid"]]))
        rows.append({"eid": a["eid"], "members": ms, "n": 1, "first_seen": a["ts"], "last_seen": a["ts"]})
    if related:
        X = extras(rows)
    else:  # big detection lists: verdict sources only (related_view over thousands of rows is slow)
        X = {"notes": {}, "classes": {}, "unotes": {}}
        try:
            import enrich, corr_llm, kb
            allids = [m for r in rows for m in r["members"]]
            N, C, U = enrich.load(allids), corr_llm.classes(allids, pending=True), kb.event_notes(allids)
            for r in rows:
                for m in reversed(r["members"]):
                    for src, dst in ((N, "notes"), (C, "classes"), (U, "unotes")):
                        if m in src and r["eid"] not in X[dst]:
                            X[dst][r["eid"]] = src[m]
        except Exception as e:  # noqa: BLE001 - the page works without them
            print(f"alert_view: {e}", file=sys.stderr)
    # notes people (or the profiler) wrote on the artifacts these alerts carry: IPs, domains, processes, users
    an, at = {}, {}
    if art_limit:
        try:
            import kb
            EV = _ev_view([r["eid"] for r in rows])
            for a in alerts:
                if a["eid"] in an:
                    continue
                ev = EV.get(a["eid"]) or {}
                keys = kb.event_artifact_keys({"label": f"{a.get('text') or ''} {ev.get('label') or ''}", "ips": [t for t in a.get("targets") or [] if isinstance(t, str)],
                                               "host_ips": ev.get("host_ips"), "dst_ips": ev.get("dst_ips"), "arts": ev.get("arts")})
                hits = kb.notes_by_artifacts(keys, limit=art_limit, use=False)  # a person viewing alerts does not count as using the notes
                if hits:  # one copy of each note (art_note_text), alerts reference it by id with the artifacts that matched
                    an[a["eid"]] = [{"id": n["id"], "matched": hit} for _sc, hit, n in hits]
                    for _sc, _hit, n in hits:
                        at.setdefault(str(n["id"]), {"id": n["id"], "subject": n["subject"], "category": n.get("category") or "",
                                                     "text": str(n.get("text") or "")[:700], "author": n.get("author") or "", "model": n.get("model") or "",
                                                     "via": n.get("via") or "", "status": n.get("status") or "", "updated": n.get("updated"),
                                                     "ts": n.get("ts"), "last_used": n.get("last_used"), "expires": n.get("expires")})
        except Exception as e:  # noqa: BLE001
            print(f"alert_view artifact notes: {e}", file=sys.stderr)
    X["art_notes"], X["art_note_text"] = an, at
    try:
        W = web_research([m for r in rows for m in r["members"]])
        X["web"] = {}
        for r in rows:
            seen_q = {}
            for m in r["members"]:
                for w in sorted(W.get(m, []), key=lambda w: -w["ts"]):
                    k = (w["kind"], w["query"].strip().lower())  # the same look-up re-run by later reviews: one row, counted
                    if k in seen_q:
                        seen_q[k]["times"] += 1
                        seen_q[k]["own"] = seen_q[k]["own"] or w["own"]
                        continue
                    seen_q[k] = {**w, "times": 1}
                    X["web"].setdefault(r["eid"], []).append(seen_q[k])
            if r["eid"] in X["web"]:
                X["web"][r["eid"]].sort(key=lambda w: -w["ts"])
    except Exception as e:  # noqa: BLE001
        print(f"alert_view web research: {e}", file=sys.stderr)
    for ns in (X.get("unotes") or {}).values():  # the page shows text, author, verdict, status only
        for n in ns:
            n.pop("artifacts", None); n.pop("label", None)
    for a in alerts:
        a["verdict"], a["vsrc"] = alert_verdict(a["eid"], X)
    return alerts, X


def detections(limit=300, verdict=None):
    """Held detections (watcher / scan findings that were not promoted to alarms) with their verdicts, newest first,
    plus verdict counts over every alert and detection kept (30 days)."""
    c = store._dc()
    rows = [store._arow(r) for r in c.execute("SELECT * FROM alerts WHERE cleared=0 AND held=1 ORDER BY id DESC")]
    allrows = rows + store.alerts_recent(2000)
    for a in allrows:
        a["eid"] = alert_ref(a)
    refs = list(dict.fromkeys(a["eid"] for a in allrows))
    X = {"classes": {}, "unotes": {}}
    try:
        import corr_llm, kb
        ids = list(dict.fromkeys(refs + [f"alert|{a['id']}" for a in allrows]))
        C, U = corr_llm.classes(ids, pending=True), kb.event_notes(ids)
        for a in allrows:
            for m in (a["eid"], f"alert|{a['id']}"):
                for src, dst in ((C, "classes"), (U, "unotes")):
                    if m in src and a["eid"] not in X[dst]:
                        X[dst][a["eid"]] = src[m]
    except Exception as e:  # noqa: BLE001
        print(f"detections: {e}", file=sys.stderr)
    counts = {"alarms": {}, "detections": {}}
    pick = []
    for i, a in enumerate(allrows):
        v, _ = alert_verdict(a["eid"], X)
        b = counts["detections" if i < len(rows) else "alarms"]
        b[v] = b.get(v, 0) + 1
        if i < len(rows) and (not verdict or v == verdict):
            pick.append(a)
    shown, X2 = alert_view(pick[:limit], related=False, art_limit=4)
    return {"alerts": shown, "total": len(rows), "matching": len(pick), "counts": counts, "extra": X2}


def posture_items(raw, analysis):
    """The rows of one Posture page (a snapshot or time range) that get an Occurred time, as evtime items: baseline
    findings (f|...), host findings (hf|...) and threat-intel hits (ti|...), with the range's window. Ids match the
    page's evId()s. Built from the range's own data: a time range's correlation map is its nightly report's, which
    lists other rows."""
    raw, analysis = raw or {}, analysis or {}
    gen = _ts_iso(raw.get("generated"))
    if not gen:
        return []
    w0, w1 = gen - 3600 * float(raw.get("hours") or 24), gen
    devices = raw.get("devices") or {}
    mac2ip = {str(d.get("mac", "")).lower(): ip for ip, d in devices.items() if d.get("mac")}
    out = []
    for f in analysis.get("findings") or []:
        dev = str(f.get("device") or "")
        ip = dev if re.fullmatch(r"[\d.]+", dev) else mac2ip.get(dev.lower(), "")
        out.append({"eid": f"f|{f.get('kind')}|{dev}|{f.get('detail', '')}", "type": "finding", "label": f.get("detail", ""),
                    "t0": w0, "t1": w1, "host_ips": [ip] if ip else [], "item": None})
    for f in (raw.get("hosts") or {}).get("findings") or []:
        out.append({"eid": f"hf|{f.get('key', '')}", "type": "host", "label": f.get("text", ""), "t0": w0, "t1": w1, "host_ips": [], "item": None})
    ti = raw.get("threat_intel") or {}
    for h in ti.get("ip_hits_in") or []:
        out.append({"eid": f"ti|in|{h.get('ip')}", "type": "ti", "label": "", "t0": w0, "t1": w1, "host_ips": [], "item": None})
    for h in ti.get("ip_hits_out") or []:
        out.append({"eid": f"ti|out|{h.get('ip')}", "type": "ti", "label": "", "t0": w0, "t1": w1, "host_ips": [], "item": None})
    for h in [*(ti.get("domain_hits") or []), *(ti.get("new_domains") or [])]:
        dn = h.get("domain") or h.get("name")
        if dn:
            out.append({"eid": f"ti|dom|{dn}", "type": "ti", "label": "", "t0": w0, "t1": w1, "host_ips": [], "item": None})
    return out


def _ts_iso(v):
    from datetime import datetime, timezone
    try:
        d = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
    except ValueError:
        return None
    return (d if d.tzinfo else d.replace(tzinfo=timezone.utc)).timestamp()


def window_times(items, queue=None):
    """Posture: when each row of one time range happened -> ({eid: [et0, et1]}, pending). items: posture_items().
    Record times come from the event_times cache (filled by evtime.py on the host); missing ones are queued at the host
    broker (POST /evtime) and show up on a later call; a row with no record gets [None, None]."""
    c = _c()
    out, miss = {}, []
    for it in items or []:
        if it.get("t1") is None:
            continue
        r = c.execute("SELECT et0, et1 FROM event_times WHERE eid=? AND w0=? AND w1=?",
                      (it["eid"], int(it["t0"] if it.get("t0") is not None else it["t1"]), int(it["t1"]))).fetchone()
        if r:
            out[it["eid"]] = [r[0], r[1]]
        else:
            miss.append(it)
    if miss:
        try:
            (queue or _queue_broker)(miss)
        except Exception as e:  # noqa: BLE001 - broker down: the page shows the times it has
            print(f"eventstore: evtime queue failed: {e}", file=sys.stderr)
    return out, len(miss)


def _queue_broker(items):
    import corr_llm
    for i in range(0, len(items), 300):  # broker request bodies are capped at 200 kB
        corr_llm.broker("/evtime", {"items": items[i:i + 300]}, timeout=15)
