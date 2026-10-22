"""Suppress rules: hide a finding by signature name (optionally plus one artifact: ip, domain, user, process, port, file; the
artifact may be one of the event itself or of an event correlated with it).

A suppressed finding is checked off (it moves to More > Checked, note "suppressed: rule N ...") and a suppressed alert is
hidden from the feed and not pushed. Nothing is bypassed: the event stays in the correlation, is researched and reviewed like
any other, and if the reviewer classifies it as suspicious it moves back to the findings (corr_llm.reopen_checked) and
the rule does not close it again. Removing a rule brings back what it suppressed. Rules live in the store (suppress_rules).
Only events that have a check-off list (baseline / endpoint findings, fix-list items, triage alarms) and alerts can be hidden.
"""
import os, sys, threading, time

_ROOT = os.environ.get("NETMON_DIR", "/netmon")
if os.path.isdir(_ROOT) and _ROOT not in sys.path:
    sys.path.append(_ROOT)

import autoclose
import corr_llm
import store

NOTE_PREFIX = "suppressed: rule "
_lock = threading.Lock()


def _c():
    c = store.connect()
    c.execute("""CREATE TABLE IF NOT EXISTS suppress_log (type TEXT NOT NULL, key TEXT NOT NULL, rule INTEGER, eid TEXT,
                 at TEXT, state TEXT NOT NULL, PRIMARY KEY (type, key))""")
    for col, ddl in (("hits", "INTEGER DEFAULT 0"), ("last_sid", "TEXT")):  # match counter: once per snapshot the item is seen matching
        try:
            c.execute(f"ALTER TABLE suppress_log ADD COLUMN {col} {ddl}")
        except Exception:  # noqa: BLE001 - already there
            pass
    return c


def _targets(raw, analysis, open_issues, E):
    """{eid: [(ack type, key, label)]} for the events that have a check-off list."""
    out = {}
    for eid, typ, key, label in autoclose._items(raw, analysis, open_issues):
        out.setdefault(eid, []).append((typ, key, label))
    for eid in E:
        if eid not in out:
            for typ, key in corr_llm._ack_keys(eid):
                out.setdefault(eid, []).append((typ, key, (E[eid] or {}).get("label") or eid))
    return out


def apply(E, raw, analysis, open_issues, related=None, sid=None):
    """Check off the events a rule covers. Idempotent; a person (or the reviewer) un-checking one is respected."""
    rules = store.suppress_list()
    if not rules or not E:
        return 0
    n = 0
    with _lock:
        c = _c()
        acks = store.acks_load(c)
        log = {(r["type"], r["key"]): r["state"] for r in c.execute("SELECT type, key, state FROM suppress_log")}
        def match(eid, ev):
            ips, arts, ctx = list(ev.get("ips") or []) + list(ev.get("dst_ips") or []), list(ev.get("arts") or []), ""
            for r_ in (related or {}).get(eid) or []:  # the artifacts of the correlated events count too
                o = E.get(r_.get("id")) or {}
                ips += list(o.get("ips") or []) + list(o.get("dst_ips") or [])
                arts += list(o.get("arts") or [])
                ctx += " " + str(o.get("label") or "")
            return next((r for r in rules if store.suppress_match(r, ev.get("label"), ips, arts, ctx)), None)

        # watcher alerts: hidden from the feed (cleared, not pushed) by a rule whose artifact is one of the alert's or its correlated events'
        al = {str(r["id"]): r for r in c.execute("SELECT id, cleared FROM alerts WHERE cleared=0")}
        for eid, ev in E.items():
            if not eid.startswith("alert|") or eid.split("|")[1] not in al:
                continue
            aid = eid.split("|")[1]
            rule = match(eid, ev)
            if not rule or log.get(("alert", aid)) == "reopened":
                continue
            with store.tx(c):
                c.execute("UPDATE alerts SET cleared=1, cleared_rule=?, cleared_at=?, read=1, pushed=1 WHERE id=? AND cleared=0", (-rule["id"], time.time(), int(aid)))
                c.execute("INSERT OR REPLACE INTO suppress_log VALUES (?,?,?,?,?, 'applied')", ("alert", aid, rule["id"], eid, store.now_iso()))
            n += 1
        for eid, items in _targets(raw, analysis, open_issues, E).items():
            ev = E.get(eid)
            if not ev:
                continue
            rule = match(eid, ev)
            if not rule:
                continue
            for typ, key, label in items:
                a = (acks.get(typ) or {}).get(key)
                st = log.get((typ, key))
                if sid and st in ("applied", None) and (a or st is None):  # matched again in this snapshot -> count it once per snapshot
                    with store.tx(c):
                        c.execute("UPDATE suppress_log SET hits=COALESCE(hits,0)+1, last_sid=? WHERE type=? AND key=? AND COALESCE(last_sid,'')!=?", (sid, typ, key, sid))
                if st == "applied" and not a:  # a person (or the review) un-checked it after we did
                    with store.tx(c):
                        c.execute("UPDATE suppress_log SET state='reopened', at=? WHERE type=? AND key=?", (store.now_iso(), typ, key))
                    continue
                if a or st == "reopened":
                    continue
                store.ack_set(typ, key, True, f"{NOTE_PREFIX}{rule['id']}: {rule['name']}" + (f" + {rule['art_type']} {rule['art']}" if rule.get("art_type") else ""), label, c=c)
                with store.tx(c):
                    c.execute("INSERT OR REPLACE INTO suppress_log (type, key, rule, eid, at, state, hits, last_sid) VALUES (?,?,?,?,?, 'applied', ?, ?)", (typ, key, rule["id"], eid, store.now_iso(), 1 if sid else 0, sid))
                n += 1
    if n:
        print(f"suppress: checked off {n} item(s)", file=sys.stderr)
    return n


def sweep_open(rid):
    """Check off every stored open event (Open findings page, any age) that a rule covers, not just the ones in the newest
    snapshot. Same ack identities as the page's own check-off (all grouped variants), logged so removing the rule reopens them."""
    import json
    import eventstore
    rule = next((r for r in store.suppress_list() if r["id"] == int(rid)), None)
    if not rule:
        return 0
    n = 0
    with _lock:
        c = _c()
        docs = {}
        for r in c.execute("SELECT eid, doc FROM events WHERE resolved=0"):
            try:
                docs[r["eid"]] = json.loads(r["doc"] or "{}")
            except ValueError:
                docs[r["eid"]] = {}
        acks = store.acks_load(c)
        log = {(r["type"], r["key"]): r["state"] for r in c.execute("SELECT type, key, state FROM suppress_log")}
        for e in eventstore.open_events(limit=10 ** 6)["events"]:
            if str(e["eid"]).startswith("alert|"):  # alerts are hidden by store.suppress_add itself
                continue
            ids = [e["eid"]] + list(e.get("members") or [])
            d = docs.get(e["eid"]) or {}
            ips = list(d.get("ips") or []) + list(d.get("dst_ips") or []) + list(e.get("ips") or [])
            if not store.suppress_match(rule, e["label"], ips, d.get("arts") or []):
                continue
            note = f"{NOTE_PREFIX}{rule['id']}: {rule['name']}" + (f" + {rule['art_type']} {rule['art']}" if rule.get("art_type") else "")
            for a in e["acks"]:
                typ, key = a["type"], a["key"]
                if (acks.get(typ) or {}).get(key) or log.get((typ, key)) == "reopened":
                    continue
                store.ack_set(typ, key, True, note, e["label"], c=c)
                with store.tx(c):
                    c.execute("INSERT OR REPLACE INTO suppress_log (type, key, rule, eid, at, state, hits, last_sid) VALUES (?,?,?,?,?, 'applied', 0, NULL)", (typ, key, rule["id"], e["eid"], store.now_iso()))
                n += 1
    if n:
        print(f"suppress: swept {n} stored open-event ack(s) for rule {rid}", file=sys.stderr)
    return n


def mark_reopened(typ, key):
    try:
        c = _c()
        with store.tx(c):
            c.execute("UPDATE suppress_log SET state='reopened', at=? WHERE type=? AND key=?", (store.now_iso(), typ, key))
    except Exception:  # noqa: BLE001
        pass


def remove(rid):
    """Delete a rule: un-check what it checked off and restore the alerts it hid -> (items reopened, alerts restored)."""
    with _lock:
        c = _c()
        rows = c.execute("SELECT type, key, state FROM suppress_log WHERE rule=?", (int(rid),)).fetchall()
        acks = store.acks_load(c)
        n = 0
        for r in rows:
            a = (acks.get(r["type"]) or {}).get(r["key"])
            if a and str(a.get("note") or "").startswith(NOTE_PREFIX):
                store.ack_set(r["type"], r["key"], False, c=c)
                n += 1
        with store.tx(c):
            c.execute("DELETE FROM suppress_log WHERE rule=?", (int(rid),))
        return n, store.suppress_remove(rid, c)


def counts():
    """{rule id: events checked off} + {rule id: alerts hidden}."""
    c = _c()
    ev = {r[0]: r[1] for r in c.execute("SELECT rule, count(*) FROM suppress_log WHERE state='applied' AND type!='alert' GROUP BY rule")}
    al = {-k: v for k, v in store.mute_counts(c).items() if k is not None and k < 0}
    return ev, al


def item_hits():
    """{"type|key": times matched} for the Suppressed table."""
    c = _c()
    return {f"{r[0]}|{r[1]}": r[2] or 0 for r in c.execute("SELECT type, key, hits FROM suppress_log WHERE state='applied' AND type!='alert'")}
