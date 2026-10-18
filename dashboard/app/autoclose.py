"""Security Triage auto-close (More -> Configuration).

When enabled, events whose AI research note (enrich.py) has verdict "expected" and/or "benign" are checked off
automatically, i.e. moved to the closed findings on the Checked page, with the note "auto-closed: AI verdict ...".

Only events that have a check-off list can be closed: baseline findings (f|...), endpoint/host findings (hf|...),
fix-list issues (iss|...; segmentation issues map to the shared "seg" flow key). Other researched events (IDS
signatures, watcher alerts, gateway events, threat intel, admin sessions) have no checklist and are only counted.

Rules:
  - an item a person already checked off is left alone;
  - an item that was auto-closed and later un-checked by a person is never auto-closed again (log state "reopened");
  - when an auto-closed item's verdict changes to something not enabled (e.g. the AI later says "suspicious"),
    it is reopened automatically;
  - turning an option off stops new closures; "reopen" (reopen_all) restores everything auto-closed.
Settings live in the store's meta table (key "autoclose"); the closure log in table autoclose_log.
"""
import json, sys, threading, time

import enrich
import store
from risk import seg_key_finding, seg_key_issue

KINDS = ("expected", "benign")
NOTE_PREFIX = "auto-closed: AI verdict "
_lock = threading.Lock()
_last = {"at": None, "result": None}


def _c():
    c = store.connect()
    c.execute("""CREATE TABLE IF NOT EXISTS autoclose_log (type TEXT NOT NULL, key TEXT NOT NULL, eid TEXT, verdict TEXT,
                 model TEXT, at TEXT, state TEXT NOT NULL, PRIMARY KEY (type, key))""")
    return c


def settings(c=None):
    c = c or _c()
    r = c.execute("SELECT v FROM meta WHERE k='autoclose'").fetchone()
    s = json.loads(r[0]) if r else {}
    return {"expected": bool(s.get("expected")), "benign": bool(s.get("benign")),
            "updated_by": s.get("updated_by"), "updated_at": s.get("updated_at")}


def set_settings(expected, benign, user):
    c = _c()
    s = {"expected": bool(expected), "benign": bool(benign), "updated_by": user, "updated_at": store.now_iso()}
    with store.tx(c):
        c.execute("INSERT OR REPLACE INTO meta VALUES ('autoclose', ?)", (json.dumps(s),))
    return s


def fnv(s):
    """Same hash as fnv() in app.js (UTF-16 code units, base36) - ack keys for baseline findings."""
    h = 0x811c9dc5
    b = s.encode("utf-16-le")
    for i in range(0, len(b), 2):
        h ^= b[i] | (b[i + 1] << 8)
        h = (h * 0x01000193) & 0xFFFFFFFF
    d, out = "0123456789abcdefghijklmnopqrstuvwxyz", ""
    while True:
        h, r = divmod(h, 36)
        out = d[r] + out
        if not h:
            return out


def _js(v):
    return "undefined" if v is None else str(v)


def _items(raw, analysis, open_issues):
    """[(eid, ack_type, ack_key, label)] for every closable event in the snapshot."""
    out = []
    for f in (analysis or {}).get("findings") or []:
        eid = f"f|{f.get('kind')}|{f.get('device') or ''}|{f.get('detail', '')}"
        sk = seg_key_finding(f)
        out.append((eid, "seg", sk, f"Segmentation: {f.get('detail', '')}") if sk else
                   (eid, "finding", fnv(f"{_js(f.get('device'))}|{_js(f.get('kind'))}|{_js(f.get('detail'))}"),
                    f"{f.get('kind')}: {f.get('detail', '')}"))
    for f in ((raw or {}).get("hosts") or {}).get("findings") or []:
        if f.get("key"):
            out.append((f"hf|{f['key']}", "host", f["key"], f.get("text", "")))
    for i in open_issues or []:
        sk = seg_key_issue(i["key"])
        out.append((f"iss|{i['key']}", "seg" if sk else "issue", sk or i["key"], f"{i.get('title', '')} — {i.get('target', '')}"))
    return out


def run(raw, analysis, open_issues, other_eids=(), dry=False):
    """Apply the enabled options to the snapshot. Returns counts (also the preview for the Configuration card)."""
    with _lock:
        c = _c()
        s = settings(c)
        on = {k for k in KINDS if s[k]}
        items = _items(raw, analysis, open_issues)
        notes = enrich.load([i[0] for i in items] + list(other_eids))
        acks = store.acks_load(c)
        log = {(r["type"], r["key"]): dict(r) for r in c.execute("SELECT * FROM autoclose_log")}
        res = {k: {"closable": 0, "would_close": 0, "closed_now": 0, "auto_closed": 0, "reopened_by_user": 0, "no_checklist": 0}
               for k in KINDS}
        res["reopened_verdict_changed"] = 0
        seen = set()
        for eid, typ, key, label in items:
            if (typ, key) in seen:
                continue
            seen.add((typ, key))
            n = notes.get(eid) or {}
            v = n.get("verdict")
            a = (acks.get(typ) or {}).get(key)
            lg = log.get((typ, key))
            auto = bool(a and str(a.get("note") or "").startswith(NOTE_PREFIX))
            if v not in KINDS:
                if auto and lg and lg["state"] == "closed" and not dry:  # verdict changed since: bring it back
                    store.ack_set(typ, key, False, c=c)
                    with store.tx(c):
                        c.execute("UPDATE autoclose_log SET state='reopened-verdict', verdict=?, at=? WHERE type=? AND key=?",
                                  (v or "", store.now_iso(), typ, key))
                    res["reopened_verdict_changed"] += 1
                continue
            r = res[v]
            r["closable"] += 1
            if lg and lg["state"] == "closed" and not a:  # a person un-checked it after we closed it
                if not dry:
                    with store.tx(c):
                        c.execute("UPDATE autoclose_log SET state='reopened', at=? WHERE type=? AND key=?", (store.now_iso(), typ, key))
                lg["state"] = "reopened"
            if lg and lg["state"] == "reopened":
                r["reopened_by_user"] += 1
                continue
            if auto:
                r["auto_closed"] += 1
                continue
            if a:
                continue  # checked off by a person
            r["would_close"] += 1
            if v in on and not dry:
                note = f"{NOTE_PREFIX}{v} ({n.get('model') or 'AI'}): {n.get('summary') or ''}"
                store.ack_set(typ, key, True, note, label, c=c)
                with store.tx(c):
                    c.execute("INSERT OR REPLACE INTO autoclose_log VALUES (?,?,?,?,?,?, 'closed')",
                              (typ, key, eid, v, str(n.get("model") or "")[:80], store.now_iso()))
                r["closed_now"] += 1
                r["auto_closed"] += 1
                r["would_close"] -= 1
        for eid in other_eids:  # researched events without a check-off list
            v = (notes.get(eid) or {}).get("verdict")
            if v in KINDS:
                res[v]["no_checklist"] += 1
        res["settings"] = s
        if not dry:
            _last.update(at=store.now_iso(), result=res)
            closed = sum(res[k]["closed_now"] for k in KINDS)
            if closed or res["reopened_verdict_changed"]:
                print(f"autoclose: closed {closed}, reopened {res['reopened_verdict_changed']} (verdict changed)", file=sys.stderr)
        res["last_run"] = _last["at"]
        return res


def reopen_all(user, kind=None):
    """Un-check every item that auto-close closed (optionally only one verdict); they won't be auto-closed again."""
    with _lock:
        c = _c()
        acks = store.acks_load(c)
        rows = c.execute("SELECT type, key, verdict FROM autoclose_log WHERE state='closed'").fetchall()
        n = 0
        for r in rows:
            if kind and r["verdict"] != kind:
                continue
            a = (acks.get(r["type"]) or {}).get(r["key"])
            if a and str(a.get("note") or "").startswith(NOTE_PREFIX):
                store.ack_set(r["type"], r["key"], False, c=c)
                n += 1
            with store.tx(c):
                c.execute("UPDATE autoclose_log SET state='reopened', at=? WHERE type=? AND key=?", (store.now_iso(), r["type"], r["key"]))
        print(f"autoclose: {user} reopened {n} auto-closed item(s){' (' + kind + ')' if kind else ''}", file=sys.stderr)
        return n


def start(get_inputs, every=300):
    """Background loop: get_inputs() -> (raw, analysis, open_issues, other_eids) for the newest snapshot."""
    def loop():
        time.sleep(20)
        while True:
            try:
                s = settings()
                if s["expected"] or s["benign"]:
                    inp = get_inputs()
                    if inp:
                        run(*inp)
            except Exception as e:  # noqa: BLE001 - never kill the server
                print(f"autoclose error: {e}", file=sys.stderr)
            time.sleep(every)
    threading.Thread(target=loop, daemon=True, name="autoclose").start()
