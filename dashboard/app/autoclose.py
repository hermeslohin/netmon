"""Security Triage auto-close (More -> Configuration).

Four options (settings reviewer_expected, reviewer_benign, researcher_expected, researcher_benign): close events the correlation reviewer LLM classified expected/benign
(corr_llm event_class), and/or events whose AI research note (enrich.py) has verdict "expected"/"benign". A source calling
the event suspicious/malicious blocks closing. Events are checked off automatically, i.e. moved to the closed findings on the Checked page, with the note "auto-closed: AI verdict ...".

Closed: the snapshot's checklist items - baseline findings (f|...), endpoint/host findings (hf|...), fix-list issues
(iss|...; segmentation issues map to the shared "seg" flow key) - and every event on the Open events page (any age: IDS
signatures, watcher alerts, gateway events, threat intel, admin sessions, older findings), using the same check-offs
that page writes. The extra keys of a grouped event are kept in autoclose_log.refs so a reopen restores them too.

Rules:
  - an item a person already checked off is left alone;
  - an item that was auto-closed and later un-checked by a person is never auto-closed again (log state "reopened");
  - when an auto-closed item's verdict changes to something not enabled (e.g. the AI later says "suspicious"),
    it is reopened automatically;
  - turning an option off stops new closures; "reopen" (reopen_all) restores everything auto-closed.
When: right after each review (research) job stores its notes (enrich.sh put -> `python /app/autoclose.py run`), so new
verdicts are applied once per review run; every 5 minutes from the dashboard's ingest thread (so new reviewer
classifications close without waiting for a review job); plus "Run now" on the Configuration page.
Settings live in the store's meta table (key "autoclose"); the closure log in table autoclose_log; the last pass in
meta "autoclose_last".
"""
import json, os, sys, threading

# store.py lives in the netmon root (/netmon in the container); add it before importing it, as server.py does.
_ROOT = os.environ.get("NETMON_DIR", "/netmon")
if os.path.isdir(_ROOT) and _ROOT not in sys.path:
    sys.path.append(_ROOT)

import enrich
import store
from risk import seg_key_finding, seg_key_issue

KINDS = ("expected", "benign")  # verdicts that close an item
SOURCES = ("reviewer", "researcher")  # who decided: the correlation reviewer's classification / the research note
OPTS = tuple(f"{src}_{k}" for src in SOURCES for k in KINDS)  # the four switches: reviewer_expected, reviewer_benign, ...
NOTE_PREFIX = "auto-closed: AI verdict "
_lock = threading.Lock()


def _init(c):
    c.execute("""CREATE TABLE IF NOT EXISTS autoclose_log (type TEXT NOT NULL, key TEXT NOT NULL, eid TEXT, verdict TEXT,
                 model TEXT, at TEXT, state TEXT NOT NULL, PRIMARY KEY (type, key))""")
    if "source" not in {r[1] for r in c.execute("PRAGMA table_info(autoclose_log)")}:
        c.execute("ALTER TABLE autoclose_log ADD COLUMN source TEXT")  # NULL = researcher (rows written before the reviewer option)
    if "refs" not in {r[1] for r in c.execute("PRAGMA table_info(autoclose_log)")}:
        c.execute("ALTER TABLE autoclose_log ADD COLUMN refs TEXT")  # JSON [[type, key], ...] also checked off (Open events groups)


def _c():
    return store.tl_conn("autoclose", _init)


def settings(c=None):
    c = c or _c()
    r = c.execute("SELECT v FROM meta WHERE k='autoclose'").fetchone()
    s = json.loads(r[0]) if r else {}
    if not any(o in s for o in OPTS):  # saved before the reviewer option: expected/benign meant the research note's verdict
        old = {"researcher_expected": s.get("expected"), "researcher_benign": s.get("benign")}  # very first version
        for src in SOURCES:  # intermediate version: one switch per source covered both verdicts
            if src in s:
                old.update({f"{src}_{k}": s[src] for k in KINDS})
        s = {**s, **old}
    return {**{o: bool(s.get(o)) for o in OPTS}, "updated_by": s.get("updated_by"), "updated_at": s.get("updated_at")}


def set_settings(opts, user):
    c = _c()
    s = {**{o: bool((opts or {}).get(o)) for o in OPTS}, "updated_by": user, "updated_at": store.now_iso()}
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


def last_run(c=None):
    c = c or _c()
    r = c.execute("SELECT v FROM meta WHERE k='autoclose_last'").fetchone()
    return json.loads(r[0]) if r else None


def _verdicts(eid, notes, cls):
    """{source: verdict} - researcher = the research note's verdict, reviewer = the correlation reviewer's label."""
    out = {}
    v = (notes.get(eid) or {}).get("verdict")
    if v:
        out["researcher"] = v
    v = (cls.get(eid) or {}).get("label")
    if v:
        out["reviewer"] = v
    return out


BAD = ("suspicious", "malicious")


def _refs_of(row):
    """Extra (type, key) check-offs an autoclose_log row closed together with its own."""
    try:
        return [tuple(x) for x in json.loads((dict(row) if row else {}).get("refs") or "[]")]
    except (ValueError, TypeError):
        return []


def run(raw, analysis, open_issues, other_eids=(), dry=False, trigger="manual", with_open=True):
    """Apply the enabled options to the snapshot. Returns counts (also the preview for the Configuration card).
    An item closes when an enabled source says expected/benign and no source calls it suspicious/malicious."""
    import corr_llm
    with _lock:
        c = _c()
        s = settings(c)
        on = {o for o in OPTS if s[o]}
        items = _items(raw, analysis, open_issues)
        ids = [i[0] for i in items] + list(other_eids)
        notes = enrich.load(ids)
        cls = corr_llm.classes(ids)
        acks = store.acks_load(c)
        log = {(r["type"], r["key"]): dict(r) for r in c.execute("SELECT * FROM autoclose_log")}
        res = {o: {"closable": 0, "would_close": 0, "closed_now": 0, "auto_closed": 0, "reopened_by_user": 0, "no_checklist": 0}
               for o in OPTS}
        res["reopened_verdict_changed"] = 0
        seen, handled = set(), set()

        def handle(eid, refs, label, members=()):
            """One closable event: refs[0] is its own check-off (logged); the rest are checked off with it."""
            typ, key = refs[0]
            vs = _verdicts(eid, notes, cls)
            good = [f"{k}_{vs[k]}" for k in SOURCES if vs.get(k) in KINDS]
            bad = any(v in BAD for v in vs.values()) or any(
                v in BAD for m in members if m != eid for v in _verdicts(m, notes, cls).values())
            a = (acks.get(typ) or {}).get(key)
            lg = log.get((typ, key))
            auto = bool(a and str(a.get("note") or "").startswith(NOTE_PREFIX))
            if not good or bad:
                if auto and lg and lg["state"] == "closed" and not dry:  # verdict changed since: bring it back
                    for t, k in dict.fromkeys([(typ, key), *_refs_of(lg)]):
                        b = (acks.get(t) or {}).get(k)
                        if b and str(b.get("note") or "").startswith(NOTE_PREFIX):
                            store.ack_set(t, k, False, c=c)
                    with store.tx(c):
                        c.execute("UPDATE autoclose_log SET state='reopened-verdict', verdict=?, at=? WHERE type=? AND key=?",
                                  (",".join(f"{k}:{v}" for k, v in vs.items())[:120], store.now_iso(), typ, key))
                    res["reopened_verdict_changed"] += 1
                return
            if lg and lg["state"] == "closed" and not a:  # a person un-checked it after we closed it
                if not dry:
                    with store.tx(c):
                        c.execute("UPDATE autoclose_log SET state='reopened', at=? WHERE type=? AND key=?", (store.now_iso(), typ, key))
                lg["state"] = "reopened"
            for k in good:
                res[k]["closable"] += 1
            if lg and lg["state"] == "reopened":
                for k in good:
                    res[k]["reopened_by_user"] += 1
                return
            if auto:
                src = (lg or {}).get("source") or "researcher"
                o = f"{src}_{(lg or {}).get('verdict')}"
                res[o if o in good else good[0]]["auto_closed"] += 1
                return
            if a:
                return  # checked off by a person
            hit = next((k for k in good if k in on), None)
            for k in good:
                res[k]["would_close"] += 1
            if hit and not dry:
                src, v = hit.split("_")
                who = (notes.get(eid) if src == "researcher" else cls.get(eid)) or {}
                text = who.get("summary") if src == "researcher" else who.get("reason")
                note = f"{NOTE_PREFIX}{v} ({src}, {who.get('model') or 'AI'}): {text or ''}"
                for t, k in dict.fromkeys(refs):
                    if not (acks.get(t) or {}).get(k):
                        store.ack_set(t, k, True, note, label, c=c)
                with store.tx(c):
                    c.execute("INSERT OR REPLACE INTO autoclose_log (type, key, eid, verdict, model, at, state, source, refs) "
                              "VALUES (?,?,?,?,?,?, 'closed', ?, ?)",
                              (typ, key, eid, v, str(who.get("model") or "")[:80], store.now_iso(), src, json.dumps(refs[1:])))
                for k in good:
                    res[k]["would_close"] -= 1
                    res[k]["auto_closed"] += 1 if k == hit else 0
                res[hit]["closed_now"] += 1

        for eid, typ, key, label in items:
            if (typ, key) in seen:
                continue
            seen.add((typ, key))
            handle(eid, [(typ, key)], label)
        if with_open:  # every event on the Open events page, any age, closed with the check-offs that page writes
            import eventstore
            oe = eventstore.open_events(limit=10 ** 6)["events"]
            more = list(dict.fromkeys(i for e in oe for i in [e["eid"], *(e.get("members") or [])] if i not in notes and i not in cls))
            if more:
                notes.update(enrich.load(more))
                cls.update(corr_llm.classes(more))
            for e in oe:
                refs = [(x["type"], x["key"]) for x in e.get("acks") or []]
                if not refs or any(r in seen for r in refs):
                    continue
                seen.update(refs)
                handled.update([e["eid"], *(e.get("members") or [])])
                handle(e["eid"], refs, e.get("label") or "", e.get("members") or ())
            # closed earlier and so no longer listed: still reopen it when its verdict turned bad / not enabled
            gone = [lg for (t, k), lg in log.items() if lg["state"] == "closed" and (t, k) not in seen and lg.get("eid")]
            if gone:
                more = [lg["eid"] for lg in gone if lg["eid"] not in notes and lg["eid"] not in cls]
                if more:
                    notes.update(enrich.load(more))
                    cls.update(corr_llm.classes(more))
                for lg in gone:
                    vs = _verdicts(lg["eid"], notes, cls)
                    if not vs or (any(v in KINDS for v in vs.values()) and not any(v in BAD for v in vs.values())):
                        continue  # no verdict any more (pruned) or still fine: leave it closed
                    seen.add((lg["type"], lg["key"]))
                    handle(lg["eid"], [(lg["type"], lg["key"]), *_refs_of(lg)], "")
        for eid in other_eids:  # researched events without a check-off list
            if eid in handled:
                continue
            vs = _verdicts(eid, notes, cls)
            if any(v in BAD for v in vs.values()):
                continue
            for k in SOURCES:
                if vs.get(k) in KINDS:
                    res[f"{k}_{vs[k]}"]["no_checklist"] += 1
        res["settings"] = s
        if not dry:
            closed = {o: res[o]["closed_now"] for o in OPTS}
            with store.tx(c):
                c.execute("INSERT OR REPLACE INTO meta VALUES ('autoclose_last', ?)", (json.dumps(
                    {"at": store.now_iso(), "trigger": trigger, "closed": closed, "reopened": res["reopened_verdict_changed"],
                     "enabled": sorted(on)}),))
            if trigger != "timer" or any(closed.values()) or res["reopened_verdict_changed"]:
                print(f"autoclose ({trigger}): closed {closed}, reopened {res['reopened_verdict_changed']} (verdict changed)", file=sys.stderr)
        res["last_run"] = last_run(c)
        return res


def reopen_all(user, kind=None):
    """Un-check every item that auto-close closed (optionally only one option, e.g. reviewer_benign); they won't be auto-closed again."""
    with _lock:
        c = _c()
        acks = store.acks_load(c)
        rows = c.execute("SELECT type, key, source, verdict, refs FROM autoclose_log WHERE state='closed'").fetchall()
        n = 0
        for r in rows:
            if kind and f"{r['source'] or 'researcher'}_{r['verdict']}" != kind:
                continue
            for i, (t, k) in enumerate(dict.fromkeys([(r["type"], r["key"]), *_refs_of(r)])):
                a = (acks.get(t) or {}).get(k)
                if a and str(a.get("note") or "").startswith(NOTE_PREFIX):
                    store.ack_set(t, k, False, c=c)
                    n += 1 if i == 0 else 0
            with store.tx(c):
                c.execute("UPDATE autoclose_log SET state='reopened', at=? WHERE type=? AND key=?", (store.now_iso(), r["type"], r["key"]))
        print(f"autoclose: {user} reopened {n} auto-closed item(s){' (' + kind + ')' if kind else ''}", file=sys.stderr)
        return n


if __name__ == "__main__":
    # `python /app/autoclose.py run [trigger]` - called by enrich.sh put right after the review job stores its notes
    if sys.argv[1:2] != ["run"]:
        raise SystemExit("usage: autoclose.py run [trigger]")
    import server  # noqa: E402 - sets NETMON_DB to the writable /state DB like the dashboard (no HTTP server is started)
    s = settings()
    if not any(s[o] for o in OPTS):
        print(json.dumps({"autoclose": "off"}))
        raise SystemExit(0)
    inp = server.autoclose_inputs()
    r = run(*inp, trigger=sys.argv[2] if len(sys.argv) > 2 else "review job") if inp else {"error": "no snapshot"}
    print(json.dumps({"autoclose": {k: r.get(k) for k in (*OPTS, "reopened_verdict_changed", "error") if k in r}}))
