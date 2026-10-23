"""How many times each correlation event has been seen: once per snapshot the event is present in (alerts: once per raised alert with the same text)."""
import os, sys, threading
_ROOT = os.environ.get("NETMON_DIR", "/netmon")
if os.path.isdir(_ROOT) and _ROOT not in sys.path:
    sys.path.append(_ROOT)
import store

_lock = threading.Lock()


def _c():
    return store.tl_conn("eventseen", lambda c: c.execute("""CREATE TABLE IF NOT EXISTS event_seen (eid TEXT PRIMARY KEY, first TEXT, last TEXT, n INTEGER NOT NULL DEFAULT 0, last_sid TEXT)"""))


def bump(E, sid):
    """Count every event of the latest snapshot once per snapshot."""
    if not E or not sid:
        return
    with _lock:
        c = _c()
        now = store.now_iso()
        rows = [(e, now, now, sid) for e in E if not e.startswith("alert|")]
        with store.tx(c):
            c.executemany("INSERT OR IGNORE INTO event_seen (eid, first, last, n, last_sid) VALUES (?,?,?,0,NULL)", [(r[0], r[1], r[2]) for r in rows])
            c.executemany("UPDATE event_seen SET n=n+1, last=?, last_sid=? WHERE eid=? AND COALESCE(last_sid,'')!=?", [(now, sid, r[0], sid) for r in rows])


def _t(v):
    import datetime
    return datetime.datetime.fromtimestamp(v).strftime("%Y-%m-%d %H:%M") if isinstance(v, (int, float)) else v


def view(E):
    """{eid: {n, first, last}} for the events given."""
    c = _c()
    out = {}
    db = {r[0]: r for r in c.execute("SELECT eid, n, first, last FROM event_seen")}
    for eid, ev in (E or {}).items():
        if eid.startswith("alert|"):
            continue
        r = db.get(eid)
        if r:
            out[eid] = {"n": r[1], "first": r[2], "last": r[3]}
    al = {}
    for r in c.execute("SELECT text, count(*), min(ts), max(ts) FROM alerts GROUP BY text"):
        al[r[0]] = r
    for eid, ev in (E or {}).items():
        if eid.startswith("alert|"):
            r = al.get(str(ev.get("label") or ""))
            if r:
                out[eid] = {"n": r[1], "first": _t(r[2]), "last": _t(r[3])}
    return out
