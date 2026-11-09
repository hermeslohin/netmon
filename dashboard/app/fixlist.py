"""Fix list (recurring misconfiguration / security-suggestion tracker) in SQL.

Each review run is evaluated once by issues.py's checks (issues._eval) and stored as rows; the Fix list itself is one
SQL query over those rows, so it covers every run ever made, also runs whose documents are gone (runarchive.prune).

Tables (netmon.db, or any sqlite connection passed in):
  fix_run(sid, generated, full, mt, site)          one row per evaluated review run; full = covered >= 23 h (only a full
                                                   run can clear an issue); mt/site = what it was evaluated against
  fix_run_source(sid, source)                      data sources the run had (raw, analysis, hosts, unifi, k8s)
  fix_run_device(sid, dev)                         devices present in the run (MAC, else IP)
  fix_run_ipmac(sid, ip, mac)                      the run's ip -> mac map (IP2MAC = newest run's mac per ip)
  fix_run_lookup(sid, ip, mac)                     IP2MAC values the evaluation used (mac NULL = none): a run that
                                                   still has documents is evaluated again when one of them changes
  fix_item(sid, pos, key, dev, source, severity, category, title, ip, host, target, fix, evidence)
                                                   the issues the run raised (pos = order the checks emitted them)

Rules (same as before the move to SQL):
  occurrences  runs that raised the key; first/last seen = generated time of the first/last of them
  able runs    runs from the first occurrence on that had the key's source (of its newest occurrence) and were full,
               or raised it themselves
  status       newest able run lacks the key: 'open (device not seen)' when the key has a device that run did not see,
               else 'fixed' (fixed_at = first able run after the last occurrence); otherwise 'open' when the newest run
               raised it, else 'open (not re-checked)'
"""
import json
import sqlite3
import threading

import issues

FIELDS = ("key", "dev", "source", "severity", "category", "title", "ip", "host", "target", "fix", "evidence")
DDL = """CREATE TABLE IF NOT EXISTS fix_run (
  sid TEXT PRIMARY KEY, generated TEXT, full INTEGER NOT NULL DEFAULT 1, mt TEXT, site TEXT) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS fix_run_source (sid TEXT NOT NULL, source TEXT NOT NULL, PRIMARY KEY (sid, source)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS fix_run_device (sid TEXT NOT NULL, dev TEXT NOT NULL, PRIMARY KEY (sid, dev)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS fix_run_ipmac (sid TEXT NOT NULL, ip TEXT NOT NULL, mac TEXT NOT NULL, PRIMARY KEY (sid, ip)) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS fix_run_ipmac_ip ON fix_run_ipmac(ip, sid);
CREATE TABLE IF NOT EXISTS fix_run_lookup (sid TEXT NOT NULL, ip TEXT NOT NULL, mac TEXT, PRIMARY KEY (sid, ip)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS fix_item (
  sid TEXT NOT NULL, pos INTEGER NOT NULL, key TEXT NOT NULL, dev TEXT NOT NULL DEFAULT '', source TEXT NOT NULL DEFAULT '',
  severity TEXT, category TEXT, title TEXT, ip TEXT, host TEXT, target TEXT, fix TEXT, evidence TEXT,
  PRIMARY KEY (sid, key)) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS fix_item_key ON fix_item(key, sid);"""
RUN_TABLES = ("fix_run", "fix_run_source", "fix_run_device", "fix_run_ipmac", "fix_run_lookup", "fix_item")
_lock = threading.RLock()


def init(c):
    c.executescript(DDL)
    return c


def conn():
    import store
    return store.tl_conn("fixlist", init)


def _tx(c):
    import contextlib

    @contextlib.contextmanager
    def t():
        c.execute("BEGIN IMMEDIATE")
        try:
            yield c
            c.execute("COMMIT")
        except BaseException:
            c.execute("ROLLBACK")
            raise
    return t()


# ------------------------------------------------------------------ writing runs
def _put_ipmac(c, sid, devmap):
    c.execute("DELETE FROM fix_run_ipmac WHERE sid=?", (sid,))
    c.executemany("INSERT INTO fix_run_ipmac(sid, ip, mac) VALUES (?,?,?)", [(sid, ip, m) for ip, m in devmap.items()])


def put_run(c, sid, generated, ev, devmap, mt=None, site=None):
    """Store one evaluated run (issues._eval result) - replaces whatever the run had."""
    for t in RUN_TABLES:
        c.execute(f"DELETE FROM {t} WHERE sid=?", (sid,))  # noqa: S608 - fixed table names
    c.execute("INSERT INTO fix_run(sid, generated, full, mt, site) VALUES (?,?,?,?,?)",
              (sid, generated, 1 if ev.get("full") else 0, None if mt is None else str(mt), site))
    c.executemany("INSERT INTO fix_run_source VALUES (?,?)", [(sid, s) for s in sorted(ev.get("srcs") or ())])
    c.executemany("INSERT INTO fix_run_device VALUES (?,?)", [(sid, d) for d in sorted(ev.get("present") or ())])
    c.executemany("INSERT INTO fix_run_lookup VALUES (?,?,?)", [(sid, ip, m) for ip, m in (ev.get("look") or {}).items()])
    c.executemany("INSERT INTO fix_run_ipmac(sid, ip, mac) VALUES (?,?,?)", [(sid, ip, m) for ip, m in (devmap or {}).items()])
    c.executemany(f"INSERT INTO fix_item(sid, pos, {', '.join(FIELDS)}) VALUES (?,?,{','.join('?' * len(FIELDS))})",  # noqa: S608
                  [(sid, i, k, iss.get("dev") or "", iss.get("source") or "", *[iss.get(f) for f in FIELDS[3:]])
                   for i, (k, iss) in enumerate((ev.get("cur") or {}).items())])


def ip2mac(c):
    """ip -> mac of the newest run that saw the ip with a mac (what issues.IP2MAC was over every run)."""
    return dict(c.execute("""SELECT f.ip, f.mac FROM fix_run_ipmac f
                             JOIN (SELECT ip, MAX(sid) s FROM fix_run_ipmac GROUP BY ip) n ON n.ip = f.ip AND n.s = f.sid"""))


def _evaluate(raw, an, i2m):
    with issues._TRACK_LOCK:
        issues.IP2MAC.clear()
        issues.IP2MAC.update(i2m)
        return issues._eval(raw, an)


def sync(items, c=None, keep=8):
    """Bring the tables up to date with the review runs that still have documents.
    items: ordered [(sid, mtime, load)] where load() -> (generated, raw, analysis) or None.
    A run is (re)evaluated when it is new, its documents changed, the site settings changed, or an IP2MAC value its
    evaluation used has changed. Runs without documents keep their stored rows. Returns the sids evaluated."""
    c = c or conn()
    site = issues._site_sig()
    with _lock:
        known = {r[0]: r[1] for r in c.execute("SELECT sid, mt FROM fix_run")}
        fresh, new = {}, []
        for sid, mt, load in items:  # pass 1: new / changed runs contribute their ip->mac map first
            if sid in known and known[sid] == str(mt):
                continue
            got = load()
            if not got or not got[1]:
                continue
            with _tx(c):
                _put_ipmac(c, sid, issues._devmap(got[1]))
            new.append(sid)
            if len(fresh) < keep:
                fresh[sid] = got
        i2m = ip2mac(c)
        sites = dict(c.execute("SELECT sid, site FROM fix_run"))
        looks = {}
        for sid, ip, m in c.execute("SELECT sid, ip, mac FROM fix_run_lookup"):
            looks.setdefault(sid, {})[ip] = m
        done = []
        for sid, mt, load in items:  # pass 2: evaluate what needs it
            if sid not in new and sites.get(sid) == site and all(i2m.get(ip) == m for ip, m in looks.get(sid, {}).items()):
                continue
            got = fresh.pop(sid, None) or load()
            if not got or not got[1]:
                continue
            ev = _evaluate(got[1], got[2], i2m)
            with _tx(c):
                put_run(c, sid, got[0], ev, issues._devmap(got[1]), mt, site)
            done.append(sid)
        return done


# ------------------------------------------------------------------ the Fix list
_Q = """
WITH runs AS (SELECT sid, generated, full FROM fix_run),
h AS (SELECT key, MIN(sid) first_snap, MAX(sid) last_snap, COUNT(*) occ FROM fix_item GROUP BY key),
hl AS (SELECT h.*, li.dev, li.source, fp.pos first_pos FROM h
       JOIN fix_item li ON li.key = h.key AND li.sid = h.last_snap
       JOIN fix_item fp ON fp.key = h.key AND fp.sid = h.first_snap),
able AS MATERIALIZED (SELECT hl.key, r.sid, r.generated FROM hl JOIN runs r ON r.sid >= hl.first_snap
         WHERE EXISTS (SELECT 1 FROM fix_run_source s WHERE s.sid = r.sid AND s.source = hl.source)
           AND (r.full = 1 OR EXISTS (SELECT 1 FROM fix_item x WHERE x.sid = r.sid AND x.key = hl.key))),
agg AS (SELECT key, COUNT(*) checked, MAX(sid) last_able FROM able GROUP BY key),
st AS (
  SELECT hl.*, COALESCE(agg.checked, 0) checked, agg.last_able,
         agg.last_able IS NOT NULL AND NOT EXISTS (SELECT 1 FROM fix_item x WHERE x.sid = agg.last_able AND x.key = hl.key) gone,
         EXISTS (SELECT 1 FROM fix_run_device d WHERE d.sid = agg.last_able AND d.dev = hl.dev) dev_seen
  FROM hl LEFT JOIN agg ON agg.key = hl.key)
SELECT st.key, st.first_snap, st.last_snap, st.occ, st.checked, st.first_pos,
       (SELECT generated FROM runs WHERE sid = st.first_snap) first_seen,
       (SELECT generated FROM runs WHERE sid = st.last_snap) last_seen,
       CASE WHEN st.gone AND st.dev <> '' AND NOT st.dev_seen THEN 'open (device not seen)'
            WHEN st.gone THEN 'fixed'
            WHEN st.last_snap = (SELECT MAX(sid) FROM runs) THEN 'open'
            ELSE 'open (not re-checked)' END status,
       CASE WHEN st.gone AND NOT (st.dev <> '' AND NOT st.dev_seen) THEN
            COALESCE((SELECT a.generated FROM able a WHERE a.key = st.key AND a.sid > st.last_snap ORDER BY a.sid LIMIT 1),
                     (SELECT generated FROM runs WHERE sid = st.last_able)) END fixed_at,
       li.severity, li.category, li.title, li.ip, li.host, li.target, li.fix, li.evidence, li.dev, li.source
FROM st JOIN fix_item li ON li.key = st.key AND li.sid = st.last_snap
ORDER BY st.first_snap, st.first_pos
"""


def track(c=None, min_occ=2):
    """The Fix list: {latest, snapshots, min_occurrences, open, fixed} (open by severity, occurrences, title; fixed newest first)."""
    c = c or conn()
    with _lock:
        latest, n = c.execute("SELECT MAX(sid), COUNT(*) FROM fix_run").fetchone()
        open_, fixed = [], []
        cur = c.execute(_Q)
        cols = [d[0] for d in cur.description]
        for row in cur:
            r = dict(zip(cols, row))
            h = {f: r.get(f) for f in FIELDS}
            h.update(first_seen=r["first_seen"], first_snap=r["first_snap"], occurrences=r["occ"], last_seen=r["last_seen"],
                     last_snap=r["last_snap"], checked=r["checked"], status=r["status"])
            if r["status"] == "fixed":
                h["fixed_at"] = r["fixed_at"]
                fixed.append(h)
            else:
                h["recurring"] = r["occ"] >= min_occ
                open_.append(h)
    open_.sort(key=lambda x: (issues.SEV_ORDER.get(x["severity"], 9), -x["occurrences"], x["title"] or ""))
    fixed.sort(key=lambda x: x.get("fixed_at") or "", reverse=True)
    return {"latest": latest, "snapshots": n, "min_occurrences": min_occ, "open": open_, "fixed": fixed}


def track_snaps(snaps, min_occ=2):
    """Fix list over in-memory runs [(sid, generated, raw, analysis)] (ordered), in a throwaway SQLite database."""
    c = init(sqlite3.connect(":memory:", isolation_level=None))
    try:
        snaps = list(snaps)
        i2m = {}
        for _, _, raw, _ in snaps:
            i2m.update(issues._devmap(raw))
        for sid, gen, raw, an in snaps:
            with _tx(c):
                put_run(c, sid, gen, _evaluate(raw, an, i2m), issues._devmap(raw))
        return track(c, min_occ)
    finally:
        c.close()


# ------------------------------------------------------------------ one-off: the JSON blobs run_summary.iss held before
def migrate_blobs(c=None):
    """Move run_summary.iss (compressed JSON of each run's tracker inputs) into the tables, then drop the column."""
    import zlib
    c = c or conn()
    cols = [r[1] for r in c.execute("PRAGMA table_info(run_summary)")]
    if "iss" not in cols:
        return 0
    n = 0
    have = {r[0] for r in c.execute("SELECT sid FROM fix_run")}
    rows = c.execute("SELECT sid, generated, iss FROM run_summary WHERE iss IS NOT NULL ORDER BY sid").fetchall()
    with _lock, _tx(c):
        for sid, gen, blob in rows:
            if sid in have:
                continue
            d = json.loads(zlib.decompress(blob))
            ev = d.get("ev") or {}
            if ev.get("cur") is None:
                continue
            put_run(c, sid, d.get("gen") or gen, ev, d.get("dev") or {}, "migrated", d.get("site"))
            n += 1
    try:
        c.execute("ALTER TABLE run_summary DROP COLUMN iss")
    except sqlite3.OperationalError:
        with _tx(c):
            c.execute("UPDATE run_summary SET iss = NULL")
    return n
