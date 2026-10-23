#!/usr/bin/python3
"""netmon operational store (SQLite, WAL). Single source of truth for netmon's own state.

Replaces the JSON files:
  baseline/devices_seen.json   -> table devices        (registry_load / registry_save)
  baseline/hosts_seen.json     -> table host_baseline  (hosts_load / hosts_save)
  baseline/history.jsonl       -> table history (+ served_ports index)  (history_load / history_append)
  baseline/watch_state.json    -> table watch_mute     (mute_filter)
  dashboard/state/acks.json    -> table acks           (acks_load / ack_set)

Raw events stay in Security Onion Elasticsearch. Snapshots (data/), time ranges (ranges/) and job/config state (users, scheduler,
research_job, llm_*, integrations) are JSON documents in table docs (jload/jdump/jexists/jglob).

DB location: $NETMON_DB, else $STATE_DIR/netmon.db (dashboard container: /state), else
<netmon>/dashboard/state/netmon.db. It lives on the dashboard's writable state volume so the container can
keep /netmon mounted read-only (SQLite WAL needs a writable directory even for readers).

CLI: store.py migrate | stats | backup | export <dir> | check
"""
import contextlib, glob, json, os, re, sqlite3, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
SCHEMA_VERSION = 1


def db_path():
    if os.environ.get("NETMON_DB"):
        return os.environ["NETMON_DB"]
    if os.environ.get("STATE_DIR"):
        return os.path.join(os.environ["STATE_DIR"], "netmon.db")
    return os.path.join(HERE, "dashboard", "state", "netmon.db")


SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS acks (
  type TEXT NOT NULL, key TEXT NOT NULL, at TEXT NOT NULL, note TEXT DEFAULT '', label TEXT DEFAULT '',
  PRIMARY KEY (type, key));
CREATE TABLE IF NOT EXISTS watch_mute (key TEXT PRIMARY KEY, ts REAL NOT NULL);
CREATE TABLE IF NOT EXISTS devices (
  key TEXT PRIMARY KEY, mac TEXT, name TEXT, first_seen TEXT, last_seen TEXT, known INTEGER, doc TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS devices_last ON devices(last_seen);
CREATE TABLE IF NOT EXISTS host_baseline (
  host TEXT NOT NULL, kind TEXT NOT NULL, doc TEXT NOT NULL, updated TEXT NOT NULL, PRIMARY KEY (host, kind));
CREATE TABLE IF NOT EXISTS history (generated TEXT PRIMARY KEY, hours INTEGER, doc TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS served_ports (
  generated TEXT NOT NULL REFERENCES history(generated) ON DELETE CASCADE, ip TEXT NOT NULL, port TEXT NOT NULL,
  PRIMARY KEY (generated, ip, port));
CREATE INDEX IF NOT EXISTS served_ip ON served_ports(ip);
CREATE TABLE IF NOT EXISTS alerts (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, key TEXT NOT NULL, text TEXT NOT NULL,
  severity TEXT DEFAULT 'urgent', source TEXT DEFAULT 'watcher', pushed INTEGER DEFAULT 0, read INTEGER DEFAULT 0);
CREATE INDEX IF NOT EXISTS alerts_pushed ON alerts(pushed);
CREATE TABLE IF NOT EXISTS alert_mutes (
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, host TEXT NOT NULL DEFAULT '', by TEXT, at REAL NOT NULL,
  limit_key TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS suppress_rules (
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, art_type TEXT NOT NULL DEFAULT '', art TEXT NOT NULL DEFAULT '',
  by TEXT, at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS seg_suppress (
  id INTEGER PRIMARY KEY AUTOINCREMENT, src TEXT NOT NULL DEFAULT '', dst TEXT NOT NULL DEFAULT '', ports TEXT NOT NULL DEFAULT '',
  by TEXT, at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS ids_suppress (
  id INTEGER PRIMARY KEY AUTOINCREMENT, sig TEXT NOT NULL, host TEXT NOT NULL DEFAULT '', by TEXT, at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS sec_findings (
  key TEXT PRIMARY KEY, tool TEXT, severity TEXT, title TEXT, location TEXT, fix TEXT, detail TEXT,
  first_seen TEXT, last_seen TEXT, status TEXT NOT NULL DEFAULT 'open', fixed_at TEXT, notified INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS docs (
  name TEXT PRIMARY KEY, doc BLOB NOT NULL, updated REAL NOT NULL, size INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS cfg (
  doc TEXT NOT NULL, seq INTEGER NOT NULL, path TEXT NOT NULL, vtype TEXT NOT NULL, value TEXT,
  PRIMARY KEY (doc, seq));
CREATE INDEX IF NOT EXISTS cfg_path ON cfg(doc, path);
CREATE TABLE IF NOT EXISTS push_prefs (
  user TEXT PRIMARY KEY, mode TEXT NOT NULL DEFAULT 'all', devices TEXT NOT NULL DEFAULT '[]', updated TEXT);
CREATE TABLE IF NOT EXISTS push_subs (
  endpoint TEXT PRIMARY KEY, user TEXT, keys TEXT NOT NULL, ua TEXT, created TEXT, last_ok TEXT, fails INTEGER DEFAULT 0);
"""


def connect(path=None):
    p = path or db_path()
    os.makedirs(os.path.dirname(p), exist_ok=True)
    old = os.umask(0o077)  # DB holds push-subscription secrets: owner-only (also covers -wal/-shm created now)
    try:
        c = sqlite3.connect(p, timeout=15, isolation_level=None)
    finally:
        os.umask(old)
    for f in (p, p + "-wal", p + "-shm"):
        try:
            if os.path.exists(f) and os.stat(f).st_mode & 0o077:
                os.chmod(f, 0o600)
        except OSError:
            pass  # autocommit; explicit BEGIN IMMEDIATE for writes
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA synchronous=NORMAL")
    c.execute("PRAGMA foreign_keys=ON")
    c.execute("PRAGMA temp_store=MEMORY")  # dashboard container has a read-only /tmp
    c.execute("PRAGMA busy_timeout=15000")
    c.executescript(SCHEMA)
    if "targets" not in {r[1] for r in c.execute("PRAGMA table_info(alerts)")}:  # schema v2: devices an alert is about
        c.execute("ALTER TABLE alerts ADD COLUMN targets TEXT NOT NULL DEFAULT '[]'")
    have = {r[1] for r in c.execute("PRAGMA table_info(alerts)")}
    for col, decl in (("cleared", "INTEGER NOT NULL DEFAULT 0"), ("cleared_rule", "INTEGER"), ("cleared_at", "REAL"), ("held", "INTEGER NOT NULL DEFAULT 0")):  # alerts a mute rule cleared (kept, hidden from the feed)
        if col not in have:
            c.execute(f"ALTER TABLE alerts ADD COLUMN {col} {decl}")
    c.execute("INSERT OR IGNORE INTO meta VALUES ('schema_version', ?)", (str(SCHEMA_VERSION),))
    return c


@contextlib.contextmanager
def tx(c):
    """Write transaction; takes the write lock up front so read-modify-write is safe across processes."""
    c.execute("BEGIN IMMEDIATE")
    try:
        yield c
        c.execute("COMMIT")
    except BaseException:
        c.execute("ROLLBACK")
        raise


def now_iso():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


# ------------------------------------------------------------------ docs (JSON documents: snapshots, time ranges, job state)
# A document is addressed by the path it used to have as a file. Paths under a data/ or ranges/ directory (and the state
# files in DOC_FILES) live in the `docs` table, zlib-compressed; any other path is still read/written as a plain file.
# jload / jdump / jexists / jglob / jmtime / jdelete are drop-in replacements for the open()/json/glob/os.path calls.
import threading, zlib
DOC_FILES = {"research_job.json", "scheduler.json", "llm_config.json", "llm_providers.json", "integrations.json", "users.json"}
_dl = threading.local()


def doc_name(path):
    """'data/2026-10-22T0500Z.analysis', 'ranges/r2026...status', 'state/users' or None when the path is a real file."""
    path = os.path.abspath(str(path))
    d, f = os.path.split(path)
    if f.endswith(".tmp"):
        f = f[:-4]
    b = os.path.basename(d)
    if cfg_doc(path):
        return None
    if f.endswith(".work.json"):  # enrich.sh redirects into it from a shell: a real scratch file
        return None
    if b in ("data", "ranges") and f.endswith(".json"):
        return b + "/" + f[:-5]
    if f in DOC_FILES and b in ("state", ".state"):
        return "state/" + f[:-5]
    return None


def _dc():
    c = getattr(_dl, "c", None)
    if c is None or _dl.path != db_path():
        c = _dl.c = connect()
        _dl.path = db_path()
    return c


def tl_conn(tag, init=None):
    """Per-thread shared connection (one fd per thread, never one per call); init(c) runs once per thread+tag."""
    c = _dc()
    done = getattr(_dl, "inited", None)
    if done is None or getattr(_dl, "inited_c", None) is not c:
        done = _dl.inited = set()
        _dl.inited_c = c
    if tag not in done:
        if init:
            init(c)
        done.add(tag)
    return c


def doc_put(name, obj, c=None):
    raw = json.dumps(obj, default=str, separators=(",", ":")).encode()
    c = c or _dc()
    with tx(c):
        c.execute("INSERT INTO docs(name,doc,updated,size) VALUES (?,?,?,?) ON CONFLICT(name) DO UPDATE SET doc=excluded.doc, updated=excluded.updated, size=excluded.size",
                  (name, zlib.compress(raw, 6), time.time(), len(raw)))


def doc_get(name, default=None, c=None):
    r = (c or _dc()).execute("SELECT doc FROM docs WHERE name=?", (name,)).fetchone()
    return json.loads(zlib.decompress(r[0])) if r else default


def doc_exists(name):
    return _dc().execute("SELECT 1 FROM docs WHERE name=?", (name,)).fetchone() is not None


def doc_mtime(name):
    r = _dc().execute("SELECT updated FROM docs WHERE name=?", (name,)).fetchone()
    return r[0] if r else None


def doc_names(prefix):
    return [r[0] for r in _dc().execute("SELECT name FROM docs WHERE name LIKE ? ESCAPE '\\' ORDER BY name", (prefix.replace("_", "\\_").replace("%", "\\%") + "%",))]


def doc_delete(name):
    c = _dc()
    with tx(c):
        c.execute("DELETE FROM docs WHERE name=?", (name,))


def cfg_doc(path):
    """'policy' for <netmon>/policy.json (also host_policy, known_benign, site); None for anything else (incl. *.example.json)."""
    d, f = os.path.split(os.path.abspath(str(path)))
    if d == HERE and f.endswith(".json") and f[:-5] in CFG_DOCS:
        return f[:-5]
    return None


def jload(path, default=None):
    cd = cfg_doc(path)
    if cd:
        return cfg_load(cd, shared=False) if cfg_has(cd) else default
    n = doc_name(path)
    if n:
        return doc_get(n, default)
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def jdump(obj, path, **kw):
    cd = cfg_doc(path)
    if cd:
        cfg_save(cd, obj)
        return
    n = doc_name(path)
    if n:
        return doc_put(n, obj)
    tmp = str(path) + ".tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f, **kw)
    os.replace(tmp, path)


def jexists(path):
    cd = cfg_doc(path)
    if cd:
        return cfg_has(cd)
    n = doc_name(path)
    return doc_exists(n) if n else os.path.exists(path)


def jmtime(path):
    cd = cfg_doc(path)
    if cd:
        return float(_cfg_ver(_dc(), cd))
    n = doc_name(path)
    return doc_mtime(n) if n else os.path.getmtime(path)


def jdelete(path):
    n = doc_name(path)
    if n:
        doc_delete(n)
    elif os.path.exists(path):
        os.remove(path)


def jglob(directory, pattern="*.json"):
    """Paths (as the files used to be named) of the documents in `directory`, sorted, matching a glob pattern."""
    import fnmatch
    d = os.path.abspath(directory)
    b = os.path.basename(d)
    if b in ("data", "ranges"):
        return [os.path.join(d, n.split("/", 1)[1] + ".json") for n in doc_names(b + "/")
                if fnmatch.fnmatch(n.split("/", 1)[1] + ".json", pattern)]
    return sorted(glob.glob(os.path.join(d, pattern)))


def docs_migrate(dirs, delete=False):
    """Load every *.json in these directories into the docs table (and remove the file once it reads back identically)."""
    n = 0
    for d in dirs:
        for p in sorted(glob.glob(os.path.join(d, "*.json"))):
            nm = doc_name(p)
            if not nm:
                continue
            try:
                obj = json.load(open(p))
            except ValueError:
                continue
            doc_put(nm, obj)
            if delete and doc_get(nm) == obj:
                os.remove(p)
            n += 1
    return n


# ------------------------------------------------------------------ cfg (policy / host_policy / known_benign / site)
# Editable settings, one row per value: (doc, seq, path, vtype, value). path is "section/key/#3" (dict keys escaped, "#n" = list
# item n); vtype is str|int|float|bool|null, or list|dict for an empty container. seq keeps document order. The dashboard's
# Policy page edits these as tables; cfg_load() hands the rest of netmon the same dict the JSON files used to give.
import copy
CFG_DOCS = ("policy", "host_policy", "known_benign", "site")
_cfg_cache = {}


def _esc(k):
    return str(k).replace("%", "%25").replace("/", "%2F").replace("#", "%23")


def _unesc(k):
    return k.replace("%23", "#").replace("%2F", "/").replace("%25", "%")


def cfg_flatten(obj, path=()):
    """Yield (path string, vtype, value text) for every leaf of a nested dict/list."""
    if isinstance(obj, dict):
        if not obj:
            yield "/".join(path), "dict", None
        for k, v in obj.items():
            yield from cfg_flatten(v, path + (_esc(k),))
    elif isinstance(obj, (list, tuple)):
        if not obj:
            yield "/".join(path), "list", None
        for i, v in enumerate(obj):
            yield from cfg_flatten(v, path + (f"#{i}",))
    elif obj is None:
        yield "/".join(path), "null", None
    elif isinstance(obj, bool):
        yield "/".join(path), "bool", "1" if obj else "0"
    elif isinstance(obj, int):
        yield "/".join(path), "int", str(obj)
    elif isinstance(obj, float):
        yield "/".join(path), "float", repr(obj)
    else:
        yield "/".join(path), "str", str(obj)


def cfg_build(rows):
    """Inverse of cfg_flatten; rows = [(path, vtype, value)] in document order."""
    root = {}
    for path, vt, val in rows:
        segs = path.split("/") if path else []
        leaf = {"dict": {}, "list": [], "null": None, "bool": val == "1", "int": int(val) if vt == "int" else None,
                "float": float(val) if vt == "float" else None, "str": val if val is not None else ""}[vt]
        node = root
        for i, sg in enumerate(segs):
            last = i == len(segs) - 1
            nxt_list = (not last) and segs[i + 1].startswith("#")
            if sg.startswith("#"):  # node is a list
                idx = int(sg[1:])
                while len(node) <= idx:
                    node.append(None)
                if last:
                    node[idx] = leaf
                else:
                    if node[idx] is None:
                        node[idx] = [] if nxt_list else {}
                    node = node[idx]
            else:
                key = _unesc(sg)
                if last:
                    node[key] = leaf
                else:
                    if key not in node:
                        node[key] = [] if nxt_list else {}
                    node = node[key]
    return root


def _cfg_ver(c, doc):
    r = c.execute("SELECT v FROM meta WHERE k=?", ("cfg_ver:" + doc,)).fetchone()
    return r[0] if r else "0"


def cfg_save(doc, data, c=None):
    c = c or _dc()
    rows = [(doc, i, p, vt, v) for i, (p, vt, v) in enumerate(cfg_flatten(data))]
    with tx(c):
        c.execute("DELETE FROM cfg WHERE doc=?", (doc,))
        c.executemany("INSERT INTO cfg(doc,seq,path,vtype,value) VALUES (?,?,?,?,?)", rows)
        c.execute("INSERT OR REPLACE INTO meta VALUES (?, ?)", ("cfg_ver:" + doc, str(time.time())))
    _cfg_cache.pop((db_path(), doc), None)
    return len(rows)


_CFG_TTL = 2.0  # seconds a process trusts its cached copy before asking the DB whether the settings changed


def cfg_load(doc, c=None, shared=False):
    """The settings document as a dict (a private copy unless shared=True; cached, refreshed within a couple of seconds of a save)."""
    k = (db_path(), doc)
    hit = _cfg_cache.get(k)
    if not hit or time.time() - hit[2] > _CFG_TTL:
        c = c or _dc()
        ver = _cfg_ver(c, doc)
        if not hit or hit[0] != ver:
            rows = [(r[0], r[1], r[2]) for r in c.execute("SELECT path, vtype, value FROM cfg WHERE doc=? ORDER BY seq", (doc,))]
            hit = (ver, cfg_build(rows), time.time())
        else:
            hit = (hit[0], hit[1], time.time())
        _cfg_cache[k] = hit
    return hit[1] if shared else copy.deepcopy(hit[1])


def cfg_has(doc, c=None):
    return (c or _dc()).execute("SELECT 1 FROM cfg WHERE doc=? LIMIT 1", (doc,)).fetchone() is not None


# ------------------------------------------------------------------ acks (dashboard check-offs)
def acks_load(c=None):
    c = c or _dc()
    out = {"issue": {}, "alarm": {}, "finding": {}, "host": {}}
    for r in c.execute("SELECT type, key, at, note, label FROM acks"):
        out.setdefault(r["type"], {})[r["key"]] = {"at": r["at"], "note": r["note"], "label": r["label"]}
    return out


def ack_set(typ, key, checked, note="", label="", c=None):
    c = c or _dc()
    with tx(c):
        if checked:
            c.execute("INSERT INTO acks(type,key,at,note,label) VALUES (?,?,?,?,?) "
                      "ON CONFLICT(type,key) DO UPDATE SET at=excluded.at, note=excluded.note, "
                      "label=CASE WHEN excluded.label!='' THEN excluded.label ELSE acks.label END",
                      (typ, key, now_iso(), (note or "")[:500], (label or "")[:300]))
        else:
            c.execute("DELETE FROM acks WHERE type=? AND key=?", (typ, key))
    return acks_load(c)


def ack_set_many(items, checked, note="", c=None):
    """Bulk check-off/restore in ONE transaction; items: [(type, key, label)]. Returns the full ack map once."""
    c = c or _dc()
    at = now_iso()
    with tx(c):
        for typ, key, label in items:
            if checked:
                c.execute("INSERT INTO acks(type,key,at,note,label) VALUES (?,?,?,?,?) "
                          "ON CONFLICT(type,key) DO UPDATE SET at=excluded.at, note=excluded.note, "
                          "label=CASE WHEN excluded.label!='' THEN excluded.label ELSE acks.label END",
                          (typ, key, at, (note or "")[:500], (label or "")[:300]))
            else:
                c.execute("DELETE FROM acks WHERE type=? AND key=?", (typ, key))
    return acks_load(c)


# ------------------------------------------------------------------ watcher mute state
def mute_filter(alerts, hours, c=None):
    """alerts: [(key, text)]. Returns the ones not muted in the last `hours`, and mutes them (atomically)."""
    c = c or _dc()
    now = time.time()
    with tx(c):
        c.execute("DELETE FROM watch_mute WHERE ts < ?", (now - hours * 3600,))
        muted = {r[0] for r in c.execute("SELECT key FROM watch_mute")}
        fresh, seen = [], set()
        for k, t in alerts:
            if k in muted or k in seen:
                continue
            seen.add(k)
            fresh.append((k, t))
        c.executemany("INSERT OR REPLACE INTO watch_mute VALUES (?,?)", [(k, now) for k, _ in fresh])
    return fresh


def mutes(c=None):
    c = c or _dc()
    return {r["key"]: r["ts"] for r in c.execute("SELECT key, ts FROM watch_mute")}


# ------------------------------------------------------------------ urgent alerts feed + web-push subscriptions
HELD_SOURCES = ("watcher", "secscan", "account", "report")  # detections: kept as events for the correlation / AI review, but not an alarm until promoted


def alerts_add(items, source="watcher", c=None):
    """items: [(key, text, severity[, targets])]. targets = device identifiers the alert is about (IPs, MACs,
    host names); derived from key+text when omitted. Queued for web push by the dashboard (pushed=0).
    An alert that matches a saved mute rule (alert_mutes) is stored already cleared: not pushed, not read-counted, hidden
    from the feed and the correlation, but kept so "show cleared" can list it."""
    c = c or _dc()
    now = time.time()
    mutes_ = mute_list(c)
    sups_ = suppress_list(c)
    rows = []
    for it in items:
        tg = sorted(it[3] if len(it) > 3 and it[3] else alert_targets(it[0], it[1]))
        hit = next((m for m in mutes_ if mute_match(m, it[1], tg)), None)
        sup = None if hit else next((r for r in sups_ if suppress_match(r, it[1], tg)), None)
        if sup:  # suppressed (not muted): hidden from the feed and not pushed, but still correlated
            hit = {"id": -sup["id"]}
        held = 1 if source in HELD_SOURCES else 0  # an alarm is an event / finding that is medium or high AND reviewed as suspicious (alerts_promote)
        rows.append((now, it[0], it[1], it[2] if len(it) > 2 else "urgent", source, json.dumps(tg),
                     1 if hit else 0, hit["id"] if hit else None, now if hit else None, 1 if (hit or held) else 0, 1 if (hit or held) else 0, held))
    with tx(c):
        c.executemany("INSERT INTO alerts(ts,key,text,severity,source,targets,cleared,cleared_rule,cleared_at,pushed,read,held) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", rows)
        c.execute("DELETE FROM alerts WHERE ts < ?", (now - 30 * 86400,))  # keep 30 days


# ------------------------------------------------------------------ alert mute rules (kept; applied to every future alert)
def _mglob(pat, text, sub):
    pat, text = str(pat).lower(), str(text).lower()
    if "*" in pat or "?" in pat:
        import re as _re  # only * and ? are wildcards; [ ] are literal (event text has "['1.2.3.4']")
        rx = "".join(".*" if ch == "*" else "." if ch == "?" else _re.escape(ch) for ch in pat)
        return _re.fullmatch(rx, text, _re.S) is not None
    return pat in text if sub else pat == text


def mute_match(m, text, targets=()):
    """Same semantics as corr_llm.rule_match for an alert: name = glob / contains over the text, host = one of the alert's
    targets or the host in its text."""
    if m.get("name") and not _mglob(m["name"], text or "", True):
        return False
    h = m.get("host")
    return not h or any(_mglob(h, t, False) for t in targets or []) or _mglob(h, text or "", True)


def mute_list(c=None):
    c = c or _dc()
    return [dict(r) for r in c.execute("SELECT * FROM alert_mutes ORDER BY id")]


def mute_add(name, host, by, limit_key="", c=None):
    """Save a mute rule and clear every existing alert it matches -> (rule id, number cleared)."""
    raise ValueError("never-send mute rules were removed")
    c = c or _dc()
    name, host = str(name or "").strip()[:200], str(host or "").strip()[:200]
    if not name.replace("*", "").replace("?", "").strip():
        raise ValueError("a mute rule needs some text that is not just wildcards")
    now = time.time()
    with tx(c):
        r = c.execute("SELECT id FROM alert_mutes WHERE lower(name)=lower(?) AND lower(host)=lower(?)", (name, host)).fetchone()
        if r:
            mid = r[0]
        else:
            if c.execute("SELECT count(*) FROM alert_mutes").fetchone()[0] >= 200:
                raise ValueError("too many mute rules (200)")
            mid = c.execute("INSERT INTO alert_mutes(name,host,by,at,limit_key) VALUES (?,?,?,?,?)", (name, host, str(by)[:60], now, limit_key)).lastrowid
    return mid, mute_apply(mid, c)


def mute_apply(mid, c=None):
    """Clear the not-yet-cleared alerts a saved rule matches."""
    c = c or _dc()
    m = next((x for x in mute_list(c) if x["id"] == mid), None)
    if not m:
        return 0
    now = time.time()
    ids = [a["id"] for a in (_arow(r) for r in c.execute("SELECT * FROM alerts WHERE cleared=0")) if mute_match(m, a["text"], a["targets"])]
    with tx(c):
        c.executemany("UPDATE alerts SET cleared=1, cleared_rule=?, cleared_at=?, read=1, pushed=1 WHERE id=?", [(mid, now, i) for i in ids])
    return len(ids)


def mute_remove(mid, c=None):
    """Delete a rule; the alerts it cleared come back into the feed (as read, never pushed) -> (limit_key, restored)."""
    c = c or _dc()
    r = c.execute("SELECT limit_key FROM alert_mutes WHERE id=?", (int(mid),)).fetchone()
    if not r:
        return None, 0
    with tx(c):
        n = c.execute("UPDATE alerts SET cleared=0, cleared_rule=NULL, cleared_at=NULL WHERE cleared_rule=?", (int(mid),)).rowcount
        c.execute("DELETE FROM alert_mutes WHERE id=?", (int(mid),))
    return r[0], n


def mute_counts(c=None):
    c = c or _dc()
    return {r[0]: r[1] for r in c.execute("SELECT cleared_rule, count(*) FROM alerts WHERE cleared=1 GROUP BY cleared_rule")}


# ------------------------------------------------------------------ suppress rules (hide a finding, keep it in correlation)
SUPPRESS_ARTS = ("ip", "domain", "user", "process", "port", "file")
_PORT_RE = re.compile(r"(?:\bport\s*|[:/])(\d{1,5})\b", re.I)


def suppress_match(r, label, ips=(), arts=(), ctx=""):
    """Does a suppress rule cover an event / alert? name = signature (glob, or contains) over the event text; art_type + art
    (ip, domain, user, process, port, file) must also be among the event's artifacts when the rule has them. ips: IPs / targets,
    arts: [[kind, value, ...]] artifacts (kind file|process|user|dns), ctx: extra text (labels of correlated events) searched
    for the artifact; for events, ips / arts / ctx also hold those of the correlated events."""
    label = str(label or "")
    if not r.get("name") or not _mglob(r["name"], label, True):
        return False
    t, v = r.get("art_type") or "", str(r.get("art") or "").strip()
    if not t or not v:
        return True
    text = label + " " + str(ctx or "")
    glob = "*" in v or "?" in v
    if t == "ip":
        if glob:
            return any(_mglob(v, i, False) for i in ips or []) or _mglob(v, text, True)
        return v.lower() in {str(i).lower() for i in ips or []} or bool(re.search(r"(?<![\d.])" + re.escape(v) + r"(?![\d.])", text))
    if t == "port":
        ports = set(_PORT_RE.findall(text)) | {str(a[1]) for a in arts or [] if a and a[0] == "port"}
        return v in ports
    kind = "dns" if t == "domain" else t
    vals = [str(a[1]) for a in arts or [] if a and a[0] == kind]
    if glob:
        return any(_mglob(v, x, False) for x in vals) or _mglob(v, text, True)
    return any(v.lower() in x.lower() for x in vals) or v.lower() in text.lower()


def suppress_list(c=None):
    c = c or _dc()
    return [dict(r) for r in c.execute("SELECT * FROM suppress_rules ORDER BY id")]


def suppress_add(name, art_type, art, by, c=None):
    """Save a suppress rule and hide the existing alerts it covers -> (rule id, alerts hidden)."""
    c = c or _dc()
    name, art_type, art = str(name or "").strip()[:200], str(art_type or "").strip().lower(), str(art or "").strip()[:200]
    if not name.replace("*", "").replace("?", "").strip():
        raise ValueError("a suppress rule needs a signature name that is not just wildcards")
    if art_type and art_type not in SUPPRESS_ARTS:
        raise ValueError("artifact type must be one of " + ", ".join(SUPPRESS_ARTS))
    if bool(art_type) != bool(art):
        raise ValueError("give both the artifact type and its value, or neither")
    with tx(c):
        r = c.execute("SELECT id FROM suppress_rules WHERE lower(name)=lower(?) AND art_type=? AND lower(art)=lower(?)", (name, art_type, art)).fetchone()
        if r:
            rid = r[0]
        else:
            if c.execute("SELECT count(*) FROM suppress_rules").fetchone()[0] >= 200:
                raise ValueError("too many suppress rules (200)")
            rid = c.execute("INSERT INTO suppress_rules(name,art_type,art,by,at) VALUES (?,?,?,?,?)", (name, art_type, art, str(by)[:60], time.time())).lastrowid
    rule = next(x for x in suppress_list(c) if x["id"] == rid)
    now = time.time()
    ids = [a["id"] for a in (_arow(x) for x in c.execute("SELECT * FROM alerts WHERE cleared=0")) if suppress_match(rule, a["text"], a["targets"])]
    with tx(c):
        c.executemany("UPDATE alerts SET cleared=1, cleared_rule=?, cleared_at=?, read=1, pushed=1 WHERE id=?", [(-rid, now, i) for i in ids])
    return rid, len(ids)


# ------------------------------------------------------------------ segmentation suppress rules (source IP / destination IP / ports)
def seg_suppress_list(c=None):
    c = c or _dc()
    return [dict(r) for r in c.execute("SELECT * FROM seg_suppress ORDER BY id")]


def seg_suppress_add(src, dst, ports, by, c=None):
    """Hide segmentation violations from source / destination (IP or glob like 10.1.*) / ports ("22,3389"); blank = any."""
    c = c or _dc()
    src, dst = str(src or "").strip()[:100], str(dst or "").strip()[:100]
    ports = ",".join(p.strip() for p in str(ports or "").replace(" ", ",").split(",") if p.strip())[:200]
    if not (src or dst or ports):
        raise ValueError("give a source IP, a destination IP or ports")
    if not all(p.isdigit() and 0 < int(p) < 65536 or p == "*" for p in ports.split(",") if p):
        raise ValueError("ports must be numbers like 22,3389")
    if any(x.replace("*", "").replace("?", "") == "" and x for x in (src, dst)) or (src in ("*",) and dst in ("*",)):
        raise ValueError("an IP of only wildcards would hide everything")
    with tx(c):
        r = c.execute("SELECT id FROM seg_suppress WHERE src=? AND dst=? AND ports=?", (src, dst, ports)).fetchone()
        if r:
            return r[0]
        if c.execute("SELECT count(*) FROM seg_suppress").fetchone()[0] >= 500:
            raise ValueError("too many segmentation suppress rules (500)")
        return c.execute("INSERT INTO seg_suppress(src,dst,ports,by,at) VALUES (?,?,?,?,?)", (src, dst, ports, str(by)[:60], time.time())).lastrowid


def seg_suppress_remove(rid, c=None):
    c = c or _dc()
    with tx(c):
        return c.execute("DELETE FROM seg_suppress WHERE id=?", (int(rid),)).rowcount


def seg_suppress_match(rules, src, dst, port):
    """True when any rule covers the flow src -> dst:port (all fields the rule has must match)."""
    for r in rules or ():
        if r.get("src") and not _mglob(r["src"], src, False):
            continue
        if r.get("dst") and not _mglob(r["dst"], dst, False):
            continue
        if r.get("ports") and str(port) not in r["ports"].split(","):
            continue
        return True
    return False


# ------------------------------------------------------------------ IDS signature suppress rules (signature, optional host)
def ids_suppress_list(c=None):
    c = c or _dc()
    return [dict(r) for r in c.execute("SELECT * FROM ids_suppress ORDER BY id")]


def ids_suppress_add(sig, host, by, c=None):
    """Hide an IDS signature (exact name, or glob with * ?) everywhere in netmon; host blank = all hosts, else only alerts with that IP."""
    c = c or _dc()
    sig, host = str(sig or "").strip()[:300], str(host or "").strip()[:100]
    if not sig or sig.replace("*", "").replace("?", "") == "":
        raise ValueError("give a signature name")
    with tx(c):
        r = c.execute("SELECT id FROM ids_suppress WHERE sig=? AND host=?", (sig, host)).fetchone()
        if r:
            return r[0]
        if c.execute("SELECT count(*) FROM ids_suppress").fetchone()[0] >= 500:
            raise ValueError("too many IDS suppress rules (500)")
        return c.execute("INSERT INTO ids_suppress(sig,host,by,at) VALUES (?,?,?,?)", (sig, host, str(by)[:60], time.time())).lastrowid


def ids_suppress_remove(rid, c=None):
    c = c or _dc()
    with tx(c):
        return c.execute("DELETE FROM ids_suppress WHERE id=?", (int(rid),)).rowcount


def ids_filter(raw, rules):
    """Copy of a snapshot's raw with the IDS signatures the rules cover removed (host rule: only that host's alerts)."""
    al = (raw or {}).get("alerts") or {}
    if not rules or not al.get("signatures"):
        return raw
    out, total, gone = [], al.get("total") or 0, 0
    for sg in al["signatures"]:
        rs = [r for r in rules if _mglob(r["sig"], sg.get("name", ""), False)]
        if not rs:
            out.append(sg)
            continue
        if any(not r["host"] for r in rs):
            gone += sg.get("count") or 0
            continue
        hosts = {r["host"] for r in rs}
        src = {k: v for k, v in (sg.get("src") or {}).items() if not any(_mglob(h, k, False) for h in hosts)}
        dst = {k: v for k, v in (sg.get("dst") or {}).items() if not any(_mglob(h, k, False) for h in hosts)}
        if not src and not dst:
            gone += sg.get("count") or 0
            continue
        n = max(sum(src.values()), sum(dst.values()))
        gone += max(0, (sg.get("count") or 0) - n)
        out.append(dict(sg, src=src, dst=dst, count=n))
    return dict(raw, alerts=dict(al, signatures=out, total=max(0, total - gone)))


def suppress_remove(rid, c=None):
    """Delete a suppress rule; the alerts it hid come back into the feed -> number restored."""
    c = c or _dc()
    with tx(c):
        n = c.execute("UPDATE alerts SET cleared=0, cleared_rule=NULL, cleared_at=NULL WHERE cleared_rule=?", (-int(rid),)).rowcount
        c.execute("DELETE FROM suppress_rules WHERE id=?", (int(rid),))
    return n


def _arow(r):
    d = dict(r)
    d["targets"] = json.loads(d.get("targets") or "[]")
    return d


def alerts_recent(limit=100, c=None, cleared=False, suppressed=False):
    """The alert feed (newest first). Alerts a mute rule cleared are left out unless cleared=True (then only those).
    suppressed=True (correlation, research, review) also returns the alerts a suppress rule hid: suppressing hides a
    finding, it does not take the event out of correlation."""
    c = c or _dc()
    if suppressed and not cleared:
        return [_arow(r) for r in c.execute("SELECT * FROM alerts WHERE (cleared=0 OR cleared_rule<0) AND source!='review' ORDER BY id DESC LIMIT ?", (limit,))]
    return [_arow(r) for r in c.execute("SELECT * FROM alerts WHERE cleared=? AND held=0 ORDER BY id DESC LIMIT ?", (1 if cleared else 0, limit))]


def alerts_promote(ids, c=None):
    """Held detections the review calls suspicious (medium/high) become alarms: into the feed, unread, queued for push."""
    c = c or _dc()
    ids = [int(i) for i in ids]
    with tx(c):
        n = 0
        for i in ids:
            n += c.execute("UPDATE alerts SET held=0, read=0, pushed=0 WHERE id=? AND held=1 AND cleared=0", (i,)).rowcount
    return n


def alerts_hold(ids, c=None):
    """The opposite: no longer suspicious / medium+ -> out of the feed again (still an event)."""
    c = c or _dc()
    ids = [int(i) for i in ids]
    with tx(c):
        n = 0
        for i in ids:
            n += c.execute("UPDATE alerts SET held=1, read=1, pushed=1 WHERE id=? AND held=0 AND source IN ('watcher','secscan','account','report')", (i,)).rowcount
    return n


def alerts_delete(ids, c=None):
    """Remove these watcher alerts (used when an analyst mutes an alert class and clears what already fired)."""
    c = c or _dc()
    ids = [int(i) for i in ids]
    if not ids:
        return 0
    with tx(c):
        c.executemany("DELETE FROM alerts WHERE id=?", [(i,) for i in ids])
    return len(ids)


def alerts_unpushed(c=None):
    c = c or _dc()
    return [_arow(r) for r in c.execute("SELECT * FROM alerts WHERE pushed=0 ORDER BY id")]


# ---- per-device alert subscriptions
_IP_RE = re.compile(r"\b(?:10|172|192)\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
_MAC_RE = re.compile(r"\b[0-9a-f]{2}(?::[0-9a-f]{2}){5}\b", re.I)


def _endpoint_ips():
    try:
        return {k.lower(): v for k, v in cfg_load("host_policy", shared=True).get("endpoint_ips", {}).items()}
    except Exception:
        return {}


def _label(name):
    return (name or "").strip().lower().split(".")[0]


def alert_targets(key, text):
    """Device identifiers an alert is about: private IPv4s, MACs, and (for endpoint alerts) host name + mapped IP."""
    s = f"{key} {text}"
    t = {"ip:" + ip for ip in _IP_RE.findall(s) if ip.startswith(("10.", "192.168.")) or re.match(r"172\.(1[6-9]|2\d|3[01])\.", ip)}
    t |= {"mac:" + m.lower() for m in _MAC_RE.findall(s)}
    parts = key.split("|")
    if parts[0] == "host" and len(parts) >= 3:  # host|<kind>|<hostname>|...
        hname = parts[2].lower()
        t.add("host:" + _label(hname))
        ip = _endpoint_ips().get(hname)
        if ip:
            t.add("ip:" + ip)
    return t


def device_ids(dev):
    """Identifiers of a registry device: its IPs, MAC and name label (matches endpoint host alerts)."""
    out = {"ip:" + ip for ip in dev.get("ips") or []}
    if dev.get("mac"):
        out.add("mac:" + dev["mac"].lower())
    if dev.get("name") and not _IP_RE.fullmatch(dev["name"]):
        out.add("host:" + _label(dev["name"]))
    for h, ip in _endpoint_ips().items():
        if ip in (dev.get("ips") or []):
            out.add("host:" + _label(h))
    return out


def prefs_get(user, c=None):
    c = c or _dc()
    r = c.execute("SELECT mode, devices FROM push_prefs WHERE user=?", (user,)).fetchone()
    return {"mode": r["mode"], "devices": json.loads(r["devices"])} if r else {"mode": "all", "devices": []}


def prefs_set(user, mode, devices, c=None):
    c = c or _dc()
    if mode not in ("all", "some"):
        raise ValueError("mode must be all or some")
    with tx(c):
        c.execute("INSERT INTO push_prefs(user,mode,devices,updated) VALUES (?,?,?,?) ON CONFLICT(user) DO UPDATE SET "
                  "mode=excluded.mode, devices=excluded.devices, updated=excluded.updated",
                  (user, mode, json.dumps(sorted(set(map(str, devices)))[:500]), now_iso()))
    return prefs_get(user, c)


def watch_ids(user, c=None, reg=None):
    """None = all devices; else the identifier set of the user's chosen devices (resolved now, so DHCP changes follow)."""
    c = c or _dc()
    p = prefs_get(user, c)
    if p["mode"] == "all":
        return None
    reg = reg if reg is not None else registry_load(c)
    ids = set()
    for k in p["devices"]:
        if k in reg:
            ids |= device_ids(reg[k])
        elif k.startswith("host:"):
            ids.add("host:" + _label(k[5:]))
            ip = _endpoint_ips().get(k[5:].lower())
            if ip:
                ids.add("ip:" + ip)
    return ids


def alert_for(alert, ids):
    return ids is None or bool(ids & set(alert.get("targets") or []))


def alerts_mark(ids, field="pushed", c=None):
    c = c or _dc()
    if field not in ("pushed", "read") or not ids:
        return
    with tx(c):
        c.executemany(f"UPDATE alerts SET {field}=1 WHERE id=?", [(i,) for i in ids])


def alerts_read_all(c=None):
    c = c or _dc()
    with tx(c):
        c.execute("UPDATE alerts SET read=1 WHERE read=0")


def push_sub_save(sub, user, ua="", c=None):
    c = c or _dc()
    with tx(c):
        c.execute("INSERT INTO push_subs(endpoint,user,keys,ua,created,fails) VALUES (?,?,?,?,?,0) "
                  "ON CONFLICT(endpoint) DO UPDATE SET user=excluded.user, keys=excluded.keys, ua=excluded.ua, fails=0",
                  (sub["endpoint"], user, json.dumps(sub.get("keys") or {}), ua[:200], now_iso()))


def push_sub_delete(endpoint, c=None):
    c = c or _dc()
    with tx(c):
        c.execute("DELETE FROM push_subs WHERE endpoint=?", (endpoint,))


def push_subs(c=None):
    c = c or _dc()
    return [dict(r, keys=json.loads(r["keys"])) for r in c.execute("SELECT * FROM push_subs")]


def push_sub_result(endpoint, ok, c=None):
    c = c or _dc()
    with tx(c):
        if ok:
            c.execute("UPDATE push_subs SET last_ok=?, fails=0 WHERE endpoint=?", (now_iso(), endpoint))
        else:
            c.execute("UPDATE push_subs SET fails=fails+1 WHERE endpoint=?", (endpoint,))
            c.execute("DELETE FROM push_subs WHERE endpoint=? AND fails>=5", (endpoint,))


# ------------------------------------------------------------------ software security findings (sec_scan.sh -> secfindings.py)
def sec_sync(findings, c=None):
    """findings: [{key, tool, severity, title, location, fix, detail}] = everything currently open (accepted ones removed).
    Upserts them, marks previously-open keys that disappeared as fixed. Returns (new, still_open, fixed) lists of keys."""
    c = c or _dc()
    now = now_iso()
    cur = {f["key"]: f for f in findings}
    with tx(c):
        prev = {r["key"]: r["status"] for r in c.execute("SELECT key, status FROM sec_findings")}
        new = [k for k in cur if prev.get(k) != "open"]
        for k, f in cur.items():
            c.execute("INSERT INTO sec_findings(key,tool,severity,title,location,fix,detail,first_seen,last_seen,status,notified) "
                      "VALUES (?,?,?,?,?,?,?,?,?, 'open', 0) ON CONFLICT(key) DO UPDATE SET severity=excluded.severity, "
                      "title=excluded.title, location=excluded.location, fix=excluded.fix, detail=excluded.detail, "
                      "last_seen=excluded.last_seen, status='open', fixed_at=NULL, "
                      "notified=CASE WHEN sec_findings.status='open' THEN sec_findings.notified ELSE 0 END",
                      (k, f.get("tool"), f.get("severity"), f.get("title"), f.get("location"), f.get("fix"), f.get("detail"), now, now))
        fixed = [k for k, s in prev.items() if s == "open" and k not in cur]
        c.executemany("UPDATE sec_findings SET status='fixed', fixed_at=? WHERE key=?", [(now, k) for k in fixed])
    return new, [k for k in cur if k not in new], fixed


def sec_list(status=None, c=None):
    c = c or _dc()
    q = "SELECT * FROM sec_findings" + (" WHERE status=?" if status else "") + " ORDER BY last_seen DESC"
    return [dict(r) for r in c.execute(q, (status,) if status else ())]


def sec_mark_notified(keys, c=None):
    c = c or _dc()
    with tx(c):
        c.executemany("UPDATE sec_findings SET notified=1 WHERE key=?", [(k,) for k in keys])


# ------------------------------------------------------------------ device registry
def registry_load(c=None):
    c = c or _dc()
    return {r["key"]: json.loads(r["doc"]) for r in c.execute("SELECT key, doc FROM devices")}


def registry_save(reg, c=None):
    c = c or _dc()
    with tx(c):
        c.executemany("INSERT INTO devices(key,mac,name,first_seen,last_seen,known,doc) VALUES (?,?,?,?,?,?,?) "
                      "ON CONFLICT(key) DO UPDATE SET mac=excluded.mac, name=excluded.name, first_seen=excluded.first_seen, "
                      "last_seen=excluded.last_seen, known=excluded.known, doc=excluded.doc",
                      [(k, v.get("mac"), v.get("name"), v.get("first_seen"), v.get("last_seen"), int(bool(v.get("known"))),
                        json.dumps(v)) for k, v in reg.items()])


def registry_ips(c=None):
    c = c or _dc()
    ips = set()
    for r in c.execute("SELECT doc FROM devices"):
        ips.update(json.loads(r[0]).get("ips") or [])
    return ips


# ------------------------------------------------------------------ host baseline (hosts.py / osq.py)
def hosts_load(c=None):
    """Same shape as the old hosts_seen.json: {host: {kind: dict|str}, "_meta": {...}}."""
    c = c or _dc()
    out = {}
    for r in c.execute("SELECT host, kind, doc FROM host_baseline"):
        out.setdefault(r["host"], {})[r["kind"]] = json.loads(r["doc"])
    return out


def hosts_save(base, c=None):
    """Upsert every (host, kind) document in one transaction. A kind's document is replaced whole (osq removals work)."""
    c = c or _dc()
    ts = now_iso()
    rows = [(h, k, json.dumps(v, sort_keys=True), ts) for h, kinds in base.items() if isinstance(kinds, dict) for k, v in kinds.items()]
    with tx(c):
        c.executemany("INSERT INTO host_baseline(host,kind,doc,updated) VALUES (?,?,?,?) "
                      "ON CONFLICT(host,kind) DO UPDATE SET doc=excluded.doc, updated=excluded.updated "
                      "WHERE host_baseline.doc != excluded.doc", rows)


# ------------------------------------------------------------------ per-snapshot history (analyze.py baseline)
def history_load(c=None, limit=None):
    c = c or _dc()
    sql = "SELECT doc FROM history ORDER BY generated"
    rows = [json.loads(r[0]) for r in c.execute(sql)]
    return rows[-limit:] if limit else rows


def history_has(generated, c=None):
    c = c or _dc()
    return c.execute("SELECT 1 FROM history WHERE generated=?", (generated,)).fetchone() is not None


def _served_rows(rec):
    out = set()
    for d in (rec.get("devices") or {}).values():
        for p in (d.get("served") or {}):
            if d.get("ip"):
                out.add((rec["generated"], d["ip"], str(p).split("/")[0]))
    return out


def history_append(rec, keep=None, c=None):
    c = c or _dc()
    with tx(c):
        c.execute("INSERT OR REPLACE INTO history(generated,hours,doc) VALUES (?,?,?)", (rec["generated"], rec.get("hours"), json.dumps(rec)))
        c.executemany("INSERT OR IGNORE INTO served_ports VALUES (?,?,?)", list(_served_rows(rec)))
        if keep:
            c.execute("DELETE FROM history WHERE generated NOT IN (SELECT generated FROM history ORDER BY generated DESC LIMIT ?)", (keep,))


def served_ports(c=None):
    """{ip: {port,...}} across retained history - what the watcher needs, without parsing the history docs."""
    c = c or _dc()
    out = {}
    for r in c.execute("SELECT DISTINCT ip, port FROM served_ports"):
        out.setdefault(r["ip"], set()).add(r["port"])
    return out


def history_count(c=None):
    c = c or _dc()
    return c.execute("SELECT COUNT(*) FROM history").fetchone()[0]


# ------------------------------------------------------------------ ops
def migrate(base_dir=None, acks_file=None, c=None, overwrite=False):
    """One-time import of the legacy JSON files. Idempotent; refuses to clobber existing rows unless overwrite."""
    base_dir = base_dir or os.path.join(HERE, "baseline")
    acks_file = acks_file or os.path.join(HERE, "dashboard", "state", "acks.json")
    c = c or _dc()
    done = {}
    if not overwrite and c.execute("SELECT v FROM meta WHERE k='migrated_at'").fetchone():
        raise SystemExit("already migrated (meta.migrated_at set); pass overwrite=True to re-import")

    def lj(p, d):
        try:
            return json.load(open(p))
        except Exception:
            return d
    reg = lj(os.path.join(base_dir, "devices_seen.json"), {})
    registry_save(reg, c)
    done["devices"] = len(reg)
    hs = lj(os.path.join(base_dir, "hosts_seen.json"), {})
    hosts_save(hs, c)
    done["host_baseline_docs"] = sum(len(v) for v in hs.values() if isinstance(v, dict))
    n = 0
    hp = os.path.join(base_dir, "history.jsonl")
    if os.path.exists(hp):
        for line in open(hp):
            if line.strip():
                history_append(json.loads(line), c=c)
                n += 1
    done["history"] = n
    ws = lj(os.path.join(base_dir, "watch_state.json"), {})
    with tx(c):
        c.executemany("INSERT OR REPLACE INTO watch_mute VALUES (?,?)", list(ws.items()))
    done["watch_mute"] = len(ws)
    a = lj(acks_file, {})
    with tx(c):
        for typ, b in a.items():
            for k, v in (b or {}).items():
                c.execute("INSERT OR REPLACE INTO acks VALUES (?,?,?,?,?)", (typ, k, v.get("at") or now_iso(), v.get("note", ""), v.get("label", "")))
    done["acks"] = sum(len(b or {}) for b in a.values())
    with tx(c):
        c.execute("INSERT OR REPLACE INTO meta VALUES ('migrated_at', ?)", (now_iso(),))
        c.execute("INSERT OR REPLACE INTO meta VALUES ('migrated_counts', ?)", (json.dumps(done),))
    return done


def stats(c=None):
    c = c or _dc()
    t = {r[0]: c.execute(f"SELECT COUNT(*) FROM {r[0]}").fetchone()[0]
         for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    t["_file_bytes"] = os.path.getsize(db_path()) if os.path.exists(db_path()) else 0
    t["_meta"] = {r[0]: r[1] for r in c.execute("SELECT k, v FROM meta")}
    return t


def backup(dest_dir=None, keep=14, c=None):
    """Consistent online copy (sqlite backup API) to baseline/backup/netmon-YYYYmmdd.db; keeps the last `keep`."""
    c = c or _dc()
    dest_dir = dest_dir or os.environ.get("NETMON_BACKUP_DIR") or os.path.join(HERE, "baseline", "backup")
    os.makedirs(dest_dir, exist_ok=True)
    dest = os.path.join(dest_dir, f"netmon-{time.strftime('%Y%m%d')}.db")
    b = sqlite3.connect(dest)
    c.backup(b)
    b.close()
    olds = sorted(glob.glob(os.path.join(dest_dir, "netmon-*.db")))
    for p in olds[:-keep]:
        os.remove(p)
    return dest


def integrity(c=None):
    c = c or _dc()
    return c.execute("PRAGMA integrity_check").fetchone()[0]


def export(dest_dir, c=None):
    """Rollback path: write the legacy JSON files back out."""
    c = c or _dc()
    os.makedirs(dest_dir, exist_ok=True)
    json.dump(registry_load(c), open(os.path.join(dest_dir, "devices_seen.json"), "w"), indent=1)
    json.dump(hosts_load(c), open(os.path.join(dest_dir, "hosts_seen.json"), "w"), indent=1, sort_keys=True)
    json.dump(mutes(c), open(os.path.join(dest_dir, "watch_state.json"), "w"))
    json.dump(acks_load(c), open(os.path.join(dest_dir, "acks.json"), "w"), indent=1)
    with open(os.path.join(dest_dir, "history.jsonl"), "w") as f:
        for h in history_load(c):
            f.write(json.dumps(h) + "\n")
    return dest_dir


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "stats"
    if cmd == "migrate":
        print(json.dumps(migrate(overwrite="--overwrite" in sys.argv)))
    elif cmd == "stats":
        print(db_path())
        print(json.dumps(stats(), indent=1))
    elif cmd == "backup":
        print(backup())
    elif cmd == "cfg-import":  # store.py cfg-import <doc> <file.json>: load a settings file into the cfg table
        print(cfg_save(sys.argv[2], json.load(open(sys.argv[3]))), "rows")
    elif cmd == "cfg-export":  # store.py cfg-export <doc>: print it as JSON (backup / rollback)
        print(json.dumps(cfg_load(sys.argv[2]), indent=1))
    elif cmd == "check":
        print(integrity())
    elif cmd == "export":
        print(export(sys.argv[2]))
