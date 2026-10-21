#!/usr/bin/python3
"""netmon operational store (SQLite, WAL). Single source of truth for netmon's own state.

Replaces the JSON files:
  baseline/devices_seen.json   -> table devices        (registry_load / registry_save)
  baseline/hosts_seen.json     -> table host_baseline  (hosts_load / hosts_save)
  baseline/history.jsonl       -> table history (+ served_ports index)  (history_load / history_append)
  baseline/watch_state.json    -> table watch_mute     (mute_filter)
  dashboard/state/acks.json    -> table acks           (acks_load / ack_set)

Raw events stay in Security Onion Elasticsearch; nightly snapshots stay in data/*.json (for now).

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
CREATE TABLE IF NOT EXISTS sec_findings (
  key TEXT PRIMARY KEY, tool TEXT, severity TEXT, title TEXT, location TEXT, fix TEXT, detail TEXT,
  first_seen TEXT, last_seen TEXT, status TEXT NOT NULL DEFAULT 'open', fixed_at TEXT, notified INTEGER DEFAULT 0);
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
    for col, decl in (("cleared", "INTEGER NOT NULL DEFAULT 0"), ("cleared_rule", "INTEGER"), ("cleared_at", "REAL")):  # alerts a mute rule cleared (kept, hidden from the feed)
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


# ------------------------------------------------------------------ acks (dashboard check-offs)
def acks_load(c=None):
    c = c or connect()
    out = {"issue": {}, "alarm": {}, "finding": {}, "host": {}}
    for r in c.execute("SELECT type, key, at, note, label FROM acks"):
        out.setdefault(r["type"], {})[r["key"]] = {"at": r["at"], "note": r["note"], "label": r["label"]}
    return out


def ack_set(typ, key, checked, note="", label="", c=None):
    c = c or connect()
    with tx(c):
        if checked:
            c.execute("INSERT INTO acks(type,key,at,note,label) VALUES (?,?,?,?,?) "
                      "ON CONFLICT(type,key) DO UPDATE SET at=excluded.at, note=excluded.note, "
                      "label=CASE WHEN excluded.label!='' THEN excluded.label ELSE acks.label END",
                      (typ, key, now_iso(), (note or "")[:500], (label or "")[:300]))
        else:
            c.execute("DELETE FROM acks WHERE type=? AND key=?", (typ, key))
    return acks_load(c)


# ------------------------------------------------------------------ watcher mute state
def mute_filter(alerts, hours, c=None):
    """alerts: [(key, text)]. Returns the ones not muted in the last `hours`, and mutes them (atomically)."""
    c = c or connect()
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
    c = c or connect()
    return {r["key"]: r["ts"] for r in c.execute("SELECT key, ts FROM watch_mute")}


# ------------------------------------------------------------------ urgent alerts feed + web-push subscriptions
def alerts_add(items, source="watcher", c=None):
    """items: [(key, text, severity[, targets])]. targets = device identifiers the alert is about (IPs, MACs,
    host names); derived from key+text when omitted. Queued for web push by the dashboard (pushed=0).
    An alert that matches a saved mute rule (alert_mutes) is stored already cleared: not pushed, not read-counted, hidden
    from the feed and the correlation, but kept so "show cleared" can list it."""
    c = c or connect()
    now = time.time()
    mutes_ = mute_list(c)
    rows = []
    for it in items:
        tg = sorted(it[3] if len(it) > 3 and it[3] else alert_targets(it[0], it[1]))
        hit = next((m for m in mutes_ if mute_match(m, it[1], tg)), None)
        rows.append((now, it[0], it[1], it[2] if len(it) > 2 else "urgent", source, json.dumps(tg),
                     1 if hit else 0, hit["id"] if hit else None, now if hit else None, 1 if hit else 0, 1 if hit else 0))
    with tx(c):
        c.executemany("INSERT INTO alerts(ts,key,text,severity,source,targets,cleared,cleared_rule,cleared_at,pushed,read) VALUES (?,?,?,?,?,?,?,?,?,?,?)", rows)
        c.execute("DELETE FROM alerts WHERE ts < ?", (now - 30 * 86400,))  # keep 30 days


# ------------------------------------------------------------------ alert mute rules (kept; applied to every future alert)
def _mglob(pat, text, sub):
    pat, text = str(pat).lower(), str(text).lower()
    if "*" in pat or "?" in pat:
        import fnmatch
        return fnmatch.fnmatchcase(text, pat)
    return pat in text if sub else pat == text


def mute_match(m, text, targets=()):
    """Same semantics as corr_llm.rule_match for an alert: name = glob / contains over the text, host = one of the alert's
    targets or the host in its text."""
    if m.get("name") and not _mglob(m["name"], text or "", True):
        return False
    h = m.get("host")
    return not h or any(_mglob(h, t, False) for t in targets or []) or _mglob(h, text or "", True)


def mute_list(c=None):
    c = c or connect()
    return [dict(r) for r in c.execute("SELECT * FROM alert_mutes ORDER BY id")]


def mute_add(name, host, by, limit_key="", c=None):
    """Save a mute rule and clear every existing alert it matches -> (rule id, number cleared)."""
    c = c or connect()
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
    c = c or connect()
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
    c = c or connect()
    r = c.execute("SELECT limit_key FROM alert_mutes WHERE id=?", (int(mid),)).fetchone()
    if not r:
        return None, 0
    with tx(c):
        n = c.execute("UPDATE alerts SET cleared=0, cleared_rule=NULL, cleared_at=NULL WHERE cleared_rule=?", (int(mid),)).rowcount
        c.execute("DELETE FROM alert_mutes WHERE id=?", (int(mid),))
    return r[0], n


def mute_counts(c=None):
    c = c or connect()
    return {r[0]: r[1] for r in c.execute("SELECT cleared_rule, count(*) FROM alerts WHERE cleared=1 GROUP BY cleared_rule")}


def _arow(r):
    d = dict(r)
    d["targets"] = json.loads(d.get("targets") or "[]")
    return d


def alerts_recent(limit=100, c=None, cleared=False):
    """The alert feed (newest first). Alerts a mute rule cleared are left out unless cleared=True (then only those)."""
    c = c or connect()
    return [_arow(r) for r in c.execute("SELECT * FROM alerts WHERE cleared=? ORDER BY id DESC LIMIT ?", (1 if cleared else 0, limit))]


def alerts_delete(ids, c=None):
    """Remove these watcher alerts (used when an analyst mutes an alert class and clears what already fired)."""
    c = c or connect()
    ids = [int(i) for i in ids]
    if not ids:
        return 0
    with tx(c):
        c.executemany("DELETE FROM alerts WHERE id=?", [(i,) for i in ids])
    return len(ids)


def alerts_unpushed(c=None):
    c = c or connect()
    return [_arow(r) for r in c.execute("SELECT * FROM alerts WHERE pushed=0 ORDER BY id")]


# ---- per-device alert subscriptions
_IP_RE = re.compile(r"\b(?:10|172|192)\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
_MAC_RE = re.compile(r"\b[0-9a-f]{2}(?::[0-9a-f]{2}){5}\b", re.I)


def _endpoint_ips():
    try:
        return {k.lower(): v for k, v in json.load(open(os.path.join(HERE, "host_policy.json"))).get("endpoint_ips", {}).items()}
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
    c = c or connect()
    r = c.execute("SELECT mode, devices FROM push_prefs WHERE user=?", (user,)).fetchone()
    return {"mode": r["mode"], "devices": json.loads(r["devices"])} if r else {"mode": "all", "devices": []}


def prefs_set(user, mode, devices, c=None):
    c = c or connect()
    if mode not in ("all", "some"):
        raise ValueError("mode must be all or some")
    with tx(c):
        c.execute("INSERT INTO push_prefs(user,mode,devices,updated) VALUES (?,?,?,?) ON CONFLICT(user) DO UPDATE SET "
                  "mode=excluded.mode, devices=excluded.devices, updated=excluded.updated",
                  (user, mode, json.dumps(sorted(set(map(str, devices)))[:500]), now_iso()))
    return prefs_get(user, c)


def watch_ids(user, c=None, reg=None):
    """None = all devices; else the identifier set of the user's chosen devices (resolved now, so DHCP changes follow)."""
    c = c or connect()
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
    c = c or connect()
    if field not in ("pushed", "read") or not ids:
        return
    with tx(c):
        c.executemany(f"UPDATE alerts SET {field}=1 WHERE id=?", [(i,) for i in ids])


def alerts_read_all(c=None):
    c = c or connect()
    with tx(c):
        c.execute("UPDATE alerts SET read=1 WHERE read=0")


def push_sub_save(sub, user, ua="", c=None):
    c = c or connect()
    with tx(c):
        c.execute("INSERT INTO push_subs(endpoint,user,keys,ua,created,fails) VALUES (?,?,?,?,?,0) "
                  "ON CONFLICT(endpoint) DO UPDATE SET user=excluded.user, keys=excluded.keys, ua=excluded.ua, fails=0",
                  (sub["endpoint"], user, json.dumps(sub.get("keys") or {}), ua[:200], now_iso()))


def push_sub_delete(endpoint, c=None):
    c = c or connect()
    with tx(c):
        c.execute("DELETE FROM push_subs WHERE endpoint=?", (endpoint,))


def push_subs(c=None):
    c = c or connect()
    return [dict(r, keys=json.loads(r["keys"])) for r in c.execute("SELECT * FROM push_subs")]


def push_sub_result(endpoint, ok, c=None):
    c = c or connect()
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
    c = c or connect()
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
    c = c or connect()
    q = "SELECT * FROM sec_findings" + (" WHERE status=?" if status else "") + " ORDER BY last_seen DESC"
    return [dict(r) for r in c.execute(q, (status,) if status else ())]


def sec_mark_notified(keys, c=None):
    c = c or connect()
    with tx(c):
        c.executemany("UPDATE sec_findings SET notified=1 WHERE key=?", [(k,) for k in keys])


# ------------------------------------------------------------------ device registry
def registry_load(c=None):
    c = c or connect()
    return {r["key"]: json.loads(r["doc"]) for r in c.execute("SELECT key, doc FROM devices")}


def registry_save(reg, c=None):
    c = c or connect()
    with tx(c):
        c.executemany("INSERT INTO devices(key,mac,name,first_seen,last_seen,known,doc) VALUES (?,?,?,?,?,?,?) "
                      "ON CONFLICT(key) DO UPDATE SET mac=excluded.mac, name=excluded.name, first_seen=excluded.first_seen, "
                      "last_seen=excluded.last_seen, known=excluded.known, doc=excluded.doc",
                      [(k, v.get("mac"), v.get("name"), v.get("first_seen"), v.get("last_seen"), int(bool(v.get("known"))),
                        json.dumps(v)) for k, v in reg.items()])


def registry_ips(c=None):
    c = c or connect()
    ips = set()
    for r in c.execute("SELECT doc FROM devices"):
        ips.update(json.loads(r[0]).get("ips") or [])
    return ips


# ------------------------------------------------------------------ host baseline (hosts.py / osq.py)
def hosts_load(c=None):
    """Same shape as the old hosts_seen.json: {host: {kind: dict|str}, "_meta": {...}}."""
    c = c or connect()
    out = {}
    for r in c.execute("SELECT host, kind, doc FROM host_baseline"):
        out.setdefault(r["host"], {})[r["kind"]] = json.loads(r["doc"])
    return out


def hosts_save(base, c=None):
    """Upsert every (host, kind) document in one transaction. A kind's document is replaced whole (osq removals work)."""
    c = c or connect()
    ts = now_iso()
    rows = [(h, k, json.dumps(v, sort_keys=True), ts) for h, kinds in base.items() if isinstance(kinds, dict) for k, v in kinds.items()]
    with tx(c):
        c.executemany("INSERT INTO host_baseline(host,kind,doc,updated) VALUES (?,?,?,?) "
                      "ON CONFLICT(host,kind) DO UPDATE SET doc=excluded.doc, updated=excluded.updated "
                      "WHERE host_baseline.doc != excluded.doc", rows)


# ------------------------------------------------------------------ per-snapshot history (analyze.py baseline)
def history_load(c=None, limit=None):
    c = c or connect()
    sql = "SELECT doc FROM history ORDER BY generated"
    rows = [json.loads(r[0]) for r in c.execute(sql)]
    return rows[-limit:] if limit else rows


def history_has(generated, c=None):
    c = c or connect()
    return c.execute("SELECT 1 FROM history WHERE generated=?", (generated,)).fetchone() is not None


def _served_rows(rec):
    out = set()
    for d in (rec.get("devices") or {}).values():
        for p in (d.get("served") or {}):
            if d.get("ip"):
                out.add((rec["generated"], d["ip"], str(p).split("/")[0]))
    return out


def history_append(rec, keep=None, c=None):
    c = c or connect()
    with tx(c):
        c.execute("INSERT OR REPLACE INTO history(generated,hours,doc) VALUES (?,?,?)", (rec["generated"], rec.get("hours"), json.dumps(rec)))
        c.executemany("INSERT OR IGNORE INTO served_ports VALUES (?,?,?)", list(_served_rows(rec)))
        if keep:
            c.execute("DELETE FROM history WHERE generated NOT IN (SELECT generated FROM history ORDER BY generated DESC LIMIT ?)", (keep,))


def served_ports(c=None):
    """{ip: {port,...}} across retained history - what the watcher needs, without parsing the history docs."""
    c = c or connect()
    out = {}
    for r in c.execute("SELECT DISTINCT ip, port FROM served_ports"):
        out.setdefault(r["ip"], set()).add(r["port"])
    return out


def history_count(c=None):
    c = c or connect()
    return c.execute("SELECT COUNT(*) FROM history").fetchone()[0]


# ------------------------------------------------------------------ ops
def migrate(base_dir=None, acks_file=None, c=None, overwrite=False):
    """One-time import of the legacy JSON files. Idempotent; refuses to clobber existing rows unless overwrite."""
    base_dir = base_dir or os.path.join(HERE, "baseline")
    acks_file = acks_file or os.path.join(HERE, "dashboard", "state", "acks.json")
    c = c or connect()
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
    c = c or connect()
    t = {r[0]: c.execute(f"SELECT COUNT(*) FROM {r[0]}").fetchone()[0]
         for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    t["_file_bytes"] = os.path.getsize(db_path()) if os.path.exists(db_path()) else 0
    t["_meta"] = {r[0]: r[1] for r in c.execute("SELECT k, v FROM meta")}
    return t


def backup(dest_dir=None, keep=14, c=None):
    """Consistent online copy (sqlite backup API) to baseline/backup/netmon-YYYYmmdd.db; keeps the last `keep`."""
    c = c or connect()
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
    c = c or connect()
    return c.execute("PRAGMA integrity_check").fetchone()[0]


def export(dest_dir, c=None):
    """Rollback path: write the legacy JSON files back out."""
    c = c or connect()
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
    elif cmd == "check":
        print(integrity())
    elif cmd == "export":
        print(export(sys.argv[2]))
