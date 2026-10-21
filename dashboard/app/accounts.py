"""Accounts seen on the network (Network > Users) and the profile notes the correlation writes.

Everything here is deterministic (no LLM): each snapshot's correlation pass records what it already knows,

  user_obs(snap, user, host, src, via, kind, hour, ok, fail, n)   who did what where, per snapshot (idempotent: a snapshot's rows are
                                                                  replaced on every pass)
  ip_obs(snap, ip, role, etype, n)                                 how often an IP appears in correlated events and as what
  ip_arts(snap, ip, kind, value, n)                                users / processes / DNS names that appear in those events

and then summarises them as host notes (category `behavior`, via `correlation profile`, tagged `[profile:...]` so a note is
updated in place and left untouched when its text did not change):
  - frequent IP addresses: how often they show up, as source or destination, in which kinds of events, with which accounts,
    processes and names
  - the accounts that log in to / run things on a host, where they come from and how they log in

Sources for accounts (raw snapshot): endpoint logins, auth failures, sudo, account changes, admin sessions (SSH/RDP/...),
and suspicious processes. Tables live in kb.db next to the host notes.

CLI (inside the dashboard container, after `import server`): accounts.py backfill  - record every stored snapshot.
"""
import re
import sqlite3
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone

import kb

VIA = "correlation profile"
MIN_IP_EVENTS = {"int": 5, "ext": 3}   # events (summed over reports) before an IP is "frequent"
MAX_IP_NOTES = 25
_IP = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_NEWUSER = re.compile(r"(?:new|delete[d]?|removed) user: name=([A-Za-z_][\w.-]{0,31})")


def _db():
    c = sqlite3.connect(kb.DB, timeout=10)
    c.execute("""CREATE TABLE IF NOT EXISTS user_obs (snap TEXT, user TEXT, host TEXT, src TEXT, via TEXT, kind TEXT, hour INTEGER,
                 ok INTEGER, fail INTEGER, n INTEGER, ts REAL, PRIMARY KEY (snap, user, host, src, via, kind, hour))""")
    c.execute("CREATE INDEX IF NOT EXISTS user_obs_user ON user_obs(user)")
    c.execute("""CREATE TABLE IF NOT EXISTS ip_obs (snap TEXT, ip TEXT, role TEXT, etype TEXT, n INTEGER, PRIMARY KEY (snap, ip, role, etype))""")
    c.execute("""CREATE TABLE IF NOT EXISTS ip_arts (snap TEXT, ip TEXT, kind TEXT, value TEXT, n INTEGER, PRIMARY KEY (snap, ip, kind, value))""")
    c.execute("CREATE INDEX IF NOT EXISTS ip_obs_ip ON ip_obs(ip)")
    return c


def _ts(v):
    if not v:
        return None
    try:
        return datetime.fromisoformat(str(v).replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def _hour(v):
    t = _ts(v)
    return datetime.fromtimestamp(t, timezone.utc).hour if t else -1


def _short(h):
    h = str(h or "")
    return h if _IP.match(h) else h.split(".")[0]


# ---------------------------------------------------------------- accounts
def observations(raw, admin):
    """raw snapshot + lateral.admin_sessions() -> [(user, host, src, via, kind, hour, ok, fail, n)]."""
    H = (raw or {}).get("hosts") or {}
    A = H.get("auth") or {}
    out = []
    for r in A.get("logins") or []:
        u = str(r.get("user") or "").strip()
        if not u:
            continue
        c = int(r.get("count") or 1)
        good = str(r.get("outcome") or "").lower() in ("success", "ok", "accepted")
        out.append((u, r.get("host") or "", r.get("src") or "", r.get("via") or "", "login", _hour(r.get("last")), c if good else 0, 0 if good else c, c))
    for r in A.get("failures") or []:
        srcs = sorted((r.get("sources") or {}).items(), key=lambda x: -x[1])
        procs = sorted((r.get("processes") or {}).items(), key=lambda x: -x[1])
        for u, c in (r.get("users") or {}).items():
            out.append((str(u), r.get("host") or "", srcs[0][0] if srcs else "", procs[0][0] if procs else "", "authfail", -1, 0, int(c), int(c)))
    for r in A.get("sudo") or []:
        u = str(r.get("user") or "").strip()
        if u:
            c = int(r.get("count") or 1)
            bad = bool(r.get("error"))
            out.append((u, r.get("host") or "", "as " + str(r.get("as") or "root"), str(r.get("command") or "")[:120], "sudo", _hour(r.get("last")), 0 if bad else c, c if bad else 0, c))
    for r in A.get("account_changes") or []:
        m = _NEWUSER.search(str(r.get("message") or ""))
        if m:
            out.append((m.group(1), r.get("host") or "", "", str(r.get("process") or ""), "account-change", _hour(r.get("at")), 1, 0, 1))
    for a in admin or []:
        hrs = {_hour(a.get("first")), _hour(a.get("last"))}
        for u, v in (a.get("users") or {}).items():
            ok, fail = int((v or {}).get("ok") or 0), int((v or {}).get("fail") or 0)
            for h in hrs:
                out.append((str(u), a.get("dst") or "", a.get("src") or "", a.get("protocol") or "", "admin", h, ok, fail, ok + fail))
    for p in (H.get("processes") or {}).get("suspicious") or []:
        u = str(p.get("user") or "").strip()
        if u:
            out.append((u, p.get("host") or "", "", str(p.get("exe") or "")[:120], "process", _hour(p.get("at")), 0, 0, int(p.get("count") or 1)))
    return out


def record_users(sid, raw, admin):
    rows = {}
    for u, host, src, via, kind, hour, ok, fail, n in observations(raw, admin):
        k = (u, host, src, via, kind, hour)
        o = rows.setdefault(k, [0, 0, 0])
        o[0] += ok; o[1] += fail; o[2] += n
    now = time.time()
    with _db() as c:
        c.execute("DELETE FROM user_obs WHERE snap=?", (sid,))
        c.executemany("INSERT OR REPLACE INTO user_obs VALUES (?,?,?,?,?,?,?,?,?,?,?)", [(sid, *k, *v, now) for k, v in rows.items()])
    return len(rows)


def _load():
    with _db() as c:
        rows = c.execute("SELECT snap, user, host, src, via, kind, hour, ok, fail, n FROM user_obs").fetchall()
        snaps = sorted({r[0] for r in c.execute("SELECT DISTINCT snap FROM user_obs")})
    return rows, snaps


def _snap_time(sid):
    m = re.match(r"(\d{4})-(\d\d)-(\d\d)T(\d\d)(\d\d)Z", sid or "")
    return datetime(*map(int, m.groups()), tzinfo=timezone.utc).timestamp() if m else None


def _top(cn, n=4):
    return [k for k, _ in cn.most_common(n) if k]


def overview(user=None, all_snaps=0):
    """Per account: totals and patterns. user= adds the full breakdown for that account."""
    rows, snaps = _load()
    total_snaps = max(all_snaps, len(snaps), 1)
    U = {}
    for snap, u, host, src, via, kind, hour, ok, fail, n in rows:
        d = U.setdefault(u, {"user": u, "snaps": set(), "ok": 0, "fail": 0, "events": 0, "hosts": Counter(), "srcs": Counter(), "via": Counter(),
                             "kinds": Counter(), "hours": Counter(), "sudo": 0, "procs": Counter(), "pairs": defaultdict(lambda: {"ok": 0, "fail": 0, "n": 0, "last": ""})})
        d["snaps"].add(snap); d["ok"] += ok; d["fail"] += fail; d["events"] += n
        d["kinds"][kind] += n
        if host:
            d["hosts"][_short(host)] += n
        if src and not src.startswith("as "):
            d["srcs"][src] += n
        if kind in ("login", "admin", "authfail") and via:
            d["via"][via] += n
        if kind == "sudo":
            d["sudo"] += n
        if kind == "process" and via:
            d["procs"][via] += n
        if hour >= 0:
            d["hours"][hour] += n
        p = d["pairs"][(kind, _short(host), src, via)]
        p["ok"] += ok; p["fail"] += fail; p["n"] += n; p["last"] = max(p["last"], snap)
    newest = snaps[-1] if snaps else ""
    out = []
    for u, d in U.items():
        ss = sorted(d["snaps"])
        flags = []
        if d["fail"] and d["fail"] >= max(3, d["ok"]):
            flags.append("mostly failures")
        elif d["fail"]:
            flags.append("has failures")
        if u in ("root", "administrator", "admin") or d["sudo"] or d["kinds"].get("sudo"):
            flags.append("privileged")
        if d["kinds"].get("account-change"):
            flags.append("created/removed")
        t0, t1 = _snap_time(ss[0]), _snap_time(newest)
        if len(ss) <= 1 and newest in d["snaps"] and len(snaps) > 3:
            flags.append("new")
        if not (d["kinds"].get("login") or d["kinds"].get("admin") or d["kinds"].get("authfail")):
            flags.append("no logins (service account?)")
        hrs = sorted(d["hours"])
        out.append({"user": u, "first": ss[0], "last": ss[-1], "reports": len(ss), "of": total_snaps, "ok": d["ok"], "fail": d["fail"], "events": d["events"],
                    "hosts": _top(d["hosts"], 5), "n_hosts": len(d["hosts"]), "sources": _top(d["srcs"], 5), "n_sources": len(d["srcs"]), "methods": _top(d["via"], 4),
                    "sudo": d["sudo"], "processes": _top(d["procs"], 3), "hours": {str(h): c for h, c in sorted(d["hours"].items())},
                    "active_hours": f"{hrs[0]:02d}-{hrs[-1]:02d} UTC" if hrs else "", "flags": flags, "pattern": _pattern(u, d, len(ss), total_snaps),
                    "_t": (t0, t1)})
    out.sort(key=lambda x: (-("mostly failures" in x["flags"]), -x["events"]))
    for o in out:
        o.pop("_t", None)
    res = {"users": out, "reports": len(snaps), "newest": newest}
    if user:
        d = U.get(user)
        res["detail"] = None if not d else {"user": user, "rows": sorted(
            ({"kind": k[0], "host": k[1], "src": k[2], "via": k[3], "ok": v["ok"], "fail": v["fail"], "n": v["n"], "last": v["last"]} for k, v in d["pairs"].items()),
            key=lambda r: -r["n"])}
    return res


def _pattern(u, d, nsnap, total):
    """One plain-language sentence about how an account is normally used."""
    bits = []
    lg = d["kinds"].get("login", 0) + d["kinds"].get("admin", 0)
    if lg:
        h = ", ".join(_top(d["hosts"], 3))
        s = ", ".join(_top(d["srcs"], 3))
        m = ", ".join(_top(d["via"], 2))
        bits.append(f"logs in to {len(d['hosts'])} host(s)" + (f" ({h})" if h else "") + (f" from {len(d['srcs'])} source(s)" + (f" ({s})" if s else "") if d["srcs"] else "")
                    + (f" via {m}" if m else ""))
    if d["fail"]:
        bits.append(f"{d['fail']} failed attempt(s) against {d['ok']} successful")
    if d["sudo"]:
        bits.append(f"{d['sudo']} sudo command(s)")
    if d["procs"]:
        bits.append("runs " + ", ".join(_top(d["procs"], 2)))
    if d["hours"]:
        hs = sorted(d["hours"])
        bits.append(f"active {hs[0]:02d}-{hs[-1]:02d} UTC")
    bits.append(f"seen in {nsnap} of {total} reports")
    return (u + " " + "; ".join(bits)) + "."


# ---------------------------------------------------------------- frequent IPs
def record_ips(sid, events):
    """events = correlate.build()['events'] -> per-snapshot IP usage."""
    obs, arts = Counter(), Counter()
    for e in events.values():
        a = [x for x in e.get("arts") or [] if x[0] in ("user", "process", "dns", "file")]
        for role, ips in (("source", e.get("host_ips")), ("destination", e.get("dst_ips"))):
            for ip in ips or []:
                if _IP.match(ip) and not ip.endswith(".1") and not ip.endswith(".255"):
                    obs[(ip, role, e.get("type") or "")] += 1
                    for kind, value, _ in a:
                        arts[(ip, kind, value[:160])] += 1
    with _db() as c:
        c.execute("DELETE FROM ip_obs WHERE snap=?", (sid,))
        c.execute("DELETE FROM ip_arts WHERE snap=?", (sid,))
        c.executemany("INSERT OR REPLACE INTO ip_obs VALUES (?,?,?,?,?)", [(sid, *k, v) for k, v in obs.items()])
        c.executemany("INSERT OR REPLACE INTO ip_arts VALUES (?,?,?,?,?)", [(sid, *k, v) for k, v in arts.items()])
    return len(obs)


def _internal(ip, is_internal):
    try:
        return bool(is_internal(ip))
    except Exception:  # noqa: BLE001
        return ip.startswith(("10.", "192.168.", "172."))


def ip_profiles(is_internal=lambda ip: False):
    """Frequent IPs with how they are used, across every recorded report."""
    with _db() as c:
        obs = c.execute("SELECT snap, ip, role, etype, n FROM ip_obs").fetchall()
        arts = c.execute("SELECT ip, kind, value, SUM(n) FROM ip_arts GROUP BY ip, kind, value").fetchall()
    P = {}
    for snap, ip, role, et, n in obs:
        d = P.setdefault(ip, {"ip": ip, "events": 0, "snaps": set(), "roles": Counter(), "types": Counter()})
        d["events"] += n; d["snaps"].add(snap); d["roles"][role] += n; d["types"][et] += n
    A = defaultdict(lambda: defaultdict(Counter))
    for ip, kind, value, n in arts:
        A[ip][kind][value] += n
    res = []
    for ip, d in P.items():
        ext = not _internal(ip, is_internal)
        if d["events"] < MIN_IP_EVENTS["ext" if ext else "int"]:
            continue
        res.append({**d, "ext": ext, "users": _top(A[ip]["user"], 5), "processes": _top(A[ip]["process"], 5), "dns": _top(A[ip]["dns"], 5), "files": _top(A[ip]["file"], 3)})
    res.sort(key=lambda x: -x["events"])
    return res[:MAX_IP_NOTES]


def _ip_text(p, nsnaps):
    role = " and ".join(f"{r} {c}x" for r, c in p["roles"].most_common()) or "-"
    types = ", ".join(f"{t} {c}" for t, c in p["types"].most_common(5))
    bits = [f"{'External' if p['ext'] else 'Internal'} IP {p['ip']} appears in {p['events']} correlated event(s) over {len(p['snaps'])} of {nsnaps} reports ({role}). Event types: {types}."]
    for lab, key in (("Accounts", "users"), ("Processes", "processes"), ("Names", "dns"), ("Files", "files")):
        if p[key]:
            bits.append(f"{lab}: {', '.join(p[key])}.")
    bits.append("Counted from the correlation, not reviewed by a person.")
    return " ".join(bits)[:1900]


def _put(subject_spec, tag, text):
    """Add or update (in place, only when changed) the profile note with this tag on one subject."""
    subj, _ = kb.resolve(**{k: subject_spec.get(k) for k in ("ip", "mac", "host", "dom", "subject")})
    old = [x for x in kb.host_notes([subj]) if x["text"].startswith(tag)]
    full = f"{tag} {text}"
    if old and old[0]["text"] == full[:kb.MAX_TEXT] and old[0].get("via") == VIA:
        return 0
    kb.add_host_note(subject_spec, full, "behavior", author="netmon", model="", via=VIA, note_id=old[0]["id"] if old else None)
    return 1


def write_notes(is_internal=lambda ip: False):
    """Host notes for frequent IPs and for the accounts seen on each host. Returns (ip notes, host notes) written/changed."""
    _, snaps = _load()
    with _db() as c:
        nsn = c.execute("SELECT COUNT(DISTINCT snap) FROM ip_obs").fetchone()[0] or 1
    a = b = 0
    for p in ip_profiles(is_internal):
        try:
            a += _put({"ip": p["ip"]}, "[profile:ip]", _ip_text(p, nsn))
        except ValueError as e:
            print(f"accounts: ip note skipped for {p['ip']}: {e}")
    by_host = defaultdict(list)
    rows, _ = _load()
    hosts = {}
    for snap, u, host, src, via, kind, hour, ok, fail, n in rows:
        if host and kind in ("login", "admin", "sudo", "process", "authfail"):
            h = hosts.setdefault(host, defaultdict(lambda: {"ok": 0, "fail": 0, "srcs": Counter(), "via": Counter(), "sudo": 0}))[u]
            h["ok"] += ok; h["fail"] += fail
            if src and not src.startswith("as "):
                h["srcs"][src] += n
            if via and kind in ("login", "admin"):
                h["via"][via] += n
            if kind == "sudo":
                h["sudo"] += n
    for host, us in hosts.items():
        lines = []
        for u, h in sorted(us.items(), key=lambda x: -(x[1]["ok"] + x[1]["fail"]))[:8]:
            s = f"{u}: {h['ok']} ok / {h['fail']} failed"
            if h["srcs"]:
                s += " from " + ", ".join(_top(h["srcs"], 3))
            if h["via"]:
                s += " via " + ", ".join(_top(h["via"], 2))
            if h["sudo"]:
                s += f", {h['sudo']} sudo"
            lines.append(s)
        spec = {"ip": host} if _IP.match(host) else {"host": host}
        try:
            b += _put(spec, "[profile:users]", "Accounts seen on this host (all recorded reports): " + "; ".join(lines) + ". Counted from logs, not reviewed by a person.")
        except ValueError as e:
            print(f"accounts: user note skipped for {host}: {e}")
    return a, b


def process(sid, raw, admin, events, is_internal):
    """One correlation pass for a snapshot: record, then (only changed) notes."""
    n1 = record_users(sid, raw, admin)
    n2 = record_ips(sid, events)
    return n1, n2, write_notes(is_internal)


if __name__ == "__main__":
    import sys
    if sys.argv[1:] == ["backfill"]:
        import server, lateral, os, site_cfg
        pol = server.with_cleared(server.load_json(os.path.join(server.ROOT, "policy.json"), {}))
        for s in server.snapshots():
            r = server.snapshot(s["id"])
            if not r:
                continue
            adm = lateral.admin_sessions(r["raw"], pol)
            v = server.correlation(s["id"]) or {}
            print(s["id"], record_users(s["id"], r["raw"], adm), record_ips(s["id"], v.get("events") or {}))
        print(write_notes(site_cfg.is_internal))
