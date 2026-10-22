#!/usr/bin/env python3
"""netmon dashboard - stdlib-only HTTPS server.

Reads the netmon pipeline output (mounted read-only at /netmon) and serves a
single-page dashboard plus a small JSON API. Data is re-read on every request
(with an mtime cache), so new snapshots appear without restarting.
"""
import issues
import risk
import lateral
import correlate
import corr_llm
import enrich
import autoclose
import itemcmp
import llm_providers
import auth
import tintel
import chat
import kb
import audit
from http.cookies import SimpleCookie
import base64, glob, gzip, hmac, json, os, re, ssl, sys, threading, time
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

ROOT = os.environ.get("NETMON_DIR", "/netmon")
# Access control (docs/ACCESS_CONTROL.md). The role lives in users.json (auth.py); NETMON_ADMINS is no longer used.
#   admin    - everything
#   defender - reads everything and does analyst work (check-offs, notes, AI verdicts, chat); changes no settings
#   user     - only the alerts / events of the devices an admin assigned to them (allow-list below)
USER_GET = {"/api/me", "/api/account", "/api/site", "/api/alerts", "/api/push/key", "/api/push/prefs", "/api/my"}
USER_POST = {"/api/logout", "/api/account/password", "/api/push/subscribe", "/api/push/unsubscribe", "/api/push/test",
             "/api/alerts/read", "/api/kb/event", "/api/audit/view", "/api/research/request"}  # /api/kb/event: own notes on own devices' events only (checked below)
ADMIN_POST = ("/api/users", "/api/config/", "/api/llm/config", "/api/llm/esqueries", "/api/llm/notes", "/api/llm/research", "/api/aireview/clear-", "/api/llm/providers", "/api/aireview/compare", "/api/compare/item", "/api/compare/adopt")


def watch_ids(user, role, reg=None):
    """Device identifiers a user's alerts are scoped to. None = all devices (never for the user role)."""
    ids = store.watch_ids(user, reg=reg)
    return set() if ids is None and role == "user" else ids


def assigned_devices(user):
    """The device-catalog entries assigned to a user (their alert / access scope)."""
    p = store.prefs_get(user)
    if p["mode"] != "some":
        return []
    want = set(p["devices"])
    return [d for d in device_catalog() if d["id"] in want]


def my_events(user):
    """Correlated events (latest snapshot) that involve one of the user's assigned devices - for the user role."""
    ids = watch_ids(user, "user")
    ips = {i[3:] for i in ids if i.startswith("ip:")}
    s = snapshots()
    sid = s[-1]["id"] if s else ""
    ev = ((correlation(sid) or {}).get("events") or {}) if sid and ips else {}
    out = []
    for k, e in ev.items():
        if e.get("type") == "alert" or not ips & set(e.get("ips") or []):
            continue  # alerts come from /api/alerts (they carry their own device targets)
        out.append({"id": k, "type": e.get("type"), "label": e.get("label"), "sev": e.get("sev"), "t0": e.get("t0"),
                    "ips": sorted(ips & set(e.get("ips") or []))})
    out.sort(key=lambda e: -(e["t0"] or 0))
    try:  # a User only ever sees their OWN notes (others' analyst notes on the same event family stay private)
        un = kb.event_notes([e["id"] for e in out], author=user)
    except Exception as e:  # noqa: BLE001 - the page works without notes
        print(f"my notes unavailable: {e}", file=sys.stderr)
        un = {}
    return {"snapshot": sid, "devices": assigned_devices(user), "events": out, "unotes": un}
def llm_models():
    """Models the AI review page may choose: the local LM Studio server ("local") and the admin-added API-key
    providers ("custom", llm_providers.py). The local group is empty when an admin has disabled it."""
    try:
        cu = llm_providers.model_groups()
    except Exception as e:  # noqa: BLE001 - a broken providers file must not hide the local models
        print(f"llm providers unreadable: {e}", file=sys.stderr)
        cu = []
    return {"local": llm_providers.offered_local_models() if llm_providers.local_enabled() else [], "custom": cu}


def llm_allowed(provider, model, M=None):
    return llm_providers.known(provider) and llm_providers.allowed(provider, model)


DATA = os.path.join(ROOT, "data")
BASE = os.path.join(ROOT, "baseline")
STATE = os.environ.get("STATE_DIR", "/state")
ACKS = os.path.join(STATE, "acks.json")  # legacy; check-offs now live in the SQLite store
os.environ.setdefault("NETMON_DB", os.path.join(STATE, "netmon.db"))
if ROOT not in sys.path:
    sys.path.append(ROOT)
import store  # noqa: E402  /netmon/store.py, DB on the writable /state volume
import lookback  # noqa: E402  /netmon/lookback.py: research job lookback window (AI review page)
import research_cfg  # noqa: E402  /netmon/research_cfg.py: research job model, schedule, cost caps (store meta table)
import pushsvc  # noqa: E402  web push for urgent alerts
import site_cfg as SITE  # noqa: E402  network-specific values (/netmon/site.json, git-ignored)
os.environ.setdefault("NETMON_INTEGRATIONS", os.path.join(STATE, "integrations.json"))  # writable /state, 0600
os.environ["NETMON_IN_DASHBOARD"] = "1"
import integrations  # noqa: E402  /netmon/integrations.py: Elasticsearch + UniFi settings (More > Configuration)
SELF_IP, SELF_HOST = SITE.get("self_ip") or "", SITE.get("self_host") or "netmon-host"
_ack_lock = threading.Lock()
STATIC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")


def _build_hash():
    import hashlib
    h = hashlib.sha1()
    for p in sorted(glob.glob(os.path.join(STATIC, "*"))):
        if os.path.isfile(p):
            h.update(open(p, "rb").read())
    return h.hexdigest()[:10]


BUILD = _build_hash()  # changes whenever any static file changes (image rebuild)
ASSET_RE = re.compile(r'(?:src|href)="/[\w.-]+\.(?:js|css)"')
PORT = int(os.environ.get("PORT", "8443"))
CERT = os.environ.get("CERT", "/certs/dashboard.crt")
KEY = os.environ.get("KEY", "/certs/dashboard.key")
USER = os.environ.get("DASH_USER", "")
PASS = os.environ.get("DASH_PASS", "")
SNAP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{4}Z$")
COMPANIONS = ("analysis", "sources")

_cache = {}


def load_json(path, default=None):
    cd = store.cfg_doc(path)
    if cd:  # policy / host_policy / known_benign / site: tables in the cfg table
        return store.cfg_load(cd, shared=True) if store.cfg_has(cd) else default
    dn = store.doc_name(path)
    if dn:  # snapshots / time ranges / job state live in the SQLite docs table
        mt = store.doc_mtime(dn)
        if mt is None:
            return default
        hit = _cache.get(path)
        if hit and hit[0] == mt:
            return hit[1]
        try:
            val = store.doc_get(dn, default)
        except Exception as e:  # noqa: BLE001
            print("load error", path, e, file=sys.stderr)
            return hit[1] if hit else default
        _cache[path] = (mt, val)
        return val
    try:
        st = os.stat(path)
    except OSError:
        return default
    hit = _cache.get(path)
    if hit and hit[0] == st.st_mtime:
        return hit[1]
    try:
        with open(path) as f:
            if path.endswith(".jsonl"):
                val = [json.loads(l) for l in f if l.strip()]
            else:
                val = json.load(f)
    except Exception as e:  # partially written file etc.
        print("load error", path, e, file=sys.stderr)
        return hit[1] if hit else default
    _cache[path] = (st.st_mtime, val)
    return val


def snapshots():
    out = []
    for p in store.jglob(DATA, "*.json"):
        sid = os.path.basename(p)[:-5]
        if not SNAP_RE.match(sid):
            continue
        out.append({"id": sid,
                    "has": [c for c in COMPANIONS
                            if store.jexists(os.path.join(DATA, f"{sid}.{c}.json"))]})
    return out


RANGE_RE = re.compile(r"^r\d{8}T\d{4}Z-\d{8}T\d{4}Z$")
RANGES = os.path.join(STATE, "ranges")  # written by the host broker (collect.py --start/--end + analyze.py --readonly)


def base_snapshot(end_iso):
    """The newest nightly snapshot generated at or before `end_iso`: its AI alarms go with a
    time range (alarms stay per report run; everything else is collected for the range)."""
    s = snapshots()
    if not s:
        return None
    end = str(end_iso or "")[:16].replace("-", "").replace(":", "")  # 20261018T1700
    best = None
    for x in s:
        if x["id"].replace("-", "")[:13] <= end:
            best = x["id"]
    return best or s[0]["id"]


def range_status(rid):
    return load_json(os.path.join(RANGES, rid + ".status.json"), None) if RANGE_RE.match(rid or "") else None


# Sections of a time range that the page loads one by one (collect.py --section); until each arrives the snapshot holds
# an empty placeholder of the right shape so every view still renders.
SECTION_DEFAULTS = {"unifi": {}, "totals": {}, "devices": {}, "alerts": {}, "detections": [], "notices": [], "weird": [], "unknown_dhcp": [],
                    "dns_tunnel": [], "threat_intel": {}, "beacons": {}, "internal": {}, "admin_access": {}, "iot_dest": {}, "files": {},
                    "tls": {}, "hosts": {}, "mitre_ids": {}, "inventory_ips": {}, "zeek_retention_start": None, "inventory_file": "", "self_ip": ""}
SECTION_KEYS = {"unifi": ["unifi"], "totals": ["totals"], "devices": ["devices", "unknown_dhcp", "zeek_retention_start", "inventory_file", "self_ip", "inventory_ips"],
                "alerts": ["alerts"], "detections": ["detections"], "notices": ["notices", "weird"], "dns_tunnel": ["dns_tunnel"], "threat_intel": ["threat_intel"],
                "beacons": ["beacons"], "internal": ["internal"], "admin_access": ["admin_access"], "iot_dest": ["iot_dest"], "files": ["files"], "tls": ["tls"],
                "hosts": ["hosts"], "mitre_ids": ["mitre_ids"]}
SECTION_NAMES = list(SECTION_KEYS) + ["analysis"]


def range_meta(rid):
    return load_json(os.path.join(RANGES, rid + ".meta.json"), None) if RANGE_RE.match(rid or "") else None


def range_skeleton(rid):
    """A time range that is still being collected: the window, UniFi-independent placeholders, the nightly companions.
    The page then asks /api/section for each piece."""
    m = range_meta(rid)
    if not m:
        return None
    base = base_snapshot(m["generated"])
    b = snapshot(base) if base else None
    raw = {"generated": m["generated"], "hours": m["hours"], "range": {"start": m["start"], "end": m["end"]}}
    for keys in SECTION_KEYS.values():
        for k in keys:
            raw[k] = json.loads(json.dumps(SECTION_DEFAULTS.get(k, {})))
    res = {"id": rid, "raw": raw, "analysis": {}, "range": raw["range"], "base": base, "pending": SECTION_NAMES, "section_keys": SECTION_KEYS}
    for c in ("sources",):
        res[c] = (b or {}).get(c)
    return res


def range_section(rid, name):
    """One piece of a time range, queried from Elasticsearch on the host when first asked (then cached on disk)."""
    if name not in SECTION_NAMES or not range_meta(rid):
        return None
    if name == "analysis":
        r = corr_llm.broker("/section", {"id": rid, "name": name}, timeout=300)
        return {"analysis": load_json(os.path.join(RANGES, rid + ".analysis.json"), {}), "seconds": r.get("seconds")}
    done = load_json(os.path.join(RANGES, rid + ".json"), None)  # fully assembled earlier: slice it
    if done is not None:
        return {k: done.get(k, SECTION_DEFAULTS.get(k, {})) for k in SECTION_KEYS[name]}
    p = os.path.join(RANGES, f"{rid}.sec.{name}.json")
    if not store.jexists(p):
        corr_llm.broker("/section", {"id": rid, "name": name}, timeout=300)
    return load_json(p, None)


def range_snapshot(rid):
    raw = load_json(os.path.join(RANGES, rid + ".json"))
    an = load_json(os.path.join(RANGES, rid + ".analysis.json"))
    if raw is None or an is None:
        return None
    base = base_snapshot(raw.get("generated"))
    b = snapshot(base) if base else None
    res = {"id": rid, "raw": raw, "analysis": an, "range": raw.get("range"), "base": base}
    for c in ("sources",):
        res[c] = (b or {}).get(c)
    return res


def resolve_sid(sid):
    """A time-range id -> the nightly snapshot whose alarms / correlation belong to it."""
    if RANGE_RE.match(sid or ""):
        r = load_json(os.path.join(RANGES, sid + ".json")) or range_meta(sid) or {}
        return base_snapshot(r.get("generated") or "") or sid
    return sid


_fseen = {"sig": None, "val": {}}


def finding_last_seen():
    """{finding key: generated time of the newest nightly snapshot that contained it} (baseline 'f|kind|dev|detail', host 'hf|key')."""
    snaps = snapshots()
    sig = tuple((s["id"], store.jmtime(os.path.join(DATA, s["id"] + ".json"))) for s in snaps)
    if _fseen["sig"] != sig:
        seen = {}
        for s in snaps:  # oldest -> newest, so the last write wins
            raw = load_json(os.path.join(DATA, s["id"] + ".json")) or {}
            an = load_json(os.path.join(DATA, s["id"] + ".analysis.json")) or {}
            gen = raw.get("generated")
            if not gen:
                continue
            for f in an.get("findings") or []:
                seen["f|%s|%s|%s" % (f.get("kind"), f.get("device") or "", f.get("detail") or "")] = gen
            for f in (raw.get("hosts") or {}).get("findings") or []:
                seen["hf|" + str(f.get("key"))] = gen
        _fseen["sig"], _fseen["val"] = sig, seen
    return _fseen["val"]


def snapshot(sid):
    res = _snapshot(sid)
    if res and res.get("analysis"):
        try:
            res = dict(res, analysis=seg_filter(res["analysis"]))  # suppressed segmentation flows are not shown anywhere
        except Exception as e:  # noqa: BLE001
            print(f"segmentation suppress filter failed: {e}", file=sys.stderr)
    if res and res.get("raw"):
        try:
            res = dict(res, raw=store.ids_filter(res["raw"], store.ids_suppress_list()))  # suppressed IDS signatures are not shown anywhere
        except Exception as e:  # noqa: BLE001
            print(f"ids suppress filter failed: {e}", file=sys.stderr)
    if res:
        try:
            seen = finding_last_seen()
            gen = (res.get("raw") or {}).get("generated")
            for f in (res.get("analysis") or {}).get("findings") or []:
                f["last_seen"] = seen.get("f|%s|%s|%s" % (f.get("kind"), f.get("device") or "", f.get("detail") or "")) or gen
            for f in ((res.get("raw") or {}).get("hosts") or {}).get("findings") or []:
                f["last_seen"] = seen.get("hf|" + str(f.get("key"))) or gen
        except Exception as e:  # noqa: BLE001 - never break the snapshot for a display column
            print("finding last_seen failed", e, file=sys.stderr)
    return res


def _snapshot(sid):
    if RANGE_RE.match(sid or ""):
        return range_snapshot(sid)
    if not SNAP_RE.match(sid or ""):
        return None
    raw = load_json(os.path.join(DATA, sid + ".json"))
    if raw is None:
        return None
    res = {"id": sid, "raw": raw}
    for c in COMPANIONS:
        res[c] = load_json(os.path.join(DATA, f"{sid}.{c}.json"))
    return res


def history():
    """Compact per-snapshot history: totals + per-device headline numbers."""
    rows = store.history_load()
    out = []
    for r in rows:
        devs = {}
        for k, v in (r.get("devices") or {}).items():
            devs[k] = {f: v.get(f) for f in ("ip", "name", "known", "total", "sent", "recv",
                                             "conns", "ext_peers", "ext_out", "rejected",
                                             "dns_q", "nx", "inbound_ext_sources", "hourly")}
        out.append({"generated": r.get("generated"), "hours": r.get("hours"),
                    "totals": r.get("totals"), "devices": devs,
                    "signatures": r.get("signatures")})
    return out


def registry():
    return {
        "devices_seen": store.registry_load(),
        "hosts_seen": store.hosts_load(),
        "watch_state": store.mutes(),
        "policy": load_json(os.path.join(ROOT, "policy.json"), {}),
        "host_policy": load_json(os.path.join(ROOT, "host_policy.json"), {}),
        "known_benign": load_json(os.path.join(ROOT, "known_benign.json"), {}),
    }


def device_catalog():
    """Devices a user can subscribe to: the device registry + Fleet endpoints not otherwise represented."""
    reg = store.registry_load()
    out, have_ips = [], set()
    for k, v in reg.items():
        ips = v.get("ips") or []
        have_ips.update(ips)
        out.append({"id": k, "name": v.get("name") or "", "ips": ips, "mac": v.get("mac") or "", "known": bool(v.get("known")),
                    "last_seen": v.get("last_seen") or ""})
    pol = load_json(os.path.join(ROOT, "host_policy.json"), {}) or {}
    for h, ip in (pol.get("endpoint_ips") or {}).items():
        if ip not in have_ips:
            out.append({"id": "host:" + h, "name": h, "ips": [ip], "mac": "", "known": True, "last_seen": "", "endpoint": True})
    eps = {ip: h for h, ip in (pol.get("endpoint_ips") or {}).items()}
    for d in out:
        d["endpoint"] = d.get("endpoint") or any(ip in eps for ip in d["ips"])
    out.sort(key=lambda d: (not d["known"], not d["name"], (d["name"] or "").lower(), d["ips"][:1]))
    return out


class ClearedSet(set):
    """The cleared segmentation flow keys + the segmentation suppress rules: a flow key "<src IP or MAC>|<dst>|<port>" is
    'in' the set when it was cleared or a suppress rule (source IP / destination IP / ports) covers it. Every consumer of
    the cleared set (risk, lateral, correlation, fix list) therefore drops suppressed flows."""
    rules, mac2ip = (), {}

    def __contains__(self, key):
        if set.__contains__(self, key):
            return True
        if not self.rules or not isinstance(key, str):
            return False
        p = key.split("|")
        if len(p) != 3:
            return False
        s = p[0].lower()
        return store.seg_suppress_match(self.rules, self.mac2ip.get(s, s), p[1], p[2])


_MAC2IP = {"sid": None, "v": {}}


def _mac2ip():
    snaps = snapshots()
    if not snaps:
        return {}
    sid = snaps[-1]["id"]
    if _MAC2IP["sid"] != sid:
        raw = load_json(os.path.join(DATA, sid + ".json")) or {}
        _MAC2IP.update(sid=sid, v={str(d.get("mac")).lower(): ip for ip, d in (raw.get("devices") or {}).items() if d.get("mac")})
    return _MAC2IP["v"]


def seg_filter(analysis):
    """analysis without the segmentation violations / findings a suppress rule covers (a copy; the file is untouched)."""
    rules = store.seg_suppress_list()
    if not rules or not analysis:
        return analysis
    m2i = _mac2ip()
    hit = lambda s, d, p: store.seg_suppress_match(rules, m2i.get(str(s).lower(), s), d, p)  # noqa: E731
    out = dict(analysis)
    out["violations"] = [v for v in analysis.get("violations") or [] if not hit(v.get("src"), v.get("dst"), v.get("port"))]
    keep = []
    for f in analysis.get("findings") or []:
        k = risk.seg_key_finding(f)
        if k and hit(*k.split("|")):
            continue
        keep.append(f)
    out["findings"] = keep
    return out


def cfg_validate(doc, data):
    """Reject a settings change that would break a job (bad regex, wrong shape). Returns an error text or None."""
    try:
        if doc == "host_policy":
            for k in ("suspicious_cmdline", "service_parents"):
                for r in data.get(k) or []:
                    re.compile(str(r))
            for k in ("service_child_suspicious", "net_suspicious_procs"):
                if data.get(k):
                    re.compile(str(data[k]))
        if doc == "policy":
            import ipaddress
            zs = data.get("zones") or {}
            if not isinstance(zs, dict):
                return "zones must be a table of name -> CIDR"
            for z, c in zs.items():
                if not z.startswith("_"):
                    ipaddress.ip_network(str(c), strict=False)
            for z, r in (data.get("zone_roles") or {}).items():
                if not z.startswith("_") and r not in ("dmz", "protected", "mgmt", "user", "iot"):
                    return f"zone_roles[{z}] must be one of dmz, protected, mgmt, user, iot"
            for a in data.get("allow") or []:
                if not isinstance(a, dict) or not a.get("src") or not a.get("dst"):
                    return "every allow rule needs a src and a dst"
        if doc == "site":
            import ipaddress
            ipaddress.ip_network(str(data.get("internal_cidr") or "10.0.0.0/8"), strict=False)
            if not isinstance(data.get("internal_prefixes"), list) or not data["internal_prefixes"]:
                return "internal_prefixes needs at least one prefix"
        if doc == "known_benign":
            for k in ("signatures", "names"):
                if not isinstance(data.get(k), dict):
                    return f"{k} must be a table of name -> reason"
    except (re.error, ValueError) as e:
        return f"invalid value: {e}"
    return None


def with_cleared(pol):
    """policy + the set of segmentation flows people have cleared (ack type "seg"); see risk.seg_key."""
    try:
        pol = dict(pol or {}); cs = ClearedSet((store.acks_load().get("seg") or {}).keys())
        cs.rules, cs.mac2ip = store.seg_suppress_list(), _mac2ip()
        pol["_cleared_seg"] = cs
    except Exception as e:  # noqa: BLE001 - without the ack store nothing is cleared
        print(f"cleared segmentation lookup failed: {e}", file=sys.stderr)
    return pol


def read_acks():
    return store.acks_load()


def write_ack(typ, key, checked, note="", label=""):
    """Check-off store: {type: {key: {at, note, label}}}. Atomic replace."""
    with _ack_lock:
        return store.ack_set(typ, key, checked, note, label)


_issues = {"sig": None, "val": None}


_CORR = {}


def snap_window(sid):
    """(start, end) datetimes of a nightly snapshot's window (generated - hours, generated)."""
    import datetime as dt
    raw = load_json(os.path.join(DATA, sid + ".json")) or {}
    try:
        e = dt.datetime.fromisoformat(raw["generated"])
        return e - dt.timedelta(hours=float(raw.get("hours") or 24)), e
    except (KeyError, ValueError, TypeError):
        return None


def range_request(body):
    """{start, end} -> (response, code). A window that matches a nightly snapshot (±10 min) just uses it; anything
    else is collected by the host broker into /state/ranges (the container has no Elasticsearch key)."""
    import datetime as dt
    try:
        s = dt.datetime.fromisoformat(str(body.get("start") or "").replace("Z", "+00:00"))
        e = dt.datetime.fromisoformat(str(body.get("end") or "").replace("Z", "+00:00"))
        if not (s.tzinfo and e.tzinfo):
            raise ValueError
    except ValueError:
        return {"error": "start and end must be ISO times with a UTC offset"}, 400
    if e <= s:
        return {"error": "the end must be after the start"}, 400
    tol = dt.timedelta(minutes=10)
    for x in reversed(snapshots()):
        w = snap_window(x["id"])
        if w and abs(w[0] - s) <= tol and abs(w[1] - e) <= tol:
            return {"id": x["id"], "status": "done", "snapshot": True}, 200
    try:
        r = corr_llm.broker("/range", {"start": s.isoformat(), "end": e.isoformat()}, timeout=30)
    except Exception as ex:  # noqa: BLE001 - broker down / validation error
        return {"error": str(ex).replace("broker: ", "")[:300]}, 400
    return r, 200


def lateral_periods(periods):
    """[(start, end), ...] -> (raw, analysis) merged over all periods. Each period is queried from Elasticsearch on the
    host (broker section 'lateral', cached per window); the merge happens here. Raises ValueError for a bad period."""
    import datetime as dt
    from concurrent.futures import ThreadPoolExecutor
    wins = []
    for st, en in periods[:8]:
        try:
            s = dt.datetime.fromisoformat(str(st).replace("Z", "+00:00"))
            e = dt.datetime.fromisoformat(str(en).replace("Z", "+00:00"))
            if not (s.tzinfo and e.tzinfo):
                raise ValueError
        except ValueError:
            raise ValueError("each period needs an ISO start and end with a UTC offset") from None
        wins.append((s, e))
    if not wins:
        raise ValueError("no time period given")

    def one(w):
        r = corr_llm.broker("/range", {"start": w[0].isoformat(), "end": w[1].isoformat()}, timeout=30)
        corr_llm.broker("/section", {"id": r["id"], "name": "lateral"}, timeout=300)
        d = load_json(os.path.join(RANGES, r["id"] + ".sec.lateral.json"))
        if d is None:
            raise RuntimeError("no data for " + r["id"])
        return d
    try:
        with ThreadPoolExecutor(3) as ex:
            data = list(ex.map(one, wins))
    except RuntimeError as ex:  # broker down / validation error
        raise ValueError(str(ex).replace("broker: ", "")[:300]) from None
    return lateral.merge_periods(data)


def correlation(sid):
    """Related-events map for a snapshot (correlate.py). Cached until the snapshot, its alerts or the issues change.
    A time range uses its nightly snapshot's map (correlation, AI verdicts and research notes are per report run)."""
    sid = resolve_sid(sid)
    res = snapshot(sid)
    if not res:
        return None
    alerts = store.alerts_recent(2000, suppressed=True)  # suppressed alerts are hidden in the feed but still correlated
    it = issue_tracker()
    _clr = with_cleared({}).get("_cleared_seg") or set()  # includes the segmentation suppress rules
    open_iss = [i for i in it.get("open", []) if (i.get("status", "open") == "open" or str(i.get("status", "")).startswith("open"))
                and risk.seg_key_issue(i["key"]) not in _clr]
    ck = (sid, alerts[0]["id"] if alerts else 0, len(open_iss), len(acks_load_all()), tuple(r["id"] for r in store.seg_suppress_list()), tuple(r["id"] for r in store.ids_suppress_list()))
    if _CORR.get("k") == ck:
        return _CORR["v"]
    pol = with_cleared(load_json(os.path.join(ROOT, "policy.json"), {}))
    try:
        import mitre
        tech = lambda src, text: [i for _, ids, _ in mitre.rules_for("host" if src == "alert" and text.startswith("host|") else src,
                                                                       text.split("|", 1)[1] if src == "alert" and text.startswith("host|") else text) for i in ids]
    except Exception:  # noqa: BLE001
        tech = lambda src, text: []
    import site_cfg as SITE
    adm = lateral.admin_sessions(res["raw"], pol)
    latest = bool(snapshots()) and snapshots()[-1]["id"] == sid
    v = correlate.build(res["raw"], res["analysis"], alerts, open_iss, adm,
                        SITE.is_internal, lateral._resolver(res["raw"]), tech, latest=latest,
                        cleared=pol.get("_cleared_seg") or set(), triage=res.get("triage"))
    try:  # suppress rules: check off what they cover (the events stay in the correlation)
        import suppress
        suppress.apply(v.get("events") or {}, res["raw"], res["analysis"], open_iss, v.get("related"), sid=sid if latest else None)
    except Exception as e:  # noqa: BLE001
        print(f"suppress: apply failed: {e}", file=sys.stderr)
    try:  # persist every event (sqlite `events`): open until checked off, whatever the time picker says
        import eventstore
        eventstore.upsert(v.get("events") or {}, sid, str(res["raw"].get("generated") or "") or None, v.get("items"))
        eventstore.sync_vulns(v.get("events") or {}, latest)
    except Exception as e:  # noqa: BLE001
        print(f"eventstore: upsert failed: {e}", file=sys.stderr)
    try:  # count how many snapshots each event has been seen in
        import eventseen
        if latest:
            eventseen.bump(v.get("events") or {}, sid)
    except Exception as e:  # noqa: BLE001
        print(f"eventseen: bump failed: {e}", file=sys.stderr)
    try:  # profile what this pass knows (accounts, frequent IPs) and keep the host notes about them current
        import accounts
        accounts.record_users(sid, res["raw"], adm)
        accounts.record_ips(sid, v.get("events") or {})
        if latest:
            accounts.write_notes(SITE.is_internal)
    except Exception as e:  # noqa: BLE001 - profiling must never break correlation
        print(f"accounts: profile pass failed: {e}", file=sys.stderr)
    _CORR.update(k=ck, v=v)
    return v


def autoclose_inputs():
    """(raw, analysis, open fix-list issues, non-closable researched event ids) for the newest snapshot."""
    snaps = snapshots()
    res = snapshot(snaps[-1]["id"]) if snaps else None
    if not res:
        return None
    it = issue_tracker()
    open_iss = [i for i in it.get("open", []) if i.get("status", "open") == "open" or str(i.get("status", "")).startswith("open")]
    try:
        other = [e for e in ((correlation(snaps[-1]["id"]) or {}).get("events") or {}) if e.split("|", 1)[0] not in ("f", "hf", "iss")]
    except Exception:  # noqa: BLE001 - counts only
        other = []
    return res["raw"], res["analysis"], open_iss, other


def review_job():
    """The research job's settings + run state (research_cfg.py / research_job.json) for the AI review and
    Configuration pages."""
    try:
        cfg, st = research_cfg.get(), research_cfg.status()
    except Exception as e:  # noqa: BLE001 - page still works, schedule just isn't shown
        return {"error": f"research job settings unavailable: {str(e)[:160]}"}
    runs = st.get("runs") or []
    last = next((r for r in runs if r.get("status") != "running"), {})
    return {"job": "research", "name": "Correlation job", "model": cfg["model"], "provider": cfg["provider"],
            "provider_name": llm_providers.name(cfg["provider"]) if cfg["provider"] else "",
            "interval_minutes": cfg["interval_minutes"], "enabled": cfg["enabled"], "next_run_at": research_cfg.next_run(),
            "last_run_at": last.get("started"), "last_status": last.get("status"), "running": st.get("running"),
            "requested": research_cfg.pending_request(),
            "limits": {k: cfg[k] for k in ("max_run_usd", "max_day_usd", "max_run_tokens", "max_batches", "max_searches")}, "web_research": cfg["web_research"], "es_search": cfg["es_search"],
            "severities": cfg["severities"], "severity_options": cfg["severity_options"],
            "modes": cfg["modes"], "mode_options": cfg["mode_options"], "mode_cats": cfg["mode_cats"],
            "spent_today_usd": round(research_cfg.spent_today(), 2), "limit_ranges": cfg["limits"]}


def acks_load_all():
    try:
        return store.acks_load()
    except Exception:  # noqa: BLE001
        return {}


def issue_tracker():
    snaps = snapshots()
    sig = tuple((s["id"], store.jmtime(os.path.join(DATA, s["id"] + ".json"))) for s in snaps)
    if _issues["sig"] != sig:
        rows = []
        for s in snaps:
            raw = load_json(os.path.join(DATA, s["id"] + ".json"))
            if raw:
                rows.append((s["id"], raw.get("generated"), raw,
                             load_json(os.path.join(DATA, s["id"] + ".analysis.json"))))
        _issues["val"], _issues["sig"] = issues.track(rows), sig
    tr = with_software_vulns(_issues["val"])
    try:  # segmentation fix-list items a suppress rule covers
        cs = with_cleared({}).get("_cleared_seg")
        if cs is not None and getattr(cs, "rules", None) and tr.get("open"):
            tr = dict(tr, open=[i for i in tr["open"] if not (risk.seg_key_issue(i.get("key", "")) in cs)])
    except Exception as e:  # noqa: BLE001
        print(f"seg suppress (issues): {e}", file=sys.stderr)
    return tr


def with_software_vulns(tr):
    """Merge open findings from the netmon software security scan (store.sec_findings) into the tracker as issues."""
    try:
        sv = store.sec_list()
    except Exception:
        return tr
    mk = lambda f: {"key": f["key"], "dev": "", "source": "secscan", "severity": f["severity"], "category": "Software vulnerability",
                    "title": f["title"], "ip": SELF_IP, "host": SELF_HOST, "target": f"netmon ({f['location']})",
                    "fix": f["fix"] or "", "evidence": f"{f['tool']}: {f['location']} {f.get('detail') or ''}".strip(),
                    "first_seen": f["first_seen"], "last_seen": f["last_seen"], "occurrences": 1, "checked": 1,
                    "status": "open" if f["status"] == "open" else "fixed", "fixed_at": f.get("fixed_at"), "recurring": False}
    out = dict(tr)
    out["open"] = list(tr.get("open", [])) + [mk(f) for f in sv if f["status"] == "open"]
    out["fixed"] = [mk(f) for f in sv if f["status"] == "fixed"] + list(tr.get("fixed", []))
    out["open"].sort(key=lambda x: (issues.SEV_ORDER.get(x["severity"], 9), -x.get("occurrences", 1), x["title"]))
    return out


# ---------------------------------------------------------------- audit log (audit.py -> Elasticsearch logs-netmon)
AUDIT_GET = {"/api/ti/lookup": "ti.lookup", "/api/audit": "audit.search", "/api/audit/doc": "audit.open",
             "/api/compare/item": "compare.item.history", "/api/aireview/compare": "aireview.compare.history"}
AUDIT_TARGET = ("username", "doc", "id", "eid", "key", "pair", "event", "section", "kind", "title", "subject", "route", "provider", "model")


def audit_action_name(path, body):
    """/api/users + {action: add} -> users.add ; /api/acks + {checked} -> acks.check ; /api/login -> auth.login"""
    base = {"/api/login": "auth.login", "/api/logout": "auth.logout", "/api/audit/view": "page.view",
            "/api/account/password": "account.password"}.get(path) or path[len("/api/"):].strip("/").replace("/", ".")
    if path == "/api/acks":
        return base + (".check" if body.get("checked") else ".uncheck")
    act = body.get("action") if isinstance(body, dict) else None
    return f"{base}.{act}" if isinstance(act, str) and re.fullmatch(r"[a-z_-]{1,30}", act) else base


def audit_target(body):
    if not isinstance(body, dict):
        return None
    t = [f"{k}={str(body[k])[:200]}" for k in AUDIT_TARGET if isinstance(body.get(k), (str, int)) and str(body.get(k))]
    return "; ".join(t) or None


MIME = {".html": "text/html; charset=utf-8", ".js": "application/javascript",
        ".css": "text/css", ".svg": "image/svg+xml", ".ico": "image/x-icon",
        ".png": "image/png", ".json": "application/manifest+json"}


class H(BaseHTTPRequestHandler):
    server_version = "netmon"
    sys_version = ""  # don't advertise the Python version

    def log_message(self, fmt, *a):
        sys.stderr.write("%s %s\n" % (self.address_string(), fmt % a))

    def send_response(self, code, message=None):
        self._code = code  # for the audit entry of this request
        super().send_response(code, message)

    def _audit(self, user, role, act, method, path, params=None, target=None, message=None, category="web"):
        code = getattr(self, "_code", None)
        out = "success" if code and code < 400 else "failure"
        try:
            audit.action(user, act, role=role, ip=self._client_ip(), outcome=out, method=method, path=path, status=code, params=params,
                         target=target, message=message or f"{user or '-'} {act} -> {code}", category=category,
                         ua=self.headers.get("User-Agent"))
        except Exception as e:  # noqa: BLE001 - auditing must never break a request
            print(f"audit failed: {e}", file=sys.stderr)

    COOKIE = "netmon_session"
    PUBLIC = {"/login", "/login.html", "/login.js", "/style.css", "/healthz", "/api/login",
              "/sw.js", "/manifest.json", "/icon-192.png", "/icon-512.png"}  # PWA shell: no data in these

    def _user(self):
        c = SimpleCookie(self.headers.get("Cookie", ""))
        return auth.session_user(c[self.COOKIE].value) if self.COOKIE in c else None

    def _client_ip(self):
        """Real client address. cloudflared connects from loopback, so only then trust Cloudflare's header."""
        peer = self.client_address[0]
        if peer in ("127.0.0.1", "::1"):
            fwd = (self.headers.get("CF-Connecting-IP") or "").strip()
            if re.fullmatch(r"[0-9a-fA-F:.]{2,45}", fwd):
                return fwd
        return peer

    def _set_cookie(self, value, max_age):
        self.send_header("Set-Cookie", f"{self.COOKIE}={value}; Path=/; Max-Age={max_age}; HttpOnly; Secure; SameSite=Strict")

    def _deny(self, path):
        if path.startswith("/api/"):
            return self._json({"error": "login required"}, 401)
        self.send_response(302)
        self.send_header("Location", "/login")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _send(self, code, body, ctype, cache="no-store"):
        if isinstance(body, str):
            body = body.encode()
        gz = "gzip" in self.headers.get("Accept-Encoding", "") and len(body) > 1024
        if gz:
            body = gzip.compress(body, 5)
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", cache)
        for c in getattr(self, "_pending_cookies", []):
            self.send_header("Set-Cookie", c)
        self._pending_cookies = []
        for k_, v_ in getattr(self, "_extra_headers", []):
            self.send_header(k_, v_)
        self._extra_headers = []
        self._sec_headers()
        if gz:
            self.send_header("Content-Encoding", "gzip")
        self.end_headers()
        self.wfile.write(body)

    def _sec_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Strict-Transport-Security", "max-age=31536000")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; "
                         "base-uri 'none'; form-action 'self'; frame-ancestors 'none'; worker-src 'self'; manifest-src 'self'")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")

    def _chat_send(self, user, body):
        """Run one chat turn (chat.py) and send its events to the browser as server-sent events (text/event-stream)."""
        cid, text = str(body.get("id", "")), str(body.get("text", "")).strip()
        if not text:
            return self._json({"error": "empty message"}, 400)
        if len(text) > chat.MAX_INPUT:
            return self._json({"error": f"message too long (max {chat.MAX_INPUT} characters)"}, 400)
        if not chat.owns(user, cid):
            return self._json({"error": "no such chat"}, 404)
        err = chat.rate_check(user)
        if err:
            return self._json({"error": err}, 429)
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-store, no-transform")
        self.send_header("X-Accel-Buffering", "no")
        self._sec_headers()
        self.end_headers()
        self.close_connection = True

        def emit(ev, data):
            self.wfile.write(f"event: {ev}\ndata: {json.dumps(data, separators=(',', ':'))}\n\n".encode())
            self.wfile.flush()
        chat_model, m = None, body.get("model")
        if isinstance(m, dict) and m.get("model") and auth.role_of(user) == "admin":
            m = {"provider": str(m.get("provider", ""))[:40], "model": str(m.get("model", ""))[:120]}
            if llm_allowed(m["provider"], m["model"]):
                chat_model = m
        print(f"chat: {user} -> {cid} ({len(text)} chars){' model ' + chat_model['model'] if chat_model else ''}", file=sys.stderr)
        rec, t0 = {}, time.time()
        try:
            emit("start", {})
            _priv = auth.role_of(user) in ("admin", "defender")  # only admins / network defenders may choose; others get the defaults (Elasticsearch on, web off)
            chat.stream(user, cid, text, emit, body.get("context"), chat_model, rec,
                        es=bool(body.get("es", True)) if _priv else True, web=bool(body.get("web", False)) if _priv else False)
        except (BrokenPipeError, ConnectionResetError):
            print(f"chat: {user} disconnected mid-answer", file=sys.stderr)
            rec.update(status="disconnected", error="browser disconnected mid-answer")
        except Exception as e:  # provider down / timeout: tell the browser, keep the server alive
            print(f"chat error for {user}: {e.__class__.__name__}: {e}", file=sys.stderr)
            rec.update(status="failed", error=f"{e.__class__.__name__}: {e}")
            try:
                emit("end", {"status": "failed", "error": "The assistant is unavailable right now. Try again in a minute."})
            except OSError:
                pass
        finally:
            try:
                audit.llm("chat", rec.get("provider") or "", rec.get("model") or "", user=user, prompt=rec.get("input") or text,
                          response=rec.get("answer"), seconds=round(time.time() - t0, 2), error=rec.get("error") or None, session=cid,
                          tools=rec.get("tools"), status=rec.get("status"), usage=rec.get("usage"),
                          message=f"Ask AI: {user} - {re.sub(chr(92) + 's+', ' ', text)[:100]} ({rec.get('status')})")
            except Exception as e:  # noqa: BLE001
                print(f"audit (chat) failed: {e}", file=sys.stderr)

    def _chat(self, user, body):
        if not chat.enabled():
            return self._json({"error": "chat is not configured on this server"}, 503)
        act, cid = body.get("action"), str(body.get("id", ""))
        try:
            if act == "list":
                return self._json({"chats": chat.sessions(user), "max_input": chat.MAX_INPUT})
            if act == "new":
                return self._json({"id": chat.create(user)})
            if act == "history":
                h = chat.history(user, cid)
                return self._json({"messages": h}) if h is not None else self._json({"error": "no such chat"}, 404)
            if act == "delete":
                return self._json({"ok": True}) if chat.delete(user, cid) else self._json({"error": "no such chat"}, 404)
            if act == "send":
                return self._chat_send(user, body)
        except Exception as e:
            print(f"chat {act} error for {user}: {e.__class__.__name__}: {e}", file=sys.stderr)
            return self._json({"error": "The assistant is unavailable right now."}, 502)
        return self._json({"error": "bad action"}, 400)

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj, separators=(",", ":"), default=str), "application/json")

    def do_POST(self):
        self._code, self._aud = None, {"path": urlparse(self.path).path}
        try:
            self._do_post()
        finally:  # every POST is a user action: one audit entry with the outcome (status code), secrets redacted
            a = self._aud
            body = a.get("body") if isinstance(a.get("body"), dict) else {}
            user = a.get("user") or (str(body.get("username", ""))[:64] if a["path"] == "/api/login" else None)
            if a["path"] == "/api/chat" and body.get("action") in ("list",):
                pass  # the chat page's own refresh of its session list, not an action
            else:
                self._audit(user, a.get("role"), audit_action_name(a["path"], body), "POST", a["path"],
                            params={k: v for k, v in body.items() if k != "username" or a["path"] != "/api/login"},
                            target=audit_target(body), category="authentication" if a["path"] in ("/api/login", "/api/logout") else "web")

    def _do_post(self):
        u = urlparse(self.path)
        # CSRF guard: browsers can't send this header cross-site without a CORS preflight we never approve
        if self.headers.get("X-Netmon") != "1" or "application/json" not in self.headers.get("Content-Type", ""):
            return self._json({"error": "bad request"}, 400)
        try:
            n = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(min(n, 65536)) or b"{}")
            self._aud["body"] = body
            if u.path == "/api/login":
                cookie, err = auth.login(str(body.get("username", "")), str(body.get("password", "")), self._client_ip())
                if err:
                    print(f"login failed for {str(body.get('username', ''))[:40]!r} from {self._client_ip()}", file=sys.stderr)
                    return self._json({"error": err}, 401)
                self._pending_cookies = [f"{self.COOKIE}={cookie}; Path=/; Max-Age={auth.SESSION_TTL}; HttpOnly; Secure; SameSite=Strict"]
                return self._json({"ok": True})
            user = self._user()
            if not user:
                return self._json({"error": "login required"}, 401)
            role = auth.role_of(user)
            self._aud.update(user=user, role=role)
            if role == "user" and u.path not in USER_POST:
                return self._json({"error": "your account can only view the alerts for its assigned devices"}, 403)
            if role != "admin" and (u.path.startswith(ADMIN_POST) or (u.path == "/api/aireview" and body.get("action") == "adopt")):
                print(f"access denied: {user} ({role}) POST {u.path}", file=sys.stderr)
                return self._json({"error": "only an admin can change settings, users or models"}, 403)
            if u.path == "/api/logout":
                self._pending_cookies = [f"{self.COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict"]
                return self._json({"ok": True})
            if u.path == "/api/chat":
                return self._chat(user, body)
            if u.path == "/api/range":  # header time picker: a start/end that isn't a nightly snapshot window
                return self._json(*range_request(body))
            if u.path == "/api/audit/view":  # the browser reports a page view; do_POST writes the audit entry
                self._aud["body"] = {"route": str(body.get("route", ""))[:200]}
                return self._json({"ok": True})
            if u.path == "/api/account/password":
                cookie, err = auth.change_own_password(user, str(body.get("current", "")), str(body.get("password", "")), self._client_ip())
                if err:
                    print(f"password change failed for {user!r} from {self._client_ip()}: {err}", file=sys.stderr)
                    return self._json({"error": err}, 400)
                self._pending_cookies = [f"{self.COOKIE}={cookie}; Path=/; Max-Age={auth.SESSION_TTL}; HttpOnly; Secure; SameSite=Strict"]
                print(f"password changed by {user} from {self._client_ip()} (other sessions signed out)", file=sys.stderr)
                try:
                    store.alerts_add([(f"account|pw|{user}|{int(time.time())}", f"Dashboard account '{user}' changed its password "
                                       f"(from {self._client_ip()}). Other sessions were signed out. If this wasn't you, reset it on the Users page.",
                                       "urgent", ["ip:" + SELF_IP, "host:" + SELF_HOST])], source="account")
                except Exception as e:  # a failed notification must not undo a successful password change
                    print(f"password-change alert not queued: {e}", file=sys.stderr)
                return self._json({"ok": True})
            if u.path == "/api/users":
                act, name = body.get("action"), str(body.get("username", "")).strip()
                if act == "add":
                    err = auth.add(name, str(body.get("password", "")), str(body.get("role") or "user"))
                elif act == "role":
                    err = auth.set_role(name, str(body.get("role", "")), user)
                elif act == "delete":
                    err = auth.delete(name, user)
                elif act == "password":
                    err = auth.set_password(name, str(body.get("password", "")), actor=user, current=str(body.get("current", "")))
                elif act == "devices":  # assign devices to a user = the devices they get alerts / the bell count for
                    mode = str(body.get("mode", "all"))
                    devs = [str(x)[:120] for x in (body.get("devices") or [])][:500]
                    err = (None if name in {x["username"] for x in auth.public_list()} else "no such user") \
                        or (None if mode in ("all", "some") else "mode must be all or some") \
                        or ("pick at least one device, or choose All devices" if mode == "some" and not devs else None) \
                        or ("a User can only be given specific devices, not All devices" if mode == "all" and auth.role_of(name) == "user" else None)
                    if not err:
                        store.prefs_set(name, mode, devs)
                        print(f"user admin: {user} assigned {name} -> {mode} ({len(devs)} devices)", file=sys.stderr)
                else:
                    err = "unknown action"
                if err:
                    return self._json({"error": err}, 400)
                print(f"user admin: {user} {act} {name}", file=sys.stderr)
                return self._json({"ok": True, "users": auth.public_list(), "me": user})
            if u.path == "/api/push/subscribe":
                sub = body.get("subscription") or {}
                if not str(sub.get("endpoint", "")).startswith("https://") or not (sub.get("keys") or {}).get("p256dh"):
                    return self._json({"error": "invalid subscription"}, 400)
                store.push_sub_save(sub, user, self.headers.get("User-Agent", ""))
                print(f"push: {user} subscribed {sub['endpoint'][:50]}…", file=sys.stderr)
                return self._json({"ok": True, "subscribers": len(store.push_subs())})
            if u.path == "/api/push/unsubscribe":
                store.push_sub_delete(str(body.get("endpoint", "")))
                return self._json({"ok": True})
            if u.path == "/api/push/test":
                ep = str(body.get("endpoint", ""))
                subs = [s for s in store.push_subs() if (not ep or s["endpoint"] == ep) and (role == "admin" or s.get("user") == user)]
                res = [pushsvc.send(s, {"title": "netmon: test notification", "body": f"Notifications are working on this device ({user}).",
                                        "tag": "netmon-test", "url": "/#/alerts", "severity": "urgent"}) for s in subs]
                return self._json({"sent": sum(1 for ok, _ in res if ok), "errors": [e for ok, e in res if not ok], "targets": len(subs)})
            if u.path == "/api/push/prefs":
                mode = str(body.get("mode", "all"))
                devs = [str(x)[:120] for x in (body.get("devices") or [])][:500]
                if mode == "some" and not devs:
                    return self._json({"error": "pick at least one device, or choose All devices"}, 400)
                p = store.prefs_set(user, mode, devs)
                print(f"push prefs: {user} -> {mode} ({len(devs)} devices)", file=sys.stderr)
                return self._json({"prefs": p})
            if u.path.startswith("/api/config/integrations/"):
                parts = u.path.split("/")  # /api/config/integrations/<section>[/test]
                sec = parts[4] if len(parts) > 4 else ""
                try:
                    if len(parts) > 5 and parts[5] == "test":
                        return self._json(integrations.test(sec, body))
                    r = integrations.save(sec, body, user)
                    print(f"integrations: {user} saved {sec} (url={'set' if body.get('url') else 'default'}, "
                          f"key={'cleared' if body.get('clear_key') else 'changed' if body.get('api_key') else 'kept'})", file=sys.stderr)
                    return self._json({**r, "admin": True})
                except ValueError as e:
                    return self._json({"error": str(e)}, 400)
            if u.path == "/api/config/lookback":  # hours of logs each research run collects (admin; read by collect.py auto)
                try:
                    res = lookback.put(body.get("hours"), user)
                except ValueError as e:
                    return self._json({"error": str(e)}, 400)
                print(f"research lookback: {user} set {res['hours']} h", file=sys.stderr)
                return self._json({"ok": True, "lookback": res})
            if u.path in ("/api/config/triage", "/api/config/triage/reopen", "/api/config/triage/run", "/api/config/review-schedule"):
                if u.path == "/api/config/review-schedule":
                    try:
                        mins = int(body.get("hours") or 0) * 60 + int(body.get("minutes") or 0)
                        research_cfg.put({"interval_minutes": mins}, user)
                    except (TypeError, ValueError) as e:
                        return self._json({"error": f"could not change the research job schedule: {str(e)[:200]}"}, 400)
                    print(f"research schedule: {user} -> every {mins} min", file=sys.stderr)
                inp = autoclose_inputs()
                if u.path == "/api/config/triage":
                    autoclose.set_settings(body.get("expected"), body.get("benign"), user)
                    print(f"autoclose settings: {user} expected={bool(body.get('expected'))} benign={bool(body.get('benign'))}", file=sys.stderr)
                elif u.path == "/api/config/triage/reopen":
                    k = body.get("kind")
                    autoclose.reopen_all(user, k if k in autoclose.KINDS else None)
                elif u.path == "/api/config/triage/run" and inp:
                    autoclose.run(*inp, trigger=f"run now ({user})")
                r = autoclose.run(*inp, dry=True) if inp else {"settings": autoclose.settings()}
                return self._json({**r, "review": review_job(), "admin": True})
            if u.path == "/api/llm/config":  # choose the model of the correlation reviewer, the research job or the chat
                sec, prov, model = str(body.get("section", "")), str(body.get("provider", "")), str(body.get("model", ""))[:120]
                if sec not in ("correlation", "research", "chat") or not llm_allowed(prov, model):
                    return self._json({"error": "unknown section, provider or model"}, 400)
                if sec == "correlation":
                    corr_llm.set_correlation(prov, model, user)
                    res = corr_llm.config()["correlation"]
                elif sec == "chat":
                    corr_llm.set_chat(prov, model, user)
                    res = corr_llm.config()["chat"]
                else:
                    research_cfg.put({"provider": prov, "model": model}, user)
                    res = review_job()
                print(f"llm config: {user} set {sec} -> {prov}/{model}", file=sys.stderr)
                return self._json({"ok": True, sec: res})
            if u.path == "/api/llm/chat-es":  # may the Ask AI chat search Elasticsearch
                res = corr_llm.set_chat_es(bool(body.get("enabled")), user)
                print(f"llm chat-es: {user} set enabled={res['enabled']}", file=sys.stderr)
                return self._json({"ok": True, "chat_es": res})
            if u.path == "/api/llm/esqueries":  # may the correlation reviewer search Elasticsearch, and how often per event
                try:
                    res = corr_llm.set_es_queries(bool(body.get("enabled")), body.get("max"), user)
                except (TypeError, ValueError) as e:
                    return self._json({"error": str(e)[:200]}, 400)
                print(f"llm esqueries: {user} set enabled={res['enabled']} max={res['max']}", file=sys.stderr)
                return self._json({"ok": True, "es_queries": res})
            if u.path == "/api/llm/notes":  # most host / user notes the reviewer gets per event
                try:
                    res = corr_llm.set_notes_limit(body.get("max"), user, body.get("chars"), body.get("per_subject"))
                except (TypeError, ValueError) as e:
                    return self._json({"error": str(e)[:200]}, 400)
                print(f"llm notes: {user} set max notes per event={res['max']}, note characters={res['chars']}", file=sys.stderr)
                return self._json({"ok": True, "context_notes": res})
            if u.path == "/api/llm/research":  # research job: cost caps, on/off, run now (admin)
                if body.get("action") == "run":
                    research_cfg.request(user)
                    print(f"research job: {user} requested a run", file=sys.stderr)
                    return self._json({"ok": True, "research": review_job()})
                fields = {k: body[k] for k in ("max_run_usd", "max_day_usd", "max_run_tokens", "max_batches", "max_searches", "enabled", "web_research", "es_search", "severities", "modes") if k in body}
                try:
                    research_cfg.put(fields, user)
                except ValueError as e:
                    return self._json({"error": str(e)[:300]}, 400)
                print(f"research job: {user} set {fields}", file=sys.stderr)
                return self._json({"ok": True, "research": review_job()})
            if u.path == "/api/alerts/mutes":  # remove a saved mute rule: its cleared alerts return to the feed
                if body.get("action") != "remove":
                    return self._json({"error": "action must be remove"}, 400)
                lk, n = store.mute_remove(int(body.get("id") or 0))
                if lk is None:
                    return self._json({"error": "no such mute rule"}, 404)
                try:
                    if lk:
                        corr_llm.set_limits(user, None, None, None, None, None, lk, None)
                except Exception as e:  # noqa: BLE001 - the matching never-send rule may already be gone
                    print(f"mute remove: limits rule: {e}", file=sys.stderr)
                _CORR.clear()
                print(f"alert mute: {user} removed rule {body.get('id')}; {n} alerts restored", file=sys.stderr)
                return self._json({"ok": True, "restored": n})
            if u.path == "/api/llm/review-limits":  # which candidate links the reviewer never sees (admin)
                try:
                    corr_llm.set_limits(user, body.get("skip_pairs"), body.get("exclude"), body.get("unexclude"), body.get("max_links"), body.get("rule"), body.get("unrule"), body.get("pair_modes"), classify=body.get("classify"), window=body.get("window"), discard_days=body.get("discard_days"))
                except ValueError as e:
                    print(f"review-limits: {user}: rejected: {e}", file=sys.stderr)
                    return self._json({"error": str(e)[:300]}, 400)
                cleared = 0
                if body.get("ids_suppress") or body.get("unids_suppress"):  # IDS signature (+ optional host): hidden everywhere in netmon
                    try:
                        if body.get("unids_suppress"):
                            store.ids_suppress_remove(body["unids_suppress"])
                            print(f"ids suppress: {user} removed rule {body['unids_suppress']}", file=sys.stderr)
                        else:
                            sp = body["ids_suppress"]
                            rid = store.ids_suppress_add(sp.get("sig"), sp.get("host"), user)
                            print(f"ids suppress: {user} added rule {rid} {json.dumps(sp)[:200]}", file=sys.stderr)
                        _CORR.clear()
                    except ValueError as e:
                        return self._json({"error": str(e)[:300]}, 400)
                    return self._json({"ok": True, "ids_rules": store.ids_suppress_list()})
                if body.get("seg_suppress") or body.get("unseg_suppress"):  # segmentation violations: hide by source IP / destination IP / ports; not correlated
                    try:
                        if body.get("unseg_suppress"):
                            store.seg_suppress_remove(body["unseg_suppress"])
                            print(f"seg suppress: {user} removed rule {body['unseg_suppress']}", file=sys.stderr)
                        else:
                            sp = body["seg_suppress"]
                            rid = store.seg_suppress_add(sp.get("src"), sp.get("dst"), sp.get("ports"), user)
                            print(f"seg suppress: {user} added rule {rid} {json.dumps(sp)[:200]}", file=sys.stderr)
                        _CORR.clear()
                    except ValueError as e:
                        return self._json({"error": str(e)[:300]}, 400)
                    return self._json({"ok": True, "seg_rules": store.seg_suppress_list()})
                if body.get("suppress") or body.get("unsuppress"):  # suppress rules: hide a finding by signature (+ artifact), still correlated
                    try:
                        import suppress
                        sp = body.get("suppress") or {}
                        swept = 0
                        if body.get("unsuppress"):
                            r = suppress.remove(body["unsuppress"])
                            print(f"suppress: {user} removed rule {body['unsuppress']}: reopened {r[0]} item(s), restored {r[1]} alert(s)", file=sys.stderr)
                        else:
                            rid, cleared = store.suppress_add(sp.get("name"), sp.get("art_type"), sp.get("art"), user)
                            print(f"suppress: {user} added rule {rid} {json.dumps(sp)[:200]}; hid {cleared} alert(s)", file=sys.stderr)
                            swept = suppress.sweep_open(rid)  # also close the stored open findings (any age) the rule covers
                        _CORR.clear()
                        sid0 = (snapshots() or [{"id": ""}])[-1]["id"]
                        correlation(sid0)  # applies the rules to the events now
                    except ValueError as e:
                        return self._json({"error": str(e)[:300]}, 400)
                    return self._json({"ok": True, "cleared_alerts": cleared, "cleared_open": swept, "limits": corr_llm.limits_view(correlation(sid0) or {})})
                if body.get("rule") and body.get("clear_alerts"):  # muting an alert class: save the mute rule (applied to every future alert) and clear the alerts that already fired
                    try:
                        rl = {k: str(body["rule"].get(k) or "").strip() for k in ("name", "host")}
                        lk = "rule|" + "|".join([rl["name"].lower()[:200], rl["host"].lower()[:200], "", str(body["rule"].get("scope") or "both")])
                        _mid, cleared = store.mute_add(rl["name"], rl["host"], user, lk)
                        _CORR.clear()
                    except Exception as e:  # noqa: BLE001
                        print(f"clear alerts failed: {e}", file=sys.stderr)
                print(f"review limits: {user} cleared {cleared} alerts; set {json.dumps({k: body[k] for k in ('skip_pairs', 'exclude', 'unexclude', 'max_links', 'rule', 'unrule', 'pair_modes', 'classify', 'window', 'discard_days') if k in body})[:300]}", file=sys.stderr)
                return self._json({"ok": True, "cleared_alerts": cleared, "limits": corr_llm.limits_view(correlation((snapshots() or [{"id": ""}])[-1]["id"]) or {})})
            if u.path in ("/api/aireview/clear-review", "/api/aireview/clear-research"):  # admin: empty a queue (see ADMIN_POST)
                try:
                    if u.path.endswith("review"):
                        n = corr_llm.clear_pending([x["id"] for x in (snapshots() or [])][-3:], user)
                        what, res = "review queue", {"dismissed": sum(n.values())}
                    else:
                        res = enrich.clear_queue(user, False)
                        what = "research queue"
                        if res.get("error"):
                            return self._json(res, 400)
                        enrich._QCACHE.clear()
                except Exception as e:  # noqa: BLE001
                    return self._json({"error": str(e)[:300]}, 500)
                print(f"queue cleared: {user} emptied the {what} {json.dumps(res)[:200]}", file=sys.stderr)
                return self._json({"ok": True, **res})
            if u.path == "/api/llm/providers":  # admin-added AI providers (any OpenAI-compatible or Anthropic API with a key)
                act = str(body.get("action") or "")
                try:
                    if act == "save" and str(body.get("id") or "") == llm_providers.LOCAL:
                        res = llm_providers.save_local(body, user)
                        print(f"llm providers: {user} set local (LM Studio) enabled={res['enabled']} rate_per_hour={res['rate_per_hour']}",
                              file=sys.stderr)
                        return self._json({"ok": True, "provider": res, "providers": llm_providers.public()})
                    if act == "save":
                        res = llm_providers.save(body, user)
                        print(f"llm providers: {user} saved {res['name']!r} ({res['type']}, {res['base_url']}, {len(res['models'])} models, "
                              f"key={'changed' if body.get('api_key') else 'kept'})", file=sys.stderr)
                        return self._json({"ok": True, "provider": res, "providers": llm_providers.public()})
                    if act == "delete":
                        pid = str(body.get("id") or "")
                        cfg, rj = corr_llm.config(), research_cfg.get()
                        use = [n for n, p in (("correlation reviewer", cfg["correlation"]["provider"]), ("chat", cfg["chat"]["provider"]),
                                              ("research job", rj["provider"])) if p == llm_providers.PREFIX + pid]
                        if use:
                            return self._json({"error": f"this provider is used by the {' and the '.join(use)} - pick another model there first"}, 400)
                        llm_providers.delete(pid)
                        print(f"llm providers: {user} deleted provider {pid}", file=sys.stderr)
                        return self._json({"ok": True, "providers": llm_providers.public()})
                    if act == "test":
                        return self._json(llm_providers.test(body))
                    if act == "models":
                        return self._json(llm_providers.fetch_models(body))
                except ValueError as e:
                    return self._json({"error": str(e)[:300]}, 400)
                except RuntimeError as e:  # provider rejected the key / unreachable (key already scrubbed)
                    return self._json({"error": str(e)[:400]}, 502)
                return self._json({"error": "unknown action"}, 400)
            if u.path == "/api/compare/item":  # one finding / alarm / note, several models, side by side
                kind, title = str(body.get("kind", ""))[:60], str(body.get("title", ""))[:300]
                item = body.get("item")
                M = llm_models()
                tg = [{"provider": str(t.get("provider")), "model": str(t.get("model"))[:120]} for t in (body.get("targets") or [])[:4] if isinstance(t, dict)]
                tg = [t for t in tg if llm_allowed(t["provider"], t["model"], M)]
                if not tg or not (kind and title) or len(json.dumps(item, default=str)) > 40000:
                    return self._json({"error": "pick 1-4 available models"}, 400)
                print(f"item compare: {user} {len(tg)} models on {kind}: {title[:80]!r}", file=sys.stderr)
                return self._json(itemcmp.compare(kind, title, item, tg, user))
            if u.path == "/api/compare/adopt":  # use one model's assessment as an event's research note
                eid = str(body.get("event", ""))[:1200]
                if not eid:
                    return self._json({"error": "event required"}, 400)
                enrich.adopt_note(eid, body.get("verdict"), body.get("priority"), str(body.get("summary") or ""), str(body.get("reasoning") or ""),
                                  str(body.get("model") or "model"), user)
                print(f"item compare: {user} adopted {str(body.get('model'))[:60]} for {eid[:100]!r}", file=sys.stderr)
                return self._json({"ok": True})
            if u.path == "/api/aireview/compare":  # one decision, several models, side by side
                pr = str(body.get("pair", ""))[:1200]
                M = llm_models()
                tg = [{"provider": str(t.get("provider")), "model": str(t.get("model"))[:120]} for t in (body.get("targets") or [])[:4] if isinstance(t, dict)]
                tg = [t for t in tg if llm_allowed(t["provider"], t["model"], M)]
                if not tg or "\x1f" not in pr:
                    return self._json({"error": "pick 1-4 available models"}, 400)
                s_ = snapshots()
                base = correlation(s_[-1]["id"] if s_ else "") or {}
                try:
                    res = corr_llm.compare(pr, base, tg, user)
                except ValueError as e:
                    return self._json({"error": str(e)}, 400)
                print(f"ai compare: {user} {len(tg)} models on {pr[:100]!r}", file=sys.stderr)
                return self._json(res)
            if u.path == "/api/aireview" and body.get("action") == "adopt":
                pr = str(body.get("pair", ""))[:1200]
                corr_llm.adopt(pr, bool(body.get("related")), body.get("confidence"), str(body.get("reason") or ""), str(body.get("model") or "model"), user)
                print(f"ai review: {user} adopted {str(body.get('model'))[:60]} on {pr[:100]!r}", file=sys.stderr)
                return self._json({"ok": True})
            if u.path == "/api/aireview":  # override or re-review one AI verdict
                act, pr = str(body.get("action", "")), str(body.get("pair", ""))
                if act not in ("confirm", "reject", "rereview"):
                    return self._json({"error": "action must be confirm, reject or rereview"}, 400)
                try:
                    corr_llm.override(pr, {"confirm": True, "reject": False, "rereview": None}[act], user)
                except ValueError as e:
                    return self._json({"error": str(e)}, 400)
                print(f"ai review: {user} {act} {pr[:120]!r}", file=sys.stderr)
                return self._json({"ok": True})
            if u.path == "/api/kb/host":  # host/device/domain notes (AI-written knowledge; people may add or delete)
                act = body.get("action")
                if act == "add":
                    nid = kb.add_host_note({"subject": body.get("subject")}, body.get("text"), body.get("category"), author="user:" + user,
                                           via="dashboard", note_id=body.get("id"))
                    print(f"kb: {user} {'updated' if body.get('id') else 'added'} host note {nid} on {str(body.get('subject'))[:60]}", file=sys.stderr)
                    return self._json({"ok": True, "id": nid})
                if act == "delete":
                    n = kb.delete_host_note(body.get("id"))
                    print(f"kb: {user} deleted host note {body.get('id')!r}", file=sys.stderr)
                    return self._json({"ok": bool(n)})
                if act in ("approve", "reject", "clear"):  # admin / network defender: approve = authoritative for the AI, reject = kept but never sent
                    if role not in ("admin", "defender"):
                        return self._json({"error": "only a network defender or admin can review notes"}, 403)
                    n = kb.review_host_note(body.get("id"), act, user)
                    print(f"kb: {user} {act} host note {body.get('id')!r}", file=sys.stderr)
                    return self._json({"ok": bool(n)})
                return self._json({"error": "action must be add, delete, approve, reject or clear"}, 400)
            if u.path == "/api/research/request":  # send one event to the research job if it was not researched yet
                eid, act = str(body.get("eid") or "")[:300], body.get("action")
                if not eid or act not in ("status", "send"):
                    return self._json({"error": "eid and action status|send required"}, 400)
                if role == "user" and eid not in {e["id"] for e in my_events(user)["events"]}:
                    print(f"access denied: {user} (user) research request outside their devices {eid[:80]!r}", file=sys.stderr)
                    return self._json({"error": "not one of your devices' events"}, 403)
                try:
                    r = enrich.request_research(eid, user, act == "send")
                except ValueError as e:
                    return self._json({"error": str(e)}, 400)
                if act == "send":
                    print(f"research requested: {user} ({role}) {eid[:100]!r} -> {r['state']}", file=sys.stderr)
                return self._json({"ok": True, **r})
            if u.path == "/api/kb/event":  # people's notes on an event (📝); the AI reads APPROVED ones as guidance
                act, eid = body.get("action"), str(body.get("eid") or "")
                mine = user if role == "user" else None  # a User sees / deletes only their own notes
                notes_for = lambda: kb.event_notes([eid], author=mine).get(eid, [])  # noqa: E731
                if role == "user" and act not in ("add", "delete"):
                    return self._json({"error": "only a network defender or admin can approve notes"}, 403)
                if act == "add":
                    if role == "user" and eid not in {e["id"] for e in my_events(user)["events"]}:
                        print(f"access denied: {user} (user) note on event outside their devices {eid[:80]!r}", file=sys.stderr)
                        return self._json({"error": "you can only add notes to events of your assigned devices"}, 403)
                    try:
                        nid = kb.add_event_note(eid, body.get("text"), user, body.get("label"), role=role)
                    except ValueError as e:
                        return self._json({"error": str(e)}, 400)
                    print(f"kb: {user} ({role}) added event note {nid} on {eid[:80]!r}{' - pending approval' if role == 'user' else ''}", file=sys.stderr)
                    return self._json({"ok": True, "id": nid, "notes": notes_for()})
                if act == "delete":
                    n = kb.delete_event_note(body.get("id"), author=mine)
                    print(f"kb: {user} deleted event note {body.get('id')!r}" + ("" if n else " - refused/not found"), file=sys.stderr)
                    return self._json({"ok": bool(n), "notes": notes_for()})
                if act in ("approve", "reject"):  # defender / admin gate before a User's note may reach the AI
                    n = kb.review_event_note(body.get("id"), act == "approve", user)
                    print(f"kb: {user} ({role}) {act}d event note {body.get('id')!r}", file=sys.stderr)
                    return self._json({"ok": bool(n), "notes": notes_for() if eid else []})
                return self._json({"error": "action must be add, delete, approve or reject"}, 400)
            if u.path == "/api/alerts/read":
                if role == "user":  # private read marker: a user must not clear the shared 🔔 for everyone else
                    ids = watch_ids(user, role)
                    mine = [r["id"] for r in store.alerts_recent(2000) if store.alert_for(r, ids)]
                    auth.set_read_upto(user, max(mine or [0]))
                    return self._json({"ok": True})
                store.alerts_read_all()
                return self._json({"ok": True})
            if u.path == "/api/config/discover":  # admin only: build a zone/role/device-class proposal from UniFi; apply=true merges it
                try:
                    import discover
                    prop = discover.build()
                    if not body.get("apply"):
                        return self._json({"ok": True, **prop})
                    ow = bool(body.get("overwrite"))
                    n = discover.apply(prop, overwrite=ow)
                    print(f"settings: {user} applied UniFi discovery (overwrite={ow}): {n}", file=sys.stderr)
                    return self._json({"ok": True, "applied": n})
                except Exception as e:  # noqa: BLE001
                    print(f"discover failed: {type(e).__name__}: {e}", file=sys.stderr)
                    hint = " - set the UniFi API key under More > Configuration" if "401" in str(e) or "403" in str(e) or not integrations.unifi_key() else ""
                    return self._json({"error": f"UniFi discovery failed: {type(e).__name__}: {e}{hint}"}, 502)
            if u.path == "/api/config/cfg":  # admin only (ADMIN_POST prefix); set one value inside a settings document
                doc, kp, val = str(body.get("doc") or ""), body.get("path"), body.get("value")
                if doc not in store.CFG_DOCS or not isinstance(kp, list) or not kp or len(kp) > 6 or "value" not in body:
                    return self._json({"error": "doc, path and value required"}, 400)
                if len(json.dumps(val)) > 400000:
                    return self._json({"error": "value too large"}, 400)
                data = store.cfg_load(doc)
                node = data
                for k in kp[:-1]:
                    node = node[k] if isinstance(node, list) and isinstance(k, int) and 0 <= k < len(node) else (node.get(k) if isinstance(node, dict) else None)
                    if node is None:
                        return self._json({"error": "no such section"}, 400)
                last = kp[-1]
                if isinstance(node, list) and isinstance(last, int) and 0 <= last < len(node):
                    node[last] = val
                elif isinstance(node, dict) and isinstance(last, str) and not last.startswith("_"):
                    node[last] = val
                else:
                    return self._json({"error": "bad path"}, 400)
                bad = cfg_validate(doc, data)
                if bad:
                    return self._json({"error": bad}, 400)
                n = store.cfg_save(doc, data)
                print(f"settings: {user} changed {doc} / {'/'.join(map(str, kp))} ({n} rows)", file=sys.stderr)
                return self._json({"ok": True, "rows": n})
            if u.path == "/api/acks":
                typ, key = str(body.get("type", ""))[:40], str(body.get("key", ""))[:600]
                if not typ or not key:
                    return self._json({"error": "type and key required"}, 400)
                return self._json(write_ack(typ, key, bool(body.get("checked")), str(body.get("note") or ""),
                                            str(body.get("label") or "")))
            return self._json({"error": "not found"}, 404)
        except Exception as e:
            print("post error", e, file=sys.stderr)
            return self._json({"error": str(e)}, 500)

    def do_GET(self):
        self._code, self._aud = None, {}
        try:
            self._do_get()
        finally:  # GETs are data loads; audited: report downloads, lookups, audit-log reads and every denied request
            a, code = self._aud, getattr(self, "_code", None)
            p = urlparse(self.path).path
            act = a.get("act") or AUDIT_GET.get(p)
            if a.get("user") and (act or code == 403):
                q = {k: v[0][:300] for k, v in parse_qs(urlparse(self.path).query).items()}
                self._audit(a["user"], a.get("role"), act or "access.denied", "GET", p, params=q or None, target=a.get("target"),
                            category="file" if act == "report.download" else "web")

    def _do_get(self):
        u = urlparse(self.path)
        path, q = u.path, parse_qs(u.query)
        if path == "/healthz":
            return self._send(200, "ok", "text/plain")
        if path == "/login":
            path = "/login.html"
        user = None if path in self.PUBLIC else self._user()
        if path not in self.PUBLIC and not user:
            return self._deny(path)
        role = auth.role_of(user) if user else None
        self._aud.update(user=user, role=role)
        if role == "user" and (path.startswith("/api/")) and path not in USER_GET:
            return self._json({"error": "your account can only view the alerts for its assigned devices"}, 403)
        admin = role == "admin"
        try:
            if path == "/api/me":
                return self._json({"user": user, "role": role, "role_name": auth.ROLE_NAMES.get(role, role)})
            if path == "/api/my":
                return self._json(my_events(user))
            if path == "/api/site":
                return self._json({"site_name": SITE.public().get("site_name")} if role == "user" else SITE.public())
            if path == "/api/account":
                return self._json(auth.account_info(user))
            if path == "/api/users":
                ul = auth.public_list()
                return self._json({"users": ul, "me": user, "min_password": auth.MIN_PW,
                                   "prefs": {x["username"]: store.prefs_get(x["username"]) for x in ul}, "devices": device_catalog()})
            if path in ("/api/audit", "/api/audit/doc", "/api/audit/status"):  # More > Audit log (admin only)
                if not admin:
                    return self._json({"error": "only an admin can read the audit log"}, 403)
                try:
                    if path == "/api/audit/status":
                        return self._json(audit.status())
                    if path == "/api/audit/doc":
                        d = audit.doc((q.get("id") or [""])[0])
                        return self._json({"doc": d}) if d else self._json({"error": "not found"}, 404)
                    return self._json({**audit.search({k: v[0] for k, v in q.items()}), "status": audit.status()})
                except ValueError as e:
                    return self._json({"error": str(e)}, 400)
                except Exception as e:  # noqa: BLE001 - ES down / no key: the page says so
                    # 200, not 502: behind the Cloudflare tunnel a 502 body is replaced by Cloudflare's own HTML page
                    return self._json({"error": f"audit log unavailable: {str(getattr(e, 'reason', e))[:200]}", "status": audit.status()})
            if path == "/api/snapshots":
                return self._json(snapshots())
            if path == "/api/range/status":
                st = range_status((q.get("id") or [""])[0])
                return self._json(st) if st else self._json({"error": "not found"}, 404)
            if path == "/api/snapshot":
                sid = (q.get("id") or [""])[0]
                if sid == "latest":
                    s = snapshots()
                    sid = s[-1]["id"] if s else ""
                res = snapshot(sid) or range_skeleton(sid)
                return self._json(res) if res else self._json({"error": "not found"}, 404)
            if path == "/api/section":  # one piece of a time range (the page loads them two at a time, top to bottom)
                try:
                    res = range_section((q.get("id") or [""])[0], (q.get("name") or [""])[0])
                except Exception as ex:  # noqa: BLE001 - broker down / collector failed
                    return self._json({"error": str(ex).replace("broker: ", "")[:300]}, 502)
                return self._json(res) if res is not None else self._json({"error": "not found"}, 404)
            if path == "/api/acks":
                return self._json(read_acks())
            if path == "/api/events/open":  # every unchecked event, any age (persisted in sqlite `events`)
                import eventstore
                return self._json(eventstore.open_events(types=set(q.get("type") or []) or None, sev=(q.get("sev") or [""])[0].lower() or None,
                                                         q=(q.get("q") or [""])[0] or None, limit=min(int((q.get("limit") or ["2000"])[0]), 5000)))
            if path == "/api/notes/by-event":  # research notes for events that may no longer be in the loaded snapshot (checked-off / aged out)
                try:
                    return self._json(enrich.load([e[:600] for e in (q.get("e") or [])[:40]]))
                except Exception as e:  # noqa: BLE001
                    print(f"notes by event: {e}", file=sys.stderr)
                    return self._json({})
            if path == "/api/checked/notes":  # research notes of checked-off items (kept even when the event is gone from the snapshot)
                try:
                    return self._json(enrich.for_acks(read_acks()))
                except Exception as e:  # noqa: BLE001
                    print(f"checked notes: {e}", file=sys.stderr)
                    return self._json({})
            if path == "/api/llm/providers":
                if not admin:
                    return self._json({"admin": False, "providers": []})
                return self._json({"admin": True, "providers": llm_providers.public(),
                                   "types": {k: v for k, v in llm_providers.TYPES.items()}})
            if path == "/api/config/integrations":
                if not admin:
                    return self._json({"admin": False})
                return self._json({**integrations.public(), "admin": True})
            if path == "/api/config/cfg":  # Settings page: policy / host_policy / known_benign / site as editable tables
                if role not in ("admin", "defender"):
                    return self._json({"error": "only an admin or defender can read the settings"}, 403)
                doc = (q.get("doc") or ["policy"])[0]
                if doc not in store.CFG_DOCS:
                    return self._json({"error": "unknown settings document"}, 404)
                return self._json({"doc": doc, "docs": list(store.CFG_DOCS), "data": store.cfg_load(doc), "admin": admin})
            if path == "/api/config/triage":
                inp = autoclose_inputs()
                return self._json({**(autoclose.run(*inp, dry=True) if inp else {"settings": autoclose.settings()}), "review": review_job(),
                                   "admin": admin})
            if path == "/api/ti/feeds":
                return self._json(tintel.feed_status())
            if path == "/api/ti/lookup":
                return self._json(tintel.lookup((q.get("q") or [""])[0][:300]))
            if path == "/api/ti/trend":
                rows = [(x["id"], load_json(os.path.join(DATA, x["id"] + ".json"))) for x in snapshots()]
                return self._json(tintel.trend([(i, r) for i, r in rows if r]))
            if path == "/api/history":
                return self._json(history())
            if path == "/api/issues":
                return self._json(issue_tracker())
            if path in ("/api/risk", "/api/lateral"):
                sid = (q.get("id") or ["latest"])[0]
                if sid == "latest":
                    s = snapshots()
                    sid = s[-1]["id"] if s else ""
                pol = with_cleared(load_json(os.path.join(ROOT, "policy.json"), {}))
                kbn = load_json(os.path.join(ROOT, "known_benign.json"), {})
                if path == "/api/lateral" and (q.get("p") or [""])[0]:  # time picker: one or more periods, straight from Elasticsearch
                    try:
                        per = [x.split("~") for x in (q.get("p") or [""])[0].split(",")]
                        raw_p, an_p = lateral_periods([(x[0], x[1]) for x in per])
                    except (ValueError, IndexError) as ex:
                        return self._json({"error": str(ex) or "bad periods"}, 400)
                    s_ = snapshots()  # host risk scores come from the newest nightly snapshot
                    base = snapshot(s_[-1]["id"]) if s_ else None
                    rr = risk.compute(base["raw"], base["analysis"], issue_tracker(), pol, kbn) if base and base.get("analysis") else None
                    return self._json(lateral.build(raw_p, an_p, pol, rr, kbn))
                res = snapshot(sid)
                if not res:
                    return self._json({"error": "not found"}, 404)
                rr = risk.compute(res["raw"], res["analysis"], issue_tracker(), pol, kbn)
                if path == "/api/risk":
                    return self._json(rr)
                return self._json(lateral.build(res["raw"], res["analysis"], pol, rr, kbn))
            if path == "/api/llm/models":
                return self._json({**llm_models(), "admin": admin})
            if path == "/api/compare/item":
                return self._json({"history": itemcmp.history(str((q.get("key") or [""])[0])[:64])})
            if path == "/api/aireview/compare":
                return self._json({"history": corr_llm.comparisons(str((q.get("pair") or [""])[0])[:1200])})
            if path == "/api/aireview/review-queue":  # links awaiting review (admin / network defender)
                s_ = snapshots()
                return self._json(corr_llm.pending_list(correlation(s_[-1]["id"]) if s_ else {}))
            if path == "/api/aireview/research-queue":  # events awaiting research (admin)
                if not admin:
                    return self._json({"error": "admin only"}, 403)
                return self._json(enrich.queue_items())
            if path == "/api/aireview":
                s_ = snapshots()
                sid = s_[-1]["id"] if s_ else ""
                base = correlation(sid) or {}
                ov = {**corr_llm.overview(base.get("events") or {}, corr_llm.apply(base)), "snapshot": sid, "admin": admin, "can_limit": role in ("admin", "defender"),
                      "provider_names": {p["provider"]: p["name"] for p in llm_providers.public()}}
                ov["research"] = review_job()
                ov["limits"] = corr_llm.limits_view(base)
                ov["chat"] = corr_llm.config()["chat"]
                ov["lookback"] = lookback.get()
                try:
                    ov["research_status"] = enrich.status((base.get("events") or {}).keys())
                except Exception as e:  # noqa: BLE001 - the reviewer view must not depend on the research job status
                    ov["research_status"] = {"error": str(e)[:200]}
                return self._json(ov)
            if path == "/api/correlate":
                sid = (q.get("id") or ["latest"])[0]
                if sid == "latest":
                    s_ = snapshots()
                    sid = s_[-1]["id"] if s_ else ""
                corr_llm.want(sid)  # the LLM reviewer also covers snapshots people are looking at
                res_ = kb.apply(enrich.apply(corr_llm.apply(correlation(sid))))
                if res_:
                    res_ = {k: v for k, v in res_.items() if k != "items"}
                    try:
                        import eventseen
                        res_ = dict(res_, seen=eventseen.view(res_.get("events")))
                    except Exception as e:  # noqa: BLE001
                        print(f"eventseen: view failed: {e}", file=sys.stderr)
                return self._json(res_ or {"error": "not found"}, 200)
            if path == "/api/accounts":  # Network > Users: accounts seen and their patterns (?user= adds that account's breakdown + events)
                import accounts
                u = (q.get("user") or [""])[0]
                res = accounts.overview(u or None, len(snapshots()))
                if u:
                    sl = snapshots()
                    c_ = (correlation(sl[-1]["id"]) or {}).get("events") or {} if sl else {}
                    res["events"] = [{"id": i, "type": e["type"], "label": e["label"], "link": e["link"], "t0": e["t0"], "sev": e["sev"]} for i, e in c_.items()
                                     if any(a[0] == "user" and a[1].lower() == u.lower() for a in e.get("arts") or [])][:60]
                return self._json(res)
            if path == "/api/kb/host":  # notes for one device / endpoint / domain: ?s=mac:..,ip:..,host:..,dom:..
                subs = [s.strip() for s in (q.get("s") or [""])[0].split(",") if s.strip()][:20]
                return self._json({"notes": kb.host_notes(subs)})
            if path == "/api/kb/resolve":  # canonical subject for ?ip= / ?mac= / ?host= / ?dom=
                try:
                    s_, label = kb.resolve(ip=(q.get("ip") or [None])[0], mac=(q.get("mac") or [None])[0],
                                            host=(q.get("host") or [None])[0], dom=(q.get("dom") or [None])[0])
                except ValueError as e:
                    return self._json({"error": str(e)}, 400)
                return self._json({"subject": s_, "label": label})
            if path == "/api/kb/dns":  # Network > Internet notes: DNS notes by domain / subdomain
                return self._json({"domains": kb.dns_notes((q.get("q") or [""])[0])})
            if path == "/api/kb/internet":  # Network > Internet notes: every external IP that has notes
                return self._json({"ips": kb.internet_notes((q.get("q") or [""])[0])})
            if path == "/api/research/running":  # header microscope: is the research job running right now
                try:
                    return self._json({"running": bool(review_job().get("running"))})
                except Exception:  # noqa: BLE001
                    return self._json({"running": False})
            if path == "/api/suppress":  # Checked page: suppress rules + what they hid
                import suppress
                ce, ca = suppress.counts()
                return self._json({"rules": [{**r, "events": ce.get(r["id"], 0), "alerts": ca.get(r["id"], 0)} for r in store.suppress_list()],
                                   "seg_rules": store.seg_suppress_list(), "ids_rules": store.ids_suppress_list(), "hits": suppress.item_hits(), "can_edit": role in ("admin", "defender")})
            if path == "/api/suppress/suggest":  # the correlation event behind a check-off item: label + every artifact of it and of its correlated events
                t, k = (q.get("type") or [""])[0], (q.get("key") or [""])[0]
                sl = snapshots()
                base = (correlation(sl[-1]["id"]) or {}) if sl else {}
                E = base.get("events") or {}
                for eid, ev in E.items():
                    if t == "alert":  # a watcher alert: found by its text
                        if not (eid.startswith("alert|") and str(ev.get("label") or "") == k[:160]):
                            continue
                    elif (t, k) not in corr_llm._ack_keys(eid):
                        continue
                    out, seen = [], set()

                    def put(typ, val, src, rel=""):
                        val = str(val).strip()
                        if val and (typ, val.lower()) not in seen:
                            seen.add((typ, val.lower()))
                            out.append({"type": typ, "value": val, "from": src, "rel": rel[:80]})
                    for src, e2, name in [("event", ev, "")] + [("correlated", E[r["id"]], E[r["id"]].get("label") or "") for r in (base.get("related") or {}).get(eid, []) if r["id"] in E]:
                        for i in (e2.get("ips") or []) + (e2.get("dst_ips") or []):
                            put("ip", i, src, name)
                        for a in e2.get("arts") or []:
                            put({"dns": "domain"}.get(a[0], a[0]), a[1], src, name)
                        for pt in store._PORT_RE.findall(e2.get("label") or ""):
                            put("port", pt, src, name)
                    return self._json({"eid": eid, "label": ev.get("label"), "artifacts": out[:80]})
                return self._json({"eid": "", "label": "", "artifacts": []})
            if path == "/api/kb/all":  # the Notes page
                return self._json({"host_notes": kb.host_notes(), "event_notes": kb.all_event_notes()})
            if path == "/api/mitre":
                sid = (q.get("id") or ["latest"])[0]
                if sid == "latest":
                    sl = snapshots()
                    sid = sl[-1]["id"] if sl else ""
                res = snapshot(sid)
                if not res:
                    return self._json({"error": "not found"}, 404)
                if ROOT not in sys.path:
                    sys.path.append(ROOT)
                import mitre
                return self._json(mitre.map_all(res["raw"], res.get("analysis"), res.get("triage"), issue_tracker(), read_acks()))
            if path == "/api/registry":
                return self._json(registry())
            if path == "/api/push/key":
                return self._json({"key": pushsvc.public_key(), "status": pushsvc.status()})
            if path == "/api/alerts/mutes":  # saved alert mute rules + how many alerts each has cleared (admin / defender)
                if role == "user":
                    return self._json({"error": "forbidden"}, 403)
                cnt = store.mute_counts()
                return self._json({"mutes": [{**m, "cleared": cnt.get(m["id"], 0)} for m in store.mute_list()]})
            if path == "/api/alerts":
                lim = max(1, min(int((q.get("limit") or ["100"])[0]), 2000))
                ids = watch_ids(user, role)
                if role == "user":  # only their devices' alerts ever leave the server; private read marker
                    upto = auth.read_upto(user)
                    rows = [dict(r, mine=True, read=1 if r["id"] <= upto else 0) for r in store.alerts_recent(2000) if store.alert_for(r, ids)][:lim]
                    n = sum(1 for r in rows if not r["read"])
                    return self._json({"alerts": rows, "unread": n, "unread_mine": n, "mode": "some"})
                if (q.get("cleared") or [""])[0] and role != "user":  # alerts a mute rule cleared (Show cleared)
                    mn = {m["id"]: m for m in store.mute_list()}
                    rows = store.alerts_recent(lim, cleared=True)
                    for r in rows:
                        m = mn.get(r.get("cleared_rule")) or {}
                        r["mine"], r["rule"] = store.alert_for(r, ids), (m.get("name", "") + (" @ " + m["host"] if m.get("host") else "")) if m else "(rule removed)"
                    return self._json({"alerts": rows, "cleared": True})
                rows = store.alerts_recent(lim)
                for r in rows:
                    r["mine"] = store.alert_for(r, ids)
                return self._json({"alerts": rows, "unread": sum(1 for r in rows if not r["read"]),
                                   "unread_mine": sum(1 for r in rows if not r["read"] and r["mine"]),
                                   "mode": "all" if ids is None else "some"})
            if path == "/api/push/prefs":
                if role == "user":
                    return self._json({"prefs": store.prefs_get(user), "devices": assigned_devices(user), "locked": True})
                return self._json({"prefs": store.prefs_get(user), "devices": device_catalog()})
            if path in ("/", "/index.html"):
                path = "/index.html"
            fn = os.path.normpath(os.path.join(STATIC, path.lstrip("/")))
            if fn.startswith(STATIC) and os.path.isfile(fn):
                with open(fn, "rb") as f:
                    ext = os.path.splitext(fn)[1]
                    body = f.read()
                    if path == "/sw.js":  # never cache the service worker; scope = whole site
                        self._extra_headers = [("Service-Worker-Allowed", "/")]
                        return self._send(200, body, MIME[".js"], "no-cache")
                    if ext == ".html":  # stamp asset URLs with the build hash so browsers / Cloudflare never serve stale JS/CSS
                        body = ASSET_RE.sub(lambda m: m.group(0)[:-1] + "?v=" + BUILD + '"', body.decode()).encode()
                        return self._send(200, body, MIME[".html"], "no-store")
                    versioned = "v=" in (u.query or "")
                    return self._send(200, body, MIME.get(ext, "application/octet-stream"),
                                      "public, max-age=31536000, immutable" if versioned else "no-cache")
            return self._send(404, "not found", "text/plain")
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as e:
            print("error", e, file=sys.stderr)
            return self._json({"error": str(e)}, 500)


def main():
    if len(sys.argv) >= 4 and sys.argv[1] == "set-role":
        # recovery: docker exec -it netmon-dashboard python /app/server.py set-role <user> admin|defender|user
        err = auth.set_role(sys.argv[2], sys.argv[3], actor=None)
        audit.action("console", "users.role", outcome="failure" if err else "success", category="iam", target=f"username={sys.argv[2]}; role={sys.argv[3]}",
                     message=f"console (docker exec) set-role {sys.argv[2]} {sys.argv[3]}: {err or 'ok'}")
        audit.flush(drain=False)
        print(err or "ok")
        sys.exit(1 if err else 0)
    if len(sys.argv) >= 3 and sys.argv[1] in ("set-password", "add-user"):
        # recovery: docker exec -it netmon-dashboard python /app/server.py set-password <user>
        #           docker exec -it netmon-dashboard python /app/server.py add-user <user> [admin|defender|user]  (default admin)
        import getpass
        name, pw = sys.argv[2], getpass.getpass(f"new password for {sys.argv[2]}: ")
        role = sys.argv[3] if len(sys.argv) >= 4 else "admin"
        err = auth.add(name, pw, role) if sys.argv[1] == "add-user" or name not in auth.load() else auth.set_password(name, pw)
        audit.action("console", "users.add" if sys.argv[1] == "add-user" else "users.password", outcome="failure" if err else "success", category="iam",
                     target=f"username={name}", message=f"console (docker exec) {sys.argv[1]} {name}: {err or 'ok'}")
        audit.flush(drain=False)
        print(err or "ok")
        sys.exit(1 if err else 0)
    if auth.bootstrap(USER, PASS):
        print(f"seeded users.json with {USER!r} from DASH_USER/DASH_PASS", flush=True)
    mig = auth.migrate_roles()
    if mig:
        print(f"access control: existing accounts made admins: {', '.join(sorted(mig))}", flush=True)
    try:  # audit log writer (Elasticsearch logs-netmon); spools to /state while ES is unreachable
        audit.start()
        print(f"audit log -> {integrations.es_url() or '(no ES URL)'}/{audit.index()} (key {'set' if integrations.audit_key() else 'NOT set - spooling'})", flush=True)
    except Exception as e:  # noqa: BLE001
        print("audit log disabled:", e, flush=True)
    try:
        pushsvc.start()
        print(f"web push enabled ({len(store.push_subs())} subscribers)", flush=True)
    except Exception as e:
        print("web push disabled:", e, flush=True)
    try:  # local-LLM review of correlation candidates (corr_llm.py); no-op when NETMON_LLM=off
        corr_llm.start(correlation, lambda: (snapshots() or [{"id": ""}])[-1]["id"])
        print(f"correlation review: local LLM at {corr_llm.URL} ({'on' if corr_llm.ENABLED else 'off'})", file=sys.stderr)
    except Exception as e:  # noqa: BLE001
        print(f"correlation review disabled: {e}", file=sys.stderr)
    def _ingest():  # backfill the stored events from every snapshot (oldest first), then keep the newest current
        import eventstore
        done = False
        while True:
            try:
                ss = snapshots()
                if not done:
                    for sn in ss:
                        correlation(sn["id"])
                    done = True
                elif ss:
                    correlation(ss[-1]["id"])
            except Exception as e:  # noqa: BLE001
                print(f"eventstore ingest: {e}", file=sys.stderr)
            time.sleep(300)
    threading.Thread(target=_ingest, daemon=True, name="eventstore-ingest").start()
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), H)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(CERT, KEY)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    print(f"netmon dashboard on https://0.0.0.0:{PORT} (data {ROOT}, users={len(auth.load())})",
          flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
