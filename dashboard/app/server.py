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
import auth
import tintel
import chat
import kb
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
             "/api/alerts/read"}
ADMIN_POST = ("/api/users", "/api/config/", "/api/llm/config", "/api/aireview/compare", "/api/compare/item", "/api/compare/adopt")


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
    return {"snapshot": sid, "devices": assigned_devices(user), "events": out}
LLM_PROVIDERS = ("lmstudio", "anthropic")


def llm_models():
    """Models the AI review page may choose: from the host broker (Anthropic + LM Studio), else LM Studio only."""
    try:
        return corr_llm.broker("/models", timeout=15)
    except Exception as e:  # noqa: BLE001 - broker down: local models still work
        try:
            d = corr_llm._get(corr_llm.URL.replace("/v1", "/api/v0") + "/models", timeout=5)
            loc = [{"id": m["id"], "loaded": m.get("state") == "loaded"} for m in d.get("data", []) if m.get("type") in ("llm", "vlm")]
        except Exception:  # noqa: BLE001
            loc = []
        return {"anthropic": [], "local": loc, "error": f"LLM broker unavailable: {str(e)[:160]}"}


def llm_allowed(provider, model, M=None):
    M = M or llm_models()
    return (provider == "anthropic" and model in {m["id"] for m in M.get("anthropic", [])}) or \
        (provider == "lmstudio" and model in {m["id"] for m in M.get("local", [])})
DATA = os.path.join(ROOT, "data")
BASE = os.path.join(ROOT, "baseline")
STATE = os.environ.get("STATE_DIR", "/state")
ACKS = os.path.join(STATE, "acks.json")  # legacy; check-offs now live in the SQLite store
os.environ.setdefault("NETMON_DB", os.path.join(STATE, "netmon.db"))
if ROOT not in sys.path:
    sys.path.append(ROOT)
import store  # noqa: E402  /netmon/store.py, DB on the writable /state volume
import pushsvc  # noqa: E402  web push for urgent alerts
import site_cfg as SITE  # noqa: E402  network-specific values (/netmon/site.json, git-ignored)
os.environ.setdefault("NETMON_INTEGRATIONS", os.path.join(STATE, "integrations.json"))  # writable /state, 0600
os.environ["NETMON_IN_DASHBOARD"] = "1"
import integrations  # noqa: E402  /netmon/integrations.py: Elasticsearch + UniFi settings (More > Configuration)
SELF_IP, SELF_HOST = SITE.get("self_ip") or "", SITE.get("self_host") or "netmon-host"
REPORTS = os.environ.get("REPORTS_DIR", "/reports")  # nightly PDFs (read-only mount of ~/network_reports)
REPORT_RE = re.compile(r"^network-report-(\d{4}-\d{2}-\d{2}T\d{4}Z)\.pdf$")


def report_list():
    out = []
    try:
        names = os.listdir(REPORTS)
    except OSError:
        return out
    for n in names:
        m = REPORT_RE.match(n)
        if m:
            st = os.stat(os.path.join(REPORTS, n))
            out.append({"name": n, "stamp": m.group(1), "size": st.st_size, "mtime": int(st.st_mtime),
                        "has_snapshot": os.path.exists(os.path.join(DATA, m.group(1) + ".json"))})
    return sorted(out, key=lambda r: r["stamp"], reverse=True)
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
COMPANIONS = ("analysis", "triage", "briefing", "sources")

_cache = {}


def load_json(path, default=None):
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
    for p in sorted(glob.glob(os.path.join(DATA, "*.json"))):
        sid = os.path.basename(p)[:-5]
        if not SNAP_RE.match(sid):
            continue
        out.append({"id": sid,
                    "has": [c for c in COMPANIONS
                            if os.path.exists(os.path.join(DATA, f"{sid}.{c}.json"))]})
    return out


def snapshot(sid):
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


def with_cleared(pol):
    """policy + the set of segmentation flows people have cleared (ack type "seg"); see risk.seg_key."""
    try:
        pol = dict(pol or {}); pol["_cleared_seg"] = set((store.acks_load().get("seg") or {}).keys())
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


def correlation(sid):
    """Related-events map for a snapshot (correlate.py). Cached until the snapshot, its alerts or the issues change."""
    res = snapshot(sid)
    if not res:
        return None
    alerts = store.alerts_recent(2000)
    it = issue_tracker()
    _clr = with_cleared({}).get("_cleared_seg") or set()
    open_iss = [i for i in it.get("open", []) if (i.get("status", "open") == "open" or str(i.get("status", "")).startswith("open"))
                and risk.seg_key_issue(i["key"]) not in _clr]
    ck = (sid, alerts[0]["id"] if alerts else 0, len(open_iss), len(acks_load_all()))
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
    v = correlate.build(res["raw"], res["analysis"], alerts, open_iss, lateral.admin_sessions(res["raw"], pol),
                        SITE.is_internal, lateral._resolver(res["raw"]), tech, latest=bool(snapshots()) and snapshots()[-1]["id"] == sid,
                        cleared=pol.get("_cleared_seg") or set())
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


_review_cache = {}


def review_job():
    """The review (research) cron job's schedule, from the host broker; cached 60 s."""
    if _review_cache.get("t", 0) > time.time() - 60:
        return _review_cache["v"]
    try:
        v = corr_llm.broker("/research", timeout=10)
    except Exception as e:  # noqa: BLE001 - broker down: page still works, schedule just isn't shown
        v = {"error": f"LLM broker unavailable: {str(e)[:160]}"}
    _review_cache.update(t=time.time(), v=v)
    return v


def acks_load_all():
    try:
        return store.acks_load()
    except Exception:  # noqa: BLE001
        return {}


def issue_tracker():
    snaps = snapshots()
    sig = tuple((s["id"], os.path.getmtime(os.path.join(DATA, s["id"] + ".json"))) for s in snaps)
    if _issues["sig"] != sig:
        rows = []
        for s in snaps:
            raw = load_json(os.path.join(DATA, s["id"] + ".json"))
            if raw:
                rows.append((s["id"], raw.get("generated"), raw,
                             load_json(os.path.join(DATA, s["id"] + ".analysis.json"))))
        _issues["val"], _issues["sig"] = issues.track(rows), sig
    return with_software_vulns(_issues["val"])


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


MIME = {".html": "text/html; charset=utf-8", ".js": "application/javascript",
        ".css": "text/css", ".svg": "image/svg+xml", ".ico": "image/x-icon",
        ".png": "image/png", ".json": "application/manifest+json"}


class H(BaseHTTPRequestHandler):
    server_version = "netmon"
    sys_version = ""  # don't advertise the Python version

    def log_message(self, fmt, *a):
        sys.stderr.write("%s %s\n" % (self.address_string(), fmt % a))

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
        """Relay one Hermes turn to the browser as server-sent events (text/event-stream)."""
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
            if m["provider"] in LLM_PROVIDERS and llm_allowed(m["provider"], m["model"]):
                chat_model = m
        print(f"chat: {user} -> {cid} ({len(text)} chars){' model ' + chat_model['model'] if chat_model else ''}", file=sys.stderr)
        try:
            emit("start", {})
            chat.stream(user, cid, text, emit, body.get("context"), chat_model)
        except (BrokenPipeError, ConnectionResetError):
            print(f"chat: {user} disconnected mid-answer", file=sys.stderr)
        except Exception as e:  # Hermes down / timeout: tell the browser, keep the server alive
            print(f"chat error for {user}: {e.__class__.__name__}: {e}", file=sys.stderr)
            try:
                emit("end", {"status": "failed", "error": "The assistant is unavailable right now. Try again in a minute."})
            except OSError:
                pass

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
        u = urlparse(self.path)
        # CSRF guard: browsers can't send this header cross-site without a CORS preflight we never approve
        if self.headers.get("X-Netmon") != "1" or "application/json" not in self.headers.get("Content-Type", ""):
            return self._json({"error": "bad request"}, 400)
        try:
            n = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(min(n, 65536)) or b"{}")
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
            if u.path in ("/api/config/triage", "/api/config/triage/reopen", "/api/config/triage/run", "/api/config/review-schedule"):
                if u.path == "/api/config/review-schedule":
                    try:
                        r = corr_llm.broker("/research/schedule", {"hours": body.get("hours"), "minutes": body.get("minutes")}, timeout=90)
                    except Exception as e:  # noqa: BLE001
                        return self._json({"error": f"could not change the review job schedule: {str(e)[:200]}"}, 502)
                    print(f"review schedule: {user} -> {body.get('hours')}h {body.get('minutes')}m ({r.get('schedule')})", file=sys.stderr)
                    _review_cache.clear()
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
            if u.path == "/api/llm/config":  # choose the correlation reviewer or the research job's model
                sec, prov, model = str(body.get("section", "")), str(body.get("provider", "")), str(body.get("model", ""))[:120]
                if sec not in ("correlation", "research") or prov not in LLM_PROVIDERS or not llm_allowed(prov, model):
                    return self._json({"error": "unknown section, provider or model"}, 400)
                if sec == "correlation":
                    corr_llm.set_correlation(prov, model, user)
                    res = corr_llm.config()["correlation"]
                else:
                    try:
                        res = corr_llm.broker("/research", {"provider": prov, "model": model}, timeout=90)
                    except Exception as e:  # noqa: BLE001
                        return self._json({"error": str(e)[:300]}, 502)
                print(f"llm config: {user} set {sec} -> {prov}/{model}", file=sys.stderr)
                return self._json({"ok": True, sec: res})
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
            if u.path == "/api/kb/host":  # host/device notes (AI-written knowledge; people may add or delete)
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
                return self._json({"error": "action must be add or delete"}, 400)
            if u.path == "/api/kb/event":  # people's notes on an event (📝); the AI reads them as guidance
                act = body.get("action")
                if act == "add":
                    nid = kb.add_event_note(body.get("eid"), body.get("text"), user, body.get("label"))
                    print(f"kb: {user} added event note {nid} on {str(body.get('eid'))[:80]!r}", file=sys.stderr)
                    return self._json({"ok": True, "id": nid, "notes": kb.event_notes([str(body.get("eid"))]).get(str(body.get("eid")), [])})
                if act == "delete":
                    n = kb.delete_event_note(body.get("id"))
                    print(f"kb: {user} deleted event note {body.get('id')!r}", file=sys.stderr)
                    return self._json({"ok": bool(n), "notes": kb.event_notes([str(body.get("eid") or "")]).get(str(body.get("eid") or ""), [])})
                return self._json({"error": "action must be add or delete"}, 400)
            if u.path == "/api/alerts/read":
                if role == "user":  # private read marker: a user must not clear the shared 🔔 for everyone else
                    ids = watch_ids(user, role)
                    mine = [r["id"] for r in store.alerts_recent(2000) if store.alert_for(r, ids)]
                    auth.set_read_upto(user, max(mine or [0]))
                    return self._json({"ok": True})
                store.alerts_read_all()
                return self._json({"ok": True})
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
        if role == "user" and (path.startswith("/api/") or path.startswith("/reports/")) and path not in USER_GET:
            return self._json({"error": "your account can only view the alerts for its assigned devices"}, 403)
        admin = role == "admin"
        try:
            if path == "/api/me":
                return self._json({"user": user, "role": role, "role_name": auth.ROLE_NAMES.get(role, role)})
            if path == "/api/my":
                return self._json(my_events(user))
            if path == "/api/reports":
                return self._json({"reports": report_list()})
            if path.startswith("/reports/"):
                name = path[len("/reports/"):]
                if not REPORT_RE.match(name):  # strict whitelist: no paths, no traversal
                    return self._send(404, "not found", "text/plain")
                fn = os.path.join(REPORTS, name)
                if not os.path.isfile(fn):
                    return self._send(404, "not found", "text/plain")
                with open(fn, "rb") as f:
                    body = f.read()
                inline = (q.get("view") or ["0"])[0] == "1"
                self._extra_headers = [("Content-Disposition", f'{"inline" if inline else "attachment"}; filename="{name}"')]
                print(f"report download: {user} {name} ({'view' if inline else 'download'})", file=sys.stderr)
                return self._send(200, body, "application/pdf", "private, no-store")
            if path == "/api/site":
                return self._json({"site_name": SITE.public().get("site_name")} if role == "user" else SITE.public())
            if path == "/api/account":
                return self._json(auth.account_info(user))
            if path == "/api/users":
                ul = auth.public_list()
                return self._json({"users": ul, "me": user, "min_password": auth.MIN_PW,
                                   "prefs": {x["username"]: store.prefs_get(x["username"]) for x in ul}, "devices": device_catalog()})
            if path == "/api/snapshots":
                return self._json(snapshots())
            if path == "/api/snapshot":
                sid = (q.get("id") or [""])[0]
                if sid == "latest":
                    s = snapshots()
                    sid = s[-1]["id"] if s else ""
                res = snapshot(sid)
                return self._json(res) if res else self._json({"error": "not found"}, 404)
            if path == "/api/acks":
                return self._json(read_acks())
            if path == "/api/config/integrations":
                if not admin:
                    return self._json({"admin": False})
                return self._json({**integrations.public(), "admin": True})
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
                res = snapshot(sid)
                if not res:
                    return self._json({"error": "not found"}, 404)
                pol = with_cleared(load_json(os.path.join(ROOT, "policy.json"), {}))
                kbn = load_json(os.path.join(ROOT, "known_benign.json"), {})
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
            if path == "/api/aireview":
                s_ = snapshots()
                sid = s_[-1]["id"] if s_ else ""
                base = correlation(sid) or {}
                ov = {**corr_llm.overview(base.get("events") or {}, corr_llm.apply(base)), "snapshot": sid, "admin": admin}
                try:
                    ov["research"] = corr_llm.broker("/research", timeout=10)
                except Exception as e:  # noqa: BLE001
                    ov["research"] = {"error": str(e)[:200]}
                try:
                    ov["claude"] = enrich.status((base.get("events") or {}).keys())
                except Exception as e:  # noqa: BLE001 - the local-LLM view must not depend on the Claude status
                    ov["claude"] = {"error": str(e)[:200]}
                return self._json(ov)
            if path == "/api/correlate":
                sid = (q.get("id") or ["latest"])[0]
                if sid == "latest":
                    s_ = snapshots()
                    sid = s_[-1]["id"] if s_ else ""
                corr_llm.want(sid)  # the LLM reviewer also covers snapshots people are looking at
                return self._json(kb.apply(enrich.apply(corr_llm.apply(correlation(sid)))) or {"error": "not found"}, 200)
            if path == "/api/kb/host":  # notes for one device / endpoint: ?s=mac:..,ip:..,host:..
                subs = [s.strip() for s in (q.get("s") or [""])[0].split(",") if s.strip()][:20]
                return self._json({"notes": kb.host_notes(subs)})
            if path == "/api/kb/resolve":  # canonical subject for ?ip= / ?mac= / ?host=
                try:
                    s_, label = kb.resolve(ip=(q.get("ip") or [None])[0], mac=(q.get("mac") or [None])[0], host=(q.get("host") or [None])[0])
                except ValueError as e:
                    return self._json({"error": str(e)}, 400)
                return self._json({"subject": s_, "label": label})
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
            if path == "/api/alerts":
                lim = max(1, min(int((q.get("limit") or ["100"])[0]), 2000))
                ids = watch_ids(user, role)
                if role == "user":  # only their devices' alerts ever leave the server; private read marker
                    upto = auth.read_upto(user)
                    rows = [dict(r, mine=True, read=1 if r["id"] <= upto else 0) for r in store.alerts_recent(2000) if store.alert_for(r, ids)][:lim]
                    n = sum(1 for r in rows if not r["read"])
                    return self._json({"alerts": rows, "unread": n, "unread_mine": n, "mode": "some"})
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
        print(err or "ok")
        sys.exit(1 if err else 0)
    if len(sys.argv) >= 3 and sys.argv[1] in ("set-password", "add-user"):
        # recovery: docker exec -it netmon-dashboard python /app/server.py set-password <user>
        #           docker exec -it netmon-dashboard python /app/server.py add-user <user> [admin|defender|user]  (default admin)
        import getpass
        name, pw = sys.argv[2], getpass.getpass(f"new password for {sys.argv[2]}: ")
        role = sys.argv[3] if len(sys.argv) >= 4 else "admin"
        err = auth.add(name, pw, role) if sys.argv[1] == "add-user" or name not in auth.load() else auth.set_password(name, pw)
        print(err or "ok")
        sys.exit(1 if err else 0)
    if auth.bootstrap(USER, PASS):
        print(f"seeded users.json with {USER!r} from DASH_USER/DASH_PASS", flush=True)
    mig = auth.migrate_roles()
    if mig:
        print(f"access control: existing accounts made admins: {', '.join(sorted(mig))}", flush=True)
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
