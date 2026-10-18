"""User store + signed session cookies for the netmon dashboard (stdlib only).

users.json : {username: {"hash": "scrypt$n$r$p$salt$dk", "gen": int, "role": "admin"|"defender"|"user",
                          "created": iso, "last_login": iso, "pw_changed": iso}}
Roles (docs/ACCESS_CONTROL.md): admin = everything; defender = sees everything, changes no settings;
user = sees only alerts/events for the devices an admin assigned to them. Records without a role (accounts
created before roles existed) are migrated to "admin" once at startup by migrate_roles().
secret.key : random HMAC key for session cookies
Session cookie value = base64(user) . expiry . gen . hmac   (stateless; survives restarts)
`gen` is bumped on password change / delete, which invalidates that user's existing sessions.
"""
import base64, hashlib, hmac, json, os, re, secrets, threading, time

STATE = os.environ.get("STATE_DIR", "/state")
USERS = os.path.join(STATE, "users.json")
SECRET = os.path.join(STATE, "secret.key")
SESSION_TTL = int(os.environ.get("SESSION_HOURS", "12")) * 3600
MIN_PW = 10
NAME_RE = re.compile(r"^[A-Za-z0-9._@-]{2,40}$")
ROLES = ("admin", "defender", "user")
ROLE_NAMES = {"admin": "Admin", "defender": "Network defender", "user": "User"}
_lock = threading.Lock()
_fail = {}  # client ip -> [timestamps]
_ufail = {}  # username -> [(timestamp, client ip)]
IP_MAX, IP_WIN = 8, 300          # per real client IP: 8 failures / 5 min
USER_MAX, USER_WIN = 20, 900     # per username from the Internet: 20 failures / 15 min (LAN clients are exempt)


def _now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _secret():
    try:
        with open(SECRET, "rb") as f:
            k = f.read()
            if len(k) >= 32:
                return k
    except OSError:
        pass
    k = secrets.token_bytes(32)
    with open(SECRET, "wb") as f:
        f.write(k)
    os.chmod(SECRET, 0o600)
    return k


def _hash(pw, salt=None, n=2 ** 14, r=8, p=1):
    salt = salt or secrets.token_bytes(16)
    dk = hashlib.scrypt(pw.encode(), salt=salt, n=n, r=r, p=p, maxmem=64 * 1024 * 1024, dklen=32)
    return f"scrypt${n}${r}${p}${salt.hex()}${dk.hex()}"


def _verify(pw, stored):
    try:
        _, n, r, p, salt, dk = stored.split("$")
        return hmac.compare_digest(_hash(pw, bytes.fromhex(salt), int(n), int(r), int(p)).split("$")[-1], dk)
    except Exception:
        return False


def load():
    try:
        with open(USERS) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def _save(u):
    tmp = USERS + ".tmp"
    with open(tmp, "w") as f:
        json.dump(u, f, indent=1)
    os.chmod(tmp, 0o600)
    os.replace(tmp, USERS)


def bootstrap(env_user, env_pass):
    """First start: seed users.json from DASH_USER/DASH_PASS. Afterwards env vars are ignored."""
    with _lock:
        if load() or not env_user or not env_pass:
            return False
        _save({env_user: {"hash": _hash(env_pass), "gen": 1, "role": "admin", "created": _now(), "pw_changed": _now(), "last_login": None}})
        return True


def migrate_roles():
    """One-time upgrade: accounts that predate roles keep the full access they had, i.e. become admins.
    Returns the names migrated."""
    with _lock:
        u = load()
        todo = [k for k, v in u.items() if v.get("role") not in ROLES]
        for k in todo:
            u[k]["role"] = "admin"
        if todo:
            _save(u)
        return todo


def role_of(username):
    """The user's role; unknown users / damaged records get the least privilege."""
    r = (load().get(username) or {}).get("role")
    return r if r in ROLES else "user"


def set_role(username, role, actor):
    if role not in ROLES:
        return "role must be admin, defender or user"
    with _lock:
        u = load()
        if username not in u:
            return "no such user"
        if u[username].get("role") == "admin" and role != "admin" and \
                sum(1 for v in u.values() if v.get("role") == "admin") <= 1:
            return "can't remove the last admin"
        if username == actor and role != "admin":
            return "you can't take admin away from yourself - ask another admin"
        u[username]["role"] = role  # read on every request, so it takes effect immediately (no sign-out needed)
        _save(u)


def read_upto(username):
    """User-role accounts keep a private "read up to alert id" marker instead of the shared read flag."""
    return int((load().get(username) or {}).get("read_upto") or 0)


def set_read_upto(username, alert_id):
    with _lock:
        u = load()
        if username in u and int(alert_id) > int(u[username].get("read_upto") or 0):
            u[username]["read_upto"] = int(alert_id)
            _save(u)


def public_list():
    return [{"username": k, "role": v.get("role") if v.get("role") in ROLES else "user", "created": v.get("created"),
             "last_login": v.get("last_login"), "pw_changed": v.get("pw_changed")}
            for k, v in sorted(load().items())]


def check_password_rules(pw):
    if len(pw) < MIN_PW:
        return f"password must be at least {MIN_PW} characters"
    return None


def add(username, pw, role="user"):
    if role not in ROLES:
        return "role must be admin, defender or user"
    if not NAME_RE.match(username or ""):
        return "username: 2-40 chars, letters/digits/._@-"
    err = check_password_rules(pw or "")
    if err:
        return err
    with _lock:
        u = load()
        if username in u:
            return "user already exists"
        u[username] = {"hash": _hash(pw), "gen": 1, "role": role, "created": _now(), "pw_changed": _now(), "last_login": None}
        _save(u)


def delete(username, actor):
    with _lock:
        u = load()
        if username not in u:
            return "no such user"
        if username == actor:
            return "you can't delete the account you're logged in with"
        if len(u) <= 1:
            return "can't delete the last user"
        if u[username].get("role") == "admin" and sum(1 for v in u.values() if v.get("role") == "admin") <= 1:
            return "can't delete the last admin"
        del u[username]
        _save(u)


def set_password(username, pw, actor=None, current=None):
    err = check_password_rules(pw or "")
    if err:
        return err
    with _lock:
        u = load()
        if username not in u:
            return "no such user"
        if actor == username and not _verify(current or "", u[username]["hash"]):
            return "current password is wrong"
        u[username]["hash"] = _hash(pw)
        u[username]["gen"] = u[username].get("gen", 1) + 1  # logs out that user's other sessions
        u[username]["pw_changed"] = _now()
        _save(u)


def change_own_password(username, current, new, ip):
    """Self-service change. Returns (new_cookie, None) or (None, error). Wrong current passwords count toward the
    same per-IP throttle as failed logins; other sessions of this user are signed out (gen bump), this one is re-issued."""
    if throttled(ip):
        return None, "too many failed attempts - wait 5 minutes"
    u = load()
    rec = u.get(username)
    if not rec:
        return None, "no such user"
    if not _verify(current or "", rec["hash"]):
        _fail.setdefault(ip, []).append(time.time())
        return None, "current password is wrong"
    if new == current:
        return None, "the new password must be different from the current one"
    if username.lower() in (new or "").lower():
        return None, "the password must not contain your username"
    err = check_password_rules(new or "")
    if err:
        return None, err
    with _lock:
        u = load()
        u[username]["hash"] = _hash(new)
        u[username]["gen"] = u[username].get("gen", 1) + 1
        u[username]["pw_changed"] = _now()
        _save(u)
        gen = u[username]["gen"]
    return make_cookie(username, gen), None


def account_info(username):
    v = load().get(username) or {}
    return {"user": username, "role": role_of(username), "created": v.get("created"), "last_login": v.get("last_login"), "pw_changed": v.get("pw_changed"),
            "min_password": MIN_PW}


def _private(ip):
    import ipaddress
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_loopback
    except ValueError:
        return False


def throttled(ip):
    t = time.time()
    _fail[ip] = [x for x in _fail.get(ip, []) if t - x < IP_WIN]
    return len(_fail[ip]) >= IP_MAX


def user_throttled(username, ip):
    """Distributed guessing against one account. LAN clients are never locked out by Internet failures."""
    if _private(ip):
        return False
    t = time.time()
    _ufail[username] = [x for x in _ufail.get(username, []) if t - x[0] < USER_WIN]
    return sum(1 for _, src in _ufail[username] if not _private(src)) >= USER_MAX


def login(username, pw, ip):
    """Returns cookie value or None. ip = the real client address (Cloudflare-forwarded when via the tunnel)."""
    if throttled(ip):
        return None, "too many failed attempts - wait 5 minutes"
    if user_throttled(username, ip):
        return None, "this account is temporarily locked for remote sign-in - wait 15 minutes or sign in from the home network"
    u = load()
    rec = u.get(username)
    # always run a hash so timing doesn't reveal whether the user exists
    ok = _verify(pw or "", rec["hash"]) if rec else (_hash(pw or "x") and False)
    if not ok:
        _fail.setdefault(ip, []).append(time.time())
        if username:
            _ufail.setdefault(username[:64], []).append((time.time(), ip))
        return None, "invalid username or password"
    _fail.pop(ip, None)
    with _lock:
        u = load()
        if username in u:
            u[username]["last_login"] = _now()
            _save(u)
    return make_cookie(username, rec.get("gen", 1)), None


def make_cookie(username, gen):
    exp = int(time.time()) + SESSION_TTL
    body = f"{base64.urlsafe_b64encode(username.encode()).decode()}.{exp}.{gen}"
    sig = hmac.new(_secret(), body.encode(), hashlib.sha256).hexdigest()
    return f"{body}.{sig}"


def session_user(cookie_value):
    try:
        b64, exp, gen, sig = cookie_value.split(".")
        body = f"{b64}.{exp}.{gen}"
        if not hmac.compare_digest(sig, hmac.new(_secret(), body.encode(), hashlib.sha256).hexdigest()):
            return None
        if int(exp) < time.time():
            return None
        user = base64.urlsafe_b64decode(b64.encode()).decode()
        rec = load().get(user)
        if not rec or rec.get("gen", 1) != int(gen):
            return None
        return user
    except Exception:
        return None
