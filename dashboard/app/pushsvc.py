"""Web Push for urgent netmon alerts.

The 15-min watcher (watch.py, on the host) writes fresh alerts to the SQLite `alerts` table. A background thread here
picks up rows with pushed=0 and sends them as Web Push notifications (VAPID, RFC 8030/8291/8292) to every browser that
enabled notifications in the dashboard. VAPID key pair is generated once into /state/vapid_private.pem.
"""
import base64, json, os, sys, threading, time

import store
import auth  # roles: a User only gets pushes for assigned devices

STATE = os.environ.get("STATE_DIR", "/state")
KEYFILE = os.path.join(STATE, "vapid_private.pem")
import site_cfg as SITE  # noqa: E402  (server.py puts /netmon on sys.path before importing us)
SUB = os.environ.get("DASH_VAPID_SUB") or SITE.get("vapid_contact")
INTERVAL = int(os.environ.get("DASH_PUSH_INTERVAL", 20))
_status = {"last_run": None, "last_error": None, "sent": 0}


def _b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def ensure_keys():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    if not os.path.exists(KEYFILE):
        k = ec.generate_private_key(ec.SECP256R1())
        pem = k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        fd = os.open(KEYFILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(pem)
    k = serialization.load_pem_private_key(open(KEYFILE, "rb").read(), None)
    return k


def public_key():
    """applicationServerKey for PushManager.subscribe: uncompressed P-256 point, base64url."""
    from cryptography.hazmat.primitives import serialization
    pub = ensure_keys().public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    return _b64u(pub)


def send(sub, payload, ttl=3600, urgency="high"):
    from pywebpush import webpush, WebPushException
    try:
        webpush({"endpoint": sub["endpoint"], "keys": sub["keys"]}, json.dumps(payload), vapid_private_key=KEYFILE,
                vapid_claims={"sub": SUB}, ttl=ttl, headers={"Urgency": urgency}, timeout=15)
        store.push_sub_result(sub["endpoint"], True)
        return True, ""
    except WebPushException as e:
        code = getattr(e.response, "status_code", None)
        if code in (404, 410):  # subscription expired / unsubscribed
            store.push_sub_delete(sub["endpoint"])
        else:
            store.push_sub_result(sub["endpoint"], False)
        return False, f"{code}: {str(e)[:200]}"
    except Exception as e:
        store.push_sub_result(sub["endpoint"], False)
        return False, f"{type(e).__name__}: {str(e)[:200]}"


def payload_for(rows):
    if len(rows) == 1:
        r = rows[0]
        return {"title": "netmon: " + ("ALERT" if r["severity"] == "investigate" else "urgent"), "body": r["text"][:400],
                "tag": "netmon-" + str(r["id"]), "url": "/#/reports" if r.get("source") == "report" else "/#/alerts",
                "severity": r["severity"]}
    inv = sum(1 for r in rows if r["severity"] == "investigate")
    body = "\n".join("• " + r["text"][:140] for r in rows[:4]) + (f"\n…and {len(rows) - 4} more" if len(rows) > 4 else "")
    return {"title": f"netmon: {len(rows)} urgent alerts" + (f" ({inv} investigate)" if inv else ""), "body": body,
            "tag": "netmon-batch-" + str(rows[-1]["id"]), "url": "/#/alerts", "severity": "investigate" if inv else "urgent"}


def run_once():
    rows = store.alerts_unpushed()
    if not rows:
        return 0
    subs = store.push_subs()
    reg = store.registry_load() if subs else {}
    wanted = {}  # user -> identifier set (None = all devices)
    for s in subs:
        u = s.get("user") or ""
        if u not in wanted:
            wanted[u] = store.watch_ids(u, reg=reg)
            if wanted[u] is None and auth.role_of(u) == "user":
                wanted[u] = set()  # a User only ever gets alerts for the devices assigned to them
        mine = [r for r in rows if store.alert_for(r, wanted[u])]
        if not mine:
            continue  # nothing about this user's devices
        p = payload_for(mine)
        ok, err = send(s, p)
        if ok:
            _status["sent"] += 1
        else:
            _status["last_error"] = err
            print(f"push to {s['endpoint'][:60]}… failed: {err}", file=sys.stderr, flush=True)
    store.alerts_mark([r["id"] for r in rows], "pushed")  # mark even with no subscribers: no flood on first subscribe
    return len(rows)


def _loop():
    while True:
        try:
            run_once()
            _status["last_run"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        except Exception as e:
            _status["last_error"] = f"{type(e).__name__}: {e}"
            print("push loop error:", e, file=sys.stderr, flush=True)
        time.sleep(INTERVAL)


def start():
    ensure_keys()
    threading.Thread(target=_loop, name="webpush", daemon=True).start()


def status():
    return dict(_status, subscribers=len(store.push_subs()), interval_s=INTERVAL)
