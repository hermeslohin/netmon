#!/usr/bin/env python3
"""netmon host broker: the two things the locked-down dashboard container needs the host for.

The dashboard has no Elasticsearch key and cannot run the collectors. This small loopback-only HTTP service runs on
the host (systemd user unit netmon-broker.service, plain /usr/bin/python3, stdlib only) and offers exactly:

  POST /range     {start, end} (UTC ISO, whole minutes) -> background `collect.py --start --end --out` +
                  `analyze.py --readonly` into dashboard/state/ranges/<id>.json (the dashboard's time range picker).
                  Progress: <id>.status.json.
  POST /esquery   {query, anchor} -> one bounded, read-only Elasticsearch search for the correlation reviewer
                  (es_context.py builds it from a structured request; the model never sends DSL). At most 600 per hour.
  GET  /health

Every request needs "Authorization: Bearer <NETMON_BROKER_KEY>" (dashboard/.env).
"""
import glob, hmac, json, os, subprocess, sys, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

NM = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, NM)
HOST, PORT = "127.0.0.1", int(os.environ.get("NETMON_BROKER_PORT", "8650"))
PY = os.environ.get("NETMON_PYTHON") or "/usr/bin/python3"
ES_RATE = (600, 3600)  # reviewer Elasticsearch look-ups per hour (each one is also capped per event by the dashboard)
_lock, _es_sent = threading.Lock(), []
RANGES = os.path.join(NM, "dashboard", "state", "ranges")
RANGE_MAX_H, RANGE_MAX_AGE_D, RANGE_KEEP = 31 * 24, 120, 30


def _key():
    for line in open(os.path.join(NM, "dashboard", ".env")):
        if line.startswith("NETMON_BROKER_KEY="):
            return line.split("=", 1)[1].strip()
    raise SystemExit("NETMON_BROKER_KEY missing in dashboard/.env")


KEY = _key()


def esquery(b):
    import es_context
    with _lock:
        now = time.time()
        _es_sent[:] = [t for t in _es_sent if now - t < ES_RATE[1]]
        if len(_es_sent) >= ES_RATE[0]:
            raise ValueError("rate limit: too many reviewer Elasticsearch queries this hour")
        _es_sent.append(now)
    t = time.time()
    out = es_context.run(b.get("query"), b.get("anchor"))
    out["seconds"] = round(time.time() - t, 2)
    return out



_range_lock = threading.Lock()
_range_running = {}


def _utc(s):
    import datetime as dt
    t = dt.datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    if not t.tzinfo:
        raise ValueError("start/end need a UTC offset")
    return t.astimezone(dt.timezone.utc).replace(second=0, microsecond=0)


def range_id(s, e):
    return "r" + s.strftime("%Y%m%dT%H%MZ") + "-" + e.strftime("%Y%m%dT%H%MZ")


def _rstatus(rid, **kw):
    p = os.path.join(RANGES, rid + ".status.json")
    cur = {}
    try:
        cur = json.load(open(p))
    except (OSError, ValueError):
        pass
    cur.update(kw, updated=time.time())
    with open(p + ".tmp", "w") as f:
        json.dump(cur, f)
    os.replace(p + ".tmp", p)
    return cur


def _prune():
    files = sorted(glob.glob(os.path.join(RANGES, "r*.json")), key=os.path.getmtime)
    ids = []
    for f in files:
        b = os.path.basename(f).split(".")[0]
        if b not in ids:
            ids.append(b)
    for b in ids[:-RANGE_KEEP]:
        for f in glob.glob(os.path.join(RANGES, b + ".*")):
            os.remove(f)


def _range_job(rid, s, e):
    out = os.path.join(RANGES, rid + ".json")
    t = time.time()
    try:
        _rstatus(rid, status="collecting", started=t, start=s.isoformat(), end=e.isoformat(), step="Querying Security Onion and UniFi")
        p = subprocess.run([PY, os.path.join(NM, "collect.py"), "--start", s.isoformat(), "--end", e.isoformat(), "--out", out],  # noqa: S603 - fixed argv, validated times
                           capture_output=True, text=True, timeout=3600, cwd=NM)
        if p.returncode or not os.path.exists(out):
            raise RuntimeError((p.stderr or p.stdout or "collect failed")[-400:])
        _rstatus(rid, status="analyzing", step="Comparing with the baseline")
        p = subprocess.run([PY, os.path.join(NM, "analyze.py"), out, "--readonly"],  # noqa: S603 - fixed argv
                           capture_output=True, text=True, timeout=900, cwd=NM)
        if p.returncode:
            raise RuntimeError((p.stderr or p.stdout or "analyze failed")[-400:])
        _rstatus(rid, status="done", step="", seconds=round(time.time() - t, 1))
        _prune()
    except Exception as ex:  # noqa: BLE001 - reported to the dashboard through the status file
        print(f"range {rid} failed: {ex}", file=sys.stderr)
        _rstatus(rid, status="failed", error=str(ex)[-400:], seconds=round(time.time() - t, 1))
    finally:
        with _range_lock:
            _range_running.pop(rid, None)


def range_start(b):
    import datetime as dt
    s, e = _utc(b.get("start")), _utc(b.get("end"))
    now = dt.datetime.now(dt.timezone.utc).replace(second=0, microsecond=0)
    e = min(e, now)
    if e <= s:
        raise ValueError("the end must be after the start (and not in the future)")
    if (e - s).total_seconds() < 15 * 60:
        raise ValueError("the range must be at least 15 minutes")
    if (e - s).total_seconds() > RANGE_MAX_H * 3600:
        raise ValueError(f"the range can be at most {RANGE_MAX_H // 24} days")
    if (now - s).days > RANGE_MAX_AGE_D:
        raise ValueError(f"the start can be at most {RANGE_MAX_AGE_D} days ago")
    os.makedirs(RANGES, exist_ok=True)
    rid = range_id(s, e)
    if os.path.exists(os.path.join(RANGES, rid + ".analysis.json")):
        return {"id": rid, "status": "done"}
    with _range_lock:
        if rid in _range_running:
            return {"id": rid, "status": "running"}
        if _range_running:
            raise ValueError("another time range is being collected - try again in a minute")
        _range_running[rid] = time.time()
    _rstatus(rid, status="queued", start=s.isoformat(), end=e.isoformat(), error="")
    threading.Thread(target=_range_job, args=(rid, s, e), daemon=True).start()
    return {"id": rid, "status": "running"}


class H(BaseHTTPRequestHandler):
    def log_message(self, fmt, *a):
        print("broker:", fmt % a, file=sys.stderr)

    def _send(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def _auth(self):
        h = self.headers.get("Authorization", "")
        return hmac.compare_digest(h.encode(), f"Bearer {KEY}".encode())

    def do_GET(self):
        if not self._auth():
            return self._send(401, {"error": "unauthorized"})
        if self.path == "/health":
            return self._send(200, {"ok": True})
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        if not self._auth():
            return self._send(401, {"error": "unauthorized"})
        try:
            n = int(self.headers.get("Content-Length") or 0)
            if n > 200_000:
                return self._send(413, {"error": "too large"})
            b = json.loads(self.rfile.read(n) or b"{}")
            if self.path == "/range":
                return self._send(200, range_start(b))
            if self.path == "/esquery":
                return self._send(200, esquery(b))
            return self._send(404, {"error": "not found"})
        except ValueError as e:
            return self._send(400, {"error": str(e)[:300]})
        except Exception as e:  # noqa: BLE001
            return self._send(502, {"error": f"{type(e).__name__}: {str(e)[:300]}"})


if __name__ == "__main__":
    print(f"netmon host broker on http://{HOST}:{PORT}", file=sys.stderr)
    ThreadingHTTPServer((HOST, PORT), H).serve_forever()
