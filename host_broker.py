#!/usr/bin/env python3
"""netmon host broker: the two things the locked-down dashboard container needs the host for.

The dashboard has no Elasticsearch key and cannot run the collectors. This small loopback-only HTTP service runs on
the host (systemd user unit netmon-broker.service, plain /usr/bin/python3, stdlib only) and offers exactly:

  POST /range     {start, end} (UTC ISO, whole minutes) -> background `collect.py --start --end --out` +
                  `analyze.py --readonly` into dashboard/state/ranges/<id>.json (the dashboard's time range picker).
                  Progress: <id>.status.json.
  POST /section   {id, name} -> one section of a time range (collect.py --section: queries Elasticsearch/UniFi cache directly, a
                  second or two each) into dashboard/state/ranges/<id>.sec.<name>.json; name "analysis" assembles every
                  section into <id>.json and runs analyze.py --readonly. The page loads sections one by one.
  POST /section {name: "lateral"} -> the lateral-movement report's data for a period (internal flows, admin sessions, violations).
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
            try:
                os.remove(f)
            except FileNotFoundError:  # a parallel request pruned it first
                pass


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
    # sections are collected on demand (POST /section) as the page asks for them: just record the window
    meta = {"id": rid, "start": s.isoformat(), "end": e.isoformat(), "generated": e.isoformat(),
            "hours": round((e - s).total_seconds() / 3600, 3)}
    mp = os.path.join(RANGES, rid + ".meta.json")
    with open(mp + ".tmp", "w") as f:
        json.dump(meta, f)
    os.replace(mp + ".tmp", mp)
    _rstatus(rid, status="sections", start=s.isoformat(), end=e.isoformat(), error="")
    _prune()
    return {"id": rid, "status": "sections"}


SECTIONS = ["unifi", "totals", "devices", "alerts", "detections", "notices", "dns_tunnel", "threat_intel", "beacons", "internal",
            "admin_access", "iot_dest", "files", "tls", "hosts", "mitre_ids"]
_sec_sem = threading.Semaphore(3)
_sec_locks, _sec_locks_guard = {}, threading.Lock()


def _sec_path(rid, name):
    return os.path.join(RANGES, f"{rid}.sec.{name}.json")


def _run_section(rid, name):
    out = _sec_path(rid, name)
    if os.path.exists(out):
        return
    meta = json.load(open(os.path.join(RANGES, rid + ".meta.json")))
    with _sec_sem:
        p = subprocess.run([PY, os.path.join(NM, "collect.py"), "--start", meta["start"], "--end", meta["end"], "--section", name, "--out", out],  # noqa: S603 - fixed argv, validated names/times
                           capture_output=True, text=True, timeout=900, cwd=NM)
    if p.returncode or not os.path.exists(out):
        raise RuntimeError(f"{name}: " + (p.stderr or p.stdout or "collect failed")[-300:])


def section(b):
    import re
    rid, name = str(b.get("id") or ""), str(b.get("name") or "")
    if not re.match(r"^r\d{8}T\d{4}Z-\d{8}T\d{4}Z$", rid) or not os.path.exists(os.path.join(RANGES, rid + ".meta.json")):
        raise ValueError("unknown time range")
    if name != "analysis" and name != "lateral" and name not in SECTIONS:
        raise ValueError("unknown section")
    with _sec_locks_guard:
        lk = _sec_locks.setdefault((rid, name), threading.Lock())
    t = time.time()
    with lk:  # two requests for the same piece share one run
        if name != "analysis":
            _run_section(rid, name)
        elif not os.path.exists(os.path.join(RANGES, rid + ".analysis.json")):
            meta = json.load(open(os.path.join(RANGES, rid + ".meta.json")))
            raw = {"generated": meta["generated"], "hours": meta["hours"], "range": {"start": meta["start"], "end": meta["end"]}}
            for n in SECTIONS:
                _run_section(rid, n)  # normally all done already; computes any the page has not asked for yet
                raw.update(json.load(open(_sec_path(rid, n))))
            out = os.path.join(RANGES, rid + ".json")
            with open(out + ".tmp", "w") as f:
                json.dump(raw, f, indent=1, default=str)
            os.replace(out + ".tmp", out)
            p = subprocess.run([PY, os.path.join(NM, "analyze.py"), out, "--readonly"],  # noqa: S603 - fixed argv
                               capture_output=True, text=True, timeout=900, cwd=NM)
            if p.returncode:
                raise RuntimeError((p.stderr or p.stdout or "analyze failed")[-300:])
            for n in SECTIONS:  # the assembled files now hold everything
                try:
                    os.remove(_sec_path(rid, n))
                except OSError:
                    pass
            _rstatus(rid, status="done", step="")
    return {"ok": True, "seconds": round(time.time() - t, 2)}


_ev_proc = [None]


def research_event(b):
    """Start a research run for one event now (review.py --event). One at a time; the dashboard keeps the request queued otherwise."""
    eid = str(b.get("eid") or "")
    if not eid or len(eid) > 300 or "\x00" in eid:
        raise ValueError("eid required")
    if _ev_proc[0] and _ev_proc[0].poll() is None:
        return {"started": False, "reason": "another single-event research is running"}
    log = open(os.path.join(NM, "logs", "research-event.log"), "a")
    _ev_proc[0] = subprocess.Popen([PY, os.path.join(NM, "review.py"), "--event", eid, "--trigger", "event:" + str(b.get("user") or "")[:40]],  # noqa: S603
                                   cwd=NM, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
    return {"started": True}


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
            if self.path == "/section":
                return self._send(200, section(b))
            if self.path == "/research-event":
                return self._send(200, research_event(b))
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
