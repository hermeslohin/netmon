#!/usr/bin/env python3
"""netmon scheduler: runs the pipeline's recurring jobs on the host (systemd user unit netmon-scheduler.service).

  watcher        every 15 minutes            watch.py (urgent alerts -> dashboard + Web Push)
  research job   grid set on the dashboard   review.py (research_cfg: interval, anchored at 05:00 UTC; on/off)
                 + "Run now" requests from the AI review page
  weekly         Sunday 03:00 UTC            weekly_rebuild.sh (dashboard image rebuild + security scan)
Jobs never overlap with themselves; a slot missed while the host was down is not made up, except the research job,
which starts late within its own slot. Output of each job goes to logs/<job>.log (rotated at 5 MB).

Usage: scheduler.py            run forever (the systemd unit)
       scheduler.py status     next run of each job
"""
import datetime as dt
import json
import os
import subprocess
import sys
import time

NM = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, NM)
import research_cfg as RC  # noqa: E402
import store  # noqa: E402

PY = os.environ.get("NETMON_PYTHON") or "/usr/bin/python3"
LOGS = os.path.join(NM, "logs")
STATE = os.path.join(RC.STATE, "scheduler.json")
JOBS = {
    "watch": [PY, os.path.join(NM, "watch.py")],
    "research": [PY, os.path.join(NM, "review.py"), "--trigger", "schedule"],
    "weekly": [os.path.join(NM, "weekly_rebuild.sh")],
    "unifi": [PY, os.path.join(NM, "unifi.py"), "--prewarm"],  # keeps data/unifi_cache warm so ranges/snapshots skip the slow cloud calls
}
running = {}


def _state():
    return store.jload(STATE, {}) or {}


def _save(s):
    store.jdump(s, STATE)


def _log(name):
    os.makedirs(LOGS, exist_ok=True)
    p = os.path.join(LOGS, f"{name}.log")
    if os.path.exists(p) and os.path.getsize(p) > 5_000_000:
        os.replace(p, p + ".1")
    return open(p, "a")


def start(name, argv=None, why=""):
    p = running.get(name)
    if p and p.poll() is None:
        return False
    f = _log(name)
    f.write(f"\n=== {dt.datetime.now(dt.timezone.utc):%Y-%m-%d %H:%M:%S} UTC start {name} {why}\n")
    f.flush()
    running[name] = subprocess.Popen(argv or JOBS[name], cwd=NM, stdout=f, stderr=subprocess.STDOUT, start_new_session=True)  # noqa: S603
    print(f"started {name} {why} (pid {running[name].pid})", flush=True)
    return True


def reap():
    for n, p in list(running.items()):
        rc = p.poll()
        if rc is not None:
            print(f"{n} finished with exit code {rc}", flush=True)
            del running[n]


def tick(now=None):
    now = now or time.time()
    t = dt.datetime.fromtimestamp(now, dt.timezone.utc)
    s = _state()
    # watcher: once per 15-minute slot
    q = int(now // 900)
    if s.get("watch") != q:
        if start("watch", why="(15-min slot)"):
            s["watch"] = q
    # UniFi pre-warm: every 5-minute slot (a still-running one is not doubled)
    uq = int(now // 300)
    if s.get("unifi") != uq and start("unifi", why="(5-min slot)"):
        s["unifi"] = uq
    # weekly rebuild: Sunday 03:00-03:59 UTC, once per week
    wk = t.strftime("%G-W%V")
    if t.weekday() == 6 and t.hour == 3 and s.get("weekly") != wk:
        if start("weekly", why="(Sunday 03 UTC)"):
            s["weekly"] = wk
    # research job: manual request, else once per grid slot
    req = RC.pending_request()
    if req and not (running.get("research") and running["research"].poll() is None):
        RC.take_request()
        start("research", [PY, os.path.join(NM, "review.py"), "--trigger", "manual"], f"(requested by {req.get('by')})")
    cfg = RC.get()
    if cfg["enabled"] and cfg["model"]:
        st = RC.slot_start(RC.slot(now, cfg["interval_minutes"]), cfg["interval_minutes"])
        if "research" not in s:
            s["research"] = st  # first start: wait for the next slot instead of running at once
        elif st > float(s.get("research") or 0):  # a new slot began (an interval change never re-runs an earlier slot)
            if start("research", why=f"(slot {dt.datetime.fromtimestamp(st, dt.timezone.utc):%H:%M} UTC)"):
                s["research"] = st
    _save(s)


def status():
    cfg = RC.get()
    now = time.time()
    nxt_q = (int(now // 900) + 1) * 900
    t = dt.datetime.now(dt.timezone.utc)
    days = (6 - t.weekday()) % 7
    wk = (t + dt.timedelta(days=days)).replace(hour=3, minute=0, second=0, microsecond=0)
    if wk <= t:
        wk += dt.timedelta(days=7)
    return {"watch": nxt_q, "research": RC.next_run(), "research_interval_minutes": cfg["interval_minutes"],
            "research_enabled": cfg["enabled"], "weekly": wk.timestamp(), "last": _state()}


def main():
    if sys.argv[1:2] == ["status"]:
        print(json.dumps(status(), indent=1))
        return 0
    print(f"netmon scheduler started (python {PY})", flush=True)
    while True:
        try:
            reap()
            tick()
        except Exception as e:  # noqa: BLE001 - keep scheduling; the error shows in the journal
            print(f"scheduler error: {type(e).__name__}: {e}", file=sys.stderr, flush=True)
        time.sleep(20)


if __name__ == "__main__":
    sys.exit(main())
