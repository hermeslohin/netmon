#!/usr/bin/env python3
"""Settings, schedule and status of the review job (review.py): collect -> analyze -> reviewer -> queue.

Settings live in the netmon store's meta table (key "review_job"), so the dashboard container (AI review page) and the
host scheduler read the same values:
  interval_minutes      5 .. 1440; runs sit on a grid anchored at 05:00 UTC (the daily 24 h run)
  enabled               the scheduler skips the job when off
  modes                 per event category what the job does with an event that has no note yet:
                          "review" - the reviewer model (the correlation reviewer, AI review > Models) compares it with
                                     earlier notes and copies a matching one; anything it cannot match is queued
                          "queue"  - queued without a model call
                          "test"   - queued and tagged "testing" (shows what a mode would queue; new deployments)
                          "skip"   - ignored
                        Categories: see MODE_CATS and enrich.py:_events. Queued events wait on AI review > Queue for a
                        person; nothing here ever researches an event.
  severities            legacy view of modes: the severity categories in "queue" or "review"
A "run now" request from the dashboard is meta key "review_request"; the scheduler starts the job and clears it.
review.py writes its run state to <state>/review_job.json (running / last runs / token use), read by the dashboard.

Usage: review_cfg.py show | due | request
"""
import json
import os
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
import store  # noqa: E402

KEY, REQ = "review_job", "review_request"
_OLD_KEY, _OLD_REQ, _OLD_STATUS = "research_job", "research_request", "research_job.json"  # before the review / research split
DAILY_HOUR = 5
SEVERITIES = ("high", "medium", "low", "info")  # the standard severity vocabulary (risk.py SEV_BASE, issues.py SEV_ORDER)
MODES = ("review", "queue", "skip", "test")
MODE_CATS = (("host", "Endpoint host findings"), ("ids12", "Suricata severity 1-2 signatures"), ("gw", "UniFi gateway events"),
             ("seg_high", "Segmentation: high (admin ports)"), ("seg_medium", "Segmentation: medium (odd ports)"),
             ("seg_low", "Segmentation: low (standard ports)"), ("ti", "Threat-intel hits"), ("alert", "Urgent alarms (watcher)"), ("high", "Other events: high"),
             ("medium", "Other events: medium"), ("low", "Other events: low"), ("info", "Other events: info"))
LEGACY_MODES = {"host": "queue", "ids12": "queue", "gw": "queue", "seg_high": "queue", "seg_medium": "queue", "seg_low": "queue", "ti": "queue", "alert": "queue",
                "high": "queue", "medium": "queue", "low": "skip", "info": "skip"}  # what deployments made before modes existed do
DEFAULT_MODES = {k: "test" for k in LEGACY_MODES}  # new deployments start in test mode
DEFAULTS = {"interval_minutes": 240, "enabled": True, "modes": DEFAULT_MODES}
LIMITS = {"interval_minutes": (5, 1440)}
STATE = os.environ.get("STATE_DIR") or ("/state" if os.path.isdir("/state") else os.path.join(_HERE, "dashboard", "state"))
STATUS = os.path.join(STATE, "review_job.json")


def _meta(k):
    try:
        with store.connect() as c:
            r = c.execute("SELECT v FROM meta WHERE k=?", (k,)).fetchone()
        return json.loads(r[0]) if r else {}
    except Exception:  # noqa: BLE001
        return {}


def _meta_put(k, v):
    with store.connect() as c:
        if v is None:
            c.execute("DELETE FROM meta WHERE k=?", (k,))
        else:
            c.execute("INSERT OR REPLACE INTO meta VALUES (?, ?)", (k, json.dumps(v)))


def _mode(m):
    return "queue" if m == "research" else m  # stored before the split: "research" meant "queue it for the model"


def _stored():
    v = _meta(KEY)
    if v:
        return v
    old = _meta(_OLD_KEY)  # settings saved before the split: the schedule and modes lived with the research settings
    v = {k: old[k] for k in ("interval_minutes", "enabled", "modes", "severities", "by", "at") if k in old}
    return v or ({"_old": True} if old else {})  # an existing deployment keeps the legacy modes


def get():
    v = _stored()
    out = {k: v.get(k, d) for k, d in DEFAULTS.items()}
    for k, (lo, hi) in LIMITS.items():
        try:
            out[k] = type(DEFAULTS[k])(out[k])
            if not lo <= out[k] <= hi:
                out[k] = DEFAULTS[k]
        except (TypeError, ValueError):
            out[k] = DEFAULTS[k]
    out["enabled"] = bool(out["enabled"])
    modes = dict(DEFAULT_MODES if not v else LEGACY_MODES)  # a deployment that already has settings keeps its behaviour
    if isinstance(v.get("severities"), list) and not isinstance(v.get("modes"), dict):  # settings saved before modes existed
        for s_ in SEVERITIES:
            modes[s_] = "queue" if s_ in v["severities"] else "skip"
    if isinstance(v.get("modes"), dict):
        old = v["modes"].get("seg")  # one segmentation category before it was split by severity
        if _mode(old) in MODES:
            modes.update({k: _mode(old) for k in ("seg_high", "seg_medium", "seg_low")})
        modes.update({k: _mode(m) for k, m in v["modes"].items() if k in DEFAULT_MODES and _mode(m) in MODES})
    out["modes"] = modes
    out["severities"] = [s_ for s_ in SEVERITIES if modes[s_] in ("queue", "review")]
    out.update(by=v.get("by"), at=v.get("at"), daily_hour=DAILY_HOUR, limits=LIMITS, severity_options=list(SEVERITIES),
               mode_options=list(MODES), mode_cats=[{"key": k, "label": l} for k, l in MODE_CATS])
    return out


def put(fields, user):
    """Update some settings (interval_minutes, enabled, modes, legacy severities)."""
    cur = {k: v for k, v in _stored().items() if k in DEFAULTS}
    for k, v in fields.items():
        if k == "enabled":
            cur[k] = bool(v)
        elif k == "modes":
            v = {a: _mode(b) for a, b in v.items()} if isinstance(v, dict) else v
            if not isinstance(v, dict) or any(a not in DEFAULT_MODES or b not in MODES for a, b in v.items()):
                raise ValueError(f"modes must map {', '.join(DEFAULT_MODES)} to one of {', '.join(MODES)}")
            m = get()["modes"]
            m.update(v)
            if all(x == "skip" for x in m.values()):
                raise ValueError("at least one category must be review or queue")
            cur[k] = m
        elif k == "severities":  # legacy API: a list of severities to queue
            m = get()["modes"]
            for s_ in SEVERITIES:
                m[s_] = "queue" if s_ in (v or []) else "skip"
            cur["modes"] = m
        elif k in LIMITS:
            lo, hi = LIMITS[k]
            try:
                n = type(DEFAULTS[k])(v)
            except (TypeError, ValueError):
                raise ValueError(f"{k} must be a number") from None
            if not lo <= n <= hi:
                raise ValueError(f"{k} must be between {lo} and {hi}")
            cur[k] = n
    cur.setdefault("modes", get()["modes"])  # pin the effective modes so a later default change never alters this deployment
    cur.update(by=str(user)[:64], at=time.time())
    _meta_put(KEY, cur)
    return get()


def slot(now=None, interval=None):
    """Index of the schedule slot `now` falls in (grid of `interval` minutes anchored at 05:00 UTC)."""
    now = time.time() if now is None else now
    interval = interval or get()["interval_minutes"]
    return int((now - DAILY_HOUR * 3600) // (interval * 60))


def slot_start(n, interval):
    return n * interval * 60 + DAILY_HOUR * 3600


def next_run(now=None):
    s = get()
    now = time.time() if now is None else now
    return slot_start(slot(now, s["interval_minutes"]) + 1, s["interval_minutes"]) if s["enabled"] else None


def request(user):
    _meta_put(REQ, {"by": str(user)[:64], "at": time.time()})


def take_request():
    r = _meta(REQ) or _meta(_OLD_REQ)
    if r:
        _meta_put(REQ, None)
        _meta_put(_OLD_REQ, None)
    return r or None


def pending_request():
    return _meta(REQ) or _meta(_OLD_REQ) or None


def status():
    d = store.jload(STATUS, None)
    if d is None:  # first read after the split: the review runs were kept with the research state
        old = store.jload(os.path.join(STATE, _OLD_STATUS), {}) or {}
        d = {k: old[k] for k in ("runs", "summary", "last_status", "last_error", "failure_streak", "last_run") if k in old}
        d["usage"] = [u for u in old.get("usage") or [] if not u.get("event_run")]
    return d or {}


def write_status(d):
    store.jdump(d, STATUS)


if __name__ == "__main__":
    a = sys.argv[1:2]
    if a == ["due"]:
        print(json.dumps({"slot": slot(), "next_run": next_run()}))
    elif a == ["request"]:
        request("cli")
        print("requested")
    else:
        print(json.dumps(get(), indent=1))
