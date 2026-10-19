#!/usr/bin/env python3
"""Settings, schedule and status of the research job (review.py): AI triage + event research + daily PDF.

Settings live in the netmon store's meta table (key "research_job"), so the dashboard container (which writes them
from the AI review / Configuration pages) and the host scheduler read the same values:
  provider, model       which AI does the research ("api:<id>" from llm_providers, or "lmstudio")
  interval_minutes      30 .. 1440; runs sit on a grid anchored at 05:00 UTC (the daily PDF run)
  enabled               the scheduler skips the job when off
  max_run_usd           stop a run when its estimated cost passes this (needs a price for the model; 0 = no cap)
  max_day_usd           no new run once today's runs (UTC) cost this much (0 = no cap)
  max_run_tokens        stop a run after this many tokens (input + output; 0 = no cap) - works without prices
  max_batches           event-research conversations per run (8 work items each)
  modes                 per event category what the job does: "research" (send to the model; events that already have
                         a note are only rewritten if the new run contradicts it), "review" (never sent to the model:
                         the work list is matched against earlier research - the event's own note and the notes of
                         correlated events - and anything already researched is left alone) or "skip" (ignored).
                         Categories: host, ids12, gw, ti, alert (by kind) and high, medium, low, info (all other events
                         by severity) - see MODE_CATS and enrich.py:_events
  severities            legacy view of modes: the severity categories that are not "skip"
A "run now" request from the dashboard is meta key "research_request"; the scheduler starts the job and clears it.
review.py writes its state to <state>/research_job.json (running / last runs / token use), read by the dashboard.

Usage: research_cfg.py show | due | request
"""
import json
import os
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
import store  # noqa: E402

KEY, REQ = "research_job", "research_request"
PDF_HOUR = 5
SEVERITIES = ("high", "medium", "low", "info")  # the standard severity vocabulary (risk.py SEV_BASE, issues.py SEV_ORDER)
MODES = ("research", "review", "skip")
MODE_CATS = (("host", "Endpoint host findings"), ("ids12", "Suricata severity 1-2 signatures"), ("gw", "UniFi gateway events"),
             ("ti", "Threat-intel hits"), ("alert", "Urgent alarms (watcher)"), ("high", "Other events: high"),
             ("medium", "Other events: medium"), ("low", "Other events: low"), ("info", "Other events: info"))
DEFAULT_MODES = {"host": "research", "ids12": "research", "gw": "research", "ti": "research", "alert": "research",
                 "high": "research", "medium": "research", "low": "skip", "info": "skip"}
DEFAULTS = {"provider": "", "model": "", "interval_minutes": 240, "enabled": True, "max_run_usd": 5.0, "max_day_usd": 20.0,
            "max_run_tokens": 25_000_000, "max_batches": 10, "severities": ["high", "medium"],
            "modes": DEFAULT_MODES}
LIMITS = {"interval_minutes": (30, 1440), "max_run_usd": (0, 1000), "max_day_usd": (0, 5000), "max_run_tokens": (0, 100_000_000),
          "max_batches": (0, 40)}
STATE = os.environ.get("STATE_DIR") or ("/state" if os.path.isdir("/state") else os.path.join(_HERE, "dashboard", "state"))
STATUS = os.path.join(STATE, "research_job.json")


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


def get():
    v = _meta(KEY)
    out = {k: v.get(k, d) for k, d in DEFAULTS.items()}
    for k, (lo, hi) in LIMITS.items():
        try:
            out[k] = type(DEFAULTS[k])(out[k])
            if not lo <= out[k] <= hi:
                out[k] = DEFAULTS[k]
        except (TypeError, ValueError):
            out[k] = DEFAULTS[k]
    modes = dict(DEFAULT_MODES)
    if isinstance(v.get("severities"), list) and not isinstance(v.get("modes"), dict):  # settings saved before modes existed
        for s_ in SEVERITIES:
            modes[s_] = "research" if s_ in v["severities"] else "skip"
    if isinstance(v.get("modes"), dict):
        modes.update({k: m for k, m in v["modes"].items() if k in DEFAULT_MODES and m in MODES})
    out["modes"] = modes
    out["severities"] = [s_ for s_ in SEVERITIES if modes[s_] != "skip"]
    out.update(by=v.get("by"), at=v.get("at"), pdf_hour=PDF_HOUR, limits=LIMITS, severity_options=list(SEVERITIES),
               mode_options=list(MODES), mode_cats=[{"key": k, "label": l} for k, l in MODE_CATS])
    return out


def put(fields, user, check_model=None):
    """Update some settings. check_model(provider, model) -> bool validates a model change."""
    cur = {k: v for k, v in _meta(KEY).items() if k in DEFAULTS}
    for k, v in fields.items():
        if k not in DEFAULTS:
            continue
        if k in ("provider", "model"):
            cur[k] = str(v or "")[:120]
        elif k == "enabled":
            cur[k] = bool(v)
        elif k == "modes":
            if not isinstance(v, dict) or any(a not in DEFAULT_MODES or b not in MODES for a, b in v.items()):
                raise ValueError(f"modes must map {', '.join(DEFAULT_MODES)} to one of {', '.join(MODES)}")
            m = get()["modes"]
            m.update(v)
            if all(x == "skip" for x in m.values()):
                raise ValueError("at least one category must be research or review")
            cur[k] = m
        elif k == "severities":  # legacy API: a list of severities to research
            m = get()["modes"]
            for s_ in SEVERITIES:
                m[s_] = "research" if s_ in (v or []) else "skip"
            cur["modes"] = m
        else:
            lo, hi = LIMITS[k]
            try:
                n = type(DEFAULTS[k])(v)
            except (TypeError, ValueError):
                raise ValueError(f"{k} must be a number") from None
            if not lo <= n <= hi:
                raise ValueError(f"{k} must be between {lo} and {hi}")
            cur[k] = n
    if ("provider" in fields or "model" in fields) and check_model and not check_model(cur.get("provider"), cur.get("model")):
        raise ValueError("unknown provider or model")
    cur.update(by=str(user)[:64], at=time.time())
    _meta_put(KEY, cur)
    return get()


def slot(now=None, interval=None):
    """Index of the schedule slot `now` falls in (grid of `interval` minutes anchored at 05:00 UTC)."""
    now = time.time() if now is None else now
    interval = interval or get()["interval_minutes"]
    return int((now - PDF_HOUR * 3600) // (interval * 60))


def slot_start(n, interval):
    return n * interval * 60 + PDF_HOUR * 3600


def next_run(now=None):
    s = get()
    now = time.time() if now is None else now
    return slot_start(slot(now, s["interval_minutes"]) + 1, s["interval_minutes"]) if s["enabled"] else None


def request(user):
    _meta_put(REQ, {"by": str(user)[:64], "at": time.time()})


def take_request():
    r = _meta(REQ)
    if r:
        _meta_put(REQ, None)
    return r or None


def pending_request():
    return _meta(REQ) or None


def status():
    try:
        return json.load(open(STATUS))
    except (OSError, ValueError):
        return {}


def write_status(d):
    tmp = STATUS + ".tmp"
    with open(tmp, "w") as f:
        json.dump(d, f, indent=1, default=str)
    os.replace(tmp, STATUS)


def spent_today():
    day = time.strftime("%Y-%m-%d", time.gmtime())
    return sum(u.get("cost_usd") or 0 for u in status().get("usage") or [] if time.strftime("%Y-%m-%d", time.gmtime(u.get("at") or 0)) == day)


if __name__ == "__main__":
    a = sys.argv[1:2]
    if a == ["due"]:
        print(json.dumps({"slot": slot(), "next_run": next_run()}))
    elif a == ["request"]:
        request("cli")
        print("requested")
    else:
        print(json.dumps(get(), indent=1))
