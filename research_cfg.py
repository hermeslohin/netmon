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
  severities            which event severities the job will send out for research; others are skipped before any
                         model call (host findings, severity-1/2 Suricata signatures and gateway events are always
                         researched regardless of this setting - see enrich.py:_events)
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
DEFAULTS = {"provider": "", "model": "", "interval_minutes": 240, "enabled": True, "max_run_usd": 5.0, "max_day_usd": 20.0,
            "max_run_tokens": 25_000_000, "max_batches": 10, "severities": ["high", "medium"]}
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
    sevs = [s for s in (out.get("severities") or []) if s in SEVERITIES] if isinstance(out.get("severities"), list) else []
    out["severities"] = sevs or list(DEFAULTS["severities"])
    out.update(by=v.get("by"), at=v.get("at"), pdf_hour=PDF_HOUR, limits=LIMITS, severity_options=list(SEVERITIES))
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
        elif k == "severities":
            sevs = sorted({str(s) for s in (v or []) if str(s) in SEVERITIES}, key=SEVERITIES.index)
            if not sevs:
                raise ValueError(f"severities must include at least one of {', '.join(SEVERITIES)}")
            cur[k] = sevs
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
