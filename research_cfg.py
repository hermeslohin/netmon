#!/usr/bin/env python3
"""Settings and usage of on-demand event research (research.py): a person sends one event to research.

Nothing here runs on a schedule: research starts only when a person clicks Send to research (the dashboard asks the
host broker, which starts research.py --event; a click that has to wait is started by the scheduler once the running
research ends). The scheduled review job has its own settings (review_cfg.py).
Settings live in the netmon store's meta table (key "research_job"):
  provider, model       which AI does the research ("api:<id>" from llm_providers, or "lmstudio")
  max_run_usd           stop a research run when its estimated cost passes this (needs a price for the model; 0 = no cap)
  max_day_usd           no new research once today's research (UTC) cost this much (0 = no cap)
  max_run_tokens        stop a research run after this many tokens (input + output; 0 = no cap) - works without prices
  max_searches          web searches allowed per event (0 = no cap)
  max_batches           research conversations per run (8 events each)
  es_search             True/False (default True): let the research model search Elasticsearch (es_search tool)
  web_research          True/False (new deployments: False): let it search and read web pages (and cite them)
Pending clicks are meta key "research_requests" (enrich.request_research). research.py writes token use and cost per
researched event to <state>/research_job.json, read by the dashboard.

Usage: research_cfg.py show
"""
import json
import os
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
import store  # noqa: E402

KEY = "research_job"
DEFAULTS = {"provider": "", "model": "", "max_run_usd": 5.0, "max_day_usd": 20.0,
            "max_run_tokens": 25_000_000, "max_batches": 10, "max_searches": 3, "web_research": False, "es_search": True}
LIMITS = {"max_run_usd": (0, 1000), "max_day_usd": (0, 5000), "max_run_tokens": (0, 100_000_000),
          "max_batches": (0, 40), "max_searches": (0, 20)}
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
    if v:  # a deployment that already has settings keeps its behaviour: web research was on before it became an option
        out["web_research"] = v.get("web_research", True)
    for k, (lo, hi) in LIMITS.items():
        try:
            out[k] = type(DEFAULTS[k])(out[k])
            if not lo <= out[k] <= hi:
                out[k] = DEFAULTS[k]
        except (TypeError, ValueError):
            out[k] = DEFAULTS[k]
    out["web_research"], out["es_search"] = bool(out["web_research"]), bool(out["es_search"])
    out.update(by=v.get("by"), at=v.get("at"), limits=LIMITS)
    return out


def put(fields, user, check_model=None):
    """Update some settings. check_model(provider, model) -> bool validates a model change."""
    cur = dict(_meta(KEY))  # keeps keys of the old combined record (schedule, modes) that review_cfg migrates from
    if "web_research" not in cur:
        cur["web_research"] = get()["web_research"]  # pin it: saving another setting must not switch web access on
    for k, v in fields.items():
        if k not in DEFAULTS:
            continue
        if k in ("provider", "model"):
            cur[k] = str(v or "")[:120]
        elif k in ("web_research", "es_search"):
            cur[k] = bool(v)
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


def status():
    return store.jload(STATUS, {}) or {}


def write_status(d):
    store.jdump(d, STATUS)


def spent_today():
    """Cost of today's (UTC) event research."""
    day = time.strftime("%Y-%m-%d", time.gmtime())
    return sum(u.get("cost_usd") or 0 for u in status().get("usage") or []
               if u.get("event_run") and time.strftime("%Y-%m-%d", time.gmtime(u.get("at") or 0)) == day)


if __name__ == "__main__":
    print(json.dumps(get(), indent=1))
