"""Time window shared by every collector: the last N minutes before NOW, or before a fixed END.

The nightly run and the 15-minute watcher use "now". A dashboard time range (collect.py --start/--end, started by the
host LLM broker for the dashboard's range picker) sets NETMON_WINDOW_END to the end of the range, so every query
covers [end - N minutes, end] instead of [now - N minutes, now].
"""
import datetime as dt
import os


def end():
    """ISO end of the window (UTC, 'Z'), or None for now."""
    return os.environ.get("NETMON_WINDOW_END") or None


def end_dt():
    e = end()
    return dt.datetime.fromisoformat(e.replace("Z", "+00:00")) if e else dt.datetime.now(dt.timezone.utc)


def end_ms():
    return int(end_dt().timestamp() * 1000)


def since(minutes):
    """Elasticsearch range filter for the last `minutes` of the window."""
    m = max(1, int(round(minutes)))
    e = end()
    if e:
        return {"range": {"@timestamp": {"gte": f"{e}||-{m}m", "lte": e}}}
    return {"range": {"@timestamp": {"gte": f"now-{m}m"}}}


def since_h(hours):
    return since(float(hours) * 60)


def is_range():
    return bool(end())
