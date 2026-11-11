#!/usr/bin/env python3
"""Event window: ONE setting (minutes) that drives the correlation, the review job's lookback and the event reviewer.

  * correlation   - two events only become a candidate link when they happened at most this far apart
                    (correlate.py; the AI review page's old separate "window" limit follows it too);
  * review job    - each run collects every event that arrived since the previous run PLUS one window before
                    that (window.arrival back=), so a new event always meets the events of the window before it;
  * settle wait   - a correlated group is labelled by the event reviewer once, after its newest member is this
                    old and none of its links is undecided; late Elasticsearch arrivals are covered by waiting for a
                    committed pull past that point (the stream's bookmark for stream-only groups, else the watcher's).

Stored in the SQLite cfg table, settings document "site", key "event_window_minutes" (More > Settings > Site). Read
live: every caller asks minutes() (cfg_load re-checks the DB every couple of seconds), so a change applies to the
worker and the correlation without a restart. Before this setting existed the review job had an hours lookback in the
store meta table (key "review_lookback", earlier "research_lookback"); migrate() copies that value over once
(hours x 60, clamped to the range) instead of dropping it.
The daily run (05 UTC) always covers 24 h, whatever the setting, so the device baseline stays daily.

Usage: lookback.py            hours of logs for a run starting now (what `collect.py auto` uses)
       lookback.py show       the setting as JSON
"""
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import store  # noqa: E402

DOC, FIELD = "site", "event_window_minutes"
KEY, _OLD_KEY = "review_lookback", "research_lookback"  # the retired hours setting (store meta), read once by migrate()
DEFAULT, MIN_M, MAX_M = 10, 2, 120
INGEST_SLACK_S = 300  # Elasticsearch arrivals lag the event time by up to a few minutes (ingest pipeline + refresh)
DAILY_HOUR = 5  # UTC hour of the daily 24 h run (the review schedule is anchored on it)


def valid(v):
    """The value as int minutes when it is a whole number within MIN_M-MAX_M, else None."""
    if isinstance(v, bool):
        return None
    if isinstance(v, float) and v.is_integer():
        v = int(v)
    if isinstance(v, str) and v.strip().isdigit():
        v = int(v.strip())
    return v if isinstance(v, int) and MIN_M <= v <= MAX_M else None


def _old_hours():
    try:
        with store.connect() as c:
            r = c.execute("SELECT v FROM meta WHERE k=?", (KEY,)).fetchone() or c.execute("SELECT v FROM meta WHERE k=?", (_OLD_KEY,)).fetchone()
        v = json.loads(r[0]) if r else {}
    except Exception:  # noqa: BLE001 - no store / bad row
        return None
    h = v.get("hours") if isinstance(v, dict) else None
    return h if isinstance(h, (int, float)) and not isinstance(h, bool) and h > 0 else None


def migrate():
    """Copy the retired hours lookback into the event window once (only when the window was never set). Returns the
    migrated minutes or None."""
    try:
        d = store.cfg_load(DOC)
    except Exception:  # noqa: BLE001 - no store yet
        return None
    if FIELD in d:
        return None
    h = _old_hours()
    if h is None:
        return None
    m = max(MIN_M, min(MAX_M, int(round(h * 60))))
    d[FIELD] = m
    d["_migrated_" + FIELD] = f"from the review lookback of {h:g} h"
    store.cfg_save(DOC, d)
    print(f"event window: migrated the review lookback of {h:g} h to {m} min", file=sys.stderr)
    return m


def minutes():
    """The event window in minutes (live: a Settings change is seen within a couple of seconds)."""
    try:
        v = valid(store.cfg_load(DOC, shared=True).get(FIELD))
    except Exception:  # noqa: BLE001 - no store / no row: default
        v = None
    return DEFAULT if v is None else v


def settle_s():
    """Seconds after a group's newest member before the event reviewer labels it."""
    return minutes() * 60


def get():
    try:
        d = store.cfg_load(DOC, shared=True)
    except Exception:  # noqa: BLE001
        d = {}
    m = minutes()
    return {"minutes": m, "hours": round(m / 60, 4), "set": FIELD in d, "migrated": d.get("_migrated_" + FIELD) or "",
            "default": DEFAULT, "min": MIN_M, "max": MAX_M, "ingest_slack_s": INGEST_SLACK_S, "daily_hour": DAILY_HOUR,
            "where": "More > Settings > Site > " + FIELD}


def put(mins, user):
    """Set the event window (minutes, MIN_M-MAX_M). The Settings page saves through /api/config/cfg (same check in
    server.cfg_validate); this is the programmatic setter."""
    v = valid(mins)
    if v is None:
        raise ValueError(f"{FIELD} must be a whole number of minutes between {MIN_M} and {MAX_M}")
    d = store.cfg_load(DOC)
    d[FIELD] = v
    store.cfg_save(DOC, d)
    print(f"event window: {str(user)[:64]} set {v} min", file=sys.stderr)
    return get()


def for_run(hour=None):
    """(hours, why) for a run starting at UTC `hour` (default now): the event window (collect.py adds the time since
    the previous run through its arrival bookmark), or 24 h on the daily run."""
    hour = time.gmtime().tm_hour if hour is None else hour
    if hour == DAILY_HOUR:
        return 24, "daily run: always 24 h"
    migrate()
    g = get()
    return g["hours"], f"event window {g['minutes']} min ({'Settings > Site' if g['set'] else 'default'})"


if __name__ == "__main__":
    if sys.argv[1:2] == ["show"]:
        print(json.dumps(get()))
    else:
        print(for_run()[0])
