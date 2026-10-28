#!/usr/bin/env python3
"""Lookback window of the review job (review.py): how many hours of logs each run collects.

Admins set it on the dashboard's AI review page (POST /api/config/lookback); it is stored in the netmon store's
meta table (key "review_lookback"; read from "research_lookback" when saved before the rename) so the host job and the dashboard container read the same value.
The daily run (05 UTC) always covers 24 h, whatever the setting, so the device baseline stays daily.

Usage: lookback.py            hours for a run starting now (what `collect.py auto` uses)
       lookback.py show       the setting as JSON
"""
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import store  # noqa: E402

KEY, _OLD_KEY = "review_lookback", "research_lookback"
DEFAULT, MIN_H, MAX_H = 24, 1, 24
DAILY_HOUR = 5  # UTC hour of the daily 24 h run (the review schedule is anchored on it)


def get():
    try:
        with store.connect() as c:
            r = c.execute("SELECT v FROM meta WHERE k=?", (KEY,)).fetchone() or c.execute("SELECT v FROM meta WHERE k=?", (_OLD_KEY,)).fetchone()
        v = json.loads(r[0]) if r else {}
    except Exception:  # noqa: BLE001 - no store / no row: default 24 h
        v = {}
    h = v.get("hours")
    return {"hours": h if isinstance(h, int) and MIN_H <= h <= MAX_H else DEFAULT, "by": v.get("by"), "at": v.get("at"),
            "default": DEFAULT, "min": MIN_H, "max": MAX_H, "daily_hour": DAILY_HOUR}


def put(hours, user):
    s = str(hours).strip() if isinstance(hours, (int, str)) and not isinstance(hours, bool) else ""
    if not s.isdigit():
        raise ValueError("hours must be a whole number")
    h = int(s)
    if not MIN_H <= h <= MAX_H:
        raise ValueError(f"hours must be between {MIN_H} and {MAX_H}")
    with store.connect() as c:
        c.execute("INSERT OR REPLACE INTO meta VALUES (?, ?)", (KEY, json.dumps({"hours": h, "by": str(user)[:64], "at": time.time()})))
    return get()


def for_run(hour=None):
    """(hours, why) for a run starting at UTC `hour` (default now)."""
    hour = time.gmtime().tm_hour if hour is None else hour
    if hour == DAILY_HOUR:
        return 24, "daily run: always 24 h"
    s = get()
    return s["hours"], ("configured on the AI review page" if s.get("at") else "default")


if __name__ == "__main__":
    if sys.argv[1:2] == ["show"]:
        print(json.dumps(get()))
    else:
        print(for_run()[0])
