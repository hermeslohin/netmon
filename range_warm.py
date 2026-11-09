#!/usr/bin/env python3
"""Pre-collect the dashboard's default time range (the last 24 h, ending on the current 15-minute boundary).

The dashboard opens on that window (server.default_range). Started by scheduler.py every 15-minute slot, right after
the review run, so a page load finds it already assembled instead of collecting 17 sections first. Uses the host
broker's own functions in-process (same collect.py --section + analyze.py --readonly path as the time picker).
Only the newest KEEP warm ranges are kept (doc state/range_warm); time ranges people picked are pruned by the broker.

    range_warm.py            warm the current slot
    range_warm.py --end ISO  warm a given end (tests / by hand)
"""
import datetime as dt
import os
import sys
import time

NM = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, NM)
import store  # noqa: E402
import host_broker as HB  # noqa: E402

HOURS = 24
KEEP = 3
DOC = "state/range_warm"


def slot_end(now=None):
    now = now or time.time()
    return dt.datetime.fromtimestamp(int(now // 900) * 900, dt.timezone.utc)


def warm(end=None):
    e = end or slot_end()
    s = e - dt.timedelta(hours=HOURS)
    t = time.time()
    r = HB.range_start({"start": s.isoformat(), "end": e.isoformat()}, warm=True)
    rid = r["id"]
    if r.get("status") != "done":
        HB.section({"id": rid, "name": "analysis"})
    st = store.doc_get(DOC, {}) or {}
    ids = [i for i in st.get("ids", []) if i != rid] + [rid]
    for old in ids[:-KEEP]:
        for f in store.jglob(HB.RANGES, old + ".*"):
            store.jdelete(f)
        try:
            store.jdelete(os.path.join(HB.RANGES, old + ".json"))
        except OSError:
            pass
    store.doc_put(DOC, {"ids": ids[-KEEP:], "updated": time.time()})
    print(f"warmed {rid} in {time.time() - t:.1f} s", flush=True)
    return rid


if __name__ == "__main__":
    end = None
    if sys.argv[1:2] == ["--end"]:
        end = dt.datetime.fromisoformat(sys.argv[2].replace("Z", "+00:00"))
    warm(end)
