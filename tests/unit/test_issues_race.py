"""Regression: the Fix list (fixlist.sync / issues._eval) runs in request threads and background jobs at once; the
shared IP2MAC / lookup state must never leak between evaluations (the 'NoneType' object has no attribute 'items' outage)."""
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); import _env  # noqa: E401,E702,E402

import sqlite3  # noqa: E402
import threading  # noqa: E402
import unittest  # noqa: E402

import fixlist  # noqa: E402

RAW = {"devices": {f"10.0.0.{i}": {"name": f"h{i}"} for i in range(200)}, "hours": 24}
ITEMS = [(f"s{i}", i, (lambda: ("2026-11-07T00:00:00Z", RAW, {}))) for i in range(6)]


class TrackerRaceTest(unittest.TestCase):
    def test_concurrent_runs_store_complete_rows(self):
        """Eight threads syncing at once (each its own database) all store every run with its lookups.
        REQ: OPS-05"""
        errs, dbs = [], []

        def work():
            try:
                c = fixlist.init(sqlite3.connect(":memory:", isolation_level=None, check_same_thread=False))
                fixlist.sync(ITEMS, c)
                dbs.append((c.execute("SELECT COUNT(*) FROM fix_run").fetchone()[0], c.execute("SELECT COUNT(*) FROM fix_run_lookup").fetchone()[0]))
            except Exception as e:  # noqa: BLE001
                errs.append(e)
        for _ in range(3):
            ts = [threading.Thread(target=work) for _ in range(8)]
            [t.start() for t in ts]
            [t.join() for t in ts]
        self.assertEqual(errs, [])
        self.assertEqual(set(dbs), {(6, 6 * 200)})

    def test_lost_lookups_are_reevaluated(self):
        """A run whose stored lookups no longer match the current IP->MAC map is evaluated again.
        REQ: OPS-05"""
        c = fixlist.init(sqlite3.connect(":memory:", isolation_level=None))
        fixlist.sync(ITEMS, c)
        c.execute("UPDATE fix_run_lookup SET mac='changed' WHERE sid='s0'")
        self.assertEqual(fixlist.sync(ITEMS, c), ["s0"])


if __name__ == "__main__":
    unittest.main()
