"""Regression: the Fix-list tracker (issues.track_incremental) is evaluated by request threads and background jobs at
once; it must never cache a broken result (the 'NoneType' object has no attribute 'items' outage)."""
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); import _env  # noqa: E401,E702,E402

import threading  # noqa: E402
import unittest  # noqa: E402

import issues  # noqa: E402

RAW = {"devices": {f"10.0.0.{i}": {"name": f"h{i}"} for i in range(200)}, "hours": 24}
ITEMS = [(f"s{i}", i, (lambda: ("2026-11-07T00:00:00Z", RAW, {}))) for i in range(6)]


class TrackerRaceTest(unittest.TestCase):
    def test_concurrent_runs_do_not_poison_the_cache(self):
        """REQ: OPS-05"""
        cache, errs = {}, []

        def work(c):
            try:
                issues.track_incremental(ITEMS, c)
            except Exception as e:  # noqa: BLE001
                errs.append(e)
        for _ in range(3):
            ts = [threading.Thread(target=work, args=(cache if j % 2 else {},)) for j in range(8)]
            [t.start() for t in ts]
            [t.join() for t in ts]
        self.assertEqual(errs, [])
        self.assertTrue(all(isinstance(c["ev"]["look"], dict) for c in cache.values() if c["ev"] is not None))

    def test_poisoned_entry_is_reevaluated(self):
        """REQ: OPS-05"""
        cache = {}
        issues.track_incremental(ITEMS, cache)
        cache["s0"]["ev"]["look"] = None
        issues.track_incremental(ITEMS, cache)
        self.assertIsInstance(cache["s0"]["ev"]["look"], dict)


if __name__ == "__main__":
    unittest.main()
