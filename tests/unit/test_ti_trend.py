"""Threat-intel trend endpoint: built one snapshot at a time (never all snapshots in memory)."""
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); import _env  # noqa: E401,E402

import unittest  # noqa: E402

import tintel  # noqa: E402


class TestTrend(unittest.TestCase):
    def test_trend_cached_loads_each_once(self):
        """Each snapshot is loaded once, reduced to its counter row, and reloaded only when its mtime changes;
        rows of deleted snapshots are dropped.
        REQ: DASH-07
        """
        tintel._trend_rows.clear()
        raw = {"s1": {"generated": "a", "threat_intel": {"ip_hits_in": [{"conns": 3}], "domain_hits": [1, 2]}},
               "s2": {"generated": "b", "threat_intel": {"ip_hits_out": [1]}}}
        mt, loads = {"s1": 1.0, "s2": 1.0}, []

        def load(sid):
            loads.append(sid)
            return raw[sid]
        rows = tintel.trend_cached(["s1", "s2"], mt.get, load)
        self.assertEqual([(r["id"], r["in_conns"], r["domains"], r["out_ips"]) for r in rows], [("s1", 3, 2, 0), ("s2", 0, 0, 1)])
        tintel.trend_cached(["s1", "s2"], mt.get, load)
        self.assertEqual(loads, ["s1", "s2"])  # cached
        mt["s2"] = 2.0
        tintel.trend_cached(["s1", "s2"], mt.get, load)
        self.assertEqual(loads, ["s1", "s2", "s2"])
        tintel.trend_cached(["s1"], mt.get, load)
        self.assertEqual(set(tintel._trend_rows), {"s1"})
        self.assertTrue(all(isinstance(v[1], dict) and "threat_intel" not in v[1] for v in tintel._trend_rows.values()))


if __name__ == "__main__":
    unittest.main()
