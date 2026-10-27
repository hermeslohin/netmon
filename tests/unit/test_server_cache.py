"""Unit tests for the dashboard's in-memory document cache (server.load_json)."""
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); import _env  # noqa: E401,E402

import unittest  # noqa: E402

import fixtures  # noqa: E402
import server  # noqa: E402


class CacheBound(unittest.TestCase):
    def setUp(self):
        _env.fresh_db()
        server._cache.clear()

    def test_cache_is_lru_bounded(self):
        """Inserting more than _CACHE_MAX entries evicts the least recently used; a read refreshes an entry.
        REQ: OPS-05"""
        n = server._CACHE_MAX
        for i in range(n):
            server._cache_put(f"p{i}", 1, i)
        self.assertIsNotNone(server._cache_get("p0"))  # p0 is now most recent
        for i in range(n, n + 5):
            server._cache_put(f"p{i}", 1, i)
        self.assertEqual(len(server._cache), n)
        self.assertIsNotNone(server._cache_get("p0"))
        self.assertIsNone(server._cache_get("p1"))

    def test_snapshot_loads_stay_bounded(self):
        """Loading many snapshot docs through load_json never keeps more than _CACHE_MAX parsed docs.
        REQ: OPS-05, DASH-02"""
        for i in range(server._CACHE_MAX + 8):
            sid = "2026-01-%02dT%02d00Z" % (1 + i // 24, i % 24)
            fixtures.seed_snapshot(sid)
            self.assertIsNotNone(server.load_json(os.path.join(server.DATA, sid + ".json")))
        self.assertLessEqual(len(server._cache), server._CACHE_MAX)


if __name__ == "__main__":
    unittest.main()
