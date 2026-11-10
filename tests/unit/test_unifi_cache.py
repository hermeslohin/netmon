"""Unit tests for the UniFi pre-warm cache (unifi.py): it lives in netmon.db (unifi_rows/unifi_streams + docs unifi/*),
keeps its freshness rules, never writes files, redacts controller credentials, and the retired cache dir stays gone."""
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); import _env  # noqa: E401,E402

import shutil  # noqa: E402
import sqlite3  # noqa: E402
import tempfile  # noqa: E402
import time  # noqa: E402
import unittest  # noqa: E402
import zlib  # noqa: E402

import store  # noqa: E402
import unifi  # noqa: E402

SETTINGS = [
    {"key": "mgmt", "x_api_token": "tok-123", "x_mgmt_key": "abcd", "x_ssh_password": "pw", "x_ssh_sha512passwd": "$6$x",
     "x_ssh_enabled": True, "x_ssh_keys": []},
    {"key": "magic_site_to_site_vpn", "public_key": "pub", "x_private_key": "wg-secret-9"},
    {"key": "ips", "ips_mode": "ips", "utm_token": "u", "enabled_categories": ["a"]},
    {"key": "connectivity", "x_mesh_psk": "m", "nested": [{"radius_secret": "r", "x_passphrase": "p"}]},
]
SECRETS = ("tok-123", "abcd", "\"pw\"", "$6$x", "wg-secret-9", "\"u\"", "\"m\"", "\"r\"", "\"p\"")
H = 3600_000


class UnifiCache(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="unifi-", dir=_env.TMP)
        self.old_db = os.environ.get("NETMON_DB")
        os.environ["NETMON_DB"] = os.path.join(self.tmp, "netmon.db")
        self.calls = []
        self.saved = {k: getattr(unifi, k) for k in ("_syslog_raw", "_flows_raw", "_legacy_raw", "MAX_ROWS")}
        self.now = int(time.time() * 1000)

        def syslog_raw(cat, a, b):
            self.calls.append(("syslog", cat, a, b))
            return [{"id": f"{cat}-{t}", "timestamp": t} for t in range(self.now - 10 * H, self.now + 1, H) if a <= t <= b]

        def flows_raw(a, b, max_pages=40):
            self.calls.append(("flows", a, b))
            return [{"id": f"f{t}", "time": t} for t in range(self.now - 5 * H, self.now + 1, H) if a <= t <= b], False

        def legacy_raw(path, body=None):
            self.calls.append(("legacy", path))
            return SETTINGS if path == "get/setting" else [{"mac": "aa", "n": len(self.calls)}]
        unifi._syslog_raw, unifi._flows_raw, unifi._legacy_raw = syslog_raw, flows_raw, legacy_raw

    def tearDown(self):
        for k, v in self.saved.items():
            setattr(unifi, k, v)
        if self.old_db is None:
            os.environ.pop("NETMON_DB", None)
        else:
            os.environ["NETMON_DB"] = self.old_db
        shutil.rmtree(self.tmp, True)

    def test_settings_cache_has_no_credentials(self):
        """Every write of a legacy (settings) cache blanks controller credentials but keeps what netmon reads.
        REQ: SEC-06"""
        unifi._csave("legacy-get/setting", {"at": 1, "data": SETTINGS})  # the prewarm() path: raw data straight in
        raw = zlib.decompress(store._dc().execute("SELECT doc FROM docs WHERE name='unifi/legacy-get_setting'").fetchone()[0]).decode()
        for s in SECRETS:
            self.assertNotIn(s, raw)
        st = {s["key"]: s for s in unifi._cload("legacy-get/setting")["data"]}
        self.assertEqual(st["ips"]["ips_mode"], "ips")
        self.assertEqual(st["mgmt"]["x_ssh_enabled"], True)
        self.assertEqual(st["magic_site_to_site_vpn"]["public_key"], "pub")
        self.assertEqual(st["mgmt"]["x_api_token"], "[redacted]")

    def test_prewarm_fills_store_and_serves_reads_without_files(self):
        """The UniFi pre-warm writes logs/flows as rows and current-state calls as docs in netmon.db, creates no files,
        and syslog()/flows()/legacy() inside the cached window answer from the store with no API call.
        REQ: STO-16"""
        before = set(os.listdir(self.tmp))
        out = unifi.prewarm()
        self.assertEqual(out["syslog-all"]["rows"], 11)
        self.assertEqual(out["flows"]["rows"], 6)
        self.assertEqual(set(os.listdir(self.tmp)) - before - {"netmon.db", "netmon.db-wal", "netmon.db-shm"}, set())
        self.assertFalse(hasattr(unifi, "CACHE_DIR"))
        n = len(self.calls)
        rows = unifi.syslog("all", self.now - 3 * H, self.now)
        self.assertEqual([r["timestamp"] for r in rows], [self.now - k * H for k in range(4)])  # newest first, inclusive
        fl, trunc = unifi.flows(self.now - 2 * H, self.now)
        self.assertEqual((len(fl), trunc), (3, False))
        self.assertEqual(unifi.legacy("stat/sta")[0]["mac"], "aa")
        self.assertEqual(len(self.calls), n, "served from the store")
        unifi.syslog("all", self.now - 40 * 86400_000, self.now)  # before the cached window: live call
        self.assertEqual(self.calls[-1][0], "syslog")

    def test_refresh_fetches_tail_dedups_trims_and_caps(self):
        """A refresh only fetches the tail, merges rows by id, drops rows past the retention, keeps the newest MAX_ROWS
        (the window start follows), and a stale current-state doc is re-fetched after LEGACY_TTL.
        REQ: STO-16"""
        def fetch(a, b):
            return unifi._syslog_raw("all", a, b), False
        unifi._refresh("syslog-all", "timestamp", fetch, 33 * 86400_000, self.now)
        self.calls.clear()
        c = unifi._refresh("syslog-all", "timestamp", fetch, 33 * 86400_000, self.now + 1000)
        self.assertEqual(self.calls[0][2], self.now + 1000 - 180_000 - 1000)  # tail only (from the cached end - 3 min)
        self.assertEqual(c["rows"], 11)  # same ids: no duplicates
        unifi.MAX_ROWS = 4
        c = unifi._refresh("syslog-all", "timestamp", fetch, 33 * 86400_000, self.now + 2000)
        self.assertEqual(c["rows"], 4)
        self.assertEqual(c["from"], self.now - 3 * H)
        c = unifi._refresh("flows", "time", unifi._flows_raw, 2 * H, self.now)
        self.assertEqual(c["rows"], 3)  # retention
        unifi._csave("legacy-stat/sta", {"at": time.time() - unifi.LEGACY_TTL - 5, "data": [{"mac": "old"}]})
        self.assertNotEqual(unifi.legacy("stat/sta")[0]["mac"], "old")
        self.assertEqual(self.calls[-1], ("legacy", "stat/sta"))

    def test_reader_sees_one_consistent_commit(self):
        """A reader in a read transaction keeps seeing the window and rows of one commit while the pre-warm writes (WAL).
        REQ: STO-16"""
        unifi.prewarm()
        r = sqlite3.connect(os.environ["NETMON_DB"], isolation_level=None)
        r.execute("BEGIN")
        w0 = r.execute("SELECT t_to FROM unifi_streams WHERE stream='flows'").fetchone()[0]
        n0 = r.execute("SELECT COUNT(*) FROM unifi_rows WHERE stream='flows'").fetchone()[0]
        store.unifi_write("flows", [{"id": "new", "time": self.now + 5}], "time", self.now - 5 * H, self.now + 10, self.now - 5 * H, 100)
        self.assertEqual(r.execute("SELECT t_to FROM unifi_streams WHERE stream='flows'").fetchone()[0], w0)
        self.assertEqual(r.execute("SELECT COUNT(*) FROM unifi_rows WHERE stream='flows'").fetchone()[0], n0)
        r.execute("COMMIT")
        self.assertEqual(r.execute("SELECT COUNT(*) FROM unifi_rows WHERE stream='flows'").fetchone()[0], n0 + 1)
        r.close()

    def test_retired_cache_dir_is_blocked(self):
        """The ship gate flags the retired data/unifi_cache directory on disk and any source that names it again; the
        repo itself is clean.
        REQ: STO-16"""
        self.assertEqual(store.retired_check(disk=False), [])
        root = os.path.join(self.tmp, "repo")
        os.makedirs(os.path.join(root, "data", "unifi_cache"))
        with open(os.path.join(root, "x.py"), "w") as f:
            f.write("CACHE = 'data/unifi_cache'\n")
        bad = store.retired_check(root)
        self.assertTrue(any("exists" in b for b in bad))
        self.assertTrue(any(b.startswith("x.py") for b in bad))


if __name__ == "__main__":
    unittest.main()
