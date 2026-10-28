"""Unit tests for the UniFi on-disk cache (unifi.py): controller credentials are redacted, files are owner-only."""
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); import _env  # noqa: E401,E402

import json  # noqa: E402
import shutil  # noqa: E402
import stat  # noqa: E402
import tempfile  # noqa: E402
import unittest  # noqa: E402

import unifi  # noqa: E402

SETTINGS = [
    {"key": "mgmt", "x_api_token": "tok-123", "x_mgmt_key": "abcd", "x_ssh_password": "pw", "x_ssh_sha512passwd": "$6$x",
     "x_ssh_enabled": True, "x_ssh_keys": []},
    {"key": "magic_site_to_site_vpn", "public_key": "pub", "x_private_key": "wg-secret-9"},
    {"key": "ips", "ips_mode": "ips", "utm_token": "u", "enabled_categories": ["a"]},
    {"key": "connectivity", "x_mesh_psk": "m", "nested": [{"radius_secret": "r", "x_passphrase": "p"}]},
]
SECRETS = ("tok-123", "abcd", "\"pw\"", "$6$x", "wg-secret-9", "\"u\"", "\"m\"", "\"r\"", "\"p\"")


class UnifiCache(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="unifi-", dir=_env.TMP)
        self.old = unifi.CACHE_DIR
        unifi.CACHE_DIR = os.path.join(self.tmp, "unifi_cache")

    def tearDown(self):
        unifi.CACHE_DIR = self.old
        shutil.rmtree(self.tmp, True)

    def test_settings_cache_has_no_credentials(self):
        """Every write of a legacy (settings) cache blanks controller credentials but keeps what netmon reads.
        REQ: SEC-06"""
        unifi._csave("legacy-get/setting", {"at": 1, "data": SETTINGS})  # the prewarm() path: raw data straight in
        raw = open(unifi._cpath("legacy-get/setting")).read()
        for s in SECRETS:
            self.assertNotIn(s, raw)
        st = {s["key"]: s for s in json.loads(raw)["data"]}
        self.assertEqual(st["ips"]["ips_mode"], "ips")
        self.assertEqual(st["mgmt"]["x_ssh_enabled"], True)
        self.assertEqual(st["magic_site_to_site_vpn"]["public_key"], "pub")
        self.assertEqual(st["mgmt"]["x_api_token"], "[redacted]")

    def test_cache_is_owner_only(self):
        """The cache directory is 0700 and its files 0600 (it holds inventory and logs).
        REQ: SEC-06"""
        unifi._csave("flows", {"rows": []})
        self.assertEqual(stat.S_IMODE(os.stat(unifi.CACHE_DIR).st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(os.stat(unifi._cpath("flows")).st_mode), 0o600)


if __name__ == "__main__":
    unittest.main()
