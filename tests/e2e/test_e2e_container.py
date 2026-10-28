"""E2E (deployed): read-only checks of the RUNNING netmon-dashboard container.

Skipped automatically when docker or the container is not available. Only runs `docker inspect` and fetches the
public /healthz and /login pages plus one unauthenticated API call that must be refused - nothing is changed.
"""
import http.client
import json
import os
import shutil
import ssl
import subprocess
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import _env  # noqa: E402,F401

NAME = os.environ.get("NETMON_CONTAINER", "netmon-dashboard")
PORT = int(os.environ.get("NETMON_LIVE_PORT", "8443"))


def inspect():
    if not shutil.which("docker"):
        return None
    r = subprocess.run(["docker", "inspect", NAME], capture_output=True, text=True, timeout=20)
    return json.loads(r.stdout)[0] if r.returncode == 0 else None


INFO = inspect()


def get(path):
    ctx = ssl.create_default_context()
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    c = http.client.HTTPSConnection("127.0.0.1", PORT, context=ctx, timeout=10)
    c.request("GET", path)
    r = c.getresponse()
    body = r.read()
    c.close()
    return r.status, body, {k.lower(): v for k, v in r.getheaders()}


@unittest.skipUnless(INFO and INFO["State"]["Running"], f"container {NAME} not running here")
class DeployedContainer(unittest.TestCase):
    """Hardening and health of the deployed dashboard container."""

    def test_read_only_root_fs(self):
        """The container's root filesystem is read-only.
        REQ: OPS-02"""
        self.assertTrue(INFO["HostConfig"]["ReadonlyRootfs"])

    def test_runs_as_non_root(self):
        """The container process runs as a non-root user.
        REQ: OPS-02"""
        user = INFO["Config"]["User"] or "0"
        self.assertNotIn(user.split(":")[0], ("", "0", "root"))

    def test_capabilities_dropped(self):
        """All Linux capabilities are dropped and no-new-privileges is set.
        REQ: OPS-02"""
        self.assertIn("ALL", INFO["HostConfig"]["CapDrop"] or [])
        self.assertIn("no-new-privileges", " ".join(INFO["HostConfig"]["SecurityOpt"] or []))

    def test_health_check_passing(self):
        """Docker reports the container healthy (HEALTHCHECK on /healthz).
        REQ: OPS-02, DASH-04"""
        st = (INFO["State"].get("Health") or {}).get("Status")
        for _ in range(45):  # a ship right after a redeploy finds it still "starting" (first probe after ~60 s)
            if st != "starting":
                break
            time.sleep(2)
            st = (inspect()["State"].get("Health") or {}).get("Status")
        self.assertEqual(st, "healthy")

    def test_live_healthz_and_auth_wall(self):
        """The live dashboard answers /healthz, serves the login page and refuses the API without a session.
        REQ: DASH-04, AC-01, SEC-01"""
        try:
            code, body, h = get("/healthz")
        except OSError as e:
            self.skipTest(f"dashboard port {PORT} not reachable: {e}")
        self.assertEqual((code, body), (200, b"ok"))
        self.assertEqual(h.get("x-frame-options"), "DENY")
        self.assertEqual(get("/login")[0], 200)
        self.assertEqual(get("/api/snapshots")[0], 401)


if __name__ == "__main__":
    unittest.main()
