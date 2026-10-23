"""E2E: role-based access control and the audit trail, exercised through the real server.

Accounts of each role are created through the admin API (as an admin would on More > Dashboard users).
"""
import json
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import _env  # noqa: E402,F401
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness  # noqa: E402

SRV = None
PW = "role-test-password-1"
SEED = """
import fixtures, store
fixtures.seed_snapshot()
store.alerts_add([fixtures.alert("kid phone contacted a threat-listed IP", key="t|kid", targets=["host:kidphone"]),
                  fixtures.alert("lab server brute force", key="t|lab", targets=["host:labserver"])], source="unifi")
"""


def setUpModule():
    global SRV
    SRV = harness.Server(seed=SEED).__enter__()
    a = SRV.login()
    for name, role in (("e2e-defender", "defender"), ("e2e-user", "user"), ("e2e-admin2", "admin")):
        code, body, _ = a.post("/api/users", {"action": "add", "username": name, "password": PW, "role": role})
        assert code == 200, (name, code, body)
    code, body, _ = a.post("/api/users", {"action": "devices", "username": "e2e-user", "mode": "some", "devices": ["host:kidphone"]})
    assert code == 200, body


def tearDownModule():
    if SRV:
        SRV.__exit__(None, None, None)


def as_(name):
    return SRV.login(name, PW)


class RoleMatrix(unittest.TestCase):
    """What each role may read and change."""

    def test_roles_reported(self):
        """/api/me reports each account's role and its display name.
        REQ: AC-02"""
        self.assertEqual(as_("e2e-defender").get("/api/me")[1]["role_name"], "Network defender")
        self.assertEqual(as_("e2e-user").get("/api/me")[1]["role"], "user")

    def test_user_limited_to_allow_list_get(self):
        """A User gets 403 on every data API outside USER_GET, and 200 on the allowed ones.
        REQ: AC-03, AC-06"""
        u = as_("e2e-user")
        for p in ("/api/snapshots", "/api/snapshot?id=latest", "/api/risk", "/api/correlate", "/api/users", "/api/audit",
                  "/api/config/cfg", "/api/kb/all", "/api/events/open", "/api/mitre", "/api/lateral"):
            self.assertEqual(u.get(p)[0], 403, p)
        for p in ("/api/me", "/api/account", "/api/site", "/api/alerts", "/api/push/prefs", "/api/my", "/api/tuning"):
            self.assertEqual(u.get(p)[0], 200, p)

    def test_user_limited_to_allow_list_post(self):
        """A User cannot check items off, chat, manage users or change config (403).
        REQ: AC-03"""
        u = as_("e2e-user")
        for p, b in (("/api/acks", {"type": "issue", "key": "x", "checked": True}), ("/api/chat", {"action": "list"}),
                     ("/api/users", {"action": "add", "username": "evil1", "password": PW}), ("/api/config/cfg", {}),
                     ("/api/aireview", {}), ("/api/suppress", {})):
            self.assertEqual(u.post(p, b)[0], 403, p)

    def test_user_page_html_still_loads(self):
        """A User can load the app shell (the page itself decides which views to show).
        REQ: AC-03, DASH-01"""
        self.assertEqual(as_("e2e-user").get("/")[0], 200)

    def test_defender_reads_everything(self):
        """A Network defender can read the data, users and settings views.
        REQ: AC-04"""
        d = as_("e2e-defender")
        for p in ("/api/snapshots", "/api/risk", "/api/correlate", "/api/users", "/api/config/cfg", "/api/kb/all"):
            self.assertEqual(d.get(p)[0], 200, p)

    def test_defender_cannot_change_settings(self):
        """Every admin-only POST (users, config, AI models/providers) returns 403 for a defender and changes nothing.
        REQ: AC-04, AC-08"""
        d = as_("e2e-defender")
        for p, b in (("/api/users", {"action": "add", "username": "sneaky", "password": PW, "role": "admin"}),
                     ("/api/users", {"action": "role", "username": "e2e-defender", "role": "admin"}),
                     ("/api/config/cfg", {"doc": "site", "path": ["site_name"], "value": "x"}),
                     ("/api/llm/config", {}), ("/api/llm/providers", {}), ("/api/config/integrations/es", {})):
            self.assertEqual(d.post(p, b)[0], 403, p)
        names = {u["username"] for u in SRV.login().get("/api/users")[1]["users"]}
        self.assertNotIn("sneaky", names)
        self.assertEqual(d.get("/api/me")[1]["role"], "defender")

    def test_defender_can_do_analyst_work(self):
        """A defender may check items off (analyst work is not a setting).
        REQ: AC-04, DASH-05"""
        d = as_("e2e-defender")
        self.assertEqual(d.post("/api/acks", {"type": "issue", "key": "def|work", "checked": True})[0], 200)

    def test_audit_log_admin_only(self):
        """The audit log page data is admin-only.
        REQ: AC-04, AUD-01"""
        self.assertEqual(as_("e2e-defender").get("/api/audit/status")[0], 403)
        self.assertEqual(SRV.login().get("/api/audit/status")[0], 200)


class UserScope(unittest.TestCase):
    """A User only ever sees their assigned devices."""

    def test_user_sees_only_assigned_device_alerts(self):
        """The alert feed of a User contains the alert for their device and not the other one.
        REQ: AC-06, STO-07"""
        rows = as_("e2e-user").get("/api/alerts")[1]["alerts"]
        keys = {r["key"] for r in rows}
        self.assertIn("t|kid", keys)
        self.assertNotIn("t|lab", keys)

    def test_admin_sees_all_alerts(self):
        """An admin's feed has both alerts.
        REQ: AC-06"""
        keys = {r["key"] for r in SRV.login().get("/api/alerts?limit=500")[1]["alerts"]}
        self.assertTrue({"t|kid", "t|lab"} <= keys)

    def test_user_site_config_reduced(self):
        """The site config a User receives has the site name but no IP hints, prefixes or admin workstations.
        REQ: AC-06, CFG-01"""
        s = as_("e2e-user").get("/api/site")[1]
        self.assertIn("site_name", s)
        for k in ("internal_prefixes", "host_ips", "admin_workstations", "honeypot_ips", "sensor_ip"):
            self.assertNotIn(k, s)
        self.assertIn("internal_prefixes", SRV.login().get("/api/site")[1])

    def test_user_device_prefs_locked(self):
        """A User's notification settings are locked to the devices an admin assigned.
        REQ: AC-06, STO-07"""
        b = as_("e2e-user").get("/api/push/prefs")[1]
        self.assertTrue(b["locked"])
        self.assertEqual(b["prefs"], {"mode": "some", "devices": ["host:kidphone"]})

    def test_user_cannot_be_given_all_devices(self):
        """Assigning 'All devices' to a User is refused.
        REQ: AC-06"""
        code, body, _ = SRV.login().post("/api/users", {"action": "devices", "username": "e2e-user", "mode": "all"})
        self.assertEqual(code, 400)
        self.assertIn("User", body["error"])

    def test_user_read_marker_is_private(self):
        """A User marking all read does not clear the shared bell of admins.
        REQ: AC-07"""
        a = SRV.login()
        before = a.get("/api/alerts?limit=500")[1]["unread"]
        u = as_("e2e-user")
        self.assertEqual(u.post("/api/alerts/read", {"all": True})[0], 200)
        self.assertEqual(u.get("/api/alerts")[1]["unread"], 0)
        self.assertEqual(a.get("/api/alerts?limit=500")[1]["unread"], before)


class UserAdmin(unittest.TestCase):
    """Admin user management and its safety rules."""

    def test_add_user_validation(self):
        """Short passwords, bad names, unknown roles and duplicates are rejected.
        REQ: AUTH-02, AUTH-03, AC-08"""
        a = SRV.login()
        for b in ({"username": "ok-name", "password": "short"}, {"username": "bad name!", "password": PW},
                  {"username": "ok-name2", "password": PW, "role": "root"}, {"username": "e2e-user", "password": PW}):
            self.assertEqual(a.post("/api/users", dict(b, action="add"))[0], 400, b)

    def test_default_role_is_user(self):
        """A user added without a role gets the least privilege (User).
        REQ: AC-02, AC-08"""
        a = SRV.login()
        a.post("/api/users", {"action": "add", "username": "e2e-default", "password": PW})
        self.assertEqual(as_("e2e-default").get("/api/me")[1]["role"], "user")

    def test_role_change_applies_on_next_request(self):
        """Promoting an account takes effect on its very next request, without signing in again.
        REQ: AC-08"""
        a = SRV.login()
        a.post("/api/users", {"action": "add", "username": "e2e-promote", "password": PW, "role": "user"})
        s = as_("e2e-promote")
        self.assertEqual(s.get("/api/risk")[0], 403)
        self.assertEqual(a.post("/api/users", {"action": "role", "username": "e2e-promote", "role": "defender"})[0], 200)
        self.assertEqual(s.get("/api/risk")[0], 200)

    def test_admin_cannot_demote_self(self):
        """An admin trying to demote themself is refused.
        REQ: AC-05"""
        a = as_("e2e-admin2")
        code, body, _ = a.post("/api/users", {"action": "role", "username": "e2e-admin2", "role": "user"})
        self.assertEqual(code, 400)
        self.assertEqual(a.get("/api/me")[1]["role"], "admin")

    def test_delete_user_revokes_access(self):
        """Deleting an account ends its existing session.
        REQ: AC-08, AUTH-04"""
        a = SRV.login()
        a.post("/api/users", {"action": "add", "username": "e2e-delete", "password": PW, "role": "defender"})
        s = as_("e2e-delete")
        self.assertEqual(a.post("/api/users", {"action": "delete", "username": "e2e-delete"})[0], 200)
        self.assertEqual(s.get("/api/me")[0], 401)

    def test_admin_password_reset(self):
        """An admin can reset another account's password; the old one stops working.
        REQ: AC-08, AUTH-01"""
        a = SRV.login()
        a.post("/api/users", {"action": "add", "username": "e2e-reset", "password": PW, "role": "user"})
        self.assertEqual(a.post("/api/users", {"action": "password", "username": "e2e-reset", "password": "brand-new-password-7"})[0], 200)
        c = SRV.client()
        self.assertEqual(c.post("/api/login", {"username": "e2e-reset", "password": PW}, headers={"CF-Connecting-IP": "10.202.0.1"})[0], 401)
        self.assertEqual(SRV.login("e2e-reset", "brand-new-password-7").get("/api/me")[0], 200)


class AuditTrail(unittest.TestCase):
    """Audit entries are written (spooled, as no Elasticsearch is configured) with secrets redacted."""

    def _entries(self, pred, wait=15):
        spool = os.path.join(SRV.state, "audit_spool.jsonl")
        end = time.time() + wait
        while time.time() < end:
            rows = []
            for f in (spool, spool + ".sending"):
                if os.path.exists(f):
                    with open(f) as fh:
                        rows += [json.loads(x) for x in fh if x.strip()]
            hit = [r for r in rows if pred(r)]
            if hit:
                return hit, rows
            time.sleep(0.5)
        return [], rows

    def test_user_add_audited_without_password(self):
        """Adding a user is audited with the actor and outcome, and the password never appears in the log.
        REQ: AUD-01, AUD-03"""
        secret = "audit-secret-password-42"
        SRV.login().post("/api/users", {"action": "add", "username": "e2e-audited", "password": secret, "role": "user"})
        hit, rows = self._entries(lambda r: "e2e-audited" in json.dumps(r))
        self.assertTrue(hit, f"no audit entry; {len(rows)} spooled")
        self.assertNotIn(secret, "".join(json.dumps(r) for r in rows))

    def test_failed_login_audited(self):
        """A failed sign-in is audited as a failure.
        REQ: AUD-02"""
        c = SRV.client()
        c.post("/api/login", {"username": "e2e-ghost", "password": "wrong-password-xx"}, headers={"CF-Connecting-IP": "10.203.0.1"})
        hit, _ = self._entries(lambda r: "e2e-ghost" in json.dumps(r))
        self.assertTrue(hit)
        self.assertIn("failure", json.dumps(hit[0]))

    def test_denied_request_audited(self):
        """A request refused with 403 is audited as access denied.
        REQ: AUD-02, AC-03"""
        as_("e2e-user").get("/api/users")
        hit, _ = self._entries(lambda r: "e2e-user" in json.dumps(r) and "denied" in json.dumps(r))
        self.assertTrue(hit)

    def test_spool_file_owner_only(self):
        """The audit spool file is created owner-only (0600).
        REQ: AUD-03, SEC-06"""
        self._entries(lambda r: True)
        spool = os.path.join(SRV.state, "audit_spool.jsonl")
        if not os.path.exists(spool):
            self.skipTest("spool already rotated to .sending")
        self.assertEqual(os.stat(spool).st_mode & 0o077, 0)

    def test_state_db_owner_only(self):
        """The server's SQLite state DB is owner-only (0600).
        REQ: SEC-06"""
        self.assertEqual(os.stat(os.path.join(SRV.state, "netmon.db")).st_mode & 0o077, 0)


if __name__ == "__main__":
    unittest.main()
