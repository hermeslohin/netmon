"""E2E: the Alerts page API (#/alerts) through the real server - the feed and its query parameters, read markers, the
my-devices filter, held detections with verdicts, legacy mute rules and the cleared view, for admin, defender and user.

One server process for the module. The seed stores alarms, watcher detections, alerts a legacy mute rule cleared and one a
suppress rule hid, two registry devices, and AI verdicts on two alerts. Tests that change state only touch their own rows.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import _env  # noqa: E402,F401
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness  # noqa: E402
import fixtures as F  # noqa: E402

IP, EXT = F.IPS, F.EXT
PW = "alerts-test-password-1"
SRV = None
SEED = r'''
import time, fixtures as F, store, corr_llm
IP, EXT = F.IPS, F.EXT
store.registry_save({F.mac(1): {"mac": F.mac(1), "name": "laptop", "ips": [IP["laptop"]], "known": 1},
                     F.mac(5): {"mac": F.mac(5), "name": "phone", "ips": [IP["phone"]], "known": 1}})
c = store._dc()
with store.tx(c):  # legacy "never send" mute rules, as an older version saved them (creating them is no longer possible)
    for n in ("legacy beacon*", "legacy scan*"):
        c.execute("INSERT INTO alert_mutes(name,host,by,at,limit_key) VALUES (?,?,?,?,?)", (n, "", "old-admin", time.time(), ""))
store.suppress_add("noisy printer", "", "", "seed")
store.alerts_add([("a|lap1", "Beacon from %s to %s" % (IP["laptop"], EXT["bad"]), "investigate"),
                  ("a|ph1", "Odd DNS from %s" % IP["phone"], "urgent"),
                  ("a|gen", "Feed lag with no device", "urgent"),
                  ("a|mut1", "legacy beacon to %s from %s" % (EXT["bad"], IP["laptop"]), "urgent"),
                  ("a|mut2", "legacy scan of %s" % IP["server"], "urgent"),
                  ("a|sup", "noisy printer %s" % IP["camera"], "urgent")], source="corr")
store.alerts_add([("w|1", "IDS: ET MALWARE Test - %s -> %s" % (IP["laptop"], EXT["bad"]), "investigate"),
                  ("w|2", "New device active: 10.0.7.7 made 30 connections - never seen before", "urgent")], source="watcher")
ids = {r["key"]: r["id"] for r in c.execute("SELECT id, key FROM alerts")}
with corr_llm._db() as cc:
    for k, label, why in (("w|1", "benign", "Known scanner."), ("a|lap1", "suspicious", "Beacon to a listed IP.")):
        cc.execute("INSERT OR REPLACE INTO event_class (eid, label, confidence, reason, model, sig, ts) VALUES (?,?,?,?,?,?,?)", ("alert|%d" % ids[k], label, 0.8, why, "test-model", "s", time.time()))
'''


def setUpModule():
    global SRV
    SRV = harness.Server(seed=SEED).__enter__()
    a = SRV.login()
    for name, role in (("alr-defender", "defender"), ("alr-user", "user")):
        code, body, _ = a.post("/api/users", {"action": "add", "username": name, "password": PW, "role": role})
        if code != 200:
            raise RuntimeError(f"add {name}: {code} {body}")
    code, body, _ = a.post("/api/users", {"action": "devices", "username": "alr-user", "mode": "some", "devices": [F.mac(5)]})
    if code != 200:
        raise RuntimeError(f"assign devices: {code} {body}")


def tearDownModule():
    if SRV:
        SRV.__exit__(None, None, None)


def as_(name):
    return SRV.login(name, PW)


def keys(body):
    return [r["key"] for r in body["alerts"]]


class AlertsApi(unittest.TestCase):
    """GET /api/alerts, /api/alerts/mutes and POST /api/alerts/read and /api/alerts/mutes by role."""

    @classmethod
    def setUpClass(cls):
        cls.admin, cls.defender, cls.user = SRV.login(), as_("alr-defender"), as_("alr-user")

    def get(self, c, path, code=200):
        st, body, _ = c.get(path)
        self.assertEqual(st, code, body)
        return body

    def test_feed_order_limit_and_hidden_rows(self):
        """The feed is newest first and leaves out held detections, mute-cleared and suppressed alerts; limit is clamped to 1..2000.
        REQ: ALR-01"""
        b = self.get(self.admin, "/api/alerts?limit=200")
        k = [x for x in keys(b) if x in ("a|gen", "a|ph1", "a|lap1")]
        self.assertEqual(k, ["a|gen", "a|ph1", "a|lap1"])
        self.assertFalse({"w|1", "w|2", "a|mut2", "a|sup"} & set(keys(b)))
        self.assertEqual(b["mode"], "all")
        self.assertTrue(all(r["mine"] for r in b["alerts"]))
        self.assertIsNone(b["extra"])
        self.assertEqual(b["unread"], sum(1 for r in b["alerts"] if not r["read"]))
        self.assertEqual(len(self.get(self.admin, "/api/alerts?limit=0")["alerts"]), 1)
        self.assertEqual(len(self.get(self.admin, "/api/alerts?limit=1")["alerts"]), 1)
        self.assertEqual(keys(self.get(self.admin, "/api/alerts?limit=99999")), keys(b))
        self.assertEqual(keys(self.get(self.admin, "/api/alerts")), keys(b))

    def test_only_my_devices_for_admin_and_defender(self):
        """An admin or defender who chose devices still gets every alert, flagged mine only for their devices, with unread_mine and mode some.
        REQ: ALR-02"""
        c = as_("alr-defender")
        st, body, _ = c.post("/api/push/prefs", {"mode": "some", "devices": [F.mac(1)]})
        self.assertEqual(st, 200, body)
        try:
            b = self.get(c, "/api/alerts?limit=200")
            mine = {r["key"]: r["mine"] for r in b["alerts"]}
            self.assertEqual(b["mode"], "some")
            self.assertTrue(mine["a|lap1"])
            self.assertFalse(mine["a|ph1"] or mine["a|gen"], "an alert without a device goes only to people watching all devices")
            self.assertEqual(b["unread_mine"], sum(1 for r in b["alerts"] if r["mine"] and not r["read"]))
            st, body, _ = c.post("/api/push/prefs", {"mode": "some", "devices": []})
            self.assertEqual((st, body.get("error")), (400, "pick at least one device, or choose All devices"))
        finally:
            c.post("/api/push/prefs", {"mode": "all", "devices": []})

    def test_user_sees_only_assigned_devices_and_no_extras(self):
        """A User gets only their devices' alarms; cleared=1 and held=1 are ignored for them and mute rules are refused.
        REQ: ALR-02, ALR-05, ALR-07"""
        b = self.get(self.user, "/api/alerts?limit=200")
        self.assertEqual([k for k in keys(b) if not k.startswith("a|new")], ["a|ph1"])  # a|new*: added on the phone by the read test
        self.assertEqual(b["mode"], "some")
        self.assertTrue(all(r["mine"] for r in b["alerts"]))
        self.assertEqual(b["unread"], b["unread_mine"])
        for q in ("cleared=1", "held=1", "held=1&v=benign", "extra=1"):
            with self.subTest(q=q):
                r = self.get(self.user, "/api/alerts?" + q)
                self.assertNotIn("cleared", r)
                self.assertNotIn("counts", r)
                self.assertFalse({"a|mut1", "a|mut2", "a|sup", "w|1", "w|2", "a|lap1"} & set(keys(r)))
        self.get(self.user, "/api/alerts/mutes", 403)
        st, _, _ = self.user.post("/api/alerts/mutes", {"action": "remove", "id": 1})
        self.assertEqual(st, 403)

    def test_extra_adds_verdicts(self):
        """extra=1 adds each alarm's event id, verdict and its source, and the research extras keyed by event id.
        REQ: ALR-03"""
        for c in (self.admin, self.defender):
            b = self.get(c, "/api/alerts?limit=200&extra=1")
            row = {r["key"]: r for r in b["alerts"]}
            lap = row["a|lap1"]
            self.assertEqual(lap["eid"], f"alert|{lap['id']}")
            self.assertEqual((lap["verdict"], lap["vsrc"]), ("suspicious", "ai"))
            self.assertEqual((row["a|gen"]["verdict"], row["a|gen"]["vsrc"]), ("unreviewed", ""))
            self.assertEqual(b["extra"]["classes"][lap["eid"]]["label"], "suspicious")

    def test_held_detections_and_verdict_filter(self):
        """held=1 lists the watcher's held detections newest first with verdict counts for detections and alarms; v= filters, an unknown v is ignored.
        REQ: ALR-04"""
        for c in (self.admin, self.defender):
            d = self.get(c, "/api/alerts?held=1&limit=200")
            self.assertEqual(keys(d), ["w|2", "w|1"])
            self.assertEqual((d["total"], d["matching"]), (2, 2))
            self.assertEqual(d["counts"]["detections"], {"benign": 1, "unreviewed": 1})
            self.assertEqual(d["counts"]["alarms"].get("suspicious"), 1)
            self.assertEqual([(r["verdict"], r["mine"]) for r in d["alerts"]], [("unreviewed", True), ("benign", True)])
            b = self.get(c, "/api/alerts?held=1&v=benign")
            self.assertEqual((keys(b), b["matching"], b["total"]), (["w|1"], 1, 2))
            self.assertEqual(self.get(c, "/api/alerts?held=1&v=unreviewed")["matching"], 1)
            self.assertEqual(self.get(c, "/api/alerts?held=1&v=suspicious")["alerts"], [])
            self.assertEqual(self.get(c, "/api/alerts?held=1&v=bogus")["matching"], 2)
            self.assertEqual(len(self.get(c, "/api/alerts?held=1&limit=1")["alerts"]), 1)

    def test_cleared_view_names_the_mute_rule(self):
        """cleared=1 lists the alerts a legacy mute rule cleared, newest first, each with the rule that cleared it.
        REQ: ALR-05"""
        for c in (self.admin, self.defender):
            b = self.get(c, "/api/alerts?cleared=1&limit=500")
            self.assertTrue(b["cleared"])
            rule = {r["key"]: r["rule"] for r in b["alerts"]}
            self.assertEqual(rule["a|mut2"], "legacy scan*")
            if "a|mut1" in rule:  # restored if the remove test already ran
                self.assertEqual(rule["a|mut1"], "legacy beacon*")
            self.assertFalse({"a|gen", "w|1"} & set(rule))

    def test_cleared_view_does_not_call_a_suppressed_alert_rule_removed(self):
        """An alert hidden by a suppress rule that still exists is not shown in the mute-cleared view as cleared by a removed rule.
        REQ: ALR-05"""
        b = self.get(self.admin, "/api/alerts?cleared=1&limit=500")
        self.assertNotIn(("a|sup", "(rule removed)"), [(r["key"], r["rule"]) for r in b["alerts"]])

    def test_mute_rules_list(self):
        """Admins and defenders get the legacy mute rules with how many alerts each cleared.
        REQ: ALR-07"""
        for c in (self.admin, self.defender):
            m = {r["name"]: r for r in self.get(c, "/api/alerts/mutes")["mutes"]}
            self.assertEqual(m["legacy scan*"]["cleared"], 1)
            self.assertEqual((m["legacy scan*"]["host"], m["legacy scan*"]["by"]), ("", "old-admin"))
            if "legacy beacon*" in m:
                self.assertEqual(m["legacy beacon*"]["cleared"], 1)

    def test_mute_rule_remove_restores_alerts(self):
        """Only remove is accepted; an unknown rule is 404; removing a rule (as a defender) brings its alert back into the feed as read.
        REQ: ALR-08, ALR-09"""
        st, body, _ = self.defender.post("/api/alerts/mutes", {"action": "add", "name": "anything*"})
        self.assertEqual((st, body.get("error")), (400, "action must be remove"))
        st, body, _ = self.defender.post("/api/alerts/mutes", {"action": "remove", "id": 99999})
        self.assertEqual((st, body.get("error")), (404, "no such mute rule"))
        rid = next(r["id"] for r in self.get(self.admin, "/api/alerts/mutes")["mutes"] if r["name"] == "legacy beacon*")
        st, body, _ = self.defender.post("/api/alerts/mutes", {"action": "remove", "id": rid})
        self.assertEqual((st, body), (200, {"ok": True, "restored": 1}))
        self.assertNotIn(rid, [r["id"] for r in self.get(self.admin, "/api/alerts/mutes")["mutes"]])
        feed = {r["key"]: r for r in self.get(self.admin, "/api/alerts?limit=200")["alerts"]}
        self.assertIn("a|mut1", feed)
        self.assertEqual(feed["a|mut1"]["read"], 1)
        self.assertNotIn("a|mut1", keys(self.get(self.admin, "/api/alerts?cleared=1")))
        st, _, _ = self.defender.post("/api/alerts/mutes", {"action": "remove", "id": rid})
        self.assertEqual(st, 404)

    def test_mute_remove_bad_id_is_a_client_error(self):
        """A non-numeric mute rule id is a 400 bad request, not a 500 server error.
        REQ: ALR-08"""
        st, _, _ = self.admin.post("/api/alerts/mutes", {"action": "remove", "id": "x"})
        self.assertEqual(st, 400)

    def test_bad_limit_is_a_client_error(self):
        """A non-numeric limit on the feed is a 400 bad request, not a 500 server error.
        REQ: ALR-01"""
        st, _, _ = self.admin.get("/api/alerts?limit=abc")
        self.assertEqual(st, 400)

    def test_read_markers_per_role(self):
        """A User's mark-read is private (others still see the alert unread); an admin or defender marks every alert read for everyone.
        REQ: ALR-06, ALR-20"""
        SRV.run_py("import fixtures as F, store\nstore.alerts_add([('a|new', 'New thing on %s' % F.IPS['phone'], 'urgent')], source='corr')")
        u = self.get(self.user, "/api/alerts")
        self.assertEqual({r["key"]: r["read"] for r in u["alerts"]}.get("a|new"), 0)
        self.assertGreaterEqual(u["unread"], 1)
        st, body, _ = self.user.post("/api/alerts/read", {})
        self.assertEqual((st, body), (200, {"ok": True}))
        u = self.get(self.user, "/api/alerts")
        self.assertEqual((u["unread"], u["unread_mine"]), (0, 0))
        a = self.get(self.admin, "/api/alerts?limit=200")
        self.assertEqual({r["key"]: r["read"] for r in a["alerts"]}["a|new"], 0, "the User's marker is private")
        self.assertGreaterEqual(a["unread"], 1)
        st, _, _ = self.defender.post("/api/alerts/read", {})
        self.assertEqual(st, 200)
        a = self.get(self.admin, "/api/alerts?limit=200")
        self.assertEqual((a["unread"], a["unread_mine"]), (0, 0))
        self.assertTrue(all(r["read"] for r in a["alerts"]))
        SRV.run_py("import fixtures as F, store\nstore.alerts_add([('a|new2', 'Another on %s' % F.IPS['phone'], 'urgent')], source='corr')")
        self.assertEqual(self.get(self.user, "/api/alerts")["unread"], 1, "a newer alert is unread for the User again")

    def test_page_and_script_served(self):
        """Every role can load the alerts page script; anonymous requests to the feed are refused.
        REQ: ALR-20"""
        for c in (self.admin, self.defender, self.user):
            st, js, _ = c.get("/alerts.js")
            self.assertEqual(st, 200)
            self.assertIn("V.alerts", js)
        st, _, _ = SRV.client().get("/api/alerts")
        self.assertEqual(st, 401)


if __name__ == "__main__":
    unittest.main()
