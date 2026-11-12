"""Plain-language alerts for the User role (dashboard/app/plainmsg.py) and alarm lifetime in corr_llm.sync_alarms."""
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); import _env  # noqa: E401,E702,E402

import time  # noqa: E402
import unittest  # noqa: E402
from unittest import mock  # noqa: E402

import auth  # noqa: E402
import corr_llm  # noqa: E402
import plainmsg  # noqa: E402
import pushsvc  # noqa: E402
import store  # noqa: E402
from fixtures import mac, IPS  # noqa: E402

ICU = "ids|ET INFO DNS Query for Suspicious .icu Domain"
ICU_TEXT = "IDS: ET INFO DNS Query for Suspicious .icu Domain x1 - AI review: suspicious (While the specific .icu domain was not captured)"


def _reset():
    c = getattr(store._dl, "c", None)
    if c is not None:
        c.close()
    _env.fresh_db()
    store._cfg_cache.clear()
    with corr_llm._db() as c:
        c.execute("DELETE FROM event_class")


def _classify(eid, label):
    with corr_llm._db() as c:
        c.execute("INSERT OR REPLACE INTO event_class (eid, label, confidence, reason, model, sig, ts) VALUES (?,?,?,?,?,?,?)",
                  (eid, label, 0.9, "Verdict: suspicious.", "m", "sig", time.time()))


class TestPlainLine(unittest.TestCase):
    def setUp(self):
        _reset()
        self.reg = {mac(1): {"mac": mac(1), "ips": [IPS["laptop"]], "name": "Kitchen tablet"}}

    def tearDown(self):
        _reset()

    def test_phishing_tld_names_device_without_signature(self):
        """A suspicious-TLD IDS hit reads as a possible phishing / scam site on the named device; no rule name, IP or AI text.
        REQ: AC-09"""
        a = {"key": "ev|" + ICU, "text": ICU_TEXT, "targets": ["ip:" + IPS["laptop"]]}
        s = plainmsg.line(a, self.reg)
        self.assertEqual(s, "Kitchen tablet: possible phishing or scam website visited.")
        for leak in ("ET INFO", ".icu", "AI review", IPS["laptop"]):
            self.assertNotIn(leak, s)

    def test_categories(self):
        """Common alert kinds map to short plain messages; unknown ones get a generic line.
        REQ: AC-09"""
        cases = {"phishing kit landing page": "possible phishing website visited",
                 "newly-registered-domain: X - a.pro registered": "possible phishing or scam website visited",
                 "IDS: ET MALWARE Win32 CnC beacon": "possible malware activity",
                 "IDS: ET SCAN Potential SSH Scan OUTBOUND x3": "this device is scanning other computers (possible infection)",
                 "volume-spike: kube - total 37 MB": "unusually heavy internet use",
                 "New device joined: MAC x": "a new device joined your network",
                 "Host ALERT: Successful ssh/password login as bob": "unusual sign-in activity",
                 "something nobody has seen": "suspicious activity"}
        for text, want in cases.items():
            self.assertEqual(plainmsg.kind({"key": "", "text": text}), want, text)

    def test_no_device_capitalised(self):
        """Without a known device the line is just the capitalised message (never an IP or MAC as a name).
        REQ: AC-09"""
        reg = {mac(2): {"mac": mac(2), "ips": [IPS["server"]], "name": IPS["server"]}}
        self.assertEqual(plainmsg.line({"key": "", "text": "volume-spike", "targets": ["ip:" + IPS["server"]]}, reg),
                         "Unusually heavy internet use.")


class TestUserPush(unittest.TestCase):
    def setUp(self):
        _reset()
        store.jdump({"admin1": {"hash": "x", "role": "admin"}, "user1": {"hash": "x", "role": "user"}}, auth.USERS)
        store.registry_save({mac(1): {"mac": mac(1), "ips": [IPS["laptop"]], "name": "Kitchen tablet"}})
        d = store.cfg_load("site")
        d["push_wait_for_ai"] = False
        store.cfg_save("site", d)
        import site_cfg
        site_cfg._cache = None
        store.prefs_set("user1", "some", [mac(1)])
        for n, u in ((1, "admin1"), (2, "user1")):
            store.push_sub_save({"endpoint": f"https://push.example.invalid/{n}", "keys": {"p256dh": "x", "auth": "y"}}, u)
        self.sent = {}
        p = mock.patch.object(pushsvc, "send", lambda s, pl: (self.sent.__setitem__(s["endpoint"][-1], pl), (True, ""))[1])
        p.start()
        self.addCleanup(p.stop)

    def tearDown(self):
        _reset()

    def _alarm(self):
        store.alerts_add([("ev|" + ICU, ICU_TEXT + f" on {IPS['laptop']}", "urgent")], source="review")

    def test_user_gets_plain_admin_gets_signature(self):
        """The same alarm pushes plain words to a User and the full signature text to an admin.
        REQ: AC-09, STO-07"""
        _classify(ICU, "suspicious")
        self._alarm()
        pushsvc.run_once()
        self.assertIn("ET INFO DNS Query", self.sent["1"]["body"])
        u = self.sent["2"]
        self.assertEqual(u["title"], "Syn: heads up")
        self.assertEqual(u["body"], "Kitchen tablet: possible phishing or scam website visited. Look out - tap for what to do.")


    def test_no_verdict_no_user_push(self):
        """Without a verdict a User gets nothing, even when the admin gets the fail-safe push; the User is pushed once,
        when the suspicious verdict lands later.
        REQ: AC-10"""
        import pushgate
        self._alarm()
        with mock.patch.object(pushgate, "reviewer_down", lambda: "reviewer off"):
            pushsvc.run_once()
        self.assertIn("1", self.sent)
        self.assertNotIn("2", self.sent)
        self.sent.clear()
        pushsvc.run_once()
        self.assertEqual(self.sent, {})
        _classify(ICU, "suspicious")
        pushsvc.run_once()
        self.assertEqual(set(self.sent), {"2"})
        self.sent.clear()
        pushsvc.run_once()
        self.assertEqual(self.sent, {})

    def test_benign_verdict_never_reaches_user(self):
        """A final expected / benign verdict means no push and no Alerts-page row for a User.
        REQ: AC-10"""
        import pushgate
        _classify(ICU, "benign")
        self._alarm()
        with mock.patch.object(pushgate, "reviewer_down", lambda: "reviewer off"):
            pushsvc.run_once()
        self.assertNotIn("2", self.sent)
        rows = store.alerts_recent(10)
        self.assertEqual(pushgate.user_visible(rows), [])
        _classify(ICU, "suspicious")
        self.assertEqual(len(pushgate.user_visible(rows)), 1)

    def test_pending_group_waits(self):
        """A provisional (fast) label is not a verdict: the User waits.
        REQ: AC-10"""
        import json as _j
        import pushgate
        _classify(ICU, "suspicious")
        with corr_llm._db() as c:
            c.execute("UPDATE event_class SET covered=? WHERE eid=?", (_j.dumps({"fast": True}), ICU))
        self._alarm()
        self.assertEqual(pushgate.user_verdict(store.alerts_recent(1)[0])[0], "wait")


class TestAlarmLifetime(unittest.TestCase):
    """An alarm stays in the feed when its event only ages out of the snapshot; it goes when the review withdraws it."""

    def setUp(self):
        _reset()

    def tearDown(self):
        _reset()

    def _feed(self):
        return [a["key"] for a in store.alerts_recent(50)]

    def test_aged_out_event_keeps_alarm(self):
        """Suspicious medium event -> alarm; event leaves the snapshot -> alarm stays; label turns benign -> alarm goes.
        REQ: STO-06"""
        _classify(ICU, "suspicious")
        ev = {ICU: {"label": "IDS: x", "sev": "medium", "ips": [IPS["laptop"]]}}
        corr_llm.sync_alarms({"events": ev})
        self.assertEqual(self._feed(), ["ev|" + ICU])
        corr_llm.sync_alarms({"events": {}})
        self.assertEqual(self._feed(), ["ev|" + ICU])
        corr_llm.sync_alarms({"events": ev})  # back in the window: no duplicate alarm
        self.assertEqual(self._feed(), ["ev|" + ICU])
        _classify(ICU, "benign")
        corr_llm.sync_alarms({"events": {}})
        self.assertEqual(self._feed(), [])

    def test_downgraded_event_still_withdrawn(self):
        """An event still in the snapshot that dropped below medium loses its alarm.
        REQ: STO-06"""
        _classify(ICU, "suspicious")
        corr_llm.sync_alarms({"events": {ICU: {"label": "IDS: x", "sev": "high", "ips": []}}})
        self.assertEqual(len(self._feed()), 1)
        corr_llm.sync_alarms({"events": {ICU: {"label": "IDS: x", "sev": "low", "ips": []}}})
        self.assertEqual(self._feed(), [])

    def test_promoted_detection_survives_age_out(self):
        """A promoted watcher detection is not re-held just because its event left the snapshot.
        REQ: STO-06"""
        store.alerts_add([("seg|a", f"odd {IPS['laptop']}", "urgent")], source="watcher")
        aid = store._dc().execute("SELECT id FROM alerts").fetchone()[0]
        _classify("alert|%d" % aid, "suspicious")
        corr_llm.sync_alarms({"events": {"alert|%d" % aid: {"sev": "medium"}}})
        self.assertEqual(len(self._feed()), 1)
        corr_llm.sync_alarms({"events": {}})
        self.assertEqual(len(self._feed()), 1)


class TestVerdictMark(unittest.TestCase):
    """Auto-close runs within seconds of a verdict: the dashboard loop watches corr_llm.verdict_mark()."""

    def setUp(self):
        _reset()

    def tearDown(self):
        _reset()

    def test_mark_changes_on_new_and_replaced_verdict(self):
        """Storing a verdict, and replacing one, both change the mark; reading does not.
        REQ: STO-08"""
        m0 = corr_llm.verdict_mark()
        self.assertEqual(corr_llm.verdict_mark(), m0)
        _classify(ICU, "suspicious")
        m1 = corr_llm.verdict_mark()
        self.assertNotEqual(m1, m0)
        time.sleep(0.01)
        _classify(ICU, "expected")
        self.assertNotEqual(corr_llm.verdict_mark(), m1)


if __name__ == "__main__":
    unittest.main()
