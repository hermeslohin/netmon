"""Unit tests for dashboard/app/autoclose.py: AI-verdict auto-close of open events (Open events page, any type/age)."""
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); import _env  # noqa: E401,E402

import time  # noqa: E402
import unittest  # noqa: E402

import store  # noqa: E402
import corr_llm  # noqa: E402
import eventstore  # noqa: E402
import autoclose  # noqa: E402

IDS = "ids|ET POLICY Example signature 12"
GW = "gw|THREAT_BLOCKED|1792700000|10.0.0.5|1.2.3.4"
BAD_IDS = "ids|ET TROJAN Something bad 7"


def _classify(eid, label):
    with corr_llm._db() as c:
        c.execute("INSERT OR REPLACE INTO event_class (eid, label, confidence, reason, model, sig, ts) VALUES (?,?,?,?,?,?,?)", (eid, label, 0.9, "test reason", "test-model", "sig", time.time()))


def _acked(typ, key):
    return bool((store.acks_load(store._dc()).get(typ) or {}).get(key))


class AutoCloseOpenEvents(unittest.TestCase):
    def setUp(self):
        _env.fresh_db()
        store._cfg_cache.clear()
        with corr_llm._db() as c:
            c.execute("DELETE FROM event_class")
        eventstore.upsert({
            IDS: {"type": "ids", "label": "IDS: ET POLICY Example signature 12 x3", "sev": "low", "t1": 100},
            GW: {"type": "gw", "label": "Gateway THREAT_BLOCKED from 10.0.0.5", "sev": "medium", "t1": 101},
            BAD_IDS: {"type": "ids", "label": "IDS: ET TROJAN Something bad 7 x1", "sev": "high", "t1": 102},
        }, "s1")
        autoclose.set_settings({"reviewer_expected": True, "reviewer_benign": True}, "test")

    def refs(self, eid):
        e = next(x for x in eventstore.open_events()["events"] if x["eid"] == eid)
        return [(a["type"], a["key"]) for a in e["acks"]]

    def test_expected_open_events_are_closed(self):
        """Open events without a snapshot checklist (IDS, gateway) the event reviewer calls expected/benign are checked off;
        a suspicious one stays open, and they leave the Open events list.
        REQ: STO-08
        """
        _classify(IDS, "expected"); _classify(GW, "benign"); _classify(BAD_IDS, "suspicious")
        ids_refs, gw_refs = self.refs(IDS), self.refs(GW)
        r = autoclose.run({}, {}, [], trigger="test")
        self.assertEqual(r["reviewer_expected"]["closed_now"], 1)
        self.assertEqual(r["reviewer_benign"]["closed_now"], 1)
        for t, k in ids_refs + gw_refs:
            self.assertTrue(_acked(t, k), (t, k))
        left = {e["eid"] for e in eventstore.open_events()["events"]}
        self.assertEqual(left, {BAD_IDS})

    def test_dry_run_and_disabled_option_change_nothing(self):
        """A preview (dry) or a verdict whose option is off never checks anything off.
        REQ: STO-08
        """
        _classify(IDS, "expected")
        r = autoclose.run({}, {}, [], dry=True)
        self.assertEqual(r["reviewer_expected"]["would_close"], 1)
        self.assertEqual(len(eventstore.open_events()["events"]), 3)
        autoclose.set_settings({"reviewer_benign": True}, "test")
        autoclose.run({}, {}, [], trigger="test")
        self.assertEqual(len(eventstore.open_events()["events"]), 3)

    def test_person_reopen_is_respected_and_verdict_change_reopens(self):
        """An auto-closed event a person un-checks is never auto-closed again; one whose verdict turns suspicious is
        reopened with all of its check-offs; reopen_all restores everything auto-closed.
        REQ: STO-08
        """
        _classify(IDS, "expected"); _classify(GW, "expected")
        ids_refs, gw_refs = self.refs(IDS), self.refs(GW)
        autoclose.run({}, {}, [], trigger="test")
        for t, k in ids_refs:  # a person brings IDS back
            store.ack_set(t, k, False)
        autoclose.run({}, {}, [], trigger="test")
        self.assertIn(IDS, {e["eid"] for e in eventstore.open_events()["events"]})
        _classify(GW, "suspicious")  # the event reviewer changes its mind about GW
        r = autoclose.run({}, {}, [], trigger="test")
        self.assertEqual(r["reopened_verdict_changed"], 1)
        for t, k in gw_refs:
            self.assertFalse(_acked(t, k), (t, k))
        _classify(GW, "benign")
        autoclose.run({}, {}, [], trigger="test")
        self.assertNotIn(GW, {e["eid"] for e in eventstore.open_events()["events"]})
        self.assertEqual(autoclose.reopen_all("test"), 1)
        self.assertIn(GW, {e["eid"] for e in eventstore.open_events()["events"]})

    def test_suppressed_item_is_never_reopened(self):
        """An auto-closed event that a suppress rule covers stays hidden when its verdict turns suspicious.
        REQ: STO-08, STO-05
        """
        _classify(IDS, "expected")
        autoclose.run({}, {}, [], trigger="test")
        store.suppress_add("*ET POLICY Example*", "", "", by="t")
        _classify(IDS, "suspicious")
        r = autoclose.run({}, {}, [], trigger="test")
        self.assertEqual(r["reopened_verdict_changed"], 0)
        self.assertNotIn(IDS, {e["eid"] for e in eventstore.open_events()["events"]})

    def test_ai_reopen_does_not_block_a_later_close(self):
        """An event the AI review reopened (suspicious) is closed again when a later review calls it expected; only a
        person's un-check blocks auto-close for good.
        REQ: STO-08
        """
        _classify(GW, "expected")
        refs = self.refs(GW)
        autoclose.run({}, {}, [], trigger="test")
        self.assertTrue(all(_acked(t, k) for t, k in refs))
        _classify(GW, "suspicious")
        corr_llm.reopen_checked(GW, "test")
        self.assertIn(GW, {e["eid"] for e in eventstore.open_events()["events"]})
        _classify(GW, "expected")
        autoclose.run({}, {}, [], trigger="test")
        self.assertNotIn(GW, {e["eid"] for e in eventstore.open_events()["events"]})

    def test_person_verdict_is_authoritative(self):
        """A person's Expected/Benign verdict note closes the event even with every option off and is never reopened by
        an AI 'suspicious'; a person's Suspicious keeps it open even when the event reviewer says expected.
        REQ: STO-08
        """
        import kb
        autoclose.set_settings({}, "test")
        _classify(IDS, "suspicious"); _classify(GW, "expected")
        kb.add_event_note(IDS, "my backup job", "admin1", verdict="expected")
        kb.add_event_note(GW, "", "admin1", verdict="suspicious")
        self.assertTrue(kb.event_notes([IDS])[IDS][0]["text"].startswith(kb.VERDICT_TAG + "EXPECTED"))
        r = autoclose.run({}, {}, [], trigger="test")
        self.assertEqual(r["person_expected"]["closed_now"], 1)
        left = {e["eid"] for e in eventstore.open_events()["events"]}
        self.assertNotIn(IDS, left)
        self.assertIn(GW, left)
        self.assertEqual(corr_llm.reopen_checked(IDS, "ai says suspicious"), 0)
        self.assertNotIn(IDS, {e["eid"] for e in eventstore.open_events()["events"]})
        uid = kb.add_event_note(BAD_IDS, "", "u1", role="user", verdict="benign")  # a User's verdict waits for approval
        autoclose.run({}, {}, [], trigger="test")
        self.assertIn(BAD_IDS, {e["eid"] for e in eventstore.open_events()["events"]})
        kb.review_event_note(uid, True, "admin1")
        autoclose.run({}, {}, [], trigger="test")
        self.assertNotIn(BAD_IDS, {e["eid"] for e in eventstore.open_events()["events"]})


from fixtures import mac  # noqa: E402
MAC = mac(41)  # generated at run time: no literal MAC in the repo
SUS_F = f"f|dns-long-names|{MAC}|40 queries >= 60 chars vs normal 2"
OK_F = f"f|port-spike|{MAC}|port 443/tcp: 600 conns vs normal 10"
ADM = "adm|10.0.0.9|10.0.0.1|SSH"


def _cls(eid, label, conf=0.9, ts=None):
    with corr_llm._db() as c:
        c.execute("INSERT OR REPLACE INTO event_class (eid, label, confidence, reason, model, sig, ts) VALUES (?,?,?,?,?,?,?)", (eid, label, conf, "r", "m", "sig", ts or time.time()))


def _open():
    return {e["eid"] for e in eventstore.open_events()["events"]}


class AutoCloseGuardRails(unittest.TestCase):
    """Guard rails between AI auto-close and a person staying in control (min confidence, protected categories,
    host hold, closure expiry)."""

    def setUp(self):
        _env.fresh_db()
        store._cfg_cache.clear()
        with corr_llm._db() as c:
            c.execute("DELETE FROM event_class")
        eventstore.upsert({
            IDS: {"type": "ids", "label": "IDS: ET POLICY Example signature 12 x3", "sev": "low", "t1": 100},
            ADM: {"type": "admin", "label": "Admin SSH 10.0.0.9 -> 10.0.0.1", "sev": "medium", "t1": 101},
            OK_F: {"type": "finding", "label": "port-spike on the TV", "sev": "low", "t1": 102, "host_ips": ["10.0.0.40"]},
        }, "s1")
        autoclose.set_settings({"reviewer_expected": True, "reviewer_benign": True, **autoclose.GUARD_DEFAULTS}, "test")

    def test_settings_defaults_merge_and_ranges(self):
        """Guard settings default to 0.8 / 7 days / attack categories, survive a switches-only save and are clamped.
        REQ: STO-12
        """
        s = autoclose._guard({})
        self.assertEqual((s["min_conf"], s["expire_days"]), (0.8, 7))
        self.assertIn("admin", s["protect"]); self.assertNotIn("high_sev", s["protect"])
        autoclose.set_settings({"min_conf": 2, "expire_days": -3, "protect": ["admin", "bogus"], "reviewer_benign": True}, "t")
        autoclose.set_settings({"reviewer_expected": True}, "t")  # the switches card saves only the four switches
        s = autoclose.settings()
        self.assertEqual((s["min_conf"], s["expire_days"], s["protect"]), (1.0, 0, ["admin"]))
        self.assertTrue(s["reviewer_expected"]); self.assertFalse(s["reviewer_benign"])

    def test_low_confidence_reviewer_label_stays_open(self):
        """An event reviewer label below min_conf does not close the event; at or above it (or with min_conf 0) it does.
        REQ: STO-12
        """
        _cls(IDS, "expected", 0.6)
        r = autoclose.run({}, {}, [], trigger="test")
        self.assertEqual(r["guard"]["low_conf"], 1)
        self.assertIn(IDS, _open())
        autoclose.set_settings({"reviewer_expected": True, "min_conf": 0.6}, "t")
        autoclose.run({}, {}, [], trigger="test")
        self.assertNotIn(IDS, _open())

    def test_protected_category_needs_a_person(self):
        """An admin-access event is never closed by an AI verdict while its category is protected; a person's verdict
        still closes it, and unprotecting the category lets the AI close it.
        REQ: STO-12
        """
        import kb
        self.assertEqual(autoclose.categories(ADM, "medium"), {"admin"})
        self.assertEqual(autoclose.categories(ADM, "allowed-admin"), set())
        _cls(ADM, "expected", 0.99)
        r = autoclose.run({}, {}, [], trigger="test")
        self.assertEqual((r["guard"]["protected"], r["guard"]["by_cat"]), (1, {"admin": 1}))
        self.assertIn(ADM, _open())
        autoclose.set_settings({"reviewer_expected": True, "protect": []}, "t")
        autoclose.run({}, {}, [], trigger="test")
        self.assertNotIn(ADM, _open())
        adm2 = "adm|10.0.0.8|10.0.0.1|SSH"
        eventstore.upsert({adm2: {"type": "admin", "label": "Admin SSH 10.0.0.8 -> 10.0.0.1", "sev": "medium", "t1": 105}}, "s3")
        autoclose.set_settings({"reviewer_expected": True, "protect": ["admin"]}, "t")
        _cls(adm2, "expected", 0.99)
        kb.add_event_note(adm2, "my own login", "admin1", verdict="expected")
        r = autoclose.run({}, {}, [], trigger="test")
        self.assertEqual(r["person_expected"]["closed_now"], 1)

    def test_suspicious_event_holds_and_reopens_its_host(self):
        """While an open event on a host is called suspicious, AI verdicts close nothing else on that host and AI
        closures of its recently active events reopen; once a person checks the suspicious one off they close again.
        REQ: STO-12
        """
        _cls(OK_F, "benign")
        autoclose.run({}, {}, [], trigger="test")
        self.assertNotIn(OK_F, _open())
        eventstore.upsert({SUS_F: {"type": "finding", "label": "long DNS names on the TV", "sev": "medium", "t1": 103}}, "s2")
        _cls(SUS_F, "suspicious")
        r = autoclose.run({}, {}, [], trigger="test")
        self.assertEqual(r["guard"]["reopened_host"], 1)
        self.assertIn(OK_F, _open())
        r = autoclose.run({}, {}, [], dry=True)
        self.assertEqual(r["guard"]["host"], 1)
        self.assertIn(MAC, r["guard"]["hosts"])
        for a in next(e for e in eventstore.open_events()["events"] if e["eid"] == SUS_F)["acks"]:
            store.ack_set(a["type"], a["key"], True, "looked at it", "")  # a person handles the suspicious event
        autoclose.run({}, {}, [], trigger="test")
        self.assertNotIn(OK_F, _open())

    def test_ai_closure_expires_when_the_event_repeats(self):
        """An AI closure older than expire_days reopens when the event repeats; it closes again only on a newer verdict.
        REQ: STO-12
        """
        _cls(IDS, "expected", ts=time.time() - 20 * 86400)
        autoclose.run({}, {}, [], trigger="test")
        self.assertNotIn(IDS, _open())
        old = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 10 * 86400))
        c = autoclose._c()
        with store.tx(c):
            c.execute("UPDATE autoclose_log SET at=?", (old,))
        eventstore.upsert({IDS: {"type": "ids", "label": "IDS: ET POLICY Example signature 12 x3", "sev": "low", "t1": 200}}, "s9")
        self.assertEqual(autoclose.run({}, {}, [], dry=True)["guard"]["expire_due"], 1)
        r = autoclose.run({}, {}, [], trigger="test")
        self.assertEqual(r["guard"]["expired"], 1)
        self.assertEqual(r["guard"]["stale"], 1)
        self.assertIn(IDS, _open())
        _cls(IDS, "expected")  # judged again
        autoclose.run({}, {}, [], trigger="test")
        self.assertNotIn(IDS, _open())
        # a newer closure of a later repeat keeps the group closed: older closures of the group do not expire
        c2 = autoclose._c()
        with store.tx(c2):
            c2.execute("INSERT INTO autoclose_log (type, key, eid, verdict, model, at, state, source) VALUES "
                       "('finding', 'old1', ?, 'expected', 'm', ?, 'closed', 'reviewer')", (IDS, old))
        self.assertEqual(autoclose.run({}, {}, [], dry=True)["guard"]["expire_due"], 0)
        autoclose.set_settings({"reviewer_expected": True, "expire_days": 0}, "t")
        with store.tx(c):
            c.execute("UPDATE autoclose_log SET at=?", (old,))
        self.assertEqual(autoclose.run({}, {}, [], trigger="test")["guard"]["expired"], 0)


if __name__ == "__main__":
    unittest.main()
