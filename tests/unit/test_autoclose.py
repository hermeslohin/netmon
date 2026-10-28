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
        c.execute("INSERT OR REPLACE INTO event_class VALUES (?,?,?,?,?,?,?)", (eid, label, 0.9, "test reason", "test-model", "sig", time.time()))


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
        """Open events without a snapshot checklist (IDS, gateway) the reviewer calls expected/benign are checked off;
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
        _classify(GW, "suspicious")  # the reviewer changes its mind about GW
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
        an AI 'suspicious'; a person's Suspicious keeps it open even when the reviewer says expected.
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


if __name__ == "__main__":
    unittest.main()
