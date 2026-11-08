"""A person's Expected / Benign verdict with chosen artifacts (scope): kb.py stores and matches it, clef.owner_adjust weighs it
over the decision model, and corr_llm.clef_events applies it to other events that show every chosen artifact."""
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); import _env  # noqa: E401,E402

import json  # noqa: E402
import unittest  # noqa: E402

import clef  # noqa: E402
import corr_llm  # noqa: E402
import kb  # noqa: E402
from unit import test_clef_stage as T  # noqa: E402  (fake /v1/systemone server: 0.7 for every event answer)


class ScopeStore(unittest.TestCase):
    def setUp(self):
        with kb._db() as c:
            c.execute("DELETE FROM event_notes")

    tearDown = setUp

    def test_clean_scope_validates_and_normalises(self):
        """Only ip / dns / proc / user / port keys survive, in the same form as an event's artifact keys.
        REQ: STO-14
        """
        got = kb.clean_scope(["proc:/usr/bin/Restic", "dns:Backup.Example.COM.", "user:Bob", "port:443", "port:99999",
                              "ip:10.0.0.5", "ip:nope", "foo:bar", "ip:10.0.0.5"])
        self.assertEqual(got, ["proc:restic", "dns:backup.example.com", "user:bob", "port:443", "ip:10.0.0.5"])

    def test_scope_saved_only_for_expected_benign(self):
        """The chosen artifacts are stored with an expected / benign verdict, named in the note text, and never kept for suspicious.
        REQ: STO-14
        """
        kb.add_event_note("e1", "nightly backup", "user:dan", verdict="expected", scope=["ip:10.0.0.5", "proc:restic"])
        kb.add_event_note("e2", "", "user:dan", verdict="suspicious", scope=["ip:10.0.0.5"])
        n1, n2 = kb.event_notes(["e1"])["e1"][0], kb.event_notes(["e2"])["e2"][0]
        self.assertEqual(n1["scope"], ["ip:10.0.0.5", "proc:restic"])
        self.assertEqual(n1["artifacts"], n1["scope"])
        self.assertIn("applies to any event with ip:10.0.0.5, proc:restic", n1["text"])
        self.assertTrue(n1["text"].endswith("nightly backup"))
        self.assertEqual(n2["scope"], [])
        self.assertEqual([n["id"] for n in kb.scoped_verdicts()], [n1["id"]])

    def test_match_needs_every_artifact(self):
        """A scoped verdict applies only to events showing all of its artifacts.
        REQ: STO-14
        """
        kb.add_event_note("e1", "", "user:dan", verdict="benign", scope=["ip:10.0.0.5", "port:22"])
        sv = kb.scoped_verdicts()
        self.assertEqual(len(kb.scope_matches({"ip:10.0.0.5", "port:22", "dns:x.com"}, sv)), 1)
        self.assertEqual(kb.scope_matches({"ip:10.0.0.5"}, sv), [])

    def test_user_note_needs_approval(self):
        """A User account's scoped verdict is not applied until approved.
        REQ: STO-14
        """
        kb.add_event_note("e1", "", "user:kid", role="user", verdict="expected", scope=["ip:10.0.0.5"])
        self.assertEqual(kb.scoped_verdicts(), [])


class OwnerWeight(unittest.TestCase):
    def test_owner_adjust(self):
        """Expected pulls suspicious toward 0 and expected toward 1 with the given weight; threat intel halves the weight.
        REQ: STO-14
        """
        self.assertEqual(clef.owner_adjust(0.9, 0.1, "expected", 0.9), (0.09, 0.91))
        self.assertEqual(clef.owner_adjust(0.9, 0.1, "benign", 0.9), (0.09, 0.1))
        self.assertEqual(clef.owner_adjust(0.9, 0.1, "expected", 0.9, ti=True), (0.495, 0.505))
        s, e = clef.owner_adjust(0.2, 0.8, "suspicious", 0.8)
        self.assertGreater(s, 0.8); self.assertLess(e, 0.2)
        self.assertGreater(clef.OWNER_WEIGHT["artifacts"], clef.OWNER_WEIGHT["event"])


class ScopedVerdictOnOtherEvent(unittest.TestCase):
    """End to end against the fake decision-model server (both answers 0.7 = 'suspicious' on its own)."""
    setUpClass, tearDownClass = T.ClefStageTest.setUpClass, T.ClefStageTest.tearDownClass

    def setUp(self):
        T.ClefStageTest.setUp(self)
        with kb._db() as c:
            c.execute("DELETE FROM event_notes")

    def tearDown(self):
        with kb._db() as c:
            c.execute("DELETE FROM event_notes")

    def test_scoped_verdict_relabels_matching_event(self):
        """An expected verdict written on another event, scoped to an artifact event 'a' shows, turns the decision model's
        'suspicious' into 'expected', keeps the raw answers and the verdict, and is sent to the model as an owner note.
        REQ: STO-14
        """
        kb.add_event_note("other-event", "my backup box", "user:dan", verdict="expected", scope=["ip:10.0.0.5"])
        n = corr_llm.clef_events(T.BASE, [("a", "sig1", ["b"], ["b", "c"])])
        self.assertEqual(n, 1)
        v = corr_llm.clef_events_view(["a"])["a"]
        self.assertEqual(v["label"], "expected")
        self.assertEqual(v["raw"], {"p_suspicious": 0.7, "p_expected": 0.7})
        self.assertEqual(v["owner"]["kind"], "artifacts")
        self.assertEqual(v["owner"]["match"], ["ip:10.0.0.5"])
        st = json.loads(next(s for q, s in T.CALLS if q != "related"))
        self.assertTrue(any("owner verdict written on another event" in x for x in st["EVENT"].get("owner_notes", [])))

    def test_no_match_keeps_model_label(self):
        """A scoped verdict on an artifact the event does not show changes nothing.
        REQ: STO-14
        """
        kb.add_event_note("other-event", "", "user:dan", verdict="expected", scope=["ip:10.9.9.9"])
        corr_llm.clef_events(T.BASE, [("a", "sig1", ["b"], ["b", "c"])])
        v = corr_llm.clef_events_view(["a"])["a"]
        self.assertEqual(v["label"], "suspicious")
        self.assertNotIn("owner", v)

    def test_new_verdict_changes_signature(self):
        """A new verdict that applies to an event changes its review signature, so it is decided again.
        REQ: STO-14
        """
        self.assertEqual(corr_llm._with_owner("abc", None), "abc")
        a = corr_llm._with_owner("abc", {"kind": "artifacts", "note": 1, "verdict": "expected"})
        self.assertNotEqual(a, "abc")
        self.assertNotEqual(a, corr_llm._with_owner("abc", {"kind": "artifacts", "note": 2, "verdict": "expected"}))


if __name__ == "__main__":
    unittest.main()
