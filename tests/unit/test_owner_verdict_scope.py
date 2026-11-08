"""A person's Expected / Benign verdict with chosen artifacts (scope): kb.py stores and matches it, corr_llm.apply_owner weighs it
over the event reviewer's label, and corr_llm.event_pass applies it to other events that show every chosen artifact."""
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); import _env  # noqa: E401,E402

import json  # noqa: E402
import unittest  # noqa: E402

import corr_llm  # noqa: E402
import kb  # noqa: E402
import fixtures as F  # noqa: E402
from unit import test_clef_stage as T  # noqa: E402  (fake /v1/systemone server for the link decisions)


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

    def test_scope_keys_name_device_finding_signature_port(self):
        """Baseline findings, IDS signatures and gateway events offer the device, the kind of finding, the signature and
        ports written as 443/tcp, so a verdict can be scoped to e.g. 'port-spike on this device on port 443'.
        REQ: STO-14
        """
        self.assertEqual(sorted(kb.scope_keys(f"f|port-spike|{F.mac(1)}|x", {"label": "port 443/tcp: 358 conns vs normal"})),
                         ["dev:" + F.mac(1), "find:port-spike", "port:443"])
        self.assertIn("sig:ET INFO Http Client Body contains pin= in cleartext",
                      kb.scope_keys("f|new-signature|-|x", {"label": "first time seen: 'ET INFO Http Client Body contains pin= in cleartext' x1"}))
        self.assertEqual(kb.scope_keys("ids|ET INFO STUN Binding", {"label": "IDS"}), {"sig:ET INFO STUN Binding"})
        self.assertEqual(kb.scope_keys("gw|t|THREAT_BLOCKED_V3|a|b", {}), {"find:threat_blocked_v3"})
        self.assertEqual(kb.clean_scope(["dev:" + F.mac(1).upper(), "find:Port-Spike", "find:bad value!", "dev:not a host"]),
                         ["dev:" + F.mac(1), "find:port-spike"])

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
    def test_apply_owner(self):
        """A person's verdict replaces the event reviewer's label unless the reviewer is at least as confident as the verdict's
        weight; a threat-intel hit keeps a suspicious label; an agreeing label is kept as is.
        REQ: STO-14
        """
        W = corr_llm.OWNER_WEIGHT
        ov = {"verdict": "expected", "kind": "artifacts", "weight": W["artifacts"], "note": 1, "match": ["ip:10.0.0.5"]}
        lab, conf, rec = corr_llm.apply_owner("suspicious", 0.8, ov)
        self.assertEqual((lab, conf, rec["applied"], rec["model_label"]), ("expected", W["artifacts"], True, "suspicious"))
        lab, _c, rec = corr_llm.apply_owner("suspicious", 0.97, ov)
        self.assertEqual((lab, rec["applied"], rec["held"]), ("suspicious", False, "event reviewer confident"))
        lab, _c, rec = corr_llm.apply_owner("suspicious", 0.5, ov, ti=True)
        self.assertEqual((lab, rec["held"]), ("suspicious", "threat intel"))
        self.assertEqual(corr_llm.apply_owner("benign", 0.6, None), ("benign", 0.6, None))
        self.assertTrue(corr_llm.apply_owner("expected", 0.6, ov)[2]["agreed"])
        self.assertGreater(W["artifacts"], W["event"])


class ScopedVerdictOnOtherEvent(unittest.TestCase):
    """End to end: the event reviewer (stubbed) says suspicious; a person's scoped verdict decides the stored label."""
    setUpClass, tearDownClass = T.ClefStageTest.setUpClass, T.ClefStageTest.tearDownClass

    def setUp(self):
        T.ClefStageTest.setUp(self)
        with kb._db() as c:
            c.execute("DELETE FROM event_notes")
        self.sys = []

        def fake(target, anchor, cands, notes, *a, **kw):
            self.sys.append((kw.get("system") or "", notes))
            return ([{"id": "anchor", "label": "suspicious", "confidence": 0.7, "reason": "ssh brute force"}], {"prompt": 1, "completion": 1}, 1.0)
        self.old = (corr_llm._ask_full, corr_llm._target, corr_llm.reopen_checked)
        corr_llm._ask_full, corr_llm._target, corr_llm.reopen_checked = fake, (lambda model=None: {"provider": "lmstudio", "model": "reviewer"}), (lambda *a, **k: None)
        corr_llm.clef_pass(T.BASE, [("a", r) for r in T.BASE["related"]["a"]])

    def tearDown(self):
        corr_llm._ask_full, corr_llm._target, corr_llm.reopen_checked = self.old
        with kb._db() as c:
            c.execute("DELETE FROM event_notes")

    def test_scoped_verdict_relabels_matching_event(self):
        """An expected verdict written on another event, scoped to an artifact event 'a' shows, is told to the event reviewer
        (PERSON'S VERDICT line + owner note) and outweighs its 'suspicious' (0.7); the reviewer's own call is kept.
        REQ: STO-14
        """
        kb.add_event_note("other-event", "my backup box", "user:dan", verdict="expected", scope=["ip:10.0.0.5"])
        self.assertEqual(corr_llm.event_pass(T.BASE), 1)
        c = corr_llm.classes(["a"])["a"]
        self.assertEqual(c["label"], "expected")
        self.assertEqual((c["owner"]["kind"], c["owner"]["match"], c["owner"]["model_label"], c["owner"]["applied"]),
                         ("artifacts", ["ip:10.0.0.5"], "suspicious", True))
        self.assertTrue(c["reason"].startswith("Person's verdict applied"))
        system, notes = self.sys[0]
        self.assertIn("PERSON'S VERDICT: expected", system)
        self.assertTrue(any("owner verdict written on another event" in x for x in notes.get("anchor", [])))

    def test_no_match_keeps_model_label(self):
        """A scoped verdict on an artifact the event does not show changes nothing.
        REQ: STO-14
        """
        kb.add_event_note("other-event", "", "user:dan", verdict="expected", scope=["ip:10.9.9.9"])
        corr_llm.event_pass(T.BASE)
        c = corr_llm.classes(["a"])["a"]
        self.assertEqual(c["label"], "suspicious")
        self.assertNotIn("owner", c)
        self.assertNotIn("\nPERSON'S VERDICT:", self.sys[0][0])

    def test_new_verdict_changes_signature(self):
        """A new verdict that applies to an event changes its review signature, so it is reviewed again.
        REQ: STO-14
        """
        self.assertEqual(corr_llm._with_owner("abc", None), "abc")
        a = corr_llm._with_owner("abc", {"kind": "artifacts", "note": 1, "verdict": "expected"})
        self.assertNotEqual(a, "abc")
        self.assertNotEqual(a, corr_llm._with_owner("abc", {"kind": "artifacts", "note": 2, "verdict": "expected"}))
        corr_llm.event_pass(T.BASE)
        self.assertEqual(corr_llm.event_pass(T.BASE), 0)
        kb.add_event_note("other-event", "", "user:dan", verdict="benign", scope=["ip:10.0.0.5"])
        self.assertEqual(corr_llm.event_pass(T.BASE), 1)
        self.assertEqual(corr_llm.classes(["a"])["a"]["label"], "benign")


if __name__ == "__main__":
    unittest.main()
