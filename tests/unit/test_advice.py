"""Unit tests for dashboard/app/advice.py: the analyst's advice for the device owner on each alert (a second verdict in
plain language: what to do), its guard rail, when it is (re)written, and how the pages get it."""
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); import _env  # noqa: E401,E402

import json  # noqa: E402
import time  # noqa: E402
import unittest  # noqa: E402
from unittest import mock  # noqa: E402

import store  # noqa: E402
import corr_llm  # noqa: E402
import eventstore  # noqa: E402
import advice  # noqa: E402

TARGET = {"provider": "lmstudio", "model": "test-model"}


def _classify(eid, label="suspicious", conf=0.9, reason="Beacons to a known C2 server."):
    with corr_llm._db() as c:
        c.execute("INSERT OR REPLACE INTO event_class (eid, label, confidence, reason, model, sig, ts) VALUES (?,?,?,?,?,?,?)",
                  (eid, label, conf, reason, "test-model", "sig", time.time()))


def _answer(**kw):
    d = {"action": "stop_app", "headline": "Stop using the FreeVPN app", "steps": ["Open Settings", "Uninstall FreeVPN"],
         "message": "Syn detected your laptop sending traffic through the FreeVPN app. FreeVPN is known for routing traffic to malware servers. Please stop using it and uninstall it.", "target": "FreeVPN"}
    d.update(kw)
    return (json.dumps(d), {"prompt": 10, "completion": 10}, 0.1)


class AdviceTest(unittest.TestCase):
    def setUp(self):
        with corr_llm._db() as c:
            advice._schema(c)
            for q in ("DELETE FROM user_advice", "DELETE FROM event_class", "DELETE FROM event_sources"):
                c.execute(q)
        store._dc().execute("DELETE FROM alerts")

    def _alert(self, text="IDS ET MALWARE beacon from laptop", key="k|1"):
        store.alerts_add([(key, text, "investigate", ["ip:192.0.2.20"])], source="review")
        a = store.alerts_recent(10)[0]
        return a, eventstore.alert_ref(a)

    def test_pass_writes_advice_and_skips_unchanged(self):
        """pass_() asks the model once per reviewed alert, stores action / headline / steps / why / target, and does not
        ask again until the alert, the reviewer's verdict or the research note changes.
        REQ: ALR-26"""
        _a, eid = self._alert()
        _classify(eid)
        with mock.patch.object(corr_llm, "_target", return_value=TARGET), mock.patch.object(corr_llm, "_complete", return_value=_answer()) as m:
            self.assertEqual(advice.pass_(), 1)
            self.assertEqual(advice.pass_(), 0, "unchanged inputs: no second model call")
            self.assertEqual(m.call_count, 1)
            sys_prompt, prompt = m.call_args[0][1], m.call_args[0][2]
            self.assertIn("PERSON WHO USES THE", sys_prompt)
            self.assertIn('starts with "Syn detected"', sys_prompt)
            self.assertIn("Beacons to a known C2 server.", prompt)
            self.assertEqual(m.call_args[1]["purpose"], "user-advice")
            _classify(eid, reason="Now also a malware file hash.")
            self.assertEqual(advice.pass_(), 1, "a new reviewer reason rewrites the advice")
        v = advice.get([eid])[eid]
        self.assertEqual((v["action"], v["label"], v["headline"], v["target"]), ("stop_app", "Stop using this app", "Stop using the FreeVPN app", "FreeVPN"))
        self.assertEqual(v["steps"], ["Open Settings", "Uninstall FreeVPN"])
        self.assertTrue(v["message"].startswith("Syn detected your laptop"))

    def test_unreviewed_alerts_wait(self):
        """An alert without an event reviewer label (or a pending one) gets no advice yet and costs no model call.
        REQ: ALR-26"""
        _a, eid = self._alert()
        with mock.patch.object(corr_llm, "_target", return_value=TARGET), mock.patch.object(corr_llm, "_complete", return_value=_answer()) as m:
            self.assertEqual(advice.pass_(), 0)
            self.assertEqual(m.call_count, 0)

    def test_stop_device_guard_rail(self):
        """"Stop using this device" needs a confident suspicious verdict; otherwise it is softened to "Keep an eye out".
        REQ: ALR-26"""
        cl = {"label": "suspicious", "confidence": 0.8, "reason": "x"}
        with mock.patch.object(corr_llm, "_complete", return_value=_answer(action="stop_device")):
            self.assertEqual(advice.advise(TARGET, {"text": "t"}, cl)[0], "watch")
            self.assertEqual(advice.advise(TARGET, {"text": "t"}, {**cl, "confidence": 0.9})[0], "stop_device")
            self.assertEqual(advice.advise(TARGET, {"text": "t"}, {**cl, "label": "expected", "confidence": 0.99})[0], "watch")

    def test_bad_answers_are_dropped(self):
        """An unknown action, an empty headline, an empty message or non-JSON text stores nothing; steps are capped at 4.
        REQ: ALR-26"""
        for txt in (_answer(action="format_disk"), _answer(headline="  "), _answer(message=" "), ("not json", {}, 0)):
            with mock.patch.object(corr_llm, "_complete", return_value=txt):
                self.assertIsNone(advice.advise(TARGET, {"text": "t"}, {"label": "suspicious", "confidence": 0.9}))
        with mock.patch.object(corr_llm, "_complete", return_value=_answer(steps=["1", "2", "3", "4", "5", " "])):
            self.assertEqual(advice.advise(TARGET, {"text": "t"}, {"label": "suspicious", "confidence": 0.9})[2], ["1", "2", "3", "4"])

    def test_prompt_change_rewrites_advice(self):
        """Bumping PROMPT_VER changes every alert's input signature, so all advice is rewritten with the new prompt.
        REQ: ALR-26"""
        a, eid = self._alert()
        cl = {"label": "suspicious", "reason": "r"}
        s1 = advice._sig(a, cl, None)
        with mock.patch.object(advice, "PROMPT_VER", advice.PROMPT_VER + 1):
            self.assertNotEqual(advice._sig(a, cl, None), s1)

    def test_model_error_does_not_stop_the_pass(self):
        """A failing model call is logged and retried next pass; nothing is stored.
        REQ: ALR-26"""
        _a, eid = self._alert()
        _classify(eid)
        with mock.patch.object(corr_llm, "_target", return_value=TARGET), mock.patch.object(corr_llm, "_complete", side_effect=RuntimeError("down")):
            self.assertEqual(advice.pass_(), 0)
        self.assertEqual(advice.get([eid]), {})

    def test_pages_get_the_advice(self):
        """alert_view (Alerts, every role) and extras (Open events) carry the advice keyed by the row's event id.
        REQ: ALR-27, OE-21"""
        a, eid = self._alert()
        _classify(eid)
        with mock.patch.object(corr_llm, "_target", return_value=TARGET), mock.patch.object(corr_llm, "_complete", return_value=_answer()):
            advice.pass_()
        _rows, X = eventstore.alert_view([dict(a)], related=False, art_limit=0)
        self.assertEqual(X["advice"][eid]["headline"], "Stop using the FreeVPN app")
        ex = eventstore.extras([{"eid": eid, "members": [eid], "n": 1, "first_seen": 0, "last_seen": 0}])
        self.assertEqual(ex["advice"][eid]["action"], "stop_app")


if __name__ == "__main__":
    unittest.main()
