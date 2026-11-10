"""Phone-push gate (dashboard/app/pushgate.py): urgent alarms wait for the event reviewer's group verdict, expected /
benign alarms that pass every auto-close guard rail are not pushed, and every failure mode still pushes."""
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); import _env  # noqa: E401,E702,E402

import time  # noqa: E402
import unittest  # noqa: E402
from unittest import mock  # noqa: E402

import auth  # noqa: E402
import autoclose  # noqa: E402
import corr_llm  # noqa: E402
import pushgate  # noqa: E402
import pushsvc  # noqa: E402
import store  # noqa: E402
from fixtures import IPS  # noqa: E402

FINAL = {"label": "suspicious", "confidence": 0.9, "reason": "Outbound beacon to a new host. More detail follows.", "model": "m", "at": 1}


def _reset():
    c = getattr(store._dl, "c", None)
    if c is not None:
        c.close()
    _env.fresh_db()
    store._cfg_cache.clear()
    pushgate._SCHEMA["done"] = ""


def _site(**kw):
    d = store.cfg_load("site")
    d.update(kw)
    store.cfg_save("site", d)
    import site_cfg
    site_cfg._cache = None


class TestPushGate(unittest.TestCase):
    def setUp(self):
        _reset()
        store.jdump({"admin1": {"hash": "x", "role": "admin"}}, auth.USERS)
        store.push_sub_save({"endpoint": "https://push.example.invalid/1", "keys": {"p256dh": "x", "auth": "y"}}, "admin1")
        self.sent = []
        self.cls = {}  # eid -> classes() record
        self.off = None
        for p in (mock.patch.object(pushsvc, "send", lambda s, p: (self.sent.append(p), (True, ""))[1]),
                  mock.patch.object(corr_llm, "classes", lambda eids, pending=False: {e: self.cls[e] for e in eids if e in self.cls}),
                  mock.patch.object(corr_llm, "reviewer_off", lambda: self.off),
                  mock.patch.dict(corr_llm.STATUS, {"error": "", "error_kind": "", "error_at": None})):
            p.start()
            self.addCleanup(p.stop)

    def tearDown(self):
        _reset()

    def _alarm(self, sev="urgent"):
        store.alerts_add([("ev|f|beacon-new|x", f"laptop {IPS['laptop']} beacon", sev)], source="review")
        return store.alerts_unpushed()[-1]["id"]

    def _gate(self, aid):
        r = store._dc().execute("SELECT state, why FROM push_gate WHERE alert_id=?", (aid,)).fetchone()
        return tuple(r) if r else None

    def test_held_until_verdict(self):
        """An urgent alarm whose group is still Pending review is held (not pushed, still unpushed and in the feed);
        once the group verdict arrives it is pushed with that verdict.
        REQ: PSH-01"""
        aid = self._alarm()
        self.cls["f|beacon-new|x"] = {"label": "pending", "pending": {"settles": time.time() + 300}}
        pushsvc.run_once()
        self.assertEqual(self.sent, [])
        self.assertEqual([r["id"] for r in store.alerts_unpushed()], [aid])
        self.assertEqual(self._gate(aid)[0], "held")
        self.assertIn(aid, [a["id"] for a in store.alerts_recent(10)])  # on the dashboard meanwhile
        self.cls["f|beacon-new|x"] = dict(FINAL)
        pushsvc.run_once()
        self.assertEqual(len(self.sent), 1)
        self.assertEqual(store.alerts_unpushed(), [])
        self.assertEqual(self._gate(aid)[0], "pushed")

    def test_provisional_label_is_held(self):
        """A provisional single-event (fast) label does not release the push; the group review does.
        REQ: PSH-01"""
        aid = self._alarm()
        self.cls["f|beacon-new|x"] = dict(FINAL)
        with mock.patch.object(pushgate, "verdict_of", lambda e: {"state": "pending", "label": "suspicious", "reason": "provisional label"}):
            pushsvc.run_once()
        self.assertEqual(self.sent, [])
        self.assertEqual(self._gate(aid)[0], "held")

    def test_expected_and_guardrails_no_push(self):
        """Expected / benign with every auto-close guard rail passed: no phone push, the alarm stays on the dashboard
        and push_gate logs 'push suppressed by AI verdict'.
        REQ: PSH-02"""
        aid = self._alarm()
        self.cls["f|beacon-new|x"] = {**FINAL, "label": "expected"}
        with mock.patch.object(autoclose, "push_check", return_value={"ok": True, "verdict": "expected", "source": "reviewer", "guard": None, "why": ""}) as pc:
            pushsvc.run_once()
        pc.assert_called_once()
        self.assertEqual(self.sent, [])
        self.assertEqual(store.alerts_unpushed(), [])
        st, why = self._gate(aid)
        self.assertEqual(st, "suppressed")
        self.assertIn("push suppressed by AI verdict", why)
        self.assertIn(aid, [a["id"] for a in store.alerts_recent(10)])
        self.assertEqual(pushgate.for_event("f|beacon-new|x")[0]["state"], "suppressed")

    def test_expected_failing_guardrail_pushes(self):
        """Expected but held back by a guard rail (protected category, held host, low confidence): pushed, with the guard.
        REQ: PSH-03"""
        aid = self._alarm()
        self.cls["f|beacon-new|x"] = {**FINAL, "label": "expected"}
        with mock.patch.object(autoclose, "push_check", return_value={"ok": False, "verdict": "expected", "source": "reviewer", "guard": "protected", "why": "protected category: c2_exfil"}):
            pushsvc.run_once()
        self.assertEqual(len(self.sent), 1)
        self.assertIn("protected category", self.sent[0]["body"])
        self.assertEqual(self._gate(aid)[0], "pushed")

    def test_withdrawn_alarm_judged_on_stored_copy(self):
        """An alarm the review withdraws while held (group no longer suspicious) is still judged: expected + guard
        rails passed = suppressed; expected failing a guard rail = pushed from the stored copy.
        REQ: PSH-02, PSH-03"""
        aid = self._alarm()
        self.cls["f|beacon-new|x"] = {"label": "pending", "pending": {}}
        pushsvc.run_once()
        store.alerts_delete([aid])
        self.cls["f|beacon-new|x"] = {**FINAL, "label": "expected"}
        with mock.patch.object(autoclose, "push_check", return_value={"ok": False, "verdict": "expected", "source": "reviewer", "guard": "host", "why": "held host"}):
            pushsvc.run_once()
        self.assertEqual(len(self.sent), 1)
        self.assertIn("beacon", self.sent[0]["body"])
        self.assertEqual(self._gate(aid)[0], "pushed")

    def test_malicious_pushes_with_context(self):
        """Suspicious / malicious / unknown verdicts always push, carrying verdict, one-line reason and group size.
        REQ: PSH-04"""
        for lab in ("malicious", "suspicious", "unknown"):
            self.sent.clear()
            store._dc().execute("DELETE FROM alerts")
            aid = self._alarm("investigate")
            self.cls["f|beacon-new|x"] = {**FINAL, "label": lab}
            with mock.patch.object(pushgate, "verdict_of", wraps=pushgate.verdict_of), \
                 mock.patch.object(autoclose, "push_check", side_effect=AssertionError("never asked")):
                pushsvc.run_once()
            (p,) = self.sent
            self.assertIn("AI " + lab, p["title"])
            self.assertIn(f"AI verdict: {lab} 90% - Outbound beacon to a new host.", p["body"])
            self.assertNotIn("More detail", p["body"])
            self.assertEqual(self._gate(aid)[0], "pushed")

    def test_timeout_pushes_anyway(self):
        """No verdict within push_hold_max_minutes (0 = event window + 5): pushed marked 'AI review unavailable'.
        REQ: PSH-05"""
        self.assertEqual(pushgate.settings()["hold_min"], 15)
        _site(push_hold_max_minutes=3)
        self.assertEqual(pushgate.settings()["hold_min"], 3)
        aid = self._alarm()
        self.cls["f|beacon-new|x"] = {"label": "pending", "pending": {}}
        pushsvc.run_once()
        self.assertEqual(self.sent, [])
        store._dc().execute("UPDATE push_gate SET first_ts=first_ts-181 WHERE alert_id=?", (aid,))
        pushsvc.run_once()
        (p,) = self.sent
        self.assertIn("AI review unavailable", p["title"])
        self.assertIn("no verdict within 3 min", p["body"])
        self.assertEqual(self._gate(aid)[0], "pushed-unavailable")

    def test_reviewer_down_pushes(self):
        """Reviewer off, reviewer erroring, 'Not reviewed', or the gate itself failing: pushed at once, marked
        'AI review unavailable'. Never dropped silently.
        REQ: PSH-05"""
        cases = [("off", lambda: setattr(self, "off", "the event reviewer is off (NETMON_LLM)")),
                 ("error", lambda: corr_llm.STATUS.update(error="ConnectionError", error_kind="reviewer", error_at=time.time())),
                 ("unreviewed", lambda: self.cls.update({"f|beacon-new|x": {"label": "unreviewed", "unreviewed": "excluded from review"}})),
                 ("crash", None)]
        for name, setup in cases:
            self.sent.clear()
            self.off = None
            corr_llm.STATUS.update(error="", error_kind="", error_at=None)
            self.cls = {"f|beacon-new|x": {"label": "pending", "pending": {}}}
            store._dc().execute("DELETE FROM alerts")
            aid = self._alarm()
            if setup:
                setup()
                pushsvc.run_once()
            else:
                with mock.patch.object(pushgate, "_check", side_effect=RuntimeError("boom")):
                    pushsvc.run_once()
            self.assertEqual(len(self.sent), 1, name)
            self.assertIn("AI review unavailable", self.sent[0]["title"], name)
            self.assertEqual(self._gate(aid)[0], "pushed-unavailable", name)
            self.assertEqual(store.alerts_unpushed(), [], name)

    def test_switch_off_keeps_old_behaviour(self):
        """push_wait_for_ai off: every alarm is pushed at once, without AI context, as before the gate.
        REQ: PSH-06"""
        _site(push_wait_for_ai=False)
        self._alarm()
        self.cls["f|beacon-new|x"] = {"label": "pending", "pending": {}}
        pushsvc.run_once()
        (p,) = self.sent
        self.assertEqual(p["title"], "Syn: urgent")
        self.assertNotIn("AI", p["body"])
        self.assertEqual(store.alerts_unpushed(), [])

    def test_settings_validated(self):
        """Both settings live in the cfg table (site doc), show with defaults, and bad values are refused.
        REQ: PSH-06"""
        import server
        d = server.cfg_with_defaults("site", {})
        self.assertIs(d["push_wait_for_ai"], True)
        self.assertEqual(d["push_hold_max_minutes"], 0)
        self.assertIn("_doc_push_hold_max_minutes", d)
        self.assertIsNone(server.cfg_validate("site", {"internal_prefixes": ["10."], "push_wait_for_ai": False, "push_hold_max_minutes": 30}))
        for bad in ({"push_wait_for_ai": "yes"}, {"push_hold_max_minutes": -1}, {"push_hold_max_minutes": 241}, {"push_hold_max_minutes": 2.5}):
            self.assertTrue(server.cfg_validate("site", {"internal_prefixes": ["10."], **bad}), bad)


class TestPushCheckUsesGuardRails(unittest.TestCase):
    def test_push_check_calls_autoclose_guard_rails(self):
        """push_check applies autoclose.guard_rails (the same function auto-close's run() uses), so a guard that holds
        an auto-close also keeps the push; a clean pass suppresses; a person's verdict and suspicious sources win.
        REQ: PSH-02, PSH-03"""
        _reset()
        import eventstore, enrich, kb  # noqa: E401
        cls = {"e1": {"label": "expected", "confidence": 0.95, "at": 1}}
        pv = {}
        with mock.patch.object(eventstore, "open_events", return_value={"events": []}), \
             mock.patch.object(autoclose, "_event_index", return_value=({}, {})), \
             mock.patch.object(enrich, "load", return_value={}), \
             mock.patch.object(corr_llm, "classes", lambda ids, pending=False: {k: v for k, v in cls.items() if k in ids}), \
             mock.patch.object(kb, "person_verdicts", lambda ids: {k: v for k, v in pv.items() if k in ids}):
            with mock.patch.object(autoclose, "guard_rails", wraps=autoclose.guard_rails) as gr:
                r = autoclose.push_check("e1")
            gr.assert_called_once()
            self.assertTrue(r["ok"], r)
            with mock.patch.object(autoclose, "guard_rails", return_value=("protected", "protected category: admin", ["reviewer_expected"], [], ["admin"])):
                r = autoclose.push_check("e1")
            self.assertFalse(r["ok"])
            self.assertEqual(r["guard"], "protected")
            cls["e2"] = {"label": "suspicious", "at": 2}
            self.assertFalse(autoclose.push_check("e1", ["e2"])["ok"])
            pv["e1"] = {"verdict": "benign", "ts": 3, "author": "user:a"}
            self.assertTrue(autoclose.push_check("e1", ["e2"])["ok"])
        _reset()


if __name__ == "__main__":
    unittest.main()
