"""Every open event gets an event reviewer label, a Pending review badge or a 'Not reviewed: <reason>' badge
(corr_llm.review_base / event_pass open_ids / classes pending=True), also after its review run stopped being the newest."""
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); import _env  # noqa: E401,E402

import time  # noqa: E402
import unittest  # noqa: E402
from unittest import mock  # noqa: E402

import corr_llm  # noqa: E402
import store  # noqa: E402


def _ev(label, t, sev="medium", typ="host"):
    return {"type": typ, "label": label, "sev": sev, "t0": t, "t1": t, "ips": ["10.0.0.5"]}


class TestOpenEventsCoverage(unittest.TestCase):
    """Open events outside the newest review run, linkless ones and never-reviewed ones never show a blank label."""

    def setUp(self):
        _env.fresh_db()
        store._cfg_cache.clear()
        with corr_llm._db() as c:
            for t in ("verdicts", "event_class", "review_pending", "review_events", "decision_inputs", "event_sources"):
                c.execute(f'DELETE FROM "{t}"')  # noqa: S608 - fixed table names
        corr_llm._REVIEW_FAILS.clear()
        self.calls = []

        def fake(target, anchor, cands, *a, **kw):
            self.calls.append((anchor["label"], sorted(c[0]["label"] for c in cands)))
            return ([{"id": "anchor", "label": "benign", "confidence": 0.8, "reason": "routine"}], {"prompt": 1, "completion": 1}, 1.0)
        self.patches = [mock.patch.object(corr_llm, "_ask_full", fake),
                        mock.patch.object(corr_llm, "_target", lambda model=None: {"provider": "lmstudio", "model": "reviewer"}),
                        mock.patch.object(corr_llm, "reopen_checked", lambda *a, **k: None),
                        mock.patch.object(corr_llm, "reviewer_off", lambda: None)]
        for p in self.patches:
            p.start()
        self.saved_open = dict(corr_llm._OPEN)

    def tearDown(self):
        for p in self.patches:
            p.stop()
        corr_llm._OPEN.clear(); corr_llm._OPEN.update(self.saved_open)
        corr_llm._REVIEW_FAILS.clear()
        _env.fresh_db()

    def decide(self, a, b, related=True):
        with corr_llm._db() as c:
            c.execute("INSERT OR REPLACE INTO verdicts (pair, related, confidence, reason, model, ts) VALUES (?,?,?,?,?,?)",
                      (corr_llm.pair(a, b), 1 if related else 0, 0.9, "clef", "clef", time.time()))

    def set_open(self, rows):
        corr_llm._OPEN.update(t=time.time() + 3600, rows=rows, m={m for r in rows for m in [r["eid"], *r["members"]]})

    def badge(self, eid):
        """What a page shows for an event: 'verdict', 'pending' or 'unreviewed' (with its reason), or None = blank."""
        c = corr_llm.classes([eid], pending=True).get(eid)
        if not c:
            return None
        if c["label"] == "pending":
            return "pending" if c.get("pending") else None
        if c["label"] == "unreviewed":
            return "unreviewed" if c.get("unreviewed") else None
        return "verdict"

    def test_open_event_of_an_older_run_gets_labelled(self):
        """An open event whose review run is no longer the newest (and a linkless one) shows Pending review with its
        settle time, then gets an event reviewer label once settled; acked events of old runs are not reviewed.
        REQ: EVW-08"""
        now = 1_800_000_000
        runs = {"old": {"events": {"x": _ev("new executable Xvnc", now - 300), "y": _ev("new executable xauth", now - 290),
                                   "z": _ev("new executable gtk-update", now - 280), "acked": _ev("old acked", now - 280)},
                        "related": {"x": [{"id": "y", "score": 5, "why": []}], "acked": [{"id": "z", "score": 1, "why": []}]}},
                "new": {"events": {"n": _ev("unrelated", now - 10)}, "related": {}}}
        self.decide("x", "y"); self.decide("acked", "z", related=False)
        rows = [{"eid": e, "members": [e], "last_sid": "old"} for e in ("x", "y", "z")] + [{"eid": "n", "members": ["n"], "last_sid": "new"}]
        self.set_open(rows)
        base, focus, open_ids, sids = corr_llm.review_base(runs.get, "new", rows)
        self.assertEqual(sids, ["old"])
        self.assertEqual(open_ids, {"x", "y", "z", "n"})
        self.assertNotIn("acked", focus)
        self.assertEqual(corr_llm.event_pass(base, now=now, focus=focus, open_ids=open_ids), 0)
        for e in ("x", "y", "z", "n"):
            self.assertEqual(self.badge(e), "pending", e)
        self.assertEqual(corr_llm.classes(["x"], pending=True)["x"]["pending"]["settles"], now - 290 + corr_llm.settle_s())
        later = now + corr_llm.settle_s() + 1
        n = corr_llm.event_pass(base, now=later, focus=focus, open_ids=open_ids)
        self.assertEqual(n, 3)  # group x+y, linkless z, linkless n: one call each
        self.assertEqual(len(self.calls), 3)
        for e in ("x", "y", "z", "n"):
            self.assertEqual(self.badge(e), "verdict", e)
        self.assertIsNone(corr_llm.classes(["acked"], pending=True).get("acked"))  # not open: no badge needed, not reviewed

    def test_never_reviewed_open_events_say_why_and_new_ones_are_queued(self):
        """An open event the reviewer will never label shows 'Not reviewed: <reason>' (cleared by a person, review run
        removed); one opened since the last pass shows Pending review (queued); no open event is ever blank.
        REQ: EVW-08"""
        now = 1_800_000_000
        base = {"events": {"c": _ev("cleared", now - 2000), "d": _ev("fine", now - 2000)}, "related": {}}
        rows = [{"eid": "c", "members": ["c"], "last_sid": "r"}, {"eid": "gone", "members": ["gone"], "last_sid": "pruned"},
                {"eid": "d", "members": ["d"], "last_sid": "r"}, {"eid": "fresh", "members": ["fresh"], "last_sid": "r2"}]
        with mock.patch.object(corr_llm, "_cleared", lambda: {"c"}):
            corr_llm.event_pass(base, now=now, focus=set(base["events"]), open_ids={"c", "gone", "d"})
        self.set_open(rows)
        c = corr_llm.classes(["c", "gone", "d", "fresh"], pending=True)
        self.assertIn("cleared", c["c"]["unreviewed"])
        self.assertIn("removed", c["gone"]["unreviewed"])
        self.assertEqual(c["d"]["label"], "benign")
        self.assertTrue(c["fresh"]["pending"]["queued"])
        for r in rows:
            self.assertIsNotNone(self.badge(r["eid"]), r["eid"])
        self.assertEqual(corr_llm.clef_overview()["pending"]["events"], 0)  # 'not reviewed' rows are not counted as pending
        with mock.patch.object(corr_llm, "reviewer_off", lambda: "the event reviewer is off (NETMON_LLM)"):
            self.assertIn("off", corr_llm.classes(["fresh"], pending=True)["fresh"]["unreviewed"])
        self.assertIsNone(corr_llm.classes(["fresh"], pending=False).get("fresh"))  # auto-close never sees a placeholder

    def test_event_of_a_pruned_run_is_rebuilt_from_the_event_store(self):
        """An open event whose review run's documents were pruned is rebuilt from the events table and labelled.
        REQ: EVW-08"""
        import eventstore
        now = time.time()
        with eventstore._c() as c:
            c.execute("INSERT INTO events (eid, type, label, sev, link, t0, t1, first_seen, last_seen, last_sid, n, resolved, doc) "
                      "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", ("hf|exec-new|h|/usr/bin/x", "host", "New executable x", "medium", "#", now - 4000,
                                                              now - 4000, "a", "b", "pruned", 1, 0, '{"ips": ["10.0.0.5"]}'))
        rows = [{"eid": "hf|exec-new|h|/usr/bin/x", "members": ["hf|exec-new|h|/usr/bin/x"], "last_sid": "pruned"}]
        base, focus, open_ids, _ = corr_llm.review_base({"new": {"events": {}, "related": {}}}.get, "new", rows)
        self.assertEqual(base["events"]["hf|exec-new|h|/usr/bin/x"]["type"], "host")
        self.assertEqual(corr_llm.event_pass(base, now=now, focus=focus, open_ids=open_ids), 1)
        self.assertEqual(self.badge("hf|exec-new|h|/usr/bin/x"), "verdict")


if __name__ == "__main__":
    unittest.main()
