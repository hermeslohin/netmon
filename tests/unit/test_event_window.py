"""Event window (lookback.py): one setting for the correlation window, the review job's coverage and the event
reviewer's settle wait; group reviews in corr_llm.event_pass (one call per settled correlated group, Pending review)."""
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); import _env  # noqa: E401,E402

import json  # noqa: E402
import time  # noqa: E402
import unittest  # noqa: E402
from unittest import mock  # noqa: E402

import corr_llm  # noqa: E402
import correlate  # noqa: E402
import eventstore  # noqa: E402
import lookback  # noqa: E402
import review_cfg  # noqa: E402
import store  # noqa: E402
import window  # noqa: E402


def _clean():
    _env.fresh_db()
    with store.connect() as c:
        c.execute("DELETE FROM meta WHERE k IN (?, ?, ?, ?, ?)", (lookback.KEY, lookback._OLD_KEY, review_cfg.KEY, "arrival:watch", "arrival:review"))
    store._cfg_cache.clear()


def _set_window(m):
    d = store.cfg_load("site")
    d["event_window_minutes"] = m
    store.cfg_save("site", d)


class TestEventWindowSetting(unittest.TestCase):
    """lookback.py: default, range check, live pickup and migration of the old hours lookback."""

    def setUp(self):
        _clean()

    def tearDown(self):
        _clean()

    def test_default_and_range(self):
        """Without a stored value the event window is 10 min (range 2-120) and lives in the cfg table's site document.
        REQ: EVW-01"""
        g = lookback.get()
        self.assertEqual((g["minutes"], g["default"], g["min"], g["max"], g["set"]), (10, 10, 2, 120, False))
        self.assertEqual(lookback.settle_s(), 10 * 60 + lookback.INGEST_SLACK_S)
        self.assertEqual(lookback.put(" 25 ", "admin")["minutes"], 25)
        self.assertEqual(store.cfg_load("site")["event_window_minutes"], 25)
        self.assertTrue(lookback.get()["set"])

    def test_put_rejects_invalid(self):
        """put() refuses values outside 2-120, fractions, booleans and non-numbers and keeps the saved value.
        REQ: EVW-01"""
        lookback.put(8, "a")
        for bad in (0, 1, 121, -5, "1.5", 1.5, True, None, "abc", "", [4]):
            with self.assertRaises(ValueError, msg=repr(bad)):
                lookback.put(bad, "a")
        self.assertEqual(lookback.minutes(), 8)
        _set_window(999)  # a bad value written straight into the table reads back as the default
        self.assertEqual(lookback.minutes(), 10)

    def test_live_pickup(self):
        """A change saved in the cfg table is seen by minutes(), the correlation and the event reviewer without a restart.
        REQ: EVW-01"""
        _set_window(5)
        self.assertEqual(lookback.minutes(), 5)
        self.assertEqual(correlate.window_s(), 300)
        self.assertEqual(corr_llm.settle_s(), 300 + correlate.INGEST_SLACK_S)
        self.assertEqual(corr_llm.limits()["window_minutes"], 5)
        _set_window(10)
        self.assertEqual(correlate.window_s(), 600)

    def test_migrates_old_hours_lookback(self):
        """The retired review lookback (store meta, hours) is copied once into the event window (hours x 60, clamped).
        REQ: EVW-01"""
        with store.connect() as c:
            c.execute("INSERT OR REPLACE INTO meta VALUES (?, ?)", (lookback.KEY, json.dumps({"hours": 1, "by": "a", "at": 1})))
        self.assertEqual(lookback.migrate(), 60)
        self.assertEqual(lookback.minutes(), 60)
        self.assertIn("1 h", lookback.get()["migrated"])
        self.assertIsNone(lookback.migrate())  # once only: a later change is never overwritten
        lookback.put(10, "a")
        self.assertIsNone(lookback.migrate())
        self.assertEqual(lookback.minutes(), 10)

    def test_for_run(self):
        """The 05 UTC daily run stays 24 h; other runs use the event window in hours.
        REQ: EVW-01, OPS-03"""
        self.assertEqual(lookback.for_run(5)[0], 24)
        lookback.put(30, "a")
        self.assertEqual(lookback.for_run(10)[0], 0.5)

    def test_review_interval_capped_at_window(self):
        """The review job runs at least once per event window (never under its 5-minute floor); the stored interval is kept.
        REQ: EVW-03"""
        review_cfg.put({"interval_minutes": 15}, "a")
        self.assertEqual((review_cfg.get()["interval_minutes"], review_cfg.get()["interval_effective"]), (15, 10))
        lookback.put(2, "a")
        self.assertEqual(review_cfg.get()["interval_effective"], 5)
        lookback.put(60, "a")
        self.assertEqual(review_cfg.get()["interval_effective"], 15)
        n = review_cfg.next_run(1_800_000_000)
        self.assertEqual((n - review_cfg.DAILY_HOUR * 3600) % 900, 0)


class TestWatchPeriod(unittest.TestCase):
    """scheduler: the Elasticsearch pull (watcher) runs once per event window and follows the setting live."""

    def setUp(self):
        _clean()

    def tearDown(self):
        _clean()

    def test_watch_runs_once_per_window(self):
        """With a 10-min window the watcher starts once per 10-min slot; at 5 min it follows at once.
        REQ: EVW-06"""
        import scheduler
        started = []
        t0 = 1_800_000_000 - 1_800_000_000 % 600
        with mock.patch.object(scheduler, "start", side_effect=lambda job, *a, **k: started.append(job) or True), \
                mock.patch.object(scheduler, "_state", return_value={}) as st, mock.patch.object(scheduler, "_save"):
            state = {"review": 0}
            st.return_value = state
            for k in range(0, 1800, 60):  # 30 minutes, one tick a minute
                scheduler.tick(t0 + k)
            self.assertEqual(started.count("watch"), 3)
            self.assertEqual(scheduler.watch_period(), 600)
            lookback.put(5, "a")
            started.clear()
            for k in range(1800, 3600, 60):
                scheduler.tick(t0 + k)
            self.assertEqual(started.count("watch"), 6)
        self.assertEqual(scheduler.status()["watch_period_minutes"], 5)

    def test_watch_pulls_touch_end_to_end(self):
        """Watcher arrival windows read from the bookmark: consecutive pulls have no gap and no overlap.
        REQ: EVW-06"""
        prev = None
        for k in range(4):
            window.arrival("watch", 10, now=1_800_000_000 + k * 600)
            frm, to = window._ARR["frm"], window._ARR["to"]
            if prev is not None:
                self.assertEqual(frm, prev)
            window.commit()
            prev = to
        window._ARR.clear()


class TestCoverage(unittest.TestCase):
    """window.arrival back=: review runs cover everything since the previous run plus one window, with no gaps."""

    def setUp(self):
        _clean()

    def tearDown(self):
        window._ARR.clear()
        _clean()

    def test_no_gaps_when_interval_exceeds_window(self):
        """With a 10-min window and runs 15 min apart, each run starts one window before the previous run's end.
        REQ: EVW-03"""
        t0, prev_to = 1_800_000_000, None
        for k in range(4):
            w = window.arrival("review", 10, overlap=True, now=t0 + k * 900, back=600)
            frm, to = window._ARR["frm"], window._ARR["to"]
            if prev_to is not None:
                self.assertLessEqual(frm, prev_to - 600)  # overlap of one window: nothing between two runs
            self.assertGreater(w["span_minutes"], 10 if k else 9)
            window.commit()
            prev_to = to


class TestCorrelationWindow(unittest.TestCase):
    """correlate.build: two events farther apart than the event window never become a candidate link."""

    GEN = 1_800_000_000

    def build(self, gap_s, window_s=None):
        raw = {"generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.GEN)), "hours": 1}
        alerts = [{"id": 1, "ts": self.GEN - 100 - gap_s, "key": "x|1", "text": "ssh failures from 10.0.0.7 to 10.0.0.9", "targets": ["ip:10.0.0.9"]},
                  {"id": 2, "ts": self.GEN - 100, "key": "x|2", "text": "new admin session 10.0.0.7 to 10.0.0.9", "targets": ["ip:10.0.0.9"]}]
        return correlate.build(raw, {}, alerts, [], [], lambda ip: ip.startswith("10."), lambda h: "", lambda s, t: [], latest=True, window=window_s)

    def linked(self, res):
        return any(r["id"].startswith("alert|") for lst in res["related"].values() for r in lst)

    def test_links_only_within_window(self):
        """Events 5 min apart link with a 10-min window; 20 min apart they do not, unless the window is widened.
        REQ: EVW-02"""
        self.assertTrue(self.linked(self.build(300, 600)))
        self.assertFalse(self.linked(self.build(1200, 600)))
        self.assertTrue(self.linked(self.build(1200, 1800)))

    def test_default_follows_setting(self):
        """Without an explicit window build() uses the live setting.
        REQ: EVW-02"""
        _clean()
        try:
            _set_window(30)
            self.assertTrue(self.linked(self.build(1200)))
            _set_window(10)
            self.assertFalse(self.linked(self.build(1200)))
        finally:
            _clean()


def _ev(label, t, sev="medium"):
    return {"type": "alert", "label": label, "sev": sev, "t0": t, "t1": t, "ips": ["10.0.0.5"]}


class TestGroupReview(unittest.TestCase):
    """event_pass: one event reviewer call per settled correlated group, labels on every member, Pending review."""

    def setUp(self):
        _clean()
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
                        mock.patch.object(corr_llm, "reopen_checked", lambda *a, **k: None)]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        corr_llm._REVIEW_FAILS.clear()
        _clean()

    def decide(self, a, b, related=True):
        with corr_llm._db() as c:
            c.execute("INSERT OR REPLACE INTO verdicts (pair, related, confidence, reason, model, ts) VALUES (?,?,?,?,?,?)",
                      (corr_llm.pair(a, b), 1 if related else 0, 0.9, "clef", "clef", time.time()))

    def labels(self):
        return dict(corr_llm._db().execute("SELECT eid, label FROM event_class"))

    def test_waits_for_settle_then_one_call_for_the_group(self):
        """A group is labelled once, after its newest event is one window + ingest slack old: one call, every member labelled.
        REQ: EVW-04"""
        now = 1_800_000_000
        base = {"events": {"a": _ev("ssh failures", now - 400), "b": _ev("ssh login", now - 300), "c": _ev("sudo use", now - 200)},
                "related": {"a": [{"id": "b", "score": 5, "why": []}], "b": [{"id": "c", "score": 5, "why": []}]}}
        self.decide("a", "b"); self.decide("b", "c")
        self.assertEqual(corr_llm.event_pass(base, now=now), 0)
        self.assertEqual(self.calls, [])
        P = corr_llm.classes(["a", "b", "c"], pending=True)
        self.assertEqual({e: v["label"] for e, v in P.items()}, {"a": "pending", "b": "pending", "c": "pending"})
        self.assertEqual(P["a"]["pending"]["settles"], now - 200 + corr_llm.settle_s())
        self.assertEqual(P["a"]["pending"]["n"], 3)
        later = now - 200 + corr_llm.settle_s() + 1
        self.assertEqual(corr_llm.event_pass(base, now=later), 1)
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(len(self.calls[0][1]), 2)  # the other two members came with the one call
        self.assertEqual(self.labels(), {"a": "benign", "b": "benign", "c": "benign"})
        self.assertEqual(corr_llm.classes(["a"], pending=True)["a"].get("pending"), None)
        self.assertEqual(corr_llm.event_pass(base, now=later + 60), 0)  # no re-label on later passes
        self.assertEqual(len(self.calls), 1)
        row = corr_llm._db().execute("SELECT members, kind FROM review_events").fetchone()
        self.assertEqual(row, (3, "group"))

    def test_undecided_link_keeps_group_pending(self):
        """A group with an undecided link is not reviewed even after its settle time, and says links are deciding.
        REQ: EVW-04"""
        now = 1_800_000_000
        base = {"events": {"a": _ev("x", now - 5000), "b": _ev("y", now - 5000), "c": _ev("z", now - 5000)},
                "related": {"a": [{"id": "b", "score": 5, "why": []}, {"id": "c", "score": 5, "why": []}]}}
        self.decide("a", "b")
        self.assertEqual(corr_llm.event_pass(base, now=now), 0)
        self.assertTrue(corr_llm.classes(["a"], pending=True)["a"]["pending"]["links"])
        self.decide("a", "c", related=False)
        self.assertEqual(corr_llm.event_pass(base, now=now), 1)
        self.assertEqual(self.labels(), {"a": "benign", "b": "benign"})

    def test_new_member_rereviewed_once_after_settling(self):
        """A labelled group that gains a member keeps its label, shows Pending review and is reviewed once more after it settles.
        REQ: EVW-04"""
        now = 1_800_000_000
        base = {"events": {"a": _ev("x", now - 5000), "b": _ev("y", now - 4900)}, "related": {"a": [{"id": "b", "score": 5, "why": []}]}}
        self.decide("a", "b")
        self.assertEqual(corr_llm.event_pass(base, now=now), 1)
        base["events"]["d"] = _ev("w", now - 60)
        base["related"]["d"] = [{"id": "b", "score": 5, "why": []}]
        self.decide("d", "b")
        self.assertEqual(corr_llm.event_pass(base, now=now), 0)
        P = corr_llm.classes(["a", "d"], pending=True)
        self.assertEqual(P["a"]["label"], "benign")  # the earlier label stays visible
        self.assertTrue(P["a"]["pending"]["rereview"])
        self.assertEqual(P["d"]["label"], "pending")
        self.assertEqual(corr_llm.event_pass(base, now=now - 60 + corr_llm.settle_s() + 1), 1)
        self.assertEqual(len(self.calls), 2)
        self.assertEqual(self.labels(), {"a": "benign", "b": "benign", "d": "benign"})

    def test_high_severity_fast_path(self):
        """A high-severity event with no label gets a provisional label at once; its group review follows the settle.
        REQ: EVW-05"""
        now = 1_800_000_000
        base = {"events": {"a": _ev("threat intel hit", now - 30, "high"), "b": _ev("dns", now - 20)}, "related": {"a": [{"id": "b", "score": 5, "why": []}]}}
        self.decide("a", "b")
        self.assertEqual(corr_llm.event_pass(base, now=now), 1)
        self.assertEqual(self.labels(), {"a": "benign"})
        self.assertEqual(corr_llm.event_pass(base, now=now + 1), 0)  # provisional label: no second fast call
        self.assertTrue(corr_llm.classes(["a"], pending=True)["a"]["pending"])
        self.assertEqual(corr_llm.event_pass(base, now=now - 20 + corr_llm.settle_s() + 1), 1)
        self.assertEqual(self.labels(), {"a": "benign", "b": "benign"})
        self.assertEqual([k for (k,) in corr_llm._db().execute("SELECT kind FROM review_events ORDER BY ts, rowid")], ["fast", "group"])

    def test_waits_for_a_pull_after_newest_plus_window(self):
        """A group whose settle time passed is still pending until an Elasticsearch pull committed arrivals past newest + one window.
        REQ: EVW-06"""
        now = 1_800_000_000
        newest = now - 2000
        base = {"events": {"a": _ev("x", newest - 60), "b": _ev("y", newest)}, "related": {"a": [{"id": "b", "score": 5, "why": []}]}}
        self.decide("a", "b")
        with store.connect() as c:  # the last pull ended before newest + window: a late member could still arrive
            c.execute("INSERT OR REPLACE INTO meta VALUES (?, ?)", ("arrival:watch", json.dumps({"to": newest + 300, "from": newest - 300})))
        self.assertEqual(corr_llm.event_pass(base, now=now), 0)
        p = corr_llm.classes(["a"], pending=True)["a"]["pending"]
        self.assertGreater(p["settles"], newest + 600)
        window.arrival("watch", 10, now=newest + 600 + 300)  # the next pull covers past newest + window
        window.commit()
        window._ARR.clear()
        self.assertEqual(corr_llm.event_pass(base, now=now), 1)
        self.assertEqual(self.labels(), {"a": "benign", "b": "benign"})

    def test_alert_verdict_pending(self):
        """Pages show Pending review (filterable) for an event whose group has not settled, never a blank or Not reviewed.
        REQ: EVW-05"""
        now = time.time()
        base = {"events": {"a": _ev("x", now - 30), "b": _ev("y", now - 20)}, "related": {"a": [{"id": "b", "score": 5, "why": []}]}}
        self.decide("a", "b")
        corr_llm.event_pass(base, now=now)
        X = {"classes": corr_llm.classes(["a"], pending=True)}
        self.assertEqual(eventstore.alert_verdict("a", X), ("pending", "ai"))
        ov = corr_llm.clef_overview()["pending"]
        self.assertEqual(ov["events"], 2)
        self.assertEqual(ov["past_settle"], 0)


if __name__ == "__main__":
    unittest.main()
