#!/usr/bin/env python3
"""Unit tests for the review / research split: review.py never researches, research.py runs only for a person's click."""
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); import _env  # noqa: E401,E402

import json  # noqa: E402
import types  # noqa: E402
import unittest  # noqa: E402
from unittest import mock  # noqa: E402

import research  # noqa: E402
import review  # noqa: E402
import scheduler  # noqa: E402

ITEMS = {"events": [{"id": "ids|1", "mode": "review", "prior": [{"id": "p1"}]}, {"id": "gw|2", "mode": "review"},
                    {"id": "hf|3", "mode": "queue"}, {"id": "hf|4", "mode": "queue", "note": {"verdict": "benign"}}]}


def _review():
    r = review.Review.__new__(review.Review)
    r.args = types.SimpleNamespace(trigger="schedule", skip_collect=True)
    r.stem, r.counts, r.errors, r.daily, r.web, r.es, r.max_searches = "/tmp/x", {}, [], False, False, True, 0
    r.fetched, r.es_found = set(), []
    r.target, r.reviewer_ok = {"provider": "lmstudio", "model": "gemma"}, True
    r.status = mock.Mock()
    r.budget = mock.Mock(summary=lambda: {"prompt": 0, "completion": 0, "cache_read": 0, "cache_write": 0, "cost_usd": 0, "total": 0, "calls": 0})
    return r


class ReviewNeverResearchesTest(unittest.TestCase):
    def _queue(self, r, decide=None):
        calls, cmds = [], []

        def conv(self, name, system, user, tools, stop, **k):
            calls.append((name, sorted(tools)))
            if decide:
                tools["submit_review"][0]({"decisions": decide})

        def fake_sh(cmd, timeout=None, inp=None):
            cmds.append(cmd[1:2])
            return 0, "", ""
        with mock.patch.object(review, "sh", fake_sh), mock.patch.object(review, "jload", return_value=json.loads(json.dumps(ITEMS))), \
                mock.patch.object(review.os, "remove"), mock.patch.object(review.Review, "converse", conv), \
                mock.patch.object(review, "prompt", lambda n: n):
            r.queue()
        return calls, cmds

    def test_reviewer_only_copies_or_queues(self):
        """The review job's reviewer only sees review-category items with a prior note, gets no web or submit_notes tool,
        and every item it does not copy stays in the queue.
        REQ: OPS-06"""
        r = _review()
        calls, cmds = self._queue(r, decide=[{"id": "ids|1", "action": "copy", "from": "p1", "reason": "same"}])
        self.assertEqual([c[0] for c in calls], ["review1"])
        self.assertIn("submit_review", calls[0][1])
        for t in ("submit_notes", "web_search", "web_fetch"):
            self.assertNotIn(t, calls[0][1])
        self.assertEqual(r.counts["review_copied"], 1)
        self.assertEqual(r.counts["queued"], 2)  # gw|2 (no prior) + hf|3 (queue mode)
        self.assertNotIn(["put"], cmds)  # never stores new notes

    def test_reviewer_queue_decision(self):
        """A "queue" decision leaves the event in the queue; nothing is copied.
        REQ: OPS-06"""
        r = _review()
        self._queue(r, decide=[{"id": "ids|1", "action": "queue", "reason": "different"}])
        self.assertEqual(r.counts.get("review_copied", 0), 0)
        self.assertEqual(r.counts["queued"], 3)
        self.assertIn("left in the queue", r.summary())
        self.assertNotIn("research", r.summary().lower())

    def test_no_reviewer_model_makes_no_call(self):
        """Without a usable reviewer model the run still finishes; review items wait in the queue.
        REQ: OPS-06"""
        r = _review()
        r.reviewer_ok = False
        calls, _ = self._queue(r)
        self.assertEqual(calls, [])
        self.assertEqual(r.counts["queued"], 3)

    def test_review_uses_the_correlation_reviewer_model(self):
        """review.py takes its model from the correlation reviewer (corr_llm), not from the research settings.
        REQ: OPS-06"""
        fake = types.SimpleNamespace(_target=lambda: {"provider": "lmstudio", "model": "google/gemma"})
        with mock.patch.dict(sys.modules, {"corr_llm": fake}):
            self.assertEqual(review.reviewer_target(), {"provider": "lmstudio", "model": "google/gemma"})
        self.assertNotIn("research_cfg", review.RC.__name__)


class ResearchOnDemandTest(unittest.TestCase):
    def test_research_requires_an_event(self):
        """research.py refuses to start without --event: there is no scheduled or batch research.
        REQ: OPS-06"""
        with mock.patch.object(sys, "argv", ["research.py"]), mock.patch("sys.stderr"), self.assertRaises(SystemExit):
            research.main()

    def test_scheduler_never_schedules_research(self):
        """The scheduler's jobs contain no research.py; research starts only from a queued Send to research click.
        REQ: OPS-06"""
        self.assertFalse(any("research.py" in " ".join(v) for v in scheduler.JOBS.values()))
        started, puts = [], []
        fake_start = lambda name, argv=None, why="": started.append(argv) or True  # noqa: E731
        scheduler.running.pop("research", None)
        with mock.patch.object(scheduler, "start", fake_start), mock.patch("research_cfg._meta", return_value={}):
            scheduler._dispatch_research()
        self.assertEqual(started, [])
        reqs = {"items": {"k": {"eid": "hf|9", "by": "dan", "at": 1}}}
        with mock.patch.object(scheduler, "start", fake_start), mock.patch("research_cfg._meta", return_value=reqs), \
                mock.patch("research_cfg._meta_put", lambda k, v: puts.append(v)):
            scheduler._dispatch_research()
        self.assertEqual(len(started), 1)
        self.assertTrue(started[0][1].endswith("research.py") and started[0][3] == "hf|9")
        self.assertEqual(puts[0]["items"]["k"]["tries"], 1)


if __name__ == "__main__":
    unittest.main()
