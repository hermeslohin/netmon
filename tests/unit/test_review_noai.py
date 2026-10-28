#!/usr/bin/env python3
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); import _env  # noqa: E402

import types  # noqa: E402
import unittest  # noqa: E402
from unittest import mock  # noqa: E402

import review  # noqa: E402

ITEMS = {"events": [{"id": "ids|1", "mode": "review", "prior": [{"id": "p1"}]}, {"id": "gw|2", "mode": "review"},
                    {"id": "hf|3", "mode": "research"}]}


def _run(trigger, event=None):
    r = review.Run.__new__(review.Run)
    r.args = types.SimpleNamespace(trigger=trigger, event=event)
    r.daily, r.pdf = False, False
    r.stem, r.counts, r.errors, r.researched, r.max_batches, r.web = "/tmp/x", {}, [], [], 2, False
    r.status = mock.Mock()
    r.target = {"provider": "api:x", "model": "m"}
    return r


class ScheduledNoAITest(unittest.TestCase):
    def _enrich(self, r):
        calls = []
        with mock.patch.object(review, "sh", return_value=(0, "", "")), mock.patch.object(review, "jload", return_value=ITEMS), \
                mock.patch.object(review.os, "remove"), mock.patch.object(review.Run, "converse", lambda self, name, *a, **k: calls.append(name)), \
                mock.patch.object(review.Run, "tools", lambda self, *a: {}), mock.patch.object(review, "prompt", lambda n: ""):
            r.budget = mock.Mock(summary=lambda: {"prompt": 0, "completion": 0, "cache_read": 0, "cache_write": 0, "cost_usd": 0, "total": 0, "calls": 0})
            r.enrich()
        return calls

    def test_scheduled_run_makes_no_ai_call(self):
        """A scheduled run queues work items but never calls the model (no reviewer, no research).
        REQ: OPS-06"""
        r = _run("schedule")
        self.assertEqual(self._enrich(r), [])
        self.assertEqual(r.counts["review_to_research"], 2)
        self.assertIn("no AI calls", r.summary())

    def test_manual_run_uses_reviewer_only(self):
        """Run now (manual) runs the reviewer but no event research.
        REQ: OPS-06"""
        calls = self._enrich(_run("manual"))
        self.assertTrue(calls and all(c.startswith("review") for c in calls))

    def test_event_request_researches(self):
        """Send to research (--event) is the only path to event research.
        REQ: OPS-06"""
        calls = self._enrich(_run("manual", event="hf|3"))
        self.assertTrue(any(c.startswith("enrich") for c in calls))


if __name__ == "__main__":
    unittest.main()
