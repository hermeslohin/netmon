"""Unit tests for the event reviewer's one-paragraph output contract, the decision state's kept count and the
"events processed" counts in the Review log (corr_llm._touch, review.Status.finish, reviewlog.job_runs)."""
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); import _env  # noqa: E401,E402

import json  # noqa: E402
import time  # noqa: E402
import unittest  # noqa: E402

import audit  # noqa: E402
import clef  # noqa: E402
import corr_llm  # noqa: E402
import reviewlog  # noqa: E402
import review  # noqa: E402
import review_cfg  # noqa: E402


def _ev(i, label="x"):
    return {"type": "ids", "label": f"{label} {i}", "sev": "low"}


class ReviewerParagraphContractTest(unittest.TestCase):
    """The event reviewer writes one reason paragraph per event and only artifacts per link."""

    def test_schema_does_not_require_link_reason(self):
        """The event-review JSON schema requires id, label, confidence and artifacts, but no per-link reason.
        REQ: FEAT-07"""
        item = corr_llm.ESCHEMA["properties"]["decisions"]["items"]
        self.assertEqual(set(item["required"]), {"id", "label", "confidence", "artifacts"})
        self.assertIn("reason", item["properties"])  # the anchor's paragraph is still allowed
        self.assertIn("link", item["properties"]["label"]["enum"])

    def test_prompt_asks_for_analyst_write_up(self):
        """The event reviewer prompt asks for an analyst write-up (up to two headed paragraphs) and artifacts only (no reason) per candidate.
        REQ: FEAT-07"""
        s = corr_llm.EVENT_SYSTEM
        self.assertIn("up to two short paragraphs", s)
        self.assertIn("security analyst", s)
        self.assertIn("only its", s.replace("\n", " ").replace("   ", " "))
        self.assertIn("no reason text", s)
        self.assertNotIn('"reason", "artifacts"}', corr_llm.EFMT)


class EventsProcessedTest(unittest.TestCase):
    """Review log entries count the distinct events processed."""

    def setUp(self):
        self._st = dict(corr_llm.STATUS)
        self._seen = set(corr_llm._EVENTS_SEEN)
        reviewlog.RING.clear()
        self.sent = []
        self._emit = audit.emit
        audit.emit = self.sent.append
        self._rc = (review_cfg.status, review_cfg.write_status)

    def tearDown(self):
        corr_llm.STATUS.clear(); corr_llm.STATUS.update(self._st)
        corr_llm._EVENTS_SEEN.clear(); corr_llm._EVENTS_SEEN.update(self._seen)
        audit.emit = self._emit
        review_cfg.status, review_cfg.write_status = self._rc

    def test_touch_counts_distinct_events(self):
        """Touching the same event twice (link decided, then labelled) counts it once; empty ids are ignored.
        REQ: FEAT-09"""
        corr_llm._EVENTS_SEEN.clear()
        corr_llm._touch("a", "b")
        corr_llm._touch("a")
        corr_llm._touch("", None)
        self.assertEqual(corr_llm.STATUS["events_this_run"], 2)

    def test_review_job_run_records_counts(self):
        """A finished review-job run stores events processed / given a note / queued, and the Review log entry carries them.
        REQ: FEAT-09"""
        saved = {}
        review_cfg.status = lambda: json.loads(json.dumps(saved.get("d") or {}))
        review_cfg.write_status = lambda d: saved.__setitem__("d", json.loads(json.dumps(d)))

        class Budget:
            def summary(self):
                return {"prompt": 0, "completion": 0, "total": 0, "cache_read": 0, "cache_write": 0, "cost_usd": 0, "calls": 0}

        st = review.Status({"model": "m", "provider": "p"}, "schedule", False)
        st.run["started"] = time.time() - 5
        st.finish("completed", None, Budget(), "ok", False, {"work_items": 7, "review_copied": 3, "queued": 2})
        run = saved["d"]["runs"][0]
        self.assertEqual((run["events"], run["events_reviewed"], run["events_queued"]), (7, 3, 2))
        state = {}
        self.assertEqual(reviewlog.job_runs(state), 1)
        d = self.sent[-1]
        R = d["netmon"]["review"]
        self.assertEqual((R["events_processed"], R["events_reviewed"], R["events_queued"]), (7, 3, 2))
        self.assertIn("7 events processed, 3 given a note, 2 queued", d["message"])

    def test_run_without_counts_has_no_counts_text(self):
        """A run that recorded no counts (older runs, crash before counting) logs no "events processed" text.
        REQ: FEAT-09"""
        saved = {}
        review_cfg.status = lambda: json.loads(json.dumps(saved.get("d") or {}))
        review_cfg.write_status = lambda d: saved.__setitem__("d", json.loads(json.dumps(d)))

        class Budget:
            def summary(self):
                return {"prompt": 0, "completion": 0, "total": 0, "cache_read": 0, "cache_write": 0, "cost_usd": 0, "calls": 0}

        st = review.Status({"model": "m"}, "manual", False)
        st.finish("failed", "boom", Budget(), "", False)
        run = saved["d"]["runs"][0]
        self.assertIsNone(run["events"]); self.assertIsNone(run["events_reviewed"])
        reviewlog.job_runs({})
        self.assertNotIn("events processed", self.sent[-1]["message"])
        self.assertEqual(self.sent[-1]["event"]["outcome"], "failure")


if __name__ == "__main__":
    unittest.main()


class AnalystWriteUp(unittest.TestCase):
    def test_write_up_format_and_summaries(self):
        """Two headed paragraphs are asked for, stored long enough, and the Verdict paragraph feeds alarms and pushes.
        REQ: REV-01"""
        import corr_llm
        import pushgate
        for h in ("Why it fired: ", "Verdict: "):
            self.assertIn(h, corr_llm.EVENT_SYSTEM)
            self.assertIn(h, corr_llm.CLASS_SYSTEM)
        self.assertGreaterEqual(corr_llm.REASON_MAX, 2000)
        r = ("Why it fired: OpenCTI lists 141.193.213.10 (Phishunt, score 60); the iPad reached www.clever.com on it, a WP Engine "
             "address shared by many sites.\n\nVerdict: Expected. The site is Clever, a school login portal. Nothing to do.")
        self.assertEqual(corr_llm.reason_summary(r), "Expected. The site is Clever, a school login portal. Nothing to do.")
        self.assertEqual(pushgate._line(r), "Expected. The site is Clever, a school login portal. Nothing to do.")
        self.assertTrue(corr_llm.reason_summary("x " * 200).endswith("…"))
