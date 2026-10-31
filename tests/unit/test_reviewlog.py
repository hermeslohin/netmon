"""Review log (reviewlog.py) and the daily audit indices (audit.index_for) - no Elasticsearch needed."""
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); import _env  # noqa: E402

import json  # noqa: E402
import time  # noqa: E402
import unittest  # noqa: E402

import audit  # noqa: E402
import reviewlog  # noqa: E402


class ReviewLogTest(unittest.TestCase):
    def setUp(self):
        reviewlog.RING.clear()
        self.sent = []
        self._emit = audit.emit
        audit.emit = self.sent.append

    def tearDown(self):
        audit.emit = self._emit

    def test_daily_index_name(self):
        """Every entry is written to <base>-YYYY.MM.DD of its own @timestamp (UTC), so retention can drop whole days;
        reads cover the daily indices and the older single index.
        REQ: AUD-04"""
        self.assertEqual(audit.index_for({"@timestamp": "2026-10-31T23:59:59.000Z"}), audit.index() + ".2026.10.31")
        self.assertRegex(audit.index_for({}), r"\.\d{4}\.\d\d\.\d\d$")
        self.assertEqual(audit.read_pattern(), f"{audit.index()},{audit.index()}.*,{audit.index()}-*")
        t = json.load(open(audit.TEMPLATE))
        self.assertIn("logs-netmon.*", t["index_patterns"])
        self.assertIn("review", t["template"]["mappings"]["properties"]["netmon"]["properties"])

    def test_correlation_pass_logged(self):
        """A pass that did work is logged with its counts; an idle pass is not; a failing one is logged as a problem.
        REQ: AUD-04"""
        st = {"decided_this_run": 12, "clef_events_this_run": 3, "classified_this_run": 3, "model": "gemma", "clef_model": "Cloudflare/clef"}
        d = reviewlog.correlation_pass(time.time() - 4, time.time(), st, 15)
        self.assertEqual(d["event"]["dataset"], "netmon.review")
        self.assertEqual(d["netmon"]["review"]["status"], "ok")
        self.assertEqual(d["netmon"]["review"]["links_decided"], 12)
        self.assertIsNone(reviewlog.correlation_pass(time.time(), time.time(), {}, 0))
        bad = reviewlog.correlation_pass(time.time(), time.time(), {"review_failed_this_run": 2, "classified_this_run": 1}, 1)
        self.assertEqual(bad["netmon"]["review"]["status"], "partial")
        self.assertEqual(bad["event"]["outcome"], "failure")
        crash = reviewlog.correlation_pass(time.time(), time.time(), {}, 0, "RuntimeError: boom")
        self.assertEqual(crash["netmon"]["review"]["status"], "crashed")
        self.assertEqual(len(self.sent), 3)

    def test_view_falls_back_to_memory(self):
        """Without Elasticsearch the card shows the in-memory ring, with per-kind totals.
        REQ: AUD-04"""
        reviewlog.correlation_pass(time.time(), time.time(), {"decided_this_run": 5}, 5)
        reviewlog.correlation_pass(time.time(), time.time(), {"error": "decision model unreachable", "error_kind": "decision"}, 0)
        v = reviewlog.view(24)
        self.assertIn("memory", v["source"])
        self.assertEqual(v["summary"]["correlation"]["entries"], 2)
        self.assertEqual(v["summary"]["correlation"]["problems"], 1)
        self.assertEqual(v["summary"]["correlation"]["links"], 5)
        self.assertEqual(v["rows"][0]["status"], "waiting")


if __name__ == "__main__":
    unittest.main()
