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

    def test_review_log_follows_reviewer_switch(self):
        """The review log counts as the event reviewer: dropped while "Send event reviewer events" is off,
        and the Review log card then shows the in-memory entries.
        REQ: AUD-04"""
        import integrations
        from unittest import mock
        audit.emit = self._emit
        with mock.patch.object(integrations, "audit_send", lambda who: who != "reviewer"), mock.patch.object(audit._q, "put_nowait") as put:
            reviewlog.correlation_pass(time.time() - 1, time.time(), {"decided_this_run": 2, "events_this_run": 2}, 2)
            put.assert_not_called()
            v = reviewlog.view(24)
        self.assertTrue(v["source"].startswith("memory (audit log sending off)"))
        self.assertEqual(v["total"], 1)

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
        st = {"events_this_run": 9, "decided_this_run": 12, "clef_events_this_run": 3, "classified_this_run": 3, "model": "gemma", "clef_model": "Cloudflare/clef"}
        d = reviewlog.correlation_pass(time.time() - 4, time.time(), st, 15)
        self.assertEqual(d["event"]["dataset"], "netmon.review")
        self.assertEqual(d["netmon"]["review"]["status"], "ok")
        self.assertEqual(d["netmon"]["review"]["links_decided"], 12)
        self.assertEqual(d["netmon"]["review"]["events_processed"], 9)
        self.assertIn("9 events processed", d["message"])
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
        reviewlog.correlation_pass(time.time(), time.time(), {"decided_this_run": 5, "events_this_run": 4}, 5)
        reviewlog.correlation_pass(time.time(), time.time(), {"error": "decision model unreachable", "error_kind": "decision"}, 0)
        v = reviewlog.view(24)
        self.assertIn("memory", v["source"])
        self.assertEqual(v["summary"]["correlation"]["entries"], 2)
        self.assertEqual(v["summary"]["correlation"]["problems"], 1)
        self.assertEqual(v["summary"]["correlation"]["links"], 5)
        self.assertEqual(v["summary"]["correlation"]["events"], 4)
        self.assertEqual(v["rows"][1]["events"], 4)
        self.assertEqual(v["rows"][0]["status"], "waiting")


class ReviewBusyTest(unittest.TestCase):
    """Correlation review busy share on the Review log card."""
    def test_busy_share_from_aggregation(self):
        """Busy % = summed pass time / period, with median and longest pass, capped at 100%.
        REQ: AIR-02"""
        b = reviewlog.busy_view([], 24, {"passes": 300, "busy_s": 43200, "p50_s": 120.4, "max_s": 500.6})
        self.assertEqual(b, {"busy_pct": 50.0, "busy_s": 43200, "busy_passes": 300, "pass_p50_s": 120, "pass_max_s": 501})
        self.assertEqual(reviewlog.busy_view([], 1, {"passes": 1, "busy_s": 9999, "p50_s": 9999, "max_s": 9999})["busy_pct"], 100.0)

    def test_busy_share_from_listed_rows(self):
        """Without the aggregation (memory ring) the listed correlation passes are summed; no passes = 0%.
        REQ: AIR-02"""
        b = reviewlog.busy_view([{"seconds": 1800}, {"seconds": 600}, {"seconds": 1200}], 1)
        self.assertEqual((b["busy_pct"], b["busy_passes"], b["pass_p50_s"], b["pass_max_s"]), (100.0, 3, 1200, 1800))
        self.assertEqual(reviewlog.busy_view([{"seconds": 360}], 1)["busy_pct"], 10.0)
        e = reviewlog.busy_view([], 24)
        self.assertEqual((e["busy_pct"], e["busy_passes"], e["pass_p50_s"]), (0.0, 0, None))

    def test_view_uses_aggregation(self):
        """view() puts the Elasticsearch busy aggregation into the correlation summary.
        REQ: AIR-02"""
        from unittest import mock
        import integrations
        with mock.patch.object(integrations, "audit_send", lambda who: True), \
                mock.patch.object(audit, "review_entries", return_value=([], 0)), \
                mock.patch.object(audit, "review_busy", return_value={"passes": 10, "busy_s": 1800, "p50_s": 150, "max_s": 400}):
            c = reviewlog.view(1)["summary"]["correlation"]
        self.assertEqual((c["busy_pct"], c["busy_passes"], c["pass_p50_s"], c["pass_max_s"]), (50.0, 10, 150, 400))


if __name__ == "__main__":
    unittest.main()
