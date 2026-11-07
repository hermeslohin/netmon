"""Unit tests for AI pipeline monitoring paging (corr_llm.verdict_page / overview without rows): the Decisions list loads
newest-first in pages with server-side filters, and the page's core request carries no verdict rows."""
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); import _env  # noqa: E402

import unittest  # noqa: E402

import corr_llm  # noqa: E402


class VerdictPaging(unittest.TestCase):
    def setUp(self):
        with corr_llm._db() as c:
            c.execute("DELETE FROM verdicts")
            for i in range(25):  # 25 links: even = confirmed, every 5th set by a person, confidence 0.5 / 0.95
                c.execute("INSERT INTO verdicts (pair, related, confidence, reason, model, ts) VALUES (?, ?, ?, ?, ?, ?)",
                          (corr_llm.pair(f"ids|{i}", f"alert|{i}"), int(i % 2 == 0), 0.95 if i % 3 else 0.5, "r",
                           "manual:x" if i % 5 == 0 else "m", 1000 + i))
        self.ev = {f"ids|{i}": {"type": "ids", "label": f"I{i}"} for i in range(10)} | {f"alert|{i}": {"type": "alert", "label": f"A{i}"} for i in range(10)}

    def tearDown(self):
        with corr_llm._db() as c:
            c.execute("DELETE FROM verdicts")

    def test_pages_newest_first_without_gaps(self):
        """REQ: AIR-01"""
        p1 = corr_llm.verdict_page(self.ev, 0, 10)
        p2 = corr_llm.verdict_page(self.ev, 10, 10)
        p3 = corr_llm.verdict_page(self.ev, 20, 10)
        self.assertEqual(p1["total"], 25)
        self.assertTrue(p1["more"]); self.assertTrue(p2["more"]); self.assertFalse(p3["more"])
        ts = [r["ts"] for r in p1["rows"] + p2["rows"] + p3["rows"]]
        self.assertEqual(ts, sorted(range(1000, 1025), reverse=True))
        self.assertEqual(p1["rows"][0]["a_label"] if p1["rows"][0]["a"].startswith("ids") else p1["rows"][0]["b_label"], "ids|24")

    def test_filters_apply_on_the_server(self):
        """REQ: AIR-01"""
        self.assertEqual(corr_llm.verdict_page(self.ev, 0, 100, verdict="confirmed")["total"], 13)
        self.assertEqual(corr_llm.verdict_page(self.ev, 0, 100, verdict="rejected")["total"], 12)
        self.assertEqual(corr_llm.verdict_page(self.ev, 0, 100, verdict="manual")["total"], 5)
        self.assertEqual(corr_llm.verdict_page(self.ev, 0, 100, conf="low")["total"], 9)
        cur = corr_llm.verdict_page(self.ev, 0, 100, scope="current")
        self.assertEqual(cur["total"], 10)
        self.assertTrue(all(r["current"] for r in cur["rows"]))
        self.assertEqual(corr_llm.verdict_page(self.ev, 0, 100, pair="alert-ids")["total"], 25)
        self.assertEqual(corr_llm.verdict_page(self.ev, 0, 100, pair="ids-vuln")["total"], 0)
        self.assertEqual(corr_llm.verdict_page(self.ev, 0, 3, types=["ids"])["total"], 25)

    def test_limit_is_clamped(self):
        """REQ: AIR-01"""
        self.assertEqual(len(corr_llm.verdict_page(self.ev, -5, 0)["rows"]), 1)
        self.assertEqual(corr_llm.verdict_page(self.ev, 0, 10**6)["total"], 25)

    def test_overview_core_has_no_rows_but_keeps_totals(self):
        """REQ: AIR-01"""
        ov = corr_llm.overview(self.ev, {}, with_rows=False, with_clef=False)
        self.assertNotIn("verdicts", ov)
        self.assertNotIn("clef", ov)
        self.assertEqual(ov["totals"]["manual"], 5)
        self.assertEqual(ov["totals"]["manual_related"], 3)  # 0, 10, 20
        self.assertEqual(len(corr_llm.overview(self.ev, {}, with_clef=False)["verdicts"]), 25)  # old shape still there


if __name__ == "__main__":
    unittest.main()
