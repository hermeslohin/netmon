"""Unit tests for AI pipeline monitoring: the core request carries no verdict rows (no Decisions list on the page)."""
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); import _env  # noqa: E402

import unittest  # noqa: E402

import corr_llm  # noqa: E402


class OverviewCore(unittest.TestCase):
    """The monitoring page's core overview."""
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

    def test_overview_core_has_no_rows_but_keeps_totals(self):
        """The core overview has no verdict rows or decision-model numbers but still counts manual verdicts.
        REQ: AIR-01"""
        ov = corr_llm.overview(self.ev, {}, with_rows=False, with_clef=False)
        self.assertNotIn("verdicts", ov)
        self.assertNotIn("clef", ov)
        self.assertEqual(ov["totals"]["manual"], 5)
        self.assertEqual(ov["totals"]["manual_related"], 3)  # 0, 10, 20
        self.assertEqual(len(corr_llm.overview(self.ev, {}, with_clef=False)["verdicts"]), 25)  # old shape still there

    def test_decisions_list_removed(self):
        """The Decisions list, its endpoint and its pager are gone.
        REQ: AIR-01"""
        self.assertFalse(hasattr(corr_llm, "verdict_page"))
        app = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "dashboard", "app")
        with open(os.path.join(app, "server.py"), encoding="utf-8") as f:
            self.assertNotIn("/api/aireview/verdicts", f.read())
        with open(os.path.join(app, "static", "aireview.js"), encoding="utf-8") as f:
            js = f.read()
        self.assertNotIn("decisionsCard", js)
        self.assertNotIn("/api/aireview/verdicts", js)


if __name__ == "__main__":
    unittest.main()
