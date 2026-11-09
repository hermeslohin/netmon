import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); import _env  # noqa: E401,E702,E402
"""Event reviewer web look-ups are items in the audit log (aireview.websearch) carrying the search, why, event, results and links."""
import unittest  # noqa: E402
from unittest import mock  # noqa: E402

import corr_llm  # noqa: E402


class WebSearchAuditTest(unittest.TestCase):
    def setUp(self):
        with corr_llm._lock, corr_llm._db() as c:
            c.execute("DELETE FROM web_queries")

    def _log(self, item, res, err, cached=False):
        logw = corr_llm._web_logger("ev|1", ["ev|2"], "m1", "event-review")
        logw.cached = cached
        with mock.patch.object(corr_llm.audit, "action") as act:
            logw(item, res, err, 1.234)
        self.assertEqual(act.call_count, 1)
        return act.call_args

    def test_search_entry(self):
        """A web search is one audit item with its query, why, event, result count and result links.
        REQ: AUD-06"""
        a = self._log({"search": "cve-2026-1 exploit", "why": "check the signature"},
                      {"results": 2, "urls": [{"url": "https://ex.org/a", "title": "A"}, {"url": "https://ex.org/b", "title": "B"}]}, None, cached=True)
        self.assertEqual(a.args, ("netmon (event reviewer)", "aireview.websearch"))
        k = a.kwargs
        self.assertEqual((k["outcome"], k["target"], k["category"]), ("success", "ev|1", "network"))
        p = k["params"]
        self.assertEqual((p["kind"], p["query"], p["why"], p["results"], p["cached"], p["model"], p["purpose"], p["candidates"]),
                         ("search", "cve-2026-1 exploit", "check the signature", 2, True, "m1", "event-review", ["ev|2"]))
        self.assertEqual(p["urls"], [{"url": "https://ex.org/a", "title": "A"}, {"url": "https://ex.org/b", "title": "B"}])
        self.assertIn("searched the web for cve-2026-1 exploit", k["message"])
        self.assertIn("2 result(s) (cached)", k["message"])

    def test_failed_page_read(self):
        """A failed page read is a failure item naming the URL and the error.
        REQ: AUD-06"""
        k = self._log({"url": "https://ex.org/x"}, None, "timeout").kwargs
        self.assertEqual((k["outcome"], k["params"]["kind"], k["params"]["query"], k["params"]["error"], k["params"]["urls"]),
                         ("failure", "page", "https://ex.org/x", "timeout", []))
        self.assertIn("read the page https://ex.org/x - failed: timeout", k["message"])


if __name__ == "__main__":
    unittest.main()
