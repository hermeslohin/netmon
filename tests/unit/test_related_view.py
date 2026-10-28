"""Open events page: related events of rows older than the loaded snapshot come from the stored verdicts
(corr_llm.related_view), with artifacts and the decision model's (clef) confidence."""
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); import _env  # noqa: E402

import unittest  # noqa: E402

import corr_llm  # noqa: E402


class RelatedView(unittest.TestCase):
    def setUp(self):
        with corr_llm._db() as c:
            for t in ("verdicts", "clef", "pair_artifacts", "clef_event"):
                c.execute(f"DELETE FROM {t}")
            P = corr_llm.pair
            c.executemany("INSERT INTO verdicts (pair, related, confidence, reason, model, ts) VALUES (?,?,?,?,?,?)", [
                (P("a1", "x"), 1, 0.9, "same host", "cloudflare_clef", 10),
                (P("a2", "x"), 1, 0.7, "newer verdict", "cloudflare_clef", 20),  # same partner via another repeat: newest kept
                (P("a2", "y"), 1, 0.5, "old reviewer", "gemma", 5),
                (P("a1", "z"), 0, 0.1, "not related", "cloudflare_clef", 5),   # rejected: never listed
                (P("a1", "a2"), 1, 0.9, "repeat", "cloudflare_clef", 5)])      # link inside the row's own repeats: skipped
            c.execute("INSERT INTO clef (pair, p_related, related, model, ts) VALUES (?,?,?,?,?)", (P("a2", "x"), 0.83, 1, "cloudflare_clef", 20))
            c.execute("INSERT INTO pair_artifacts (pair, kind, value, relation, decision, model, ts) VALUES (?,?,?,?,?,?,?)",
                      (P("a2", "x"), "ip", "10.0.0.5", "shared host", "suspicious", "gemma", 20))
            c.execute("INSERT INTO clef_event (eid, p_suspicious, p_expected, label, model, ts) VALUES (?,?,?,?,?,?)", ("a2", 0.8, 0.1, "suspicious", "cloudflare_clef", 20))

    def test_counts_details_and_clef(self):
        """Stored related links of a row (all its repeats), newest verdict per partner, artifacts and clef decisions.
        REQ: STO-10
        """
        n, _ = corr_llm.related_view({"a2": {"a1", "a2"}}, detail=False)
        self.assertEqual(sorted(y for y, _ in n["a2"]), ["x", "y"])
        R, partners = corr_llm.related_view({"a2": {"a1", "a2"}})
        self.assertEqual(partners, {"x", "y"})
        x = R["a2"][0]
        self.assertEqual((x["id"], x["llm_reason"], x["llm"]), ("x", "newer verdict", "yes"))
        self.assertAlmostEqual(x["clef"]["p_related"], 0.83)
        self.assertEqual(x["llm_artifacts"][0]["value"], "10.0.0.5")
        self.assertIsNone(R["a2"][1]["clef"])
        self.assertEqual(corr_llm.clef_events_view(["a2", "a1"])["a2"]["label"], "suspicious")


if __name__ == "__main__":
    unittest.main()
