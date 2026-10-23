"""Unit tests for mitre.py: rule matching, technique lookup, alert tags and catalog validation."""
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); import _env  # noqa: E402

import re  # noqa: E402
import unittest  # noqa: E402

import mitre  # noqa: E402

SOURCES = {"analysis", "host", "issue", "unifi", "alarm", "ids", "admin", "alert", "*"}


class CatalogTest(unittest.TestCase):
    """The bundled ATT&CK catalog and RULES table are consistent."""

    def test_catalog_loads(self):
        """The bundled catalog has a version, tactics and several hundred techniques.
        REQ: MIT-01"""
        c = mitre.catalog()
        self.assertTrue(c["version"])
        self.assertGreater(len(c["techniques"]), 300)
        self.assertTrue(c["tactic_order"])
        for short in c["tactic_order"]:
            self.assertIn(short, c["tactics"])

    def test_check_reports_no_bad_rules(self):
        """check() finds no rule referencing a technique missing from the catalog.
        REQ: MIT-01"""
        self.assertEqual(mitre.check(), [])

    def test_check_detects_unknown_id(self):
        """check() reports a rule whose technique id is not in the catalog.
        REQ: MIT-01"""
        saved = list(mitre.RULES)
        try:
            mitre.RULES.append(("analysis", r"^zzz", "observed", ["T9999"], "bogus"))
            self.assertEqual(mitre.check(), [("analysis", r"^zzz", "T9999")])
        finally:
            mitre.RULES[:] = saved

    def test_rule_shape(self):
        """Every rule has a known source, a compilable regex, a known relation and well-formed technique ids.
        REQ: MIT-01"""
        for s, rx, rel, tids, why in mitre.RULES:
            self.assertIn(s, SOURCES, rx)
            re.compile(rx)
            self.assertIn(rel, ("observed", "exposure", "n/a"), rx)
            for t in tids:
                self.assertRegex(t, r"^T\d{4}(\.\d{3})?$")
            if rel == "n/a":
                self.assertEqual(tids, [])

    def test_rule_techniques_have_names_and_tactics(self):
        """Every technique a rule references resolves to a named entry with at least one tactic.
        REQ: MIT-01"""
        tactics = mitre.catalog()["tactics"]
        for _, _, _, tids, _ in mitre.RULES:
            for t in tids:
                e = mitre.tech(t)
                self.assertTrue(e.get("name"), t)
                self.assertTrue(e.get("tactics"), t)
                for tac in e["tactics"]:
                    self.assertIn(tac, tactics)


class LookupTest(unittest.TestCase):
    """rules_for(), tech(), tags_for() and _norm_ids()."""

    def test_tech_lookup(self):
        """tech() returns the catalog entry; sub-techniques fall back to the parent; unknown gives {}.
        REQ: MIT-01"""
        self.assertEqual(mitre.tech("T1071")["name"], "Application Layer Protocol")
        self.assertTrue(mitre.tech("T1071.004").get("name"))
        self.assertEqual(mitre.tech("T1071.999"), mitre.tech("T1071"))
        self.assertEqual(mitre.tech("T0000"), {})

    def test_rules_for_beacon(self):
        """A beacon finding maps to observed C2 techniques.
        REQ: MIT-01"""
        r = mitre.rules_for("analysis", "beacon")
        self.assertEqual(len(r), 1)
        rel, tids, why = r[0]
        self.assertEqual(rel, "observed")
        self.assertEqual(tids, ["T1071", "T1029"])

    def test_rules_for_first_match_only(self):
        """Only the first matching rule of a source is returned (rules are ordered specific to generic).
        REQ: MIT-01"""
        # "ti-ip-in" matches both the generic ^ti-ip rule (listed first) and the ^ti-ip-in rule
        self.assertEqual(mitre.rules_for("analysis", "ti-ip-in"), [("observed", ["T1071"], "traffic with a threat-listed host")])

    def test_rules_for_case_insensitive(self):
        """Rule regexes match case-insensitively.
        REQ: MIT-01"""
        self.assertEqual(mitre.rules_for("alarm", "ADMIN LOGIN from x")[0][1], ["T1078"])

    def test_rules_for_source_scoped(self):
        """A rule for one source does not apply to another source.
        REQ: MIT-01"""
        self.assertEqual(mitre.rules_for("unifi", "beacon"), [])
        self.assertEqual(mitre.rules_for("analysis", "nothing-matches-this"), [])

    def test_exposure_relation(self):
        """Exposure findings carry the exposure relation.
        REQ: MIT-01"""
        self.assertEqual(mitre.rules_for("analysis", "inbound-exposure")[0][0], "exposure")

    def test_tags_for(self):
        """tags_for() renders at most two techniques with names; no match gives ''.
        REQ: MIT-01"""
        self.assertEqual(mitre.tags_for("analysis", "beacon"), " [ATT&CK T1071 Application Layer Protocol, T1029 Scheduled Transfer]")
        self.assertEqual(mitre.tags_for("analysis", "no-such-kind"), "")
        self.assertEqual(mitre.tags_for("analysis", "new-signature"), "")  # n/a rule has no ids

    def test_norm_ids(self):
        """_norm_ids() keeps only well-formed technique ids from a scalar or list.
        REQ: MIT-01"""
        self.assertEqual(mitre._norm_ids(None), [])
        self.assertEqual(mitre._norm_ids("T1110"), ["T1110"])
        self.assertEqual(mitre._norm_ids([" T1110.001 ", "TA0001", "T12", "x", "T1059"]), ["T1110.001", "T1059"])


if __name__ == "__main__":
    unittest.main()
