import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); import _env  # noqa: E401,E402
"""Failed CIS Kubernetes checks are Fix list items, not endpoint findings."""
import unittest  # noqa: E402

import issues  # noqa: E402

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
import k8s  # noqa: E402

CIS = {"c1": {"results": [
    {"id": "5.2.2", "title": "Privileged containers are minimized", "status": "fail", "detail": "privileged", "count": 2, "items": ["a/x", "b/y"]},
    {"id": "1.2.16", "title": "profiling", "status": "accepted", "detail": "", "count": 0, "items": []},
    {"id": "5.3.2", "title": "netpol", "status": "pass", "detail": "", "count": 0, "items": []}]},
    "c2": {"error": "401 Unauthorized"}}


class CisFixListTest(unittest.TestCase):
    def test_failed_checks_are_fix_list_items(self):
        """REQ: KUBE-06"""
        out = issues.check_snapshot({"k8s": {"cis": CIS}}, {})
        ks = sorted(k for k in out if k.startswith("k8s-cis"))
        self.assertEqual(ks, ["k8s-cis|c1|5.2.2", "k8s-cis|c2|error"])
        i = out["k8s-cis|c1|5.2.2"]
        self.assertEqual((i["source"], i["severity"], i["host"]), ("k8s", "medium", "Kubernetes c1"))
        self.assertIn("a/x", i["evidence"])
        self.assertTrue(i["fix"])
        self.assertIn("k8s", issues.sources_of({"k8s": {"cis": CIS}}, {}))
        self.assertNotIn("k8s", issues.sources_of({}, {}))

    def test_not_endpoint_findings(self):
        """REQ: KUBE-06"""
        keys = [k for k, _p, _t in k8s.findings({"cis": CIS, "coverage": [], "signals": [], "events": []}, nightly=True)]
        self.assertFalse([k for k in keys if k.startswith("k8s-cis")], keys)


if __name__ == "__main__":
    unittest.main()
