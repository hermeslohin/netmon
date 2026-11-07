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


    def test_image_cves_are_fix_list_items(self):
        """REQ: KUBE-10"""
        img = {"image": "reg.example/acme/app:1.0", "repo": "acme/app", "update": "1.2", "clusters": ["c1"], "namespaces": ["c1/apps"],
               "current": {"counts": {"CRITICAL": 2, "HIGH": 5}}, "fixed_by_update": {"counts": {"CRITICAL": 2, "HIGH": 3}}}
        low = {**img, "repo": "acme/low", "fixed_by_update": {"counts": {"HIGH": 1}}}
        none = {**img, "repo": "acme/none", "fixed_by_update": {"counts": {}}}
        raw = {"k8s": {"images_scan": {"images": [img, low, none]}}}
        out = issues.check_snapshot(raw, {})
        self.assertEqual(sorted(k for k in out if k.startswith("k8s-imgcve")), ["k8s-imgcve|acme/app", "k8s-imgcve|acme/low"])
        i = out["k8s-imgcve|acme/app"]
        self.assertEqual((i["source"], i["severity"], i["host"]), ("k8s", "high", "Kubernetes c1"))
        self.assertIn("1.2", i["fix"])
        self.assertEqual(out["k8s-imgcve|acme/low"]["severity"], "medium")
        self.assertIn("k8s", issues.sources_of(raw, {}))
        keys = [k for k, _p, _t in k8s.findings({"images_scan": raw["k8s"]["images_scan"], "coverage": [], "signals": [], "events": []}, nightly=True)]
        self.assertFalse([k for k in keys if k.startswith("k8s-imgcve")], keys)


if __name__ == "__main__":
    unittest.main()
