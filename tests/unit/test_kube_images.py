"""Kubernetes multi-cluster filter, events into Open events, and container image updates/CVEs (k8s.py, kube_images.py)."""
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); import _env  # noqa: E401,E702,E402

import unittest  # noqa: E402
from unittest import mock  # noqa: E402

import k8s  # noqa: E402
import kube_images as KI  # noqa: E402


class TagTest(unittest.TestCase):
    def test_parse_ref(self):
        """REQ: KUBE-10"""
        self.assertEqual(KI.parse_ref("nginx"), ("docker.io", "library/nginx", "", ""))
        self.assertEqual(KI.parse_ref("quay.io/calico/node:v3.33.0"), ("quay.io", "calico/node", "v3.33.0", ""))
        self.assertEqual(KI.parse_ref("registry:5000/a/b:1.2@sha256:ab"), ("registry:5000", "a/b", "1.2", "sha256:ab"))
        self.assertEqual(KI.parse_ref("opencti/worker:7.261030.1")[:3], ("docker.io", "opencti/worker", "7.261030.1"))

    def test_newer_tags_same_shape_no_prerelease(self):
        """REQ: KUBE-10"""
        tags = ["v3.33.0", "v3.33.1", "v3.34.0", "v4.0.0-rc1", "v4.0.0", "v3.35.0-beta", "latest", "v3.34.0-arm64"]
        self.assertEqual(KI.newer_tags("v3.33.0", tags), ("v4.0.0", "v3.34.0"))
        self.assertEqual(KI.newer_tags("4.1.2-debian-12-r1", ["4.1.2-debian-12-r1", "4.1.3-debian-12-r0", "4.1.3"]), ("4.1.3-debian-12-r0", "4.1.3-debian-12-r0"))
        self.assertEqual(KI.newer_tags("latest", tags), (None, None))
        self.assertEqual(KI.newer_tags("v4.0.0", tags), (None, None))

    def test_fixed_by_update_and_findings(self):
        """REQ: KUBE-10"""
        cur = {"counts": {}, "vulns": [{"id": "CVE-1", "severity": "CRITICAL", "fixed": "1.1"}, {"id": "CVE-2", "severity": "HIGH", "fixed": ""}], "scanned": "2026-11-07T00:00:00Z"}
        new = {"counts": {"HIGH": 1}, "vulns": [{"id": "CVE-2", "severity": "HIGH", "fixed": ""}], "scanned": "2026-11-07T00:00:00Z"}
        with mock.patch.object(KI, "list_tags", return_value=["1.0", "1.1"]), mock.patch.object(KI, "trivy", side_effect=[cur, new]):
            r = KI.check_image("example/app:1.0", "docker.io/example/app@sha256:aa", "linux/arm64", {})
        self.assertEqual(r["update"], "1.1")
        self.assertEqual(r["fixed_by_update"]["ids"], ["CVE-1"])
        self.assertEqual(r["fixable_in_place"], 1)
        r["namespaces"] = ["talos/apps"]
        f = KI.findings({"images": [r]})
        self.assertEqual((f[0][0], f[0][1]), ("k8s-imgcve|example/app", "Investigate"))
        self.assertEqual(KI.findings({"images": [dict(r, fixed_by_update={"counts": {}})]}), [])


class TrivyArgsTest(unittest.TestCase):
    def test_image_reference_cannot_inject_options(self):
        """REQ: KUBE-10"""
        with mock.patch.object(KI.subprocess, "run") as run:
            for bad in ("--config=/etc/x", "-q", "a b", "img;rm", ""):
                with self.assertRaises(ValueError):
                    KI.trivy(bad, "linux/arm64")
            with self.assertRaises(ValueError):
                KI.trivy("nginx:1", "--x")
            run.assert_not_called()
            run.return_value = mock.Mock(returncode=0, stdout="{}", stderr="")
            KI.trivy("docker.io/library/nginx@sha256:" + "a" * 64, "linux/arm64")
            argv = run.call_args[0][0]
            self.assertEqual(argv[-2:], ["--", "docker.io/library/nginx@sha256:" + "a" * 64])


class ClusterFilterTest(unittest.TestCase):
    def tearDown(self):
        k8s.set_cluster(None)

    def test_queries_limited_to_cluster_nodes(self):
        """REQ: KUBE-08"""
        with mock.patch.object(k8s, "cluster_nodes", return_value={"talos": ["n1", "n2"], "lab": []}):
            k8s.set_cluster("talos")
            r = k8s.rng(60)
            self.assertIn({"terms": {"host.name": ["n1", "n2"]}}, r["bool"]["filter"])
            k8s.set_cluster("lab")  # a cluster with no Security Onion data matches nothing, never everything
            self.assertEqual(k8s.rng(60)["bool"]["filter"][1], {"terms": {"host.name": ["(none)"]}})
            with self.assertRaises(ValueError):
                k8s.set_cluster("nope")
            k8s.set_cluster(None)
            self.assertNotIn("host.name", str(k8s.rng(60)))


class EventsToOpenEventsTest(unittest.TestCase):
    def test_warning_events_and_log_hits_become_info_findings(self):
        """REQ: KUBE-09"""
        d = {"events": [{"security": False, "message": "Back-off restarting failed container", "ns": "apps", "reason": "BackOff", "kind": "Pod",
                         "object": "web-7d9f8c6b5-abcde", "count": 4, "cluster": "talos"}],
             "signals": [{"kind": "authfail", "label": "Authentication failures", "severity": "medium", "ns": "apps", "pod": "db-0", "container": "pg",
                          "count": 3, "examples": ["password authentication failed"], "exempt": ""}]}
        with mock.patch.object(k8s, "policy", return_value={"signal_exempt": {}, "exec_alert": 1, "deny_alert": 20}):
            night = {k: p for k, p, _ in k8s.findings(d, nightly=True)}
            watch = k8s.findings(d, nightly=False)
        self.assertEqual(night, {"k8s-ev|apps|BackOff|web": "Info", "k8s-log|authfail|apps|db-0|pg": "Info"})
        self.assertEqual(watch, [])


if __name__ == "__main__":
    unittest.main()
