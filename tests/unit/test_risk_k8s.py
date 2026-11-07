"""Risk: Kubernetes workloads ranked with hosts (risk.k8s_rows)."""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "dashboard", "app"))
import risk  # noqa: E402


def wl(**kw):
    w = {"id": "k8s:c1/app/Deployment/web", "cluster": "c1", "ns": "app", "kind": "Deployment", "name": "web", "pods": ["web-abc-12345"],
         "ips": ["10.0.0.5"], "nodes": ["n1"], "images": ["docker.io/acme/web:1.0"], "flags": [], "privileged": False, "host": [],
         "root": False, "token": False, "secrets_env": [], "restarts": 0, "services": [], "exposed": [], "ingress_hosts": [],
         "no_tls": [], "netpol": True, "psa": "", "cis": []}
    w.update(kw)
    return w


def raw(ws, images=None, **k8s):
    return {"k8s": {"workloads": ws, "images_scan": {"images": images or []}, "so_nodes": {"c1": ["n1"]}, **k8s}}


SCAN = {"image": "docker.io/acme/web:1.0", "repo": "acme/web", "update": "1.1",
        "current": {"counts": {"CRITICAL": 3, "HIGH": 10}}, "fixed_by_update": {"counts": {"CRITICAL": 3, "HIGH": 8}}}


class K8sRiskTest(unittest.TestCase):
    def test_hardened_internal_workload_is_low(self):
        """REQ: KUBE-11"""
        rows, vulns = risk.k8s_rows(raw([wl()], [{**SCAN, "current": {"counts": {}}}]))
        self.assertEqual(len(rows), 1)
        r = rows[0]
        self.assertEqual((r["class"], r["zone"], r["impact"]), ("container", "c1", 3))
        self.assertLess(r["score"], 5)
        self.assertEqual(vulns, [])

    def test_exposed_vulnerable_privileged_ranks_higher(self):
        """REQ: KUBE-11"""
        bad = wl(id="k8s:c1/app/Deployment/bad", name="bad", pods=["bad-1"], privileged=True, host=["hostPath"], netpol=False,
                 ingress_hosts=["bad.example"], no_tls=["bad.example"], secrets_env=["DB_PASSWORD"])
        rows, vulns = risk.k8s_rows(raw([wl(), bad], [SCAN]))
        by = {r["name"]: r for r in rows}
        self.assertGreater(by["app/bad"]["score"], by["app/web"]["score"] + 20)
        self.assertEqual(by["app/bad"]["impact"], 5)
        self.assertEqual(by["app/bad"]["components"]["reach"], 8)
        self.assertGreaterEqual(by["app/bad"]["components"]["exposure"], 16)
        cve = [v for v in vulns if v["category"] == "Image CVEs"]
        self.assertEqual(len(cve), 2)  # one per workload running the image
        self.assertIn("update to 1.1", cve[0]["fix"])
        self.assertEqual(vulns[0]["target"], "c1/app/bad")  # exposure raises the vulnerability score
        self.assertEqual(vulns, sorted(vulns, key=lambda v: -v["score"]))

    def test_threat_from_security_onion_and_host_network_alerts_go_to_node(self):
        """REQ: KUBE-11"""
        sig = {"ns": "app", "pod": "web-abc-12345", "kind": "cmd", "label": "Reverse shell", "severity": "high"}
        ex = {**sig, "exempt": "threat intel"}
        alert = {"rule": "ET X", "src": ["10.0.0.5"], "dst": []}
        rows, _ = risk.k8s_rows(raw([wl()], signals=[sig], alerts=[alert]))
        self.assertEqual(rows[0]["components"]["threat"], 13)
        rows, _ = risk.k8s_rows(raw([wl()], signals=[ex]))
        self.assertEqual(rows[0]["components"]["threat"], 0)
        rows, _ = risk.k8s_rows(raw([wl(host=["hostNetwork"], ips=["192.0.2.1"])], alerts=[{**alert, "src": ["192.0.2.1"]}]))
        self.assertEqual(rows[0]["components"]["threat"], 0)

    def test_visibility_impact_override_and_no_data(self):
        """REQ: KUBE-11"""
        r = raw([wl(ns="kube-system")])
        r["k8s"]["so_nodes"] = {"c1": []}
        rows, _ = risk.k8s_rows(r)
        self.assertEqual(rows[0]["impact"], 5)
        self.assertEqual(rows[0]["components"]["visibility"], 8)  # no SO data + image not scanned
        rows, _ = risk.k8s_rows(raw([wl()]), {"impact": {"app/web": [2, "test box"]}})
        self.assertEqual((rows[0]["impact"], rows[0]["impact_why"]), (2, "test box"))
        self.assertEqual(risk.k8s_rows({}), ([], []))


if __name__ == "__main__":
    unittest.main()
