"""Unit tests for the read-only Kubernetes API integration, the CIS benchmark and the map (kube_api / kube_cis / kube_map)."""
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); import _env  # noqa: E401,E702,E402

import unittest  # noqa: E402
from unittest import mock  # noqa: E402

import integrations  # noqa: E402
import kube_api  # noqa: E402
import kube_cis  # noqa: E402
import kube_map  # noqa: E402


def pod(ns, name, *, sa="app", priv=False, root=True, ape=None, drop=None, seccomp=None, host_net=False, labels=None, owner=None,
        env_secret=False, comp=None, cmd=None, automount=None):
    sc = {"privileged": priv}
    if not root:
        sc["runAsNonRoot"] = True
    if ape is not None:
        sc["allowPrivilegeEscalation"] = ape
    if drop:
        sc["capabilities"] = {"drop": drop}
    if seccomp:
        sc["seccompProfile"] = {"type": seccomp}
    c = {"name": "main", "image": "img:1", "securityContext": sc, "command": cmd or []}
    if env_secret:
        c["env"] = [{"name": "PW", "valueFrom": {"secretKeyRef": {"name": "db", "key": "pw"}}}]
    md = {"namespace": ns, "name": name, "labels": labels or ({"component": comp} if comp else {})}
    if owner:
        md["ownerReferences"] = [{"kind": owner[0], "name": owner[1], "controller": True}]
    sp = {"containers": [c], "serviceAccountName": sa, "hostNetwork": host_net, "nodeName": "n1"}
    if automount is not None:
        sp["automountServiceAccountToken"] = automount
    return {"metadata": md, "spec": sp, "status": {"phase": "Running", "podIP": "10.244.0.5",
                                                   "containerStatuses": [{"name": "main", "ready": True, "restartCount": 2, "state": {"running": {}}}]}}


class FakeCli:
    used = "https://api:6443"

    def __init__(self, data, allowed=()):
        self.data, self.allowed = data, set(allowed)

    def version(self):
        return {"gitVersion": "v1.36.0"}

    def items(self, path):
        return self.data.get(path, [])

    try_items = items

    def can_i(self, verb, res, **k):
        return f"{verb} {res}" in self.allowed


GOOD_API = ["/usr/local/bin/kube-apiserver", "--anonymous-auth=false", "--profiling=false", "--enable-admission-plugins=NodeRestriction",
            "--audit-log-path=/a", "--audit-log-maxage=30", "--audit-log-maxbackup=10", "--audit-log-maxsize=100", "--tls-min-version=VersionTLS13"]


def cluster(**over):
    d = {"/api/v1/namespaces": [{"metadata": {"name": "apps", "labels": {"pod-security.kubernetes.io/enforce": "restricted"}}},
                                {"metadata": {"name": "kube-system", "labels": {}}}],
         "/api/v1/pods": [pod("kube-system", "kube-apiserver-n1", comp="kube-apiserver", cmd=GOOD_API),
                          pod("apps", "web-5f7c9d8b4-x2k9p", root=False, ape=False, drop=["ALL"], seccomp="RuntimeDefault", automount=False,
                              labels={"app": "web"}, owner=("ReplicaSet", "web-5f7c9d8b4"))],
         "/api/v1/serviceaccounts": [{"metadata": {"namespace": "apps", "name": "default"}, "automountServiceAccountToken": False}],
         "/api/v1/services": [{"metadata": {"namespace": "apps", "name": "web"}, "spec": {"type": "ClusterIP", "clusterIP": "10.96.0.9", "selector": {"app": "web"},
                                                                                          "ports": [{"port": 80, "targetPort": 8080}]}}],
         "/apis/networking.k8s.io/v1/networkpolicies": [{"metadata": {"namespace": "apps", "name": "deny"}}],
         "/apis/networking.k8s.io/v1/ingresses": [{"metadata": {"namespace": "apps", "name": "web"}, "spec": {"rules": [{"host": "web.lan", "http": {"paths": [
             {"path": "/", "backend": {"service": {"name": "web", "port": {"number": 80}}}}]}}]}}],
         "/apis/apps/v1/replicasets": [{"metadata": {"namespace": "apps", "name": "web-5f7c9d8b4", "ownerReferences": [{"kind": "Deployment", "name": "web", "controller": True}]}}]}
    d.update(over)
    return d


class CisTest(unittest.TestCase):
    def setUp(self):
        p = mock.patch.object(kube_cis, "_pol", return_value={"skip": ["kube-system"], "accept": {}})
        self.pol = p.start()
        self.addCleanup(p.stop)

    def by_id(self, d):
        return {r["id"]: r for r in d["results"]}

    def test_hardened_cluster_has_no_failures(self):
        """REQ: KUBE-06"""
        r = self.by_id(kube_cis.run(FakeCli(cluster())))
        fails = [k for k, v in r.items() if v["status"] == "fail" and k not in ("1.2.3", "1.2.5", "1.2.17", "1.2.23", "1.2.24", "1.2.25", "1.2.26", "1.2.27", "1.2.28", "3.2.1", "1.2.4")]
        self.assertEqual(fails, [])
        self.assertEqual(r["1.2.1"]["status"], "pass")
        self.assertEqual(kube_cis.findings({"results": []}), [])

    def test_bad_pod_fails_pod_security(self):
        """REQ: KUBE-06"""
        d = cluster()
        d["/api/v1/pods"].append(pod("apps", "evil", priv=True, host_net=True, env_secret=True))
        r = self.by_id(kube_cis.run(FakeCli(d)))
        for k in ("5.2.2", "5.2.5", "5.2.6", "5.2.7", "5.4.1", "5.7.2"):
            self.assertEqual(r[k]["status"], "fail", k)
            self.assertIn("apps/pod/evil", " ".join(r[k]["items"]))

    def test_privileged_namespace_listed_not_failed(self):
        """REQ: KUBE-06"""
        d = cluster()
        d["/api/v1/namespaces"].append({"metadata": {"name": "cni", "labels": {"pod-security.kubernetes.io/enforce": "privileged"}}})
        d["/api/v1/pods"].append(pod("cni", "node-agent", priv=True))
        r = self.by_id(kube_cis.run(FakeCli(d)))
        self.assertEqual(r["5.2.2"]["status"], "pass")
        self.assertTrue(r["5.2.2"]["accepted_items"])

    def test_flags_and_accept(self):
        """REQ: KUBE-06"""
        d = cluster()
        d["/api/v1/pods"][0] = pod("kube-system", "kube-apiserver-n1", comp="kube-apiserver", cmd=["kube-apiserver", "--anonymous-auth=true", "--profiling=true"])
        self.pol.return_value = {"skip": ["kube-system"], "accept": {"1.2.16": "lab only"}}
        res = kube_cis.run(FakeCli(d))
        r = self.by_id(res)
        self.assertEqual(r["1.2.1"]["status"], "fail")
        self.assertEqual(r["1.2.16"]["status"], "accepted")
        keys = [k for k, _, _ in kube_cis.findings(res)]
        self.assertIn("k8s-cis|default|1.2.1", keys)
        self.assertNotIn("k8s-cis|default|1.2.16", keys)

    def test_node_level_sections_are_manual(self):
        """REQ: KUBE-06"""
        r = self.by_id(kube_cis.run(FakeCli(cluster())))
        for k in ("1.1", "2", "4"):
            self.assertEqual(r[k]["status"], "manual")

    def test_rbac_wildcards_and_default_cluster_admin(self):
        """REQ: KUBE-06"""
        d = cluster(**{"/apis/rbac.authorization.k8s.io/v1/clusterroles": [{"metadata": {"name": "cluster-admin"}, "rules": [{"verbs": ["*"], "resources": ["*"], "apiGroups": ["*"]}]},
                                                                           {"metadata": {"name": "too-much"}, "rules": [{"verbs": ["*"], "resources": ["secrets"], "apiGroups": [""]}]}],
                       "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings": [
                           {"metadata": {"name": "cluster-admin"}, "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"}, "subjects": [{"kind": "Group", "name": "system:masters"}]},
                           {"metadata": {"name": "ci"}, "roleRef": {"kind": "ClusterRole", "name": "too-much"}, "subjects": [{"kind": "ServiceAccount", "name": "ci", "namespace": "apps"}]}]})
        r = self.by_id(kube_cis.run(FakeCli(d)))
        self.assertEqual(r["5.1.7"]["status"], "manual")  # the built-in binding is not a failure
        self.assertEqual(r["5.1.3"]["items"], ["ClusterRole too-much"])
        self.assertIn("sa:apps/ci", r["5.1.2"]["items"][0])


class MapTest(unittest.TestCase):
    def test_edges_and_workloads(self):
        """REQ: KUBE-07"""
        with mock.patch.object(kube_map.kube_cis if hasattr(kube_map, "kube_cis") else kube_cis, "latest", return_value={}):
            d = kube_map.build(FakeCli(cluster()))
        e = {(x["from"], x["to"], x["kind"]) for x in d["edges"]}
        self.assertIn(("ing:apps/web", "svc:apps/web", "routes"), e)
        self.assertIn(("svc:apps/web", "pod:apps/web-5f7c9d8b4-x2k9p", "selects"), e)
        self.assertIn(("wl:apps/Deployment/web", "pod:apps/web-5f7c9d8b4-x2k9p", "owns"), e)
        p = next(x for x in d["pods"] if x["name"].startswith("web"))
        self.assertEqual(p["containers"][0]["restarts"], 2)
        self.assertNotIn("may run as root", p["containers"][0]["security"]["flags"])
        self.assertEqual(d["ingresses"][0]["no_tls"], ["web.lan"])


class IntegrationTest(unittest.TestCase):
    def test_candidate_validation(self):
        """REQ: KUBE-05"""
        with self.assertRaises(ValueError):
            integrations._kube_candidate({}, {"url": "http://api:6443", "api_key": "x"})
        with self.assertRaises(ValueError):
            integrations._kube_candidate({}, {"url": "https://api:6443", "api_key": "two words"})
        with self.assertRaises(ValueError):
            integrations._kube_candidate({}, {"url": "https://api:6443", "enabled": True})
        n = integrations._kube_candidate({"api_key": "old"}, {"url": "https://a:6443, https://b:6443", "enabled": True})
        self.assertEqual((n["url"], n["api_key"]), ("https://a:6443,https://b:6443", "old"))  # blank token keeps the saved one

    def test_token_never_public(self):
        """REQ: KUBE-05"""
        cfg = {"kubernetes": {"clusters": {"a": {"enabled": True, "url": "https://a:6443", "api_key": "eyJsecretTOKEN1234"}}}}
        with mock.patch.object(integrations, "load", return_value=cfg):
            pub = integrations.public()["kubernetes"]
        self.assertNotIn("eyJsecretTOKEN1234", str(pub))
        self.assertTrue(pub["clusters"][0]["key_set"])

    def test_multi_cluster_and_legacy_settings(self):
        """REQ: KUBE-05"""
        legacy = {"kubernetes": {"enabled": True, "url": "https://a:6443", "api_key": "t"}}
        with mock.patch.object(integrations, "load", return_value=legacy):
            self.assertEqual([c["name"] for c in integrations.kube_clusters()], ["default"])
        two = {"kubernetes": {"clusters": {"talos": {"enabled": True, "url": "https://a:6443", "api_key": "t"},
                                           "lab": {"enabled": False, "url": "https://b:6443", "api_key": "u"}}}}
        with mock.patch.object(integrations, "load", return_value=two):
            self.assertEqual([(c["name"], c["usable"]) for c in integrations.kube_clusters()], [("lab", False), ("talos", True)])
            self.assertEqual(integrations.kubernetes()["name"], "talos")
            c = integrations.candidate("kubernetes", {"cluster": "lab", "delete": True})
            self.assertEqual(list(c["clusters"]), ["talos"])
            with self.assertRaises(ValueError):
                integrations.candidate("kubernetes", {"cluster": "Bad Name"})

    def test_client_refuses_http_and_unconfigured(self):
        """REQ: KUBE-05"""
        with self.assertRaises(ValueError):
            kube_api.Client({"url": "http://a:6443", "api_key": "t"})
        with self.assertRaises(kube_api.NotConfigured):
            kube_api.Client({"url": "", "api_key": ""})

    def test_check_flags_write_access(self):
        """REQ: KUBE-05"""
        cli = FakeCli({"/api/v1/nodes": [{}]}, allowed={"list secrets"})
        with mock.patch.object(kube_api, "Client", return_value=cli):
            r = kube_api.check({"url": "https://a", "api_key": "t"})
        self.assertFalse(r["read_only"])
        self.assertEqual(r["too_much"], ["list secrets"])


if __name__ == "__main__":
    unittest.main()
