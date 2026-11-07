import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); import _env  # noqa: E401,E402
"""Kubernetes pod notes: kb subjects pod:<cluster>/<namespace>/<workload> that people and the AI read and write."""
import unittest  # noqa: E402

import kb  # noqa: E402


class PodNotesTest(unittest.TestCase):
    def test_subject_is_the_workload(self):
        """REQ: KUBE-12"""
        self.assertEqual(kb.resolve(subject="pod:talos/calico-system/calico-node-6lw86")[0], "pod:talos/calico-system/calico-node")
        self.assertEqual(kb.resolve(subject="pod:Talos/apps/web-7d9f8c6b5d-x2k4p")[0], "pod:talos/apps/web")
        self.assertEqual(kb.pod_subject("c1", "apps", "db-0"), "pod:c1/apps/db-0")
        for bad in ("pod:a/b", "pod:a_/b/c", "pod:../x/y", "pod:a/b/c/d", "pod:a/b/-x"):
            with self.assertRaises(ValueError, msg=bad):
                kb.resolve(subject=bad)

    def test_event_to_pod(self):
        """REQ: KUBE-12"""
        self.assertEqual(kb.pod_of_event({"eid": "hf|k8s-ev|longhorn-system|Unhealthy|longhorn-manager",
                                          "label": "Kubernetes Unhealthy on Pod longhorn-system/x [talos] x6"}), ("talos", "longhorn-system", "longhorn-manager"))
        self.assertEqual(kb.pod_of_event("hf|k8s-log|cmd|opencti|opencti-worker|worker"), ("", "opencti", "opencti-worker"))
        self.assertIsNone(kb.pod_of_event("hf|k8s-cis|talos|5.2.1"))
        self.assertIsNone(kb.pod_of_event("ids|1|2"))

    def test_ai_writes_and_reads_pod_notes(self):
        """REQ: KUBE-12"""
        r = kb.put({"model": "m", "via": "test", "host_notes": [{"subject": "pod:c9/shop/web-abc12345-zz9zz", "category": "role", "text": "serves the shop"}]})
        self.assertEqual(r["host_notes_added"], 1, r)
        ns = kb.pod_notes("shop", "web-abc12345-zz9zz", "c9")
        self.assertEqual([(n["subject"], n["text"], n["author"]) for n in ns], [("pod:c9/shop/web", "serves the shop", "ai")])
        self.assertEqual(len(kb.pod_notes("shop", "web")), 1)  # any cluster
        self.assertEqual(kb.pod_notes("shop_", "web"), [])  # LIKE wildcards are escaped
        r = kb.put({"model": "m", "host_notes": [{"subject": "pod:c9/shop/web", "id": ns[0]["id"], "category": "role", "text": "serves the shop (nginx)"}]})
        self.assertEqual(r["host_notes_updated"], 1)
        self.assertEqual(kb.pod_notes("shop", "web", "c9")[0]["text"], "serves the shop (nginx)")


    def test_event_reviewer_writes_pod_note(self):
        """REQ: KUBE-12"""
        import corr_llm
        eid = "hf|k8s-ev|shop|Unhealthy|cart"
        ev = {"id": eid, "label": "Kubernetes Unhealthy on Pod shop/cart-7d9f8c6b5d-x2k4p [c7] x3: probe failed"}
        self.assertEqual(corr_llm._note_pods(kb, "m", "[exp:dns:x]", "[exp:dns:x] Expected dns x", (eid, ev)), 1)
        ns = kb.pod_notes("shop", "cart", "c7")
        self.assertEqual([(n["subject"], n["author"], n["category"]) for n in ns], [("pod:c7/shop/cart", "ai", "behavior")])
        self.assertEqual(corr_llm._note_pods(kb, "m", "[exp:dns:x]", "[exp:dns:x] Expected dns x", ("ids|1", {"label": "x"})), 0)
        owner, ai = corr_llm._context_notes({"anchor": eid}, {eid: {**ev, "ips": []}})
        self.assertTrue(any(x.startswith("pod note [behavior] c7/shop/cart") for x in ai.get("anchor", [])), ai)


if __name__ == "__main__":
    unittest.main()
