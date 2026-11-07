import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); import _env  # noqa: E401,E402
"""Kubernetes pod notes: filed on the object that creates the pods (kb subject pod:<cluster>/<namespace>/<kind>/<name>),
so one note applies to every pod a Deployment / StatefulSet / DaemonSet / CronJob / Job makes. People and the AI read and write them."""
import unittest  # noqa: E402

import kb  # noqa: E402


class PodNotesTest(unittest.TestCase):
    def test_subject_is_the_owner(self):
        """REQ: KUBE-12"""
        self.assertEqual(kb.resolve(subject="pod:Talos/apps/Deployment/web"), ("pod:talos/apps/deployment/web", "Deployment apps/web (talos)"))
        self.assertEqual(kb.pod_subject("c1", "apps", "statefulset", "db"), "pod:c1/apps/statefulset/db")
        self.assertEqual(kb.pod_subject("", "kube-system", "pod", "kube-apiserver-n1"), "pod:default/kube-system/pod/kube-apiserver-n1")
        # old 3-part subjects (pod name without its suffix) still resolve, so notes written before stay readable
        self.assertEqual(kb.resolve(subject="pod:talos/calico-system/calico-node-6lw86")[0], "pod:talos/calico-system/calico-node")
        for bad in ("pod:a/b", "pod:a_/b/c", "pod:../x/y", "pod:a/b/widget/d", "pod:a/b/-x", "pod:a/b/deployment/-x", "pod:a/b/c/d/e"):
            with self.assertRaises(ValueError, msg=bad):
                kb.resolve(subject=bad)

    def test_event_to_owner(self):
        """REQ: KUBE-12"""
        self.assertEqual(kb.pod_of_event({"eid": "hf|k8s-ev|longhorn-system|Unhealthy|longhorn-manager",
                                          "label": "Kubernetes Unhealthy on Pod longhorn-system/longhorn-manager-x5fg8 [talos] (owner daemonset/longhorn-manager) x6"}),
                         ("talos", "longhorn-system", "daemonset", "longhorn-manager"))
        self.assertEqual(kb.pod_of_event({"eid": "hf|k8s-log|cmd|opencti|opencti-worker|worker",
                                          "label": "Suspicious command in container logs of opencti/opencti-worker-7b7699bc8-dffkj (worker): 2x"}),
                         ("", "opencti", "deployment", "opencti-worker"))  # older text without the owner tag: guessed from the pod name
        self.assertEqual(kb.pod_of_event("hf|k8s-log|cmd|opencti|opencti-worker|worker"), ("", "opencti", "", "opencti-worker"))
        self.assertIsNone(kb.pod_of_event("hf|k8s-cis|talos|5.2.1"))
        self.assertIsNone(kb.pod_of_event("ids|1|2"))

    def test_guess_owner(self):
        """REQ: KUBE-12"""
        self.assertEqual(kb.guess_owner("opencti-worker-7b7699bc8-dffkj"), ("deployment", "opencti-worker"))
        self.assertEqual(kb.guess_owner("opencti-rabbitmq-0"), ("statefulset", "opencti-rabbitmq"))
        self.assertEqual(kb.guess_owner("calico-node-6lw86"), ("daemonset", "calico-node"))
        self.assertEqual(kb.guess_owner("kube-apiserver-talos-63g-2o9"), ("pod", "kube-apiserver-talos-63g-2o9"))

    def test_note_applies_to_every_pod_of_the_owner(self):
        """REQ: KUBE-12"""
        r = kb.put({"model": "m", "via": "test", "host_notes": [{"subject": "pod:c9/shop/deployment/web", "category": "role", "text": "serves the shop"}]})
        self.assertEqual(r["host_notes_added"], 1, r)
        ns = kb.pod_notes("shop", "web", "c9", kind="deployment")
        self.assertEqual([(n["subject"], n["text"], n["author"]) for n in ns], [("pod:c9/shop/deployment/web", "serves the shop", "ai")])
        for pod in ("web-abc12345-zz9zz", "web-77f6d9c4b8-k2l9q"):  # any pod it creates, old or new, finds the same note
            self.assertEqual(len(kb.pod_notes("shop", pod, "c9")), 1, pod)
        self.assertEqual(len(kb.pod_notes("shop", "web")), 1)  # any cluster, any kind
        self.assertEqual(kb.pod_notes("shop", "web", "c9", kind="statefulset"), [])  # another object of the same name
        self.assertEqual(kb.pod_notes("shop_", "web"), [])  # LIKE wildcards are escaped
        self.assertEqual(kb.pod_notes("deployment", "web"), [])  # % never spans parts
        r = kb.put({"model": "m", "host_notes": [{"subject": "pod:c9/shop/deployment/web", "id": ns[0]["id"], "category": "role", "text": "serves the shop (nginx)"}]})
        self.assertEqual(r["host_notes_updated"], 1)
        self.assertEqual(kb.pod_notes("shop", "web", "c9", kind="deployment")[0]["text"], "serves the shop (nginx)")
        self.assertEqual(kb.pod_note_counts().get("pod:c9/shop/deployment/web"), 1)
        kb.put({"model": "m", "host_notes": [{"subject": "pod:c9/db/statefulset/pg", "category": "role", "text": "postgres"}]})
        self.assertEqual(len(kb.pod_notes("db", "pg-0", "c9")), 1)  # StatefulSet pod (ordinal name) -> its StatefulSet's notes

    def test_event_reviewer_writes_pod_note(self):
        """REQ: KUBE-12"""
        import corr_llm
        eid = "hf|k8s-ev|shop|Unhealthy|cart"
        ev = {"id": eid, "label": "Kubernetes Unhealthy on Pod shop/cart-7d9f8c6b5d-x2k4p [c7] (owner deployment/cart) x3: probe failed"}
        self.assertEqual(corr_llm._note_pods(kb, "m", "[exp:dns:x]", "[exp:dns:x] Expected dns x", (eid, ev)), 1)
        ns = kb.pod_notes("shop", "cart", "c7", kind="deployment")
        self.assertEqual([(n["subject"], n["author"], n["category"]) for n in ns], [("pod:c7/shop/deployment/cart", "ai", "behavior")])
        self.assertEqual(corr_llm._note_pods(kb, "m", "[exp:dns:x]", "[exp:dns:x] Expected dns x", ("ids|1", {"label": "x"})), 0)
        owner, ai = corr_llm._context_notes({"anchor": eid}, {eid: {**ev, "ips": []}})
        self.assertTrue(any(x.startswith("pod note [behavior] c7/shop/deployment/cart") for x in ai.get("anchor", [])), ai)


if __name__ == "__main__":
    unittest.main()
