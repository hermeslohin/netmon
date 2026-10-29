"""Decision-model stage of the correlation review (clef.py + corr_llm.clef_pass / event_pass), against a fake
/v1/systemone server on loopback and a stubbed reviewer - no LM Studio, no real model."""
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); import _env  # noqa: E402

import json  # noqa: E402
import threading  # noqa: E402
import unittest  # noqa: E402
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer  # noqa: E402

import clef  # noqa: E402
import corr_llm  # noqa: E402

CALLS = []  # (question, state) in call order


class _H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        self.send_response(200); self.end_headers(); self.wfile.write(b'{"status":"ok"}')

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        q = next(iter(body["questions"]))
        CALLS.append((q, body["state"]))
        st = body["state"]
        p = (0.9 if st.count("nas") >= 2 else 0.1) if q == "related" else 0.7 if q == "suspicious" else 0.2  # related: yes when both events name the same host "nas"
        out = json.dumps({"answers": {k: {"type": "noul", "noul": p} for k in body["questions"]}}).encode()
        self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers(); self.wfile.write(out)


def _ev(t, label):
    return {"type": t, "label": label, "sev": "medium", "t0": 1_700_000_000, "ips": ["10.0.0.5"]}


BASE = {"events": {"a": _ev("alert", "failed ssh logins to nas"), "b": _ev("ids", "ssh brute force on nas"),
                   "c": _ev("vuln", "printer firmware outdated")},
        "related": {"a": [{"id": "b", "score": 5, "why": ["same host"]}, {"id": "c", "score": 2, "why": ["same hour"]}]}}


class ClefStageTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), _H)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        clef.URL_DEFAULT = f"http://127.0.0.1:{cls.srv.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def setUp(self):
        CALLS.clear()
        with corr_llm._db() as c:
            c.execute("DELETE FROM clef"); c.execute("DELETE FROM verdicts"); c.execute("DELETE FROM event_class"); c.execute("DELETE FROM clef_event")

    def test_decision_model_decides_every_link(self):
        """Only related questions are asked; the decision model's answer is the verdict for every link, yes and no.
        REQ: LLM-03"""
        n = corr_llm.clef_pass(BASE, [("a", r) for r in BASE["related"]["a"]])
        self.assertEqual(n, 2)
        self.assertEqual([q for q, _ in CALLS], ["related", "related"])  # links only: event decisions come in event_pass
        v = corr_llm.verdicts({corr_llm.pair("a", "b"), corr_llm.pair("a", "c")})
        self.assertTrue(v[corr_llm.pair("a", "b")]["related"])
        self.assertFalse(v[corr_llm.pair("a", "c")]["related"])
        self.assertTrue(all(x["model"] == clef.config()["model"] for x in v.values()))

    def test_event_pass_one_call_with_all_related_events(self):
        """After every link is decided the reviewer gets ONE call per event with all its related events, classifies the
        event and writes the link notes; it cannot change a link's verdict.
        REQ: LLM-03"""
        corr_llm.clef_pass(BASE, [("a", r) for r in BASE["related"]["a"]])
        calls = []

        def fake(target, anchor, cands, *a, **kw):
            calls.append(([c[0]["label"] for c in cands], kw.get("system")))
            return ([{"id": "anchor", "label": "benign", "confidence": 0.8, "reason": "brute force then login"},
                     {"id": "c1", "label": "link", "confidence": 0.9, "reason": "same ssh target nas", "artifacts": []}], {"prompt": 10, "completion": 5}, 1.0)
        old, oldt = corr_llm._ask_full, corr_llm._target
        corr_llm._ask_full, corr_llm._target = fake, lambda model=None: {"provider": "lmstudio", "model": "reviewer"}
        oldr = corr_llm.reopen_checked
        corr_llm.reopen_checked = lambda *a, **k: None
        try:
            n = corr_llm.event_pass(BASE)
        finally:
            corr_llm._ask_full, corr_llm._target, corr_llm.reopen_checked = old, oldt, oldr
        self.assertEqual(n, 1)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][0], ["ssh brute force on nas"])  # only the clef-related event gets a link note
        self.assertTrue(calls[0][1].startswith(corr_llm.EVENT_SYSTEM))
        self.assertIn("DECISION MODEL LABEL: suspicious", calls[0][1])
        v = corr_llm.verdicts({corr_llm.pair("a", "b")})[corr_llm.pair("a", "b")]
        self.assertTrue(v["related"]); self.assertTrue(v["reason"].startswith("same ssh target nas"))
        with corr_llm._db() as c:
            self.assertEqual(c.execute("SELECT label FROM event_class WHERE eid='a'").fetchone()[0], "suspicious")
        # the decision model labelled the event (one request over the event and ALL its candidates) and that label is used;
        # the reviewer's own (different) label is only recorded for the agreement figure
        self.assertEqual([q for q, _ in CALLS], ["related", "related", "suspicious"])
        self.assertIn("printer firmware", CALLS[-1][1])  # the not-related candidate is in the decision model's state too
        with corr_llm._db() as c:
            self.assertEqual(c.execute("SELECT reviewer_label FROM clef_event WHERE eid='a'").fetchone()[0], "benign")
        self.assertEqual(corr_llm.clef_compare()["matrix"], {"suspicious|benign": 1})

    def test_rereview_clears_decision(self):
        """Asking again removes the decision-model answer so the whole chain runs again.
        REQ: LLM-03"""
        corr_llm.clef_pass(BASE, [("a", r) for r in BASE["related"]["a"]])
        corr_llm.override(corr_llm.pair("a", "c"), None, "tester")
        self.assertNotIn(corr_llm.pair("a", "c"), corr_llm.clef_decisions([corr_llm.pair("a", "c")]))

    def test_config_is_loopback_only(self):
        """A non-loopback URL in the settings is ignored (event data never leaves the host).
        REQ: LLM-03"""
        raw = corr_llm._raw_config()
        corr_llm._save_config({**raw, "clef": {"url": "http://evil.example:8091"}})
        try:
            self.assertTrue(clef.config()["url"].startswith("http://127.0.0.1"))
        finally:
            corr_llm._save_config(raw)


class ClefServerSettingsTest(unittest.TestCase):
    def test_validate(self):
        """Server settings accept only listed model files / runtimes and safe numbers; batch must cover a whole input.
        REQ: LLM-03"""
        import clef_server as CS
        old_m, old_s = CS.models, CS.servers
        CS.models = lambda: [{"path": "/m/Cloudflare_clef-Q4_K_S.gguf", "name": "x", "gb": 1, "flash": False}]
        CS.servers = lambda: ["/b/llama.cpp-cuda-2.65.1/llama-server"]
        try:
            ok = CS.validate({"gguf": "/m/Cloudflare_clef-Q4_K_S.gguf", "parallel": 2, "ctx": 16384, "batch": 8192})
            self.assertEqual((ok["parallel"], ok["ctx"]), (2, 16384))
            for bad in ({"gguf": "/etc/passwd"}, {"server": "/bin/sh"}, {"parallel": 99}, {"batch": 512}, {"port": 22}):
                with self.assertRaises(ValueError):
                    CS.validate(bad)
            CS.save({"parallel": 3}, "tester")
            self.assertIn('CLEF_PARALLEL:=3', CS.shell_env())
        finally:
            CS.models, CS.servers = old_m, old_s

    def test_patapsco_backend(self):
        """The Patapsco AI backend (default) is reached on loopback; only known backends are accepted; start/stop/restart
        drive the ModelDeployment through kubectl (stubbed here) and never the host unit.
        REQ: LLM-03"""
        import clef_server as CS
        calls, old = [], CS._kubectl
        CS._kubectl = lambda *a, timeout=30: (calls.append(a), (0, ""))[1]
        try:
            CS.save({"backend": "patapsco"}, "tester")
            self.assertEqual(CS.url(), "http://127.0.0.1:30891")
            with self.assertRaises(ValueError):
                CS.validate({"backend": "cloud"})
            CS.control("stop"); CS.control("start"); CS.control("restart")
            self.assertIn('{"spec": {"replicas": 0}}', calls[0]); self.assertIn('{"spec": {"replicas": 1}}', calls[1])
            self.assertEqual(calls[2][:2], ("delete", "pod"))
            old_url = clef.URL_DEFAULT
            clef.URL_DEFAULT = ""
            try:
                self.assertEqual(clef.config()["url"], clef.PATAPSCO_URL)
                CS.save({"backend": "host", "port": 8091}, "tester")
                self.assertEqual(clef.config()["url"], "http://127.0.0.1:8091")
            finally:
                clef.URL_DEFAULT = old_url
        finally:
            CS._kubectl = old
            CS.save({"backend": "patapsco"}, "tester")

    def test_sglang_health_and_model_field(self):
        """SGLang (Patapsco backend) answers /health with an empty 200 - that counts as healthy - and needs the served
        model name in every /v1/systemone body (it rejects requests without it with HTTP 422).
        REQ: LLM-03"""
        seen = []

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                self.send_response(200); self.send_header("Content-Length", "0"); self.end_headers()

            def do_POST(self):
                b = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                seen.append(b)
                if "model" not in b:
                    self.send_response(422); self.end_headers(); return
                out = json.dumps({"answers": {k: {"type": "noul", "noul": 0.9} for k in b["questions"]}}).encode()
                self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers(); self.wfile.write(out)
        srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            url = f"http://127.0.0.1:{srv.server_port}"
            self.assertTrue(clef.healthy(url))
            ans, _ = clef.ask("{}", {"related": "related?"}, url=url)
            self.assertEqual(ans, {"related": 0.9})
            self.assertEqual(seen[-1]["model"], clef.config()["model"])
        finally:
            srv.shutdown(); srv.server_close()


if __name__ == "__main__":
    unittest.main()
