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
        p = (0.9 if st.count("nas") >= 2 else 0.1) if q == "related" else 0.7  # related: yes when both events name the same host "nas"
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
            return ([{"id": "anchor", "label": "suspicious", "confidence": 0.8, "reason": "brute force then login"},
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
        self.assertEqual(calls[0][0], ["ssh brute force on nas"])  # only the clef-related event
        self.assertIs(calls[0][1], corr_llm.EVENT_SYSTEM)
        v = corr_llm.verdicts({corr_llm.pair("a", "b")})[corr_llm.pair("a", "b")]
        self.assertTrue(v["related"]); self.assertTrue(v["reason"].startswith("same ssh target nas"))
        with corr_llm._db() as c:
            self.assertEqual(c.execute("SELECT label FROM event_class WHERE eid='a'").fetchone()[0], "suspicious")
        self.assertEqual([q for q, _ in CALLS], ["related", "related"])  # the decision model never labels events

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


if __name__ == "__main__":
    unittest.main()
