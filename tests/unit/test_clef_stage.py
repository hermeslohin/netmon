"""Decision-model stage of the correlation review (clef.py + corr_llm.clef_pass / run_once), against a fake
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
        # related: yes when both events name the same host "nas"; suspicious: yes when "failed" appears
        p = (0.9 if st.count("nas") >= 2 else 0.1) if q == "related" else (0.8 if "failed" in st else 0.2)
        out = json.dumps({"answers": {q: {"type": "noul", "noul": p}}}).encode()
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
            c.execute("DELETE FROM clef"); c.execute("DELETE FROM verdicts")

    def test_stages_in_order_and_rejection_is_final(self):
        """All related questions come before any suspicious question; a no is written as a final verdict and only the
        related pair is left for the reviewer, which then sees both answers.
        REQ: LLM-03"""
        left = corr_llm.clef_pass(BASE, [("a", BASE["related"]["a"])])
        qs = [q for q, _ in CALLS]
        self.assertEqual(qs, ["related", "related", "suspicious"])
        self.assertEqual([(a, [r["id"] for r in t]) for a, t in left], [("a", ["b"])])
        v = corr_llm.verdicts({corr_llm.pair("a", "c"), corr_llm.pair("a", "b")})
        self.assertFalse(v[corr_llm.pair("a", "c")]["related"])
        self.assertNotIn(corr_llm.pair("a", "b"), v)  # the reviewer writes that one
        d = corr_llm.clef_decisions([corr_llm.pair("a", "b")])[corr_llm.pair("a", "b")]
        self.assertTrue(d["related"]); self.assertTrue(d["suspicious"])
        self.assertIn("suspicious: YES", corr_llm._clef_line(d))

    def test_reviewer_gets_answers_and_writes_notes(self):
        """The reviewer prompt carries the decision model's answers; its reason is stored, relatedness stays the decision model's.
        REQ: LLM-03"""
        corr_llm.clef_pass(BASE, [("a", BASE["related"]["a"])])
        seen = {}

        def fake_ask(model, anchor, cands, *a, **kw):
            seen["why"], seen["system"] = cands[0][1]["why"], kw.get("system") or ""
            return [{"id": "c1", "related": False, "confidence": 0.3, "reason": "only shares a host", "artifacts": []}]
        old = corr_llm._ask
        corr_llm._ask = fake_ask
        try:
            n = corr_llm._review({"provider": "lmstudio", "model": "reviewer"}, "a", BASE, [BASE["related"]["a"][0]])
        finally:
            corr_llm._ask = old
        self.assertEqual(n, 1)
        self.assertTrue(any(w.startswith("decision model: related YES") for w in seen["why"]))
        self.assertIn("DECISION MODEL", seen["system"])
        v = corr_llm.verdicts({corr_llm.pair("a", "b")})[corr_llm.pair("a", "b")]
        self.assertTrue(v["related"])
        self.assertTrue(v["reason"].startswith("[reviewer disagreed:"))

    def test_rereview_clears_decision(self):
        """Asking again removes the decision-model answer so the whole chain runs again.
        REQ: LLM-03"""
        corr_llm.clef_pass(BASE, [("a", BASE["related"]["a"])])
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


if __name__ == "__main__":
    unittest.main()
