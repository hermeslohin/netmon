"""Unit tests for the event reviewer's web look-ups (corr_llm.py): private-detail filter, cited-source checking, logging + overview."""
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); import _env  # noqa: E402

import json  # noqa: E402
import unittest  # noqa: E402
from unittest import mock  # noqa: E402

import corr_llm  # noqa: E402
from fixtures import mac  # noqa: E402


class WebPrivate(unittest.TestCase):
    def test_refuses_lan_details(self):
        """REQ: WEB-07"""
        for q in ("10.1.2.3 owner", "192.168.0.4", mac(7) + " vendor", "printer.lan", "fd12:3456::1 host"):
            self.assertTrue(corr_llm._web_private(q), q)

    def test_allows_public_indicators(self):
        """REQ: WEB-07"""
        for q in ("ET POLICY curl User-Agent Outbound", "who owns 142.250.80.46", "CVE-2024-3094 xz backdoor", "svchost.exe network"):
            self.assertFalse(corr_llm._web_private(q), q)


class WebLookup(unittest.TestCase):
    def test_search_logs_and_only_returned_urls_are_cited(self):
        """REQ: WEB-08"""
        rows = [{"url": "https://a.example/sig", "title": "Sig A", "snippet": "s"}, {"url": "https://b.example/x", "title": "B", "snippet": "t"}]
        rounds = []

        def fake(target, system, user, max_tokens, purpose="", actor="", queries=False, schemas=None, fmts=None):
            rounds.append(user)
            if len(rounds) == 1:
                return json.dumps({"decisions": [], "queries": [], "web": [{"search": "ET INFO test sig", "why": "meaning"}]}), {}, 0
            return json.dumps({"decisions": [{"id": "anchor", "label": "benign", "confidence": 0.9, "reason": "r",
                                              "sources": ["https://a.example/sig", "https://invented.example/"]}]}), {}, 0
        with mock.patch.object(corr_llm, "_complete", fake), mock.patch("webtools.search", return_value=rows):
            logw = corr_llm._web_logger("ids|t", [], "m", "unit-test")
            dec, _u, _s = corr_llm._ask_full({"provider": "lmstudio", "model": "m"}, {"type": "ids", "label": "x", "t0": None}, [], {},
                                             web_max=2, on_web=logw, base_tokens=50)
        self.assertIn("<web_result", rounds[1])
        self.assertEqual(logw.n, 1)
        self.assertEqual(corr_llm._sources(dec[0], logw), [{"url": "https://a.example/sig", "title": "Sig A"}])
        ov = corr_llm.web_overview({})
        self.assertGreaterEqual(ov["total"], 1)
        self.assertEqual(ov["recent"][0]["query"], "ET INFO test sig")

    def test_private_search_refused_and_reported(self):
        """REQ: WEB-07"""
        logw = corr_llm._web_logger("ids|t", [], "m", "unit-test")
        with mock.patch("webtools.search") as s:
            out = corr_llm._web_lookup(1, {"search": "10.0.0.9 who", "why": "w"}, logw)
        s.assert_not_called()
        self.assertIn("refused", out)

    def test_lookups_first_runs_planned_searches_before_deciding(self):
        """REQ: WEB-08"""
        systems = []

        def fake(target, system, user, max_tokens, purpose="", actor="", queries=False, schemas=None, fmts=None):
            systems.append((system, user, schemas))
            if "PLANNING STEP" in system:
                return json.dumps({"queries": [{"source": "zeek", "match": {"source.ip": "198.51.100.7"}, "why": "w"}], "web": []}), {"prompt": 5}, 0
            return json.dumps({"decisions": [{"id": "c1", "related": False, "confidence": 0.5, "reason": "r", "artifacts": []}], "queries": []}), {"prompt": 5}, 0
        logq = mock.Mock()
        with mock.patch.object(corr_llm, "_complete", fake), mock.patch.object(corr_llm, "lookup_plan", return_value=True), \
                mock.patch.object(corr_llm, "broker", return_value={"total": 3, "docs": [], "query": {"source": "zeek"}}):
            dec, usage, _s = corr_llm._ask_full({"provider": "lmstudio", "model": "m"}, {"type": "ids", "label": "x", "t0": None}, [], {},
                                                es_max=3, on_query=logq)
        self.assertIn("PLANNING STEP", systems[0][0])
        self.assertIs(systems[0][2][1], corr_llm.PSCHEMA)
        self.assertIn("<es_result", systems[1][1])
        self.assertEqual((usage["es"], usage["planned"]), (1, True))
        logq.assert_called_once()

    def test_planned_query_slips_are_fixed(self):
        """REQ: WEB-08"""
        q = corr_llm._fix_query({"source": "zeek", "match": {"destination_port": 161, "rule.name": "GPL SNMP public access udp x357"},
                                 "start": "2026-11-05 00:00 UTC", "end": "soon"})
        self.assertEqual(q["match"], {"destination.port": 161, "rule.name": "GPL SNMP public access udp"})
        self.assertEqual(q["start"], "2026-11-05T00:00:00+00:00")
        self.assertNotIn("end", q)

    def test_web_artifacts(self):
        """REQ: WEB-08"""
        self.assertEqual(corr_llm.web_artifacts([{"url": "https://a/", "title": "A"}])[0]["kind"], "web")


if __name__ == "__main__":
    unittest.main()
