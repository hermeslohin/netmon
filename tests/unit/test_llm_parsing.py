"""Unit tests for the network-free parsing helpers of corr_llm.py and llm_providers.py."""
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); import _env  # noqa: E402

import json  # noqa: E402
import unittest  # noqa: E402

import corr_llm  # noqa: E402
import llm_providers as LP  # noqa: E402


class FirstJsonTest(unittest.TestCase):
    """corr_llm._json() and corr_llm._json() take the first complete JSON object of a reply."""

    def test_plain_object(self):
        """A bare JSON object is parsed as-is.
        REQ: LLM-01"""
        self.assertEqual(corr_llm._json('{"verdict": "benign"}'), {"verdict": "benign"})

    def test_code_fence_and_prose(self):
        """Prose and code fences around the object are ignored.
        REQ: LLM-01"""
        txt = 'Sure! Here it is:\n```json\n{"verdict": "suspicious", "priority": "Review"}\n```\nHope that helps.'
        self.assertEqual(corr_llm._json(txt)["verdict"], "suspicious")

    def test_second_object_ignored(self):
        """When a reply holds two objects only the first is used.
        REQ: LLM-01"""
        self.assertEqual(corr_llm._json('{"a": 1}\n{"a": 2}'), {"a": 1})
        self.assertEqual(corr_llm._json('x {"a": 1} {"b": 2}'), {"a": 1})

    def test_braces_inside_strings(self):
        """Braces inside JSON strings do not end the object early.
        REQ: LLM-01"""
        self.assertEqual(corr_llm._json('{"summary": "saw {weird} }} text", "n": 1}'), {"summary": "saw {weird} }} text", "n": 1})

    def test_nested_object(self):
        """Nested objects are returned whole.
        REQ: LLM-01"""
        self.assertEqual(corr_llm._json('ok {"decisions": [{"id": "a", "related": true}]} end')["decisions"][0]["related"], True)

    def test_no_json_raises(self):
        """A reply without any '{' raises ValueError.
        REQ: LLM-01"""
        with self.assertRaises(ValueError):
            corr_llm._json("I cannot answer that.")

    def test_truncated_json_raises(self):
        """A truncated object raises a ValueError (JSONDecodeError) instead of returning partial data.
        REQ: LLM-01"""
        with self.assertRaises(ValueError):
            corr_llm._json('{"verdict": "benign", "summary": "cut')
        with self.assertRaises(ValueError):
            corr_llm._json("no json here")


class CorrLlmHelpersTest(unittest.TestCase):
    """Pure helpers of corr_llm.py: artifacts, severities, classes, rules and windows."""

    def test_clean_artifacts(self):
        """clean_artifacts() maps kind aliases, drops invalid entries and duplicates, and caps at 12.
        REQ: LLM-01"""
        arts = [{"kind": "Domain", "value": "x.example.com", "decision": "Suspicious"},
                {"kind": "dns", "value": "x.example.com", "decision": "benign"},  # duplicate
                {"kind": "path", "value": "/tmp/a", "decision": "expected", "relation": "r" * 500},
                {"kind": "weird", "value": "v", "decision": "benign"},
                {"kind": "ip", "value": "", "decision": "benign"},
                {"kind": "user", "value": "bob", "decision": "maybe"},
                "not a dict"]
        out = corr_llm.clean_artifacts(arts)
        self.assertEqual([(a["kind"], a["value"], a["decision"]) for a in out], [("dns", "x.example.com", "suspicious"), ("file", "/tmp/a", "expected")])
        self.assertEqual(len(out[1]["relation"]), 200)
        many = [{"kind": "ip", "value": f"10.0.0.{i}", "decision": "benign"} for i in range(30)]
        self.assertEqual(len(corr_llm.clean_artifacts(many)), 12)
        self.assertEqual(corr_llm.clean_artifacts(None), [])

    def test_sev_of(self):
        """sev_of() normalises severity words to low/medium/high; unknown or missing is low.
        REQ: LLM-01"""
        cases = {"Critical": "high", "investigate": "high", "warning": "medium", "Review": "medium", "info": "low", None: "low", "": "low"}
        for s, want in cases.items():
            self.assertEqual(corr_llm.sev_of({"sev": s}), want, s)
        self.assertEqual(corr_llm.sev_of(None), "low")

    def test_etype_and_pclass(self):
        """Segmentation issues/findings form the 'seg' class; other events use their type, split by severity.
        REQ: COR-03"""
        self.assertEqual(corr_llm.etype("iss|seg|x", {"type": "vuln"}), "seg")
        self.assertEqual(corr_llm.etype("f|segmentation|x|y", {}), "seg")
        self.assertEqual(corr_llm.etype("ids|sig", None), "ids")
        self.assertEqual(corr_llm.pclass("alert|1", {"type": "alert", "sev": "high"}), "alert_high")
        self.assertEqual(corr_llm.split_class("seg_medium"), ("seg", "medium"))
        self.assertEqual(corr_llm.split_class("vuln"), ("vuln", ""))
        self.assertEqual(corr_llm.pair_type("vuln", "alert"), "alert-vuln")

    def test_pair_mode_legacy_fallbacks(self):
        """pair_mode() prefers the exact pair, then legacy un-split keys, then the default.
        REQ: COR-03"""
        self.assertEqual(corr_llm.pair_mode({"alert_high-vuln_low": "skip"}, "review", "vuln_low", "alert_high"), "skip")
        self.assertEqual(corr_llm.pair_mode({"alert-vuln": "skip"}, "review", "alert_high", "vuln_low"), "skip")
        self.assertEqual(corr_llm.pair_mode({"host-seg_high": "skip"}, "review", "seg_low", "seg_high"), "skip")
        self.assertEqual(corr_llm.pair_mode({}, "review", "ids_low", "gw_low"), "review")

    def test_fam_masks_port_numbers(self):
        """_fam() masks 4-5 digit numbers so one family covers every port, but leaves shorter numbers.
        REQ: COR-03"""
        self.assertEqual(corr_llm._fam("iss|seg|10.0.1.10|8443"), "iss|seg|10.0.1.10|#")
        self.assertEqual(corr_llm._fam("ids|x 22"), "ids|x 22")

    def test_glob(self):
        """_glob(): * and ? are wildcards over the whole text, [ ] are literal, plain patterns are substring/exact.
        REQ: LLM-01"""
        self.assertTrue(corr_llm._glob("ET SCAN*", "et scan nmap", False))
        self.assertFalse(corr_llm._glob("SCAN*", "ET SCAN", False))
        self.assertTrue(corr_llm._glob("['10.0.0.?']", "['10.0.0.5']", False))
        self.assertTrue(corr_llm._glob("scan", "ET SCAN probe", True))
        self.assertFalse(corr_llm._glob("scan", "ET SCAN probe", False))
        self.assertTrue(corr_llm._glob("Exact", "exact", False))

    def test_rule_match_and_suppressed(self):
        """A rule matches only when all its fields match; suppressed() honours the rule scope.
        REQ: LLM-01"""
        ev = {"label": "IDS: ET SCAN probe from 203.0.113.9", "ips": ["10.0.2.20"]}
        self.assertTrue(corr_llm.rule_match({"name": "et scan"}, "ids|x", ev))
        self.assertTrue(corr_llm.rule_match({"name": "scan", "host": "10.0.2.*"}, "ids|x", ev))
        self.assertFalse(corr_llm.rule_match({"name": "scan", "host": "10.0.3.*"}, "ids|x", ev))
        self.assertTrue(corr_llm.rule_match({"id": "ids|*"}, "ids|x", ev))
        self.assertFalse(corr_llm.rule_match({"id": "ids"}, "ids|x", ev))
        rules = [{"name": "scan", "scope": "research"}]
        self.assertTrue(corr_llm.suppressed(rules, "research", "ids|x", ev))
        self.assertFalse(corr_llm.suppressed(rules, "review", "ids|x", ev))
        self.assertTrue(corr_llm.suppressed([{"name": "scan"}], "review", "ids|x", ev))

    def test_apart_fn(self):
        """apart_fn(window) reports events whose time spans are more than window minutes apart; time-less events never are.
        REQ: COR-03"""
        apart = corr_llm.apart_fn(60)
        self.assertFalse(apart({"t0": 0, "t1": 100}, {"t0": 100 + 3600}))
        self.assertTrue(apart({"t0": 0, "t1": 100}, {"t0": 101 + 3600}))
        self.assertFalse(apart({"t0": None}, {"t0": 10 ** 9}))
        self.assertFalse(apart({}, {"t0": 1}))
        self.assertFalse(corr_llm.apart_fn(0)({"t0": 0}, {"t0": 10 ** 9}))

    def test_num_clamps(self):
        """_num() clamps to the range and returns 0 for non-numbers.
        REQ: LLM-01"""
        self.assertEqual(corr_llm._num("50", 0, 10), 10)
        self.assertEqual(corr_llm._num(-5, 0, 10), 0)
        self.assertEqual(corr_llm._num("abc", 1, 10), 0)
        self.assertEqual(corr_llm._num(None, 1, 10), 1)

    def test_pair_key_unordered(self):
        """pair() gives the same key for both orders of two event ids.
        REQ: COR-03"""
        self.assertEqual(corr_llm.pair("b", "a"), corr_llm.pair("a", "b"))
        self.assertEqual(corr_llm.pair("a", "b"), "a\x1fb")


class ProviderHelpersTest(unittest.TestCase):
    """Pure helpers of llm_providers.py (no network, provider storage stubbed where needed)."""

    def test_is_custom_and_known(self):
        """'api:<id>' providers are custom; 'lmstudio' is known but not custom; other values are neither.
        REQ: LLM-01"""
        self.assertTrue(LP.is_custom("api:x"))
        self.assertFalse(LP.is_custom("lmstudio"))
        self.assertFalse(LP.is_custom(None))
        self.assertTrue(LP.known("lmstudio"))
        self.assertTrue(LP.known("api:x"))
        self.assertFalse(LP.known("openai"))

    def test_mask(self):
        """_mask() shows only the last 4 chars of a long key, 'set' for a short one and '' for none.
        REQ: LLM-01"""
        self.assertEqual(LP._mask("abcdefghijklmnop"), "…mnop")
        self.assertEqual(LP._mask("short"), "set")
        self.assertEqual(LP._mask(""), "")

    def test_scrub(self):
        """_scrub() removes the given key and anything that looks like an sk- key from error text.
        REQ: LLM-01"""
        s = LP._scrub("bad key sk-abcdefgh12 and secretvalue99", "secretvalue99")
        self.assertNotIn("abcdefgh12", s)
        self.assertNotIn("secretvalue99", s)
        self.assertIn("[key]", s)

    def test_base_url(self):
        """_base_url() defaults per type and allows http only for loopback/private hosts, never credentials/query.
        REQ: LLM-01"""
        self.assertEqual(LP._base_url("openai", ""), "https://api.openai.com/v1")
        self.assertEqual(LP._base_url("anthropic", None), "https://api.anthropic.com")
        self.assertEqual(LP._base_url("openai", "http://10.0.0.5:8000/v1/"), "http://10.0.0.5:8000/v1")
        self.assertEqual(LP._base_url("openai", "http://localhost:1234/v1"), "http://localhost:1234/v1")
        # (RFC 5737 documentation IPs count as private for ipaddress, so a public http host is tested by name)
        for bad in ("http://example.com/v1", "https://u:p@example.com", "https://example.com/v1?a=1",
                    "https://example.com/#f", "ftp://example.com", "file:///etc/passwd"):
            with self.assertRaises(ValueError, msg=bad):
                LP._base_url("openai", bad)

    def test_models_parsing(self):
        """_models() reads one model per line with optional prices and de-duplicates ids.
        REQ: LLM-01"""
        models, prices = LP._models("gpt-x 2.5 10\nclaude-y, 3, 15, 0.3\n\ngpt-x\n")
        self.assertEqual(models, ["gpt-x", "claude-y"])
        self.assertEqual(prices, {"gpt-x": [2.5, 10.0], "claude-y": [3.0, 15.0, 0.3]})
        self.assertEqual(LP._models(["a", "b", "a"]), (["a", "b"], {}))

    def test_models_rejects_bad_input(self):
        """_models() rejects odd characters, a single price, out-of-range or non-numeric prices and too many models.
        REQ: LLM-01"""
        for bad in ("bad model!", "-leading", "m 5", "m 1 2000", "m x y"):
            with self.assertRaises(ValueError, msg=bad):
                LP._models(bad)
        with self.assertRaises(ValueError):
            LP._models([f"m{i}" for i in range(LP.MAX_MODELS + 1)])

    def test_int(self):
        """_int() returns the default for empty input and validates whole numbers within bounds.
        REQ: LLM-01"""
        self.assertEqual(LP._int("", 1, 10, 5, "n"), 5)
        self.assertEqual(LP._int("7", 1, 10, 5, "n"), 7)
        for bad in ("x", "0", "11", "1.5"):
            with self.assertRaises(ValueError, msg=bad):
                LP._int(bad, 1, 10, 5, "n")

    def test_headers_and_models_path(self):
        """Anthropic gets x-api-key and a version header; OpenAI-compatible gets a Bearer token.
        REQ: LLM-01"""
        a = LP._headers({"type": "anthropic", "api_key": "k1"})
        self.assertEqual((a["x-api-key"], a["anthropic-version"]), ("k1", LP.ANTHROPIC_VERSION))
        self.assertEqual(LP._headers({"type": "openai", "api_key": "k2"})["Authorization"], "Bearer k2")
        self.assertEqual(LP._models_path({"type": "anthropic"}), "/v1/models?limit=1000")
        self.assertEqual(LP._models_path({"type": "openai"}), "/models")

    def test_skip_filter(self):
        """Non-chat models (embeddings, audio, images) are filtered; chat models pass.
        REQ: LLM-01"""
        for m in ("text-embedding-3-small", "whisper-1", "tts-1", "dall-e-3", "gpt-4o-realtime"):
            self.assertTrue(LP._SKIP.search(m), m)
        for m in ("gpt-4o", "claude-sonnet-4", "o3-mini"):
            self.assertFalse(LP._SKIP.search(m), m)

    def test_oa_messages(self):
        """Neutral messages convert to OpenAI chat format, including tool calls and results.
        REQ: LLM-01"""
        msgs = [{"role": "user", "content": "hi"},
                {"role": "assistant", "content": "", "tool_calls": [{"id": "c1", "name": "es_search", "args": {"q": "x"}}]},
                {"role": "tool", "id": "c1", "content": "res"}]
        out = LP._oa_messages("sys", msgs)
        self.assertEqual(out[0], {"role": "system", "content": "sys"})
        self.assertIsNone(out[2]["content"])
        self.assertEqual(json.loads(out[2]["tool_calls"][0]["function"]["arguments"]), {"q": "x"})
        self.assertEqual(out[3], {"role": "tool", "tool_call_id": "c1", "content": "res"})
        self.assertEqual(LP._oa_messages("", [{"role": "user"}]), [{"role": "user", "content": ""}])

    def test_an_messages(self):
        """Anthropic conversion merges consecutive tool results into one user turn and marks the last block for caching.
        REQ: LLM-01"""
        msgs = [{"role": "user", "content": "q"},
                {"role": "assistant", "tool_calls": [{"id": "a", "name": "t", "args": {}}, {"id": "b", "name": "t"}]},
                {"role": "tool", "id": "a", "content": "1"}, {"role": "tool", "id": "b", "content": "2"}]
        out = LP._an_messages(msgs, cache=True)
        self.assertEqual([m["role"] for m in out], ["user", "assistant", "user"])
        self.assertEqual([b["tool_use_id"] for b in out[2]["content"]], ["a", "b"])
        self.assertEqual(out[2]["content"][-1]["cache_control"], {"type": "ephemeral"})
        self.assertNotIn("cache_control", LP._an_messages(msgs, cache=False)[2]["content"][-1])
        self.assertEqual(LP._an_messages([{"role": "assistant"}], False)[0]["content"], [{"type": "text", "text": "(no text)"}])

    def test_rs_input(self):
        """Responses-API input keeps raw assistant items and converts tool calls/results.
        REQ: LLM-01"""
        raw = [{"type": "reasoning", "encrypted_content": "x"}]
        msgs = [{"role": "user", "content": "q"}, {"role": "assistant", "raw": raw, "content": "ignored"},
                {"role": "assistant", "content": "c", "tool_calls": [{"id": "1", "name": "f", "args": {"a": 1}}]},
                {"role": "tool", "id": "1", "content": "r"}]
        out = LP._rs_input(msgs)
        self.assertEqual(out[1], raw[0])
        self.assertEqual(out[2], {"role": "assistant", "content": "c"})
        self.assertEqual(out[3]["type"], "function_call")
        self.assertEqual(out[4], {"type": "function_call_output", "call_id": "1", "output": "r"})

    def test_price_and_cost(self):
        """price() reads admin prices (cached-input defaults to input), local is free, unknown is None; cost() uses them.
        REQ: LLM-01"""
        saved = LP._load_all
        LP._load_all = lambda: ([{"id": "p1", "name": "P1", "api_key": "k", "models": ["m", "n"], "prices": {"m": [2.0, 8.0]}}], {})
        try:
            self.assertEqual(LP.price("api:p1", "m"), {"in": 2.0, "out": 8.0, "cache_read": 2.0})
            self.assertIsNone(LP.price("api:p1", "n"))
            self.assertEqual(LP.price("lmstudio", "any"), {"in": 0.0, "out": 0.0, "cache_read": 0.0})
            self.assertAlmostEqual(LP.cost("api:p1", "m", {"prompt": 1_000_000, "completion": 500_000}), 6.0)
            self.assertIsNone(LP.cost("api:p1", "n", {"prompt": 1}))
            self.assertEqual(LP.cost("api:p1", "m", None), 0.0)
            self.assertTrue(LP.allowed("api:p1", "m"))
            self.assertFalse(LP.allowed("api:p1", "zzz"))
            self.assertEqual(LP.name("api:p1"), "P1")
            self.assertEqual(LP.name("api:nope"), "api:nope")
        finally:
            LP._load_all = saved


if __name__ == "__main__":
    unittest.main()
