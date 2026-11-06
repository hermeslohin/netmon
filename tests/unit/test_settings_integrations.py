"""Unit tests for the Integrations settings (integrations.py) sections elasticsearch, unifi and audit, plus the audit on/off switches end to end."""
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); import _env  # noqa: E401,E702,E402

import io  # noqa: E402
import json  # noqa: E402
import shutil  # noqa: E402
import tempfile  # noqa: E402
import time  # noqa: E402
import unittest  # noqa: E402
import urllib.error  # noqa: E402
from unittest import mock  # noqa: E402

import audit  # noqa: E402
import integrations  # noqa: E402
import reviewlog  # noqa: E402

FAKE_KEY = "x" * 12 + "abcd"    # placeholders, not credentials
OTHER_KEY = "y" * 12 + "wxyz"
ES = "https://es.example.com:9200"
SITE_ES = "https://site-es.example.com:9200"
UNIFI = "https://unifi.example.com"
ENV_VARS = ("ES_URL", "ES_API_KEY", "NETMON_AUDIT_ES_KEY", "NETMON_IN_DASHBOARD")


def _http_error(code=401, reason="Unauthorized", body=None):
    fp = io.BytesIO(json.dumps(body if body is not None else {"error": {"reason": "bad api key"}}).encode())
    return urllib.error.HTTPError("https://es.example.com/x", code, reason, {}, fp)


class _Base(unittest.TestCase):
    """Isolation: empty temp integrations doc, empty host secrets file, no env overrides, site es_url stubbed."""

    def setUp(self):
        _env.fresh_db()
        integrations._cache["k"] = None
        self.tmp = tempfile.mkdtemp(prefix="settings-int-", dir=_env.TMP)
        self.secrets = os.path.join(self.tmp, "secrets.env")
        open(self.secrets, "w").close()
        self.site = {"es_url": SITE_ES}
        orig_get = integrations.SITE.get
        self.patches = [
            mock.patch.object(integrations, "SECRETS", self.secrets),
            mock.patch.dict(os.environ, {}),
            mock.patch.object(integrations.SITE, "get", lambda k, d=None: self.site.get(k, d) if k == "es_url" else orig_get(k, d)),
        ]
        for p in self.patches:
            p.start()
        for v in ENV_VARS:
            os.environ.pop(v, None)

    def tearDown(self):
        for p in reversed(self.patches):
            p.stop()
        shutil.rmtree(self.tmp, True)
        _env.fresh_db()
        integrations._cache["k"] = None

    def host_secrets(self, **kv):
        with open(self.secrets, "w") as f:
            f.writelines(f"{k}={v}\n" for k, v in kv.items())

    def stored(self, section):
        integrations._cache["k"] = None
        return dict(integrations.load().get(section) or {})

    def assert_refused(self, section, body):
        before = self.stored(section)
        with self.assertRaises(ValueError):
            integrations.save(section, body, "admin")
        self.assertEqual(self.stored(section), before, "a refused post must not change the stored settings")


class UrlSettings(_Base):
    """Elasticsearch and UniFi URLs: http(s) only, normalised, fallbacks when blank."""

    def test_bad_urls_refused(self):
        """Elasticsearch and UniFi URLs that are not http(s) or contain spaces/quotes/brackets are refused and nothing is saved.
        REQ: SET-01"""
        for sec in ("elasticsearch", "unifi"):
            for bad in ("ftp://es.example.com", "es.example.com:9200", "javascript:alert(1)", "https://a b.example.com",
                        'https://es.example.com/"x', "https://es.example.com/<x>", "https://es.example.com/'", "https://x.example.com/a\nb"):
                with self.subTest(sec=sec, url=bad):
                    self.assert_refused(sec, {"url": bad})

    def test_good_urls_normalised(self):
        """http:// and https:// URLs are accepted, trimmed and stored without the trailing slash.
        REQ: SET-01"""
        integrations.save("elasticsearch", {"url": "  " + ES + "/ "}, "admin")
        integrations.save("unifi", {"url": "http://unifi.example.com/"}, "admin")
        self.assertEqual(self.stored("elasticsearch")["url"], ES)
        self.assertEqual(self.stored("unifi")["url"], "http://unifi.example.com")
        self.assertEqual((integrations.es_url(), integrations.unifi_url()), (ES, "http://unifi.example.com"))
        self.assertEqual(integrations._clean_url("https://e.example.com/" + "a" * 400)[:8], "https://")
        self.assertLessEqual(len(integrations._clean_url("https://e.example.com/" + "a" * 400)), 300)

    def test_es_url_fallback_chain(self):
        """The Elasticsearch URL is ES_URL from the environment, else the saved setting, else site.json es_url; blank saved = fallback.
        REQ: SET-02"""
        self.assertEqual(integrations.es_url(), SITE_ES)
        integrations.save("elasticsearch", {"url": ES + "/"}, "admin")
        self.assertEqual(integrations.es_url(), ES)
        os.environ["ES_URL"] = "https://env-es.example.com/"
        self.assertEqual(integrations.es_url(), "https://env-es.example.com")
        del os.environ["ES_URL"]
        integrations.save("elasticsearch", {"url": ""}, "admin")
        self.assertEqual(integrations.es_url(), SITE_ES)
        p = integrations.public()["elasticsearch"]
        self.assertEqual((p["url"], p["url_fallback"]), ("", SITE_ES))

    def test_unifi_url_default(self):
        """The UniFi API URL defaults to https://api.ui.com; a saved URL overrides it and a blank one restores the default.
        REQ: SET-08"""
        self.assertEqual(integrations.unifi_url(), integrations.UNIFI_DEFAULT)
        integrations.save("unifi", {"url": UNIFI}, "admin")
        self.assertEqual(integrations.unifi_url(), UNIFI)
        self.assertEqual(integrations.public()["unifi"]["url"], UNIFI)
        integrations.save("unifi", {"url": ""}, "admin")
        self.assertEqual(integrations.unifi_url(), "https://api.ui.com")
        self.assertEqual(integrations.public()["unifi"]["url_fallback"], "https://api.ui.com")

    def test_http_layer_refuses_other_schemes(self):
        """The shared HTTP helper refuses anything but http(s) before opening a connection.
        REQ: SET-01"""
        with mock.patch("urllib.request.urlopen") as op:
            for bad in ("ftp://es.example.com/", "file:///etc/passwd", "es.example.com"):
                with self.assertRaises(ValueError):
                    integrations._http(bad, {})
            op.assert_not_called()


class IndexSettings(_Base):
    """Elasticsearch per-collector index overrides."""

    def test_bad_index_names_refused(self):
        """Index patterns with spaces, slashes, quotes, ?, #, a leading _ - + or over 200 characters are refused.
        REQ: SET-03"""
        for bad in ("logs zeek", "logs/zeek", 'lo"gs', "lo'gs", "logs?x", "logs#x", "logs\\x", "<x>", "_all", "-logs", "+logs", "a" * 201):
            with self.subTest(ix=bad):
                self.assert_refused("elasticsearch", {"url": ES, "indices": {"zeek": bad}})

    def test_index_patterns_allowed(self):
        """Comma-separated patterns and wildcards are accepted for the collector indices (not for the audit index).
        REQ: SET-03"""
        integrations.save("elasticsearch", {"indices": {"zeek": " logs-zeek-*,other-zeek ", "suricata": "ids-*"}}, "admin")
        ix = self.stored("elasticsearch")["indices"]
        self.assertEqual(ix, {"zeek": "logs-zeek-*,other-zeek", "suricata": "ids-*", "detections": ""})

    def test_per_index_override_and_defaults(self):
        """es_index() returns the saved override for each collector and the Security Onion default for blank or unknown ones.
        REQ: SET-04"""
        for n, d in integrations.INDEX_DEFAULTS.items():
            self.assertEqual(integrations.es_index(n), d)
        integrations.save("elasticsearch", {"indices": {"suricata": "my-ids", "bogus": "ignored"}}, "admin")
        self.assertEqual(integrations.es_index("suricata"), "my-ids")
        self.assertEqual(integrations.es_index("zeek"), "logs-zeek-so")
        self.assertEqual(integrations.es_index("detections"), "logs-detections.alerts-so")
        self.assertNotIn("bogus", self.stored("elasticsearch")["indices"])
        p = integrations.public()["elasticsearch"]
        self.assertEqual(p["indices"], {"zeek": "", "suricata": "my-ids", "detections": ""})
        self.assertEqual(p["index_defaults"], integrations.INDEX_DEFAULTS)
        self.assertEqual(set(p["index_labels"]), set(integrations.INDEX_DEFAULTS))

    def test_map_index_translates_defaults(self):
        """map_index() swaps each default index name in a comma list for its configured one and leaves other names alone.
        REQ: SET-04"""
        self.assertEqual(integrations.map_index("logs-zeek-so,logs-suricata.alerts-so"), "logs-zeek-so,logs-suricata.alerts-so")
        integrations.save("elasticsearch", {"indices": {"zeek": "z1,z2", "detections": "det"}}, "admin")
        self.assertEqual(integrations.map_index("logs-zeek-so,logs-suricata.alerts-so,custom"), "z1,z2,logs-suricata.alerts-so,custom")
        self.assertEqual(integrations.map_index("logs-detections.alerts-so"), "det")
        self.assertEqual(integrations.map_index("unrelated-*"), "unrelated-*")

    def test_url_post_resets_missing_indices(self):
        """An Elasticsearch post always carries the whole form: indices left out of it go back to their defaults.
        REQ: SET-04"""
        integrations.save("elasticsearch", {"url": ES, "indices": {"zeek": "z1"}}, "admin")
        integrations.save("elasticsearch", {"url": ES}, "admin")
        self.assertEqual(integrations.es_index("zeek"), "logs-zeek-so")


class ApiKeys(_Base):
    """API keys are write-only: masked on read, kept when blank, cleared on request, with fallbacks."""

    def test_public_masks_keys(self):
        """public() never returns an API key, only key_set and a masked hint of the last four characters.
        REQ: SET-05"""
        for sec in ("elasticsearch", "unifi", "audit"):
            integrations.save(sec, {"api_key": FAKE_KEY}, "admin")
        pub = integrations.public()
        self.assertNotIn(FAKE_KEY, json.dumps(pub, ensure_ascii=False))
        for sec in ("elasticsearch", "unifi", "audit"):
            with self.subTest(sec=sec):
                self.assertTrue(pub[sec]["key_set"])
                self.assertEqual(pub[sec]["key_hint"], "••••abcd")
                self.assertNotIn("api_key", pub[sec])
        self.assertEqual(integrations._mask("short"), "••••")
        self.assertEqual(integrations._mask(""), "")

    def test_blank_keeps_clear_key_clears(self):
        """A blank api_key keeps the stored key, a new one replaces it, and clear_key removes it, for every section.
        REQ: SET-06"""
        getters = {"elasticsearch": integrations.es_key, "unifi": integrations.unifi_key, "audit": integrations.audit_key}
        for sec, get in getters.items():
            with self.subTest(sec=sec):
                integrations.save(sec, {"api_key": FAKE_KEY}, "admin")
                integrations.save(sec, {"api_key": ""}, "admin")
                self.assertEqual(get(), FAKE_KEY)
                integrations.save(sec, {}, "admin")
                self.assertEqual(get(), FAKE_KEY)
                integrations.save(sec, {"api_key": OTHER_KEY}, "admin")
                self.assertEqual(get(), OTHER_KEY)
                integrations.save(sec, {"api_key": FAKE_KEY, "clear_key": True}, "admin")
                self.assertEqual(get(), "")
                self.assertFalse(integrations.public()[sec]["key_set"])

    def test_bad_keys_refused(self):
        """API keys with whitespace inside or over 400 characters are refused and the old key stays.
        REQ: SET-06"""
        for sec in ("elasticsearch", "unifi", "audit"):
            integrations.save(sec, {"api_key": FAKE_KEY}, "admin")
            for bad in ("x" * 8 + " " + "x" * 8, "x" * 8 + "\t" + "x" * 8, "x" * 401):
                with self.subTest(sec=sec, n=len(bad)):
                    self.assert_refused(sec, {"api_key": bad})
            self.assertEqual(self.stored(sec)["api_key"], FAKE_KEY)
        self.assertEqual(integrations._clean_key("  " + FAKE_KEY + "  "), FAKE_KEY)

    def test_es_key_fallbacks(self):
        """The Elasticsearch key is ES_API_KEY from the environment, else the saved key, else ES_API_KEY in the host secrets file.
        REQ: SET-07"""
        self.assertEqual(integrations.es_key(), "")
        self.host_secrets(ES_API_KEY='"' + "h" * 16 + '"', UNIFI_API_KEY="u" * 16)
        self.assertEqual(integrations.es_key(), "h" * 16)
        self.assertTrue(integrations.public()["elasticsearch"]["key_fallback_present"])
        integrations.save("elasticsearch", {"api_key": FAKE_KEY}, "admin")
        self.assertEqual(integrations.es_key(), FAKE_KEY)
        os.environ["ES_API_KEY"] = OTHER_KEY
        self.assertEqual(integrations.es_key(), OTHER_KEY)

    def test_unifi_key_fallback(self):
        """The UniFi key is the saved key, else UNIFI_API_KEY in the host secrets file; a missing file means no key.
        REQ: SET-07"""
        self.assertEqual(integrations.unifi_key(), "")
        self.assertIs(integrations.public()["unifi"]["key_fallback_present"], False)
        self.host_secrets(UNIFI_API_KEY="u" * 16)
        self.assertEqual(integrations.unifi_key(), "u" * 16)
        self.assertTrue(integrations.public()["unifi"]["key_fallback_present"])
        integrations.save("unifi", {"api_key": FAKE_KEY}, "admin")
        self.assertEqual(integrations.unifi_key(), FAKE_KEY)
        os.remove(self.secrets)
        self.assertEqual(integrations.host_secret("UNIFI_API_KEY"), "")

    def test_container_hides_host_fallback(self):
        """Inside the dashboard container the host secrets file is not checked, so key_fallback_present is unknown (None).
        REQ: SET-07"""
        self.host_secrets(ES_API_KEY="h" * 16, UNIFI_API_KEY="u" * 16)
        os.environ["NETMON_IN_DASHBOARD"] = "1"
        p = integrations.public()
        self.assertIsNone(p["elasticsearch"]["key_fallback_present"])
        self.assertIsNone(p["unifi"]["key_fallback_present"])

    def test_audit_key_env_fallback(self):
        """The audit key is the saved key, else NETMON_AUDIT_ES_KEY from the environment (shown masked); never the ES key.
        REQ: SET-07"""
        self.host_secrets(ES_API_KEY="h" * 16)
        integrations.save("elasticsearch", {"api_key": OTHER_KEY}, "admin")
        self.assertEqual(integrations.audit_key(), "")
        os.environ["NETMON_AUDIT_ES_KEY"] = "e" * 12 + "envk"
        self.assertEqual(integrations.audit_key(), "e" * 12 + "envk")
        a = integrations.public()["audit"]
        self.assertTrue(a["key_set"])
        self.assertEqual(a["key_hint"], "••••envk")
        integrations.save("audit", {"api_key": FAKE_KEY}, "admin")
        self.assertEqual(integrations.audit_key(), FAKE_KEY)


class AuditSettings(_Base):
    """Audit section: one concrete index, switch-only posts, reviewer/researcher switches."""

    def test_audit_index_one_concrete_name(self):
        """The audit index must be one concrete name: commas, wildcards and invalid names are refused; blank means logs-netmon.
        REQ: SET-09"""
        self.assertEqual(integrations.audit_index(), "logs-netmon")
        for bad in ("logs-netmon,other", "logs-*", "*", "a b", "_x", "lo/gs"):
            with self.subTest(ix=bad):
                self.assert_refused("audit", {"index": bad})
        integrations.save("audit", {"index": " my-audit "}, "admin")
        self.assertEqual(integrations.audit_index(), "my-audit")
        self.assertEqual(audit.index(), "my-audit")
        a = integrations.public()["audit"]
        self.assertEqual((a["index"], a["index_default"]), ("my-audit", "logs-netmon"))
        integrations.save("audit", {"index": ""}, "admin")
        self.assertEqual(integrations.audit_index(), "logs-netmon")

    def test_switch_only_post_keeps_index_and_key(self):
        """A post carrying only the send switches leaves the audit index and key as they were.
        REQ: SET-10"""
        integrations.save("audit", {"index": "my-audit", "api_key": FAKE_KEY}, "admin")
        integrations.save("audit", {"send_reviewer": False}, "admin")
        s = self.stored("audit")
        self.assertEqual((s["index"], s["api_key"], s["send_reviewer"]), ("my-audit", FAKE_KEY, False))
        integrations.save("audit", {"send_researcher": False, "send_reviewer": True}, "admin")
        s = self.stored("audit")
        self.assertEqual((s["index"], s["api_key"]), ("my-audit", FAKE_KEY))

    def test_key_post_resets_blank_index(self):
        """A post that carries the api_key (the key/index form) also sets the index, so an omitted index means the default.
        REQ: SET-10"""
        integrations.save("audit", {"index": "my-audit"}, "admin")
        integrations.save("audit", {"api_key": FAKE_KEY}, "admin")
        self.assertEqual(integrations.audit_index(), "logs-netmon")
        self.assertEqual(integrations.audit_key(), FAKE_KEY)

    def test_send_switches_default_on_and_independent(self):
        """send_reviewer and send_researcher are on by default and each toggles without changing the other.
        REQ: SET-11"""
        self.assertTrue(integrations.audit_send("reviewer"))
        self.assertTrue(integrations.audit_send("researcher"))
        a = integrations.public()["audit"]
        self.assertEqual((a["send_reviewer"], a["send_researcher"]), (True, True))
        integrations.save("audit", {"send_reviewer": False}, "admin")
        self.assertEqual((integrations.audit_send("reviewer"), integrations.audit_send("researcher")), (False, True))
        integrations.save("audit", {"send_researcher": 0}, "admin")
        self.assertEqual((integrations.audit_send("reviewer"), integrations.audit_send("researcher")), (False, False))
        integrations.save("audit", {"send_reviewer": 1}, "admin")
        self.assertEqual((integrations.audit_send("reviewer"), integrations.audit_send("researcher")), (True, False))
        a = integrations.public()["audit"]
        self.assertEqual((a["send_reviewer"], a["send_researcher"]), (True, False))
        integrations.save("audit", {"index": "x-audit"}, "admin")  # a post without the switches keeps them
        self.assertEqual((integrations.audit_send("reviewer"), integrations.audit_send("researcher")), (True, False))


class SaveStamps(_Base):
    """Every save is stamped and limited to the known sections."""

    def test_updated_by_and_at(self):
        """Each save stamps updated_by with the user and updated_at with the UTC time, shown by public().
        REQ: SET-12"""
        t0 = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        for sec in ("elasticsearch", "unifi", "audit"):
            pub = integrations.save(sec, {}, "alice-" + sec)
            with self.subTest(sec=sec):
                self.assertEqual(pub[sec]["updated_by"], "alice-" + sec)
                self.assertRegex(pub[sec]["updated_at"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
                self.assertGreaterEqual(pub[sec]["updated_at"], t0)
        self.assertIsNone(integrations.public()["web"]["updated_by"])

    def test_sections_saved_independently(self):
        """Saving one section leaves the others untouched, and an unknown section is refused.
        REQ: SET-12"""
        integrations.save("unifi", {"url": UNIFI, "api_key": FAKE_KEY}, "bob")
        integrations.save("elasticsearch", {"url": ES}, "alice")
        u = self.stored("unifi")
        self.assertEqual((u["url"], u["api_key"], u["updated_by"]), (UNIFI, FAKE_KEY, "bob"))
        with self.assertRaises(ValueError):
            integrations.save("nope", {}, "alice")
        self.assertNotIn("nope", integrations.load())

    def test_candidate_does_not_save(self):
        """candidate() merges a form post with the stored section without writing anything.
        REQ: SET-12"""
        integrations.save("unifi", {"url": UNIFI, "api_key": FAKE_KEY}, "bob")
        c = integrations.candidate("unifi", {"url": "https://other.example.com"})
        self.assertEqual((c["url"], c["api_key"]), ("https://other.example.com", FAKE_KEY))
        self.assertEqual(self.stored("unifi")["url"], UNIFI)

    def test_num_helper(self):
        """The numeric field helper accepts in-range numbers and refuses non-numbers and out-of-range values.
        REQ: SET-12"""
        self.assertEqual(integrations._num("5", 0, 10, "n"), 5)
        self.assertEqual(integrations._num(0.7, 0.5, 1.0, "c", float), 0.7)
        for bad in ("x", None, 11, -1):
            with self.assertRaises(ValueError):
                integrations._num(bad, 0, 10, "n")


class ConnectionTests(_Base):
    """test() for each section with a stubbed HTTP layer: success, error and missing-key paths."""

    def test_es_success(self):
        """The Elasticsearch test searches every collector index (unsaved form values win) with the form key and reports 24 h counts.
        REQ: SET-13"""
        integrations.save("elasticsearch", {"url": "https://saved.example.com", "api_key": OTHER_KEY}, "admin")
        calls = []

        def fake(url, headers, data=None, timeout=15, verify=True):
            calls.append((url, headers, json.loads(data), verify))
            return {"hits": {"total": {"value": 7}}}
        with mock.patch.object(integrations, "_http", fake):
            r = integrations.test("elasticsearch", {"url": ES + "/", "api_key": FAKE_KEY, "indices": {"zeek": "my-zeek"}})
        self.assertTrue(r["ok"])
        self.assertEqual(r["url"], ES)
        self.assertEqual({n: v["index"] for n, v in r["indices"].items()},
                         {"zeek": "my-zeek", "suricata": "logs-suricata.alerts-so", "detections": "logs-detections.alerts-so"})
        self.assertTrue(all(v["ok"] and v["docs_24h"] == 7 for v in r["indices"].values()))
        self.assertEqual(calls[0][0], ES + "/my-zeek/_search")
        self.assertEqual(calls[0][1]["Authorization"], "ApiKey " + FAKE_KEY)
        self.assertEqual(calls[0][2]["size"], 0)
        self.assertIs(calls[0][3], False)  # Security Onion's own CA
        self.assertEqual(self.stored("elasticsearch")["url"], "https://saved.example.com", "test() must not save")

    def test_es_fallbacks_and_errors(self):
        """The Elasticsearch test falls back to site es_url and the host key; one failing index makes ok false and never raises.
        REQ: SET-13"""
        self.host_secrets(ES_API_KEY="h" * 16)
        seen = []

        def fake(url, headers, data=None, timeout=15, verify=True):
            seen.append((url, headers["Authorization"]))
            if "suricata" in url:
                raise _http_error(403, "Forbidden", {"error": {"reason": "no read privilege"}})
            if "detections" in url:
                raise urllib.error.URLError("connection refused")
            return {"hits": {"total": {"value": 1}}}
        with mock.patch.object(integrations, "_http", fake):
            r = integrations.test("elasticsearch", {})
        self.assertFalse(r["ok"])
        self.assertEqual(r["url"], SITE_ES)
        self.assertTrue(seen[0][0].startswith(SITE_ES + "/"))
        self.assertEqual(seen[0][1], "ApiKey " + "h" * 16)
        self.assertTrue(r["indices"]["zeek"]["ok"])
        self.assertEqual(r["indices"]["suricata"]["error"], "HTTP 403 Forbidden: no read privilege")
        self.assertEqual(r["indices"]["detections"]["error"], "connection refused")

    def test_es_no_key(self):
        """Without any Elasticsearch key the test reports an error and makes no request.
        REQ: SET-13"""
        with mock.patch.object(integrations, "_http") as h:
            r = integrations.test("elasticsearch", {"url": ES})
        h.assert_not_called()
        self.assertFalse(r["ok"])
        self.assertIn("API key", r["error"])

    def test_unifi_success_and_error(self):
        """The UniFi test calls /v1/hosts with X-API-KEY, counts consoles and hosts, and reports HTTP errors without raising.
        REQ: SET-13"""
        calls = []

        def ok(url, headers, data=None, timeout=15, verify=True):
            calls.append((url, headers, verify))
            return {"data": [{"type": "console"}, {"type": "console"}, {"type": "other"}]}
        with mock.patch.object(integrations, "_http", ok):
            r = integrations.test("unifi", {"api_key": FAKE_KEY})
        self.assertEqual(r, {"ok": True, "url": "https://api.ui.com", "consoles": 2, "hosts": 3})
        self.assertEqual(calls[0][0], "https://api.ui.com/v1/hosts")
        self.assertEqual(calls[0][1]["X-API-KEY"], FAKE_KEY)
        self.assertIs(calls[0][2], True)  # UniFi cloud: normal TLS verification

        def bad(*a, **k):
            raise _http_error(401, "Unauthorized", {"error": "invalid key"})
        with mock.patch.object(integrations, "_http", bad):
            r = integrations.test("unifi", {"url": UNIFI, "api_key": FAKE_KEY})
        self.assertEqual(r, {"ok": False, "url": UNIFI, "error": "HTTP 401 Unauthorized: invalid key"})

        def boom(*a, **k):
            raise RuntimeError("weird failure")
        with mock.patch.object(integrations, "_http", boom):
            r = integrations.test("unifi", {"url": UNIFI, "api_key": FAKE_KEY})
        self.assertFalse(r["ok"])
        self.assertEqual(r["error"], "weird failure")

    def test_unifi_key_fallback_and_missing(self):
        """The UniFi test uses the stored or host-file key when the form has none, and reports a missing key without a request.
        REQ: SET-13"""
        with mock.patch.object(integrations, "_http") as h:
            r = integrations.test("unifi", {"url": UNIFI})
            h.assert_not_called()
        self.assertFalse(r["ok"])
        self.assertIn("API key", r["error"])
        self.host_secrets(UNIFI_API_KEY="u" * 16)
        with mock.patch.object(integrations, "_http", return_value={"data": []}) as h:
            r = integrations.test("unifi", {})
        self.assertEqual(h.call_args[0][1]["X-API-KEY"], "u" * 16)
        self.assertEqual((r["ok"], r["hosts"], r["consoles"]), (True, 0, 0))

    def test_audit_success_and_error(self):
        """The audit test counts the audit index on the effective ES URL with the audit key (form value wins) and never raises.
        REQ: SET-13"""
        integrations.save("elasticsearch", {"url": ES, "api_key": OTHER_KEY}, "admin")
        calls = []

        def ok(url, headers, data=None, timeout=15, verify=True):
            calls.append((url, headers, data, verify))
            return {"count": 42}
        with mock.patch.object(integrations, "_http", ok):
            r = integrations.test("audit", {"index": "my-audit", "api_key": FAKE_KEY})
        self.assertEqual(r, {"ok": True, "url": ES, "index": "my-audit", "docs": 42})
        self.assertEqual(calls[0][:3], (ES + "/my-audit/_count", {"Authorization": "ApiKey " + FAKE_KEY}, None))
        self.assertIs(calls[0][3], False)
        with mock.patch.object(integrations, "_http", side_effect=_http_error(404, "Not Found", {"error": {"reason": "no such index"}})):
            r = integrations.test("audit", {"api_key": FAKE_KEY})
        self.assertEqual(r, {"ok": False, "url": ES, "index": "logs-netmon", "error": "HTTP 404 Not Found: no such index"})
        with mock.patch.object(integrations, "_http", side_effect=urllib.error.URLError("timed out")):
            r = integrations.test("audit", {"api_key": FAKE_KEY})
        self.assertEqual(r["error"], "timed out")
        self.assertEqual(self.stored("audit"), {}, "test() must not save")

    def test_audit_no_key(self):
        """The audit test needs an audit key (entered or saved); without one it reports an error and makes no request.
        REQ: SET-13"""
        with mock.patch.object(integrations, "_http") as h:
            r = integrations.test("audit", {})
            h.assert_not_called()
        self.assertFalse(r["ok"])
        self.assertIn("audit API key", r["error"])
        integrations.save("audit", {"api_key": FAKE_KEY}, "admin")
        with mock.patch.object(integrations, "_http", return_value={"count": 0}):
            self.assertTrue(integrations.test("audit", {})["ok"])

    def test_invalid_form_values_rejected(self):
        """test() validates the form like save(): a bad URL, index or key raises ValueError before any request.
        REQ: SET-13"""
        with mock.patch.object(integrations, "_http") as h:
            for sec, body in (("elasticsearch", {"url": "ftp://x.example.com", "api_key": FAKE_KEY}),
                              ("elasticsearch", {"api_key": FAKE_KEY, "indices": {"zeek": "a b"}}),
                              ("unifi", {"url": "nope", "api_key": FAKE_KEY}),
                              ("audit", {"index": "a,b", "api_key": FAKE_KEY}),
                              ("audit", {"api_key": "bad key"})):
                with self.subTest(sec=sec, body=body), self.assertRaises(ValueError):
                    integrations.test(sec, body)
            with self.assertRaises(ValueError):
                integrations.test("nope", {})
            h.assert_not_called()


class AuditSwitchesEndToEnd(_Base):
    """The Audit log page switches, flipped with integrations.save, decide what audit.emit queues."""

    PERSON = "alice"

    def setUp(self):
        super().setUp()
        self._status = dict(audit.STATUS)
        audit.STATUS.pop("skipped", None)
        self._ring = list(reviewlog.RING)
        reviewlog.RING.clear()
        self.sent = []
        self.put = mock.patch.object(audit._q, "put_nowait", side_effect=self.sent.append)
        self.put.start()

    def tearDown(self):
        self.put.stop()
        audit.STATUS.clear()
        audit.STATUS.update(self._status)
        reviewlog.RING.clear()
        reviewlog.RING.extend(self._ring)
        super().tearDown()

    def emit_all(self):
        """One entry from every mapped background actor plus user actions; returns the user names queued."""
        self.sent.clear()
        for name in audit.ACTORS:
            audit.emit({"user": {"name": name}, "message": "bg"})
        audit.llm("chat", "local", "m", user="netmon (event reviewer)", prompt="p", response="r")
        audit.llm("research", "local", "m", user="netmon (event research)", prompt="p", response="r")
        audit.action(self.PERSON, "settings.save", method="POST", path="/api/x")
        audit.llm("chat", "local", "m", user=self.PERSON, prompt="p", response="r")
        audit.emit({"user": {"name": "netmon"}, "message": "plain system entry"})
        return [d["user"]["name"] for d in self.sent]

    def test_actor_map(self):
        """audit.ACTORS maps every background actor to the reviewer or researcher switch as documented.
        REQ: SET-14"""
        self.assertEqual(audit.ACTORS, {
            "netmon (event reviewer)": "reviewer", "netmon (background reviewer)": "reviewer", "netmon (review job)": "reviewer",
            "netmon (review log)": "reviewer", "netmon (event research)": "researcher", "netmon (research job)": "researcher"})
        self.assertEqual(audit.ACTORS[reviewlog.ACTOR], "reviewer")

    def test_both_on_sends_everything(self):
        """With both switches on (the default) every entry is queued and nothing is skipped.
        REQ: SET-14"""
        names = self.emit_all()
        self.assertEqual(len(names), len(audit.ACTORS) + 5)
        self.assertEqual(audit.STATUS.get("skipped", 0), 0)

    def test_reviewer_off(self):
        """Switching reviewer events off drops the four reviewer actors' entries, counts them as skipped, and keeps researcher and user entries.
        REQ: SET-14"""
        integrations.save("audit", {"send_reviewer": False}, "admin")
        names = self.emit_all()
        rev = [n for n, w in audit.ACTORS.items() if w == "reviewer"]
        self.assertFalse(set(rev) & set(names))
        self.assertEqual(audit.STATUS["skipped"], len(rev) + 1)
        self.assertIn("netmon (event research)", names)
        self.assertIn("netmon (research job)", names)
        self.assertEqual(names.count(self.PERSON), 2)
        self.assertIn("netmon", names)

    def test_researcher_off(self):
        """Switching researcher events off drops event research and research job entries only, counted as skipped.
        REQ: SET-14"""
        integrations.save("audit", {"send_researcher": False}, "admin")
        names = self.emit_all()
        self.assertNotIn("netmon (event research)", names)
        self.assertNotIn("netmon (research job)", names)
        self.assertEqual(audit.STATUS["skipped"], 3)
        for n in ("netmon (event reviewer)", "netmon (background reviewer)", "netmon (review job)", "netmon (review log)"):
            self.assertIn(n, names)
        self.assertEqual(names.count(self.PERSON), 2)

    def test_both_off_never_drops_people(self):
        """With both switches off only user actions (and other non-mapped entries) are queued; switching back on resumes sending.
        REQ: SET-14"""
        integrations.save("audit", {"send_reviewer": False, "send_researcher": False}, "admin")
        names = self.emit_all()
        self.assertEqual(sorted(names), sorted([self.PERSON, self.PERSON, "netmon"]))
        self.assertEqual(audit.STATUS["skipped"], len(audit.ACTORS) + 2)
        with mock.patch.object(audit, "_es", side_effect=RuntimeError("no ES in tests")):
            st = audit.status()
        self.assertEqual((st["send_reviewer"], st["send_researcher"], st["skipped"]), (False, False, len(audit.ACTORS) + 2))
        integrations.save("audit", {"send_reviewer": True, "send_researcher": True}, "admin")
        self.assertEqual(len(self.emit_all()), len(audit.ACTORS) + 5)

    def test_review_log_entries_follow_reviewer_switch(self):
        """A correlation review pass is queued while the reviewer switch is on and only kept in memory while it is off.
        REQ: SET-14"""
        now = time.time()
        reviewlog.correlation_pass(now - 2, now - 1, {"decided_this_run": 1, "events_this_run": 1}, 1)
        self.assertEqual([d["user"]["name"] for d in self.sent], [reviewlog.ACTOR])
        integrations.save("audit", {"send_reviewer": False}, "admin")
        self.sent.clear()
        reviewlog.correlation_pass(now - 1, now, {"decided_this_run": 2, "events_this_run": 2}, 2)
        self.assertEqual(self.sent, [])
        self.assertEqual(len(reviewlog.RING), 2)
        self.assertEqual(audit.STATUS["skipped"], 1)

    def test_review_log_view_source(self):
        """The Review log card reads Elasticsearch while the reviewer switch is on and reports 'memory (audit log sending off)' when it is off.
        REQ: SET-15"""
        now = time.time()
        reviewlog.correlation_pass(now - 1, now, {"decided_this_run": 1, "events_this_run": 1}, 1)
        with mock.patch.object(audit, "review_entries", return_value=([], 0)) as re_:
            v = reviewlog.view(24)
        re_.assert_called_once()
        self.assertEqual((v["source"], v["total"]), ("elasticsearch", 0))
        integrations.save("audit", {"send_reviewer": False}, "admin")
        with mock.patch.object(audit, "review_entries", side_effect=AssertionError("must not query ES")) as re_:
            v = reviewlog.view(24)
        re_.assert_not_called()
        self.assertEqual(v["source"], "memory (audit log sending off)")
        self.assertEqual((v["total"], v["error"]), (1, ""))
        self.assertEqual(v["summary"]["correlation"]["entries"], 1)
        integrations.save("audit", {"send_reviewer": True, "send_researcher": False}, "admin")  # researcher switch is irrelevant here
        with mock.patch.object(audit, "review_entries", return_value=([], 0)):
            self.assertEqual(reviewlog.view(24)["source"], "elasticsearch")


if __name__ == "__main__":
    unittest.main()
