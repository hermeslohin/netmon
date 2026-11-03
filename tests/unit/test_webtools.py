"""Unit tests for the web search integration: integrations.py (web section) and webtools.py Firecrawl (cloud / self-hosted)."""
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); import _env  # noqa: E401,E402

import unittest  # noqa: E402
from unittest import mock  # noqa: E402

import integrations  # noqa: E402
import webtools  # noqa: E402

FAKE_KEY = "x" * 12 + "abcd"  # placeholder, not a credential
OWN = "https://firecrawl.internal.example"


def _reset():
    _env.fresh_db()
    integrations._cache["k"] = None


class WebConfig(unittest.TestCase):
    def setUp(self):
        _reset()
        self.hs = mock.patch.object(integrations, "host_secret", lambda n: "hostkey" + "x" * 8 if n == "FIRECRAWL_API_KEY" else "")
        self.hs.start()

    def tearDown(self):
        self.hs.stop()

    def test_self_hosted_firecrawl_needs_no_key(self):
        """Firecrawl with its own URL is usable without a key, and the host (cloud) key is never sent to it.
        REQ: WEB-01"""
        integrations.save("web", {"provider": "firecrawl", "url": OWN}, "t")
        w = integrations.web()
        self.assertEqual((w["provider"], w["url"], w["api_key"]), ("firecrawl", OWN, ""))

    def test_cloud_firecrawl_uses_host_key(self):
        """Firecrawl without a URL is the cloud and falls back to the host secrets key.
        REQ: WEB-02"""
        integrations.save("web", {"provider": "firecrawl"}, "t")
        w = integrations.web()
        self.assertEqual((w["provider"], w["url"]), ("firecrawl", integrations.FIRECRAWL_DEFAULT))
        self.assertTrue(w["api_key"].startswith("hostkey"))

    def test_url_change_drops_saved_key(self):
        """a key saved for one Firecrawl instance is dropped when the URL changes without a new key.
        REQ: WEB-03"""
        integrations.save("web", {"provider": "firecrawl", "api_key": FAKE_KEY}, "t")
        integrations.save("web", {"provider": "firecrawl", "url": OWN}, "t")
        self.assertEqual(integrations.load()["web"]["api_key"], "")

    def test_bad_ca_and_url_refused(self):
        """an invalid CA or URL is refused; the CA is only used for a self-hosted instance.
        REQ: WEB-04"""
        with self.assertRaises(ValueError):
            integrations.save("web", {"provider": "firecrawl", "url": OWN, "ca_pem": "nope"}, "t")
        with self.assertRaises(ValueError):
            integrations.save("web", {"provider": "firecrawl", "url": "ftp://x"}, "t")
        self.assertEqual(integrations._web_eff({"provider": "firecrawl", "api_key": FAKE_KEY, "ca_pem": "pem"})["ca_pem"], "")
        self.assertFalse(integrations.public()["web"]["ca_set"])


class FirecrawlCalls(unittest.TestCase):
    CFG = {"provider": "firecrawl", "api_key": "", "url": OWN, "ca_pem": ""}

    def test_search_hits_configured_instance_without_auth(self):
        """search posts to <url>/v1/search, with no Authorization header when there is no key.
        REQ: WEB-05"""
        with mock.patch.object(webtools, "_post", return_value={"data": [{"url": "https://a.example", "title": "A", "description": "d"}]}) as p:
            r = webtools.search("q", 3, cfg=self.CFG)
        self.assertEqual(p.call_args.args[0], OWN + "/v1/search")
        self.assertEqual(p.call_args.args[2], {})
        self.assertEqual(r[0]["url"], "https://a.example")

    def test_fetch_refuses_private_redirect_target(self):
        """a page Firecrawl fetched after redirecting to a private address is refused.
        REQ: WEB-06"""
        def pub(u):
            if "10.0.0.5" in u:
                raise ValueError("non-public")
            return u
        with mock.patch.object(webtools, "_public", side_effect=pub), \
                mock.patch.object(webtools, "_post", return_value={"data": {"markdown": "secret", "metadata": {"url": "http://10.0.0.5/admin"}}}):
            with self.assertRaises(ValueError):
                webtools.fetch("https://public.example/r", cfg=self.CFG)
        with mock.patch.object(webtools, "_public", side_effect=pub), \
                mock.patch.object(webtools, "_post", return_value={"data": {"markdown": "hello", "metadata": {"title": "T"}}}) as p:
            r = webtools.fetch("https://public.example/", cfg={**self.CFG, "api_key": FAKE_KEY})
        self.assertEqual((r["text"], r["title"]), ("hello", "T"))
        self.assertEqual(p.call_args.args[0], OWN + "/v1/scrape")
        self.assertEqual(p.call_args.args[2], {"Authorization": f"Bearer {FAKE_KEY}"})


if __name__ == "__main__":
    unittest.main()
