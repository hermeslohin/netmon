"""Configurable threat-intel feeds (extras.feed_list / apply_feed_config, integrations section 'feeds') and the
file-hash / file-name artifacts and watcher checks."""
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); import _env  # noqa: E401,E402

import ast  # noqa: E402
import shutil  # noqa: E402
import tempfile  # noqa: E402
import unittest  # noqa: E402
from unittest import mock  # noqa: E402

import extras  # noqa: E402
import integrations  # noqa: E402
import opencti  # noqa: E402

SHA = "853f51dcb039588ee4b606b131da01658a52cd7f642a5a37237db909c8b14ca0"


def _reset():
    _env.fresh_db()
    integrations._cache["k"] = None


class TestFeedConfig(unittest.TestCase):
    def setUp(self):
        _reset()
        self.tmp = tempfile.mkdtemp()
        self.p = mock.patch.object(extras, "INTEL", self.tmp)
        self.p.start()

    def tearDown(self):
        self.p.stop()
        shutil.rmtree(self.tmp, True)
        _reset()

    def test_validation(self):
        """Built-ins cannot be deleted; custom feeds need a good name, URL and type.
        REQ: FEED-01
        """
        for b in ({"delete": ["feodo_ips"]}, {"items": [{"name": "Bad Name", "url": "https://x.example/l", "kind": "ips"}]},
                  {"items": [{"name": "opencti_x", "url": "https://x.example/l", "kind": "ips"}]},
                  {"items": [{"name": "mylist", "url": "ftp://x.example/l", "kind": "ips"}]},
                  {"items": [{"name": "mylist", "url": "https://x.example/l", "kind": "nope"}]},
                  {"items": [{"name": "mylist", "url": "", "kind": "ips"}]}):
            with self.assertRaises(ValueError, msg=b):
                integrations.save("feeds", b, "admin")

    def test_toggle_url_custom_and_opencti_cover(self):
        """Turning off, re-pointing, adding and the OpenCTI cover all show in feed_list / ACTIVE / SERIOUS.
        REQ: FEED-01
        """
        integrations.save("feeds", {"items": [{"name": "cins_badguys", "enabled": False},
                                              {"name": "feodo_ips", "url": "https://mirror.example/feodo.txt", "enabled": True, "serious": True},
                                              {"name": "my_doms", "url": "https://x.example/d.txt", "kind": "hosts", "serious": True}]}, "admin")
        fl = {f["name"]: f for f in extras.apply_feed_config()}
        self.assertEqual(fl["cins_badguys"]["inactive_why"], "turned off")
        self.assertEqual(extras.ACTIVE["feodo_ips"][0], "https://mirror.example/feodo.txt")
        self.assertIn("my_doms", extras.ACTIVE)
        self.assertIn("my_doms", extras.SERIOUS)
        self.assertNotIn("cins_badguys", extras.ACTIVE)
        self.assertIn("urlhaus_hosts", extras.ACTIVE)  # OpenCTI off: covered feeds still run
        integrations.save("opencti", {"url": "https://octi.example", "api_key": "x" * 16, "enabled": True}, "admin")
        fl = {f["name"]: f for f in extras.apply_feed_config()}
        self.assertEqual(fl["urlhaus_hosts"]["inactive_why"], "covered by OpenCTI")
        self.assertNotIn("urlhaus_hosts", extras.ACTIVE)
        integrations.save("feeds", {"delete": ["my_doms"]}, "admin")
        self.assertNotIn("my_doms", {f["name"] for f in extras.feed_list()})
        p = integrations.public()["feeds"]
        self.assertIn("hosts", p["kinds"])

    def test_inactive_not_loaded_and_url_change_refetches(self):
        """An inactive feed's file is ignored; bare-domain lists parse; a new URL is fetched although the file is fresh.
        REQ: FEED-02
        """
        open(os.path.join(self.tmp, "cins_badguys.txt"), "w").write("45.33.32.1\n")
        integrations.save("feeds", {"items": [{"name": "cins_badguys", "enabled": False},
                                              {"name": "my_doms", "url": "https://x.example/d.txt", "kind": "hosts"}]}, "admin")
        open(os.path.join(self.tmp, "my_doms.txt"), "w").write("# netmon-source: https://x.example/d.txt\nbad.example\n0.0.0.0 worse.example\nlocalhost\n")
        f = extras.load_feeds()
        self.assertEqual(extras.match_ip("45.33.32.1", f), [])
        self.assertEqual(extras.match_domain("a.bad.example", f), ("bad.example", ["my_doms"]))
        self.assertEqual(extras.match_domain("worse.example", f)[1], ["my_doms"])
        self.assertNotIn("localhost", f["hosts"])
        got = []

        class R:
            def __init__(self, u):
                got.append(u)

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self, n=-1):
                return b"new.example\n" * 20
        with mock.patch.object(extras, "ACTIVE", {}), mock.patch.object(extras.urllib.request, "urlopen", lambda req, timeout=60: R(req.full_url)):
            extras.refresh_feeds(max_age_h=12)
            got_first = [u for u in got if "x.example" in u]
            self.assertEqual(got_first, [])  # fresh, same URL: not fetched
            integrations.save("feeds", {"items": [{"name": "my_doms", "url": "https://y.example/d.txt", "kind": "hosts"}]}, "admin")
            extras.refresh_feeds(max_age_h=12)
        self.assertIn("https://y.example/d.txt", got)
        self.assertTrue(open(os.path.join(self.tmp, "my_doms.txt")).read().startswith("# netmon-source: https://y.example/d.txt"))
        self.assertEqual(extras.count_feed("a.example\n10.0.0.1\n", "hosts"), 1)
        import tintel
        tintel._cache["sig"] = None
        with mock.patch.object(tintel.extras, "INTEL", self.tmp):
            rows = {r["feed"]: r for r in tintel.feed_status()}
        self.assertEqual(rows["my_doms"]["entries"], 1)
        self.assertEqual((rows["cins_badguys"]["active"], rows["cins_badguys"]["entries"]), (False, 0))
        self.assertTrue(all({"entries", "serious", "url", "age_h"} <= set(r) for r in rows.values()))


class TestFileArtifacts(unittest.TestCase):
    def setUp(self):
        _reset()
        self.tmp = tempfile.mkdtemp()
        self.p = [mock.patch.object(extras, "INTEL", self.tmp), mock.patch.object(opencti, "INTEL", self.tmp)]
        for x in self.p:
            x.start()
        import intelmatch
        intelmatch._cache["sig"] = None
        opencti.write_local({SHA: ("hashes", 90, "MalwareBazaar | nanocore"), "evil-test.com": ("hosts", 60, ""),
                             "NanoInvoice-2026.exe": ("filenames", 85, "")}, 80)

    def tearDown(self):
        for x in self.p:
            x.stop()
        shutil.rmtree(self.tmp, True)
        _reset()

    def test_artifacts_hash_ip_filename_marked(self):
        """artifacts_of reads hashes, bare file names and external IPs, and marks listed ones.
        REQ: OCTI-08
        """
        import correlate
        a = correlate.artifacts_of(f"pc1 ran NanoInvoice-2026.exe md5 x sha256: {SHA.upper()} then talked to 45.33.32.7, 10.0.0.9 and evil-test.com")
        k = {(x[0], x[1]): x[2] for x in a}
        self.assertIn("listed in opencti_hashes", k[("hash", SHA)])
        self.assertIn("listed in opencti_high_filenames", k[("file", "NanoInvoice-2026.exe")])
        self.assertIn(("ip", "45.33.32.7"), k)
        self.assertNotIn(("ip", "10.0.0.9"), k)
        self.assertIn("listed in opencti_hosts", k[("dns", "evil-test.com")])
        import kb
        self.assertTrue(kb.valid_art("hash", SHA) and kb.valid_art("file", "payload.scr"))
        self.assertFalse(kb.valid_art("hash", "0" * 64))

    def test_sighting_target_falls_back_to_observable(self):
        """No indicator: the sighting points at the observable that carries the hash.
        REQ: OCTI-09
        """
        calls = []

        class C:
            def q(self, query, variables=None, timeout=60):
                calls.append((query, variables))
                if "indicators(" in query:
                    return {"indicators": {"edges": []}}
                return {"stixCyberObservables": {"edges": [{"node": {"id": "obs-9"}}]}}
        self.assertEqual(opencti._find_indicator(C(), SHA.upper()), "obs-9")
        self.assertIn("hashes.SHA-256", str(calls[-1][1]))
        self.assertIsNone(opencti._find_indicator(C(), "zz"))

    def test_watcher_file_intel(self):
        """The watcher's file check alerts on a listed hash seen by Zeek or Defend and records an OpenCTI hit.
        REQ: OCTI-09
        """
        src = open(os.path.join(_env.REPO if hasattr(_env, "REPO") else os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "watch.py")).read()
        fn = [n for n in ast.parse(src).body if isinstance(n, ast.FunctionDef) and n.name == "file_intel"][0]

        def q(idx, body):
            agg = next(iter(body["aggs"]))
            flt = body["query"]["bool"]["filter"]
            terms = next((x["terms"] for x in flt if "terms" in x), {})
            if "process.hash.sha256" in terms:
                return {"aggregations": {agg: {"buckets": [{"key": SHA, "doc_count": 2, "host": {"buckets": [{"key": "pc1", "doc_count": 2}]},
                                                             "exe": {"buckets": [{"key": "C:\\\\x\\\\a.exe"}]}}]}}}
            return {"aggregations": {agg: {"buckets": []}}}
        g = {"q": q, "ds": lambda d: {"term": {"event.dataset": d}}, "buckets": lambda a: a.get("buckets", []), "extras": extras, "os": os,
             "sys": sys, "SITE": mock.Mock(is_internal=lambda ip: ip.startswith("10.")), "R": {}, "feeds": extras.load_feeds(),
             "nm": lambda x: x, "octi_hits": [], "alerts": []}
        g["alert"] = lambda k, t: g["alerts"].append((k, t))
        exec(compile(ast.Module([fn], []), "watch.py", "exec"), g)  # noqa: S102 - the watcher's own function, under test
        g["file_intel"]()
        self.assertEqual(len(g["alerts"]), 1)
        self.assertIn("pc1 ran C:\\\\x\\\\a.exe", g["alerts"][0][1])
        self.assertIn("nanocore", g["alerts"][0][1])
        self.assertEqual(g["octi_hits"][0]["value"], SHA)


if __name__ == "__main__":
    unittest.main()
