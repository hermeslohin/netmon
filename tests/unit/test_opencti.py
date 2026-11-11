"""Unit tests for the OpenCTI integration: integrations.py (opencti section) and opencti.py."""
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); import _env  # noqa: E401,E402

import json  # noqa: E402
import shutil  # noqa: E402
import sqlite3  # noqa: E402
import tempfile  # noqa: E402
import time  # noqa: E402
import unittest  # noqa: E402
from unittest import mock  # noqa: E402

import extras  # noqa: E402
import integrations  # noqa: E402
import opencti  # noqa: E402
import store  # noqa: E402

FAKE_TOKEN = "x" * 12 + "abcd"  # placeholder, not a credential
CFG = {**integrations.OPENCTI_DEFAULTS, "url": "https://octi.example", "api_key": FAKE_TOKEN, "enabled": True, "usable": True}


def _reset():
    _env.fresh_db()
    integrations._cache["k"] = None


class FakeClient:
    """Records GraphQL calls; answers the queries opencti.py makes."""

    def __init__(self, existing_sighting=None, indicator="ind-1"):
        self.calls, self.existing, self.indicator = [], existing_sighting, indicator

    def q(self, query, variables=None, timeout=60):
        self.calls.append((query, variables))
        if "identities(" in query:
            return {"identities": {"edges": [{"node": {"id": "ident-1"}}]}}
        if "indicators(first:1" in query:
            return {"indicators": {"edges": [{"node": {"id": self.indicator}}] if self.indicator else []}}
        if "stixSightingRelationships(" in query:
            return {"stixSightingRelationships": {"edges": [{"node": self.existing}] if self.existing else []}}
        if "incidentAdd" in query:
            return {"incidentAdd": {"id": "inc-%d" % len(self.calls)}}
        if "stixCyberObservableAdd" in query:
            return {"stixCyberObservableAdd": {"id": "obs-%d" % len(self.calls)}}
        return {}

    def identity(self, name):
        return "ident-1"

    def mutations(self, word):
        return [v for q, v in self.calls if word in q]


class TestSettings(unittest.TestCase):
    def setUp(self):
        _reset()

    tearDown = setUp

    def test_validation_and_masking(self):
        """Bad scores, confidence, severity, URL and CA are rejected; the token is masked and kept when left blank.
        REQ: OCTI-01
        """
        bad = [{"url": "ftp://x"}, {"url": "https://x", "min_score": 101}, {"url": "https://x", "incident_min_conf": 0.2},
               {"url": "https://x", "incident_min_sev": "nope"}, {"url": "https://x", "ca_pem": "not a cert"}, {"enabled": True, "url": ""}]
        for b in bad:
            with self.assertRaises(ValueError, msg=b):
                integrations.save("opencti", b, "admin")
        integrations.save("opencti", {"url": "https://octi.example/", "api_key": FAKE_TOKEN, "enabled": True, "min_score": 40}, "admin")
        p = integrations.public()["opencti"]
        self.assertTrue(p["key_set"])
        self.assertEqual(p["key_hint"], "••••abcd")
        self.assertNotIn(FAKE_TOKEN, json.dumps(p))
        integrations.save("opencti", {"url": "https://octi.example", "api_key": ""}, "admin")  # blank keeps the token
        o = integrations.opencti()
        self.assertEqual((o["url"], o["api_key"], o["min_score"], o["usable"]), ("https://octi.example", FAKE_TOKEN, 40, True))

    def test_not_usable_without_enable_or_token(self):
        """Disabled, or without a token, the integration is not usable and run() does nothing.
        REQ: OCTI-01
        """
        self.assertFalse(integrations.opencti()["usable"])
        integrations.save("opencti", {"url": "https://octi.example", "enabled": True}, "admin")
        self.assertFalse(integrations.opencti()["usable"])
        tmp = tempfile.mkdtemp()
        try:  # run() removes the lists when disabled: never against the live intel/ directory
            with mock.patch.object(opencti, "INTEL", tmp), mock.patch.object(opencti, "Client", side_effect=AssertionError("must not connect")):
                self.assertEqual(opencti.run(), {"enabled": False})
        finally:
            shutil.rmtree(tmp, True)


class TestIndicators(unittest.TestCase):
    def setUp(self):
        _reset()
        self.tmp = tempfile.mkdtemp()
        self.p = [mock.patch.object(opencti, "INTEL", self.tmp), mock.patch.object(extras, "INTEL", self.tmp)]
        for x in self.p:
            x.start()

    def tearDown(self):
        for x in self.p:
            x.stop()
        shutil.rmtree(self.tmp, True)
        _reset()

    def test_parse_pattern(self):
        """Only single-value IP / domain / hostname patterns are used; private addresses and compound patterns are not.
        REQ: OCTI-02
        """
        self.assertEqual(opencti.parse_pattern("[ipv4-addr:value = '45.33.32.9']"), ("ips", "45.33.32.9"))
        self.assertEqual(opencti.parse_pattern("[domain-name:value = 'Evil.Example.']"), ("hosts", "evil.example"))
        self.assertEqual(opencti.parse_pattern("[hostname:value = 'c2.bad.example']"), ("hosts", "c2.bad.example"))
        for p in ("[ipv4-addr:value = '10.1.2.3']", "[ipv4-addr:value = '198.51.100.0/24']", "[url:value = 'https://github.com/x/a.exe']",
                  "[file:hashes.'SHA-256' = 'ab']", "[domain-name:value = 'a.example'] OR [domain-name:value = 'b.example']", "[domain-name:value = 'localhost']"):
            self.assertIsNone(opencti.parse_pattern(p), p)

    def test_merge_and_feed_files(self):
        """Revoked, expired and low-score indicators drop out; high scores land in the SERIOUS lists that load_feeds matches.
        REQ: OCTI-02
        """
        nodes = [{"pattern": "[ipv4-addr:value = '45.33.32.9']", "x_opencti_score": 90, "updated_at": "2026-01-02"},
                 {"pattern": "[domain-name:value = 'bad.example']", "x_opencti_score": 60, "updated_at": "2026-01-03"},
                 {"pattern": "[ipv4-addr:value = '45.33.32.10']", "x_opencti_score": 20, "updated_at": "2026-01-01"},
                 {"pattern": "[ipv4-addr:value = '45.33.32.11']", "x_opencti_score": 70, "valid_until": "2000-01-01T00:00:00Z"}]
        e, newest = opencti.merge({"45.33.32.10": ("ips", 60, "")}, nodes, 50)
        self.assertEqual(newest, "2026-01-03")
        self.assertEqual(e, {"45.33.32.9": ("ips", 90, ""), "bad.example": ("hosts", 60, "")})
        opencti.merge(e, [{"pattern": "[domain-name:value = 'bad.example']", "x_opencti_score": 60, "revoked": True}], 50)
        self.assertNotIn("bad.example", e)
        e["bad.example"] = ("hosts", 60, "AlienVault | vidar")
        opencti.write_local(e, 80)
        self.assertEqual(opencti.read_local(), e)
        f = extras.load_feeds()
        self.assertEqual(extras.match_ip("45.33.32.9", f), ["opencti_high_ips"])
        self.assertIn("opencti_high_ips", extras.SERIOUS)
        self.assertEqual(extras.match_domain("www.bad.example", f), ("bad.example", ["opencti_hosts"]))

    def test_disabled_removes_lists(self):
        """Switched off, one run removes the local lists.
        REQ: OCTI-03
        """
        opencti.write_local({"45.33.32.9": ("ips", 90, "")}, 80)
        self.assertEqual(store.ti_local_status()["opencti_high_ips"][0], 1)
        open(os.path.join(self.tmp, "opencti_ips.txt"), "w").write("1.2.3.4\n")  # pre-SQLite leftover
        opencti.run()
        self.assertEqual(store.ti_local_status(), {})
        self.assertEqual(extras.local_lists(), {})
        self.assertFalse(any(n.startswith("opencti_") for n in os.listdir(self.tmp)))

    def test_list_names_are_bound_not_spliced(self):
        """Reading or clearing named lists binds the names as data (json_each), so a hostile name cannot change the SQL.
        REQ: OCTI-02
        """
        store.ti_local_write({"a": ("ips", [("1.2.3.4", 90, "")]), "b": ("hosts", [("x.example", 60, "")])})
        evil = "a') OR 1=1 --"
        self.assertEqual(store.ti_local_read([evil]), {})
        self.assertEqual(store.ti_local_read(["a"]), {"a": [("1.2.3.4", 90, "")]})
        store.ti_local_clear([evil])
        self.assertEqual(set(store.ti_local_status()), {"a", "b"})
        store.ti_local_clear(["a"])
        self.assertEqual(set(store.ti_local_status()), {"b"})

    def test_lists_live_in_sqlite(self):
        """The OpenCTI lists are rows in the store (table ti_local), never files; a pull drops pre-SQLite files.
        REQ: OCTI-02
        """
        open(os.path.join(self.tmp, "opencti_hosts.txt"), "w").write("0.0.0.0 old.example\n")
        sizes = opencti.write_local({"45.33.32.9": ("ips", 90, "ThreatFox # c2\nx"), "bad.example": ("hosts", 60, "")}, 80)
        self.assertEqual((sizes["opencti_high_ips"], sizes["opencti_hosts"], sizes["opencti_ips"]), (1, 1, 0))
        self.assertEqual(os.listdir(self.tmp), [])
        rows = store.connect().execute("SELECT list, value, kind, score, meta FROM ti_local ORDER BY value").fetchall()
        self.assertEqual([tuple(r) for r in rows], [("opencti_high_ips", "45.33.32.9", "ips", 90, "ThreatFox # c2 x"), ("opencti_hosts", "bad.example", "hosts", 60, "")])
        self.assertEqual(set(store.ti_local_status()), set(opencti.LISTS))
        self.assertTrue(opencti.have_local())
        self.assertEqual(extras.match_domain("a.bad.example", extras.load_feeds()), ("bad.example", ["opencti_hosts"]))

    def test_pull_full_then_incremental(self):
        """The first pull is a full one filtered server-side; the next (after an hour) only asks for updated indicators.
        REQ: OCTI-02
        """
        seen = []

        def fake_fetch(cli, since=None, min_score=0):
            seen.append(since)
            return [{"pattern": "[ipv4-addr:value = '45.33.32.9']", "x_opencti_score": 90, "updated_at": "2026-01-02T00:00:00Z"}]
        st = {}
        with mock.patch.object(opencti, "fetch_indicators", fake_fetch), mock.patch.object(opencti, "fetch_samples", lambda cli, since=None: []), \
                mock.patch.object(opencti, "fetch_feed_ips", lambda cli, ms, since=None: []):
            r = opencti.pull(None, CFG, st)
            self.assertTrue(r["full"])
            self.assertIsNone(opencti.pull(None, CFG, st))  # not due yet
            st["last_pull_ts"] -= 3700
            r = opencti.pull(None, CFG, st)
        self.assertFalse(r["full"])
        self.assertEqual(seen, [None, "2026-01-02T00:00:00Z"])
        self.assertEqual(st["indicators"], 1)


    def test_hashes_names_and_samples(self):
        """File-hash and file-name patterns are pulled; generic names and junk hashes are not; malware samples add every
        hash (SERIOUS) and their specific names; matching is case-insensitive.
        REQ: OCTI-06
        """
        sha = "248ded4723e9f5da793e5e42d1ba7c2293dd704718f149b84b3b9b818a1f51db"
        self.assertEqual(opencti.parse_pattern(f"[file:hashes.'SHA-256' = '{sha.upper()}']"), ("hashes", sha))
        self.assertEqual(opencti.parse_pattern("[file:hashes.MD5 = '19483ddf132d2839ff65f0c05f6d6d8a']"), ("hashes", "19483ddf132d2839ff65f0c05f6d6d8a"))
        self.assertEqual(opencti.parse_pattern("[file:name = 'Wave-executer.exe']"), ("filenames", "Wave-executer.exe"))
        for p in ("[file:name = 'setup.exe']", "[file:name = 'a.js']", "[file:hashes.MD5 = '00000000000000000000000000000000']",
                  f"[file:name = '{sha}.exe']"):
            self.assertIsNone(opencti.parse_pattern(p), p)
        e, _ = opencti.merge({}, [{"pattern": f"[file:hashes.'SHA-256' = '{sha}']", "x_opencti_score": 50,
                                   "createdBy": {"name": "AlienVault"}, "objectLabel": [{"value": "vidar"}]}], 50)
        e, _ = opencti.merge_samples(e, [{"entity_type": "Artifact", "hashes": [{"algorithm": "MD5", "hash": "ACB04F4CBF1965BCA5F4BA2E9565FC9C"},
                                                                               {"algorithm": "SHA-256", "hash": "853f51dcb039588ee4b606b131da01658a52cd7f642a5a37237db909c8b14ca0"}],
                                          "x_opencti_additional_names": ["NanoInvoice-2026.exe", "setup.exe"], "objectLabel": [{"value": "nanocore"}]}])
        self.assertEqual(e[sha][:2], ("hashes", 50))
        self.assertEqual(e["acb04f4cbf1965bca5f4ba2e9565fc9c"][:2], ("hashes", 90))
        self.assertIn("NanoInvoice-2026.exe", e)
        self.assertNotIn("setup.exe", e)
        opencti.write_local(e, 80)
        self.assertEqual(opencti.read_local(), e)
        f = extras.load_feeds()
        self.assertEqual(extras.match_hash(sha.upper(), f), ["opencti_hashes"])
        self.assertIn("opencti_hashes", extras.SERIOUS)
        self.assertEqual(extras.match_filename("C:\\Users\\x\\nanoinvoice-2026.EXE", f), ["opencti_high_filenames"])
        self.assertEqual(extras.match_filename("setup.exe", f), [])

    def test_reviewer_hits(self):
        """intelmatch finds hits on an event's IPs, domains, file names and hashes, with the OpenCTI score and labels,
        serious first, and changes the review signature only when there are hits.
        REQ: OCTI-07
        """
        import intelmatch
        sha = "853f51dcb039588ee4b606b131da01658a52cd7f642a5a37237db909c8b14ca0"
        opencti.write_local({"45.33.32.9": ("ips", 90, "ThreatFox | cobalt strike"), "bad.example": ("hosts", 60, "AlienVault | vidar"),
                             sha: ("hashes", 90, "MalwareBazaar | nanocore, rat"), "NanoInvoice-2026.exe": ("filenames", 60, "MalwareBazaar")}, 80)
        with mock.patch.object(intelmatch.extras, "INTEL", self.tmp):
            intelmatch._cache["sig"] = None
            ev = {"arts": [["dns", "cdn.bad.example", "domain in event"], ["file", "/home/u/Downloads/NanoInvoice-2026.exe", "file mentioned"],
                           ["hash", sha.upper(), "sha256 of the file"], ["process", "/usr/bin/curl", "process"]],
                  "ips": ["10.0.0.5", "45.33.32.9"]}
            hs = intelmatch.hits(ev)
            self.assertEqual([h["kind"] for h in hs][:2], ["hash", "ip"])  # serious + highest score first
            self.assertEqual({h["kind"] for h in hs}, {"hash", "ip", "dns", "file"})
            ln = intelmatch.lines(ev)
            self.assertTrue(any("nanocore" in x and "opencti_hashes" in x for x in ln), ln)
            self.assertTrue(any(x.startswith("dns=cdn.bad.example (matched bad.example)") for x in ln), ln)
            self.assertTrue(any("weak on its own" in x for x in ln), ln)
            self.assertTrue(intelmatch.sig(ev))
            self.assertEqual(intelmatch.sig({"arts": [["dns", "good.example", ""]], "ips": ["10.0.0.5"]}), "")


class TestReporting(unittest.TestCase):
    def setUp(self):
        _reset()
        integrations.save("opencti", {"url": "https://octi.example", "api_key": FAKE_TOKEN, "enabled": True, "incidents": True}, "admin")

    tearDown = setUp

    def test_sightings_create_then_bump(self):
        """A new hit creates a sighting; an existing one has its count added and last_seen moved. Non-OpenCTI hits are ignored.
        REQ: OCTI-04
        """
        fc = FakeClient()
        hits = [{"value": "bad.example", "feeds": ["opencti_hosts"], "count": 3, "sources": ["laptop"]},
                {"value": "bad.example", "feeds": ["opencti_hosts"], "count": 2, "sources": ["phone"]},
                {"value": "45.33.32.5", "feeds": ["feodo_ips"], "count": 9}]
        with mock.patch.object(opencti, "Client", return_value=fc):
            r = opencti.report_sightings(hits)
        self.assertEqual((r["sent"], r["created"]), (1, 1))
        add = fc.mutations("stixSightingRelationshipAdd")[0]["i"]
        self.assertEqual((add["fromId"], add["toId"], add["attribute_count"]), ("ind-1", "ident-1", 5))
        fc2 = FakeClient(existing_sighting={"id": "s-1", "attribute_count": 7})
        with mock.patch.object(opencti, "Client", return_value=fc2):
            r = opencti.report_sightings(hits[:1])
        self.assertEqual(r["updated"], 1)
        edit = fc2.mutations("stixSightingRelationshipEdit")[0]
        self.assertEqual(edit["i"][0], {"key": "attribute_count", "value": ["10"]})

    def test_sighting_failure_never_raises(self):
        """An unreachable OpenCTI is recorded as last_error; the watcher carries on.
        REQ: OCTI-04
        """
        boom = mock.Mock(side_effect=OSError("down"))
        with mock.patch.object(opencti, "Client", boom):
            r = opencti.report_sightings([{"value": "bad.example", "feeds": ["opencti_hosts"], "count": 1}])
        self.assertEqual(r["sent"], 0)
        self.assertIn("down", (store.jload(opencti.STATE, {}) or {}).get("last_error", ""))

    def _events(self, rows, classes):
        with store.connect() as c:
            c.executescript("""CREATE TABLE IF NOT EXISTS events (eid TEXT PRIMARY KEY, type TEXT NOT NULL, label TEXT NOT NULL DEFAULT '',
              sev TEXT DEFAULT '', link TEXT DEFAULT '', t0 REAL, t1 REAL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, last_sid TEXT,
              n INTEGER NOT NULL DEFAULT 1, resolved INTEGER NOT NULL DEFAULT 0, doc TEXT NOT NULL DEFAULT '{}')""")
            c.execute("DELETE FROM events")
            for r in rows:
                c.execute("INSERT INTO events (eid,type,label,sev,first_seen,last_seen,n,resolved,doc) VALUES (?,?,?,?,?,?,?,?,?)", r)
        db = os.path.join(os.path.dirname(opencti.STATE), "corr_llm.db")
        k = sqlite3.connect(db)
        k.execute("CREATE TABLE IF NOT EXISTS event_class (eid TEXT PRIMARY KEY, label TEXT, confidence REAL, reason TEXT, model TEXT, sig TEXT, ts REAL)")
        k.execute("DELETE FROM event_class")
        k.executemany("INSERT INTO event_class (eid,label,confidence,reason) VALUES (?,?,?,?)", classes)
        k.commit()
        k.close()

    def test_incidents_filter_and_observables(self):
        """Only suspicious, confident, severe enough open events become incidents, once; only public IPs/domains are attached.
        REQ: OCTI-05
        """
        now = time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime())
        doc = json.dumps({"ips": ["10.0.0.5"], "host_ips": ["45.33.32.50"], "arts": [["dns", "c2.bad.example", ""], ["dns", "nas.lan", ""]]})
        self._events([("gw|1", "gw", "Gateway threat", "high", now, now, 3, 0, doc),
                      ("gw|2", "gw", "low one", "low", now, now, 1, 0, "{}"),
                      ("gw|3", "gw", "benign one", "urgent", now, now, 1, 0, "{}"),
                      ("gw|4", "gw", "unsure", "urgent", now, now, 1, 0, "{}"),
                      ("gw|5", "gw", "closed", "urgent", now, now, 1, 1, "{}"),
                      ("gw|6", "gw", "old", "urgent", "2020-01-01T00:00:00+00:00", "2020-01-01T00:00:00+00:00", 1, 0, "{}")],
                     [("gw|1", "suspicious", 0.9, "bad"), ("gw|2", "suspicious", 0.99, "x"), ("gw|3", "benign", 0.99, "x"),
                      ("gw|4", "suspicious", 0.6, "x"), ("gw|5", "suspicious", 0.99, "x"), ("gw|6", "suspicious", 0.99, "x")])
        cfg, fc, st = integrations.opencti(), FakeClient(), {}
        r = opencti.report_incidents(fc, cfg, st, "ident-1")
        self.assertEqual(r, {"created": 1, "updated": 0})
        inc = fc.mutations("incidentAdd")[0]["i"]
        self.assertEqual((inc["severity"], inc["confidence"], inc["createdBy"]), ("high", 90, "ident-1"))
        obs = [v["v"]["value"] for v in fc.mutations("stixCyberObservableAdd")]
        self.assertEqual(sorted(obs), ["45.33.32.50", "c2.bad.example"])
        self.assertEqual(len(fc.mutations("stixCoreRelationshipAdd")), 2)
        r = opencti.report_incidents(FakeClient(), cfg, st, "ident-1")  # same event again: nothing new
        self.assertEqual(r, {"created": 0, "updated": 0})


if __name__ == "__main__":
    unittest.main()


class TestIpOnlyHitsAreWeak(unittest.TestCase):
    def setUp(self):
        _reset()
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, True)
        _reset()

    def test_ip_only_hits_are_weak(self):
        """IP-only hits are weak (CDN addresses weaker still); a big provider's own host is never listed; look-alikes stay.
        REQ: OCTI-10
        """
        import intelmatch
        sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "dashboard", "app"))
        import corr_llm
        self.assertIsNone(opencti.parse_pattern("[domain-name:value = 'login.microsoftonline.com']"))
        self.assertIsNone(opencti.url_host("https://login.microsoftonline.com/common/oauth2"))
        self.assertEqual(opencti.parse_pattern("[domain-name:value = 'teams.microsoftonline-sharepoint.online']"),
                         ("hosts", "teams.microsoftonline-sharepoint.online"))
        self.assertTrue(extras.is_cdn("Cloudflare London, LLC") and extras.is_cdn("WPEngine, Inc."))
        self.assertFalse(extras.is_cdn("Hetzner Online GmbH") or extras.is_cdn(""))
        opencti.write_local({"141.193.213.10": ("ips", 60, "Phishunt | phishing"), "bad.example": ("hosts", 60, "AlienVault")}, 80)
        with mock.patch.object(intelmatch.extras, "INTEL", self.tmp):
            intelmatch._cache["sig"] = None
            ip_only = {"arts": [], "ips": ["141.193.213.10"]}
            self.assertTrue(any("NOT suspicious on its own" in x for x in intelmatch.lines(ip_only)), intelmatch.lines(ip_only))
            self.assertFalse(intelmatch.strong(ip_only))
            self.assertTrue(intelmatch.strong({"arts": [["dns", "x.bad.example", ""]], "ips": ["141.193.213.10"]}))
        self.assertIn("IP-only hit is NOT evidence of harm", corr_llm.EVENT_SYSTEM)
        self.assertIn("IP-only hit is NOT suspicious", corr_llm.CLASS_SYSTEM)
