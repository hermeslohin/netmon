"""Unit tests for DNS, TLS and IPs notes: TLS certificates are artifacts with notes, domain notes reach events about their
subdomains, cert artifacts are attached to events naming a server the certificate was presented for, and an entry whose
last note timed out is deleted."""
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); import _env  # noqa: E401,E402

import time  # noqa: E402
import unittest  # noqa: E402

import correlate  # noqa: E402
import kb  # noqa: E402

SHA = "ab" * 8 + "0123456789abcdef" * 3


class CertDnsNotes(unittest.TestCase):
    def setUp(self):
        with kb._db() as c:
            c.execute("DELETE FROM host_notes")
            c.execute("DELETE FROM note_artifacts")

    def test_cert_is_an_artifact_subject(self):
        """art:cert:<sha256> is a valid note subject (lower-cased); bad fingerprints are refused; cert_notes groups them.
        REQ: STO-13
        """
        self.assertEqual(kb.resolve(subject="art:cert:" + SHA.upper())[0], "art:cert:" + SHA)
        with self.assertRaises(ValueError):
            kb.resolve(subject="art:cert:1234")
        kb.add_host_note({"subject": "art:cert:" + SHA}, "Vendor update server certificate.", author="user:dan")
        self.assertEqual([(r["sha256"], r["n"]) for r in kb.cert_notes()], [(SHA, 1)])

    def test_cert_note_reaches_event_with_cert_artifact(self):
        """An event carrying the certificate as an artifact gets its note via notes_by_artifacts.
        REQ: STO-13
        """
        kb.add_host_note({"subject": "art:cert:" + SHA}, "Known appliance self-signed cert.", author="user:dan")
        keys = kb.event_artifact_keys({"arts": [["cert", SHA, "TLS certificate"]]})
        self.assertIn("cert:" + SHA, keys)
        hits = kb.notes_by_artifacts(keys, use=False)
        self.assertEqual([n["text"] for _s, _h, n in hits], ["Known appliance self-signed cert."])

    def test_parent_domain_note_reaches_subdomain_event(self):
        """A note on example.com reaches an event about a.b.example.com; a note merely mentioning example.com does not.
        REQ: STO-13
        """
        kb.add_host_note({"dom": "example.com"}, "Vendor CDN.", author="user:dan")
        kb.add_host_note({"ip": "198.51.100.7"}, "Talks to example.com sometimes.", author="user:dan")
        hits = kb.notes_by_artifacts({"dns:a.b.example.com"}, use=False)
        self.assertEqual([n["text"] for _s, _h, n in hits], ["Vendor CDN."])
        self.assertEqual(kb.notes_by_artifacts({"dns:example.org"}, use=False), [])

    def test_correlate_adds_cert_artifact(self):
        """build() gives an event that names a server the certificate was presented for that certificate as an artifact.
        REQ: STO-13
        """
        gen = correlate._ts("2026-11-09T00:00:00Z")
        raw = {"generated": "2026-11-09T00:00:00Z", "hours": 24, "devices": {},
               "tls": {"certs": [{"sha256": SHA, "subject": "CN=api.example.com", "san_dns": ["api.example.com"], "sni": ["api.example.com"]}]}}
        res = correlate.build(raw, None, [{"id": 1, "ts": gen - 600, "text": "beacon from 10.0.0.5 to api.example.com", "key": "beacon|x", "targets": [], "severity": "high"}],
                              [], [], lambda ip: ip.startswith("10."), lambda h: "", lambda s_, t: [])
        arts = [a for e in res["events"].values() for a in e["arts"]]
        self.assertIn(["cert", SHA], [a[:2] for a in arts])

    def test_entry_deleted_when_last_note_times_out(self):
        """When every note of an IP / domain / certificate has expired, the entry is gone from the lists.
        REQ: STO-13
        """
        old = time.time() - 400 * 86400
        for s in ("art:cert:" + SHA, "dom:example.com", "ip:198.51.100.7"):
            nid = kb.add_host_note({"subject": s}, "old note", author="ai")
            with kb._db() as c:
                c.execute("UPDATE host_notes SET ts=?, updated=?, last_used=? WHERE id=?", (old, old, old, nid))
        kb._purged["t"] = 0
        if not kb.expire_days():
            self.skipTest("expiry off")
        self.assertEqual(kb.cert_notes(), [])
        self.assertEqual(kb.dns_notes(), [])
        self.assertEqual(kb.internet_notes(), [])
        with kb._db() as c:
            self.assertEqual(c.execute("SELECT count(*) FROM host_notes").fetchone()[0], 0)
            self.assertEqual(c.execute("SELECT count(*) FROM note_artifacts").fetchone()[0], 0)


if __name__ == "__main__":
    unittest.main()
