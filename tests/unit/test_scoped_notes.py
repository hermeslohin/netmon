"""Unit tests for dashboard/app/kb.py wider-scope internet notes: parent-domain notes cover subdomains, CIDR-range notes cover addresses."""
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); import _env  # noqa: E401,E402

import unittest  # noqa: E402

import kb  # noqa: E402


class ScopedNotes(unittest.TestCase):
    def setUp(self):
        with kb._db() as c:
            c.execute("DELETE FROM host_notes")
            c.execute("DELETE FROM note_artifacts")

    def test_wildcard_domain_note_covers_subdomains(self):
        """A note added as *.example.com is stored on dom:example.com and applies to a.b.example.com, not to other domains.
        REQ: STO-13
        """
        nid = kb.add_host_note({"subject": "dom:*.example.com"}, "Vendor update CDN.", author="user:dan")
        with kb._db() as c:
            self.assertEqual(c.execute("SELECT subject FROM host_notes WHERE id=?", (nid,)).fetchone()[0], "dom:example.com")
        hits = kb.dns_notes_for(["a.b.example.com"])
        self.assertEqual([(d, ex) for _n, d, _nt, ex in hits], [("example.com", False)])
        self.assertEqual(kb.dns_notes_for(["example.org"]), [])

    def test_cidr_note_covers_addresses_in_range(self):
        """A net:<cidr> note applies to every address in the range (narrowest first), never outside it; host bits are cleared.
        REQ: STO-13
        """
        kb.add_host_note({"subject": "net:203.0.113.77/24"}, "Hoster A range.", author="user:dan")
        kb.add_host_note({"ip": "203.0.0.0/16"}, "Hoster A supernet.", author="user:dan")
        kb.add_host_note({"ip": "203.0.113.9"}, "Their API host.", author="user:dan")
        got = [(r, n["text"]) for r, n in kb.ip_notes_for("203.0.113.9")]
        self.assertEqual(got, [("", "Their API host."), ("203.0.113.0/24", "Hoster A range."), ("203.0.0.0/16", "Hoster A supernet.")])
        self.assertEqual(kb.ip_notes_for("198.51.100.1"), [])
        self.assertIn("203.0.113.0/24", [r["ip"] for r in kb.internet_notes() if r["range"]])

    def test_cidr_validation(self):
        """Too-wide or malformed ranges are refused; a /32 is stored as a plain IP note.
        REQ: STO-13
        """
        with self.assertRaises(ValueError):
            kb.resolve(subject="net:10.0.0.0/4")
        with self.assertRaises(ValueError):
            kb.resolve(subject="net:not-a-range/24")
        self.assertEqual(kb.resolve(subject="net:198.51.100.5/32")[0], "ip:198.51.100.5")


if __name__ == "__main__":
    unittest.main()
