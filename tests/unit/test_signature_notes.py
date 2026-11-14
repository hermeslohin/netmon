"""Security > Event notes: kb.signature_notes groups people's event notes by IDS signature, kb.update_event_note edits them."""
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); import _env  # noqa: E401,E402

import unittest  # noqa: E402

import kb  # noqa: E402

SIG = "ET INFO Observed Cloudflare Tunneling Domain (argotunnel .com in TLS SNI)"


class SignatureNotes(unittest.TestCase):
    """Notes tied to IDS signatures, and editing them."""

    def setUp(self):
        with kb._db() as c:
            c.execute("DELETE FROM event_notes")

    tearDown = setUp

    def test_notes_grouped_by_signature(self):
        """A note counts for an IDS signature via its ids| event, a sig: verdict scope or a quoted signature in its label.
        REQ: STO-17
        """
        a = kb.add_event_note("ids|" + SIG, "Cloudflare tunnels.", "dan")
        b = kb.add_event_note("hf|net-new|h1|/usr/bin/x|1.2.3.4", "", "dan", verdict="expected", scope=["sig:ET SCAN Nmap", "ip:10.0.0.5"])
        c = kb.add_event_note("alert|1", "seen before", "dan", label="host alert 'ET POLICY Curl User Agent' x3")
        got = {(g["type"], g["sig"]): [n["id"] for n in g["notes"]] for g in kb.signature_notes()}
        self.assertEqual(got[("ids", SIG)], [a])
        self.assertEqual(got[("ids", "ET SCAN Nmap")], [b])
        self.assertEqual(got[("ids", "ET POLICY Curl User Agent")], [c])
        self.assertEqual(kb.signature_notes()[0]["sig"], "ET POLICY Curl User Agent")  # newest note first
        self.assertEqual(kb.signature_notes(author="someone-else"), [])

    def test_every_note_has_a_signature(self):
        """Notes on detections other than IDS are listed under their detection kind (e.g. newly-registered-domain), host finding,
        threat-intel direction, admin service or alert title, so no note is left out.
        REQ: STO-17
        """
        ids = {
            ("finding", "newly-registered-domain"): kb.add_event_note("f|newly-registered-domain|aa|quail.example registered 2026-10-20", "", "dan", verdict="benign"),
            ("host", "agent-off"): kb.add_event_note("hf|agent-off|Mac", "laptop asleep", "dan"),
            ("ti", "inbound from a listed IP"): kb.add_event_note("ti|in|45.79.218.244", "minecraft players", "dan"),
            ("admin", "SSH"): kb.add_event_note("adm|10.0.0.1|10.0.0.2|SSH", "jump host", "dan"),
            ("alert", "Host notice"): kb.add_event_note("alert|9", "ok", "dan", label="Host notice: minecraft accepted a connection"),
            ("event", "weird"): kb.add_event_note("weird", "ok", "dan"),
        }
        x = kb.add_event_note("hf|net-new|h1|/usr/bin/x|1.2.3.4", "", "dan", verdict="expected", scope=["find:beacon-new"])
        got = {(g["type"], g["sig"]): [n["id"] for n in g["notes"]] for g in kb.signature_notes()}
        for k, nid in ids.items():
            self.assertEqual(got[k], [nid], k)
        self.assertEqual((got[("host", "net-new")], got[("finding", "beacon-new")]), ([x], [x]))
        self.assertEqual(set(sum(got.values(), [])), set(ids.values()) | {x})

    def test_note_select_lists_every_column(self):
        """The fixed event-note SELECT (no string-built SQL) names exactly the note columns, in order.
        REQ: STO-17
        """
        self.assertEqual(kb._ENOTE_SEL.split("SELECT ", 1)[1].split(" FROM", 1)[0], ", ".join(kb._ECOLS))

    def test_body_strips_verdict_boilerplate(self):
        """The editable text is the person's own words, without the ANALYST VERDICT prefix.
        REQ: STO-17
        """
        kb.add_event_note("ids|" + SIG, "our tunnel", "dan", verdict="expected", scope=["sig:" + SIG])
        n = kb.signature_notes()[0]["notes"][0]
        self.assertTrue(n["text"].startswith(kb.VERDICT_TAG))
        self.assertEqual(n["body"], "our tunnel")
        self.assertEqual(kb.note_body({"text": "plain note"}), "plain note")

    def test_defender_edit_changes_text_verdict_scope_and_keeps_status(self):
        """A defender's edit rewrites text, verdict and scope, rebuilds the verdict text, records the editor and keeps the status.
        REQ: STO-17
        """
        nid = kb.add_event_note("ids|" + SIG, "old", "dan", verdict="expected", scope=["sig:" + SIG, "ip:10.0.0.5"])
        n = kb.update_event_note(nid, "new reason", "ann", role="defender", verdict="benign", scope=["sig:" + SIG, "bogus:x"])
        self.assertEqual((n["verdict"], n["scope"], n["status"], n["edited_by"]), ("benign", ["sig:" + SIG], "approved", "ann"))
        self.assertTrue(n["text"].startswith(kb.VERDICT_TAG + "BENIGN (set by ann"))
        self.assertTrue(n["text"].endswith("new reason"))
        self.assertIsNotNone(n["edited_at"])
        n = kb.update_event_note(nid, "now plain", "ann", role="admin", verdict="")
        self.assertEqual((n["verdict"], n["scope"], n["text"]), ("", [], "now plain"))
        n = kb.update_event_note(nid, "keep verdict", "ann", role="admin", verdict="suspicious", scope=["ip:10.0.0.5"])
        self.assertEqual((n["verdict"], n["scope"]), ("suspicious", []))  # scope only for expected / benign

    def test_user_edits_only_own_note_and_goes_back_to_pending(self):
        """A User cannot edit someone else's note; their own edited note is pending again with the review cleared.
        REQ: STO-17
        """
        theirs = kb.add_event_note("ids|" + SIG, "admin note", "dan")
        mine = kb.add_event_note("ids|" + SIG, "my note", "bob", role="user")
        kb.review_event_note(mine, True, "dan")
        self.assertIsNone(kb.update_event_note(theirs, "hijack", "bob", role="user", author="bob"))
        self.assertEqual(kb.event_note(theirs)["text"], "admin note")
        n = kb.update_event_note(mine, "my edited note", "bob", role="user", author="bob")
        self.assertEqual((n["status"], n["reviewed_by"], n["text"]), ("pending", None, "my edited note"))

    def test_edit_validation(self):
        """Empty text without a verdict, an unknown verdict or a bad id are refused; a missing note returns None.
        REQ: STO-17
        """
        nid = kb.add_event_note("ids|" + SIG, "x", "dan")
        for args in ((nid, "  ", "dan"), (nid, "t", "dan", "admin", "maybe"), ("abc", "t", "dan")):
            with self.assertRaises(ValueError):
                kb.update_event_note(*args)
        self.assertIsNone(kb.update_event_note(nid + 999, "t", "dan"))
        self.assertTrue(kb.update_event_note(nid, "", "dan", verdict="suspicious")["text"].startswith(kb.VERDICT_TAG))


if __name__ == "__main__":
    unittest.main()
