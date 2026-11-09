import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); import _env  # noqa: E401,E402
"""Host note expiry: a note carries its creation date and the date it was last used; an AI reading it for an event or host,
or a person editing / reviewing it, restarts the clock, and a note unused for the configured days (default 30) is deleted."""
import time  # noqa: E402
import unittest  # noqa: E402

import corr_llm  # noqa: E402
import kb  # noqa: E402

DAY = 86400


class NoteExpiryTest(unittest.TestCase):
    """Unused host notes expire after the configured number of days."""

    def setUp(self):
        corr_llm._save_config({})
        with kb._db() as c:
            c.execute("DELETE FROM note_artifacts")
            c.execute("DELETE FROM host_notes")

    def _age(self, nid, days):
        with kb._db() as c:
            c.execute("UPDATE host_notes SET last_used=? WHERE id=?", (time.time() - days * DAY, nid))

    def test_new_note_is_dated_and_shows_expiry(self):
        """A new note gets its creation date and last-used date, and listings show when it expires (default 30 days).
        REQ: STO-15"""
        t0 = time.time()
        nid = kb.add_host_note({"ip": "192.0.2.10"}, "test box", "role", author="user:alice")
        n = kb.host_notes(["ip:192.0.2.10"])[0]
        self.assertEqual(n["id"], nid)
        self.assertGreaterEqual(n["ts"], t0)
        self.assertGreaterEqual(n["last_used"], t0)
        self.assertAlmostEqual(n["expires"], n["last_used"] + 30 * DAY, delta=1)
        self.assertEqual(kb.expire_days(), 30)

    def test_ai_read_resets_the_clock_but_listing_does_not(self):
        """An AI read for specific hosts (and an artifact match) restarts the clock; a dashboard listing or full dump does not.
        REQ: STO-15"""
        nid = kb.add_host_note({"ip": "192.0.2.11"}, "talks to 192.0.2.99 nightly", "baseline", author="ai")
        self._age(nid, 20)
        kb.host_notes(["ip:192.0.2.11"])  # dashboard page (ai=False)
        kb.host_notes(ai=True)  # full listing
        kb.dump()
        old = kb.host_notes(["ip:192.0.2.11"])[0]["last_used"]
        self.assertLess(old, time.time() - 19 * DAY)
        kb.notes_by_artifacts(["ip:192.0.2.99"], use=False)  # a person viewing alerts
        self.assertEqual(kb.host_notes(["ip:192.0.2.11"])[0]["last_used"], old)
        n = kb.host_notes(["ip:192.0.2.11"], ai=True)[0]  # handed to the reviewer for this host
        self.assertGreater(n["last_used"], time.time() - 5)
        self._age(nid, 20)
        kb.notes_by_artifacts(["ip:192.0.2.99"])
        self.assertGreater(kb.host_notes(["ip:192.0.2.11"])[0]["last_used"], time.time() - 5)

    def test_edit_and_review_reset_the_clock(self):
        """Editing or accepting / rejecting a note counts as using it.
        REQ: STO-15"""
        nid = kb.add_host_note({"ip": "192.0.2.12"}, "a", author="user:bob")
        self._age(nid, 25)
        kb.add_host_note({"ip": "192.0.2.12"}, "b", author="user:bob", note_id=nid)
        self.assertGreater(kb.host_notes(["ip:192.0.2.12"])[0]["last_used"], time.time() - 5)
        self._age(nid, 25)
        kb.review_host_note(nid, "approve", "carol")
        self.assertGreater(kb.host_notes(["ip:192.0.2.12"])[0]["last_used"], time.time() - 5)

    def test_purge_deletes_only_expired_notes(self):
        """Notes unused longer than the setting are deleted with their artifact index rows; 0 days turns expiry off.
        REQ: STO-15, SET-16"""
        old = kb.add_host_note({"ip": "192.0.2.13"}, "old note on 192.0.2.98", author="ai")
        new = kb.add_host_note({"ip": "192.0.2.13"}, "fresh note", author="ai")
        self._age(old, 31)
        self._age(new, 29)
        gone = kb.purge_expired()
        self.assertEqual([g[0] for g in gone], [old])
        self.assertEqual([n["id"] for n in kb.host_notes(["ip:192.0.2.13"])], [new])
        with kb._db() as c:
            self.assertEqual(c.execute("SELECT count(*) FROM note_artifacts WHERE note_id=?", (old,)).fetchone()[0], 0)
        corr_llm.set_notes_limit(None, "admin", expire_days=7)
        self.assertEqual([g[0] for g in kb.purge_expired()], [new])
        nid = kb.add_host_note({"ip": "192.0.2.14"}, "kept forever", author="ai")
        self._age(nid, 5000)
        corr_llm.set_notes_limit(None, "admin", expire_days=0)
        self.assertEqual(kb.purge_expired(), [])
        self.assertIsNone(kb.host_notes(["ip:192.0.2.14"])[0]["expires"])

    def test_setting_range_and_config_view(self):
        """Note expiry is 0-3650 days (default 30), saved with the user, shown in the AI pipeline config, refused out of range.
        REQ: SET-16"""
        cn = corr_llm.config()["context_notes"]
        self.assertEqual((cn["expire_days"], cn["expire_days_default"], cn["expire_days_limit"]), (30, 30, 3650))
        res = corr_llm.set_notes_limit(None, "admin", expire_days="45")
        self.assertEqual((res["expire_days"], res["by"], kb.expire_days()), (45, "admin", 45))
        for bad in (-1, 3651, "soon"):
            with self.assertRaises(ValueError, msg=bad):
                corr_llm.set_notes_limit(None, "evil", expire_days=bad)
        self.assertEqual(kb.expire_days(), 45)
        corr_llm._save_config({"context_notes": {"expire_days": 99999}})
        self.assertEqual(kb.expire_days(), 3650)
        corr_llm._save_config({"context_notes": {"expire_days": "x"}})
        self.assertEqual(kb.expire_days(), 30)


if __name__ == "__main__":
    unittest.main()
