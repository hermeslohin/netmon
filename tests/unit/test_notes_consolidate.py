"""Unit tests for dashboard/app/notes_consolidate.py: nightly merge of AI-written host notes (AI review > Host note consolidation)."""
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); import _env  # noqa: E401,E402

import datetime as dt  # noqa: E402
import json  # noqa: E402
import unittest  # noqa: E402
from unittest import mock  # noqa: E402

import corr_llm  # noqa: E402
import kb  # noqa: E402
import notes_consolidate as NC  # noqa: E402

SUBJ = {"ip": "10.9.9.9"}


def _notes():
    with kb._db() as c:
        return [dict(zip(("id", "category", "text", "author", "via", "status"), r))
                for r in c.execute("SELECT id, category, text, author, via, status FROM host_notes WHERE subject='ip:10.9.9.9' ORDER BY id")]


class Consolidate(unittest.TestCase):
    def setUp(self):
        with NC._db() as c:
            c.execute("DELETE FROM host_notes")
            c.execute("DELETE FROM note_artifacts")
            c.execute("DELETE FROM consolidate_subjects")
        self.a = kb.add_host_note(SUBJ, "[reviewer:dns:x.example.com] Expected dns x.example.com: update check. Seen in a correlation between 'a' and 'b'. "
                                  "Event reviewer judgement (m1), unverified; delete if wrong.", "behavior", author="ai", model="m1", via="event reviewer")
        self.b = kb.add_host_note(SUBJ, "[reviewer:ip:192.0.2.7] Expected ip 192.0.2.7: x.example.com update service on 443/tcp. Event reviewer judgement (m1), unverified.",
                                  "behavior", author="ai", model="m1", via="event reviewer")
        self.p = kb.add_host_note(SUBJ, "Owner says this is the NAS.", "role", author="user:dan", via="dashboard")
        self.t = {"provider": "lmstudio", "model": "test-model"}

    def _answer(self, groups):
        return mock.patch.object(corr_llm, "_complete", return_value=(json.dumps({"notes": groups}), {}, 0.1))

    def test_merge_keeps_tags_and_facts_and_leaves_person_notes(self):
        """Two overlapping AI notes become one that keeps both [reviewer:] tags and every identifier; the person's note is untouched.
        REQ: STO-09
        """
        with self._answer([{"from": [self.a, self.b], "category": "behavior",
                            "text": "Update check: x.example.com resolves to 192.0.2.7, reached on 443/tcp. Unverified."}]):
            r = NC.consolidate_subject("ip:10.9.9.9", self.t)
        ns = _notes()
        self.assertEqual((r["before"], r["after"], r["merged"]), (2, 1, 1))
        merged = next(n for n in ns if n["via"] == NC.VIA)
        self.assertEqual(merged["id"], min(self.a, self.b))
        self.assertTrue(merged["text"].startswith("[reviewer:dns:x.example.com] [reviewer:ip:192.0.2.7] "))
        self.assertTrue(any(n["id"] == self.p and n["text"] == "Owner says this is the NAS." for n in ns))

    def test_merge_that_drops_an_identifier_is_rejected(self):
        """A merge missing an IP is retried once naming it; if it is still missing, the notes stay as they were.
        REQ: STO-09
        """
        before = _notes()
        with self._answer([{"from": [self.a, self.b], "category": "behavior", "text": "Update check to x.example.com on 443/tcp."}]):
            r = NC.consolidate_subject("ip:10.9.9.9", self.t)
        self.assertEqual(r["rejected"], 1)
        self.assertEqual(_notes(), before)

    def test_bad_ids_and_person_notes_are_ignored(self):
        """Groups naming a person's note, an unknown id or reusing an id are dropped.
        REQ: STO-09
        """
        before = _notes()
        with self._answer([{"from": [self.a, self.p], "category": "role", "text": "x"}, {"from": [999999], "category": "role", "text": "y"}]):
            NC.consolidate_subject("ip:10.9.9.9", self.t)
        self.assertEqual(_notes(), before)

    def test_unchanged_subject_is_skipped_next_time(self):
        """After a pass, a host whose notes did not change is not sent again (unless --all).
        REQ: STO-09
        """
        with self._answer([{"from": [self.a], "category": "behavior", "text": "x.example.com update check. Unverified."},
                           {"from": [self.b], "category": "behavior", "text": "192.0.2.7 on 443/tcp. Unverified."}]):
            NC.consolidate_subject("ip:10.9.9.9", self.t)
        self.assertNotIn("ip:10.9.9.9", NC._todo())
        self.assertIn("ip:10.9.9.9", NC._todo(full=True))

    def test_reviewer_does_not_overwrite_a_consolidated_note(self):
        """kb.tagged_slot: the event reviewer updates its own one-tag note, skips a merged note carrying the tag, adds a new one otherwise.
        REQ: STO-09
        """
        ns = [{"id": 1, "text": "[reviewer:dns:a.com] [reviewer:ip:1.2.3.4] merged"}, {"id": 2, "text": "[reviewer:dns:b.com] own"}]
        self.assertEqual(kb.tagged_slot(ns, "[reviewer:dns:b.com]"), ("update", 2))
        self.assertEqual(kb.tagged_slot(ns, "[reviewer:dns:a.com]"), ("skip", None))
        self.assertEqual(kb.tagged_slot(ns, "[reviewer:dns:a.com]", "suspicious"), ("add", None))
        self.assertEqual(kb.tagged_slot(ns, "[reviewer:dns:c.com]"), ("add", None))

    def test_notes_about_different_artifacts_are_not_merged(self):
        """Two notes that share no artifact (a DNS name and an unrelated IP) stay separate even if the model merges them.
        REQ: STO-11
        """
        c1 = kb.add_host_note(SUBJ, "[reviewer:dns:y.example.org] Expected dns y.example.org: telemetry. Unverified.", "behavior", author="ai", via="event reviewer")
        c2 = kb.add_host_note(SUBJ, "[reviewer:process:/usr/bin/pasta.avx2] Expected process /usr/bin/pasta.avx2: port forwarder. Unverified.",
                              "behavior", author="ai", via="event reviewer")
        before = _notes()
        with self._answer([{"from": [c1, c2], "category": "behavior",
                            "text": "/usr/bin/pasta.avx2 contacts y.example.org for telemetry. Unverified."}]):
            r = NC.consolidate_subject("ip:10.9.9.9", self.t)
        self.assertEqual(_notes(), before)
        self.assertGreaterEqual(r["rejected"], 1)

    def test_merge_that_adds_an_identifier_is_rejected(self):
        """A merged text naming an IP / domain that none of its notes had is not written.
        REQ: STO-11
        """
        before = _notes()
        with self._answer([{"from": [self.a, self.b], "category": "behavior",
                            "text": "x.example.com update check at 192.0.2.7 on 443/tcp, also reached via 198.51.100.9. Unverified."}]):
            r = NC.consolidate_subject("ip:10.9.9.9", self.t)
        self.assertEqual(_notes(), before)
        self.assertGreaterEqual(r["rejected"], 1)

    def test_malformed_tags_are_dropped_and_never_indexed(self):
        """[reviewer:ip:25565] / [reviewer:dns:25565] are not artifacts: not indexed, and not carried into a merged note.
        REQ: STO-11
        """
        self.assertEqual(kb.artifact_keys("[reviewer:ip:25565] [reviewer:dns:25565] [reviewer:process:443/tcp]"), {"port:25565", "port:443"} & kb.artifact_keys("[reviewer:ip:25565] [reviewer:dns:25565] [reviewer:process:443/tcp]"))
        self.assertFalse(kb.valid_art("ip", "25565"))
        self.assertFalse(kb.valid_art("dns", "LivingRoomTV"))
        self.assertFalse(kb.valid_art("process", "8.8.8.8"))
        self.assertFalse(kb.valid_art("process", "SSH"))
        self.assertFalse(kb.valid_art("process", "8220/tcp"))
        self.assertFalse(kb.valid_art("user", "10.20.30.40"))
        self.assertTrue(kb.valid_art("process", "chrome.exe"))
        for proto in ("dns", "icmp", "ssl", "http", "spicy_stun", "ssh/publickey"):
            self.assertFalse(kb.valid_art("process", proto), proto)
        self.assertFalse(kb.valid_art("user", "THREAT_BLOCKED_V3"))
        self.assertTrue(kb.valid_art("file", "app/static/app.js"))
        self.assertTrue(kb.valid_art("process", "/usr/bin/python3.12"))
        self.assertTrue(kb.valid_art("dns", "doh.dns.apple.com"))
        x = kb.add_host_note(SUBJ, "[reviewer:dns:x.example.com] [reviewer:ip:25565] x.example.com also on 25565/tcp. Unverified.", "behavior", author="ai", via="event reviewer")
        with self._answer([{"from": [self.a, x], "category": "behavior", "text": "x.example.com update check, also on 25565/tcp. Unverified."}]):
            NC.consolidate_subject("ip:10.9.9.9", self.t)
        merged = next(n for n in _notes() if n["via"] == NC.VIA)
        self.assertIn("[reviewer:dns:x.example.com]", merged["text"])
        self.assertNotIn("[reviewer:ip:25565]", merged["text"])

    def test_other_host_notes_match_only_on_shared_ip_or_dns(self):
        """A note on another host about its own process does not attach to an event that runs the same process name elsewhere.
        REQ: COR-05
        """
        kb.add_host_note({"ip": "10.8.8.8"}, "[reviewer:process:/usr/bin/python3.12] Expected process /usr/bin/python3.12 here. Unverified.", "behavior", author="ai")
        d = kb.add_host_note({"ip": "10.8.8.8"}, "[reviewer:dns:x.example.com] Expected dns x.example.com here. Unverified.", "behavior", author="ai")
        got = kb.notes_by_artifacts({"proc:python3.12", "dns:x.example.com"}, exclude_ids={self.a, self.b})
        self.assertEqual([n["id"] for _s, _h, n in got], [d])

    def test_reviewer_artifact_owner_is_the_single_source_host(self):
        """art_owners: a process belongs to the event's single source host; an artifact in no event, or an event with several
        source hosts, gets no owner (no note is written).
        REQ: COR-05
        """
        a = {"label": "x", "host_ips": ["10.0.2.20"], "dst_ips": ["10.0.1.10"], "ips": ["10.0.1.10", "10.0.2.20"], "arts": [["process", "/usr/bin/pasta.avx2", ""]]}
        b = {"label": "y", "host_ips": ["10.0.1.10", "10.0.3.3"], "ips": ["10.0.1.10", "10.0.3.3"], "arts": [["process", "/usr/bin/curl", ""]]}
        self.assertEqual(corr_llm.art_owners("process", "/usr/bin/pasta.avx2", (a, b)), ["10.0.2.20"])
        self.assertEqual(corr_llm.art_owners("process", "/usr/bin/curl", (a, b)), [])
        self.assertEqual(corr_llm.art_owners("process", "/usr/bin/nc", (a, b)), [])
        self.assertEqual(corr_llm.clean_artifacts([{"kind": "ip", "value": "25565", "decision": "expected"},
                                                   {"kind": "dns", "value": "a.example.com", "decision": "expected"}])[0]["value"], "a.example.com")


class Schedule(unittest.TestCase):
    def test_settings_validation_and_due_window(self):
        """Time must be HH:MM and the zone known; the run is due inside 3 h after the local time, once per day.
        REQ: STO-09
        """
        with self.assertRaises(ValueError):
            NC.set_cfg("t", at_time="25:00")
        with self.assertRaises(ValueError):
            NC.set_cfg("t", tz="Mars/Base")
        NC.set_cfg("t", enabled=True, at_time="03:00", tz="UTC")
        NC._meta("last_scheduled_day", "")
        at = dt.datetime(2026, 1, 5, 3, 30, tzinfo=dt.timezone.utc).timestamp()
        self.assertEqual(NC.due(at), "2026-01-05")
        self.assertIsNone(NC.due(at - 3600))
        self.assertIsNone(NC.due(at + 4 * 3600))
        NC._meta("last_scheduled_day", "2026-01-05")
        self.assertIsNone(NC.due(at))
        NC.set_cfg("t", enabled=False)
        self.assertIsNone(NC.due(at + 86400))


if __name__ == "__main__":
    unittest.main()
