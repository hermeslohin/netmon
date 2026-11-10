"""hosts.as_of / first-seen minutes: a time range collected after the review job still reports the first-seen host
findings that happened in it (the review job has already added them to the host baseline)."""
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); import _env  # noqa: E401,E402

import time  # noqa: E402
import unittest  # noqa: E402
from unittest import mock  # noqa: E402

import hosts  # noqa: E402


def _data(exe):
    return {"processes": {"execs": {"host-a": {exe: {"count": 1, "users": ["u"], "parents": ["/usr/bin/bash"], "sha256": "ab" * 32}}},
                          "suspicious": []}}


class TestBaselineAsOf(unittest.TestCase):
    def setUp(self):
        _env.fresh_db()

    def test_range_after_review_still_reports_new_executable(self):
        """The review job learns a new executable (stamped with its minute on a seasoned host); a range starting before
        that minute still lists exec-new, a range starting after it does not, and old day-only entries stay known.
        REQ: POS-21"""
        base = {"_meta": {"seeded": "2020-01-01"}, "host-a": {"_first": "2020-01-01", "exec": {"/usr/bin/ls": "2020-01-01"}}}
        with mock.patch.object(hosts, "load_base", lambda: base), mock.patch("store.hosts_save", lambda b: None):
            hosts.update_baseline(_data("/usr/bin/newtool"))
        st = base["host-a"]["exec"]["/usr/bin/newtool"]
        self.assertRegex(st, r"^\d{4}-\d\d-\d\dT\d\d:\d\dZ$")
        keys = lambda b: [k for k, _, _ in hosts.findings(_data("/usr/bin/newtool"), b) if k.startswith("exec-new")]  # noqa: E731
        self.assertEqual(keys(base), [])  # the live baseline knows it
        before = time.strftime("%Y-%m-%dT%H:%M", time.gmtime(time.time() - 3600))
        self.assertEqual(keys(hosts.as_of(base, before)), ["exec-new|host-a|/usr/bin/newtool"])
        after = time.strftime("%Y-%m-%dT%H:%M", time.gmtime(time.time() + 120))
        self.assertEqual(keys(hosts.as_of(base, after)), [])
        self.assertIn("/usr/bin/ls", hosts.as_of(base, before)["host-a"]["exec"])  # day-only entries are kept

    def test_seeding_host_keeps_day_stamps(self):
        """A host still being seeded (first seen today) gets day stamps, so a later range does not flood it with 'new'.
        REQ: POS-21"""
        today = time.strftime("%Y-%m-%d")
        base = {"_meta": {"seeded": "2020-01-01"}, "host-a": {"_first": today, "exec": {}}}
        with mock.patch.object(hosts, "load_base", lambda: base), mock.patch("store.hosts_save", lambda b: None):
            hosts.update_baseline(_data("/usr/bin/newtool"))
        self.assertEqual(base["host-a"]["exec"]["/usr/bin/newtool"], today)


if __name__ == "__main__":
    unittest.main()
