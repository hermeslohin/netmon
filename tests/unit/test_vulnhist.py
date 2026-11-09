"""vulnhist.py: daily vulnerability counts (Fix list, CIS, image CVEs) and the series the line charts read."""
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); import _env  # noqa: E401,E402

import sqlite3  # noqa: E402
import unittest  # noqa: E402
from unittest import mock  # noqa: E402

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
import scheduler  # noqa: E402
import vulnhist  # noqa: E402

IMG = {"images": [
    {"clusters": ["a", "b"], "current": {"vulns": [{"id": "CVE-1", "severity": "CRITICAL", "fixed": "2"}, {"id": "CVE-2", "severity": "LOW", "fixed": ""},
                                                   {"id": "CVE-9", "severity": "UNKNOWN"}]}},
    {"clusters": ["a"], "current": {"vulns": [{"id": "CVE-1", "severity": "HIGH", "fixed": ""}, {"id": "CVE-3", "severity": "MEDIUM", "fixed": "1"}]}}]}


def db():
    c = sqlite3.connect(":memory:", isolation_level=None)
    return vulnhist.init(c)


class VulnHistTest(unittest.TestCase):
    def test_cve_counts_distinct_per_cluster(self):
        """A CVE in several images counts once per cluster at its highest severity; UNKNOWN is left out.
        REQ: KUBE-13"""
        out = vulnhist.cve_counts(IMG)
        self.assertEqual(out["a"], {"critical": 1, "high": 0, "medium": 1, "low": 1, "total": 3, "fixable": 2, "images": 2})
        self.assertEqual(out["b"], {"critical": 1, "high": 0, "medium": 0, "low": 1, "total": 2, "fixable": 1, "images": 1})

    def test_record_replaces_same_day_and_series_sums_clusters(self):
        """A second record the same day replaces that day's rows; the k8s series sums clusters unless one is picked.
        REQ: KUBE-13"""
        c = db()
        with mock.patch.object(vulnhist, "fixlist_counts", return_value={"total": 5, "high": 5}), \
             mock.patch.object(vulnhist, "cis_counts", return_value={"a": {"fail": 3, "pass": 1}, "b": {"fail": 2, "pass": 4}}), \
             mock.patch.object(vulnhist, "cve_counts", return_value={"a": {"total": 10}, "b": {"total": 1}}):
            vulnhist.record("2026-11-01", c)
        with mock.patch.object(vulnhist, "fixlist_counts", return_value={"total": 4, "high": 4}), \
             mock.patch.object(vulnhist, "cis_counts", return_value={"a": {"fail": 1, "pass": 3}}), \
             mock.patch.object(vulnhist, "cve_counts", side_effect=RuntimeError("no scan")):
            r = vulnhist.record("2026-11-01", c)
        self.assertIn("k8s_cve", r["errors"])
        with mock.patch.object(vulnhist.dt, "datetime", wraps=vulnhist.dt.datetime) as d:
            d.now.return_value = vulnhist.dt.datetime(2026, 11, 2, tzinfo=vulnhist.dt.timezone.utc)
            f = vulnhist.series("fixlist", c=c)
            k = vulnhist.series("k8s", c=c)
            ka = vulnhist.series("k8s", "a", c=c)
        self.assertEqual((f["days"], f["series"]["total"], f["src"]), (["2026-11-01"], [4], ["daily"]))
        self.assertEqual(k["cis"]["fail"], [1])          # cluster b's CIS rows were replaced by the re-run
        self.assertEqual(k["cve"]["total"], [11])       # the failed CVE part kept the earlier rows
        self.assertEqual(ka["cve"]["total"], [10])
        self.assertEqual(k["clusters"], ["a", "b"])

    def test_backfill_never_overwrites_daily(self):
        """Backfill fills only days without rows and marks them 'backfill'; a gap in the days is a null, not a zero.
        REQ: KUBE-13"""
        c = db()
        c.execute("CREATE TABLE fix_run (sid TEXT, generated TEXT, full INTEGER)")
        c.execute("CREATE TABLE fix_item (sid TEXT, key TEXT, severity TEXT)")
        c.executemany("INSERT INTO fix_run VALUES (?,?,?)", [("r1", "2026-10-01T05:00:00", 1), ("r2", "2026-10-02T05:00:00", 1)])
        c.executemany("INSERT INTO fix_item VALUES (?,?,?)", [("r1", "k8s-cis|a|5.2.2", "medium"), ("r1", "k8s-cis|a|error", "medium"),
                                                              ("r2", "k8s-cis|a|5.2.2", "medium"), ("r2", "k8s-cis|a|5.1.1", "medium")])
        vulnhist._put(c, "2026-10-02", "fixlist", {"total": 99}, "daily")
        with mock.patch.object(vulnhist, "_fixlist_as_of", side_effect=lambda sid: {"critical": 0, "high": 1, "medium": 2, "low": 0, "info": 0}):
            n = vulnhist.backfill(c)
        self.assertEqual(n, {"fixlist": 1, "k8s_cis": 2})
        rows = {(d, s, m): (v, src) for d, s, m, v, src in c.execute("SELECT day, scope, metric, value, src FROM vuln_hist")}
        self.assertEqual(rows[("2026-10-01", "fixlist", "total")], (3, "backfill"))
        self.assertEqual(rows[("2026-10-02", "fixlist", "total")], (99, "daily"))
        self.assertEqual(rows[("2026-10-01", "k8s_cis|a", "fail")], (1, "backfill"))  # the |error item is not a failed check
        self.assertEqual(rows[("2026-10-02", "k8s_cis|a", "fail")], (2, "backfill"))

    def test_scheduler_runs_it_daily(self):
        """The scheduler has a daily vulnhist job (vulnhist.py record).
        REQ: KUBE-13"""
        self.assertEqual(scheduler.JOBS["vulnhist"][1:], [os.path.join(scheduler.NM, "vulnhist.py"), "record"])


if __name__ == "__main__":
    unittest.main()
