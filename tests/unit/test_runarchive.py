"""Review-run documents are pipeline input only: run summaries (runarchive.py), pruning, the time-range-only page API
and the default window."""
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); import _env  # noqa: E401,E702,E402

import datetime as dt  # noqa: E402
import json  # noqa: E402
import unittest  # noqa: E402

import fixtures as F  # noqa: E402
import runarchive  # noqa: E402
import server  # noqa: E402
import store  # noqa: E402


def reset():
    _env.fresh_db()
    server._cache.clear()
    server._fseen.update(sig=None, val={})
    server._rsync.update(sig=None)
    server._issues.clear()
    server._issues.update(sig=None, val=None)


def seed(sid, **raw_kw):
    raw = F.raw_snapshot(sid)
    raw.update(raw_kw)
    store.jdump(raw, os.path.join(server.DATA, sid + ".json"))
    store.jdump(F.analysis(sid), os.path.join(server.DATA, sid + ".analysis.json"))
    store.jdump({"sources": []}, os.path.join(server.DATA, sid + ".sources.json"))
    server._cache.clear()
    return raw


def sids_on_disk():
    return [x["id"] for x in server.snapshots()]


class RunSummary(unittest.TestCase):
    def setUp(self):
        reset()

    def test_summary_keeps_trend_and_last_seen_after_prune(self):
        """runs_sync folds each run once into run_summary + finding_seen; after its documents are deleted the
        threat-intel trend and finding 'last seen' still include it.
        REQ: DASH-07, OPS-06"""
        seed(F.SID_OLD, threat_intel={"ip_hits_in": [{"conns": 3}], "domain_hits": [1]})
        seed(F.SID)
        server.runs_sync()
        rows = runarchive.ti_rows()
        self.assertEqual([r["id"] for r in rows], [F.SID_OLD, F.SID])
        self.assertEqual(rows[0]["in_conns"], 3)
        seen_before = dict(server.finding_last_seen())
        self.assertTrue(seen_before)
        server.issue_tracker()  # stores the Fix-list inputs of both runs
        gone = runarchive.prune(sids_on_disk(), F.SID, keep_recent=1, daily_days=0, data_dir=server.DATA)
        self.assertEqual(gone, [F.SID_OLD])
        self.assertFalse(store.jexists(os.path.join(server.DATA, F.SID_OLD + ".json")))
        self.assertFalse(store.jexists(os.path.join(server.DATA, F.SID_OLD + ".analysis.json")))
        server._rsync.update(sig=None)
        self.assertEqual([r["id"] for r in runarchive.ti_rows()], [F.SID_OLD, F.SID])
        self.assertEqual(server.finding_last_seen(), seen_before)

    def test_prune_needs_summary_and_ingest(self):
        """A run keeps its documents until it is summarised, its Fix-list inputs are stored and the event store has
        ingested it; the newest runs and the 05 UTC daily runs of the tuning window always stay.
        REQ: OPS-06"""
        ids = ["2026-01-03T0500Z", "2026-01-03T1200Z", "2026-01-04T0500Z", "2026-01-04T1200Z", "2026-01-05T1200Z"]
        for i in ids:
            seed(i)
        self.assertEqual(runarchive.prunable(ids, ids[-1], keep_recent=1, daily_days=1), [])  # nothing summarised yet
        server.runs_sync()
        self.assertEqual(runarchive.prunable(ids, ids[-1], keep_recent=1, daily_days=1), [])  # Fix-list inputs not stored
        server.issue_tracker()
        self.assertEqual(runarchive.prunable(ids, "", keep_recent=1, daily_days=1), [])  # not ingested
        self.assertEqual(runarchive.prunable(ids, "2026-01-03T1200Z", keep_recent=1, daily_days=1), ["2026-01-03T0500Z", "2026-01-03T1200Z"])
        self.assertEqual(runarchive.prunable(ids, ids[-1], keep_recent=1, daily_days=1),
                         ["2026-01-03T0500Z", "2026-01-03T1200Z", "2026-01-04T1200Z"])  # 01-04 05Z = daily, 01-05 = newest

    def test_fix_list_counts_pruned_runs(self):
        """The Fix list gives the same open issues and occurrence counts after older runs lose their documents
        (their stored tracker inputs take part), also after a dashboard restart (empty in-memory cache).
        REQ: OPS-06"""
        seed(F.SID_OLD)
        seed(F.SID)
        before = server.issue_tracker()
        server.runs_sync()
        runarchive.prune(sids_on_disk(), F.SID, keep_recent=1, daily_days=0, data_dir=server.DATA)
        self.assertEqual(sids_on_disk(), [F.SID])
        server._issues.clear()  # restart
        server._issues.update(sig=None, val=None)
        after = server.issue_tracker()
        key = lambda it: sorted((i["key"], i["occurrences"], i["status"]) for i in it["open"])
        self.assertEqual(key(after), key(before))
        self.assertEqual(after["snapshots"], before["snapshots"])


class RangeOnlyPage(unittest.TestCase):
    def setUp(self):
        reset()

    def test_snapshot_api_refuses_review_runs(self):
        """The page API serves time ranges only: a review-run id is refused, there is no /api/snapshots list, and a
        time range does not load its base review run's documents.
        REQ: POS-01"""
        seed(F.SID)
        app = ""
        for n in ("app.js", "timerange.js"):
            with open(os.path.join(_env.APP, "static", n)) as f:
                app += f.read()
        self.assertNotIn("/api/snapshots", app)
        self.assertNotIn("rgSnap", app)
        with open(os.path.join(_env.APP, "server.py")) as f:
            src = f.read()
        self.assertNotIn('path == "/api/snapshots"', src)
        self.assertIn("if not RANGE_RE.match(sid):", src)
        rid = "r20260104T1200Z-20260105T1200Z"
        store.jdump(F.raw_snapshot(F.SID), os.path.join(server.RANGES, rid + ".json"))
        store.jdump(F.analysis(F.SID), os.path.join(server.RANGES, rid + ".analysis.json"))
        server._cache.clear()
        loaded = []
        orig = server._snapshot
        server._snapshot = lambda sid: (loaded.append(sid), orig(sid))[1]
        try:
            res = server.snapshot(rid)
        finally:
            server._snapshot = orig
        self.assertEqual(loaded, [rid])
        self.assertEqual(res["base"], F.SID)
        self.assertNotIn("sources", res)

    def test_default_range_picks_newest_done_window(self):
        """/api/range/default: the last 24 h ending on the 15-minute boundary; when that slot is not collected yet the
        newest done one up to 30 minutes older is used; with none done the page collects a fresh range.
        REQ: POS-04"""
        now = dt.datetime(2026, 1, 5, 12, 7, tzinfo=dt.timezone.utc).timestamp()
        d = server.default_range(now)
        self.assertEqual((d["start"], d["end"], d["ready"]), ("2026-01-04T12:00:00+00:00", "2026-01-05T12:00:00+00:00", False))
        rid = "r20260104T1145Z-20260105T1145Z"
        store.jdump({"status": "done"}, os.path.join(server.RANGES, rid + ".status.json"))
        server._cache.clear()
        d = server.default_range(now)
        self.assertEqual((d["id"], d["ready"], d["end"]), (rid, True, "2026-01-05T11:45:00+00:00"))
        old = "r20260104T1100Z-20260105T1100Z"  # older than 30 minutes: not used
        store.jdump({"status": "done"}, os.path.join(server.RANGES, old + ".status.json"))
        server._cache.clear()
        self.assertEqual(server.default_range(now + 3600)["ready"], False)

    def test_range_request_never_uses_review_run(self):
        """A window that matches a review run is still collected as a time range by the host broker.
        REQ: POS-04"""
        seed(F.SID)
        calls = []
        orig = server.corr_llm.broker
        server.corr_llm.broker = lambda path, body, timeout=0: (calls.append(path), {"id": "rX", "status": "sections"})[1]
        try:
            res, code = server.range_request({"start": "2026-01-04T12:00:00Z", "end": "2026-01-05T12:00:00Z"})
        finally:
            server.corr_llm.broker = orig
        self.assertEqual((code, calls, "snapshot" in res), (200, ["/range"], False))


class RangeWarm(unittest.TestCase):
    def test_broker_prune_spares_warm_ranges(self):
        """The broker's range prune (people's picks, RANGE_KEEP) never deletes the pre-collected default windows,
        and range_warm keeps only its newest KEEP.
        REQ: POS-04"""
        _env.fresh_db()
        import host_broker as HB
        import range_warm as RW
        old_ranges, old_keep = HB.RANGES, HB.RANGE_KEEP
        HB.RANGES = server.RANGES
        HB.RANGE_KEEP = 1
        try:
            for rid in ("r20260101T0000Z-20260101T0100Z", "r20260102T0000Z-20260102T0100Z", "r20260103T0000Z-20260103T0100Z"):
                store.jdump({"id": rid}, os.path.join(HB.RANGES, rid + ".meta.json"))
            store.doc_put(RW.DOC, {"ids": ["r20260101T0000Z-20260101T0100Z"]})
            HB._prune()
            left = sorted({os.path.basename(f).split(".")[0] for f in store.jglob(HB.RANGES, "r*.json")})
            self.assertEqual(left, ["r20260101T0000Z-20260101T0100Z", "r20260103T0000Z-20260103T0100Z"])
        finally:
            HB.RANGES, HB.RANGE_KEEP = old_ranges, old_keep


if __name__ == "__main__":
    unittest.main()
