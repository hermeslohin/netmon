"""Event stream (stream.py + streamchecks.py): Suricata / syslog / host alerts tailed every few seconds by arrival time,
and the event reviewer settling stream-only groups on the stream's bookmark (corr_llm.event_pass)."""
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); import _env  # noqa: E401,E402

import importlib  # noqa: E402
import json  # noqa: E402
import time  # noqa: E402
import types  # noqa: E402
import unittest  # noqa: E402
from unittest import mock  # noqa: E402

import corr_llm  # noqa: E402
import store  # noqa: E402
import streamchecks  # noqa: E402
import window  # noqa: E402


def _clean():
    _env.fresh_db()
    with store.connect() as c:
        c.execute("DELETE FROM meta WHERE k IN ('arrival:stream', 'arrival:watch')")
        c.execute("DELETE FROM watch_mute")
        c.execute("DELETE FROM alerts")
    window._ARR.clear()
    store._cfg_cache.clear()


class FakeES:
    """Canned answers per index; raise= an index name whose search fails."""

    def __init__(self, ids=(), syslog=None, defend=(), detect=(), fail=None):
        self.ids, self.syslog, self.defend, self.detect, self.fail = list(ids), syslog or {}, list(defend), list(detect), fail
        self.calls = []

    def q(self, idx, body):
        self.calls.append((idx, body))
        if self.fail and idx.startswith(self.fail):
            raise OSError("es down (test)")
        if idx.startswith("logs-suricata"):
            return {"aggregations": {"s": {"buckets": self.ids}}}
        if idx.startswith("logs-system.syslog"):
            return {"aggregations": {"p": {"buckets": self.syslog}}}
        if idx.startswith("logs-endpoint.alerts"):
            return {"hits": {"hits": [{"_source": s} for s in self.defend]}}
        if idx.startswith("logs-detections"):
            return {"hits": {"hits": [{"_source": s} for s in self.detect]}}
        return {}


def ids_bucket(name, src="10.0.0.5", dst="1.2.3.4", t0=1_790_000_000_000):
    return {"key": name, "doc_count": 2, "src": {"buckets": [{"key": src}]}, "dst": {"buckets": [{"key": dst}]},
            "mt": {"buckets": []}, "t0": {"value": t0, "value_as_string": "2026-09-21T13:46:40Z"}, "in": {"value": t0 + 5000}}


def load_stream(es):
    """Import stream.py with collect stubbed (no Elasticsearch credentials in tests)."""
    fake = types.SimpleNamespace(q=es.q, inventory=lambda: ({}, None))
    argv = list(sys.argv)
    try:
        with mock.patch.dict(sys.modules, {"collect": fake}):
            sys.modules.pop("stream", None)
            mod = importlib.import_module("stream")
    finally:
        sys.argv[:] = argv
    mod.q = es.q
    return mod


class StreamTick(unittest.TestCase):
    """stream.tick(): bookmark windows, shared keys / mute, held source, failure handling."""

    def setUp(self):
        _clean()

    def tearDown(self):
        _clean()

    def test_ticks_touch_end_to_end_and_store_held_alerts(self):
        """Each tick reads (bookmark, now - margin] on event.ingested; alerts are stored held, source stream, with the event time.
        REQ: EVW-09"""
        es = FakeES(ids=[ids_bucket("ET MALWARE Test C2")],
                    detect=[{"@timestamp": "2027-01-15T08:00:01Z", "rule": {"name": "SOC Login Failure"}, "event": {"severity_label": "high"},
                             "event_data": {"host": {"name": "securityonion"}, "user": {"name": "bob"}}}])
        st = load_stream(es)
        ctx = st.Ctx()
        now = 1_800_000_600
        r1 = st.tick(ctx, now=now)
        self.assertEqual(r1["failed"], [])
        self.assertEqual(sorted(r1["new"]), ["host|detect|securityonion|SOC Login Failure", "ids|ET MALWARE Test C2|['10.0.0.5']"])
        rows = {r["key"]: r for r in store.connect().execute("SELECT key, source, held, event_ts, text FROM alerts")}
        self.assertEqual({r["source"] for r in rows.values()}, {"stream"})
        self.assertEqual({r["held"] for r in rows.values()}, {1})
        self.assertEqual(rows["ids|ET MALWARE Test C2|['10.0.0.5']"]["event_ts"], 1_790_000_000)
        self.assertIn("user bob", rows["host|detect|securityonion|SOC Login Failure"]["text"])
        self.assertEqual(window.bookmark("stream"), now - window.STREAM_MARGIN_S)
        window._ARR.clear()
        r2 = st.tick(ctx, now=now + 15)
        self.assertEqual(r2["window"]["from"], r1["window"]["to"])  # touching windows: nothing read twice, nothing skipped
        self.assertEqual(r2["new"], [])  # same keys again: muted for 12 h (shared with the watcher)
        self.assertEqual(store.connect().execute("SELECT COUNT(*) FROM alerts").fetchone()[0], 2)
        self.assertIn("event.ingested", json.dumps(es.calls[-1][1]["query"]["bool"]["filter"][0]))  # arrival time, not @timestamp

    def test_failed_check_keeps_bookmark(self):
        """An Elasticsearch error in any check keeps the bookmark, so the next tick re-reads the same span.
        REQ: EVW-09"""
        import hosts
        st = load_stream(FakeES(fail="logs-system.syslog"))
        ctx = st.Ctx()
        self.enterContext(mock.patch.object(hosts, "SYSLOG_PATTERNS", {"OOM killer": {"q": "*out of memory*", "watch": True}}))
        with store.connect() as c:
            c.execute("INSERT OR REPLACE INTO meta VALUES (?, ?)", ("arrival:stream", json.dumps({"to": 1_800_000_000, "from": 1_799_999_985})))
        r = st.tick(ctx, now=1_800_000_100)
        self.assertEqual(r["failed"], ["syslog"])
        self.assertEqual(window.bookmark("stream"), 1_800_000_000)
        self.assertEqual(store.doc_get(st.STATUS_DOC)["errors"], 1)

    def test_watcher_twin_is_muted(self):
        """An IDS alert the watcher already raised (same key) is not stored a second time by the stream.
        REQ: EVW-09"""
        store.mute_filter([("ids|ET MALWARE Test C2|['10.0.0.5']", "x")], 12)
        st = load_stream(FakeES(ids=[ids_bucket("ET MALWARE Test C2")]))
        self.assertEqual(st.tick(st.Ctx(), now=1_800_000_600)["new"], [])

    def test_syslog_one_search_for_all_patterns(self):
        """Watched syslog patterns are read in ONE search (filters aggregation) and become the watcher's host|syslog| keys.
        REQ: EVW-09"""
        b = {"OOM killer": {"h": {"buckets": [{"key": "nodeA", "doc_count": 3, "first": {"value": 1_790_000_000_000, "value_as_string": "2027-01-15T08:00:00Z"},
                                               "last": {"value_as_string": "2027-01-15T08:01:00Z"},
                                               "s": {"hits": {"hits": [{"_source": {"message": "Out of memory: Killed process 42"}}]}}}]}}}
        es = FakeES(syslog=b)
        got = []
        pats = {"OOM killer": {"q": "*out of memory*", "sev": "Investigate", "watch": True}, "segfault": {"q": "*segfault*", "watch": False}}
        import hosts
        with mock.patch.object(hosts, "SYSLOG_PATTERNS", pats):
            n = streamchecks.syslog(es.q, {"range": {"event.ingested": {}}}, lambda k, t, at=None, **kw: got.append((k, t, at)))
        self.assertEqual(n, 1)
        self.assertEqual(len([c for c in es.calls if c[0].startswith("logs-system.syslog")]), 1)
        self.assertEqual(list(es.calls[0][1]["aggs"]["p"]["filters"]["filters"]), ["OOM killer"])  # unwatched patterns not queried
        self.assertEqual(got[0][0], "host|syslog|nodea|OOM killer")  # host names folded as hosts.hn() does
        self.assertEqual(got[0][2], 1_790_000_000)


class StreamSettle(unittest.TestCase):
    """event_pass: a stream-only group settles on the stream's bookmark; a mixed group on the watcher's."""

    def setUp(self):
        _clean()
        with corr_llm._db() as c:
            for sql in ("DELETE FROM verdicts", "DELETE FROM event_class", "DELETE FROM review_pending", "DELETE FROM review_events",
                        "DELETE FROM decision_inputs", "DELETE FROM event_sources"):
                c.execute(sql)
        corr_llm._REVIEW_FAILS.clear()
        self.calls = []

        def fake(target, anchor, cands, *a, **kw):
            self.calls.append(anchor["label"])
            return ([{"id": "anchor", "label": "benign", "confidence": 0.8, "reason": "routine"}], {"prompt": 1, "completion": 1}, 1.0)
        self.patches = [mock.patch.object(corr_llm, "_ask_full", fake),
                        mock.patch.object(corr_llm, "_target", lambda model=None: {"provider": "lmstudio", "model": "reviewer"}),
                        mock.patch.object(corr_llm, "reopen_checked", lambda *a, **k: None)]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        _clean()

    def _alert(self, key):
        store.alerts_add([(key, key, "urgent")], source="stream")
        return f"alert|{store.connect().execute('SELECT MAX(id) FROM alerts').fetchone()[0]}"

    def _bm(self, job, to):
        with store.connect() as c:
            c.execute("INSERT OR REPLACE INTO meta VALUES (?, ?)", (f"arrival:{job}", json.dumps({"to": to, "from": to - 15})))

    def _decide(self, a, b):
        with corr_llm._db() as c:
            c.execute("INSERT OR REPLACE INTO verdicts (pair, related, confidence, reason, model, ts) VALUES (?,?,?,?,?,?)",
                      (corr_llm.pair(a, b), 1, 0.9, "clef", "clef", time.time()))

    def test_stream_only_group_settles_on_stream_bookmark(self):
        """A group of stream events is labelled once newest + window has passed and the STREAM bookmark covers it, while the
        watcher's bookmark is still behind; its pending settle time is about a minute after newest + window, not the next pull slot.
        REQ: EVW-10"""
        now = time.time()
        a, b = self._alert("ids|ET X|['10.0.0.5']"), self._alert("host|syslog|nodea|OOM killer")  # host names folded as hosts.hn() does
        newest = now - 700  # one 10-min window + 100 s ago
        base = {"events": {a: {"type": "alert", "label": "ids", "sev": "medium", "t0": newest - 30, "t1": newest - 30},
                           b: {"type": "alert", "label": "oom", "sev": "medium", "t0": newest, "t1": newest}},
                "related": {a: [{"id": b, "score": 5, "why": []}]}}
        self._decide(a, b)
        self._bm("watch", newest + 100)  # the watcher's last pull ended before newest + window
        self._bm("stream", newest + 500)  # the stream is not there yet either
        self.assertEqual(corr_llm.event_pass(base, now=now), 0)
        p = corr_llm.classes([a], pending=True)[a]["pending"]
        self.assertAlmostEqual(p["settles"], newest + 600 + corr_llm.STREAM_LAG_S, delta=1)
        self._bm("stream", now - 60)  # the stream tick past newest + window
        self.assertEqual(corr_llm.event_pass(base, now=now), 1)
        self.assertEqual(len(self.calls), 1)

    def test_mixed_group_waits_for_the_watcher(self):
        """A group with an event the stream does not check (e.g. a new device) still waits for the watcher's pull.
        REQ: EVW-10"""
        now = time.time()
        a, b = self._alert("ids|ET X|['10.0.0.5']"), self._alert("newmac|example-device")
        newest = now - 700
        base = {"events": {a: {"type": "alert", "label": "ids", "sev": "medium", "t0": newest, "t1": newest},
                           b: {"type": "alert", "label": "new", "sev": "medium", "t0": newest, "t1": newest}},
                "related": {a: [{"id": b, "score": 5, "why": []}]}}
        self._decide(a, b)
        self._bm("watch", newest + 100)
        self._bm("stream", now - 60)
        self.assertEqual(corr_llm.event_pass(base, now=now), 0)
        self._bm("watch", newest + 650)
        self.assertEqual(corr_llm.event_pass(base, now=now), 1)

    def test_idle_wakes_on_new_alert(self):
        """The reviewer's idle wait ends within one step when a new alert arrives (not after the full minute).
        REQ: EVW-10"""
        mark = corr_llm._wake_mark()
        sleeps = []

        def slp(s):
            sleeps.append(s)
            if len(sleeps) == 2:
                store.alerts_add([("ids|late", "late", "urgent")], source="stream")
        with mock.patch.object(corr_llm.time, "sleep", slp):
            corr_llm._idle(60, mark, step=5)
        self.assertEqual(len(sleeps), 2)


if __name__ == "__main__":
    unittest.main()
