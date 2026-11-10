"""Event times from Elasticsearch (evtime.py): which records an event maps to, the stored first/last record times on
Open events and its firings, the Posture per-range cache and the broker queue."""
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); import _env  # noqa: E401,E402

import json  # noqa: E402
import unittest  # noqa: E402
from unittest import mock  # noqa: E402

import fixtures  # noqa: E402
import eventstore  # noqa: E402

import evtime  # noqa: E402

IP = fixtures.IPS
EXT = fixtures.EXT
DEV = fixtures.mac(9)


class FakeES:
    """Stand-in for esq.q: answers min/max @timestamp from fixed records, recording each query."""

    def __init__(self, recs):
        self.recs, self.calls = recs, []  # recs: [(index, {field: value}, epoch s)]

    def _match(self, flt, doc):
        if "term" in flt:
            (f, v), = flt["term"].items()
            return doc.get(f) == v
        if "terms" in flt:
            (f, v), = flt["terms"].items()
            return doc.get(f) in v
        if "range" in flt:
            (f, r), = flt["range"].items()
            if f == "@timestamp":
                return True
            x = doc.get(f)
            return x is not None and x >= r.get("gte", x)
        if "bool" in flt:
            return any(self._match(s, doc) for s in flt["bool"]["should"])
        raise AssertionError(f"unexpected filter {flt}")

    def __call__(self, index, body):
        self.calls.append((index, body))
        flt = body["query"]["bool"]["filter"]
        rng = flt[0]["range"]["@timestamp"]
        lo, hi = rng["gte"] / 1000, rng["lte"] / 1000
        ts = [t for i, d, t in self.recs if i == index and lo <= t <= hi and all(self._match(f, d) for f in flt[1:])]
        return {"hits": {"total": {"value": len(ts)}},
                "aggregations": {"a": {"value": min(ts) * 1000 if ts else None}, "b": {"value": max(ts) * 1000 if ts else None}}}


class SpecTest(unittest.TestCase):
    """spec()/resolve(): the Elasticsearch records behind each kind of event."""

    def test_port_spike_uses_device_and_port(self):
        """A baseline port spike looks up the device's Zeek connections on that port inside the event's window.
        REQ: EVT-01"""
        eid = f"f|port-spike|{DEV}|port 443/tcp: 59 conns vs normal 0"
        es = FakeES([("logs-zeek-so", {"event.dataset": "zeek.conn", "source.ip": IP["laptop"], "destination.port": 443}, 1500),
                     ("logs-zeek-so", {"event.dataset": "zeek.conn", "source.ip": IP["laptop"], "destination.port": 443}, 1700),
                     ("logs-zeek-so", {"event.dataset": "zeek.conn", "source.ip": IP["laptop"], "destination.port": 443}, 9000),
                     ("logs-zeek-so", {"event.dataset": "zeek.conn", "source.ip": IP["laptop"], "destination.port": 80}, 1200)])
        self.assertEqual(evtime.resolve(eid, "finding", {}, {"host_ips": [IP["laptop"]]}, "", 1000, 2000, es), (1500, 1700))

    def test_falls_back_to_broader_query(self):
        """When the specific record is not found, the next, broader alternative answers.
        REQ: EVT-01"""
        eid = f"f|legacy-tls|{DEV}|uses TLSv10 x2 (broken/deprecated)"
        es = FakeES([("logs-zeek-so", {"event.dataset": "zeek.ssl", "source.ip": IP["laptop"], "ssl.version": "TLSv12"}, 1300)])
        self.assertEqual(evtime.resolve(eid, "finding", {}, {"host_ips": [IP["laptop"]]}, "", 1000, 2000, es), (1300, 1300))
        self.assertEqual(len(es.calls), 2)

    def test_direct_types_need_no_query(self):
        """IDS signatures, admin sessions and gateway events already carry record times: copied, nothing queried.
        REQ: EVT-01"""
        es = FakeES([])
        for typ in ("ids", "admin", "gw"):
            self.assertEqual(evtime.resolve(f"{typ}|x", typ, {}, {}, "", 10, 20, es), (10, 20))
        self.assertEqual(es.calls, [])

    def test_status_findings_have_no_record(self):
        """Status findings (agent offline, silent device, Kubernetes inventory) have nothing to look up.
        REQ: EVT-01"""
        for eid, typ in (("hf|agent-off|host-a", "host"), (f"f|silent|{DEV}|no traffic", "finding"), ("hf|k8s-img|c1|x", "host")):
            self.assertEqual(evtime.spec(eid, typ, {}, {"host_ips": [IP["laptop"]]}, ""), [], eid)

    def test_host_finding_process(self):
        """A new-process host finding looks up that executable's process events on that host.
        REQ: EVT-01"""
        es = FakeES([("logs-endpoint.events.process-*", {"host.name": "host-a", "process.executable": "/usr/bin/tool"}, 1800)])
        self.assertEqual(evtime.resolve("hf|exec-new|host-a|/usr/bin/tool", "host", {}, {}, "", 1000, 2000, es), (1800, 1800))

    def test_alert_window_reaches_back(self):
        """An alert's records are searched in the watcher window before it fired, not at the alert's own time.
        REQ: EVT-01"""
        es = FakeES([("logs-zeek-so", {"event.dataset": "zeek.conn", "destination.ip": IP["server"], "destination.port": 8443}, 5000 - 1200)])
        item = {"key": f"inport|{IP['server']}|8443", "text": "New Internet-facing port"}
        self.assertEqual(evtime.resolve("alert|7", "alert", item, {}, "", 5000, 5000, es), (3800, 3800))

    def test_nothing_found_is_none(self):
        """No matching record -> (None, None), so the page falls back to when netmon saw it.
        REQ: EVT-01"""
        self.assertEqual(evtime.resolve(f"ti|in|{EXT['bad']}", "ti", {}, {}, "", 1000, 2000, FakeES([])), (None, None))


class StoreTest(unittest.TestCase):
    """run(): fills et0/et1 on open events and firings; open_events/detail return them."""

    def setUp(self):
        _env.fresh_db()

    def test_run_fills_events_and_firings(self):
        """Open events and their firings get first/last record times; a later window only looks up the new part and widens them.
        REQ: EVT-02"""
        eid = f"ti|in|{EXT['bad']}"
        eventstore.upsert({eid: {"type": "ti", "label": "x", "sev": "high", "t0": 1000, "t1": 2000}}, "s1", "2026-01-01T00:00:00Z")
        es = FakeES([("logs-zeek-so", {"event.dataset": "zeek.conn", "source.ip": EXT["bad"]}, t) for t in (1100, 1900, 2500)])
        st = evtime.run(budget=30, q=es, log=lambda m: None)
        self.assertEqual(st["errors"], 0)
        c = eventstore._c()
        r = c.execute("SELECT et0, et1, et_upto FROM events WHERE eid=?", (eid,)).fetchone()
        self.assertEqual((r[0], r[1], r[2]), (1100, 1900, 2000))
        f = c.execute("SELECT et0, et1 FROM event_fires WHERE eid=?", (eid,)).fetchone()
        self.assertEqual((f[0], f[1]), (1100, 1900))
        n = len(es.calls)
        evtime.run(budget=30, q=es, log=lambda m: None)
        self.assertEqual(len(es.calls), n)  # nothing new to look up
        eventstore.upsert({eid: {"type": "ti", "label": "x", "sev": "high", "t0": 2000, "t1": 3000}}, "s2", "2026-01-02T00:00:00Z")
        evtime.run(budget=30, q=es, log=lambda m: None)
        r = c.execute("SELECT et0, et1 FROM events WHERE eid=?", (eid,)).fetchone()
        self.assertEqual((r[0], r[1]), (1100, 2500))
        lo = [b["query"]["bool"]["filter"][0]["range"]["@timestamp"]["gte"] for _, b in es.calls[n:]]
        self.assertTrue(all(x >= 2000 * 1000 for x in lo), lo)  # incremental: from the old window end

    def test_open_events_and_detail_carry_times(self):
        """/api/events/open rows carry et0/et1 (earliest / latest over the grouped variants) and detail() firings their own.
        REQ: EVT-02"""
        a = f"f|port-spike|{DEV}|port 443/tcp: 5 conns vs normal 0"
        b = f"f|port-spike|{DEV}|port 443/tcp: 9 conns vs normal 0"
        eventstore.upsert({a: {"type": "finding", "label": "a", "sev": "low", "t0": 1000, "t1": 2000, "host_ips": [IP["laptop"]]}}, "s1", "2026-01-01T00:00:00Z")
        eventstore.upsert({b: {"type": "finding", "label": "b", "sev": "low", "t0": 5000, "t1": 6000, "host_ips": [IP["laptop"]]}}, "s2", "2026-01-02T00:00:00Z")
        es = FakeES([("logs-zeek-so", {"event.dataset": "zeek.conn", "source.ip": IP["laptop"], "destination.port": 443}, t) for t in (1200, 1300, 5500)])
        evtime.run(budget=30, q=es, log=lambda m: None)
        rows = eventstore.open_events()["events"]
        self.assertEqual(len(rows), 1)
        self.assertEqual((rows[0]["et0"], rows[0]["et1"]), (1200, 5500))
        d = eventstore.detail(b)
        self.assertEqual(sorted((f["et0"], f["et1"]) for f in d["fires"]), [(1200, 1300), (5500, 5500)])


class WindowTimesTest(unittest.TestCase):
    """Posture: per-range times come from the event_times cache; missing ones are queued at the broker."""

    def setUp(self):
        _env.fresh_db()

    def raw(self):
        return ({"generated": "2026-01-02T00:00:00Z", "hours": 24, "devices": {IP["laptop"]: {"mac": DEV}},
                 "hosts": {"findings": [{"key": "exec-new|host-a|/usr/bin/tool", "text": "host-a: new program"}]},
                 "threat_intel": {"ip_hits_in": [{"ip": EXT["bad"]}], "domain_hits": [{"domain": "bad.example"}]}},
                {"findings": [{"kind": "port-spike", "device": DEV, "detail": "port 443/tcp: 9 conns vs normal 0"}]})

    def test_posture_items_match_page_ids(self):
        """Posture rows become items with the page's ids, the range's window and the device's IP.
        REQ: EVT-03"""
        items = eventstore.posture_items(*self.raw())
        self.assertEqual([x["eid"] for x in items], [f"f|port-spike|{DEV}|port 443/tcp: 9 conns vs normal 0", "hf|exec-new|host-a|/usr/bin/tool",
                                                     f"ti|in|{EXT['bad']}", "ti|dom|bad.example"])
        self.assertEqual(items[0]["host_ips"], [IP["laptop"]])
        self.assertEqual(items[0]["t1"] - items[0]["t0"], 86400)
        self.assertEqual(eventstore.posture_items({}, {}), [])

    def test_cache_and_queue(self):
        """Uncached rows go to the broker queue (pending); once looked up they come back from the cache, nothing queued.
        REQ: EVT-03"""
        items = eventstore.posture_items(*self.raw())
        sent = []
        out, pending = eventstore.window_times(items, queue=sent.extend)
        self.assertEqual((out, pending, len(sent)), ({}, 4, 4))
        w1 = items[0]["t1"]
        es = FakeES([("logs-zeek-so", {"event.dataset": "zeek.conn", "source.ip": EXT["bad"]}, w1 - 100),
                     ("logs-zeek-so", {"event.dataset": "zeek.conn", "source.ip": IP["laptop"], "destination.port": 443}, w1 - 50)])
        got, left = evtime.window_times(sent, q=es, log=lambda m: None)
        self.assertEqual(left, 0)
        out, pending = eventstore.window_times(items, queue=lambda x: self.fail("nothing to queue"))
        self.assertEqual(pending, 0)
        self.assertEqual(out[f"ti|in|{EXT['bad']}"], [w1 - 100, w1 - 100])
        self.assertEqual(out[items[0]["eid"]], [w1 - 50, w1 - 50])
        self.assertEqual(out["ti|dom|bad.example"], [None, None])  # no record: answered, shown as —

    def test_broker_down_still_answers(self):
        """A broker failure never breaks the page: the cached times are returned and the rest stay pending.
        REQ: EVT-03"""
        def boom(items):
            raise RuntimeError("broker down")
        with mock.patch("sys.stderr"):
            self.assertEqual(eventstore.window_times([{"eid": "ti|in|x", "type": "ti", "t0": 1, "t1": 2}], queue=boom), ({}, 1))


class ApiTest(unittest.TestCase):
    """server.py: the Posture event-times endpoint."""

    def test_endpoint_routed_and_not_for_user_role(self):
        """GET /api/events/times is routed to eventstore.window_times and, like the other /api/events/* endpoints,
        is not on the User role's allow-list.
        REQ: EVT-03"""
        import server
        self.assertNotIn("/api/events/times", server.USER_GET)
        with open(os.path.join(_env.APP, "server.py")) as f:
            src = f.read()
        i = src.index('if path == "/api/events/times"')
        self.assertIn("eventstore.window_times(eventstore.posture_items(", src[i:i + 800])


if __name__ == "__main__":
    unittest.main()
