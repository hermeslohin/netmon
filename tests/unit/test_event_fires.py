"""Unit tests for eventstore firings: only events seen in Elasticsearch fire, overlapping report windows merge into one firing."""
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); import _env  # noqa: E401,E402

import unittest  # noqa: E402

import fixtures  # noqa: E402
import store  # noqa: E402
import eventstore  # noqa: E402

DEV = fixtures.mac(7)
IDS = "ids|ET POLICY Example signature 99"
BEACON_A = f"f|beacon|{DEV}|beacon to example every 60s, 12 conns"
BEACON_B = f"f|beacon|{DEV}|beacon to example every 60s, 15 conns"
NEWDEV = f"f|new-device|{DEV}|first seen"
GW = "gw|THREAT_BLOCKED|1792700000|x|y"


def _fires(eid_prefix):
    c = eventstore._c()
    return [dict(r) for r in c.execute("SELECT eid,sid,t0,t1 FROM event_fires WHERE eid >= ? AND eid < ? ORDER BY sid",
                                       (eid_prefix, eid_prefix + "\uffff"))]


class EsSourcedTest(unittest.TestCase):
    """es_sourced() decides which event types can fire."""

    def test_es_types_fire_and_others_do_not(self):
        """IDS, host, threat-intel and Zeek-derived findings are ES-sourced; gateway, vulnerability and inventory findings are not.
        REQ: FEAT-01"""
        self.assertTrue(eventstore.es_sourced(IDS, "ids"))
        self.assertTrue(eventstore.es_sourced("host|x", "host"))
        self.assertTrue(eventstore.es_sourced("ti|x", "ti"))
        self.assertTrue(eventstore.es_sourced(BEACON_A, "finding"))
        self.assertTrue(eventstore.es_sourced(BEACON_A, ""))  # f| prefix alone marks a finding
        for kind in eventstore.NON_ES_FINDINGS:
            self.assertFalse(eventstore.es_sourced(f"f|{kind}|{DEV}|x", "finding"), kind)
        self.assertFalse(eventstore.es_sourced(GW, "gw"))
        self.assertFalse(eventstore.es_sourced("vuln|x", "vuln"))
        self.assertFalse(eventstore.es_sourced("f", "finding"))  # malformed finding id


class FiringsTest(unittest.TestCase):
    """upsert() records a firing per real occurrence in Elasticsearch data, not per report."""

    def setUp(self):
        _env.fresh_db()
        store._cfg_cache.clear()
        eventstore._c().execute("DELETE FROM event_fires")

    def test_non_es_events_never_fire(self):
        """Gateway events and inventory findings are stored as events but never get a firing row.
        REQ: FEAT-01"""
        eventstore.upsert({GW: {"type": "gw", "label": "gw", "t0": 10, "t1": 20},
                           NEWDEV: {"type": "finding", "label": "new device", "t0": 10, "t1": 20}}, "s1")
        self.assertEqual(_fires("gw|"), [])
        self.assertEqual(_fires("f|new-device|"), [])
        n = eventstore._c().execute("SELECT COUNT(*) FROM events").fetchone()[0]
        self.assertEqual(n, 2)

    def test_events_without_end_time_do_not_fire(self):
        """An ES event without a t1 (no occurrence time) records no firing.
        REQ: FEAT-01"""
        eventstore.upsert({IDS: {"type": "ids", "label": "x", "t1": None}}, "s1")
        self.assertEqual(_fires("ids|"), [])

    def test_ids_fires_per_new_alert_time(self):
        """An IDS signature fires once per new last-alert time; a later report with the same time adds no firing.
        REQ: FEAT-01"""
        eventstore.upsert({IDS: {"type": "ids", "label": "x", "t1": 100}}, "s1")
        eventstore.upsert({IDS: {"type": "ids", "label": "x", "t1": 100}}, "s2")
        self.assertEqual(len(_fires("ids|")), 1)
        eventstore.upsert({IDS: {"type": "ids", "label": "x", "t1": 500}}, "s3")
        F = _fires("ids|")
        self.assertEqual([f["sid"] for f in F], ["s1", "s3"])

    def test_overlapping_windows_extend_one_firing(self):
        """A finding variant whose report window overlaps the previous firing of the same condition extends that firing.
        REQ: FEAT-01"""
        eventstore.upsert({BEACON_A: {"type": "finding", "label": "b", "t0": 0, "t1": 100}}, "s1")
        eventstore.upsert({BEACON_B: {"type": "finding", "label": "b", "t0": 50, "t1": 160}}, "s2")
        F = _fires("f|beacon|")
        self.assertEqual(len(F), 1, F)
        self.assertEqual((F[0]["eid"], F[0]["sid"], F[0]["t1"]), (BEACON_A, "s1", 160))

    def test_disjoint_window_is_a_new_firing(self):
        """A window that starts after the previous firing ended is a new firing.
        REQ: FEAT-01"""
        eventstore.upsert({BEACON_A: {"type": "finding", "label": "b", "t0": 0, "t1": 100}}, "s1")
        eventstore.upsert({BEACON_B: {"type": "finding", "label": "b", "t0": 200, "t1": 300}}, "s2")
        self.assertEqual([f["sid"] for f in _fires("f|beacon|")], ["s1", "s2"])

    def test_seen_count_counts_reports(self):
        """The event's n (seen N times) still counts report appearances even when no new firing is recorded.
        REQ: FEAT-01"""
        eventstore.upsert({IDS: {"type": "ids", "label": "x", "t1": 100}}, "s1")
        eventstore.upsert({IDS: {"type": "ids", "label": "x", "t1": 100}}, "s2")
        n = eventstore._c().execute("SELECT n FROM events WHERE eid=?", (IDS,)).fetchone()[0]
        self.assertEqual(n, 2)


class DetailPerFiringTest(unittest.TestCase):
    """detail() keeps the review time of every merged related link so each firing can show its own links."""

    def setUp(self):
        _env.fresh_db()
        store._cfg_cache.clear()
        eventstore._c().execute("DELETE FROM event_fires")
        import corr_llm
        self.corr_llm = corr_llm
        self._saved = (corr_llm.related_view, corr_llm.decision_inputs_view, corr_llm.decision_inputs_since)

    def tearDown(self):
        c = self.corr_llm
        c.related_view, c.decision_inputs_view, c.decision_inputs_since = self._saved

    def test_merged_related_links_keep_each_review_time(self):
        """Two variants of one related condition merge into one line with both review times (llm_ats), merged artifacts,
        and the higher-confidence variant's fields.
        REQ: FEAT-02"""
        eventstore.upsert({IDS: {"type": "ids", "label": "x", "t1": 100}}, "s1")
        rows = [{"id": BEACON_A, "llm_conf": 0.6, "llm_reason": "low", "llm_at": 1000.0,
                 "llm_artifacts": [{"kind": "ip", "value": "a"}]},
                {"id": BEACON_B, "llm_conf": 0.9, "llm_reason": "high", "llm_at": 2000.0,
                 "llm_artifacts": [{"kind": "ip", "value": "a"}, {"kind": "dns", "value": "b"}]}]
        c = self.corr_llm
        c.related_view = lambda groups, **k: ({e: list(rows) for e in groups}, {BEACON_A, BEACON_B})
        c.decision_inputs_view = lambda eids: {}
        c.decision_inputs_since = lambda: None
        d = eventstore.detail(IDS)
        L = d["by_event"][IDS]
        self.assertEqual(len(L), 1)
        x = L[0]
        self.assertEqual(sorted(x["llm_ats"]), [1000.0, 2000.0])
        self.assertEqual(x["variants"], 2)
        self.assertEqual(x["llm_reason"], "high")
        self.assertEqual({(a["kind"], a["value"]) for a in x["llm_artifacts"]}, {("ip", "a"), ("dns", "b")})
        self.assertEqual(len(d["fires"]), 1)


if __name__ == "__main__":
    unittest.main()
