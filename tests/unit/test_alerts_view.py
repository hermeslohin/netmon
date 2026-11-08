"""Unit tests for the Alerts page helpers in dashboard/app/eventstore.py: verdicts, web research, artifact notes, detections."""
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); import _env  # noqa: E401,E402

import json  # noqa: E402
import time  # noqa: E402
import unittest  # noqa: E402

import store  # noqa: E402
import corr_llm  # noqa: E402
import eventstore  # noqa: E402
import kb  # noqa: E402

EV = "ids|ET POLICY Example signature 5"


def _web(ts, anchor, query, kind="search", cands=(), purpose=None, urls=None, error=None, cached=0):
    with corr_llm._db() as c:
        c.execute("INSERT INTO web_queries (ts, anchor, candidates, model, kind, query, why, results, urls, seconds, error, purpose, cached) "
                  "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                  (ts, anchor, json.dumps(list(cands)), "test-model", kind, query, "because", 3,
                   json.dumps(urls if urls is not None else [{"url": "https://example.org/a", "title": "A"}]), 0.1, error, purpose, cached))


def _classify(eid, label, model="test-model"):
    with corr_llm._db() as c:
        c.execute("INSERT OR REPLACE INTO event_class (eid, label, confidence, reason, model, sig, ts) VALUES (?,?,?,?,?,?,?)", (eid, label, 0.9, "test reason", model, "sig", time.time()))


def _clear_ai():
    with corr_llm._db() as c:
        for q in ("DELETE FROM web_queries", "DELETE FROM event_class", "DELETE FROM event_sources", "DELETE FROM clef_event"):
            c.execute(q)


class AlertRefVerdictTest(unittest.TestCase):
    """alert_ref() and alert_verdict(): which event an alert row is about and whose verdict it shows."""

    def test_alert_ref(self):
        """A review alarm (key ev|<eid>) points at the reviewed event; any other alert is its own event alert|<id>.
        REQ: FEAT-03"""
        self.assertEqual(eventstore.alert_ref({"id": 7, "key": "ev|" + EV}), EV)
        self.assertEqual(eventstore.alert_ref({"id": 7, "key": "watch|x"}), "alert|7")
        self.assertEqual(eventstore.alert_ref({"id": 7, "key": "ev|"}), "alert|7")
        self.assertEqual(eventstore.alert_ref({"id": 8, "key": None}), "alert|8")

    def test_person_verdict_wins(self):
        """A person's verdict beats the event reviewer's; rejected notes are ignored; the decision model gives no event verdict.
        REQ: FEAT-03"""
        X = {"unotes": {EV: [{"verdict": "benign"}, {"verdict": "suspicious", "status": "rejected"}]},
             "classes": {EV: {"label": "suspicious"}}}
        self.assertEqual(eventstore.alert_verdict(EV, X), ("benign", "person"))
        X["unotes"] = {EV: [{"verdict": "suspicious", "status": "rejected"}]}
        self.assertEqual(eventstore.alert_verdict(EV, X), ("suspicious", "ai"))
        X["classes"] = {EV: {"label": "not-a-verdict"}}
        self.assertEqual(eventstore.alert_verdict(EV, X), ("unreviewed", ""))
        self.assertEqual(eventstore.alert_verdict(EV, {}), ("unreviewed", ""))

    def test_newest_person_verdict_counts(self):
        """With several approved person notes, the newest (last) verdict is used.
        REQ: FEAT-03"""
        X = {"unotes": {EV: [{"verdict": "suspicious"}, {"verdict": "expected"}]}}
        self.assertEqual(eventstore.alert_verdict(EV, X), ("expected", "person"))


class WebResearchTest(unittest.TestCase):
    """web_research(): the event reviewer's web look-ups per event."""

    def setUp(self):
        _env.fresh_db()
        _clear_ai()

    def test_own_and_candidate_lookups(self):
        """Look-ups anchored on the event are own; look-ups run while it was a candidate name the anchor; manual tests are left out.
        REQ: FEAT-04"""
        now = time.time()
        _web(now - 30, EV, "own query")
        _web(now - 20, "other|anchor", "candidate query", cands=[EV])
        _web(now - 10, EV, "manual", purpose="manual-test")
        W = eventstore.web_research([EV])[EV]
        self.assertEqual([w["query"] for w in W], ["candidate query", "own query"])  # newest first
        self.assertFalse(W[0]["own"]); self.assertEqual(W[0]["anchor"], "other|anchor")
        self.assertTrue(W[1]["own"]); self.assertEqual(W[1]["anchor"], "")
        self.assertEqual(eventstore.web_research([]), {})

    def test_only_http_urls_and_per_cap(self):
        """Only http(s) result links are kept, and at most `per` look-ups are returned per event.
        REQ: FEAT-04"""
        now = time.time()
        _web(now, EV, "q0", urls=[{"url": "javascript:alert(1)"}, {"url": "https://example.org/x", "title": "X"}, "junk"])
        for i in range(1, 6):
            _web(now - i, EV, f"q{i}")
        W = eventstore.web_research([EV], per=3)[EV]
        self.assertEqual(len(W), 3)
        self.assertEqual(W[0]["urls"], [{"url": "https://example.org/x", "title": "X"}])


class AlertViewTest(unittest.TestCase):
    """alert_view(): Alerts page rows with verdicts, web research, people's notes and artifact notes."""

    def setUp(self):
        _env.fresh_db()
        _clear_ai()
        self._kb = (kb.event_notes, kb.notes_by_artifacts)

    def tearDown(self):
        kb.event_notes, kb.notes_by_artifacts = self._kb

    def test_empty(self):
        """No alerts: nothing to look up.
        REQ: FEAT-05"""
        self.assertEqual(eventstore.alert_view([]), ([], {}))

    def test_verdict_and_web_dedup(self):
        """Each alert gets its event id and verdict; the same look-up re-run by later reviews is one row with a times count.
        REQ: FEAT-05"""
        now = time.time()
        _classify(EV, "suspicious")
        _web(now - 20, EV, "Same Query ")
        _web(now - 10, EV, "same query")
        _web(now - 5, EV, "same query", kind="read")
        alerts = [{"id": 1, "key": "ev|" + EV, "ts": now, "text": "x", "targets": []},
                  {"id": 2, "key": "watch|y", "ts": now, "text": "y", "targets": []}]
        rows, X = eventstore.alert_view(alerts, related=False, art_limit=0)
        self.assertEqual([(r["eid"], r["verdict"], r["vsrc"]) for r in rows],
                         [(EV, "suspicious", "ai"), ("alert|2", "unreviewed", "")])
        W = X["web"][EV]
        self.assertEqual([(w["kind"], w["times"]) for w in W], [("read", 1), ("search", 2)])
        self.assertEqual(X["art_notes"], {})

    def test_people_notes_trimmed_and_artifact_notes_shared(self):
        """People's notes lose their artifacts/label fields; artifact notes are stored once and referenced by id per alert.
        REQ: FEAT-05"""
        kb.event_notes = lambda ids, **k: {i: [{"text": "looked at it", "verdict": "benign", "artifacts": ["a"], "label": "L"}]
                                           for i in ids if i == EV}
        note = {"id": 42, "subject": "a host", "category": "host", "text": "t" * 900, "author": "tester"}
        kb.notes_by_artifacts = lambda keys, limit=12, **k: [(1.0, ["ip:x"], note)]
        now = time.time()
        alerts = [{"id": 1, "key": "ev|" + EV, "ts": now, "text": "x", "targets": []},
                  {"id": 3, "key": "ev|" + EV, "ts": now, "text": "x again", "targets": []},
                  {"id": 2, "key": "watch|y", "ts": now, "text": "y", "targets": []}]
        rows, X = eventstore.alert_view(alerts, related=False, art_limit=4)
        self.assertEqual(X["unotes"][EV], [{"text": "looked at it", "verdict": "benign"}])
        self.assertEqual(rows[0]["verdict"], "benign"); self.assertEqual(rows[0]["vsrc"], "person")
        self.assertEqual(X["art_notes"][EV], [{"id": 42, "matched": ["ip:x"]}])
        self.assertEqual(set(X["art_notes"]), {EV, "alert|2"})
        self.assertEqual(list(X["art_note_text"]), ["42"])
        self.assertEqual(len(X["art_note_text"]["42"]["text"]), 700)


class DetectionsTest(unittest.TestCase):
    """detections(): held detections with verdicts and verdict counts."""

    def setUp(self):
        _env.fresh_db()
        _clear_ai()
        store._cfg_cache.clear()

    def test_counts_and_filter(self):
        """Held detections are listed newest first with verdict counts kept apart from alarms; a verdict filter narrows the list.
        REQ: FEAT-06"""
        store.alerts_add([("w|1", "detection one", "urgent", ["t1"]), ("w|2", "detection two", "urgent", ["t2"])], source="watcher")
        store.alerts_add([("a|1", "an alarm", "urgent", ["t3"])], source="review")
        ids = {r["key"]: r["id"] for r in store._dc().execute("SELECT id, key FROM alerts")}
        _classify(f"alert|{ids['w|1']}", "benign")
        _classify(f"alert|{ids['a|1']}", "suspicious")
        D = eventstore.detections()
        self.assertEqual(D["total"], 2)
        self.assertEqual([a["key"] for a in D["alerts"]], ["w|2", "w|1"])
        self.assertEqual(D["counts"]["detections"], {"unreviewed": 1, "benign": 1})
        self.assertEqual(D["counts"]["alarms"], {"suspicious": 1})
        F = eventstore.detections(verdict="benign")
        self.assertEqual((F["matching"], [a["key"] for a in F["alerts"]]), (1, ["w|1"]))
        self.assertEqual(F["alerts"][0]["verdict"], "benign")
        self.assertEqual(len(eventstore.detections(limit=1)["alerts"]), 1)


if __name__ == "__main__":
    unittest.main()
