"""Unit tests for the IDS events Verdict column: GET /api/verdicts (server.event_verdicts) and the tables that show it."""
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); import _env  # noqa: E401,E702,E402

import re  # noqa: E402
import time  # noqa: E402
import unittest  # noqa: E402
from unittest import mock  # noqa: E402

import corr_llm  # noqa: E402
import server  # noqa: E402

SIG = "ids|ET SCAN Test Probe"
OTHER = "ids|ET INFO Never Seen Rule"
STATIC = os.path.join(_env.APP, "static")


class EventVerdicts(unittest.TestCase):
    """server.event_verdicts: stored labels and research note verdicts for any event ids."""

    def setUp(self):
        with corr_llm._db() as c:
            c.execute("DELETE FROM event_class")
            c.execute("INSERT OR REPLACE INTO event_class (eid, label, confidence, reason, model, sig, ts) VALUES (?,?,?,?,?,?,?)",
                      (SIG, "suspicious", 0.8, "scan from a lab host", "test-model", "sig", time.time()))

    def tearDown(self):
        with corr_llm._db() as c:
            c.execute("DELETE FROM event_class")

    def test_label_of_signature_outside_any_snapshot(self):
        """A signature's stored event reviewer label is returned by event id even when no loaded snapshot holds the event, and an unlabelled signature gets none.
        REQ: POS-22"""
        with mock.patch.object(server.enrich, "load", return_value={}):
            r = server.event_verdicts([SIG, OTHER, SIG, ""])
        self.assertEqual(r["classes"][SIG]["label"], "suspicious")
        self.assertEqual(r["classes"][SIG]["model"], "test-model")
        self.assertNotIn(OTHER, r["classes"])
        self.assertEqual(r["notes"], {})

    def test_research_note_verdict_included(self):
        """The research note verdict of the signature comes back with only its short fields (no research text or links).
        REQ: POS-22"""
        note = {"verdict": "benign", "priority": "low", "summary": "known scanner", "model": "m", "at": 1.0, "research": "long text", "links": ["x"]}
        with mock.patch.object(server.enrich, "load", return_value={OTHER: note}):
            r = server.event_verdicts([OTHER])
        self.assertEqual(r["notes"][OTHER], {"verdict": "benign", "priority": "low", "summary": "known scanner", "model": "m", "at": 1.0})

    def test_empty_and_failing_lookups(self):
        """No ids returns empty maps, and a failing notes store leaves the labels intact instead of failing the request.
        REQ: POS-22"""
        self.assertEqual(server.event_verdicts([]), {"classes": {}, "notes": {}})
        with mock.patch.object(server.enrich, "load", side_effect=RuntimeError("db gone")):
            r = server.event_verdicts([SIG])
        self.assertEqual(r["classes"][SIG]["label"], "suspicious")
        self.assertEqual(r["notes"], {})

    def test_user_role_cannot_read_verdicts(self):
        """GET /api/verdicts is analyst data: it is not on the User role's allow-list.
        REQ: POS-22"""
        self.assertNotIn("/api/verdicts", server.USER_GET)


class VerdictColumn(unittest.TestCase):
    """Every IDS signature table carries the Verdict column keyed by the signature's event id."""

    def test_ids_tables_have_verdict_column(self):
        """Posture's IDS signatures, a device's IDS alerts and Threat intel's malware/exploit signatures each add vdCol on ids|<name>.
        REQ: POS-22"""
        app = open(os.path.join(STATIC, "app.js"), encoding="utf-8").read()
        tls = open(os.path.join(STATIC, "tlsintel.js"), encoding="utf-8").read()
        col = "vdCol((x) => x.name && `ids|${x.name}`)"
        self.assertEqual(app.count(col), 2)
        self.assertEqual(tls.count(col), 1)
        self.assertTrue(re.search(r'const vdCol = \(idOf\) => \(\{ k: "_vd", t: "Verdict"', app))
        self.assertIn('"/api/verdicts?"', app)


class PostureIdsEvents(unittest.TestCase):
    """The Posture IDS events box looks and behaves like the findings boxes."""

    def test_ids_events_box_like_findings(self):
        """IDS events: check-off column (ack event ids|<name>, shared with Open events), Severity badge from the Suricata
        number (gives the coloured row edge), open count title, checked rows via ackSplit/ackRowCls; no separate Suppress column.
        REQ: POS-23"""
        app = open(os.path.join(STATIC, "app.js"), encoding="utf-8").read()
        body = app[app.index('const IE = ackSplit("ids", sigs, "sec-ids")'):app.index('const SV = ackSplit("violation"')]
        self.assertIn("card(`IDS events (${IE.open.length} open, ", body)
        self.assertIn('ackCol("ids", ', body)
        self.assertIn('t: "Severity", fmt: (v, x) => `<span title="Suricata severity ${esc(v ?? "?")}">${badge(idsSev(x))}</span>`', body)
        self.assertIn('rowClass: ackRowCls("ids")', body)
        self.assertNotIn("idsSupBtn", body)
        self.assertIn('if (type === "ids") return ["event", `ids|${x?.name || ""}`];', app)
        self.assertIn('const idsSev = (x) => (x.severity <= 1 ? "high" : x.severity === 2 ? "medium" : "low");', app)
        css = open(os.path.join(STATIC, "style.css"), encoding="utf-8").read()
        self.assertIn("tr:has(td .sev-critical,td .sev-high", css)  # the badge's class paints the row's left edge
        self.assertNotIn("IDS signatures", app.replace("IDS signature rules", ""))


if __name__ == "__main__":
    unittest.main()
