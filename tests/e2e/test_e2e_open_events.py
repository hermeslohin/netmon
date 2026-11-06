"""E2E: the Open events API of the real dashboard server - list, filters, limits, display merges, check-offs, the event
window (detail / inputs / related) and who may read it.

One server process for the class, its store seeded with a snapshot and a known set of persisted events.
"""
import os
import sys
import unittest
from urllib.parse import quote

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import _env  # noqa: E402,F401
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness  # noqa: E402
import fixtures  # noqa: E402

IP, EXT = fixtures.IPS, fixtures.EXT
DEV = fixtures.mac(21)
IDS = "ids|E2E OE signature"
GW = "gw|E2E_BLOCK|1792700000|x|y"
TI = "ti|out|" + EXT["bad"]
BEACON_1 = f"f|beacon|{DEV}|beacon to {EXT['bad']} every ~60s, 145 conns"
BEACON_2 = f"f|beacon|{DEV}|beacon to {EXT['bad']} every ~61s, 3,983 conns"
SEG_A = f"f|segmentation|{DEV}|E2E Box -> Lab Server ({IP['server']}) 22/tcp"
SEG_B = f"f|segmentation|{DEV}|E2E Box -> Yard Camera ({IP['camera']}) 22/tcp"
BULK = 5005
OE_PATHS = ("/api/events/open", "/api/events/detail?e=" + quote(IDS), "/api/events/inputs?e=" + quote(IDS),
            "/api/events/related?e=" + quote(IDS))

SEED = f"""
import fixtures, eventstore, corr_llm
fixtures.seed_snapshot(fixtures.SID)
def ev(t, label, sev, t0=None, t1=None, **kw):
    return {{"type": t, "label": label, "sev": sev, "t0": t0, "t1": t1, **kw}}
def seg(e):
    p = e.split("|")
    return {{"kind": "segmentation", "device": p[2], "detail": "|".join(p[3:]), "name": "E2E Box"}}
eventstore.upsert({{{IDS!r}: ev("ids", "IDS: E2E OE signature x4", "medium", 100, 400),
                   {GW!r}: ev("gw", "E2E gateway blocked", "high", 100, 300),
                   {TI!r}: ev("ti", "E2E outbound to listed IP", "high", 100, 350, ips=[{EXT['bad']!r}]),
                   {BEACON_1!r}: ev("finding", "E2E beacon 145 conns", "medium", 0, 100),
                   {SEG_A!r}: ev("finding", "E2E seg a", "high", 0, 10, ips=[{IP['server']!r}])}},
                  "2026-01-04T1200Z", "2026-01-04T12:00:00Z", {{{SEG_A!r}: seg({SEG_A!r})}})
eventstore.upsert({{{BEACON_2!r}: ev("finding", "E2E beacon 3983 conns", "medium", 200, 300),
                   {SEG_B!r}: ev("finding", "E2E seg b", "high", 20, 30, ips=[{IP['camera']!r}])}},
                  "2026-01-05T1200Z", "2026-01-05T12:00:00Z", {{{SEG_B!r}: seg({SEG_B!r})}})
eventstore.upsert({{"ids|E2E bulk %05d" % i: ev("ids", "E2E bulk %05d" % i, "info") for i in range({BULK})}}, "bulk")
with corr_llm._db() as c:
    c.execute("INSERT INTO verdicts (pair, related, confidence, reason, model, ts) VALUES (?,?,?,?,?,?)",
              (corr_llm.pair({BEACON_1!r}, {GW!r}), 1, 0.9, "same host", "e2e", 10))
"""  # noqa: S608 - a seed script run in the test server's store, all values bound as parameters


class OpenEventsApi(unittest.TestCase):
    """/api/events/open, /detail, /inputs and /related against a seeded store."""

    @classmethod
    def setUpClass(cls):
        cls.srv = harness.Server(seed=SEED).__enter__()
        cls.c = cls.srv.login()

    @classmethod
    def tearDownClass(cls):
        cls.srv.__exit__(None, None, None)

    def get(self, path, c=None):
        code, body, _ = (c or self.c).get(path)
        self.assertEqual(code, 200, (path, body))
        return body

    def eids(self, path):
        return [e["eid"] for e in self.get(path)["events"]]

    def test_list_order_and_collapsed_rows(self):
        """The list is severity then newest first, beacon variants are one row and the segmentation flows of one device
        are one '-> multiple devices (2)' row.
        REQ: OE-04, OE-03, OE-09, OE-17
        """
        body = self.get("/api/events/open?q=E2E&limit=20")
        ev = {e["eid"]: e for e in body["events"]}
        self.assertEqual([e["eid"] for e in body["events"]][:3], [TI, GW, SEG_B])
        beacon = ev[BEACON_2]
        self.assertNotIn(BEACON_1, ev)
        self.assertEqual((beacon["repeats"], beacon["members"]), (2, [BEACON_1, BEACON_2]))
        seg = ev[SEG_B]
        self.assertNotIn(SEG_A, ev)
        self.assertTrue(seg["label"].endswith("-> multiple devices (2)"), seg["label"])
        self.assertEqual(len(seg["children"]), 2)

    def test_filters(self):
        """type= (repeatable), sev= (any case) and q= filter the rows; counts and total stay unfiltered.
        REQ: OE-05, OE-17
        """
        self.assertEqual(self.eids("/api/events/open?type=gw&type=ti&q=E2E"), [TI, GW])
        self.assertEqual(self.eids("/api/events/open?sev=HIGH&q=e2e%20gateway"), [GW])
        body = self.get("/api/events/open?type=vuln&q=nothing-matches")
        self.assertEqual(body["events"], [])
        self.assertGreaterEqual(body["counts"].get("ids", 0), BULK + 1)
        self.assertGreaterEqual(body["total"], BULK + 5)

    def test_limit_default_and_cap(self):
        """Without limit at most 2000 rows come back; any larger limit is capped at 5000; limit=0 is the count only.
        REQ: OE-18
        """
        self.assertEqual(self.get("/api/events/open")["shown"], 2000)
        body = self.get("/api/events/open?limit=999999")
        self.assertEqual((body["shown"], len(body["events"])), (5000, 5000))
        body = self.get("/api/events/open?limit=0")
        self.assertEqual((body["events"], body["extra"]), ([], {}))
        self.assertGreaterEqual(body["total"], BULK + 5)

    def test_negative_limit_returns_no_rows(self):
        """A negative limit returns no rows (counts only), never rows beyond the 5000 cap.
        REQ: OE-18
        """
        self.assertEqual(self.get("/api/events/open?limit=-1")["shown"], 0)

    def test_non_numeric_limit_is_a_client_error(self):
        """A non-numeric limit is answered 400 (bad request), not 500.
        REQ: OE-18
        """
        code, _, _ = self.c.get("/api/events/open?limit=abc")
        self.assertEqual(code, 400)

    def test_check_off_and_restore_through_api(self):
        """Posting a row's check-off list hides it (total drops by one); unchecking restores it.
        REQ: OE-07, OE-17
        """
        row = next(e for e in self.get("/api/events/open?type=ids&q=E2E%20OE")["events"] if e["eid"] == IDS)
        self.assertEqual(row["acks"][0], {"type": "event", "key": IDS})
        before = self.get("/api/events/open?limit=0")["total"]
        items = [{**a, "label": row["label"]} for a in row["acks"]]
        self.assertEqual(self.c.post("/api/acks", {"items": items, "checked": True})[0], 200)
        try:
            self.assertNotIn(IDS, self.eids("/api/events/open?type=ids&q=E2E%20OE"))
            self.assertEqual(self.get("/api/events/open?limit=0")["total"], before - 1)
            self.assertIn(IDS, self.get("/api/acks").get("event", {}))
        finally:
            self.assertEqual(self.c.post("/api/acks", {"items": items, "checked": False})[0], 200)
        self.assertIn(IDS, self.eids("/api/events/open?type=ids&q=E2E%20OE"))

    def test_detail_window(self):
        """/detail lists both beacon variants newest first and their firings; no or an unknown id gives an empty answer.
        REQ: OE-12, OE-17
        """
        d = self.get("/api/events/detail?e=" + quote(BEACON_1))
        self.assertEqual([o["eid"] for o in d["occurrences"]], [BEACON_2, BEACON_1])
        self.assertEqual({f["eid"] for f in d["fires"]}, {BEACON_1, BEACON_2})
        self.assertEqual([r["id"] for r in d["by_event"].get(BEACON_1, [])], [GW])
        self.assertEqual(self.get("/api/events/detail"), {"occurrences": [], "related": []})
        self.assertEqual(self.get("/api/events/detail?e=" + "x" * 2000)["occurrences"], [])

    def test_inputs(self):
        """/inputs answers an empty determination list (LLM off) and an empty shape without an id.
        REQ: OE-13, OE-17
        """
        self.assertEqual(self.get("/api/events/inputs"), {"decisions": [], "events": {}})
        self.assertEqual(self.get("/api/events/inputs?e=" + quote(IDS))["decisions"], [])

    def test_related_and_member_cap(self):
        """/related returns stored links of the row's members; only the first 12 m= members are used.
        REQ: OE-11, OE-17
        """
        r = self.get(f"/api/events/related?e={quote(BEACON_2)}&m={quote(BEACON_1)}")
        self.assertEqual([x["id"] for x in r["related"]], [GW])
        self.assertEqual(r["events"][GW]["type"], "gw")
        many = "".join(f"&m=ids|filler{i}" for i in range(12)) + "&m=" + quote(BEACON_1)
        self.assertEqual(self.get(f"/api/events/related?e={quote(BEACON_2)}{many}")["related"], [])
        self.assertEqual(self.get("/api/events/related"), {"related": []})

    def test_roles(self):
        """Admins and defenders read every Open events endpoint; the User role gets 403 and no session gets 401.
        REQ: OE-14
        """
        name, pw = "e2e-oe-def", "defender-password-1"
        self.assertEqual(self.c.post("/api/users", {"action": "add", "username": name, "password": pw, "role": "defender"})[0], 200)
        uname, upw = "e2e-oe-user", "user-password-12345"
        self.assertEqual(self.c.post("/api/users", {"action": "add", "username": uname, "password": upw, "role": "user"})[0], 200)
        d, u, anon = self.srv.login(name, pw), self.srv.login(uname, upw), self.srv.client()
        for p in OE_PATHS:
            self.assertEqual(d.get(p)[0], 200, p)
            self.assertEqual(u.get(p)[0], 403, p)
            self.assertEqual(anon.get(p)[0], 401, p)


if __name__ == "__main__":
    unittest.main()
