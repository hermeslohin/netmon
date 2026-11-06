"""E2E: Network -> Lateral movement through the real server - GET /api/lateral for a seeded snapshot, roles, the p= period path
against a stub host broker on loopback, and clearing a segmentation flow.

One server process for the class, seeded with one nightly snapshot, a zone policy and two pre-collected 'lateral' range
sections. The host broker is a tiny HTTP server in this process that maps a period start to one of those section ids.
"""
import http.server
import json
import os
import sys
import threading
import unittest
from urllib.parse import quote

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import _env  # noqa: E402,F401
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness  # noqa: E402
import fixtures as F  # noqa: E402

IP = F.IPS
A, B, C, D = IP["laptop"], IP["server"], IP["camera"], IP["dmz"]
PW = "lateral-test-password-1"
KEY = "lateral-test-broker-key"
R1, R2 = "r20260101T0000Z-20260101T0600Z", "r20260102T0000Z-20260102T0600Z"
P1, P2, P_DOWN = ("2026-01-01T00:00:00Z", "2026-01-01T06:00:00Z"), ("2026-01-02T00:00:00Z", "2026-01-02T06:00:00Z"), \
    ("2026-01-03T00:00:00Z", "2026-01-03T06:00:00Z")
SEED = f"R1, R2 = {R1!r}, {R2!r}\n" + r'''
import os, fixtures as F, store
IP = F.IPS
A, B, C, D = IP["laptop"], IP["server"], IP["camera"], IP["dmz"]
data, rng = os.path.join(os.environ["NETMON_DIR"], "data"), os.path.join(os.environ["STATE_DIR"], "ranges")

def viol(src, dst, port, conns=4):
    return {"src": src, "dst": dst, "port": port, "proto": "tcp", "conns": conns, "answered": conns, "severity": "high", "reason": "dmz -> protected"}

store.cfg_save("policy", F.zone_policy(allow=[{"src": A, "dst": B, "ports": [22], "why": "admin laptop"}]))
raw, an = F.raw_snapshot(F.SID), F.analysis(F.SID)
raw["internal"]["flows"] = [F.flow(A, B, 22, conns=3), F.flow(D, B, 22, conns=4), F.flow(A, C, 80, conns=2),
                            F.flow(C, B, 3389, conns=6, answered=0)]
raw["admin_access"]["logins"] = [F.login(D, B, False, count=12, user="root")]
an["violations"] = [viol(D, B, 22)]
store.jdump(raw, os.path.join(data, F.SID + ".json"))
store.jdump(an, os.path.join(data, F.SID + ".analysis.json"))
# two periods queried "from Elasticsearch": the broker answers with these section ids
store.jdump({"internal": {"flows": [F.flow(D, B, 22, conns=2)]}, "violations": [viol(D, B, 22, 2)],
             "admin_access": {"logins": [F.login(D, B, False, count=5, user="root")]}}, os.path.join(rng, R1 + ".sec.lateral.json"))
store.jdump({"internal": {"flows": [F.flow(D, B, 22, conns=5), F.flow(C, A, 8080, conns=7)]},
             "admin_access": {"logins": [F.login(D, B, False, count=1, user="root")]}}, os.path.join(rng, R2 + ".sec.lateral.json"))
'''

CALLS = []


class Broker(http.server.BaseHTTPRequestHandler):
    """Stub host broker: /range maps a known period start to its section id; anything else is an Elasticsearch error."""

    def do_POST(self):  # noqa: N802 - http.server API
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
        CALLS.append((self.path, body, self.headers.get("Authorization")))
        ids = {"2026-01-01T00:00:00+00:00": R1, "2026-01-02T00:00:00+00:00": R2}
        if self.headers.get("Authorization") != f"Bearer {KEY}":
            code, out = 401, {"error": "bad key"}
        elif self.path == "/range" and body.get("start") in ids:
            code, out = 200, {"id": ids[body["start"]]}
        elif self.path == "/section":
            code, out = 200, {"status": "done"}
        else:
            code, out = 500, {"error": "Elasticsearch unreachable"}
        data = json.dumps(out).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):
        pass


def edge(g, s, t):
    return next((e for e in g["edges"] if e["src"] == s and e["dst"] == t), None)


def pq(*periods):
    return "&p=" + quote(",".join(f"{s}~{e}" for s, e in periods), safe="")


class LateralApiE2E(unittest.TestCase):
    """GET /api/lateral end to end: snapshot graph, roles, multi-period path, cleared flows."""

    @classmethod
    def setUpClass(cls):
        cls.broker = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Broker)
        threading.Thread(target=cls.broker.serve_forever, daemon=True).start()
        url = f"http://127.0.0.1:{cls.broker.server_address[1]}"
        cls.srv = harness.Server(seed=SEED, NETMON_BROKER_URL=url, NETMON_BROKER_KEY=KEY).__enter__()
        cls.admin = cls.srv.login()
        for name, role in (("lat-defender", "defender"), ("lat-user", "user")):
            code, body, _ = cls.admin.post("/api/users", {"action": "add", "username": name, "password": PW, "role": role})
            if code != 200:
                raise RuntimeError(f"add {name}: {code} {body}")

    @classmethod
    def tearDownClass(cls):
        cls.srv.__exit__(None, None, None)
        cls.broker.shutdown()
        cls.broker.server_close()

    def setUp(self):
        CALLS.clear()

    def test_snapshot_graph(self):
        """/api/lateral?id=<snapshot> (and id=latest) returns the snapshot's graph rated with the stored zone policy and allow rules.
        REQ: LAT-30"""
        code, g, _ = self.admin.get("/api/lateral?id=" + F.SID)
        self.assertEqual(code, 200)
        self.assertEqual(self.admin.get("/api/lateral?id=latest")[1]["edges"], g["edges"])
        self.assertEqual({(e["src"], e["dst"]): e["level"] for e in g["edges"]},
                         {(D, B): "high", (C, B): "medium", (A, B): "allowed-admin", (A, C): "normal"})
        self.assertEqual(edge(g, D, B)["auth_fail"], 12)
        self.assertEqual({n["id"]: n["name"] for n in g["nodes"]}[A], "Admin Laptop")
        self.assertEqual(g["counts"]["high"], 1)
        self.assertEqual([(s["src"], s["dst"], s["level"]) for s in g["admin"]], [(D, B, "high")])
        self.assertEqual(CALLS, [])  # a nightly snapshot never asks the broker

    def test_unknown_snapshot_404(self):
        """An unknown or path-like snapshot id is a 404.
        REQ: LAT-30"""
        self.assertEqual(self.admin.get("/api/lateral?id=2020-01-01T0000Z")[0], 404)
        self.assertEqual(self.admin.get("/api/lateral?id=" + quote("../../etc/passwd", safe=""))[0], 404)

    def test_roles(self):
        """Admins and network defenders read the Lateral movement data; a User gets 403 and an anonymous caller 401.
        REQ: LAT-31"""
        d = self.srv.login("lat-defender", PW)
        self.assertEqual(d.get("/api/lateral?id=" + F.SID)[0], 200)
        self.assertEqual(d.get("/api/lateral?id=" + F.SID + pq(P1))[0], 200)
        u = self.srv.login("lat-user", PW)
        self.assertEqual(u.get("/api/lateral?id=" + F.SID)[0], 403)
        self.assertEqual(u.get("/api/lateral?id=" + F.SID + pq(P1))[0], 403)
        self.assertEqual(self.srv.client().get("/api/lateral?id=" + F.SID)[0], 401)
        self.assertEqual(len([c for c in CALLS if c[0] == "/range"]), 1)  # only the defender's request reached the broker

    def test_periods_merged(self):
        """p=<start~end,...> queries each period through the broker and serves one merged graph: counts added, worst level kept.
        REQ: LAT-29, LAT-30"""
        code, g, _ = self.admin.get("/api/lateral?id=" + F.SID + pq(P1, P2))
        self.assertEqual(code, 200, g)
        e = edge(g, D, B)
        self.assertEqual((e["level"], e["conns"], e["auth_fail"]), ("high", 7, 6))
        self.assertIsNotNone(edge(g, C, A))            # only in the second period
        self.assertIsNone(edge(g, A, C))               # only in the nightly snapshot, not in the periods
        self.assertEqual(sorted((p, b.get("start") or b.get("id")) for p, b, _ in CALLS),
                         [("/range", "2026-01-01T00:00:00+00:00"), ("/range", "2026-01-02T00:00:00+00:00"), ("/section", R1), ("/section", R2)])
        self.assertTrue(all(auth == f"Bearer {KEY}" for _, _, auth in CALLS))

    def test_bad_periods_400(self):
        """Malformed periods, a period without a UTC offset, or a broker/Elasticsearch error give a clean 400 with a message.
        REQ: LAT-29, LAT-30"""
        base = "/api/lateral?id=" + F.SID
        code, body, _ = self.admin.get(base + pq(("2026-01-01T00:00:00", "2026-01-01T06:00:00")))
        self.assertEqual((code, body["error"]), (400, "each period needs an ISO start and end with a UTC offset"))
        self.assertEqual(self.admin.get(base + "&p=garbage")[0], 400)
        code, body, _ = self.admin.get(base + pq(P1, P_DOWN))
        self.assertEqual((code, body["error"]), (400, "Elasticsearch unreachable"))

    def test_clearing_a_flow_marks_it_allowed(self):
        """Clearing a segmentation flow (check-off type 'seg') shows it as allowed on /api/lateral; unclearing brings the level back.
        REQ: LAT-23, LAT-30"""
        key = f"{D}|{B}|22"
        try:
            self.assertEqual(self.admin.post("/api/acks", {"type": "seg", "key": key, "checked": True, "label": "Segmentation: test"})[0], 200)
            g = self.admin.get("/api/lateral?id=" + F.SID)[1]
            p22 = next(p for p in edge(g, D, B)["ports"] if p["port"] == 22)
            self.assertEqual((p22["level"], p22["why"]), ("allowed-admin", "segmentation flow cleared by a user"))
            self.assertEqual(edge(g, D, B)["level"], "high")  # the 12 failed root logins still rate the link high
            gp = self.admin.get("/api/lateral?id=" + F.SID + pq(P2))[1]
            self.assertEqual(next(p for p in edge(gp, D, B)["ports"] if p["port"] == 22)["level"], "allowed-admin")  # periods too
        finally:
            self.admin.post("/api/acks", {"type": "seg", "key": key, "checked": False})
        g = self.admin.get("/api/lateral?id=" + F.SID)[1]
        self.assertEqual(next(p for p in edge(g, D, B)["ports"] if p["port"] == 22)["level"], "high")


if __name__ == "__main__":
    unittest.main()
