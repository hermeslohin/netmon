"""E2E: the data behind Network -> Network map and Network -> Traffic map through the real server - snapshot internal
flows / zone matrix / UniFi summary, registry zones and names, history trend, time-range sections, static scripts, roles.

One server process for the class, seeded with two nightly snapshots, a collected time range, the zone policy, the device
registry and two history records. No host broker and no UniFi key, so nothing reaches out.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import _env  # noqa: E402,F401
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness  # noqa: E402
import fixtures as F  # noqa: E402

IP, EXT = F.IPS, F.EXT
RID = "r20260105T0600Z-20260105T1800Z"
PW = "network-test-password-1"
MATRIX = {"user -> servers": {"conns": 100, "bytes": 5000, "ports": {"22/tcp": 60, "443/tcp": 40}},
          "iot -> user": {"conns": 25, "bytes": 10, "ports": {"80/tcp": 25}}}
SEED = f"RID = {RID!r}\nMATRIX = {MATRIX!r}\n" + r'''
import os, fixtures as F, store
IP, EXT = F.IPS, F.EXT
root = os.environ["NETMON_DIR"]
data, rng = os.path.join(root, "data"), os.path.join(os.environ["STATE_DIR"], "ranges")

def net_raw(sid, conns):
    raw = F.raw_snapshot(sid)
    raw["internal"] = {"matrix": MATRIX, "scans": [],
                       "flows": [F.flow(IP["laptop"], IP["server"], 22, conns=conns, src_zone="user", dst_zone="servers", service="ssh"),
                                 F.flow(IP["camera"], IP["laptop"], 80, conns=25, src_zone="iot", dst_zone="user")]}
    raw["unifi"] = {"health": {"isp": "Example ISP", "status": {"wan": "ok"}, "latency_ms": 9},
                    "clients": {"online": 3, "known_total": 7, "by_network": {"Main": 2, "IoT": 1},
                                "not_in_inventory": [{"ip": "10.0.9.70", "mac": F.mac(9), "name": "UniFi Box"}]},
                    "flows": {"total": 40, "actions": {"blocked": 6}, "blocked_by_policy": {"Block IoT": 6}}}
    return raw

for sid, n in ((F.SID_OLD, 30), (F.SID, 60)):
    store.jdump(net_raw(sid, n), os.path.join(data, sid + ".json"))
    store.jdump(F.analysis(sid), os.path.join(data, sid + ".analysis.json"))
s, e = "2026-01-05T06:00:00+00:00", "2026-01-05T18:00:00+00:00"
raw = net_raw(F.SID, 7)
raw.update(generated=e, hours=12, range={"start": s, "end": e})
store.jdump(raw, os.path.join(rng, RID + ".json"))
store.jdump(F.analysis(F.SID), os.path.join(rng, RID + ".analysis.json"))
store.jdump({"id": RID, "start": s, "end": e, "generated": e, "hours": 12}, os.path.join(rng, RID + ".meta.json"))
store.jdump(F.zone_policy(device_classes={F.mac(2): "server"}), os.path.join(root, "policy.json"))
store.jdump({"names": {"10.0.2.1": "core gw"}, "signatures": []}, os.path.join(root, "known_benign.json"))
store.registry_save({F.mac(2): {"mac": F.mac(2), "name": "Lab Server", "ips": [IP["server"]], "known": True,
                                "first_seen": "2026-01-01", "last_seen": "2026-01-05"}})
for gen, n in (("2026-01-04T12:00:00+00:00", 2), ("2026-01-05T12:00:00+00:00", 3)):
    store.history_append({"generated": gen, "hours": 24, "totals": {"conns": n}, "signatures": {},
                          "devices": {IP["laptop"]: {"ip": IP["laptop"], "name": "Admin Laptop", "total": 100 * n, "ext_out": n, "conns": n}}})
'''


class NetworkPagesE2E(unittest.TestCase):
    """Network map and Traffic map APIs, scripts and role checks against one real server."""

    @classmethod
    def setUpClass(cls):
        cls.srv = harness.Server(seed=SEED).__enter__()
        cls.admin = cls.srv.login()
        for name, role in (("e2e-defender", "defender"), ("e2e-user", "user")):
            code, body, _ = cls.admin.post("/api/users", {"action": "add", "username": name, "password": PW, "role": role})
            if code != 200:
                raise AssertionError((name, code, body))

    @classmethod
    def tearDownClass(cls):
        cls.srv.__exit__(None, None, None)

    def test_snapshot_network_data(self):
        """/api/snapshot?id=latest returns the newest snapshot's internal flows, zone matrix and UniFi summary unchanged.
        REQ: NET-24, NET-03, NET-20"""
        code, body, _ = self.admin.get("/api/snapshot?id=latest")
        self.assertEqual(code, 200)
        self.assertEqual(body["id"], F.SID)
        raw = body["raw"]
        self.assertEqual(raw["internal"]["matrix"], MATRIX)
        self.assertEqual([(f["src"], f["dst"], f["conns"], f["src_zone"]) for f in raw["internal"]["flows"]],
                         [(IP["laptop"], IP["server"], 60, "user"), (IP["camera"], IP["laptop"], 25, "iot")])
        self.assertEqual(raw["unifi"]["clients"]["by_network"], {"Main": 2, "IoT": 1})
        self.assertEqual(raw["unifi"]["health"]["isp"], "Example ISP")
        self.assertIn(IP["laptop"], raw["inventory_ips"])
        old = self.admin.get("/api/snapshot?id=" + F.SID_OLD)[1]["raw"]["internal"]["flows"][0]["conns"]
        self.assertEqual(old, 30)

    def test_range_sections(self):
        """A collected time range serves its 'internal' and 'unifi' sections from the stored range; unknown sections or ranges are 404.
        REQ: NET-24"""
        code, body, _ = self.admin.get(f"/api/section?id={RID}&name=internal")
        self.assertEqual(code, 200)
        self.assertEqual(list(body), ["internal"])
        self.assertEqual(body["internal"]["flows"][0]["conns"], 7)
        code, body, _ = self.admin.get(f"/api/section?id={RID}&name=unifi")
        self.assertEqual((code, body["unifi"]["flows"]["total"]), (200, 40))
        self.assertEqual(self.admin.get(f"/api/section?id={RID}&name=bogus")[0], 404)
        self.assertEqual(self.admin.get("/api/section?id=r20250101T0000Z-20250101T0100Z&name=internal")[0], 404)
        self.assertEqual(self.admin.get(f"/api/snapshot?id={RID}")[1]["raw"]["internal"]["matrix"], MATRIX)

    def test_registry_and_history(self):
        """/api/registry carries the zones, device classes, known-benign names and devices; /api/history the compact trend, oldest first.
        REQ: NET-07, NET-08"""
        code, reg, _ = self.admin.get("/api/registry")
        self.assertEqual(code, 200)
        self.assertEqual(reg["policy"]["zones"], F.zone_policy()["zones"])
        self.assertEqual(reg["policy"]["device_classes"], {F.mac(2): "server"})
        self.assertEqual(reg["known_benign"]["names"], {"10.0.2.1": "core gw"})
        self.assertEqual(reg["devices_seen"][F.mac(2)]["ips"], [IP["server"]])
        code, hist, _ = self.admin.get("/api/history")
        self.assertEqual(code, 200)
        self.assertEqual([h["generated"] for h in hist], ["2026-01-04T12:00:00+00:00", "2026-01-05T12:00:00+00:00"])
        self.assertEqual(hist[1]["devices"][IP["laptop"]]["total"], 300)

    def test_pages_and_scripts(self):
        """The dashboard links both pages in the Network menu and serves netmap.js and app.js with the view code.
        REQ: NET-22"""
        code, html, _ = self.admin.get("/", raw=True)
        self.assertEqual(code, 200)
        html = html.decode() if isinstance(html, bytes) else html
        self.assertIn('href="#/netmap"', html)
        self.assertIn('href="#/traffic"', html)
        self.assertIn('src="/netmap.js?v=', html)
        for path, needle in (("/netmap.js", "V.netmap = "), ("/app.js", "V.traffic = "), ("/app.js", "function historyNetwork")):
            code, js, _ = self.admin.get(path, raw=True)
            self.assertEqual(code, 200, path)
            self.assertIn(needle, js.decode() if isinstance(js, bytes) else js)

    def test_roles(self):
        """A User gets 403 on every API the Network pages load; a Network defender and an admin can read them.
        REQ: NET-23"""
        paths = ("/api/snapshot?id=latest", "/api/registry", "/api/history", f"/api/section?id={RID}&name=internal", "/api/risk", "/api/issues")
        u, d = self.srv.login("e2e-user", PW), self.srv.login("e2e-defender", PW)
        for p in paths:
            self.assertEqual(u.get(p)[0], 403, p)
            self.assertEqual(d.get(p)[0], 200, p)
            self.assertEqual(self.admin.get(p)[0], 200, p)
        self.assertEqual(harness.Client("127.0.0.1", self.srv.port).get("/api/registry")[0], 401)


if __name__ == "__main__":
    unittest.main()
