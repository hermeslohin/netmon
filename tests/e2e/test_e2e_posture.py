"""E2E: the data behind Security -> Posture through the real server - snapshots and time ranges, suppress rules, check-offs, roles.

One server process for the module, seeded with two review runs (server-side input only: the page API refuses them) and three
collected time ranges that fill every Posture box: one per review-run window (RID_OLD, RID_DAY) and a 12-hour one (RID).
No host broker is configured, so anything that would need a new Elasticsearch collection fails cleanly instead of reaching out.
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
RID = "r20260105T0600Z-20260105T1800Z"  # ends after SID's review run -> base SID
RID_OLD = "r20260103T1200Z-20260104T1200Z"  # the same 24 h window as review run SID_OLD
RID_DAY = "r20260104T1200Z-20260105T1200Z"  # the same 24 h window as review run SID
PW = "posture-test-password-1"
SRV = None
SEED = f"RID, RID_OLD, RID_DAY = {RID!r}, {RID_OLD!r}, {RID_DAY!r}\n" + r'''
import os, fixtures as F, store
IP, EXT = F.IPS, F.EXT
data, rng = os.path.join(os.environ["NETMON_DIR"], "data"), os.path.join(os.environ["STATE_DIR"], "ranges")

def viol(src, dst, port, sev):
    return {"src": src, "dst": dst, "port": port, "proto": "tcp", "conns": 4, "answered": 4, "severity": sev, "reason": "zone policy"}

def posture(sid):
    raw, an = F.raw_snapshot(sid), F.analysis(sid)
    raw["hosts"] = {"findings": [{"key": "hnet-in|host-a|%s:22|%s" % (IP["server"], EXT["bad"]), "priority": "high", "text": "inbound SSH"}]}
    raw["alerts"]["signatures"].append({"name": "ET SCAN Test Probe", "count": 5, "severity": 2, "category": "Attempted Recon",
                                        "src": {IP["dmz"]: 5}, "dst": {IP["server"]: 5}})
    raw["alerts"]["total"] = 8
    raw["beacons"] = {"pairs_scored": 40, "candidates": [{"src": IP["camera"], "dst": EXT["bad"], "port": 443, "interval_s": 60,
                                                          "jitter_s": 1, "conns": 1400, "coverage_h": 23, "score": 0.97}]}
    raw["threat_intel"].update(feed_status={"feed-a": "ok"}, ip_hits_in=[{"ip": EXT["bad"], "feeds": ["feed-a"], "conns": 3,
                                                                          "targets": {IP["server"]: 3}, "ports": [22]}])
    raw["dns_tunnel"] = [{"domain": "tunnel.example", "score": 0.9, "queries": 900, "sources": {IP["phone"]: 900}}]
    raw["tls"]["malicious_ja3"] = [{"ja3": "0" * 32, "malware": "TestBot", "count": 2, "sources": {IP["camera"]: 2}}]
    raw["internal"]["scans"] = [{"src": IP["dmz"], "failed_conns": 300, "hosts": 30, "ports": 50}]
    raw["files"] = {"files": [{"mime": "application/x-dosexec", "receiver": IP["laptop"], "size": 1000}],
                    "software": [{"ip": IP["server"], "name": "OpenSSH", "version": "9.6"}], "pe_count": 1}
    an["violations"] = [viol(IP["dmz"], IP["server"], 22, "high"), viol(IP["camera"], IP["laptop"], 8080, "medium")]
    return raw, an

for sid in (F.SID_OLD, F.SID):
    raw, an = posture(sid)
    store.jdump(raw, os.path.join(data, sid + ".json"))
    store.jdump(an, os.path.join(data, sid + ".analysis.json"))

def seed_range(rid, sid, hours, findings=None):
    raw, an = posture(sid)
    s, e = ["%s-%s-%sT%s:%s:00+00:00" % (x[0:4], x[4:6], x[6:8], x[9:11], x[11:13]) for x in rid[1:].split("-")]
    raw.update(generated=e, hours=hours, range={"start": s, "end": e})
    if findings is not None:
        an["findings"] = findings
    store.jdump(raw, os.path.join(rng, "%s.json" % rid))
    store.jdump(an, os.path.join(rng, "%s.analysis.json" % rid))
    store.jdump({"id": rid, "start": s, "end": e, "generated": e, "hours": hours}, os.path.join(rng, "%s.meta.json" % rid))

seed_range(RID_OLD, F.SID_OLD, 24)
seed_range(RID_DAY, F.SID, 24)
seed_range(RID, F.SID, 12, [{"severity": "low", "device": IP["laptop"], "name": "Admin Laptop", "kind": "new-port", "detail": "range-only finding"}])
'''


def setUpModule():
    global SRV
    SRV = harness.Server(seed=SEED).__enter__()
    a = SRV.login()
    for name, role in (("pos-defender", "defender"), ("pos-user", "user")):
        code, body, _ = a.post("/api/users", {"action": "add", "username": name, "password": PW, "role": role})
        if code != 200:
            raise RuntimeError(f"add {name}: {code} {body}")


def tearDownModule():
    if SRV:
        SRV.__exit__(None, None, None)


def as_(name):
    return SRV.login(name, PW)


def flows(snap):
    return {(v["src"], v["dst"], v["port"]) for v in snap["analysis"]["violations"]}


def sigs(snap):
    return {s["name"] for s in snap["raw"]["alerts"]["signatures"]}


class PostureSnapshotApi(unittest.TestCase):
    """GET /api/snapshot serves what the Posture page renders, for time ranges only."""

    def test_time_range_has_every_posture_section(self):
        """GET /api/snapshot?id=<time range> returns the collected range with every Posture box's data.
        REQ: POS-01, POS-02"""
        c = SRV.login()
        code, s, _ = c.get("/api/snapshot?id=" + RID_DAY)
        self.assertEqual((code, s["id"], s["base"]), (200, RID_DAY, F.SID))
        raw, an = s["raw"], s["analysis"]
        self.assertTrue(an["findings"])
        self.assertTrue(all("last_seen" in f for f in an["findings"]))
        self.assertEqual(raw["hosts"]["findings"][0]["key"].split("|")[1], "host-a")
        self.assertEqual(sigs(s), {"ET INFO Test Signature", "ET SCAN Test Probe"})
        self.assertEqual(len(an["violations"]), 2)
        self.assertEqual(len(raw["beacons"]["candidates"]), 1)
        self.assertEqual(raw["threat_intel"]["feed_status"], {"feed-a": "ok"})
        self.assertEqual(len(raw["threat_intel"]["ip_hits_in"]), 1)
        self.assertEqual(raw["dns_tunnel"][0]["domain"], "tunnel.example")
        self.assertEqual(raw["tls"]["malicious_ja3"][0]["malware"], "TestBot")
        self.assertEqual(len(raw["internal"]["scans"]), 1)
        self.assertEqual((raw["files"]["pe_count"], raw["files"]["software"][0]["name"]), (1, "OpenSSH"))

    def test_review_runs_refused_and_unknown_ids(self):
        """There is no review-run list (/api/snapshots is 404); review-run ids (and 'latest') are refused with 'pick a time range';
        unknown, malformed or traversal ids are 404.
        REQ: POS-01"""
        c = SRV.login()
        self.assertEqual(c.get("/api/snapshots")[0], 404)
        for sid in ("latest", F.SID, F.SID_OLD):
            code, r, _ = c.get("/api/snapshot?id=" + sid)
            self.assertEqual(code, 404, sid)
            self.assertIn("pick a time range", r["error"], sid)
        for sid in ("2026-02-01T1200Z", "..%2Fstate%2Fusers", "r20260101T0000Z-20260101T0100Z", ""):
            self.assertEqual(c.get("/api/snapshot?id=" + sid)[0], 404, sid)

    def test_time_range_names_its_base_review_run(self):
        """A collected time range returns its own findings and names the review run (base) whose correlation it uses.
        REQ: POS-05, POS-06"""
        code, s, _ = SRV.login().get("/api/snapshot?id=" + RID)
        self.assertEqual((code, s["id"], s["base"]), (200, RID, F.SID))
        self.assertEqual(s["range"]["end"], "2026-01-05T18:00:00+00:00")
        self.assertEqual([f["detail"] for f in s["analysis"]["findings"]], ["range-only finding"])

    def test_range_sections(self):
        """GET /api/section slices an assembled range; unknown pieces are 404 and nothing reaches a host broker.
        REQ: POS-06"""
        c = SRV.login()
        code, b, _ = c.get(f"/api/section?id={RID}&name=beacons")
        self.assertEqual((code, b["beacons"]["pairs_scored"]), (200, 40))
        self.assertEqual(c.get(f"/api/section?id={RID}&name=nosuch")[0], 404)
        self.assertEqual(c.get(f"/api/section?id={F.SID}&name=beacons")[0], 404)

    def test_range_request(self):
        """POST /api/range: every window, even one matching a review run, needs the host broker (400 here, none configured).
        REQ: POS-04"""
        c = SRV.login()
        for body in ({"start": "2026-01-03T12:05:00Z", "end": "2026-01-04T12:05:00Z"}, {"start": "2026-01-03T00:00:00Z", "end": "2026-01-03T06:00:00Z"}):
            code, r, _ = c.post("/api/range", body)
            self.assertEqual(code, 400, body)
            self.assertIn("broker", r["error"], body)
            self.assertNotIn("snapshot", r, body)
        code, r, _ = c.post("/api/range", {"start": "2026-01-03T06:00:00Z", "end": "2026-01-03T00:00:00Z"})
        self.assertEqual((code, r["error"]), (400, "the end must be after the start"))


class PostureSuppressApi(unittest.TestCase):
    """Suppress rules posted from Posture hide rows in every time range until removed."""

    def test_seg_suppress_hides_everywhere_then_restores(self):
        """A segmentation suppress rule hides the flow in every time range; removing it brings the flow back.
        REQ: POS-07, POS-10"""
        c = SRV.login()
        flow = (IP["dmz"], IP["server"], 22)
        code, r, _ = c.post("/api/llm/review-limits", {"seg_suppress": {"src": IP["dmz"], "dst": IP["server"], "ports": "22"}})
        self.assertEqual(code, 200, r)
        rid = r["seg_rules"][-1]["id"]
        try:
            for sid in (RID_OLD, RID_DAY, RID):
                s = c.get("/api/snapshot?id=" + sid)[1]
                self.assertNotIn(flow, flows(s), sid)
                self.assertIn((IP["camera"], IP["laptop"], 8080), flows(s), sid)
                self.assertNotIn("segmentation", [f["kind"] for f in s["analysis"]["findings"]], sid)
        finally:
            code, r, _ = c.post("/api/llm/review-limits", {"unseg_suppress": rid})
        self.assertEqual((code, r["seg_rules"]), (200, []))
        self.assertIn(flow, flows(c.get("/api/snapshot?id=" + RID_DAY)[1]))

    def test_ids_suppress_hides_everywhere_then_restores(self):
        """An IDS suppress rule (glob) hides the signature and its count in every time range; removing it restores them.
        REQ: POS-09, POS-10"""
        c = SRV.login()
        code, r, _ = as_("pos-defender").post("/api/llm/review-limits", {"ids_suppress": {"sig": "ET SCAN *"}})
        self.assertEqual(code, 200, r)
        rid = r["ids_rules"][-1]["id"]
        try:
            for sid in (RID_OLD, RID_DAY, RID):
                s = c.get("/api/snapshot?id=" + sid)[1]
                self.assertEqual(sigs(s), {"ET INFO Test Signature"}, sid)
                self.assertEqual(s["raw"]["alerts"]["total"], 3, sid)
            self.assertEqual([x["sig"] for x in c.get("/api/suppress")[1]["ids_rules"]], ["ET SCAN *"])
        finally:
            c.post("/api/llm/review-limits", {"unids_suppress": rid})
        self.assertEqual(c.get("/api/snapshot?id=" + RID_DAY)[1]["raw"]["alerts"]["total"], 8)

    def test_bad_suppress_rules_rejected(self):
        """Suppress rules that are empty or would hide everything are refused with 400 and nothing is stored.
        REQ: POS-20"""
        c = SRV.login()
        for body in ({"seg_suppress": {"src": "*", "dst": "", "ports": ""}}, {"seg_suppress": {"src": "", "dst": "", "ports": "99999"}},
                     {"seg_suppress": {"src": " ", "dst": "", "ports": ""}}, {"ids_suppress": {"sig": "**"}}):
            code, r, _ = c.post("/api/llm/review-limits", body)
            self.assertEqual(code, 400, body)
            self.assertIn("error", r)
        s = c.get("/api/suppress")[1]
        self.assertEqual((s["seg_rules"], s["ids_rules"]), ([], []))


class PostureCheckOffApi(unittest.TestCase):
    """Check-offs made on Posture are shared by every time range."""

    def test_check_off_persists_across_ranges(self):
        """A check-off stays checked whichever time range is loaded, and the row stays in the data for 'show N checked'.
        REQ: POS-12"""
        c = SRV.login()
        key = f"{IP['camera']}|{EXT['bad']}|443"
        code, acks, _ = c.post("/api/acks", {"type": "beacon", "key": key, "checked": True, "label": "Beacon"})
        self.assertEqual(code, 200)
        try:
            for sid in (RID_OLD, RID, RID_DAY):
                s = c.get("/api/snapshot?id=" + sid)[1]
                self.assertEqual(len(s["raw"]["beacons"]["candidates"]), 1, sid)
                self.assertIn(key, c.get("/api/acks")[1]["beacon"], sid)
            self.assertEqual(c.get("/api/acks")[1]["beacon"][key]["label"], "Beacon")
        finally:
            c.post("/api/acks", {"type": "beacon", "key": key, "checked": False})
        self.assertNotIn(key, c.get("/api/acks")[1].get("beacon", {}))

    def test_cleared_segmentation_shared(self):
        """Clearing a segmentation flow (ack type 'seg', bulk form) is visible to every account and does not filter the time range.
        REQ: POS-11, POS-12"""
        a, d = SRV.login(), as_("pos-defender")
        key = f"{F.mac(4)}|{IP['server']}|22"
        code, _, _ = d.post("/api/acks", {"items": [{"type": "seg", "key": key, "label": "DMZ to server SSH"}], "checked": True})
        self.assertEqual(code, 200)
        try:
            self.assertIn(key, a.get("/api/acks")[1]["seg"])
            self.assertIn((IP["dmz"], IP["server"], 22), flows(a.get("/api/snapshot?id=" + RID)[1]))
        finally:
            a.post("/api/acks", {"type": "seg", "key": key, "checked": False})

    def test_ack_needs_type_and_key(self):
        """A check-off without a type or key is a 400.
        REQ: POS-12"""
        self.assertEqual(SRV.login().post("/api/acks", {"type": "beacon", "checked": True})[0], 400)


class PostureRoles(unittest.TestCase):
    """Who may read Posture data and change check-offs or suppress rules."""

    def test_user_role_cannot_read_or_change_posture(self):
        """A User gets 403 for time ranges, sections, check-offs and suppress rules, and nothing is changed.
        REQ: POS-19"""
        u = as_("pos-user")
        for p in (f"/api/snapshot?id={RID}", f"/api/section?id={RID}&name=beacons", "/api/acks", "/api/suppress"):
            self.assertEqual(u.get(p)[0], 403, p)
        for p, b in (("/api/acks", {"type": "beacon", "key": "x|y|1", "checked": True}),
                     ("/api/llm/review-limits", {"seg_suppress": {"src": IP["dmz"]}}),
                     ("/api/llm/review-limits", {"ids_suppress": {"sig": "ET INFO Test Signature"}}),
                     ("/api/range", {"start": "2026-01-03T12:00:00Z", "end": "2026-01-04T12:00:00Z"})):
            self.assertEqual(u.post(p, b)[0], 403, p)
        a = SRV.login()
        self.assertNotIn("x|y|1", a.get("/api/acks")[1].get("beacon", {}))
        s = a.get("/api/suppress")[1]
        self.assertEqual((s["seg_rules"], s["ids_rules"]), ([], []))

    def test_defender_reads_and_edits(self):
        """A Network defender reads Posture data and may add and remove suppress rules (can_edit).
        REQ: POS-19"""
        d = as_("pos-defender")
        self.assertEqual(d.get("/api/snapshot?id=" + RID)[0], 200)
        self.assertTrue(d.get("/api/suppress")[1]["can_edit"])
        code, r, _ = d.post("/api/llm/review-limits", {"seg_suppress": {"dst": IP["laptop"], "ports": "8080"}})
        self.assertEqual(code, 200, r)
        code, r, _ = d.post("/api/llm/review-limits", {"unseg_suppress": r["seg_rules"][-1]["id"]})
        self.assertEqual((code, r["seg_rules"]), (200, []))


if __name__ == "__main__":
    unittest.main()
