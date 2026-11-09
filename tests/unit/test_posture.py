"""Unit tests for the data behind Security -> Posture (dashboard view 'security'): snapshots, time ranges, suppress filters, cleared segmentation, check-offs and the app.js check-off logic."""
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); import _env  # noqa: E401,E702,E402

import copy  # noqa: E402
import datetime as dt  # noqa: E402
import json  # noqa: E402
import re  # noqa: E402
import shutil  # noqa: E402
import subprocess  # noqa: E402
import unittest  # noqa: E402

import fixtures as F  # noqa: E402
import corr_llm  # noqa: E402
import risk  # noqa: E402
import server  # noqa: E402
import store  # noqa: E402

IP = F.IPS
NET = IP["dmz"].rsplit(".", 1)[0]          # the DMZ /24 prefix, for glob rules ("<prefix>.*")
RID = "r20260105T0600Z-20260105T1800Z"     # a range ending after SID (2026-01-05 12:00) -> base SID
RID_GAP = "r20260104T1300Z-20260104T1400Z"  # no nightly report ends inside it -> the one before it (SID_OLD)
RID_EARLY = "r20260101T0000Z-20260101T0600Z"  # before every nightly report -> the oldest one
NODE = shutil.which("node")
APP_JS = os.path.join(_env.APP, "static", "app.js")


def _iso(rid_part):
    """'20260105T0600Z' -> '2026-01-05T06:00:00+00:00'."""
    return dt.datetime.strptime(rid_part, "%Y%m%dT%H%MZ").replace(tzinfo=dt.timezone.utc).isoformat()


def host_findings():
    """Endpoint findings in the shape hosts.py writes (raw.hosts.findings): key '<kind>|<host>|...'."""
    return [{"key": f"hnet-in|host-a|{IP['server']}:22|{F.EXT['bad']}", "priority": "high", "text": "inbound SSH from a listed IP"},
            {"key": "acct-new|host-b|svc-user", "priority": "medium", "text": "new local account svc-user"}]


def violation(src, dst, port, sev="high"):
    return {"src": src, "dst": dst, "port": port, "proto": "tcp", "conns": 4, "answered": 4, "severity": sev, "reason": "dmz -> protected"}


def seed_posture(sid=F.SID, extra_find=None):
    """A nightly snapshot with every Posture section filled in (host findings, violations, beacons, TI, tunnel, JA3, files)."""
    raw = F.raw_snapshot(sid)
    raw["hosts"] = {"findings": host_findings()}
    raw["alerts"]["signatures"].append({"name": "ET SCAN Test Probe", "count": 5, "severity": 2, "category": "Attempted Recon",
                                        "src": {IP["dmz"]: 3, IP["phone"]: 2}, "dst": {IP["server"]: 5}})
    raw["alerts"]["total"] = 8
    raw["beacons"] = {"pairs_scored": 40, "candidates": [{"src": IP["camera"], "dst": F.EXT["bad"], "port": 443, "interval_s": 60,
                                                          "jitter_s": 1, "conns": 1400, "coverage_h": 23, "score": 0.97}]}
    raw["threat_intel"].update(feed_status={"feed-a": "ok"}, feed_sizes={"feed-a": 1000},
                               ip_hits_in=[{"ip": F.EXT["bad"], "feeds": ["feed-a"], "conns": 3, "targets": {IP["server"]: 3}, "ports": [22]}],
                               ip_hits_out=[{"ip": F.EXT["bad"], "sources": {IP["laptop"]: 1}}],
                               domain_hits=[{"domain": "bad.example", "sources": {IP["laptop"]: 2}}])
    raw["dns_tunnel"] = [{"domain": "Tunnel.Example", "score": 0.9, "queries": 900, "unique_subdomains": 800, "entropy": 4.1,
                          "nxdomain": 10, "sources": {IP["phone"]: 900}}]
    raw["tls"]["malicious_ja3"] = [{"ja3": "0" * 32, "malware": "TestBot", "count": 2, "sources": {IP["camera"]: 2}, "servers": [F.EXT["bad"]]}]
    raw["internal"]["scans"] = [{"src": IP["dmz"], "failed_conns": 300, "hosts": 30, "ports": 50, "top_ports": [22, 445]}]
    raw["files"] = {"files": [{"time": raw["generated"], "mime": "application/x-dosexec", "receiver": IP["laptop"], "host": "dl.example",
                               "size": 1000, "mhr_detect_pct": 0}], "software": [{"ip": IP["server"], "name": "OpenSSH", "version": "9.6",
                                                                                   "type": "server", "unparsed": "OpenSSH_9.6"}], "pe_count": 1}
    raw["notices"], raw["weird"] = [{"note": "SSL::Invalid_Server_Cert", "count": 2}], [{"name": "bad_TCP_checksum", "count": 9, "src": {IP["laptop"]: 9}}]
    an = F.analysis(sid)
    an["violations"] = [violation(IP["dmz"], IP["server"], 22), violation(IP["camera"], IP["laptop"], 8080, "medium")]
    if extra_find:
        an["findings"].append(extra_find)
    store.jdump(raw, os.path.join(server.DATA, sid + ".json"))
    store.jdump(an, os.path.join(server.DATA, sid + ".analysis.json"))
    return raw, an


def seed_range(rid, findings=None):
    """A fully collected time range (ranges/<rid>.json + .analysis.json) as host_broker writes it (generated = range end)."""
    s, e = rid[1:].split("-")
    raw = F.raw_snapshot(F.SID)
    raw.update(generated=_iso(e), hours=12, range={"start": _iso(s), "end": _iso(e)})
    an = F.analysis(F.SID)
    an["findings"] = findings if findings is not None else [{"severity": "low", "device": IP["laptop"], "name": "Admin Laptop",
                                                             "kind": "new-port", "detail": "range-only finding"}]
    an["violations"] = [violation(IP["dmz"], IP["server"], 22)]
    store.jdump(raw, os.path.join(server.RANGES, rid + ".json"))
    store.jdump(an, os.path.join(server.RANGES, rid + ".analysis.json"))
    return raw, an


def reset():
    _env.fresh_db()
    server._cache.clear()
    server._MAC2IP.update(sid=None, v={})
    server._fseen.update(sig=None, val={})


class PostureSnapshotLoad(unittest.TestCase):
    """Loading a nightly snapshot and the Posture sections it carries."""

    def setUp(self):
        reset()

    def test_snapshot_returns_raw_and_companions(self):
        """snapshot() returns the raw collection plus its analysis and sources companions (None when absent).
        REQ: POS-01"""
        raw, an = seed_posture()
        res = server.snapshot(F.SID)
        self.assertEqual(res["id"], F.SID)
        self.assertEqual(res["raw"]["generated"], raw["generated"])
        self.assertEqual(len(res["analysis"]["findings"]), len(an["findings"]))
        self.assertIsNone(res["sources"])

    def test_snapshot_rejects_bad_ids(self):
        """snapshot() returns None for a missing snapshot, a malformed id or a path-traversal id.
        REQ: POS-01"""
        seed_posture()
        for sid in ("2026-01-09T1200Z", "latest", "../state/users", F.SID + "/../x", "", None, "r2026-bad"):
            self.assertIsNone(server.snapshot(sid), sid)

    def test_snapshots_list_ordered_with_companions(self):
        """snapshots() lists only well-formed nightly ids, oldest first, with the companions each one has.
        REQ: POS-01"""
        seed_posture(F.SID)
        F.seed_snapshot(F.SID_OLD, with_analysis=False)
        store.jdump({"x": 1}, os.path.join(server.DATA, "notasnapshot.json"))
        s = server.snapshots()
        self.assertEqual([x["id"] for x in s], [F.SID_OLD, F.SID])
        self.assertEqual(s[0]["has"], [])
        self.assertEqual(s[1]["has"], ["analysis"])

    def test_every_posture_section_present(self):
        """The snapshot holds the data of every Posture box: baseline/host findings, IDS, violations, beacons, TI, tunnel, JA3/scans, files/software.
        REQ: POS-02"""
        seed_posture()
        res = server.snapshot(F.SID)
        raw, an = res["raw"], res["analysis"]
        self.assertTrue([f for f in an["findings"] if f["kind"] != "segmentation"])
        self.assertEqual([f["key"] for f in raw["hosts"]["findings"]], [f["key"] for f in host_findings()])
        self.assertEqual({s["name"] for s in raw["alerts"]["signatures"]}, {"ET INFO Test Signature", "ET SCAN Test Probe"})
        self.assertEqual(len(an["violations"]), 2)
        self.assertEqual(raw["beacons"]["candidates"][0]["port"], 443)
        self.assertEqual(raw["beacons"]["pairs_scored"], 40)
        ti = raw["threat_intel"]
        self.assertEqual(ti["feed_status"], {"feed-a": "ok"})
        for k in ("ip_hits_in", "ip_hits_out", "domain_hits", "new_domains"):
            self.assertIsInstance(ti[k], list, k)
        self.assertEqual(raw["dns_tunnel"][0]["domain"], "Tunnel.Example")
        self.assertEqual(raw["tls"]["malicious_ja3"][0]["malware"], "TestBot")
        self.assertEqual(raw["internal"]["scans"][0]["src"], IP["dmz"])
        self.assertEqual(raw["files"]["pe_count"], 1)
        self.assertEqual(raw["files"]["software"][0]["name"], "OpenSSH")
        self.assertTrue(raw["notices"] and raw["weird"])

    def test_findings_get_last_seen(self):
        """Baseline and host findings carry last_seen: the newest nightly report that contained them, else the snapshot's own time.
        REQ: POS-13"""
        old_only = {"severity": "low", "device": IP["laptop"], "name": "Admin Laptop", "kind": "new-asn", "detail": "only in old"}
        raw_old, _ = seed_posture(F.SID_OLD, extra_find=old_only)
        raw_new, _ = seed_posture(F.SID)
        new = server.snapshot(F.SID)
        for f in new["analysis"]["findings"]:
            self.assertEqual(f["last_seen"], raw_new["generated"])
        for f in new["raw"]["hosts"]["findings"]:
            self.assertEqual(f["last_seen"], raw_new["generated"])
        old = server.snapshot(F.SID_OLD)
        ls = {f["detail"]: f["last_seen"] for f in old["analysis"]["findings"]}
        self.assertEqual(ls["only in old"], raw_old["generated"])
        self.assertEqual(ls["uploaded 3x the baseline"], raw_new["generated"])  # seen again in the newer report


class TimeRangeSemantics(unittest.TestCase):
    """Nightly windows vs arbitrary time ranges and which nightly report a range follows."""

    def setUp(self):
        reset()
        self._broker = corr_llm.broker
        self.calls = []

    def tearDown(self):
        corr_llm.broker = self._broker

    def stub_broker(self, result=None, exc=None, write=None):
        def fake(path, body=None, timeout=330):
            self.calls.append((path, body))
            if write:
                store.jdump(*write)
            if exc:
                raise exc
            return result or {}
        corr_llm.broker = fake

    def test_snap_window(self):
        """snap_window gives (generated - hours, generated); hours default to 24; None when the snapshot or its time is missing.
        REQ: POS-03"""
        seed_posture()
        s, e = server.snap_window(F.SID)
        self.assertEqual(e.isoformat(), "2026-01-05T12:00:00+00:00")
        self.assertEqual(e - s, dt.timedelta(hours=24))
        raw = F.raw_snapshot(F.SID_OLD)
        raw.pop("hours")
        store.jdump(raw, os.path.join(server.DATA, F.SID_OLD + ".json"))
        server._cache.clear()
        s, e = server.snap_window(F.SID_OLD)
        self.assertEqual(e - s, dt.timedelta(hours=24))
        raw["generated"] = "not a time"
        store.jdump(raw, os.path.join(server.DATA, F.SID_OLD + ".json"))
        server._cache.clear()
        self.assertIsNone(server.snap_window(F.SID_OLD))
        self.assertIsNone(server.snap_window("2026-02-01T1200Z"))

    def test_range_matching_nightly_window_uses_snapshot(self):
        """A start/end within 10 minutes of a nightly window loads that snapshot without asking the host broker.
        REQ: POS-04"""
        seed_posture()
        self.stub_broker(exc=AssertionError("broker must not be called"))
        res, code = server.range_request({"start": "2026-01-04T12:09:00Z", "end": "2026-01-05T11:51:00+00:00"})
        self.assertEqual((code, res), (200, {"id": F.SID, "status": "done", "snapshot": True}))
        self.assertEqual(self.calls, [])

    def test_arbitrary_range_goes_to_broker(self):
        """Any other window is handed to the host broker (/range) with UTC ISO times and its answer returned.
        REQ: POS-04"""
        seed_posture()
        self.stub_broker(result={"id": RID, "status": "sections"})
        res, code = server.range_request({"start": "2026-01-04T12:11:00Z", "end": "2026-01-05T12:00:00Z"})
        self.assertEqual((code, res["id"]), (200, RID))
        self.assertEqual(self.calls, [("/range", {"start": "2026-01-04T12:11:00+00:00", "end": "2026-01-05T12:00:00+00:00"})])

    def test_range_request_validation(self):
        """Times without a UTC offset, unparsable times or an end not after the start are 400; a broker error is a 400 with its message.
        REQ: POS-04"""
        self.stub_broker(exc=RuntimeError("broker: the range must be at least 15 minutes"))
        for body in ({"start": "2026-01-04T12:00:00", "end": "2026-01-05T12:00:00"}, {"start": "yesterday", "end": "today"}, {},
                     {"start": "2026-01-05T12:00:00Z", "end": "2026-01-05T12:00:00Z"}, {"start": "2026-01-05T13:00:00Z", "end": "2026-01-05T12:00:00Z"}):
            res, code = server.range_request(body)
            self.assertEqual(code, 400, body)
            self.assertIn("error", res)
        self.assertEqual(self.calls, [])
        res, code = server.range_request({"start": "2026-01-05T12:00:00Z", "end": "2026-01-05T12:05:00Z"})
        self.assertEqual((code, res["error"]), (400, "the range must be at least 15 minutes"))

    def test_base_snapshot_picks_newest_report_ending_by_range_end(self):
        """base_snapshot: the newest nightly generated at or before the end; inclusive; the oldest when none is; None without snapshots.
        REQ: POS-05"""
        self.assertIsNone(server.base_snapshot("2026-01-05T12:00:00+00:00"))
        seed_posture(F.SID_OLD)
        seed_posture(F.SID)
        self.assertEqual(server.base_snapshot("2026-01-05T18:00:00+00:00"), F.SID)
        self.assertEqual(server.base_snapshot("2026-01-05T12:00:00+00:00"), F.SID)  # ends exactly at the range end
        self.assertEqual(server.base_snapshot("2026-01-05T11:59:00+00:00"), F.SID_OLD)
        self.assertEqual(server.base_snapshot("2026-01-01T06:00:00+00:00"), F.SID_OLD)  # nothing before: the oldest
        self.assertEqual(server.base_snapshot(None), F.SID_OLD)

    def test_range_snapshot_follows_nightly_report(self):
        """A collected range shows its own findings; base (AI triage / alarms) and sources come from the nightly report by its end.
        REQ: POS-05, POS-06"""
        seed_posture(F.SID_OLD)
        seed_posture(F.SID)
        store.jdump({"src": "from SID"}, os.path.join(server.DATA, F.SID + ".sources.json"))
        seed_range(RID)
        seed_range(RID_GAP)
        seed_range(RID_EARLY)
        r = server.snapshot(RID)
        self.assertEqual((r["id"], r["base"], r["range"]["end"]), (RID, F.SID, "2026-01-05T18:00:00+00:00"))
        self.assertEqual([f["detail"] for f in r["analysis"]["findings"]], ["range-only finding"])
        self.assertEqual(r["sources"], {"src": "from SID"})
        self.assertEqual(server.snapshot(RID_GAP)["base"], F.SID_OLD)
        self.assertEqual(server.snapshot(RID_EARLY)["base"], F.SID_OLD)
        self.assertEqual(server.resolve_sid(RID), F.SID)
        self.assertEqual(server.resolve_sid(F.SID_OLD), F.SID_OLD)

    def test_range_snapshot_needs_raw_and_analysis(self):
        """A range without its analysis (still collecting) is not a snapshot; the page gets the skeleton instead.
        REQ: POS-06"""
        seed_posture()
        raw, _ = seed_range(RID)
        store.jdelete(os.path.join(server.RANGES, RID + ".analysis.json"))
        server._cache.clear()
        self.assertIsNone(server.snapshot(RID))
        self.assertIsNone(server.range_skeleton(RID))  # no meta either
        meta = {"id": RID, "start": raw["range"]["start"], "end": raw["range"]["end"], "generated": raw["range"]["end"], "hours": 12}
        store.jdump(meta, os.path.join(server.RANGES, RID + ".meta.json"))
        sk = server.range_skeleton(RID)
        self.assertEqual((sk["base"], sk["pending"]), (F.SID, server.SECTION_NAMES))
        self.assertEqual(sk["raw"]["range"], {"start": meta["start"], "end": meta["end"]})
        self.assertEqual(sk["raw"]["beacons"], {})
        self.assertEqual(sk["raw"]["dns_tunnel"], [])
        self.assertEqual(sk["analysis"], {})
        sk["raw"]["dns_tunnel"].append(1)  # placeholders are fresh copies, never the shared defaults
        self.assertEqual(server.SECTION_DEFAULTS["dns_tunnel"], [])

    def test_range_section_slices_or_asks_broker(self):
        """range_section slices an assembled range without the broker, asks the broker for a missing piece, rejects unknown names.
        REQ: POS-06"""
        seed_posture()
        raw, _ = seed_range(RID)
        store.jdump({"id": RID, "start": raw["range"]["start"], "end": raw["range"]["end"], "generated": raw["range"]["end"], "hours": 12},
                    os.path.join(server.RANGES, RID + ".meta.json"))
        self.stub_broker(exc=AssertionError("broker must not be called"))
        self.assertEqual(server.range_section(RID, "beacons"), {"beacons": raw["beacons"]})
        self.assertEqual(set(server.range_section(RID, "notices")), {"notices", "weird"})
        self.assertIsNone(server.range_section(RID, "secrets"))
        self.assertIsNone(server.range_section("r20260101T0000Z-20260101T0100Z", "beacons"))
        store.jdelete(os.path.join(server.RANGES, RID + ".json"))
        server._cache.clear()
        p = os.path.join(server.RANGES, RID + ".sec.files.json")
        self.stub_broker(write=({"files": {"files": [], "software": [], "pe_count": 0}}, p))
        self.assertEqual(server.range_section(RID, "files")["files"]["pe_count"], 0)
        self.assertEqual(self.calls, [("/section", {"id": RID, "name": "files"})])


class SuppressRulesHideEverywhere(unittest.TestCase):
    """Segmentation and IDS suppress rules hide matching rows from every snapshot and range."""

    def setUp(self):
        reset()

    def test_seg_filter_hides_violations_and_findings(self):
        """seg_filter drops the violations and segmentation findings a rule covers, keeps the rest and never changes its input.
        REQ: POS-07"""
        _, an = seed_posture()
        self.assertIs(server.seg_filter(an), an)  # no rules: untouched
        store.seg_suppress_add(IP["dmz"], "", "22", "t")
        before = copy.deepcopy(an)
        out = server.seg_filter(an)
        self.assertEqual(an, before)
        self.assertEqual([(v["src"], v["port"]) for v in out["violations"]], [(IP["camera"], 8080)])
        self.assertNotIn("segmentation", [f["kind"] for f in out["findings"]])
        self.assertEqual(len(out["findings"]), len(an["findings"]) - 1)
        self.assertIsNone(server.seg_filter(None))

    def test_seg_filter_rule_by_ip_hides_mac_keyed_finding(self):
        """A rule on a source IP also hides a segmentation finding keyed by that device's MAC (MAC -> IP from the newest snapshot).
        REQ: POS-08"""
        mac_find = {"severity": "high", "device": F.mac(4).upper(), "name": "DMZ Game Box", "kind": "segmentation",
                    "detail": f"DMZ Game Box -> Admin Laptop ({IP['laptop']}) 3389/tcp"}
        _, an = seed_posture(extra_find=mac_find)
        store.seg_suppress_add(NET + ".*", IP["laptop"], "3389", "t")
        kept = [f["detail"] for f in server.seg_filter(an)["findings"]]
        self.assertNotIn(mac_find["detail"], kept)
        self.assertIn(an["findings"][0]["detail"], kept)  # port 22 to the server: not covered

    def test_snapshot_applies_suppress_rules_without_touching_store(self):
        """snapshot() applies segmentation and IDS suppress rules; the stored documents stay complete and removing the rules restores the rows.
        REQ: POS-07, POS-09"""
        seed_posture()
        sr = store.seg_suppress_add("", IP["server"], "", "t")
        ir = store.ids_suppress_add("ET SCAN *", "", "t")
        res = server.snapshot(F.SID)
        self.assertEqual([v["dst"] for v in res["analysis"]["violations"]], [IP["laptop"]])
        self.assertEqual([s["name"] for s in res["raw"]["alerts"]["signatures"]], ["ET INFO Test Signature"])
        self.assertEqual(res["raw"]["alerts"]["total"], 3)
        self.assertEqual(len(store.jload(os.path.join(server.DATA, F.SID + ".analysis.json"))["violations"]), 2)
        self.assertEqual(len(store.jload(os.path.join(server.DATA, F.SID + ".json"))["alerts"]["signatures"]), 2)
        store.seg_suppress_remove(sr)
        store.ids_suppress_remove(ir)
        res = server.snapshot(F.SID)
        self.assertEqual(len(res["analysis"]["violations"]), 2)
        self.assertEqual(res["raw"]["alerts"]["total"], 8)

    def test_ids_host_rule_strips_only_that_host(self):
        """An IDS rule with a host strips that host's share of the signature in the snapshot and lowers the counts.
        REQ: POS-09"""
        seed_posture()
        store.ids_suppress_add("ET SCAN Test Probe", IP["dmz"], "t")
        sg = {s["name"]: s for s in server.snapshot(F.SID)["raw"]["alerts"]["signatures"]}
        self.assertEqual(sg["ET SCAN Test Probe"]["src"], {IP["phone"]: 2})
        self.assertEqual(sg["ET SCAN Test Probe"]["count"], 5)  # dst side still holds 5: count = max(src, dst)

    def test_rules_apply_to_every_range(self):
        """Suppress rules are not time based: the same rule hides the row in a nightly snapshot and in a collected range.
        REQ: POS-10"""
        seed_posture(F.SID_OLD)
        seed_posture(F.SID)
        seed_range(RID)
        store.seg_suppress_add(IP["dmz"], IP["server"], "22", "t")
        store.ids_suppress_add("ET INFO Test Signature", "", "t")
        for sid in (F.SID_OLD, F.SID, RID):
            res = server.snapshot(sid)
            self.assertNotIn((IP["dmz"], IP["server"], 22), [(v["src"], v["dst"], v["port"]) for v in res["analysis"]["violations"]], sid)
            self.assertNotIn("ET INFO Test Signature", [s["name"] for s in res["raw"]["alerts"]["signatures"]], sid)

    def test_filter_failure_keeps_snapshot(self):
        """A failing suppress filter is logged and the snapshot is still served unfiltered.
        REQ: POS-07"""
        seed_posture()
        orig = store.seg_suppress_list
        store.seg_suppress_list = lambda c=None: (_ for _ in ()).throw(RuntimeError("db gone"))
        try:
            res = server.snapshot(F.SID)
        finally:
            store.seg_suppress_list = orig
        self.assertEqual(len(res["analysis"]["violations"]), 2)


class ClearedSegmentation(unittest.TestCase):
    """with_cleared / ClearedSet: cleared flows and segmentation suppress rules as one set."""

    def setUp(self):
        reset()

    def test_cleared_set_membership(self):
        """ClearedSet holds cleared flow keys, covers rule-matched flows (MAC sources via mac2ip) and rejects malformed keys.
        REQ: POS-11"""
        cs = server.ClearedSet({f"{F.mac(1)}|{IP['server']}|22"})
        self.assertIn(f"{F.mac(1)}|{IP['server']}|22", cs)
        self.assertNotIn(f"{IP['laptop']}|{IP['server']}|22", cs)
        cs.rules = [{"src": IP["laptop"], "dst": "", "ports": "445"}]
        cs.mac2ip = {F.mac(1): IP["laptop"]}
        self.assertIn(f"{IP['laptop']}|{IP['server']}|445", cs)
        self.assertIn(f"{F.mac(1).upper()}|{IP['server']}|445", cs)  # MAC form, any case, mapped to the IP
        self.assertNotIn(f"{IP['laptop']}|{IP['server']}|22", cs)
        for bad in ("a|b", f"{IP['laptop']}|{IP['server']}|445|x", 42, None):
            self.assertNotIn(bad, cs)

    def test_with_cleared_combines_acks_and_rules(self):
        """with_cleared copies the policy and adds _cleared_seg from 'seg' check-offs, suppress rules and the newest MAC -> IP map.
        REQ: POS-11"""
        seed_posture()
        store.ack_set("seg", f"{F.mac(4)}|{IP['server']}|22", True, label="DMZ to server SSH")
        store.ack_set("finding", "not-a-flow", True)
        store.seg_suppress_add("", IP["laptop"], "8080", "t")
        pol = {"zones": {}}
        out = server.with_cleared(pol)
        self.assertNotIn("_cleared_seg", pol)
        cs = out["_cleared_seg"]
        self.assertEqual(set(cs), {f"{F.mac(4)}|{IP['server']}|22"})
        self.assertIn(f"{F.mac(3)}|{IP['laptop']}|8080", cs)  # camera MAC -> its IP, covered by the rule
        self.assertNotIn(f"{F.mac(3)}|{IP['laptop']}|80", cs)
        self.assertTrue(risk.seg_is_cleared(cs, IP["dmz"], IP["server"], 22, server.snapshot(F.SID)["raw"]["devices"]))
        self.assertEqual(server.with_cleared(None)["_cleared_seg"], cs)

    def test_with_cleared_survives_store_failure(self):
        """When the check-off store fails, with_cleared returns the policy without a cleared set instead of raising.
        REQ: POS-11"""
        orig = store.acks_load
        store.acks_load = lambda c=None: (_ for _ in ()).throw(RuntimeError("locked"))
        try:
            out = server.with_cleared({"a": 1})
        finally:
            store.acks_load = orig
        self.assertEqual(out, {"a": 1})


class CheckOffsRangeIndependent(unittest.TestCase):
    """Check-offs are stored once and apply to every snapshot and range."""

    def setUp(self):
        reset()

    def test_check_off_independent_of_loaded_range(self):
        """write_ack stores {type: {key: at/note/label/by}} with no snapshot or range attached; read_acks is the same whatever is loaded.
        REQ: POS-12"""
        seed_posture(F.SID_OLD)
        seed_posture(F.SID)
        seed_range(RID)
        server.write_ack("beacon", f"{IP['camera']}|{F.EXT['bad']}|443", True, "update check", "Beacon")
        server.write_ack("dnstunnel", "tunnel.example", True)
        acks = []
        for sid in (F.SID_OLD, RID, F.SID):
            server.snapshot(sid)
            acks.append(server.read_acks())
        self.assertEqual(acks[0], acks[1])
        self.assertEqual(acks[1], acks[2])
        b = acks[0]["beacon"][f"{IP['camera']}|{F.EXT['bad']}|443"]
        self.assertEqual(set(b), {"at", "note", "label", "by"})
        self.assertEqual((b["note"], b["label"]), ("update check", "Beacon"))
        out = server.write_ack("dnstunnel", "tunnel.example", False)
        self.assertNotIn("tunnel.example", out.get("dnstunnel", {}))

    def test_check_off_does_not_filter_server_side(self):
        """Checked-off rows stay in the snapshot data (the page hides them, 'show N checked' brings them back); only suppress rules filter.
        REQ: POS-12"""
        seed_posture()
        server.write_ack("seg", f"{IP['dmz']}|{IP['server']}|22", True)
        server.write_ack("host", host_findings()[0]["key"], True)
        res = server.snapshot(F.SID)
        self.assertEqual(len(res["analysis"]["violations"]), 2)
        self.assertEqual(len(res["raw"]["hosts"]["findings"]), 2)


# ------------------------------------------------------------------ app.js check-off logic, run under node
def _app_js():
    with open(APP_JS, encoding="utf-8") as f:
        return f.read()


def _js_slice(src, start_pat, end_pat):
    i = src.index(start_pat)
    return src[i:src.index(end_pat, i)]


def run_js(body):
    """Run `body` after the check-off block of app.js (fnv .. ackSplit) and the host-finding column helpers; returns its printed JSON."""
    src = _app_js()
    ack = _js_slice(src, "/* ---------- check-off (acknowledge) ---------- */", "const ackCol")
    hf = _js_slice(src, "const hfHost = ", "function hfToRow")
    pre = ("var document = {addEventListener() {}}, window = {};\n"
           "var S = {acks: {}, showAcked: {}, snap: {raw: {devices: {}}, analysis: {findings: []}}};\n"
           "var HQ = ''; const hq = () => new URLSearchParams(HQ);\n"
           "const esc = (s) => String(s); const linkifyIps = (s) => String(s); const ft = (s) => String(s);\n"
           "const hostLink = (h) => `<host ${h}>`; const entries = (o) => Object.entries(o || {});\n")
    r = subprocess.run([NODE, "-"], input=pre + ack + "\n" + hf + "\n" + body, capture_output=True, text=True, timeout=30)  # noqa: S603 - node on repo files
    if r.returncode:
        raise RuntimeError(r.stderr[-2000:])
    return json.loads(r.stdout)


@unittest.skipUnless(NODE, "node not installed")
class PostureAckLogicJs(unittest.TestCase):
    """app.js ackSplit / acked / ACK keys / segmentation keys / host-finding columns, executed under node."""

    def test_ack_split(self):
        """ackSplit splits rows into open and checked, shows only open ones unless the section shows checked (or ?ev=), and offers a toggle.
        REQ: POS-14"""
        out = run_js("""
const rows = [{src: 'a', dst: 'b', port: 1}, {src: 'a', dst: 'c', port: 2}, {src: 'x', dst: 'y', port: 3}];
S.acks = {beacon: {'a|c|2': {at: 't'}}};
const r1 = ackSplit('beacon', rows, 'sec-beacon');
S.showAcked['sec-beacon'] = true; const r2 = ackSplit('beacon', rows, 'sec-beacon');
S.showAcked = {}; HQ = 'ev=1'; const r3 = ackSplit('beacon', rows, 'sec-beacon');
HQ = ''; S.acks = {}; const r4 = ackSplit('beacon', rows, 'sec-beacon');
const p = (r) => ({open: r.open.map((x) => x.port), done: r.done.map((x) => x.port), show: r.show.map((x) => x.port), toggle: r.toggle});
console.log(JSON.stringify([p(r1), p(r2), p(r3), p(r4)]));""")
        self.assertEqual(out[0]["open"], [1, 3])
        self.assertEqual(out[0]["done"], [2])
        self.assertEqual(out[0]["show"], [1, 3])
        self.assertIn("show 1 checked", out[0]["toggle"])
        self.assertIn('data-s="sec-beacon"', out[0]["toggle"])
        self.assertEqual(out[1]["show"], [1, 3, 2])
        self.assertIn("hide 1 checked", out[1]["toggle"])
        self.assertEqual(out[2]["show"], [1, 3, 2])
        self.assertEqual((out[3]["done"], out[3]["toggle"]), ([], ""))

    def test_ack_keys(self):
        """Check-off keys: finding = fnv(device|kind|detail) (same as Python), host = finding key, beacon = src|dst|port, DNS tunnel = lower-case domain.
        REQ: POS-15"""
        import correlate
        f = {"device": IP["phone"], "kind": "upload-spike", "detail": "uploaded 3x the baseline"}
        hfk = host_findings()[0]["key"]
        out = run_js(f"""
const f = {json.dumps(f)};
S.acks = {{finding: {{[ACK.finding(f)]: {{at: 't'}}}}, host: {{{json.dumps(hfk)}: {{at: 't'}}}}, dnstunnel: {{'tunnel.example': {{at: 't'}}}}}};
console.log(JSON.stringify({{finding: ACK.finding(f), host: ACK.host({{key: {json.dumps(hfk)}}}), beacon: ACK.beacon({{src: 'a', dst: 'b', port: 443}}),
  tun: ACK.dnstunnel({{domain: 'Tunnel.Example'}}), af: acked('finding', f), ah: acked('host', {{key: {json.dumps(hfk)}}}),
  at: acked('dnstunnel', {{domain: 'TUNNEL.example'}}), other: acked('finding', Object.assign({{}}, f, {{detail: 'x'}}))}}));""")
        self.assertEqual(out["finding"], correlate.fnv(f"{f['device']}|{f['kind']}|{f['detail']}"))
        self.assertEqual((out["host"], out["beacon"], out["tun"]), (hfk, "a|b|443", "tunnel.example"))
        self.assertEqual((out["af"], out["ah"], out["at"], out["other"]), (True, True, True, False))

    def test_segmentation_flow_keys(self):
        """Violations, segmentation findings and seg| Fix-list items share the 'seg' flow key; MAC and IP forms of one flow both count as cleared.
        REQ: POS-16"""
        seg_find = F.analysis()["findings"][0]
        out = run_js(f"""
S.snap.raw.devices = {{{json.dumps(IP['dmz'])}: {{mac: {json.dumps(F.mac(4).upper())}}}}};
const v = {{src: {json.dumps(IP['dmz'])}, dst: {json.dumps(IP['server'])}, port: 22}};
const fresh = segKey('violation', v);
S.acks = {{seg: {{[`${{v.src}}|${{v.dst}}|22`]: {{at: 't'}}}}}};
const ipForm = [segKey('violation', v), acked('violation', v)];
S.acks = {{seg: {{[fresh]: {{at: 't'}}}}}};
console.log(JSON.stringify({{fresh, ipForm, macAcked: acked('violation', v), ref: ackRef('violation', v),
  find: segKey('finding', {json.dumps(seg_find)}), iss: segKey('issue', {{key: 'seg|AA:BB|' + v.dst + '|22|x'}}), plain: segKey('issue', {{key: 'tls|x'}}),
  other: acked('violation', {{src: v.src, dst: v.dst, port: 23}})}}));""")
        self.assertEqual(out["fresh"], f"{F.mac(4)}|{IP['server']}|22")  # MAC form follows the device through DHCP changes
        self.assertEqual(out["ipForm"], [f"{IP['dmz']}|{IP['server']}|22", True])  # an existing IP-form clear is reused
        self.assertTrue(out["macAcked"])
        self.assertEqual(out["ref"], ["seg", f"{F.mac(4)}|{IP['server']}|22"])
        self.assertEqual(out["find"], risk.seg_key_finding(seg_find))
        self.assertEqual(out["iss"], f"aa:bb|{IP['server']}|22")
        self.assertIsNone(out["plain"])
        self.assertFalse(out["other"])

    def test_base_findings_exclude_segmentation(self):
        """Baseline findings leave out segmentation findings (own box) and resolve a MAC-keyed device to its Host IP.
        REQ: POS-17"""
        an = F.analysis()
        out = run_js(f"""
S.snap.raw.devices = {{{json.dumps(IP['camera'])}: {{mac: {json.dumps(F.mac(3))}}}}};
console.log(JSON.stringify(baseFind({json.dumps(an)}).map((f) => [f.kind, f.host_ip])));""")
        self.assertEqual(out, [["new-country", IP["camera"]], ["upload-spike", IP["phone"]]])

    def test_host_finding_host_and_to_columns(self):
        """Host findings: Host is the second key part; To is the remote side for outbound, this host:port with the source for inbound, empty otherwise.
        REQ: POS-18"""
        out = run_js(f"""
const k = {json.dumps(host_findings()[0]['key'])};
console.log(JSON.stringify({{host: hfHost('hf|' + k), host2: hfHost('acct-new|host-b|svc-user'), none: hfHost(''),
  inb: hfTo(k, ''), out: hfTo('hnet-proc|host-a|curl|' + {json.dumps(F.EXT['cdn'])} + ':443', ''),
  nn: hfTo('net-new|host-a|x|' + {json.dumps(F.EXT['cdn'])} + ',' + {json.dumps(F.EXT['bad'])}, ''),
  af: hfTo('authfail|host-a|' + {json.dumps(F.EXT['bad'])}, ''), acct: hfTo('acct-new|host-b|svc-user', '')}}));""")
        self.assertEqual((out["host"], out["host2"], out["none"]), ("host-a", "host-b", ""))
        self.assertTrue(out["inb"].startswith("<host host-a>"))
        self.assertIn(":22", out["inb"])
        self.assertIn(f"from {F.EXT['bad']}", out["inb"])
        self.assertEqual(out["out"], f"{F.EXT['cdn']}:443")
        self.assertEqual(out["nn"], f"{F.EXT['cdn']}, {F.EXT['bad']}")
        self.assertIn(f"from {F.EXT['bad']}", out["af"])
        self.assertEqual(out["acct"], "")

    def test_posture_view_renders_sections_in_order(self):
        """The Posture view (V.security) builds its boxes from the snapshot sections this file checks, in the documented order.
        REQ: POS-02"""
        src = _app_js()
        body = _js_slice(src, "V.security = (el) => {", "/* ----- Traffic ----- */")
        titles = ["<h1>Posture</h1>", "Baseline findings", "Host findings", "IDS signatures (", "Segmentation violations", "Beacon candidates",
                  "Threat-intel feeds", "Inbound hits from listed IPs", "Outbound TI hits", "DNS-tunnel scoring",
                  "Malicious JA3 / internal scans / detections", "Zeek notices", "Zeek weird", "Files (", "Software inventory from traffic"]
        pos = [body.find(t) for t in titles]
        self.assertNotIn(-1, pos, dict(zip(titles, pos)))
        self.assertEqual(pos, sorted(pos))
        for data in ("an.violations", "raw.beacons?.candidates", "raw.dns_tunnel", "raw.tls?.malicious_ja3", "raw.internal?.scans",
                     "raw.files?.software", "ti.ip_hits_in", "S.snap.raw.hosts"):
            self.assertIn(data, body)
        self.assertTrue(re.search(r"V\.security = \(el, a\) => \{ sec\(el, a\); gatewaySecurity\(el\); \}", src))


if __name__ == "__main__":
    unittest.main()
