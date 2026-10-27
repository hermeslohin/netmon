"""Unit tests for dashboard/app/issues.py (per-snapshot Fix-list checks and cross-snapshot tracking)."""
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); import _env  # noqa: E401,E702,E402

import copy  # noqa: E402
import unittest  # noqa: E402

import fixtures as F  # noqa: E402
import issues  # noqa: E402

IP = F.IPS


def raw_with(**extra):
    raw = F.raw_snapshot()
    raw.update(extra)
    return raw


def snap(sid, raw, an=None, gen=None):
    return (sid, gen or sid, raw, an)


class _CleanIP2MAC(unittest.TestCase):
    """Base: issues.IP2MAC is module state; empty it around each test."""

    def setUp(self):
        saved = dict(issues.IP2MAC)
        issues.IP2MAC.clear()
        self.addCleanup(lambda: (issues.IP2MAC.clear(), issues.IP2MAC.update(saved)))


class RawChecksTests(_CleanIP2MAC):
    """check_snapshot(): checks driven by raw device data."""

    def test_plaintext_services_flagged(self):
        """Outbound Telnet/FTP use creates a medium 'plain|<mac>|<svc>' issue; encrypted services do not.
        REQ: ISS-01"""
        raw = raw_with()
        raw["devices"][IP["laptop"]]["services_out"] = {"telnet": {"conns": 7}, "ftp": {"conns": 2}, "ssl": {"conns": 40}}
        out = issues.check_snapshot(raw, None)
        k = f"plain|{F.mac(1)}|telnet"
        self.assertIn(k, out)
        self.assertIn(f"plain|{F.mac(1)}|ftp", out)
        self.assertNotIn(f"plain|{F.mac(1)}|ssl", out)
        i = out[k]
        self.assertEqual((i["severity"], i["category"], i["source"]), ("medium", "Security suggestion", "raw"))
        self.assertEqual(i["title"], "Plaintext protocol: Telnet")
        self.assertEqual(i["evidence"], "7 conns")
        self.assertEqual(i["ip"], IP["laptop"])
        self.assertEqual(i["target"], "Admin Laptop")
        self.assertEqual(i["dev"], F.mac(1))

    def test_all_plaintext_protocols_known(self):
        """Every catalogued plaintext protocol (telnet, ftp, tftp, snmp, irc, pop3) is detected.
        REQ: ISS-01"""
        raw = raw_with()
        raw["devices"][IP["phone"]]["services_out"] = {s: {"conns": 1} for s in issues.PLAINTEXT_SVCS}
        out = issues.check_snapshot(raw, None)
        self.assertEqual({k.split("|")[2] for k in out if k.startswith("plain|")},
                         {"telnet", "ftp", "tftp", "snmp", "irc", "pop3"})

    def test_fixture_snapshot_is_clean(self):
        """The baseline synthetic snapshot (no plaintext, no legacy TLS) produces no device issues.
        REQ: ISS-01"""
        out = issues.check_snapshot(F.raw_snapshot(), None)
        self.assertEqual(out, {})

    def test_legacy_tls_flagged(self):
        """SSLv3/TLS 1.0/1.1 use creates a low 'tls-legacy' issue listing only the legacy versions.
        REQ: ISS-01"""
        raw = raw_with(tls={"devices": {IP["camera"]: {"versions": {"TLSv10": 4, "TLSv12": 90, "SSLv3": 1}},
                                        IP["phone"]: {"versions": {"TLSv12": 9, "TLSv13": 30}}}})
        out = issues.check_snapshot(raw, None)
        i = out[f"tls-legacy|{F.mac(3)}"]
        self.assertEqual(i["severity"], "low")
        self.assertEqual(i["evidence"], "TLSv10 ×4, SSLv3 ×1")
        self.assertNotIn(f"tls-legacy|{F.mac(5)}", out)

    def test_legacy_tls_regex_exact(self):
        """The legacy TLS matcher accepts exactly SSLv2/SSLv3/TLSv10/TLSv11.
        REQ: ISS-01"""
        for v in ("SSLv2", "SSLv3", "TLSv10", "TLSv11"):
            self.assertTrue(issues.LEGACY_TLS.match(v), v)
        for v in ("TLSv12", "TLSv13", "TLSv100", "xTLSv10", "DTLSv10"):
            self.assertFalse(issues.LEGACY_TLS.match(v), v)

    def test_external_dns_severity_threshold(self):
        """Hard-coded external resolvers: medium above 50 queries, low otherwise; evidence sorted by count.
        REQ: ISS-01"""
        raw = raw_with()
        raw["devices"][IP["laptop"]]["dns"] = {"external_resolvers": {F.EXT["dns"]: 40, F.EXT["cdn"]: 11}}
        raw["devices"][IP["phone"]]["dns"] = {"external_resolvers": {F.EXT["dns"]: 50}}
        out = issues.check_snapshot(raw, None)
        self.assertEqual(out[f"dns-ext|{F.mac(1)}"]["severity"], "medium")
        self.assertEqual(out[f"dns-ext|{F.mac(1)}"]["evidence"], f"{F.EXT['dns']} ×40, {F.EXT['cdn']} ×11")
        self.assertEqual(out[f"dns-ext|{F.mac(5)}"]["severity"], "low")

    def test_doh_flagged_low(self):
        """DNS-over-HTTPS use creates a low 'doh' issue.
        REQ: ISS-01"""
        raw = raw_with()
        raw["devices"][IP["phone"]]["dns"] = {"doh": {"dns.example": 3}}
        self.assertEqual(issues.check_snapshot(raw, None)[f"doh|{F.mac(5)}"]["severity"], "low")

    def test_key_falls_back_to_ip_without_mac(self):
        """A device without a MAC is keyed by IP; with a MAC learned in IP2MAC the MAC is used.
        REQ: ISS-01, RISK-03"""
        raw = raw_with()
        del raw["devices"][IP["phone"]]["mac"]
        raw["devices"][IP["phone"]]["services_out"] = {"telnet": {"conns": 1}}
        self.assertIn(f"plain|{IP['phone']}|telnet", issues.check_snapshot(raw, None))
        issues.IP2MAC[IP["phone"]] = F.mac(55)
        self.assertIn(f"plain|{F.mac(55)}|telnet", issues.check_snapshot(raw, None))

    def test_capture_loss_levels(self):
        """Capture loss: none at <=2%, medium above 2% (or on a CaptureLoss notice), high above 20%.
        REQ: ISS-01"""
        def sev(missed, notices=()):
            out = issues.check_snapshot(raw_with(totals={"ip_bytes": 1000, "missed_bytes": missed}, notices=list(notices)), None)
            return (out.get("sensor|capture-loss") or {}).get("severity")
        self.assertIsNone(sev(20))
        self.assertEqual(sev(21), "medium")
        self.assertEqual(sev(201), "high")
        self.assertEqual(sev(0, [{"note": "CaptureLoss::Too_Much_Loss", "count": 3}]), "medium")
        self.assertIsNone(issues.check_snapshot(raw_with(totals={}), None).get("sensor|capture-loss"))

    def test_unknown_dhcp_inventory(self):
        """Devices missing from the DHCP inventory become low 'inv|<mac>' hygiene issues.
        REQ: ISS-01"""
        raw = raw_with(unknown_dhcp=[{"ip": "10.0.1.99", "macs": [F.mac(99)], "hostname": "mystery"}])
        i = issues.check_snapshot(raw, None)[f"inv|{F.mac(99)}"]
        self.assertEqual((i["severity"], i["category"]), ("low", "Hygiene"))


class AnalysisChecksTests(_CleanIP2MAC):
    """check_snapshot(): checks driven by analysis findings."""

    def test_finding_kinds_mapped(self):
        """Outdated software, JA3, inbound threat intel and internal scans map to sw/ja3/ti-in/scan issues.
        REQ: ISS-01"""
        an = {"findings": [
            {"kind": "outdated-software", "device": IP["camera"], "detail": "OldLib 1.0: end of life"},
            {"kind": "malicious-ja3", "device": F.mac(1), "detail": "TLS client fingerprint abc123 matches X"},
            {"kind": "ti-ip-in", "device": IP["dmz"], "detail": "answered 4 inbound"},
            {"kind": "internal-scan", "device": IP["phone"], "detail": "scan"},
            {"kind": "new-country", "device": IP["phone"], "detail": "ignored"}]}
        out = issues.check_snapshot(F.raw_snapshot(), an)
        self.assertIn(f"sw|{F.mac(3)}|OldLib 1.0", out)
        self.assertIn(f"ja3|{F.mac(1)}|abc123", out)
        self.assertEqual(out[f"ja3|{F.mac(1)}|abc123"]["ip"], IP["laptop"])
        self.assertEqual(out[f"ti-in|{F.mac(4)}"]["severity"], "medium")
        self.assertEqual(out[f"scan|{F.mac(5)}"]["category"], "Misconfiguration")
        self.assertEqual(len(out), 4)

    def test_segmentation_findings_not_in_fix_list(self):
        """Segmentation findings are tracked on Lateral/Risk pages, never as Fix-list issues.
        REQ: ISS-01"""
        out = issues.check_snapshot(F.raw_snapshot(), F.analysis())
        self.assertFalse([k for k in out if k.startswith("seg|")])


class HostsAndUnifiChecksTests(_CleanIP2MAC):
    """check_snapshot(): Elastic endpoint and UniFi gateway checks."""

    def test_endpoint_checks(self):
        """Unhealthy agents, failed Defend, SSH password logins and >=5 auth failures produce issues.
        REQ: ISS-01"""
        hosts = {"fleet": [{"host": "WS-One", "status": "degraded", "bad_components": ["endpoint", {"id": "osquery"}]},
                           {"host": "ws-two", "status": "online"}],
                 "defend": [{"host": "WS-One", "status": "failure", "failed_protections": ["malware"]},
                            {"host": "ws-two", "status": "success"}],
                 "auth": {"logins": [{"host": "srv", "user": "root", "via": "password", "outcome": "success", "count": 2},
                                     {"host": "srv", "user": "bob", "via": "password", "outcome": "success"},
                                     {"host": "srv", "user": "eve", "via": "publickey", "outcome": "success"}],
                          "failures": [{"host": "srv", "count": 5}, {"host": "other", "count": 4}]},
                 "syslog": {"srv": {"OOM killer": {"sev": "Investigate", "count": 3}}}}
        out = issues.check_snapshot(raw_with(hosts=hosts), None)
        self.assertEqual(out["agent|ws-one"]["title"], "Elastic Agent degraded")
        self.assertIn("endpoint, osquery", out["agent|ws-one"]["evidence"])
        self.assertNotIn("agent|ws-two", out)
        self.assertEqual(out["defend|ws-one"]["severity"], "high")
        self.assertNotIn("defend|ws-two", out)
        self.assertEqual(out["sshpw|srv|root"]["severity"], "medium")
        self.assertEqual(out["sshpw|srv|bob"]["severity"], "low")
        self.assertNotIn("sshpw|srv|eve", out)
        self.assertIn("authfail|srv", out)
        self.assertNotIn("authfail|other", out)
        self.assertEqual(out["syslog|srv|OOM killer"]["severity"], "medium")

    def test_unifi_checks(self):
        """UniFi IDS-only mode, unprotected networks, endpoint scanning off, odd admin source, offline devices.
        REQ: ISS-01"""
        unifi = {"settings": {"ips_mode": "ids", "all_networks": ["Default", "IoT", "Internet 1"],
                              "protected_networks": ["Default"], "endpoint_scanning": False},
                 "admin": {"logins": [{"ip": F.EXT["bad"], "unexpected_source": True}, {"ip": "10.0.1.10"}]},
                 "events": {"devices": [{"key": "EVT_AP_UNREACHABLE", "message": "AP lost"}]}}
        out = issues.check_snapshot(raw_with(unifi=unifi), None)
        self.assertEqual(out["unifi|ips-mode"]["severity"], "medium")
        self.assertIn("unifi|unprotected|IoT", out)
        self.assertNotIn("unifi|unprotected|Default", out)
        self.assertNotIn("unifi|unprotected|Internet 1", out)
        self.assertEqual(out["unifi|endpoint-scan"]["severity"], "info")
        self.assertEqual(out[f"unifi|admin-src|{F.EXT['bad']}"]["severity"], "high")
        self.assertNotIn("unifi|admin-src|10.0.1.10", out)
        self.assertIn("unifi|devices-offline", out)
        for i in out.values():
            self.assertEqual(i["dev"], "")

    def test_sources_of(self):
        """The set of data sources reflects analysis, hosts and UniFi settings availability.
        REQ: ISS-02"""
        self.assertEqual(issues.sources_of({}, None), {"raw"})
        self.assertEqual(issues.sources_of({"hosts": {"fleet": []}, "unifi": {"settings": {"x": 1}}}, {"f": 1}),
                         {"raw", "analysis", "hosts", "unifi"})
        self.assertEqual(issues.sources_of({"unifi": {"admin": {}}}, {}), {"raw"})


class TrackTests(_CleanIP2MAC):
    """track(): occurrences, recurrence and fixed/open status across snapshots."""

    def telnet_raw(self, on=True, hours=24, sid=F.SID):
        raw = F.raw_snapshot(sid)
        raw["hours"] = hours
        if on:
            raw["devices"][IP["laptop"]]["services_out"] = {"telnet": {"conns": 3}}
        return raw

    def test_occurrences_and_recurring(self):
        """An issue seen in 3 snapshots has 3 occurrences, first/last seen, open status and is recurring.
        REQ: ISS-02"""
        snaps = [snap(f"s{n}", self.telnet_raw()) for n in (1, 2, 3)]
        t = issues.track(snaps)
        self.assertEqual((t["latest"], t["snapshots"], t["min_occurrences"]), ("s3", 3, 2))
        i = next(x for x in t["open"] if x["key"] == f"plain|{F.mac(1)}|telnet")
        self.assertEqual((i["occurrences"], i["first_seen"], i["last_seen"], i["status"]), (3, "s1", "s3", "open"))
        self.assertTrue(i["recurring"])
        self.assertEqual(i["checked"], 3)
        self.assertNotIn("seen_in", i)

    def test_single_occurrence_not_recurring(self):
        """A one-off issue stays open but is not recurring under the default min_occ=2; min_occ=1 makes it recurring.
        REQ: ISS-02"""
        t = issues.track([snap("s1", self.telnet_raw())])
        self.assertFalse(t["open"][0]["recurring"])
        self.assertTrue(issues.track([snap("s1", self.telnet_raw())], min_occ=1)["open"][0]["recurring"])

    def test_fixed_when_absent_in_later_full_snapshot(self):
        """An issue missing from a later 24 h snapshot is fixed at that snapshot's time.
        REQ: ISS-02"""
        t = issues.track([snap("s1", self.telnet_raw()), snap("s2", self.telnet_raw()), snap("s3", self.telnet_raw(on=False)),
                          snap("s4", self.telnet_raw(on=False))])
        self.assertEqual(t["open"], [])
        f = t["fixed"][0]
        self.assertEqual((f["status"], f["fixed_at"], f["occurrences"]), ("fixed", "s3", 2))

    def test_short_snapshot_cannot_fix(self):
        """A short-lookback snapshot (< 23 h) without the issue does not mark it fixed.
        REQ: ISS-02"""
        t = issues.track([snap("s1", self.telnet_raw()), snap("s2", self.telnet_raw(on=False, hours=6))])
        self.assertEqual(t["fixed"], [])
        self.assertEqual(t["open"][0]["status"], "open (not re-checked)")

    def test_missing_source_not_rechecked(self):
        """When the latest snapshot lacks the issue's source (no UniFi data) it stays 'open (not re-checked)'.
        REQ: ISS-02"""
        r1 = F.raw_snapshot()
        r1["unifi"] = {"settings": {"ips_mode": "ids"}}
        r2 = F.raw_snapshot()
        r2["unifi"] = {}
        t = issues.track([snap("s1", r1), snap("s2", r2)])
        i = next(x for x in t["open"] if x["key"] == "unifi|ips-mode")
        self.assertEqual(i["status"], "open (not re-checked)")
        self.assertEqual(t["fixed"], [])

    def test_device_not_seen_stays_open(self):
        """An issue of a device absent from the latest snapshot is 'open (device not seen)', not fixed.
        REQ: ISS-02"""
        r2 = self.telnet_raw(on=False)
        del r2["devices"][IP["laptop"]]
        t = issues.track([snap("s1", self.telnet_raw()), snap("s2", r2)])
        self.assertEqual(t["fixed"], [])
        self.assertEqual(t["open"][0]["status"], "open (device not seen)")

    def test_mac_key_follows_dhcp_change(self):
        """A device that changes IP keeps one issue key (by MAC), so occurrences accumulate.
        REQ: ISS-02, RISK-03"""
        r1 = self.telnet_raw()
        r2 = copy.deepcopy(r1)
        r2["devices"]["10.0.1.77"] = r2["devices"].pop(IP["laptop"])
        t = issues.track([snap("s1", r1), snap("s2", r2)])
        i = next(x for x in t["open"] if x["key"] == f"plain|{F.mac(1)}|telnet")
        self.assertEqual(i["occurrences"], 2)
        self.assertEqual(i["ip"], "10.0.1.77")

    def test_ip2mac_learned_across_snapshots(self):
        """A snapshot that lacks a device's MAC still keys it by the MAC learned from another snapshot.
        REQ: ISS-02, RISK-03"""
        r1 = self.telnet_raw()
        r2 = self.telnet_raw()
        del r2["devices"][IP["laptop"]]["mac"]
        t = issues.track([snap("s1", r1), snap("s2", r2)])
        keys = [x["key"] for x in t["open"]]
        self.assertEqual(keys, [f"plain|{F.mac(1)}|telnet"])
        self.assertEqual(t["open"][0]["occurrences"], 2)

    def test_open_sorted_by_severity_then_occurrences(self):
        """Open issues sort by severity (high first) then by occurrences descending.
        REQ: ISS-02"""
        def r(extra):
            x = F.raw_snapshot()
            x["devices"][IP["laptop"]]["services_out"] = {"telnet": {"conns": 1}}
            x["tls"] = {"devices": {IP["camera"]: {"versions": {"TLSv10": 1}}}}
            x.update(extra)
            return x
        t = issues.track([snap("s1", r({})), snap("s2", r({"totals": {"ip_bytes": 100, "missed_bytes": 50}}))])
        self.assertEqual([x["severity"] for x in t["open"]], ["high", "medium", "low"])

    def test_empty_history(self):
        """Tracking no snapshots yields empty lists and no latest snapshot.
        REQ: ISS-02"""
        self.assertEqual(issues.track([]), {"latest": None, "snapshots": 0, "min_occurrences": 2, "open": [], "fixed": []})


if __name__ == "__main__":
    unittest.main()


class IncrementalTrackTests(_CleanIP2MAC):
    """track_incremental(): same result as track(), parsing only new/changed snapshots."""

    def _items(self, snaps, mts, loads):
        def mk(s):
            def load():
                loads.append(s[0])
                return s[1], copy.deepcopy(s[2]), s[3]
            return load
        return [(s[0], mts.get(s[0], 1), mk(s)) for s in snaps]

    def test_incremental_matches_full_and_reuses_cache(self):
        """Cached per-snapshot results give the identical tracker; a new snapshot is the only one parsed again,
        and a snapshot whose IP->MAC lookup changed is re-evaluated.
        REQ: ISS-02, OPS-05"""
        r1 = raw_with(); r1["devices"][IP["laptop"]]["services_out"] = {"telnet": {"conns": 3}}
        r2 = raw_with(); del r2["devices"][IP["phone"]]["mac"]; r2["devices"][IP["phone"]]["services_out"] = {"ftp": {"conns": 1}}
        r3 = raw_with()
        s1, s2, s3 = snap("2026-01-01T0000Z", r1), snap("2026-01-02T0000Z", r2), snap("2026-01-03T0000Z", r3)
        cache, loads = {}, []
        full = lambda ss: issues.track([(a, b, copy.deepcopy(c), d) for a, b, c, d in ss])
        self.assertEqual(issues.track_incremental(self._items([s1, s2], {}, loads), cache), full([s1, s2]))
        loads.clear()
        self.assertEqual(issues.track_incremental(self._items([s1, s2, s3], {}, loads), cache), full([s1, s2, s3]))
        self.assertEqual(loads, ["2026-01-03T0000Z"])  # only the new one
        # the phone's MAC disappears from every snapshot -> s2's lookup result changes -> s2 is re-evaluated
        r3b = copy.deepcopy(r3); del r3b["devices"][IP["phone"]]["mac"]
        r1b = copy.deepcopy(r1); del r1b["devices"][IP["phone"]]["mac"]
        s1b, s3b = snap(s1[0], r1b), snap(s3[0], r3b)
        loads.clear()
        got = issues.track_incremental(self._items([s1b, s2, s3b], {s1[0]: 2, s3[0]: 2}, loads), cache)
        self.assertEqual(got, full([s1b, s2, s3b]))
        self.assertIn(s2[0], loads)
