"""Unit tests for dashboard/app/risk.py (vulnerability and host risk scoring, zones, segmentation keys)."""
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); import _env  # noqa: E401,E702,E402

import unittest  # noqa: E402

import fixtures as F  # noqa: E402
import risk  # noqa: E402

IP = F.IPS
GW = "10.0.1.1"


def mkraw(devices=None, **extra):
    """Minimal raw snapshot: devices {ip: device dict} plus any extra top-level sections."""
    raw = {"devices": devices or {}, "alerts": {"signatures": []}, "beacons": {}, "threat_intel": {}, "tls": {},
           "internal": {}, "hosts": {}, "admin_access": {}, "inventory_ips": {}}
    raw.update(extra)
    return raw


def dev(name, i, known=True, served=None):
    d = F.device(name, i, known=known, served=served)
    return d


def tracker(*issues):
    return {"open": list(issues)}


def vuln(result, key):
    return next(v for v in result["vulns"] if v["key"] == key)


def host(result, hid):
    return next((h for h in result["hosts"] if h["id"] == hid), None)


class _Patch:
    """Mixin: patch module attributes and restore them after each test."""

    def patch(self, obj, name, value):
        old = getattr(obj, name)
        setattr(obj, name, value)
        self.addCleanup(setattr, obj, name, old)


class ZoneAndKeyTests(unittest.TestCase):
    """Pure helpers: CIDR zone mapping and segmentation flow keys."""

    def test_zone_of_maps_ip_to_cidr_zone(self):
        """An IP inside a policy CIDR maps to that zone name.
        REQ: RISK-03"""
        zones = F.zone_policy()["zones"]
        self.assertEqual(risk.zone_of(IP["laptop"], zones), "user")
        self.assertEqual(risk.zone_of(IP["server"], zones), "servers")
        self.assertEqual(risk.zone_of(IP["dmz"], zones), "dmz")

    def test_zone_of_unmatched_and_invalid(self):
        """An IP outside every zone is 'internet'; an unparseable value gives an empty zone.
        REQ: RISK-03"""
        zones = F.zone_policy()["zones"]
        self.assertEqual(risk.zone_of("10.200.0.5", zones), "internet")
        self.assertEqual(risk.zone_of(F.EXT["bad"], zones), "internet")
        self.assertEqual(risk.zone_of("not-an-ip", zones), "")
        self.assertEqual(risk.zone_of("", zones), "")
        self.assertEqual(risk.zone_of(None, zones), "")
        self.assertEqual(risk.zone_of(IP["laptop"], {}), "internet")

    def test_zone_of_prefix_boundaries(self):
        """CIDR masks are honoured exactly (/24 edge addresses, /16 and /0 zones).
        REQ: RISK-03"""
        zones = {"a": "10.5.0.0/16"}
        self.assertEqual(risk.zone_of("10.5.255.254", zones), "a")
        self.assertEqual(risk.zone_of("10.6.0.1", zones), "internet")
        self.assertEqual(risk.zone_of("10.0.1.255", {"u": "10.0.1.0/24"}), "u")
        self.assertEqual(risk.zone_of("10.0.2.0", {"u": "10.0.1.0/24"}), "internet")
        self.assertEqual(risk.zone_of(F.EXT["cdn"], {"all": "0.0.0.0/0"}), "all")

    def test_seg_key_maps_ip_to_device_mac(self):
        """A source IP is replaced by its device MAC so the key survives DHCP address changes.
        REQ: RISK-03"""
        m = F.mac(7).upper()
        devices = {IP["laptop"]: {"mac": m}}
        self.assertEqual(risk.seg_key(IP["laptop"], IP["server"], 22, devices), f"{m.lower()}|{IP['server']}|22")

    def test_seg_key_keeps_unknown_ip_and_mac(self):
        """Unknown IPs and MAC sources are kept as-is (lowercased); no device map leaves the IP.
        REQ: RISK-03"""
        self.assertEqual(risk.seg_key(IP["phone"], IP["server"], 22, {IP["laptop"]: {"mac": F.mac(1)}}),
                         f"{IP['phone']}|{IP['server']}|22")
        self.assertEqual(risk.seg_key(F.mac(9).upper(), IP["server"], "445"), f"{F.mac(9)}|{IP['server']}|445")
        self.assertEqual(risk.seg_key(IP["phone"], IP["server"], 22), f"{IP['phone']}|{IP['server']}|22")
        self.assertEqual(risk.seg_key(None, IP["server"], 22), f"|{IP['server']}|22")

    def test_seg_key_issue_parses_seg_issue_keys(self):
        """A 'seg|<dev>|<dst>|<port>' Fix-list key converts to the flow key; other keys give None.
        REQ: RISK-03"""
        self.assertEqual(risk.seg_key_issue(f"seg|{F.mac(2).upper()}|{IP['server']}|22"), f"{F.mac(2)}|{IP['server']}|22")
        self.assertIsNone(risk.seg_key_issue(f"plain|{F.mac(2)}|telnet"))
        self.assertIsNone(risk.seg_key_issue("seg|x|y"))

    def test_seg_key_finding_parses_segmentation_detail(self):
        """A segmentation finding's detail yields '<device>|<dst ip>|<port>'; other kinds give None.
        REQ: RISK-03"""
        f = {"kind": "segmentation", "device": F.mac(4).upper(),
             "detail": f"DMZ host initiating -> Lab Server ({IP['server']}) 22/tcp, 5 conns (5 answered)"}
        self.assertEqual(risk.seg_key_finding(f), f"{F.mac(4)}|{IP['server']}|22")
        self.assertIsNone(risk.seg_key_finding({**f, "kind": "new-country"}))
        self.assertIsNone(risk.seg_key_finding({"kind": "segmentation", "device": "x", "detail": "no flow here"}))

    def test_seg_is_cleared_ip_and_mac_forms(self):
        """A flow cleared under its MAC form is cleared when looked up by IP, and the IP form also matches.
        REQ: RISK-04"""
        devices = {IP["laptop"]: {"mac": F.mac(1)}}
        mac_form = {f"{F.mac(1)}|{IP['server']}|22"}
        ip_form = {f"{IP['laptop']}|{IP['server']}|22"}
        self.assertTrue(risk.seg_is_cleared(mac_form, IP["laptop"], IP["server"], 22, devices))
        self.assertTrue(risk.seg_is_cleared(mac_form, F.mac(1).upper(), IP["server"], 22, devices))
        self.assertTrue(risk.seg_is_cleared(ip_form, IP["laptop"], IP["server"], 22, devices))
        self.assertFalse(risk.seg_is_cleared(mac_form, IP["laptop"], IP["server"], 23, devices))
        self.assertFalse(risk.seg_is_cleared(set(), IP["laptop"], IP["server"], 22, devices))
        self.assertFalse(risk.seg_is_cleared(None, IP["laptop"], IP["server"], 22, devices))

    def test_seg_cleared_reads_policy(self):
        """seg_cleared returns the policy's _cleared_seg set or an empty set.
        REQ: RISK-04"""
        self.assertEqual(risk.seg_cleared(None), set())
        self.assertEqual(risk.seg_cleared({}), set())
        self.assertEqual(risk.seg_cleared({"_cleared_seg": {"a|b|1"}}), {"a|b|1"})

    def test_exposed_services_only_low_tcp_with_external_conns(self):
        """Only TCP ports below 32768 with external connections count as internet-exposed (ICMP/UDP ignored).
        REQ: RISK-01"""
        d = {"served_ports": {
            "443/tcp": {"ext_conns": 12}, "22/tcp": {"ext_conns": 0}, "53/udp": {"ext_conns": 9},
            "8/icmp": {"ext_conns": 4}, "40000/tcp": {"ext_conns": 3}, "3/tcp": {"ext_conns": 3}, "8080/tcp": {"ext_conns": 1}}}
        self.assertEqual(sorted(risk.exposed_services(d)), [("443/tcp", 12), ("8080/tcp", 1)])
        self.assertEqual(risk.exposed_services({}), [])


class HostIpTests(_Patch, unittest.TestCase):
    """Resolution of endpoint host names to device IPs."""

    def test_host_ip_from_site_map(self):
        """The site host_ips map (lowercase names) wins over name matching.
        REQ: RISK-01"""
        self.patch(risk, "HOST_IP", {"workstation-a": IP["laptop"]})
        self.assertEqual(risk._host_ip("Workstation-A", {}), IP["laptop"])

    def test_host_ip_short_name_match(self):
        """An FQDN resolves through a device name/hostname whose short form matches (names > 3 chars only).
        REQ: RISK-01"""
        self.patch(risk, "HOST_IP", {})
        devices = {IP["server"]: {"name": "Labbox server", "hostname": ""}, IP["phone"]: {"name": "abc"}}
        self.assertEqual(risk._host_ip("labbox.example.test", devices), IP["server"])
        self.assertEqual(risk._host_ip("abc.example.test", devices), "")
        self.assertEqual(risk._host_ip("", devices), "")
        self.assertEqual(risk._host_ip(None, devices), "")


class VulnScoreTests(_Patch, unittest.TestCase):
    """Vulnerability risk = severity base x kind factor x exposure x recurrence, capped at 100."""

    def setUp(self):
        self.pol = F.zone_policy()
        self.raw = mkraw({IP["laptop"]: dev("Admin Laptop", 1), IP["server"]: dev("Lab Server", 2),
                          IP["dmz"]: dev("DMZ Box", 4),
                          IP["camera"]: dev("Cam", 3, served={"443/tcp": {"ext_conns": 5}})})

    def score(self, *issues, raw=None, pol=None):
        return risk.compute(raw or self.raw, {}, tracker(*issues), pol or self.pol, {})

    def test_severity_base_values(self):
        """Neutral kind on a neutral host scores exactly the severity base (45/28/14/5, other 10).
        REQ: RISK-01"""
        sevs = {"high": 45, "medium": 28, "low": 14, "info": 5, "weird": 10}
        r = self.score(*[F.issue(f"scan|{s}", s, ip=IP["laptop"]) for s in sevs])
        for s, base in sevs.items():
            self.assertEqual(vuln(r, f"scan|{s}")["score"], base)

    def test_kind_factors(self):
        """Kind factors come from the key prefix (plain 1.2, ti-in 1.5, defend 1.4, inv 0.4, doh 0.5, unknown 1.0).
        REQ: RISK-01"""
        cases = {f"plain|{F.mac(1)}|telnet": 1.2, f"ti-in|{F.mac(1)}": 1.5, "defend|host-a": 1.4,
                 f"inv|{F.mac(1)}": 0.4, f"doh|{F.mac(1)}": 0.5, f"syslog|host-a|OOM killer": 0.7,
                 f"sshpw|host-a|root": 1.1, "brandnew|thing": 1.0}
        r = self.score(*[F.issue(k, "medium", ip=IP["laptop"]) for k in cases])
        for k, f in cases.items():
            self.assertAlmostEqual(vuln(r, k)["score"], round(28 * f, 1), msg=k)

    def test_unifi_ips_mode_documented_limitation(self):
        """unifi|ips-mode resolves to the generic 'unifi' factor 0.8 (documented known limitation), admin-src gets 1.4.
        REQ: RISK-01"""
        r = self.score(F.issue("unifi|ips-mode", "medium", host="UniFi gateway"),
                       F.issue("unifi|admin-src|192.0.2.9", "high", host="UniFi gateway"))
        self.assertAlmostEqual(vuln(r, "unifi|ips-mode")["score"], round(28 * 0.8, 1))
        self.assertAlmostEqual(vuln(r, "unifi|admin-src|192.0.2.9")["score"], round(45 * 1.4, 1))

    def test_exposure_factor_order(self):
        """Host exposure: internet-exposed 1.4, DMZ 1.3, protected 1.15, otherwise 1.0.
        REQ: RISK-01"""
        r = self.score(F.issue("scan|cam", "low", ip=IP["camera"]), F.issue("scan|dmz", "low", ip=IP["dmz"]),
                       F.issue("scan|srv", "low", ip=IP["server"]), F.issue("scan|lap", "low", ip=IP["laptop"]),
                       F.issue("scan|none", "low"))
        self.assertAlmostEqual(vuln(r, "scan|cam")["score"], round(14 * 1.4, 1))
        self.assertAlmostEqual(vuln(r, "scan|dmz")["score"], round(14 * 1.3, 1))
        self.assertAlmostEqual(vuln(r, "scan|srv")["score"], round(14 * 1.15, 1))
        self.assertEqual(vuln(r, "scan|lap")["score"], 14)
        self.assertEqual(vuln(r, "scan|none")["score"], 14)

    def test_exposed_wins_over_dmz(self):
        """A DMZ host that also serves the internet gets the 1.4 exposure factor (first rule wins).
        REQ: RISK-01"""
        self.raw["devices"][IP["dmz"]]["served_ports"] = {"443/tcp": {"ext_conns": 3}}
        r = self.score(F.issue("scan|dmz", "low", ip=IP["dmz"]))
        self.assertAlmostEqual(vuln(r, "scan|dmz")["score"], round(14 * 1.4, 1))

    def test_seg_issue_in_dmz_uses_seg_dmz_factor(self):
        """A seg issue whose host is in a DMZ-role zone uses the 1.5 seg-dmz factor (plus DMZ exposure 1.3).
        REQ: RISK-01, RISK-03"""
        r = self.score(F.issue(f"seg|{F.mac(4)}|{IP['server']}|22", "high", ip=IP["dmz"]),
                       F.issue(f"seg|{F.mac(1)}|{IP['server']}|22", "high", ip=IP["laptop"]))
        self.assertAlmostEqual(vuln(r, f"seg|{F.mac(4)}|{IP['server']}|22")["score"], round(45 * 1.5 * 1.3, 1))
        self.assertEqual(vuln(r, f"seg|{F.mac(1)}|{IP['server']}|22")["score"], 45)

    def test_legacy_zone_name_role(self):
        """Without zone_roles, legacy zone names map to roles (dmz -> dmz, servers -> protected).
        REQ: RISK-01, RISK-03"""
        pol = F.zone_policy()
        pol.pop("zone_roles")
        r = self.score(F.issue("scan|srv", "low", ip=IP["server"]), F.issue("scan|dmz", "low", ip=IP["dmz"]), pol=pol)
        self.assertAlmostEqual(vuln(r, "scan|srv")["score"], round(14 * 1.15, 1))
        self.assertAlmostEqual(vuln(r, "scan|dmz")["score"], round(14 * 1.3, 1))

    def test_recurrence_bonus_capped(self):
        """Recurrence adds 8% per extra occurrence and stops at +40% (6+ occurrences).
        REQ: RISK-01, ISS-02"""
        r = self.score(*[F.issue(f"scan|o{n}", "medium", ip=IP["laptop"], occurrences=n) for n in (1, 2, 4, 6, 20)])
        self.assertEqual(vuln(r, "scan|o1")["score"], 28)
        self.assertAlmostEqual(vuln(r, "scan|o2")["score"], round(28 * 1.08, 1))
        self.assertAlmostEqual(vuln(r, "scan|o4")["score"], round(28 * 1.24, 1))
        self.assertAlmostEqual(vuln(r, "scan|o6")["score"], round(28 * 1.40, 1))
        self.assertEqual(vuln(r, "scan|o20")["score"], vuln(r, "scan|o6")["score"])

    def test_score_capped_at_100(self):
        """Even the worst combination never exceeds 100.
        REQ: RISK-01"""
        self.raw["devices"][IP["dmz"]]["served_ports"] = {"443/tcp": {"ext_conns": 3}}
        r = self.score(F.issue(f"ti-in|{F.mac(4)}", "high", ip=IP["dmz"], occurrences=50))
        self.assertEqual(vuln(r, f"ti-in|{F.mac(4)}")["score"], 100.0)
        for v in r["vulns"]:
            self.assertGreaterEqual(v["score"], 0)
            self.assertLessEqual(v["score"], 100)

    def test_drivers_explain_multipliers(self):
        """Drivers list severity, kind factor, exposure and recurrence in plain language.
        REQ: RISK-01"""
        r = self.score(F.issue(f"plain|{F.mac(3)}|telnet", "medium", ip=IP["camera"], occurrences=4))
        d = vuln(r, f"plain|{F.mac(3)}|telnet")["drivers"]
        self.assertEqual(d[0], "medium severity (28)")
        self.assertIn("×1.2 credentials in cleartext", d)
        self.assertIn("×1.4 host exposes services to the internet", d)
        self.assertIn("×1.24 recurring in 4 reports", d)

    def test_vulns_sorted_and_ranked(self):
        """Vulnerabilities are sorted by score descending and ranked from 1.
        REQ: RISK-01"""
        r = self.score(F.issue("inv|a", "low", ip=IP["laptop"]), F.issue("defend|b", "high", host="b-host"),
                       F.issue("scan|c", "medium", ip=IP["laptop"]))
        scores = [v["score"] for v in r["vulns"]]
        self.assertEqual(scores, sorted(scores, reverse=True))
        self.assertEqual([v["rank"] for v in r["vulns"]], [1, 2, 3])
        self.assertEqual(r["vulns"][0]["key"], "defend|b")

    def test_host_name_resolves_to_ip_for_exposure(self):
        """An issue with only a host name is resolved to the device IP via host_ips and gets its exposure factor.
        REQ: RISK-01"""
        self.patch(risk, "HOST_IP", {"camhost": IP["camera"]})
        r = self.score(F.issue("sshpw|camhost|pi", "low", host="CamHost"))
        v = vuln(r, "sshpw|camhost|pi")
        self.assertEqual(v["ip"], IP["camera"])
        self.assertAlmostEqual(v["score"], round(14 * 1.1 * 1.4, 1))

    def test_cleared_seg_issue_dropped(self):
        """A seg issue whose flow was cleared (MAC form) is not scored; other issues still are.
        REQ: RISK-04"""
        k = f"seg|{F.mac(1)}|{IP['server']}|22"
        pol = F.zone_policy(_cleared_seg={f"{F.mac(1)}|{IP['server']}|22"})
        r = self.score(F.issue(k, "high", ip=IP["laptop"]), F.issue("scan|x", "low", ip=IP["laptop"]), pol=pol)
        self.assertEqual([v["key"] for v in r["vulns"]], ["scan|x"])


class HostScoreTests(_Patch, unittest.TestCase):
    """Host risk = capped likelihood components x impact / 5."""

    def setUp(self):
        self.pol = F.zone_policy()

    def compute(self, raw, issues=(), analysis=None, pol=None, kb=None):
        return risk.compute(raw, analysis or {}, tracker(*issues), pol or self.pol, kb or {})

    def test_worked_example_from_spec(self):
        """The RISK_SCORING.md worked example reproduces: vulns 85.9 / 39.2, likelihood 45.9, host risk 45.9.
        REQ: RISK-01, RISK-02"""
        srv = dev("Labbox", 2, served={"443/tcp": {"ext_conns": 9}, "8443/tcp": {"ext_conns": 2}})
        lap = dev("Admin Laptop", 1)
        raw = mkraw({IP["server"]: srv, IP["laptop"]: lap},
                    threat_intel={"ip_hits_in": [{"ip": F.EXT["bad"], "targets": {IP["server"]: 4}}]},
                    alerts={"signatures": [{"name": "ET SCAN test rule", "src": {IP["server"]: 3}}]},
                    internal={"flows": [F.flow(IP["server"], IP["laptop"], 445, answered=2)]},
                    hosts={"fleet": [{"host": "labbox", "status": "online"}]})
        pol = F.zone_policy(device_classes={F.mac(2): "server"})
        an = {"findings": [{"severity": "medium", "device": F.mac(2), "kind": "new-country", "detail": "x"}]}
        r = self.compute(raw, [F.issue("sshpw|labbox|root", "high", ip=IP["server"], occurrences=4, title="SSH pw"),
                               F.issue(f"sw|{F.mac(2)}|pkg", "medium", ip=IP["server"], title="Outdated")], an, pol)
        self.assertEqual(vuln(r, "sshpw|labbox|root")["score"], 85.9)
        self.assertEqual(vuln(r, f"sw|{F.mac(2)}|pkg")["score"], 39.2)
        h = host(r, IP["server"])
        self.assertEqual(h["components"], {"exposure": 19, "weaknesses": 18.9, "threat": 6, "reach": 2, "visibility": 0})
        self.assertEqual(h["likelihood"], 45.9)
        self.assertEqual(h["impact"], 5)
        self.assertEqual(h["score"], 45.9)
        self.assertEqual(h["vulns"], 2)
        self.assertEqual(h["top_vuln"], "SSH pw")

    def test_components_capped_and_score_bounded(self):
        """With every signal saturated each component stays at its cap and the score never exceeds 100.
        REQ: RISK-02"""
        t = IP["dmz"]
        served = {f"{p}/tcp": {"ext_conns": 5} for p in (22, 80, 443, 8080, 8443, 25)}
        d = dev("Hot Box", 4, known=False, served=served)
        others = {"10.0.1.50": dev("a", 11), "10.0.2.50": dev("b", 12), "10.0.3.50": dev("c", 13)}
        raw = mkraw({t: d, **others},
                    threat_intel={"ip_hits_in": [{"targets": {t: 1}}], "ip_hits_out": [{"ip": F.EXT["bad"], "sources": {t: 1}}]},
                    alerts={"signatures": [{"name": f"rule {n}", "src": {t: 1}} for n in range(6)]},
                    beacons={"candidates": [{"src": t, "dst": F.EXT["bad"], "domain": ""} for _ in range(4)]},
                    internal={"flows": [F.flow(t, o, 80) for o in others]},
                    admin_access={"logins": [F.login(F.EXT["cdn"], t, False, count=20)]})
        an = {"findings": [{"severity": "high", "device": F.mac(4), "kind": f"k{n}", "detail": ""} for n in range(6)],
              "violations": [{"src": t, "dst": o, "port": p, "proto": "tcp"} for o in others for p in (22, 23)]}
        issues = [F.issue(f"ti-in|x{n}", "high", ip=t, occurrences=9) for n in range(12)] + [F.issue(f"doh|{F.mac(4)}", "low", ip=t)]
        self.patch(risk, "IMPACT_OVERRIDE", {**risk.IMPACT_OVERRIDE, t: (5, "crown jewel")})
        r = self.compute(raw, issues, an)
        h = host(r, t)
        caps = r["model"]["components_max"]
        self.assertEqual(caps, {"exposure": 25, "weaknesses": 30, "threat": 25, "reach": 10, "visibility": 10})
        for c, cap in caps.items():
            self.assertLessEqual(h["components"][c], cap, c)
        self.assertEqual(h["components"], {"exposure": 25, "weaknesses": 30.0, "threat": 25, "reach": 10, "visibility": 10})
        self.assertEqual(h["likelihood"], 100)
        self.assertEqual(h["score"], 100)
        for x in r["hosts"]:
            self.assertGreaterEqual(x["score"], 0)
            self.assertLessEqual(x["score"], 100)

    def test_weaknesses_diminishing_returns(self):
        """One 100-point vuln fills 18 weakness points, two fill 25.2 (30 x (1 - prod(1 - 0.6 s/100))).
        REQ: RISK-02"""
        t = IP["dmz"]
        raw = mkraw({t: dev("X", 4, served={"443/tcp": {"ext_conns": 1}})})
        one = self.compute(raw, [F.issue("ti-in|a", "high", ip=t, occurrences=9)])
        two = self.compute(raw, [F.issue("ti-in|a", "high", ip=t, occurrences=9), F.issue("ti-in|b", "high", ip=t, occurrences=9)])
        self.assertEqual(host(one, t)["components"]["weaknesses"], 18.0)
        self.assertEqual(host(two, t)["components"]["weaknesses"], 25.2)

    def test_impact_by_class_role_and_fallbacks(self):
        """Impact uses device class, then zone role, unknown class or zone gives 2, DMZ gives 3.
        REQ: RISK-02, RISK-03"""
        devs = {"10.0.1.20": dev("cam in user", 20, known=False), "10.0.1.21": dev("k8s node", 21, known=False),
                "10.0.1.22": dev("odd class", 22, known=False), IP["server"]: dev("srv", 2, known=False),
                "10.0.3.25": dev("plug", 25, known=False), "10.0.9.26": dev("dmz box", 26, known=False),
                "10.0.50.5": dev("nowhere", 27, known=False), "10.0.1.28": dev("user zone", 28, known=False)}
        pol = F.zone_policy(device_classes={F.mac(20): "camera", F.mac(21): "k8s", "10.0.1.22": "toaster"})
        r = self.compute(mkraw(devs), pol=pol)
        imp = {h["id"]: h["impact"] for h in r["hosts"]}
        self.assertEqual(imp["10.0.1.20"], 2)
        self.assertEqual(imp["10.0.1.21"], 4)
        self.assertEqual(imp["10.0.1.22"], 2)
        self.assertEqual(imp[IP["server"]], 5)
        self.assertEqual(imp["10.0.3.25"], 2)
        self.assertEqual(imp["10.0.9.26"], 3)
        self.assertEqual(imp["10.0.50.5"], 2)
        self.assertEqual(imp["10.0.1.28"], 3)
        for h in r["hosts"]:
            self.assertEqual(h["score"], round(h["likelihood"] * h["impact"] / 5, 1))

    def test_crown_jewel_override(self):
        """A crown-jewel IP gets impact 5 with its configured reason even when its zone would say less.
        REQ: RISK-02"""
        self.patch(risk, "IMPACT_OVERRIDE", {**risk.IMPACT_OVERRIDE, IP["camera"]: (5, "holds the backups")})
        r = self.compute(mkraw({IP["camera"]: dev("Cam", 3, known=False)}))
        h = host(r, IP["camera"])
        self.assertEqual((h["impact"], h["impact_why"]), (5, "holds the backups"))

    def test_endpoint_only_target_and_case_merge(self):
        """An endpoint known only by host name is scored with impact 4; case variants of its name merge.
        REQ: RISK-02"""
        self.patch(risk, "HOST_IP", {})
        r = self.compute(mkraw({}), [F.issue("defend|ws-alpha", "high", host="WS-Alpha"),
                                     F.issue("agent|ws-alpha", "medium", host="ws-alpha")])
        self.assertIsNone(host(r, "WS-Alpha"))
        h = host(r, "ws-alpha")
        self.assertEqual(h["impact"], 4)
        self.assertEqual(h["ip"], "")
        self.assertEqual(h["vulns"], 2)

    def test_gateway_addresses_merge_into_gateway_entity(self):
        """Gateway/broadcast addresses are not scored as hosts; their issues go to 'UniFi gateway' (impact 5).
        REQ: RISK-02"""
        raw = mkraw({GW: dev("gw", 30), IP["laptop"]: dev("lap", 1)})
        r = self.compute(raw, [F.issue("dns-ext|gw", "medium", ip=GW), F.issue("unifi|ips-mode", "medium", host="UniFi gateway")])
        self.assertIsNone(host(r, GW))
        g = host(r, "UniFi gateway")
        self.assertEqual(g["impact"], 5)
        self.assertEqual(g["vulns"], 2)

    def test_zero_score_host_without_issues_dropped(self):
        """A known, quiet, unclassified user-zone device scores 0 and is left out of the ranking.
        REQ: RISK-02"""
        r = self.compute(mkraw({IP["laptop"]: dev("lap", 1), IP["phone"]: dev("phone", 5, known=False)}))
        self.assertIsNone(host(r, IP["laptop"]))
        self.assertIsNotNone(host(r, IP["phone"]))
        self.assertEqual([h["rank"] for h in r["hosts"]], list(range(1, len(r["hosts"]) + 1)))

    def test_visibility_gaps(self):
        """Unknown device +4, server/DMZ without agent +4 (infra exempt), unhealthy agent +3, DNS bypass +2.
        REQ: RISK-02"""
        self.patch(risk, "HOST_IP", {"srv-b": "10.0.2.21"})
        devs = {"10.0.2.20": dev("srv-a", 40, known=False), "10.0.2.21": dev("srv-b", 41),
                "10.0.2.22": dev("switch", 42), "10.0.1.23": dev("lap", 43)}
        raw = mkraw(devs, hosts={"fleet": [{"host": "srv-b", "status": "offline"}]})
        pol = F.zone_policy(device_classes={F.mac(42): "infra"})
        r = self.compute(raw, [F.issue("dns-ext|x", "low", ip="10.0.1.23")], pol=pol)
        self.assertEqual(host(r, "10.0.2.20")["components"]["visibility"], 8)
        self.assertEqual(host(r, "10.0.2.21")["components"]["visibility"], 3)
        self.assertIsNone(host(r, "10.0.2.22"))
        self.assertEqual(host(r, "10.0.1.23")["components"]["visibility"], 2)

    def test_threat_signals_and_known_benign(self):
        """Findings (high 6/med 3/low 1, weakness kinds excluded), IDS 3 each, beacons 3 each; benign ones ignored.
        REQ: RISK-02"""
        t = IP["laptop"]
        raw = mkraw({t: dev("lap", 1)},
                    alerts={"signatures": [{"name": "ET POLICY noisy", "src": {t: 9}}, {"name": "ET TROJAN x", "src": {t: 1}}]},
                    beacons={"candidates": [{"src": t, "domain": "updates.example.com"}, {"src": t, "dst": F.EXT["bad"]}]})
        an = {"findings": [{"severity": "high", "device": F.mac(1), "kind": "beacon-new"},
                           {"severity": "low", "device": t, "kind": "odd-hours"},
                           {"severity": "high", "device": t, "kind": "segmentation"},
                           {"severity": "low", "device": t, "kind": "legacy-tls"}]}
        kb = {"signatures": {"ET POLICY": "noise"}, "beacon_domains": {"example.com": "cdn"}}
        h = host(self.compute(raw, analysis=an, kb=kb), t)
        self.assertEqual(h["components"]["threat"], 6 + 1 + 3 + 3)
        texts = [d["text"] for d in h["drivers"]]
        self.assertTrue(any(x.startswith("IDS: ET TROJAN x") for x in texts))
        self.assertIn("2 behaviour anomalies (beacon-new, odd-hours)", texts)

    def test_threat_intel_contact_adds_15(self):
        """Contacting a threat-listed destination adds 15 threat points; a malicious JA3 source adds 2.
        REQ: RISK-02"""
        t = IP["phone"]
        raw = mkraw({t: dev("phone", 5)}, threat_intel={"domain_hits": [{"name": "bad.example", "sources": {t: 2}}]},
                    tls={"malicious_ja3": [{"ja3": "x", "sources": {t: 1}}]})
        self.assertEqual(host(self.compute(raw), t)["components"]["threat"], 17)

    def test_lateral_reach_zones_and_violations(self):
        """Reach: 2 per other answered zone (own zone/internet/unanswered excluded) + 1 per uncleared violation.
        REQ: RISK-02, RISK-04"""
        t = IP["laptop"]
        flows = [F.flow(t, IP["server"], 22), F.flow(t, IP["camera"], 80), F.flow(t, IP["phone"], 80),
                 F.flow(t, IP["dmz"], 80, answered=0), F.flow(t, F.EXT["cdn"], 443)]
        viol = [{"src": t, "dst": IP["server"], "port": 22, "proto": "tcp"},
                {"src": t, "dst": IP["camera"], "port": 80, "proto": "tcp"}]
        raw = mkraw({t: dev("lap", 1)}, internal={"flows": flows})
        h = host(self.compute(raw, analysis={"violations": viol}), t)
        self.assertEqual(h["components"]["reach"], 4 + 2)
        pol = F.zone_policy(_cleared_seg={f"{F.mac(1)}|{IP['server']}|22"})
        h2 = host(self.compute(raw, analysis={"violations": viol}, pol=pol), t)
        self.assertEqual(h2["components"]["reach"], 4 + 1)

    def test_failed_admin_logins_raise_both_ends(self):
        """Failed admin logins add threat to the destination (3/session +4 if high) and reach to the source (2/session).
        REQ: RISK-02, LAT-01"""
        s, d = IP["laptop"], IP["server"]
        raw = mkraw({s: dev("lap", 1), d: dev("srv", 2)},
                    admin_access={"logins": [F.login(s, d, False, count=12)]}, hosts={"fleet": [{"host": "srv"}]})
        self.patch(risk, "HOST_IP", {"srv": d})
        r = self.compute(raw)
        self.assertEqual(host(r, d)["components"]["threat"], 7)
        self.assertTrue(any("12 failed admin login" in x["text"] for x in host(r, d)["drivers"]))
        self.assertEqual(host(r, s)["components"]["reach"], 2)

    def test_hosts_sorted_by_score(self):
        """Host rows are sorted by score descending with consecutive ranks.
        REQ: RISK-02"""
        raw = mkraw({IP["server"]: dev("srv", 2, known=False), IP["camera"]: dev("cam", 3, known=False),
                     IP["phone"]: dev("ph", 5, known=False)})
        r = self.compute(raw, [F.issue("scan|x", "high", ip=IP["camera"])])
        scores = [h["score"] for h in r["hosts"]]
        self.assertEqual(scores, sorted(scores, reverse=True))
        self.assertEqual([h["rank"] for h in r["hosts"]], [1, 2, 3])

    def test_empty_inputs(self):
        """compute() copes with empty raw/analysis/tracker/policy and returns empty rankings.
        REQ: RISK-02"""
        r = risk.compute({}, None, None, None, None)
        self.assertEqual((r["hosts"], r["vulns"]), ([], []))
        self.assertEqual(r["model"]["sev_base"]["high"], 45)


if __name__ == "__main__":
    unittest.main()
