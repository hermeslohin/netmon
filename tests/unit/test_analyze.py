"""Unit tests for the pure helpers of analyze.py (device keys, baseline records, deviation statistics)."""
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); import _env  # noqa: E401,E702,E402

import unittest  # noqa: E402

import fixtures as F  # noqa: E402
import analyze  # noqa: E402

IP = F.IPS


class _Patch:
    """Mixin: patch module attributes and restore them after each test."""

    def patch(self, obj, name, value):
        old = getattr(obj, name)
        setattr(obj, name, value)
        self.addCleanup(setattr, obj, name, old)


class DevKeyTests(unittest.TestCase):
    """dev_key(): baseline records are keyed by MAC when known, else IP."""

    def test_mac_preferred(self):
        """A device with a MAC is keyed by its MAC so DHCP address changes keep its baseline.
        REQ: RISK-03"""
        self.assertEqual(analyze.dev_key(IP["laptop"], F.device("lap", 1)), F.mac(1))

    def test_ip_fallback(self):
        """A device without (or with an empty) MAC is keyed by its IP.
        REQ: RISK-03"""
        self.assertEqual(analyze.dev_key(IP["phone"], {}), IP["phone"])
        self.assertEqual(analyze.dev_key(IP["phone"], {"mac": ""}), IP["phone"])
        self.assertEqual(analyze.dev_key(IP["phone"], {"mac": None}), IP["phone"])


class CompactTests(unittest.TestCase):
    """compact(): the per-device daily baseline record."""

    def setUp(self):
        self.d = F.device("Admin Laptop", 1, served=F.served(8080, "http", conns=7, sources=2, ext_conns=3))
        self.d["hourly_conns"] = {"3": 0, "9": 4, "10": 2}
        self.d["hourly_bytes"] = {"9": 1234.6, "10": 10.2}
        self.d["dports_out"]["853/tcp"] = {"conns": 6, "service": ""}
        self.d["dns"]["doh"] = {"dns.example": 2}
        self.c = analyze.compact(IP["laptop"], self.d)

    def test_volume_fields(self):
        """Totals and counts are copied; conns = originated + responded connections.
        REQ: ANA-01"""
        c = self.c
        self.assertEqual((c["ip"], c["name"], c["known"]), (IP["laptop"], "Admin Laptop", True))
        self.assertEqual((c["total"], c["sent"], c["recv"]), (460_000.0, 60_000.0, 400_000.0))
        self.assertEqual(c["conns"], 123)
        self.assertEqual((c["ext_peers"], c["ext_out"], c["rejected"]), (3, 10_000.0, 2))
        self.assertEqual((c["dns_q"], c["nx"], c["inbound_ext_sources"]), (200, 3, 0))

    def test_hours_and_rounding(self):
        """Active hours list only hours with connections (sorted); hourly bytes and geo values are rounded.
        REQ: ANA-01"""
        self.assertEqual(self.c["active_hours"], ["10", "9"])
        self.assertEqual(self.c["hourly"], {"9": 1235, "10": 10})
        self.assertEqual(self.c["countries"], {"US": 40})
        self.assertEqual(self.c["asns"], {"AS64500 Example": 40})

    def test_service_and_port_maps(self):
        """Services, destination ports, port services and served ports are reduced to counts.
        REQ: ANA-01"""
        c = self.c
        self.assertEqual(c["services"], {"ssl": 40})
        self.assertEqual(c["dports"], {"443": 40, "853/tcp": 6})
        self.assertEqual(c["port_svc"], {"443": "ssl", "853/tcp": ""})
        self.assertEqual(c["served"], {"8080": {"conns": 7, "sources": 2, "ext": 3, "svc": "http"}})
        self.assertEqual(c["ext_dports"], {"443": 40})

    def test_dns_summary(self):
        """The DNS summary keeps distinct counts, qtypes, TLDs, top domains, resolvers, DoH and DoT conns.
        REQ: ANA-01"""
        dns = self.c["dns"]
        self.assertEqual(self.c["domains"], ["example.com"])
        self.assertEqual((dns["unique_names"], dns["unique_domains"]), (20, 8))
        self.assertEqual(dns["qtypes"], {"A": 200})
        self.assertEqual(dns["resolvers"], [F.EXT["dns"]])
        self.assertEqual(dns["doh"], ["dns.example"])
        self.assertEqual(dns["dot"], 6)

    def test_sparse_device(self):
        """A device with almost no data compacts to zero/empty defaults without errors.
        REQ: ANA-01"""
        c = analyze.compact(IP["phone"], {})
        self.assertEqual((c["total"], c["conns"], c["known"], c["active_hours"], c["services"], c["served"]),
                         (0, 0, False, [], {}, {}))
        self.assertEqual(c["dns"]["dot"], 0)
        self.assertEqual(c["dns"]["doh"], [])


class StatsTests(unittest.TestCase):
    """med()/mad(): robust statistics of the baseline."""

    def test_median(self):
        """med() is the statistical median and 0 for an empty list.
        REQ: ANA-01"""
        self.assertEqual(analyze.med([3, 1, 2]), 2)
        self.assertEqual(analyze.med([1, 2, 3, 4]), 2.5)
        self.assertEqual(analyze.med([]), 0)

    def test_mad(self):
        """mad() is the median absolute deviation from the median and 0 for an empty list.
        REQ: ANA-01"""
        self.assertEqual(analyze.mad([1, 1, 2, 2, 4, 6, 9]), 1)
        self.assertEqual(analyze.mad([5, 5, 5]), 0)
        self.assertEqual(analyze.mad([]), 0)


class SpikeTests(_Patch, unittest.TestCase):
    """spike()/sp(): 'far above its own normal' detection."""

    def setUp(self):
        self.patch(analyze, "SCALE", 1.0)

    def test_requires_floor_and_history(self):
        """Below the absolute floor or with fewer than MIN_DAYS of history nothing is a spike.
        REQ: ANA-01"""
        self.assertFalse(analyze.spike(99, [1, 1, 1], 100))
        self.assertTrue(analyze.spike(101, [1, 1, 1], 100))
        self.assertFalse(analyze.spike(1000, [1, 1], 100))
        self.assertTrue(analyze.spike(1000, [1, 1], 100, min_days=2))

    @unittest.expectedFailure
    def test_value_equal_to_floor_counts(self):
        """A value exactly at the floor ('at least min', extras.SPIKE_COMMON) far above normal is a spike.
        APP BUG: spike() compares today > max(mult*m, m+madf*d, floor), so a value equal to min is never flagged.
        REQ: ANA-01"""
        self.assertTrue(analyze.spike(100, [1, 1, 1], 100))

    def test_multiple_and_mad_rules(self):
        """A value must exceed both mult x median and median + madf x MAD.
        REQ: ANA-01"""
        hist = [100, 100, 100]
        self.assertFalse(analyze.spike(300, hist, 10))
        self.assertTrue(analyze.spike(301, hist, 10))
        noisy = [100, 140, 60, 100, 180, 20]   # median 100, MAD 40 -> needs > 340
        self.assertFalse(analyze.spike(340, noisy, 10))
        self.assertTrue(analyze.spike(341, noisy, 10))
        self.assertTrue(analyze.spike(250, hist, 10, mult=2))

    def test_time_range_scaling(self):
        """Counts of a 48 h range are halved before comparing; distinct counts of a 6 h range are not scaled up.
        REQ: ANA-01"""
        self.patch(analyze, "SCALE", 2.0)
        self.assertFalse(analyze.spike(600, [100, 100, 100], 10))
        self.assertTrue(analyze.spike(700, [100, 100, 100], 10))
        self.patch(analyze, "SCALE", 0.25)
        self.assertTrue(analyze.spike(100, [10, 10, 10], 10))           # 100 / 0.25 = 400 > 30
        self.assertFalse(analyze.spike(25, [10, 10, 10], 10, card=True))  # card: not scaled up -> 25 < 30

    def test_sp_uses_configured_severity(self):
        """sp() returns the configured severity on a spike, None when off or not a spike.
        REQ: ANA-01"""
        row = {"min": 50, "times_normal": 3, "mad_factor": 6, "min_days": 3, "severity": "high"}
        self.patch(analyze, "_SP", {"fan_out": row, "dns_volume": {**row, "severity": "off"}})
        self.assertEqual(analyze.sp("fan_out", 500, [10, 10, 10]), "high")
        self.assertIsNone(analyze.sp("fan_out", 20, [1, 1, 1]))
        self.assertIsNone(analyze.sp("dns_volume", 5000, [10, 10, 10]))


class SmallHelperTests(unittest.TestCase):
    """ephemeral(), tunnel_level(), beacon_id(), enrich_today()."""

    def test_ephemeral_ports(self):
        """High UDP ports and P2P/STUN services are ephemeral; TCP or low ports are not.
        REQ: ANA-01"""
        self.assertTrue(analyze.ephemeral("40000/udp"))
        self.assertTrue(analyze.ephemeral("32768/udp"))
        self.assertFalse(analyze.ephemeral("32767/udp"))
        self.assertFalse(analyze.ephemeral("40000/tcp"))
        self.assertTrue(analyze.ephemeral("3478/udp", "spicy_stun"))
        self.assertFalse(analyze.ephemeral("x/udp"))

    def test_tunnel_level(self):
        """DNS tunnel candidates: suspect (score>=5, >=150 subs), watch (score>=3, >=50 subs, ratio>=0.5), else None.
        REQ: ANA-01"""
        t = lambda s, u, r=1.0: analyze.tunnel_level({"score": s, "unique_subdomains": u, "sample_unique_ratio": r})  # noqa: E731
        self.assertEqual(t(5, 150), "suspect")
        self.assertEqual(t(5, 149), "watch")
        self.assertEqual(t(3, 50, 0.5), "watch")
        self.assertIsNone(t(3, 50, 0.49))
        self.assertIsNone(t(2.9, 500))
        self.assertIsNone(t(4, 49))

    def test_beacon_id(self):
        """Beacon ids prefer domain, then ASN, then destination IP, plus the port.
        REQ: ANA-01"""
        self.assertEqual(analyze.beacon_id({"domain": "c2.example", "asn": "AS1", "dst": F.EXT["bad"], "port": 443}), "c2.example:443")
        self.assertEqual(analyze.beacon_id({"asn": "AS1", "dst": F.EXT["bad"], "port": 80}), "AS1:80")
        self.assertEqual(analyze.beacon_id({"dst": F.EXT["bad"], "port": 8443}), f"{F.EXT['bad']}:8443")

    def test_enrich_today(self):
        """enrich_today attaches JA4, software, IoT destinations, answered internal peers and beacons by device key.
        REQ: ANA-01"""
        k = F.mac(3)
        today = {k: {"ip": IP["camera"]}}
        ip2key = {IP["camera"]: k}
        snap = {"tls": {"devices": {IP["camera"]: {"ja4": {"t13d_x": 3}}, IP["phone"]: {"ja4": {"y": 1}}}},
                "files": {"software": [{"ip": IP["camera"], "name": "CamFW"}]},
                "iot_dest": {IP["camera"]: {"domains": {"cloud.example": 4}, "asns": {"AS64500": 10}, "no_asn_ips": [F.EXT["bad"]]}},
                "internal": {"flows": [F.flow(IP["camera"], IP["server"], 554, answered=3), F.flow(IP["camera"], IP["laptop"], 80, answered=2)]},
                "beacons": {"candidates": [{"src": IP["camera"], "domain": "cloud.example", "dst": F.EXT["cdn"], "port": 443}]}}
        analyze.enrich_today(snap, today, ip2key)
        t = today[k]
        self.assertEqual(t["ja4"], ["t13d_x"])
        self.assertEqual(t["software"], ["CamFW"])
        self.assertEqual(t["iot"], {"domains": ["cloud.example"], "asns": {"AS64500": 10}, "raw_ips": [F.EXT["bad"]]})
        self.assertEqual(t["internal_peers"], [f"{IP['server']}:554/tcp"])
        self.assertEqual(t["beacons"], ["cloud.example:443"])
        self.assertEqual(set(today), {k})


if __name__ == "__main__":
    unittest.main()
