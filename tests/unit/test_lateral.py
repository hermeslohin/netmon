"""Unit tests for dashboard/app/lateral.py (admin-session levels, lateral graph edges, multi-period merge)."""
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); import _env  # noqa: E401,E702,E402

import unittest  # noqa: E402

import fixtures as F  # noqa: E402
import lateral  # noqa: E402

IP = F.IPS
A, B = IP["laptop"], IP["server"]          # user zone -> servers zone


def raw(logins=(), conns=(), tools=(), flows=(), scans=(), devices=None, **extra):
    r = {"devices": devices if devices is not None else {A: {"mac": F.mac(1), "name": "Admin Laptop", "known": True},
                                                          B: {"mac": F.mac(2), "name": "Lab Server", "known": True}},
         "admin_access": {"logins": list(logins), "conns": list(conns), "tools": list(tools)},
         "internal": {"flows": list(flows), "scans": list(scans)}, "inventory_ips": {}}
    r.update(extra)
    return r


def session(rows, src=A, dst=B):
    return next(r for r in rows if r["src"] == src and r["dst"] == dst)


def edge(result, s, t):
    return next((e for e in result["edges"] if e["src"] == s and e["dst"] == t), None)


class AllowedTests(unittest.TestCase):
    """_allowed(): network-policy allow-rule matching."""

    F0 = {"src": A, "dst": B, "src_zone": "user", "dst_zone": "servers", "port": 22, "proto": "tcp"}

    def test_matches_by_ip_zone_class_wildcard(self):
        """Allow rules match src/dst by IP, zone, class, '*' or omission, and return their reason.
        REQ: LAT-01"""
        for rule in ({"src": A, "dst": B}, {"src": "user", "dst": "servers"}, {"src": "work", "dst": "server"},
                     {"src": "*", "dst": "*"}, {"dst": B}):
            self.assertTrue(lateral._allowed(self.F0, "work", "server", [rule]), rule)
        self.assertEqual(lateral._allowed(self.F0, "", "", [{"src": A, "dst": B, "why": "backup job"}]), "backup job")
        self.assertEqual(lateral._allowed(self.F0, "", "", [{"src": A, "dst": B}]), "allowed by policy")

    def test_port_restrictions(self):
        """A rule with ports only matches listed ports (bare number or 'port/proto').
        REQ: LAT-01"""
        self.assertTrue(lateral._allowed(self.F0, "", "", [{"src": A, "dst": B, "ports": [22]}]))
        self.assertTrue(lateral._allowed(self.F0, "", "", [{"src": A, "dst": B, "ports": ["22/tcp"]}]))
        self.assertIsNone(lateral._allowed(self.F0, "", "", [{"src": A, "dst": B, "ports": [3389, "22/udp"]}]))

    def test_non_matching(self):
        """Rules for another source or destination, or an empty list, do not allow the flow.
        REQ: LAT-01"""
        self.assertIsNone(lateral._allowed(self.F0, "", "", [{"src": IP["phone"], "dst": B}, {"src": A, "dst": "iot"}]))
        self.assertIsNone(lateral._allowed(self.F0, "", "", []))


class AdminSessionTests(unittest.TestCase):
    """admin_sessions(): risk level per (src, dst, protocol)."""

    def setUp(self):
        self.pol = F.zone_policy()

    def lvl(self, r, pol=None):
        rows = lateral.admin_sessions(r, pol or self.pol)
        return session(rows)

    def test_password_guessing_is_high(self):
        """>= 10 failed logins is high (password guessing).
        REQ: LAT-01"""
        s = self.lvl(raw(logins=[F.login(A, B, False, count=10)]))
        self.assertEqual(s["level"], "high")
        self.assertIn("password guessing", s["why"])
        self.assertEqual(s["outcome"], "failed")
        self.assertEqual((s["src_zone"], s["dst_zone"]), ("user", "servers"))

    def test_invalid_users_is_high(self):
        """>= 3 failed logins with invalid user names is high.
        REQ: LAT-01"""
        s = self.lvl(raw(logins=[F.login(A, B, False, count=3, user="u", detail="Invalid user")]))
        self.assertEqual(s["level"], "high")
        self.assertIn("3 invalid user names", s["why"])

    def test_failures_then_success_is_high(self):
        """>= 3 failures followed by a success on one account is high; a typo or two then success is medium.
        REQ: LAT-01"""
        s = self.lvl(raw(logins=[F.login(A, B, False, count=3, user="ops"), F.login(A, B, True, user="ops")]))
        self.assertEqual(s["level"], "high")
        self.assertIn("ops", s["why"])
        self.assertEqual(s["outcome"], "mixed")
        s2 = self.lvl(raw(logins=[F.login(A, B, False, count=2, user="ops"), F.login(A, B, True, user="ops")]))
        self.assertEqual(s2["level"], "medium")
        self.assertIn("; 1 successful", s2["why"])

    def test_single_failure_is_medium(self):
        """Any failed login (below the high thresholds) is medium.
        REQ: LAT-01"""
        self.assertEqual(self.lvl(raw(logins=[F.login(A, B, False)]))["level"], "medium")
        self.assertEqual(self.lvl(raw(logins=[F.login(A, B, False, count=9)]))["level"], "medium")

    def test_refused_connections(self):
        """>= 5 refused connections to an admin port is medium, 1-4 is low.
        REQ: LAT-01"""
        s = self.lvl(raw(conns=[F.admin_conn(A, B, attempts=5, connected=0, failed=5)]))
        self.assertEqual(s["level"], "medium")
        self.assertEqual(s["outcome"], "failed")
        self.assertEqual(self.lvl(raw(conns=[F.admin_conn(A, B, attempts=4, connected=0, failed=4)]))["level"], "low")

    def test_database_traffic_is_normal(self):
        """Successful database client sessions are 'normal'.
        REQ: LAT-01"""
        s = self.lvl(raw(conns=[F.admin_conn(A, B, port=5432, protocol="PostgreSQL", category="database")]))
        self.assertEqual(s["level"], "normal")

    def test_uncovered_success_is_low(self):
        """A successful admin session not in the allow list is low.
        REQ: LAT-01"""
        s = self.lvl(raw(conns=[F.admin_conn(A, B)]))
        self.assertEqual(s["level"], "low")
        self.assertEqual(s["outcome"], "success")

    def test_allow_rule_downgrades_to_allowed_admin(self):
        """A successful session matched by an allow rule (zone or port) becomes allowed-admin.
        REQ: LAT-01"""
        pol = F.zone_policy(allow=[{"src": "user", "dst": "servers", "ports": [22], "why": "admin ws"}])
        s = self.lvl(raw(conns=[F.admin_conn(A, B)]), pol)
        self.assertEqual((s["level"], s["why"]), ("allowed-admin", "allowed: admin ws"))
        pol2 = F.zone_policy(allow=[{"src": "user", "dst": "servers", "ports": [3389]}])
        self.assertEqual(self.lvl(raw(conns=[F.admin_conn(A, B)]), pol2)["level"], "low")

    def test_allow_by_device_class(self):
        """Allow rules can name device classes (from the device MAC).
        REQ: LAT-01"""
        pol = F.zone_policy(allow=[{"src": "work", "dst": "server"}], device_classes={F.mac(1): "work", F.mac(2): "server"})
        self.assertEqual(self.lvl(raw(conns=[F.admin_conn(A, B)]), pol)["level"], "allowed-admin")

    def test_allow_rule_does_not_hide_failures(self):
        """Failed logins escalate even when the flow is allow-listed.
        REQ: LAT-01"""
        pol = F.zone_policy(allow=[{"src": "*", "dst": "*"}])
        s = self.lvl(raw(conns=[F.admin_conn(A, B)], logins=[F.login(A, B, False, count=12)]), pol)
        self.assertEqual(s["level"], "high")

    def test_cleared_flow_is_allowed_but_failures_escalate(self):
        """A user-cleared segmentation flow (MAC form) makes a success allowed-admin; failures still escalate.
        REQ: LAT-01, RISK-04"""
        pol = F.zone_policy(_cleared_seg={f"{F.mac(1)}|{B}|22"})
        s = self.lvl(raw(conns=[F.admin_conn(A, B)]), pol)
        self.assertEqual((s["level"], s["why"]), ("allowed-admin", "allowed: segmentation flow cleared by a user"))
        self.assertEqual(self.lvl(raw(conns=[F.admin_conn(A, B)], logins=[F.login(A, B, False)]), pol)["level"], "medium")

    def test_self_and_loopback_skipped(self):
        """Sessions to self or from/to loopback are ignored.
        REQ: LAT-01"""
        rows = lateral.admin_sessions(raw(logins=[F.login(A, A, False), F.login("127.0.0.1", B, False),
                                                  F.login(A, "127.0.0.1", False)]), self.pol)
        self.assertEqual(rows, [])

    def test_sorted_worst_first(self):
        """Sessions are sorted by level (high first), then by failures.
        REQ: LAT-01"""
        C = IP["phone"]
        rows = lateral.admin_sessions(raw(conns=[F.admin_conn(C, B)], logins=[F.login(A, B, False, count=20)]), self.pol)
        self.assertEqual([r["level"] for r in rows], ["high", "low"])

    def test_tool_evidence_resolved_by_inventory_name(self):
        """Endpoint admin-tool evidence resolves host names via the inventory and counts as a success.
        REQ: LAT-01"""
        r = raw(tools=[{"host": "admin laptop", "target": "lab server", "protocol": "SSH", "tool": "ssh", "count": 2}],
                inventory_ips={A: "Admin Laptop", B: "Lab Server"})
        s = self.lvl(r)
        self.assertEqual((s["level"], s["outcome"]), ("low", "success"))

    def test_empty(self):
        """No admin evidence yields no sessions (also with no policy).
        REQ: LAT-01"""
        self.assertEqual(lateral.admin_sessions({}, None), [])


class BuildTests(unittest.TestCase):
    """build(): the lateral-movement graph."""

    def setUp(self):
        self.pol = F.zone_policy()

    def build(self, r, an=None, pol=None, rr=None):
        return lateral.build(r, an or {}, pol or self.pol, rr)

    def test_only_internal_edges(self):
        """Edges exist only between internal zoned hosts; internet, unzoned, self, broadcast and multicast are skipped.
        REQ: LAT-01"""
        flows = [F.flow(A, B, 80), F.flow(A, F.EXT["cdn"], 443), F.flow(A, "10.200.0.1", 80), F.flow(A, A, 80),
                 F.flow(A, "10.0.1.255", 137), F.flow(A, "224.0.0.251", 5353)]
        g = self.build(raw(flows=flows))
        self.assertEqual([(e["src"], e["dst"]) for e in g["edges"]], [(A, B)])
        self.assertEqual({n["id"] for n in g["nodes"]}, {A, B})
        self.assertEqual(g["zones"], ["servers", "user"])

    def test_violation_sets_edge_level(self):
        """A segmentation violation gives its port the violation severity and reason.
        REQ: LAT-01"""
        an = {"violations": [{"src": A, "dst": B, "port": 22, "proto": "tcp", "severity": "high", "reason": "admin port"}]}
        g = self.build(raw(flows=[F.flow(A, B, 22), F.flow(A, B, 80)]), an)
        e = edge(g, A, B)
        self.assertEqual(e["level"], "high")
        self.assertEqual((e["ports"][0]["port"], e["ports"][0]["level"], e["ports"][0]["why"]), (22, "high", "admin port"))
        self.assertEqual(g["counts"]["high"], 1)

    def test_cleared_violation_shown_allowed(self):
        """A violation on a user-cleared flow is shown as allowed-admin.
        REQ: LAT-01, RISK-04"""
        an = {"violations": [{"src": A, "dst": B, "port": 22, "proto": "tcp", "severity": "high", "reason": "x"}]}
        g = self.build(raw(flows=[F.flow(A, B, 22)]), an, F.zone_policy(_cleared_seg={f"{F.mac(1)}|{B}|22"}))
        self.assertEqual(edge(g, A, B)["level"], "allowed-admin")

    def test_port_classification(self):
        """Unanswered sensitive port x5 is medium, scanner traffic medium, answered sensitive low/allowed, else normal.
        REQ: LAT-01"""
        C, D = IP["camera"], IP["phone"]
        flows = [F.flow(A, B, 3389, conns=5, answered=0), F.flow(C, B, 9999, answered=0), F.flow(D, B, 22),
                 F.flow(A, C, 5353, proto="udp"), F.flow(D, C, 22)]
        pol = F.zone_policy(allow=[{"src": D, "dst": C, "ports": [22]}])
        g = self.build(raw(flows=flows, scans=[{"src": C, "failed_conns": 100}]), pol=pol)
        self.assertEqual(edge(g, A, B)["level"], "medium")
        self.assertEqual(edge(g, C, B)["level"], "medium")
        self.assertIn("internal scan", edge(g, C, B)["ports"][0]["why"])
        self.assertEqual(edge(g, D, B)["level"], "low")
        self.assertEqual(edge(g, A, C)["level"], "normal")
        self.assertEqual(edge(g, A, C)["ports"][0]["why"], "discovery/gateway service")
        self.assertEqual(edge(g, D, C)["level"], "allowed-admin")

    def test_unanswered_sensitive_below_threshold_normal(self):
        """Four unanswered attempts at a sensitive port stay normal (threshold is 5).
        REQ: LAT-01"""
        g = self.build(raw(flows=[F.flow(A, B, 3389, conns=4, answered=0)]))
        self.assertEqual(edge(g, A, B)["level"], "normal")

    def test_edge_takes_worst_port_and_sums(self):
        """An edge aggregates conns/answered/bytes of its ports and takes the worst port level.
        REQ: LAT-01, LAT-02"""
        g = self.build(raw(flows=[F.flow(A, B, 80, conns=10, answered=10, nbytes=1000), F.flow(A, B, 22, conns=3, answered=3, nbytes=50)]))
        e = edge(g, A, B)
        self.assertEqual((e["conns"], e["answered"], e["bytes"]), (13, 13, 1050.0))
        self.assertEqual(e["level"], "low")
        self.assertEqual([p["port"] for p in e["ports"]], [22, 80])

    def test_admin_session_raises_edge(self):
        """Admin sessions attach to edges (even without flows) and raise the edge and port level.
        REQ: LAT-01"""
        g = self.build(raw(flows=[F.flow(A, B, 22)], logins=[F.login(A, B, False, count=15)],
                           conns=[F.admin_conn(A, B)]))
        e = edge(g, A, B)
        self.assertEqual(e["level"], "high")
        self.assertEqual(e["ports"][0]["level"], "high")
        self.assertEqual(e["auth_fail"], 15)
        self.assertEqual(len(e["admin"]), 1)  # conn + login evidence for SSH merge into one session
        self.assertEqual((e["admin"][0]["auth_fail"], e["admin"][0]["ports"]), (15, [22]))
        g2 = self.build(raw(logins=[F.login(IP["phone"], B, False)]))
        e2 = edge(g2, IP["phone"], B)
        self.assertEqual((e2["level"], e2["conns"]), ("medium", 0))
        self.assertTrue(g2["admin_collected"])

    def test_edge_score_formula(self):
        """Edge score = weight x (0.6 + 0.2 x dst impact) x (1 + conns/1000) x (1 + fails/25).
        REQ: LAT-01"""
        g = self.build(raw(flows=[F.flow(A, B, 22, conns=100)]), rr={"hosts": [{"ip": B, "impact": 5, "score": 40, "rank": 1}]})
        e = edge(g, A, B)
        self.assertEqual(e["score"], round(1 * (0.6 + 0.2 * 5) * 1.1 * 1, 2))
        node = next(n for n in g["nodes"] if n["id"] == B)
        self.assertEqual((node["risk"], node["rank"], node["in_risky"], node["in_conns"]), (40, 1, 1, 100))
        g2 = self.build(raw(flows=[F.flow(A, B, 22, conns=5000)], logins=[F.login(A, B, False, count=100)]))
        self.assertEqual(edge(g2, A, B)["score"], round(3 * (0.6 + 0.2 * 3) * 2 * 3, 2))

    def test_gateway_naming(self):
        """Gateway addresses (.1) are named after their zone and flagged as gateways.
        REQ: LAT-01"""
        g = self.build(raw(flows=[F.flow(A, "10.0.1.1", 53, proto="udp")]))
        gw = next(n for n in g["nodes"] if n["id"] == "10.0.1.1")
        self.assertEqual((gw["name"], gw["gateway"]), ("gateway (user)", True))
        self.assertEqual(edge(g, A, "10.0.1.1")["level"], "normal")

    def test_counts_cover_all_levels(self):
        """The counts summary has every level key and sums to the edge count.
        REQ: LAT-01"""
        g = self.build(raw(flows=[F.flow(A, B, 22), F.flow(B, A, 80)]))
        self.assertEqual(set(g["counts"]), set(lateral.ORDER))
        self.assertEqual(sum(g["counts"].values()), len(g["edges"]))


class MergePeriodsTests(unittest.TestCase):
    """merge_periods(): several periods combined into one raw/analysis pair."""

    def test_flows_summed_per_key(self):
        """Flows with the same (src, dst, port, proto) have conns/answered/bytes summed; others kept apart.
        REQ: LAT-02"""
        p1 = {"internal": {"flows": [F.flow(A, B, 22, conns=2, answered=1, nbytes=10), F.flow(A, B, 80)]}}
        p2 = {"internal": {"flows": [F.flow(A, B, 22, conns=3, answered=0, nbytes=None), F.flow(A, B, 22, proto="udp")]}}
        r, an = lateral.merge_periods([p1, p2])
        fl = {(f["port"], f["proto"]): f for f in r["internal"]["flows"]}
        self.assertEqual(len(fl), 3)
        self.assertEqual((fl[(22, "tcp")]["conns"], fl[(22, "tcp")]["answered"], fl[(22, "tcp")]["bytes"]), (5, 1, 10))
        self.assertEqual(an, {"violations": []})

    def test_inputs_not_mutated(self):
        """Merging does not modify the input period dicts.
        REQ: LAT-02"""
        f = F.flow(A, B, 22, conns=2)
        lateral.merge_periods([{"internal": {"flows": [f]}}, {"internal": {"flows": [F.flow(A, B, 22, conns=3)]}}])
        self.assertEqual(f["conns"], 2)

    def test_violations_summed_worst_severity(self):
        """Violations are summed per flow and keep the worst severity with its reason.
        REQ: LAT-02"""
        v = {"src": A, "dst": B, "port": 22, "proto": "tcp", "conns": 2, "answered": 1, "bytes": 5}
        _, an = lateral.merge_periods([{"violations": [{**v, "severity": "low", "reason": "a"}]},
                                       {"violations": [{**v, "severity": "high", "reason": "b"}]},
                                       {"violations": [{**v, "severity": "medium", "reason": "c"}]}])
        m = an["violations"][0]
        self.assertEqual((m["conns"], m["answered"], m["bytes"], m["severity"], m["reason"]), (6, 3, 15, "high", "b"))

    def test_scans_keep_worst_per_source(self):
        """Internal scans keep the record with the most failed connections per source.
        REQ: LAT-02"""
        r, _ = lateral.merge_periods([{"internal": {"scans": [{"src": A, "failed_conns": 50}]}},
                                      {"internal": {"scans": [{"src": A, "failed_conns": 80}, {"src": B, "failed_conns": 1}]}},
                                      {"internal": {"scans": [{"src": A, "failed_conns": 10}]}}])
        sc = {s["src"]: s["failed_conns"] for s in r["internal"]["scans"]}
        self.assertEqual(sc, {A: 80, B: 1})

    def test_admin_concatenated_and_sources_summed(self):
        """Admin conns/logins/tools are concatenated, source counts summed, devices and inventory merged.
        REQ: LAT-02"""
        p1 = {"admin_access": {"logins": [F.login(A, B, False, count=5)], "sources": {"auth": 3}, "errors": {"x": "e1"}},
              "devices": {A: {"mac": F.mac(1)}}, "inventory_ips": {A: "lap"}}
        p2 = {"admin_access": {"logins": [F.login(A, B, False, count=5)], "conns": [F.admin_conn(A, B)], "sources": {"auth": 4, "zeek": None}},
              "devices": {B: {"mac": F.mac(2)}}, "inventory_ips": {B: "srv"}}
        r, _ = lateral.merge_periods([p1, p2])
        adm = r["admin_access"]
        self.assertEqual((len(adm["logins"]), len(adm["conns"]), adm["tools"]), (2, 1, []))
        self.assertEqual(adm["sources"], {"auth": 7, "zeek": 0})
        self.assertEqual(adm["errors"], {"x": "e1"})
        self.assertEqual(set(r["devices"]), {A, B})
        self.assertEqual(r["inventory_ips"], {A: "lap", B: "srv"})

    def test_merged_failures_cross_threshold(self):
        """Failures split over two periods add up: 5 + 5 failed logins become one high session in the merged graph.
        REQ: LAT-02, LAT-01"""
        p = {"admin_access": {"logins": [F.login(A, B, False, count=5)]}, "devices": {A: {"mac": F.mac(1)}}}
        one = lateral.build(*lateral.merge_periods([p]), F.zone_policy(), None)
        both = lateral.build(*lateral.merge_periods([p, p]), F.zone_policy(), None)
        self.assertEqual(edge(one, A, B)["level"], "medium")
        self.assertEqual(edge(both, A, B)["level"], "high")

    def test_empty(self):
        """No periods give an empty but well-formed raw/analysis pair.
        REQ: LAT-02"""
        r, an = lateral.merge_periods([])
        self.assertEqual(r["internal"], {"flows": [], "scans": []})
        self.assertEqual(r["admin_access"], {"conns": [], "logins": [], "tools": [], "sources": {}, "errors": {}})
        self.assertEqual(an, {"violations": []})


if __name__ == "__main__":
    unittest.main()
