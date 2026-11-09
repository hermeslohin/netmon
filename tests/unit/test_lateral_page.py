"""Unit tests for the Lateral movement page: lateral.build() gaps (naming, gateways, scans, allow/cleared flows, internet hosts), server.lateral_periods() and lateral.js page logic under node."""
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); import _env  # noqa: E401,E702,E402

import json  # noqa: E402
import shutil  # noqa: E402
import subprocess  # noqa: E402
import unittest  # noqa: E402

import fixtures as F  # noqa: E402
import corr_llm  # noqa: E402
import lateral  # noqa: E402
import server  # noqa: E402
import store  # noqa: E402

IP, EXT = F.IPS, F.EXT
A, B, C, D, P = IP["laptop"], IP["server"], IP["camera"], IP["dmz"], IP["phone"]
GW = A.rsplit(".", 1)[0] + ".1"        # the user zone's gateway interface
NODE_FALLBACK = os.path.expanduser(os.environ.get("NETMON_NODE", "~/.hermes/tools/node-26.7.0-linux-arm64/bin/node"))
NODE = shutil.which("node") or (NODE_FALLBACK if os.path.exists(NODE_FALLBACK) else None)
LAT_JS = os.path.join(_env.APP, "static", "lateral.js")
APP_JS = os.path.join(_env.APP, "static", "app.js")


def raw(flows=(), logins=(), conns=(), scans=(), devices=None, inv=None, **extra):
    r = {"devices": devices if devices is not None else {A: {"mac": F.mac(1), "name": "Admin Laptop", "known": True},
                                                          B: {"mac": F.mac(2), "name": "Lab Server", "known": True}},
         "admin_access": {"logins": list(logins), "conns": list(conns), "tools": [], "sources": {"auth": 1}},
         "internal": {"flows": list(flows), "scans": list(scans)}, "inventory_ips": inv or {}}
    r.update(extra)
    return r


def edge(g, s, t):
    return next((e for e in g["edges"] if e["src"] == s and e["dst"] == t), None)


def node(g, ip):
    return next((n for n in g["nodes"] if n["id"] == ip), None)


def viol(src, dst, port, sev="high", reason="dmz -> protected", conns=4):
    return {"src": src, "dst": dst, "port": port, "proto": "tcp", "conns": conns, "answered": conns, "bytes": 100,
            "severity": sev, "reason": reason}


def reset():
    _env.fresh_db()
    server._cache.clear()
    server._MAC2IP.update(sid=None, v={})


# ------------------------------------------------------------------ lateral.build(): what test_lateral.py does not cover
class NamingTests(unittest.TestCase):
    """Node names, gateway names, inventory flag and device class on the graph."""

    def test_device_name_then_inventory_then_known_benign_then_ip(self):
        """A host is named after its device, else its inventory entry, else a known-benign name, else its IP.
        REQ: LAT-20"""
        r = raw(flows=[F.flow(A, B, 80), F.flow(A, C, 80), F.flow(A, D, 80), F.flow(A, P, 80)], inv={C: "Yard Camera", A: "inventory name"})
        g = lateral.build(r, {}, F.zone_policy(), None, {"names": {D: "Game box (kb)", A: "kb name"}})
        self.assertEqual({ip: node(g, ip)["name"] for ip in (A, B, C, D, P)},
                         {A: "Admin Laptop", B: "Lab Server", C: "Yard Camera", D: "Game box (kb)", P: P})

    def test_gateway_named_from_known_benign(self):
        """A gateway interface (.1) takes its known-benign name when there is one, else 'gateway (<zone>)'; it is never 'known'.
        REQ: LAT-20"""
        r = raw(flows=[F.flow(A, GW, 53, proto="udp"), F.flow(B, B.rsplit(".", 1)[0] + ".1", 53, proto="udp")])
        g = lateral.build(r, {}, F.zone_policy(), None, {"names": {GW: "Core router"}})
        self.assertEqual((node(g, GW)["name"], node(g, GW)["gateway"], node(g, GW)["known"]), ("Core router", True, False))
        self.assertEqual(node(g, B.rsplit(".", 1)[0] + ".1")["name"], "gateway (servers)")

    def test_known_flag_and_device_class(self):
        """Nodes carry 'known' from the device record and their device class (by MAC, else by IP).
        REQ: LAT-20"""
        devs = {A: {"mac": F.mac(1), "name": "Admin Laptop", "known": True}, B: {"mac": F.mac(2), "name": "Lab Server", "known": False}}
        pol = F.zone_policy(device_classes={F.mac(1): "work", C: "camera"})
        g = lateral.build(raw(flows=[F.flow(A, B, 80), F.flow(C, B, 80)], devices=devs), {}, pol, None)
        self.assertEqual([(node(g, ip)["known"], node(g, ip)["class"]) for ip in (A, B, C)], [(True, "work"), (False, ""), (False, "camera")])


class PortRuleTests(unittest.TestCase):
    """Port classification exceptions: gateways, scans, UDP, allow-rule reasons."""

    def test_gateway_and_udp_exceptions(self):
        """Unanswered admin-port attempts to a gateway, or over UDP, stay normal; scan traffic to a gateway or answered is not a scan link.
        REQ: LAT-21"""
        flows = [F.flow(A, GW, 22, conns=9, answered=0), F.flow(A, B, 3389, proto="udp", conns=9, answered=0),
                 F.flow(C, GW, 9999, answered=0), F.flow(C, B, 8080, answered=3, conns=3)]
        g = lateral.build(raw(flows=flows, scans=[{"src": C, "failed_conns": 90}]), {}, F.zone_policy(), None)
        self.assertEqual((edge(g, A, GW)["level"], edge(g, A, GW)["ports"][0]["why"]), ("normal", "discovery/gateway service"))
        self.assertEqual(edge(g, A, B)["level"], "normal")
        self.assertEqual(edge(g, C, GW)["level"], "normal")
        self.assertEqual((edge(g, C, B)["level"], edge(g, C, B)["ports"][0]["why"]), ("normal", ""))

    def test_scan_reason_names_the_scanner(self):
        """An unanswered TCP flow from an internal scanner is medium and its reason names the scanner.
        REQ: LAT-21"""
        g = lateral.build(raw(flows=[F.flow(A, B, 9999, answered=0)], scans=[{"src": A, "failed_conns": 300}]), {}, F.zone_policy(), None)
        self.assertEqual(edge(g, A, B)["ports"][0]["why"], "part of internal scan by Admin Laptop")

    def test_allow_rule_reason_on_edges(self):
        """An allow rule gives an answered admin port 'admin port, allowed: <why>' and a plain port its reason as the why text.
        REQ: LAT-22"""
        pol = F.zone_policy(allow=[{"src": A, "dst": B, "why": "backup job"}])
        g = lateral.build(raw(flows=[F.flow(A, B, 22), F.flow(A, B, 873)]), {}, pol, None)
        why = {p["port"]: (p["level"], p["why"]) for p in edge(g, A, B)["ports"]}
        self.assertEqual(why, {22: ("allowed-admin", "admin port, allowed: backup job"), 873: ("normal", "backup job")})
        self.assertEqual(edge(g, A, B)["level"], "allowed-admin")

    def test_allow_rule_does_not_hide_violation_or_failures(self):
        """A violation or repeated unanswered admin attempts are rated before the allow list, so allowing the pair does not hide them.
        REQ: LAT-22"""
        pol = F.zone_policy(allow=[{"src": "*", "dst": "*"}])
        g = lateral.build(raw(flows=[F.flow(D, B, 22), F.flow(A, B, 3389, conns=6, answered=0)]), {"violations": [viol(D, B, 22)]}, pol, None)
        self.assertEqual((edge(g, D, B)["level"], edge(g, A, B)["level"]), ("high", "medium"))


class ClearedFlowTests(unittest.TestCase):
    """Cleared segmentation flows (ack type 'seg', MAC/IP form, suppress rules) on the graph."""

    def setUp(self):
        reset()

    def test_cleared_port_only(self):
        """Clearing one flow (IP form) makes that port allowed-admin; other ports on the same link keep their level.
        REQ: LAT-23"""
        pol = F.zone_policy(_cleared_seg={f"{D}|{B}|22"})
        g = lateral.build(raw(flows=[F.flow(D, B, 22), F.flow(D, B, 3389, conns=7, answered=0)]), {"violations": [viol(D, B, 22)]}, pol, None)
        lv = {p["port"]: (p["level"], p["why"]) for p in edge(g, D, B)["ports"]}
        self.assertEqual(lv[22], ("allowed-admin", "segmentation flow cleared by a user"))
        self.assertEqual(lv[3389][0], "medium")
        self.assertEqual(edge(g, D, B)["level"], "medium")

    def test_cleared_from_ack_store_and_suppress_rule(self):
        """server.with_cleared() feeds the check-off store (MAC form) and segmentation suppress rules into the graph as allowed flows.
        REQ: LAT-23, POS-11"""
        store.ack_set("seg", f"{F.mac(4)}|{B}|22", True)
        store.seg_suppress_add(C, "", "3389", "test")
        devs = {D: {"mac": F.mac(4), "name": "DMZ Game Box", "known": True}, B: {"mac": F.mac(2), "name": "Lab Server", "known": True}}
        an = {"violations": [viol(D, B, 22), viol(C, B, 3389, "high", "iot -> servers")]}
        pol = server.with_cleared(F.zone_policy())
        g = lateral.build(raw(flows=[F.flow(D, B, 22), F.flow(C, B, 3389), F.flow(C, B, 445)], devices=devs), an, pol, None)
        self.assertEqual(edge(g, D, B)["level"], "allowed-admin")
        lv = {p["port"]: p["level"] for p in edge(g, C, B)["ports"]}
        self.assertEqual(lv, {3389: "allowed-admin", 445: "low"})
        store.ack_set("seg", f"{F.mac(4)}|{B}|22", False)
        g2 = lateral.build(raw(flows=[F.flow(D, B, 22)], devices=devs), an, server.with_cleared(F.zone_policy()), None)
        self.assertEqual(edge(g2, D, B)["level"], "high")


class InternetAndAdminEdgeTests(unittest.TestCase):
    """Internet hosts are never on the graph; admin evidence adds port rows and fields to edges."""

    def test_admin_session_to_internet_not_mapped(self):
        """An admin session to an internet address stays in the admin list but adds no edge or node.
        REQ: LAT-24"""
        g = lateral.build(raw(logins=[F.login(A, EXT["bad"], False, count=3)]), {}, F.zone_policy(), None)
        self.assertEqual((g["edges"], g["nodes"], len(g["admin"])), ([], [], 1))

    def test_admin_session_from_internet_not_mapped(self):
        """An admin session from an internet address does not put the internet host on the graph.
        REQ: LAT-24"""
        g = lateral.build(raw(logins=[F.login(EXT["bad"], B, False, count=3)]), {}, F.zone_policy(), None)
        self.assertEqual([n["zone"] for n in g["nodes"] if n["zone"] == "internet"], [])
        self.assertIsNone(edge(g, EXT["bad"], B))

    def test_admin_port_row_added_and_sorted(self):
        """A session on a port without a flow adds a port row (protocol as service, session level and reason); rows sort worst first.
        REQ: LAT-25"""
        g = lateral.build(raw(flows=[F.flow(A, B, 80, conns=50)], logins=[F.login(A, B, False, count=2)],
                              conns=[F.admin_conn(A, B, attempts=4, connected=2, failed=2)]), {}, F.zone_policy(), None)
        e = edge(g, A, B)
        self.assertEqual([(p["port"], p["service"], p["level"]) for p in e["ports"]], [(22, "SSH", "medium"), (80, "", "normal")])
        self.assertEqual((e["ports"][0]["conns"], e["ports"][0]["answered"], e["ports"][0]["why"]), (4, 2, "2 failed login(s)"))
        self.assertEqual((e["auth_fail"], e["auth_ok"], e["conns"]), (2, 0, 50))
        self.assertEqual(e["score"], round(2 * (0.6 + 0.2 * 3) * 1.05 * (1 + 4 / 25), 2))  # fails = 2 logins + 2 refused

    def test_login_only_session_port_zero(self):
        """A session seen only in login logs (no port) gets a port-0 row counting its logins.
        REQ: LAT-25"""
        g = lateral.build(raw(logins=[F.login(A, B, True, count=3, protocol="RDP")]), {}, F.zone_policy(), None)
        p = edge(g, A, B)["ports"][0]
        self.assertEqual((p["port"], p["service"], p["conns"], p["answered"]), (0, "RDP", 3, 3))


class GraphSummaryTests(unittest.TestCase):
    """Node counters, edge order and the admin-collection flags."""

    def test_node_counters_and_edge_order(self):
        """Nodes count risky links and connections in/out; edges sort by level, then score.
        REQ: LAT-26"""
        flows = [F.flow(D, B, 22, conns=3), F.flow(A, B, 22, conns=8), F.flow(C, B, 22, conns=2), F.flow(A, C, 80, conns=5)]
        g = lateral.build(raw(flows=flows), {"violations": [viol(D, B, 22)]}, F.zone_policy(), None)
        self.assertEqual([(e["src"], e["dst"]) for e in g["edges"]], [(D, B), (A, B), (C, B), (A, C)])
        b, a = node(g, B), node(g, A)
        self.assertEqual((b["in_risky"], b["in_conns"], b["out_risky"], b["out_conns"]), (3, 13, 0, 0))
        self.assertEqual((a["out_risky"], a["out_conns"]), (1, 13))

    def test_admin_collected_and_sources(self):
        """admin_collected is false for snapshots without admin_access; admin_sources passes the collector's source counts on.
        REQ: LAT-26"""
        r = raw(flows=[F.flow(A, B, 80)])
        self.assertEqual(lateral.build(r, {}, F.zone_policy(), None)["admin_sources"], {"auth": 1})
        r.pop("admin_access")
        g = lateral.build(r, {}, F.zone_policy(), None)
        self.assertEqual((g["admin_collected"], g["admin_sources"], g["admin"]), (False, None, []))


class ResolverTests(unittest.TestCase):
    """_resolver(): endpoint host names to internal IPs for admin evidence."""

    def test_resolve_ip_hostname_fqdn_inventory(self):
        """IPs pass through; host names resolve by device name/hostname (short, > 3 chars) or inventory name, FQDNs by their first label.
        REQ: LAT-27"""
        r = {"devices": {B: {"name": "Lab Server", "hostname": "labsrv"}}, "inventory_ips": {A: "Admin-Laptop"}}
        res = lateral._resolver(r)
        self.assertEqual([res(x) for x in (C, "labsrv.example.lan", "LAB", "admin-laptop", "admin-laptop.example.lan", "", None, "nosuch")],
                         [C, B, "", A, A, "", "", ""])


class PeriodGraphTests(unittest.TestCase):
    """Several periods merged then drawn as one graph."""

    def test_link_in_one_period_and_worst_level_kept(self):
        """A link seen in only one period appears; a link high in one period and normal in another stays high with summed counts.
        REQ: LAT-28, LAT-02"""
        p1 = {"internal": {"flows": [F.flow(D, B, 22, conns=2)]}, "violations": [viol(D, B, 22, "high", "dmz -> protected", 2)],
              "devices": {B: {"mac": F.mac(2), "name": "Lab Server"}}}
        p2 = {"internal": {"flows": [F.flow(D, B, 22, conns=5), F.flow(A, C, 80)], "scans": [{"src": A, "failed_conns": 99}]}}
        g = lateral.build(*lateral.merge_periods([p1, p2]), F.zone_policy(), None)
        self.assertEqual((edge(g, D, B)["level"], edge(g, D, B)["conns"]), ("high", 7))
        self.assertIsNotNone(edge(g, A, C))
        self.assertEqual(node(g, B)["name"], "Lab Server")
        self.assertTrue(g["admin_collected"])  # the merged pair always carries admin_access


# ------------------------------------------------------------------ server.lateral_periods() with a stubbed host broker
class LateralPeriodsTests(unittest.TestCase):
    """server.lateral_periods(): validation, broker calls per period, merge."""

    def setUp(self):
        reset()
        self._broker, self.calls = corr_llm.broker, []

    def tearDown(self):
        corr_llm.broker = self._broker

    def stub(self, data=None, exc=None):
        """Fake broker: /range -> id from the start time, /section writes that id's lateral section (unless data lacks it)."""
        def fake(path, body=None, timeout=330):
            self.calls.append((path, body))
            if exc:
                raise exc
            if path == "/range":
                return {"id": "r" + body["start"][:10].replace("-", "")}
            d = (data or {}).get(body["id"])
            if d is not None:
                store.jdump(d, os.path.join(server.RANGES, body["id"] + ".sec.lateral.json"))
            return {"status": "done"}
        corr_llm.broker = fake

    def test_periods_merged_via_broker(self):
        """Each period is asked for with /range and its 'lateral' section, then all periods are merged.
        REQ: LAT-29"""
        d1 = {"internal": {"flows": [F.flow(A, B, 22, conns=2)]}}
        d2 = {"internal": {"flows": [F.flow(A, B, 22, conns=3)]}}
        self.stub({"r20260101": d1, "r20260102": d2})
        rw, an = server.lateral_periods([("2026-01-01T00:00:00Z", "2026-01-01T06:00:00Z"), ("2026-01-02T00:00:00+00:00", "2026-01-02T06:00:00+00:00")])
        self.assertEqual(rw["internal"]["flows"][0]["conns"], 5)
        self.assertEqual(an, {"violations": []})
        self.assertEqual(sorted((b for p, b in self.calls if p == "/range"), key=lambda b: b["start"]),
                         [{"start": "2026-01-01T00:00:00+00:00", "end": "2026-01-01T06:00:00+00:00"},
                          {"start": "2026-01-02T00:00:00+00:00", "end": "2026-01-02T06:00:00+00:00"}])
        self.assertEqual(sorted(b["id"] for p, b in self.calls if p == "/section"), ["r20260101", "r20260102"])
        self.assertTrue(all(b["name"] == "lateral" for p, b in self.calls if p == "/section"))

    def test_validation(self):
        """Periods without a UTC offset, unparsable, or none at all are a ValueError before the broker is asked.
        REQ: LAT-29"""
        self.stub()
        for per in ([("2026-01-01T00:00:00", "2026-01-01T06:00:00")], [("yesterday", "today")], []):
            with self.assertRaises(ValueError):
                server.lateral_periods(per)
        self.assertEqual(self.calls, [])

    def test_at_most_eight_periods(self):
        """Only the first 8 periods are queried.
        REQ: LAT-29"""
        days = [f"2026-01-{d:02d}" for d in range(1, 11)]
        self.stub({"r" + d.replace("-", ""): {} for d in days})
        server.lateral_periods([(d + "T00:00:00Z", d + "T06:00:00Z") for d in days])
        self.assertEqual(len([1 for p, _ in self.calls if p == "/range"]), 8)

    def test_broker_errors_become_value_errors(self):
        """A broker error, or a period whose section never appeared, is a ValueError with a readable message.
        REQ: LAT-29"""
        self.stub(exc=RuntimeError("broker: Elasticsearch unreachable"))
        with self.assertRaisesRegex(ValueError, "^Elasticsearch unreachable$"):
            server.lateral_periods([("2026-01-01T00:00:00Z", "2026-01-01T06:00:00Z")])
        self.stub({})
        with self.assertRaisesRegex(ValueError, "no data for r20260101"):
            server.lateral_periods([("2026-01-01T00:00:00Z", "2026-01-01T06:00:00Z")])

    def test_user_role_cannot_read_lateral(self):
        """The User role's GET allow-list has neither /api/lateral nor /api/risk.
        REQ: LAT-31"""
        self.assertNotIn("/api/lateral", server.USER_GET)
        self.assertNotIn("/api/risk", server.USER_GET)


# ------------------------------------------------------------------ lateral.js under node
JS_HARNESS = r"""
const fs = require("fs"), vm = require("vm");
const [latPath, appPath, dataPath, bodyPath] = process.argv.slice(2);
const app = fs.readFileSync(appPath, "utf8"), data = JSON.parse(fs.readFileSync(dataPath, "utf8"));
const slice = (s, a, b) => { const i = s.indexOf(a); if (i < 0) throw new Error("missing " + a); const j = s.indexOf(b, i); if (j < 0) throw new Error("missing " + b); return s.slice(i, j); };
class El {
  constructor(tag, id) { this.tag = tag; this.id = id || ""; this.children = []; this.attrs = {}; this.style = {}; this.dataset = {}; this.html = []; this._inner = "";
    this.textContent = ""; this.classList = { add() {}, contains: () => false }; this.className = ""; }
  set innerHTML(v) { this._inner = String(v); this.children = []; this.html = []; }
  get innerHTML() { return this._inner; }
  insertAdjacentHTML(_, h) { this.html.push(h); }
  appendChild(c) { this.children.push(c); return c; }
  append(...c) { this.children.push(...c); }
  setAttribute(k, v) { this.attrs[k] = String(v); }
  getAttribute(k) { return this.attrs[k]; }
  addEventListener() {}
  querySelector(s) { const me = this; return s === ".loading" ? { set outerHTML(v) { me.error = v; }, remove() { me.loaded = true; } } : null; }
  scrollIntoView() {} setPointerCapture() {} getBoundingClientRect() { return { left: 0, top: 0, width: 900, height: 600 }; }
  toString() { return "[object HTMLDivElement]"; }  // what string + element gives in a browser
}
const reg = new Map();
const txt = (x) => x == null ? "" : typeof x === "string" ? x : Array.isArray(x) ? x.map(txt).join("\n")
  : x instanceof El ? [x.title || "", x._inner, ...x.html, x.textContent, ...(x.cells || []).flat().map(String), ...x.children.map(txt)].join("\n") : String(x);
const walk = (x, f, acc = []) => { if (x instanceof El) { if (f(x)) acc.push(x); x.children.forEach((c) => walk(c, f, acc)); } return acc; };
const ctx = { console, JSON, Math, Object, Array, Set, Map, String, Number, Promise, Error, URLSearchParams, encodeURIComponent, El, reg, txt, walk,
  V: {}, DATA: data, calls: [], HQ: "", apiError: null, result: null, innerWidth: 1200, innerHeight: 800 };
ctx.window = ctx;
ctx.out = (v) => { ctx.result = v; };
ctx.matchMedia = () => ({ matches: false });
ctx.addEventListener = ctx.removeEventListener = ctx.clearTimeout = ctx.scrollTo = ctx.go = () => {};
ctx.setTimeout = () => 0;
ctx.document = { createElement: (t) => new El(t), createElementNS: (ns, t) => new El(t), addEventListener() {},
  getElementById: (id) => { if (!reg.has(id)) reg.set(id, new El("div", id)); return reg.get(id); } };
ctx.S = { snap: { id: data.sid, raw: data.raw, analysis: data.analysis }, acks: data.acks || {}, extra: data.extra || null };
Object.assign(ctx, {
  esc: (s) => String(s ?? ""), fn: (n) => String(n ?? 0), fb: (n) => String(n ?? 0) + "B", ft: (t) => (t ? String(t) : ""), riskBadge: (v) => "risk " + v,
  entries: (o) => Object.entries(o || {}), kpis: (l) => "KPIS:" + JSON.stringify(l), clickable: () => ({}), drillHere() {},
  hq: () => new URLSearchParams(ctx.HQ),
  card: (title, body) => { const c = new El("div"); c.title = title; c.body = typeof body === "string" ? body : null;
    if (typeof body === "string") { const w = new El("div"); w._inner = body; c.children.push(w); } else if (body) c.children.push(body); return c; },
  table: (id, cols, rows, opts = {}) => { const t = new El("table"); t.isTable = true; t.cols = cols.map((c) => c.t); t.rows = rows; t.opts = opts;
    t.cells = rows.map((r) => cols.map((c) => (c.fmt ? c.fmt(r[c.k], r) : r[c.k]))); return t; },
  grid: (cls, ...cs) => { const g = new El("div"); cs.filter(Boolean).forEach((c) => g.children.push(c)); return g; },
  chartCard: (title, cfg) => { const c = new El("div"); c.title = title; c.cfg = cfg; return c; },
  doughnutCfg: (o) => ({ data: { labels: Object.keys(o), datasets: [{ data: Object.values(o) }] } }),
  ACK: { admin: (s) => `${s.src}|${s.dst}|${s.protocol}` },
});
ctx.acked = (t, x) => !!ctx.S.acks?.[t]?.[ctx.ACK[t](x)];
ctx.ackInfo = (t, x) => ctx.S.acks?.[t]?.[ctx.ACK[t](x)];
ctx.ackCol = (t) => ({ k: "_ack", t: "✓", fmt: (v, x) => (ctx.acked(t, x) ? "[x]" : "[ ]") });
ctx.ackRowCls = () => () => "";
ctx.api = async (u) => { ctx.calls.push(u); if (ctx.apiError) throw new Error(ctx.apiError); return JSON.parse(JSON.stringify(data.D)); };
vm.createContext(ctx);
vm.runInContext(slice(app, "function hashWith(", "\nfunction hashWithout") + "\n" + slice(app, "const SEG_RE", "const ackRef") + "\n"
  + slice(app, "function segClearedCard() {", "/* ---------- suppress rules (Settings"), ctx);
vm.runInContext(fs.readFileSync(latPath, "utf8"), ctx);
(async () => {
  await vm.runInContext("(async () => {\n" + fs.readFileSync(bodyPath, "utf8") + "\n})()", ctx);
  process.stdout.write(JSON.stringify(ctx.result));
})().catch((e) => { console.error((e && e.stack) || e); process.exit(1); });
"""


def page_raw():
    """A snapshot slice for the page: 5 internal hosts (2 not in the device list), a gateway, every link level and two admin sessions."""
    devs = {A: {"mac": F.mac(1), "name": "Admin Laptop", "known": True}, B: {"mac": F.mac(2), "name": "Lab Server", "known": True},
            D: {"mac": F.mac(4), "name": "DMZ Game Box", "known": True}}
    flows = [F.flow(A, B, 22, src_zone="user", dst_zone="servers"), F.flow(D, B, 22, conns=4), F.flow(C, B, 3389, conns=5, answered=0), F.flow(A, GW, 53, proto="udp"),
             F.flow(A, C, 80), F.flow(P, B, 22), F.flow(C, D, 445)]
    logins = [F.login(A, B, False, count=2, user="ops"), F.login(A, B, True, user="ops"), F.login(D, B, False, count=12, user="root")]
    return raw(flows=flows, logins=logins, conns=[F.admin_conn(A, B)], devices=devs, inv={C: "Yard Camera"})


def page_data(**over):
    r = page_raw()
    an = {"violations": [viol(D, B, 22)],
          "findings": [{"severity": "high", "device": D, "name": "DMZ Game Box", "kind": "segmentation", "detail": f"DMZ Game Box -> Lab Server ({B}) 22/tcp"}]}
    pol = F.zone_policy(allow=[{"src": P, "dst": B, "ports": [22], "why": "admin ws"}])
    rr = {"hosts": [{"ip": B, "score": 45, "rank": 1, "impact": 5}, {"ip": A, "score": 10, "rank": 2}, {"ip": C, "score": 30, "rank": 3}]}
    d = {"sid": F.SID, "raw": r, "analysis": an, "D": lateral.build(r, an, pol, rr), "acks": {}}
    d.update(over)
    return d


@unittest.skipUnless(NODE, "node not available")
class LateralPageJs(unittest.TestCase):
    """lateral.js (V.lateral and its helpers) under node with stubbed page helpers and real lateral.build() data."""

    def run_js(self, body, data=None):
        d = os.environ["NETMON_TEST_TMP"]
        paths = [os.path.join(d, n) for n in ("lat_harness.js", "lat_data.json", "lat_body.js")]
        for p, content in zip(paths, (JS_HARNESS, json.dumps(data or page_data()), body)):
            with open(p, "w", encoding="utf-8") as f:
                f.write(content)
        r = subprocess.run([NODE, paths[0], LAT_JS, APP_JS, paths[1], paths[2]], capture_output=True, text=True, timeout=60)  # noqa: S603 - node on repo files
        if r.returncode:
            raise AssertionError(r.stderr[-3000:])
        return json.loads(r.stdout)

    def test_filters(self):
        """The Show filter keeps risky / high+medium / risky+allowed / all links; gateway links only when ticked; focus keeps one host's links.
        REQ: LAT-32"""
        out = self.run_js("""
const D = DATA.D, r = {};
for (const f of ["risky", "high", "admin", "all"]) { LM.filter = f; r[f] = lmVisible(D).edges.length; }
LM.gateways = true; r.allGw = lmVisible(D).edges.length;
LM.focus = DATA.C; const v = lmVisible(D); r.focus = v.edges.map((e) => e.src + ">" + e.dst).sort(); r.focusNodes = v.nodes.map((n) => n.id).sort();
LM.focus = null; LM.filter = "high"; r.highLevels = [...new Set(lmVisible(D).edges.map((e) => e.level))].sort();
out(r);""".replace("DATA.C", json.dumps(C)))
        self.assertEqual({k: out[k] for k in ("risky", "high", "admin", "all", "allGw")}, {"risky": 4, "high": 3, "admin": 5, "all": 6, "allGw": 7})
        self.assertEqual(out["focus"], sorted([f"{A}>{C}", f"{C}>{B}", f"{C}>{D}"]))
        self.assertEqual(out["focusNodes"], sorted([A, B, C, D]))
        self.assertEqual(out["highLevels"], ["high", "medium"])

    def test_loads_snapshot_and_kpis(self):
        """Without extra periods the page asks /api/lateral?id=<snapshot>, shows the level KPIs (gateways not counted) and the filter/focus controls.
        REQ: LAT-33, LAT-34"""
        out = self.run_js("""
const el = new El("div"); await V.lateral(el);
const ctr = el.children.find((c) => c.className === "tbltools");
out({calls, html: el.html, loaded: !!el.loaded, ctr: ctr._inner, shown: el.children.filter((c) => c.title).map((c) => c.title),
     tcard: walk(el, (x) => x.title && x.title.startsWith("Connections shown")).map((x) => x.title)});""")
        self.assertEqual(out["calls"], [f"/api/lateral?id={F.SID}"])
        self.assertTrue(out["loaded"])
        kp = [h for h in out["html"] if h.startswith("KPIS:")][0]
        self.assertEqual(json.loads(kp[5:]), [["High-risk links", 1, "bad"], ["Medium-risk links", 2, "warn"], ["Low-risk links", 1],
                                              ["Allowed admin links", 1], ["Normal links", 2], ["Internal hosts", 5]])
        self.assertFalse(any("periods combined" in h for h in out["html"]))
        ctr = out["ctr"]
        self.assertEqual(ctr.count("<option value=\""), 4 + 1 + 5)  # 4 filters, '(none)', 5 hosts (gateway left out)
        self.assertIn('<option value="risky" selected>', ctr)
        self.assertNotIn(f'value="{GW}"', ctr)
        self.assertLess(ctr.index(f'value="{B}"'), ctr.index(f'value="{C}"'))  # focus list sorted by host risk
        self.assertLess(ctr.index(f'value="{C}"'), ctr.index(f'value="{A}"'))
        self.assertEqual(out["tcard"], ["Connections shown (4)"])

    def test_periods_from_time_picker(self):
        """Extra periods (or a custom range) are sent as p=start~end,...; more than one shows the 'N periods combined' note.
        REQ: LAT-33"""
        out = self.run_js("""
const R = [{start: "2026-01-01T00:00:00Z", end: "2026-01-01T06:00:00Z"}, {start: "2026-01-02T00:00:00Z", end: "2026-01-02T06:00:00Z"}];
window.rangePeriods = () => R.slice(0, S.extra ? 2 : 1);
S.extra = [R[1]]; const el = new El("div"); await V.lateral(el);
S.extra = null; S.snap.id = "r20260101T0000Z-20260101T0600Z"; const el2 = new El("div"); await V.lateral(el2);
out({calls, note: el.html.filter((h) => h.includes("periods combined")), note2: el2.html.filter((h) => h.includes("periods combined"))});""")
        p2 = "2026-01-01T00:00:00Z~2026-01-01T06:00:00Z,2026-01-02T00:00:00Z~2026-01-02T06:00:00Z"
        from urllib.parse import quote
        self.assertEqual(out["calls"][0], f"/api/lateral?id={F.SID}&p=" + quote(p2, safe="~"))
        self.assertEqual(out["calls"][1], "/api/lateral?id=r20260101T0000Z-20260101T0600Z&p=" + quote("2026-01-01T00:00:00Z~2026-01-01T06:00:00Z", safe="~"))
        self.assertEqual(len(out["note"]), 1)
        self.assertIn("<b>2 periods combined</b>", out["note"][0])
        self.assertIn("1. 2026-01-01T00:00:00Z → 2026-01-01T06:00:00Z", out["note"][0])
        self.assertEqual(out["note2"], [])

    def test_cache_and_error(self):
        """The fetched graph is reused while the snapshot and periods stay the same; an API error is shown instead of the page.
        REQ: LAT-33"""
        out = self.run_js("""
await V.lateral(new El("div")); await V.lateral(new El("div")); const n1 = calls.length;
S.snap.id = "2026-01-04T1200Z"; await V.lateral(new El("div")); const n2 = calls.length;
S.lateral = null; apiError = "not found"; const el = new El("div"); await V.lateral(el);
out({n1, n2, err: el.error, html: el.html});""")
        self.assertEqual((out["n1"], out["n2"]), (1, 2))
        self.assertEqual(out["err"], "<pre>Error: not found</pre>")
        self.assertEqual(out["html"], [])

    def test_levels_legend_matches_backend(self):
        """The details panel legend lists every risk level (same keys and order as lateral.ORDER) plus 'never answered'.
        REQ: LAT-35"""
        out = self.run_js("""
lmRenderPanel(DATA.D); const p = reg.get("lmPanel")._inner;
out({keys: Object.keys(LM_LEVELS), labels: Object.values(LM_LEVELS).map((v) => v.l), p, filters: LM_FILTERS.map((f) => f[0])});""")
        self.assertEqual(out["keys"], lateral.ORDER)
        pos = [out["p"].find("> " + lab + "</div>") for lab in out["labels"]]
        self.assertNotIn(-1, pos)
        self.assertEqual(pos, sorted(pos))
        self.assertIn("never answered (attempt/scan)", out["p"])
        self.assertIn("GW = gateway interface", out["p"])
        self.assertEqual(out["filters"], ["risky", "high", "admin", "all"])

    def test_graph_drawing(self):
        """The SVG has one arrow marker per level, two paths per link (unanswered dashed), GW/risk labels and a dashed ring for hosts not in inventory.
        REQ: LAT-36"""
        out = self.run_js("""
LM.filter = "all"; LM.gateways = true; const box = new El("div"); lmRenderGraph(box, DATA.D);
const svg = box.children.find((c) => c.tag === "svg"), [defs, root] = svg.children, [gZ, gE, gN] = root.children;
const vis = gE.children.filter((p, i) => i % 2 === 0);
const texts = walk(gN, (x) => x.tag === "text").map((t) => t.textContent);
const rings = walk(gN, (x) => x.tag === "circle" && x.attrs["stroke-dasharray"] === "2 2").length;
LM.filter = "high"; LM.focus = "nosuch"; const empty = new El("div"); lmRenderGraph(empty, DATA.D);
out({markers: defs.children.map((m) => m.attrs.id), paths: gE.children.length, dashed: vis.filter((p) => p.attrs["stroke-dasharray"] === "4 3").length,
     colours: vis.map((p) => p.attrs.stroke), texts, rings, zones: walk(gZ, (x) => x.tag === "text").map((t) => t.textContent).sort(), empty: empty._inner});""")
        self.assertEqual(out["markers"], ["lm-arrow-" + k for k in lateral.ORDER])
        self.assertEqual(out["paths"], 2 * 7)
        self.assertEqual(out["dashed"], 1)  # only the never-answered RDP attempts
        self.assertIn("#f85149", out["colours"])
        self.assertIn("GW", out["texts"])
        self.assertIn(45, out["texts"])   # risk score inside the bubble (>= 8)
        self.assertEqual(out["rings"], 2)   # camera and phone are not in the device list
        self.assertEqual(out["zones"], ["DMZ · 1", "IOT · 1", "SERVERS · 1", "USER · 3"])
        self.assertIn("No connections at this filter level", out["empty"])

    def test_clear_column(self):
        """The ports table offers a Clear box only on violation or already-cleared ports, keyed like the Posture finding or the MAC form.
        REQ: LAT-37, POS-16"""
        body = """
const D = DATA.D; LM.data = D; const e = D.edges.find((x) => x.src === "SRC" && x.dst === "DST");
const t = lmPortsTable(e); const i = t.cols.indexOf("Clear"); out(Object.fromEntries(t.rows.map((r, j) => [r.port, t.cells[j][i]])));"""
        def clear(src, dst, **over):
            return self.run_js(body.replace("SRC", src).replace("DST", dst), page_data(**over))
        with_finding = clear(D, B)
        self.assertEqual(with_finding["0"], "")  # the login-only SSH row (no port) is not a violation
        self.assertIn(f'data-k="{D}|{B}|22"', with_finding["22"])  # the key the Posture finding uses
        self.assertNotIn("checked", with_finding["22"].split("title=")[0])
        no_finding = clear(D, B, analysis={"violations": [viol(D, B, 22)], "findings": []})
        self.assertIn(f'data-k="{F.mac(4)}|{B}|22"', no_finding["22"])
        acked = clear(D, B, acks={"seg": {f"{D}|{B}|22": {"at": "t"}}})
        self.assertIn(" checked ", acked["22"])
        self.assertIn("Cleared — uncheck to bring it back", acked["22"])
        self.assertIn("Segmentation: DMZ Game Box → Lab Server:22", acked["22"])
        self.assertEqual(set(clear(A, B).values()), {""})  # no violation, nothing cleared: no box
        self.assertIn(f'data-k="{A}|{C}|80"', clear(A, C, acks={"seg": {f"{A}|{C}|80": {"at": "t"}}})["80"])

    def test_admin_section_open_and_checked(self):
        """Admin access: KPIs summed over sessions, open and checked lists split by check-off, tools card absent without tools.
        REQ: LAT-38"""
        out = self.run_js("""
const el = new El("div"); await V.lateral(el);
const titles = walk(el, (x) => x.title).map((x) => x.title);
const lst = walk(el, (x) => x.id === "admin-list")[0];
out({titles, kp: el.html.filter((h) => h.startsWith("KPIS:")), rows: walk(lst, (x) => x.isTable)[0].rows.map((a) => a.src)});""",
                          page_data(acks={"admin": {f"{A}|{B}|SSH": {"at": "t"}}}))
        self.assertIn("Admin sessions (1 open · 1 checked)", out["titles"])
        self.assertIn("Checked admin sessions (1)", out["titles"])
        self.assertIn("Logins by protocol (click to list)", out["titles"])
        self.assertFalse(any(t.startswith("Admin tools run on endpoints") for t in out["titles"]))
        self.assertEqual(out["rows"], [D])
        self.assertEqual(json.loads(out["kp"][1][5:]), [["Admin sessions", 2], ["Successful logins", "1", "good"], ["Failed logins", "14", "bad"],
                                                        ["Refused connections", "0", ""], ["High-risk sessions", 1, "bad"], ["Protocols", 1]])

    def test_checked_admin_sessions_card_shows_table(self):
        """The Checked admin sessions card holds a table of the checked sessions, not a stringified element.
        REQ: LAT-38"""
        out = self.run_js("""
const el = new El("div"); await V.lateral(el); const chk = walk(el, (x) => x.id === "admin-checked")[0];
out({text: txt(chk), tables: walk(chk, (x) => x.isTable).map((t) => t.rows.length)});""", page_data(acks={"admin": {f"{A}|{B}|SSH": {"at": "t"}}}))
        self.assertNotIn("[object", out["text"])
        self.assertEqual(out["tables"], [1])

    def test_admin_section_empty_and_not_collected(self):
        """No sessions shows 'No admin sessions in this time range.'; a snapshot without admin collection explains that instead.
        REQ: LAT-38"""
        body = """const el = new El("div"); await V.lateral(el); out(txt(el));"""
        d = page_data()
        d["D"]["admin"] = []
        self.assertIn("No admin sessions in this time range.", self.run_js(body, d))
        d["D"]["admin_collected"] = False
        t = self.run_js(body, d)
        self.assertIn("taken before admin-access collection was added", t)
        self.assertNotIn("No admin sessions in this time range.", t)

    def test_cleared_segmentation_card(self):
        """Cleared flows (MAC form) get a 'Cleared segmentation' card resolving the device and its activity; none without clears.
        REQ: LAT-39"""
        body = """const el = new El("div"); await V.lateral(el); const c = walk(el, (x) => x.id === "seg-cleared")[0];
out(c ? {title: c.title, rows: walk(c, (x) => x.isTable)[0].rows} : null);"""
        self.assertIsNone(self.run_js(body))
        out = self.run_js(body, page_data(acks={"seg": {f"{F.mac(4)}|{B}|22": {"at": "t1", "label": "Segmentation: box"}}}))
        self.assertEqual(out["title"], "Cleared segmentation (1)")
        r = out["rows"][0]
        self.assertEqual((r["src"], r["dst"], r["port"], r["label"]), (D, B, "22", "Segmentation: box"))
        self.assertEqual((r["seen"], r["reason"]), ("4 conns in this time range", "dmz -> protected"))

    def test_edge_details_panel(self):
        """Clicking a link shows its level, both ends with zone chips, counts, score, ports and its admin-session cards.
        REQ: LAT-40"""
        out = self.run_js(f"""
const D = DATA.D; LM.data = D; LM.sel = {{edge: D.edges.find((e) => e.src === {json.dumps(A)} && e.dst === {json.dumps(B)})}};
lmRenderPanel(D); const p = reg.get("lmPanel"); out({{text: txt(p), tables: walk(p, (x) => x.isTable).map((t) => t.cols)}});""")
        t = out["text"]
        self.assertIn(">Medium</span> Connection</h2>", t)
        self.assertIn(f'<a href="#/device/{A}">Admin Laptop</a>', t)
        self.assertIn('<span class="chip">servers</span>', t)
        self.assertIn("<span>1 (1 answered)</span>", t)
        self.assertIn("<h3>Admin sessions</h3>", t)
        self.assertIn("Failed + succeeded", t)
        self.assertIn('ops <span class="badge sev-high">2✗</span> <span class="badge sev-good">1✓</span>', t)
        self.assertIn("Evidence</span><span>Zeek conn, login log", t)
        self.assertEqual(out["tables"], [["Port", "Svc", "Risk", "Conns", "Ans", "Bytes", "Why", "Clear"]])

    def test_node_details_panel_and_route_focus(self):
        """#/lateral/<ip> focuses that host (filter widened to include allowed admin) and shows its in/out links, device and admin links.
        REQ: LAT-40"""
        out = self.run_js(f"""
LM.filter = "risky"; const el = new El("div"); await V.lateral(el, {json.dumps(B)}); const f1 = LM.filter, p = txt(reg.get("lmPanel"));
LM.filter = "all"; await V.lateral(new El("div"), {json.dumps(B)}); const f2 = LM.filter;
LM.sel = {{node: DATA.D.nodes.find((n) => n.gateway)}}; LM.focus = null; lmRenderPanel(DATA.D); const gw = txt(reg.get("lmPanel"));
out({{f1, f2, p, gw, focus: LM.focus}});""")
        self.assertEqual((out["f1"], out["f2"]), ("admin", "all"))
        p = out["p"]
        self.assertIn("<h2>Lab Server</h2>", p)
        self.assertIn('<button id="lmFocus">Show everything</button>', p)
        self.assertIn(f'<a href="#/device/{B}"><button>Device page →</button></a>', p)
        self.assertIn(f"#/lateral?ahost={B}&amp;at=admin-list".replace("&amp;", "&"), p)
        self.assertIn("Admin sessions (2) →", p)
        self.assertIn("<h3>Outgoing (0)</h3>", p)
        self.assertIn("<h3>Incoming (4)</h3>", p)
        self.assertNotIn("Device page", out["gw"])
        self.assertIn("Focus on this host", out["gw"])


if __name__ == "__main__":
    unittest.main()
