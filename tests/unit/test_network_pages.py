"""Unit tests for Network -> Network map (#/netmap, netmap.js) and Network -> Traffic map (#/traffic, app.js V.traffic +
gatewayTraffic + historyNetwork): the server data behind them (internal flows / zone matrix, UniFi summary, history,
registry) and the page scripts run under node with a tiny fake DOM."""
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); import _env  # noqa: E401,E702,E402

import json  # noqa: E402
import re  # noqa: E402
import shutil  # noqa: E402
import subprocess  # noqa: E402
import unittest  # noqa: E402
from unittest import mock  # noqa: E402

import fixtures as F  # noqa: E402
import extras  # noqa: E402
import server  # noqa: E402
import store  # noqa: E402
import unifi  # noqa: E402
import window  # noqa: E402

IP, EXT = F.IPS, F.EXT
NODE_FALLBACK = os.path.expanduser(os.environ.get("NETMON_NODE", "~/.hermes/tools/node-26.7.0-linux-arm64/bin/node"))
NODE = shutil.which("node") or (NODE_FALLBACK if os.path.exists(NODE_FALLBACK) else None)
STATIC = os.path.join(_env.APP, "static")
POL = F.zone_policy()  # user 10.0.1.0/24, servers 10.0.2.0/24, iot 10.0.3.0/24, dmz 10.0.9.0/24


def net(zone, last):
    """An address inside one of the zone_policy() zones, e.g. net('iot', 7) -> 10.0.3.7."""
    return POL["zones"][zone].split("/")[0].rsplit(".", 1)[0] + "." + str(last)


# ------------------------------------------------------------------ node harness
def _read(name):
    with open(os.path.join(STATIC, name), encoding="utf-8") as f:
        return f.read()


def _slice(src, start, end):
    i = src.index(start)
    return src[i:src.index(end, i)]


PRELUDE = r"""
class El {
  constructor(tag, attrs) { this.tag = tag; this.attrs = { ...(attrs || {}) }; this.children = []; this.style = {}; this.dataset = {};
    this.listeners = {}; this._text = ""; this._html = ""; this.id = ""; this.className = ""; this.clientWidth = 0;
    this.classList = { add: () => {}, remove: () => {}, toggle: () => {} }; this.onclick = null; }
  appendChild(c) { this.children.push(c); if (c && c.id) IDS[c.id] = c; return c; }
  append(...c) { for (const x of c) this.appendChild(x); }
  setAttribute(k, v) { this.attrs[k] = v; }
  addEventListener(t, f) { (this.listeners[t] = this.listeners[t] || []).push(f); }
  set textContent(v) { this._text = String(v); } get textContent() { return this._text; }
  set innerHTML(v) { this._html = String(v); if (!v) this.children = []; for (const m of String(v).matchAll(/id=['"]([^'"]+)['"]/g)) IDS[m[1]] = IDS[m[1]] || new El("div"); }
  get innerHTML() { return this._html; }
  insertAdjacentHTML(_, h) { this._html += h; }
  getBoundingClientRect() { return { left: 0, top: 0, width: 1200, height: 800 }; }
  get isConnected() { return true; }
  toJSON() { return { tag: this.tag, id: this.id, cls: this.className, attrs: this.attrs, text: this._text, html: this._html, children: this.children }; }
}
const IDS = {};
var document = { createElement: (t) => new El(t), getElementById: (id) => IDS[id] || null, addEventListener() {} };
var window = { innerWidth: 1400, addEventListener() {}, removeEventListener() {}, scrollTo() {} };
var location = { hash: "", replace(h) { this.replaced = h; } };
const svgEl = (t, a) => new El(t, a);
var SITE = { site_name: "", internal_prefixes: ["10."], display_names: {}, honeypot_ips: [] };
const HOST_IP_HINTS = {};
var S = { snap: { raw: { devices: {} } }, reg: { policy: {} }, risk: null, issues: null, idx: { ipHosts: {}, rows: [] }, acks: {}, hist: [], histInRange: false };
const V = { security: () => {}, devices: () => {} };
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const entries = (o) => Object.entries(o || {});
const fn = (n) => (n == null || n === "" ? "" : String(+n));
const fb = (n) => (+n || 0) + "B";
const ft = (t) => (t ? String(t) : "");
const badge = (s) => `<badge ${s}>`;
const riskBadge = (v) => `<risk ${v}>`;
const acked = (type, x) => !!S.acks?.[type]?.[x.key];
const ipLink = (ip) => `<ip ${ip}>`;
const hostLink = (h) => `<host ${h}>`;
const KP = [];
const kpis = (a) => { KP.push(a); return "<kpis/>"; };
const card = (title, body) => { const c = new El("card"); c.title = title; c.body = body; if (typeof body === "string") c.innerHTML = body; c.toJSON = () => ({ card: title, body }); return c; };
const grid = (cls, ...xs) => ({ grid: cls, items: xs });
const table = (_, cols, rows, opts) => ({ table: cols.map((c) => c.k), rows, opts: { ...(opts || {}), onclick: undefined } });
const kvTable = (o, k, v) => ({ kv: o, k, v });
const chartCard = (title, cfg) => ({ chart: title, cfg });
const barCfg = (labels, data) => ({ labels, data });
const doughnutCfg = (o) => ({ doughnut: o || null });
const topTalkersChart = () => ({ chart: "top talkers" });
const drill = () => {}, go = () => {};
const PALETTE = ["#0", "#1", "#2", "#3", "#4", "#5"];
const bytesAxis = {}, bytesTip = {};
const clickable = () => ({});
"""


def _app_parts():
    app = _read("app.js")
    return "\n".join([
        _slice(app, "const sortDesc", "\n") + "\n",
        _slice(app, "function ip2n", "/* ---------- index the snapshot"),
        _slice(app, "let _hnbi = null;", "function deviceClass"),
        _slice(app, "function unifiHealthHtml", "/* ----- Devices list"),
        _slice(app, "V.traffic = (el) => {", "/* ----- DNS & TLS"),
        _slice(app, "const secHead", "// stable id of a UniFi gateway event"),
        "V.unifi = " + _slice(app, "V.unifi = ", "\n")[len("V.unifi = "):] + "\n",
        _slice(app, "function historyNetwork", "function historyHosts"),
        "V.history = " + _slice(app, "V.history = ", "\n")[len("V.history = "):] + "\n",
        _slice(app, "{ const sec = V.security", "/* ---------- router"),
    ])


def run_js(body):
    """Run `body` after the stubs, the app.js pieces the Network pages use, lateral.js zone colours and all of netmap.js."""
    lat = _read("lateral.js")
    col = re.search(r"^const LM_ZONE_COL = .*$", lat, re.M).group(0)
    src = PRELUDE + _app_parts() + "\n" + col + "\n" + _read("netmap.js") + "\n" + body
    r = subprocess.run([NODE, "-"], input=src, capture_output=True, text=True, timeout=30)  # noqa: S603 - node on repo files
    if r.returncode:
        raise RuntimeError(r.stderr[-3000:])
    return json.loads(r.stdout)


def walk(node, out=None):
    """Every fake-DOM node below `node` (depth first)."""
    out = [] if out is None else out
    if isinstance(node, dict):
        out.append(node)
        for c in node.get("children") or []:
            walk(c, out)
    return out


def texts(node):
    return [n["text"] for n in walk(node) if n.get("tag") in ("text", "title") and n.get("text")]


# ------------------------------------------------------------------ server side: internal flows / zone matrix (extras.py)
def _conn_aggs(pairs, scans=()):
    """An Elasticsearch response in the shape internal_traffic() asks for: pairs = (src, dst, port, proto, conns, ok, bytes, svc)."""
    p = [{"key": [s, d, port, tr], "doc_count": c, "ok": {"doc_count": ok}, "b": {"value": b},
          "svc": {"buckets": [{"key": svc}] if svc else []}} for s, d, port, tr, c, ok, b, svc in pairs]
    sc = [{"key": s, "doc_count": n, "hosts": {"value": h}, "ports": {"value": pt}, "top": {"buckets": [{"key": k} for k in top]}}
          for s, n, h, pt, top in scans]
    return {"aggregations": {"p": {"buckets": p}, "scan": {"s": {"buckets": sc}}}}


def internal(pairs, scans=(), policy=None):
    """extras.internal_traffic() against a stubbed Elasticsearch (no collect.py import, no network)."""
    resp = _conn_aggs(pairs, scans)
    seen = []

    def q(index, body):
        seen.append((index, body))
        return resp
    ctx = (q, lambda d: {"term": {"event.dataset": d}}, lambda a: a.get("buckets", []))
    with mock.patch.object(extras, "_ctx", return_value=ctx), mock.patch.object(extras, "rng", return_value={"range": {}}), \
            mock.patch.object(extras, "load_policy", return_value=policy if policy is not None else POL):
        return extras.internal_traffic(24), seen


class InternalTraffic(unittest.TestCase):
    """extras.zone_of and extras.internal_traffic: the raw.internal flows, scans and zone matrix of the Traffic map."""

    def test_zone_of(self):
        """An address maps to the policy zone whose CIDR contains it, other internal addresses to internal-other, the rest to external.
        REQ: NET-01"""
        self.assertEqual(extras.zone_of(IP["laptop"], POL), "user")
        self.assertEqual(extras.zone_of(IP["dmz"], POL), "dmz")
        self.assertEqual(extras.zone_of(net("servers", 255), POL), "servers")
        self.assertEqual(extras.zone_of("10.200.0.5", POL), "internal-other")
        self.assertEqual(extras.zone_of(EXT["cdn"], POL), "external")
        self.assertEqual(extras.zone_of("not-an-ip", POL), "external")
        self.assertEqual(extras.zone_of(IP["laptop"], {"zones": {}}), "internal-other")

    def test_flows(self):
        """Each source/destination/port/protocol bucket becomes one flow with conns, answered, bytes, service and both zones; broadcast and self flows are dropped.
        REQ: NET-02"""
        out, seen = internal([
            (IP["laptop"], IP["server"], 22, "tcp", 10, 9, 5000, "ssh"),
            (IP["camera"], IP["laptop"], 8080, "tcp", 4, 0, 0, ""),
            (IP["laptop"], net("user", 255), 137, "udp", 50, 50, 900, "netbios"),
            (IP["server"], IP["server"], 53, "udp", 7, 7, 70, "dns"),
        ])
        self.assertEqual(seen[0][0], "logs-zeek-so")
        self.assertEqual(out["flows"], [
            {"src": IP["laptop"], "dst": IP["server"], "port": 22, "proto": "tcp", "conns": 10, "answered": 9, "bytes": 5000,
             "service": "ssh", "src_zone": "user", "dst_zone": "servers"},
            {"src": IP["camera"], "dst": IP["laptop"], "port": 8080, "proto": "tcp", "conns": 4, "answered": 0, "bytes": 0,
             "service": "", "src_zone": "iot", "dst_zone": "user"}])

    def test_matrix(self):
        """The zone matrix sums conns and bytes per 'src -> dst' zone pair, keeps the 6 busiest port/protocols and lists the busiest pair first.
        REQ: NET-03"""
        pairs = [(IP["laptop"], IP["server"], 1000 + i, "tcp", i + 1, i + 1, 10, "") for i in range(8)]
        pairs += [(IP["camera"], IP["server"], 443, "tcp", 100, 100, 1, ""), (IP["camera"], net("servers", 5), 443, "tcp", 50, 0, 2, ""),
                  (IP["dmz"], IP["laptop"], 22, "tcp", 1, 1, 3, "ssh")]
        m = internal(pairs)[0]["matrix"]
        self.assertEqual(list(m), ["iot -> servers", "user -> servers", "dmz -> user"])
        self.assertEqual(m["iot -> servers"], {"conns": 150, "bytes": 3, "ports": {"443/tcp": 150}})
        self.assertEqual((m["user -> servers"]["conns"], m["user -> servers"]["bytes"]), (36, 80))
        self.assertEqual(list(m["user -> servers"]["ports"]), [f"{1000 + i}/tcp" for i in range(7, 1, -1)])
        self.assertEqual(internal([])[0], {"flows": [], "scans": [], "matrix": {}})

    def test_scans(self):
        """A source with failed connections to at least the host or port threshold is a scan; gateway (.1) addresses never are.
        REQ: NET-04"""
        scans = [(IP["dmz"], 300, 25, 3, [22, 445]), (IP["laptop"], 80, 2, 45, [80]), (IP["phone"], 10, 19, 39, [443]),
                 (net("user", 1), 900, 200, 200, [5353])]
        out = internal([], scans)[0]["scans"]
        self.assertEqual([s["src"] for s in out], [IP["dmz"], IP["laptop"]])
        self.assertEqual(out[0], {"src": IP["dmz"], "failed_conns": 300, "hosts": 25, "ports": 3, "top_ports": [22, 445]})
        strict = internal([], scans, dict(POL, scan_thresholds={"hosts": 100, "ports": 100}))[0]["scans"]
        self.assertEqual(strict, [])


# ------------------------------------------------------------------ server side: UniFi gateway summary (unifi.collect, stubbed)
T1 = 1_767_614_400_000  # 2026-01-05 12:00 UTC (ms)


def fake_legacy(path, body=None):
    t_new, t_old = (T1 - 3600_000) // 1000, (T1 - 10 * 86400_000) // 1000
    data = {
        "stat/sta": [{"mac": F.mac(1), "ip": IP["laptop"], "name": "Admin Laptop", "network": "Main", "first_seen": t_old},
                     {"mac": F.mac(20), "ip": net("iot", 20), "hostname": "plug-20", "network": "IoT", "oui": "Example", "first_seen": t_new},
                     {"mac": F.mac(21), "ip": net("iot", 20), "network": "IoT", "is_guest": True}],
        "rest/user": [{"mac": F.mac(1), "name": "Admin Laptop"}, {"mac": F.mac(30), "name": "Old Tablet", "first_seen": t_old}],
        "get/setting": [{"key": "ips", "ips_mode": "ips", "enabled_categories": ["a", "b"], "enabled_networks": ["n1"]}],
        "rest/networkconf": [{"_id": "n1", "name": "Main"}],
        "stat/health": [{"subsystem": "wan", "status": "ok", "isp_name": "Example ISP", "wan_ip": EXT["cdn"]},
                        {"subsystem": "www", "status": "ok", "latency": 12, "drops": 1, "uptime": 86400}],
    }
    return data[path]


def fake_flows(t0, t1):
    blk = {"action": "blocked", "risk": "low"}
    return ([{**blk, "count": 3, "source": {"client_name": "Yard Camera", "ip": IP["camera"]}, "destination": {"ip": EXT["bad"], "domains": ["bad.example"]},
              "policies": [{"name": "Block IoT", "type": "FIREWALL"}]},
             {**blk, "count": 2, "direction": "outgoing", "source": {"ip": IP["phone"]}, "destination": {"ip": EXT["bad"], "region": "XX"},
              "policies": [{"name": "Region Blocking", "internal_type": "REGION_BLOCK"}]},
             {"action": "allowed", "risk": "high", "direction": "incoming", "time": T1, "source": {"ip": EXT["bad"]},
              "destination": {"ip": IP["server"], "port": 22}, "policies": []}], False)


class UnifiSummary(unittest.TestCase):
    """unifi.collect() with a stubbed controller: the clients, flow blocks and health the Network and Traffic maps show."""

    def collect(self):
        with mock.patch.object(unifi.INTEG, "unifi_key", return_value="test-key"), mock.patch.object(unifi, "legacy", fake_legacy), \
                mock.patch.object(unifi, "flows", fake_flows), mock.patch.object(unifi, "syslog", lambda *a: []), \
                mock.patch.object(unifi, "inventory_macs", return_value={F.mac(1): "Admin Laptop"}), \
                mock.patch.object(window, "end_ms", return_value=T1):
            return unifi.collect(24)

    def test_clients(self):
        """Clients: online count, known total, clients per network, those missing from the inventory, first seen in the window and IP conflicts.
        REQ: NET-05"""
        c = self.collect()["clients"]
        self.assertEqual((c["online"], c["known_total"], c["guests"]), (3, 2, 1))
        self.assertEqual(c["by_network"], {"Main": 1, "IoT": 2})
        self.assertEqual([x["mac"] for x in c["not_in_inventory"]], [F.mac(20), F.mac(21)])
        self.assertEqual((c["not_in_inventory"][0]["name"], c["not_in_inventory"][0]["vendor"]), ("plug-20", "Example"))
        self.assertEqual([x["mac"] for x in c["first_seen_in_window"]], [F.mac(20)])
        self.assertEqual(list(c["ip_conflicts"]), [net("iot", 20)])

    def test_no_key_skipped(self):
        """Without a UniFi API key the collector skips (no controller call) and says why.
        REQ: NET-05"""
        with mock.patch.object(unifi.INTEG, "unifi_key", return_value=""), mock.patch.object(unifi, "legacy", side_effect=AssertionError):
            out = unifi.collect(24)
        self.assertEqual(list(out), ["skipped"])

    def test_flows_and_health(self):
        """Flows: totals, blocks per policy, top blocked clients with their domains, region blocks and risky flows; health keeps ISP, WAN IP and latency.
        REQ: NET-06"""
        out = self.collect()
        fl, h = out["flows"], out["health"]
        self.assertEqual((fl["total"], fl["actions"]), (3, {"blocked": 2, "allowed": 1}))
        self.assertEqual(fl["blocked_by_policy"], {"Block IoT": 1, "Region Blocking": 1})
        self.assertEqual(fl["top_blocked_clients"][0], {"client": "Yard Camera", "count": 3, "top_domains": [("bad.example", 3)]})
        self.assertEqual(fl["region_blocks"], [{"client": IP["phone"], "dst": EXT["bad"], "region": "XX", "direction": "outgoing", "count": 2}])
        self.assertEqual([(r["src"], r["dst"], r["port"]) for r in fl["risky"]], [(EXT["bad"], IP["server"], 22)])
        self.assertEqual(h, {"status": {"wan": "ok", "www": "ok"}, "isp": "Example ISP", "wan_ip": EXT["cdn"], "latency_ms": 12,
                             "drops": 1, "uptime_s": 86400})
        self.assertEqual(out["settings"]["protected_networks"], ["Main"])
        self.assertEqual(out["errors"], {})


# ------------------------------------------------------------------ server side: history + registry
def hist_rec(gen, n):
    devs = {IP["laptop"]: {"ip": IP["laptop"], "name": "Admin Laptop", "known": True, "total": 1000 * n, "ext_out": 10 * n, "conns": n,
                           "ports": {"443": 9}, "secret_extra": "x"}}
    return {"generated": gen, "hours": 24, "totals": {"conns": n}, "devices": devs, "signatures": {}, "not_served": 1}


class HistoryAndRegistry(unittest.TestCase):
    """server.history() and server.registry(): the trend and zone/name data both Network pages read."""

    def setUp(self):
        _env.fresh_db()

    def test_history_compact(self):
        """/api/history lists banked snapshots oldest first with only the per-device headline numbers the trend charts use.
        REQ: NET-07"""
        self.assertEqual(server.history(), [])
        store.history_append(hist_rec("2026-01-05T12:00:00+00:00", 3))
        store.history_append(hist_rec("2026-01-04T12:00:00+00:00", 2))
        h = server.history()
        self.assertEqual([x["generated"] for x in h], ["2026-01-04T12:00:00+00:00", "2026-01-05T12:00:00+00:00"])
        self.assertEqual(set(h[0]), {"generated", "hours", "totals", "devices", "signatures"})
        d = h[1]["devices"][IP["laptop"]]
        self.assertEqual((d["total"], d["ext_out"], d["conns"], d["name"]), (3000, 30, 3, "Admin Laptop"))
        self.assertNotIn("secret_extra", d)
        self.assertNotIn("ports", d)

    def test_registry(self):
        """/api/registry carries the policy zones and device classes, known-benign display names and the device registry.
        REQ: NET-08"""
        pol = F.zone_policy(device_classes={F.mac(2): "server"})
        store.jdump(pol, os.path.join(server.ROOT, "policy.json"))
        store.jdump({"names": {net("servers", 1): "core switch"}, "signatures": []}, os.path.join(server.ROOT, "known_benign.json"))
        store.registry_save({F.mac(2): {"mac": F.mac(2), "name": "Lab Server", "ips": [IP["server"]], "known": True,
                                        "first_seen": "2026-01-01", "last_seen": "2026-01-05"}})
        r = server.registry()
        self.assertEqual(r["policy"]["zones"], pol["zones"])
        self.assertEqual(r["policy"]["device_classes"], {F.mac(2): "server"})
        self.assertEqual(r["known_benign"]["names"], {net("servers", 1): "core switch"})
        self.assertEqual(r["devices_seen"][F.mac(2)]["ips"], [IP["server"]])
        _env.fresh_db()
        self.assertEqual((server.registry()["policy"], server.registry()["devices_seen"]), ({}, {}))

    def test_network_apis_not_for_user_role(self):
        """None of the APIs the Network pages load is on the User role's allow-list, and both pages are outside the User views.
        REQ: NET-23"""
        for p in ("/api/snapshot", "/api/history", "/api/registry", "/api/issues", "/api/risk", "/api/section", "/api/acks", "/api/site"):
            if p == "/api/site":
                self.assertIn(p, server.USER_GET)  # reduced to the site name for users
            else:
                self.assertNotIn(p, server.USER_GET)
        views = re.search(r"const USER_VIEWS = new Set\(\[(.*?)\]\)", _read("app.js")).group(1)
        self.assertNotIn("netmap", views)
        self.assertNotIn("traffic", views)


# ------------------------------------------------------------------ Network map (netmap.js) under node
GW_USER, GW_SRV = net("user", 1), net("servers", 1)
OTHER = "10.200.0.5"  # private, outside every zone -> the 'other' box


def live(name, i, known=True, total=1000):
    return {"name": name, "mac": F.mac(i), "oui": "Example", "hostname": "", "known": known, "total_bytes": total, "orig_conns": 3, "resp_conns": 2}


def netmap_state():
    """The S / SITE state app.js builds from /api/snapshot, /api/registry, /api/risk, /api/issues and /api/site."""
    zones = dict(POL["zones"], lab="10.0.4.0/24")
    reg = {"policy": {"zones": zones, "device_classes": {F.mac(1): "work", IP["server"]: "server", F.mac(3): "camera"}},
           "known_benign": {"names": {IP["phone"]: "Benign Phone Name", GW_SRV: "core gw"}},
           "devices_seen": {
               "k1": {"mac": F.mac(1), "ips": [IP["laptop"]], "name": "Reg Laptop", "oui": "unknown", "known": True,
                      "first_seen": "2026-01-01", "last_seen": "2026-01-05", "days_seen": 5},
               "k7": {"mac": F.mac(7), "ips": [net("user", 50), net("user", 51)], "name": "Mover", "known": True},
               "k8": {"mac": F.mac(8), "ips": [net("iot", 60)], "name": "Reg Only", "known": False},
               "k10": {"mac": F.mac(10), "ips": [net("servers", 80)], "name": "", "known": True}}}
    raw = {"devices": {IP["laptop"]: live("Live Laptop", 1, total=5000), IP["server"]: live("", 2), IP["phone"]: live("", 5),
                       IP["camera"]: live("Yard Camera", 3), OTHER: live("", 11, known=False), EXT["cdn"]: live("cdn", 12),
                       GW_USER: live("gw", 13)},
           "inventory_ips": {IP["laptop"]: "Inv Laptop", IP["server"]: "Inv Server", IP["phone"]: "Inv Phone",
                             net("iot", 61): "Inv Only", net("servers", 255): "bcast"},
           "unifi": {"health": {"isp": "Example ISP", "wan_ip": EXT["cdn"], "status": {"wan": "ok"}},
                     "clients": {"online": 4, "by_network": {"Main": 4},
                                 "not_in_inventory": [{"ip": net("user", 50), "mac": F.mac(7), "name": "Old Mover IP"},
                                                      {"ip": net("dmz", 70), "mac": F.mac(9), "name": "UniFi Box", "vendor": "Example"}]}}}
    S = {"snap": {"raw": raw}, "reg": reg, "risk": {"hosts": [{"ip": IP["laptop"], "score": 45, "rank": 1}, {"ip": IP["camera"], "score": 12, "rank": 2}]},
         "issues": {"open": [{"ip": IP["laptop"], "key": "a", "severity": "high", "title": "t-a"}, {"ip": IP["laptop"], "key": "b", "severity": "low", "title": "t-b"},
                             {"ip": IP["camera"], "key": "c", "severity": "low", "title": "t-c"}]},
         "acks": {"issue": {"c": {"at": "t"}}}, "idx": {"ipHosts": {IP["laptop"]: ["host-a"]}, "rows": []}}
    site = {"display_names": {IP["camera"]: "Display Cam"}, "honeypot_ips": [net("dmz", 70)]}
    return S, site, {"hint-host": net("servers", 80)}


def setup_js(S=None, site=None, hints=None):
    d = netmap_state() if S is None else (S, site or {}, hints or {})
    return f"Object.assign(S, {json.dumps(d[0])}); Object.assign(SITE, {json.dumps(d[1])}); Object.assign(HOST_IP_HINTS, {json.dumps(d[2])});\n"


@unittest.skipUnless(NODE, "node not installed")
class NetmapHostsJs(unittest.TestCase):
    """netmap.js nmHosts / nmZones / nmRiskColor: which hosts are drawn, in which zone, under which name."""

    @classmethod
    def setUpClass(cls):
        out = run_js(setup_js() + "const hs = nmHosts(); console.log(JSON.stringify({hosts: hs, zones: nmZones(hs)}));")
        cls.hosts = {h["ip"]: h for h in out["hosts"]}
        cls.zones = out["zones"]

    def test_zone_assignment(self):
        """Hosts land in the policy zone of their address, private unzoned addresses in 'other'; internet, gateway (.1), broadcast and network addresses are not drawn.
        REQ: NET-09"""
        h = self.hosts
        self.assertEqual((h[IP["laptop"]]["zone"], h[IP["server"]]["zone"], h[IP["camera"]]["zone"], h[OTHER]["zone"]), ("user", "servers", "iot", "other"))
        for ip in (EXT["cdn"], GW_USER, net("servers", 255)):
            self.assertNotIn(ip, h)
        js = run_js("S.reg = {policy: {zones: {lan: '10.0.0.0/16', all: '0.0.0.0/0'}}}; console.log(JSON.stringify([zoneOf('10.0.200.9'), zoneOf('10.1.0.1'), zoneOf('x')]));")
        self.assertEqual(js, ["lan", "all", ""])

    def test_sources_merge(self):
        """A host merges the baseline registry, DHCP inventory, UniFi clients and live traffic; live traffic marks it active, and an old IP whose MAC moved is dropped.
        REQ: NET-10"""
        lap = self.hosts[IP["laptop"]]
        self.assertEqual(lap["sources"], ["baseline", "DHCP", "traffic"])
        self.assertEqual((lap["active"], lap["total"], lap["conns"], lap["mac"], lap["vendor"]), (True, 5000, 5, F.mac(1), "Example"))
        self.assertEqual((lap["first_seen"], lap["days_seen"]), ("2026-01-01", 5))
        self.assertEqual(self.hosts[net("dmz", 70)]["sources"], ["UniFi"])
        self.assertEqual(self.hosts[net("iot", 61)]["sources"], ["DHCP"])
        self.assertNotIn(net("user", 50), self.hosts)
        self.assertIn(net("user", 51), self.hosts)
        self.assertFalse(self.hosts[net("iot", 60)].get("active"))
        self.assertEqual(len(self.hosts), 10)

    def test_naming(self):
        """Host name order: site display name, live traffic name, known-benign name, DHCP name, registry/UniFi name, endpoint host hint, then the IP.
        REQ: NET-11"""
        n = {ip: h["name"] for ip, h in self.hosts.items()}
        self.assertEqual(n[IP["camera"]], "Display Cam")
        self.assertEqual(n[IP["laptop"]], "Live Laptop")
        self.assertEqual(n[IP["phone"]], "Benign Phone Name")
        self.assertEqual(n[IP["server"]], "Inv Server")
        self.assertEqual((n[net("user", 51)], n[net("dmz", 70)]), ("Mover", "UniFi Box"))
        self.assertEqual(n[net("servers", 80)], "hint-host")
        self.assertEqual(n[OTHER], OTHER)

    def test_decorations(self):
        """Hosts carry their device class (by MAC, then IP), risk score and rank, open issues not checked off, Elastic agent and honeypot flags.
        REQ: NET-12"""
        h = self.hosts
        self.assertEqual((h[IP["laptop"]]["cls"], h[IP["server"]]["cls"], h[IP["camera"]]["cls"], h[OTHER]["cls"]), ("work", "server", "camera", ""))
        self.assertEqual((h[IP["laptop"]]["risk"], h[IP["laptop"]]["rank"], h[IP["phone"]]["risk"]), (45, 1, 0))
        self.assertEqual((h[IP["laptop"]]["issues"], h[IP["camera"]]["issues"]), (2, 0))
        self.assertEqual([ip for ip, x in h.items() if x["agent"]], [IP["laptop"]])
        self.assertEqual([ip for ip, x in h.items() if x["honeypot"]], [net("dmz", 70)])
        self.assertEqual(sorted(ip for ip, x in h.items() if not x.get("known")), sorted([net("iot", 60), OTHER, net("dmz", 70)]))

    def test_zones(self):
        """Zones: every configured zone even when empty, fixed order then alphabetical, gateway .1 address and name, host/active/unknown/risk/issue totals, hosts sorted by class then name.
        REQ: NET-13"""
        z = {x["id"]: x for x in self.zones}
        self.assertEqual([x["id"] for x in self.zones], ["servers", "dmz", "other", "iot", "lab", "user"])
        self.assertEqual((z["servers"]["gw"], z["servers"]["gwName"], z["servers"]["cidr"]), (GW_SRV, "core gw", POL["zones"]["servers"]))
        self.assertEqual((z["other"]["gw"], z["other"]["cidr"]), ("", ""))
        self.assertEqual((z["lab"]["hosts"], z["lab"]["active"], z["lab"]["maxRisk"]), ([], 0, 0))
        u = z["user"]
        self.assertEqual((len(u["hosts"]), u["active"], u["unknown"], u["maxRisk"], u["issues"]), (3, 2, 0, 45, 2))
        self.assertEqual((z["iot"]["unknown"], z["iot"]["maxRisk"]), (1, 12))
        self.assertEqual([h["name"] for h in z["servers"]["hosts"]], ["Inv Server", "hint-host"])
        self.assertEqual([h["name"] for h in z["user"]["hosts"]], ["Live Laptop", "Benign Phone Name", "Mover"])  # class "work" first, then by name

    def test_risk_colour(self):
        """Risk colours: red from 40, amber from 20, yellow from 8, green below (as in RISK_SCORING.md).
        REQ: NET-14"""
        out = run_js("console.log(JSON.stringify([0, 7.9, 8, 19, 20, 39, 40, 99].map(nmRiskColor)));")
        self.assertEqual(out, ["#3fb950", "#3fb950", "#e3b341", "#e3b341", "#d29922", "#d29922", "#f85149", "#f85149"])


RENDER = r"""
const hs = nmHosts(), zs = nmZones(hs);
const draw = () => { const box = new El("div"); box.clientWidth = 1400; nmRender(box, zs); const svg = box.children.find((c) => c.tag === "svg");
  const [gL, gZ, gN] = svg.children[0].children; return { gL, gZ, gN, zb: box.children[0] }; };
const out = {};
out.all = draw();
NM.inactive = false; out.active = draw(); NM.inactive = true;
NM.q = "cam"; out.search = draw(); NM.q = "";
console.log(JSON.stringify(out));
"""


@unittest.skipUnless(NODE, "node not installed")
class NetmapRenderJs(unittest.TestCase):
    """netmap.js nmRender / nmPanel / V.netmap: nodes, links, badges, empty zones, panel and tables."""

    def test_nodes_and_links(self):
        """One node per visible host (inactive ones hidden on request, search dims the rest), one uplink per zone with its gateway address, risk badges from 8, 'no hosts seen' in empty zones.
        REQ: NET-15"""
        out = run_js(setup_js() + RENDER)
        nodes = out["all"]["gN"]["children"]
        self.assertEqual(texts(nodes[0]), ["Internet"])
        self.assertEqual(texts(nodes[1])[:2], ["UniFi gateway / firewall", f"Example ISP · {EXT['cdn']}"])
        hosts = nodes[2:]
        self.assertEqual(len(hosts), 10)
        self.assertEqual(len(out["active"]["gN"]["children"]) - 2, 5)
        lap = next(n for n in hosts if IP["laptop"] in texts(n))
        circles = [c for c in walk(lap) if c["tag"] == "circle"]
        self.assertEqual(circles[0]["attrs"]["fill"], "#f85149")
        self.assertIn("#3fb950", [c["attrs"].get("fill") for c in circles])  # agent dot
        self.assertIn("2", texts(lap))  # open issues badge
        unk = next(n for n in hosts if net("iot", 60) in texts(n))
        self.assertIn("#d29922", [c["attrs"].get("stroke") for c in walk(unk) if c["tag"] == "circle"])
        self.assertIn("not seen in this time range", texts(unk)[-1])
        dim = {n["attrs"]["style"].split("opacity:")[1] for n in out["search"]["gN"]["children"][2:]}
        self.assertEqual(dim, {"0.15", "1"})
        hit = [n for n in out["search"]["gN"]["children"][2:] if n["attrs"]["style"].endswith("opacity:1")]
        self.assertEqual([texts(n)[2] for n in hit], [IP["camera"]])
        lines = out["all"]["gL"]["children"]
        self.assertEqual(sorted(t["text"] for t in lines if t["tag"] == "text"),
                         sorted([POL["zones"][z].split("/")[0][:-1] + "1" for z in POL["zones"]] + ["10.0.4.1"]))
        zone_boxes = out["all"]["gZ"]["children"]
        self.assertEqual([texts(z)[0] for z in zone_boxes], ["SERVERS", "DMZ", "OTHER", "IOT", "LAB", "USER"])
        self.assertEqual(sum("highest host risk in zone" in texts(z) for z in zone_boxes), 2)  # user (45) and iot (12)
        self.assertIn("no hosts seen", texts(zone_boxes[4]))
        self.assertIn("no hosts seen", texts(out["active"]["gZ"]["children"][1]))  # DMZ: only a not-seen host
        self.assertEqual(texts(out["all"]["gZ"]["children"][3])[1], POL["zones"]["iot"] + "  ·  3 hosts, 1 active, 1 unknown")

    def test_page_kpis_and_tables(self):
        """The page shows zone/host/active/not-seen/not-in-inventory/agent tiles, a zone summary with the riskiest host and the full host list.
        REQ: NET-16"""
        out = run_js(setup_js() + "const el = new El('main'); V.netmap(el); console.log(JSON.stringify({kp: KP, el}));")
        self.assertEqual(out["kp"][0], [["Zones", 6], ["Hosts", 10], ["Active in this range", 5, "good"], ["Not seen", 5],
                                        ["Not in inventory", 3, "warn"], ["With Elastic agent", 1]])
        cards = {c["card"]: c["body"] for c in out["el"]["children"] if "card" in c}
        zt = {r["id"]: r for r in cards["Zones"]["rows"]}
        self.assertEqual((zt["user"]["n"], zt["user"]["top"]["ip"], zt["lab"]["n"]), (3, IP["laptop"], 0))
        self.assertEqual(cards["Zones"]["opts"]["sort"], "maxRisk")
        self.assertEqual(len(cards["All hosts (10)"]["rows"]), 10)
        self.assertIn("Internet hosts are not mapped", out["el"]["html"])

    def test_panel(self):
        """Clicking the gateway lists UniFi health and every zone interface; clicking a host shows its details, deduplicated sources, open issues and device links.
        REQ: NET-17"""
        out = run_js(setup_js() + """const hs = nmHosts(), zs = nmZones(hs); IDS.nmPanel = new El('div');
nmPanel(zs); const legend = IDS.nmPanel.innerHTML;
NM.sel = {gateway: true}; nmPanel(zs); const gw = IDS.nmPanel.innerHTML;
const lap = hs.find((h) => h.ip === '%s'); lap.sources.push('DHCP'); NM.sel = {host: lap}; nmPanel(zs); const host = IDS.nmPanel.innerHTML;
NM.sel = {host: hs.find((h) => h.ip === '%s')}; nmPanel(zs); const inv = IDS.nmPanel.innerHTML;
console.log(JSON.stringify({legend, gw, host, inv}));""" % (IP["laptop"], net("iot", 61)))
        self.assertIn("Unclassified", out["legend"])
        self.assertIn("<h2>UniFi gateway</h2>", out["gw"])
        self.assertIn("Example ISP", out["gw"])
        for z in POL["zones"]:
            self.assertIn(POL["zones"][z], out["gw"])
        self.assertIn("<h2>Live Laptop</h2>", out["host"])
        self.assertIn("baseline, DHCP, traffic</span>", out["host"])
        self.assertIn("Open issues (2)", out["host"])
        self.assertIn(f'href="#/device/{IP["laptop"]}"', out["host"])
        self.assertIn("<host host-a>", out["host"])
        self.assertNotIn("#/device/", out["inv"])  # no live traffic -> no device page link
        self.assertIn("not seen in this time range", out["inv"])

    def test_empty_with_zones(self):
        """With zones configured but no hosts at all (an empty snapshot) every zone is drawn empty and the tiles are zero.
        REQ: NET-16, NET-25"""
        S = {"snap": {"raw": {"devices": {}}}, "reg": {"policy": {"zones": POL["zones"]}}, "idx": {"ipHosts": {}, "rows": []}}
        out = run_js(setup_js(S) + "const el = new El('main'); V.netmap(el); console.log(JSON.stringify({kp: KP, g: IDS.nmGraph}));")
        self.assertEqual([k[1] for k in out["kp"][0]], [4, 0, 0, 0, 0, 0])
        self.assertEqual(texts(out["g"]).count("no hosts seen"), 4)

    def test_empty_without_zones(self):
        """With no zones configured and no hosts the Network map still renders (tiles at zero, gateway drawn) instead of throwing.
        REQ: NET-25"""
        S = {"snap": {"raw": {"devices": {}}}, "reg": {"policy": {}}, "idx": {"ipHosts": {}, "rows": []}}
        out = run_js(setup_js(S) + "const el = new El('main'); V.netmap(el); console.log(JSON.stringify({kp: KP, g: IDS.nmGraph}));")
        self.assertEqual([k[1] for k in out["kp"][0]], [0, 0, 0, 0, 0, 0])
        self.assertIn("UniFi gateway / firewall", texts(out["g"]))


# ------------------------------------------------------------------ Traffic map (app.js V.traffic + gatewayTraffic + historyNetwork)
def traffic_state(unifi_data=None, hist=None, in_range=True):
    d1 = dict(live("Admin Laptop", 1), countries={"US": 100, "DE": 50}, asns={"AS64500 Example": 120, "AS64501 Other": 30},
              protocols={"tcp": {"bytes": 7}, "udp": 3})
    d2 = dict(live("Yard Camera", 3), countries={"US": 10}, asns={"AS64500 Example": 10}, protocols={"tcp": 1})
    raw = {"devices": {IP["laptop"]: d1, IP["camera"]: d2},
           "internal": {"matrix": {"user -> servers": {"conns": 100, "bytes": 5000, "ports": {"22/tcp": 60, "443/tcp": 40}},
                                   "iot -> user": {"conns": 25, "bytes": 10, "ports": {"80/tcp": 25}}},
                        "flows": [F.flow(IP["laptop"], IP["server"], 22, conns=60, src_zone="user", dst_zone="servers"),
                                  F.flow(IP["laptop"], IP["server"], 443, conns=40, src_zone="user", dst_zone="servers"),
                                  F.flow(IP["camera"], IP["laptop"], 80, conns=25, src_zone="iot", dst_zone="user")]}}
    if unifi_data is not None:
        raw["unifi"] = unifi_data
    rows = [{"ip": IP["laptop"], "name": "Admin Laptop", "ext_out": 10}, {"ip": IP["camera"], "name": "", "ext_out": 99}]
    S = {"snap": {"raw": raw}, "reg": {"policy": {"zones": POL["zones"]}}, "idx": {"ipHosts": {}, "rows": rows},
         "hist": hist or [], "histInRange": in_range}
    return S


UNIFI = {"health": {"isp": "Example ISP", "wan_ip": EXT["cdn"], "status": {"wan": "ok"}, "latency_ms": 9, "drops": 0, "uptime_s": 86400},
         "clients": {"online": 3, "known_total": 7, "by_network": {"Main": 2, "IoT": 1}},
         "flows": {"total": 40, "actions": {"blocked": 6}, "blocked_by_policy": {"Block IoT": 6},
                   "top_blocked_clients": [{"client": "Yard Camera", "count": 6, "top_domains": [["bad.example", 6]]}],
                   "region_blocks": [], "risky": []}}
HIST = [{"generated": "2026-01-04T12:00:00+00:00", "devices": {"a": {"total": 100, "ext_out": 5, "conns": 2}, "b": {"total": 50, "conns": 1}}},
        {"generated": "2026-01-05T12:00:00+00:00", "devices": {"a": {"total": 300, "ext_out": 7, "conns": 4}}}]


def traffic(S):
    out = run_js(setup_js(S, {}, {}) + "const el = new El('main'); V.traffic(el); console.log(JSON.stringify({kp: KP, el}));")
    items = []
    for c in out["el"]["children"]:
        items.extend(c["items"] if "grid" in c else [c])
    return out, items


def find(items, prefix):
    hit = [i for i in items if str(i.get("card") or i.get("chart") or "").startswith(prefix)]
    if not hit:
        raise AssertionError(f"no box starting {prefix!r} in {[i.get('card') or i.get('chart') for i in items]}")
    return hit[0]


@unittest.skipUnless(NODE, "node not installed")
class TrafficMapJs(unittest.TestCase):
    """app.js Traffic map: zone matrix, internal flows, ASN/country/protocol totals, gateway section and history trend."""

    def test_zone_matrix(self):
        """The zone-to-zone heatmap has one sorted row and column per zone in the matrix, conns and bytes per cell, top ports on hover, shading by share of the busiest cell.
        REQ: NET-18"""
        _, items = traffic(traffic_state())
        h = find(items, "Zone-to-zone matrix")["body"]
        self.assertEqual(re.findall(r'<th class="num">([^<]+)</th>', h), ["iot", "servers", "user"])
        rows = re.findall(r"<tr><th>([^<]+)</th>(.*?)</tr>", h.split("<tbody>")[1], re.S)
        self.assertEqual([r[0] for r in rows], ["iot", "servers", "user"])
        cells = {r[0]: re.findall(r'<td class="num" style="background:rgba\(88,166,255,([\d.]+)\)" title="([^"]*)">(.*?)</td>', r[1], re.S) for r in rows}
        self.assertEqual(cells["user"][1][2], '100<br><span class="small">5000B</span>')
        self.assertEqual(cells["user"][1][1], "22/tcp: 60\n443/tcp: 40")
        self.assertAlmostEqual(float(cells["user"][1][0]), 0.87)
        self.assertAlmostEqual(float(cells["iot"][2][0]), 0.495)
        self.assertEqual([c[2] for c in cells["servers"]], ["", "", ""])
        self.assertEqual(cells["servers"][0][0], "0")

    def test_flows_and_totals(self):
        """Internal flows are listed (busiest first, up to 100) and internet bytes are summed over devices by country, ASN and protocol.
        REQ: NET-19"""
        _, items = traffic(traffic_state())
        fl = find(items, "Internal flows (3)")["body"]
        self.assertEqual((fl["opts"]["sort"], fl["opts"]["limit"], len(fl["rows"])), ("conns", 100, 3))
        self.assertEqual(fl["table"], ["src", "src_zone", "dst", "dst_zone", "port", "proto", "service", "conns", "answered", "bytes"])
        self.assertEqual(find(items, "All ASNs")["body"]["kv"], {"AS64500 Example": 130, "AS64501 Other": 30})
        self.assertEqual(find(items, "All countries")["body"]["kv"], {"US": 110, "DE": 50})
        self.assertEqual(find(items, "Protocols")["cfg"]["doughnut"], {"tcp": 8, "udp": 3})
        self.assertEqual(find(items, "Top ASNs")["cfg"]["labels"], ["AS64500 Example", "AS64501 Other"])
        up = find(items, "Internet upload by device")["cfg"]
        self.assertEqual((up["labels"], up["data"]), ([IP["camera"], "Admin Laptop"], [99, 10]))

    def test_empty(self):
        """Without internal traffic, UniFi or history the page still renders: an empty matrix, 'Internal flows (0)', no gateway and no trend section.
        REQ: NET-18, NET-20, NET-21"""
        S = {"snap": {"raw": {"devices": {}}}, "reg": {"policy": {}}, "idx": {"ipHosts": {}, "rows": []}, "hist": []}
        out, items = traffic(S)
        self.assertNotIn("<td", find(items, "Zone-to-zone matrix")["body"])
        self.assertEqual(find(items, "Internal flows (0)")["body"]["rows"], [])
        self.assertEqual(find(items, "All ASNs")["body"]["kv"], {})
        self.assertEqual([c.get("id") for c in out["el"]["children"] if c.get("id")], [])
        self.assertEqual(out["kp"], [])

    def test_gateway_section(self):
        """With UniFi data the page adds a 'Gateway (UniFi)' section: client and flow tiles, health, blocks by policy, clients by network, top blocked clients.
        REQ: NET-20"""
        out, items = traffic(traffic_state(UNIFI))
        self.assertIn("gateway", [c.get("id") for c in out["el"]["children"]])
        self.assertEqual(out["kp"][0], [["Clients online", "3"], ["Known clients", "7"], ["Flows logged", "40"], ["Blocked", "6"]])
        health = find(items, "Gateway health")["body"]
        self.assertIn("Example ISP", health)
        self.assertIn("1.0 days", health)
        self.assertIn("Main: 2, IoT: 1", health)
        self.assertEqual(find(items, "Blocks by policy")["cfg"]["doughnut"], {"Block IoT": 6})
        self.assertEqual(find(items, "Top blocked clients")["body"]["rows"][0]["client"], "Yard Camera")
        self.assertNotIn("Risky flows", [i.get("card") for i in items])
        skipped, items2 = traffic(traffic_state({"skipped": "no UniFi API key"}))
        self.assertIn("No UniFi data", find(items2, "Gateway health")["body"])

    def test_history_trend(self):
        """With banked history the page adds a trend section: total and internet-upload bytes, hosts and connections per snapshot.
        REQ: NET-21"""
        out, items = traffic(traffic_state(hist=HIST, in_range=False))
        sec = next(c for c in out["el"]["children"] if c.get("id") == "trend")
        self.assertIn("2 banked baseline snapshots", sec["html"])
        self.assertIn("fewer than two inside the selected range", sec["html"])
        tot = find(items, "Total bytes per snapshot")["cfg"]["data"]
        self.assertEqual(tot["labels"], [h["generated"] for h in HIST])
        self.assertEqual([d["data"] for d in tot["datasets"]], [[150, 300], [5, 7]])
        hc = find(items, "Hosts & connections per snapshot")["cfg"]["data"]["datasets"]
        self.assertEqual([d["data"] for d in hc], [[2, 1], [3, 4]])
        inr, _ = traffic(traffic_state(hist=HIST, in_range=True))
        self.assertIn("inside the selected time range", next(c for c in inr["el"]["children"] if c.get("id") == "trend")["html"])

    def test_composition_and_old_bookmarks(self):
        """The Traffic map is the traffic view, then the gateway section, then the trend; old #/unifi and #/history links land on those sections.
        REQ: NET-22"""
        out, _ = traffic(traffic_state(UNIFI, HIST))
        ids = [c.get("id") for c in out["el"]["children"] if c.get("id")]
        self.assertEqual(ids, ["gateway", "trend"])
        self.assertEqual(out["el"]["html"].split("<kpis/>")[0], "<h1>Traffic map</h1>")
        r = run_js("V.unifi(); const a = location.replaced; V.history(); console.log(JSON.stringify([a, location.replaced]));")
        self.assertEqual(r, ["#/traffic?at=gateway", "#/traffic?at=trend"])


@unittest.skipUnless(NODE, "node not installed")
class NetworkRolesJs(unittest.TestCase):
    """app.js route(): which roles may open the Network map and Traffic map."""

    def test_user_role_redirected(self):
        """A User opening #/netmap or #/traffic gets 'My devices'; a defender or admin gets the page.
        REQ: NET-23"""
        app = _read("app.js")
        uv = _slice(app, "const USER_VIEWS", "\n")
        body = _slice(app, "async function route(keep)", "const arg =")
        lines = [ln for ln in body.splitlines() if ln.strip().startswith(("let [view", "if (isUserRole() && !USER_VIEWS"))]
        self.assertEqual(len(lines), 2)
        js = uv + "\nlet ROLE = ''; const isUserRole = () => ROLE === 'user';\nfunction pick(h, r) { ROLE = r; location.hash = h;\n" + "\n".join(lines) + \
            "\nreturn view; }\nconsole.log(JSON.stringify(['#/netmap', '#/traffic', '#/traffic?at=gateway'].flatMap((h) => ['user', 'defender', 'admin'].map((r) => pick(h, r)))));"
        self.assertEqual(run_js(js), ["my", "netmap", "netmap", "my", "traffic", "traffic", "my", "traffic", "traffic"])


if __name__ == "__main__":
    unittest.main()
