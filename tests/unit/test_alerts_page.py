"""Unit tests for the Alerts page (#/alerts): the alert store's mute / suppress / retention rules, the 15-minute watcher
(watch.py) raising alerts from synthetic Elasticsearch answers, and alerts.js (bell, verdict chips, columns, detections
card, device picker, empty states) under node."""
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); import _env  # noqa: E401,E702,E402

import contextlib  # noqa: E402
import io  # noqa: E402
import json  # noqa: E402
import runpy  # noqa: E402
import shutil  # noqa: E402
import subprocess  # noqa: E402
import time  # noqa: E402
import types  # noqa: E402
import unittest  # noqa: E402
from unittest import mock  # noqa: E402

import fixtures as F  # noqa: E402
import extras as real_extras  # noqa: E402
import store  # noqa: E402

IP, EXT = F.IPS, F.EXT
WATCH = os.path.join(_env.REPO, "watch.py")
ALERTS_JS = os.path.join(_env.APP, "static", "alerts.js")
NODE_FALLBACK = os.path.expanduser(os.environ.get("NETMON_NODE", "~/.hermes/tools/node-26.7.0-linux-arm64/bin/node"))
NODE = shutil.which("node") or (NODE_FALLBACK if os.path.exists(NODE_FALLBACK) else None)


def rows():
    """Every stored alert (oldest first) with its flags."""
    return [store._arow(r) for r in store._dc().execute("SELECT * FROM alerts ORDER BY id")]


def add_mute(name, host="", limit_key=""):
    """A legacy mute rule (creation is gone from the UI and store.mute_add), inserted as an old version saved it."""
    c = store._dc()
    with store.tx(c):
        return c.execute("INSERT INTO alert_mutes(name,host,by,at,limit_key) VALUES (?,?,?,?,?)", (name, host, "tester", time.time(), limit_key)).lastrowid


# ------------------------------------------------------------------ store: legacy mute rules, suppress rules, retention
class AlertStoreTest(unittest.TestCase):
    """store.alerts_* behaviour behind the feed: mute-rule clearing and restore, suppressed alerts, 30-day window."""

    def setUp(self):
        _env.fresh_db()

    def test_muted_alert_is_stored_cleared_read_and_never_pushed(self):
        """A new alert matching a host-scoped legacy mute rule is stored cleared, read and already pushed; one for another host is not.
        REQ: ALR-09"""
        mid = add_mute("port scan*", IP["dmz"])
        store.alerts_add([("s|1", f"Port scan from {IP['dmz']}", "urgent"), ("s|2", f"Port scan from {IP['server']}", "urgent")], source="corr")
        a, b = rows()
        self.assertEqual((a["cleared"], a["cleared_rule"], a["read"], a["pushed"]), (1, mid, 1, 1))
        self.assertIsNotNone(a["cleared_at"])
        self.assertEqual((b["cleared"], b["read"], b["pushed"]), (0, 0, 0))
        self.assertEqual([x["key"] for x in store.alerts_unpushed()], ["s|2"])
        self.assertEqual([x["key"] for x in store.alerts_recent()], ["s|2"])

    def test_mute_remove_restores_only_its_alerts_as_read_and_unpushed_stays_empty(self):
        """Removing one mute rule brings back only the alerts it cleared, as read and without queueing them for push again.
        REQ: ALR-09"""
        m1, m2 = add_mute("beacon*"), add_mute("dns burst*")
        store.alerts_add([("b|1", "Beacon to a host", "urgent"), ("d|1", "DNS burst seen", "urgent"), ("o|1", "Other", "urgent")], source="corr")
        store.suppress_add("Other", "", "", "tester")
        self.assertEqual(store.mute_counts(), {m1: 1, m2: 1, -1 * store.suppress_list()[0]["id"]: 1})
        self.assertEqual(store.mute_remove(m1), ("", 1))
        back = {x["key"]: x for x in store.alerts_recent()}
        self.assertEqual(set(back), {"b|1"})
        self.assertEqual((back["b|1"]["read"], back["b|1"]["pushed"], back["b|1"]["cleared_rule"]), (1, 1, None))
        self.assertEqual(store.alerts_unpushed(), [])
        self.assertEqual([m["id"] for m in store.mute_list()], [m2])
        self.assertEqual(store.mute_counts().get(m2), 1)

    def test_mute_add_cannot_create_rules(self):
        """No new mute rule can be created any more, even with a valid pattern; the rule list stays empty.
        REQ: ALR-08"""
        with self.assertRaises(ValueError):
            store.mute_add("Beacon*", IP["laptop"], "tester")
        self.assertEqual(store.mute_list(), [])

    def test_suppressed_alert_hidden_from_feed_but_correlated(self):
        """A suppressed alert is out of the feed and push queue but still in the correlation set; muted and review alerts are not.
        REQ: ALR-10"""
        add_mute("muted thing*")
        store.suppress_add("suppressed thing", "", "", "tester")
        store.alerts_add([("x|sup", "suppressed thing on a host", "urgent"), ("x|mut", "muted thing here", "urgent"),
                          ("x|ok", "plain alert", "urgent")], source="corr")
        store.alerts_add([("x|rev", "an alarm the review raised", "investigate")], source="review")
        store.alerts_add([("x|held", "a watcher detection", "urgent")], source="watcher")
        self.assertEqual({a["key"] for a in store.alerts_recent()}, {"x|ok", "x|rev"})
        self.assertEqual({a["key"] for a in store.alerts_recent(suppressed=True)}, {"x|sup", "x|ok", "x|held"})
        self.assertNotIn("x|sup", {a["key"] for a in store.alerts_unpushed()})

    def test_thirty_day_window_covers_every_kind(self):
        """Adding alerts keeps a 29-day-old alert and deletes 31-day-old ones whether cleared, held or in the feed.
        REQ: ALR-11"""
        c = store._dc()
        now = time.time()
        with store.tx(c):
            for k, age, cleared, held in (("keep", 29, 0, 0), ("old", 31, 0, 0), ("old-cl", 31, 1, 0), ("old-held", 31, 0, 1)):
                c.execute("INSERT INTO alerts(ts,key,text,cleared,held) VALUES (?,?,?,?,?)", (now - age * 86400, k, k, cleared, held))
        store.alerts_add([("new", "new", "urgent")], source="corr")
        self.assertEqual([r["key"] for r in rows()], ["keep", "new"])


# ------------------------------------------------------------------ watch.py with stubbed Elasticsearch / feeds / hosts
class FakeES:
    """Answers the watcher's Elasticsearch queries from canned buckets, by which check sent them."""

    def __init__(self, **kw):
        self.ids, self.dhcp, self.conn_src, self.inport = kw.get("ids", []), kw.get("dhcp", []), kw.get("conn_src", []), kw.get("inport", [])
        self.dns, self.ssl, self.tiip = kw.get("dns", []), kw.get("ssl", []), kw.get("tiip", [])
        self.tunnel, self.tunnel_subs = kw.get("tunnel", []), kw.get("tunnel_subs", [])
        self.queries, self.bodies = [], []

    @staticmethod
    def _dataset(body):
        for f in body.get("query", {}).get("bool", {}).get("filter", []):
            v = f.get("term", {}).get("event.dataset")
            if v:
                return v
        return ""

    def q(self, idx, body):
        self.queries.append(idx)
        self.bodies.append(body)
        aggs, dset = body.get("aggs") or {}, self._dataset(body)
        if not aggs:  # the DNS-tunnel subdomain sample
            return {"hits": {"hits": [{"_source": {"dns": {"subdomain": s}}} for s in self.tunnel_subs]}}
        name = next(iter(aggs))
        field = (aggs[name].get("terms") or {}).get("field")
        if idx.startswith("logs-suricata"):
            b = self.ids
        elif name == "m":
            b = self.dhcp
        elif name == "s":
            b = self.conn_src
        elif name == "p":
            b = self.inport
        elif name == "n":
            b = self.dns if dset == "zeek.dns" else self.ssl if dset == "zeek.ssl" else []
        elif name == "d" and field == "destination.ip":
            b = self.tiip
        elif name == "d":
            b = self.tunnel
        else:
            b = []
        return {"aggregations": {name: {"buckets": b}}}


def bk(key, n=1, **sub):
    """One terms bucket; sub-aggregations given as lists of keys become nested bucket lists."""
    out = {"key": key, "doc_count": n}
    for k, v in sub.items():
        out[k] = {"buckets": [{"key": x, "doc_count": 1} for x in v]} if isinstance(v, list) else v
    return out


def run_watch(es, inv=None, domain_hits=None, ip_hits=None, findings=(), acks=(), admin=()):
    """Run watch.py in-process with every outside dependency stubbed (store is the isolated test DB) -> stderr text."""
    inv = inv or {}
    domain_hits, ip_hits = domain_hits or {}, ip_hits or {}
    collect = types.SimpleNamespace(q=es.q, ds=lambda n: {"term": {"event.dataset": n}}, buckets=lambda a: a.get("buckets", []),
                                    inventory=lambda: (inv, {}))
    ext = types.SimpleNamespace(refresh_feeds=lambda **k: None, load_feeds=lambda: {}, SERIOUS={"feodo", "urlhaus_ip"},
                                match_domain=lambda d, f: (d, domain_hits[d]) if d in domain_hits else (None, []),
                                match_ip=lambda ip, f: ip_hits.get(ip, []), entropy=real_extras.entropy,
                                admin_access=lambda minutes: {"errors": {}}, local_lists=lambda: {}, LOCAL_FEEDS={},
                                match_hash=lambda v, f: [], match_filename=lambda v, f: [])
    site = types.SimpleNamespace(get=lambda k, d=None: "10.0.0.0/8" if k == "internal_cidr" else d, is_internal=lambda ip: ip.startswith("10."))
    def _findings(hd, base, nightly=False):
        if findings is RuntimeError:
            raise RuntimeError("host index down (test)")
        return list(findings)
    hosts = types.SimpleNamespace(gather=lambda w, nightly=False: {}, load_base=lambda: {}, findings=_findings)
    hosts_ack = types.SimpleNamespace(load=lambda: set(acks))
    lateral = types.SimpleNamespace(admin_sessions=lambda raw, pol: list(admin))
    mitre = types.SimpleNamespace(tech=lambda i: {"name": "Technique " + i}, tags_for=lambda kind, text: "")
    opencti = types.SimpleNamespace(report_sightings=lambda hits, w: "stub")
    mods = {"collect": collect, "extras": ext, "site_cfg": site, "hosts": hosts, "hosts_ack": hosts_ack, "lateral": lateral,
            "mitre": mitre, "opencti": opencti}
    argv, path, err = list(sys.argv), list(sys.path), io.StringIO()
    try:
        with mock.patch.dict(sys.modules, mods), contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            runpy.run_path(WATCH, run_name="netmon_watch_under_test")
    finally:
        sys.argv[:], sys.path[:] = argv, path
    return err.getvalue()


def raised():
    """{key: (text, severity, source, held)} of what the watcher stored."""
    return {r["key"]: (r["text"], r["severity"], r["source"], r["held"]) for r in rows()}


class WatcherRulesTest(unittest.TestCase):
    """watch.py fixed rules, run against synthetic Elasticsearch answers."""

    def setUp(self):
        _env.fresh_db()

    def seed_registry(self):
        store.registry_save({F.mac(1): {"mac": F.mac(1), "name": "laptop", "ips": [IP["laptop"]], "known": 1}})

    def test_arrival_bookmark_moves_only_after_clean_run(self):
        """The watcher selects by event.ingested and commits its bookmark only when no check failed.
        REQ: CFG-05"""
        import window
        with store.connect() as c:
            c.execute("DELETE FROM meta WHERE k='arrival:watch'")
        es = FakeES()
        run_watch(es)
        b1 = window.bookmark("watch")
        self.assertIsNotNone(b1)
        self.assertTrue(any("event.ingested" in json.dumps(x) for x in es.bodies))
        bad = FakeES()
        with mock.patch.object(window, "commit", side_effect=AssertionError("must not commit")):
            err = run_watch(bad, findings=RuntimeError)
        self.assertIn("arrival window kept", err)

    def test_late_ids_alert_says_when_it_happened(self):
        """An IDS alert whose first event arrived >30 min late names when it happened and how late it arrived.
        REQ: CFG-05"""
        es = FakeES(ids=[bk("ET MALWARE late one", 2, src=[IP["laptop"]], dst=["203.0.113.9"],
                            t0={"value": 1_800_000_000_000, "value_as_string": "2027-01-15T08:00:00.000Z"},
                            **{"in": {"value": 1_800_000_000_000 + 3 * 3600_000}})])
        run_watch(es)
        txt = next(t for t, *_ in raised().values() if "late one" in t)
        self.assertIn("arrived 3.0 h late", txt)
        self.assertIn("happened 2027-01-15 08:00 UTC", txt)

    def test_ids_severity1_and_malware_categories_raise_investigate(self):
        """A Suricata hit not on the known-benign list raises an investigate detection with source/destination and ATT&CK; a benign one is skipped.
        REQ: ALR-12"""
        store.jdump({"signatures": {"ET INFO Benign Thing": "ok"}}, os.path.join(_env.REPO, "known_benign.json"))
        es = FakeES(ids=[bk("ET MALWARE Test C2 Beacon", 3, src=[IP["laptop"]], dst=[EXT["bad"]], mt=["T1071"]),
                         bk("ET INFO Benign Thing seen", 9, src=[IP["server"]], dst=[EXT["cdn"]], mt=[])])
        run_watch(es)
        got = raised()
        key = f"ids|ET MALWARE Test C2 Beacon|{[IP['laptop']]}"
        self.assertEqual(set(got), {key})
        text, sev, src, held = got[key]
        self.assertEqual((sev, src, held), ("investigate", "watcher", 1))
        self.assertIn(f"IDS: ET MALWARE Test C2 Beacon x3 - {IP['laptop']} -> {EXT['bad']}", text)
        self.assertIn("[ATT&CK T1071 Technique T1071]", text)
        self.assertNotIn("**", text)

    def test_new_device_dhcp_mac_and_active_ip(self):
        """An unknown DHCP MAC and an unknown internal IP with 10+ connections raise new-device detections; known, quiet, .1 and .255 do not.
        REQ: ALR-13"""
        self.seed_registry()
        es = FakeES(dhcp=[bk(F.mac(9).upper(), 2, ip=["10.0.5.50"], h=["guest-pc"]), bk(F.mac(1), 2, ip=[IP["laptop"]], h=[])],
                    conn_src=[bk("10.0.5.60", 25), bk("10.0.5.61", 9), bk("10.0.5.1", 50), bk("10.0.5.255", 50), bk(IP["laptop"], 99)])
        run_watch(es)
        got = raised()
        self.assertEqual(set(got), {f"newmac|{F.mac(9)}", "newip|10.0.5.60"})
        self.assertIn(f"New device joined: MAC {F.mac(9)} host guest-pc got 10.0.5.50", got[f"newmac|{F.mac(9)}"][0])
        self.assertEqual(got["newip|10.0.5.60"][:2], ("New device active: 10.0.5.60 made 25 connections - never seen before", "urgent"))

    def test_new_device_check_needs_a_registry(self):
        """With an empty device registry the new-device checks are skipped (no flood of alerts on a first run).
        REQ: ALR-13"""
        run_watch(FakeES(dhcp=[bk(F.mac(9), 2, ip=["10.0.5.50"], h=[])], conn_src=[bk("10.0.5.60", 25)]))
        self.assertEqual(raised(), {})

    def test_new_internet_facing_port(self):
        """An answered inbound port a device never served raises a detection; a served port, or no history yet, does not.
        REQ: ALR-14"""
        es = FakeES(inport=[bk([IP["server"], 8443], 7, s={"value": 3}, b={"value": 1234.0}),
                            bk([IP["server"], 443], 7, s={"value": 3}, b={"value": 10.0})])
        run_watch(es)
        self.assertEqual(raised(), {}, "no history: every port would be new, so nothing is raised")
        store.history_append({"generated": "2026-01-05T12:00:00+00:00", "hours": 24, "devices": {"d": {"ip": IP["server"], "served": {"443/tcp": {}}}}})
        run_watch(es)
        got = raised()
        self.assertEqual(set(got), {f"inport|{IP['server']}|8443"})
        self.assertEqual(got[f"inport|{IP['server']}|8443"][0],
                         f"New Internet-facing port: {IP['server']} answered 7 conns on port 8443 from 3 Internet hosts (1234 bytes)")

    def test_threat_intel_domain_sni_and_serious_ip(self):
        """DNS names and TLS SNI on a feed raise investigate detections; an outbound IP only when listed on a serious feed.
        REQ: ALR-15"""
        es = FakeES(dns=[bk("bad.example", 4, s=[IP["phone"]]), bk("fine.example", 4, s=[IP["phone"]])],
                    ssl=[bk("c2.example", 2, s=[IP["laptop"]])],
                    tiip=[bk(EXT["bad"], 5, s=[IP["camera"]], p=[443]), bk(EXT["cdn"], 5, s=[IP["camera"]], p=[80])])
        run_watch(es, domain_hits={"bad.example": ["urlhaus"], "c2.example": ["threatfox"]},
                  ip_hits={EXT["bad"]: ["feodo"], EXT["cdn"]: ["some_list"]})
        got = raised()
        self.assertEqual(set(got), {f"tidom|bad.example|{[IP['phone']]}", f"tidom|c2.example|{[IP['laptop']]}", f"tiip|{EXT['bad']}|{[IP['camera']]}"})
        self.assertTrue(all(v[1] == "investigate" for v in got.values()))
        self.assertEqual(got[f"tiip|{EXT['bad']}|{[IP['camera']]}"][0], f"Threat-intel IP: {IP['camera']} -> {EXT['bad']}:[443] x5 (listed in feodo)")

    def test_dns_tunnel_thresholds(self):
        """A domain with 150+ distinct long high-entropy subdomains raises a tunnel detection; too few, short or benign-listed do not.
        REQ: ALR-16"""
        import random
        rnd = random.Random(7)  # noqa: S311 - seeded test data (random-looking DNS labels), not crypto
        subs = ["".join(rnd.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(40)) for _ in range(100)]
        store.jdump({"dns_domains": ["allowed.example"]}, os.path.join(_env.REPO, "known_benign.json"))
        es = FakeES(tunnel=[bk("tunnel.example", 900, u={"value": 400}, al={"value": 40.0}, s=[IP["phone"]]),
                            bk("few.example", 900, u={"value": 149}, al={"value": 40.0}, s=[IP["phone"]]),
                            bk("allowed.example", 900, u={"value": 400}, al={"value": 40.0}, s=[IP["phone"]]),
                            bk("short.example", 900, u={"value": 400}, al={"value": 12.0}, s=[IP["phone"]])], tunnel_subs=subs)
        run_watch(es)
        got = raised()
        self.assertEqual(set(got), {"tunnel|tunnel.example"})
        self.assertTrue(got["tunnel|tunnel.example"][0].startswith("Possible DNS tunnel: tunnel.example - 400 distinct subdomains in 1h, avg 40 chars"))
        self.assertEqual(got["tunnel|tunnel.example"][1], "urgent")

    def test_endpoint_problems(self):
        """Investigate-level host findings always alert (ALERT, investigate); review-level only for the listed kinds; checked-off ones never.
        REQ: ALR-17"""
        f = [("proc-bad|host-a|evil", "Investigate", "suspicious process on host-a"), ("agent-off|host-b", "Review", "agent offline on host-b"),
             ("exe-new|host-c|x", "Review", "new executable on host-c"), ("login-new|host-d|svc", "Review", "first-seen login on host-d"),
             ("proc-bad|host-e|evil", "Investigate", "already investigated")]
        run_watch(FakeES(), findings=f, acks={"login-new|host-d|svc", "proc-bad|host-e|evil"})
        got = raised()
        self.assertEqual(set(got), {"host|proc-bad|host-a|evil", "host|agent-off|host-b"})
        self.assertEqual(got["host|proc-bad|host-a|evil"][:2], ("Host ALERT: suspicious process on host-a", "investigate"))
        self.assertEqual(got["host|agent-off|host-b"][:2], ("Host notice: agent offline on host-b", "urgent"))

    def test_failed_admin_logins(self):
        """High / medium admin sessions with failed logins or refused connections alert (high = ALERT); low or failure-free ones do not.
        REQ: ALR-18"""
        def sess(level, fail=True, refused=False, src=IP["dmz"], dst=IP["server"]):
            return {"level": level, "auth_fail": fail, "conn_failed": refused, "src": src, "dst": dst, "protocol": "SSH", "why": "password guessing",
                    "users": {"root": {"fail": 6, "ok": 1}, "ops": {"fail": 0, "ok": 2}}}
        adm = [sess("high"), sess("medium", fail=False, refused=True, dst=IP["laptop"]), sess("low", dst=IP["camera"]),
               sess("high", fail=False, dst=IP["phone"])]
        run_watch(FakeES(), admin=adm)
        got = raised()
        hi = f"admin|{IP['dmz']}|{IP['server']}|SSH|high"
        self.assertEqual(set(got), {hi, f"admin|{IP['dmz']}|{IP['laptop']}|SSH|medium"})
        self.assertEqual(got[hi][:2], (f"Admin ALERT: SSH {IP['dmz']} -> {IP['server']}: password guessing - accounts root (6 failed, 1 ok)", "investigate"))
        self.assertTrue(got[f"admin|{IP['dmz']}|{IP['laptop']}|SSH|medium"][0].startswith("Admin notice:"))

    def test_repeat_muted_for_twelve_hours(self):
        """A finding raised once is not raised again on the next run; after 12 hours it is raised again.
        REQ: ALR-19"""
        es = FakeES(ids=[bk("ET MALWARE Repeat", 1, src=[IP["laptop"]], dst=[EXT["bad"]], mt=[])])
        run_watch(es)
        run_watch(es)
        self.assertEqual(len(rows()), 1)
        c = store._dc()
        with store.tx(c):
            c.execute("UPDATE watch_mute SET ts = ?", (time.time() - 11.5 * 3600,))
        run_watch(es)
        self.assertEqual(len(rows()), 1, "still inside the 12 h window")
        with store.tx(c):
            c.execute("UPDATE watch_mute SET ts = ?", (time.time() - 12.5 * 3600,))
        run_watch(es)
        self.assertEqual(len(rows()), 2)

    def test_watcher_detections_are_held_not_alarms(self):
        """Watcher findings are stored as held detections: not in the alarm feed, not pushed, not unread, but listed for the AI review.
        REQ: ALR-19"""
        run_watch(FakeES(ids=[bk("ET MALWARE Held", 1, src=[IP["laptop"]], dst=[EXT["bad"]], mt=[])]))
        self.assertEqual(store.alerts_recent(), [])
        self.assertEqual(store.alerts_unpushed(), [])
        (r,) = rows()
        self.assertEqual((r["held"], r["read"], r["pushed"]), (1, 1, 1))
        self.assertEqual([a["key"] for a in store.alerts_recent(suppressed=True)], [r["key"]])
        self.assertIn("ip:" + IP["laptop"], r["targets"])


# ------------------------------------------------------------------ alerts.js under node
JS_HARNESS = r"""
const fs = require("fs"), vm = require("vm");
const [src, dataPath] = process.argv.slice(2);
const D = JSON.parse(fs.readFileSync(dataPath, "utf8"));
const ALL = [], CALLS = [], POSTS = [], OPENED = [];
let RERENDER = 0;
class Elem {
  constructor(sel) { this.sel = sel; this.children = []; this.html = []; this._q = {}; this.handlers = {}; this.style = {}; this.dataset = {};
    this.attrs = {}; this.classList = { toggle() {}, add() {}, remove() {} }; this.innerHTML = ""; this.textContent = ""; }
  querySelector(s) { if (!this._q[s]) { const e = new Elem(s); this._q[s] = e; ALL.push(e); } return this._q[s]; }
  querySelectorAll(s) { return ((D.qa || {})[s] || []).map((d) => { const e = new Elem(s); e.dataset = { ...d }; ALL.push(e); return e; }); }
  addEventListener(t, f) { this.handlers[t] = f; }
  appendChild(c) { this.children.push(c); return c; }
  insertAdjacentHTML(_, h) { this.html.push(h); }
  setAttribute(k, v) { this.attrs[k] = v; }
  focus() {} setSelectionRange() {} scrollIntoView() { this.scrolled = true; } replaceChildren(...a) { this.textContent = a.join(""); }
}
const BELL = [new Elem(".alert-count"), new Elem(".alert-count")];
const S = { me: { role: D.role } };
const route = (u) => {
  const R = D.routes || {};
  const v = u.includes("held=1") ? R.held : u.includes("cleared=1") ? R.cleared : u.includes("extra=1") ? (R.extra || R.feed)
    : u.startsWith("/api/alerts/mutes") ? (POSTS.some((p) => p[0] === "/api/alerts/mutes") && R.mutes_after ? R.mutes_after : R.mutes) : u.startsWith("/api/push/prefs") ? R.prefs : u.startsWith("/api/alerts") ? R.feed : undefined;
  if (v === "error" || v === undefined) throw new Error("no route " + u);
  return JSON.parse(JSON.stringify(v));
};
const doc = { hidden: false, title: "", querySelectorAll: (s) => (s === ".alert-count" ? BELL : []), querySelector: () => null,
              addEventListener() {}, createElement: (t) => new Elem(t) };
const ctx = {
  S, SITE: { site_name: D.site || "" }, V: {}, console, URLSearchParams, atob: (s) => Buffer.from(s, "base64").toString("binary"),
  navigator: { userAgent: "node" }, matchMedia: () => ({ matches: false }), location: { hash: "#/alerts" }, document: doc,
  setInterval: () => 0, confirm: () => true, alert: () => {},
  esc: (s) => String(s ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/"/g, "&quot;"), linkifyIps: (s) => String(s), fn: (n) => String(n),
  kpis: (l) => "KPIS:" + JSON.stringify(l), askCol: () => ({ k: "_ask", t: "Ask" }), isUserRole: () => S.me.role === "user",
  hq: () => new URLSearchParams(D.hq || ""), rerender: () => { RERENDER++; },
  card: (title, body) => { const c = new Elem("card"); c.title = title; c.body = body; ALL.push(c); return c; },
  table: (id, cols, rows, opts) => ({ _table: true, cols: cols.map((c) => c.t), keys: cols.map((c) => c.k),
    cells: rows.map((r) => cols.map((c) => (c.fmt ? c.fmt(r[c.k], r) : String(r[c.k] ?? "")))), rowClass: rows.map((r) => (opts.rowClass ? opts.rowClass(r) : "")),
    sort: opts.sort, filter: !!opts.filter, onclick: !!opts.onclick, evId: opts.evId ? rows.map(opts.evId) : null,
    sortKeys: cols.map((c) => (c.sort ? rows.map((r) => c.sort(r)) : null)) }),
  api: async (u) => { CALLS.push(u); return route(u); },
  apiPost: async (u, b) => { POSTS.push([u, b]); return { ok: true }; },
};
ctx.window = ctx; ctx.oeOpenDetail = (o) => OPENED.push(o);
const tick = () => new Promise((r) => setTimeout(r, 0));
const dump = (x) => {
  if (!x || typeof x !== "object") return x;
  if (x._table) return x;
  return { sel: x.sel, title: x.title, body: dump(x.body), innerHTML: x.innerHTML, text: String(x.textContent), html: x.html, children: x.children.map(dump) };
};
vm.createContext(ctx);
vm.runInContext(fs.readFileSync(src, "utf8"), ctx);
(async () => {
  for (let i = 0; i < 5; i++) await tick();  // the initial poll()
  const out = [];
  for (const st of D.steps || [{ do: "render" }]) {
    if (st.do === "render") {
      CALLS.length = 0;
      const el = new Elem("page");
      await ctx.V.alerts(el);
      for (let i = 0; i < 5; i++) await tick();
      const settings = el._q["#alSet"]?._q[".slide-in"];
      out.push({ head: el.innerHTML, html: el.html, cards: el.children.map(dump), settings: settings ? settings.children.map(dump) : [], calls: [...CALLS] });
    } else if (st.do === "click") {
      const e = [...ALL].reverse().find((x) => x.sel === st.sel && (x.handlers.click || x.onclick) && (!st.v || x.dataset.v === st.v));
      if (!e) throw new Error("nothing to click: " + st.sel);
      await (e.handlers.click || e.onclick)({ target: e });
      for (let i = 0; i < 5; i++) await tick();
      out.push({ clicked: st.sel });
    } else if (st.do === "mute-rm") {
      const c = [...ALL].reverse().find((x) => x.sel === "card" && String(x.title).startsWith("Alert mute rules"));
      const b = { dataset: { id: String(st.id) }, disabled: false };
      await c.handlers.click({ target: { closest: () => b } });
      out.push({ clicked: "mute-rm" });
    } else if (st.do === "picker") {
      const o = { ...st.opts, save: async (m, d) => { POSTS.push(["save", { mode: m, devices: d }]); return "saved " + m; } };
      if (st.cancel) o.cancel = () => {};
      const c = ctx.window.devicePicker(o);
      if (st.save) { await c._q[".dp-save"].onclick(); }
      out.push({ picker: c.innerHTML, msg: c._q[".dp-msg"]?.textContent || "" });
    }
  }
  process.stdout.write(JSON.stringify({ steps: out, posts: POSTS, bell: BELL.map((b) => [String(b.textContent), b.style.display]), title: doc.title, rerenders: RERENDER }));
})().catch((e) => { console.error(e && e.stack || e); process.exit(1); });
"""

NOW = 1767600000  # 2026-01-05
NO_HELD = {"alerts": [], "total": 0, "matching": 0, "counts": {"alarms": {}, "detections": {}}, "extra": {}}
USER_PREFS = {"prefs": {"mode": "some", "devices": []}, "devices": [], "locked": True}


def feed_row(i, text, read=0, mine=True, verdict="unreviewed", vsrc="", sev="urgent"):
    """One row as /api/alerts?extra=1 returns it (eid / verdict / vsrc set by eventstore.alert_view)."""
    return {"id": i, "ts": NOW - i * 60, "key": f"k|{i}", "text": text, "severity": sev, "read": read, "mine": mine,
            "targets": ["ip:" + IP["laptop"]], "source": "corr", "eid": f"alert|{i}", "verdict": verdict, "vsrc": vsrc}


def plain(rows_):
    """The same rows as the plain feed (/api/alerts?limit=200) returns them: no verdict fields."""
    return [{k: v for k, v in r.items() if k not in ("eid", "verdict", "vsrc")} for r in rows_]


def feed(rows_=(), unread=None, unread_mine=None, mode="all"):
    rows_ = list(rows_)
    n = sum(1 for r in rows_ if not r["read"])
    return {"alerts": plain(rows_), "unread": n if unread is None else unread, "unread_mine": n if unread_mine is None else unread_mine, "mode": mode}


def counts(alarms=None, det=None):
    return {"alarms": alarms or {}, "detections": det or {}}


@unittest.skipUnless(NODE, "node not available")
class AlertsPageJsTest(unittest.TestCase):
    """alerts.js V.alerts, devicePicker and the bell under node with stubbed page helpers."""

    def run_js(self, role="admin", feed_=None, extra=None, held="error", mutes=None, mutes_after=None, cleared=None, prefs=None,
               steps=None, hq="", qa=None):
        d = os.environ["NETMON_TEST_TMP"]
        hp, dp = os.path.join(d, "alr_harness.js"), os.path.join(d, "alr_data.json")
        with open(hp, "w") as f:
            f.write(JS_HARNESS)
        routes = {"feed": feed_ if feed_ is not None else feed(), "extra": extra, "held": held,
                  "mutes": mutes if mutes is not None else {"mutes": []}, "mutes_after": mutes_after,
                  "cleared": cleared if cleared is not None else {"alerts": [], "cleared": True},
                  "prefs": prefs or {"prefs": {"mode": "all", "devices": []}, "devices": []}}
        with open(dp, "w") as f:
            json.dump({"role": role, "site": "Lab", "routes": routes, "steps": steps, "hq": hq, "qa": qa or {}}, f)
        r = subprocess.run([NODE, hp, ALERTS_JS, dp], capture_output=True, text=True, timeout=30)  # noqa: S603 - node on repo files
        self.assertEqual(r.returncode, 0, r.stderr)
        return json.loads(r.stdout)

    @staticmethod
    def card(step, prefix):
        return next((c for c in step["cards"] if str(c["title"]).startswith(prefix)), None)

    def test_bell_count_and_title(self):
        """The bell shows the unread count (99+ above 99) and the tab title carries it; with nothing unread the bell is hidden.
        REQ: ALR-20"""
        out = self.run_js(feed_=feed(unread=150, unread_mine=2), steps=[])
        self.assertEqual(out["bell"], [["99+", ""], ["99+", ""]])
        self.assertEqual(out["title"], "(150) netmon · Lab")
        out = self.run_js(feed_=feed(unread=0, unread_mine=0), steps=[])
        self.assertEqual(out["bell"][0], ["0", "none"])
        self.assertEqual(out["title"], "netmon · Lab")

    def test_bell_uses_my_devices_count_when_narrowed(self):
        """For an account alerting on chosen devices only, the bell counts the unread alerts of those devices.
        REQ: ALR-20"""
        out = self.run_js(feed_=feed(unread=40, unread_mine=3, mode="some"), steps=[])
        self.assertEqual(out["bell"][0], ["3", ""])
        self.assertEqual(out["title"], "(3) netmon · Lab")

    def test_mark_all_read_button(self):
        """Mark all read posts /api/alerts/read, zeroes the bell and redraws the page; it is only offered while something is unread.
        REQ: ALR-20, ALR-06"""
        out = self.run_js(feed_=feed([feed_row(1, "an unread alert")]), steps=[{"do": "render"}, {"do": "click", "sel": "#markRead"}])
        ac = self.card(out["steps"][0], "Recent alerts")
        self.assertIn('id="markRead"', ac["title"])
        self.assertIn("(1, 1 new)", ac["title"])
        self.assertIn(["/api/alerts/read", {}], out["posts"])
        self.assertEqual(out["bell"][0], ["0", "none"])
        self.assertGreaterEqual(out["rerenders"], 1)
        out = self.run_js(feed_=feed([feed_row(1, "read", read=1)]))
        self.assertNotIn("markRead", self.card(out["steps"][0], "Recent alerts")["title"])

    def test_verdict_chip_and_provenance(self):
        """The Verdict column shows not reviewed, a person's verdict with 👤, the event reviewer's with its confidence, or the decision model's.
        REQ: ALR-21"""
        rows_ = [feed_row(1, "a"), feed_row(2, "b", verdict="suspicious", vsrc="person"),
                 feed_row(3, "c", verdict="benign", vsrc="ai"), feed_row(4, "d", verdict="expected", vsrc="model")]
        extra = {"alerts": rows_, "extra": {"classes": {"alert|3": {"label": "benign", "confidence": 0.83, "reason": "Decision model: x"}}}}
        out = self.run_js(feed_=feed(rows_), extra=extra, held=NO_HELD)
        t = self.card(out["steps"][0], "Recent alerts")["body"]
        col = t["cols"].index("Verdict")
        v = [r[col] for r in t["cells"]]
        self.assertIn("not reviewed", v[0])
        self.assertIn("👤 suspicious", v[1])
        self.assertIn("a person's verdict", v[1])
        self.assertIn('class="note-v v-benign"', v[2])
        self.assertIn("AI 83%", v[2])
        self.assertIn("event reviewer (AI)", v[2])
        self.assertIn('expected</span> <span class="small muted">model</span>', v[3])
        self.assertEqual(t["sortKeys"][col], [3, 0, 2, 1], "sorted suspicious, expected, benign, unreviewed")

    def test_alarm_columns_by_role(self):
        """Admins and defenders get Ask, When, Level, Verdict, Alert, Research, Notes, Artifact notes, row links and filter; a User gets When, Level, Alert only.
        REQ: ALR-22"""
        rows_ = [feed_row(1, "a", sev="investigate")]
        for role in ("admin", "defender"):
            with self.subTest(role=role):
                out = self.run_js(role=role, feed_=feed(rows_), extra={"alerts": rows_, "extra": {}}, held=NO_HELD)
                t = self.card(out["steps"][0], "Recent alerts")["body"]
                self.assertEqual(t["cols"], ["Ask", "When", "Level", "Verdict", "Alert", "Research", "Notes", "Artifact notes"])
                self.assertTrue(t["onclick"] and t["filter"])
                self.assertEqual(t["evId"], ["alert|1"])
                self.assertIn("sev-high", t["cells"][0][2])
                self.assertEqual(t["rowClass"], ["unread"])
        out = self.run_js(role="user", feed_=feed(rows_, mode="some"), prefs=USER_PREFS)
        st = out["steps"][0]
        t = self.card(st, "Alerts for my devices")["body"]
        self.assertEqual(t["cols"], ["When", "Level", "Alert"])
        self.assertFalse(t["onclick"] or t["filter"])
        self.assertIsNone(t["evId"])
        self.assertNotIn("fTog", self.card(st, "Alerts for my devices")["title"])
        self.assertEqual(st["calls"], ["/api/push/prefs"], "a User's page loads no verdicts, detections or mute rules")

    def test_research_notes_and_artifact_cells(self):
        """Research shows the research note, reviewed, cited pages and look-ups (or the decision model's p(suspicious)); Notes and Artifact notes show counts.
        REQ: ALR-22"""
        rows_ = [feed_row(1, "a", verdict="benign", vsrc="ai"), feed_row(2, "b"), feed_row(3, "c")]
        ex = {"classes": {"alert|1": {"label": "benign", "confidence": 0.9, "reason": "Routine update traffic.", "sources": [{"url": "https://a"}, {"url": "https://b"}]}},
              "notes": {"alert|1": {"verdict": "benign", "summary": "known updater"}},
              "web": {"alert|1": [{"kind": "search", "query": "updater domain"}]},
              "clef_ev": {"alert|2": {"p_suspicious": 0.27}},
              "unotes": {"alert|1": [{"status": "pending"}, {"status": "approved"}]},
              "art_notes": {"alert|1": [{"id": "n1"}]}, "art_note_text": {"n1": {"subject": "updater", "text": "fine"}}}
        out = self.run_js(feed_=feed(rows_), extra={"alerts": rows_, "extra": ex}, held=NO_HELD)
        t = self.card(out["steps"][0], "Recent alerts")["body"]
        c = {k: [r[t["cols"].index(k)] for r in t["cells"]] for k in ("Research", "Notes", "Artifact notes", "Alert")}
        for s in ("📝 benign", "🤖 reviewed", "🌍2", "🔎1"):
            self.assertIn(s, c["Research"][0])
        self.assertIn("decision model: p(suspicious) 27%", c["Research"][1])
        self.assertIn("none yet", c["Research"][2])
        self.assertIn("📝 2 ⏳", c["Notes"][0])
        self.assertIn('data-unote="alert|2"', c["Notes"][1])
        self.assertIn("🏷 1", c["Artifact notes"][0])
        self.assertIn("–", c["Artifact notes"][1])
        self.assertIn("Routine update traffic.", c["Alert"][0])
        self.assertIn("🤖 Event reviewer", c["Alert"][0])
        self.assertNotIn("Event reviewer", c["Alert"][1])

    def test_detections_card_kpis_and_chips(self):
        """The detections card lists held detections with verdict chips and counts; KPI tiles add alarms and detections per verdict.
        REQ: ALR-23"""
        det = [feed_row(5, "held one", verdict="benign", vsrc="ai"), feed_row(6, "held two", sev="low")]
        held = {"alerts": det, "total": 7, "matching": 7, "counts": counts({"suspicious": 1}, {"benign": 4, "unreviewed": 3}), "extra": {}}
        out = self.run_js(extra={"alerts": [], "extra": {}}, held=held)
        st = out["steps"][0]
        kp = json.loads(next(h for h in st["html"] if h.startswith("KPIS:"))[5:])
        self.assertEqual([k[0] for k in kp], ["Suspicious", "Expected", "Benign", "Not reviewed"])
        self.assertIn('>1</a> <span class="small muted">1 alarm</span>', kp[0][1])
        self.assertEqual((kp[0][2], kp[1][2], kp[2][2], kp[3][2]), ("bad", "good", "good", ""))
        self.assertIn(">4</a>", kp[2][1])
        self.assertIn(">3</a>", kp[3][1])
        dc = self.card(st, "Detections by verdict")
        self.assertEqual(dc["title"], "Detections by verdict (7, newest 2 shown)")
        self.assertIn('class="vf-chip on" data-v="">All (7)', dc["body"])
        self.assertIn('data-v="benign">Benign (4)', dc["body"])
        self.assertIn('data-v="suspicious">Suspicious (0)', dc["body"])
        t = dc["children"][0]
        self.assertEqual(t["cols"], ["When", "Level", "Verdict", "Detection", "Research", "Notes", "Artifact notes"])
        self.assertIn("sev-medium", t["cells"][0][1])
        self.assertIn("sev-low", t["cells"][1][1])
        self.assertTrue(t["onclick"] and t["filter"])

    def test_detections_verdict_filter_round_trip(self):
        """Clicking a verdict chip re-requests the detections with v=<verdict> and titles the card with the match count; no match says so.
        REQ: ALR-23, ALR-25"""
        held = {"alerts": [], "total": 3, "matching": 0, "counts": counts({}, {"benign": 3}), "extra": {}}
        out = self.run_js(extra={"alerts": [], "extra": {}}, held=held, qa={".vf-chip": [{"v": "suspicious"}]},
                          steps=[{"do": "render"}, {"do": "click", "sel": ".vf-chip", "v": "suspicious"}, {"do": "render"}])
        self.assertIn("/api/alerts?held=1&limit=200", out["steps"][0]["calls"])
        self.assertIn("/api/alerts?held=1&limit=200&v=suspicious", out["steps"][2]["calls"])
        dc = self.card(out["steps"][2], "Detections by verdict")
        self.assertEqual(dc["title"], "Detections by verdict (0 suspicious)")
        self.assertIn('class="vf-chip on" data-v="suspicious"', dc["body"])
        self.assertEqual((dc["children"][0]["sel"], dc["children"][0]["text"]), ("div", "No detections with this verdict."))

    def test_only_my_devices_toggle(self):
        """An admin alerting on chosen devices sees only their alerts with a show all N link; the toggle shows every alert; ?ev= skips the filter.
        REQ: ALR-02, ALR-25"""
        rows_ = [feed_row(1, "mine", mine=True), feed_row(2, "other", mine=False, read=1)]
        f = feed(rows_, unread=1, unread_mine=1, mode="some")
        out = self.run_js(feed_=f, extra={"alerts": rows_, "extra": {}}, held=NO_HELD,
                          steps=[{"do": "render"}, {"do": "click", "sel": "#fTog"}, {"do": "render"}])
        a = self.card(out["steps"][0], "Alerts for my devices")
        self.assertIn("(1, 1 new)", a["title"])
        self.assertIn("show all 2", a["title"])
        self.assertEqual(a["body"]["cells"][0][4].count("mine"), 1)
        b = self.card(out["steps"][2], "Recent alerts")
        self.assertIn("(2, 1 new)", b["title"])
        self.assertIn("only my devices", b["title"])
        out = self.run_js(feed_=f, extra={"alerts": rows_, "extra": {}}, held=NO_HELD, hq="ev=alert|2")
        self.assertIn("(2, 1 new)", self.card(out["steps"][0], "Recent alerts")["title"])

    def test_mute_rules_card_and_cleared_view(self):
        """Admins / defenders see the legacy mute rules with Remove rule and show cleared (N); the cleared view lists what rules cleared; Users see neither.
        REQ: ALR-07, ALR-05, ALR-25"""
        mutes = {"mutes": [{"id": 3, "name": "beacon*", "host": "", "by": "old-admin", "at": NOW, "cleared": 2},
                           {"id": 4, "name": "scan", "host": IP["dmz"], "by": "old-admin", "at": NOW, "cleared": 1}]}
        cleared = {"alerts": [dict(plain([feed_row(9, "Beacon x")])[0], rule="beacon*")], "cleared": True}
        for role in ("admin", "defender"):
            with self.subTest(role=role):
                out = self.run_js(role=role, mutes=mutes, cleared=cleared,
                                  steps=[{"do": "render"}, {"do": "click", "sel": "#clTog"}, {"do": "render"}, {"do": "mute-rm", "id": 3}])
                st = out["steps"][0]
                mc = self.card(st, "Alert mute rules")
                self.assertEqual(mc["title"], "Alert mute rules (2)")
                t = mc["children"][0]
                self.assertEqual(t["cols"], ["Alert text pattern", "Host", "Muted by", "When", "Cleared", ""])
                self.assertIn("any", t["cells"][0][1])
                self.assertIn(IP["dmz"], t["cells"][1][1])
                self.assertIn('class="mute-rm" data-id="3"', t["cells"][0][5])
                self.assertIn("show cleared (3)", self.card(st, "Recent alerts")["title"])
                cv = self.card(out["steps"][2], "Cleared alerts")
                self.assertTrue(cv["title"].startswith("Cleared alerts (1)"))
                self.assertIn("back to recent alerts", cv["title"])
                self.assertEqual(cv["body"]["cols"], ["When", "Level", "Alert", "Cleared by rule"])
                self.assertIn("beacon*", cv["body"]["cells"][0][3])
                self.assertIsNone(self.card(out["steps"][2], "Recent alerts"), "the cleared view replaces the feed")
                self.assertIn("/api/alerts?cleared=1&limit=500", out["steps"][2]["calls"])
                self.assertIn(["/api/alerts/mutes", {"action": "remove", "id": 3}], out["posts"])
        out = self.run_js(role="user", feed_=feed(mode="some"), mutes=mutes, prefs=USER_PREFS)
        self.assertNotIn("/api/alerts/mutes", out["steps"][0]["calls"])
        self.assertIsNone(self.card(out["steps"][0], "Alert mute rules"))

    def test_no_mute_rules_means_no_mute_card(self):
        """Without legacy mute rules there is no mute-rules card and no show cleared link.
        REQ: ALR-25"""
        out = self.run_js(feed_=feed([feed_row(1, "a", read=1)]))
        st = out["steps"][0]
        self.assertIsNone(self.card(st, "Alert mute rules"))
        self.assertNotIn("show cleared", self.card(st, "Recent alerts")["title"])

    def test_empty_mute_card_does_not_offer_removed_mute_creation(self):
        """After the last mute rule is removed in the cleared view, the empty rules card must not tell people to create one with mute name….
        REQ: ALR-25"""
        mutes = {"mutes": [{"id": 3, "name": "beacon*", "host": "", "by": "a", "at": NOW, "cleared": 1}]}
        out = self.run_js(mutes=mutes, mutes_after={"mutes": []},
                          steps=[{"do": "render"}, {"do": "click", "sel": "#clTog"}, {"do": "render"}, {"do": "mute-rm", "id": 3}, {"do": "render"}])
        mc = self.card(out["steps"][4], "Alert mute rules")
        self.assertEqual(mc["title"], "Alert mute rules (0)")
        self.assertNotIn("mute name", "".join(mc["html"]))

    def test_empty_states(self):
        """With no alerts the feed says so; an empty detections list and an empty cleared view say so too.
        REQ: ALR-25"""
        out = self.run_js(extra={"alerts": [], "extra": {}}, held=NO_HELD,
                          mutes={"mutes": [{"id": 1, "name": "x", "host": "", "by": "a", "at": NOW, "cleared": 0}]},
                          steps=[{"do": "render"}, {"do": "click", "sel": "#clTog"}, {"do": "render"}])
        st = out["steps"][0]
        ac = self.card(st, "Recent alerts")
        self.assertEqual(ac["body"], '<div class="empty">No urgent alerts in the last 30 days.</div>')
        self.assertNotIn("markRead", ac["title"])
        dc = self.card(st, "Detections by verdict")
        self.assertEqual(dc["title"], "Detections by verdict (0)")
        self.assertEqual(dc["children"][0]["text"], "No detections with this verdict.")
        self.assertIn("No cleared alerts in the last 30 days.", self.card(out["steps"][2], "Cleared alerts")["body"])

    def test_older_server_falls_back_to_plain_feed(self):
        """When the verdict extras, detections and mute rules cannot be loaded the page still shows the plain feed, without verdict columns or detections.
        REQ: ALR-25"""
        out = self.run_js(feed_=feed([feed_row(1, "plain")]), extra="error", held="error", mutes="error")
        st = out["steps"][0]
        t = self.card(st, "Recent alerts")["body"]
        self.assertEqual(t["cols"], ["Ask", "When", "Level", "Alert"])
        self.assertFalse(t["onclick"])
        self.assertIsNone(self.card(st, "Detections by verdict"))
        self.assertIsNone(self.card(st, "Alert mute rules"))
        self.assertFalse(any(h.startswith("KPIS:") for h in st["html"]))

    def test_my_devices_panel_locked_for_user(self):
        """A User sees the devices an admin assigned (read-only) or a note that none are assigned; no picker.
        REQ: ALR-24"""
        devs = [{"id": "d1", "name": "Kid phone", "ips": [IP["phone"]], "mac": F.mac(3)}, {"id": "d2", "name": "", "ips": [IP["camera"]], "mac": ""}]
        out = self.run_js(role="user", feed_=feed(mode="some"), prefs={"prefs": {"mode": "some", "devices": ["d1", "d2"]}, "devices": devs, "locked": True})
        s = out["steps"][0]["settings"]
        self.assertEqual([c["title"] for c in s], ["Notifications on this device", "Your devices"])
        self.assertIn("<b>Kid phone</b>", s[1]["body"])
        self.assertIn(f"{IP['phone']} · {F.mac(3)}", s[1]["body"])
        self.assertIn(f"<b>{IP['camera']}</b>", s[1]["body"])
        self.assertIn("assigned by an admin", s[1]["body"])
        self.assertNotIn("dp-save", s[1]["innerHTML"] + s[1]["body"])
        out = self.run_js(role="user", feed_=feed(mode="some"), prefs=USER_PREFS)
        self.assertIn("No devices are assigned to your account yet", out["steps"][0]["settings"][1]["body"])

    def test_my_devices_picker_for_admin(self):
        """An admin or defender gets the Which devices alert me picker with All devices and Only devices I choose.
        REQ: ALR-24"""
        for role in ("admin", "defender"):
            with self.subTest(role=role):
                out = self.run_js(role=role, prefs={"prefs": {"mode": "all", "devices": []},
                                                    "devices": [{"id": "d1", "name": "Lap", "ips": [IP["laptop"]], "mac": F.mac(1), "known": True}]})
                s = out["steps"][0]["settings"]
                self.assertEqual(s[1]["title"], "Which devices alert me")
                self.assertIn('value="all" checked', s[1]["innerHTML"])
                self.assertIn("Only devices I choose", s[1]["innerHTML"])
                self.assertIn("<b>Lap</b>", s[1]["innerHTML"])

    def test_device_picker_modes(self):
        """devicePicker: all hides the list, some shows it with chosen devices first and a count, badges, noAll, cancel, no match and the save message.
        REQ: ALR-24"""
        devs = [{"id": "a", "name": "Alpha", "ips": [IP["laptop"]], "mac": F.mac(1), "known": True},
                {"id": "b", "name": "", "ips": [IP["server"], IP["dmz"], "10.0.2.99"], "mac": F.mac(2), "known": False, "endpoint": True}]
        base = {"title": "Pick", "intro": "choose"}
        out = self.run_js(steps=[{"do": "picker", "opts": dict(base, prefs={"mode": "all", "devices": []}, devices=devs)},
                                 {"do": "picker", "opts": dict(base, prefs={"mode": "some", "devices": ["b"]}, devices=devs, noAll=True, someLabel="Assigned"),
                                  "cancel": True, "save": True},
                                 {"do": "picker", "opts": dict(base, prefs={"mode": "some", "devices": []}, devices=[])}])
        p0, p1, p2 = (s["picker"] for s in out["steps"])
        self.assertIn('value="all" checked', p0)
        self.assertIn('class="dp-list" style="display:none"', p0)
        self.assertNotIn("dp-cancel", p0)
        self.assertNotIn('value="all"', p1)
        self.assertIn("<b>Assigned</b>", p1)
        self.assertIn("(1 selected)", p1)
        self.assertIn('class="dp-list" style=""', p1)
        self.assertLess(p1.index('value="b" checked'), p1.index('value="a"'), "chosen devices are listed first")
        self.assertIn('sev-info">endpoint', p1)
        self.assertIn('sev-unknown">unknown', p1)
        self.assertIn(f"<b>{IP['server']}</b>", p1, "a device without a name is labelled by its first IP")
        self.assertIn(f"{IP['server']} · {IP['dmz']} · {F.mac(2)}", p1)
        self.assertNotIn("10.0.2.99", p1)
        self.assertIn("dp-cancel", p1)
        self.assertEqual(out["steps"][1]["msg"], "saved some")
        self.assertIn(["save", {"mode": "some", "devices": ["b"]}], out["posts"])
        self.assertIn("No match.", p2)


if __name__ == "__main__":
    unittest.main()
