"""Unit tests for the Settings page documents: settings_docs catalog vs templates, store cfg round trip, server.cfg_validate
and the /api/config/cfg handler, auto-tune (tuning.py) and UniFi auto-discover (discover.py, UniFi stubbed)."""
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); import _env  # noqa: E401,E402

import contextlib  # noqa: E402
import copy  # noqa: E402
import io  # noqa: E402
import json  # noqa: E402
import unittest  # noqa: E402
from unittest import mock  # noqa: E402

import fixtures  # noqa: E402
import store  # noqa: E402
import settings_docs  # noqa: E402
import site_cfg  # noqa: E402
import tuning  # noqa: E402
import discover  # noqa: E402
import server  # noqa: E402
from server import cfg_validate  # noqa: E402

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
TEMPLATES = {d: os.path.join(REPO, d + ".example.json") for d in store.CFG_DOCS}
MB = 1024 * 1024


def template(doc):
    with open(TEMPLATES[doc]) as f:
        return json.load(f)


def keys(d):
    return [k for k in d if not k.startswith("_")]


def reset():
    _env.fresh_db()
    store._cfg_cache.clear()
    site_cfg._cache = None
    site_cfg._at = 0.0
    site_cfg._src = None


def seed_templates():
    for d in store.CFG_DOCS:
        store.cfg_save(d, template(d))


def post(path, body, role="admin", raw=None):
    """Drive the real POST handler (server.H._do_post) without a socket; returns (status code, response object)."""
    h = server.H.__new__(server.H)
    data = raw if raw is not None else json.dumps(body).encode()
    h.path = path
    h.headers = {"X-Netmon": "1", "Content-Type": "application/json", "Content-Length": str(len(data))}
    h.rfile = io.BytesIO(data)
    h._aud, h._code, h._body_read = {"path": path}, None, False
    out = {}
    h._json = lambda obj, code=200: out.update(obj=obj, code=code)
    with mock.patch.object(server.H, "_user", lambda self: "settings-tester"), \
            mock.patch.object(server.auth, "role_of", lambda u: role), contextlib.redirect_stderr(io.StringIO()):
        h._do_post()
    return out["code"], out["obj"]


# ---------------------------------------------------------------- catalog
class SettingsCatalog(unittest.TestCase):
    """settings_docs.DOCS matches the shipped templates and code defaults."""

    def test_every_documented_key_is_shipped(self):
        """Every key documented in settings_docs.DOCS exists in its *.example.json template or in the code defaults.
        REQ: SET-40"""
        self.assertEqual(set(settings_docs.DOCS), set(store.CFG_DOCS))
        for doc, m in settings_docs.DOCS.items():
            shipped = set(keys(template(doc))) | (set(site_cfg.DEFAULTS) if doc == "site" else set())
            for k in m:
                with self.subTest(doc=doc, key=k):
                    self.assertIn(k, shipped)

    def test_no_undocumented_template_setting(self):
        """Every setting in the shipped templates (and every site default) has a DOCS entry, so none is undocumented.
        REQ: SET-41"""
        for doc in store.CFG_DOCS:
            for k in keys(template(doc)):
                with self.subTest(doc=doc, key=k):
                    self.assertIn(k, settings_docs.DOCS[doc])
        for k in site_cfg.DEFAULTS:
            with self.subTest(site_default=k):
                self.assertIn(k, settings_docs.DOCS["site"])

    def test_template_notes_match_catalog(self):
        """The _doc_<key> note in each template is exactly the catalog text and every catalog text is non-empty.
        REQ: SET-41"""
        for doc, m in settings_docs.DOCS.items():
            t = template(doc)
            for k, text in m.items():
                with self.subTest(doc=doc, key=k):
                    self.assertTrue(text.strip())
                    self.assertEqual(t.get("_doc_" + k), text)


# ---------------------------------------------------------------- store round trip
class CfgRoundTrip(unittest.TestCase):
    """store.cfg_save / cfg_load give back exactly what was saved."""

    def setUp(self):
        reset()

    def tearDown(self):
        reset()

    def test_templates_round_trip_key_by_key(self):
        """Each template, and each documented key in it, comes back unchanged (values and types) after cfg_save/cfg_load.
        REQ: SET-42"""
        for doc in store.CFG_DOCS:
            t = template(doc)
            n = store.cfg_save(doc, t)
            self.assertGreater(n, 0)
            store._cfg_cache.clear()
            back = store.cfg_load(doc)
            self.assertEqual(back, t)
            self.assertEqual(list(back), list(t))  # document order kept
            for k in settings_docs.DOCS[doc]:
                with self.subTest(doc=doc, key=k):
                    self.assertEqual(json.dumps(back[k], sort_keys=True), json.dumps(t[k], sort_keys=True))

    def test_awkward_values_round_trip(self):
        """Keys with / # %, floats, bools, None, empty strings and empty / nested containers survive the round trip.
        REQ: SET-42"""
        d = {"a/b": {"#1": 1, "50%": 0.75}, "flag": True, "off": False, "none": None, "empty": "", "el": [], "ed": {},
             "nested": [[1, 2], [], [{"x": "y"}]], "ports": [22, 443], "neg": -3, "mac": {fixtures.mac(1): "camera"}}
        store.cfg_save("policy", d)
        store._cfg_cache.clear()
        back = store.cfg_load("policy")
        self.assertEqual(back, d)
        self.assertIs(back["flag"], True)
        self.assertIsInstance(back["a/b"]["50%"], float)

    def test_load_returns_private_copy(self):
        """Mutating the dict from cfg_load does not change the stored settings.
        REQ: SET-42"""
        store.cfg_save("site", template("site"))
        d = store.cfg_load("site")
        d["site_name"] = "changed"
        self.assertEqual(store.cfg_load("site")["site_name"], template("site")["site_name"])


# ---------------------------------------------------------------- cfg_validate
class CfgValidate(unittest.TestCase):
    """server.cfg_validate accepts the templates and rejects malformed values per document."""

    def bad(self, doc, data):
        self.assertIsNotNone(cfg_validate(doc, data), f"{doc} accepted {data!r}")

    def pol(self, **kw):
        p = template("policy")
        p.update(kw)
        return p

    def test_templates_are_valid(self):
        """Every shipped template passes its document's validator.
        REQ: SET-43"""
        for doc in store.CFG_DOCS:
            with self.subTest(doc=doc):
                self.assertIsNone(cfg_validate(doc, template(doc)))

    def test_bad_zones_rejected(self):
        """A zone whose subnet is not a CIDR, or a zones value that is not a table, is rejected; _ notes are skipped.
        REQ: SET-44"""
        for z in ({"lan": "10.0.0.0/33"}, {"lan": "not-a-net"}, {"lan": "10.0.0.300/24"}, ["10.0.0.0/24"]):
            with self.subTest(zones=z):
                self.bad("policy", self.pol(zones=z))
        self.assertIsNone(cfg_validate("policy", self.pol(zones={"lan": "10.0.0.0/24", "_doc": "not a cidr"})))
        self.assertIsNone(cfg_validate("policy", self.pol(zones={"lan": "10.0.0.5/24"})))  # host bits allowed (strict=False)

    def test_unknown_zone_role_rejected(self):
        """A zone role outside dmz, protected, mgmt, user, iot is rejected; each valid role is accepted.
        REQ: SET-44"""
        self.bad("policy", self.pol(zone_roles={"lan": "kitchen"}))
        self.assertIn("zone_roles[lan]", cfg_validate("policy", self.pol(zone_roles={"lan": "kitchen"})))
        for r in discover.ROLES:
            self.assertIsNone(cfg_validate("policy", self.pol(zone_roles={"lan": r})))

    def test_upload_spike_values(self):
        """upload_spike rejects a bad severity, non-numeric / boolean / negative numbers, unknown keys and a non-table.
        REQ: SET-45"""
        base = template("policy")["upload_spike"]
        for k, v in (("severity", "loud"), ("min_mb", "25"), ("min_mb", True), ("times_normal", -1), ("min_days", None), ("bogus", 1)):
            with self.subTest(key=k, value=v):
                self.bad("policy", self.pol(upload_spike={**base, k: v}))
        self.bad("policy", self.pol(upload_spike=[1, 2]))
        for sev in ("high", "medium", "low", "off"):
            self.assertIsNone(cfg_validate("policy", self.pol(upload_spike={**base, "severity": sev, "min_mb": 0, "mad_factor": 2.5})))

    def test_new_destination_class_lists(self):
        """new_domain_classes / new_tls_classes accept lists of device classes, 'unclassified', '*' and [];
        anything else (unknown class, a string, a number) is refused.
        REQ: ANA-30"""
        for k in ("new_domain_classes", "new_tls_classes"):
            for good in (["iot", "camera"], ["*"], ["unclassified", "personal"], []):
                self.assertIsNone(cfg_validate("policy", self.pol(**{k: good})))
            for bad in (["toaster"], "iot", [1], {"iot": 1}):
                with self.subTest(key=k, value=bad):
                    self.bad("policy", self.pol(**{k: bad}))
        import server
        shown = server.cfg_with_defaults("policy", {"zones": {}})
        self.assertEqual(shown["new_tls_classes"], ["iot"])
        self.assertTrue(shown["_doc_new_domain_classes"])
        self.assertEqual(server.cfg_with_defaults("policy", {"new_tls_classes": ["*"]})["new_tls_classes"], ["*"])
        t = template("policy")
        self.assertEqual(t["new_domain_classes"], ["iot"])
        self.assertEqual(t["new_tls_classes"], ["iot"])

    def test_spike_threshold_values(self):
        """spike_thresholds rejects an unknown detection, a non-table row, bad severity, negative or text numbers and unknown columns.
        REQ: SET-45"""
        st = template("policy")["spike_thresholds"]
        row = st["fan_out"]
        cases = [{"made_up": row}, {"fan_out": 5}, {"fan_out": {**row, "severity": "urgent"}}, {"fan_out": {**row, "min": -1}},
                 {"fan_out": {**row, "min": "50"}}, {"fan_out": {**row, "mad_factor": False}}, {"fan_out": {**row, "colour": 1}}]
        for c in cases:
            with self.subTest(case=c):
                self.bad("policy", self.pol(spike_thresholds={**st, **c}))
        self.bad("policy", self.pol(spike_thresholds=[row]))
        self.assertIsNone(cfg_validate("policy", self.pol(spike_thresholds={**st, "_doc": "x", "fan_out": {**row, "_note": "y"}})))

    def test_beacon_values(self):
        """beacon rejects port numbers outside 1-65535 or of the wrong type, scores outside 0-1, counts below 1 and unknown keys.
        REQ: SET-46"""
        b = template("policy")["beacon"]
        cases = [("ignore_ports", [0]), ("ignore_ports", [65536]), ("ignore_ports", ["53"]), ("ignore_ports", [True]),
                 ("ignore_ports", 53), ("min_score", 1.5), ("min_score", "high"), ("min_coverage", -0.1),
                 ("unlabelled_min_score", True), ("min_conns", 0), ("min_intervals", "ten"), ("period", 60)]
        for k, v in cases:
            with self.subTest(key=k, value=v):
                self.bad("policy", self.pol(beacon={**b, k: v}))
        self.bad("policy", self.pol(beacon="strict"))
        self.assertIsNone(cfg_validate("policy", self.pol(beacon={**b, "ignore_ports": [1, 65535], "min_score": 0, "min_coverage": 1})))

    def test_allow_rules_need_src_and_dst(self):
        """An allow rule without src or dst, or that is not a table, is rejected.
        REQ: SET-46"""
        for rule in ({"src": "lan"}, {"dst": "servers"}, {"src": "", "dst": "servers"}, "lan->servers"):
            with self.subTest(rule=rule):
                self.bad("policy", self.pol(allow=[rule]))
        self.assertIsNone(cfg_validate("policy", self.pol(allow=[{"src": "*", "dst": "servers", "ports": [22]}])))

    def test_unknown_device_class_rejected(self):
        """A device class outside the documented list (iot, camera, media, game, personal, work, server, k8s, infra) is rejected.
        REQ: SET-47"""
        self.bad("policy", self.pol(device_classes={fixtures.mac(1): "toaster"}))

    def test_bad_sensitive_port_rejected(self):
        """A sensitive / discovery / gateway port that is not a number from 1 to 65535 is rejected.
        REQ: SET-47"""
        for k in ("sensitive_ports", "discovery_ports", "gateway_ports"):
            self.bad("policy", self.pol(**{k: [22, 70000]}))
            self.bad("policy", self.pol(**{k: ["ssh"]}))

    def test_scan_threshold_types_rejected(self):
        """scan_thresholds hosts/ports must be numbers: a text value would crash extras' scan comparison and the auto-tune.
        REQ: SET-47"""
        self.bad("policy", self.pol(scan_thresholds={"hosts": "many", "ports": 40}))

    def test_host_policy_regexes(self):
        """host_policy rejects an invalid regex in suspicious_cmdline, service_parents or service_child_suspicious.
        REQ: SET-48"""
        hp = template("host_policy")
        for k, v in (("suspicious_cmdline", ["ok", "(unclosed"]), ("service_parents", ["[bad"]), ("service_child_suspicious", "(sh|")):
            with self.subTest(key=k):
                self.bad("host_policy", {**hp, k: v})
                self.assertIn("invalid value", cfg_validate("host_policy", {**hp, k: v}))
        self.assertIsNone(cfg_validate("host_policy", {**hp, "suspicious_cmdline": [r"\bnc\b"]}))

    def test_site_values(self):
        """site rejects an internal_cidr that is not a CIDR and empty or non-list internal_prefixes.
        REQ: SET-48"""
        s = template("site")
        for k, v in (("internal_cidr", "10.0.0.0/40"), ("internal_cidr", "intranet"), ("internal_prefixes", []), ("internal_prefixes", "10.")):
            with self.subTest(key=k, value=v):
                self.bad("site", {**s, k: v})
        self.assertIsNone(cfg_validate("site", {**s, "internal_cidr": "192.0.2.0/24", "internal_prefixes": ["192.0.2."]}))

    def test_known_benign_shape(self):
        """known_benign rejects signatures or names that are not tables (including a missing one).
        REQ: SET-48"""
        kb = template("known_benign")
        self.bad("known_benign", {**kb, "signatures": ["GPL ICMP PING"]})
        self.bad("known_benign", {**kb, "names": "gateway"})
        self.bad("known_benign", {k: v for k, v in kb.items() if k != "names"})


# ---------------------------------------------------------------- /api/config/cfg handler
class CfgPostHandler(unittest.TestCase):
    """POST /api/config/cfg sets one value inside a settings document, with path and size guards."""

    def setUp(self):
        reset()
        seed_templates()

    def tearDown(self):
        reset()

    def test_valid_change_is_saved(self):
        """An admin setting a nested value saves it and leaves every other setting unchanged.
        REQ: SET-49"""
        before = store.cfg_load("policy")
        code, r = post("/api/config/cfg", {"doc": "policy", "path": ["beacon", "min_score"], "value": 0.9})
        self.assertEqual(code, 200, r)
        self.assertTrue(r["ok"])
        after = store.cfg_load("policy")
        self.assertEqual(after["beacon"]["min_score"], 0.9)
        after["beacon"]["min_score"] = before["beacon"]["min_score"]
        self.assertEqual(after, before)

    def test_list_index_set(self):
        """A list item is replaced by index; an index past the end is rejected and nothing is saved.
        REQ: SET-49"""
        code, _ = post("/api/config/cfg", {"doc": "policy", "path": ["sensitive_ports", 0], "value": 2222})
        self.assertEqual(code, 200)
        self.assertEqual(store.cfg_load("policy")["sensitive_ports"][0], 2222)
        n = len(store.cfg_load("policy")["sensitive_ports"])
        for idx in (n, -1):
            with self.subTest(idx=idx):
                before = store.cfg_load("policy")
                code, r = post("/api/config/cfg", {"doc": "policy", "path": ["sensitive_ports", idx], "value": 1})
                self.assertEqual((code, r["error"]), (400, "bad path"))
                self.assertEqual(store.cfg_load("policy"), before)

    def test_bad_requests_rejected(self):
        """Unknown doc, missing value, empty / non-list / over-6-deep path, a _ key and a missing section are all 400 with nothing saved.
        REQ: SET-50"""
        before = {d: store.cfg_load(d) for d in store.CFG_DOCS}
        cases = [({"doc": "integrations", "path": ["x"], "value": 1}, "doc, path and value required"),
                 ({"doc": "policy", "path": ["beacon", "min_score"]}, "doc, path and value required"),
                 ({"doc": "policy", "path": [], "value": 1}, "doc, path and value required"),
                 ({"doc": "policy", "path": "beacon/min_score", "value": 1}, "doc, path and value required"),
                 ({"doc": "policy", "path": ["a", "b", "c", "d", "e", "f", "g"], "value": 1}, "doc, path and value required"),
                 ({"doc": "policy", "path": ["_doc_beacon"], "value": "hacked"}, "bad path"),
                 ({"doc": "policy", "path": ["beacon", "_doc"], "value": "hacked"}, "bad path"),
                 ({"doc": "policy", "path": ["no_such", "key"], "value": 1}, "no such section"),
                 ({"doc": "policy", "path": ["sensitive_ports", 99, "x"], "value": 1}, "no such section")]
        for body, err in cases:
            with self.subTest(body=body):
                code, r = post("/api/config/cfg", body)
                self.assertEqual((code, r.get("error")), (400, err))
        self.assertEqual({d: store.cfg_load(d) for d in store.CFG_DOCS}, before)

    def test_invalid_value_not_saved(self):
        """A change the validator rejects (bad CIDR, unknown role, bad regex) returns 400 and leaves the document as it was.
        REQ: SET-50"""
        for doc, path, val in (("policy", ["zones", "lan"], "10.0.0.0/99"), ("policy", ["zone_roles", "lan"], "kitchen"),
                               ("host_policy", ["service_child_suspicious"], "(sh"), ("site", ["internal_prefixes"], [])):
            with self.subTest(doc=doc, path=path):
                before = store.cfg_load(doc)
                code, r = post("/api/config/cfg", {"doc": doc, "path": path, "value": val})
                self.assertEqual(code, 400, r)
                self.assertEqual(store.cfg_load(doc), before)

    def test_oversized_and_non_admin(self):
        """A request body over the 64 KB cap is refused before parsing (so the 400000 value cap is never reached) and a defender gets 403.
        REQ: SET-50"""
        before = store.cfg_load("known_benign")
        big = json.dumps({"doc": "known_benign", "path": ["names", "x"], "value": "a" * 70000}).encode()
        code, r = post("/api/config/cfg", None, raw=big)
        self.assertEqual(code, 413, r)
        code, r = post("/api/config/cfg", {"doc": "known_benign", "path": ["names", "x"], "value": "y"}, role="defender")
        self.assertEqual(code, 403)
        self.assertEqual(store.cfg_load("known_benign"), before)


# ---------------------------------------------------------------- auto-tune
def seed_noisy_history(days=15, devices=4):
    """Uploads alternate 1 MB / 60 MB per day on every device: the default upload_spike fires about every other day."""
    for d in range(days):
        devs = {f"10.0.1.{10 + i}": {"sent": 60 * MB if d % 2 else MB, "ext_peers": 10, "rejected": 0, "dns_q": 100} for i in range(devices)}
        store.history_append({"generated": "2026-10-%02dT05:00:00+00:00" % (d + 1), "hours": 24, "devices": devs})


def seed_snaps(scans=True, resolver_beacons=False, days=14):
    for d in range(days):
        cands = [{"src": f"10.0.1.{20 + i}", "dst": "192.0.2.53", "port": 53, "score": 0.9, "domain": ""} for i in range(3)] if resolver_beacons else []
        store.doc_put("data/2026-10-%02dT0500Z" % (d + 1), {"internal": {"scans": [{"src": "10.0.5.5", "hosts": 25, "ports": 5}] if scans else []},
                                                           "beacons": {"candidates": cands}})


class AutoTune(unittest.TestCase):
    """tuning.recommend proposes only; tuning.apply writes only accepted, still-current proposals."""

    def setUp(self):
        reset()
        seed_templates()

    def tearDown(self):
        reset()

    def recs(self):
        return {r["id"]: r for r in tuning.recommend()["recommendations"]}

    def test_recommend_saves_nothing(self):
        """recommend() on noisy history proposes changes but leaves every settings document and its version untouched.
        REQ: SET-51"""
        seed_noisy_history()
        seed_snaps()
        ver = {d: store._cfg_ver(store._dc(), d) for d in store.CFG_DOCS}
        before = {d: store.cfg_load(d) for d in store.CFG_DOCS}
        out = tuning.recommend()
        self.assertIn("Nothing is changed", out["note"])
        self.assertEqual((out["window_days"], out["snapshots"]), (14, 14))
        self.assertEqual({d: store._cfg_ver(store._dc(), d) for d in store.CFG_DOCS}, ver)
        store._cfg_cache.clear()
        self.assertEqual({d: store.cfg_load(d) for d in store.CFG_DOCS}, before)

    def test_noisy_detections_get_less_sensitive(self):
        """Noisy upload and chronic scan findings get raised thresholds; quiet detections are left at status ok.
        REQ: SET-51"""
        seed_noisy_history()
        seed_snaps()
        r = self.recs()
        up = r["upload_spike"]
        self.assertEqual(up["status"], "change")
        self.assertEqual(up["target"], {"section": "upload_spike"})
        self.assertGreater(up["changes"]["min_mb"], up["current"]["min_mb"])
        self.assertLessEqual(up["events_after"] / 14, tuning.BUDGET["upload_spike"])
        self.assertEqual(r["scan_thresholds"]["status"], "change")
        self.assertEqual(r["scan_thresholds"]["changes"], {"hosts": 32})  # 25 * 1.25 + 1 rounded; ports already above the level
        for rid in ("fan_out", "failed_conns", "dns_volume", "beacon"):
            self.assertEqual(r[rid]["status"], "ok", rid)
            self.assertNotIn("changes", r[rid])
        for x in r.values():  # severity and min_days are never proposed
            self.assertFalse({"severity", "min_days"} & set(x.get("changes") or {}))

    def test_switched_off_and_resolver_beacons(self):
        """A detection with severity off is reported as off; chronic unnamed port-53 beacon pairs propose ignoring port 53.
        REQ: SET-51"""
        pol = store.cfg_load("policy")
        pol["upload_spike"]["severity"] = "off"
        store.cfg_save("policy", pol)
        seed_noisy_history()
        seed_snaps(scans=False, resolver_beacons=True)
        r = self.recs()
        self.assertEqual(r["upload_spike"]["status"], "off")
        self.assertEqual(r["scan_thresholds"]["status"], "ok")
        self.assertEqual(r["beacon"]["status"], "change")
        self.assertIn(53, r["beacon"]["changes"]["ignore_ports"])
        self.assertTrue(set(pol["beacon"]["ignore_ports"]) <= set(r["beacon"]["changes"]["ignore_ports"]))

    def test_apply_writes_only_accepted_current_values(self):
        """apply() sets just the accepted recommendation's proposed values (not tampered ones), skips unknown / unchanged ids, and does not save.
        REQ: SET-52"""
        seed_noisy_history()
        seed_snaps()
        rec = self.recs()["upload_spike"]
        before = store.cfg_load("policy")
        done, pol = tuning.apply([{"id": "upload_spike", "changes": {"min_mb": 1, "severity": "off"}},
                                  {"id": "fan_out"}, {"id": "made_up"}, {}])
        self.assertEqual(done, ["upload_spike"])
        self.assertEqual(store.cfg_load("policy"), before)  # apply returns the policy; the caller validates and saves
        exp = copy.deepcopy(before)
        exp["upload_spike"].update(rec["changes"])
        self.assertEqual(pol, exp)
        self.assertEqual(pol["upload_spike"]["severity"], before["upload_spike"]["severity"])
        self.assertIsNone(cfg_validate("policy", pol))
        self.assertEqual(tuning.apply(None), ([], before))

    def test_tune_apply_endpoint(self):
        """POST /api/config/tune-apply saves the accepted change and only it; nothing accepted gives 409 and no write.
        REQ: SET-52"""
        seed_noisy_history()
        seed_snaps()
        before = store.cfg_load("policy")
        code, r = post("/api/config/tune-apply", {"accept": [{"id": "made_up"}]})
        self.assertEqual(code, 409)
        self.assertEqual(store.cfg_load("policy"), before)
        code, r = post("/api/config/tune-apply", {"accept": [{"id": "scan_thresholds"}]})
        self.assertEqual((code, r["applied"]), (200, ["scan_thresholds"]))
        after = store.cfg_load("policy")
        self.assertEqual(after["scan_thresholds"], {"hosts": 32, "ports": before["scan_thresholds"]["ports"]})
        after["scan_thresholds"] = before["scan_thresholds"]
        self.assertEqual(after, before)


# ---------------------------------------------------------------- UniFi discover
NETS = [
    {"purpose": "corporate", "name": "Home", "ip_subnet": "10.10.0.1/24", "vlan": 10},
    {"purpose": "corporate", "name": "Server VLAN", "ip_subnet": "10.20.0.1/24", "vlan": 20},
    {"purpose": "guest", "name": "Friends", "ip_subnet": "10.30.0.1/24", "vlan": 30},
    {"purpose": "corporate", "name": "DMZ", "ip_subnet": "10.40.0.1/24", "vlan": 40},
    {"purpose": "corporate", "name": "IPMI", "ip_subnet": "10.50.0.1/24", "vlan": 50},
    {"purpose": "corporate", "name": "Smart home", "ip_subnet": "10.60.0.1/24", "vlan": 60},
    {"purpose": "corporate", "name": "Plain", "ip_subnet": "10.70.0.1/24", "vlan": 70},
    {"purpose": "corporate", "name": "Plain", "ip_subnet": "10.71.0.1/24", "vlan": 71},
    {"purpose": "wan", "name": "Internet", "ip_subnet": "192.0.2.1/24"},
    {"purpose": "corporate", "name": "Old", "ip_subnet": "10.80.0.1/24", "enabled": False},
    {"purpose": "corporate", "name": "No subnet"},
    {"purpose": "corporate", "name": "Broken", "ip_subnet": "nonsense"},
]
CAT = {1: "IP Camera", 2: "Smartphone", 3: "Server", 4: "Smart Plug"}


def unifi_stub(nets=NETS, users=None, sta=None, devices=None, cats=CAT):
    users = users if users is not None else [
        {"mac": fixtures.mac(1).upper(), "last_ip": "10.10.0.21", "dev_cat": 1, "name": "porch"},
        {"mac": fixtures.mac(2), "last_ip": "10.10.0.22", "dev_cat": 2},
        {"mac": fixtures.mac(3), "fixed_ip": "10.70.0.5", "dev_cat": 3},
        {"mac": fixtures.mac(4), "last_ip": "10.70.0.6", "hostname": "k8s-node-1"},
        {"mac": fixtures.mac(5), "last_ip": "10.60.0.7", "dev_cat": 4},
        {"mac": fixtures.mac(6), "last_ip": "10.20.0.8"},
        {"mac": fixtures.mac(7), "last_ip": "10.10.0.30"},  # no fingerprint, user zone -> no class
    ]
    sta = sta if sta is not None else [{"mac": fixtures.mac(2).replace(":", "-"), "ip": "10.10.0.23"}]
    devices = devices if devices is not None else [{"mac": fixtures.mac(9), "type": "usw", "name": "core switch", "ip": "10.50.0.2"}]
    raw = {"rest/networkconf": nets, "rest/user": users, "stat/sta": sta, "stat/device": devices}

    def legacy(ep):
        return copy.deepcopy(raw[ep])

    def req(url, body=None, timeout=40):
        if "fingerprint" not in url:
            raise AssertionError("unexpected UniFi call " + url)
        return {"dev_type_ids": {str(k): v for k, v in cats.items()}}

    return legacy, req


@contextlib.contextmanager
def stubbed_unifi(**kw):
    legacy, req = unifi_stub(**kw)
    with mock.patch.object(discover.unifi, "_legacy_raw", legacy), mock.patch.object(discover.unifi, "_req", req), \
            mock.patch.object(discover.unifi, "base", lambda: "https://unifi.invalid"):
        yield


class UnifiDiscover(unittest.TestCase):
    """discover.build proposes zones/roles/classes from (stubbed) UniFi; discover.apply merges or overwrites."""

    def setUp(self):
        reset()

    def tearDown(self):
        reset()

    def build(self, pol=None, **kw):
        with stubbed_unifi(**kw):
            return discover.build(pol if pol is not None else {})

    def test_one_zone_per_subnet(self):
        """Every enabled corporate/guest network with a valid subnet becomes one zone (network CIDR); wan, disabled and broken ones are skipped.
        REQ: SET-53"""
        p = self.build()
        self.assertEqual(p["zones"], {"home": "10.10.0.0/24", "server-vlan": "10.20.0.0/24", "friends": "10.30.0.0/24",
                                      "dmz": "10.40.0.0/24", "ipmi": "10.50.0.0/24", "smart-home": "10.60.0.0/24",
                                      "plain": "10.70.0.0/24", "plain-2": "10.71.0.0/24"})
        self.assertEqual(p["site_prefixes"], ["10.10.", "10.20.", "10.30.", "10.40.", "10.50.", "10.60.", "10.70.", "10.71."])
        self.assertEqual({d["zone"] for d in p["detail"]["zones"]}, set(p["zones"]))
        self.assertIsNone(cfg_validate("policy", {"zones": p["zones"], "zone_roles": p["zone_roles"]}))

    def test_roles_from_name_guest_and_members(self):
        """Roles come from the guest flag (iot) and the name (dmz, mgmt, protected, iot); otherwise mostly-server members make it protected, else user.
        REQ: SET-53"""
        r = self.build()["zone_roles"]
        self.assertEqual(r, {"home": "user", "server-vlan": "protected", "friends": "iot", "dmz": "dmz", "ipmi": "mgmt",
                             "smart-home": "iot", "plain": "protected", "plain-2": "user"})
        self.assertTrue(set(r.values()) <= set(discover.ROLES))

    def test_existing_zone_name_kept_and_classes(self):
        """A subnet that already has a zone keeps its name; gear is infra, fingerprints and hostnames give classes, MACs are normalised.
        REQ: SET-53"""
        p = self.build({"zones": {"house": "10.10.0.0/24"}})
        self.assertEqual(p["zones"]["house"], "10.10.0.0/24")
        self.assertNotIn("home", p["zones"])
        self.assertTrue(next(z for z in p["detail"]["zones"] if z["zone"] == "house")["existing"])
        c = p["device_classes"]
        self.assertEqual(c, {fixtures.mac(9): "infra", fixtures.mac(1): "camera", fixtures.mac(2): "personal", fixtures.mac(3): "server",
                             fixtures.mac(4): "k8s", fixtures.mac(5): "iot", fixtures.mac(6): "server"})
        dev2 = next(d for d in p["detail"]["devices"] if d["key"] == fixtures.mac(2))
        self.assertEqual(dev2["ip"], "10.10.0.23")  # online stat/sta wins over rest/user
        self.assertTrue(all(v in ("iot", "camera", "media", "game", "personal", "work", "server", "k8s", "infra") for v in c.values()))

    def test_build_writes_nothing(self):
        """build() is a proposal only: the policy and site documents are not changed.
        REQ: SET-53"""
        store.cfg_save("policy", {"zones": {"house": "10.10.0.0/24"}})
        before = store.cfg_load("policy")
        with stubbed_unifi():
            discover.build()
        self.assertEqual(store.cfg_load("policy"), before)
        self.assertFalse(store.cfg_has("site"))

    def test_apply_merge_keeps_existing(self):
        """apply() without overwrite adds new zones, roles and classes but keeps every existing name, role and class.
        REQ: SET-54"""
        pol = {"zones": {"house": "10.10.0.0/24", "dmz": "10.99.0.0/24"}, "zone_roles": {"house": "protected", "dmz": "dmz"},
               "device_classes": {fixtures.mac(1): "media", "10.10.0.23": "work"}, "sensitive_ports": [22]}
        store.cfg_save("policy", pol)
        store.cfg_save("site", {"internal_prefixes": ["10."]})
        p = self.build(copy.deepcopy(pol))
        n = discover.apply(p)
        out = store.cfg_load("policy")
        self.assertEqual(out["zone_roles"]["house"], "protected")
        self.assertEqual(out["zones"]["dmz"], "10.99.0.0/24")  # proposal's dmz (other subnet) does not replace it
        self.assertNotIn("home", out["zones"])
        self.assertEqual(out["device_classes"][fixtures.mac(1)], "media")
        self.assertEqual(out["device_classes"]["10.10.0.23"], "work")
        self.assertNotIn(fixtures.mac(2), out["device_classes"])  # already classified by IP
        self.assertEqual(out["zones"]["server-vlan"], "10.20.0.0/24")
        self.assertEqual(out["zone_roles"]["server-vlan"], "protected")
        self.assertEqual(out["sensitive_ports"], [22])
        for k, v in pol["zones"].items():
            self.assertEqual(out["zones"][k], v)
        self.assertEqual(n["changed"], 0)
        self.assertEqual(n["zones"], 6)  # 8 discovered, house exists by subnet, dmz name taken
        self.assertEqual(store.cfg_load("site")["internal_prefixes"], ["10."])  # all 10.x subnets already covered
        self.assertIsNone(cfg_validate("policy", out))

    def test_apply_overwrite_replaces_but_never_removes(self):
        """apply(overwrite=True) replaces existing roles and classes with the proposal but removes nothing.
        REQ: SET-54"""
        pol = {"zones": {"house": "10.10.0.0/24", "extra": "10.200.0.0/24"}, "zone_roles": {"house": "protected", "extra": "mgmt"},
               "device_classes": {fixtures.mac(1): "media", "10.10.0.23": "work", fixtures.mac(50): "game"}}
        store.cfg_save("policy", pol)
        p = self.build(copy.deepcopy(pol))
        n = discover.apply(p, overwrite=True)
        out = store.cfg_load("policy")
        self.assertEqual(out["zone_roles"]["house"], "user")
        self.assertEqual(out["device_classes"][fixtures.mac(1)], "camera")
        self.assertEqual(out["device_classes"]["10.10.0.23"], "personal")
        self.assertEqual(out["zones"]["extra"], "10.200.0.0/24")
        self.assertEqual(out["zone_roles"]["extra"], "mgmt")
        self.assertEqual(out["device_classes"][fixtures.mac(50)], "game")
        self.assertEqual(n["changed"], 2)

    def test_apply_site_prefixes(self):
        """apply() replaces an untouched default '10.' prefix with the real non-10 prefixes and appends new prefixes otherwise.
        REQ: SET-55"""
        nets = [{"purpose": "corporate", "name": "Doc net", "ip_subnet": "192.0.2.1/24"}]
        store.cfg_save("site", {"internal_prefixes": ["10."]})
        with stubbed_unifi(nets=nets, users=[], sta=[], devices=[]):
            n = discover.apply(discover.build({}))
        self.assertEqual(store.cfg_load("site")["internal_prefixes"], ["192.0."])
        self.assertEqual(n["prefixes"], 1)
        store.cfg_save("site", {"internal_prefixes": ["10.", "172.16."]})
        with stubbed_unifi(nets=nets, users=[], sta=[], devices=[]):
            discover.apply(discover.build({}))
        self.assertEqual(store.cfg_load("site")["internal_prefixes"], ["10.", "172.16.", "192.0."])

    def test_discover_endpoint_preview_and_apply(self):
        """POST /api/config/discover returns the proposal without writing; with apply=true it merges and reports counts.
        REQ: SET-55"""
        store.cfg_save("policy", {"zones": {}})
        with stubbed_unifi():
            code, r = post("/api/config/discover", {})
            self.assertEqual(code, 200)
            self.assertIn("zones", r)
            self.assertEqual(store.cfg_load("policy"), {"zones": {}})
            code, r = post("/api/config/discover", {"apply": True})
        self.assertEqual(code, 200)
        self.assertEqual(r["applied"]["zones"], 8)
        self.assertEqual(len(store.cfg_load("policy")["zones"]), 8)


if __name__ == "__main__":
    unittest.main()
