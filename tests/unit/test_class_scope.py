"""Device-class scope of the upload_spike / scan_thresholds / beacon rules (policy classes + by_class): config merge,
the collectors (extras.internal_traffic / extras.beacons) and analyze's upload check, validation, class rename/remove,
and auto-tune per class (tuning.py)."""
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); import _env  # noqa: E401,E702,E402

import copy  # noqa: E402
import json  # noqa: E402
import unittest  # noqa: E402
from datetime import datetime, timezone  # noqa: E402
from unittest import mock  # noqa: E402

import analyze  # noqa: E402
import classdefs  # noqa: E402
import extras  # noqa: E402
import server  # noqa: E402
import site_cfg  # noqa: E402
import store  # noqa: E402
import tuning  # noqa: E402
from server import cfg_validate  # noqa: E402
from fixtures import mac  # noqa: E402

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
MB = 1024 * 1024
SRV, IOT, NONE = "10.0.7.10", "10.0.7.20", "10.0.7.30"  # a server, an iot device, an unclassified device
SRVS = [SRV, "10.0.7.11", "10.0.7.12", "10.0.7.13"]  # four servers: enough upload noise to exceed the auto-tune budget


def reset():
    _env.fresh_db()
    store._cfg_cache.clear()
    site_cfg._cache = None


def policy(**sections):
    with open(os.path.join(REPO, "policy.example.json")) as f:
        pol = json.load(f)
    pol["device_classes"] = {**{ip: "server" for ip in SRVS}, IOT: "iot"}
    pol.update(sections)
    store.cfg_save("policy", pol)
    return pol


class Base(unittest.TestCase):
    def setUp(self):
        reset()
        p = mock.patch.object(extras, "load_policy", lambda: store.cfg_load("policy"))
        p.start()
        self.addCleanup(p.stop)

    def tearDown(self):
        reset()


class ConfigMerge(Base):
    def test_no_scope_is_unchanged(self):
        """Without classes / by_class every device gets the section's numbers and the rule applies to every class.
        REQ: CLS-06"""
        pol = policy()
        base = extras.upload_cfg(pol=pol)
        for cls in ("server", "iot", "unclassified", None):
            u = extras.upload_cfg(cls or "unclassified", pol)
            self.assertTrue(u.pop("applies"))
            self.assertEqual(u, base)
        self.assertNotIn("applies", extras.beacon_cfg(pol))
        self.assertEqual(extras.scan_cfg(pol), {"hosts": 20, "ports": 40})

    def test_class_filter_and_overrides(self):
        """classes limits the rule to the ticked classes; by_class overrides only the given numbers of that class;
        'unclassified' covers devices with no class; '*' = every device; ignore_ports is never per class.
        REQ: CLS-06"""
        pol = policy(upload_spike={"min_mb": 25, "classes": ["server", "unclassified"], "by_class": {"server": {"min_mb": 5000, "severity": "medium"}}},
                     scan_thresholds={"hosts": 20, "ports": 40, "classes": ["*"], "by_class": {"iot": {"hosts": 60}}},
                     beacon={"min_score": 0.75, "by_class": {"server": {"min_score": 0.95, "ignore_ports": [1]}}})
        s, i, n = (extras.upload_cfg(c, pol) for c in ("server", "iot", "unclassified"))
        self.assertEqual((s["applies"], s["min_mb"], s["severity"], s["times_normal"]), (True, 5000, "medium", 3))
        self.assertFalse(i["applies"])
        self.assertEqual((n["applies"], n["min_mb"]), (True, 25))
        self.assertEqual(extras.scan_cfg(pol, "iot"), {"hosts": 60, "ports": 40, "applies": True})
        self.assertEqual(extras.scan_cfg(pol, "server")["hosts"], 20)
        b = extras.beacon_cfg(pol, "server")
        self.assertEqual((b["min_score"], b["ignore_ports"]), (0.95, [3478, 19302]))
        self.assertEqual(extras.scoped_classes(pol, "beacon"), ["server"])


def _fake_es(scans=(), pairs=()):
    """q / ds / buckets stand-ins: one aggregation answer for internal_traffic, pair + hits answers for beacons."""
    t0 = datetime(2026, 11, 1, tzinfo=timezone.utc).timestamp()

    def q(_idx, body):
        aggs = body.get("aggs") or {}
        if "scan" in aggs:
            return {"aggregations": {"p": {"buckets": []}, "scan": {"s": {"buckets": [
                {"key": ip, "doc_count": 100, "hosts": {"value": h}, "ports": {"value": p}, "top": {"buckets": []}} for ip, h, p in scans]}}}}
        if "p" in aggs:
            md = aggs["p"]["multi_terms"]["min_doc_count"]
            return {"aggregations": {"p": {"buckets": [{"key": [src, "198.51.100.9", 443], "doc_count": n} for src, n in pairs if n >= md]}}}
        if body.get("size") == 5000:  # one connection every 10 minutes for a day: a perfect beacon (score 1)
            return {"hits": {"hits": [{"_source": {"@timestamp": datetime.fromtimestamp(t0 + k * 600, timezone.utc).isoformat(),
                                                   "client": {"ip_bytes": 300}}} for k in range(144)]}}
        return {"aggregations": {"d": {"buckets": []}}}
    return q, (lambda name: {"term": {"ds": name}}), (lambda a: a.get("buckets", []))


class Collectors(Base):
    def run_scan(self, scans):
        with mock.patch.object(extras, "_ctx", lambda: _fake_es(scans=scans)), mock.patch.object(extras, "rng", lambda *a, **k: {}):
            return {s["src"] for s in extras.internal_traffic(24)["scans"]}

    def test_scan_per_class(self):
        """internal_traffic reports a scanner by its own class's numbers and only for the classes the rule runs for.
        REQ: CLS-07"""
        rows = [(SRV, 30, 1), (IOT, 30, 1), (NONE, 30, 1)]
        policy(scan_thresholds={"hosts": 20, "ports": 40})
        self.assertEqual(self.run_scan(rows), {SRV, IOT, NONE})
        policy(scan_thresholds={"hosts": 20, "ports": 40, "by_class": {"iot": {"hosts": 50}}})
        self.assertEqual(self.run_scan(rows), {SRV, NONE})
        policy(scan_thresholds={"hosts": 20, "ports": 40, "classes": ["server"]})
        self.assertEqual(self.run_scan(rows), {SRV})

    def test_scan_class_from_registry_mac(self):
        """A device classed by MAC is found through the device registry (the collector only sees IPs).
        REQ: CLS-07"""
        mac_ = mac(0x31)
        pol = policy(scan_thresholds={"hosts": 20, "ports": 40, "classes": ["camera"]})
        pol["device_classes"][mac_] = "camera"
        store.cfg_save("policy", pol)
        store.registry_save({mac_: {"mac": mac_, "ips": [NONE]}})
        self.assertEqual(self.run_scan([(NONE, 30, 1), (SRV, 30, 1)]), {NONE})

    def test_beacon_per_class(self):
        """beacons() queries loosely enough for the loosest class, then applies each source's class: filter, min_conns
        and min_score overrides.
        REQ: CLS-07"""
        def run(pairs):
            with mock.patch.object(extras, "_ctx", lambda: _fake_es(pairs=pairs)), mock.patch.object(extras, "rng", lambda *a, **k: {}):
                return {c["src"] for c in extras.beacons(24)["candidates"]}
        pairs = [(SRV, 144), (IOT, 144), (NONE, 144)]
        policy(beacon={"min_conns": 36})
        self.assertEqual(run(pairs), {SRV, IOT, NONE})
        policy(beacon={"min_conns": 36, "classes": ["iot", "server"], "by_class": {"server": {"min_conns": 500}}})
        self.assertEqual(run(pairs), {IOT})
        policy(beacon={"min_conns": 500, "by_class": {"iot": {"min_conns": 100}}})  # ES pre-filter follows the loosest class
        self.assertEqual(run(pairs), {IOT})

    def test_upload_per_class(self):
        """analyze's upload-spike check takes the device's class settings (MAC or IP key) and skips classes the rule
        does not run for.
        REQ: CLS-07"""
        pol = policy(upload_spike={"min_mb": 25, "classes": ["server", "iot"], "by_class": {"server": {"min_mb": 9000}}})
        cache = {}
        self.assertEqual(analyze.upload_cfg_for(pol, SRV, {"ip": SRV}, cache)["min_mb"], 9000)
        self.assertEqual(analyze.upload_cfg_for(pol, IOT, {"ip": IOT}, cache)["min_mb"], 25)
        self.assertFalse(analyze.upload_cfg_for(pol, NONE, {"ip": NONE}, cache)["applies"])
        pol["device_classes"][mac(0x32)] = "server"
        self.assertEqual(analyze.upload_cfg_for(pol, mac(0x32), {"ip": "10.0.7.99"}, {})["min_mb"], 9000)


class Validation(Base):
    def test_validate_scope(self):
        """classes must be defined classes (or unclassified / *); by_class rows need a known class, at least one
        allowed setting and valid values; ignore_ports cannot be set per class; the Settings page gets empty defaults.
        REQ: CLS-08"""
        pol = policy()
        ok = copy.deepcopy(pol)
        ok["upload_spike"].update(classes=["server", "unclassified"], by_class={"server": {"min_mb": 100, "severity": "low"}})
        ok["scan_thresholds"].update(classes=["*"], by_class={"iot": {"hosts": 60}})
        ok["beacon"].update(classes=[], by_class={"iot": {"min_score": 0.9}})
        self.assertIsNone(cfg_validate("policy", ok))
        for sec, patch in (("upload_spike", {"classes": ["nope"]}), ("upload_spike", {"classes": "server"}),
                           ("upload_spike", {"by_class": {"nope": {"min_mb": 1}}}), ("upload_spike", {"by_class": {"server": {}}}),
                           ("upload_spike", {"by_class": {"server": {"severity": "loud"}}}), ("scan_thresholds", {"by_class": {"iot": {"hosts": 0}}}),
                           ("beacon", {"by_class": {"iot": {"ignore_ports": [1]}}}), ("beacon", {"by_class": {"iot": {"min_score": 2}}}),
                           ("beacon", {"by_class": []})):
            bad = copy.deepcopy(pol)
            bad[sec].update(patch)
            self.assertTrue(cfg_validate("policy", bad), (sec, patch))
        shown = server.cfg_with_defaults("policy", pol)
        for sec in extras.SCOPED:
            self.assertEqual((shown[sec]["classes"], shown[sec]["by_class"]), ([], {}))
            self.assertIn("Device classes:", shown["_doc_" + sec])

    def test_rename_and_remove_follow(self):
        """Renaming a class renames it in classes / by_class; removing it moves the filter to the class its devices
        moved to (never widening a narrowed rule to every device) and drops its overrides.
        REQ: CLS-08"""
        pol = policy(upload_spike={"min_mb": 25, "classes": ["server"], "by_class": {"server": {"min_mb": 9000}}})
        pol = classdefs.rename(pol, "server", "servers")
        self.assertEqual((pol["upload_spike"]["classes"], list(pol["upload_spike"]["by_class"])), (["servers"], ["servers"]))
        out = classdefs.remove(copy.deepcopy(pol), "servers", move_to="")
        self.assertEqual(out["upload_spike"]["classes"], ["unclassified"])
        self.assertEqual(out["upload_spike"]["by_class"], {"unclassified": {"min_mb": 9000}})
        out = classdefs.remove(copy.deepcopy(pol), "servers", move_to="work")
        self.assertEqual(out["upload_spike"]["classes"], ["work"])
        self.assertIsNone(cfg_validate("policy", out))


def seed(upload_noisy=(), scans=()):
    for d in range(15):
        devs = {ip: {"ip": ip, "sent": (60 * MB if d % 2 else MB) if ip in upload_noisy else MB, "ext_peers": 10, "rejected": 0, "dns_q": 100}
                for ip in (*SRVS, IOT, NONE)}
        store.history_append({"generated": "2026-10-%02dT05:00:00+00:00" % (d + 1), "hours": 24, "devices": devs})
    for d in range(14):
        store.doc_put("data/2026-10-%02dT0500Z" % (d + 1), {"internal": {"scans": [{"src": s, "hosts": 25, "ports": 5} for s in scans]},
                                                           "beacons": {"candidates": []}})


class AutoTuneScope(Base):
    def recs(self):
        return {r["id"]: r for r in tuning.recommend()["recommendations"]}

    def test_proposal_per_override_class(self):
        """Each by_class override gets its own proposal (id section@class) judged on that class's devices only; the
        section's proposal uses the other devices the rule runs for; apply writes by_class[class] only.
        REQ: CLS-09"""
        policy(upload_spike={"min_mb": 25, "times_normal": 3, "mad_factor": 6, "min_days": 3, "severity": "high", "by_class": {"server": {"times_normal": 3}}})
        seed(upload_noisy=SRVS)
        r = self.recs()
        self.assertEqual(r["upload_spike@server"]["status"], "change")
        self.assertEqual(r["upload_spike@server"]["target"], {"section": "upload_spike", "class": "server"})
        self.assertEqual(r["upload_spike"]["status"], "ok")  # the noise is only on the server
        before = store.cfg_load("policy")
        done, pol = tuning.apply([{"id": "upload_spike@server"}])
        self.assertEqual(done, ["upload_spike@server"])
        self.assertEqual({k: v for k, v in pol["upload_spike"].items() if k != "by_class"}, {k: v for k, v in before["upload_spike"].items() if k != "by_class"})
        self.assertEqual(pol["upload_spike"]["by_class"]["server"], {"times_normal": 3, **r["upload_spike@server"]["changes"]})
        self.assertIsNone(cfg_validate("policy", pol))

    def test_class_filter_excludes_devices(self):
        """Devices of classes the rule does not run for are left out of the replay (no proposal from their noise).
        REQ: CLS-09"""
        policy(upload_spike={"min_mb": 25, "times_normal": 3, "mad_factor": 6, "min_days": 3, "severity": "high", "classes": ["iot"]})
        seed(upload_noisy=SRVS)
        self.assertEqual(self.recs()["upload_spike"]["status"], "ok")
        policy(upload_spike={"min_mb": 25, "times_normal": 3, "mad_factor": 6, "min_days": 3, "severity": "high", "classes": ["server"]})
        self.assertEqual(self.recs()["upload_spike"]["status"], "change")

    def test_class_only_alternative(self):
        """When one class causes a section-wide change, a narrower 'class only (new override)' proposal is offered as
        well, written to by_class; it is optional (not pre-selected on the page).
        REQ: CLS-09"""
        policy(scan_thresholds={"hosts": 20, "ports": 40})
        seed(scans=(IOT,))
        r = self.recs()
        self.assertEqual(r["scan_thresholds"]["status"], "change")
        alt = r["scan_thresholds@iot"]
        self.assertIn("(new override)", alt["title"])
        self.assertEqual(alt["changes"], {"hosts": 32})
        done, pol = tuning.apply([{"id": "scan_thresholds@iot"}])
        self.assertEqual(pol["scan_thresholds"]["by_class"], {"iot": {"hosts": 32}})
        self.assertEqual(pol["scan_thresholds"]["hosts"], 20)
        self.assertIsNone(cfg_validate("policy", pol))


if __name__ == "__main__":
    unittest.main()
