"""volume-spike thresholds in the policy (Settings > Network policy > volume_spike): defaults equal the former hardcoded
numbers, a global change and a per-class override take effect in analyze's check, the class filter, validation, the
Settings page default, the event-card tuning info, the per-class alarm switch and auto-tune."""
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); import _env  # noqa: E401,E702,E402

import copy  # noqa: E402
import json  # noqa: E402
import unittest  # noqa: E402
from unittest import mock  # noqa: E402

import analyze  # noqa: E402
import classdefs  # noqa: E402
import extras  # noqa: E402
import server  # noqa: E402
import site_cfg  # noqa: E402
import store  # noqa: E402
import tuning  # noqa: E402
from fixtures import mac  # noqa: E402
from server import cfg_validate  # noqa: E402

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
MB = analyze.MB
SRV, IOT, NONE = "10.0.8.10", "10.0.8.20", "10.0.8.30"  # a server, an iot device, an unclassified device
SRVS = [SRV, "10.0.8.11", "10.0.8.12", "10.0.8.13"]
OLD = {"min_mb": 50, "times_normal": 3, "mad_factor": 6, "min_days": 3, "severity": "medium"}  # the former hardcoded check


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


def past(*mb):
    return [{"total": v * MB} for v in mb]


def old_check(today, hist):
    """The check exactly as analyze.py had it before: spike(total, history, 50 MB) with the default 3x / 6 MAD / MIN_DAYS."""
    return analyze.spike(today, hist, 50 * MB)


class Base(unittest.TestCase):
    def setUp(self):
        reset()
        p = mock.patch.object(extras, "load_policy", lambda: store.cfg_load("policy"))
        p.start()
        self.addCleanup(p.stop)
        analyze.SCALE = 1.0

    def tearDown(self):
        reset()


class Defaults(Base):
    def test_defaults_equal_old_hardcoded(self):
        """The volume_spike defaults (code, policy.example.json, Settings page for an install without the section) are
        the former hardcoded numbers, and the check gives the same answer as the old one on a grid of cases.
        REQ: VOL-01"""
        self.assertEqual(extras.VOLUME_SPIKE, OLD)
        with open(os.path.join(REPO, "policy.example.json")) as f:
            self.assertEqual(json.load(f)["volume_spike"], OLD)
        pol = policy()
        pol.pop("volume_spike")
        self.assertEqual({k: v for k, v in extras.volume_cfg(pol=pol).items()}, OLD)
        shown = server.cfg_with_defaults("policy", pol)
        self.assertEqual({k: v for k, v in shown["volume_spike"].items() if k not in extras.SCOPE_KEYS}, OLD)
        self.assertEqual((shown["volume_spike"]["classes"], shown["volume_spike"]["by_class"]), ([], {}))
        self.assertIn("volume-spike", shown["_doc_volume_spike"])
        for p in (pol, policy()):  # no section / the template section
            for hist in ([10, 12, 11], [10, 12], [100, 100, 100], [10, 80, 10, 80], [1, 1, 1, 1, 1]):
                for today in (20, 49, 51, 120, 301, 1000):
                    t, h = {"ip": SRV, "total": today * MB}, past(*hist)
                    got = analyze.volume_finding(p, SRV, t, h)
                    want = old_check(t["total"], [x["total"] for x in h])
                    self.assertEqual(bool(got), want, (hist, today))
                    if got:
                        self.assertEqual(got[0], "medium")
                        self.assertEqual(got[1], f"total {today:.0f} MB vs normal {analyze.med(hist):.0f} MB")


class Thresholds(Base):
    def test_global_change_takes_effect(self):
        """A global volume_spike change applies to every device: min_mb, times_normal, mad_factor, min_days and
        severity (off silences the finding).
        REQ: VOL-02"""
        t, h = {"ip": IOT, "total": 120 * MB}, past(10, 12, 11)
        self.assertEqual(analyze.volume_finding(policy(), IOT, t, h)[0], "medium")
        self.assertIsNone(analyze.volume_finding(policy(volume_spike={**OLD, "min_mb": 200}), IOT, t, h))
        self.assertIsNone(analyze.volume_finding(policy(volume_spike={**OLD, "times_normal": 20}), IOT, t, h))
        self.assertIsNone(analyze.volume_finding(policy(volume_spike={**OLD, "min_days": 5}), IOT, t, h))
        self.assertIsNone(analyze.volume_finding(policy(volume_spike={**OLD, "severity": "off"}), IOT, t, h))
        self.assertEqual(analyze.volume_finding(policy(volume_spike={**OLD, "severity": "high"}), IOT, t, h)[0], "high")
        small = {"ip": IOT, "total": 30 * MB}
        low = past(5, 6, 5)
        self.assertIsNone(analyze.volume_finding(policy(), IOT, small, low))
        self.assertIsNotNone(analyze.volume_finding(policy(volume_spike={**OLD, "min_mb": 20}), IOT, small, low))
        uneven = past(10, 40, 10, 40, 10, 40)  # median 25, MAD 15: 120 MB passes 3x (75) and normal + 6 MAD (115), not + 7 MAD (130)
        self.assertIsNotNone(analyze.volume_finding(policy(), IOT, t, uneven))
        self.assertIsNone(analyze.volume_finding(policy(volume_spike={**OLD, "mad_factor": 7}), IOT, t, uneven))

    def test_per_class_override(self):
        """by_class gives one class its own numbers (MAC or IP key); other classes keep the section's values.
        REQ: VOL-03"""
        pol = policy(volume_spike={**OLD, "by_class": {"server": {"min_mb": 5000, "severity": "low"}, "iot": {"severity": "high"}}})
        t, h = {"total": 600 * MB}, past(10, 12, 11)
        self.assertIsNone(analyze.volume_finding(pol, SRV, {**t, "ip": SRV}, h))
        self.assertEqual(analyze.volume_finding(pol, SRV, {"ip": SRV, "total": 6000 * MB}, h)[0], "low")
        self.assertEqual(analyze.volume_finding(pol, IOT, {**t, "ip": IOT}, h)[0], "high")
        self.assertEqual(analyze.volume_finding(pol, NONE, {**t, "ip": NONE}, h)[0], "medium")
        pol["device_classes"][mac(0x42)] = "server"
        self.assertIsNone(analyze.volume_finding(pol, mac(0x42), {**t, "ip": "10.0.8.99"}, h))

    def test_class_limit(self):
        """classes limits the rule to the ticked classes ('unclassified' = devices with no class, none ticked or '*'
        = every device).
        REQ: VOL-04"""
        t, h = {"total": 600 * MB}, past(10, 12, 11)
        pol = policy(volume_spike={**OLD, "classes": ["iot", "unclassified"]})
        self.assertIsNone(analyze.volume_finding(pol, SRV, {**t, "ip": SRV}, h))
        self.assertIsNotNone(analyze.volume_finding(pol, IOT, {**t, "ip": IOT}, h))
        self.assertIsNotNone(analyze.volume_finding(pol, NONE, {**t, "ip": NONE}, h))
        for cl in ([], ["*"]):
            pol = policy(volume_spike={**OLD, "classes": cl})
            self.assertIsNotNone(analyze.volume_finding(pol, SRV, {**t, "ip": SRV}, h))


class Settings(Base):
    def test_validation_and_rescope(self):
        """cfg_validate checks volume_spike like upload_spike (severity, non-negative numbers, unknown keys, scope);
        a class rename / removal follows into its classes / by_class; the event card lists its values.
        REQ: VOL-05"""
        pol = policy()
        ok = copy.deepcopy(pol)
        ok["volume_spike"].update(classes=["server", "unclassified"], by_class={"server": {"min_mb": 900, "severity": "low"}})
        self.assertIsNone(cfg_validate("policy", ok))
        for patch in ({"severity": "loud"}, {"min_mb": -1}, {"min_mb": True}, {"min_mb": "x"}, {"nope": 1},
                      {"classes": ["nope"]}, {"by_class": {"nope": {"min_mb": 1}}}, {"by_class": {"server": {}}},
                      {"by_class": {"server": {"severity": "loud"}}}, {"by_class": {"server": {"window": 1}}}):
            bad = copy.deepcopy(pol)
            bad["volume_spike"] = {**bad["volume_spike"], **patch}
            self.assertIsNotNone(cfg_validate("policy", bad), patch)
        self.assertIsNotNone(cfg_validate("policy", {**pol, "volume_spike": [1]}))
        pol = policy(volume_spike={**OLD, "classes": ["server"], "by_class": {"server": {"min_mb": 900}}})
        pol = classdefs.rename(pol, "server", "servers")
        self.assertEqual((pol["volume_spike"]["classes"], list(pol["volume_spike"]["by_class"])), (["servers"], ["servers"]))
        store.cfg_save("policy", policy(volume_spike={**OLD, "severity": "low"}))
        info = server.tuning_info()["settings"]["volume_spike"]
        self.assertEqual((info["kinds"], info["values"]["severity"], info["values"]["min_mb"]), ("^volume-spike", "low", 50))

    def test_class_alarm_switch(self):
        """volume-spike is in the per-class alarm list (Device class definitions) and its switch silences the finding
        for that class only.
        REQ: VOL-05"""
        self.assertIn("volume-spike", [a[0] for a in classdefs.ALARMS])
        pol = {"class_defs": [{"name": "server", "like": "server", "off": ["volume-spike"]}]}
        self.assertFalse(classdefs.alarm_enabled(pol, "server", "volume-spike"))
        self.assertTrue(classdefs.alarm_enabled(pol, "iot", "volume-spike"))


def seed(noisy=()):
    for d in range(15):
        devs = {ip: {"ip": ip, "total": (120 if d % 2 else 2) * tuning.MB if ip in noisy else 10 * tuning.MB, "sent": tuning.MB,
                     "ext_peers": 10, "rejected": 0, "dns_q": 100} for ip in (*SRVS, IOT, NONE)}
        store.history_append({"generated": "2026-10-%02dT05:00:00+00:00" % (d + 1), "hours": 24, "devices": devs})


class AutoTune(Base):
    def recs(self):
        return {r["id"]: r for r in tuning.recommend()["recommendations"]}

    def test_auto_tune_volume(self):
        """Auto-tune proposes volume_spike values (section-wide and per by_class override, MB units) and apply writes
        only the proposed numbers into the section or the class override; a section not saved yet starts from its
        defaults.
        REQ: VOL-05"""
        pol = policy()
        pol.pop("volume_spike")
        store.cfg_save("policy", pol)
        seed(noisy=SRVS)
        r = self.recs()["volume_spike"]
        self.assertEqual((r["status"], r["unit"], r["target"]), ("change", "MB", {"section": "volume_spike"}))
        self.assertEqual(r["current"]["min_mb"], 50)
        done, out = tuning.apply([{"id": "volume_spike"}])
        self.assertEqual(done, ["volume_spike"])
        self.assertEqual(out["volume_spike"], {**OLD, **r["changes"]})
        self.assertIsNone(cfg_validate("policy", out))
        policy(volume_spike={**OLD, "by_class": {"server": {"times_normal": 3}}})
        r = self.recs()
        self.assertEqual(r["volume_spike@server"]["status"], "change")
        self.assertEqual(r["volume_spike"]["status"], "ok")
        done, out = tuning.apply([{"id": "volume_spike@server"}])
        self.assertEqual({k: v for k, v in out["volume_spike"].items() if k != "by_class"}, OLD)
        self.assertEqual(out["volume_spike"]["by_class"]["server"], {"times_normal": 3, **r["volume_spike@server"]["changes"]})


if __name__ == "__main__":
    unittest.main()
