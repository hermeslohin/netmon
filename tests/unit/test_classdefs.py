"""Unit tests for device class definitions and per-class alarm switches (classdefs.py, Settings > Network policy >
Device class definitions, POST /api/config/classes) and the gold magnifying-glass buttons."""
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); import _env  # noqa: E401,E702,E402

import re  # noqa: E402
import unittest  # noqa: E402

import fixtures as F  # noqa: E402
import analyze  # noqa: E402
import classdefs  # noqa: E402
import extras  # noqa: E402
import hosts  # noqa: E402
import store  # noqa: E402

IP = F.IPS
NEW_DEST = set(classdefs.NEW_DEST_KINDS)


def _server():
    sys.path.insert(0, _env.APP)
    import server
    return server


class Defaults(unittest.TestCase):
    """Without class_defs every alarm behaves as before the switches existed."""

    def test_defaults_reproduce_previous_behaviour(self):
        """With no class_defs the built-in classes and unclassified are defined, each behaving like itself; every alarm is
        on for every class except the new-destination ones, which stay iot-only (the old new_domain_classes /
        new_tls_classes default); the old keys are still honoured until the first class edit.
        REQ: CLS-01"""
        ds = classdefs.defs({})
        self.assertEqual([d["name"] for d in ds], [*classdefs.BUILTIN, "unclassified"])
        for d in ds:
            self.assertEqual(d["like"], d["name"])
            for kind in classdefs.ALARM_IDS:
                want = d["name"] == "iot" or kind not in NEW_DEST
                self.assertEqual(classdefs.alarm_enabled({}, d["name"], kind), want, (d["name"], kind))
        self.assertTrue(classdefs.alarm_enabled({}, "never-defined", "upload-spike"))
        pol = {"new_domain_classes": ["camera"], "new_tls_classes": ["*"]}
        self.assertTrue(classdefs.alarm_enabled(pol, "camera", "iot-new-domain"))
        self.assertFalse(classdefs.alarm_enabled(pol, "iot", "iot-new-domain"))
        self.assertTrue(all(classdefs.alarm_enabled(pol, c, "new-tls-server") for c in (*classdefs.BUILTIN, "unclassified")))
        # analyze's gate passes every finding of a device class through unchanged
        got = []
        g = analyze.gate(lambda *a: got.append(a), {"device_classes": {F.mac(1): "personal"}}, {F.mac(1): {"ip": IP["laptop"]}})
        for kind in sorted(classdefs.ALARM_IDS - NEW_DEST):
            g("medium", F.mac(1), kind, "x")
        self.assertEqual(len(got), len(classdefs.ALARM_IDS - NEW_DEST))
        self.assertEqual(classdefs.like({}, "camera"), "camera")
        self.assertEqual(classdefs.like({}, None), "unclassified")

    def test_every_raised_kind_is_in_the_catalogue(self):
        """Every finding kind analyze.py raises with a literal kind appears in the alarm catalogue, so each one has a switch.
        REQ: CLS-01"""
        src = open(os.path.join(_env.REPO, "analyze.py"), encoding="utf-8").read()
        kinds = set(re.findall(r'add\([^,]*,\s*[^,]*,\s*"([a-z0-9-]+)"', src))
        self.assertTrue(kinds)
        self.assertEqual(sorted(kinds - classdefs.ALARM_IDS), [])


class Switches(unittest.TestCase):
    """A switched-off alarm is never raised for devices of that class."""

    def test_switch_off_suppresses_the_alarm(self):
        """Turning an alarm off for a class drops it in analyze (findings), in hosts (endpoint findings, matched by the
        learned host name) and in collect (new-destination collection), while other classes still raise it.
        REQ: CLS-02"""
        kp, ki = F.mac(1), F.mac(3)
        pol = {"device_classes": {kp: "personal", ki: "iot"},
               "class_defs": [{"name": "personal", "like": "personal", "off": ["upload-spike"]},
                              {"name": "iot", "like": "iot", "off": ["iot-new-domain", "iot-new-network", "iot-raw-ip", "new-tls-server"]}]}
        got = []
        g = analyze.gate(lambda sev, k, kind, m: got.append((k, kind)), pol, {kp: {"ip": IP["laptop"]}, ki: {"ip": IP["camera"]}})
        g("high", kp, "upload-spike", "x")
        g("high", ki, "upload-spike", "x")
        g("high", kp, "volume-spike", "x")
        self.assertEqual(got, [(ki, "upload-spike"), (kp, "volume-spike")])
        # a class missing from class_defs falls back to the unclassified row
        self.assertTrue(classdefs.alarm_enabled(pol, "camera", "upload-spike"))
        self.assertEqual(extras.new_dest_ips({IP["camera"]: {"mac": ki}}, pol), [])  # all new-destination switches off
        # endpoint findings: host-<kind>, matched to the device by registry hostname
        reg = {kp: {"mac": kp, "hostname": "laptop-a", "ips": [IP["laptop"]]}}
        pol2 = {**pol, "class_defs": [{"name": "personal", "like": "personal", "off": ["host-exec-new"]}]}
        F_ = [("exec-new|laptop-a|/tmp/x", "Review", "t"), ("exec-new|other-host|/tmp/x", "Review", "t"),
              ("login-new|laptop-a|u|s|ssh", "Review", "t")]
        self.assertEqual([f[0] for f in hosts.class_gate(F_, pol2, reg)], ["exec-new|other-host|/tmp/x", "login-new|laptop-a|u|s|ssh"])

    def test_watch_alerts_pass_the_switch(self):
        """watch.py live alerts for a device (IDS, new device, inbound port, threat intel, admin access) name their alarm
        kind and device, so alert() can drop the ones switched off for the device's class.
        REQ: CLS-02"""
        src = open(os.path.join(_env.REPO, "watch.py"), encoding="utf-8").read()
        for kind in ("ids", "new-device-dhcp", "new-device", "inbound-port", "ti-domain", "ti-ip-out", "admin-access"):
            self.assertIn(f'kind="{kind}"', src)
            self.assertIn(kind, classdefs.ALARM_IDS)
        self.assertIn("if kind and (ip or mac) and not alarm_on(kind, ip, mac):", src)


class Edits(unittest.TestCase):
    """Add / rename / remove through POST /api/config/classes."""

    def setUp(self):
        self.k1, self.k2 = F.mac(1), F.mac(2)
        store.cfg_save("policy", {"zones": {}, "device_classes": {self.k1: "server", self.k2: "personal"},
                                  "allow": [{"src": "personal", "dst": "server", "ports": [445]}],
                                  "new_domain_classes": ["iot"], "new_tls_classes": ["iot", "camera"]})
        self.srv = _server()

    def post(self, **b):
        return self.srv.classes_post(b, "tester")

    def test_add_rename_and_migrate(self):
        """Adding a class stores class_defs (migrating new_domain_classes / new_tls_classes into the switches and dropping
        them); renaming updates device_classes and allow rules; device_classes then accepts the new name and refuses an
        undefined one; duplicates and bad names are refused.
        REQ: CLS-03"""
        r, st = self.post(op="add", name="nas", like="server")
        self.assertEqual(st, 200, r)
        p = store.cfg_load("policy")
        self.assertNotIn("new_domain_classes", p)
        self.assertNotIn("new_tls_classes", p)
        cam = next(d for d in p["class_defs"] if d["name"] == "camera")
        self.assertIn("iot-new-domain", cam["off"])
        self.assertNotIn("new-tls-server", cam["off"])  # migrated from new_tls_classes
        self.assertEqual(next(d for d in p["class_defs"] if d["name"] == "nas")["like"], "server")
        self.assertEqual(self.post(op="add", name="nas", like="server")[1], 400)
        self.assertEqual(self.post(op="add", name="Bad Name!", like="iot")[1], 400)
        self.assertEqual(self.post(op="add", name="x", like="nope")[1], 400)
        r, st = self.post(op="rename", name="personal", new="family")
        self.assertEqual(st, 200, r)
        p = store.cfg_load("policy")
        self.assertEqual(p["device_classes"][self.k2], "family")
        self.assertEqual(p["allow"][0]["src"], "family")
        self.assertEqual(next(d for d in p["class_defs"] if d["name"] == "family")["like"], "personal")
        self.assertIsNone(self.srv.cfg_validate("policy", {**p, "device_classes": {self.k1: "nas"}}))
        self.assertTrue(self.srv.cfg_validate("policy", {**p, "device_classes": {self.k1: "personal"}}))
        self.assertEqual(self.post(op="rename", name="family", new="server")[1], 400)  # taken

    def test_remove_in_use_needs_a_target(self):
        """Removing a class no device uses just removes it; removing one in use is refused until a target class (or
        unclassified) is chosen, then its devices move there; unclassified itself cannot be removed.
        REQ: CLS-03"""
        r, st = self.post(op="remove", name="game")
        self.assertEqual(st, 200, r)
        self.assertNotIn("game", classdefs.names(store.cfg_load("policy")))
        r, st = self.post(op="remove", name="server")
        self.assertEqual(st, 400)
        self.assertEqual(r["in_use"], 1)
        self.assertEqual(store.cfg_load("policy")["device_classes"][self.k1], "server")
        self.assertEqual(self.post(op="remove", name="server", move_to="nope")[1], 400)
        r, st = self.post(op="remove", name="server", move_to="k8s")
        self.assertEqual(st, 200, r)
        self.assertEqual(store.cfg_load("policy")["device_classes"][self.k1], "k8s")
        r, st = self.post(op="remove", name="personal", move_to="")
        self.assertEqual(st, 200, r)
        self.assertNotIn(self.k2, store.cfg_load("policy")["device_classes"])
        self.assertEqual(self.post(op="remove", name="unclassified")[1], 400)

    def test_update_switches(self):
        """update sets a class's switched-off alarms (unknown kinds refused) and is read back by alarm_enabled; a
        device_classes row with an undefined class does not block class edits, and adding that class makes it valid.
        REQ: CLS-02, CLS-03"""
        p0 = store.cfg_load("policy")
        store.cfg_save("policy", {**p0, "device_classes": {**p0["device_classes"], F.mac(5): "printer"}})
        self.assertTrue(self.srv.cfg_validate("policy", store.cfg_load("policy")))
        self.assertEqual(self.post(op="add", name="printer", like="iot")[1], 200)
        self.assertIsNone(self.srv.cfg_validate("policy", store.cfg_load("policy")))
        r, st = self.post(op="update", name="personal", off=["upload-spike"])
        self.assertEqual(st, 200, r)
        p = store.cfg_load("policy")
        self.assertFalse(classdefs.alarm_enabled(p, "personal", "upload-spike"))
        self.assertTrue(classdefs.alarm_enabled(p, "server", "upload-spike"))
        self.assertEqual(self.post(op="update", name="personal", off=["no-such-alarm"])[1], 400)
        self.assertEqual(self.post(op="bogus", name="x")[1], 400)


class BehavesLike(unittest.TestCase):
    """User-added classes follow the built-in rules of the class they behave like."""

    def test_user_class_follows_its_builtin(self):
        """A user class behaving like camera is held to the camera protected-zone rule and gets camera risk impact and
        alarm defaults; behaving like personal it is not flagged; built-in classes cannot behave like another class.
        REQ: CLS-04"""
        src, dst = IP["camera"], IP["server"]
        flow = {"src": src, "dst": dst, "port": 8080, "proto": "tcp", "service": "http", "answered": 3, "conns": 9,
                "src_zone": "cams", "dst_zone": "servers"}
        base = {"zones": {"cams": "10.0.3.0/24", "servers": "10.0.2.0/24"}, "zone_roles": {"cams": "iot", "servers": "protected"},
                "device_classes": {F.mac(3): "doorbell"}}
        for like_, flagged in (("camera", True), ("personal", False)):
            pol = classdefs.add(base, "doorbell", like_)
            v = extras.policy_violations([flow], {src: F.mac(3)}, pol)
            self.assertEqual(bool([x for x in v if "device reaching" in x["reason"]]), flagged, like_)
            self.assertEqual(classdefs.like(pol, "doorbell"), like_)
        pol = classdefs.add({}, "doorbell", "iot")
        self.assertTrue(classdefs.alarm_enabled(pol, "doorbell", "iot-new-domain"))  # copies iot's switches
        with self.assertRaises(ValueError):
            classdefs.update(pol, "camera", like_="iot")
        self.assertTrue(classdefs.valid_defs([{"name": "camera", "like": "iot", "off": []}]))
        risk = open(os.path.join(_env.APP, "risk.py"), encoding="utf-8").read()
        self.assertIn("IMPACT_BY_CLASS.get(rcls, 0)", risk)


class SettingsCard(unittest.TestCase):
    """The settings page wiring."""

    def test_card_and_dropdown(self):
        """The policy settings GET returns the alarm catalogue and built-in classes; settings.js renders the Device class
        definitions card (rename, behaves like, per-alarm switches, remove with a move target) and the device_classes
        values as a drop-down of the defined classes next to the learned host name.
        REQ: CLS-05"""
        js = open(os.path.join(_env.APP, "static", "settings.js"), encoding="utf-8").read()
        for s in ("function classDefsCard(", 'op: "rename"', 'op: "update", name: d.name, off:', 'op: "remove", name: d.name, move_to:',
                  'op: "add"', "Behaves like", 'key === "device_classes" ? classSelect(v, ed)', "learnedEl(k)"):
            self.assertIn(s, js)
        srv = open(os.path.join(_env.APP, "server.py"), encoding="utf-8").read()
        self.assertIn('"alarms": classdefs.catalogue()', srv)
        self.assertIn('if u.path == "/api/config/classes":', srv)


class EyeglassGold(unittest.TestCase):
    """The magnifying-glass buttons use the gold action style."""

    def test_magnifier_buttons_are_gold(self):
        """The pivot (open related events) and Search-in-Elasticsearch buttons and the web-research count use the gold
        line magnifier icon (no emoji), with the gold colour variables for normal, hover, active and focus states; the
        times-seen flair uses a gold line eye icon instead of the 👁 emoji.
        REQ: UI-92"""
        st = os.path.join(_env.APP, "static")
        css = open(os.path.join(st, "style.css"), encoding="utf-8").read()
        self.assertIn(".ic-search{--i:url(", css)
        self.assertIn(".pivh,.kib-btn.art-kib{color:var(--gold)", css)
        for state in (".pivh:hover", ".pivh:active", ".pivh:focus-visible", ".kib-btn.art-kib:hover", ".kib-btn.art-kib:active"):
            self.assertIn(state, css)
        for f in ("pivot.js", "kbnotes.js", "alerts.js"):
            js = open(os.path.join(st, f), encoding="utf-8").read()
            self.assertIn('class="ic ic-search', js, f)
            for m in re.finditer(r'<button type="button" class="(?:pivh|kib-btn art-kib)[^`]*?</button>', js):
                self.assertNotRegex(m.group(0), "[\U0001F50D\U0001F50E]", f)
        # the times-seen eye: gold line icon, not the emoji
        rel = open(os.path.join(st, "related.js"), encoding="utf-8").read()
        self.assertIn('<i class="ic ic-eye"', rel)
        self.assertNotIn("\U0001F441", rel)
        self.assertIn(".seen-flair .ic{", css)
        self.assertIn(".ic-eye{--i:url(", css)


if __name__ == "__main__":
    unittest.main()
