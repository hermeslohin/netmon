"""Unit tests for per-user alert targeting (store.py prefs/watch_ids/alert_targets) and Web Push fan-out (pushsvc.py)."""
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); import _env  # noqa: E401,E702,E402

import io  # noqa: E402
import types  # noqa: E402
import unittest  # noqa: E402
from unittest import mock  # noqa: E402

import store  # noqa: E402
import auth  # noqa: E402
import pushsvc  # noqa: E402
from fixtures import mac, IPS  # noqa: E402

ALT_PRIV = ".".join(["192", "168", "77", "5"])   # another RFC1918 range, assembled at run time


def _reset_db():
    """Empty the isolated DB and drop store's cached settings (fresh_db keeps the cfg cache)."""
    c = getattr(store._dl, "c", None)
    if c is not None:
        c.close()
    _env.fresh_db()
    store._cfg_cache.clear()


def _endpoint_ips(mapping):
    store.cfg_save("host_policy", {"endpoint_ips": mapping})


class _Base(unittest.TestCase):
    """Fresh DB and settings cache around each test."""

    def setUp(self):
        _reset_db()

    def tearDown(self):
        _reset_db()


class TestAlertTargets(_Base):
    """Which device identifiers an alert is about."""

    def test_private_ips_extracted(self):
        """10/8, 172.16/12 and 192.168/16 addresses in key or text become ip: targets.
        REQ: STO-07"""
        t = store.alert_targets("seg|" + IPS["laptop"], f"talks to {IPS['server']} and 172.20.1.2 and {ALT_PRIV}")
        self.assertEqual(t, {"ip:" + IPS["laptop"], "ip:" + IPS["server"], "ip:172.20.1.2", "ip:" + ALT_PRIV})

    def test_public_and_out_of_range_ips_ignored(self):
        """Documentation/public addresses and 172.x outside 16-31 are not device targets.
        REQ: STO-07"""
        self.assertEqual(store.alert_targets("k", "to 192.0.2.53 and 172.40.0.1 and 172.15.0.1 and 203.0.113.66"), set())

    def test_ip_boundaries(self):
        """An address embedded in a longer number is not mistaken for a device IP.
        REQ: STO-07"""
        self.assertEqual(store.alert_targets("k", "id 110.0.1.10 x"), set())
        self.assertEqual(store.alert_targets("k", "10.0.1.100:443"), {"ip:10.0.1.100"})

    def test_macs_lowercased(self):
        """MAC addresses (any case) become lower-case mac: targets.
        REQ: STO-07"""
        self.assertEqual(store.alert_targets("k", "new device " + mac(9).upper()), {"mac:" + mac(9)})

    def test_host_key_adds_label_and_mapped_ip(self):
        """host|<kind>|<name> keys add the short host label and the endpoint IP mapped in host_policy.
        REQ: STO-07"""
        _endpoint_ips({"WS-01.corp.example": IPS["laptop"]})
        t = store.alert_targets("host|av|ws-01.corp.example|x", "malware found")
        self.assertEqual(t, {"host:ws-01", "ip:" + IPS["laptop"]})

    def test_short_host_key_ignored(self):
        """A host key without a name part adds no host target.
        REQ: STO-07"""
        self.assertEqual(store.alert_targets("host|av", "x"), set())


class TestDeviceIds(_Base):
    """Identifiers of a registry device."""

    def test_device_ids_basic(self):
        """A device yields its IPs, lower-case MAC and name label.
        REQ: STO-07"""
        d = {"ips": [IPS["laptop"], IPS["phone"]], "mac": mac(1).upper(), "name": "Laptop.lan"}
        self.assertEqual(store.device_ids(d), {"ip:" + IPS["laptop"], "ip:" + IPS["phone"], "mac:" + mac(1), "host:laptop"})

    def test_ip_name_not_used_as_host(self):
        """A device whose name is just an IP gets no host: identifier.
        REQ: STO-07"""
        self.assertEqual(store.device_ids({"ips": [IPS["camera"]], "name": IPS["camera"]}), {"ip:" + IPS["camera"]})

    def test_empty_device(self):
        """A device with no IPs, MAC or name has no identifiers.
        REQ: STO-07"""
        self.assertEqual(store.device_ids({}), set())
        self.assertEqual(store.device_ids({"ips": None, "mac": None, "name": ""}), set())

    def test_endpoint_host_mapped_by_ip(self):
        """A host in host_policy.endpoint_ips whose IP the device has adds that host's label.
        REQ: STO-07"""
        _endpoint_ips({"WS-02": IPS["server"]})
        self.assertIn("host:ws-02", store.device_ids({"ips": [IPS["server"]]}))
        self.assertNotIn("host:ws-02", store.device_ids({"ips": [IPS["laptop"]]}))


class TestPrefs(_Base):
    """Per-user push preferences."""

    def test_default_is_all(self):
        """A user without saved prefs gets mode 'all' with no devices.
        REQ: STO-07"""
        self.assertEqual(store.prefs_get("nobody"), {"mode": "all", "devices": []})

    def test_set_and_get(self):
        """prefs_set stores a sorted, de-duplicated, stringified device list and returns it.
        REQ: STO-07"""
        r = store.prefs_set("alice", "some", [mac(2), mac(1), mac(2), 5])
        self.assertEqual(r, {"mode": "some", "devices": sorted(["5", mac(1), mac(2)])})
        self.assertEqual(store.prefs_get("alice"), r)

    def test_update_overwrites(self):
        """A second prefs_set replaces the earlier choice for that user only.
        REQ: STO-07"""
        store.prefs_set("alice", "some", [mac(1)])
        store.prefs_set("bob", "some", [mac(3)])
        store.prefs_set("alice", "all", [])
        self.assertEqual(store.prefs_get("alice"), {"mode": "all", "devices": []})
        self.assertEqual(store.prefs_get("bob")["devices"], [mac(3)])

    def test_bad_mode_rejected(self):
        """Modes other than 'all' and 'some' raise ValueError and store nothing.
        REQ: STO-07"""
        with self.assertRaises(ValueError):
            store.prefs_set("alice", "none", [])
        self.assertEqual(store.prefs_get("alice")["mode"], "all")

    def test_device_list_capped(self):
        """At most 500 devices are stored.
        REQ: STO-07"""
        self.assertEqual(len(store.prefs_set("alice", "some", [f"d{i:04d}" for i in range(600)])["devices"]), 500)


class TestWatchIds(_Base):
    """Resolving a user's chosen devices to identifiers."""

    def setUp(self):
        super().setUp()
        self.reg = {mac(1): {"mac": mac(1), "ips": [IPS["laptop"]], "name": "Laptop"},
                    mac(3): {"mac": mac(3), "ips": [IPS["camera"]], "name": "Camera"}}
        store.registry_save(self.reg)

    def test_mode_all_is_none(self):
        """Mode 'all' resolves to None (every device).
        REQ: STO-07"""
        self.assertIsNone(store.watch_ids("alice"))

    def test_some_resolves_registry_devices(self):
        """Chosen registry devices resolve to their current identifiers, read from the DB registry.
        REQ: STO-07"""
        store.prefs_set("alice", "some", [mac(1)])
        self.assertEqual(store.watch_ids("alice"), {"ip:" + IPS["laptop"], "mac:" + mac(1), "host:laptop"})

    def test_dhcp_change_followed(self):
        """When the device's IP changes in the registry, the user's identifiers follow it.
        REQ: STO-07, RISK-03"""
        store.prefs_set("alice", "some", [mac(1)])
        self.reg[mac(1)]["ips"] = [IPS["dmz"]]
        ids = store.watch_ids("alice", reg=self.reg)
        self.assertIn("ip:" + IPS["dmz"], ids)
        self.assertNotIn("ip:" + IPS["laptop"], ids)

    def test_host_entries_and_unknown_keys(self):
        """'host:<name>' choices add the label (and mapped IP); unknown registry keys are ignored.
        REQ: STO-07"""
        _endpoint_ips({"ws-09": IPS["server"]})
        store.prefs_set("alice", "some", ["host:WS-09.corp.example", "host:ws-09", "gone-device"])
        self.assertEqual(store.watch_ids("alice"), {"host:ws-09", "ip:" + IPS["server"]})

    def test_some_with_nothing_chosen(self):
        """Mode 'some' with no devices resolves to an empty set (no alerts).
        REQ: STO-07"""
        store.prefs_set("alice", "some", [])
        self.assertEqual(store.watch_ids("alice"), set())

    def test_alert_for(self):
        """alert_for: None matches every alert; otherwise an alert matches only on a shared identifier.
        REQ: STO-07, AC-06"""
        a = {"targets": ["ip:" + IPS["laptop"]]}
        self.assertTrue(store.alert_for(a, None))
        self.assertTrue(store.alert_for(a, {"ip:" + IPS["laptop"], "mac:x"}))
        self.assertFalse(store.alert_for(a, {"ip:" + IPS["camera"]}))
        self.assertFalse(store.alert_for(a, set()))
        self.assertFalse(store.alert_for({"targets": None}, {"ip:" + IPS["laptop"]}))
        self.assertTrue(store.alert_for({}, None))


class TestPayload(unittest.TestCase):
    """Web Push notification payloads."""

    def r(self, i, sev="urgent", text="t", source="dashboard"):
        return {"id": i, "severity": sev, "text": text, "source": source}

    def test_single_alert(self):
        """One investigate alert gives an ALERT title, its text, a per-alert tag and the alerts page.
        REQ: STO-06"""
        p = pushsvc.payload_for([self.r(7, "investigate", "x" * 500)])
        self.assertEqual(p["title"], "netmon: ALERT")
        self.assertEqual(len(p["body"]), 400)
        self.assertEqual((p["tag"], p["url"], p["severity"]), ("netmon-7", "/#/alerts", "investigate"))

    def test_single_urgent_report(self):
        """One urgent alert from a report links to the reports page.
        REQ: STO-06"""
        p = pushsvc.payload_for([self.r(3, source="report")])
        self.assertEqual((p["title"], p["url"]), ("netmon: urgent", "/#/reports"))

    def test_batch(self):
        """Several alerts are summarised: count, investigate count, first 4 lines and an '…and N more' tail.
        REQ: STO-06"""
        rows = [self.r(i, "investigate" if i < 2 else "urgent", f"line{i}") for i in range(6)]
        p = pushsvc.payload_for(rows)
        self.assertEqual(p["title"], "netmon: 6 urgent alerts (2 investigate)")
        self.assertEqual(p["body"].count("• "), 4)
        self.assertTrue(p["body"].endswith("…and 2 more"))
        self.assertEqual((p["tag"], p["severity"]), ("netmon-batch-5", "investigate"))

    def test_batch_without_investigate(self):
        """A batch of only urgent alerts has no investigate suffix and urgent severity.
        REQ: STO-06"""
        p = pushsvc.payload_for([self.r(1), self.r(2)])
        self.assertEqual((p["title"], p["severity"]), ("netmon: 2 urgent alerts", "urgent"))
        self.assertNotIn("more", p["body"])


class TestRunOnce(_Base):
    """Fan-out of unpushed alerts to subscribed browsers, filtered per user."""

    def setUp(self):
        super().setUp()
        self._status = dict(pushsvc._status)
        store.jdump({"admin1": {"hash": "x", "role": "admin"}, "def1": {"hash": "x", "role": "defender"},
                     "user1": {"hash": "x", "role": "user"}, "user2": {"hash": "x", "role": "user"}}, auth.USERS)
        store.registry_save({mac(1): {"mac": mac(1), "ips": [IPS["laptop"]], "name": "Laptop"},
                             mac(3): {"mac": mac(3), "ips": [IPS["camera"]], "name": "Camera"}})
        self.sent = []
        self.ok = True
        p = mock.patch.object(pushsvc, "send", self._send)
        p.start()
        self.addCleanup(p.stop)

    def tearDown(self):
        pushsvc._status.clear()
        pushsvc._status.update(self._status)
        super().tearDown()

    def _send(self, sub, payload):
        self.sent.append((sub["endpoint"], payload))
        return (True, "") if self.ok else (False, "500: test failure")

    def _sub(self, n, user):
        store.push_sub_save({"endpoint": f"https://push.example.invalid/{n}", "keys": {"p256dh": "x", "auth": "y"}}, user)

    def _alerts(self):
        store.alerts_add([("seg|a", f"laptop {IPS['laptop']} odd", "urgent"),
                          ("seg|b", f"camera {IPS['camera']} odd", "investigate")], source="test")

    def by_endpoint(self):
        return {e.rsplit("/", 1)[1]: p for e, p in self.sent}

    def test_nothing_unpushed(self):
        """With no unpushed alerts nothing is sent and 0 is returned.
        REQ: STO-06"""
        self._sub(1, "admin1")
        self.assertEqual(pushsvc.run_once(), 0)
        self.assertEqual(self.sent, [])

    def test_marked_pushed_without_subscribers(self):
        """Alerts are marked pushed even with no subscribers, so a first subscription is not flooded.
        REQ: STO-06"""
        self._alerts()
        self.assertEqual(pushsvc.run_once(), 2)
        self.assertEqual(store.alerts_unpushed(), [])
        self.assertEqual(pushsvc.run_once(), 0)

    def test_held_detections_not_pushed(self):
        """Watcher detections are held (not an alarm until promoted) and so never reach push.
        REQ: STO-06"""
        store.alerts_add([("seg|a", f"laptop {IPS['laptop']}", "urgent")], source="watcher")
        self._sub(1, "admin1")
        self.assertEqual(pushsvc.run_once(), 0)
        self.assertEqual(self.sent, [])

    def test_targeting_per_user(self):
        """Admin 'all' gets both alerts; a User with the laptop gets only the laptop alert; a User with 'all' gets none.
        REQ: STO-07, AC-06"""
        self._alerts()
        store.prefs_set("user1", "some", [mac(1)])
        self._sub(1, "admin1")
        self._sub(2, "user1")
        self._sub(3, "user2")
        pushsvc.run_once()
        got = self.by_endpoint()
        self.assertEqual(set(got), {"1", "2"})
        self.assertTrue(got["1"]["title"].startswith("netmon: 2 urgent alerts"))
        self.assertEqual(got["2"]["title"], "netmon: urgent")
        self.assertIn(IPS["laptop"], got["2"]["body"])

    def test_defender_can_narrow(self):
        """A defender who picked only the camera gets only the camera alert.
        REQ: STO-07"""
        self._alerts()
        store.prefs_set("def1", "some", [mac(3)])
        self._sub(1, "def1")
        pushsvc.run_once()
        (payload,) = self.by_endpoint().values()
        self.assertEqual(payload["title"], "netmon: ALERT")
        self.assertIn(IPS["camera"], payload["body"])

    def test_anonymous_subscription_gets_nothing(self):
        """A subscription with no user (or an unknown user) is treated as a User with no devices.
        REQ: STO-07, AC-02"""
        self._alerts()
        self._sub(1, "")
        self._sub(2, "ghost")
        pushsvc.run_once()
        self.assertEqual(self.sent, [])

    def test_every_browser_of_a_user(self):
        """Each subscribed browser of the same user receives the notification.
        REQ: STO-07"""
        self._alerts()
        self._sub(1, "admin1")
        self._sub(2, "admin1")
        pushsvc.run_once()
        self.assertEqual(set(self.by_endpoint()), {"1", "2"})
        self.assertEqual(pushsvc._status["sent"], self._status["sent"] + 2)

    def test_send_failure_recorded(self):
        """A failed send records last_error and the alerts are still marked pushed (no retry storm).
        REQ: STO-06"""
        self.ok = False
        self._alerts()
        self._sub(1, "admin1")
        with mock.patch("sys.stderr", io.StringIO()) as err:
            pushsvc.run_once()
        self.assertEqual(pushsvc._status["last_error"], "500: test failure")
        self.assertIn("failed", err.getvalue())
        self.assertEqual(store.alerts_unpushed(), [])


class _FakePushError(Exception):
    def __init__(self, msg, response=None):
        super().__init__(msg)
        self.response = response


class TestSend(_Base):
    """send(): subscription bookkeeping for each Web Push outcome (pywebpush replaced by a fake)."""

    EP = "https://push.example.invalid/s1"

    def setUp(self):
        super().setUp()
        store.push_sub_save({"endpoint": self.EP, "keys": {"p256dh": "x", "auth": "y"}}, "admin1")
        self.calls = []
        self.exc = None
        fake = types.ModuleType("pywebpush")
        fake.WebPushException = _FakePushError

        def webpush(sub, data, **kw):
            self.calls.append((sub, data, kw))
            if self.exc:
                raise self.exc
        fake.webpush = webpush
        p = mock.patch.dict(sys.modules, {"pywebpush": fake})
        p.start()
        self.addCleanup(p.stop)

    def sub(self):
        return next((s for s in store.push_subs() if s["endpoint"] == self.EP), None)

    def test_success(self):
        """A delivered push returns ok, uses high urgency and records last_ok with fails reset.
        REQ: STO-06"""
        ok, err = pushsvc.send(self.sub(), {"title": "t"})
        self.assertEqual((ok, err), (True, ""))
        self.assertEqual(self.calls[0][2]["headers"], {"Urgency": "high"})
        self.assertEqual(self.calls[0][2]["vapid_claims"], {"sub": pushsvc.SUB})
        self.assertIsNotNone(self.sub()["last_ok"])
        self.assertEqual(self.sub()["fails"], 0)

    def test_gone_subscription_deleted(self):
        """A 410 Gone answer deletes the subscription at once.
        REQ: STO-06"""
        self.exc = _FakePushError("gone", types.SimpleNamespace(status_code=410))
        ok, err = pushsvc.send(self.sub(), {})
        self.assertFalse(ok)
        self.assertTrue(err.startswith("410"))
        self.assertIsNone(self.sub())

    def test_transient_failures_counted_then_dropped(self):
        """Other failures count up; after 5 consecutive failures the subscription is removed.
        REQ: STO-06"""
        self.exc = _FakePushError("server error", types.SimpleNamespace(status_code=500))
        for i in range(4):
            pushsvc.send(self.sub(), {})
            self.assertEqual(self.sub()["fails"], i + 1)
        pushsvc.send(self.sub(), {})
        self.assertIsNone(self.sub())

    def test_unexpected_error_never_raises(self):
        """A non-push exception (e.g. network) is reported as an error string, not raised.
        REQ: STO-06"""
        self.exc = OSError("network down")
        ok, err = pushsvc.send(self.sub(), {})
        self.assertFalse(ok)
        self.assertEqual(err, "OSError: network down")
        self.assertEqual(self.sub()["fails"], 1)

    def test_resubscribe_resets_failures(self):
        """Saving the subscription again (re-subscribe) resets its failure count and owner.
        REQ: STO-07"""
        store.push_sub_result(self.EP, False)
        store.push_sub_save({"endpoint": self.EP, "keys": {}}, "user1")
        s = self.sub()
        self.assertEqual((s["fails"], s["user"]), (0, "user1"))


if __name__ == "__main__":
    unittest.main()
