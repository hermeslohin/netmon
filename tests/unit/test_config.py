"""Unit tests for the config helpers: site_cfg.py, window.py, lookback.py, research_cfg.py."""
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); import _env  # noqa: E401,E402

import datetime as dt  # noqa: E402
import json  # noqa: E402
import time  # noqa: E402
import unittest  # noqa: E402
from unittest import mock  # noqa: E402

import lookback  # noqa: E402
import research_cfg as rc  # noqa: E402
import site_cfg  # noqa: E402
import store  # noqa: E402
import window  # noqa: E402


def _reset_site():
    site_cfg._cache = None
    site_cfg._at = 0.0
    site_cfg._src = None
    store._cfg_cache.clear()


def _clean_meta():
    """fresh_db() keeps the meta table: drop the keys these modules own."""
    with store.connect() as c:
        c.execute("DELETE FROM meta WHERE k IN (?, ?, ?)", (lookback.KEY, rc.KEY, rc.REQ))


def _meta_raw(k, v):
    with store.connect() as c:
        c.execute("INSERT OR REPLACE INTO meta VALUES (?, ?)", (k, json.dumps(v) if not isinstance(v, str) else v))


class TestSiteCfg(unittest.TestCase):
    """site_cfg: defaults, overrides from the cfg table, public subset."""

    def setUp(self):
        _env.fresh_db()
        _reset_site()

    def tearDown(self):
        _env.fresh_db()
        _reset_site()

    def test_defaults_without_site_config(self):
        """With no site document every DEFAULTS key is returned with its default value.
        REQ: CFG-01
        """
        self.assertEqual(site_cfg.load(), site_cfg.DEFAULTS)
        self.assertEqual(site_cfg.get("internal_prefixes"), ["10."])

    def test_overrides_merge_and_private_keys_dropped(self):
        """Stored site values override defaults, unknown keys pass through and '_'-prefixed keys are dropped.
        REQ: CFG-01, STO-02
        """
        store.cfg_save("site", {"site_name": "lab", "_comment": "x", "extra": 1, "internal_prefixes": ["10.", "192.0.2."]})
        s = site_cfg.load()
        self.assertEqual(s["site_name"], "lab")
        self.assertEqual(s["extra"], 1)
        self.assertNotIn("_comment", s)
        self.assertEqual(s["gateway_name"], "gateway")

    def test_cache_ttl(self):
        """load() caches for a few seconds and picks up a changed site document after the TTL.
        REQ: CFG-01
        """
        store.cfg_save("site", {"site_name": "one"})
        self.assertEqual(site_cfg.load()["site_name"], "one")
        store.cfg_save("site", {"site_name": "two"})
        self.assertEqual(site_cfg.load()["site_name"], "one")  # still cached
        site_cfg._at = time.time() - 10
        self.assertEqual(site_cfg.load()["site_name"], "two")

    def test_store_failure_falls_back_to_defaults(self):
        """If reading the store raises, load() falls back to DEFAULTS instead of failing.
        REQ: CFG-01
        """
        with mock.patch.object(store, "cfg_load", side_effect=RuntimeError("db gone")):
            self.assertEqual(site_cfg.load(), site_cfg.DEFAULTS)

    def test_get_default_for_empty_values(self):
        """get() returns the caller default for missing/empty values ('' [] {} None) but keeps falsy non-empty values.
        REQ: CFG-01
        """
        store.cfg_save("site", {"sensor_ip": "", "flag": 0, "honeypot_ips": []})
        self.assertEqual(site_cfg.get("sensor_ip", "192.0.2.9"), "192.0.2.9")
        self.assertEqual(site_cfg.get("sensor_ip"), "")
        self.assertEqual(site_cfg.get("honeypot_ips", ["x"]), ["x"])
        self.assertEqual(site_cfg.get("missing", "d"), "d")
        self.assertIsNone(site_cfg.get("missing"))
        self.assertEqual(site_cfg.get("flag", 5), 0)

    def test_is_internal(self):
        """is_internal() matches the configured internal prefixes and is False for empty values.
        REQ: CFG-01
        """
        self.assertTrue(site_cfg.is_internal("10.1.2.3"))
        self.assertFalse(site_cfg.is_internal("203.0.113.5"))
        self.assertFalse(site_cfg.is_internal(""))
        self.assertFalse(site_cfg.is_internal(None))
        store.cfg_save("site", {"internal_prefixes": ["198.51.100."]})
        _reset_site()
        self.assertTrue(site_cfg.is_internal("198.51.100.7"))
        self.assertFalse(site_cfg.is_internal("10.1.2.3"))

    def test_public_subset(self):
        """public() exposes only the browser-safe keys, never secrets like es_url or sensitive_terms.
        REQ: CFG-01, AC-06
        """
        store.cfg_save("site", {"es_url": "https://192.0.2.1:9200", "sensitive_terms": ["secret"], "site_name": "lab"})
        p = site_cfg.public()
        self.assertEqual(set(p), {"site_name", "internal_prefixes", "host_ips", "display_names", "honeypot_ips", "self_host",
                                  "sensor_ip", "admin_workstations", "kibana_url", "kibana_data_view", "unifi_web_url", "unifi_paths"})
        self.assertEqual(p["site_name"], "lab")
        self.assertNotIn("es_url", p)
        self.assertNotIn("sensitive_terms", p)


class TestWindow(unittest.TestCase):
    """window: collection window end and Elasticsearch range filters."""

    def setUp(self):
        self._old = os.environ.pop("NETMON_WINDOW_END", None)

    def tearDown(self):
        os.environ.pop("NETMON_WINDOW_END", None)
        if self._old is not None:
            os.environ["NETMON_WINDOW_END"] = self._old

    def test_now_window(self):
        """Without NETMON_WINDOW_END the window ends now and the filter is relative to now.
        REQ: CFG-03
        """
        self.assertIsNone(window.end())
        self.assertFalse(window.is_range())
        self.assertEqual(window.since(15), {"range": {"@timestamp": {"gte": "now-15m"}}})
        self.assertAlmostEqual(window.end_ms() / 1000, time.time(), delta=5)
        self.assertEqual(window.end_dt().tzinfo, dt.timezone.utc)

    def test_empty_env_means_now(self):
        """An empty NETMON_WINDOW_END is treated as 'now'.
        REQ: CFG-03
        """
        os.environ["NETMON_WINDOW_END"] = ""
        self.assertIsNone(window.end())
        self.assertFalse(window.is_range())

    def test_fixed_end_window(self):
        """With NETMON_WINDOW_END set the filter covers [end - N m, end] and end_dt/end_ms parse the Z timestamp.
        REQ: CFG-03
        """
        os.environ["NETMON_WINDOW_END"] = "2026-01-05T12:00:00Z"
        self.assertTrue(window.is_range())
        self.assertEqual(window.since(60), {"range": {"@timestamp": {"gte": "2026-01-05T12:00:00Z||-60m", "lte": "2026-01-05T12:00:00Z"}}})
        self.assertEqual(window.end_dt(), dt.datetime(2026, 1, 5, 12, tzinfo=dt.timezone.utc))
        self.assertEqual(window.end_ms(), int(dt.datetime(2026, 1, 5, 12, tzinfo=dt.timezone.utc).timestamp() * 1000))

    def test_minutes_rounding_and_floor(self):
        """since() rounds fractional minutes and never goes below 1 minute; since_h converts hours.
        REQ: CFG-03
        """
        self.assertEqual(window.since(0)["range"]["@timestamp"]["gte"], "now-1m")
        self.assertEqual(window.since(-5)["range"]["@timestamp"]["gte"], "now-1m")
        self.assertEqual(window.since(2.6)["range"]["@timestamp"]["gte"], "now-3m")
        self.assertEqual(window.since_h(24)["range"]["@timestamp"]["gte"], "now-1440m")
        self.assertEqual(window.since_h("0.5")["range"]["@timestamp"]["gte"], "now-30m")


class TestLookback(unittest.TestCase):
    """lookback: research job lookback hours."""

    def setUp(self):
        _env.fresh_db()
        _clean_meta()

    def tearDown(self):
        _clean_meta()
        _env.fresh_db()

    def test_default(self):
        """Without a stored setting the lookback is 24 h with limits 1-24 and no author.
        REQ: CFG-02
        """
        g = lookback.get()
        self.assertEqual(g, {"hours": 24, "by": None, "at": None, "default": 24, "min": 1, "max": 24, "pdf_hour": 5})

    def test_put_valid_values(self):
        """put() accepts whole numbers 1-24 as int or (padded) string and records author and time.
        REQ: CFG-02
        """
        self.assertEqual(lookback.put(6, "admin")["hours"], 6)
        g = lookback.put(" 12 ", "x" * 100)
        self.assertEqual(g["hours"], 12)
        self.assertEqual(g["by"], "x" * 64)
        self.assertAlmostEqual(g["at"], time.time(), delta=5)
        self.assertEqual(lookback.put("1", "a")["hours"], 1)
        self.assertEqual(lookback.put(24, "a")["hours"], 24)

    def test_put_rejects_invalid(self):
        """put() rejects out-of-range, negative, fractional, boolean, None and non-numeric values and leaves the setting.
        REQ: CFG-02
        """
        lookback.put(8, "a")
        for bad in (0, 25, -1, "-3", "1.5", 1.5, True, None, "abc", "", [4]):
            with self.assertRaises(ValueError, msg=repr(bad)):
                lookback.put(bad, "a")
        self.assertEqual(lookback.get()["hours"], 8)

    def test_corrupt_stored_value_falls_back(self):
        """A stored value that is out of range, not an int, or not valid JSON reads back as the default.
        REQ: CFG-02
        """
        for raw in ({"hours": 99}, {"hours": "6"}, {"hours": 6.0}, "{not json"):
            _meta_raw(lookback.KEY, raw)
            self.assertEqual(lookback.get()["hours"], 24, raw)

    def test_for_run(self):
        """The 05 UTC PDF run always uses 24 h; other hours use the setting and say whether it is configured.
        REQ: CFG-02, OPS-03
        """
        self.assertEqual(lookback.for_run(10), (24, "default"))
        lookback.put(4, "a")
        self.assertEqual(lookback.for_run(5), (24, "PDF run: always 24 h"))
        self.assertEqual(lookback.for_run(10), (4, "configured on the AI review page"))
        self.assertIn(lookback.for_run()[0], (4, 24))


class TestResearchCfg(unittest.TestCase):
    """research_cfg: research job settings, schedule grid and run requests."""

    def setUp(self):
        _env.fresh_db()
        _clean_meta()

    def tearDown(self):
        _clean_meta()
        _env.fresh_db()

    def test_fresh_defaults(self):
        """A new deployment gets DEFAULTS with every category in test mode, web research off and no severities.
        REQ: CFG-01
        """
        g = rc.get()
        self.assertEqual(g["interval_minutes"], 240)
        self.assertFalse(g["web_research"])
        self.assertTrue(g["enabled"])
        self.assertEqual(set(g["modes"].values()), {"test"})
        self.assertEqual(set(g["modes"]), {k for k, _ in rc.MODE_CATS})
        self.assertEqual(g["severities"], [])
        self.assertEqual(g["pdf_hour"], 5)
        self.assertEqual(len(g["mode_cats"]), len(rc.MODE_CATS))

    def test_existing_deployment_keeps_legacy_behaviour(self):
        """Settings saved before modes/web_research existed get the legacy modes and web research on.
        REQ: CFG-01
        """
        _meta_raw(rc.KEY, {"model": "m"})
        g = rc.get()
        self.assertTrue(g["web_research"])
        self.assertEqual(g["modes"], rc.LEGACY_MODES)
        self.assertEqual(g["severities"], ["high", "medium"])

    def test_legacy_severities_and_seg_split(self):
        """A legacy severities list maps to research/skip; an old single 'seg' mode is applied to all three seg categories.
        REQ: CFG-01
        """
        _meta_raw(rc.KEY, {"severities": ["low"]})
        m = rc.get()["modes"]
        self.assertEqual((m["high"], m["low"], m["info"]), ("skip", "research", "skip"))
        _meta_raw(rc.KEY, {"modes": {"seg": "review", "seg_low": "skip", "bogus": "research", "host": "nonsense"}})
        m = rc.get()["modes"]
        self.assertEqual((m["seg_high"], m["seg_medium"], m["seg_low"]), ("review", "review", "skip"))
        self.assertNotIn("bogus", m)
        self.assertEqual(m["host"], "research")

    def test_get_clamps_invalid_stored_limits(self):
        """Stored numbers outside LIMITS or of the wrong type read back as the defaults.
        REQ: CFG-01
        """
        _meta_raw(rc.KEY, {"interval_minutes": 2, "max_batches": "x", "max_run_usd": "7.5", "max_searches": None})
        g = rc.get()
        self.assertEqual(g["interval_minutes"], 240)
        self.assertEqual(g["max_batches"], 10)
        self.assertEqual(g["max_run_usd"], 7.5)
        self.assertEqual(g["max_searches"], 3)

    def test_put_validates_and_coerces(self):
        """put() coerces numbers and booleans, truncates provider/model, ignores unknown keys and records the author.
        REQ: CFG-01
        """
        g = rc.put({"interval_minutes": "60", "enabled": 0, "model": "m" * 200, "max_run_usd": 2, "bogus": 1}, "admin")
        self.assertEqual(g["interval_minutes"], 60)
        self.assertFalse(g["enabled"])
        self.assertEqual(len(g["model"]), 120)
        self.assertIsInstance(g["max_run_usd"], float)
        self.assertNotIn("bogus", g)
        self.assertEqual(g["by"], "admin")
        for bad in ({"interval_minutes": 4}, {"interval_minutes": "x"}, {"max_batches": 41}, {"max_day_usd": -1}):
            with self.assertRaises(ValueError, msg=bad):
                rc.put(bad, "a")
        self.assertEqual(rc.get()["interval_minutes"], 60)

    def test_put_pins_modes(self):
        """The first put() pins the effective modes so later default changes don't alter the deployment.
        REQ: CFG-01
        """
        rc.put({"interval_minutes": 30}, "a")
        with store.connect() as c:
            stored = json.loads(c.execute("SELECT v FROM meta WHERE k=?", (rc.KEY,)).fetchone()[0])
        self.assertEqual(stored["modes"], rc.DEFAULT_MODES)
        self.assertEqual(rc.get()["modes"], rc.DEFAULT_MODES)

    def test_explicit_web_research_off_persists(self):
        """Explicitly switching web research off is stored and read back as off.
        REQ: CFG-01
        """
        rc.put({"web_research": False}, "a")
        self.assertFalse(rc.get()["web_research"])

    @unittest.expectedFailure
    def test_first_unrelated_put_keeps_web_research_off(self):
        """KNOWN BUG: on a new deployment (web_research default False) saving any other setting, e.g. the interval,
        silently turns web research ON, because get() treats any stored settings without a web_research key as a
        pre-option deployment (default True) and put() does not pin web_research the way it pins modes.
        REQ: CFG-01
        """
        self.assertFalse(rc.get()["web_research"])
        rc.put({"interval_minutes": 30}, "a")
        self.assertFalse(rc.get()["web_research"])

    def test_put_modes_validation(self):
        """put(modes=...) merges valid modes, rejects unknown categories/modes and an all-skip configuration.
        REQ: CFG-01
        """
        g = rc.put({"modes": {"high": "research", "low": "review"}}, "a")
        self.assertEqual((g["modes"]["high"], g["modes"]["low"], g["modes"]["host"]), ("research", "review", "test"))
        self.assertEqual(g["severities"], ["high", "low"])
        for bad in ({"nope": "research"}, {"high": "maybe"}, ["high"]):
            with self.assertRaises(ValueError):
                rc.put({"modes": bad}, "a")
        with self.assertRaises(ValueError):
            rc.put({"modes": {k: "skip" for k in rc.DEFAULT_MODES}}, "a")

    def test_put_legacy_severities(self):
        """The legacy severities field sets severity categories to research/skip and leaves others alone.
        REQ: CFG-01
        """
        g = rc.put({"severities": ["info"]}, "a")
        self.assertEqual([g["modes"][s] for s in rc.SEVERITIES], ["skip", "skip", "skip", "research"])
        self.assertEqual(g["modes"]["host"], "test")
        self.assertEqual(g["severities"], ["info"])

    def test_put_check_model(self):
        """A provider/model change is validated by check_model; failing validation raises and saves nothing.
        REQ: CFG-01
        """
        seen = []
        rc.put({"provider": "api:x", "model": "good"}, "a", check_model=lambda p, m: seen.append((p, m)) or True)
        self.assertEqual(seen, [("api:x", "good")])
        with self.assertRaises(ValueError):
            rc.put({"model": "bad"}, "a", check_model=lambda p, m: False)
        self.assertEqual(rc.get()["model"], "good")
        rc.put({"interval_minutes": 60}, "a", check_model=lambda p, m: False)  # no model change: not checked

    def test_slot_grid(self):
        """Slots form a grid of interval minutes anchored at 05:00 UTC; next_run is the next slot start or None when disabled.
        REQ: OPS-03
        """
        day = dt.datetime(2026, 1, 5, tzinfo=dt.timezone.utc).timestamp()
        at5 = day + 5 * 3600
        self.assertEqual(rc.slot(at5, 60), rc.slot(at5 + 3599, 60))
        self.assertEqual(rc.slot(at5, 60) + 1, rc.slot(at5 + 3600, 60))
        self.assertEqual(rc.slot_start(rc.slot(at5 + 100, 60), 60), at5)
        self.assertEqual(rc.slot_start(0, 240), 5 * 3600)
        rc.put({"interval_minutes": 240}, "a")
        self.assertEqual(rc.next_run(at5 + 1), at5 + 4 * 3600)
        self.assertEqual(rc.next_run(at5), at5 + 4 * 3600)
        self.assertEqual(rc.slot(at5), rc.slot(at5, 240))
        rc.put({"enabled": False}, "a")
        self.assertIsNone(rc.next_run(at5))

    def test_requests(self):
        """request() queues a run, pending_request() shows it and take_request() returns it once and clears it.
        REQ: OPS-03
        """
        self.assertIsNone(rc.pending_request())
        self.assertIsNone(rc.take_request())
        rc.request("u" * 80)
        self.assertEqual(rc.pending_request()["by"], "u" * 64)
        self.assertEqual(rc.take_request()["by"], "u" * 64)
        self.assertIsNone(rc.take_request())

    def test_status_and_spent_today(self):
        """write_status/status round-trip and spent_today sums only today's (UTC) run costs.
        REQ: STO-01
        """
        path = os.path.join(_env.TMP, "research_job_test.json")
        with mock.patch.object(rc, "STATUS", path):
            self.assertEqual(rc.status(), {})
            self.assertEqual(rc.spent_today(), 0)
            now = time.time()
            rc.write_status({"usage": [{"at": now, "cost_usd": 1.5}, {"at": now, "cost_usd": None},
                                       {"at": now - 3 * 86400, "cost_usd": 9}, {"cost_usd": 4}]})
            self.assertEqual(rc.status()["usage"][0]["cost_usd"], 1.5)
            self.assertEqual(rc.spent_today(), 1.5)
        if os.path.exists(path):
            os.remove(path)


if __name__ == "__main__":
    unittest.main()
