"""Unit tests for the config helpers: site_cfg.py, window.py, lookback.py, review_cfg.py, research_cfg.py."""
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); import _env  # noqa: E401,E402

import datetime as dt  # noqa: E402
import json  # noqa: E402
import time  # noqa: E402
import unittest  # noqa: E402
from unittest import mock  # noqa: E402

import lookback  # noqa: E402
import research_cfg as rc  # noqa: E402
import review_cfg as vc  # noqa: E402
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
        c.execute("DELETE FROM meta WHERE k IN (?, ?, ?, ?, ?, ?)", (lookback.KEY, lookback._OLD_KEY, rc.KEY, vc.KEY, vc.REQ, vc._OLD_REQ))


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


class TestArrivalWindow(unittest.TestCase):
    """window arrival mode: select by event.ingested with a per-job bookmark so late events are never missed."""

    def setUp(self):
        _env.fresh_db()
        import store
        with store.connect() as c:  # fresh_db keeps meta: drop the bookmarks and lag stats
            c.execute("DELETE FROM meta WHERE k LIKE 'arrival:%' OR k='ingest_lag'")
        self._old = os.environ.pop("NETMON_WINDOW_END", None)
        window.off()

    def tearDown(self):
        window.off()
        if self._old is not None:
            os.environ["NETMON_WINDOW_END"] = self._old

    @staticmethod
    def span(f):
        r = f["bool"]["should"][0]["range"]["event.ingested"]
        return r["gt"], r["lte"]

    def test_first_run_uses_nominal_span_ending_before_now(self):
        """First run: (now - margin - N min, now - margin] on event.ingested; docs without it fall back to @timestamp.
        REQ: CFG-05"""
        w = window.arrival("watch", 20, now=1_800_000_000)
        to = 1_800_000_000 - window.ARRIVAL_MARGIN_S
        self.assertTrue(w["first_run"])
        f = window.since(20)
        self.assertEqual(self.span(f), (window._iso(to - 1200), window._iso(to)))
        fb = f["bool"]["should"][1]["bool"]
        self.assertEqual(fb["must_not"], [{"exists": {"field": "event.ingested"}}])
        self.assertEqual(fb["filter"][0]["range"]["@timestamp"], {"gt": window._iso(to - 1200), "lte": window._iso(to)})

    def test_windows_touch_end_to_end(self):
        """After commit the next watcher window starts exactly where the last one ended (no gap, no overlap),
        however long the gap between runs was.
        REQ: CFG-05"""
        window.arrival("watch", 20, now=1_800_000_000)
        end1 = self.span(window.since(20))[1]
        window.commit()
        window.arrival("watch", 20, now=1_800_000_000 + 3 * 3600)  # scheduler paused 3 h
        a, b = self.span(window.since(20))
        self.assertEqual(a, end1)
        self.assertEqual(b, window._iso(1_800_000_000 + 3 * 3600 - window.ARRIVAL_MARGIN_S))

    def test_uncommitted_window_is_covered_again(self):
        """Without commit (a failed run) the next window starts at the old bookmark again.
        REQ: CFG-05"""
        window.arrival("watch", 20, now=1_800_000_000)
        window.commit()
        start = self.span(window.since(20))[1]
        window.arrival("watch", 20, now=1_800_000_900)  # failed run, never committed
        window.arrival("watch", 20, now=1_800_001_800)
        self.assertEqual(self.span(window.since(20))[0], start)

    def test_review_overlap_keeps_lookback(self):
        """overlap=True (review job): from = min(bookmark, to - lookback), so its usual lookback overlap stays.
        REQ: CFG-05"""
        window.arrival("review", 120, overlap=True, now=1_800_000_000)
        window.commit()
        window.arrival("review", 120, overlap=True, now=1_800_000_900)
        a, b = self.span(window.since_h(2))
        self.assertEqual(a, window._iso(1_800_000_900 - window.ARRIVAL_MARGIN_S - 7200))

    def test_other_spans_cover_the_job_window(self):
        """A since() with another span never starts after the job window (e.g. the 60-min DNS-tunnel check).
        REQ: CFG-05"""
        window.arrival("watch", 20, now=1_800_000_000)
        window.commit()
        window.arrival("watch", 20, now=1_800_000_000 + 7200)
        job_from = self.span(window.since(20))[0]
        self.assertEqual(self.span(window.since(60))[0], job_from)  # 2 h window > 60 min
        self.assertEqual(self.span(window.since(600))[0], window._iso(1_800_000_000 + 7200 - window.ARRIVAL_MARGIN_S - 36000))

    def test_catchup_capped(self):
        """A bookmark older than MAX_CATCHUP_H restarts at now - MAX_CATCHUP_H.
        REQ: CFG-05"""
        window.arrival("watch", 20, now=1_000_000)
        window.commit()
        now = 1_000_000 + 30 * 86400
        window.arrival("watch", 20, now=now)
        self.assertEqual(self.span(window.since(20))[0], window._iso(now - window.ARRIVAL_MARGIN_S - window.MAX_CATCHUP_H * 3600))

    def test_time_range_stays_event_time(self):
        """A dashboard time range (NETMON_WINDOW_END) always selects by @timestamp, even in arrival mode.
        REQ: CFG-05"""
        window.arrival("watch", 20)
        os.environ["NETMON_WINDOW_END"] = "2026-01-05T12:00:00Z"
        try:
            self.assertIn("range", window.since(60))
        finally:
            os.environ.pop("NETMON_WINDOW_END")

    def test_manual_run_never_commits(self):
        """job None (manual collect.py N) neither reads nor writes a bookmark.
        REQ: CFG-05"""
        window.arrival(None, 60)
        self.assertFalse(window.commit())
        self.assertIsNone(window.bookmark("None"))

    def test_lag_stats_shape_and_errors(self):
        """lag_stats reports n / late / percentiles per source and a per-source error instead of raising.
        REQ: CFG-05"""
        window.arrival("watch", 20)

        def q(ix, body):
            if ix.startswith("logs-zeek"):
                raise RuntimeError("no index")
            return {"hits": {"total": {"value": 5}}, "aggregations": {"lag": {"values": {"50.0": 7200.0, "99.0": 9000.0}},
                                                                       "mx": {"value": 9100.0}, "late": {"doc_count": 5},
                                                                       "newest": {"value_as_string": "2026-11-06T23:00:00Z"}}}
        st = window.lag_stats(q)
        self.assertIn("error", st["zeek"])
        self.assertEqual(st["suricata"], {"n": 5, "late": 5, "p50_s": 7200.0, "p99_s": 9000.0, "max_s": 9100.0, "newest_event": "2026-11-06T23:00:00Z"})
        window.save_lag(st)
        self.assertEqual(window.load_lag()["sources"]["suricata"]["late"], 5)


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
        self.assertEqual(g, {"hours": 24, "by": None, "at": None, "default": 24, "min": 1, "max": 24, "daily_hour": 5})

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
        """The 05 UTC daily run always uses 24 h; other hours use the setting and say whether it is configured.
        REQ: CFG-02, OPS-03
        """
        self.assertEqual(lookback.for_run(10), (24, "default"))
        lookback.put(4, "a")
        self.assertEqual(lookback.for_run(5), (24, "daily run: always 24 h"))
        self.assertEqual(lookback.for_run(10), (4, "configured on the AI review page"))
        self.assertIn(lookback.for_run()[0], (4, 24))


class TestReviewCfg(unittest.TestCase):
    """review_cfg: review job schedule, on/off, event modes and Run now requests."""

    def setUp(self):
        _env.fresh_db()
        _clean_meta()

    def tearDown(self):
        _clean_meta()
        _env.fresh_db()

    def test_fresh_defaults(self):
        """A new deployment gets every category in test mode, 240 min, enabled, no severities.
        REQ: CFG-01
        """
        g = vc.get()
        self.assertEqual(g["interval_minutes"], 240)
        self.assertTrue(g["enabled"])
        self.assertEqual(set(g["modes"].values()), {"test"})
        self.assertEqual(set(g["modes"]), {k for k, _ in vc.MODE_CATS})
        self.assertEqual(g["severities"], [])
        self.assertEqual(g["daily_hour"], 5)
        self.assertNotIn("research", g["mode_options"])

    def test_migrates_from_combined_research_record(self):
        """Settings saved before the review / research split (one research_job record) are read: schedule, on/off and
        modes, with the old "research" mode becoming "queue"; a record without modes keeps the legacy modes.
        REQ: CFG-01
        """
        _meta_raw(vc._OLD_KEY, {"model": "m"})
        self.assertEqual(vc.get()["modes"], vc.LEGACY_MODES)
        _meta_raw(vc._OLD_KEY, {"interval_minutes": 15, "enabled": False, "modes": {"host": "research", "ids12": "review", "low": "skip"}})
        g = vc.get()
        self.assertEqual((g["interval_minutes"], g["enabled"]), (15, False))
        self.assertEqual((g["modes"]["host"], g["modes"]["ids12"], g["modes"]["low"]), ("queue", "review", "skip"))

    def test_legacy_severities_and_seg_split(self):
        """A legacy severities list maps to queue/skip; an old single 'seg' mode is applied to all three seg categories.
        REQ: CFG-01
        """
        _meta_raw(vc.KEY, {"severities": ["low"]})
        m = vc.get()["modes"]
        self.assertEqual((m["high"], m["low"], m["info"]), ("skip", "queue", "skip"))
        _meta_raw(vc.KEY, {"modes": {"seg": "review", "seg_low": "skip", "bogus": "queue", "host": "nonsense"}})
        m = vc.get()["modes"]
        self.assertEqual((m["seg_high"], m["seg_medium"], m["seg_low"]), ("review", "review", "skip"))
        self.assertNotIn("bogus", m)
        self.assertEqual(m["host"], "queue")

    def test_put_validates(self):
        """put() coerces, range-checks the interval, merges valid modes, maps "research" to "queue" and refuses all-skip.
        REQ: CFG-01
        """
        g = vc.put({"interval_minutes": "60", "enabled": 0, "bogus": 1}, "admin")
        self.assertEqual((g["interval_minutes"], g["enabled"], g["by"]), (60, False, "admin"))
        self.assertNotIn("bogus", g)
        for bad in ({"interval_minutes": 4}, {"interval_minutes": "x"}, {"modes": {"nope": "queue"}}, {"modes": {"high": "maybe"}},
                    {"modes": {k: "skip" for k in vc.DEFAULT_MODES}}):
            with self.assertRaises(ValueError, msg=bad):
                vc.put(bad, "a")
        g = vc.put({"modes": {"high": "research", "low": "review"}}, "a")
        self.assertEqual((g["modes"]["high"], g["modes"]["low"], g["modes"]["host"]), ("queue", "review", "test"))

    def test_put_pins_modes(self):
        """The first put() pins the effective modes so later default changes don't alter the deployment.
        REQ: CFG-01
        """
        vc.put({"interval_minutes": 30}, "a")
        with store.connect() as c:
            stored = json.loads(c.execute("SELECT v FROM meta WHERE k=?", (vc.KEY,)).fetchone()[0])
        self.assertEqual(stored["modes"], vc.DEFAULT_MODES)

    def test_slot_grid(self):
        """Slots form a grid of interval minutes anchored at 05:00 UTC; next_run is the next slot start or None when disabled.
        REQ: OPS-03
        """
        day = dt.datetime(2026, 1, 5, tzinfo=dt.timezone.utc).timestamp()
        at5 = day + 5 * 3600
        self.assertEqual(vc.slot(at5, 60), vc.slot(at5 + 3599, 60))
        self.assertEqual(vc.slot(at5, 60) + 1, vc.slot(at5 + 3600, 60))
        self.assertEqual(vc.slot_start(vc.slot(at5 + 100, 60), 60), at5)
        vc.put({"interval_minutes": 240}, "a")
        self.assertEqual(vc.next_run(at5 + 1), at5 + 4 * 3600)
        vc.put({"enabled": False}, "a")
        self.assertIsNone(vc.next_run(at5))

    def test_requests(self):
        """request() queues a run, pending_request() shows it and take_request() returns it once and clears it.
        REQ: OPS-03
        """
        self.assertIsNone(vc.pending_request())
        vc.request("u" * 80)
        self.assertEqual(vc.pending_request()["by"], "u" * 64)
        self.assertEqual(vc.take_request()["by"], "u" * 64)
        self.assertIsNone(vc.take_request())

    def test_status_reads_old_review_runs(self):
        """Before review_job.json exists, status() takes the review runs from the old research_job.json, without research usage.
        REQ: STO-01
        """
        new, old = os.path.join(_env.TMP, "review_job_t.json"), os.path.join(_env.TMP, vc._OLD_STATUS)
        store.jdump({"runs": [{"status": "completed"}], "usage": [{"cost_usd": 0}, {"cost_usd": 1, "event_run": True}], "researched": [1]}, old)
        with mock.patch.object(vc, "STATUS", new), mock.patch.object(vc, "STATE", _env.TMP):
            d = vc.status()
            self.assertEqual(d["runs"], [{"status": "completed"}])
            self.assertEqual(d["usage"], [{"cost_usd": 0}])
            self.assertNotIn("researched", d)
            vc.write_status({"runs": []})
            self.assertEqual(vc.status(), {"runs": []})


class TestResearchCfg(unittest.TestCase):
    """research_cfg: event research (Send to research) model, cost caps, web / Elasticsearch access."""

    def setUp(self):
        _env.fresh_db()
        _clean_meta()

    def tearDown(self):
        _clean_meta()
        _env.fresh_db()

    def test_fresh_defaults_have_no_schedule(self):
        """A new deployment has web access off, no model and no schedule / run-request settings at all.
        REQ: CFG-01, OPS-06
        """
        g = rc.get()
        self.assertFalse(g["web_research"])
        self.assertEqual(g["model"], "")
        for k in ("interval_minutes", "enabled", "modes"):
            self.assertNotIn(k, g)
        self.assertFalse(hasattr(rc, "request") or hasattr(rc, "next_run"))

    def test_existing_deployment_keeps_web_research(self):
        """Settings saved before web_research existed read back with web research on.
        REQ: CFG-01
        """
        _meta_raw(rc.KEY, {"model": "m"})
        self.assertTrue(rc.get()["web_research"])

    def test_saving_on_new_install_keeps_web_off(self):
        """Saving another research setting on a new install does not switch web access on.
        REQ: CFG-01
        """
        rc.put({"max_batches": 2}, "a")
        self.assertFalse(rc.get()["web_research"])

    def test_get_clamps_invalid_stored_limits(self):
        """Stored numbers outside LIMITS or of the wrong type read back as the defaults.
        REQ: CFG-01
        """
        _meta_raw(rc.KEY, {"max_batches": "x", "max_run_usd": "7.5", "max_searches": None})
        g = rc.get()
        self.assertEqual((g["max_batches"], g["max_run_usd"], g["max_searches"]), (10, 7.5, 3))

    def test_put_validates_and_coerces(self):
        """put() coerces numbers and booleans, truncates provider/model, ignores unknown keys and records the author.
        REQ: CFG-01
        """
        g = rc.put({"model": "m" * 200, "max_run_usd": 2, "web_research": 0, "interval_minutes": 5, "bogus": 1}, "admin")
        self.assertEqual(len(g["model"]), 120)
        self.assertIsInstance(g["max_run_usd"], float)
        self.assertFalse(g["web_research"])
        self.assertNotIn("bogus", g)
        self.assertNotIn("interval_minutes", g)
        self.assertEqual(g["by"], "admin")
        for bad in ({"max_batches": 41}, {"max_day_usd": -1}, {"max_run_tokens": "x"}):
            with self.assertRaises(ValueError, msg=bad):
                rc.put(bad, "a")

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
        rc.put({"max_batches": 2}, "a", check_model=lambda p, m: False)  # no model change: not checked

    def test_status_and_spent_today(self):
        """write_status/status round-trip and spent_today sums only today's (UTC) research costs.
        REQ: STO-01
        """
        path = os.path.join(_env.TMP, "research_job_test.json")
        with mock.patch.object(rc, "STATUS", path):
            self.assertEqual(rc.status(), {})
            self.assertEqual(rc.spent_today(), 0)
            now = time.time()
            rc.write_status({"usage": [{"at": now, "cost_usd": 1.5, "event_run": True}, {"at": now, "cost_usd": 7},
                                       {"at": now, "cost_usd": None, "event_run": True}, {"at": now - 3 * 86400, "cost_usd": 9, "event_run": True}]})
            self.assertEqual(rc.spent_today(), 1.5)
        if os.path.exists(path):
            os.remove(path)


if __name__ == "__main__":
    unittest.main()
