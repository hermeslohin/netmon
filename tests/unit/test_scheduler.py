"""Unit tests for the scheduler's time/slot computations (scheduler.py, research_cfg.py); no jobs are started."""
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); import _env  # noqa: E402

import time  # noqa: E402
import unittest  # noqa: E402
from datetime import datetime, timezone  # noqa: E402

import research_cfg as RC  # noqa: E402
import scheduler  # noqa: E402


def ts(*a):
    return datetime(*a, tzinfo=timezone.utc).timestamp()


class SlotTest(unittest.TestCase):
    """research_cfg.slot()/slot_start(): a grid of interval minutes anchored at 05:00 UTC."""

    def test_anchor_is_slot_zero(self):
        """05:00 UTC on 1970-01-01 starts slot 0 for any interval.
        REQ: OPS-03"""
        for iv in (5, 60, 240, 1440):
            self.assertEqual(RC.slot(5 * 3600, iv), 0)
            self.assertEqual(RC.slot_start(0, iv), 5 * 3600)

    def test_slot_boundaries(self):
        """A time exactly on a boundary belongs to the new slot; one second earlier to the previous one.
        REQ: OPS-03"""
        b = ts(2026, 1, 5, 9, 0)  # 05:00 + 240 min
        self.assertEqual(RC.slot(b, 240), RC.slot(b - 1, 240) + 1)
        self.assertEqual(RC.slot_start(RC.slot(b, 240), 240), b)

    def test_slot_start_is_floor(self):
        """slot_start(slot(t)) is the latest grid point at or before t.
        REQ: OPS-03"""
        for t in (ts(2026, 1, 5, 0, 0), ts(2026, 1, 5, 4, 59), ts(2026, 1, 5, 5, 0), ts(2026, 3, 1, 13, 37, 12)):
            for iv in (5, 15, 240, 1440):
                st = RC.slot_start(RC.slot(t, iv), iv)
                self.assertLessEqual(st, t)
                self.assertLess(t - st, iv * 60)

    def test_daily_grid_lands_on_0500(self):
        """With a 1440-minute interval every slot starts at 05:00 UTC.
        REQ: OPS-03"""
        st = RC.slot_start(RC.slot(ts(2026, 6, 10, 3, 0), 1440), 1440)
        self.assertEqual(datetime.fromtimestamp(st, timezone.utc), datetime(2026, 6, 9, 5, 0, tzinfo=timezone.utc))

    def test_four_hour_grid_times(self):
        """A 240-minute grid runs at 01, 05, 09, 13, 17, 21 UTC.
        REQ: OPS-03"""
        hours = set()
        t = ts(2026, 1, 5, 0, 30)
        for _ in range(12):
            n = RC.slot(t, 240) + 1
            st = RC.slot_start(n, 240)
            hours.add(datetime.fromtimestamp(st, timezone.utc).hour)
            t = st
        self.assertEqual(hours, {1, 5, 9, 13, 17, 21})

    def test_slot_before_anchor_is_negative(self):
        """Times before the 1970 anchor give negative slot numbers (floor division), not slot 0.
        REQ: OPS-03"""
        self.assertEqual(RC.slot(0, 60), -5)
        self.assertEqual(RC.slot_start(-5, 60), 0)


class NextRunTest(unittest.TestCase):
    """research_cfg.next_run() follows the stored interval and enabled flag."""

    def tearDown(self):
        RC._meta_put(RC.KEY, None)

    def test_default_interval(self):
        """With no settings the job is enabled at 240 minutes and next_run is the next grid point.
        REQ: OPS-03"""
        RC._meta_put(RC.KEY, None)
        cfg = RC.get()
        self.assertTrue(cfg["enabled"])
        self.assertEqual(cfg["interval_minutes"], 240)
        self.assertEqual(RC.next_run(ts(2026, 1, 5, 6, 0)), ts(2026, 1, 5, 9, 0))
        self.assertEqual(RC.next_run(ts(2026, 1, 5, 9, 0)), ts(2026, 1, 5, 13, 0))

    def test_custom_interval_and_disabled(self):
        """A stored 30-minute interval moves the next run; disabling the job gives None.
        REQ: OPS-03"""
        RC._meta_put(RC.KEY, {"interval_minutes": 30})
        self.assertEqual(RC.next_run(ts(2026, 1, 5, 6, 10)), ts(2026, 1, 5, 6, 30))
        RC._meta_put(RC.KEY, {"interval_minutes": 30, "enabled": False})
        self.assertIsNone(RC.next_run(ts(2026, 1, 5, 6, 10)))

    def test_out_of_range_interval_falls_back(self):
        """An interval outside 5..1440 minutes (or not a number) falls back to the default 240.
        REQ: OPS-03"""
        for bad in (1, 5000, "abc"):
            RC._meta_put(RC.KEY, {"interval_minutes": bad})
            self.assertEqual(RC.get()["interval_minutes"], 240, bad)

    def test_put_rejects_bad_interval(self):
        """put() refuses an interval outside the allowed range.
        REQ: OPS-03"""
        with self.assertRaises(ValueError):
            RC.put({"interval_minutes": 2}, "tester")
        RC.put({"interval_minutes": 60}, "tester")
        self.assertEqual(RC.get()["interval_minutes"], 60)

    def test_slot_uses_stored_interval_when_omitted(self):
        """slot() without an interval uses the stored setting.
        REQ: OPS-03"""
        RC._meta_put(RC.KEY, {"interval_minutes": 60})
        t = ts(2026, 1, 5, 7, 30)
        self.assertEqual(RC.slot(t), RC.slot(t, 60))


class SchedulerStatusTest(unittest.TestCase):
    """scheduler.status(): next watcher slot and weekly rebuild time (pure computations, no jobs)."""

    def tearDown(self):
        RC._meta_put(RC.KEY, None)

    def test_jobs_defined(self):
        """The watch, research, weekly and unifi jobs are configured with the expected scripts.
        REQ: OPS-03"""
        self.assertEqual(set(scheduler.JOBS), {"watch", "research", "weekly", "unifi"})
        self.assertTrue(scheduler.JOBS["watch"][-1].endswith("watch.py"))
        self.assertIn("review.py", scheduler.JOBS["research"][1])
        self.assertTrue(scheduler.JOBS["weekly"][0].endswith("weekly_rebuild.sh"))
        self.assertEqual(scheduler.running, {})

    def test_status_watch_next_quarter_hour(self):
        """The next watcher run is the next 15-minute boundary, within 15 minutes from now.
        REQ: OPS-03"""
        before = time.time()
        s = scheduler.status()
        self.assertEqual(s["watch"] % 900, 0)
        self.assertGreater(s["watch"], before)
        self.assertLessEqual(s["watch"] - before, 900)

    def test_status_weekly_is_next_sunday_0300(self):
        """The weekly rebuild is the next Sunday 03:00 UTC, in the future and at most 7 days away.
        REQ: OPS-03"""
        now = time.time()
        s = scheduler.status()
        w = datetime.fromtimestamp(s["weekly"], timezone.utc)
        self.assertEqual((w.weekday(), w.hour, w.minute, w.second), (6, 3, 0, 0))
        self.assertGreater(s["weekly"], now)
        self.assertLessEqual(s["weekly"] - now, 7 * 86400)

    def test_status_research_fields(self):
        """status() reports the research next run, interval and enabled flag from research_cfg.
        REQ: OPS-03"""
        RC._meta_put(RC.KEY, {"interval_minutes": 60})
        s = scheduler.status()
        self.assertEqual(s["research_interval_minutes"], 60)
        self.assertTrue(s["research_enabled"])
        self.assertEqual((s["research"] - 5 * 3600) % 3600, 0)
        self.assertIsInstance(s["last"], dict)

    def test_week_key_format(self):
        """The weekly once-per-week key (ISO year-week) is identical all Sunday and changes the next week.
        REQ: OPS-03"""
        k = lambda t: datetime.fromtimestamp(t, timezone.utc).strftime("%G-W%V")  # noqa: E731 - same format as tick()
        sun = ts(2026, 1, 4, 3, 10)
        self.assertEqual(datetime.fromtimestamp(sun, timezone.utc).weekday(), 6)
        self.assertEqual(k(sun), k(ts(2026, 1, 4, 3, 59)))
        self.assertNotEqual(k(sun), k(sun + 7 * 86400))

    def test_watch_and_unifi_slot_numbers(self):
        """The watcher slot (now // 900) and UniFi slot (now // 300) change exactly on their boundaries.
        REQ: OPS-03"""
        b = ts(2026, 1, 5, 10, 15)
        self.assertEqual(int(b // 900), int((b - 1) // 900) + 1)
        self.assertEqual(int((b + 899) // 900), int(b // 900))
        self.assertEqual(int(b // 300), int((b - 1) // 300) + 1)


if __name__ == "__main__":
    unittest.main()
