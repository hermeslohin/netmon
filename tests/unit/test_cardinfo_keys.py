"""Static checks: every top-level box title on the AI pipeline and Alerts pages has an info (ⓘ) text in cardinfo.js."""
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); import _env  # noqa: E401,E402

import re  # noqa: E402
import unittest  # noqa: E402

STATIC = os.path.join(_env.APP, "static")


def _read(name):
    with open(os.path.join(STATIC, name), encoding="utf-8") as f:
        return f.read()


def norm(title):
    """Python model of cardinfo_ui.js norm(): drop (...) and numbers, squeeze spaces, strip trailing ' · | :', cap 80."""
    t = re.sub(r"\(.*?\)|\d[\d,.]*", "", title)
    t = re.sub(r"\s+", " ", t)
    t = re.sub(r"[\s·|:]+$", "", t)
    return t.strip()[:80]


def info_keys():
    return set(re.findall(r'^"([a-z]+\|[^"]*)"\s*:', _read("cardinfo.js"), re.M))


def lookup(keys, view, title):
    """cardinfo_ui.js lookup(): view|title, then the same title on any page (None = generic fallback text)."""
    t = norm(title)
    if f"{view}|{t}" in keys:
        return f"{view}|{t}"
    return next((k for k in sorted(keys) if k.split("|", 1)[1] == t), None)


def part_titles():
    m = re.search(r"const PART = \[(.*?)\];", _read("aireview.js"), re.S)
    return re.findall(r'\["[^"]+",\s*"([^"]+)"\]', m.group(1)) if m else []


class CardInfoKeysTest(unittest.TestCase):
    """cardinfo.js keys match the box titles the pages render."""

    def test_norm_model(self):
        """The title normalisation drops counts in brackets, numbers and trailing separators like the browser does.
        REQ: FEAT-10"""
        self.assertEqual(norm("Decisions (1,234, newest 3,000)"), "Decisions")
        self.assertEqual(norm("Review log ·"), "Review log")
        self.assertEqual(norm("Queue:  events  without a note"), "Queue: events without a note")

    def test_ai_pipeline_parts_have_info(self):
        """Both AI pipeline pages show four part boxes (Models, Correlation review, Event review, Research review) and each
        has its own ⓘ key on monitoring (aireview|) and configuration (aiconfig|).
        REQ: FEAT-10"""
        parts = part_titles()
        self.assertEqual(parts, ["Models", "Correlation review", "Event review", "Research review"])
        keys = info_keys()
        for view in ("aireview", "aiconfig"):
            for t in parts:
                self.assertIn(f"{view}|{norm(t)}", keys, f"missing cardinfo key {view}|{t}")

    def test_info_entries_have_three_texts(self):
        """Every AI pipeline ⓘ entry has what, source and use texts.
        REQ: FEAT-10"""
        js = _read("cardinfo.js")
        for k in sorted(info_keys()):
            if not k.startswith(("aireview|", "aiconfig|")):
                continue
            body = js.split(f'"{k}":', 1)[1].split("}", 1)[0]
            for f in ("what", "source", "use"):
                self.assertRegex(body, rf'"{f}"\s*:\s*"[^"]+', f"{k} lacks {f}")

    def test_parts_built_by_consolidate(self):
        """Both AI pipeline page builders end by folding their boxes into the part boxes (so only part titles get ⓘ buttons).
        REQ: FEAT-10"""
        js = _read("aireview.js")
        for fn in ("const buildCfg = async", "const build = async"):
            body = js.split(fn, 1)[1].split("\n  };", 1)[0]
            self.assertEqual(len(re.findall(r"partHead\(el, \d", body)), 4, fn)
            self.assertIn("consolidate(el)", body, fn)

    def test_detections_by_verdict_has_info(self):
        """The new Alerts box "Detections by verdict" has its own ⓘ text instead of the generic fallback.
        REQ: FEAT-11"""
        self.assertIn("Detections by verdict", _read("alerts.js"))
        self.assertIsNotNone(lookup(info_keys(), "alerts", "Detections by verdict (12)"))

    def test_auto_close_has_info(self):
        """The Configuration page box "Auto-close" (renamed from Security Triage) has its ⓘ text.
        REQ: FEAT-11"""
        self.assertIn('card("Auto-close"', _read("config.js"))
        self.assertIsNotNone(lookup(info_keys(), "config", "Auto-close"))

    def test_recent_alerts_has_info(self):
        """The Alerts page's main box (Recent alerts with its count) resolves to its ⓘ text.
        REQ: FEAT-11"""
        self.assertEqual(lookup(info_keys(), "alerts", "Recent alerts (12, 3 new)"), "alerts|Recent alerts")


if __name__ == "__main__":
    unittest.main()
