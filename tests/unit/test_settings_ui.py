"""Unit tests for small Settings / theme UI pieces: the learned host name in the device classes editor (settings.js
learnedHost) and the gold suppress button style (style.css + the row templates)."""
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); import _env  # noqa: E401,E702,E402

import json  # noqa: E402
import re  # noqa: E402
import shutil  # noqa: E402
import subprocess  # noqa: E402
import unittest  # noqa: E402

import fixtures as F  # noqa: E402

NODE_FALLBACK = os.path.expanduser(os.environ.get("NETMON_NODE", "~/.hermes/tools/node-26.7.0-linux-arm64/bin/node"))
NODE = shutil.which("node") or (NODE_FALLBACK if os.path.exists(NODE_FALLBACK) else None)
STATIC = os.path.join(_env.APP, "static")


def _read(name):
    with open(os.path.join(STATIC, name), encoding="utf-8") as f:
        return f.read()


@unittest.skipUnless(NODE, "node not available")
class LearnedHostName(unittest.TestCase):
    def run_learned(self, cases):
        src = _read("settings.js")
        i = src.index("const learnedHost = ")
        fn = src[i:src.index("window.learnedHost", i)]
        body = fn + "\nconsole.log(JSON.stringify(" + json.dumps(cases) + ".map((c) => learnedHost(c[0], c[1], c[2], c[3] ? (k) => c[3][k] : null))));"
        r = subprocess.run([NODE, "-"], input=body, capture_output=True, text=True, timeout=30)  # noqa: S603 - node on repo code
        if r.returncode:
            raise RuntimeError(r.stderr[-2000:])
        return json.loads(r.stdout)

    def test_learned_host_name_lookup_order(self):
        """learnedHost finds the name by registry key / MAC / IP, prefers the learned host name, falls back to the
        range's devices and the page's name lookup, and returns "" when nothing was learned (the page shows —).
        REQ: SET-71"""
        mac = F.mac(0x10)
        reg = {mac: {"mac": mac, "ips": ["192.0.2.10"], "hostname": "study-laptop", "name": "Study laptop"},
               "k2": {"mac": F.mac(0x11), "ips": ["192.0.2.11"], "hostname": "", "name": "Kitchen tablet"}}
        devs = {"192.0.2.20": {"mac": F.mac(0x20), "hostname": "porch-cam"}}
        out = self.run_learned([
            [mac.upper(), reg, devs, None],          # MAC key, case-insensitive -> hostname
            ["192.0.2.10", reg, devs, None],         # IP key via the registry's ips
            [F.mac(0x11), reg, devs, None],  # no hostname -> registry name
            [F.mac(0x20), reg, devs, None],  # range devices by MAC
            ["192.0.2.30", reg, devs, {"192.0.2.30": "Office printer"}],  # page name lookup
            ["192.0.2.99", reg, devs, None],         # nothing learned
            ["", reg, devs, None],
        ])
        self.assertEqual(out, ["study-laptop", "study-laptop", "Kitchen tablet", "porch-cam", "Office printer", "", ""])

    def test_editor_shows_learned_text_display_only_and_filterable(self):
        """The device_classes rows render 'learned: <name>' or 'learned: —' next to the key, the filter reads the
        .cfg-learned text, and the learned name is never part of the saved value (get() reads only the inputs).
        REQ: SET-71"""
        src = _read("settings.js")
        self.assertIn('"learned: " + (learnedHost(', src)
        self.assertIn('|| "—")', src)
        self.assertIn('key === "device_classes" && !r.ro ? learnedEl(k)', src)
        self.assertRegex(src, r'querySelectorAll\("\.cfg-learned"\)\]\.map\(\(x\) => x\.textContent\)')
        self.assertNotRegex(src, r"cfg-learned[^\n]*\.get\(")


class SuppressButtonGold(unittest.TestCase):
    def test_suppress_button_uses_the_gold_action_style(self):
        """Every suppress button template carries the line ban icon (no emoji glyph as content), and style.css styles
        .sup-btn / .mute-sup with the same gold variables as the note buttons, plus hover, active and disabled states.
        REQ: UI-90"""
        css = _read("style.css")
        shared = re.search(r"^\.unote-btn,\.extnote-btn,([^{]*)\{color:var\(--gold\)", css, re.M)
        self.assertTrue(shared, "shared gold rule missing")
        self.assertIn(".sup-btn", shared.group(1))
        self.assertIn(".mute-sup", shared.group(1))
        for state in (".sup-btn:hover", ".sup-btn:active", ".sup-btn:disabled", ".sup-btn:focus-visible"):
            self.assertIn(state, css)
        self.assertIn(".ic-ban{--i:url(", css)
        n = 0
        for f in ("app.js", "openevents.js", "related.js"):
            js = _read(f)
            for m in re.finditer(r'<button type="button" class="(?:sup-btn|mute-btn mute-sup)[^`]*?</button>', js):
                n += 1
                self.assertIn('<i class="ic ic-ban"', m.group(0), f)
                self.assertNotIn(">🚫</button>", m.group(0), f)
        self.assertGreaterEqual(n, 5)


class MoreBelowFades(unittest.TestCase):
    def test_more_below_fades_out_at_the_bottom(self):
        """The 'More below' flair stays in the layout while a box can scroll (cc-can-more) and fades out by opacity when
        the box is scrolled to the bottom (cc-has-more off) instead of disappearing at once; reduced motion turns the fade off.
        REQ: UI-91"""
        js, css = _read("cards.js"), _read("style.css")
        self.assertIn('c.classList.toggle("cc-can-more", cm)', js)
        self.assertIn("if (vy && s.offsetParent) can = true;", js)
        self.assertIn("/auto|scroll/.test(getComputedStyle(s).overflowY)", js)  # a non-scrolling table wrapper never keeps it on
        self.assertRegex(css, r"\.cc-more\{[^}]*opacity:0;visibility:hidden;pointer-events:none;transition:opacity")
        self.assertIn(".card.cc-can-more>.cc-more,.card.cc-has-more>.cc-more{display:block}", css)
        self.assertRegex(css, r"\.card\.cc-has-more>\.cc-more\{opacity:\.9;visibility:visible")
        self.assertRegex(css, r"prefers-reduced-motion:reduce\)\{\.cc-more")

    def test_more_above_fades_in_when_scrolled_down(self):
        """A 'More above' flair sits above the body while a box can scroll and fades in once it is scrolled down
        (cc-has-above), with a top edge shadow; clicking scrolls up. REQ: UI-91"""
        js, css = _read("cards.js"), _read("style.css")
        self.assertIn('ma.className = "cc-above"', js)
        self.assertIn("s.scrollTop > 12) up = s;", js)
        self.assertIn('c.classList.toggle("cc-has-above", ha)', js)
        self.assertRegex(css, r"\.cc-above\{[^}]*opacity:0;visibility:hidden;pointer-events:none;transition:opacity")
        self.assertIn(".card.cc-can-more>.cc-above{display:block}", css)
        self.assertRegex(css, r"\.card\.cc-has-above>\.cc-above\{opacity:\.9;visibility:visible")
        self.assertIn(".card.cc-has-above .sc-up-y{box-shadow:inset 0 14px", css)


if __name__ == "__main__":
    unittest.main()
