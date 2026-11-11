"""Back button / back gesture closes the open modal (static/backclose.js) - run under node with a tiny fake DOM + history."""
import os
import shutil
import subprocess  # noqa: S404 - runs node on a repo file
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tests import _env  # noqa: E402

NODE_FALLBACK = os.path.expanduser(os.environ.get("NETMON_NODE", "~/.hermes/tools/node-26.7.0-linux-arm64/bin/node"))
NODE = shutil.which("node") or (NODE_FALLBACK if os.path.exists(NODE_FALLBACK) else None)
BC_JS = os.path.join(_env.APP, "static", "backclose.js")

HARNESS = r"""
const fs = require("fs");
const src = fs.readFileSync(process.argv[2], "utf8");
let observer = null; const listeners = { popstate: [], keydown: [] };
const tick = () => new Promise((r) => setTimeout(r, 5));
function parse(s) { const m = s.trim().match(/^([a-z]*)((?:\.[\w-]+)*)(?:\[([\w-]+)(?:="([^"]*)")?\])?$/); return { tag: m[1], cls: m[2] ? m[2].slice(1).split(".") : [], attr: m[3], val: m[4] }; }
class El {
  constructor(tag, cls, attrs = {}) { this.tag = tag; this.cls = new Set(cls ? cls.split(" ") : []); this.attrs = attrs; this.kids = []; this.parent = null; this.style = {}; this.hidden = false; }
  get isConnected() { let p = this; while (p.parent) p = p.parent; return p === body; }
  get offsetParent() { return this.hidden ? null : body; }
  get classList() { const e = this; return { contains: (c) => e.cls.has(c), toggle: (c, on) => { on ? e.cls.add(c) : e.cls.delete(c); observer && observer(); } }; }
  matches(sel) { return sel.split(",").some((s) => { const p = parse(s); return (!p.tag || p.tag === this.tag) && p.cls.every((c) => this.cls.has(c)) && (!p.attr || (p.attr in this.attrs && (p.val === undefined || this.attrs[p.attr] === p.val))); }); }
  all() { return this.kids.flatMap((k) => [k, ...k.all()]); }
  querySelectorAll(sel) { return this.all().filter((e) => e.matches(sel)); }
  querySelector(sel) { return this.querySelectorAll(sel)[0] || null; }
  append(...k) { k.forEach((c) => { c.parent = this; this.kids.push(c); }); observer && observer(); return this; }
  remove() { const p = this.parent; if (!p) return; p.kids = p.kids.filter((k) => k !== this); this.parent = null; observer && observer(); }
  click() { this.onclick && this.onclick(); }
  close() { delete this.attrs.open; observer && observer(); }
}
const body = new El("body", "");
const toggle = new El("button", ""); toggle.onclick = () => body.classList.toggle("nav-open", !body.cls.has("nav-open"));
global.document = { body, querySelectorAll: (s) => body.querySelectorAll(s), getElementById: (id) => (id === "navToggle" ? toggle : null),
  dispatchEvent: (e) => listeners.keydown.forEach((f) => f(e)) };
global.KeyboardEvent = class { constructor(t, o) { this.type = t; Object.assign(this, o); } };
global.MutationObserver = class { constructor(cb) { this.cb = cb; } observe() { observer = () => this.cb([]); } };
const stack = [{ state: null, url: "#/events" }]; let idx = 0;
global.location = { get href() { return stack[idx].url; } };
global.history = { get state() { return stack[idx].state; }, get length() { return stack.length; },
  pushState(st, _t, url) { stack.splice(idx + 1); stack.push({ state: st, url }); idx++; },
  go(n) { setTimeout(() => { idx = Math.max(0, Math.min(stack.length - 1, idx + n)); listeners.popstate.forEach((f) => f({})); }, 1); } };
global.addEventListener = (t, f) => (listeners[t] = listeners[t] || []).push(f);
global.removeEventListener = () => {};
const back = async () => { history.go(-1); await tick(); await tick(); };
const nav = (url) => { stack.splice(idx + 1); stack.push({ state: null, url }); idx++; };
function modal(cls = "modal-back") { const d = new El("div", cls); const x = new El("button", "oe-x", { "aria-label": "Close" }); x.onclick = () => d.remove(); d.append(x); body.append(d); return d; }
function pop() { const d = new El("div", "rel-pop"); const x = new El("button", "rel-x"); x.onclick = () => d.remove(); d.append(x); body.append(d); return d; }
const out = {};
(async () => {
  eval(src); await tick();
  out.startDepth = idx;
  // 1. Back with a modal open closes it and stays on the page
  let m = modal(); await tick(); out.openPush = idx;
  await back(); out.backClosed = !m.isConnected; out.backIdx = idx; out.backUrl = location.href;
  // 2. Closing with the X pops its history entry silently, so the next Back navigates normally
  nav("#/alerts"); m = modal(); await tick(); const before = idx;
  m.querySelector(".oe-x").click(); await tick(); await tick(); out.xPopped = before - idx; out.xUrl = location.href;
  // 3. A popup on top of a modal: Back closes only the popup, then the modal
  m = modal(); await tick(); const p = pop(); await tick(); out.nestDepth = history.state && history.state.synModal;
  await back(); out.nest1 = [p.isConnected, m.isConnected];
  await back(); out.nest2 = [p.isConnected, m.isConnected]; out.nestUrl = location.href;
  // 4. Back with nothing open is a normal navigation back
  await back(); out.plainUrl = location.href;
  // 5. The mobile menu drawer
  body.classList.toggle("nav-open", true); await tick(); await back(); out.navClosed = !body.cls.has("nav-open"); out.navUrl = location.href;
  // 6. Welcome wizard: Back steps back while on step 2+, the wizard stays open
  const wz = new El("div", "wz-back"); const bb = new El("button", "wz-back-b"); bb.style.visibility = "visible"; let step = 1;
  bb.onclick = () => { step--; bb.style.visibility = step ? "visible" : "hidden"; }; wz.append(bb); body.append(wz); await tick();
  await back(); out.wzStep = step; out.wzOpen = wz.isConnected; out.wzDepth = history.state && history.state.synModal;
  console.log(JSON.stringify(out));
})();
"""


@unittest.skipUnless(NODE, "node not installed")
class TestBackCloses(unittest.TestCase):
    def test_back_closes_overlays(self):
        """Back (button or gesture) closes the topmost modal, popup or mobile menu instead of leaving the page; closing one any
        other way pops its history entry so the next Back navigates normally; with nothing open Back navigates back.
        REQ: UI-93"""
        r = subprocess.run([NODE, "-", BC_JS], input=HARNESS, capture_output=True, text=True, timeout=30)  # noqa: S603
        self.assertEqual(r.returncode, 0, r.stderr)
        import json
        o = json.loads(r.stdout.strip().splitlines()[-1])
        self.assertEqual(o["startDepth"], 0)
        self.assertEqual(o["openPush"], 1)                       # opening a modal adds one history entry
        self.assertTrue(o["backClosed"])
        self.assertEqual((o["backIdx"], o["backUrl"]), (0, "#/events"))  # Back closed it and stayed on the page
        self.assertEqual(o["xPopped"], 1)                        # ✕ removed the modal's entry
        self.assertEqual(o["xUrl"], "#/alerts")
        self.assertEqual(o["nestDepth"], 2)
        self.assertEqual(o["nest1"], [False, True])              # popup first
        self.assertEqual(o["nest2"], [False, False])             # then the modal
        self.assertEqual(o["nestUrl"], "#/alerts")
        self.assertEqual(o["plainUrl"], "#/events")              # nothing open: a normal Back
        self.assertTrue(o["navClosed"])
        self.assertEqual(o["navUrl"], "#/events")
        self.assertEqual((o["wzStep"], o["wzOpen"], o["wzDepth"]), (0, True, 1))  # wizard stepped back, still open


if __name__ == "__main__":
    unittest.main()
