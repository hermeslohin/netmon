"""Static checks of dashboard/app/static: referenced assets exist and app.js fnv() matches correlate.fnv (no node needed)."""
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); import _env  # noqa: E402

import glob  # noqa: E402
import json  # noqa: E402
import re  # noqa: E402
import unittest  # noqa: E402
from urllib.parse import urlparse  # noqa: E402

import correlate  # noqa: E402
import corr_llm  # noqa: E402

STATIC = os.path.join(_env.APP, "static")
HTML = sorted(glob.glob(os.path.join(STATIC, "*.html")))
APP_JS = os.path.join(STATIC, "app.js")


def _read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def refs(html):
    """(kind, url) of every <script src> and <link rel=stylesheet|manifest|icon href> in an HTML file."""
    out = []
    for tag in re.findall(r"<script\b[^>]*>", html, re.I):
        m = re.search(r"\bsrc\s*=\s*[\"']([^\"']+)", tag, re.I)
        if m:
            out.append(("script", m.group(1)))
    for tag in re.findall(r"<link\b[^>]*>", html, re.I):
        m = re.search(r"\bhref\s*=\s*[\"']([^\"']+)", tag, re.I)
        rel = re.search(r"\brel\s*=\s*[\"']([^\"']+)", tag, re.I)
        if m:
            out.append(((rel.group(1) if rel else "link").lower(), m.group(1)))
    return out


def local_file(url):
    u = urlparse(url)
    if u.scheme or u.netloc:
        return None
    return os.path.join(STATIC, u.path.lstrip("/"))


def js_fnv(s, basis, prime):
    """Python model of app.js fnv(): FNV-1a over UTF-16 code units with Math.imul and >>> 0, then toString(36)."""
    h = basis
    b = s.encode("utf-16-le")
    for i in range(0, len(b), 2):
        h ^= int.from_bytes(b[i:i + 2], "little")
        h = (h * prime) & 0xFFFFFFFF
    digits, out = "0123456789abcdefghijklmnopqrstuvwxyz", ""
    while h:
        h, r = divmod(h, 36)
        out = digits[r] + out
    return out or "0"


class HtmlReferencesTest(unittest.TestCase):
    """Every asset an HTML page references exists on disk."""

    def test_html_pages_exist(self):
        """The static directory holds index.html and login.html.
        REQ: DASH-06"""
        names = {os.path.basename(p) for p in HTML}
        self.assertTrue({"index.html", "login.html"} <= names, names)

    def test_scripts_and_stylesheets_exist(self):
        """Every script src and stylesheet href in static/*.html points to an existing file.
        REQ: DASH-06"""
        checked = 0
        for page in HTML:
            for kind, url in refs(_read(page)):
                if kind not in ("script", "stylesheet"):
                    continue
                p = local_file(url)
                self.assertIsNotNone(p, f"{page}: external {kind} {url} (CSP allows only self)")
                self.assertTrue(os.path.isfile(p), f"{os.path.basename(page)}: missing {kind} {url}")
                checked += 1
        self.assertGreater(checked, 5)

    def test_other_linked_assets_exist(self):
        """Manifest and icon links in the HTML pages point to existing files.
        REQ: DASH-06"""
        for page in HTML:
            for kind, url in refs(_read(page)):
                if kind in ("script", "stylesheet"):
                    continue
                p = local_file(url)
                if p:
                    self.assertTrue(os.path.isfile(p), f"{os.path.basename(page)}: missing {kind} {url}")

    def test_index_loads_app_js_and_style(self):
        """index.html loads style.css and app.js; app.js comes before the modules that use its helpers.
        REQ: DASH-06"""
        r = refs(_read(os.path.join(STATIC, "index.html")))
        scripts = [urlparse(u).path for k, u in r if k == "script"]
        self.assertIn("/style.css", [urlparse(u).path for k, u in r if k == "stylesheet"])
        self.assertIn("/app.js", scripts)
        for s in ("/related.js", "/aireview.js", "/cards.js"):
            if s in scripts:
                self.assertLess(scripts.index("/app.js"), scripts.index(s), s)

    def test_no_duplicate_script_tags(self):
        """No HTML page includes the same script twice.
        REQ: DASH-06"""
        for page in HTML:
            scripts = [urlparse(u).path for k, u in refs(_read(page)) if k == "script"]
            self.assertEqual(len(scripts), len(set(scripts)), page)

    def test_modals_survive_touch(self):
        """Dialogs never close on a bare backdrop mousedown (iOS shifts the dialog under the finger) and the suppress
        dialog does not pop the keyboard on touch devices.
        REQ: DASH-06"""
        for f in glob.glob(os.path.join(STATIC, "*.js")):
            src = _read(f)
            self.assertNotRegex(src, r'addEventListener\("mousedown", \((?:e|ev)\) => \{ if \((?:e|ev)\.target === d\) close\(\)', f)
        self.assertIn("function backdropClose(", _read(APP_JS))
        self.assertIn('if (!window.touchUI()) q(".sp-name").focus()', _read(os.path.join(STATIC, "related.js")))

    def test_cache_busting_query_is_numeric(self):
        """Where an asset URL carries a ?v= build hash it is a plain token, never a path or script.
        REQ: DASH-01"""
        for page in HTML:
            for _, url in refs(_read(page)):
                q = urlparse(url).query
                if q.startswith("v="):
                    self.assertRegex(q, r"^v=[0-9A-Za-z_-]+$", url)

    def test_manifest_icons_exist(self):
        """Every icon listed in manifest.json exists in the static directory.
        REQ: DASH-06"""
        m = json.loads(_read(os.path.join(STATIC, "manifest.json")))
        for icon in m.get("icons") or []:
            self.assertTrue(os.path.isfile(local_file(icon["src"])), icon["src"])


class FnvParityTest(unittest.TestCase):
    """app.js fnv() and correlate.fnv use the same FNV-1a algorithm."""

    @classmethod
    def setUpClass(cls):
        src = _read(APP_JS)
        m = re.search(r"function\s+fnv\s*\(\s*(\w+)\s*\)\s*\{(.*?)\n", src)
        cls.body = m.group(2) if m else ""
        cls.arg = m.group(1) if m else ""

    def _consts(self):
        basis = re.search(r"let\s+h\s*=\s*(0x[0-9a-fA-F]+)", self.body)
        prime = re.search(r"Math\.imul\(\s*h\s*,\s*(0x[0-9a-fA-F]+)\s*\)", self.body)
        self.assertTrue(basis and prime, self.body)
        return int(basis.group(1), 16), int(prime.group(1), 16)

    def test_fnv_function_present(self):
        """app.js defines fnv(str) as a one-argument function.
        REQ: COR-02"""
        self.assertTrue(self.body, "function fnv not found in app.js")

    def test_constants_match_python(self):
        """app.js uses the FNV-1a 32-bit offset basis 0x811c9dc5 and prime 0x01000193, as correlate.fnv does.
        REQ: COR-02"""
        basis, prime = self._consts()
        self.assertEqual((basis, prime), (0x811c9dc5, 0x01000193))
        self.assertEqual(int(correlate.fnv(""), 36), basis)
        # one step of Python's fnv with the JS constants
        self.assertEqual(int(correlate.fnv("a"), 36), ((basis ^ ord("a")) * prime) & 0xFFFFFFFF)

    def test_js_algorithm_shape(self):
        """app.js XORs each charCodeAt before multiplying, keeps 32 bits unsigned and prints base 36 (FNV-1a, not FNV-1).
        REQ: COR-02"""
        b = re.sub(r"\s+", "", self.body)
        a = self.arg
        xor = b.find(f"h^={a}.charCodeAt(i)")
        mul = b.find("h=Math.imul(h,")
        self.assertGreaterEqual(xor, 0, b)
        self.assertGreater(mul, xor, "XOR must come before the multiply (FNV-1a)")
        self.assertIn(">>>0", b)
        self.assertIn("returnh.toString(36)", b)

    def test_python_matches_js_model(self):
        """correlate.fnv equals a Python model of the app.js function (constants parsed from app.js) for typical ids.
        REQ: COR-02"""
        basis, prime = self._consts()
        for s in ("", "a", "Possible C2|Laptop", "Admin Laptop|beacon|every 60s", "SSH brute force|10.0.1.10", "Grüße|ü"):
            self.assertEqual(correlate.fnv(s), js_fnv(s, basis, prime), s)
            self.assertEqual(corr_llm._fnv(s), js_fnv(s, basis, prime), s)

    def test_alarm_ev_id_format_matches(self):
        """app.js builds alarm ids as alarm|fnv(`${title}|${who}`), the same string correlate.build hashes.
        REQ: COR-02"""
        src = _read(APP_JS)
        self.assertRegex(src, r"alarmEvId\s*=\s*\(a\)\s*=>\s*`alarm\|\$\{fnv\(`\$\{a\.title\}\|\$\{a\.who \|\| \"\"\}`\)\}`")

    def test_gw_id_format_matches(self):
        """app.js gwId() builds the same gw|time|key|src|dst id as correlate.gw_id.
        REQ: COR-02"""
        src = _read(APP_JS)
        m = re.search(r"const gwId = \(g\) => `([^`]*)`", src)
        self.assertTrue(m)
        tmpl = m.group(1)
        g = {"time": "T", "key": "K", "src": "S", "dst": "D"}
        js = re.sub(r"\$\{g\.(\w+) \|\| \"\"\}", lambda mm: g[mm.group(1)], tmpl)
        self.assertEqual(js, correlate.gw_id(g))


if __name__ == "__main__":
    unittest.main()
