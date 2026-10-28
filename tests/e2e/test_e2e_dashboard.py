"""E2E: the real dashboard server over HTTPS - transport, sign-in, sessions, pages, the JSON API and check-offs.

One server process is started for the whole module (setUpModule) with a synthetic snapshot seeded into its store.
"""
import json
import os
import re
import socket
import ssl
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import _env  # noqa: E402,F401
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness  # noqa: E402
import fixtures  # noqa: E402

SRV = None
SEED = "import fixtures; fixtures.seed_snapshot(fixtures.SID_OLD); fixtures.seed_snapshot(fixtures.SID)"


def setUpModule():
    global SRV
    SRV = harness.Server(seed=SEED).__enter__()


def tearDownModule():
    if SRV:
        SRV.__exit__(None, None, None)


def as_ip(c, ip):
    """Requests from loopback may name the real client (cloudflared): lets throttling tests use their own address."""
    return {"CF-Connecting-IP": ip}


class TransportSecurity(unittest.TestCase):
    """TLS, security headers and the public health check."""

    def test_healthz_is_public(self):
        """GET /healthz answers 200 'ok' without a session (container health check).
        REQ: DASH-04, AC-01"""
        code, body, _ = SRV.client().get("/healthz")
        self.assertEqual((code, body), (200, "ok"))

    def test_tls_1_1_refused(self):
        """A client limited to TLS 1.1 cannot complete a handshake.
        REQ: SEC-02"""
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
        try:
            import warnings
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                ctx.minimum_version = ssl.TLSVersion.TLSv1
                ctx.maximum_version = ssl.TLSVersion.TLSv1_1
        except (ValueError, ssl.SSLError):
            self.skipTest("local OpenSSL cannot even offer TLS 1.1")
        with socket.create_connection(("127.0.0.1", SRV.port), timeout=10) as s:
            with self.assertRaises((ssl.SSLError, OSError)):
                with ctx.wrap_socket(s) as t:
                    t.do_handshake()

    def test_tls_1_2_plus_negotiated(self):
        """A default client negotiates TLS 1.2 or newer.
        REQ: SEC-02"""
        ctx = ssl.create_default_context()
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
        with socket.create_connection(("127.0.0.1", SRV.port), timeout=10) as s:
            with ctx.wrap_socket(s) as t:
                self.assertIn(t.version(), ("TLSv1.2", "TLSv1.3"))

    def test_plain_http_client_does_not_break_server(self):
        """A plain-HTTP request on the TLS port is dropped and the server keeps serving.
        REQ: SEC-02, DASH-04"""
        with socket.create_connection(("127.0.0.1", SRV.port), timeout=10) as s:
            s.sendall(b"GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n")
            s.settimeout(5)
            try:
                s.recv(100)
            except OSError:
                pass
        self.assertEqual(SRV.client().get("/healthz")[0], 200)

    def test_security_headers_on_every_response_kind(self):
        """JSON, HTML, static, 401 and 404 responses all carry the security headers.
        REQ: SEC-01"""
        c = SRV.login()
        responses = [c.get("/api/me"), c.get("/"), c.get("/style.css"), SRV.client().get("/api/me"), c.get("/nope.js")]
        for code, _, h in responses:
            self.assertEqual(h.get("x-content-type-options"), "nosniff", code)
            self.assertEqual(h.get("x-frame-options"), "DENY")
            self.assertIn("max-age=", h.get("strict-transport-security", ""))
            csp = h.get("content-security-policy", "")
            for d in ("default-src 'self'", "object-src 'none'", "frame-ancestors 'none'", "base-uri 'none'"):
                self.assertIn(d, csp)
            self.assertEqual(h.get("referrer-policy"), "no-referrer")
            self.assertEqual(h.get("cross-origin-opener-policy"), "same-origin")

    def test_api_responses_not_cached(self):
        """API responses are Cache-Control: no-store (no data left in shared caches).
        REQ: SEC-01, DASH-02"""
        _, _, h = SRV.login().get("/api/snapshots")
        self.assertEqual(h.get("cache-control"), "no-store")


class SignIn(unittest.TestCase):
    """Login, logout, sessions, throttling and the CSRF guard."""

    def test_unauthenticated_api_401_and_page_redirect(self):
        """Without a session, /api/* returns 401 JSON and pages redirect to /login.
        REQ: AC-01"""
        c = SRV.client()
        code, body, _ = c.get("/api/snapshots")
        self.assertEqual((code, body.get("error")), (401, "login required"))
        code, _, h = c.get("/")
        self.assertEqual(code, 302)
        self.assertEqual(h.get("location"), "/login")

    def test_public_shell_files_served_without_session(self):
        """The login page, its script, the stylesheet and the PWA manifest are public.
        REQ: AC-01"""
        c = SRV.client()
        for p in ("/login", "/login.js", "/style.css", "/manifest.json", "/sw.js"):
            self.assertEqual(c.get(p)[0], 200, p)

    def test_unauthenticated_post_rejected(self):
        """A POST without a session gets 401 and changes nothing.
        REQ: AC-01"""
        code, _, _ = SRV.client().post("/api/acks", {"type": "issue", "key": "x", "checked": True})
        self.assertEqual(code, 401)

    def test_login_sets_strict_session_cookie(self):
        """A successful login sets an HttpOnly, Secure, SameSite=Strict session cookie with a Max-Age.
        REQ: SEC-03, AUTH-04"""
        c = SRV.client()
        code, body, h = c.post("/api/login", {"username": harness.ADMIN_USER, "password": harness.ADMIN_PASS},
                               headers=as_ip(c, "10.200.0.1"))
        self.assertEqual((code, body), (200, {"ok": True}))
        ck = [x for x in h["_set_cookie"] if x.startswith("netmon_session=")][0]
        for attr in ("HttpOnly", "Secure", "SameSite=Strict", "Path=/", "Max-Age="):
            self.assertIn(attr, ck)
        self.assertEqual(c.get("/api/me")[1]["user"], harness.ADMIN_USER)

    def test_wrong_password_rejected_generic_message(self):
        """A wrong password and an unknown user get the same 401 message (no user enumeration).
        REQ: AUTH-01"""
        c = SRV.client()
        a = c.post("/api/login", {"username": harness.ADMIN_USER, "password": "wrong-password-xx"}, headers=as_ip(c, "10.200.0.2"))
        b = c.post("/api/login", {"username": "nobody-here", "password": "wrong-password-xx"}, headers=as_ip(c, "10.200.0.2"))
        self.assertEqual(a[0], 401)
        self.assertEqual(a[1], b[1])
        self.assertIsNone(c.cookie)

    def test_failed_logins_throttled_per_client(self):
        """After 8 failures from one client address even the right password is refused; other clients are unaffected.
        REQ: AUTH-05"""
        c = SRV.client()
        bad = as_ip(c, "10.201.0.9")
        for _ in range(8):
            c.post("/api/login", {"username": harness.ADMIN_USER, "password": "wrong-password-xx"}, headers=bad)
        code, body, _ = c.post("/api/login", {"username": harness.ADMIN_USER, "password": harness.ADMIN_PASS}, headers=bad)
        self.assertEqual(code, 401)
        self.assertIn("too many", body["error"])
        ok = SRV.client()
        self.assertEqual(ok.post("/api/login", {"username": harness.ADMIN_USER, "password": harness.ADMIN_PASS},
                                 headers=as_ip(ok, "10.201.0.10"))[0], 200)

    def test_logout_clears_cookie(self):
        """POST /api/logout expires the cookie in the browser.
        REQ: AUTH-04"""
        c = SRV.login()
        code, _, h = c.post("/api/logout")
        self.assertEqual(code, 200)
        self.assertTrue(any("Max-Age=0" in x for x in h["_set_cookie"]))
        self.assertEqual(c.get("/api/me")[0], 401)

    def test_tampered_session_rejected(self):
        """A modified session cookie is not accepted.
        REQ: AUTH-04"""
        c = SRV.login()
        c.cookie = c.cookie[:-2] + ("AA" if not c.cookie.endswith("AA") else "BB")
        self.assertEqual(c.get("/api/me")[0], 401)

    def test_csrf_header_required(self):
        """POSTs without X-Netmon: 1 or without a JSON content type are refused with 400.
        REQ: SEC-01"""
        c = SRV.login()
        self.assertEqual(c.request("POST", "/api/acks", b"{}", headers={"Content-Type": "application/json", "X-Netmon": "0"})[0], 400)
        self.assertEqual(c.request("POST", "/api/acks", b"{}", headers={"Content-Type": "text/plain", "X-Netmon": "1"})[0], 400)

    def test_malformed_json_body_does_not_crash(self):
        """A broken JSON body gets an error response and the server stays up.
        REQ: SEC-01, DASH-04"""
        c = SRV.login()
        code, _, _ = c.request("POST", "/api/acks", b"{not json", headers={"Content-Type": "application/json", "X-Netmon": "1"})
        self.assertGreaterEqual(code, 400)
        self.assertEqual(c.get("/healthz")[0], 200)


class Pages(unittest.TestCase):
    """The single-page app and static files."""

    def test_index_assets_stamped_with_build_hash(self):
        """index.html references every .js/.css with ?v=<build hash>, and the stamped asset is served immutable.
        REQ: DASH-01"""
        c = SRV.login()
        code, html, h = c.get("/")
        self.assertEqual(code, 200)
        self.assertIn("text/html", h.get("content-type", ""))
        refs = re.findall(r'src="(/[\w.-]+\.js)(?:\?v=([0-9a-f]+))?"', html)
        self.assertTrue(refs)
        self.assertTrue(all(v for _, v in refs), "every script must be stamped")
        self.assertEqual(len({v for _, v in refs}), 1)
        code, _, h = c.get(f"{refs[0][0]}?v={refs[0][1]}", raw=True)
        self.assertEqual(code, 200)
        self.assertIn("immutable", h.get("cache-control", ""))

    def test_path_traversal_blocked(self):
        """Encoded and plain ../ paths cannot read files outside the static directory.
        REQ: SEC-05"""
        c = SRV.login()
        for p in ("/../server.py", "/..%2fserver.py", "/%2e%2e/%2e%2e/store.py", "/static/../../auth.py"):
            code, body, _ = c.get(p)
            self.assertIn(code, (400, 404), p)
            self.assertNotIn("import", str(body)[:400])

    def test_unknown_api_404(self):
        """Unknown API paths return 404 for GET and POST.
        REQ: SEC-05"""
        c = SRV.login()
        self.assertEqual(c.get("/api/does-not-exist")[0], 404)
        self.assertEqual(c.post("/api/does-not-exist", {})[0], 404)

    def test_gzip_for_large_responses(self):
        """Large responses are gzip-compressed when the client accepts it.
        REQ: DASH-01"""
        c = SRV.login()
        _, _, h = c.get("/api/snapshot?id=latest", headers={"Accept-Encoding": "gzip"}, raw=True)
        self.assertEqual(h.get("content-encoding"), "gzip")


class Api(unittest.TestCase):
    """Data views served from the stored snapshots (local LLM off)."""

    @classmethod
    def setUpClass(cls):
        cls.c = SRV.login()

    def test_snapshots_listed_in_order_with_companions(self):
        """/api/snapshots lists both seeded snapshots oldest first, each with its analysis companion.
        REQ: DASH-02, STO-01"""
        code, body, _ = self.c.get("/api/snapshots")
        self.assertEqual(code, 200)
        self.assertEqual([s["id"] for s in body], [fixtures.SID_OLD, fixtures.SID])
        self.assertTrue(all("analysis" in s["has"] for s in body))

    def test_latest_snapshot_round_trips_raw_data(self):
        """/api/snapshot?id=latest returns the newest snapshot with the devices written by the pipeline.
        REQ: DASH-02, STO-01"""
        code, body, _ = self.c.get("/api/snapshot?id=latest")
        self.assertEqual(code, 200)
        self.assertEqual(body["id"], fixtures.SID)
        self.assertEqual(set(body["raw"]["devices"]), set(fixtures.IPS.values()))

    def test_unknown_snapshot_404(self):
        """A snapshot id that does not exist is a 404, not an error page.
        REQ: DASH-02"""
        self.assertEqual(self.c.get("/api/snapshot?id=2020-01-01T0000Z")[0], 404)
        self.assertEqual(self.c.get("/api/snapshot?id=../../etc/passwd")[0], 404)

    def test_every_page_api_answers_200_json(self):
        """Every data API behind the dashboard pages answers 200 with JSON while the LLM is off.
        REQ: DASH-02, LLM-02"""
        for p in ("/api/me", "/api/issues", "/api/risk", "/api/lateral", "/api/mitre", "/api/alerts", "/api/correlate",
                  "/api/events/open", "/api/accounts", "/api/history", "/api/registry", "/api/kb/all", "/api/suppress",
                  "/api/config/cfg", "/api/push/prefs", "/api/aireview", "/api/tuning", "/api/account", "/api/site",
                  "/api/alerts/mutes", "/api/ti/feeds", "/api/acks", "/api/users", "/api/audit/status"):
            code, body, h = self.c.get(p)
            self.assertEqual(code, 200, p)
            self.assertIn("application/json", h.get("content-type", ""), p)
            self.assertNotIsInstance(body, str, p)

    def test_risk_scores_bounded(self):
        """Every host risk score served by /api/risk lies within 0-100.
        REQ: RISK-02, DASH-02"""
        hosts = self.c.get("/api/risk")[1]["hosts"]
        self.assertTrue(hosts)
        for h in hosts:
            self.assertGreaterEqual(h["score"], 0)
            self.assertLessEqual(h["score"], 100)

    def test_correlation_contains_seeded_findings(self):
        """The correlation view contains an event for the seeded segmentation finding.
        REQ: COR-03, DASH-02"""
        ev = self.c.get("/api/correlate")[1]["events"]
        self.assertTrue(any(k.startswith("f|segmentation|" + fixtures.IPS["dmz"]) for k in ev))

    def test_open_events_persisted(self):
        """Findings from the snapshot appear on the Open events list (persisted event store).
        REQ: DASH-02, STO-01"""
        ev = self.c.get("/api/events/open")[1]["events"]
        self.assertTrue(any(e["type"] == "finding" for e in ev))

    def test_mitre_view_has_catalog(self):
        """/api/mitre serves the ATT&CK matrix (version and tactic order).
        REQ: MIT-01, DASH-02"""
        b = self.c.get("/api/mitre")[1]
        self.assertTrue(b["version"])
        self.assertIn("initial-access", b["tactic_order"])

    def test_aireview_reports_llm_disabled(self):
        """With NETMON_LLM=off the AI review status says the reviewer is disabled, and nothing fails.
        REQ: LLM-02"""
        st = self.c.get("/api/aireview")[1]["status"]
        self.assertFalse(st["enabled"])


class CheckOffs(unittest.TestCase):
    """Check-offs written through the API are stored and read back."""

    def test_single_check_off_round_trip(self):
        """Checking an issue off stores it with its note; un-checking removes it.
        REQ: DASH-05, STO-03"""
        c = SRV.login()
        code, _, _ = c.post("/api/acks", {"type": "issue", "key": "e2e|one", "checked": True, "note": "fixed in test", "label": "E2E"})
        self.assertEqual(code, 200)
        acks = c.get("/api/acks")[1]
        self.assertIn("e2e|one", acks["issue"])
        c.post("/api/acks", {"type": "issue", "key": "e2e|one", "checked": False})
        self.assertNotIn("e2e|one", c.get("/api/acks")[1]["issue"])

    def test_bulk_check_off(self):
        """'Check all' stores many items in one request.
        REQ: DASH-05, STO-03"""
        c = SRV.login()
        items = [{"type": "finding", "key": f"e2e|bulk|{i}", "label": f"bulk {i}"} for i in range(25)]
        self.assertEqual(c.post("/api/acks", {"items": items, "checked": True})[0], 200)
        got = c.get("/api/acks")[1]["finding"]
        self.assertTrue(all(f"e2e|bulk|{i}" in got for i in range(25)))

    def test_bulk_check_off_larger_than_64k(self):
        """'Check all' on thousands of rows (body well over 64 KB) is parsed whole, not truncated; unauthenticated
        oversize bodies are refused with 413.
        REQ: DASH-05, STO-03"""
        c = SRV.login()
        items = [{"type": "finding", "key": "e2e|big|" + "k" * 80 + str(i), "label": "big"} for i in range(1500)]
        code, body, _ = c.post("/api/acks", {"items": items, "checked": True})
        self.assertEqual(code, 200, body)
        got = c.get("/api/acks")[1]["finding"]
        self.assertTrue(all(i["key"] in got for i in items))
        self.assertEqual(c.post("/api/acks", {"items": items, "checked": False})[0], 200)
        self.assertEqual(SRV.client().post("/api/acks", {"items": items, "checked": True})[0], 413)

    def test_check_off_requires_type_and_key(self):
        """A check-off without type or key is rejected with 400.
        REQ: DASH-05"""
        self.assertEqual(SRV.login().post("/api/acks", {"type": "", "key": ""})[0], 400)


class Account(unittest.TestCase):
    """Self-service account page."""

    def test_change_own_password_signs_out_other_sessions(self):
        """Changing one's password keeps this session, revokes the others and the new password works.
        REQ: DASH-03, AUTH-04, AUTH-02"""
        admin = SRV.login()
        name, pw, new = "e2e-pwchange", "first-password-123", "second-password-456"
        self.assertEqual(admin.post("/api/users", {"action": "add", "username": name, "password": pw, "role": "defender"})[0], 200)
        a, b = SRV.login(name, pw), SRV.login(name, pw)
        code, body, _ = a.post("/api/account/password", {"current": pw, "password": "short"})
        self.assertEqual(code, 400)
        code, body, _ = a.post("/api/account/password", {"current": pw, "password": new})
        self.assertEqual((code, body), (200, {"ok": True}))
        self.assertEqual(a.get("/api/me")[0], 200)
        self.assertEqual(b.get("/api/me")[0], 401)
        self.assertEqual(SRV.login(name, new).get("/api/me")[1]["user"], name)

    def test_password_change_raises_account_alert(self):
        """A password change stores an urgent 'account' detection (held for review until promoted to the bell).
        REQ: DASH-03, STO-06"""
        admin = SRV.login()
        name, pw = "e2e-pwalert", "first-password-123"
        admin.post("/api/users", {"action": "add", "username": name, "password": pw, "role": "defender"})
        SRV.login(name, pw).post("/api/account/password", {"current": pw, "password": "another-password-9"})
        out = SRV.run_py("import json, store; print(json.dumps(store.alerts_recent(500, suppressed=True)))")
        rows = [r for r in json.loads(out) if name in r["text"] and "changed its password" in r["text"]]
        self.assertTrue(rows)
        self.assertEqual((rows[0]["source"], rows[0]["severity"]), ("account", "urgent"))
        feed = [a["key"] for a in admin.get("/api/alerts?limit=500")[1]["alerts"]]
        self.assertNotIn(rows[0]["key"], feed)


if __name__ == "__main__":
    unittest.main()
