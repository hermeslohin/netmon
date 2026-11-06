"""E2E: every admin settings endpoint of the real dashboard server over HTTPS.

For each settings POST: an admin save is read back through the matching GET, invalid input returns a 4xx JSON error and
changes nothing, a Network defender and a User are refused (403) where the setting is admin-only, and every POST leaves
an audit entry with secrets redacted. The audit log's Elasticsearch is a loopback fake (FakeES) so the audit writer never
backs off and entries arrive within seconds. One server process is started for the module (setUpModule); integration "Test"
buttons are never pressed (no outbound network) and the LLM is off. Every test sets the values it reads back, so the
tests do not depend on each other's order.
"""
import json
import os
import sys
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import _env  # noqa: E402,F401
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness  # noqa: E402

SRV = None
PW = "settings-test-password-1"
DEFENDER, USER = "e2e-set-defender", "e2e-set-user"
SEED = ("import fixtures, store\nfixtures.seed_snapshot()\n"
        "store.cfg_save('policy', {'upload_spike': {'min_mb': 25, 'times_normal': 3}, 'zones': {}})\n")
LOOP = "https://127.0.0.1:9"  # loopback discard port: a saved URL that never reaches a real host
ES_DOCS, ES_LOCK = [], threading.Lock()  # audit entries the server bulk-indexed into the fake Elasticsearch below
ES_URL = None


class FakeES(BaseHTTPRequestHandler):
    """Loopback stand-in for Elasticsearch: accepts every _bulk write (so the audit writer never backs off) and keeps it."""

    def _reply(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n).decode(errors="replace") if n else ""
        if self.path.startswith("/_bulk"):
            lines = [x for x in raw.splitlines() if x.strip()]
            with ES_LOCK:
                ES_DOCS.extend(json.loads(x) for x in lines[1::2])
            out = {"errors": False, "items": [{"create": {"status": 201}} for _ in lines[1::2]]}
        else:
            out = {"acknowledged": True}
        b = json.dumps(out).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    do_GET = do_POST = do_PUT = do_HEAD = _reply

    def log_message(self, *a):
        pass


def fake_key(tag):
    """An obviously fake API key whose last four characters (the masked hint) are `tag`."""
    return "e2e-fake-" + "x" * 16 + tag


PROVIDER = {}  # the AI provider created once for the module: {"id", "provider", "model", "key"}


ES = None
ADMIN = None


def setUpModule():
    global SRV, ES, ES_URL
    ES = ThreadingHTTPServer(("127.0.0.1", 0), FakeES)
    threading.Thread(target=ES.serve_forever, daemon=True).start()
    ES_URL = f"http://127.0.0.1:{ES.server_address[1]}"
    SRV = harness.Server(seed=SEED).__enter__()
    a = SRV.login()
    for path, body in (("/api/config/integrations/elasticsearch", {"url": ES_URL, "api_key": fake_key("es00")}),
                       ("/api/config/integrations/audit", {"api_key": fake_key("au00")})):
        code, b, _ = a.post(path, body)
        assert code == 200, (path, code, b)
    for name, role in ((DEFENDER, "defender"), (USER, "user")):
        code, body, _ = a.post("/api/users", {"action": "add", "username": name, "password": PW, "role": role})
        assert code == 200, (name, code, body)


def tearDownModule():
    if SRV:
        SRV.__exit__(None, None, None)
    if ES:
        ES.shutdown()


def admin():
    """The admin's signed-in client (one session reused: signing in costs a password hash)."""
    global ADMIN
    if ADMIN is None or ADMIN.get("/api/me")[0] != 200:
        ADMIN = SRV.login()
    return ADMIN


def as_(name):
    return SRV.login(name, PW)


def provider():
    """Create (once) an OpenAI-type provider with a fake key; nothing contacts it."""
    if not PROVIDER:
        key = fake_key("pv01")
        code, body, _ = admin().post("/api/llm/providers", {"action": "save", "type": "openai", "name": "E2E settings provider",
                                                            "api_key": key, "models": ["e2e-model-a", "e2e-model-b"]})
        assert code == 200, body
        PROVIDER.update(id=body["provider"]["id"], provider=body["provider"]["provider"], model="e2e-model-a", key=key)
    return PROVIDER


def audit_rows():
    """Every audit entry so far: bulk-indexed into the fake Elasticsearch, or still spooled on disk."""
    with ES_LOCK:
        rows = list(ES_DOCS)
    spool = os.path.join(SRV.state, "audit_spool.jsonl")
    for f in (spool, spool + ".sending"):
        if os.path.exists(f):
            with open(f) as fh:
                rows += [json.loads(x) for x in fh if x.strip()]
    return rows


def audit_wait(pred, wait=20):
    """Audit entries matching pred (waits for the writer thread, which batches every ~2 s)."""
    end = time.time() + wait
    while True:
        rows = audit_rows()
        hit = [r for r in rows if pred(r)]
        if hit or time.time() > end:
            return hit, rows
        time.sleep(0.5)


def is_post(r, path, user=harness.ADMIN_USER, outcome="success"):
    return ((r.get("url") or {}).get("path") == path and (r.get("user") or {}).get("name") == user
            and (r.get("event") or {}).get("outcome") == outcome and ((r.get("http") or {}).get("request") or {}).get("method") == "POST")


def aireview(c=None):
    code, body, _ = (c or admin()).get("/api/aireview")
    assert code == 200, body
    return body


def settings_state():
    """Every persisted settings value the admin pages show (volatile counters left out)."""
    a = admin()
    ai = aireview(a)
    integ = a.get("/api/config/integrations")[1]
    return {
        "lookback": ai["lookback"]["hours"], "config": ai["config"], "clef": ai["clef"]["config"],
        "web_cache": {k: ai["web_cache"][k] for k in ("enabled", "days")},
        "review": {k: ai["review"][k] for k in ("enabled", "interval_minutes", "modes")},
        "research": {k: ai["research"][k] for k in ("provider", "model", "limits", "web_research", "es_search")},
        "limits": {k: ai["limits"][k] for k in ("max_links", "classify", "window_minutes", "discard_days", "pair_modes")},
        "chat": ai["chat"], "notes_consolidate": {k: ai["notes_consolidate"][k] for k in ("enabled", "time", "tz")},
        "triage": a.get("/api/config/triage")[1]["settings"], "integrations": integ,
        "providers": [{k: p[k] for k in ("id", "name", "key_hint", "models", "enabled", "rate_per_hour")}
                      for p in a.get("/api/llm/providers")[1]["providers"]],
        "push": a.get("/api/push/prefs")[1]["prefs"], "policy": a.get("/api/config/cfg?doc=policy")[1]["data"],
    }


class Base(unittest.TestCase):
    """Shared assertions."""

    def ok(self, c, path, body):
        code, b, _ = c.post(path, body)
        self.assertEqual(code, 200, f"{path}: {b}")
        self.assertIsInstance(b, dict)
        return b

    def bad(self, c, path, body, codes=(400,)):
        code, b, _ = c.post(path, body)
        self.assertIn(code, codes, f"{path} {body}: {code} {b}")
        self.assertIsInstance(b, dict, path)
        self.assertTrue(b.get("error"), f"{path}: no JSON error in {b}")
        return b

    def bad_unchanged(self, c, cases, view):
        """Each (path, body) in cases is rejected with a JSON 400 and view() reads the same before and after."""
        before = view()
        for path, body in cases:
            self.bad(c, path, body)
        self.assertEqual(view(), before)


class Integrations(Base):
    """Configuration > Integrations: Elasticsearch, UniFi, audit, web search, OpenCTI and feeds."""

    def integ(self, sec=None):
        code, b, _ = admin().get("/api/config/integrations")
        self.assertEqual(code, 200)
        return b[sec] if sec else b

    def test_elasticsearch_saved_and_key_masked(self):
        """Saving the Elasticsearch URL, key and index names is read back with the key shown only as a masked hint.
        REQ: SET-60, SET-61"""
        a, key = admin(), fake_key("es01")
        r = self.ok(a, "/api/config/integrations/elasticsearch",
                    {"url": ES_URL, "api_key": key, "indices": {"zeek": "e2e-zeek-*", "suricata": "", "detections": ""}})
        self.assertNotIn(key, json.dumps(r))
        es = self.integ("elasticsearch")
        self.assertEqual(es["url"], ES_URL)
        self.assertEqual(es["indices"]["zeek"], "e2e-zeek-*")
        self.assertTrue(es["key_set"])
        self.assertEqual(es["key_hint"], "••••es01")
        self.assertEqual(es["updated_by"], harness.ADMIN_USER)
        self.assertNotIn(key, json.dumps(self.integ()))

    def test_empty_key_keeps_and_clear_key_clears(self):
        """Re-saving a section with an empty key keeps the stored key; clear_key removes it.
        REQ: SET-61"""
        a = admin()
        self.ok(a, "/api/config/integrations/unifi", {"url": LOOP, "api_key": fake_key("un01")})
        self.ok(a, "/api/config/integrations/unifi", {"url": LOOP, "api_key": ""})
        self.assertEqual(self.integ("unifi")["key_hint"], "••••un01")
        self.ok(a, "/api/config/integrations/unifi", {"url": LOOP, "clear_key": True})
        u = self.integ("unifi")
        self.assertFalse(u["key_set"])
        self.assertEqual(u["key_hint"], "")

    def test_web_search_provider_saved(self):
        """The web search provider, its instance URL and key are saved and read back (key masked).
        REQ: SET-60, SET-61"""
        a, key = admin(), fake_key("wb01")
        self.ok(a, "/api/config/integrations/web", {"provider": "firecrawl", "url": LOOP, "api_key": key})
        w = self.integ("web")
        self.assertEqual((w["provider"], w["url"], w["key_hint"]), ("firecrawl", LOOP, "••••wb01"))
        self.assertNotIn(key, json.dumps(w))
        self.ok(a, "/api/config/integrations/web", {"provider": "duckduckgo"})
        self.assertEqual(self.integ("web")["provider"], "duckduckgo")

    def test_opencti_saved(self):
        """OpenCTI switches and score thresholds are saved and read back, its token masked.
        REQ: SET-60, SET-61"""
        a, key = admin(), fake_key("oc01")
        self.ok(a, "/api/config/integrations/opencti", {"url": LOOP, "api_key": key, "enabled": False, "min_score": 61,
                                                        "high_score": 90, "incident_min_sev": "urgent", "sightings": False})
        o = self.integ("opencti")
        self.assertEqual((o["url"], o["min_score"], o["high_score"], o["incident_min_sev"], o["sightings"], o["enabled"]),
                         (LOOP, 61, 90, "urgent", False, False))
        self.assertEqual(o["key_hint"], "••••oc01")
        self.assertNotIn(key, json.dumps(o))

    def test_custom_feed_added_and_deleted(self):
        """A custom threat-intel feed is added, listed, and deleted again.
        REQ: SET-60"""
        a = admin()
        self.ok(a, "/api/config/integrations/feeds", {"items": [{"name": "e2e_list", "url": LOOP + "/list.txt", "kind": "ips"}]})
        items = {f["name"]: f for f in self.integ("feeds")["items"]}
        self.assertIn("e2e_list", items)
        self.assertEqual((items["e2e_list"]["kind"], items["e2e_list"]["builtin"]), ("ips", False))
        self.ok(a, "/api/config/integrations/feeds", {"delete": ["e2e_list"]})
        self.assertNotIn("e2e_list", {f["name"] for f in self.integ("feeds")["items"]})

    def test_invalid_integration_input_rejected(self):
        """Bad URLs, keys, providers, scores, feed names and unknown sections return 400 with an error and save nothing.
        REQ: SET-62"""
        a = admin()
        builtin = self.integ("feeds")["items"][0]["name"]
        self.bad_unchanged(a, [
            ("/api/config/integrations/elasticsearch", {"url": "ftp://127.0.0.1/"}),
            ("/api/config/integrations/elasticsearch", {"url": LOOP, "indices": {"zeek": "bad index/name"}}),
            ("/api/config/integrations/unifi", {"url": LOOP, "api_key": "has a space"}),
            ("/api/config/integrations/web", {"provider": "e2e-no-such-provider"}),
            ("/api/config/integrations/web", {"provider": "firecrawl", "url": LOOP, "ca_pem": "not a certificate"}),
            ("/api/config/integrations/opencti", {"min_score": 500}),
            ("/api/config/integrations/opencti", {"enabled": True, "url": ""}),
            ("/api/config/integrations/opencti", {"incident_min_sev": "e2e-severity"}),
            ("/api/config/integrations/feeds", {"items": [{"name": "Bad Name!", "url": LOOP, "kind": "ips"}]}),
            ("/api/config/integrations/feeds", {"items": [{"name": "e2e_nokind", "url": LOOP}]}),
            ("/api/config/integrations/feeds", {"delete": [builtin]}),
            ("/api/config/integrations/audit", {"index": "logs-*"}),
            ("/api/config/integrations/e2e-bogus", {"url": LOOP}),
        ], self.integ)

    def test_audit_switches_persist(self):
        """Switching off the event reviewer / researcher audit entries persists and /api/audit/status reports it.
        REQ: SET-63"""
        a = admin()
        try:
            self.ok(a, "/api/config/integrations/audit", {"send_reviewer": False, "send_researcher": False})
            st = a.get("/api/audit/status")[1]
            self.assertIs(st["send_reviewer"], False)
            self.assertIs(st["send_researcher"], False)
            au = self.integ("audit")
            self.assertEqual((au["send_reviewer"], au["send_researcher"]), (False, False))
            self.ok(a, "/api/config/integrations/audit", {"send_reviewer": True})  # a switch-only post keeps the other one
            st = a.get("/api/audit/status")[1]
            self.assertEqual((st["send_reviewer"], st["send_researcher"]), (True, False))
        finally:
            self.ok(a, "/api/config/integrations/audit", {"send_reviewer": True, "send_researcher": True})
        self.assertIs(a.get("/api/audit/status")[1]["send_researcher"], True)


class ReviewJob(Base):
    """Review job, event research and auto-close settings."""

    def test_lookback_saved(self):
        """The review lookback hours are saved and shown on the AI pipeline page; out-of-range or non-numbers are refused.
        REQ: SET-64"""
        a = admin()
        r = self.ok(a, "/api/config/lookback", {"hours": 6})
        self.assertEqual(r["lookback"]["hours"], 6)
        self.assertEqual(aireview(a)["lookback"]["hours"], 6)
        self.assertEqual(aireview(a)["lookback"]["by"], harness.ADMIN_USER)
        self.bad_unchanged(a, [("/api/config/lookback", {"hours": 0}), ("/api/config/lookback", {"hours": 25}),
                               ("/api/config/lookback", {"hours": "six"}), ("/api/config/lookback", {"hours": True}),
                               ("/api/config/lookback", {})], lambda: aireview(a)["lookback"]["hours"])

    def test_review_schedule_saved(self):
        """The review job interval (hours + minutes) is saved and read back; under 5 minutes or a non-number is refused.
        REQ: SET-64"""
        a = admin()
        r = self.ok(a, "/api/config/review-schedule", {"hours": 2, "minutes": 30})
        self.assertEqual(r["review"]["interval_minutes"], 150)
        self.assertEqual(a.get("/api/config/triage")[1]["review"]["interval_minutes"], 150)
        self.bad_unchanged(a, [("/api/config/review-schedule", {"hours": 0, "minutes": 0}),
                               ("/api/config/review-schedule", {"hours": 30}),
                               ("/api/config/review-schedule", {"hours": "two"})],
                           lambda: aireview(a)["review"]["interval_minutes"])

    def test_review_job_switch_and_modes(self):
        """The review job on/off switch and per-category modes are saved; unknown modes or all-skip are refused.
        REQ: SET-64"""
        a = admin()
        self.ok(a, "/api/llm/review", {"enabled": False, "modes": {"info": "skip", "low": "queue"}})
        rv = aireview(a)["review"]
        self.assertIs(rv["enabled"], False)
        self.assertEqual((rv["modes"]["info"], rv["modes"]["low"]), ("skip", "queue"))
        self.ok(a, "/api/llm/review", {"enabled": True})
        self.assertIs(aireview(a)["review"]["enabled"], True)
        self.assertEqual(aireview(a)["review"]["modes"]["info"], "skip")  # untouched fields keep their value
        every = {k: "skip" for k in aireview(a)["review"]["modes"]}
        self.bad_unchanged(a, [("/api/llm/review", {"modes": {"e2e-cat": "review"}}), ("/api/llm/review", {"modes": {"info": "e2e"}}),
                               ("/api/llm/review", {"modes": every}), ("/api/llm/review", {"modes": "review"})],
                           lambda: aireview(a)["review"])

    def test_research_limits_saved(self):
        """Event research cost caps and web / Elasticsearch access are saved; out-of-range caps are refused.
        REQ: SET-64"""
        a = admin()
        self.ok(a, "/api/llm/research", {"max_batches": 7, "max_run_usd": 2.5, "web_research": True, "es_search": False})
        rs = aireview(a)["research"]
        self.assertEqual((rs["limits"]["max_batches"], rs["limits"]["max_run_usd"], rs["web_research"], rs["es_search"]), (7, 2.5, True, False))
        self.bad_unchanged(a, [("/api/llm/research", {"max_batches": 99}), ("/api/llm/research", {"max_run_usd": -1}),
                               ("/api/llm/research", {"max_searches": "many"})],
                           lambda: {k: v for k, v in aireview(a)["research"].items() if k != "spent_today_usd"})

    def test_autoclose_settings_saved(self):
        """Auto-close switches and guard rails are saved and read back; out-of-range guard values are clamped, unknown
        categories dropped.
        REQ: SET-64"""
        a = admin()
        r = self.ok(a, "/api/config/triage", {"reviewer_benign": True, "min_conf": 0.9, "expire_days": 3, "protect": ["admin"]})
        self.assertTrue(r["admin"])
        s = a.get("/api/config/triage")[1]["settings"]
        self.assertEqual((s["reviewer_benign"], s["reviewer_expected"], s["min_conf"], s["expire_days"], s["protect"]),
                         (True, False, 0.9, 3, ["admin"]))
        self.assertEqual(s["updated_by"], harness.ADMIN_USER)
        self.ok(a, "/api/config/triage", {"min_conf": 7, "expire_days": 9999, "protect": ["e2e-cat", "admin"]})
        s = a.get("/api/config/triage")[1]["settings"]
        self.assertEqual((s["min_conf"], s["expire_days"], s["protect"], s["reviewer_benign"]), (1.0, 365, ["admin"], False))

    def test_autoclose_reopen_actions(self):
        """Reopen auto-closed items and reopen-held-by-guard answer 200 with the auto-close view and keep the settings.
        REQ: SET-64"""
        a = admin()
        self.ok(a, "/api/config/triage", {"researcher_expected": True, "min_conf": 0.85})
        for p, b in (("/api/config/triage/reopen", {}), ("/api/config/triage/reopen", {"kind": "reviewer_benign"}),
                     ("/api/config/triage/reopen-guard", {})):
            r = self.ok(a, p, b)
            self.assertIn("settings", r, p)
            self.assertEqual((r["settings"]["researcher_expected"], r["settings"]["min_conf"]), (True, 0.85), p)


class Models(Base):
    """AI providers and the model each AI role uses."""

    def test_provider_saved_key_masked(self):
        """An added AI provider is listed with its models and only a masked key.
        REQ: SET-65, SET-61"""
        p = provider()
        ps = {x["id"]: x for x in admin().get("/api/llm/providers")[1]["providers"]}
        self.assertIn(p["id"], ps)
        self.assertEqual(ps[p["id"]]["models"], ["e2e-model-a", "e2e-model-b"])
        self.assertTrue(ps[p["id"]]["key_set"])
        self.assertTrue(ps[p["id"]]["key_hint"].endswith("pv01"))
        self.assertLess(len(ps[p["id"]]["key_hint"]), 8)
        self.assertNotIn(p["key"], json.dumps(ps))
        self.assertNotIn(p["key"], json.dumps(admin().get("/api/llm/models")[1]))

    def test_provider_update_keeps_key(self):
        """Updating a provider without a key keeps the stored key and applies the new settings.
        REQ: SET-65, SET-61"""
        p, a = provider(), admin()
        self.ok(a, "/api/llm/providers", {"action": "save", "id": p["id"], "type": "openai", "name": "E2E settings provider",
                                          "models": ["e2e-model-a", "e2e-model-b"], "rate_per_hour": 42})
        row = next(x for x in a.get("/api/llm/providers")[1]["providers"] if x["id"] == p["id"])
        self.assertEqual(row["rate_per_hour"], 42)
        self.assertTrue(row["key_set"])
        self.assertTrue(row["key_hint"].endswith("pv01"))

    def test_invalid_provider_rejected(self):
        """Unknown provider types, missing names or keys, bad model ids and unknown actions return 400 and save nothing.
        REQ: SET-65"""
        a = admin()
        provider()
        self.bad_unchanged(a, [
            ("/api/llm/providers", {"action": "save", "type": "e2e-type", "name": "e2e bad", "api_key": fake_key("bd01")}),
            ("/api/llm/providers", {"action": "save", "type": "openai", "name": "", "api_key": fake_key("bd02")}),
            ("/api/llm/providers", {"action": "save", "type": "openai", "name": "e2e nokey"}),
            ("/api/llm/providers", {"action": "save", "type": "openai", "name": "e2e badmodel", "api_key": fake_key("bd03"), "models": ["bad model!"]}),
            ("/api/llm/providers", {"action": "save", "type": "openai", "name": "E2E settings provider", "api_key": fake_key("bd04")}),
            ("/api/llm/providers", {"action": "save", "id": "e2e-none", "type": "openai", "name": "e2e ghost"}),
            ("/api/llm/providers", {"action": "e2e-action"}),
            ("/api/llm/providers", {}),
        ], lambda: admin().get("/api/llm/providers")[1]["providers"])

    def test_model_choice_saved_per_section(self):
        """The event reviewer, research and chat models are saved and shown; an unknown provider or model is refused.
        REQ: SET-65"""
        p, a = provider(), admin()
        r = self.ok(a, "/api/llm/config", {"section": "chat", "provider": p["provider"], "model": "e2e-model-b"})
        self.assertEqual(r["chat"]["model"], "e2e-model-b")
        self.ok(a, "/api/llm/config", {"section": "correlation", "provider": p["provider"], "model": "e2e-model-a"})
        self.ok(a, "/api/llm/config", {"section": "research", "provider": p["provider"], "model": "e2e-model-a"})
        ai = aireview(a)
        self.assertEqual((ai["chat"]["provider"], ai["chat"]["model"]), (p["provider"], "e2e-model-b"))
        self.assertEqual((ai["config"]["correlation"]["provider"], ai["config"]["correlation"]["model"]), (p["provider"], "e2e-model-a"))
        self.assertEqual((ai["research"]["provider"], ai["research"]["model"]), (p["provider"], "e2e-model-a"))
        self.bad_unchanged(a, [
            ("/api/llm/config", {"section": "chat", "provider": p["provider"], "model": "e2e-not-listed"}),
            ("/api/llm/config", {"section": "chat", "provider": "api:e2e-none", "model": "e2e-model-a"}),
            ("/api/llm/config", {"section": "e2e-section", "provider": p["provider"], "model": "e2e-model-a"}),
            ("/api/llm/config", {}),
        ], lambda: (lambda x: (x["chat"], x["config"]["correlation"], x["research"]["model"]))(aireview(a)))
        b = self.bad(a, "/api/llm/providers", {"action": "delete", "id": p["id"]})  # still in use: refused
        self.assertIn("used by", b["error"])


class EventReviewer(Base):
    """Event reviewer look-ups, decision model, context notes, note consolidation and review limits."""

    def cfg(self, k):
        return aireview()["config"][k]

    def test_es_queries_saved(self):
        """Elasticsearch look-ups per event are saved; 0, over the limit or missing are refused.
        REQ: SET-66"""
        a = admin()
        r = self.ok(a, "/api/llm/esqueries", {"enabled": True, "max": 4})
        self.assertEqual((r["es_queries"]["enabled"], r["es_queries"]["max"]), (True, 4))
        self.assertEqual((self.cfg("es_queries")["enabled"], self.cfg("es_queries")["max"]), (True, 4))
        self.bad_unchanged(a, [("/api/llm/esqueries", {"enabled": True, "max": 0}), ("/api/llm/esqueries", {"enabled": True, "max": 999}),
                               ("/api/llm/esqueries", {"enabled": True}), ("/api/llm/esqueries", {"enabled": True, "max": "four"})],
                           lambda: self.cfg("es_queries"))

    def test_web_search_saved(self):
        """Web look-ups per event are saved; out of range is refused.
        REQ: SET-66"""
        a = admin()
        self.ok(a, "/api/llm/websearch", {"enabled": True, "max": 3})
        self.assertEqual((self.cfg("web_search")["enabled"], self.cfg("web_search")["max"]), (True, 3))
        self.ok(a, "/api/llm/websearch", {"enabled": False, "max": 3})
        self.assertIs(self.cfg("web_search")["enabled"], False)
        self.bad_unchanged(a, [("/api/llm/websearch", {"enabled": True, "max": 11}), ("/api/llm/websearch", {"enabled": True, "max": None})],
                           lambda: self.cfg("web_search"))

    def test_lookup_plan_and_chat_es_saved(self):
        """The look-ups-first switch and the Ask AI Elasticsearch switch are saved both ways.
        REQ: SET-66"""
        a = admin()
        for v in (False, True):
            self.assertIs(self.ok(a, "/api/llm/lookupplan", {"enabled": v})["lookup_plan"]["enabled"], v)
            self.assertIs(self.cfg("lookup_plan")["enabled"], v)
            self.assertIs(self.ok(a, "/api/llm/chat-es", {"enabled": v})["chat_es"]["enabled"], v)
            self.assertIs(self.cfg("chat_es")["enabled"], v)

    def test_web_cache_saved_and_cleared(self):
        """The web cache switch and days kept are saved; clearing answers 200; 0 or over 30 days is refused.
        REQ: SET-66"""
        a = admin()
        self.ok(a, "/api/llm/webcache", {"enabled": False, "days": 3})
        wc = aireview(a)["web_cache"]
        self.assertEqual((wc["enabled"], wc["days"]), (False, 3))
        self.assertEqual(self.ok(a, "/api/llm/webcache", {"action": "clear"})["web_cache"]["cleared"], 0)
        self.bad_unchanged(a, [("/api/llm/webcache", {"enabled": True, "days": 0}), ("/api/llm/webcache", {"enabled": True, "days": 31}),
                               ("/api/llm/webcache", {"enabled": True})],
                           lambda: {k: aireview(a)["web_cache"][k] for k in ("enabled", "days")})

    def test_clef_saved(self):
        """The decision model switch and its thresholds are saved; thresholds outside 0.05-0.95 are refused.
        REQ: SET-66"""
        a = admin()
        r = self.ok(a, "/api/llm/clef", {"enabled": False, "related_min": 0.6, "suspicious_min": 0.7})
        self.assertEqual((r["clef"]["enabled"], r["clef"]["related_min"]), (False, 0.6))
        c = aireview(a)["clef"]["config"]
        self.assertEqual((c["enabled"], c["related_min"], c["suspicious_min"]), (False, 0.6, 0.7))
        self.bad_unchanged(a, [("/api/llm/clef", {"enabled": True, "related_min": 2}), ("/api/llm/clef", {"suspicious_min": 0.01}),
                               ("/api/llm/clef", {"related_min": "high"})],
                           lambda: aireview(a)["clef"]["config"])

    def test_context_notes_saved(self):
        """Notes per event, note characters and notes per host are saved; out of range or nothing to set is refused.
        REQ: SET-66"""
        a = admin()
        self.ok(a, "/api/llm/notes", {"max": 5, "chars": 5000, "per_subject": 20})
        n = self.cfg("context_notes")
        self.assertEqual((n["max"], n["chars"], n["per_subject"]), (5, 5000, 20))
        self.bad_unchanged(a, [("/api/llm/notes", {"max": 0}), ("/api/llm/notes", {"chars": 10}), ("/api/llm/notes", {"per_subject": 501}),
                               ("/api/llm/notes", {}), ("/api/llm/notes", {"max": "five"})],
                           lambda: self.cfg("context_notes"))

    def test_notes_consolidation_saved(self):
        """The nightly note consolidation switch, time and time zone are saved; a bad time or zone is refused.
        REQ: SET-66"""
        a = admin()
        r = self.ok(a, "/api/llm/notes-consolidate", {"enabled": False, "time": "02:15", "tz": "UTC"})
        self.assertEqual((r["notes_consolidate"]["enabled"], r["notes_consolidate"]["time"]), (False, "02:15"))
        v = a.get("/api/llm/notes-consolidate")[1]
        self.assertEqual((v["enabled"], v["time"], v["tz"]), (False, "02:15", "UTC"))
        self.bad_unchanged(a, [("/api/llm/notes-consolidate", {"time": "25:00"}), ("/api/llm/notes-consolidate", {"time": "2pm"}),
                               ("/api/llm/notes-consolidate", {"tz": "E2E/Nowhere"})],
                           lambda: {k: a.get("/api/llm/notes-consolidate")[1][k] for k in ("enabled", "time", "tz")})

    def test_review_limits_saved(self):
        """Review limits (max links, classification, time window, verdict retention, pair modes) are saved; bad values refused.
        REQ: SET-66"""
        a = admin()
        self.ok(a, "/api/llm/review-limits", {"max_links": 7, "classify": True, "window": 30, "discard_days": 10,
                                              "pair_modes": {"alert-vuln": "review"}})
        L = aireview(a)["limits"]
        self.assertEqual((L["max_links"], L["classify"], L["window_minutes"], L["discard_days"], L["pair_modes"].get("alert-vuln")),
                         (7, True, 30, 10, "review"))
        self.bad_unchanged(a, [("/api/llm/review-limits", {"max_links": -1}), ("/api/llm/review-limits", {"max_links": 201}),
                               ("/api/llm/review-limits", {"window": "soon"}), ("/api/llm/review-limits", {"discard_days": -2}),
                               ("/api/llm/review-limits", {"pair_modes": {"Bad Pair": "review"}}),
                               ("/api/llm/review-limits", {"skip_pairs": "alert-vuln"})],
                           lambda: {k: aireview(a)["limits"][k] for k in ("max_links", "classify", "window_minutes", "discard_days", "pair_modes")})


class SettingsDocs(Base):
    """Settings page documents and auto-tune."""

    def policy(self):
        return admin().get("/api/config/cfg?doc=policy")[1]["data"]

    def test_cfg_value_saved(self):
        """Setting one value inside a settings document is read back by GET /api/config/cfg.
        REQ: SET-67"""
        a = admin()
        code, body, _ = a.get("/api/config/cfg?doc=policy")
        self.assertEqual(code, 200)
        self.assertEqual(set(body["docs"]), {"policy", "host_policy", "known_benign", "site"})
        self.assertIn("upload_spike", body["data"])
        r = self.ok(a, "/api/config/cfg", {"doc": "policy", "path": ["upload_spike", "min_mb"], "value": 31})
        self.assertGreater(r["rows"], 0)
        self.assertEqual(self.policy()["upload_spike"]["min_mb"], 31)

    def test_cfg_bad_doc_path_value_rejected(self):
        """Unknown documents, malformed or private paths and values that fail validation return 400 and save nothing.
        REQ: SET-67"""
        a = admin()
        self.ok(a, "/api/config/cfg", {"doc": "policy", "path": ["upload_spike", "min_mb"], "value": 33})
        self.bad_unchanged(a, [
            ("/api/config/cfg", {"doc": "e2e-doc", "path": ["x"], "value": 1}),
            ("/api/config/cfg", {"doc": "policy", "path": [], "value": 1}),
            ("/api/config/cfg", {"doc": "policy", "path": "upload_spike", "value": 1}),
            ("/api/config/cfg", {"doc": "policy", "path": ["upload_spike", "min_mb"]}),
            ("/api/config/cfg", {"doc": "policy", "path": ["a", "b", "c", "d", "e", "f", "g"], "value": 1}),
            ("/api/config/cfg", {"doc": "policy", "path": ["e2e-missing", "x"], "value": 1}),
            ("/api/config/cfg", {"doc": "policy", "path": ["_private"], "value": 1}),
            ("/api/config/cfg", {"doc": "policy", "path": ["upload_spike", "min_mb"], "value": "lots"}),
            ("/api/config/cfg", {"doc": "policy", "path": ["upload_spike", "severity"], "value": "e2e"}),
            ("/api/config/cfg", {"doc": "policy", "path": ["zones"], "value": {"e2e": "not-a-cidr"}}),
        ], self.policy)
        self.assertEqual(self.policy()["upload_spike"]["min_mb"], 33)
        self.assertEqual(a.get("/api/config/cfg?doc=e2e-doc")[0], 404)

    def test_tune_recommend_and_empty_apply(self):
        """Auto-tune recommendations are read-only; applying an empty selection answers 409 and writes nothing.
        REQ: SET-67"""
        a = admin()
        before = self.policy()
        code, body, _ = a.get("/api/config/tune")
        self.assertEqual(code, 200)
        self.assertIsInstance(body["recommendations"], list)
        self.assertTrue(all("id" in r and "status" in r for r in body["recommendations"]))
        self.assertEqual(self.policy(), before)
        for b in ({"accept": []}, {}, {"accept": [{"id": "e2e-no-such-rec", "changes": {}}]}):
            self.bad(a, "/api/config/tune-apply", b, codes=(409,))
        self.assertEqual(self.policy(), before)


class PushPrefs(Base):
    """Own notification device choice (Alerts > Notification settings)."""

    def test_admin_and_defender_set_own_prefs(self):
        """An admin and a defender each save their own device choice, read back by GET /api/push/prefs.
        REQ: SET-68"""
        for c in (admin(), as_(DEFENDER)):
            r = self.ok(c, "/api/push/prefs", {"mode": "some", "devices": ["e2e-dev-1", "e2e-dev-2"]})
            self.assertEqual(r["prefs"], {"mode": "some", "devices": ["e2e-dev-1", "e2e-dev-2"]})
            self.assertEqual(c.get("/api/push/prefs")[1]["prefs"]["devices"], ["e2e-dev-1", "e2e-dev-2"])
            self.ok(c, "/api/push/prefs", {"mode": "all"})
            self.assertEqual(c.get("/api/push/prefs")[1]["prefs"]["mode"], "all")

    def test_some_without_devices_rejected(self):
        """Choosing "some devices" with none picked returns 400 and keeps the old choice.
        REQ: SET-68"""
        a = admin()
        self.ok(a, "/api/push/prefs", {"mode": "some", "devices": ["e2e-dev-3"]})
        self.bad_unchanged(a, [("/api/push/prefs", {"mode": "some", "devices": []})], lambda: a.get("/api/push/prefs")[1]["prefs"])

    def test_user_cannot_change_prefs(self):
        """A User cannot choose their own alert devices (an admin assigns them): 403.
        REQ: SET-68, SET-69"""
        u = as_(USER)
        before = u.get("/api/push/prefs")[1]["prefs"]
        self.bad(u, "/api/push/prefs", {"mode": "some", "devices": ["e2e-dev-4"]}, codes=(403,))
        self.assertEqual(u.get("/api/push/prefs")[1]["prefs"], before)


def admin_only_posts():
    """A valid body for every admin-only settings POST."""
    return [
        ("/api/config/integrations/elasticsearch", {"url": ES_URL, "api_key": fake_key("dn01")}),
        ("/api/config/integrations/unifi", {"url": LOOP}),
        ("/api/config/integrations/audit", {"send_reviewer": False}),
        ("/api/config/integrations/web", {"provider": "brave", "api_key": fake_key("dn02")}),
        ("/api/config/integrations/opencti", {"min_score": 12}),
        ("/api/config/integrations/feeds", {"items": [{"name": "e2e_denied", "url": LOOP, "kind": "ips"}]}),
        ("/api/config/lookback", {"hours": 2}),
        ("/api/config/review-schedule", {"hours": 9}),
        ("/api/config/triage", {"reviewer_expected": True, "min_conf": 0.55}),
        ("/api/config/triage/reopen", {}),
        ("/api/config/triage/reopen-guard", {}),
        ("/api/config/cfg", {"doc": "policy", "path": ["upload_spike", "min_mb"], "value": 77}),
        ("/api/config/tune-apply", {"accept": []}),
        ("/api/llm/config", {"section": "chat", "provider": provider()["provider"], "model": "e2e-model-a"}),
        ("/api/llm/esqueries", {"enabled": True, "max": 17}),
        ("/api/llm/websearch", {"enabled": True, "max": 9}),
        ("/api/llm/lookupplan", {"enabled": False}),
        ("/api/llm/webcache", {"enabled": True, "days": 29}),
        ("/api/llm/clef", {"related_min": 0.11}),
        ("/api/llm/notes", {"max": 99}),
        ("/api/llm/notes-consolidate", {"time": "04:44"}),
        ("/api/llm/research", {"max_batches": 39}),
        ("/api/llm/review", {"enabled": False}),
        ("/api/llm/providers", {"action": "save", "type": "openai", "name": "e2e denied", "api_key": fake_key("dn03")}),
    ]


class RoleEnforcement(Base):
    """Admin-only settings refuse defenders and users; what they may change themselves."""

    def test_defender_refused_admin_settings(self):
        """A Network defender gets 403 with a JSON error on every admin-only settings POST and nothing changes.
        REQ: SET-69"""
        d = as_(DEFENDER)
        posts = admin_only_posts()
        before = settings_state()
        for p, b in posts:
            self.bad(d, p, b, codes=(403,))
        self.assertEqual(settings_state(), before)

    def test_user_refused_all_settings(self):
        """A User gets 403 on every settings POST, including review limits, the chat switch and notification devices.
        REQ: SET-69"""
        u = as_(USER)
        posts = admin_only_posts() + [("/api/llm/review-limits", {"max_links": 66}), ("/api/llm/chat-es", {"enabled": False}),
                                      ("/api/push/prefs", {"mode": "some", "devices": ["e2e-dev-5"]})]
        before = settings_state()
        for p, b in posts:
            self.bad(u, p, b, codes=(403,))
        self.assertEqual(settings_state(), before)

    def test_defender_reads_no_secrets_or_admin_views(self):
        """A defender gets no integration settings or provider list, and 403 on auto-tune.
        REQ: SET-69, SET-61"""
        d = as_(DEFENDER)
        self.assertEqual(d.get("/api/config/integrations")[1], {"admin": False})
        self.assertEqual(d.get("/api/llm/providers")[1], {"admin": False, "providers": []})
        self.assertEqual(d.get("/api/config/tune")[0], 403)
        self.assertIs(d.get("/api/config/cfg?doc=policy")[1]["admin"], False)
        self.assertIs(d.get("/api/config/triage")[1]["admin"], False)

    def test_defender_may_set_review_limits(self):
        """A Network defender may change Review limits (analyst work per ACCESS_CONTROL.md), and the change is saved.
        REQ: SET-69"""
        d = as_(DEFENDER)
        code, body, _ = d.post("/api/llm/review-limits", {"max_links": 13})
        self.assertEqual(code, 200, body)
        self.assertEqual(aireview()["limits"]["max_links"], 13)

    def test_defender_cannot_switch_chat_es(self):
        """A Network defender cannot switch the Ask AI Elasticsearch setting (an admin setting, like the other
        Elasticsearch-search switches): 403 and nothing changes.
        REQ: SET-69"""
        a, d = admin(), as_(DEFENDER)
        self.ok(a, "/api/llm/chat-es", {"enabled": True})
        try:
            code, _, _ = d.post("/api/llm/chat-es", {"enabled": False})
            self.assertEqual(code, 403)
            self.assertIs(aireview(a)["config"]["chat_es"]["enabled"], True)
        finally:
            self.ok(a, "/api/llm/chat-es", {"enabled": True})


class SettingsAudit(Base):
    """Every settings POST is audited (into a loopback fake Elasticsearch, or the on-disk spool) with secrets redacted."""

    def test_every_settings_post_audited(self):
        """Each successful settings POST writes an audit entry naming the admin, the path, success and status 200.
        REQ: SET-70"""
        a = admin()
        posts = [(p, b) for p, b in admin_only_posts() if p != "/api/config/tune-apply"] + [
            ("/api/llm/review-limits", {"max_links": 5}), ("/api/llm/chat-es", {"enabled": True}),
            ("/api/push/prefs", {"mode": "all"})]
        old = {r["event"]["id"] for r in audit_rows()}
        for p, b in posts:
            self.ok(a, p, b)
        self.ok(a, "/api/config/integrations/audit", {"send_reviewer": True})
        self.ok(a, "/api/config/integrations/feeds", {"delete": ["e2e_denied"]})
        want = {p for p, _ in posts}
        end = time.time() + 20
        while True:
            rows = [r for r in audit_rows() if r["event"]["id"] not in old]
            seen = {p for p in want if any(is_post(r, p) and (r.get("http") or {}).get("response", {}).get("status_code") == 200 for r in rows)}
            if seen == want or time.time() > end:
                break
            time.sleep(0.5)
        self.assertEqual(sorted(want - seen), [])
        hit = next(r for r in rows if is_post(r, "/api/config/lookback"))
        self.assertEqual(hit["user"]["roles"], ["admin"])
        self.assertEqual(hit["event"]["action"], "config.lookback")
        self.assertEqual(hit["netmon"]["params"]["hours"], 2)

    def test_secrets_redacted(self):
        """API keys sent to integration and provider settings never appear in the audit log, saved or rejected.
        REQ: SET-70, SET-61"""
        a = admin()
        k1, k2, k3, k4 = fake_key("ra01"), fake_key("ra02"), fake_key("ra03"), "e2e fake " + "x" * 16
        self.ok(a, "/api/config/integrations/elasticsearch", {"url": ES_URL, "api_key": k1})
        self.ok(a, "/api/config/integrations/opencti", {"api_key": k2})
        self.ok(a, "/api/llm/providers", {"action": "save", "type": "anthropic", "name": "E2E redaction provider", "api_key": k3,
                                          "models": ["e2e-model-c"]})
        self.bad(a, "/api/config/integrations/unifi", {"url": LOOP, "api_key": k4})
        hit, rows = audit_wait(lambda r: is_post(r, "/api/config/integrations/unifi", outcome="failure"))
        self.assertTrue(hit, f"no audit entry for the rejected save; {len(rows)} spooled")
        for p in ("/api/config/integrations/elasticsearch", "/api/config/integrations/opencti", "/api/llm/providers"):
            h, _ = audit_wait(lambda r, p=p: is_post(r, p) and (r.get("netmon") or {}).get("params", {}).get("api_key") == "[redacted]")
            self.assertTrue(h, p)
        self.assertEqual(hit[-1]["netmon"]["params"]["api_key"], "[redacted]")
        blob = json.dumps(audit_rows())
        for k in (k1, k2, k3, k4):
            self.assertNotIn(k, blob)
        self.assertNotIn(k1, json.dumps(a.get("/api/config/integrations")[1]))

    def test_rejected_and_denied_posts_audited(self):
        """A rejected settings POST is audited as a failure with its 400, and a defender's refused one with 403.
        REQ: SET-70, SET-69"""
        a, d = admin(), as_(DEFENDER)
        self.bad(a, "/api/llm/clef", {"related_min": 3})
        self.bad(d, "/api/config/lookback", {"hours": 3}, codes=(403,))
        h1, _ = audit_wait(lambda r: is_post(r, "/api/llm/clef", outcome="failure") and r["http"]["response"]["status_code"] == 400)
        h2, _ = audit_wait(lambda r: is_post(r, "/api/config/lookback", user=DEFENDER, outcome="failure")
                           and r["http"]["response"]["status_code"] == 403)
        self.assertTrue(h1)
        self.assertTrue(h2)
        self.assertEqual(h2[-1]["user"]["roles"], ["defender"])


if __name__ == "__main__":
    unittest.main()
