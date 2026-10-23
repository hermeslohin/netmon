"""Unit tests for dashboard/app/audit.py: secret redaction, entry building, spooling while Elasticsearch is down."""
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); import _env  # noqa: E401,E702,E402

import io  # noqa: E402
import json  # noqa: E402
import queue  # noqa: E402
import shutil  # noqa: E402
import stat  # noqa: E402
import tempfile  # noqa: E402
import unittest  # noqa: E402
import urllib.error  # noqa: E402
from unittest import mock  # noqa: E402

import audit  # noqa: E402
import integrations  # noqa: E402

FAKE_KEY = "test-secret-value"


def _down(*a, **k):
    raise urllib.error.URLError("connection refused (test)")


class _AuditBase(unittest.TestCase):
    """Isolation: private spool file, fresh queue and STATUS, writer thread never started."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="audit-test-", dir=_env.TMP)
        self._saved = (audit.SPOOL, audit._q, dict(audit.STATUS))
        audit.SPOOL = os.path.join(self.tmp, "audit_spool.jsonl")
        audit._q = queue.Queue(maxsize=20000)
        audit.STATUS.update(sent=0, spooled=0, dropped=0, last_ok=None, last_error="")
        for k in ("skipped", "rejected", "last_reject"):
            audit.STATUS.pop(k, None)
        self.patches = [mock.patch.object(integrations, "audit_send", lambda who: True)]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        audit.SPOOL, audit._q = self._saved[0], self._saved[1]
        audit.STATUS.clear()
        audit.STATUS.update(self._saved[2])
        shutil.rmtree(self.tmp, True)

    def queued(self):
        out = []
        while True:
            try:
                out.append(audit._q.get_nowait())
            except queue.Empty:
                return out

    def spooled(self, path=None):
        with open(path or audit.SPOOL) as f:
            return [json.loads(line) for line in f if line.strip()]


class TestClean(_AuditBase):
    """Parameter redaction and truncation (clean)."""

    def test_secret_names_redacted(self):
        """Parameters named like passwords, keys, tokens, cookies or credentials are replaced by [redacted].
        REQ: AUD-01"""
        names = ["password", "pass", "new_password", "secret", "client_secret", "token", "csrf_token", "api_key",
                 "apikey", "key", "current", "cookie", "Authorization", "auth", "p256dh", "credential", "private_key", "PASSWORD"]
        out = audit.clean({n: FAKE_KEY for n in names})
        for n in names:
            self.assertEqual(out[n], "[redacted]", n)
        self.assertNotIn(FAKE_KEY, json.dumps(out))

    def test_ordinary_names_kept(self):
        """Non-secret parameters keep their value (key matching is exact for 'key' and 'current').
        REQ: AUD-01"""
        p = {"note": "checked", "keys_count": 3, "current_view": "x", "monkey": "banana", "ip": "10.0.1.10", "label": "ok"}
        self.assertEqual(audit.clean(p), p)

    def test_empty_secret_values_not_marked(self):
        """An empty / None / False secret parameter is kept as-is (nothing to hide, shows it was blank).
        REQ: AUD-01"""
        self.assertEqual(audit.clean({"password": "", "token": None, "api_key": False}),
                         {"password": "", "token": None, "api_key": False})

    def test_nested_secrets_redacted(self):
        """Secrets inside nested dicts and lists (e.g. a push subscription's keys) are redacted too.
        REQ: AUD-01"""
        p = {"sub": {"endpoint": "https://push.example.invalid/x", "keys": {"p256dh": FAKE_KEY, "auth": FAKE_KEY}},
             "items": [{"name": "a", "token": FAKE_KEY}]}
        out = audit.clean(p)
        self.assertEqual(out["sub"]["keys"], {"p256dh": "[redacted]", "auth": "[redacted]"})
        self.assertEqual(out["items"][0], {"name": "a", "token": "[redacted]"})
        self.assertEqual(out["sub"]["endpoint"], "https://push.example.invalid/x")

    def test_whole_secret_subtree_redacted(self):
        """A dict under a secret-looking name is redacted as a whole, not descended into.
        REQ: AUD-01"""
        self.assertEqual(audit.clean({"credentials": {"user": "u", "pw": FAKE_KEY}}), {"credentials": "[redacted]"})

    def test_long_strings_truncated(self):
        """Strings longer than MAX_PARAM are cut and annotated with their original length.
        REQ: AUD-01"""
        s = "a" * (audit.MAX_PARAM + 10)
        out = audit.clean({"text": s})["text"]
        self.assertTrue(out.startswith("a" * audit.MAX_PARAM))
        self.assertTrue(out.endswith(f"[{len(s)} chars]"))
        self.assertEqual(audit.clean("b" * audit.MAX_PARAM), "b" * audit.MAX_PARAM)

    def test_lists_and_dicts_capped(self):
        """Lists keep at most 50 items, dicts at most 60 keys, keys at most 80 characters.
        REQ: AUD-01"""
        self.assertEqual(len(audit.clean(list(range(100)))), 50)
        self.assertEqual(len(audit.clean({f"k{i}": i for i in range(100)})), 60)
        self.assertEqual(list(audit.clean({"x" * 200: 1})), ["x" * 80])

    def test_depth_bounded(self):
        """Nesting deeper than 4 levels collapses to an ellipsis.
        REQ: AUD-01"""
        deep = {"a": {"b": {"c": {"d": {"e": {"f": 1}}}}}}
        self.assertEqual(audit.clean(deep)["a"]["b"]["c"]["d"]["e"], "…")

    def test_scalars_untouched(self):
        """Numbers, booleans and None pass through unchanged.
        REQ: AUD-01"""
        for v in (0, 1.5, True, None):
            self.assertEqual(audit.clean(v), v)

    def test_cut(self):
        """_cut keeps short text, turns None into '' and truncates long text with a note.
        REQ: AUD-01"""
        self.assertEqual(audit._cut(None), "")
        self.assertEqual(audit._cut("abc", 5), "abc")
        self.assertEqual(audit._cut("abcdefgh", 3), "abc\n… [truncated, 8 chars]")


class TestEntries(_AuditBase):
    """Building and queueing audit entries."""

    def test_action_entry_fields(self):
        """action() queues an ECS entry with dataset, user, role, outcome, source ip, http, url and redacted params.
        REQ: AUD-01"""
        audit.action("alice", "ack.set", role="admin", ip="10.0.1.10", method="POST", path="/api/ack", status=200,
                     params={"key": "x", "note": "fine", "password": FAKE_KEY}, target="host-a", ua="UA/1.0")
        (d,) = self.queued()
        self.assertEqual(d["event"]["dataset"], "netmon.audit")
        self.assertEqual(d["event"]["action"], "ack.set")
        self.assertEqual(d["event"]["outcome"], "success")
        self.assertEqual(d["event"]["type"], ["change"])
        self.assertEqual((d["event"]["kind"], d["event"]["module"]), ("event", "netmon"))
        self.assertTrue(d["event"]["id"])
        self.assertTrue(d["@timestamp"].endswith("Z"))
        self.assertEqual(d["user"], {"name": "alice", "roles": ["admin"]})
        self.assertEqual(d["source"], {"ip": "10.0.1.10"})
        self.assertEqual(d["http"], {"request": {"method": "POST"}, "response": {"status_code": 200}})
        self.assertEqual(d["url"], {"path": "/api/ack"})
        self.assertEqual(d["user_agent"], {"original": "UA/1.0"})
        self.assertEqual(d["netmon"]["params"], {"key": "[redacted]", "note": "fine", "password": "[redacted]"})
        self.assertEqual(d["netmon"]["target"], "host-a")
        self.assertNotIn(FAKE_KEY, json.dumps(d))

    def test_failed_sign_in_entry(self):
        """A failed sign-in is recorded with failure outcome, the user name and the default message.
        REQ: AUD-02"""
        audit.action("mallory", "login", ip="10.0.1.99", outcome="failure", params={"user": "mallory", "password": FAKE_KEY})
        (d,) = self.queued()
        self.assertEqual(d["event"]["outcome"], "failure")
        self.assertEqual(d["event"]["type"], ["info"])
        self.assertEqual(d["message"], "mallory login (failure)")
        self.assertNotIn(FAKE_KEY, json.dumps(d))

    def test_denied_request_entry(self):
        """A refused GET (403) is recorded as an access event with its status code.
        REQ: AUD-02"""
        audit.action("bob", "denied", role="user", method="GET", path="/api/settings", status=403, outcome="failure")
        (d,) = self.queued()
        self.assertEqual(d["event"]["type"], ["access"])
        self.assertEqual(d["http"]["response"]["status_code"], 403)

    def test_minimal_action(self):
        """With no user and no extras the entry uses '-' and omits optional sections.
        REQ: AUD-01"""
        audit.action(None, "page.view")
        (d,) = self.queued()
        self.assertEqual(d["user"], {"name": "-"})
        for k in ("source", "http", "url", "netmon", "user_agent"):
            self.assertNotIn(k, d)

    def test_long_fields_truncated(self):
        """User names, paths, targets and user agents are length-capped.
        REQ: AUD-01"""
        audit.action("u" * 200, "x", path="/" + "p" * 500, target="t" * 2000, ua="a" * 1000)
        (d,) = self.queued()
        self.assertEqual(len(d["user"]["name"]), 80)
        self.assertEqual(len(d["url"]["path"]), 300)
        self.assertEqual(len(d["netmon"]["target"]), 1024)
        self.assertEqual(len(d["user_agent"]["original"]), 512)

    def test_llm_entry(self):
        """llm() records provider, model, prompt, completion, token usage, duration and failure outcome.
        REQ: AUD-01"""
        audit.llm("chat", "local", "model-x", user="alice", system="sys", prompt="q", response="a",
                  usage={"prompt_tokens": 12, "completion_tokens": 5}, seconds=1.5, error="boom", session="s1", tools=["t1"])
        (d,) = self.queued()
        self.assertEqual(d["event"]["dataset"], "netmon.llm")
        self.assertEqual(d["event"]["action"], "llm.chat")
        self.assertEqual(d["event"]["outcome"], "failure")
        self.assertEqual(d["event"]["duration"], 1_500_000_000)
        self.assertEqual(d["gen_ai"]["usage"], {"input_tokens": 12, "output_tokens": 5})
        self.assertEqual((d["gen_ai"]["prompt"], d["gen_ai"]["completion"]), ("q", "a"))
        L = d["netmon"]["llm"]
        self.assertEqual((L["system_prompt"], L["session_id"], L["tools"], L["error"]), ("sys", "s1", ["t1"], "boom"))
        self.assertIn(" - boom", d["message"])

    def test_llm_status_outcome_and_no_usage(self):
        """A cancelled LLM run is a failure; without usage numbers no usage block is written.
        REQ: AUD-01"""
        audit.llm("research", "p", "m", status="cancelled")
        audit.llm("research", "p", "m", status="done")
        a, b = self.queued()
        self.assertEqual(a["event"]["outcome"], "failure")
        self.assertEqual(b["event"]["outcome"], "success")
        self.assertNotIn("usage", a["gen_ai"])

    def test_background_actor_switched_off(self):
        """Entries from the background reviewer are skipped when its sending is switched off; users are not.
        REQ: AUD-01"""
        with mock.patch.object(integrations, "audit_send", lambda who: who != "reviewer"):
            audit.action("netmon (background reviewer)", "verdict")
            audit.action("netmon (research job)", "put")
            audit.action("alice", "x")
        self.assertEqual([d["user"]["name"] for d in self.queued()], ["netmon (research job)", "alice"])
        self.assertEqual(audit.STATUS["skipped"], 1)

    def test_full_queue_drops_without_raising(self):
        """When the in-memory queue is full, emit counts a drop instead of raising or blocking.
        REQ: AUD-03"""
        audit._q = queue.Queue(maxsize=1)
        audit.action("a", "one")
        audit.action("a", "two")
        self.assertEqual(audit.STATUS["dropped"], 1)
        self.assertEqual(len(self.queued()), 1)

    def test_existing_timestamp_and_id_kept(self):
        """emit keeps a caller-supplied @timestamp and event id.
        REQ: AUD-01"""
        audit.emit({"@timestamp": "2026-01-01T00:00:00Z", "event": {"id": "fixed"}, "user": {"name": "x"}})
        (d,) = self.queued()
        self.assertEqual((d["@timestamp"], d["event"]["id"]), ("2026-01-01T00:00:00Z", "fixed"))


class TestSpoolAndFlush(_AuditBase):
    """Writing to Elasticsearch, spooling while it is unreachable, and draining the spool."""

    def test_flush_nothing_to_do(self):
        """With an empty queue and no spool, flush returns 0 without contacting Elasticsearch.
        REQ: AUD-03"""
        with mock.patch.object(audit, "_es", side_effect=AssertionError("must not be called")):
            self.assertEqual(audit.flush(), 0)

    def test_unreachable_es_spools_entries(self):
        """When ES is unreachable, queued entries go to the owner-only spool file and flush does not raise.
        REQ: AUD-03"""
        audit.action("alice", "a1")
        audit.action("alice", "a2")
        with mock.patch.object(audit, "_es", side_effect=_down):
            self.assertEqual(audit.flush(), 0)
        self.assertEqual([d["event"]["action"] for d in self.spooled()], ["a1", "a2"])
        self.assertEqual(audit.STATUS["spooled"], 2)
        self.assertIn("URLError", audit.STATUS["last_error"])
        self.assertEqual(stat.S_IMODE(os.stat(audit.SPOOL).st_mode), 0o600)

    def test_no_key_configured_spools(self):
        """Without an audit key the real _es refuses and entries are spooled, never sent.
        REQ: AUD-03"""
        with mock.patch.object(integrations, "audit_key", lambda: ""), \
                mock.patch("urllib.request.urlopen", side_effect=AssertionError("no network")):
            audit.action("alice", "a1")
            self.assertEqual(audit.flush(), 0)
        self.assertIn("not configured", audit.STATUS["last_error"])
        self.assertEqual(len(self.spooled()), 1)

    def test_bad_url_scheme_refused(self):
        """_es refuses non-http(s) Elasticsearch URLs.
        REQ: AUD-03"""
        with mock.patch.object(integrations, "es_url", lambda: "file:///etc/passwd"), \
                mock.patch.object(integrations, "audit_key", lambda: FAKE_KEY):
            with self.assertRaisesRegex(RuntimeError, "bad Elasticsearch URL"):
                audit._es("GET", "/x")

    def test_es_request_shape(self):
        """_es sends ApiKey auth and ndjson content type to the configured URL and parses JSON.
        REQ: AUD-03"""
        seen = {}

        def fake_urlopen(req, context=None, timeout=None):
            seen.update(url=req.full_url, auth=req.get_header("Authorization"), ct=req.get_header("Content-type"), data=req.data)
            return io.BytesIO(b'{"ok": true}')

        with mock.patch.object(integrations, "es_url", lambda: "http://10.0.0.5:9200"), \
                mock.patch.object(integrations, "audit_key", lambda: FAKE_KEY), \
                mock.patch("urllib.request.urlopen", fake_urlopen):
            self.assertEqual(audit._es("POST", "/_bulk", "line\n", ndjson=True), {"ok": True})
        self.assertEqual(seen["url"], "http://10.0.0.5:9200/_bulk")
        self.assertEqual(seen["auth"], f"ApiKey {FAKE_KEY}")
        self.assertEqual(seen["ct"], "application/x-ndjson")
        self.assertEqual(seen["data"], b"line\n")

    def test_bulk_body_and_rejections(self):
        """_bulk sends create actions for the audit index and counts per-entry rejections without failing the batch.
        REQ: AUD-03"""
        bodies = []

        def fake_es(method, path, body=None, **kw):
            bodies.append(body)
            return {"errors": True, "items": [{"create": {"status": 201}}, {"create": {"error": {"type": "mapper_parsing"}}}]}

        with mock.patch.object(audit, "_es", fake_es), mock.patch("sys.stderr", io.StringIO()):
            self.assertEqual(audit._bulk([{"a": 1}, {"b": 2}]), 1)
        lines = bodies[0].strip().split("\n")
        self.assertEqual(len(lines), 4)
        self.assertEqual(json.loads(lines[0]), {"create": {"_index": audit.index()}})
        self.assertEqual(audit.STATUS["rejected"], 1)
        self.assertIn("mapper_parsing", audit.STATUS["last_reject"])

    def test_spool_drained_when_es_returns(self):
        """Once ES works, flush sends the spool first (oldest first), then the new entries, and removes the spool.
        REQ: AUD-03"""
        audit.action("alice", "old1")
        with mock.patch.object(audit, "_es", side_effect=_down):
            audit.flush()
        sent = []

        def ok_bulk(docs):
            sent.append([d["event"]["action"] for d in docs])
            return len(docs)

        audit.action("alice", "new1")
        with mock.patch.object(audit, "_bulk", ok_bulk):
            self.assertEqual(audit.flush(), 1)
        self.assertEqual(sent, [["old1"], ["new1"]])
        self.assertFalse(os.path.exists(audit.SPOOL))
        self.assertFalse(os.path.exists(audit.SPOOL + ".sending"))
        self.assertEqual(audit.STATUS["spooled"], 0)
        self.assertEqual(audit.STATUS["sent"], 2)
        self.assertEqual(audit.STATUS["last_error"], "")

    def test_partial_drain_keeps_unsent_without_duplicates(self):
        """If ES fails mid-drain, only the not-yet-sent chunk remains on disk for the retry.
        REQ: AUD-03"""
        with open(audit.SPOOL, "w") as f:
            for i in range(700):
                f.write(json.dumps({"n": i}) + "\n")
        calls = []

        def flaky(docs):
            calls.append(len(docs))
            if len(calls) == 2:
                raise urllib.error.URLError("down again")
            return len(docs)

        with mock.patch.object(audit, "_bulk", flaky):
            self.assertEqual(audit.flush(), 0)
        left = self.spooled(audit.SPOOL + ".sending")
        self.assertEqual([d["n"] for d in left], list(range(500, 700)))
        self.assertEqual(calls, [500, 200])

    def test_drain_false_leaves_spool(self):
        """flush(drain=False) (CLI processes) sends only the new entries and leaves the spool for the server.
        REQ: AUD-03"""
        with open(audit.SPOOL, "w") as f:
            f.write(json.dumps({"n": 1}) + "\n")
        sent = []
        audit.action("cli", "x")
        with mock.patch.object(audit, "_bulk", lambda docs: sent.append(docs) or len(docs)):
            self.assertEqual(audit.flush(drain=False), 1)
        self.assertEqual(len(sent), 1)
        self.assertEqual(len(self.spooled()), 1)

    def test_spool_cap_drops(self):
        """When the spool exceeds its size cap, further entries are counted as dropped, not written.
        REQ: AUD-03"""
        with open(audit.SPOOL, "w") as f:
            f.write("x\n")
        with mock.patch.object(audit, "SPOOL_MAX", 0):
            audit._spool([{"a": 1}, {"b": 2}])
        self.assertEqual(audit.STATUS["dropped"], 2)
        self.assertEqual(os.path.getsize(audit.SPOOL), 2)

    def test_spool_unwritable_never_raises(self):
        """If the spool cannot be written (missing directory), entries are dropped and nothing raises.
        REQ: AUD-03"""
        audit.SPOOL = os.path.join(self.tmp, "missing-dir", "spool.jsonl")
        with mock.patch("sys.stderr", io.StringIO()):
            audit._spool([{"a": 1}])
            audit.action("alice", "x")
            with mock.patch.object(audit, "_es", side_effect=_down):
                self.assertEqual(audit.flush(), 0)
        self.assertEqual(audit.STATUS["dropped"], 2)

    def test_flush_with_explicit_batch(self):
        """flush(batch) sends the given entries together with anything queued.
        REQ: AUD-03"""
        audit.action("alice", "queued")
        got = []
        with mock.patch.object(audit, "_bulk", lambda docs: got.extend(docs) or len(docs)):
            self.assertEqual(audit.flush([{"event": {"action": "given"}}]), 2)
        self.assertEqual([d["event"]["action"] for d in got], ["given", "queued"])

    def test_non_json_values_spooled_as_strings(self):
        """Values that are not JSON-serialisable (e.g. sets) are stringified in the spool instead of failing.
        REQ: AUD-03"""
        with mock.patch.object(audit, "_es", side_effect=_down):
            audit.flush([{"weird": {1, 2}}])
        self.assertIsInstance(self.spooled()[0]["weird"], str)


class TestReading(_AuditBase):
    """Query building for the Audit log page and status reporting."""

    def test_search_rejects_bad_times(self):
        """search() rejects start/end values that are not ISO timestamps with an offset.
        REQ: AUD-01"""
        with mock.patch.object(audit, "_es", side_effect=AssertionError("not reached")):
            with self.assertRaisesRegex(ValueError, "bad start"):
                audit.search({"start": "yesterday"})
            with self.assertRaisesRegex(ValueError, "bad end"):
                audit.search({"start": "2026-01-01T00:00Z", "end": "2026-01-02 00:00"})

    def test_search_query_and_rows(self):
        """search() builds filters from kind/user/outcome, bounds the page, and maps hits to rows.
        REQ: AUD-01"""
        seen = {}

        def fake_es(method, path, body=None, **kw):
            seen["body"] = body
            return {"hits": {"total": {"value": 1}, "hits": [{"_id": "abc", "_source": {
                "@timestamp": "t", "event": {"dataset": "netmon.llm", "action": "llm.chat", "outcome": "success", "duration": 2_000_000_000},
                "user": {"name": "alice", "roles": ["admin"]}, "gen_ai": {"request": {"model": "m"}, "system": "p"}}}]},
                "aggregations": {"users": {"buckets": [{"key": "alice", "doc_count": 1}]}, "tin": {"value": 7}}}

        with mock.patch.object(audit, "_es", fake_es):
            r = audit.search({"kind": "llm", "user": "alice", "outcome": "success", "page": "999", "q": "hello"})
        flt = seen["body"]["query"]["bool"]["filter"]
        self.assertIn({"term": {"event.dataset": "netmon.llm"}}, flt)
        self.assertIn({"term": {"user.name": "alice"}}, flt)
        self.assertIn({"range": {"@timestamp": {"gte": "now-24h"}}}, flt)
        self.assertEqual(r["page"], 190)
        self.assertEqual(seen["body"]["from"], 190 * 50)
        self.assertEqual(r["total"], 1)
        row = r["rows"][0]
        self.assertEqual((row["id"], row["kind"], row["role"], row["model"], row["seconds"]), ("abc", "llm", "admin", "m", 2.0))
        self.assertEqual(r["users"], [{"key": "alice", "n": 1}])
        self.assertEqual(r["tokens"], {"in": 7, "out": 0})

    def test_doc_id_validated(self):
        """doc() refuses ids with characters outside [A-Za-z0-9_-] before querying.
        REQ: AUD-01"""
        for bad in ("", None, "a/b", "x" * 65, "a b"):
            with self.assertRaises(ValueError):
                audit.doc(bad)

    def test_status_when_es_unreachable(self):
        """status() reports connected=False with an error instead of raising when ES is down.
        REQ: AUD-03"""
        with mock.patch.object(audit, "_es", side_effect=_down):
            s = audit.status()
        self.assertFalse(s["connected"])
        self.assertIn("refused", s["error"])
        self.assertEqual(s["spool_bytes"], 0)
        self.assertEqual(s["index"], audit.index())


if __name__ == "__main__":
    unittest.main()
