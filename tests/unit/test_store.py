"""Unit tests for store.py: docs, cfg, acks, mutes, suppress rules, alerts, push, findings, registry, history, ops."""
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); import _env  # noqa: E401,E402

import json  # noqa: E402
import shutil  # noqa: E402
import sqlite3  # noqa: E402
import stat  # noqa: E402
import tempfile  # noqa: E402
import threading  # noqa: E402
import time  # noqa: E402
import unittest  # noqa: E402

import fixtures  # noqa: E402
import store  # noqa: E402

DATA = os.path.join(_env.REPO, "data")
RANGES = os.path.join(_env.REPO, "ranges")


class StoreCase(unittest.TestCase):
    """Base: every test starts on an empty isolated DB with no cached settings."""

    def setUp(self):
        _env.fresh_db()
        store._cfg_cache.clear()
        self.c = store._dc()
        self.tmp = tempfile.mkdtemp(prefix="store-", dir=_env.TMP)

    def tearDown(self):
        shutil.rmtree(self.tmp, True)
        _env.fresh_db()
        store._cfg_cache.clear()

    def alert_rows(self):
        return [store._arow(r) for r in self.c.execute("SELECT * FROM alerts ORDER BY id")]


class TestConnect(StoreCase):
    """connect(), tx() and db_path()."""

    def test_db_path_prefers_netmon_db_env(self):
        """db_path() honours NETMON_DB first, then STATE_DIR, then the repo default.
        REQ: STO-01
        """
        old = {k: os.environ.get(k) for k in ("NETMON_DB", "STATE_DIR")}
        try:
            self.assertEqual(store.db_path(), os.environ["NETMON_DB"])
            del os.environ["NETMON_DB"]
            os.environ["STATE_DIR"] = self.tmp
            self.assertEqual(store.db_path(), os.path.join(self.tmp, "netmon.db"))
            del os.environ["STATE_DIR"]
            self.assertEqual(store.db_path(), os.path.join(store.HERE, "dashboard", "state", "netmon.db"))
        finally:
            for k, v in old.items():
                if v is not None:
                    os.environ[k] = v

    def test_new_database_is_owner_only(self):
        """A database created by connect() (and its WAL/SHM files) is mode 0600.
        REQ: SEC-06
        """
        p = os.path.join(self.tmp, "sub", "x.db")
        c = store.connect(p)
        c.execute("CREATE TABLE IF NOT EXISTS t(x)")
        c.execute("INSERT INTO t VALUES (1)")
        for f in (p, p + "-wal", p + "-shm"):
            if os.path.exists(f):
                self.assertEqual(stat.S_IMODE(os.stat(f).st_mode) & 0o077, 0, f)
        c.close()

    def test_existing_world_readable_db_is_tightened(self):
        """connect() chmods an existing group/world-readable database file back to 0600.
        REQ: SEC-06
        """
        p = os.path.join(self.tmp, "loose.db")
        sqlite3.connect(p).close()
        os.chmod(p, 0o644)
        store.connect(p).close()
        self.assertEqual(stat.S_IMODE(os.stat(p).st_mode), 0o600)

    def test_schema_has_migrated_alert_columns_and_wal(self):
        """The schema includes the later alert columns (targets, cleared, held...) and the DB runs in WAL mode.
        REQ: STO-01
        """
        cols = {r[1] for r in self.c.execute("PRAGMA table_info(alerts)")}
        self.assertTrue({"targets", "cleared", "cleared_rule", "cleared_at", "held"} <= cols)
        self.assertEqual(self.c.execute("PRAGMA journal_mode").fetchone()[0].lower(), "wal")
        self.assertEqual(self.c.execute("SELECT v FROM meta WHERE k='schema_version'").fetchone()[0], str(store.SCHEMA_VERSION))

    def test_tx_rolls_back_on_exception(self):
        """A write transaction that raises is rolled back and the exception propagates.
        REQ: STO-01
        """
        with self.assertRaises(RuntimeError):
            with store.tx(self.c):
                self.c.execute("INSERT INTO watch_mute VALUES ('k', 1)")
                raise RuntimeError("boom")
        self.assertEqual(store.mutes(), {})

    def test_tl_conn_runs_init_once_per_thread(self):
        """tl_conn() returns one shared connection per thread and runs the init hook once per tag.
        REQ: STO-01
        """
        calls = []
        a = store.tl_conn("t1", lambda c: calls.append(1))
        b = store.tl_conn("t1", lambda c: calls.append(1))
        self.assertIs(a, b)
        self.assertEqual(len(calls), 1)
        other = {}

        def worker():
            other["c"] = store.tl_conn("t1", lambda c: calls.append(2))
            other["id"] = id(other["c"])
            other["c"].close()
        th = threading.Thread(target=worker)
        th.start()
        th.join()
        self.assertIsNot(other["c"], a)
        self.assertEqual(calls, [1, 2])


class TestDocs(StoreCase):
    """JSON documents in the docs table (jload/jdump/jglob drop-ins)."""

    def test_doc_name_mapping(self):
        """doc_name() maps data/, ranges/ and state job files to doc names and leaves other paths as files.
        REQ: STO-01
        """
        self.assertEqual(store.doc_name(os.path.join(DATA, "2026-01-05T1200Z.analysis.json")), "data/2026-01-05T1200Z.analysis")
        self.assertEqual(store.doc_name(os.path.join(RANGES, "r1.status.json")), "ranges/r1.status")
        self.assertEqual(store.doc_name(os.path.join(DATA, "x.json.tmp")), "data/x")
        self.assertEqual(store.doc_name(os.path.join(self.tmp, "state", "users.json")), "state/users")
        self.assertEqual(store.doc_name(os.path.join(self.tmp, ".state", "scheduler.json")), "state/scheduler")
        self.assertIsNone(store.doc_name(os.path.join(self.tmp, "state", "other.json")))
        self.assertIsNone(store.doc_name(os.path.join(DATA, "x.work.json")))
        self.assertIsNone(store.doc_name(os.path.join(DATA, "x.txt")))
        self.assertIsNone(store.doc_name(os.path.join(store.HERE, "policy.json")))

    def test_jdump_jload_roundtrip_in_db(self):
        """jdump of a data/ path stores the document in the DB (no file written) and jload reads it back.
        REQ: STO-01
        """
        p = os.path.join(DATA, "unit-test-doc.json")
        obj = {"a": [1, 2, {"b": None}], "t": "x"}
        store.jdump(obj, p)
        self.assertFalse(os.path.exists(p))
        self.assertTrue(store.jexists(p))
        self.assertEqual(store.jload(p), obj)
        self.assertIsInstance(store.jmtime(p), float)
        row = self.c.execute("SELECT size FROM docs WHERE name='data/unit-test-doc'").fetchone()
        self.assertEqual(row[0], len(json.dumps(obj, separators=(",", ":"))))
        store.jdelete(p)
        self.assertFalse(store.jexists(p))
        self.assertEqual(store.jload(p, "dflt"), "dflt")

    def test_jdump_overwrites_existing_doc(self):
        """A second jdump to the same path replaces the stored document.
        REQ: STO-01
        """
        p = os.path.join(RANGES, "r9.json")
        store.jdump({"v": 1}, p)
        store.jdump({"v": 2}, p)
        self.assertEqual(store.jload(p), {"v": 2})
        self.assertEqual(self.c.execute("SELECT count(*) FROM docs").fetchone()[0], 1)

    def test_plain_file_fallback(self):
        """Paths outside data/ranges/state are read and written as ordinary JSON files.
        REQ: STO-01
        """
        p = os.path.join(self.tmp, "plain.json")
        store.jdump({"k": 1}, p, indent=1)
        self.assertTrue(os.path.exists(p))
        self.assertFalse(os.path.exists(p + ".tmp"))
        self.assertEqual(store.jload(p), {"k": 1})
        self.assertTrue(store.jexists(p))
        self.assertGreater(store.jmtime(p), 0)
        store.jdelete(p)
        self.assertFalse(os.path.exists(p))
        store.jdelete(p)  # deleting a missing file is a no-op

    def test_jload_bad_or_missing_file_returns_default(self):
        """jload returns the default for a missing file or one that is not valid JSON.
        REQ: STO-01
        """
        bad = os.path.join(self.tmp, "bad.json")
        with open(bad, "w") as f:
            f.write("{not json")
        self.assertEqual(store.jload(bad, {}), {})
        self.assertIsNone(store.jload(os.path.join(self.tmp, "nope.json")))

    def test_jglob_lists_docs_sorted_and_filtered(self):
        """jglob on data/ returns the stored documents as file paths, sorted and filtered by the pattern.
        REQ: STO-01
        """
        fixtures.seed_snapshot(fixtures.SID)
        fixtures.seed_snapshot(fixtures.SID_OLD, with_analysis=False)
        allp = store.jglob(DATA)
        self.assertEqual([os.path.basename(p) for p in allp],
                         [f"{fixtures.SID_OLD}.json", f"{fixtures.SID}.json", f"{fixtures.SID}.analysis.json"])  # sorted by doc name
        self.assertEqual([os.path.basename(p) for p in store.jglob(DATA, "*.analysis.json")], [f"{fixtures.SID}.analysis.json"])
        self.assertEqual(store.jload(allp[1])["self_ip"], fixtures.IPS["server"])

    def test_jglob_plain_directory(self):
        """jglob on an ordinary directory globs the filesystem.
        REQ: STO-01
        """
        for n in ("b.json", "a.json", "c.txt"):
            open(os.path.join(self.tmp, n), "w").close()
        self.assertEqual([os.path.basename(p) for p in store.jglob(self.tmp)], ["a.json", "b.json"])

    def test_doc_names_escapes_like_wildcards(self):
        """doc_names() treats _ and % in the prefix literally (no LIKE wildcard leakage).
        REQ: STO-01
        """
        store.doc_put("data/a_1", {})
        store.doc_put("data/ab1", {})
        store.doc_put("data/a%2", {})
        self.assertEqual(store.doc_names("data/a_"), ["data/a_1"])
        self.assertEqual(store.doc_names("data/a%"), ["data/a%2"])
        self.assertEqual(len(store.doc_names("data/")), 3)
        self.assertIsNone(store.doc_mtime("data/none"))

    def test_docs_migrate_imports_and_optionally_deletes(self):
        """docs_migrate() loads JSON files of a data/ dir into the DB, skips invalid JSON and deletes when asked.
        REQ: STO-01
        """
        d = os.path.join(self.tmp, "data")
        os.makedirs(d)
        with open(os.path.join(d, "s1.json"), "w") as f:
            json.dump({"x": 1}, f)
        with open(os.path.join(d, "bad.json"), "w") as f:
            f.write("nope")
        self.assertEqual(store.docs_migrate([d], delete=True), 1)
        self.assertEqual(store.doc_get("data/s1"), {"x": 1})
        self.assertFalse(os.path.exists(os.path.join(d, "s1.json")))
        self.assertTrue(os.path.exists(os.path.join(d, "bad.json")))


class TestCfg(StoreCase):
    """Flattened configuration rows (cfg table)."""

    SAMPLE = {"zones": {"user": {"cidrs": ["10.0.1.0/24"], "role": "user"}}, "n": 3, "f": 1.5, "b": True, "z": None,
              "e": {}, "l": [], "nested": [[1, 2], [{"k": False}], {}], "s": "", "weird/key#%": {"a%2Fb": "v"}}

    def test_flatten_build_roundtrip(self):
        """cfg_build(cfg_flatten(x)) reproduces nested dicts, lists, empty containers, types and escaped keys exactly.
        REQ: STO-02
        """
        rows = list(store.cfg_flatten(self.SAMPLE))
        back = store.cfg_build(rows)
        self.assertEqual(back, self.SAMPLE)
        self.assertIs(back["b"], True)
        self.assertIsInstance(back["n"], int)
        self.assertIsInstance(back["f"], float)

    def test_flatten_row_format(self):
        """cfg_flatten emits path / vtype / text rows, with '#n' for list items and escaped dict keys.
        REQ: STO-02
        """
        rows = dict((p, (t, v)) for p, t, v in store.cfg_flatten({"a/b": [True, 2, None], "c": {}}))
        self.assertEqual(rows["a%2Fb/#0"], ("bool", "1"))
        self.assertEqual(rows["a%2Fb/#1"], ("int", "2"))
        self.assertEqual(rows["a%2Fb/#2"], ("null", None))
        self.assertEqual(rows["c"], ("dict", None))

    @unittest.expectedFailure
    def test_top_level_empty_key_roundtrip(self):
        """KNOWN BUG: a top-level empty-string key is lost on round trip (its path is '' which cfg_build treats as the root).
        REQ: STO-02
        """
        self.assertEqual(store.cfg_build(list(store.cfg_flatten({"": 1}))), {"": 1})

    def test_cfg_save_load_and_has(self):
        """cfg_save stores a document that cfg_load returns intact; cfg_has reports presence.
        REQ: STO-02
        """
        self.assertFalse(store.cfg_has("policy"))
        n = store.cfg_save("policy", self.SAMPLE)
        self.assertEqual(n, len(list(store.cfg_flatten(self.SAMPLE))))
        self.assertTrue(store.cfg_has("policy"))
        self.assertEqual(store.cfg_load("policy"), self.SAMPLE)

    def test_cfg_load_returns_private_copy_unless_shared(self):
        """cfg_load returns a deep copy by default, so callers can't corrupt the cache; shared=True returns the cached object.
        REQ: STO-02
        """
        store.cfg_save("site", {"a": {"b": 1}})
        x = store.cfg_load("site")
        x["a"]["b"] = 99
        self.assertEqual(store.cfg_load("site"), {"a": {"b": 1}})
        self.assertIs(store.cfg_load("site", shared=True), store.cfg_load("site", shared=True))

    def test_cfg_save_replaces_whole_document_and_invalidates_cache(self):
        """A second cfg_save replaces the document and the next cfg_load sees it immediately.
        REQ: STO-02
        """
        store.cfg_save("host_policy", {"a": 1, "b": 2})
        self.assertEqual(store.cfg_load("host_policy"), {"a": 1, "b": 2})
        store.cfg_save("host_policy", {"c": 3})
        self.assertEqual(store.cfg_load("host_policy"), {"c": 3})

    def test_cfg_paths_route_through_jload_jdump(self):
        """<repo>/policy.json is a cfg document: jdump/jload/jexists/jmtime use the cfg table, not the file.
        REQ: STO-02
        """
        p = os.path.join(store.HERE, "known_benign.json")
        self.assertEqual(store.cfg_doc(p), "known_benign")
        self.assertIsNone(store.cfg_doc(os.path.join(store.HERE, "site.example.json")))
        self.assertIsNone(store.cfg_doc(os.path.join(self.tmp, "policy.json")))
        self.assertFalse(store.jexists(p))
        self.assertEqual(store.jload(p, "d"), "d")
        before = os.path.exists(p)
        store.jdump({"rules": ["x"]}, p)
        self.assertEqual(os.path.exists(p), before)  # nothing written to the checkout
        self.assertTrue(store.jexists(p))
        self.assertEqual(store.jload(p), {"rules": ["x"]})
        self.assertGreater(store.jmtime(p), 0)


class TestAcks(StoreCase):
    """Dashboard check-offs."""

    def test_ack_set_and_clear(self):
        """ack_set stores a check-off with note and label; unchecking deletes it.
        REQ: STO-03, DASH-05
        """
        out = store.ack_set("issue", "k1", True, note="fixed it", label="Telnet on server")
        self.assertEqual(out["issue"]["k1"]["note"], "fixed it")
        self.assertEqual(out["issue"]["k1"]["label"], "Telnet on server")
        self.assertRegex(out["issue"]["k1"]["at"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
        self.assertEqual(set(out), {"issue", "alarm", "finding", "host"})
        out = store.ack_set("issue", "k1", False)
        self.assertEqual(out["issue"], {})

    def test_ack_relabel_keeps_old_label_when_blank(self):
        """Re-acking with an empty label keeps the stored label; note is replaced; long text is truncated.
        REQ: STO-03
        """
        store.ack_set("finding", "f", True, note="a", label="L1")
        out = store.ack_set("finding", "f", True, note="b" * 900, label="")
        self.assertEqual(out["finding"]["f"]["label"], "L1")
        self.assertEqual(len(out["finding"]["f"]["note"]), 500)
        out = store.ack_set("finding", "f", True, label="L2")
        self.assertEqual(out["finding"]["f"]["label"], "L2")

    def test_unknown_type_appears_in_map(self):
        """An ack of a type outside the four standard ones is still returned under its own type.
        REQ: STO-03
        """
        self.assertIn("x", store.ack_set("custom", "x", True)["custom"])

    def test_ack_set_many_bulk(self):
        """ack_set_many checks and restores many items in one call with a shared timestamp.
        REQ: STO-03, DASH-05
        """
        items = [("issue", "a", "A"), ("alarm", "b", "B"), ("host", "c", "")]
        out = store.ack_set_many(items, True, note="bulk")
        self.assertEqual({out["issue"]["a"]["at"], out["alarm"]["b"]["at"], out["host"]["c"]["at"]}.__len__(), 1)
        self.assertEqual(out["alarm"]["b"]["label"], "B")
        out = store.ack_set_many(items[:2], False)
        self.assertEqual(out["issue"], {})
        self.assertEqual(out["alarm"], {})
        self.assertIn("c", out["host"])


class TestWatchMute(StoreCase):
    """Watcher mute window (mute_filter)."""

    def test_mute_filter_dedupes_and_mutes(self):
        """mute_filter passes each key once and mutes it so a repeat within the window is dropped.
        REQ: STO-06
        """
        fresh = store.mute_filter([("k1", "a"), ("k1", "dup"), ("k2", "b")], 6)
        self.assertEqual(fresh, [("k1", "a"), ("k2", "b")])
        self.assertEqual(store.mute_filter([("k1", "again"), ("k3", "c")], 6), [("k3", "c")])
        self.assertEqual(set(store.mutes()), {"k1", "k2", "k3"})

    def test_mute_filter_expires_old_mutes(self):
        """A mute older than the window is purged and the alert passes again.
        REQ: STO-06
        """
        with store.tx(self.c):
            self.c.execute("INSERT INTO watch_mute VALUES ('old', ?)", (time.time() - 7 * 3600,))
        self.assertEqual(store.mute_filter([("old", "t")], 6), [("old", "t")])


class TestMuteRules(StoreCase):
    """Alert mute ('Never send') rule matching."""

    def test_mute_add_is_disabled(self):
        """Creating never-send mute rules is switched off: mute_add raises ValueError.
        REQ: STO-04
        """
        with self.assertRaises(ValueError):
            store.mute_add("anything", "", "admin")

    def test_mglob_semantics(self):
        """_mglob: * and ? are wildcards (full match), [ ] are literal, plain text is substring or exact.
        REQ: STO-04
        """
        self.assertTrue(store._mglob("port scan*", "Port scan from x", True))
        self.assertFalse(store._mglob("scan*", "port scan", True))
        self.assertTrue(store._mglob("a?c", "abc", False))
        self.assertTrue(store._mglob("*['10.0.0.1']*", "hits ['10.0.0.1'] now", True))
        self.assertFalse(store._mglob("*[ab]*", "a", True))
        self.assertTrue(store._mglob("scan", "big SCAN here", True))
        self.assertFalse(store._mglob("scan", "big scan", False))

    def test_mute_match_name_and_host(self):
        """mute_match needs the name to match the text and the host to be a target or appear in the text.
        REQ: STO-04
        """
        m = {"name": "new device*", "host": "10.0.1.10"}
        self.assertTrue(store.mute_match(m, "New device seen", ["10.0.1.10"]))
        self.assertTrue(store.mute_match(m, "New device seen at 10.0.1.10", []))
        self.assertFalse(store.mute_match(m, "New device seen", ["10.0.1.11"]))
        self.assertFalse(store.mute_match(m, "Other", ["10.0.1.10"]))
        self.assertTrue(store.mute_match({"name": "x", "host": ""}, "has x", None))

    def test_mute_apply_and_remove_with_existing_rule(self):
        """A stored mute rule clears matching alerts (hidden, counted) and removing it restores them.
        REQ: STO-04, STO-06
        """
        store.alerts_add([("k|a", "Beacon to 203.0.113.66", "high"), ("k|b", "Other thing", "high")], source="corr")
        with store.tx(self.c):
            mid = self.c.execute("INSERT INTO alert_mutes(name,host,by,at,limit_key) VALUES ('beacon*','', 't', 0, 'lk')").lastrowid
        self.assertEqual(store.mute_apply(mid), 1)
        self.assertEqual(store.mute_apply(9999), 0)
        self.assertEqual([a["key"] for a in store.alerts_recent()], ["k|b"])
        self.assertEqual([a["key"] for a in store.alerts_recent(cleared=True)], ["k|a"])
        self.assertEqual(store.mute_counts(), {mid: 1})
        # new alerts matching the rule arrive already cleared
        store.alerts_add([("k|c", "beacon again", "high")], source="corr")
        self.assertEqual(len(store.alerts_recent(cleared=True)), 2)
        self.assertEqual(store.mute_remove(mid), ("lk", 2))
        self.assertEqual(store.mute_remove(mid), (None, 0))
        self.assertEqual(len(store.alerts_recent()), 3)


class TestSuppress(StoreCase):
    """Artifact suppress rules."""

    def test_suppress_match_name_only(self):
        """A rule without artifact matches on signature name alone; a rule without name never matches.
        REQ: STO-05
        """
        self.assertTrue(store.suppress_match({"name": "dns tunnel"}, "Possible DNS tunnel via x"))
        self.assertFalse(store.suppress_match({"name": "dns tunnel"}, "port scan"))
        self.assertFalse(store.suppress_match({"name": ""}, "anything"))

    def test_suppress_match_ip_boundaries(self):
        """An IP artifact matches the exact IP in targets or text, not a longer IP that contains it.
        REQ: STO-05
        """
        r = {"name": "scan", "art_type": "ip", "art": "10.0.0.1"}
        self.assertTrue(store.suppress_match(r, "scan from 10.0.0.1 to x"))
        self.assertFalse(store.suppress_match(r, "scan from 10.0.0.15"))
        self.assertTrue(store.suppress_match(r, "scan", ips=["10.0.0.1"]))
        g = {"name": "scan", "art_type": "ip", "art": "10.0.0.*"}
        self.assertTrue(store.suppress_match(g, "scan", ips=["10.0.0.99"]))
        self.assertFalse(store.suppress_match(g, "scan", ips=["10.0.1.99"]))

    def test_suppress_match_port_and_kinds(self):
        """Port artifacts match 'port N', ':N', '/N' or port artifacts; domain matches dns artifacts or text.
        REQ: STO-05
        """
        p = {"name": "*", "art_type": "port", "art": "22"}
        self.assertTrue(store.suppress_match(p, "conn to host:22"))
        self.assertTrue(store.suppress_match(p, "listening on port 22"))
        self.assertTrue(store.suppress_match(p, "flow tcp/22"))
        self.assertFalse(store.suppress_match(p, "conn to host:2222"))
        self.assertTrue(store.suppress_match(p, "x", arts=[["port", 22]]))
        d = {"name": "lookup", "art_type": "domain", "art": "example.com"}
        self.assertTrue(store.suppress_match(d, "lookup", arts=[["dns", "www.Example.com"]]))
        self.assertFalse(store.suppress_match(d, "lookup", arts=[["file", "example.com"]]))
        self.assertTrue(store.suppress_match(d, "lookup", ctx="related example.com"))
        f = {"name": "lookup", "art_type": "file", "art": "*.exe"}
        self.assertTrue(store.suppress_match(f, "lookup", arts=[["file", "evil.exe"]]))

    def test_suppress_add_validation(self):
        """suppress_add rejects wildcard-only names, unknown artifact types and half-given artifacts.
        REQ: STO-05
        """
        for args in (("**", "", ""), ("x", "color", "red"), ("x", "ip", ""), ("x", "", "10.0.0.1")):
            with self.assertRaises(ValueError, msg=args):
                store.suppress_add(*args, by="t")

    def test_suppress_add_hides_and_remove_restores(self):
        """suppress_add hides matching existing alerts (still correlated), dedupes rules; suppress_remove restores them.
        REQ: STO-05, STO-06
        """
        store.alerts_add([("a", "Scan from 10.0.0.1", "high"), ("b", "Scan from 10.0.0.2", "high")], source="corr")
        rid, n = store.suppress_add("scan", "IP", "10.0.0.1", "admin")
        self.assertEqual(n, 1)
        self.assertEqual(store.suppress_add("SCAN", "ip", "10.0.0.1", "admin")[0], rid)
        self.assertEqual([a["key"] for a in store.alerts_recent()], ["b"])
        self.assertEqual({a["key"] for a in store.alerts_recent(suppressed=True)}, {"a", "b"})
        hidden = [a for a in self.alert_rows() if a["key"] == "a"][0]
        self.assertEqual(hidden["cleared_rule"], -rid)
        store.alerts_add([("c", "Scan from 10.0.0.1 again", "high")], source="corr")
        c_row = [a for a in self.alert_rows() if a["key"] == "c"][0]
        self.assertEqual((c_row["cleared"], c_row["pushed"]), (1, 1))
        self.assertEqual(store.suppress_remove(rid), 2)
        self.assertEqual(len(store.alerts_recent()), 3)
        self.assertEqual(store.suppress_list(), [])


class TestSegAndIdsSuppress(StoreCase):
    """Segmentation-flow and IDS-signature suppress rules."""

    def test_seg_suppress_add_normalises_and_dedupes(self):
        """seg_suppress_add normalises the port list and returns the existing id for a duplicate rule.
        REQ: STO-05
        """
        rid = store.seg_suppress_add(" 10.0.9.40 ", "", "22 3389,", "admin")
        self.assertEqual(store.seg_suppress_list()[0]["ports"], "22,3389")
        self.assertEqual(store.seg_suppress_add("10.0.9.40", "", "22,3389", "x"), rid)
        self.assertEqual(store.seg_suppress_remove(rid), 1)
        self.assertEqual(store.seg_suppress_remove(rid), 0)

    def test_seg_suppress_add_validation(self):
        """seg_suppress_add rejects empty rules, bad ports and wildcard-only IPs.
        REQ: STO-05
        """
        for src, dst, ports in (("", "", ""), ("10.0.0.1", "", "0"), ("10.0.0.1", "", "70000"), ("10.0.0.1", "", "ssh"),
                                ("*", "", ""), ("", "?*", "22"), ("*", "*", "")):
            with self.assertRaises(ValueError, msg=(src, dst, ports)):
                store.seg_suppress_add(src, dst, ports, "t")
        self.assertTrue(store.seg_suppress_add("10.0.*", "", "*", "t"))

    def test_seg_suppress_match(self):
        """seg_suppress_match requires every field the rule sets to match the flow; blank fields match anything.
        REQ: STO-05, RISK-04
        """
        rules = [{"src": "10.0.9.*", "dst": "10.0.2.20", "ports": "22,3389"}]
        self.assertTrue(store.seg_suppress_match(rules, "10.0.9.40", "10.0.2.20", 22))
        self.assertFalse(store.seg_suppress_match(rules, "10.0.9.40", "10.0.2.20", 80))
        self.assertFalse(store.seg_suppress_match(rules, "10.0.1.10", "10.0.2.20", 22))
        self.assertFalse(store.seg_suppress_match(rules, "10.0.9.40", "10.0.2.21", 22))
        self.assertTrue(store.seg_suppress_match([{"src": "", "dst": "", "ports": "443"}], "a", "b", "443"))
        self.assertFalse(store.seg_suppress_match([], "a", "b", 1))
        self.assertFalse(store.seg_suppress_match(None, "a", "b", 1))

    def test_ids_suppress_add_remove(self):
        """ids_suppress_add validates the signature, dedupes on (sig, host) and ids_suppress_remove deletes.
        REQ: STO-05
        """
        with self.assertRaises(ValueError):
            store.ids_suppress_add("*?", "", "t")
        with self.assertRaises(ValueError):
            store.ids_suppress_add("  ", "", "t")
        a = store.ids_suppress_add("ET POLICY x", "", "t")
        self.assertEqual(store.ids_suppress_add("ET POLICY x", "", "t"), a)
        b = store.ids_suppress_add("ET POLICY x", "10.0.1.10", "t")
        self.assertNotEqual(a, b)
        self.assertEqual(len(store.ids_suppress_list()), 2)
        self.assertEqual(store.ids_suppress_remove(a), 1)

    def test_ids_filter(self):
        """ids_filter drops globally suppressed signatures, strips a host's share for host rules and fixes the total.
        REQ: STO-05
        """
        h1, h2 = "10.0.1.10", "10.0.1.11"
        raw = {"x": 1, "alerts": {"total": 35, "signatures": [
            {"name": "ET SCAN A", "count": 10, "src": {h1: 10}, "dst": {"203.0.113.1": 10}},
            {"name": "ET POLICY B", "count": 20, "src": {h1: 6, h2: 4}, "dst": {h1: 6, h2: 4}},
            {"name": "Keep", "count": 5, "src": {h2: 5}, "dst": {}}]}}
        rules = [{"sig": "ET SCAN*", "host": ""}, {"sig": "ET POLICY B", "host": h1}]
        out = store.ids_filter(raw, rules)
        sigs = {s["name"]: s for s in out["alerts"]["signatures"]}
        self.assertNotIn("ET SCAN A", sigs)
        self.assertEqual(sigs["ET POLICY B"]["count"], 4)
        self.assertEqual(sigs["ET POLICY B"]["src"], {h2: 4})
        self.assertEqual(out["alerts"]["total"], 35 - 10 - 16)
        self.assertEqual(out["x"], 1)
        self.assertEqual(raw["alerts"]["total"], 35)  # input untouched
        self.assertIs(store.ids_filter(raw, []), raw)
        self.assertIsNone(store.ids_filter(None, rules))

    def test_ids_filter_host_rule_removing_everything(self):
        """A host rule that covers every source and destination of a signature removes it entirely.
        REQ: STO-05
        """
        raw = {"alerts": {"total": 3, "signatures": [{"name": "S", "count": 3, "src": {"10.0.0.1": 3}, "dst": {}}]}}
        out = store.ids_filter(raw, [{"sig": "s", "host": "10.0.0.*"}])
        self.assertEqual(out["alerts"]["signatures"], [])
        self.assertEqual(out["alerts"]["total"], 0)


class TestAlerts(StoreCase):
    """Urgent alert feed: add, hold/promote, delete, pushed/read flags."""

    def test_held_sources_are_not_in_feed_until_promoted(self):
        """Watcher alerts are stored held (read/pushed) and appear in the feed only after alerts_promote.
        REQ: STO-06
        """
        store.alerts_add([("w|1", "watcher thing", "high")])
        self.assertEqual(store.alerts_recent(), [])
        self.assertEqual(store.alerts_unpushed(), [])
        aid = self.alert_rows()[0]["id"]
        self.assertEqual(store.alerts_promote([aid]), 1)
        self.assertEqual(store.alerts_promote([aid]), 0)
        feed = store.alerts_recent()
        self.assertEqual((feed[0]["read"], feed[0]["pushed"], feed[0]["held"]), (0, 0, 0))
        self.assertEqual(len(store.alerts_unpushed()), 1)
        self.assertEqual(store.alerts_hold([str(aid)]), 1)
        self.assertEqual(store.alerts_recent(), [])

    def test_hold_ignores_non_detection_sources(self):
        """alerts_hold only affects detection sources (watcher, secscan, account, report).
        REQ: STO-06
        """
        store.alerts_add([("c|1", "corr", "high")], source="corr")
        aid = self.alert_rows()[0]["id"]
        self.assertEqual(store.alerts_hold([aid]), 0)
        self.assertEqual(len(store.alerts_recent()), 1)

    def test_alert_defaults_and_targets(self):
        """alerts_add defaults severity to urgent and derives sorted targets from key and text unless given.
        REQ: STO-06, STO-07
        """
        m = fixtures.mac(7)
        store.alerts_add([("k", f"Device {m.upper()} at 10.0.1.10"), ("k2", "x", "low", ["ip:10.9.9.9"])], source="corr")
        a, b = self.alert_rows()
        self.assertEqual(a["severity"], "urgent")
        self.assertEqual(a["targets"], sorted(["ip:10.0.1.10", "mac:" + m]))
        self.assertEqual(b["targets"], ["ip:10.9.9.9"])
        self.assertEqual(a["source"], "corr")

    def test_old_alerts_pruned_after_30_days(self):
        """Adding alerts deletes alerts older than 30 days.
        REQ: STO-06
        """
        with store.tx(self.c):
            self.c.execute("INSERT INTO alerts(ts,key,text) VALUES (?,?,?)", (time.time() - 31 * 86400, "old", "old"))
        store.alerts_add([("new", "new", "high")], source="corr")
        self.assertEqual([a["key"] for a in self.alert_rows()], ["new"])

    def test_mark_read_all_and_delete(self):
        """alerts_mark sets pushed/read (ignores other fields), alerts_read_all marks all read, alerts_delete removes.
        REQ: STO-06
        """
        store.alerts_add([("a", "a", "high"), ("b", "b", "high")], source="corr")
        ids = [a["id"] for a in self.alert_rows()]
        store.alerts_mark(ids[:1])
        self.assertEqual([a["id"] for a in store.alerts_unpushed()], ids[1:])
        store.alerts_mark(ids, field="severity")  # not allowed: no-op
        store.alerts_mark([], field="read")
        self.assertEqual({a["read"] for a in self.alert_rows()}, {0})
        store.alerts_read_all()
        self.assertEqual({a["read"] for a in self.alert_rows()}, {1})
        self.assertEqual(store.alerts_delete([]), 0)
        self.assertEqual(store.alerts_delete(ids), 2)
        self.assertEqual(self.alert_rows(), [])

    def test_alerts_recent_order_and_limit(self):
        """alerts_recent returns newest first and honours the limit; review alerts are excluded from the suppressed view.
        REQ: STO-06
        """
        store.alerts_add([(f"k{i}", f"t{i}", "high") for i in range(5)], source="corr")
        store.alerts_add([("r", "review", "high")], source="review")
        keys = [a["key"] for a in store.alerts_recent(limit=3)]
        self.assertEqual(keys, ["r", "k4", "k3"])
        self.assertNotIn("r", [a["key"] for a in store.alerts_recent(suppressed=True)])


class TestTargetsAndPrefs(StoreCase):
    """Alert targets, device identifiers and per-user push preferences."""

    def test_alert_targets_private_only(self):
        """alert_targets keeps private IPv4s (10/8, 172.16/12, 192.168/16) and MACs, not public or doc-range IPs.
        REQ: STO-07
        """
        m = fixtures.mac(9)
        t = store.alert_targets("k", f"10.1.2.3 172.16.0.5 172.32.0.1 192.0.2.5 {m}")
        self.assertEqual(t, {"ip:10.1.2.3", "ip:172.16.0.5", "mac:" + m})

    def test_alert_targets_host_key_uses_endpoint_ips(self):
        """host|kind|name keys add the host label and the endpoint IP mapped in host_policy.
        REQ: STO-07
        """
        store.cfg_save("host_policy", {"endpoint_ips": {"WS-01": "10.0.5.5"}})
        self.assertEqual(store.alert_targets("host|proc|WS-01|x", "new process"), {"host:ws-01", "ip:10.0.5.5"})
        # an FQDN key yields the short host label; the IP lookup needs the exact endpoint name
        self.assertEqual(store.alert_targets("host|proc|ws-01.example.test|x", "new process"), {"host:ws-01"})
        self.assertEqual(store.alert_targets("host|proc", "x"), set())

    def test_device_ids(self):
        """device_ids lists a device's IPs, lower-cased MAC, name label and endpoint host names mapped to its IPs.
        REQ: STO-07
        """
        store.cfg_save("host_policy", {"endpoint_ips": {"lab-ws": "10.0.2.20"}})
        m = fixtures.mac(2)
        ids = store.device_ids({"ips": ["10.0.2.20"], "mac": m.upper(), "name": "Lab.Server"})
        self.assertEqual(ids, {"ip:10.0.2.20", "mac:" + m, "host:lab", "host:lab-ws"})
        self.assertEqual(store.device_ids({"ips": [], "name": "10.0.0.1"}), set())

    def test_prefs_default_set_and_validate(self):
        """push prefs default to all devices, store a sorted unique device list and reject unknown modes.
        REQ: STO-07
        """
        self.assertEqual(store.prefs_get("u"), {"mode": "all", "devices": []})
        self.assertEqual(store.prefs_set("u", "some", ["b", "a", "b"]), {"mode": "some", "devices": ["a", "b"]})
        with self.assertRaises(ValueError):
            store.prefs_set("u", "none", [])

    def test_watch_ids_and_alert_for(self):
        """watch_ids is None for 'all'; for 'some' it resolves registry devices and host: entries, and alert_for filters.
        REQ: STO-07, AC-06
        """
        self.assertIsNone(store.watch_ids("u"))
        self.assertTrue(store.alert_for({"targets": []}, None))
        reg = {"dev1": {"ips": ["10.0.1.10"], "mac": fixtures.mac(1), "name": "laptop"}}
        store.registry_save(reg)
        store.cfg_save("host_policy", {"endpoint_ips": {"ws9": "10.0.7.9"}})
        store.prefs_set("u", "some", ["dev1", "host:WS9", "unknown"])
        ids = store.watch_ids("u")
        self.assertEqual(ids, {"ip:10.0.1.10", "mac:" + fixtures.mac(1), "host:laptop", "host:ws9", "ip:10.0.7.9"})
        self.assertTrue(store.alert_for({"targets": ["ip:10.0.7.9"]}, ids))
        self.assertFalse(store.alert_for({"targets": ["ip:10.0.3.30"]}, ids))
        self.assertFalse(store.alert_for({}, ids))


class TestPushSubs(StoreCase):
    """Web-push subscriptions."""

    def test_save_update_delete(self):
        """push_sub_save upserts by endpoint (resetting fails) and push_sub_delete removes it.
        REQ: STO-07
        """
        sub = {"endpoint": "https://push.example.invalid/1", "keys": {"p256dh": "k", "auth": "a"}}
        store.push_sub_save(sub, "alice", ua="UA")
        store.push_sub_save(dict(sub, keys={"auth": "b"}), "bob")
        subs = store.push_subs()
        self.assertEqual(len(subs), 1)
        self.assertEqual((subs[0]["user"], subs[0]["keys"]), ("bob", {"auth": "b"}))
        store.push_sub_delete(sub["endpoint"])
        self.assertEqual(store.push_subs(), [])

    def test_failures_drop_subscription_after_five(self):
        """A subscription is removed after 5 consecutive push failures; a success resets the counter.
        REQ: STO-07
        """
        ep = "https://push.example.invalid/2"
        store.push_sub_save({"endpoint": ep}, "u")
        for _ in range(4):
            store.push_sub_result(ep, False)
        store.push_sub_result(ep, True)
        s = store.push_subs()[0]
        self.assertEqual(s["fails"], 0)
        self.assertIsNotNone(s["last_ok"])
        for _ in range(5):
            store.push_sub_result(ep, False)
        self.assertEqual(store.push_subs(), [])


class TestSecFindings(StoreCase):
    """Software security findings sync."""

    def test_sec_sync_lifecycle(self):
        """sec_sync reports new / still open / fixed keys and reopening a fixed finding counts as new again.
        REQ: STO-06
        """
        f = lambda k: {"key": k, "tool": "t", "severity": "high", "title": k}  # noqa: E731
        self.assertEqual(store.sec_sync([f("a"), f("b")]), (["a", "b"], [], []))
        store.sec_mark_notified(["a"])
        self.assertEqual(store.sec_sync([f("a")]), ([], ["a"], ["b"]))
        self.assertEqual([r["key"] for r in store.sec_list("fixed")], ["b"])
        self.assertIsNotNone(store.sec_list("fixed")[0]["fixed_at"])
        self.assertEqual(store.sec_list("open")[0]["notified"], 1)
        self.assertEqual(store.sec_sync([f("a"), f("b")]), (["b"], ["a"], []))
        rows = {r["key"]: r for r in store.sec_list()}
        self.assertEqual((rows["b"]["status"], rows["b"]["notified"], rows["b"]["fixed_at"]), ("open", 0, None))
        self.assertEqual(rows["a"]["notified"], 1)


class TestRegistryHostsHistory(StoreCase):
    """Device registry, host baseline and snapshot history."""

    def test_registry_roundtrip_and_ips(self):
        """registry_save upserts device documents; registry_load/registry_ips read them back.
        REQ: STO-01
        """
        reg = {"k1": {"mac": fixtures.mac(1), "name": "A", "ips": ["10.0.1.10", "10.0.1.12"], "known": 1},
               "k2": {"name": "B", "ips": ["10.0.2.20"]}}
        store.registry_save(reg)
        store.registry_save({"k2": {"name": "B2", "ips": []}})
        loaded = store.registry_load()
        self.assertEqual(loaded["k1"], reg["k1"])
        self.assertEqual(loaded["k2"]["name"], "B2")
        self.assertEqual(store.registry_ips(), {"10.0.1.10", "10.0.1.12"})
        self.assertEqual(self.c.execute("SELECT known FROM devices WHERE key='k2'").fetchone()[0], 0)

    def test_hosts_save_replaces_kind_docs(self):
        """hosts_save replaces each (host, kind) document whole and skips non-dict host entries.
        REQ: STO-01
        """
        store.hosts_save({"ws1": {"procs": {"a": 1, "b": 2}, "users": "x"}, "bad": "not a dict"})
        store.hosts_save({"ws1": {"procs": {"a": 1}}})
        self.assertEqual(store.hosts_load(), {"ws1": {"procs": {"a": 1}, "users": "x"}})

    def test_history_append_load_keep_and_served_ports(self):
        """history_append stores records in order, indexes served ports, and keep= trims old records and their ports.
        REQ: STO-01
        """
        for i in range(4):
            store.history_append({"generated": f"2026-01-0{i + 1}", "hours": 24,
                                  "devices": {"d": {"ip": f"10.0.0.{i}", "served": {f"{22 + i}/tcp": 1}}, "n": {"served": {"80": 1}}}})
        self.assertEqual(store.history_count(), 4)
        self.assertTrue(store.history_has("2026-01-02"))
        self.assertFalse(store.history_has("2030-01-01"))
        self.assertEqual([h["generated"] for h in store.history_load(limit=2)], ["2026-01-03", "2026-01-04"])
        self.assertEqual(store.served_ports()["10.0.0.0"], {"22"})
        store.history_append({"generated": "2026-01-05", "devices": {}}, keep=2)
        self.assertEqual([h["generated"] for h in store.history_load()], ["2026-01-04", "2026-01-05"])
        self.assertEqual(store.served_ports(), {"10.0.0.3": {"25"}})

    def test_history_reappend_replaces_served_ports(self):
        """Re-appending the same snapshot replaces its served-port index (cascade on replace).
        REQ: STO-01
        """
        store.history_append({"generated": "g", "devices": {"d": {"ip": "10.0.0.1", "served": {"22": 1}}}})
        store.history_append({"generated": "g", "devices": {"d": {"ip": "10.0.0.1", "served": {"80": 1}}}})
        self.assertEqual(store.served_ports(), {"10.0.0.1": {"80"}})
        self.assertEqual(store.history_count(), 1)


class TestOps(StoreCase):
    """migrate / stats / backup / integrity / export."""

    def _legacy(self):
        base = os.path.join(self.tmp, "baseline")
        os.makedirs(base)
        json.dump({"k1": {"name": "A", "ips": ["10.0.1.10"]}}, open(os.path.join(base, "devices_seen.json"), "w"))
        json.dump({"ws1": {"procs": {"a": 1}}, "_meta": {"v": 1}}, open(os.path.join(base, "hosts_seen.json"), "w"))
        with open(os.path.join(base, "history.jsonl"), "w") as f:
            f.write(json.dumps({"generated": "g1", "devices": {}}) + "\n\n" + json.dumps({"generated": "g2", "devices": {}}) + "\n")
        json.dump({"wk": time.time()}, open(os.path.join(base, "watch_state.json"), "w"))
        acks = os.path.join(self.tmp, "acks.json")
        json.dump({"issue": {"i1": {"at": "2026-01-01T00:00:00Z", "note": "n"}}, "host": {"h": {}}}, open(acks, "w"))
        return base, acks

    def tearDown(self):
        with store.tx(self.c):
            self.c.execute("DELETE FROM meta WHERE k IN ('migrated_at','migrated_counts')")
        super().tearDown()

    def test_migrate_imports_legacy_files_once(self):
        """migrate imports every legacy JSON file, records counts, and refuses a second run unless overwrite.
        REQ: STO-01, OPS-04
        """
        base, acks = self._legacy()
        done = store.migrate(base, acks)
        self.assertEqual(done, {"devices": 1, "host_baseline_docs": 2, "history": 2, "watch_mute": 1, "acks": 2})
        self.assertEqual(store.acks_load()["issue"]["i1"]["note"], "n")
        self.assertEqual(store.history_count(), 2)
        self.assertIn("wk", store.mutes())
        with self.assertRaises(SystemExit):
            store.migrate(base, acks)
        self.assertEqual(store.migrate(base, acks, overwrite=True)["devices"], 1)

    def test_migrate_missing_files_is_empty(self):
        """migrate over a directory without legacy files imports nothing and does not fail.
        REQ: STO-01
        """
        d = os.path.join(self.tmp, "empty")
        os.makedirs(d)
        self.assertEqual(store.migrate(d, os.path.join(d, "acks.json")),
                         {"devices": 0, "host_baseline_docs": 0, "history": 0, "watch_mute": 0, "acks": 0})

    def test_stats_and_integrity(self):
        """stats counts rows per table and reports the file size and meta; integrity_check says ok.
        REQ: OPS-04
        """
        store.ack_set("issue", "x", True)
        s = store.stats()
        self.assertEqual(s["acks"], 1)
        self.assertGreater(s["_file_bytes"], 0)
        self.assertEqual(s["_meta"]["schema_version"], str(store.SCHEMA_VERSION))
        self.assertEqual(store.integrity(), "ok")

    def test_backup_copies_and_prunes(self):
        """backup writes a consistent copy that opens with the same data, keeping only the newest `keep` files.
        REQ: OPS-04
        """
        store.ack_set("issue", "x", True)
        for d in ("20200101", "20200102", "20200103"):
            open(os.path.join(self.tmp, f"netmon-{d}.db"), "w").close()
        dest = store.backup(self.tmp, keep=2)
        self.assertTrue(os.path.basename(dest).startswith("netmon-"))
        left = sorted(os.listdir(self.tmp))
        self.assertEqual(len(left), 2)
        self.assertIn(os.path.basename(dest), left)
        b = sqlite3.connect(dest)
        self.assertEqual(b.execute("SELECT key FROM acks").fetchall(), [("x",)])
        b.close()

    def test_export_writes_legacy_files(self):
        """export writes the legacy JSON files back out with the stored content.
        REQ: OPS-04
        """
        store.registry_save({"k": {"name": "A"}})
        store.history_append({"generated": "g", "devices": {}})
        out = store.export(os.path.join(self.tmp, "exp"))
        self.assertEqual(sorted(os.listdir(out)), ["acks.json", "devices_seen.json", "history.jsonl", "hosts_seen.json", "watch_state.json"])
        self.assertEqual(json.load(open(os.path.join(out, "devices_seen.json"))), {"k": {"name": "A"}})
        with open(os.path.join(out, "history.jsonl")) as f:
            self.assertEqual([json.loads(x)["generated"] for x in f], ["g"])


if __name__ == "__main__":
    unittest.main()
