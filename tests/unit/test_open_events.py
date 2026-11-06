"""Open events page backend (eventstore: upsert, vuln lifecycle, grouping, filters, check-offs, display merges, extras,
related / detail / decision inputs) and the page script openevents.js (cards per type, columns, empty state) under node."""
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); import _env  # noqa: E401,E402

import json  # noqa: E402
import shutil  # noqa: E402
import subprocess  # noqa: E402
import unittest  # noqa: E402

import fixtures  # noqa: E402
import store  # noqa: E402
import eventstore  # noqa: E402
import corr_llm  # noqa: E402

IP = fixtures.IPS
EXT = fixtures.EXT
DEV = fixtures.mac(9)
SEG_DEV = IP["dmz"]
IDS = "ids|ET POLICY Example signature 7"
BEACON_1 = f"f|beacon|{DEV}|beacon to {EXT['bad']} every ~60s, 145 conns"
BEACON_2 = f"f|beacon|{DEV}|beacon to {EXT['bad']} every ~62s, 3,983 conns"
GW = "gw|THREAT_BLOCKED|1792700000|x|y"
ADM = f"adm|{IP['laptop']}|{IP['server']}|22"
SEG_A = f"f|segmentation|{SEG_DEV}|DMZ Game Box -> Lab Server ({IP['server']}) 22/tcp"
SEG_B = f"f|segmentation|{SEG_DEV}|DMZ Game Box -> Yard Camera ({IP['camera']}) 22/tcp"
HF_A = f"hf|hnet-proc|host-a|tool.exe|{EXT['bad']}"
HF_B = f"hf|hnet-proc|host-a|tool.exe|{EXT['cdn']}"
NODE_FALLBACK = os.path.expanduser(os.environ.get("NETMON_NODE", "~/.hermes/tools/node-26.7.0-linux-arm64/bin/node"))
NODE = shutil.which("node") or (NODE_FALLBACK if os.path.exists(NODE_FALLBACK) else None)
OE_JS = os.path.join(_env.APP, "static", "openevents.js")


def ev(typ, label, sev="medium", t0=None, t1=None, **kw):
    """One correlation event in the shape correlate.build() returns (what eventstore.upsert stores)."""
    return {"type": typ, "label": label, "sev": sev, "t0": t0, "t1": t1, **kw}


def seg_item(eid, name="DMZ Game Box"):
    p = eid.split("|")
    return {"kind": "segmentation", "device": p[2], "detail": "|".join(p[3:]), "name": name, "severity": "high"}


def row(eid):
    return eventstore._c().execute("SELECT * FROM events WHERE eid=?", (eid,)).fetchone()


def open_ids(**kw):
    return [e["eid"] for e in eventstore.open_events(**kw)["events"]]


def ack(ref, checked=True):
    store.ack_set(ref[0], ref[1], checked, c=eventstore._c())


class _Fresh(unittest.TestCase):
    """Base: empty store and empty AI verdict tables."""

    def setUp(self):
        _env.fresh_db()
        c = eventstore._c()
        c.execute("DELETE FROM events")
        c.execute("DELETE FROM event_fires")
        with corr_llm._db() as k:
            for sql in ("DELETE FROM verdicts", "DELETE FROM clef", "DELETE FROM pair_artifacts", "DELETE FROM clef_event",
                        "DELETE FROM event_class", "DELETE FROM decision_inputs"):
                k.execute(sql)


class GroupingKeyTest(unittest.TestCase):
    """_norm / gkey: the logical identity that collapses repeats of one condition."""

    def test_norm_masks_counts_keeps_ips_ports_macs(self):
        """Volatile numbers become #, while IPs, 'port N', N/tcp and MAC addresses are kept verbatim.
        REQ: OE-03
        """
        t = f"{EXT['bad']} port 443 22/tcp {DEV} 145 conns, 3,983 queries every ~180s"
        self.assertEqual(eventstore._norm(t), f"{EXT['bad']} port 443 22/tcp {DEV} # conns, # queries every ~#s")

    def test_findings_differing_only_in_numbers_share_a_key(self):
        """Two baseline findings that differ only in counts group together; a different IP, device or kind does not.
        REQ: OE-03
        """
        self.assertEqual(eventstore.gkey(BEACON_1), eventstore.gkey(BEACON_2))
        self.assertNotEqual(eventstore.gkey(BEACON_1), eventstore.gkey(BEACON_1.replace(EXT["bad"], EXT["cdn"])))
        self.assertNotEqual(eventstore.gkey(BEACON_1), eventstore.gkey(BEACON_1.replace(DEV, fixtures.mac(8))))
        self.assertNotEqual(eventstore.gkey(BEACON_1), eventstore.gkey(BEACON_1.replace("|beacon|", "|upload-spike|")))

    def test_non_findings_are_their_own_key(self):
        """IDS, gateway, host, admin and malformed finding ids are their own logical key.
        REQ: OE-03
        """
        for e in (IDS, GW, HF_A, ADM, "f|beacon|x"):
            self.assertEqual(eventstore.gkey(e), e)

    def test_segmentation_groups_by_flow_key(self):
        """A segmentation finding groups under seg|<device>|<dst ip>|<port> (the key a cleared flow uses).
        REQ: OE-03
        """
        self.assertEqual(eventstore.gkey(SEG_A), f"seg|{SEG_DEV}|{IP['server']}|22")
        self.assertEqual(eventstore.gkey(SEG_A + " 12 conns"), eventstore.gkey(SEG_A + " 99 conns"))


class UpsertTest(_Fresh):
    """upsert(): one row per event id, counted once per snapshot, newest data wins."""

    def test_empty_input_stores_nothing(self):
        """No events or no snapshot id stores nothing and returns 0.
        REQ: OE-01
        """
        self.assertEqual(eventstore.upsert({}, "s1"), 0)
        self.assertEqual(eventstore.upsert({IDS: ev("ids", "x")}, ""), 0)
        self.assertEqual(eventstore._c().execute("SELECT COUNT(*) FROM events").fetchone()[0], 0)

    def test_seen_once_per_snapshot_and_times_widen(self):
        """n counts distinct snapshots (same snapshot twice counts once); first/last seen and t0/t1 only ever widen.
        REQ: OE-01
        """
        eventstore.upsert({IDS: ev("ids", "x", t0=100, t1=200)}, "s1", "2026-01-02T00:00:00Z")
        eventstore.upsert({IDS: ev("ids", "x", t0=100, t1=200)}, "s1", "2026-01-02T00:00:00Z")
        self.assertEqual(row(IDS)["n"], 1)
        eventstore.upsert({IDS: ev("ids", "x", t0=50, t1=300)}, "s2", "2026-01-03T00:00:00Z")
        eventstore.upsert({IDS: ev("ids", "x", t0=150, t1=250)}, "s0", "2026-01-01T00:00:00Z")
        r = row(IDS)
        self.assertEqual((r["n"], r["t0"], r["t1"]), (3, 50, 300))
        self.assertEqual((r["first_seen"], r["last_seen"]), ("2026-01-01T00:00:00Z", "2026-01-03T00:00:00Z"))

    def test_older_snapshot_does_not_overwrite_newer_data(self):
        """Label, severity, link and stored doc come from the event with the latest t1; replaying an older snapshot keeps them.
        REQ: OE-01
        """
        eventstore.upsert({IDS: ev("ids", "new label", "high", t1=500, link="#/new", ips=[IP["laptop"]])}, "s2")
        eventstore.upsert({IDS: ev("ids", "old label", "low", t1=100, link="#/old", ips=[IP["phone"]])}, "s1")
        r = row(IDS)
        self.assertEqual((r["label"], r["sev"], r["link"]), ("new label", "high", "#/new"))
        self.assertEqual(json.loads(r["doc"])["ips"], [IP["laptop"]])

    def test_doc_keeps_ips_and_capped_source_item(self):
        """The stored doc keeps ips/host_ips/dst_ips/arts and the source row, with long strings and lists capped.
        REQ: OE-01
        """
        item = {"name": "sig", "text": "a" * 5000, "list": list(range(100))}
        eventstore.upsert({IDS: ev("ids", "L" * 400, ips=[IP["laptop"]], host_ips=[IP["laptop"]], dst_ips=[EXT["bad"]])},
                          "s1", items={IDS: item})
        r = row(IDS)
        d = json.loads(r["doc"])
        self.assertEqual(len(r["label"]), 300)
        self.assertEqual((d["ips"], d["host_ips"], d["dst_ips"]), ([IP["laptop"]], [IP["laptop"]], [EXT["bad"]]))
        self.assertEqual(len(d["item"]["text"]), 1500)
        self.assertEqual(len(d["item"]["list"]), 25)


class VulnLifecycleTest(_Fresh):
    """sync_vulns(): Fix-list items close when the newest snapshot no longer lists them."""

    def test_latest_snapshot_closes_unlisted_vulns_only(self):
        """The latest snapshot resolves vulnerabilities it no longer lists; listed ones and other types stay open.
        REQ: OE-02
        """
        E = {"iss|a": ev("vuln", "A"), "iss|b": ev("vuln", "B"), IDS: ev("ids", "x", t1=1)}
        eventstore.upsert(E, "s1")
        eventstore.sync_vulns({"iss|a": E["iss|a"], IDS: E[IDS]}, latest=True)
        self.assertEqual((row("iss|a")["resolved"], row("iss|b")["resolved"], row(IDS)["resolved"]), (0, 1, 0))
        self.assertEqual(set(open_ids()), {"iss|a", IDS})

    def test_older_snapshot_never_closes_vulns(self):
        """sync_vulns on a non-latest snapshot changes nothing.
        REQ: OE-02
        """
        eventstore.upsert({"iss|a": ev("vuln", "A")}, "s1")
        eventstore.sync_vulns({}, latest=False)
        self.assertEqual(row("iss|a")["resolved"], 0)

    def test_vuln_listed_again_reopens(self):
        """A resolved Fix-list item that a later snapshot lists again is open again.
        REQ: OE-02
        """
        eventstore.upsert({"iss|a": ev("vuln", "A")}, "s1")
        eventstore.sync_vulns({}, latest=True)
        self.assertNotIn("iss|a", open_ids())
        eventstore.upsert({"iss|a": ev("vuln", "A")}, "s2")
        self.assertIn("iss|a", open_ids())


class OpenEventsListTest(_Fresh):
    """open_events(): order, filters, limit, counts and collapsing of repeats."""

    def setUp(self):
        super().setUp()
        eventstore.upsert({IDS: ev("ids", "IDS: Example signature x3", "medium", t1=300),
                           GW: ev("gw", "Gateway blocked threat", "High", t1=100),
                           "iss|a": ev("vuln", "Telnet open - server", "low"),
                           "ti|out|" + EXT["bad"]: ev("ti", "Outbound to listed IP", "high", t1=200)}, "s1")

    def test_most_severe_then_newest_first(self):
        """Rows are ordered by severity (high before medium before low), then newest event time first.
        REQ: OE-04
        """
        self.assertEqual(open_ids(), ["ti|out|" + EXT["bad"], GW, IDS, "iss|a"])

    def test_type_severity_and_text_filters(self):
        """type= keeps only those types, sev= matches severity case-insensitively, q= is a case-insensitive label search.
        REQ: OE-05
        """
        self.assertEqual(open_ids(types={"ids", "vuln"}), [IDS, "iss|a"])
        self.assertEqual(open_ids(sev="high"), ["ti|out|" + EXT["bad"], GW])
        self.assertEqual(open_ids(q="TELNET"), ["iss|a"])
        self.assertEqual(open_ids(types={"ids"}, q="telnet"), [])

    def test_counts_and_total_ignore_filters(self):
        """total and per-type counts describe everything open, whatever filter or limit the request used.
        REQ: OE-05
        """
        r = eventstore.open_events(types={"ids"}, sev="low", limit=1)
        self.assertEqual(r["total"], 4)
        self.assertEqual(r["counts"], {"ids": 1, "gw": 1, "vuln": 1, "ti": 1})
        self.assertEqual(r["shown"], 0)

    def test_limit_and_count_only_request(self):
        """limit caps the rows returned (shown); limit=0 (the nav badge) returns the total with no rows and no extras.
        REQ: OE-05
        """
        r = eventstore.open_events(limit=2)
        self.assertEqual((r["shown"], len(r["events"]), r["total"]), (2, 2, 4))
        r = eventstore.open_events(limit=0)
        self.assertEqual((r["events"], r["extra"], r["total"]), ([], {}, 4))

    def test_repeats_collapse_into_one_row(self):
        """Two variants of one finding are one row: the newest variant's id and label, summed seen count, both members,
        the earliest first-seen and repeats=2.
        REQ: OE-03, OE-04
        """
        eventstore.upsert({BEACON_1: ev("finding", "beacon 145", t0=0, t1=100)}, "s1", "2026-01-01T00:00:00Z")
        eventstore.upsert({BEACON_2: ev("finding", "beacon 3983", t0=200, t1=300)}, "s2", "2026-01-02T00:00:00Z")
        r = next(e for e in eventstore.open_events()["events"] if e["type"] == "finding")
        self.assertEqual((r["eid"], r["label"], r["repeats"], r["n"]), (BEACON_2, "beacon 3983", 2, 2))
        self.assertEqual(r["members"], [BEACON_1, BEACON_2])
        self.assertEqual(r["first_seen"], "2026-01-01T00:00:00Z")
        self.assertEqual(eventstore.open_events(types={"finding"})["counts"]["finding"], 1)

    def test_row_carries_item_and_ips(self):
        """A row returns the stored source item (Ask AI / Kibana pivot) and the event's IPs.
        REQ: OE-04
        """
        eventstore.upsert({ADM: ev("admin", "admin session", ips=[IP["laptop"], IP["server"]])}, "s1",
                          items={ADM: {"src": IP["laptop"], "dst": IP["server"]}})
        r = next(e for e in eventstore.open_events()["events"] if e["eid"] == ADM)
        self.assertEqual(r["item"], {"src": IP["laptop"], "dst": IP["server"]})
        self.assertEqual(r["ips"], [IP["laptop"], IP["server"]])


class CheckOffTest(_Fresh):
    """ack_refs / k_in: which check-off hides an event, and what a check-off of a row writes."""

    def test_ack_refs_per_event_kind(self):
        """Each event kind maps to the check-off list the other pages use; kinds without one use ('event', eid).
        REQ: OE-06
        """
        self.assertEqual(eventstore.ack_refs(ADM), [("admin", ADM[4:])])
        self.assertEqual(eventstore.ack_refs(HF_A), [("host", HF_A[3:])])
        self.assertEqual(eventstore.ack_refs("iss|seg|" + SEG_DEV + "|x"), [("issue", "seg|" + SEG_DEV + "|x"), ("seg", SEG_DEV + "|x")])
        self.assertEqual(eventstore.ack_refs("alarm|abc"), [("alarm", "abc")])
        self.assertEqual(eventstore.ack_refs(GW), [("gw", GW)])
        self.assertEqual(eventstore.ack_refs(BEACON_1)[0][0], "finding")
        for e in (IDS, "ti|out|" + EXT["bad"], "alert|5"):
            self.assertEqual(eventstore.ack_refs(e), [("event", e)])

    def test_k_in(self):
        """k_in is true only when the key is stored under that ack type.
        REQ: OE-06
        """
        acks = {"event": {IDS: {}}, "host": {}}
        self.assertTrue(eventstore.k_in(acks, ("event", IDS)))
        self.assertFalse(eventstore.k_in(acks, ("host", IDS)))
        self.assertFalse(eventstore.k_in(acks, ("finding", IDS)))

    def test_checked_off_event_leaves_and_unchecking_restores(self):
        """Checking an IDS signature off (type 'event') removes it from the list and the counts; unchecking restores it.
        REQ: OE-07
        """
        eventstore.upsert({IDS: ev("ids", "x", t1=1), GW: ev("gw", "g", t1=1)}, "s1")
        ack(("event", IDS))
        r = eventstore.open_events()
        self.assertEqual(([e["eid"] for e in r["events"]], r["total"]), ([GW], 1))
        ack(("event", IDS), False)
        self.assertIn(IDS, open_ids())

    def test_row_acks_cover_every_variant(self):
        """A collapsed finding row's check-off list is its newest variant's ack, the group ack, then each variant's ack.
        REQ: OE-07
        """
        eventstore.upsert({BEACON_1: ev("finding", "b1", t0=0, t1=100)}, "s1")
        eventstore.upsert({BEACON_2: ev("finding", "b2", t0=200, t1=300)}, "s2")
        r = eventstore.open_events()["events"][0]
        refs = [(a["type"], a["key"]) for a in r["acks"]]
        self.assertEqual(refs[0], eventstore.ack_refs(BEACON_2)[0])
        self.assertEqual(refs[1], ("event", "grp|" + eventstore.gkey(BEACON_2)))
        self.assertIn(eventstore.ack_refs(BEACON_1)[0], refs)
        self.assertEqual(len(refs), len(set(refs)))

    def test_group_check_off_also_hides_future_variants(self):
        """Checking off a collapsed row (group ack) hides it, and a new variant next night with other numbers stays hidden.
        REQ: OE-07
        """
        eventstore.upsert({BEACON_1: ev("finding", "b1", t0=0, t1=100)}, "s1")
        for a in eventstore.open_events()["events"][0]["acks"]:
            ack((a["type"], a["key"]))
        self.assertEqual(open_ids(), [])
        eventstore.upsert({BEACON_2: ev("finding", "b2", t0=200, t1=300)}, "s2")
        self.assertEqual(open_ids(), [])

    def test_posture_check_off_of_newest_variant_hides_row(self):
        """Checking the newest variant off on Posture (its finding ack) hides the collapsed row on Open events too.
        REQ: OE-07
        """
        eventstore.upsert({BEACON_1: ev("finding", "b1", t0=0, t1=100)}, "s1")
        eventstore.upsert({BEACON_2: ev("finding", "b2", t0=200, t1=300)}, "s2")
        ack(eventstore.ack_refs(BEACON_2)[0])
        self.assertEqual(open_ids(), [])

    def test_cleared_segmentation_flow_hides_its_findings(self):
        """A segmentation finding is hidden when its flow key is checked off under 'seg' (cleared / suppressed flow).
        REQ: OE-07
        """
        eventstore.upsert({SEG_A + " 3 conns": ev("finding", "seg", "high", t0=0, t1=10)}, "s1")
        self.assertEqual(len(open_ids()), 1)
        ack(("seg", f"{SEG_DEV}|{IP['server']}|22"))
        self.assertEqual(open_ids(), [])

    def test_alert_events_follow_the_alert_feed(self):
        """alert|<id> events are listed only while the alert is live: cleared, held (detection) or review alerts are not.
        REQ: OE-08
        """
        store.alerts_add([("k|1", "live alert", "high")], source="manual")
        store.alerts_add([("k|2", "held detection", "high")], source="watcher")
        store.alerts_add([("k|3", "review alarm", "high")], source="review")
        ids = {r[1]: r[0] for r in eventstore._c().execute("SELECT id, key FROM alerts")}
        E = {f"alert|{ids[k]}": ev("alert", k, "high", t1=1) for k in ids}
        E["alert|notanumber"] = ev("alert", "bad id", "high", t1=1)
        eventstore.upsert(E, "s1")
        self.assertEqual(open_ids(), [f"alert|{ids['k|1']}"])
        eventstore._c().execute("UPDATE alerts SET cleared=1 WHERE key='k|1'")
        self.assertEqual(open_ids(), [])


class MergeTest(_Fresh):
    """merge_flows / _merge_variants: display merges on the Open events page (merge=True)."""

    def test_process_variants_become_one_row(self):
        """Host findings of one process on one host that differ only in the remote side are one row 'N variants' with
        every instance in children, summed counts and the union of IPs and check-offs.
        REQ: OE-09
        """
        eventstore.upsert({HF_A: ev("host", "tool to bad", "high", t1=100, ips=[EXT["bad"]])}, "s1")
        eventstore.upsert({HF_B: ev("host", "tool to cdn", "high", t1=200, ips=[EXT["cdn"]])}, "s2")
        self.assertEqual(len(eventstore.open_events()["events"]), 2)
        r = eventstore.open_events(merge=True)
        self.assertEqual(len(r["events"]), 1)
        x = r["events"][0]
        self.assertEqual((x["eid"], x["label"], x["n"], x["repeats"]), (HF_B, "host-a: tool.exe - hnet-proc - 2 variants", 2, 2))
        self.assertEqual([k["eid"] for k in x["children"]], [HF_B, HF_A])
        self.assertEqual(x["ips"], [EXT["cdn"], EXT["bad"]])
        self.assertEqual({(a["type"], a["key"]) for a in x["acks"]}, {("host", HF_A[3:]), ("host", HF_B[3:])})
        self.assertEqual(r["total"], 2)  # total counts conditions, not display rows
        for a in x["acks"]:
            ack((a["type"], a["key"]))
        self.assertEqual(open_ids(merge=True), [])

    def test_other_host_kinds_and_single_variant_not_merged(self):
        """A lone variant keeps its own label; kinds outside hnet-proc/hnet-in/net-new are never merged.
        REQ: OE-09
        """
        other = [{"eid": f"hf|edr-alert|host-a|tool.exe|{i}", "type": "host", "t1": i, "last_seen": "", "label": str(i)} for i in (1, 2)]
        lone = {"eid": HF_A, "type": "host", "t1": 1, "last_seen": "", "label": "lone"}
        out = eventstore._merge_variants(other + [lone])
        self.assertEqual([r["label"] for r in out], ["1", "2", "lone"])
        self.assertFalse(any(r.get("children") for r in out))

    def test_segmentation_toward_many_devices_is_one_row(self):
        """Segmentation findings of one device and one rule toward several devices become '-> multiple devices (N)'.
        REQ: OE-09
        """
        eventstore.upsert({SEG_A: ev("finding", "seg a", "high", t0=0, t1=10, ips=[SEG_DEV, IP["server"]])}, "s1", items={SEG_A: seg_item(SEG_A)})
        eventstore.upsert({SEG_B: ev("finding", "seg b", "high", t0=20, t1=30, ips=[SEG_DEV, IP["camera"]])}, "s2", items={SEG_B: seg_item(SEG_B)})
        r = eventstore.open_events(merge=True)
        self.assertEqual(len(r["events"]), 1)
        x = r["events"][0]
        self.assertEqual(x["label"], "segmentation: DMZ Game Box - DMZ Game Box -> multiple devices (2)")
        self.assertEqual(x["item"]["detail"], "DMZ Game Box -> multiple devices (2)")
        self.assertEqual([(k["dst"], k["ip"]) for k in x["children"]], [("Yard Camera", IP["camera"]), ("Lab Server", IP["server"])])
        self.assertEqual(x["ips"], [SEG_DEV, IP["camera"], IP["server"]])
        refs = {(a["type"], a["key"]) for a in x["acks"]}
        self.assertTrue({("seg", f"{SEG_DEV}|{IP['server']}|22"), ("seg", f"{SEG_DEV}|{IP['camera']}|22")} <= refs)

    def test_rows_without_flow_text_pass_through(self):
        """Non-segmentation rows and segmentation rows whose detail is not a flow are returned unchanged.
        REQ: OE-09
        """
        rows = [{"eid": IDS, "type": "ids", "item": None},
                {"eid": "f|segmentation|d|odd", "type": "finding", "item": {"kind": "segmentation", "detail": "odd text"}}]
        self.assertEqual(eventstore.merge_flows(rows), rows)


class ExtrasTest(_Fresh):
    """extras(): AI verdicts, classifications, notes, related counts and decision model per displayed row."""

    def setUp(self):
        super().setUp()
        import enrich, kb
        self.mods = (enrich, kb)
        self._saved = (enrich.load, corr_llm.classes, kb.event_notes)

    def tearDown(self):
        enrich, kb = self.mods
        enrich.load, corr_llm.classes, kb.event_notes = self._saved

    def test_newest_member_with_data_wins_and_seen_is_set(self):
        """A collapsed row takes the newest variant that has a note / class / person note; 'seen' carries n and times.
        REQ: OE-10
        """
        enrich, kb = self.mods
        enrich.load = lambda ids: {BEACON_1: {"verdict": "old"}, BEACON_2: {"verdict": "new"}}
        corr_llm.classes = lambda ids: {BEACON_1: {"label": "benign"}}
        kb.event_notes = lambda ids: {}
        rows = [{"eid": BEACON_2, "members": [BEACON_1, BEACON_2], "n": 3, "first_seen": "a", "last_seen": "b"}]
        X = eventstore.extras(rows)
        self.assertEqual(X["notes"][BEACON_2], {"verdict": "new"})
        self.assertEqual(X["classes"][BEACON_2], {"label": "benign"})
        self.assertEqual(X["unotes"], {})
        self.assertEqual(X["seen"][BEACON_2], {"n": 3, "first": "a", "last": "b"})

    def test_failing_sources_do_not_break_the_page(self):
        """If the notes sources raise, extras still returns empty maps and the seen counts.
        REQ: OE-10
        """
        enrich, _ = self.mods

        def boom(ids):
            raise RuntimeError("down")
        enrich.load = boom
        X = eventstore.extras([{"eid": IDS, "members": [IDS], "n": 1, "first_seen": "a", "last_seen": "a"}])
        self.assertEqual((X["notes"], X["classes"], X["unotes"]), ({}, {}, {}))
        self.assertIn(IDS, X["seen"])

    def test_related_count_and_decision_model_from_stored_verdicts(self):
        """Rows get their related count from stored verdicts (any member) and the newest member's decision-model label.
        REQ: OE-10, OE-11
        """
        P = corr_llm.pair
        with corr_llm._db() as c:
            c.execute("INSERT INTO verdicts (pair, related, confidence, reason, model, ts) VALUES (?,?,?,?,?,?)", (P(BEACON_1, IDS), 1, 0.9, "same host", "m", 10))
            c.execute("INSERT INTO verdicts (pair, related, confidence, reason, model, ts) VALUES (?,?,?,?,?,?)", (P(BEACON_2, GW), 1, 0.8, "same host", "m", 11))
            c.execute("INSERT INTO verdicts (pair, related, confidence, reason, model, ts) VALUES (?,?,?,?,?,?)", (P(BEACON_2, "ti|x"), 0, 0.1, "no", "m", 11))
            for e, lab in ((BEACON_1, "benign"), (BEACON_2, "suspicious")):
                c.execute("INSERT INTO clef_event (eid, p_suspicious, p_expected, label, model, ts) VALUES (?,?,?,?,?,?)", (e, 0.5, 0.5, lab, "m", 1))
        X = eventstore.extras([{"eid": BEACON_2, "members": [BEACON_1, BEACON_2], "n": 2, "first_seen": "a", "last_seen": "b"}])
        self.assertEqual(X["related_n"][BEACON_2], 2)
        self.assertEqual(X["clef_ev"][BEACON_2]["label"], "suspicious")

    def test_open_events_attaches_extras_for_shown_rows(self):
        """open_events returns extras keyed by the shown rows' ids.
        REQ: OE-10
        """
        enrich, kb = self.mods
        enrich.load = lambda ids: {}
        corr_llm.classes = lambda ids: {IDS: {"label": "expected"}}
        kb.event_notes = lambda ids: {}
        eventstore.upsert({IDS: ev("ids", "x", t1=1)}, "s1")
        self.assertEqual(eventstore.open_events()["extra"]["classes"], {IDS: {"label": "expected"}})


class RelatedDetailTest(_Fresh):
    """related(), detail() and decision_inputs(): the Related popover, the event window and the AI-inputs pop-up."""

    def setUp(self):
        super().setUp()
        self._saved = (corr_llm.decision_inputs_view, corr_llm.decision_inputs_since)

    def tearDown(self):
        corr_llm.decision_inputs_view, corr_llm.decision_inputs_since = self._saved

    def test_related_lists_links_of_all_members_with_event_records(self):
        """related() returns links of every member (not links between its own members), records for partners (a pruned
        partner by id) and the newest member's decision-model label.
        REQ: OE-11
        """
        eventstore.upsert({GW: ev("gw", "gateway", "high", t1=5, ips=[IP["laptop"]])}, "s1")
        P = corr_llm.pair
        with corr_llm._db() as c:
            c.executemany("INSERT INTO verdicts (pair, related, confidence, reason, model, ts) VALUES (?,?,?,?,?,?)", [
                (P(BEACON_1, GW), 1, 0.9, "same host", "m", 10), (P(BEACON_2, "ti|gone"), 1, 0.6, "dst", "m", 11),
                (P(BEACON_1, BEACON_2), 1, 0.9, "repeat", "m", 12)])
            c.execute("INSERT INTO clef_event (eid, p_suspicious, p_expected, label, model, ts) VALUES (?,?,?,?,?,?)", (BEACON_2, 0.7, 0.2, "suspicious", "m", 1))
        r = eventstore.related(BEACON_2, [BEACON_1])
        self.assertEqual([x["id"] for x in r["related"]], [GW, "ti|gone"])
        self.assertEqual(r["events"][GW]["host_ips"], [IP["laptop"]])
        self.assertEqual(r["events"]["ti|gone"], {"type": "ti", "label": "ti|gone", "link": "", "t0": None, "t1": None})
        self.assertEqual(r["clef_ev"]["label"], "suspicious")
        self.assertEqual(eventstore.related(IDS, [])["related"], [])

    def test_detail_lists_every_open_variant_newest_first(self):
        """detail() lists all open variants of the condition newest first with their firings; unrelated ids are excluded.
        REQ: OE-12
        """
        corr_llm.decision_inputs_since = lambda: None
        eventstore.upsert({BEACON_1: ev("finding", "b1", t0=0, t1=100)}, "s1")
        eventstore.upsert({BEACON_2: ev("finding", "b2", t0=200, t1=300)}, "s2")
        eventstore.upsert({f"f|beacon|{DEV}|beacon to {EXT['cdn']} 5 conns": ev("finding", "other", t0=0, t1=50)}, "s2")
        d = eventstore.detail(BEACON_1)
        self.assertEqual([o["eid"] for o in d["occurrences"]], [BEACON_2, BEACON_1])
        self.assertEqual(d["n_occurrences"], 2)
        self.assertEqual({f["eid"] for f in d["fires"]}, {BEACON_1, BEACON_2})
        for k in ("by_event", "events", "decisions", "fires_since", "inputs_since", "clef_ev"):
            self.assertIn(k, d)

    def test_detail_of_unknown_event_is_empty(self):
        """An event id that is not stored gives an empty detail, not an error.
        REQ: OE-12
        """
        self.assertEqual(eventstore.detail("ids|nothing here"), {"occurrences": [], "related": [], "events": {}, "clef_ev": None})

    def test_detail_of_resolved_vuln_shows_only_itself(self):
        """A resolved Fix-list item still opens (its own row) even though it is no longer open.
        REQ: OE-12, OE-02
        """
        corr_llm.decision_inputs_since = lambda: None
        eventstore.upsert({"iss|a": ev("vuln", "A")}, "s1")
        eventstore.sync_vulns({}, latest=True)
        d = eventstore.detail("iss|a")
        self.assertEqual([o["eid"] for o in d["occurrences"]], ["iss|a"])
        self.assertEqual(d["fires"], [])

    def test_decision_inputs_returns_input_event_records(self):
        """decision_inputs() returns the event's determinations and a record for every event passed in to them.
        REQ: OE-13
        """
        eventstore.upsert({GW: ev("gw", "gateway", "high", t1=5)}, "s1")
        D = [{"stage": "review", "at": 1, "inputs": [{"id": GW, "sent": True}, {"id": "ids|gone", "sent": False}]}]
        corr_llm.decision_inputs_view = lambda eids: {IDS: D} if IDS in eids else {}
        r = eventstore.decision_inputs(IDS)
        self.assertEqual(r["decisions"], D)
        self.assertEqual(r["events"][GW]["label"], "gateway")
        self.assertEqual(r["events"]["ids|gone"]["label"], "ids|gone")
        self.assertEqual(eventstore.decision_inputs(GW), {"decisions": [], "events": {}})


class ApiRoutingTest(unittest.TestCase):
    """server.py: the Open events GET endpoints are not open to the User role."""

    def test_user_role_allow_list_excludes_open_events(self):
        """USER_GET (the User role's GET allow-list) contains none of the /api/events/* endpoints.
        REQ: OE-14
        """
        import server
        for p in ("/api/events/open", "/api/events/detail", "/api/events/inputs", "/api/events/related"):
            self.assertNotIn(p, server.USER_GET)


JS_HARNESS = r"""
const fs = require("fs"), vm = require("vm");
const [src, dataPath] = process.argv.slice(2);
const data = JSON.parse(fs.readFileSync(dataPath, "utf8"));
const cards = [], el = { innerHTML: "", html: [], insertAdjacentHTML(_, h) { this.html.push(h); }, appendChild(c) { if (c && c.title !== undefined) cards.push(c); } };
const sel = () => ({ onchange: null });
const S = { me: { role: "admin" } };
const ctx = {
  S, V: {}, console, Date, JSON, Math, Object, Array, Set, Map, String, Number, Promise, encodeURIComponent,
  esc: (s) => String(s ?? ""), ft: (v) => String(v), badge: (v) => v, sevRank: (v) => ({ high: 0, medium: 1, low: 2 })[v] ?? 3,
  linkifyIps: (v) => String(v), ipLink: (v) => v, devCell: () => "", findHostIp: () => "", devNameFor: () => "", fn: (n) => String(n),
  hfHostCol: () => ({ k: "hf_host", t: "Host" }), hfToCol: () => ({ k: "hf_to", t: "To" }),
  kpis: (l) => "KPIS:" + JSON.stringify(l), askBtn: () => "", pivBtn: () => "", aiFlare: () => "",
  card: (title, body) => ({ title, body }), table: (id, cols, rows, opts) => ({ cols: cols.map((c) => c.t), rows: rows.map((r) => r.eid), sort: opts.sort }),
  setInterval: () => 0, addEventListener: () => {}, removeEventListener: () => {},
  api: async (u) => (u.includes("limit=0") ? { total: data.total } : data),
  document: { querySelectorAll: () => [], querySelector: () => null, addEventListener: () => {},
              createElement: () => ({ set innerHTML(v) { this._h = v; }, querySelector: sel, title: undefined }) },
};
ctx.window = ctx;
vm.createContext(ctx);
vm.runInContext(fs.readFileSync(src, "utf8"), ctx);
(async () => {
  await ctx.V.events(el);
  const card0 = (c) => ({ title: c.title, body: typeof c.body === "string" ? c.body : c.body });
  process.stdout.write(JSON.stringify({ cards: cards.map(card0), html: el.html }));
})().catch((e) => { console.error(e && e.stack || e); process.exit(1); });
"""


def _oe_row(eid, typ, sev="medium", label="x"):
    return {"eid": eid, "type": typ, "sev": sev, "label": label, "n": 1, "repeats": 1, "acks": [{"type": "event", "key": eid}],
            "first_seen": "a", "last_seen": "b", "ips": [], "members": [eid], "item": None, "t0": None, "t1": None}


@unittest.skipUnless(NODE, "node not available")
class OpenEventsPageJsTest(unittest.TestCase):
    """openevents.js V.events under node with stubbed page helpers: one card per type, columns, empty state."""

    def render(self, events, counts=None):
        d = os.environ["NETMON_TEST_TMP"]
        hp, dp = os.path.join(d, "oe_harness.js"), os.path.join(d, "oe_data.json")
        with open(hp, "w") as f:
            f.write(JS_HARNESS)
        with open(dp, "w") as f:
            json.dump({"events": events, "total": len(events), "counts": counts or {}, "extra": {}}, f)
        r = subprocess.run([NODE, hp, OE_JS, dp], capture_output=True, text=True, timeout=30)  # noqa: S603 - node on repo files
        self.assertEqual(r.returncode, 0, r.stderr)
        return json.loads(r.stdout)

    def test_one_card_per_type_in_page_order(self):
        """Rows are drawn as one card per type, in the page's fixed type order, titled with the open count.
        REQ: OE-15
        """
        ev_ = [_oe_row(IDS, "ids"), _oe_row("ids|two", "ids"), _oe_row(BEACON_1, "finding"), _oe_row("iss|a", "vuln"),
               _oe_row(GW, "gw"), _oe_row("alarm|z", "alarm")]
        out = self.render(ev_, {"ids": 2, "finding": 1, "vuln": 1, "gw": 1, "alarm": 1})
        self.assertEqual([c["title"] for c in out["cards"]], ["Baseline findings (1 open)", "IDS signatures (2 open)", "Gateway events (1 open)",
                                                               "Fix list (vulnerabilities / misconfigurations) (1 open)", "Triage alarms (1 open)"])
        self.assertEqual(out["cards"][1]["body"]["rows"], [IDS, "ids|two"])
        self.assertTrue(all(c["body"]["sort"] == "sev" for c in out["cards"]))

    def test_columns_per_type(self):
        """Every card starts with check box, Severity, Verdict, Notes and ends with First seen, Last seen, Seen; the
        middle columns depend on the type.
        REQ: OE-15
        """
        out = self.render([_oe_row(BEACON_1, "finding"), _oe_row(IDS, "ids"), _oe_row(HF_A, "host"), _oe_row(GW, "gw"),
                           _oe_row(ADM, "admin"), _oe_row("iss|a", "vuln")])
        cols = {c["title"].split(" (")[0]: c["body"]["cols"] for c in out["cards"]}
        head, tail = ["✓", "Severity", "Verdict", "Notes"], ["First seen", "Last seen", "Seen"]
        mid = {"Baseline findings": ["Kind", "Device", "Detail"], "IDS signatures": ["Signature", "Count", "From", "To"],
               "Endpoint": ["Host", "To", "Finding"], "Gateway events": ["Time", "Event"], "Admin sessions": ["Event", "Hosts"],
               "Fix list": ["Issue", "Target"]}
        self.assertEqual(set(cols), set(mid))
        for name, m in mid.items():
            self.assertEqual(cols[name], head + m + tail, name)

    def test_empty_state(self):
        """With nothing open the page shows the KPI line and one 'Nothing open' card.
        REQ: OE-16
        """
        out = self.render([])
        self.assertEqual(len(out["cards"]), 1)
        self.assertIn("Nothing open", out["cards"][0]["body"])
        self.assertTrue(any(h.startswith("KPIS:") and '["Open events",0]' in h for h in out["html"]))

    def test_every_correlation_type_has_a_card(self):
        """Every event type correlate.py emits has a card in openevents.js TYPES (no open event is invisible).
        REQ: OE-15
        """
        import re
        with open(os.path.join(_env.APP, "correlate.py")) as f:
            emitted = set(re.findall(r'\badd\((?:f?"[^"]*"|\w+),\s*"([a-z]+)"', f.read()))
        with open(OE_JS) as f:
            listed = set(re.findall(r'^\s*\["([a-z]+)", "', f.read(), re.M))
        self.assertTrue({"finding", "host", "ids", "gw", "vuln"} <= emitted, emitted)
        self.assertEqual(emitted - listed, set())


if __name__ == "__main__":
    unittest.main()
