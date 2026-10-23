"""Unit tests for dashboard/app/correlate.py: artifact extraction, stable ids, topics and the pair scoring in build()."""
import os, sys; sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))); import _env  # noqa: E402

import ipaddress  # noqa: E402
import unittest  # noqa: E402
from datetime import datetime, timezone  # noqa: E402

import correlate  # noqa: E402
import corr_llm  # noqa: E402
from fixtures import mac  # noqa: E402

GEN = "2026-01-05T12:00:00+00:00"
GEN_TS = datetime(2026, 1, 5, 12, 0, tzinfo=timezone.utc).timestamp()
NET10 = ipaddress.ip_network("10.0.0.0/8")


def internal(ip):
    try:
        return ipaddress.ip_address(ip) in NET10
    except ValueError:
        return False


def no_tech(source, text):
    return []


def raw(**kw):
    r = {"generated": GEN, "hours": 24, "devices": {"10.0.1.10": {"name": "Laptop", "mac": mac(1)},
                                                     "10.0.2.20": {"name": "Server", "mac": mac(2)}}}
    r.update(kw)
    return r


def alert(i, ts, text, key="k|x", targets=(), sev="high"):
    return {"id": i, "ts": ts, "text": text, "key": key, "targets": list(targets), "severity": sev}


def run(r=None, alerts=(), issues=(), admin=(), resolve=lambda h: "", techniques=no_tech, latest=False, analysis=None, triage=None):
    return correlate.build(r or raw(), analysis, list(alerts), list(issues), list(admin), internal, resolve, techniques,
                           latest=latest, triage=triage)


def ids(res, eid):
    return [r["id"] for r in res["related"].get(eid, [])]


class ArtifactsOfTest(unittest.TestCase):
    """artifacts_of() pulls files, processes, users and domains from event text."""

    def test_empty_text_gives_no_artifacts(self):
        """Empty or None text yields an empty artifact list.
        REQ: COR-01"""
        self.assertEqual(correlate.artifacts_of(""), [])
        self.assertEqual(correlate.artifacts_of(None), [])

    def test_process_path_in_process_context(self):
        """A binary path in a process-keyed event is reported as a process.
        REQ: COR-01"""
        arts = correlate.artifacts_of("process /usr/bin/curl contacted 203.0.113.5", key="proc-new|x")
        self.assertIn(["process", "/usr/bin/curl", "process"], arts)

    def test_new_executable_relation(self):
        """An exec-new key labels the path as a new executable, with the host label appended.
        REQ: COR-01"""
        arts = correlate.artifacts_of("executable /opt/tool/run started", key="exec-new|h", host_label="lab1")
        self.assertEqual(arts[0][:2], ["process", "/opt/tool/run"])
        self.assertEqual(arts[0][2], "new executable on lab1")

    def test_file_path_in_file_context(self):
        """A path mentioned in a file-write event is reported as a file.
        REQ: COR-01"""
        arts = correlate.artifacts_of("file /tmp/drop.sh written by job", key="fim|x")
        self.assertEqual(arts[0][:2], ["file", "/tmp/drop.sh"])
        self.assertTrue(arts[0][2].startswith("file mentioned"))

    def test_windows_path_detected(self):
        """A Windows drive path is extracted as an artifact.
        REQ: COR-01"""
        arts = correlate.artifacts_of(r"file C:\Users\bob\evil.exe dropped")
        self.assertIn(("file", r"C:\Users\bob\evil.exe"), [(a[0], a[1]) for a in arts])

    def test_trailing_punctuation_stripped(self):
        """Trailing punctuation after a path is not part of the artifact value.
        REQ: COR-01"""
        arts = correlate.artifacts_of("file /etc/passwd. modified")
        self.assertEqual(arts[0][1], "/etc/passwd")

    def test_parent_process_and_command_line(self):
        """'parent X' and 'cmd: ...' produce a parent process and a command-line artifact.
        REQ: COR-01"""
        arts = correlate.artifacts_of("process /usr/bin/python3 spawned by user alice parent bash cmd: python3 -c run", key="proc|h")
        pairs = [(a[0], a[1], a[2]) for a in arts]
        self.assertIn(("process", "bash", "parent process"), pairs)
        self.assertIn(("process", "python3 -c run", "command line"), pairs)
        self.assertIn(("user", "alice", "account that ran it"), pairs)

    def test_parent_path_not_duplicated_as_file(self):
        """A parent given as a path is only listed once, as the parent process.
        REQ: COR-01"""
        arts = correlate.artifacts_of("process /usr/bin/sh parent /usr/sbin/cron", key="proc|h")
        vals = [a[1] for a in arts]
        self.assertEqual(vals.count("/usr/sbin/cron"), 1)
        self.assertIn(["process", "/usr/sbin/cron", "parent process"], arts)

    def test_sha256_is_appended_to_relation(self):
        """A sha256 in the text is attached (first 16 hex chars) to the path's relation.
        REQ: COR-01"""
        h = "ab" * 32
        arts = correlate.artifacts_of(f"file /tmp/x.bin created sha256 {h}")
        self.assertIn("sha256 " + h[:16], arts[0][2])

    def test_stop_words_are_not_users(self):
        """Words like 'unknown' after 'user' are not reported as accounts.
        REQ: COR-01"""
        arts = correlate.artifacts_of("login by user unknown, then user agent")
        self.assertFalse([a for a in arts if a[0] == "user"])

    def test_accounts_list_parsed(self):
        """'accounts alice (1 failed, 2 ok), root (1 failed)' yields both accounts.
        REQ: COR-01"""
        arts = correlate.artifacts_of("SSH login attempts: accounts alice (1 failed, 2 ok), root (1 failed)")
        self.assertEqual([a[1] for a in arts if a[0] == "user"], ["alice", "root"])

    def test_users_argument_and_case_insensitive_dedupe(self):
        """Users passed in are added; the same user in another case is not repeated.
        REQ: COR-01"""
        arts = correlate.artifacts_of("failed login for user Alice", users=["alice", "bob"])
        users = [a[1] for a in arts if a[0] == "user"]
        self.assertEqual(users, ["Alice", "bob"])

    def test_domains_lowercased_and_deduped(self):
        """Domain names are lowercased and listed once.
        REQ: COR-01"""
        arts = correlate.artifacts_of("query Evil-Site.XYZ then evil-site.xyz again")
        self.assertEqual([a for a in arts if a[0] == "dns"], [["dns", "evil-site.xyz", "domain in event"]])

    def test_extra_artifacts_and_cap(self):
        """Extra artifacts are appended and the result is capped at MAX_ARTS.
        REQ: COR-01"""
        extra = [("dns", f"d{i}.example.com", "x") for i in range(20)]
        arts = correlate.artifacts_of("", extra=extra)
        self.assertEqual(len(arts), correlate.MAX_ARTS)
        self.assertEqual(arts[0], ["dns", "d0.example.com", "x"])

    def test_relation_truncated_to_90(self):
        """Relation text is cut at 90 characters.
        REQ: COR-01"""
        arts = correlate.artifacts_of("", extra=[("file", "/tmp/a", "r" * 200)])
        self.assertEqual(len(arts[0][2]), 90)


class IdsAndTopicsTest(unittest.TestCase):
    """fnv(), gw_id(), _ts() and topic helpers."""

    def test_fnv_known_vectors(self):
        """fnv() is 32-bit FNV-1a rendered in base 36 (empty string = offset basis).
        REQ: COR-02"""
        self.assertEqual(int(correlate.fnv(""), 36), 0x811c9dc5)
        self.assertEqual(int(correlate.fnv("a"), 36), 0xe40c292c)
        self.assertEqual(int(correlate.fnv("foobar"), 36), 0xbf9cf968)

    def test_fnv_is_lowercase_base36(self):
        """fnv() output uses only 0-9a-z.
        REQ: COR-02"""
        for s in ("x", "alarm|who", "Ünïcödé text"):
            self.assertRegex(correlate.fnv(s), r"^[0-9a-z]+$")

    def test_fnv_matches_corr_llm_for_bmp_text(self):
        """correlate.fnv and corr_llm._fnv agree for text inside the Basic Multilingual Plane.
        REQ: COR-02"""
        for s in ("", "a", "SSH brute force|10.0.1.10", "héllo wörld", "日本語"):
            self.assertEqual(correlate.fnv(s), corr_llm._fnv(s), s)

    @unittest.expectedFailure
    def test_fnv_matches_js_for_astral_characters(self):
        """fnv() hashes UTF-16 code units like app.js charCodeAt() even for characters outside the BMP (emoji).
        BUG: correlate.fnv iterates Python code points (ord(ch)), so an alarm title containing an emoji hashes
        differently than app.js fnv() and corr_llm._fnv (which use UTF-16 code units) - the alarm ids diverge.
        REQ: COR-02"""
        s = "Alarm \U0001F600|host"
        self.assertEqual(correlate.fnv(s), corr_llm._fnv(s))

    def test_gw_id_format_and_missing_fields(self):
        """gw_id() joins time/key/src/dst with '|' and uses '' for missing fields.
        REQ: COR-02"""
        self.assertEqual(correlate.gw_id({"time": "t", "key": "K", "src": "10.0.0.5", "dst": "192.0.2.1"}), "gw|t|K|10.0.0.5|192.0.2.1")
        self.assertEqual(correlate.gw_id({}), "gw||||")
        self.assertEqual(correlate.gw_id({"key": "K", "src": None}), "gw||K||")

    def test_ts_parsing(self):
        """_ts() accepts numbers and ISO strings (Z or naive = UTC) and returns None for junk.
        REQ: COR-03"""
        self.assertEqual(correlate._ts(5), 5.0)
        self.assertEqual(correlate._ts("2026-01-05T12:00:00Z"), GEN_TS)
        self.assertEqual(correlate._ts("2026-01-05T12:00:00"), GEN_TS)
        self.assertIsNone(correlate._ts(None))
        self.assertIsNone(correlate._ts(""))
        self.assertIsNone(correlate._ts("not a date"))

    def test_topics_finding(self):
        """Finding kinds map to their problem topics.
        REQ: COR-03"""
        self.assertEqual(correlate._topics_finding("ti-ip-out"), {"threat-intel"})
        self.assertEqual(correlate._topics_finding("segmentation"), {"segmentation"})
        self.assertEqual(correlate._topics_finding("outdated-software"), {"software"})
        self.assertEqual(correlate._topics_finding("something-else"), set())

    def test_topics_key(self):
        """Issue keys map by their first part; syslog keys add a syslog:<program> topic.
        REQ: COR-03"""
        self.assertEqual(correlate._topics_key("sshpw|10.0.2.20"), {"ssh-auth"})
        self.assertEqual(correlate._topics_key("syslog|h|KERNEL"), {"syslog:kernel"})
        self.assertEqual(correlate._topics_key("nope|x"), set())

    def test_every_topic_has_a_name(self):
        """Every topic produced by the finding and issue tables has a human-readable TOPIC_NAME.
        REQ: COR-03"""
        topics = {t for _, t in correlate._FINDING_TOPIC} | set(correlate._ISSUE_TOPIC.values())
        self.assertEqual(topics - set(correlate.TOPIC_NAME), set())


class BuildTest(unittest.TestCase):
    """build() scoring and linking on tiny synthetic snapshots."""

    def test_close_alerts_sharing_host_are_linked(self):
        """Two alerts on the same internal host 5 minutes apart are linked both ways with a time reason.
        REQ: COR-03"""
        t = GEN_TS - 3600
        res = run(alerts=[alert(1, t, "scan from 10.0.1.10"), alert(2, t + 300, "odd traffic 10.0.1.10")])
        self.assertEqual(ids(res, "alert|1"), ["alert|2"])
        self.assertEqual(ids(res, "alert|2"), ["alert|1"])
        why = res["related"]["alert|1"][0]["why"]
        self.assertIn("host Laptop", why)
        self.assertIn("within 15 min", why)

    def test_far_apart_alerts_not_linked(self):
        """The same host 8 hours apart scores below the threshold and is not linked.
        REQ: COR-03"""
        t = GEN_TS - 20 * 3600
        res = run(alerts=[alert(1, t, "a 10.0.1.10"), alert(2, t + 8 * 3600, "b 10.0.1.10")])
        self.assertEqual(res["related"], {})

    def test_no_shared_entity_no_link(self):
        """Simultaneous events with nothing in common are never linked.
        REQ: COR-03"""
        t = GEN_TS - 3600
        res = run(alerts=[alert(1, t, "a 10.0.1.10"), alert(2, t, "b 10.0.2.20")])
        self.assertEqual(res["related"], {})

    def test_gateway_dot1_address_ignored(self):
        """An internal address ending in .1 (gateway) is not an entity, so it does not link events.
        REQ: COR-03"""
        t = GEN_TS - 3600
        res = run(alerts=[alert(1, t, "dns via 10.0.0.1"), alert(2, t, "ntp via 10.0.0.1")])
        self.assertEqual(res["related"], {})
        self.assertEqual(res["events"]["alert|1"]["ips"], [])

    def test_alert_targets_resolve_mac_and_host(self):
        """Alert targets mac:<mac> and host:<name> resolve to internal hosts used for linking.
        REQ: COR-03"""
        t = GEN_TS - 3600
        res = run(alerts=[alert(1, t, "new device", targets=[f"mac:{mac(2)}"]), alert(2, t, "login", targets=["host:srv"])],
                  resolve=lambda h: "10.0.2.20" if h == "srv" else "")
        self.assertEqual(res["events"]["alert|1"]["ips"], ["10.0.2.20"])
        self.assertEqual(ids(res, "alert|1"), ["alert|2"])

    def test_alert_window_and_latest(self):
        """Alerts long after the window are dropped unless latest=True; long before are always dropped.
        REQ: COR-03"""
        after, before = GEN_TS + 5 * 3600, GEN_TS - 30 * 3600
        al = [alert(1, after, "x"), alert(2, before, "y")]
        self.assertEqual(run(alerts=al)["counts"]["alert"], 0)
        res = run(alerts=al, latest=True)
        self.assertEqual(list(res["events"]), ["alert|1"])
        self.assertEqual(res["window"], [GEN_TS - 24 * 3600, GEN_TS])

    def test_vulnerability_linked_by_host(self):
        """An open issue on a host links to an alert on that host with 'vulnerability on the same host'.
        REQ: COR-03"""
        res = run(alerts=[alert(1, GEN_TS - 3600, "attack on 10.0.2.20")],
                  issues=[{"key": "sshpw|10.0.2.20", "title": "SSH password login", "target": "Server", "ip": "10.0.2.20", "severity": "high"}])
        rel = res["related"]["alert|1"]
        self.assertEqual(rel[0]["id"], "iss|sshpw|10.0.2.20")
        self.assertIn("vulnerability on the same host", rel[0]["why"])
        self.assertTrue(res["events"]["iss|sshpw|10.0.2.20"]["t0"] is None)
        self.assertEqual(res["counts"]["vuln"], 1)

    def test_shared_topic_and_technique_reasons(self):
        """A shared problem topic and a shared ATT&CK technique each add a reason.
        REQ: COR-03, MIT-01"""
        t = GEN_TS - 3600
        res = run(alerts=[alert(1, t, "failed SSH T1110 10.0.2.20", key="admin|SSH|x"),
                          alert(2, t + 60, "brute force T1110 on 10.0.2.20", key="admin|SSH|y")])
        why = res["related"]["alert|1"][0]["why"]
        self.assertTrue(why[0].startswith("same problem: "))
        self.assertIn("same ATT&CK technique T1110", why)

    def test_per_type_cap_of_four(self):
        """At most 4 related events of one type are kept per event, best score first.
        REQ: COR-03"""
        t = GEN_TS - 3600
        res = run(alerts=[alert(i, t + i, f"e{i} 10.0.1.10") for i in range(1, 13)])
        for eid, lst in res["related"].items():
            self.assertEqual(len(lst), 4, eid)
            self.assertEqual([r["score"] for r in lst], sorted((r["score"] for r in lst), reverse=True))

    def test_triage_alarm_id_uses_fnv(self):
        """A triage alarm gets the id alarm|fnv(title|who); untitled alarms are skipped.
        REQ: COR-02"""
        tri = {"alarms": [{"title": "Possible C2", "who": "Laptop", "priority": "Investigate", "evidence": "10.0.1.10 T1071"}, {"title": ""}]}
        res = run(triage=tri)
        eid = "alarm|" + correlate.fnv("Possible C2|Laptop")
        self.assertEqual(list(res["events"]), [eid])
        self.assertEqual(res["events"][eid]["sev"], "high")
        self.assertEqual(res["counts"]["alarm"], 1)

    def test_gateway_events_deduped_and_windowed(self):
        """The same gateway event in high_severity and threats is one event; events outside the window are dropped.
        REQ: COR-02, COR-03"""
        g = {"time": "2026-01-05T10:00:00Z", "key": "THREAT_X", "src": "203.0.113.9", "dst": "10.0.2.20", "severity": "HIGH", "message": "blocked"}
        old = dict(g, time="2025-12-01T00:00:00Z")
        res = run(raw(unifi={"events": {"high_severity": [g], "threats": [g, old]}}))
        self.assertEqual(list(res["events"]), [correlate.gw_id(g)])
        ev = res["events"][correlate.gw_id(g)]
        self.assertEqual(ev["sev"], "high")
        self.assertEqual(ev["host_ips"], ["203.0.113.9"])  # gateway events: src is the host side, dst the destination
        self.assertEqual(ev["dst_ips"], ["10.0.2.20"])

    def test_chatty_low_ids_signature_skipped(self):
        """Low-severity IDS signatures firing more than 5000 times are left out; others are kept.
        REQ: COR-03"""
        sigs = [{"name": "STUN binding", "severity": 3, "count": 9000, "src": {"10.0.1.10": 1}},
                {"name": "ET SCAN probe", "severity": 2, "count": 9000, "src": {"203.0.113.9": 1}, "dst": {"10.0.2.20": 1}}]
        res = run(raw(alerts={"signatures": sigs}))
        self.assertEqual(list(res["events"]), ["ids|ET SCAN probe"])
        self.assertEqual(res["events"]["ids|ET SCAN probe"]["sev"], "medium")

    def test_finding_event_id_and_items(self):
        """A behaviour finding gets id f|kind|device|detail and its source row is returned in items.
        REQ: COR-02"""
        f = {"severity": "medium", "device": "10.0.1.10", "kind": "beacon", "detail": "every 60s to 203.0.113.5"}
        res = run(analysis={"findings": [f]})
        eid = "f|beacon|10.0.1.10|every 60s to 203.0.113.5"
        self.assertIn(eid, res["events"])
        self.assertIs(res["items"][eid], f)
        self.assertEqual(res["events"][eid]["host_ips"], ["10.0.1.10"])
        self.assertEqual(res["events"][eid]["dst_ips"], ["203.0.113.5"])

    def test_techniques_callback_used(self):
        """The techniques callback is consulted per source and shared IDs link events.
        REQ: COR-03, MIT-01"""
        seen = []

        def tech(source, text):
            seen.append(source)
            return ["T1046"]
        t = GEN_TS - 3600
        res = run(alerts=[alert(1, t, "x 10.0.1.10"), alert(2, t, "y 10.0.1.10")], techniques=tech)
        self.assertIn("alert", seen)
        self.assertIn("same ATT&CK technique T1046", res["related"]["alert|1"][0]["why"])


if __name__ == "__main__":
    unittest.main()
