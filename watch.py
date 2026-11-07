#!/usr/bin/python3
"""Urgent network watcher - runs every 15 min from cron (no LLM). Prints alerts (cron log only, never posted to chat) and records them in the dashboard alerts table;
prints nothing when there is nothing new. Read-only ES queries.

Checks over the last WINDOW minutes:
  1. Suricata severity-1 alerts, or malware/C2/exploit categories, not on the known-benign list
  2. New device: DHCP MAC or active internal IP never seen in the device registry (store.py) or the DHCP inventory
  3. New Internet-facing port: answered inbound conn from the Internet on a port the device has never served
  4. Threat-intel hit: DNS name / SNI or outbound conn matching abuse.ch / Spamhaus feeds (cached by the nightly run)
  5. DNS tunnel: a domain with a burst of distinct high-entropy subdomains in the last hour
  6. Host anomalies (Elastic Agent / Defend)
  7. Admin access: failed logins / password guessing / refused connections on SSH, RDP, PsExec/SMB, WMI, WinRM, VNC...
     (lateral.admin_sessions levels: high = guessing or >=3 failures then success, medium = any failed login or >=5 refused)
Each finding is suppressed for SUPPRESS_H hours after it is first sent.

Window = ARRIVAL time (window.py): every check covers the events Elasticsearch stored since the previous successful
run (event.ingested), not the events that happened in the last 20 minutes, so events that reach ES hours late (Logstash
backed up) are still checked, exactly once. The bookmark moves only when no check failed. Per-source ingest lag is
saved (meta "ingest_lag") for the Fix list and the review job.
"""
import json, os, sys

sys.argv = [sys.argv[0], "1"]
NM = os.environ.get("NETMON_DIR") or os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from collect import q, ds, buckets, inventory  # noqa: E402
import extras  # noqa: E402

WINDOW = int(os.environ.get("NETMON_WATCH_WINDOW", 20))       # minutes: first-run span; env override for testing
SUPPRESS_H = 12
import window  # noqa: E402
_AW = window.arrival("watch", WINDOW)  # (bookmark, now - margin] on event.ingested; every since() below uses it
WINDOW = _AW["nominal_minutes"]       # callers passing WINDOW get exactly the bookmark window
FAILED_CHECKS = []                    # a failed check keeps the bookmark: the next run covers this window again
import site_cfg as SITE  # noqa: E402  network-specific values (site.json, git-ignored)
import store  # noqa: E402  SQLite state: registry, served ports, host baseline, mute state. Test with NETMON_DB=<scratch db>.
R = window.since(WINDOW)
INT = {"term": {"source.ip": SITE.get("internal_cidr")}}
FAILED = ["S0", "REJ", "RSTOS0", "SH", "OTH"]


def load(p, default):
    v = store.jload(p)
    return default if v is None else v


benign = load(os.path.join(NM, "known_benign.json"), {})
registry = store.registry_load()
inv, _ = inventory()
names = {v["ip"]: v["name"] for v in inv.values()}
names.update(benign.get("names", {}))
nm = lambda ip: f"{names.get(ip, ip)} ({ip})" if names.get(ip) else ip
alerts = []


def alert(key, text):
    alerts.append((key, text))


def is_benign_sig(sig):
    return any(k.lower() in sig.lower() for k in benign.get("signatures", {}))


def late_note(b):
    """' (happened <time>, arrived N h late)' when the first event of a bucket reached ES more than LATE_S late."""
    try:
        t0, t1 = (b.get("t0") or {}).get("value"), (b.get("in") or {}).get("value")
        if t0 and t1 and (t1 - t0) / 1000 > window.LATE_S:
            return f" (happened {(b['t0'].get('value_as_string') or '')[:16].replace('T', ' ')} UTC, arrived {(t1 - t0) / 3.6e6:.1f} h late)"
    except (TypeError, ValueError, AttributeError) as e:
        print(f"(late note: {e})", file=sys.stderr)
    return ""


# 1. IDS
r = q("logs-suricata.alerts-so", {"size": 0, "query": {"bool": {"filter": [R], "should": [
    {"term": {"rule.severity": 1}},
    {"terms": {"rule.category": ["A Network Trojan was detected", "Malware Command and Control Activity Detected",
                                 "Exploit Kit Activity Detected", "Successful Administrator Privilege Gain",
                                 "Successful User Privilege Gain", "Targeted Malicious Activity was Detected",
                                 "Domain Observed Used for C2 Detected", "Crypto Currency Mining Activity Detected"]}}],
    "minimum_should_match": 1}},
    "aggs": {"s": {"terms": {"field": "rule.name", "size": 20},
                   "aggs": {"src": {"terms": {"field": "source.ip", "size": 2}}, "dst": {"terms": {"field": "destination.ip", "size": 2}},
                            "mt": {"terms": {"field": "rule.metadata.mitre_technique_id", "size": 2}},
                            "t0": {"min": {"field": "@timestamp"}}, "in": {"max": {"field": "event.ingested"}}}}}})
for b in buckets(r["aggregations"]["s"]):
    if is_benign_sig(b["key"]):
        continue
    src = [x["key"] for x in buckets(b["src"])]
    dst = [x["key"] for x in buckets(b["dst"])]
    mt = [x["key"] for x in buckets(b.get("mt") or {})]
    try:
        import mitre
        mt = " [ATT&CK " + ", ".join(f"{i} {mitre.tech(i).get('name', '')}" for i in mt) + "]" if mt else ""
    except Exception:
        mt = ""
    alert(f"ids|{b['key']}|{src[:1]}", f"**IDS:** {b['key']} x{b['doc_count']} - {', '.join(map(nm, src))} -> {', '.join(map(nm, dst))}{mt}{late_note(b)}")

# 2. New devices
known_ips = {ip for r_ in registry.values() for ip in r_.get("ips", [])}
known_macs = set(registry) | set(inv)
if registry:
    r = q("logs-zeek-so", {"size": 0, "query": {"bool": {"filter": [R, ds("zeek.dhcp")]}},
                           "aggs": {"m": {"terms": {"field": "host.mac", "size": 100},
                                          "aggs": {"ip": {"terms": {"field": "dhcp.assigned_ip", "size": 1}},
                                                   "h": {"terms": {"field": "host.hostname", "size": 1}}}}}})
    for b in buckets(r["aggregations"]["m"]):
        mac = b["key"].lower()
        if mac not in known_macs:
            ip = (buckets(b["ip"]) or [{"key": "?"}])[0]["key"]
            host = (buckets(b["h"]) or [{"key": ""}])[0]["key"]
            alert(f"newmac|{mac}", f"**New device joined:** MAC {mac} {('host ' + host) if host else ''} got {ip} - not in inventory or baseline")
    r = q("logs-zeek-so", {"size": 0, "query": {"bool": {"filter": [R, ds("zeek.conn"), INT]}},
                           "aggs": {"s": {"terms": {"field": "source.ip", "size": 400}}}})
    for b in buckets(r["aggregations"]["s"]):
        ip = b["key"]
        if ip not in known_ips and ip not in names and b["doc_count"] >= 10 and not ip.endswith((".1", ".255")):
            alert(f"newip|{ip}", f"**New device active:** {ip} made {b['doc_count']} connections - never seen before")

# 3. New Internet-facing port
served = store.served_ports()  # indexed; no longer parses every history record each run
hist = store.history_count()
r = q("logs-zeek-so", {"size": 0, "query": {"bool": {"filter": [R, ds("zeek.conn"), {"term": {"destination.ip": SITE.get("internal_cidr")}},
                                                                {"term": {"connection.local.originator": False}}],
                                                     "must_not": [{"terms": {"connection.state": FAILED}}]}},
                       "aggs": {"p": {"multi_terms": {"terms": [{"field": "destination.ip"}, {"field": "destination.port"}], "size": 100},
                                      "aggs": {"s": {"cardinality": {"field": "source.ip"}}, "b": {"sum": {"field": "network.bytes"}}}}}})
for b in buckets(r["aggregations"]["p"]):
    ip, port = b["key"][0], str(b["key"][1])
    if hist and port not in served.get(ip, set()):
        alert(f"inport|{ip}|{port}", f"**New Internet-facing port:** {nm(ip)} answered {b['doc_count']} conns on port {port} "
                                     f"from {b['s']['value']} Internet hosts ({int(b['b']['value'])} bytes)")

# 4. Threat intel (feeds cached by the nightly run; refresh only if very stale)
extras.refresh_feeds(max_age_h=36)
feeds = extras.load_feeds()
octi_hits = []  # matches on OpenCTI lists -> reported back as sightings (opencti.py; no-op unless configured)
for idx, field, dset in (("logs-zeek-so", "dns.query.name", "zeek.dns"), ("logs-zeek-so", "ssl.server_name", "zeek.ssl")):
    r = q(idx, {"size": 0, "query": {"bool": {"filter": [R, ds(dset), INT]}},
                "aggs": {"n": {"terms": {"field": field, "size": 10000}, "aggs": {"s": {"terms": {"field": "source.ip", "size": 2}}}}}})
    for b in buckets(r["aggregations"]["n"]):
        m, fl = extras.match_domain(b["key"], feeds)
        if m:
            src = [x["key"] for x in buckets(b["s"])]
            if any(f.startswith("opencti_") for f in fl):
                octi_hits.append({"value": m, "feeds": fl, "count": b["doc_count"], "sources": [nm(x) for x in src]})
            alert(f"tidom|{m}|{src[:1]}", f"**Threat-intel domain:** {', '.join(map(nm, src))} -> {b['key']} (listed in {', '.join(fl)})")
r = q("logs-zeek-so", {"size": 0, "query": {"bool": {"filter": [R, ds("zeek.conn"), INT, {"term": {"connection.local.responder": False}}]}},
                       "aggs": {"d": {"terms": {"field": "destination.ip", "size": 20000},
                                      "aggs": {"s": {"terms": {"field": "source.ip", "size": 2}}, "p": {"terms": {"field": "destination.port", "size": 2}}}}}})
for b in buckets(r["aggregations"]["d"]):
    allf = extras.match_ip(b["key"], feeds)
    if any(f.startswith("opencti_") for f in allf):
        octi_hits.append({"value": b["key"], "feeds": allf, "count": b["doc_count"], "sources": [nm(x["key"]) for x in buckets(b["s"])]})
    fl = [f for f in allf if f in extras.SERIOUS]
    if fl:
        src = [x["key"] for x in buckets(b["s"])]
        alert(f"tiip|{b['key']}|{src[:1]}", f"**Threat-intel IP:** {', '.join(map(nm, src))} -> {b['key']}:{[x['key'] for x in buckets(b['p'])]} "
                                            f"x{b['doc_count']} (listed in {', '.join(fl)})")


def file_intel():
    """4b. File hashes and file names on the threat-intel lists (OpenCTI hashes / names, hash feeds): files Zeek saw
    on the wire (md5/sha1) and processes / files Elastic Defend saw on endpoints (sha256, image and file names). The ES
    query filters on the listed values (a few thousand), never aggregates every hash or name seen."""
    hset = sorted(feeds.get("hashes") or {})
    names = set()
    for n, rows in extras.local_lists().items():  # file-name lists keep the original case; keyword fields are case-sensitive
        if extras.LOCAL_FEEDS.get(n) == "filenames":
            for v, _, _ in rows:
                v = (v or "").strip()
                if v:
                    names.update({v, v.lower()})
    if not hset and not names:
        return
    import intelmatch
    _, meta = intelmatch.feeds()

    def about(v):
        sc, m = meta.get(str(v).lower(), (None, ""))
        return f"; {m}" if m else ""

    def hit(kind, value, host, what, count):
        fl = extras.match_hash(value, feeds) if kind == "hash" else extras.match_filename(value, feeds)
        if not fl:
            return
        if any(f.startswith("opencti_") for f in fl):
            octi_hits.append({"value": value, "feeds": fl, "count": count, "sources": [host]})
        if set(fl) & extras.SERIOUS:
            label = "file hash" if kind == "hash" else "file name"
            alert(f"ti{kind}|{value.lower()}|{host}", f"**Threat-intel {label}:** {host} {what} (listed in {', '.join(fl)}{about(value)})")
    chunks = [hset[i:i + 5000] for i in range(0, len(hset), 5000)]
    for ch in chunks:
        for fld in ("hash.md5", "hash.sha1", "hash.sha256"):
            r = q("logs-zeek-so", {"size": 0, "query": {"bool": {"filter": [R, ds("zeek.file"), {"terms": {fld: ch}}]}},
                                   "aggs": {"h": {"terms": {"field": fld, "size": 200}, "aggs": {
                                       "d": {"terms": {"field": "destination.ip", "size": 2}}, "s": {"terms": {"field": "source.ip", "size": 1}},
                                       "n": {"terms": {"field": "file.name", "size": 1}}, "m": {"terms": {"field": "file.mime_type", "size": 1}}}}}})
            for b in buckets(r["aggregations"]["h"]):
                ends = [x["key"] for x in buckets(b["s"]) + buckets(b["d"])]
                inside = [x for x in ends if SITE.is_internal(x)] or ends
                other = [x for x in ends if x not in inside]
                fname = (buckets(b["n"]) or [{}])[0].get("key") or (buckets(b["m"]) or [{}])[0].get("key") or "a file"
                hit("hash", b["key"], ", ".join(map(nm, inside)) or "?",
                    f"transferred {fname}{' with ' + ', '.join(other) if other else ''} ({fld.split('.')[1]} {b['key']})", b["doc_count"])
        r = q("logs-endpoint.events.process-*", {"size": 0, "query": {"bool": {"filter": [R, {"terms": {"process.hash.sha256": ch}}]}},
                                                 "aggs": {"h": {"terms": {"field": "process.hash.sha256", "size": 200}, "aggs": {
                                                     "host": {"terms": {"field": "host.name", "size": 3}}, "exe": {"terms": {"field": "process.executable", "size": 1}}}}}})
        for b in buckets(r["aggregations"]["h"]):
            exe = (buckets(b["exe"]) or [{}])[0].get("key", "a process")
            for hb in buckets(b["host"]):
                hit("hash", b["key"], hb["key"], f"ran {exe} (sha256 {b['key']})", hb["doc_count"])
    if names:
        nl = sorted(names)
        for idx, fld, verb in (("logs-endpoint.events.process-*", "process.name", "ran"), ("logs-endpoint.events.file-*", "file.name", "wrote")):
            r = q(idx, {"size": 0, "query": {"bool": {"filter": [R, {"terms": {fld: nl}}]}},
                        "aggs": {"n": {"terms": {"field": fld, "size": 100}, "aggs": {"host": {"terms": {"field": "host.name", "size": 3}},
                                                                                     "p": {"terms": {"field": "file.path" if fld == "file.name" else "process.executable", "size": 1}}}}}})
            for b in buckets(r["aggregations"]["n"]):
                path = (buckets(b["p"]) or [{}])[0].get("key", b["key"])
                for hb in buckets(b["host"]):
                    hit("file", b["key"], hb["key"], f"{verb} {path}", hb["doc_count"])
        r = q("logs-zeek-so", {"size": 0, "query": {"bool": {"filter": [R, ds("zeek.file"), {"terms": {"file.name": nl}}]}},
                               "aggs": {"n": {"terms": {"field": "file.name", "size": 100}, "aggs": {"d": {"terms": {"field": "destination.ip", "size": 2}},
                                                                                                  "s": {"terms": {"field": "source.ip", "size": 2}}}}}})
        for b in buckets(r["aggregations"]["n"]):
            ends = [x["key"] for x in buckets(b["s"]) + buckets(b["d"])]
            inside = [x for x in ends if SITE.is_internal(x)] or ends
            hit("file", b["key"], ", ".join(map(nm, inside)) or "?", f"transferred {b['key']} over the network", b["doc_count"])


try:
    file_intel()
except Exception as e:  # noqa: BLE001 - one missing index must not stop the watcher
    FAILED_CHECKS.append("file_intel")
    print(f"file threat intel: {type(e).__name__}: {e}", file=sys.stderr)

if octi_hits:
    import opencti
    print("opencti sightings:", opencti.report_sightings(octi_hits, WINDOW), file=sys.stderr)

# 5. DNS tunnel burst (last hour of arrivals, at least the whole window)
H = window.since(60)
r = q("logs-zeek-so", {"size": 0, "query": {"bool": {"filter": [H, ds("zeek.dns"), {"term": {"destination.port": 53}}],
                                                     "must_not": [{"wildcard": {"dns.highest_registered_domain": "*arpa"}},
                                                                  {"wildcard": {"dns.highest_registered_domain": "*local*"}}]}},
                       "aggs": {"d": {"terms": {"field": "dns.highest_registered_domain", "size": 10, "order": {"u": "desc"}},
                                      "aggs": {"u": {"cardinality": {"field": "dns.subdomain"}}, "al": {"avg": {"field": "dns.subdomain_length"}},
                                               "s": {"terms": {"field": "source.ip", "size": 2}}}}}})
for b in buckets(r["aggregations"]["d"]):
    if b["u"]["value"] < 150 or b["key"] in set(benign.get("dns_domains", [])):
        continue
    s = q("logs-zeek-so", {"size": 100, "_source": ["dns.subdomain"], "query": {"bool": {"filter": [
        H, ds("zeek.dns"), {"term": {"dns.highest_registered_domain": b["key"]}}]}}})
    subs = [(x["_source"].get("dns") or {}).get("subdomain") or "" for x in s["hits"]["hits"]]
    subs = [x for x in subs if x]
    ent = sum(extras.entropy(x.replace(".", "")) for x in subs) / max(len(subs), 1)
    uniq = len(set(subs)) / max(len(subs), 1)
    if ent >= 3.5 and uniq >= 0.8 and (b["al"]["value"] or 0) >= 20:
        src = [x["key"] for x in buckets(b["s"])]
        alert(f"tunnel|{b['key']}", f"**Possible DNS tunnel:** {b['key']} - {b['u']['value']} distinct subdomains in 1h, "
                                    f"avg {b['al']['value']:.0f} chars, entropy {ent:.1f}, from {', '.join(map(nm, src))}")

# 6. Host-based anomalies (Elastic Agent / Fleet / Defend; hosts.py). Investigate-level always; of the Review-level
#    ones: first-seen logins, watched syslog patterns, agent health, and host NETWORK anomalies (process-attributed new
#    destinations, new listeners, Internet inbound, DGA-like lookups). New executables stay nightly-only (dnf noise).
try:
    import hosts, hosts_ack  # noqa: E402
    _hd = hosts.gather(WINDOW, nightly=False)
    _acks = hosts_ack.load()  # findings checked off as investigated are muted
    for k, pri, t in hosts.findings(_hd, hosts.load_base(), nightly=False):
        if k in _acks:
            continue
        if pri == "Investigate" or k.split("|")[0] in ("login-new", "syslog", "agent-off", "net-new", "hnet-newlisten", "hnet-dns-long", "hnet-in", "hnet-interp"):
            try:
                import mitre
                t += mitre.tags_for("host", f"{k}|{t}")
            except Exception:
                pass
            alert(f"host|{k}", f"**Host {'ALERT' if pri == 'Investigate' else 'notice'}:** {t}")
except Exception as e:  # never let host checks break the network watcher
    FAILED_CHECKS.append("hosts")
    print(f"(host checks failed: {type(e).__name__}: {e})", file=sys.stderr)

# 7. Admin access (SSH / RDP / PsExec / WMI / WinRM / VNC ...): failed logins and refused admin connections
try:
    sys.path.insert(0, os.path.join(NM, "dashboard", "app"))
    import lateral  # noqa: E402  same scoring as the dashboard
    _aa = extras.admin_access(minutes=WINDOW)
    _pol = load(os.path.join(NM, "policy.json"), {})
    _raw = {"admin_access": _aa, "devices": {ip: {"name": n} for ip, n in names.items()}, "inventory_ips": names}
    for a in lateral.admin_sessions(_raw, _pol):
        if a["level"] not in ("high", "medium") or not (a["auth_fail"] or a["conn_failed"]):
            continue
        users = ", ".join(f"{u} ({c['fail']} failed{', ' + str(c['ok']) + ' ok' if c['ok'] else ''})" for u, c in a["users"].items() if c["fail"]) or ""
        try:
            import mitre
            tags = mitre.tags_for("admin", f"{a['protocol']} | {a['why']}")
        except Exception:
            tags = ""
        lead = "ALERT" if a["level"] == "high" else "notice"
        alert(f"admin|{a['src']}|{a['dst']}|{a['protocol']}|{a['level']}",
              f"**Admin {lead}:** {a['protocol']} {nm(a['src'])} -> {nm(a['dst'])}: {a['why']}"
              f"{' - accounts ' + users if users else ''}{tags}")
    for k, err in (_aa.get("errors") or {}).items():
        if k != "windows_logons":
            print(f"(admin check {k} failed: {err})", file=sys.stderr)
except Exception as e:
    FAILED_CHECKS.append("admin")
    print(f"(admin checks failed: {type(e).__name__}: {e})", file=sys.stderr)

# --- dedupe + output ---
fresh = store.mute_filter(alerts, SUPPRESS_H)  # atomic: prune expired, drop muted, mute the new ones
if fresh:  # queue for the dashboard's in-app feed + browser/phone push notifications
    try:
        store.alerts_add([(k, t.replace("**", ""), "investigate" if ("ALERT" in t or t.startswith("**IDS") or "threat" in t.lower()) else "urgent")
                          for k, t in fresh])
    except Exception as e:
        print(f"(alert feed write failed: {e})", file=sys.stderr)
    try:  # alerts a saved mute rule clears are in the feed as "cleared" only: no Discord / chat message for them
        _mm = store.mute_list()
        fresh = [(k, t) for k, t in fresh if not any(store.mute_match(m, t.replace("**", ""), store.alert_targets(k, t.replace("**", ""))) for m in _mm)]
    except Exception as e:
        print(f"(mute rules unavailable: {e})", file=sys.stderr)
# no chat message: detections are events for the correlation / AI review; an alarm is raised only when the review calls one suspicious (medium/high)

# --- arrival bookmark + ingest lag ---
try:
    window.save_lag(window.lag_stats(q))
except Exception as e:  # noqa: BLE001 - lag stats are informational
    print(f"(ingest lag stats failed: {e})", file=sys.stderr)
if FAILED_CHECKS:
    print(f"arrival window kept for the next run (failed: {', '.join(FAILED_CHECKS)}): {_AW['from']} .. {_AW['to']}", file=sys.stderr)
else:
    window.commit()
