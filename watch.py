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
"""
import json, os, sys, time

sys.argv = [sys.argv[0], "1"]
NM = os.environ.get("NETMON_DIR") or os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from collect import q, ds, buckets, inventory  # noqa: E402
import extras  # noqa: E402

WINDOW = int(os.environ.get("NETMON_WATCH_WINDOW", 20))       # minutes; env override for testing
SUPPRESS_H = 12
import site_cfg as SITE  # noqa: E402  network-specific values (site.json, git-ignored)
import store  # noqa: E402  SQLite state: registry, served ports, host baseline, mute state. Test with NETMON_DB=<scratch db>.
R = {"range": {"@timestamp": {"gte": f"now-{WINDOW}m"}}}
INT = {"term": {"source.ip": SITE.get("internal_cidr")}}
FAILED = ["S0", "REJ", "RSTOS0", "SH", "OTH"]


def load(p, default):
    try:
        return json.load(open(p))
    except Exception:
        return default


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
                            "mt": {"terms": {"field": "rule.metadata.mitre_technique_id", "size": 2}}}}}})
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
    alert(f"ids|{b['key']}|{src[:1]}", f"**IDS:** {b['key']} x{b['doc_count']} - {', '.join(map(nm, src))} -> {', '.join(map(nm, dst))}{mt}")

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
for idx, field, dset in (("logs-zeek-so", "dns.query.name", "zeek.dns"), ("logs-zeek-so", "ssl.server_name", "zeek.ssl")):
    r = q(idx, {"size": 0, "query": {"bool": {"filter": [R, ds(dset), INT]}},
                "aggs": {"n": {"terms": {"field": field, "size": 10000}, "aggs": {"s": {"terms": {"field": "source.ip", "size": 2}}}}}})
    for b in buckets(r["aggregations"]["n"]):
        m, fl = extras.match_domain(b["key"], feeds)
        if m:
            src = [x["key"] for x in buckets(b["s"])]
            alert(f"tidom|{m}|{src[:1]}", f"**Threat-intel domain:** {', '.join(map(nm, src))} -> {b['key']} (listed in {', '.join(fl)})")
r = q("logs-zeek-so", {"size": 0, "query": {"bool": {"filter": [R, ds("zeek.conn"), INT, {"term": {"connection.local.responder": False}}]}},
                       "aggs": {"d": {"terms": {"field": "destination.ip", "size": 20000},
                                      "aggs": {"s": {"terms": {"field": "source.ip", "size": 2}}, "p": {"terms": {"field": "destination.port", "size": 2}}}}}})
for b in buckets(r["aggregations"]["d"]):
    fl = [f for f in extras.match_ip(b["key"], feeds) if f in extras.SERIOUS]
    if fl:
        src = [x["key"] for x in buckets(b["s"])]
        alert(f"tiip|{b['key']}|{src[:1]}", f"**Threat-intel IP:** {', '.join(map(nm, src))} -> {b['key']}:{[x['key'] for x in buckets(b['p'])]} "
                                            f"x{b['doc_count']} (listed in {', '.join(fl)})")

# 5. DNS tunnel burst (last hour)
H = {"range": {"@timestamp": {"gte": "now-60m"}}}
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
