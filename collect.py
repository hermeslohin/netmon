#!/usr/bin/python3
"""Collect 24h network behavior from Security Onion ES -> netmon/data/<date>.json.

Per-device traffic/behavior profile + alerts/notices/detections. Read-only queries.
Usage: collect.py [hours=24]                                    last N hours -> data/<stamp>.json (nightly)
       collect.py --start ISO --end ISO --out FILE              a dashboard time range: same collectors over
                                                                [start, end], written to FILE; changes no baseline
"""
import csv, glob, json, os, ssl, sys, urllib.request, datetime as dt

NM = os.environ.get("NETMON_DIR") or os.path.dirname(os.path.abspath(__file__))


def _arg(name):
    return sys.argv[sys.argv.index(name) + 1] if name in sys.argv else None


def _iso(s):
    t = dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
    return (t if t.tzinfo else t.replace(tzinfo=dt.timezone.utc)).astimezone(dt.timezone.utc)


RANGE_START, RANGE_END, OUT = _arg("--start"), _arg("--end"), _arg("--out")
LOOKBACK = None  # set by `collect.py auto` (research job lookback window)
if RANGE_START and RANGE_END:  # a dashboard time range: every collector queries [start, end] (window.py)
    _s, _e = _iso(RANGE_START), _iso(RANGE_END)
    if _e <= _s:
        raise SystemExit("--end must be after --start")
    RANGE_END = _e.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    os.environ["NETMON_WINDOW_END"] = RANGE_END
    HOURS = round((_e - _s).total_seconds() / 3600, 3)
else:
    RANGE_START = RANGE_END = None
    if sys.argv[1:2] == ["auto"]:  # research job: the lookback window set on the dashboard's AI review page (lookback.py)
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import lookback  # noqa: E402
        HOURS, _why = lookback.for_run()
        LOOKBACK = {"hours": HOURS, "source": _why}
        print(f"lookback: {HOURS} h ({_why})", file=sys.stderr)
    else:
        HOURS = int(sys.argv[1]) if len(sys.argv) > 1 and not sys.argv[1].startswith("-") else 24
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import window  # noqa: E402
import site_cfg as SITE  # noqa: E402  network-specific values live in site.json (git-ignored)
import integrations as INTEG  # noqa: E402  ES/UniFi settings from the dashboard (More > Configuration), fallbacks below
ES = INTEG.es_url()
SELF_IP = SITE.get("self_ip")
NET = SITE.get("internal_cidr")


def env_key():
    k = INTEG.es_key()  # dashboard setting, else ES_API_KEY in the host secrets file
    if not k:
        raise SystemExit("API key missing")
    return k


KEY = env_key()
CTX = ssl._create_unverified_context()


def q(index, body):
    req = urllib.request.Request(f"{ES}/{INTEG.map_index(index)}/_search", data=json.dumps(body).encode(),
                                 headers={"Authorization": f"ApiKey {KEY}", "Content-Type": "application/json"})
    return json.load(urllib.request.urlopen(req, context=CTX, timeout=180))


RANGE = window.since_h(HOURS)
INTERNAL = {"term": {"source.ip": NET}}


def ds(name):
    return {"term": {"event.dataset": name}}


def buckets(agg):
    return agg.get("buckets", [])


def by_hour(bs, val):
    """Hourly histogram -> {"HH": sum}: hours of the day (UTC), summed over the days of the window."""
    out = {}
    for x in bs:
        h = x["key_as_string"][11:13]
        out[h] = out.get(h, 0) + val(x)
    return out


def inventory():
    """Optional device inventory: newest UniFi DHCP export CSV (Name, IP Address, MAC Address, Hostname, ...).
    Location: $NETMON_INVENTORY glob, else ~/dhcp-export-all-*.csv. Without one, devices are named from DHCP/DNS only."""
    files = sorted(glob.glob(os.environ.get("NETMON_INVENTORY") or os.path.expanduser("~/dhcp-export-all-*.csv")))
    inv = {}
    if not files:
        return inv, None
    for r in csv.DictReader(open(files[-1])):
        inv[r["MAC Address"].lower()] = {"name": r["Name"], "ip": r["IP Address"], "hostname": r["Hostname"],
                                         "dns": r["Local DNS Record"], "type": r["Lease Type"]}
    return inv, files[-1]


def dhcp_map():
    """ip -> mac from Zeek DHCP over a wider window (dynamic leases)."""
    r = q("logs-zeek-so", {"size": 0, "query": {"bool": {"filter": [
        window.since_h(max(HOURS, 72)), ds("zeek.dhcp")]}},
        "aggs": {"ip": {"terms": {"field": "dhcp.assigned_ip", "size": 500},
                        "aggs": {"mac": {"terms": {"field": "host.mac", "size": 3}},
                                 "host": {"terms": {"field": "host.hostname", "size": 1}}}}}})
    m = {}
    for b in buckets(r["aggregations"]["ip"]):
        macs = [x["key"].lower() for x in buckets(b["mac"])]
        m[b["key"]] = {"macs": macs, "hostname": (buckets(b["host"]) or [{"key": ""}])[0]["key"]}
    return m


def device_traffic():
    """Per internal IP: originated + responded conns, bytes, peers, ports, hourly shape."""
    sub = {
        "conns": {"value_count": {"field": "@timestamp"}},
        "out_b": {"sum": {"field": "client.ip_bytes"}},
        "in_b": {"sum": {"field": "server.ip_bytes"}},
        "missed": {"sum": {"field": "connection.bytes.missed"}},
        "ext": {"filter": {"term": {"connection.local.responder": False}},
                "aggs": {"out_b": {"sum": {"field": "client.ip_bytes"}}, "in_b": {"sum": {"field": "server.ip_bytes"}},
                         "peers": {"cardinality": {"field": "destination.ip"}},
                         "countries": {"terms": {"field": "destination.geo.country_iso_code", "size": 10,
                                                 "order": {"b": "desc"}},
                                       "aggs": {"b": {"sum": {"field": "network.bytes"}}}},
                         "asn": {"terms": {"field": "destination.as.organization.name", "size": 8, "order": {"b": "desc"}},
                                 "aggs": {"b": {"sum": {"field": "network.bytes"}}}}}},
        "peers": {"cardinality": {"field": "destination.ip"}},
        "ports": {"terms": {"field": "destination.port", "size": 10, "order": {"b": "desc"}},
                  "aggs": {"b": {"sum": {"field": "network.bytes"}}}},
        "dports_ext": {"filter": {"term": {"connection.local.responder": False}},
                       "aggs": {"p": {"terms": {"field": "destination.port", "size": 15}}}},
        "proto": {"terms": {"field": "network.protocol", "size": 10, "order": {"b": "desc"}},
                  "aggs": {"b": {"sum": {"field": "network.bytes"}}}},
        # port/service habits as a client (what the device talks to), by connection count
        "svc_out": {"terms": {"field": "network.protocol", "size": 15, "missing": "unidentified"},
                    "aggs": {"c": {"sum": {"field": "client.ip_bytes"}}, "s": {"sum": {"field": "server.ip_bytes"}}}},
        "dport_out": {"terms": {"field": "destination.port", "size": 20},
                      "aggs": {"t": {"terms": {"field": "network.transport", "size": 1}},
                               "svc": {"terms": {"field": "network.protocol", "size": 1}},
                               "ext": {"filter": {"term": {"connection.local.responder": False}}},
                               "c": {"sum": {"field": "client.ip_bytes"}}, "s": {"sum": {"field": "server.ip_bytes"}}}},
        "top_dst": {"terms": {"field": "destination.ip", "size": 5, "order": {"b": "desc"}},
                    "aggs": {"b": {"sum": {"field": "network.bytes"}}}},
        "rejected": {"filter": {"terms": {"connection.state": ["REJ", "S0", "RSTO", "RSTOS0"]}}},
        "hourly": {"date_histogram": {"field": "@timestamp", "fixed_interval": "1h"},
                   "aggs": {"c": {"sum": {"field": "client.ip_bytes"}}, "s": {"sum": {"field": "server.ip_bytes"}}}},
        "oui": {"terms": {"field": "client.oui", "size": 1}},
    }
    r = q("logs-zeek-so", {"size": 0, "query": {"bool": {"filter": [RANGE, ds("zeek.conn"), INTERNAL]}},
                           "aggs": {"dev": {"terms": {"field": "source.ip", "size": 300}, "aggs": sub}}})
    # responder side (traffic TO the device from anyone)
    r2 = q("logs-zeek-so", {"size": 0, "query": {"bool": {"filter": [RANGE, ds("zeek.conn"),
                                                                     {"term": {"destination.ip": NET}}]}},
                            "aggs": {"dev": {"terms": {"field": "destination.ip", "size": 300},
                                             "aggs": {"conns": {"value_count": {"field": "@timestamp"}},
                                                      "in_b": {"sum": {"field": "client.ip_bytes"}},
                                                      "out_b": {"sum": {"field": "server.ip_bytes"}},
                                                      "src": {"cardinality": {"field": "source.ip"}},
                                                      # ports this device SERVES (answered connections only)
                                                      "served": {"filter": {"bool": {"must_not": [
                                                          {"terms": {"connection.state": ["S0", "REJ", "RSTOS0", "SH", "OTH"]}},
                                                          {"terms": {"destination.ip": ["255.255.255.255"]}}]}},
                                                          "aggs": {"p": {"terms": {"field": "destination.port", "size": 15},
                                                                         "aggs": {"t": {"terms": {"field": "network.transport", "size": 1}},
                                                                                  "svc": {"terms": {"field": "network.protocol", "size": 1}},
                                                                                  "src": {"cardinality": {"field": "source.ip"}},
                                                                                  "ext": {"filter": {"term": {"connection.local.originator": False}}}}}}},
                                                      "ext_src": {"filter": {"term": {"connection.local.originator": False}},
                                                                  "aggs": {"n": {"cardinality": {"field": "source.ip"}},
                                                                           "ports": {"terms": {"field": "destination.port", "size": 5}}}}}}}})
    resp = {b["key"]: b for b in buckets(r2["aggregations"]["dev"])}
    devs = {}
    for b in buckets(r["aggregations"]["dev"]):
        ip = b["key"]
        e = b["ext"]
        d = {
            "orig_conns": b["conns"]["value"], "orig_out_bytes": b["out_b"]["value"], "orig_in_bytes": b["in_b"]["value"],
            "missed_bytes": b["missed"]["value"], "peers": b["peers"]["value"], "rejected_conns": b["rejected"]["doc_count"],
            "ext_conns": e["doc_count"], "ext_out_bytes": e["out_b"]["value"], "ext_in_bytes": e["in_b"]["value"],
            "ext_peers": e["peers"]["value"],
            "countries": {x["key"]: x["b"]["value"] for x in buckets(e["countries"])},
            "asns": {x["key"]: x["b"]["value"] for x in buckets(e["asn"])},
            "ports": {str(x["key"]): x["b"]["value"] for x in buckets(b["ports"])},
            "ext_dports": {str(x["key"]): x["doc_count"] for x in buckets(b["dports_ext"]["p"])},
            "protocols": {x["key"]: x["b"]["value"] for x in buckets(b["proto"])},
            "services_out": {x["key"]: {"conns": x["doc_count"], "bytes": x["c"]["value"] + x["s"]["value"]}
                             for x in buckets(b["svc_out"])},
            "dports_out": {f'{x["key"]}/{(buckets(x["t"]) or [{"key": "?"}])[0]["key"]}': {
                "conns": x["doc_count"], "ext_conns": x["ext"]["doc_count"],
                "service": (buckets(x["svc"]) or [{"key": ""}])[0]["key"],
                "bytes": x["c"]["value"] + x["s"]["value"]} for x in buckets(b["dport_out"])},
            "top_dst": {x["key"]: x["b"]["value"] for x in buckets(b["top_dst"])},
            "hourly_bytes": by_hour(buckets(b["hourly"]), lambda x: x["c"]["value"] + x["s"]["value"]),
            "hourly_conns": by_hour(buckets(b["hourly"]), lambda x: x["doc_count"]),
            "oui": (buckets(b["oui"]) or [{"key": ""}])[0]["key"],
        }
        devs[ip] = d
    for ip, b in resp.items():
        d = devs.setdefault(ip, {"orig_conns": 0, "orig_out_bytes": 0, "orig_in_bytes": 0})
        d.update({"resp_conns": b["conns"]["value"], "resp_in_bytes": b["in_b"]["value"],
                  "resp_out_bytes": b["out_b"]["value"], "resp_sources": b["src"]["value"],
                  "inbound_ext_sources": b["ext_src"]["n"]["value"],
                  "inbound_ext_ports": [x["key"] for x in buckets(b["ext_src"]["ports"])],
                  "served_ports": {f'{x["key"]}/{(buckets(x["t"]) or [{"key": "?"}])[0]["key"]}': {
                      "conns": x["doc_count"], "sources": x["src"]["value"], "ext_conns": x["ext"]["doc_count"],
                      "service": (buckets(x["svc"]) or [{"key": ""}])[0]["key"]} for x in buckets(b["served"]["p"])}})
    for d in devs.values():
        d["total_sent"] = d.get("orig_out_bytes", 0) + d.get("resp_out_bytes", 0)
        d["total_recv"] = d.get("orig_in_bytes", 0) + d.get("resp_in_bytes", 0)
        d["total_bytes"] = d["total_sent"] + d["total_recv"]
    return devs


DOH_SNI = ["dns.google", "dns.google.com", "cloudflare-dns.com", "mozilla.cloudflare-dns.com", "one.one.one.one",
           "chrome.cloudflare-dns.com", "dns.quad9.net", "dns11.quad9.net", "doh.opendns.com", "dns.nextdns.io",
           "doh.cleanbrowsing.org", "dns.adguard-dns.com", "doh.dns.apple.com", "dns.mullvad.net"]
UNICAST_DNS = {"terms": {"destination.port": [53]}}


def dns_profile():
    """Per-device unicast DNS habits (port 53) + mDNS volume + DoH use."""
    r = q("logs-zeek-so", {"size": 0, "query": {"bool": {"filter": [RANGE, ds("zeek.dns"), INTERNAL, UNICAST_DNS]}},
                           "aggs": {"dev": {"terms": {"field": "source.ip", "size": 300}, "aggs": {
                               "uniq": {"cardinality": {"field": "dns.query.name"}},
                               "udom": {"cardinality": {"field": "dns.highest_registered_domain"}},
                               "nx": {"filter": {"term": {"dns.response.code_name": "NXDOMAIN"}},
                                      "aggs": {"d": {"terms": {"field": "dns.highest_registered_domain", "size": 5}}}},
                               "sf": {"filter": {"term": {"dns.response.code_name": "SERVFAIL"}}},
                               "qt": {"terms": {"field": "dns.query.type_name", "size": 12}},
                               "tld": {"terms": {"field": "dns.top_level_domain", "size": 15}},
                               "top": {"terms": {"field": "dns.highest_registered_domain", "size": 30}},
                               "res": {"terms": {"field": "destination.ip", "size": 6}},
                               "len": {"stats": {"field": "dns.query.length"}},
                               "long": {"filter": {"range": {"dns.query.length": {"gte": 60}}}},
                               "subheavy": {"terms": {"field": "dns.highest_registered_domain", "size": 5, "order": {"u": "desc"}},
                                            "aggs": {"u": {"cardinality": {"field": "dns.subdomain"}}}},
                               "hourly": {"date_histogram": {"field": "@timestamp", "fixed_interval": "1h"}}}}}})
    out = {}
    for b in buckets(r["aggregations"]["dev"]):
        res = {x["key"]: x["doc_count"] for x in buckets(b["res"])}
        out[b["key"]] = {
            "queries": b["doc_count"], "unique_names": b["uniq"]["value"], "unique_domains": b["udom"]["value"],
            "nxdomain": b["nx"]["doc_count"], "nx_domains": {x["key"]: x["doc_count"] for x in buckets(b["nx"]["d"])},
            "servfail": b["sf"]["doc_count"],
            "qtypes": {x["key"]: x["doc_count"] for x in buckets(b["qt"])},
            "tlds": {x["key"]: x["doc_count"] for x in buckets(b["tld"])},
            "top_domains": {x["key"]: x["doc_count"] for x in buckets(b["top"])},
            "resolvers": res, "external_resolvers": {k: v for k, v in res.items() if not (SITE.is_internal(k) or k.startswith(("10.", "192.168.", "172.16.")))},
            "avg_len": round(b["len"]["avg"] or 0, 1), "max_len": b["len"]["max"] or 0, "long_names": b["long"]["doc_count"],
            "subdomain_heavy": {x["key"]: x["u"]["value"] for x in buckets(b["subheavy"])},
            "hourly": by_hour(buckets(b["hourly"]), lambda x: x["doc_count"]),
        }
    m = q("logs-zeek-so", {"size": 0, "query": {"bool": {"filter": [RANGE, ds("zeek.dns"), INTERNAL,
                                                                      {"term": {"destination.port": 5353}}]}},
                           "aggs": {"dev": {"terms": {"field": "source.ip", "size": 300}}}})
    for b in buckets(m["aggregations"]["dev"]):
        out.setdefault(b["key"], {"queries": 0})["mdns"] = b["doc_count"]
    d = q("logs-zeek-so", {"size": 0, "query": {"bool": {"filter": [RANGE, ds("zeek.ssl"), INTERNAL,
                                                                      {"terms": {"ssl.server_name": DOH_SNI}}]}},
                           "aggs": {"dev": {"terms": {"field": "source.ip", "size": 100},
                                            "aggs": {"s": {"terms": {"field": "ssl.server_name", "size": 5}}}}}})
    for b in buckets(d["aggregations"]["dev"]):
        out.setdefault(b["key"], {"queries": 0})["doh"] = {x["key"]: x["doc_count"] for x in buckets(b["s"])}
    return out


def _entropy(s):
    import math
    from collections import Counter
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values()) if n else 0.0


TUNNEL_SKIP_SUFFIX = ("in-addr.arpa", "ip6.arpa", ".local", "local")


def dns_tunnel_candidates(top=60, sample=200):
    """Registered domains ranked by distinct subdomains, scored for DNS-tunnel traits on a random sample."""
    r = q("logs-zeek-so", {"size": 0, "query": {"bool": {"filter": [RANGE, ds("zeek.dns"), UNICAST_DNS]}},
                           "aggs": {"d": {"terms": {"field": "dns.highest_registered_domain", "size": top, "order": {"u": "desc"}},
                                          "aggs": {"u": {"cardinality": {"field": "dns.subdomain"}},
                                                   "al": {"avg": {"field": "dns.subdomain_length"}},
                                                   "ml": {"max": {"field": "dns.subdomain_length"}},
                                                   "qt": {"terms": {"field": "dns.query.type_name", "size": 4}},
                                                   "src": {"terms": {"field": "source.ip", "size": 4}},
                                                   "nx": {"filter": {"term": {"dns.response.code_name": "NXDOMAIN"}}}}}}})
    out = []
    for b in buckets(r["aggregations"]["d"]):
        dom = b["key"]
        if dom.endswith(TUNNEL_SKIP_SUFFIX) or b["u"]["value"] < 15:
            continue
        s = q("logs-zeek-so", {"size": sample, "_source": ["dns.subdomain"],
                               "query": {"function_score": {"query": {"bool": {"filter": [
                                   RANGE, ds("zeek.dns"), UNICAST_DNS, {"term": {"dns.highest_registered_domain": dom}}]}},
                                   "random_score": {"seed": 42, "field": "_seq_no"}}}})
        subs = [((h["_source"].get("dns") or {}).get("subdomain") or "") for h in s["hits"]["hits"]]
        subs = [x for x in subs if x]
        labels = [max(x.split("."), key=len) for x in subs]
        n = len(subs) or 1
        ent = sum(_entropy(x.replace(".", "")) for x in subs) / n
        uniq_ratio = len(set(subs)) / n
        digit_ratio = sum(sum(ch.isdigit() for ch in x) / max(len(x), 1) for x in subs) / n
        longest_label = max((len(x) for x in labels), default=0)
        qt = {x["key"]: x["doc_count"] for x in buckets(b["qt"])}
        odd_qt = sum(v for k, v in qt.items() if k in ("TXT", "NULL", "CNAME", "MX", "ANY", "*")) / max(b["doc_count"], 1)
        # score: each trait typical of iodine/dnscat2/dns2tcp-style tunnels adds weight
        score = 0
        score += 2 if b["u"]["value"] >= 500 else 1 if b["u"]["value"] >= 150 else 0
        score += 2 if (b["al"]["value"] or 0) >= 40 else 1 if (b["al"]["value"] or 0) >= 25 else 0
        score += 2 if ent >= 4.0 else 1 if ent >= 3.5 else 0
        score += 1 if uniq_ratio >= 0.8 and len(subs) >= 30 else 0
        score += 1 if longest_label >= 45 else 0
        score += 1 if odd_qt >= 0.3 else 0
        score += 1 if len(buckets(b["src"])) <= 2 and b["u"]["value"] >= 150 else 0
        out.append({"domain": dom, "queries": b["doc_count"], "unique_subdomains": b["u"]["value"],
                    "avg_sub_len": round(b["al"]["value"] or 0, 1), "max_sub_len": b["ml"]["value"] or 0,
                    "entropy": round(ent, 2), "sample_unique_ratio": round(uniq_ratio, 2), "digit_ratio": round(digit_ratio, 2),
                    "longest_label": longest_label, "qtypes": qt, "odd_qtype_share": round(odd_qt, 2),
                    "sources": {x["key"]: x["doc_count"] for x in buckets(b["src"])}, "nxdomain": b["nx"]["doc_count"],
                    "examples": sorted(set(subs), key=len, reverse=True)[:3], "score": score})
    return sorted(out, key=lambda x: (-x["score"], -x["unique_subdomains"]))


def alerts():
    r = q("logs-suricata.alerts-so", {"size": 0, "query": {"bool": {"filter": [RANGE]}},
                                      "aggs": {"total": {"value_count": {"field": "@timestamp"}},
                                               "sig": {"terms": {"field": "rule.name", "size": 100},
                                                       "aggs": {"sev": {"terms": {"field": "rule.severity", "size": 1}},
                                                                "cat": {"terms": {"field": "rule.category", "size": 1}},
                                                                "src": {"terms": {"field": "source.ip", "size": 5}},
                                                                "dst": {"terms": {"field": "destination.ip", "size": 5}},
                                                                "dport": {"terms": {"field": "destination.port", "size": 3}},
                                                                "first": {"min": {"field": "@timestamp"}},
                                                                "last": {"max": {"field": "@timestamp"}}}}}})
    a = r["aggregations"]
    sigs = []
    for b in buckets(a["sig"]):
        sigs.append({"name": b["key"], "count": b["doc_count"],
                     "severity": (buckets(b["sev"]) or [{"key": 3}])[0]["key"],
                     "category": (buckets(b["cat"]) or [{"key": ""}])[0]["key"],
                     "src": {x["key"]: x["doc_count"] for x in buckets(b["src"])},
                     "dst": {x["key"]: x["doc_count"] for x in buckets(b["dst"])},
                     "dport": [x["key"] for x in buckets(b["dport"])],
                     "first": b["first"].get("value_as_string"), "last": b["last"].get("value_as_string")})
    return {"total": a["total"]["value"], "signatures": sigs}


def detections():
    r = q("logs-detections.alerts-so", {"size": 50, "sort": [{"@timestamp": "desc"}], "query": {"bool": {"filter": [RANGE]}}})
    out = []
    for h in r["hits"]["hits"]:
        s = h["_source"]
        out.append({"time": s.get("@timestamp"), "rule": (s.get("rule") or {}).get("name"),
                    "source_ip": (s.get("source") or {}).get("ip"), "user": (s.get("user") or {}).get("name"),
                    "host": (s.get("host") or {}).get("name"), "message": str(s.get("message", ""))[:300]})
    return out


def notices():
    r = q("logs-zeek-so", {"size": 0, "query": {"bool": {"filter": [RANGE, ds("zeek.notice")]}},
                           "aggs": {"n": {"terms": {"field": "notice.note", "size": 30},
                                          "aggs": {"src": {"terms": {"field": "source.ip", "size": 5}},
                                                   "msg": {"terms": {"field": "notice.sub_message", "size": 3}}}}}})
    w = q("logs-zeek-so", {"size": 0, "query": {"bool": {"filter": [RANGE, ds("zeek.weird")]}},
                           "aggs": {"n": {"terms": {"field": "weird.name", "size": 20},
                                          "aggs": {"src": {"terms": {"field": "source.ip", "size": 3}}}}}})
    return ([{"note": b["key"], "count": b["doc_count"], "src": {x["key"]: x["doc_count"] for x in buckets(b["src"])},
              "examples": [x["key"] for x in buckets(b["msg"])]} for b in buckets(r["aggregations"]["n"])],
            [{"name": b["key"], "count": b["doc_count"], "src": {x["key"]: x["doc_count"] for x in buckets(b["src"])}}
             for b in buckets(w["aggregations"]["n"])])


def totals():
    r = q("logs-zeek-so", {"size": 0, "query": {"bool": {"filter": [RANGE, ds("zeek.conn")]}},
                           "aggs": {"n": {"value_count": {"field": "@timestamp"}},
                                    "cb": {"sum": {"field": "client.ip_bytes"}}, "sb": {"sum": {"field": "server.ip_bytes"}},
                                    "nb": {"sum": {"field": "network.bytes"}}, "miss": {"sum": {"field": "connection.bytes.missed"}},
                                    "ext": {"filter": {"bool": {"should": [{"term": {"connection.local.responder": False}},
                                                                           {"term": {"connection.local.originator": False}}]}},
                                            "aggs": {"cb": {"sum": {"field": "client.ip_bytes"}},
                                                     "sb": {"sum": {"field": "server.ip_bytes"}}}},
                                    "hourly": {"date_histogram": {"field": "@timestamp", "fixed_interval": "1h"},
                                               "aggs": {"c": {"sum": {"field": "client.ip_bytes"}},
                                                        "s": {"sum": {"field": "server.ip_bytes"}},
                                                        "m": {"sum": {"field": "connection.bytes.missed"}}}}}})
    a = r["aggregations"]
    return {"conns": a["n"]["value"], "ip_bytes": a["cb"]["value"] + a["sb"]["value"], "network_bytes": a["nb"]["value"],
            "missed_bytes": a["miss"]["value"], "internet_ip_bytes": a["ext"]["cb"]["value"] + a["ext"]["sb"]["value"],
            "hourly": {x["key_as_string"]: x["c"]["value"] + x["s"]["value"] for x in buckets(a["hourly"])},
            "hourly_missed": {x["key_as_string"]: x["m"]["value"] for x in buckets(a["hourly"])}}


def first_seen():
    """Earliest Zeek sighting of every internal IP across all retained data (not just the window)."""
    r = q("logs-zeek-so", {"size": 0, "query": {"bool": {"filter": [ds("zeek.conn"), INTERNAL]}},
                           "aggs": {"start": {"min": {"field": "@timestamp"}},
                                    "ip": {"terms": {"field": "source.ip", "size": 500},
                                           "aggs": {"f": {"min": {"field": "@timestamp"}}, "l": {"max": {"field": "@timestamp"}}}}}})
    a = r["aggregations"]
    return a["start"]["value_as_string"], {b["key"]: {"first": b["f"]["value_as_string"], "last": b["l"]["value_as_string"]}
                                           for b in buckets(a["ip"])}


def collect_extras(devs):
    """Threat intel, beaconing, internal/segmentation, IoT destinations, files/software, TLS. Each is
    isolated so one failing collector does not lose the whole snapshot."""
    import traceback
    import extras
    pol = extras.load_policy()
    cls = pol.get("device_classes", {})
    iot_ips = [ip for ip, d in devs.items() if SITE.is_internal(ip)
               and cls.get(d.get("mac") or "", cls.get(ip)) in ("iot", "camera", "media", "game")]
    out, errors = {}, {}
    jobs = {"threat_intel": lambda: extras.threat_intel(HOURS), "beacons": lambda: extras.beacons(HOURS),
            "internal": lambda: extras.internal_traffic(HOURS), "admin_access": lambda: extras.admin_access(HOURS), "iot_dest": lambda: extras.iot_destinations(iot_ips, HOURS),
            "files": lambda: extras.files_software(HOURS), "tls": lambda: extras.tls_profile(HOURS)}
    import unifi
    jobs["unifi"] = lambda: unifi.collect(HOURS)
    import hosts
    jobs["hosts"] = lambda: hosts.collect(HOURS, update=not RANGE_END)  # a time range never changes the host baseline
    import mitre
    jobs["mitre_ids"] = lambda: mitre.collect_ids(HOURS)
    for k, fn in jobs.items():
        try:
            out[k] = fn()
        except Exception as e:
            errors[k] = f"{type(e).__name__}: {e}"
            traceback.print_exc()
    out["extras_errors"] = errors
    return out


def main():
    inv, inv_file = inventory()
    dmap = dhcp_map()
    ip_to_mac = {v["ip"]: m for m, v in inv.items()}
    for ip, v in dmap.items():
        if v["macs"]:
            ip_to_mac[ip] = v["macs"][0]
    devs, dns = device_traffic(), dns_profile()
    for ip, d in devs.items():
        mac = ip_to_mac.get(ip)
        d["mac"] = mac
        d["name"] = inv[mac]["name"] if mac in inv else (dmap.get(ip, {}).get("hostname") or None)
        d["known"] = mac in inv
        d["dns"] = dns.get(ip, {})
        d["hostname"] = dmap.get(ip, {}).get("hostname") or ""
    ret_start, fs = first_seen()
    for ip, d in devs.items():
        d["zeek_first_seen"] = (fs.get(ip) or {}).get("first")
    unknown_dhcp = [{"ip": ip, "macs": v["macs"], "hostname": v["hostname"]} for ip, v in dmap.items()
                    if not any(m in inv for m in v["macs"])]
    nts, weird = notices()
    now = window.end_dt()
    out = {"generated": now.isoformat(), "hours": HOURS, **({"lookback": LOOKBACK} if LOOKBACK else {}), **({"range": {"start": _s.isoformat(), "end": _e.isoformat()}} if RANGE_END else {}), "inventory_file": inv_file, "self_ip": SELF_IP,
           "totals": totals(), "devices": devs, "alerts": alerts(), "detections": detections(),
           "notices": nts, "weird": weird, "unknown_dhcp": unknown_dhcp, "zeek_retention_start": ret_start,
           "dns_tunnel": dns_tunnel_candidates(),
           **collect_extras(devs),
           "inventory_ips": {v["ip"]: v["name"] for v in inv.values()}}
    if OUT:  # time range: written where the caller says (dashboard/state/ranges), never into data/
        path = OUT
        pass
    else:
        path = os.path.join(NM, "data", now.strftime("%Y-%m-%dT%H%MZ") + ".json")
    import store  # noqa: E402
    store.jdump(out, path, indent=1, default=str)  # data/ and ranges/ documents live in the SQLite docs table
    print(path)


# ---- one section at a time (dashboard time range: the host broker runs `collect.py --start --end --section NAME`) ----
SECTIONS = ["unifi", "totals", "devices", "alerts", "detections", "notices", "dns_tunnel", "threat_intel", "beacons", "internal",
            "admin_access", "iot_dest", "files", "tls", "hosts", "mitre_ids"]


def _devices_section():
    inv, inv_file = inventory()
    dmap = dhcp_map()
    ip_to_mac = {v["ip"]: m for m, v in inv.items()}
    for ip, v in dmap.items():
        if v["macs"]:
            ip_to_mac[ip] = v["macs"][0]
    devs, dns = device_traffic(), dns_profile()
    for ip, d in devs.items():
        mac = ip_to_mac.get(ip)
        d["mac"] = mac
        d["name"] = inv[mac]["name"] if mac in inv else (dmap.get(ip, {}).get("hostname") or None)
        d["known"] = mac in inv
        d["dns"] = dns.get(ip, {})
        d["hostname"] = dmap.get(ip, {}).get("hostname") or ""
    ret_start, fs = first_seen()
    for ip, d in devs.items():
        d["zeek_first_seen"] = (fs.get(ip) or {}).get("first")
    unknown_dhcp = [{"ip": ip, "macs": v["macs"], "hostname": v["hostname"]} for ip, v in dmap.items()
                    if not any(m in inv for m in v["macs"])]
    return {"devices": devs, "unknown_dhcp": unknown_dhcp, "zeek_retention_start": ret_start, "inventory_file": inv_file,
            "self_ip": SELF_IP, "inventory_ips": {v["ip"]: v["name"] for v in inv.values()}}


def _lateral_section():
    """Everything the lateral-movement report needs for a period, straight from Elasticsearch: internal flows, admin
    sessions, segmentation violations, and just enough device naming (inventory + DHCP; no traffic profile)."""
    import extras
    inv, _ = inventory()
    dmap = dhcp_map()
    ip_to_mac = {v["ip"]: m for m, v in inv.items()}
    for ip, v in dmap.items():
        if v["macs"]:
            ip_to_mac[ip] = v["macs"][0]
    it, adm = extras.internal_traffic(HOURS), extras.admin_access(HOURS)
    devs = {ip: {"mac": mac, "name": (inv[mac]["name"] if mac in inv else (dmap.get(ip, {}).get("hostname") or None)), "known": mac in inv}
            for ip, mac in ip_to_mac.items()}
    viol = extras.policy_violations(it.get("flows", []), ip_to_mac, extras.load_policy())
    return {"internal": it, "admin_access": adm, "devices": devs, "violations": viol,
            "inventory_ips": {v["ip"]: v["name"] for v in inv.values()}}


def section(name):
    import extras
    if name == "lateral":
        return _lateral_section()
    if name == "devices":
        return _devices_section()
    if name == "notices":
        nts, weird = notices()
        return {"notices": nts, "weird": weird}
    simple = {"totals": totals, "alerts": alerts, "detections": detections, "dns_tunnel": dns_tunnel_candidates}
    if name in simple:
        return {name: simple[name]()}
    if name == "iot_dest":
        devs = _devices_section()["devices"]
        pol = extras.load_policy()
        cls = pol.get("device_classes", {})
        iot_ips = [ip for ip, d in devs.items() if SITE.is_internal(ip)
                   and cls.get(d.get("mac") or "", cls.get(ip)) in ("iot", "camera", "media", "game")]
        return {name: extras.iot_destinations(iot_ips, HOURS)}
    jobs = {"threat_intel": lambda: extras.threat_intel(HOURS), "beacons": lambda: extras.beacons(HOURS),
            "internal": lambda: extras.internal_traffic(HOURS), "admin_access": lambda: extras.admin_access(HOURS),
            "files": lambda: extras.files_software(HOURS), "tls": lambda: extras.tls_profile(HOURS)}
    if name in jobs:
        return {name: jobs[name]()}
    if name == "unifi":
        import unifi
        return {name: unifi.collect(HOURS)}
    if name == "hosts":
        import hosts
        return {name: hosts.collect(HOURS, update=False)}  # a section never changes the host baseline
    if name == "mitre_ids":
        import mitre
        return {name: mitre.collect_ids(HOURS)}
    raise SystemExit(f"unknown section {name}")


def main_section(name):
    os.environ.setdefault("NETMON_RDAP_BUDGET", "0")
    out = section(name)
    path = OUT
    import store  # noqa: E402
    store.jdump(out, path, indent=1, default=str)
    print(path)


if __name__ == "__main__":
    if _arg("--section"):
        if not (OUT and RANGE_END):
            raise SystemExit("--section needs --start, --end and --out")
        main_section(_arg("--section"))
    else:
        main()
