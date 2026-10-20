#!/usr/bin/python3
"""Extra collectors for netmon (imported by collect.py and watch.py). All ES queries are read-only.

threat_intel()        - DNS names / SNI / outbound + inbound IPs vs abuse.ch, Spamhaus DROP, ET, CINS feeds;
                        RDAP registration age for rare domains (cached).
beacons()             - periodic-connection (C2-style) scoring per internal->external pair.
internal_traffic()    - internal flows, zone matrix, lateral-movement ports, scanning, policy violations.
admin_access()        - admin/lateral sessions (SSH, RDP, PsExec/SMB, WMI, WinRM, VNC...) with login success/failure.
iot_destinations()    - full contacted-domain / ASN / SNI sets for IoT-class devices (allowlist baseline).
files_software()      - executables/scripts/archives transferred (+ Team Cymru MHR hash check), Zeek software inventory.
tls_profile()         - per-device JA3/JA4, JA3 + JA3S catalogue, malicious JA3 (SSLBL), cert validation failures,
                        x509 certificate inventory with risk flags, TLS versions/ciphers.
"""
import bisect, sys, concurrent.futures as cf, csv, io, ipaddress, json, math, os, re, statistics, subprocess, time, urllib.error, urllib.request
from collections import Counter, defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import site_cfg as SITE  # noqa: E402  network-specific values live in site.json (git-ignored)

NM = os.environ.get("NETMON_DIR") or os.path.dirname(os.path.abspath(__file__))
INTEL = os.path.join(NM, "intel")
POLICY = os.path.join(NM, "policy.json")

FEEDS = {
    "urlhaus_hosts": ("https://urlhaus.abuse.ch/downloads/hostfile/", "hosts"),
    "threatfox_hosts": ("https://threatfox.abuse.ch/downloads/hostfile/", "hosts"),
    "feodo_ips": ("https://feodotracker.abuse.ch/downloads/ipblocklist.txt", "ips"),
    "sslbl_ips": ("https://sslbl.abuse.ch/blacklist/sslipblacklist.txt", "ips"),
    "et_compromised": ("https://rules.emergingthreats.net/blockrules/compromised-ips.txt", "ips"),
    "cins_badguys": ("https://cinsscore.com/list/ci-badguys.txt", "ips"),
    "spamhaus_drop": ("https://www.spamhaus.org/drop/drop.txt", "cidrs"),
    "sslbl_ja3": ("https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv", "ja3"),
}
# Feeds whose hits on OUTBOUND traffic are serious (C2 / malware infra). CINS / ET are scanner lists:
# they matter for inbound sessions that succeeded, and only as context for outbound.
SERIOUS = {"urlhaus_hosts", "threatfox_hosts", "feodo_ips", "sslbl_ips", "spamhaus_drop", "sslbl_ja3"}


# ----------------------------------------------------------------------------- helpers
def _ctx():
    from collect import q, ds, buckets  # late import: collect imports us
    return q, ds, buckets


def rng(hours=None, minutes=None):
    import window  # [end - span, end]; end = now, or the end of a dashboard time range (NETMON_WINDOW_END)
    return window.since(minutes) if minutes else window.since_h(hours or 24)


def is_internal(ip):
    return SITE.is_internal(ip)


def entropy(s):
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values()) if n else 0.0


def load_policy():
    return json.load(open(POLICY)) if os.path.exists(POLICY) else {}


def zone_of(ip, policy=None):
    policy = policy or load_policy()
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return "external"
    for z, cidr in policy.get("zones", {}).items():
        if a in ipaddress.ip_network(cidr):
            return z
    return "internal-other" if is_internal(ip) else "external"


# ----------------------------------------------------------------------------- threat intel feeds
def refresh_feeds(max_age_h=12):
    os.makedirs(INTEL, exist_ok=True)
    status = {}
    for name, (url, _) in FEEDS.items():
        path = os.path.join(INTEL, name + ".txt")
        fresh = os.path.exists(path) and time.time() - os.path.getmtime(path) < max_age_h * 3600
        if not fresh:
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "netmon/1.0 (home SOC)"})
                data = urllib.request.urlopen(req, timeout=60).read()
                if len(data) > 100:
                    open(path, "wb").write(data)
            except Exception as e:
                status[name] = f"download failed: {e}"
        if os.path.exists(path):
            status.setdefault(name, f"ok ({time.strftime('%Y-%m-%d %H:%M', time.gmtime(os.path.getmtime(path)))} UTC)")
    return status


def load_feeds():
    hosts, ips, cidrs, ja3 = defaultdict(set), defaultdict(set), [], {}
    for name, (_, kind) in FEEDS.items():
        path = os.path.join(INTEL, name + ".txt")
        if not os.path.exists(path):
            continue
        text = open(path, encoding="utf-8", errors="replace").read()
        if kind == "ja3":
            for row in csv.reader(io.StringIO(text)):
                if row and not row[0].startswith("#") and len(row) >= 4:
                    ja3[row[0].strip()] = f"{row[3].strip()} (listed {row[1][:10]}..{row[2][:10]})"
            continue
        for line in text.splitlines():
            line = line.split("#")[0].split(";")[0].strip()
            if not line:
                continue
            if kind == "hosts":
                parts = line.split()
                if len(parts) >= 2:
                    hosts[parts[1].lower().rstrip(".")].add(name)
            elif kind == "ips":
                tok = line.split()[0].split(",")[0]
                try:
                    ipaddress.ip_address(tok)
                    ips[tok].add(name)
                except ValueError:
                    pass
            elif kind == "cidrs":
                try:
                    n = ipaddress.ip_network(line.split()[0], strict=False)
                    if n.version == 4:
                        cidrs.append((int(n.network_address), int(n.broadcast_address), str(n), name))
                except ValueError:
                    pass
    cidrs.sort()
    return {"hosts": hosts, "ips": ips, "cidrs": cidrs, "cidr_starts": [c[0] for c in cidrs], "ja3": ja3}


def match_domain(name, feeds):
    name = (name or "").lower().rstrip(".")
    parts = name.split(".")
    for i in range(len(parts) - 1):
        cand = ".".join(parts[i:])
        if cand in feeds["hosts"]:
            return cand, sorted(feeds["hosts"][cand])
    return None, []


def match_ip(ip, feeds):
    hits = set(feeds["ips"].get(ip, ()))
    try:
        v = int(ipaddress.ip_address(ip))
    except ValueError:
        return sorted(hits)
    i = bisect.bisect_right(feeds["cidr_starts"], v) - 1
    if i >= 0 and feeds["cidrs"][i][0] <= v <= feeds["cidrs"][i][1]:
        hits.add(feeds["cidrs"][i][3])
    return sorted(hits)


def rdap_bootstrap():
    """IANA RDAP bootstrap (TLD -> registry RDAP base URL), refreshed weekly."""
    path = os.path.join(INTEL, "rdap_bootstrap.json")
    if not os.path.exists(path) or time.time() - os.path.getmtime(path) > 7 * 86400:
        try:
            open(path, "wb").write(urllib.request.urlopen("https://data.iana.org/rdap/dns.json", timeout=30).read())
        except Exception:
            pass
    m = {}
    try:
        for tlds, urls in json.load(open(path))["services"]:
            for t in tlds:
                m[t] = urls[0].rstrip("/") + "/"
    except Exception:
        pass
    return m


def rdap_ages(domains, budget=None, workers=6):
    """Registration date per registered domain, straight from the registry's RDAP server (IANA bootstrap),
    cached forever once known. Failures are retried on later runs; TLDs without RDAP are cached as 'no-rdap'."""
    path = os.path.join(INTEL, "rdap_cache.json")
    cache = json.load(open(path)) if os.path.exists(path) else {}
    if budget is None:  # a dashboard section (NETMON_RDAP_BUDGET=0) answers from the cache only: no per-domain internet look-ups
        budget = int(os.environ.get("NETMON_RDAP_BUDGET", "1500"))
    boot = rdap_bootstrap() if budget else {}
    todo = [d for d in domains if cache.get(d) in (None, "unavailable")][:budget]

    def look(d):
        base = boot.get(d.rsplit(".", 1)[-1].lower())
        if not base:
            return d, "no-rdap"
        for attempt in range(2):
            try:
                req = urllib.request.Request(f"{base}domain/{d}", headers={"Accept": "application/rdap+json",
                                                                           "User-Agent": "netmon/1.0"})
                j = json.load(urllib.request.urlopen(req, timeout=20))
                for e in j.get("events", []):
                    if e.get("eventAction") == "registration":
                        return d, e.get("eventDate", "")[:10]
                return d, "unknown"
            except urllib.error.HTTPError as e:
                if e.code == 404:
                    return d, "not-found"
                time.sleep(2)
            except Exception:
                time.sleep(1)
        return d, "unavailable"

    with cf.ThreadPoolExecutor(workers) as ex:
        for d, v in ex.map(look, todo):
            cache[d] = v
    os.makedirs(INTEL, exist_ok=True)
    json.dump(cache, open(path, "w"))
    return {d: cache.get(d) for d in domains}, len(todo)


def threat_intel(hours=24, minutes=None, rdap=True):
    q, ds, buckets = _ctx()
    status = refresh_feeds()
    feeds = load_feeds()
    R = rng(hours, minutes)
    out = {"feed_status": status, "feed_sizes": {"domains": len(feeds["hosts"]), "ips": len(feeds["ips"]),
                                                  "cidrs": len(feeds["cidrs"]), "ja3": len(feeds["ja3"])},
           "domain_hits": [], "ip_hits_out": [], "ip_hits_in": [], "new_domains": []}
    # --- names: DNS queries + TLS SNI
    names = defaultdict(lambda: Counter())
    r = q("logs-zeek-so", {"size": 0, "query": {"bool": {"filter": [R, ds("zeek.dns"), {"term": {"source.ip": SITE.get("internal_cidr")}}]}},
                           "aggs": {"n": {"terms": {"field": "dns.query.name", "size": 40000},
                                          "aggs": {"s": {"terms": {"field": "source.ip", "size": 4}}}}}})
    for b in buckets(r["aggregations"]["n"]):
        for s in buckets(b["s"]):
            names[b["key"]][s["key"]] += s["doc_count"]
    r = q("logs-zeek-so", {"size": 0, "query": {"bool": {"filter": [R, ds("zeek.ssl"), {"term": {"source.ip": SITE.get("internal_cidr")}}]}},
                           "aggs": {"n": {"terms": {"field": "ssl.server_name", "size": 20000},
                                          "aggs": {"s": {"terms": {"field": "source.ip", "size": 4}}}}}})
    for b in buckets(r["aggregations"]["n"]):
        for s in buckets(b["s"]):
            names[b["key"]][s["key"]] += s["doc_count"]
    for n, srcs in names.items():
        m, fl = match_domain(n, feeds)
        if m:
            out["domain_hits"].append({"name": n, "matched": m, "feeds": fl, "sources": dict(srcs.most_common(4)),
                                       "count": sum(srcs.values())})
    # --- outbound connections to listed IPs
    r = q("logs-zeek-so", {"size": 0, "query": {"bool": {"filter": [R, ds("zeek.conn"), {"term": {"source.ip": SITE.get("internal_cidr")}},
                                                                    {"term": {"connection.local.responder": False}}]}},
                           "aggs": {"d": {"terms": {"field": "destination.ip", "size": 60000},
                                          "aggs": {"s": {"terms": {"field": "source.ip", "size": 3}},
                                                   "p": {"terms": {"field": "destination.port", "size": 3}},
                                                   "est": {"filter": {"bool": {"must_not": [{"terms": {"connection.state": ["S0", "REJ", "OTH", "SH", "RSTOS0"]}}]}}},
                                                   "b": {"sum": {"field": "network.bytes"}},
                                                   "as": {"terms": {"field": "destination.as.organization.name", "size": 1}}}}}})
    for b in buckets(r["aggregations"]["d"]):
        fl = match_ip(b["key"], feeds)
        if fl:
            out["ip_hits_out"].append({"ip": b["key"], "feeds": fl, "serious": bool(set(fl) & SERIOUS), "conns": b["doc_count"],
                                       "established": b["est"]["doc_count"], "bytes": b["b"]["value"],
                                       "sources": {s["key"]: s["doc_count"] for s in buckets(b["s"])},
                                       "ports": [p["key"] for p in buckets(b["p"])],
                                       "asn": (buckets(b["as"]) or [{"key": ""}])[0]["key"]})
    # --- inbound sessions from listed IPs that were ANSWERED (scans that got nothing are noise)
    r = q("logs-zeek-so", {"size": 0, "query": {"bool": {"filter": [R, ds("zeek.conn"), {"term": {"destination.ip": SITE.get("internal_cidr")}},
                                                                    {"term": {"connection.local.originator": False}}],
                                                         "must_not": [{"terms": {"connection.state": ["S0", "REJ", "OTH", "SH", "RSTOS0"]}}]}},
                           "aggs": {"s": {"terms": {"field": "source.ip", "size": 20000},
                                          "aggs": {"d": {"terms": {"field": "destination.ip", "size": 3}},
                                                   "p": {"terms": {"field": "destination.port", "size": 3}},
                                                   "b": {"sum": {"field": "network.bytes"}}}}}})
    for b in buckets(r["aggregations"]["s"]):
        fl = match_ip(b["key"], feeds)
        if fl:
            out["ip_hits_in"].append({"ip": b["key"], "feeds": fl, "conns": b["doc_count"], "bytes": b["b"]["value"],
                                      "targets": {d["key"]: d["doc_count"] for d in buckets(b["d"])},
                                      "ports": [p["key"] for p in buckets(b["p"])]})
    # --- newly registered domains (RDAP), rarest first
    if rdap:
        r = q("logs-zeek-so", {"size": 0, "query": {"bool": {"filter": [R, ds("zeek.dns"), {"term": {"source.ip": SITE.get("internal_cidr")}},
                                                                        {"term": {"destination.port": 53}}],
                                                             "must_not": [{"wildcard": {"dns.highest_registered_domain": "*arpa"}},
                                                                          {"wildcard": {"dns.highest_registered_domain": "*local*"}}]}},
                               "aggs": {"d": {"terms": {"field": "dns.highest_registered_domain", "size": 20000},
                                              "aggs": {"s": {"terms": {"field": "source.ip", "size": 4}},
                                                       "ok": {"filter": {"term": {"dns.response.code_name": "NOERROR"}}}}}}})
        doms = {b["key"]: b for b in buckets(r["aggregations"]["d"]) if "." in b["key"] and b["ok"]["doc_count"]}
        order = sorted(doms, key=lambda d: (len(buckets(doms[d]["s"])), doms[d]["doc_count"]))
        ages, looked = rdap_ages(order)
        today = time.time()
        for d, reg in ages.items():
            if reg and reg[:2] in ("19", "20"):
                age = (today - time.mktime(time.strptime(reg, "%Y-%m-%d"))) / 86400
                if age <= 90:
                    out["new_domains"].append({"domain": d, "registered": reg, "age_days": int(age),
                                               "queries": doms[d]["doc_count"],
                                               "sources": {s["key"]: s["doc_count"] for s in buckets(doms[d]["s"])}})
        out["rdap"] = {"domains": len(doms), "looked_up_now": looked,
                       "known_age": sum(1 for v in ages.values() if v and v[:2] in ("19", "20"))}
    out["domain_hits"].sort(key=lambda x: -x["count"])
    out["ip_hits_out"].sort(key=lambda x: (not x["serious"], -x["established"]))
    out["new_domains"].sort(key=lambda x: x["age_days"])
    return out


# ----------------------------------------------------------------------------- beaconing
def _robust(vals):
    vals = sorted(vals)
    n = len(vals)
    if n < 4:
        return 0.0, 0.0, 0.0
    q1, med, q3 = vals[n // 4], statistics.median(vals), vals[(3 * n) // 4]
    skew = 0.0 if q3 == q1 else (q1 + q3 - 2 * med) / (q3 - q1)
    mad = statistics.median([abs(v - med) for v in vals])
    return med, skew, mad


def beacons(hours=24, min_conns=36, max_pairs=400):
    """RITA-style beacon score per (src, dst, port): timing regularity, size regularity, day coverage."""
    q, ds, buckets = _ctx()
    R = rng(hours)
    r = q("logs-zeek-so", {"size": 0, "query": {"bool": {"filter": [R, ds("zeek.conn"), {"term": {"source.ip": SITE.get("internal_cidr")}},
                                                                    {"term": {"connection.local.responder": False}}],
                                                         "must_not": [{"terms": {"destination.port": [3478, 19302]}}]}},
                           "aggs": {"p": {"multi_terms": {"terms": [{"field": "source.ip"}, {"field": "destination.ip"},
                                                                    {"field": "destination.port"}],
                                                          "size": max_pairs, "min_doc_count": min_conns}}}})
    pairs = [tuple(b["key"]) + (b["doc_count"],) for b in buckets(r["aggregations"]["p"])]

    def score(p):
        src, dst, port, n = p
        h = q("logs-zeek-so", {"size": 5000, "_source": ["@timestamp", "client.ip_bytes"], "sort": [{"@timestamp": "asc"}],
                               "query": {"bool": {"filter": [R, ds("zeek.conn"), {"term": {"source.ip": src}},
                                                             {"term": {"destination.ip": dst}}, {"term": {"destination.port": port}}]}}})
        ts, sizes = [], []
        from datetime import datetime
        for x in h["hits"]["hits"]:
            s = x["_source"]
            ts.append(datetime.fromisoformat(s["@timestamp"].replace("Z", "+00:00")).timestamp())
            sizes.append((s.get("client") or {}).get("ip_bytes") or 0)
        uts = sorted(set(int(t) for t in ts))
        iv = [b - a for a, b in zip(uts, uts[1:]) if b - a > 0]
        if len(iv) < 10:
            return None
        med, skew, mad = _robust(iv)
        smed, sskew, smad = _robust(sizes)
        ts_skew = 1 - abs(skew)
        ts_mad = max(0.0, 1 - mad / med) if med else 0
        coverage = min(1.0, len({int(t // 3600) for t in uts}) / hours)
        ds_skew = 1 - abs(sskew)
        ds_mad = max(0.0, 1 - smad / smed) if smed else 1.0
        sc = 0.25 * ts_skew + 0.30 * ts_mad + 0.25 * min(1.0, coverage / 0.75) + 0.10 * ds_skew + 0.10 * ds_mad
        return {"src": src, "dst": dst, "port": port, "conns": n, "interval_s": round(med), "jitter_s": round(mad),
                "coverage_h": round(coverage * hours), "bytes_median": smed, "score": round(sc, 3),
                "ts_regularity": round((ts_skew + ts_mad) / 2, 2), "size_regularity": round((ds_skew + ds_mad) / 2, 2)}

    with cf.ThreadPoolExecutor(8) as ex:
        res = [x for x in ex.map(score, pairs) if x]
    cands = [x for x in res if x["score"] >= 0.75 and x["coverage_h"] >= hours * 0.4]
    # label destinations: SNI, DNS name, ASN
    ips = list({c["dst"] for c in cands})
    labels = defaultdict(dict)
    if ips:
        a = q("logs-zeek-so", {"size": 0, "query": {"bool": {"filter": [R, ds("zeek.ssl"), {"terms": {"destination.ip": ips}}]}},
                               "aggs": {"d": {"terms": {"field": "destination.ip", "size": len(ips)},
                                              "aggs": {"n": {"terms": {"field": "ssl.server_name", "size": 1}}}}}})
        for b in buckets(a["aggregations"]["d"]):
            if buckets(b["n"]):
                labels[b["key"]]["name"] = buckets(b["n"])[0]["key"]
        a = q("logs-zeek-so", {"size": 0, "query": {"bool": {"filter": [rng(max(hours, 48)), ds("zeek.dns"), {"terms": {"dns.resolved_ip": ips}}]}},
                               "aggs": {"d": {"terms": {"field": "dns.resolved_ip", "size": len(ips), "include": ips},
                                              "aggs": {"n": {"terms": {"field": "dns.query.name", "size": 1}},
                                                       "r": {"terms": {"field": "dns.highest_registered_domain", "size": 1}}}}}})
        for b in buckets(a["aggregations"]["d"]):
            labels[b["key"]].setdefault("name", (buckets(b["n"]) or [{"key": ""}])[0]["key"])
            labels[b["key"]]["domain"] = (buckets(b["r"]) or [{"key": ""}])[0]["key"]
        a = q("logs-zeek-so", {"size": 0, "query": {"bool": {"filter": [R, ds("zeek.conn"), {"terms": {"destination.ip": ips}}]}},
                               "aggs": {"d": {"terms": {"field": "destination.ip", "size": len(ips)},
                                              "aggs": {"a": {"terms": {"field": "destination.as.organization.name", "size": 1}},
                                                       "c": {"terms": {"field": "destination.geo.country_iso_code", "size": 1}}}}}})
        for b in buckets(a["aggregations"]["d"]):
            labels[b["key"]]["asn"] = (buckets(b["a"]) or [{"key": ""}])[0]["key"]
            labels[b["key"]]["country"] = (buckets(b["c"]) or [{"key": ""}])[0]["key"]
    for c in cands:
        c.update({k: labels[c["dst"]].get(k, "") for k in ("name", "domain", "asn", "country")})
        if not c["domain"] and c["name"]:
            c["domain"] = ".".join(c["name"].split(".")[-2:])
    return {"pairs_scored": len(res), "candidates": sorted(cands, key=lambda c: -c["score"])}


# ----------------------------------------------------------------------------- internal traffic / segmentation
FAILED = ["S0", "REJ", "RSTOS0", "SH", "OTH"]


def internal_traffic(hours=24):
    q, ds, buckets = _ctx()
    pol = load_policy()
    R = rng(hours)
    base = [R, ds("zeek.conn"), {"term": {"source.ip": SITE.get("internal_cidr")}}, {"term": {"destination.ip": SITE.get("internal_cidr")}}]
    r = q("logs-zeek-so", {"size": 0, "query": {"bool": {"filter": base,
                                                         "must_not": [{"wildcard": {"destination.ip": "*.255"}}] if False else []}},
                           "aggs": {"p": {"multi_terms": {"terms": [{"field": "source.ip"}, {"field": "destination.ip"},
                                                                    {"field": "destination.port"}, {"field": "network.transport"}],
                                                          "size": 5000},
                                          "aggs": {"ok": {"filter": {"bool": {"must_not": [{"terms": {"connection.state": FAILED}}]}}},
                                                   "svc": {"terms": {"field": "network.protocol", "size": 1}},
                                                   "b": {"sum": {"field": "network.bytes"}}}},
                                    # scanning: failed attempts per source
                                    "scan": {"filter": {"terms": {"connection.state": FAILED}},
                                             "aggs": {"s": {"terms": {"field": "source.ip", "size": 300},
                                                            "aggs": {"hosts": {"cardinality": {"field": "destination.ip"}},
                                                                     "ports": {"cardinality": {"field": "destination.port"}},
                                                                     "top": {"terms": {"field": "destination.port", "size": 5}}}}}}}})
    flows = []
    for b in buckets(r["aggregations"]["p"]):
        src, dst, port, tr = b["key"]
        if dst.endswith(".255") or src == dst:
            continue
        flows.append({"src": src, "dst": dst, "port": int(port), "proto": tr, "conns": b["doc_count"],
                      "answered": b["ok"]["doc_count"], "bytes": b["b"]["value"],
                      "service": (buckets(b["svc"]) or [{"key": ""}])[0]["key"],
                      "src_zone": zone_of(src, pol), "dst_zone": zone_of(dst, pol)})
    scans = []
    th = pol.get("scan_thresholds", {"hosts": 20, "ports": 40})
    for b in buckets(r["aggregations"]["scan"]["s"]):
        top = [x["key"] for x in buckets(b["top"])]
        if b["key"].endswith(".1"):  # gateway interfaces broadcast discovery to every host
            continue
        if b["hosts"]["value"] >= th["hosts"] or b["ports"]["value"] >= th["ports"]:
            scans.append({"src": b["key"], "failed_conns": b["doc_count"], "hosts": b["hosts"]["value"],
                          "ports": b["ports"]["value"], "top_ports": top})
    matrix = defaultdict(lambda: {"conns": 0, "bytes": 0, "ports": Counter()})
    for f in flows:
        m = matrix[f"{f['src_zone']} -> {f['dst_zone']}"]
        m["conns"] += f["conns"]
        m["bytes"] += f["bytes"]
        m["ports"][f"{f['port']}/{f['proto']}"] += f["conns"]
    return {"flows": flows, "scans": scans,
            "matrix": {k: {"conns": v["conns"], "bytes": v["bytes"], "ports": dict(v["ports"].most_common(6))}
                       for k, v in sorted(matrix.items(), key=lambda x: -x[1]["conns"])}}


_SSH_OPTS_WITH_ARG = set("bcDEeFIiJLlmOoPpQRSWw")
_HOST_RE = r"[A-Za-z0-9][A-Za-z0-9._-]*"


def _redact_cmd(line):
    """Strip credentials from admin-tool command lines before they are stored or shown."""
    line = re.sub(r"(/p:|/password:|-p(?:assword)?[:=]?\s+|--password[= ]\s*|-hashes\s+|-H\s+|-Credential\s+|-pw\s+)(\S+)", r"\1***", line, flags=re.I)
    return re.sub(r"([^\s/@:]+/)?([^\s/@:]+):([^\s@]+)@", r"\1\2:***@", line)  # domain/user:password@host


def _admin_target(tool, args):
    """Remote host an admin client tool was pointed at, or "" when it was used locally."""
    line = " ".join(args)
    for pat in (r"/v:(" + _HOST_RE + ")", r"\\\\(" + _HOST_RE + ")", r"-r:(" + _HOST_RE + ")",
                r"-(?:ComputerName|cn)\s+(" + _HOST_RE + ")", r"(?:^|\s)-i\s+(" + _HOST_RE + ")" if tool == "evil-winrm" else r"$^"):
        m = re.search(pat, line, re.I)
        if m:
            return m.group(1)
    if tool in ("ssh", "sshpass", "mosh", "telnet", "vncviewer"):
        skip = False
        for a in args:
            if skip:
                skip = False; continue
            if a.startswith("-"):
                skip = len(a) == 2 and a[1] in _SSH_OPTS_WITH_ARG and tool != "telnet"; continue
            if tool == "sshpass":  # sshpass -p pw ssh host
                continue
            return a.split("@")[-1].split(":")[0]
        if tool == "sshpass":
            return _admin_target("ssh", args[args.index("ssh") + 1:]) if "ssh" in args else ""
        return ""
    for a in args:  # scp / sftp / rsync / impacket / nxc: [user@]host:path or user@host
        if a.startswith("-") or a.startswith("/"):
            continue
        m = re.match(r"^(?:[^@\s]+@)?(" + _HOST_RE + r")(?::|$)", a)
        if m and ("@" in a or ":" in a or re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", m.group(1))):
            return m.group(1)
    return ""


def admin_access(hours=24, end=None, minutes=None):
    """Admin / lateral-movement sessions between internal hosts, successful AND failed (see adminproto.py):
      conns  - Zeek conn on admin ports (SSH, RDP, SMB/PsExec, RPC/WMI, WinRM/PS remoting, VNC, Docker, k8s...):
               attempts, connected vs refused/unanswered, bytes, first/last seen
      logins - login outcomes: endpoint auth logs (sshd accepted/failed/invalid user), Windows 4624/4625 network+RDP
               logons, Zeek ssh auth_success, Zeek rdp/ntlm/kerberos results, PsExec-style service creation (dce_rpc)
      tools  - admin client tools executed on endpoints (ssh/scp, xfreerdp, PsExec, impacket, winrs, PS remoting...)
    Every source is optional: a missing index or dataset just yields nothing."""
    import adminproto as AP
    q, ds, buckets = _ctx()
    R = ({"range": {"@timestamp": {"gte": f"{end}||-{hours}h", "lte": end}}} if end    # end: backfill an older snapshot
         else rng(minutes=minutes) if minutes else rng(hours))                          # minutes: the 15-min watcher
    cidr = SITE.get("internal_cidr")
    out = {"conns": [], "logins": [], "tools": [], "sources": {}, "errors": {}}

    def src_ok(name, fn):
        try:
            n = fn()
            out["sources"][name] = n
        except Exception as e:  # noqa: BLE001 - one source failing must not lose the others
            out["errors"][name] = f"{type(e).__name__}: {str(e)[:200]}"

    def zeek_msg(h):
        try:
            return json.loads(h["_source"].get("message") or "{}")
        except ValueError:
            return {}

    # --- network: every admin-port connection between internal hosts
    def conns():
        tcp, udp = AP.tcp_admin_ports(), AP.udp_admin_ports()
        body = {"size": 0, "query": {"bool": {"filter": [R, ds("zeek.conn"), {"term": {"source.ip": cidr}}, {"term": {"destination.ip": cidr}}],
                                              "should": [{"bool": {"filter": [{"term": {"network.transport": "tcp"}}, {"terms": {"destination.port": tcp}}]}},
                                                         {"bool": {"filter": [{"term": {"network.transport": "udp"}}, {"terms": {"destination.port": udp}}]}}],
                                              "minimum_should_match": 1}},
                "aggs": {"p": {"multi_terms": {"terms": [{"field": "source.ip"}, {"field": "destination.ip"}, {"field": "destination.port"}, {"field": "network.transport"}], "size": 3000},
                               "aggs": {"fail": {"filter": {"terms": {"connection.state": AP.CONN_FAILED}}},
                                        "b": {"sum": {"field": "network.bytes"}},
                                        "t0": {"min": {"field": "@timestamp"}}, "t1": {"max": {"field": "@timestamp"}}}}}}
        r = q("logs-zeek-so", body)
        for b in buckets(r["aggregations"]["p"]):
            s, d, port, tr = b["key"]
            if s == d or d.endswith(".255"):
                continue
            lab = AP.label(port, tr)
            if not lab:
                continue
            out["conns"].append({"src": s, "dst": d, "port": int(port), "proto": tr, "protocol": lab[0], "category": lab[1],
                                 "attempts": b["doc_count"], "failed": b["fail"]["doc_count"], "connected": b["doc_count"] - b["fail"]["doc_count"],
                                 "bytes": b["b"]["value"] or 0, "first": b["t0"].get("value_as_string"), "last": b["t1"].get("value_as_string")})
        return len(out["conns"])

    def add_login(**kw):
        kw.setdefault("count", 1)
        out["logins"].append(kw)

    # --- Linux endpoints: sshd accepted / failed / invalid user (definitive login results)
    def linux_auth():
        body = {"size": 0, "query": {"bool": {"filter": [R, {"term": {"event.action": "ssh_login"}}]}},
                "aggs": {"p": {"multi_terms": {"terms": [{"field": "source.ip"}, {"field": "host.name"}, {"field": "user.name"}, {"field": "event.outcome"}], "size": 2000},
                               "aggs": {"m": {"terms": {"field": "system.auth.ssh.method", "size": 3}},
                                        "e": {"terms": {"field": "system.auth.ssh.event", "size": 3}},
                                        "t0": {"min": {"field": "@timestamp"}}, "t1": {"max": {"field": "@timestamp"}}}}}}
        r = q("logs-system.auth-*", body)
        n = 0
        for b in buckets(r["aggregations"]["p"]):
            sip, host, user, outcome = b["key"]
            add_login(src=sip, dst_host=host, user=user, protocol="SSH", ok=outcome == "success", count=b["doc_count"],
                      method=",".join(x["key"] for x in buckets(b["m"])), detail=",".join(x["key"] for x in buckets(b["e"])),
                      first=b["t0"].get("value_as_string"), last=b["t1"].get("value_as_string"), source="endpoint auth log")
            n += 1
        return n

    # --- Windows endpoints: 4624 (success) / 4625 (failure) network and RDP logons
    def windows_logons():
        body = {"size": 0, "query": {"bool": {"filter": [R, {"terms": {"event.code": ["4624", "4625"]}},
                                                         {"terms": {"winlog.event_data.LogonType": list(AP.WIN_LOGON)}}]}},
                "aggs": {"p": {"multi_terms": {"terms": [{"field": "source.ip"}, {"field": "host.name"}, {"field": "user.name"},
                                                         {"field": "event.code"}, {"field": "winlog.event_data.LogonType"}], "size": 2000},
                               "aggs": {"t0": {"min": {"field": "@timestamp"}}, "t1": {"max": {"field": "@timestamp"}},
                                        "pkg": {"terms": {"field": "winlog.event_data.AuthenticationPackageName", "size": 2}}}}}}
        r = q("logs-system.security-*,logs-windows.*", body)
        n = 0
        for b in buckets((r.get("aggregations") or {}).get("p") or {}):  # no Windows indices yet -> nothing
            sip, host, user, code, lt = b["key"]
            if sip in ("-", "127.0.0.1", "::1"):
                continue
            add_login(src=sip, dst_host=host, user=user, protocol="RDP" if str(lt) == "10" else "Windows network logon",
                      ok=str(code) == "4624", count=b["doc_count"], method=",".join(x["key"] for x in buckets(b["pkg"])),
                      detail=f"logon type {lt}: {AP.WIN_LOGON.get(str(lt), '')}", first=b["t0"].get("value_as_string"),
                      last=b["t1"].get("value_as_string"), source="Windows security log")
            n += 1
        return n

    # --- Zeek application logs: ssh auth_success, rdp result, ntlm/kerberos success, PsExec-style service creation
    def zeek_auth():
        n = 0
        body = {"size": 2000, "sort": [{"@timestamp": "desc"}], "_source": ["message", "@timestamp", "event.dataset"],
                "query": {"bool": {"filter": [R, {"terms": {"event.dataset": ["zeek.ssh", "zeek.rdp", "zeek.ntlm", "zeek.kerberos", "zeek.dce_rpc", "zeek.smb_files"]}},
                                              {"term": {"source.ip": cidr}}, {"term": {"destination.ip": cidr}}]}}}
        agg = defaultdict(lambda: {"count": 0, "first": None, "last": None})
        for h in q("logs-zeek-so", body)["hits"]["hits"]:
            m, dset, ts = zeek_msg(h), h["_source"].get("event", {}).get("dataset", ""), h["_source"].get("@timestamp")
            s, d = m.get("id.orig_h"), m.get("id.resp_h")
            if not s or not d:
                continue
            key = None
            if dset == "zeek.ssh" and m.get("auth_success") is not None:
                key = (s, d, "SSH", bool(m["auth_success"]), "", f"{m.get('auth_attempts', 0)} attempt(s), client {m.get('client', '')[:40]}")
            elif dset == "zeek.rdp" and m.get("result"):
                key = (s, d, "RDP", m["result"].lower() == "success", m.get("cookie", ""), f"result {m['result']}")
            elif dset == "zeek.ntlm" and m.get("success") is not None:
                key = (s, d, "SMB (PsExec / admin shares)" if m.get("id.resp_p") in (445, 139) else "NTLM auth", bool(m["success"]),
                       m.get("username", ""), f"NTLM {m.get('domainname', '')}")
            elif dset == "zeek.kerberos" and m.get("success") is not None and m.get("request_type") == "TGS":
                key = (s, d, "Kerberos service ticket", bool(m["success"]), (m.get("client") or "").split("/")[0], str(m.get("service", ""))[:60])
            elif dset == "zeek.dce_rpc" and m.get("endpoint") == "svcctl" and m.get("operation") in ("CreateServiceW", "CreateServiceA", "StartServiceW"):
                key = (s, d, "SMB (PsExec / admin shares)", True, "", f"remote service {m['operation']} (PsExec-style execution)")
            elif dset == "zeek.smb_files" and "psexe" in str(m.get("name", "")).lower():
                key = (s, d, "SMB (PsExec / admin shares)", True, "", f"PsExec service binary {m.get('name')} written to {m.get('path', '')}")
            if key:
                a = agg[key]; a["count"] += 1
                a["first"] = min(filter(None, [a["first"], ts])); a["last"] = max(filter(None, [a["last"], ts]))
        for (s, d, proto, ok, user, detail), a in agg.items():
            add_login(src=s, dst=d, user=user, protocol=proto, ok=ok, count=a["count"], detail=detail,
                      first=a["first"], last=a["last"], source="Zeek")
            n += 1
        return n

    # --- admin client tools run on endpoints (who launched what, towards which target)
    def tools():
        names = list(AP.ADMIN_TOOLS) + [n for n in AP.ADMIN_TOOLS if not n.endswith(".exe")] + sorted(AP.PS_NAMES)
        body = {"size": 1500, "sort": [{"@timestamp": "desc"}],
                "_source": ["@timestamp", "host.name", "user.name", "process.name", "process.args"],
                "query": {"bool": {"filter": [R, {"term": {"event.action": "exec"}}, {"terms": {"process.name": sorted(set(names))}}]}}}
        agg = {}
        ipre = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
        for h in q("logs-endpoint.events.process-*", body)["hits"]["hits"]:
            s = h["_source"]; p = s.get("process") or {}; nm = str(p.get("name", "")); args = p.get("args") or []
            line = _redact_cmd(" ".join(map(str, args)))[:300]
            if nm.lower() in AP.PS_NAMES:
                if not any(k in line.lower() for k in AP.PS_REMOTING):
                    continue
                proto = "WinRM / PowerShell remoting"
            else:
                proto = AP.ADMIN_TOOLS.get(nm.lower()) or AP.ADMIN_TOOLS.get(nm)
                if not proto:
                    continue
            target = _admin_target(nm.lower(), [str(a) for a in args[1:]])
            if not target:  # local-only use (e.g. rsync between two local dirs) is not remote admin
                continue
            key = ((s.get("host") or {}).get("name", ""), (s.get("user") or {}).get("name", ""), nm, proto, target)
            a = agg.setdefault(key, {"count": 0, "last": s.get("@timestamp"), "example": line})
            a["count"] += 1
        for (host, user, nm, proto, target), a in agg.items():
            out["tools"].append({"host": host, "user": user, "tool": nm, "protocol": proto, "target": target,
                                 "count": a["count"], "last": a["last"], "example": a["example"]})
        return len(out["tools"])

    for name, fn in (("conns", conns), ("linux_auth", linux_auth), ("windows_logons", windows_logons), ("zeek_auth", zeek_auth), ("tools", tools)):
        src_ok(name, fn)
    return out


def classify(ip, mac, pol):
    c = pol.get("device_classes", {})
    return c.get(mac or "", c.get(ip, "unclassified"))


def policy_violations(flows, ip2mac, pol):
    """Flag internal flows that break the segmentation policy (see policy.json)."""
    sens = set(pol.get("sensitive_ports", []))
    allow = pol.get("allow", [])
    disc = set(pol.get("discovery_ports", []))
    out = []

    def allowed(f, sc, dc):
        for a in allow:
            if a.get("src") not in (None, "*", f["src"], f["src_zone"], sc):
                continue
            if a.get("dst") not in (None, "*", f["dst"], f["dst_zone"], dc):
                continue
            if a.get("ports") and f["port"] not in a["ports"] and f"{f['port']}/{f['proto']}" not in a["ports"]:
                continue
            return True
        return False

    for f in flows:
        if f["answered"] == 0 and f["conns"] < 5:
            continue
        sc, dc = classify(f["src"], ip2mac.get(f["src"]), pol), classify(f["dst"], ip2mac.get(f["dst"]), pol)
        if f["dst"].endswith(".1") and (f["port"] in disc or f["port"] in pol.get("gateway_ports", [])):
            continue
        if allowed(f, sc, dc):
            continue
        reason, sev = None, None
        if f["src_zone"] == "dmz" and f["dst_zone"] != "dmz":
            reason, sev = "DMZ host initiating into the internal network", "high"
        elif sc in ("iot", "camera") and f["dst_zone"] in ("servers", "k8s", "ai"):
            reason, sev = f"{sc} device reaching {f['dst_zone']}", "high"
        elif sc in ("iot", "camera") and f["port"] in sens:
            reason, sev = f"{sc} device using admin/lateral port {f['port']}", "high"
        elif f["port"] in sens and f["answered"]:
            reason, sev = f"lateral-movement/admin port {f['port']} ({f['service'] or 'tcp'}) between internal hosts", "medium"
        elif f["src_zone"] != f["dst_zone"] and f["dst_zone"] in ("servers", "k8s", "ai") and f["port"] not in disc and f["answered"]:
            reason, sev = f"cross-zone access {f['src_zone']} -> {f['dst_zone']} on {f['port']}/{f['proto']}", "low"
        if reason:
            out.append({**f, "src_class": sc, "dst_class": dc, "reason": reason, "severity": sev})
    return sorted(out, key=lambda v: ({"high": 0, "medium": 1, "low": 2}[v["severity"]], -v["conns"]))


# ----------------------------------------------------------------------------- IoT destinations
def iot_destinations(iot_ips, hours=24):
    q, ds, buckets = _ctx()
    if not iot_ips:
        return {}
    R = rng(hours)
    out = defaultdict(lambda: {"domains": {}, "asns": {}, "sni": {}})
    r = q("logs-zeek-so", {"size": 0, "query": {"bool": {"filter": [R, ds("zeek.dns"), {"terms": {"source.ip": iot_ips}},
                                                                    {"term": {"destination.port": 53}}]}},
                           "aggs": {"s": {"terms": {"field": "source.ip", "size": len(iot_ips)},
                                          "aggs": {"d": {"terms": {"field": "dns.highest_registered_domain", "size": 200}}}}}})
    for b in buckets(r["aggregations"]["s"]):
        out[b["key"]]["domains"] = {x["key"]: x["doc_count"] for x in buckets(b["d"]) if "arpa" not in x["key"] and "local" not in x["key"]}
    r = q("logs-zeek-so", {"size": 0, "query": {"bool": {"filter": [R, ds("zeek.conn"), {"terms": {"source.ip": iot_ips}},
                                                                    {"term": {"connection.local.responder": False}}]}},
                           "aggs": {"s": {"terms": {"field": "source.ip", "size": len(iot_ips)},
                                          "aggs": {"a": {"terms": {"field": "destination.as.organization.name", "size": 60},
                                                         "aggs": {"b": {"sum": {"field": "network.bytes"}}}},
                                                   "noas": {"filter": {"bool": {"must_not": [{"exists": {"field": "destination.as.organization.name"}}]}},
                                                            "aggs": {"d": {"terms": {"field": "destination.ip", "size": 20}}}}}}}})
    for b in buckets(r["aggregations"]["s"]):
        out[b["key"]]["asns"] = {x["key"]: x["b"]["value"] for x in buckets(b["a"])}
        out[b["key"]]["no_asn_ips"] = [x["key"] for x in buckets(b["noas"]["d"]) if not is_internal(x["key"])
                                       and not x["key"].startswith(("224.", "239.", "255."))]
    r = q("logs-zeek-so", {"size": 0, "query": {"bool": {"filter": [R, ds("zeek.ssl"), {"terms": {"source.ip": iot_ips}}]}},
                           "aggs": {"s": {"terms": {"field": "source.ip", "size": len(iot_ips)},
                                          "aggs": {"n": {"terms": {"field": "ssl.server_name", "size": 100}}}}}})
    for b in buckets(r["aggregations"]["s"]):
        out[b["key"]]["sni"] = {x["key"]: x["doc_count"] for x in buckets(b["n"])}
    return dict(out)


# ----------------------------------------------------------------------------- files & software
RISKY_MIME = ["application/x-dosexec", "application/x-executable", "application/x-elf", "application/x-mach-o-executable",
              "application/x-mach-o", "application/vnd.android.package-archive", "application/x-msi", "application/x-ms-installer",
              "application/x-sh", "text/x-shellscript", "application/x-powershell", "text/x-python", "application/x-python",
              "application/java-archive", "application/x-java-applet", "application/vnd.ms-cab-compressed", "application/zip",
              "application/x-gzip", "application/x-xz", "application/x-7z-compressed", "application/x-rar",
              "application/x-apple-diskimage", "application/x-bzip2", "application/x-tar", "application/vnd.microsoft.portable-executable",
              "application/x-msdownload", "application/hta", "text/vbscript", "application/x-iso9660-image"]
EXEC_MIME = {m for m in RISKY_MIME if not any(k in m for k in ("zip", "gzip", "xz", "7z", "rar", "bzip", "tar", "cab", "iso"))}


def mhr(hash_):
    """Team Cymru Malware Hash Registry via DNS: detection % (0 = not known-bad) or None on lookup failure."""
    if not re.fullmatch(r"[0-9a-fA-F]{32,64}", hash_ or ""):
        return None  # only ever pass a hex digest to dig
    try:
        o = subprocess.run(["dig", "+short", "+time=3", "TXT", f"{hash_}.malware.hash.cymru.com"],
                           capture_output=True, text=True, timeout=10).stdout.strip().strip('"')
        return int(o.split()[1]) if o else 0
    except Exception:
        return None


def mhr_many(hashes):
    cache_p = os.path.join(INTEL, "mhr_cache.json")
    try:
        cache = json.load(open(cache_p))
    except Exception:
        cache = {}
    todo = [h for h in hashes if h not in cache]
    with cf.ThreadPoolExecutor(8) as ex:
        for h, v in zip(todo, ex.map(mhr, todo)):
            if v is not None:
                cache[h] = v
    os.makedirs(INTEL, exist_ok=True)
    json.dump(cache, open(cache_p, "w"))
    return {h: cache.get(h) for h in hashes}


def files_software(hours=24):
    q, ds, buckets = _ctx()
    R = rng(hours)
    r = q("logs-zeek-so", {"size": 500, "sort": [{"@timestamp": "desc"}],
                           "_source": ["@timestamp", "file", "hash", "source.ip", "destination.ip", "destination.port", "network.community_id"],
                           "query": {"bool": {"filter": [R, ds("zeek.file"), {"terms": {"file.mime_type": RISKY_MIME}}]}}})
    files, cids = [], set()
    for h in r["hits"]["hits"]:
        s = h["_source"]
        f = s.get("file") or {}
        src, dst = (s.get("source") or {}).get("ip"), (s.get("destination") or {}).get("ip")
        recv, sender = (dst, src) if f.get("is_orig") else (src, dst)
        hs = s.get("hash") or {}
        files.append({"time": s["@timestamp"], "mime": f.get("mime_type"), "size": (f.get("bytes") or {}).get("total") or (f.get("bytes") or {}).get("seen"),
                      "receiver": recv, "sender": sender, "port": (s.get("destination") or {}).get("port"),
                      "proto": f.get("source"), "md5": hs.get("md5"), "sha1": hs.get("sha1"), "sha256": hs.get("sha256"),
                      "cid": (s.get("network") or {}).get("community_id"), "exec": f.get("mime_type") in EXEC_MIME})
        if files[-1]["cid"]:
            cids.add(files[-1]["cid"])
    if cids:
        h = q("logs-zeek-so", {"size": 1000, "_source": ["network.community_id", "http.virtual_host", "http.uri", "http.useragent"],
                               "query": {"bool": {"filter": [R, ds("zeek.http"), {"terms": {"network.community_id": list(cids)}}]}}})
        meta = {}
        for x in h["hits"]["hits"]:
            s = x["_source"]
            meta[s["network"]["community_id"]] = s.get("http") or {}
        for f in files:
            m = meta.get(f["cid"], {})
            f.update({"host": m.get("virtual_host", ""), "uri": (m.get("uri") or "")[:120], "ua": (m.get("useragent") or "")[:80]})
    # hash reputation (unique, capped)
    hashes = list({f["md5"] or f["sha1"] for f in files if f["md5"] or f["sha1"]})[:200]
    rep = mhr_many(hashes)
    for f in files:
        f["mhr_detect_pct"] = rep.get(f["md5"] or f["sha1"])
    # dedupe identical (receiver, hash/host+uri)
    seen, uniq = set(), []
    for f in files:
        k = (f["receiver"], f["md5"] or f.get("host", "") + f.get("uri", ""), f["mime"])
        if k not in seen:
            seen.add(k)
            uniq.append(f)
    r = q("logs-zeek-so", {"size": 500, "_source": ["source.ip", "software"],
                           "query": {"bool": {"filter": [rng(max(hours, 24)), ds("zeek.software")]}}})
    sw = {}
    for h in r["hits"]["hits"]:
        s = h["_source"]
        so = s.get("software") or {}
        ip = (s.get("source") or {}).get("ip")
        v = so.get("version") or {}
        key = (ip, so.get("name"))
        sw[key] = {"ip": ip, "name": so.get("name"), "type": so.get("type"),
                   "version": ".".join(str(v[k]) for k in ("major", "minor", "minor2") if v.get(k) is not None),
                   "unparsed": (v.get("unparsed") or "")[:90]}
    r = q("logs-zeek-so", {"size": 0, "query": {"bool": {"filter": [R, ds("zeek.pe")]}}, "aggs": {"n": {"value_count": {"field": "@timestamp"}}}})
    return {"files": uniq, "software": list(sw.values()), "pe_count": r["aggregations"]["n"]["value"]}


def outdated(sw):
    """Very small rule set for clearly old/insecure software seen on the wire."""
    n, v = (sw.get("name") or ""), sw.get("version") or ""
    try:
        major = int(v.split(".")[0]) if v else None
    except ValueError:
        major = None
    if n == "OpenSSH" and major is not None and major < 9:
        return "OpenSSH < 9 (multiple CVEs, e.g. regreSSHion on 8.5-9.7)"
    if n == "MSIE":
        return "Internet Explorer user agent (EOL)"
    if n == "Chrome" and major is not None and major < 120:
        return f"Chrome {major} is far behind current"
    if n.startswith("Firefox") and major is not None and major < 115:
        return f"Firefox {major} is out of support"
    return None


# ----------------------------------------------------------------------------- TLS
WEAK_SIG = ("sha1", "md5", "md2")


def _cert_flags(c, now):
    f = []
    nb, na = c.get("not_before") or 0, c.get("not_after") or 0
    if na and na < now:
        f.append("expired")
    elif na and na - now < 30 * 86400:
        f.append("expiring <30d")
    if nb and nb > now:
        f.append("not yet valid")
    if c.get("subject") and c.get("subject") == c.get("issuer"):
        f.append("self-signed")
    if c.get("key_type") == "rsa" and (c.get("key_length") or 0) < 2048:
        f.append(f"weak key (RSA {c.get('key_length')})")
    if any(w in (c.get("sig_alg") or "").lower() for w in WEAK_SIG):
        f.append("weak signature (" + c["sig_alg"] + ")")
    if nb and na and (na - nb) / 86400 > 398 and not c.get("ca"):
        f.append("long validity")
    return f


def _name_match(pattern, name):
    pattern, name = (pattern or "").lower(), (name or "").lower()
    if pattern == name:
        return True
    return pattern.startswith("*.") and name.endswith(pattern[1:]) and name.count(".") == pattern.count(".")


def tls_profile(hours=24):
    q, ds, buckets = _ctx()
    R = rng(hours)
    feeds = load_feeds()
    r = q("logs-zeek-so", {"size": 0, "query": {"bool": {"filter": [R, ds("zeek.ssl"), {"term": {"source.ip": SITE.get("internal_cidr")}}]}},
                           "aggs": {"s": {"terms": {"field": "source.ip", "size": 300},
                                          "aggs": {"ja4": {"terms": {"field": "hash.ja4", "size": 40}},
                                                   "ja3": {"terms": {"field": "hash.ja3", "size": 40}},
                                                   "ver": {"terms": {"field": "ssl.version", "size": 6}},
                                                   "bad": {"filter": {"bool": {"must": [{"exists": {"field": "ssl.validation_status"}}],
                                                                               "must_not": [{"term": {"ssl.validation_status": "ok"}}]}},
                                                           "aggs": {"st": {"multi_terms": {"terms": [{"field": "ssl.validation_status"},
                                                                                                     {"field": "destination.ip"}], "size": 10},
                                                                           "aggs": {"n": {"terms": {"field": "ssl.server_name", "size": 1}}}}}}}},
                                    "ja3": {"terms": {"field": "hash.ja3", "size": 10000},
                                            "aggs": {"s": {"terms": {"field": "source.ip", "size": 8}},
                                                     "nsrc": {"cardinality": {"field": "source.ip"}},
                                                     "n": {"terms": {"field": "ssl.server_name", "size": 6}},
                                                     "d": {"terms": {"field": "destination.ip", "size": 3}},
                                                     "ja4": {"terms": {"field": "hash.ja4", "size": 2}},
                                                     "first": {"min": {"field": "@timestamp"}}, "last": {"max": {"field": "@timestamp"}}}},
                                    "ja3s": {"terms": {"field": "hash.ja3s", "size": 500},
                                             "aggs": {"n": {"terms": {"field": "ssl.server_name", "size": 6}},
                                                      "ncli": {"cardinality": {"field": "source.ip"}},
                                                      "nsrv": {"cardinality": {"field": "destination.ip"}},
                                                      "ja3": {"terms": {"field": "hash.ja3", "size": 4}},
                                                      "ver": {"terms": {"field": "ssl.version", "size": 2}},
                                                      "cip": {"terms": {"field": "ssl.cipher", "size": 2}}}},
                                    "sni": {"terms": {"field": "ssl.server_name", "size": 4000},
                                            "aggs": {"s": {"terms": {"field": "source.ip", "size": 6}}}},
                                    "val": {"filter": {"bool": {"must": [{"exists": {"field": "ssl.validation_status"}}],
                                                                "must_not": [{"term": {"ssl.validation_status": "ok"}}]}},
                                            "aggs": {"m": {"multi_terms": {"terms": [{"field": "ssl.validation_status"}, {"field": "ssl.server_name", "missing": ""},
                                                                                     {"field": "destination.ip"}], "size": 300},
                                                           "aggs": {"s": {"terms": {"field": "source.ip", "size": 6}}}}}},
                                    "ver": {"terms": {"field": "ssl.version", "size": 10}},
                                    "cipher": {"terms": {"field": "ssl.cipher", "size": 25}}}})
    a = r["aggregations"]
    dev = {}
    for b in buckets(a["s"]):
        bad = []
        for x in buckets(b["bad"]["st"]):
            st, dst = x["key"]
            bad.append({"status": st, "dst": dst, "count": x["doc_count"],
                        "sni": (buckets(x["n"]) or [{"key": ""}])[0]["key"], "internal": is_internal(dst)})
        dev[b["key"]] = {"ja4": {x["key"]: x["doc_count"] for x in buckets(b["ja4"])},
                         "ja3": {x["key"]: x["doc_count"] for x in buckets(b["ja3"])},
                         "versions": {x["key"]: x["doc_count"] for x in buckets(b["ver"])}, "bad_certs": bad}
    bad_ja3, ja3_list = [], []
    for b in buckets(a["ja3"]):
        e = {"ja3": b["key"], "count": b["doc_count"], "clients": b["nsrc"]["value"],
             "sources": {s["key"]: s["doc_count"] for s in buckets(b["s"])},
             "servers": [x["key"] for x in buckets(b["n"])], "dsts": [x["key"] for x in buckets(b["d"])],
             "ja4": [x["key"] for x in buckets(b["ja4"])],
             "first": b["first"].get("value_as_string"), "last": b["last"].get("value_as_string")}
        if b["key"] in feeds["ja3"]:
            e["malware"] = feeds["ja3"][b["key"]]
            bad_ja3.append(e)
        ja3_list.append(e)
    # keep the payload bounded: busiest + rarest (single-client) fingerprints + all malicious
    ja3_list.sort(key=lambda e: -e["count"])
    keep = ja3_list[:300] + [e for e in ja3_list[300:] if e["clients"] == 1][:300] + [e for e in ja3_list[300:] if e.get("malware")]
    ja3s = [{"ja3s": b["key"], "count": b["doc_count"], "clients": b["ncli"]["value"], "servers": b["nsrv"]["value"],
             "sni": [x["key"] for x in buckets(b["n"])], "ja3": [x["key"] for x in buckets(b["ja3"])],
             "versions": [x["key"] for x in buckets(b["ver"])], "ciphers": [x["key"] for x in buckets(b["cip"])]}
            for b in buckets(a["ja3s"])]
    sni_clients = {b["key"]: {s["key"]: s["doc_count"] for s in buckets(b["s"])} for b in buckets(a["sni"])}
    validation = []
    for b in buckets(a["val"]["m"]):
        st, sni, dst = b["key"]
        validation.append({"status": st, "sni": sni, "dst": dst, "count": b["doc_count"], "internal": is_internal(dst),
                           "clients": {s["key"]: s["doc_count"] for s in buckets(b["s"])}})
    # --- certificates seen (zeek x509)
    r = q("logs-zeek-so", {"size": 0, "query": {"bool": {"filter": [R, ds("zeek.x509")]}},
                           "aggs": {"c": {"terms": {"field": "hash.sha256", "size": 1500},
                                          "aggs": {"t": {"top_hits": {"size": 1, "sort": [{"@timestamp": "desc"}],
                                                                      "_source": ["x509", "@timestamp"]}},
                                                   "first": {"min": {"field": "@timestamp"}}}}}})
    now = time.time()
    certs = []
    for b in buckets(r["aggregations"]["c"]):
        hit = b["t"]["hits"]["hits"][0]["_source"]
        x = hit.get("x509") or {}
        c = x.get("certificate") or {}
        cert = {"sha256": b["key"], "count": b["doc_count"], "subject": c.get("subject", ""), "issuer": c.get("issuer", ""),
                "serial": c.get("serial", ""), "not_before": c.get("not_valid_before"), "not_after": c.get("not_valid_after"),
                "key_type": (c.get("key") or {}).get("type"), "key_length": (c.get("key") or {}).get("length"),
                "sig_alg": c.get("signing_algorithm", ""), "san_dns": (x.get("san_dns") or [])[:20],
                "ca": bool((x.get("basic_constraints") or {}).get("ca")), "last": hit.get("@timestamp"),
                "first": b["first"].get("value_as_string")}
        cert["flags"] = _cert_flags(cert, now)
        nb, na = cert["not_before"] or 0, cert["not_after"] or 0
        cert["validity_days"] = int((na - nb) / 86400) if nb and na else None
        cert["days_left"] = int((na - now) / 86400) if na else None
        cn = next((p[3:] for p in cert["subject"].split(",") if p.startswith("CN=")), "")
        names = set(cert["san_dns"]) | ({cn} if cn else set())
        clients, snis = Counter(), []
        for sni, cl in sni_clients.items():
            if any(_name_match(n, sni) for n in names):
                snis.append(sni)
                clients.update(cl)
        cert["sni"] = snis[:10]
        cert["clients"] = dict(clients.most_common(8))
        certs.append(cert)
    certs.sort(key=lambda c: (-len(c["flags"]), -c["count"]))
    return {"devices": dev, "malicious_ja3": bad_ja3, "distinct_ja3": len(ja3_list), "ja3": keep, "ja3s": ja3s,
            "distinct_ja3s": len(ja3s), "validation": validation, "certs": certs,
            "versions": {b["key"]: b["doc_count"] for b in buckets(a["ver"])},
            "ciphers": {b["key"]: b["doc_count"] for b in buckets(a["cipher"])}}
