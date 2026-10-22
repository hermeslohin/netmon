#!/usr/bin/python3
"""Compare a collect.py snapshot against the per-device baseline, then fold it into the baseline.

Usage: analyze.py [snapshot.json]   (default: newest in data/)
       analyze.py RANGE.json --readonly   a dashboard time range (collect.py --start/--end): same findings against
                                          the baseline, volumes scaled to 24 h, nothing written to the store
Writes data/<snapshot>.analysis.json and appends a compact day record to the history table (store.py / SQLite).

Baseline model (per device, keyed by MAC when known, else IP), rolling 30 snapshots:
  bytes total/sent/recv, conns, external peers, rejected conns, DNS queries + NXDOMAIN,
  active hours, countries, ASNs, external dst ports, top DNS domains, hourly byte shape.
Deviation rules need >= MIN_DAYS of history; before that the run only seeds the baseline.
"""
import datetime as dt, glob, json, os, re as _re, statistics, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import site_cfg as SITE  # noqa: E402  network-specific values live in site.json (git-ignored)

NM = os.environ.get("NETMON_DIR") or os.path.dirname(os.path.abspath(__file__))
HIST = os.path.join(NM, "baseline", "history.jsonl")  # legacy, superseded by store.py
REGISTRY = os.path.join(NM, "baseline", "devices_seen.json")  # legacy, superseded by store.py
BENIGN = os.path.join(NM, "known_benign.json")
MIN_DAYS = 3
KEEP = 30
FOLD_MIN_HOURS = 23  # report runs several times a day (12h default); only a snapshot >= 23h after the last baseline record is folded in
MB = 1e6


def dev_key(ip, d):
    return d.get("mac") or ip


def compact(ip, d):
    dns = d.get("dns") or {}
    hb = d.get("hourly_bytes") or {}
    return {
        "ip": ip, "name": d.get("name"), "known": d.get("known", False),
        "total": d.get("total_bytes", 0), "sent": d.get("total_sent", 0), "recv": d.get("total_recv", 0),
        "conns": d.get("orig_conns", 0) + d.get("resp_conns", 0), "ext_peers": d.get("ext_peers", 0),
        "ext_out": d.get("ext_out_bytes", 0), "rejected": d.get("rejected_conns", 0),
        "dns_q": dns.get("queries", 0), "nx": dns.get("nxdomain", 0),
        "inbound_ext_sources": d.get("inbound_ext_sources", 0),
        "active_hours": sorted(h for h, c in (d.get("hourly_conns") or {}).items() if c),
        "hourly": {h: round(v) for h, v in hb.items()},
        "countries": {k: round(v) for k, v in (d.get("countries") or {}).items()},
        "asns": {k: round(v) for k, v in (d.get("asns") or {}).items()},
        "ext_dports": d.get("ext_dports") or {},
        "services": {k: v["conns"] for k, v in (d.get("services_out") or {}).items()},
        "dports": {k: v["conns"] for k, v in (d.get("dports_out") or {}).items()},
        "port_svc": {k: v.get("service", "") for k, v in (d.get("dports_out") or {}).items()},
        "served": {k: {"conns": v["conns"], "sources": v["sources"], "ext": v.get("ext_conns", 0), "svc": v.get("service", "")}
                   for k, v in (d.get("served_ports") or {}).items()},
        "domains": list((dns.get("top_domains") or {}).keys()),
        "dns": {"unique_names": dns.get("unique_names", 0), "unique_domains": dns.get("unique_domains", 0),
                "qtypes": dns.get("qtypes") or {}, "tlds": dns.get("tlds") or {}, "top": dns.get("top_domains") or {},
                "resolvers": list((dns.get("resolvers") or {}).keys()), "long_names": dns.get("long_names", 0),
                "avg_len": dns.get("avg_len", 0), "mdns": dns.get("mdns") or 0, "doh": list((dns.get("doh") or {}).keys()),
                "dot": ((d.get("dports_out") or {}).get("853/tcp") or {}).get("conns", 0)},
    }


def load_history():
    import store  # SQLite (store.py); HIST/REGISTRY JSON files are legacy, kept only as pre-migration backups
    return store.history_load()


def med(xs):
    return statistics.median(xs) if xs else 0


def mad(xs):
    m = med(xs)
    return med([abs(x - m) for x in xs]) if xs else 0


P2P_SVC = {"spicy_stun", "dtls", "spicy_tailscale", "spicy_wireguard", "dns"}


def ephemeral(port_key, svc=""):
    """Random high UDP ports (Tailscale/WebRTC/STUN peers, mDNS replies) change daily; never alarm on them as 'new'."""
    num, _, tr = port_key.partition("/")
    return (tr == "udp" and num.isdigit() and int(num) >= 32768) or svc in P2P_SVC


RISKY_QTYPES = {"TXT", "NULL", "ANY", "AXFR", "IXFR", "MX", "KEY"}


def tunnel_level(t):
    """suspect / watch / None for a dns_tunnel candidate from collect.py."""
    if t["score"] >= 5 and t["unique_subdomains"] >= 150:
        return "suspect"
    if t["score"] >= 3 and t["unique_subdomains"] >= 50 and t["sample_unique_ratio"] >= 0.5:
        return "watch"
    return None


READONLY = "--readonly" in sys.argv
SCALE = 1.0  # time range of N hours: compare (value / (N/24)) with the 24 h baseline records


UPLOAD_SPIKE = {"min_mb": 25, "times_normal": 3, "mad_factor": 6, "min_days": 3, "severity": "high"}  # defaults; policy "upload_spike" overrides


def upload_cfg():
    """policy.upload_spike merged over the defaults (bad values fall back to the default)."""
    try:
        import extras
        p = extras.load_policy().get("upload_spike") or {}
    except Exception:  # noqa: BLE001
        p = {}
    out = dict(UPLOAD_SPIKE)
    for k, v in p.items():
        if k in out and not k.startswith("_"):
            try:
                out[k] = v if k == "severity" else float(v)
            except (TypeError, ValueError):
                pass
    if out["severity"] not in ("high", "medium", "low", "off"):
        out["severity"] = "high"
    return out


def spike(today, hist, floor, card=False, mult=3, madf=6, min_days=None):
    """True when today is far above the device's own normal and above an absolute floor.
    Time range: counts are scaled to 24 h; distinct counts (card=True) don't grow linearly, so they are only scaled
    down for ranges over 24 h (a 6 h range is compared as is - conservative either way)."""
    today = today / (max(SCALE, 1.0) if card else SCALE)
    if today < floor or len(hist) < (MIN_DAYS if min_days is None else min_days):
        return False
    m, d = med(hist), mad(hist)
    return today > max(mult * m, m + madf * d, floor)


def enrich_today(snap, today, ip2key):
    """Attach per-device extras (JA4, software, IoT destinations, internal peers, beacons) for baselining."""
    tls = (snap.get("tls") or {}).get("devices", {})
    for ip, d in tls.items():
        if ip in ip2key:
            today[ip2key[ip]]["ja4"] = list(d.get("ja4", {}))
    for s in (snap.get("files") or {}).get("software", []):
        if s["ip"] in ip2key:
            today[ip2key[s["ip"]]].setdefault("software", []).append(s["name"])
    for ip, d in (snap.get("iot_dest") or {}).items():
        if ip in ip2key:
            today[ip2key[ip]]["iot"] = {"domains": list(d.get("domains", {})), "asns": d.get("asns", {}),
                                        "raw_ips": d.get("no_asn_ips", [])}
    for f in (snap.get("internal") or {}).get("flows", []):
        if f["src"] in ip2key and f["answered"] >= 3:
            today[ip2key[f["src"]]].setdefault("internal_peers", []).append(f"{f['dst']}:{f['port']}/{f['proto']}")
    for c in (snap.get("beacons") or {}).get("candidates", []):
        if c["src"] in ip2key:
            today[ip2key[c["src"]]].setdefault("beacons", []).append(beacon_id(c))


def beacon_id(c):
    return f"{c.get('domain') or c.get('asn') or c['dst']}:{c['port']}"


def extras_findings(snap, today, ip2key, history, days, benign, add):
    """Threat intel, beaconing, segmentation, IoT allowlists, files/software, TLS."""
    sys.path.insert(0, NM)
    import extras
    pol = extras.load_policy()
    cls = pol.get("device_classes", {})
    devs = snap["devices"]
    name = lambda ip: (devs.get(ip) or {}).get("name") or (benign.get("names") or {}).get(ip) or ip
    klass = lambda ip: cls.get((devs.get(ip) or {}).get("mac") or "", cls.get(ip, "unclassified"))
    key = lambda ip: ip2key.get(ip, ip)
    ready = days >= MIN_DAYS
    past_of = lambda k: [h["devices"][k] for h in history if k in h.get("devices", {})]

    # --- threat intel (absolute) ---
    ti = snap.get("threat_intel") or {}
    for h in ti.get("domain_hits", []):
        for s in h["sources"]:
            add("high", key(s), "ti-domain", f"looked up {h['name']} - listed in {', '.join(h['feeds'])} ({h['sources'][s]}x)")
    for h in ti.get("ip_hits_out", []):
        for s in h["sources"]:
            if h["serious"]:
                add("high" if h["established"] else "medium", key(s), "ti-ip-out",
                    f"connected to {h['ip']} ({h['asn']}) port {h['ports']} - listed in {', '.join(h['feeds'])}; "
                    f"{h['established']} answered conns")
            elif h["established"] and h["bytes"] > 50000:
                add("low", key(s), "ti-ip-out-reputation",
                    f"talked to {h['ip']} ({h['asn']}) on {h['ports']}, an IP on scanner/reputation list {', '.join(h['feeds'])}")
    inb = {}
    for h in ti.get("ip_hits_in", []):
        for t, n in h["targets"].items():
            e = inb.setdefault(t, {"ips": set(), "conns": 0, "ports": set(), "feeds": set(), "bytes": 0})
            e["ips"].add(h["ip"]); e["conns"] += n; e["ports"].update(h["ports"]); e["feeds"].update(h["feeds"]); e["bytes"] += h["bytes"]
    for t, e in inb.items():
        public = extras.zone_role(extras.zone_of(t, pol), pol) == "dmz"
        add("low" if public and e["feeds"] <= {"cins_badguys", "et_compromised"} else "high", key(t), "ti-ip-in",
            f"answered {e['conns']} inbound conns from {len(e['ips'])} listed IPs ({', '.join(sorted(e['feeds']))}) on ports "
            f"{sorted(e['ports'])}, {int(e['bytes'])} bytes total" + (" - internet-exposed service being probed" if public else ""))
    for nd in ti.get("new_domains", []):
        if nd["age_days"] <= 30:
            for s in nd["sources"]:
                sev = "high" if klass(s) in ("iot", "camera") else "medium"
                add(sev, key(s), "newly-registered-domain", f"{nd['domain']} registered {nd['registered']} ({nd['age_days']} days old), {nd['sources'][s]} queries")

    # --- beaconing ---
    bdom = set(benign.get("beacon_domains", []))
    newdom = {n["domain"] for n in ti.get("new_domains", [])}
    tihit = {h["ip"] for h in ti.get("ip_hits_out", []) if h["serious"]}
    for c in (snap.get("beacons") or {}).get("candidates", []):
        k = key(c["src"])
        c_dom = c.get("domain") or ""
        if (c_dom in bdom or c["port"] == 123) and c["dst"] not in tihit:
            continue
        why = []
        if c["dst"] in tihit:
            why.append("destination on threat list")
        if c_dom in newdom:
            why.append("newly registered domain")
        if not c_dom:
            why.append("no DNS name / SNI (raw IP)")
        if c["port"] not in (443, 80, 123, 53, 853, 5223, 5228, 993, 8883):
            why.append(f"unusual port {c['port']}")
        seen = set().union(*[set(p.get("beacons", [])) for p in past_of(k)]) if ready else set()
        desc = (f"beacon to {c.get('name') or c['dst']} ({c.get('asn') or '?'}, {c.get('country') or '?'}) port {c['port']}: "
                f"every ~{c['interval_s']}s +/-{c['jitter_s']}s, {c['conns']} conns over {c['coverage_h']}h (score {c['score']})")
        if why and (c["dst"] in tihit or c_dom in newdom):
            add("high", k, "beacon-suspicious", desc + "; " + ", ".join(why))
        elif ready and beacon_id(c) not in seen:
            add("high" if klass(c["src"]) in ("iot", "camera") and why else "medium", k, "beacon-new",
                desc + ("; " + ", ".join(why) if why else ""))
        elif why and not ready and c["score"] >= 0.85 and not c_dom:
            add("low", k, "beacon-unlabelled", desc + "; " + ", ".join(why))

    # --- internal traffic / segmentation ---
    it = snap.get("internal") or {}
    ip2mac = {ip: d.get("mac") for ip, d in devs.items()}
    viol = extras.policy_violations(it.get("flows", []), ip2mac, pol)
    snap["_violations"] = viol
    for v in viol:
        add(v["severity"], key(v["src"]), "segmentation",
            f"{v['reason']}: -> {name(v['dst'])} ({v['dst']}) {v['port']}/{v['proto']}, {v['conns']} conns ({v['answered']} answered)")
    for s in it.get("scans", []):
        add("high", key(s["src"]), "internal-scan",
            f"{s['failed_conns']} failed conns to {s['hosts']} internal hosts / {s['ports']} ports (top {s['top_ports']})")
    if ready:
        for k, t in today.items():
            seen = set().union(*[set(p.get("internal_peers", [])) for p in past_of(k)])
            new = [x for x in t.get("internal_peers", []) if x not in seen and not x.split(":")[0].endswith(".1")]
            if new and past_of(k):
                add("low", k, "new-internal-peer", f"{len(new)} new internal destinations: {', '.join(new[:5])}")

    # --- IoT destination allowlist ---
    if ready:
        for k, t in today.items():
            if "iot" not in t:
                continue
            past = [p["iot"] for p in past_of(k) if p.get("iot")]
            if not past:
                continue
            sd = set().union(*[set(p["domains"]) for p in past])
            sa = set().union(*[set(p["asns"]) for p in past])
            sr = set().union(*[set(p.get("raw_ips", [])) for p in past])
            nd = [x for x in t["iot"]["domains"] if x not in sd]
            na = [x for x, b in t["iot"]["asns"].items() if x not in sa and b > 200000]
            nr = [x for x in t["iot"]["raw_ips"] if x not in sr]
            if nd:
                add("medium", k, "iot-new-domain", f"contacted domains outside its learned allowlist: {', '.join(nd[:6])}")
            if na:
                add("medium", k, "iot-new-network", f"sent data to new networks: {', '.join(na[:4])}")
            if nr:
                add("low", k, "iot-raw-ip", f"connected to IPs with no ASN/geo: {', '.join(nr[:4])}")

    # --- files & software ---
    fs = snap.get("files") or {}
    for f in fs.get("files", []):
        if f.get("mhr_detect_pct"):
            add("high", key(f["receiver"]), "malware-hash",
                f"received {f['mime']} from {f.get('host') or f['sender']} - {f['mhr_detect_pct']}% AV detection (Team Cymru MHR), md5 {f['md5']}")
        elif f["exec"] and klass(f["receiver"]) in ("iot", "camera", "media", "game"):
            add("high", key(f["receiver"]), "iot-executable", f"{klass(f['receiver'])} device downloaded {f['mime']} from {f.get('host') or f['sender']}{f.get('uri','')}")
    for s in fs.get("software", []):
        o = extras.outdated(s)
        if o:
            add("low", key(s["ip"]), "outdated-software", f"{s['name']} {s['version']}: {o}")
    if ready:
        for k, t in today.items():
            seen = set().union(*[set(p.get("software", [])) for p in past_of(k)])
            new = [x for x in t.get("software", []) if x not in seen]
            if new and past_of(k):
                add("low", k, "new-software", f"new software seen on the wire: {', '.join(new[:5])}")

    # --- TLS ---
    tls = snap.get("tls") or {}
    ti_dsts = {h["ip"] for h in ti.get("ip_hits_out", []) if h["serious"]}
    for j in tls.get("malicious_ja3", []):
        corroborated = bool(set(j.get("dsts", [])) & ti_dsts)
        for s in j["sources"]:
            # JA3 alone is low-fidelity (common TLS stacks collide with old malware entries); escalate only with corroboration
            add("high" if corroborated else "medium", key(s), "malicious-ja3",
                f"TLS client fingerprint {j['ja3']} matches {j['malware']} (abuse.ch SSLBL) - {j['count']} sessions to "
                f"{', '.join(j.get('servers') or j.get('dsts', []))}" + ("" if corroborated else "; destination not on any threat list, JA3 collisions are common"))
    for ip, d in tls.get("devices", {}).items():
        legacy = {v: n for v, n in d.get("versions", {}).items() if v in ("TLSv10", "TLSv11", "SSLv3", "SSLv2")}
        if legacy:
            add("low", key(ip), "legacy-tls", f"uses {', '.join(f'{v} x{n}' for v, n in legacy.items())} (broken/deprecated)")
        exp = [b for b in d.get("bad_certs", []) if "expired" in b["status"] and not b["internal"]]
        for b in exp:
            add("low", key(ip), "expired-cert", f"server {b['sni'] or b['dst']} presented an expired certificate")
    if ready:
        for k, t in today.items():
            pst = past_of(k)
            seen = set().union(*[set(p.get("ja4", [])) for p in pst])
            new = [x for x in t.get("ja4", []) if x not in seen]
            if new and pst and any(p.get("ja4") for p in pst):
                kc = klass(t["ip"])
                if kc in ("iot", "camera", "media", "game"):
                    add("medium", k, "new-tls-client", f"{kc} device used {len(new)} new TLS client fingerprint(s) (JA4 {new[0]}) - new software or tampering?")
                elif len(new) >= 3:
                    add("low", k, "new-tls-client", f"{len(new)} new TLS client fingerprints (new apps/OS update)")


def main():
    global SCALE
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    import store
    snap_path = args[0] if args else sorted(
        p for p in store.jglob(os.path.join(NM, "data"), "*.json") if os.path.basename(p).count(".") == 1)[-1]
    snap = store.jload(snap_path)
    if snap is None:
        raise SystemExit(f"no such snapshot: {snap_path}")
    if READONLY or float(snap.get("hours") or 24) < 24:  # a time range, or a research run with a short lookback window
        SCALE = max(float(snap.get("hours") or 24) / 24, 1 / 24)
    benign = store.jload(BENIGN) or {"signatures": {}, "devices": {}}
    history = load_history()
    days = len(history)

    today = {}
    for ip, d in snap["devices"].items():
        if not SITE.is_internal(ip) or ip.endswith(".255"):
            continue
        today[dev_key(ip, d)] = compact(ip, d)
    ip2key = {t["ip"]: k for k, t in today.items()}
    enrich_today(snap, today, ip2key)

    findings = []

    def add(sev, key, kind, msg):
        findings.append({"severity": sev, "device": key, "name": (today.get(key) or {}).get("name") or key,
                         "kind": kind, "detail": msg})

    extras_findings(snap, today, ip2key, history, days, benign, add)

    # --- new-device alarms raised by the watcher (DHCP MACs in neither inventory nor baseline): also baseline findings,
    # so they can be checked off, correlated and reviewed like the rest (they used to exist only in the alert feed)
    try:
        import time as _t
        sys.path.insert(0, NM)
        import store as _store
        _end = dt.datetime.fromisoformat(snap["generated"].replace("Z", "+00:00")).timestamp()
        _beg = _end - float(snap.get("hours") or 24) * 3600
        _seen = set()
        for _r in _store.connect().execute("SELECT key, text, ts FROM alerts WHERE key LIKE 'newmac|%' AND ts BETWEEN ? AND ? ORDER BY ts",
                                           (_beg, _end + 600)):
            _mac = _r[0].split("|", 1)[1].lower()
            if _mac in _seen:
                continue
            _seen.add(_mac)
            _m = _re.search(r"host (\S+) got (\S+)", _r[1])
            add("medium", _mac, "new-device-dhcp",
                f"MAC {_mac} joined via DHCP" + (f" (host {_m.group(1)}, got {_m.group(2)})" if _m else "") + " - not in inventory or baseline")
    except Exception as _e:  # noqa: BLE001
        print(f"(new-device alarms not added to findings: {_e})", file=sys.stderr)

    # --- per-device deviation vs baseline ---
    UP = upload_cfg()
    for key, t in today.items():
        past = [h["devices"][key] for h in history if key in h.get("devices", {})]
        if not past:  # brand-new devices are reported via the registry below
            continue
        if spike(t["total"], [p["total"] for p in past], 50 * MB):
            add("medium", key, "volume-spike",
                f"total {t['total']/MB:.0f} MB vs normal {med([p['total'] for p in past])/MB:.0f} MB")
        if UP["severity"] != "off" and spike(t["sent"], [p["sent"] for p in past], UP["min_mb"] * MB, mult=UP["times_normal"], madf=UP["mad_factor"], min_days=UP["min_days"]):
            add(UP["severity"], key, "upload-spike",
                f"sent {t['sent']/MB:.0f} MB vs normal {med([p['sent'] for p in past])/MB:.0f} MB (possible exfil/backup)")
        if spike(t["ext_peers"], [p["ext_peers"] for p in past], 50, card=True):
            add("medium", key, "fan-out", f"{t['ext_peers']} external peers vs normal {med([p['ext_peers'] for p in past]):.0f}")
        if spike(t["rejected"], [p["rejected"] for p in past], 500):
            add("medium", key, "failed-conns", f"{t['rejected']} rejected/unanswered conns vs normal {med([p['rejected'] for p in past]):.0f} (scanning?)")
        if spike(t["nx"], [p["nx"] for p in past], 200):
            add("medium", key, "nxdomain-spike", f"{t['nx']} NXDOMAIN vs normal {med([p['nx'] for p in past]):.0f} (DGA/misconfig?)")
        if spike(t["inbound_ext_sources"], [p.get("inbound_ext_sources", 0) for p in past], 5, card=True):
            add("high", key, "inbound-exposure", f"{t['inbound_ext_sources']} external sources connected in vs normal {med([p.get('inbound_ext_sources',0) for p in past]):.0f}")
        if len(past) >= MIN_DAYS:
            seen_c = set().union(*[p["countries"] for p in past])
            for c, b in t["countries"].items():
                if c not in seen_c and b > 1 * MB:
                    add("medium", key, "new-country", f"{b/MB:.1f} MB to {c}, never seen for this device")
            seen_a = set().union(*[p["asns"] for p in past])
            for a, b in t["asns"].items():
                if a not in seen_a and b > 20 * MB:
                    add("low", key, "new-asn", f"{b/MB:.0f} MB to new network '{a}'")
            # --- port & service habits ---
            seen_p = set().union(*[p.get("dports", {}) for p in past]) | {f"{x}/tcp" for p in past for x in p["ext_dports"]}
            for port, n in t["dports"].items():
                if port not in seen_p and n >= 20 and not ephemeral(port, t["port_svc"].get(port, "")):
                    svc = t["port_svc"].get(port) or "unidentified"
                    add("medium", key, "new-port", f"{n} conns to port {port} ({svc}), never used by this device before")
                elif port in seen_p:
                    hist_n = [p.get("dports", {}).get(port, 0) for p in past]
                    if spike(n, hist_n, 500):
                        add("low", key, "port-spike", f"port {port}: {n} conns vs normal {med(hist_n):.0f}")
            seen_s = set().union(*[p.get("services", {}) for p in past])
            for svc, n in t["services"].items():
                if svc not in seen_s and n >= 10 and svc != "unidentified":
                    add("medium", key, "new-service", f"started using {svc} ({n} conns)")
            tot = sum(t["services"].values()) or 1
            for svc, n in t["services"].items():
                shares = [p.get("services", {}).get(svc, 0) / (sum(p.get("services", {}).values()) or 1) for p in past]
                if abs(n / tot - med(shares)) > 0.30 and n >= 200:
                    add("low", key, "service-mix", f"{svc} is {100*n/tot:.0f}% of conns vs normal {100*med(shares):.0f}%")
            seen_srv = set().union(*[p.get("served", {}) for p in past])
            for port, v in t["served"].items():
                if port not in seen_srv and v["conns"] >= 3 and not ephemeral(port, v.get("svc", "")):
                    sev = "high" if v["ext"] else "medium"
                    add(sev, key, "new-listening-port",
                        f"now answering on {port} ({v['conns']} conns from {v['sources']} sources"
                        + (f", {v['ext']} from the Internet)" if v["ext"] else ")"))
            # --- DNS habits ---
            pd = [p.get("dns") or {} for p in past if p.get("dns")]
            if pd:
                td = t["dns"]
                if spike(t["dns_q"], [p["dns_q"] for p in past], 2000):
                    add("medium", key, "dns-volume", f"{t['dns_q']:,} DNS queries vs normal {med([p['dns_q'] for p in past]):,.0f}")
                if spike(td["unique_names"], [x["unique_names"] for x in pd], 300, card=True):
                    add("medium", key, "dns-unique-names",
                        f"{td['unique_names']:,} distinct names looked up vs normal {med([x['unique_names'] for x in pd]):,.0f} (DGA/scanning?)")
                if spike(td["long_names"], [x["long_names"] for x in pd], 100):
                    add("medium", key, "dns-long-names", f"{td['long_names']:,} queries >= 60 chars vs normal {med([x['long_names'] for x in pd]):,.0f}")
                seen_qt = set().union(*[x["qtypes"] for x in pd])
                tq = sum(td["qtypes"].values()) or 1
                for qt, n in td["qtypes"].items():
                    if qt not in seen_qt and n >= 10:
                        add("medium" if qt in RISKY_QTYPES else "low", key, "dns-new-qtype", f"started querying {qt} records ({n}x)")
                    shares = [x["qtypes"].get(qt, 0) / (sum(x["qtypes"].values()) or 1) for x in pd]
                    if qt in seen_qt and n >= 200 and abs(n / tq - med(shares)) > 0.30:
                        add("medium" if qt in RISKY_QTYPES else "low", key, "dns-qtype-mix", f"{qt} is {100*n/tq:.0f}% of queries vs normal {100*med(shares):.0f}%")
                seen_tld = set().union(*[x["tlds"] for x in pd])
                for tld, n in td["tlds"].items():
                    if tld not in seen_tld and n >= 20:
                        add("low", key, "dns-new-tld", f"{n} queries in .{tld}, a TLD this device never used")
                seen_dom = set().union(*[x["top"] for x in pd])
                for dom, n in td["top"].items():
                    if dom not in seen_dom and n >= max(200, 0.05 * t["dns_q"]):
                        add("medium", key, "dns-new-heavy-domain", f"{n:,} queries to {dom}, never a regular domain for this device")
                seen_res = set().union(*[x["resolvers"] for x in pd])
                for res in td["resolvers"]:
                    if res not in seen_res:
                        ext = not (SITE.is_internal(res) or res.startswith(("10.", "192.168.", "172.16.")))
                        add("high" if ext else "medium", key, "dns-new-resolver",
                            f"started using resolver {res}" + (" (external - bypasses local DNS)" if ext else ""))
                if td["dot"] >= 5 and not any(x.get("dot") for x in pd):
                    add("medium", key, "dns-dot", f"started DNS-over-TLS (853), {td['dot']} conns - lookups now hidden from Zeek")
                seen_doh = set().union(*[x["doh"] for x in pd])
                for s in td["doh"]:
                    if s not in seen_doh:
                        add("medium", key, "dns-doh", f"started DNS-over-HTTPS via {s} (hidden from DNS logging)")
            seen_h = set().union(*[p["active_hours"] for p in past])
            odd = [h for h in t["active_hours"] if h not in seen_h]
            if odd and len(seen_h) <= 18:  # only meaningful for devices with a daily rhythm
                add("low", key, "odd-hours", f"active at unusual UTC hours {odd}")

    # --- devices that went silent (not for time ranges under 24 h: many devices are idle for hours) ---
    if days >= MIN_DAYS and SCALE >= 1:
        for key in set().union(*[h["devices"].keys() for h in history]):
            seen = sum(1 for h in history if key in h["devices"])
            if key not in today and seen / days >= 0.8:
                last = next(h["devices"][key] for h in reversed(history) if key in h["devices"])
                add("low", key, "silent", f"{last.get('name') or key} ({last['ip']}) normally present, no traffic today")
                findings[-1]["name"] = last.get("name") or key

    # --- alert signatures vs baseline ---
    sig_today = {s["name"]: s["count"] for s in snap["alerts"]["signatures"]}
    for s in snap["alerts"]["signatures"]:
        past = [h["signatures"].get(s["name"], 0) for h in history]
        if days >= MIN_DAYS and not any(past):
            add("high" if s["severity"] <= 2 else "low", "-", "new-signature",
                f"first time seen: '{s['name']}' x{s['count']} from {list(s['src'])[:3]}")
        elif spike(s["count"], past, 50):
            add("medium", "-", "signature-spike", f"'{s['name']}' x{s['count']} vs normal {med(past):.0f}")

    # --- device registry: first/last seen ever (Zeek itself only retains ~2 days) ---
    import store
    reg = store.registry_load()
    seeding = not reg
    import datetime as _dt
    win_start = (_dt.datetime.fromisoformat(snap["generated"]) - _dt.timedelta(hours=snap["hours"])).isoformat()
    new_devices = []
    if READONLY:  # time range: the registry is only read; "new" = first ever seen inside the range
        win_end = snap["generated"]
        norm = lambda s: str(s or "").replace("Z", "+00:00")  # noqa: E731
        for key, t in today.items():
            d = snap["devices"][t["ip"]]
            first = (reg.get(key) or {}).get("first_seen") or d.get("zeek_first_seen") or win_end
            if norm(win_start) <= norm(first) <= norm(win_end):
                new_devices.append({"key": key, "ip": t["ip"], "name": t["name"], "mac": d.get("mac"), "oui": d.get("oui", ""),
                                    "hostname": d.get("hostname", ""), "known": t["known"], "first_seen": first,
                                    "total": t["total"], "ext_peers": t["ext_peers"], "services": t["services"],
                                    "dports": dict(list(t["dports"].items())[:8]), "served": t["served"]})
                add("high" if not t["known"] else "medium", key, "new-device",
                    f"first ever sighting of {t['ip']} ({d.get('oui') or 'unknown vendor'}) in this time range: {t['total']/MB:.1f} MB, "
                    f"services {', '.join(list(t['services'])[:4])}")
        reg = {}
    for key, t in ([] if READONLY else today.items()):
        d = snap["devices"][t["ip"]]
        first = (d.get("zeek_first_seen") if seeding else None) or snap["generated"]
        if key not in reg:
            reg[key] = {"first_seen": first, "ips": [], "name": t["name"], "mac": d.get("mac"), "oui": d.get("oui", ""),
                        "hostname": d.get("hostname", ""), "known": t["known"], "days_seen": 0}
        r = reg[key]
        r["last_seen"] = snap["generated"]
        r["days_seen"] += 1
        r["name"] = t["name"] or r["name"]
        r["known"] = t["known"]
        if t["ip"] not in r["ips"]:
            r["ips"].append(t["ip"])
        if r["first_seen"].replace("Z", "+00:00") >= win_start.replace("Z", "+00:00") and r["days_seen"] == 1:
            nd = {"key": key, "ip": t["ip"], "name": t["name"], "mac": d.get("mac"), "oui": d.get("oui", ""),
                  "hostname": d.get("hostname", ""), "known": t["known"], "first_seen": r["first_seen"],
                  "total": t["total"], "ext_peers": t["ext_peers"], "services": t["services"],
                  "dports": dict(list(t["dports"].items())[:8]), "served": t["served"]}
            new_devices.append(nd)
            if not seeding:
                add("high" if not t["known"] else "medium", key, "new-device",
                    f"first ever sighting of {t['ip']} ({d.get('oui') or 'unknown vendor'}): {t['total']/MB:.1f} MB, "
                    f"services {', '.join(list(t['services'])[:4])}")
    if not READONLY and not any(h["generated"] == snap["generated"] for h in history):
        store.registry_save(reg)

    # --- DNS tunnelling (absolute heuristics, works from day 1) ---
    dns_benign = set(benign.get("dns_domains", []))
    tunnel = []
    past_dom = [h.get("dns_domains", {}) for h in history]
    for c in snap.get("dns_tunnel", []):
        lvl = None if c["domain"] in dns_benign else tunnel_level(c)
        hist_u = [pdm.get(c["domain"], 0) for pdm in past_dom]
        exploded = spike(c["unique_subdomains"], hist_u, 150, card=True)
        c = {**c, "level": lvl or ("explosion" if exploded else None), "benign": c["domain"] in dns_benign}
        tunnel.append(c)
        srcs = ", ".join(snap["devices"].get(s, {}).get("name") or s for s in list(c["sources"])[:2])
        if lvl == "suspect":
            add("high", "-", "dns-tunnel", f"{c['domain']}: {c['unique_subdomains']:,} distinct subdomains, avg {c['avg_sub_len']} chars, "
                f"entropy {c['entropy']}, from {srcs}")
        elif lvl == "watch":
            add("medium", "-", "dns-tunnel-watch", f"{c['domain']}: {c['unique_subdomains']:,} distinct subdomains, entropy {c['entropy']} from {srcs}")
        elif exploded and not c["benign"]:
            add("medium", "-", "dns-subdomain-explosion",
                f"{c['domain']}: {c['unique_subdomains']:,} distinct subdomains vs normal {med(hist_u):.0f}")

    unknown = [{"key": k, **{f: v[f] for f in ("ip", "name", "total", "ext_peers")}}
               for k, v in today.items() if not v["known"]]

    out = {"snapshot": snap_path, "baseline_days": days, "min_days": MIN_DAYS,
           "baseline_ready": days >= MIN_DAYS, "findings": findings, "unknown_devices": unknown,
           "new_devices": new_devices, "dns_tunnel": tunnel, "violations": snap.get("_violations", []), "registry_seeded_now": seeding, "window_start": win_start,
           "zeek_retention_start": snap.get("zeek_retention_start"), "scale_24h": round(SCALE, 3)}
    ap = snap_path[:-5] + ".analysis.json"
    store.jdump(out, ap, indent=1)
    if READONLY:  # time range: nothing folded into the baseline, no backup
        print(ap, f"findings={len(findings)} (time range, read-only)")
        return

    # --- fold into baseline: one 24h record per ~day, even though the report runs several times a day ---
    # (overlapping 24h windows would otherwise flood the 30-record baseline with near-duplicates)
    stamp = snap["generated"]
    last = max((h["generated"] for h in history), default=None)
    age_h = (dt.datetime.fromisoformat(stamp) - dt.datetime.fromisoformat(last)).total_seconds() / 3600 if last else None
    full_day = float(snap.get("hours") or 24) >= FOLD_MIN_HOURS  # short lookback windows never become baseline records
    fold = full_day and not store.history_has(stamp) and (age_h is None or age_h >= FOLD_MIN_HOURS)
    print("baseline:", "folded this snapshot" if fold else
          f"not folded ({snap.get('hours')}h lookback window, only ~24h snapshots are folded)" if not full_day else
          f"not folded (last baseline record {age_h:.1f}h old, < {FOLD_MIN_HOURS}h)")
    if fold:
        store.history_append({"generated": stamp, "hours": snap["hours"], "devices": today, "signatures": sig_today,
                              "dns_domains": {c["domain"]: c["unique_subdomains"] for c in snap.get("dns_tunnel", [])},
                              "totals": {k: snap["totals"][k] for k in ("conns", "ip_bytes", "internet_ip_bytes", "missed_bytes")}},
                             keep=KEEP)
    # nightly housekeeping: consistent backup of the store (keeps 14) + integrity check
    try:
        print("store backup:", store.backup(), "integrity:", store.integrity())
    except Exception as e:
        print("store backup FAILED:", e)
    print(ap, f"baseline_days_before={days}", f"findings={len(findings)}")


if __name__ == "__main__":
    main()
