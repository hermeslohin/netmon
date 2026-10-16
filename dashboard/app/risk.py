"""Risk ranking for vulnerabilities (fix-list issues) and hosts.

Model (transparent, deterministic, tunable at the top of this file):

  Vulnerability risk (0-100) = severity base x kind factor x exposure of the
      affected host x recurrence, capped at 100.

  Host risk (0-100) = likelihood (0-100) x impact (1-5) / 5
      likelihood = exposure (<=25) + weaknesses (<=30) + threat activity (<=25)
                   + lateral reach (<=10) + visibility gaps (<=10)
      impact     = how bad a compromise of this host would be for the network
                   (security sensor / gateway / AI box / servers highest, IoT lowest)

Every score carries a list of "drivers" so the dashboard can explain it.
"""
import re
import os as _os, sys as _sys
for _p in (_os.environ.get("NETMON_DIR", "/netmon"), _os.path.expanduser("~/.hermes/netmon")):
    if _os.path.isdir(_p) and _p not in _sys.path:
        _sys.path.append(_p)
import site_cfg as SITE  # noqa: E402  network-specific values live in site.json (git-ignored)

SEV_BASE = {"high": 45, "medium": 28, "low": 14, "info": 5}
# issue-key prefix -> (factor, why)
KIND_FACTOR = {
    "seg-dmz": (1.5, "DMZ host reaching internal zones (pivot path)"),
    "ti-in": (1.5, "internet-exposed service under active probing"),
    "defend": (1.4, "EDR protections off"),
    "unifi|ips-mode": (1.3, "network-wide: attacks are logged, not blocked"),
    "unifi|admin-src": (1.4, "admin access to the gateway"),
    "sensor": (1.25, "network-wide: monitoring blind spot"),
    "agent": (1.1, "reduced endpoint visibility"),
    "sshpw": (1.1, "password-guessable admin access"),
    "plain": (1.2, "credentials in cleartext"),
    "scan": (1.0, ""), "seg": (1.0, ""), "syslog": (0.7, "stability, not directly exploitable"),
    "sw": (1.0, ""), "tls-legacy": (0.8, ""), "dns-ext": (0.8, "bypasses DNS filtering/logging"),
    "doh": (0.5, "visibility only"), "ja3": (0.5, "likely fingerprint collision"),
    "inv": (0.4, "hygiene"), "authfail": (0.8, ""), "unifi": (0.8, ""),
}
IMPACT_BY_CLASS = {"infra": 5, "server": 5, "k8s": 4, "work": 4, "personal": 3, "camera": 2,
                   "media": 2, "game": 2, "iot": 2}
IMPACT_BY_ZONE = {"servers": 5, "ai": 5, "k8s": 4, "dmz": 3, "lan": 3, "vlan3": 3, "vlan4": 3, "vlan21": 3}
IMPACT_OVERRIDE = {**{ip: (5, why) for ip, why in (SITE.get("crown_jewels") or {}).items()},  # crown jewels (site.json)
                   "UniFi gateway": (5, "gateway/firewall for every network")}
HOST_IP = dict(SITE.get("host_ips") or {})  # endpoint host name -> IP (site.json)
EPHEMERAL = 32768
ICMP_PORTS = {"0", "3", "4", "8", "11"}


def _ip2n(ip):
    try:
        a = [int(x) for x in ip.split(".")]
        return (a[0] << 24) + (a[1] << 16) + (a[2] << 8) + a[3] if len(a) == 4 else None
    except Exception:
        return None


def zone_of(ip, zones):
    n = _ip2n(ip or "")
    if n is None:
        return ""
    for z, cidr in (zones or {}).items():
        base, bits = cidr.split("/")
        b, bits = _ip2n(base), int(bits)
        m = (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF if bits else 0
        if b is not None and (n & m) == (b & m):
            return z
    return "internet"


def _host_ip(host, devices):
    if not host:
        return ""
    h = host.lower()
    if h in HOST_IP:
        return HOST_IP[h]
    short = h.split(".")[0]
    for ip, d in devices.items():
        for nm in (d.get("name"), d.get("hostname")):
            if nm and str(nm).lower().split(" ")[0].split(".")[0] == short and len(short) > 3:
                return ip
    return ""


def exposed_services(d):
    out = []
    for p, v in (d.get("served_ports") or {}).items():
        port, _, proto = p.partition("/")
        if not v.get("ext_conns") or proto == "icmp" or port in ICMP_PORTS:
            continue
        if proto == "tcp" and port.isdigit() and int(port) < EPHEMERAL:
            out.append((p, v["ext_conns"]))
    return out


def _benign(sig, kb):
    return any(k.lower() in sig.lower() for k in (kb.get("signatures") or {}))


def compute(raw, analysis, tracker, policy, known_benign):
    devices = raw.get("devices") or {}
    zones = (policy or {}).get("zones") or {}
    classes = (policy or {}).get("device_classes") or {}
    kb = known_benign or {}
    open_issues = [i for i in (tracker or {}).get("open") or []]

    # ---------- per-host context ----------
    def ctx(ip):
        d = devices.get(ip) or {}
        z = zone_of(ip, zones)
        cls = classes.get(d.get("mac", "")) or classes.get(ip) or ""
        exp = exposed_services(d)
        return d, z, cls, exp

    def exposure_factor(ip):
        if not ip:
            return 1.0, ""
        d, z, cls, exp = ctx(ip)
        if exp:
            return 1.4, "host exposes services to the internet"
        if z == "dmz":
            return 1.3, "host is in the DMZ"
        if z in ("servers", "ai"):
            return 1.15, "host is a server"
        return 1.0, ""

    # ---------- vulnerability scores ----------
    vulns = []
    for i in open_issues:
        key = i["key"]
        ip = i.get("ip") or _host_ip(i.get("host"), devices)
        pre = key.split("|")[0]
        if pre == "seg" and zone_of(ip, zones) == "dmz":
            pre = "seg-dmz"
        fk = next((k for k in (key.rsplit("|", 1)[0], "|".join(key.split("|")[:2]), pre) if k in KIND_FACTOR), pre)
        kf, kwhy = KIND_FACTOR.get(fk, (1.0, ""))
        ef, ewhy = exposure_factor(ip)
        rec = 1 + 0.08 * min(max(i.get("occurrences", 1) - 1, 0), 5)
        score = min(100.0, SEV_BASE.get(i["severity"], 10) * kf * ef * rec)
        drivers = [f"{i['severity']} severity ({SEV_BASE.get(i['severity'], 10)})"]
        if kf != 1:
            drivers.append(f"×{kf} {kwhy}".strip())
        if ef != 1:
            drivers.append(f"×{ef} {ewhy}")
        if rec > 1:
            drivers.append(f"×{rec:.2f} recurring in {i['occurrences']} reports")
        vulns.append({**{k: i.get(k) for k in ("key", "title", "severity", "category", "target", "host", "fix",
                                                "evidence", "occurrences", "first_seen", "status", "recurring")},
                      "ip": ip, "score": round(score, 1), "drivers": drivers})
    vulns.sort(key=lambda v: -v["score"])

    # ---------- host scores ----------
    findings = (analysis or {}).get("findings") or []
    macip = {d.get("mac"): ip for ip, d in devices.items() if d.get("mac")}
    f_by_ip = {}
    for f in findings:
        ip = macip.get(f.get("device"), f.get("device"))
        f_by_ip.setdefault(ip, []).append(f)
    v_by_t = {}
    for v in vulns:
        v_by_t.setdefault(v["ip"] or v["target"], []).append(v)
    sigs = (raw.get("alerts") or {}).get("signatures") or []
    beacons = (raw.get("beacons") or {}).get("candidates") or []
    ti = raw.get("threat_intel") or {}
    ja3 = (raw.get("tls") or {}).get("malicious_ja3") or []
    flows = (raw.get("internal") or {}).get("flows") or []
    viol = (analysis or {}).get("violations") or []
    hosts_raw = raw.get("hosts") or {}
    agent_ips = {_host_ip(f["host"], devices): f for f in hosts_raw.get("fleet") or []}

    def infra_addr(ip):  # gateway / broadcast addresses belong to the UniFi gateway entity
        return ip.endswith(".1") or ip.endswith(".255") or ip.endswith(".0")

    for ip in [k for k in v_by_t if k in devices and infra_addr(k)]:
        v_by_t.setdefault("UniFi gateway", []).extend(v_by_t.pop(ip))
    # merge case-variants of endpoint host names
    for k in list(v_by_t):
        if k and k not in devices and k != k.lower() and k not in IMPACT_OVERRIDE:
            v_by_t.setdefault(k.lower(), []).extend(v_by_t.pop(k))
    targets = {ip for ip in devices if not infra_addr(ip)} | {k for k in v_by_t if k}
    rows = []
    for t in targets:
        is_ip = t in devices
        d, z, cls, exp = ctx(t) if is_ip else ({}, "", "", [])
        comp, drivers = {}, []

        # exposure
        e = 0
        if exp:
            e += min(18, 8 + 2 * len(exp))
            drivers.append(("exposure", f"internet-exposed: {', '.join(p for p, _ in exp[:4])}"))
        tin = [h for h in ti.get("ip_hits_in") or [] if t in (h.get("targets") or {})]
        if tin:
            e += 7
            drivers.append(("exposure", f"probed by {len(tin)} threat-listed IPs"))
        if z == "dmz":
            e += 5
        comp["exposure"] = min(25, e)

        # weaknesses (from fix list)
        vs = v_by_t.get(t, [])
        rem = 1.0
        for v in vs:
            rem *= 1 - v["score"] / 100 * 0.6
        comp["weaknesses"] = round(30 * (1 - rem), 1)
        for v in vs[:3]:
            drivers.append(("weakness", f"{v['title']} ({v['score']:.0f})"))

        # threat activity
        th = 0
        hf = [f for f in f_by_ip.get(t, []) if f.get("kind") not in ("segmentation", "outdated-software", "legacy-tls")]
        th += sum({"high": 6, "medium": 3, "low": 1}.get(f.get("severity"), 0) for f in hf)
        if hf:
            drivers.append(("threat", f"{len(hf)} behaviour anomalies ({', '.join(sorted({f['kind'] for f in hf})[:3])})"))
        ids = [(s["name"], s["src"].get(t, 0)) for s in sigs if t in (s.get("src") or {}) and not _benign(s["name"], kb)]
        if ids:
            th += min(10, 3 * len(ids))
            drivers.append(("threat", f"IDS: {ids[0][0][:60]}" + (f" +{len(ids) - 1}" if len(ids) > 1 else "")))
        bc = [b for b in beacons if b.get("src") == t and not any(dm in (b.get("domain") or "") for dm in (kb.get("beacon_domains") or {}))]
        if bc:
            th += min(8, 3 * len(bc))
            drivers.append(("threat", f"{len(bc)} beacon-like pattern(s), e.g. {bc[0].get('name') or bc[0].get('dst')}"))
        tout = [h for h in (ti.get("ip_hits_out") or []) + (ti.get("domain_hits") or []) if t in str(h)]
        if tout:
            th += 15
            drivers.append(("threat", f"contacted {len(tout)} threat-listed destination(s)"))
        if any(t in (m.get("sources") or {}) for m in ja3):
            th += 2
        comp["threat"] = min(25, th)

        # lateral reach
        out_zones = {zone_of(f["dst"], zones) for f in flows if f.get("src") == t and f.get("answered")}
        out_zones.discard(z)
        out_zones.discard("internet")
        sv = [x for x in viol if x.get("src") == t]
        lr = min(6, 2 * len(out_zones)) + min(4, len(sv))
        if out_zones:
            drivers.append(("reach", f"reaches {len(out_zones)} other zone(s): {', '.join(sorted(out_zones))}"))
        comp["reach"] = min(10, lr)

        # visibility gaps
        vg = 0
        if is_ip and not d.get("known"):
            vg += 4
            drivers.append(("visibility", "not in inventory"))
        if is_ip and (cls in ("server", "infra", "work") or z in ("servers", "ai", "dmz")) and t not in agent_ips and cls != "infra":
            vg += 4
            drivers.append(("visibility", "no Elastic agent on a server/workstation"))
        ag = agent_ips.get(t)
        if ag and str(ag.get("status", "")).lower() not in ("online", "healthy"):
            vg += 3
        if any(v["key"].startswith(("doh|", "dns-ext|")) for v in vs):
            vg += 2
        comp["visibility"] = min(10, vg)

        likelihood = min(100, sum(comp.values()))
        if t in IMPACT_OVERRIDE:
            impact, iwhy = IMPACT_OVERRIDE[t]
        elif z == "dmz":
            impact, iwhy = 3, "DMZ host - isolated by design, but a pivot point if segmentation leaks"
        elif not is_ip:
            impact, iwhy = 4, "endpoint with Elastic agent"
        else:
            impact = max(IMPACT_BY_CLASS.get(cls, 0), IMPACT_BY_ZONE.get(z, 2) if not cls else 0) or 2
            iwhy = f"class {cls}" if cls else f"zone {z or '?'}"
        score = round(likelihood * impact / 5, 1)
        if score <= 0 and not vs:
            continue
        name = (d.get("name") or (raw.get("inventory_ips") or {}).get(t) or (kb.get("names") or {}).get(t) or t) if is_ip else t
        rows.append({"id": t, "ip": t if is_ip else "", "name": name, "zone": z, "class": cls, "score": score,
                     "likelihood": round(likelihood, 1), "impact": impact, "impact_why": iwhy,
                     "components": comp, "drivers": [{"type": a, "text": b} for a, b in drivers],
                     "vulns": len(vs), "top_vuln": vs[0]["title"] if vs else ""})
    rows.sort(key=lambda r: -r["score"])
    for n, r in enumerate(rows, 1):
        r["rank"] = n
    for n, v in enumerate(vulns, 1):
        v["rank"] = n
    return {"hosts": rows, "vulns": vulns,
            "model": {"sev_base": SEV_BASE, "impact_by_class": IMPACT_BY_CLASS,
                      "components_max": {"exposure": 25, "weaknesses": 30, "threat": 25, "reach": 10, "visibility": 10}}}
