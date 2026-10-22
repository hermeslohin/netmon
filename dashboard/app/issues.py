"""Recurring misconfiguration / security-suggestion tracker.

Every snapshot is run through deterministic checks that emit issues with a
stable key. Across all snapshots we then compute, per key: how often it was
seen, first/last seen, and whether it is still open. An issue is *fixed* once
a newer snapshot that was able to run that check no longer produces it.

Checks depend on data sources ("raw", "analysis", "hosts", "unifi"). If the
latest snapshot lacks a source (e.g. UniFi API failed) the issue stays open as
"not re-checked" rather than being marked fixed.
"""
import re
import os as _os, sys as _sys
for _p in (_os.environ.get("NETMON_DIR", "/netmon"), _os.path.dirname(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))):
    if _os.path.isdir(_p) and _p not in _sys.path:
        _sys.path.append(_p)
import site_cfg as SITE  # noqa: E402  network-specific values live in the site settings

SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}
PLAINTEXT_SVCS = {"telnet": "Telnet", "ftp": "FTP", "tftp": "TFTP", "snmp": "SNMP", "irc": "IRC", "pop3": "POP3"}
LEGACY_TLS = re.compile(r"^(SSLv2|SSLv3|TLSv10|TLSv11)$")


def _name(raw, ip):
    d = (raw.get("devices") or {}).get(ip) or {}
    return d.get("name") or (raw.get("inventory_ips") or {}).get(ip) or ip


def _mac_index(raw):
    return {d.get("mac"): ip for ip, d in (raw.get("devices") or {}).items() if d.get("mac")}


IP2MAC = {}  # filled by track(): ip -> mac learned across all snapshots


def _dkey(ip, d=None):
    return (d or {}).get("mac") or IP2MAC.get(ip) or ip


def _resolve(raw, macidx, dev):
    """Finding 'device' may be a MAC or an IP -> (key, ip)."""
    if dev and ":" in dev:
        return dev, macidx.get(dev, "")
    return _dkey(dev, (raw.get("devices") or {}).get(dev)), dev


def check_snapshot(raw, analysis):
    """Return {key: issue} for one snapshot."""
    out = {}
    macidx = _mac_index(raw)

    def add(key, source, sev, cat, title, ip="", host="", fix="", evidence=""):
        out[key] = {"key": key, "dev": key.split("|")[1] if ip else "", "source": source, "severity": sev, "category": cat, "title": title,
                    "ip": ip, "host": host, "target": (_name(raw, ip) if ip else host), "fix": fix,
                    "evidence": evidence}

    # ---------- from baseline analysis findings ----------
    for f in (analysis or {}).get("findings") or []:
        kind, det, dev = f.get("kind"), f.get("detail") or "", f.get("device")
        dkey, ip = _resolve(raw, macidx, dev)
        if kind == "segmentation":
            continue  # segmentation violations are tracked on the Lateral/Risk pages, not in the fix list
            m = re.search(r"\s*(.*?)\s*\((\d+\.\d+\.\d+\.\d+)\)\s*(\d+)/(\w+)", det.rsplit("->", 1)[-1])
            dst, dport = (m.group(2), m.group(3)) if m else ("?", "?")
            dname = m.group(1) if m else dst
            if "DMZ host initiating" in det:
                fix = (f"The DMZ host should not open connections into internal zones. If {dname}:{dport} is required "
                       f"(e.g. Elastic Fleet 8220/5055), allow exactly that source/dest/port in UniFi and in the network policy (More → Settings); block the rest.")
                cat = "Misconfiguration"
            elif "lateral-movement/admin port" in det:
                fix = (f"Admin port {dport} reachable between internal hosts. Restrict SSH/RDP to a defined admin source "
                       f"({SITE.get('admin_workstations')}) with a UniFi firewall rule, use key-only auth, then add that source to the network-policy allow list (More → Settings).")
                cat = "Security suggestion"
            else:
                fix = (f"Cross-zone flow not covered by policy. If expected, add an allow entry to netmon the network policy (More → Settings) "
                       f"(src → {dst} {dport}); otherwise block it in UniFi zone firewall.")
                cat = "Misconfiguration"
            add(f"seg|{dkey}|{dst}|{dport}", "analysis", f.get("severity", "low"), cat,
                f"Segmentation: {_name(raw, ip) if ip else dkey} → {dname}:{dport}", ip=ip, fix=fix, evidence=det)
        elif kind == "outdated-software":
            prod = det.split(":")[0]
            add(f"sw|{dkey}|{prod}", "analysis", "low", "Security suggestion", f"Outdated software: {prod}", ip=ip,
                fix="Update the device firmware/app that sends this User-Agent, or isolate it on an IoT VLAN if it can't be updated.",
                evidence=det)
        elif kind == "malicious-ja3":
            add(f"ja3|{dkey}|{det.split()[3] if len(det.split()) > 3 else ''}", "analysis", "low", "Security suggestion",
                "TLS fingerprint matches an old malware JA3 list", ip=ip,
                fix="Usually a JA3 collision with a common TLS library. Confirm the destination/SNI is legitimate; if so add the JA3 to the Known benign list (More → Settings).",
                evidence=det)
        elif kind == "ti-ip-in":
            add(f"ti-in|{dkey}", "analysis", "medium", "Security suggestion", "Internet-exposed service probed by listed attackers", ip=ip,
                fix="Restrict the port-forward to known source IPs/countries, enable UniFi IPS (prevent) on that network, keep the service patched.",
                evidence=det)
        elif kind == "internal-scan":
            add(f"scan|{dkey}", "analysis", "medium", "Misconfiguration", "Host repeatedly scanning internal network", ip=ip,
                fix="Identify the process (Tailscale portmapper / discovery tools / monitoring). If benign, tune it or whitelist in policy; otherwise investigate.",
                evidence=det)

    devices = raw.get("devices") or {}
    tlsdev = (raw.get("tls") or {}).get("devices") or {}
    for ip, d in devices.items():
        dkey = _dkey(ip, d)
        dns = d.get("dns") or {}
        ext = dns.get("external_resolvers") or {}
        if ext:
            q = sum(ext.values())
            add(f"dns-ext|{dkey}", "raw", "medium" if q > 50 else "low", "Misconfiguration",
                "Bypasses local DNS (hard-coded external resolvers)", ip=ip,
                fix=f"Block outbound 53/853 except from the gateway and NAT-redirect DNS to {SITE.get('gateway_dns_ip') or 'the gateway'} (UniFi: DNS Shield / port-53 redirect), "
                    "or set the device's DNS to the gateway.",
                evidence=", ".join(f"{k} ×{v}" for k, v in sorted(ext.items(), key=lambda x: -x[1])))
        doh = dns.get("doh") or {}
        if doh:
            add(f"doh|{dkey}", "raw", "low", "Security suggestion", "Uses DNS-over-HTTPS (invisible to DNS logging)", ip=ip,
                fix="Apple devices: iCloud Private Relay / encrypted DNS. If you want DNS visibility, disable Private Relay for this Wi-Fi or "
                    "block the DoH endpoints (UniFi content filter) so they fall back to the gateway.",
                evidence=", ".join(f"{k} ×{v}" for k, v in doh.items()))
        legacy = {k: v for k, v in ((tlsdev.get(ip) or {}).get("versions") or {}).items() if LEGACY_TLS.match(k)}
        if legacy:
            add(f"tls-legacy|{dkey}", "raw", "low", "Security suggestion", "Deprecated TLS (1.0/1.1) in use", ip=ip,
                fix="Update firmware; if none is available keep the device on the IoT network with no access to internal zones.",
                evidence=", ".join(f"{k} ×{v}" for k, v in legacy.items()))
        for svc in set(d.get("services_out") or {}) & set(PLAINTEXT_SVCS):
            add(f"plain|{dkey}|{svc}", "raw", "medium", "Security suggestion", f"Plaintext protocol: {PLAINTEXT_SVCS[svc]}", ip=ip,
                fix=f"Replace {PLAINTEXT_SVCS[svc]} with an encrypted alternative (SSH/SFTP/SNMPv3/TLS).",
                evidence=f"{d['services_out'][svc].get('conns')} conns")

    # Sensor health: capture loss
    T = raw.get("totals") or {}
    if T.get("ip_bytes"):
        loss = (T.get("missed_bytes") or 0) / T["ip_bytes"]
        notice = next((n for n in raw.get("notices") or [] if "CaptureLoss" in n.get("note", "")), None)
        if loss > 0.02 or notice:
            add("sensor|capture-loss", "raw", "high" if loss > 0.2 else "medium", "Misconfiguration",
                "Security Onion sensor is dropping packets (capture loss)", host="securityonion",
                fix="Mirror port is oversubscribed or the sensor can't keep up: mirror only the uplink (not every port), check SPAN direction "
                    "(duplicate RX+TX), raise Zeek/Suricata af_packet workers & ring size, or add sensor CPU.",
                evidence=f"{loss * 100:.1f}% of bytes missed ({T.get('missed_bytes', 0) / 1e9:.1f} GB)"
                         + (f"; Zeek {notice['note']} ×{notice['count']}" if notice else ""))

    # Inventory hygiene
    for u in raw.get("unknown_dhcp") or []:
        ip = u.get("ip", "")
        add(f"inv|{(u.get('macs') or [ip])[0]}", "raw", "low", "Hygiene", "Device not in DHCP inventory", ip=ip,
            fix="Add a DHCP reservation / name for it and re-export the DHCP list so it is tracked by name.",
            evidence=f"{u.get('hostname') or ''} {', '.join(u.get('macs') or [])}")

    # ---------- endpoints (Elastic) ----------
    H = raw.get("hosts")
    if H:
        for f in H.get("fleet") or []:
            st = str(f.get("status", "")).lower()
            if st not in ("online", "healthy"):
                bad = ", ".join(b if isinstance(b, str) else (b.get("id") or b.get("name") or str(b)) for b in f.get("bad_components") or [])
                add(f"agent|{f['host'].lower()}", "hosts", "medium", "Misconfiguration", f"Elastic Agent {st or 'unhealthy'}",
                    host=f["host"], fix="Check agent output connectivity to SO (8220 control, 5055 data, 8443 artifacts) through UniFi and so-firewall; "
                    "then `elastic-agent status` on the host.",
                    evidence=f"reason: {f.get('unhealthy_reason') or '—'}; components: {bad or '—'}; last check-in {f.get('last_checkin')}")
        for x in H.get("defend") or []:
            if x.get("status") != "success":
                add(f"defend|{x['host'].lower()}", "hosts", "high", "Misconfiguration", "Elastic Defend protections not running",
                    host=x["host"], fix="macOS: approve the Elastic system extension and grant Full Disk Access + network filter "
                    "(System Settings › Privacy & Security), ideally via an MDM/PPPC profile; then restart the agent.",
                    evidence="failed: " + ", ".join(x.get("failed_protections") or []) + "; "
                             + "; ".join(p.get("message", "") for p in (x.get("problems") or [])[:3]))
        SYSLOG_FIX = {
            "NIC link flapping": "Replace/ reseat the cable, check the switch port (speed/duplex, errors, PoE) and NIC firmware.",
            "NIC malformed Tx packets": "Driver/offload problem: update the igb driver/firmware, or disable TSO/GSO on the interface (ethtool -K).",
            "NetworkManager activation failures": "Remove or fix stale NetworkManager connection profiles (nmcli con show) for unplugged NICs.",
            "OOM killer": "Cap model/container memory (LM Studio context, docker --memory) so GPU/host memory isn't exhausted.",
        }
        for host, cats in (H.get("syslog") or {}).items():
            for cat, v in cats.items():
                add(f"syslog|{host.lower()}|{cat}", "hosts", "medium" if v.get("sev") == "Investigate" else "low", "Misconfiguration",
                    f"Recurring system error: {cat}", host=host,
                    fix=SYSLOG_FIX.get(cat, "Review the log sample and fix the underlying cause."),
                    evidence=f"×{v.get('count')} (last {v.get('last')}): {str(v.get('sample', ''))[:200]}")
        auth = H.get("auth") or {}
        for l in auth.get("logins") or []:
            if "password" in str(l.get("via", "")) and l.get("outcome") == "success":
                root = l.get("user") == "root"
                add(f"sshpw|{l['host'].lower()}|{l.get('user')}", "hosts", "medium" if root else "low", "Security suggestion",
                    f"SSH password login{' as root' if root else ''}", host=l["host"],
                    fix="Use SSH keys and set `PasswordAuthentication no`" + (" and `PermitRootLogin prohibit-password`" if root else "")
                        + " in sshd_config.",
                    evidence=f"{l.get('user')} from {l.get('src_label') or l.get('src')} ×{l.get('count')}")
        for x in auth.get("failures") or []:
            if (x.get("count") or 0) >= 5:
                add(f"authfail|{x['host'].lower()}", "hosts", "low", "Security suggestion", "Repeated authentication failures", host=x["host"],
                    fix="Confirm these are your own typos/scripts; otherwise add fail2ban / restrict SSH sources.",
                    evidence=f"×{x.get('count')} from {', '.join(x.get('sources') or {})}")

    # ---------- UniFi gateway ----------
    U = raw.get("unifi")
    if U and U.get("settings"):
        s = U["settings"]
        if s.get("ips_mode") == "ids":
            add("unifi|ips-mode", "unifi", "medium", "Misconfiguration", "UniFi IPS is in detect-only (IDS) mode", host="UniFi gateway",
                fix="Settings › CyberSecure › Intrusion Prevention: switch to 'Notify and Block' (IPS) at least for DMZ and Default.",
                evidence=f"ips_mode=ids, {s.get('categories')} categories")
        unprot = [n for n in s.get("all_networks") or [] if n not in (s.get("protected_networks") or []) and not n.startswith("Internet")]
        for n in unprot:
            add(f"unifi|unprotected|{n}", "unifi", "low", "Misconfiguration", f"Network '{n}' not covered by IPS", host="UniFi gateway",
                fix="Add the network to Intrusion Prevention's protected networks.", evidence=n)
        if s.get("endpoint_scanning") is False:
            add("unifi|endpoint-scan", "unifi", "info", "Security suggestion", "UniFi device/endpoint scanning disabled", host="UniFi gateway",
                fix="Optional: enable endpoint scanning so UniFi flags exposed services on LAN devices.", evidence="endpoint_scanning=false")
    if U:
        for l in (U.get("admin") or {}).get("logins") or []:
            if l.get("unexpected_source"):
                add(f"unifi|admin-src|{l.get('ip')}", "unifi", "high", "Security suggestion", "UniFi admin login from unexpected source",
                    host="UniFi gateway", fix="Verify it was you; if not, rotate the UniFi account password and enable 2FA.",
                    evidence=f"{l.get('admin')} from {l.get('ip')} at {l.get('time')}")
        offl = [e for e in (U.get("events") or {}).get("devices") or [] if "UNREACHABLE" in str(e.get("key", ""))]
        if offl:
            add("unifi|devices-offline", "unifi", "medium", "Misconfiguration", "UniFi network devices dropping offline", host="UniFi gateway",
                fix="Check uplink/power (PoE budget) for the APs/switches involved and their firmware.",
                evidence=f"{len(offl)} events, last: {offl[0].get('message')} {offl[0].get('time')}")
    return out


def sources_of(raw, analysis):
    s = {"raw"}
    if analysis:
        s.add("analysis")
    if raw.get("hosts"):
        s.add("hosts")
    if raw.get("unifi") and raw["unifi"].get("settings"):
        s.add("unifi")
    return s


def track(snaps, min_occ=2):
    """snaps: ordered list of (sid, generated, raw, analysis). Returns tracker dict."""
    hist = {}
    per = []
    IP2MAC.clear()
    for _, _, raw, _ in snaps:
        for ip, d in (raw.get("devices") or {}).items():
            if d.get("mac"):
                IP2MAC[ip] = d["mac"]
    present = {}
    for sid, gen, raw, an in snaps:
        present[sid] = {_dkey(ip, d) for ip, d in (raw.get("devices") or {}).items()}
        cur = check_snapshot(raw, an)
        srcs = sources_of(raw, an)
        per.append((sid, gen, srcs, cur, float(raw.get("hours") or 24) >= 23))
        for k, iss in cur.items():
            h = hist.setdefault(k, {**iss, "first_seen": gen, "first_snap": sid, "occurrences": 0, "seen_in": []})
            h.update({k2: v for k2, v in iss.items()})  # latest evidence/target wins
            h["occurrences"] += 1
            h["seen_in"].append(sid)
            h["last_seen"], h["last_snap"] = gen, sid
    latest_sid = per[-1][0] if per else None
    open_, fixed = [], []
    for k, h in hist.items():
        # snapshots after first_seen that could evaluate this check
        # a short research-run snapshot (lookback < 23 h) can raise an issue but never clear it: a few quiet hours
        # are not proof that something was fixed
        able = [p for p in per if h["source"] in p[2] and p[0] >= h["first_snap"] and (p[4] or k in p[3])]
        h["checked"] = len(able)
        last_able = able[-1] if able else None
        if last_able and k not in last_able[3] and h.get("dev") and h["dev"] not in present[last_able[0]]:
            h["status"] = "open (device not seen)"
            h["recurring"] = h["occurrences"] >= min_occ
            open_.append(h)
        elif last_able and k not in last_able[3]:
            # fixed: find the first snapshot after last_seen that could check it
            fixed_at = next((p for p in able if p[0] > h["last_snap"]), last_able)
            h["status"], h["fixed_at"] = "fixed", fixed_at[1]
            fixed.append(h)
        else:
            h["status"] = "open" if h["last_snap"] == latest_sid else "open (not re-checked)"
            h["recurring"] = h["occurrences"] >= min_occ
            open_.append(h)
    key = lambda x: (SEV_ORDER.get(x["severity"], 9), -x["occurrences"], x["title"])
    open_.sort(key=key)
    fixed.sort(key=lambda x: x.get("fixed_at") or "", reverse=True)
    for h in hist.values():
        h.pop("seen_in", None)
    return {"latest": latest_sid, "snapshots": len(per), "min_occurrences": min_occ,
            "open": open_, "fixed": fixed}
