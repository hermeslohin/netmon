#!/usr/bin/python3
"""UniFi gateway security data for the netmon report, via the unifi.ui.com cloud connector.

The local console (site.json unifi_console_ip) drops TCP from this host, so everything goes through
https://api.ui.com/v1/connector/consoles/<id>/proxy/network with the X-API-KEY in
~/.hermes/secrets/unifi_api_key.

collect(hours) -> dict with: settings (IPS/IDS config), threats (IDS/IPS detections),
threats_30d, wan/device/vpn events, admin logins + config changes (flagged when from an
unexpected source), blocked traffic-flow summary, health, client inventory check.
Run standalone for a JSON dump: unifi.py [hours]
"""
import json, os, sys, time, urllib.request, urllib.error
from collections import Counter, defaultdict
import datetime as dt

KEY_FILE = os.environ.get("UNIFI_API_KEY_FILE") or os.path.join(os.environ.get("HERMES_HOME") or os.path.expanduser("~/.hermes"), "secrets", "unifi_api_key")
API = "https://api.ui.com"
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import site_cfg as SITE  # noqa: E402  network-specific values live in site.json (git-ignored)
HOME_WAN = SITE.get("home_wan")      # admin access from here / the LAN / the VPN is expected
SKILL_INV = os.environ.get("NETMON_DEVICE_TABLE") or os.path.expanduser("~/.hermes/skills/network/home-network-devices/SKILL.md")  # optional
_KEY = None
_BASE = None


def _req(url, body=None, timeout=40):
    global _KEY
    _KEY = _KEY or open(KEY_FILE).read().strip()
    req = urllib.request.Request(url, data=json.dumps(body).encode() if body is not None else None,
                                 headers={"X-API-KEY": _KEY, "Accept": "application/json",
                                          "Content-Type": "application/json"},
                                 method="POST" if body is not None else "GET")
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            if e.code in (429, 502, 503, 504) and attempt < 2:
                time.sleep(3 * (attempt + 1))
                continue
            raise
        except (urllib.error.URLError, TimeoutError):
            if attempt < 2:
                time.sleep(3 * (attempt + 1))
                continue
            raise


def base():
    global _BASE
    if not _BASE:
        hosts = [h for h in _req(API + "/v1/hosts")["data"] if h.get("type") == "console"]
        _BASE = f"{API}/v1/connector/consoles/{hosts[0]['id']}/proxy/network"
    return _BASE


def legacy(path, body=None):
    return _req(f"{base()}/api/s/default/{path}", body)["data"]


def v2(path, body=None):
    return _req(f"{base()}/v2/api/site/default/{path}", body)


def syslog(cat, t0, t1):
    out, p = [], 0
    while True:
        d = v2(f"system-log/{cat}", {"timestampFrom": t0, "timestampTo": t1, "pageSize": 500, "pageNumber": p})
        out += d.get("data", [])
        p += 1
        if p >= d.get("total_page_count", 0) or p > 40:
            return out


def flows(t0, t1, max_pages=40):
    out, p = [], 0
    while p < max_pages:
        d = v2("traffic-flows", {"timestampFrom": t0, "timestampTo": t1, "pageSize": 500, "pageNumber": p})
        out += d.get("data", [])
        p += 1
        if not d.get("has_next"):
            return out, False
    return out, True


def iso(ms):
    return dt.datetime.fromtimestamp(ms / 1000, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def render(e):
    m = e.get("message_raw") or e.get("message") or ""
    for k, v in (e.get("parameters") or {}).items():
        if isinstance(v, dict):
            m = m.replace("{" + k + "}", str(v.get("name", v.get("id", ""))))
    return m


def inventory_macs():
    """MAC -> name from the home-network-devices skill table."""
    import re
    try:
        return {m.lower(): n.strip() for m, n in re.findall(r"^\| ([0-9a-fA-F:]{17}) \| [^|]*\| ([^|]*)\|", open(SKILL_INV).read(), re.M)}
    except OSError:
        return {}


def expected_admin_ip(ip):
    return not ip or ip == HOME_WAN or SITE.is_internal(ip) or ip.startswith(tuple(SITE.get("vpn_prefixes") or ["\0"]))


def collect(hours=24):
    if not os.path.exists(KEY_FILE):  # UniFi is optional
        return {"skipped": f"no UniFi API key at {KEY_FILE}"}
    t1 = int(time.time() * 1000)
    t0 = t1 - hours * 3600_000
    out, errors = {"window_hours": hours}, {}

    def guard(name, fn):
        try:
            out[name] = fn()
        except Exception as e:  # each piece isolated
            errors[name] = f"{type(e).__name__}: {e}"

    # --- client map (MAC/IP -> name) for labelling everything else
    clients, names = [], {}

    def _clients():
        nonlocal clients
        clients = legacy("stat/sta")
        known = legacy("rest/user")
        for c in known + clients:
            n = c.get("name") or c.get("hostname")
            if n:
                names[c["mac"]] = n
                names[c["mac"].lower()] = n
                for ip in (c.get("ip"), c.get("last_ip"), c.get("fixed_ip")):
                    if ip:
                        names[ip] = n
        inv = inventory_macs()
        for m, n in inv.items():
            names.setdefault(m, n)
        nets = Counter(c.get("network") or c.get("last_connection_network_name") or "?" for c in clients)
        unknown = [{"mac": c["mac"], "ip": c.get("ip"), "name": c.get("name") or c.get("hostname") or "",
                    "network": c.get("network"), "vendor": c.get("oui"), "first_seen": iso(c["first_seen"] * 1000) if c.get("first_seen") else None,
                    "wired": c.get("is_wired")}
                   for c in clients if c["mac"].lower() not in inv]
        new = [{"mac": c["mac"], "ip": c.get("ip"), "name": c.get("name") or c.get("hostname") or "",
                "network": c.get("network"), "first_seen": iso(c["first_seen"] * 1000)}
               for c in known + clients if c.get("first_seen") and c["first_seen"] * 1000 >= t0]
        ipdup = defaultdict(list)
        for c in clients:
            if c.get("ip"):
                ipdup[c["ip"]].append(c["mac"])
        return {"online": len(clients), "known_total": len(known), "by_network": dict(nets),
                "guests": sum(1 for c in clients if c.get("is_guest")),
                "not_in_inventory": unknown, "first_seen_in_window": list({m["mac"]: m for m in new}.values()),
                "ip_conflicts": {ip: [f"{m} ({names.get(m) or names.get(m.lower()) or '?'})" for m in ms] for ip, ms in ipdup.items() if len(ms) > 1}}
    guard("clients", _clients)

    def nm(ip_or_mac):
        return names.get(ip_or_mac) or ""

    # --- IPS/IDS configuration (posture)
    def _settings():
        st = {s["key"]: s for s in legacy("get/setting")}
        ips = st.get("ips", {})
        netnames = {}
        try:
            netnames = {n["_id"]: n.get("name") for n in legacy("rest/networkconf")}
        except Exception:
            pass
        return {"ips_mode": ips.get("ips_mode"), "categories": len(ips.get("enabled_categories", [])),
                "protected_networks": [netnames.get(i, i) for i in ips.get("enabled_networks", [])],
                "all_networks": sorted(v for v in netnames.values() if v),
                "honeypot_enabled": ips.get("honeypot_enabled"),
                "honeypots": [h.get("ip_address") for h in ips.get("honeypot", [])],
                "dns_filtering": ips.get("dns_filtering"), "ad_blocking_networks": len(ips.get("ad_blocking_configurations", [])),
                "endpoint_scanning": ips.get("endpoint_scanning"),
                "dpi": st.get("dpi", {}).get("enabled")}
    guard("settings", _settings)

    # --- system log (all categories) for the window, plus 30d security for context
    def _syslog():
        ev = syslog("all", t0, t1)
        cats = Counter(e.get("category") for e in ev)
        def slim(e):
            p = e.get("parameters") or {}
            src = (p.get("SRC_IP") or {}).get("id")
            dst = (p.get("DST_IP") or {}).get("id")
            d = {"time": iso(e["timestamp"]), "severity": e.get("severity"), "key": e.get("key"),
                 "subcategory": e.get("subcategory"), "status": e.get("status"), "message": render(e)}
            if src or dst:
                d.update({"src": src, "src_name": nm(src), "dst": dst, "dst_name": nm(dst)})
            return d
        res = {"counts": dict(cats),
               "threats": [slim(e) for e in ev if e.get("category") == "SECURITY"],
               "wan": [slim(e) for e in ev if e.get("category") == "INTERNET_AND_WAN"],
               "devices": [slim(e) for e in ev if e.get("category") == "UNIFI_DEVICES"],
               "vpn": [slim(e) for e in ev if e.get("category") == "VPN"],
               "updates": [slim(e) for e in ev if e.get("category") == "SOFTWARE_UPDATES"],
               "client_events": Counter(e.get("key") for e in ev if e.get("category") == "CLIENT_DEVICES")}
        # Teleport/VPN sources outside the expected (WAN) need a look
        res["high_severity"] = [slim(e) for e in ev if e.get("severity") in ("HIGH", "VERY_HIGH", "CRITICAL")]
        return res
    guard("events", _syslog)

    def _threats_30d():
        ev = [e for e in syslog("all", t1 - 30 * 86400_000, t1) if e.get("category") == "SECURITY"]
        return [{"time": iso(e["timestamp"]), "severity": e.get("severity"),
                 "src": ((e.get("parameters") or {}).get("SRC_IP") or {}).get("id"),
                 "dst": ((e.get("parameters") or {}).get("DST_IP") or {}).get("id"),
                 "message": render(e)} for e in ev]
    guard("threats_30d", _threats_30d)

    # --- admin activity: logins + configuration changes
    def _admin():
        ev = [e for e in syslog("admin-activity", t0, t1)]
        logins, changes = [], []
        for e in ev:
            ip = e.get("ip") or ""
            who = (e.get("admin") or {}).get("name")
            if e.get("key") == "ADMIN_ACCESS":
                logins.append({"time": iso(e["timestamp"]), "admin": who, "ip": ip, "ip_name": nm(ip),
                               "platform": e.get("platform"), "unexpected_source": not expected_admin_ip(ip)})
            else:
                m = e.get("meta") or {}
                changes.append({"time": iso(e["timestamp"]), "admin": who, "ip": ip, "ip_name": nm(ip),
                                "actor": m.get("actor"), "section": m.get("section"),
                                "object": m.get("display_property_value"), "operation": e.get("operation") or e.get("key"),
                                "fields": [u.get("property") for u in e.get("updates", [])][:10],
                                "unexpected_source": not expected_admin_ip(ip),
                                "security_relevant": (m.get("section") or "") in (
                                    "FIREWALL_POLICY", "PORT_FORWARD", "ADMIN", "SETTINGS_SUPER_SYSTEM", "NETWORK_LOCAL",
                                    "WLAN", "VPN", "DYNAMIC_DNS", "SETTINGS_IPS", "TRAFFIC_RULE") or
                                    any(k in (m.get("section") or "") for k in ("FIREWALL", "VPN", "ADMIN", "IPS", "SECURITY", "WLAN"))})
        return {"logins": logins, "changes": changes,
                "login_sources": Counter(f"{l['ip']} ({l['platform']})" for l in logins)}
    guard("admin", _admin)

    # --- blocked / risky traffic flows
    def _flows():
        fl, truncated = flows(t0, t1)
        act = Counter(f.get("action") for f in fl)
        risk = Counter(f.get("risk") for f in fl)
        by_pol = Counter(p.get("name") for f in fl for p in f.get("policies", []) if f.get("action") == "blocked")
        by_type = Counter(p.get("internal_type") or p.get("type") for f in fl for p in f.get("policies", []))
        cl = Counter()
        dom = defaultdict(Counter)
        region = Counter()
        risky = []
        for f in fl:
            s, d = f.get("source") or {}, f.get("destination") or {}
            who = s.get("client_name") or nm(s.get("mac")) or s.get("ip")
            if f.get("action") == "blocked":
                cl[who] += f.get("count", 1)
                for dm in d.get("domains") or []:
                    dom[who][dm] += f.get("count", 1)
                if any(p.get("name") == "Region Blocking" or "REGION" in (p.get("internal_type") or "") for p in f.get("policies", [])):
                    far = s if f.get("direction") == "incoming" else d
                    region[(who, d.get("ip"), far.get("region") or far.get("country") or "", f.get("direction"))] += f.get("count", 1)
            if f.get("risk") not in (None, "low") or (f.get("direction") == "incoming" and f.get("action") != "blocked"):
                risky.append({"time": iso(f["time"]) if isinstance(f.get("time"), (int, float)) else f.get("time"),
                              "src": s.get("ip"), "src_name": who, "dst": d.get("ip"), "dst_name": d.get("client_name") or "",
                              "domains": d.get("domains"), "port": d.get("port"), "risk": f.get("risk"),
                              "action": f.get("action"), "direction": f.get("direction"), "service": f.get("service"),
                              "policies": [p.get("name") for p in f.get("policies", [])]})
        return {"total": len(fl), "truncated": truncated, "actions": dict(act), "risk": dict(risk),
                "blocked_by_policy": dict(by_pol), "policy_types": dict(by_type),
                "top_blocked_clients": [{"client": c, "count": n, "top_domains": dom[c].most_common(5)} for c, n in cl.most_common(10)],
                "region_blocks": [{"client": k[0], "dst": k[1], "region": k[2], "direction": k[3], "count": n}
                                  for k, n in region.most_common(25)],
                "risky": risky[:50]}
    guard("flows", _flows)

    def _health():
        h = {x["subsystem"]: x for x in legacy("stat/health")}
        w, www = h.get("wan", {}), h.get("www", {})
        return {"status": {k: v.get("status") for k, v in h.items()}, "isp": w.get("isp_name"), "wan_ip": w.get("wan_ip"),
                "latency_ms": www.get("latency"), "drops": www.get("drops"), "uptime_s": www.get("uptime")}
    guard("health", _health)

    out["errors"] = errors
    return out


if __name__ == "__main__":
    print(json.dumps(collect(int(sys.argv[1]) if len(sys.argv) > 1 else 24), indent=1, default=str))
