#!/usr/bin/python3
"""Site configuration loader (module name site_cfg: `site` would shadow the Python stdlib module). All network-specific values (IPs, host names, domains, accounts) live in site.json,
which is git-ignored; site.example.json is the committed template. Code must read them from here, never hard-code.

Lookup: $NETMON_SITE, else site.json next to this file (host: the netmon folder, dashboard container: /netmon).
"""
import json, os

_HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULTS = {
    "site_name": "netmon", "own_domains": [], "internal_cidr": "10.0.0.0/8", "internal_prefixes": ["10."],
    "es_url": "https://127.0.0.1:9200", "sensor_ip": "", "self_ip": "", "self_host": "", "gateway_name": "gateway",
    "gateway_dns_ip": "", "unifi_console_ip": "", "home_wan": "", "vpn_prefixes": [], "honeypot_ips": [],
    "admin_workstations": "your admin workstation", "host_ips": {}, "display_names": {}, "crown_jewels": {},
    "game_ports": {}, "vapid_contact": "mailto:admin@example.invalid", "github_user": "", "github_repo": "",
    "image_repo": "", "sensitive_terms": [],
    # pivot links (dashboard 🔎 buttons): Kibana base URL + Discover data view, UniFi Network web app base + pages
    "kibana_url": "", "kibana_data_view": "logs-*", "unifi_web_url": "",
    "unifi_paths": {"Security detections (System Log)": "logs/threats", "Flows": "insights/flows"},
}
_cache = None


def load():
    global _cache
    if _cache is None:
        p = os.environ.get("NETMON_SITE") or os.path.join(_HERE, "site.json")
        try:
            data = json.load(open(p))
        except Exception:
            data = {}
        _cache = {**DEFAULTS, **{k: v for k, v in data.items() if not k.startswith("_")}}
    return _cache


def get(key, default=None):
    v = load().get(key)
    return default if v in (None, "", [], {}) and default is not None else v


def is_internal(ip):
    return bool(ip) and str(ip).startswith(tuple(load()["internal_prefixes"]))


def public():
    """Subset safe to hand to the (authenticated) browser."""
    s = load()
    return {k: s[k] for k in ("site_name", "internal_prefixes", "host_ips", "display_names", "honeypot_ips", "self_host",
                              "sensor_ip", "admin_workstations", "kibana_url", "kibana_data_view", "unifi_web_url", "unifi_paths")}


if __name__ == "__main__":
    print(json.dumps(load(), indent=1))
