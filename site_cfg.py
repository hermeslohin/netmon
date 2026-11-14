#!/usr/bin/python3
"""Site configuration loader (module name site_cfg: `site` would shadow the Python stdlib module). All network-specific values (IPs, host names, domains, accounts) live in site.json,
which now lives in the SQLite cfg table (edited on the dashboard Settings page; site.example.json is the template for a first install). Code must read them from here, never hard-code.

Lookup: store.cfg_load("site") (the DB is found like store.py does: $NETMON_DB / $STATE_DIR / dashboard/state).
"""
import json, os, time

_HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULTS = {
    "site_name": "netmon", "own_domains": [], "internal_cidr": "10.0.0.0/8", "internal_prefixes": ["10."],
    "es_url": "https://127.0.0.1:9200", "sensor_ip": "", "self_ip": "", "self_host": "", "gateway_name": "gateway",
    "gateway_dns_ip": "", "unifi_console_ip": "", "home_wan": "", "vpn_prefixes": [], "honeypot_ips": [],
    "admin_workstations": "your admin workstation", "host_ips": {}, "display_names": {}, "crown_jewels": {},
    "game_ports": {}, "vapid_contact": "mailto:admin@example.invalid", "github_user": "", "github_repo": "",
    "image_repo": "", "sensitive_terms": [],
    "event_window_minutes": 10,  # lookback.py: correlation window, review lookback and settle wait (2-120 min)
    "push_wait_for_ai": True,  # pushgate.py: urgent phone pushes wait for the event reviewer's group verdict
    "push_hold_max_minutes": 0,  # pushgate.py: longest hold before pushing anyway (0 = event window + 5 min)
    # who is told what (Daniel's rules; trust() below): defenders see everything, Users only what Syn is sure of
    "min_indicators": 2,  # corr_llm.calibrate: high confidence needs this many independent indicators of the same issue
    "few_indicators_max_confidence": 0.7,  # corr_llm.calibrate: a suspicious label with fewer indicators keeps at most this
    "user_alert_min_confidence": 0.8,  # pushgate.user_sure: Users only get suspicious verdicts at least this confident
    "stop_device_min_confidence": 1.0,  # advice.py: "stop using this device" only at this confidence (1.0 = 100% sure)
    "baseline_alerts_to_users": False,  # pushgate.is_baseline: baseline-finding alarms never go to Users when off
    # pivot links (dashboard 🔎 buttons): Kibana base URL + Discover data view, UniFi Network web app base + pages
    "kibana_url": "", "kibana_data_view": "logs-*", "unifi_web_url": "",
    "unifi_paths": {"Security detections (System Log)": "logs/threats", "Flows": "insights/flows"},
}
_cache = None
_at, _src = 0.0, None

# (key, kind, low, high) of the "who is told what" settings; kind int / float / bool
TRUST = (("min_indicators", int, 1, 5), ("few_indicators_max_confidence", float, 0.0, 1.0),
         ("user_alert_min_confidence", float, 0.0, 1.0), ("stop_device_min_confidence", float, 0.5, 1.0),
         ("baseline_alerts_to_users", bool, None, None))


def trust_error(key, v):
    """None when v is a valid value for trust setting `key`, else the reason (shown on the Settings page)."""
    for k, kind, lo, hi in TRUST:
        if k != key:
            continue
        if kind is bool:
            return None if isinstance(v, bool) else f"{k} must be on or off"
        if isinstance(v, bool) or not isinstance(v, (int, float)) or (kind is int and v != int(v)) or not lo <= v <= hi:
            return f"{k} must be {'a whole number' if kind is int else 'a number'} between {lo:g} and {hi:g}"
        return None
    return None


def trust():
    """The "who is told what" settings (More > Settings > Site), validated; a bad stored value falls back to its default."""
    s = load()
    out = {}
    for k, kind, _lo, _hi in TRUST:
        v = s.get(k, DEFAULTS[k])
        out[k] = kind(v) if trust_error(k, v) is None else DEFAULTS[k]
    return out


def load():
    global _cache, _at
    if _cache is None or time.time() - _at > 3:  # the Settings page edits these; pick changes up within seconds
        try:
            import store
            data = store.cfg_load("site", shared=True)
        except Exception:  # noqa: BLE001 - DB not reachable (yet): never cache the fallback, retry on the next call
            return _cache if _cache is not None else dict(DEFAULTS)
        if _cache is None or data is not _src:
            _cache = {**DEFAULTS, **{k: v for k, v in data.items() if not k.startswith("_")}}
            globals()["_src"] = data
        _at = time.time()
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
