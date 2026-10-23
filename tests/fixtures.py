"""Synthetic, site-neutral test data for netmon.

All addresses are in 10.0.0.0/8 (site_cfg default internal prefix) or the RFC 5737 documentation ranges
(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24). MAC addresses are generated at run time (locally administered
02:..) so no literal MAC ever appears in the repository (repo_guard would block it).
"""
import time


def mac(i):
    return ":".join(["02", "00", "00", "00", "00", "%02x" % (i & 0xFF)])


SID = "2026-01-05T1200Z"            # snapshot id format: YYYY-MM-DDTHHMMZ
SID_OLD = "2026-01-04T1200Z"
IPS = {"laptop": "10.0.1.10", "server": "10.0.2.20", "camera": "10.0.3.30", "dmz": "10.0.9.40", "phone": "10.0.1.11"}
EXT = {"bad": "203.0.113.66", "cdn": "198.51.100.7", "dns": "192.0.2.53"}


def device(name, i, ext_bytes=10_000, served=None, known=True, hour_bytes=1000):
    """One device of a collect.py snapshot, in the same shape collect.py writes (see data/<sid>.json)."""
    return {
        "name": name, "mac": mac(i), "known": known, "hostname": name.lower().replace(" ", "-"),
        "orig_conns": 120, "orig_out_bytes": 50_000.0, "orig_in_bytes": 400_000.0, "missed_bytes": 0.0,
        "peers": 5, "rejected_conns": 2, "ext_conns": 40, "ext_out_bytes": float(ext_bytes), "ext_in_bytes": ext_bytes * 4.0,
        "ext_peers": 3, "countries": {"US": 40.0}, "asns": {"AS64500 Example": 40.0}, "ports": {"443": 40.0},
        "ext_dports": {"443": 40}, "protocols": {"tcp": 120.0},
        "services_out": {"ssl": {"conns": 40, "bytes": 50_000.0}},
        "dports_out": {"443": {"conns": 40, "ext_conns": 40, "service": "ssl", "bytes": 50_000.0}},
        "top_dst": {EXT["cdn"]: 40.0}, "hourly_bytes": {str(h): float(hour_bytes) for h in range(24)},
        "hourly_conns": {str(h): 5 for h in range(24)}, "oui": "Example", "resp_conns": 3, "resp_in_bytes": 100.0,
        "resp_out_bytes": 100.0, "resp_sources": 0, "inbound_ext_sources": 0, "inbound_ext_ports": [],
        "served_ports": served or {}, "total_sent": 60_000.0, "total_recv": 400_000.0, "total_bytes": 460_000.0,
        "dns": {"queries": 200, "unique_names": 20, "unique_domains": 8, "nxdomain": 3, "nx_domains": {}, "servfail": 0,
                "qtypes": {"A": 200}, "tlds": {"com": 200}, "top_domains": {"example.com": 50}, "resolvers": {EXT["dns"]: 200},
                "external_resolvers": {}, "avg_len": 20.0, "max_len": 40.0, "long_names": 0, "subdomain_heavy": {},
                "hourly": {"12": 200}},
        "zeek_first_seen": "2026-01-01T00:00:00Z",
    }


def served(port, service, conns=5, sources=1, ext_conns=0):
    return {str(port): {"conns": conns, "sources": sources, "ext_conns": ext_conns, "service": service}}


def raw_snapshot(sid=SID):
    gen = sid[:10] + "T" + sid[11:13] + ":" + sid[13:15] + ":00+00:00"
    devices = {
        IPS["laptop"]: device("Admin Laptop", 1),
        IPS["server"]: device("Lab Server", 2, served={**served(22, "ssh"), **served(23, "telnet", conns=2)}),
        IPS["camera"]: device("Yard Camera", 3, ext_bytes=5_000),
        IPS["dmz"]: device("DMZ Game Box", 4),
        IPS["phone"]: device("Kid Phone", 5),
    }
    return {
        "generated": gen, "hours": 24, "inventory_file": "inventory (test)", "self_ip": IPS["server"],
        "totals": {"conns": 600, "ip_bytes": 2_300_000.0, "network_bytes": 2_400_000.0, "missed_bytes": 0.0,
                   "internet_ip_bytes": 300_000.0, "hourly": {}, "hourly_missed": {}},
        "devices": devices,
        "alerts": {"total": 3, "signatures": [{"name": "ET INFO Test Signature", "count": 3, "severity": 3,
                                                "category": "Misc activity", "src": {IPS["laptop"]: 3}}]},
        "detections": [], "notices": [], "weird": [],
        "unknown_dhcp": [], "zeek_retention_start": "2025-12-01T00:00:00Z", "dns_tunnel": [],
        "threat_intel": {"feed_status": {}, "feed_sizes": {}, "domain_hits": [], "ip_hits_out": [], "ip_hits_in": [],
                         "new_domains": [], "rdap": {}},
        "beacons": {"pairs_scored": 0, "candidates": []},
        "internal": {"flows": [], "scans": [], "matrix": {}},
        "admin_access": {"conns": [], "logins": [], "tools": [], "sources": {}, "errors": {}},
        "iot_dest": {}, "files": {"files": [], "software": [], "pe_count": 0},
        "tls": {"devices": {}, "malicious_ja3": [], "distinct_ja3": 0, "ja3": [], "ja3s": [], "distinct_ja3s": 0,
                "validation": [], "certs": [], "versions": {"TLSv13": 100}, "ciphers": {}},
        "unifi": {}, "hosts": {}, "mitre_ids": {"ids": [], "detections": [], "defend": []}, "extras_errors": {},
        "inventory_ips": {ip: d["name"] for ip, d in devices.items()},
    }


def analysis(sid=SID):
    return {
        "snapshot": f"data/{sid}.json", "baseline_days": 8, "min_days": 3, "baseline_ready": True,
        "findings": [
            {"severity": "high", "device": IPS["dmz"], "name": "DMZ Game Box", "kind": "segmentation",
             "detail": f"DMZ Game Box -> Lab Server ({IPS['server']}) 22/tcp"},
            {"severity": "medium", "device": mac(3), "name": "Yard Camera", "kind": "new-country",
             "detail": "new destination country XX"},
            {"severity": "low", "device": IPS["phone"], "name": "Kid Phone", "kind": "upload-spike",
             "detail": "uploaded 3x the baseline"},
        ],
        "unknown_devices": [], "new_devices": [], "dns_tunnel": [], "violations": [], "registry_seeded_now": False,
        "window_start": "2026-01-04T12:00:00+00:00", "zeek_retention_start": "2025-12-01T00:00:00Z", "scale_24h": 1.0,
    }


def policy():
    return {
        "zones": {"user": {"cidrs": ["10.0.1.0/24"], "role": "user"}, "servers": {"cidrs": ["10.0.2.0/24"], "role": "protected"},
                  "iot": {"cidrs": ["10.0.3.0/24"], "role": "iot"}, "dmz": {"cidrs": ["10.0.9.0/24"], "role": "dmz"}},
        "allow": [],
    }


def zone_policy(**extra):
    """Network policy in the on-disk format risk.py / lateral.py read: zones are name -> CIDR string,
    roles live in zone_roles (policy() above uses a nested zone format those modules do not accept)."""
    pol = {
        "zones": {"user": "10.0.1.0/24", "servers": "10.0.2.0/24", "iot": "10.0.3.0/24", "dmz": "10.0.9.0/24"},
        "zone_roles": {"user": "user", "servers": "protected", "iot": "iot", "dmz": "dmz"},
        "device_classes": {}, "allow": [], "sensitive_ports": [22, 3389, 445], "discovery_ports": [5353, 1900],
    }
    pol.update(extra)
    return pol


def issue(key, severity="medium", ip="", host="", occurrences=1, title=None, **kw):
    """One open Fix-list issue as issues.track() returns it (input for risk.compute's tracker)."""
    it = {"key": key, "severity": severity, "ip": ip, "host": host, "occurrences": occurrences,
          "title": title or key, "category": "Misconfiguration", "target": ip or host, "fix": "", "evidence": "",
          "first_seen": "2026-01-01T00:00:00+00:00", "status": "open", "recurring": occurrences >= 2}
    it.update(kw)
    return it


def flow(src, dst, port, proto="tcp", conns=1, answered=1, nbytes=100, src_zone="", dst_zone="", service=""):
    """One raw.internal.flows entry (Zeek internal<->internal aggregate)."""
    return {"src": src, "dst": dst, "port": port, "proto": proto, "conns": conns, "answered": answered,
            "bytes": nbytes, "src_zone": src_zone, "dst_zone": dst_zone, "service": service}


def login(src, dst, ok, count=1, user="admin", protocol="SSH", detail=""):
    """One raw.admin_access.logins entry."""
    return {"src": src, "dst": dst, "ok": ok, "count": count, "user": user, "protocol": protocol, "detail": detail}


def admin_conn(src, dst, port=22, attempts=1, connected=1, failed=0, protocol="SSH", category="shell", nbytes=1000):
    """One raw.admin_access.conns entry (Zeek conn evidence for an admin port)."""
    return {"src": src, "dst": dst, "port": port, "protocol": protocol, "category": category, "attempts": attempts,
            "connected": connected, "failed": failed, "bytes": nbytes}


def alert(text, key="test|alert", sev="high", targets=()):
    """One item for store.alerts_add(): (key, text, severity[, targets])."""
    return (key, text, sev, list(targets)) if targets else (key, text, sev)


_ = time


def seed_snapshot(sid=SID, with_analysis=True):
    """Write a raw snapshot (and its analysis) into the isolated store exactly where the pipeline writes them."""
    import os
    import store
    data = os.path.join(os.environ["NETMON_DIR"], "data")
    store.jdump(raw_snapshot(sid), os.path.join(data, f"{sid}.json"))
    if with_analysis:
        store.jdump(analysis(sid), os.path.join(data, f"{sid}.analysis.json"))
    return sid
