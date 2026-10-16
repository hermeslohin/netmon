"""Lateral-movement graph: internal-only host-to-host connections classified by risk.

Nodes are internal hosts (grouped by zone); edges are aggregated src->dst flows
from raw.internal.flows (Zeek conn, internal<->internal only - the internet is
never mapped). Each port on an edge is classified:

  high / medium / low   - segmentation-policy violation (analysis.violations)
  medium                - repeated failed attempts at an admin/lateral port
  medium                - part of an internal scan
  allowed-admin         - admin/lateral port explicitly allowed in policy.json
  normal                - everything else (discovery, gateway services, media...)
"""
from risk import zone_of

SEV_W = {"high": 3, "medium": 2, "low": 1, "allowed-admin": 0.5, "normal": 0}
ORDER = ["high", "medium", "low", "allowed-admin", "normal"]


def _allowed(f, sc, dc, allow):
    for a in allow:
        if a.get("src") not in (None, "*", f["src"], f["src_zone"], sc):
            continue
        if a.get("dst") not in (None, "*", f["dst"], f["dst_zone"], dc):
            continue
        if a.get("ports") and f["port"] not in a["ports"] and f"{f['port']}/{f['proto']}" not in a["ports"]:
            continue
        return a.get("why") or "allowed by policy"
    return None


def build(raw, analysis, policy, risk_result, known_benign=None):
    pol = policy or {}
    zones = pol.get("zones") or {}
    classes = pol.get("device_classes") or {}
    sens = set(pol.get("sensitive_ports") or [])
    disc = set(pol.get("discovery_ports") or [])
    allow = pol.get("allow") or []
    devices = raw.get("devices") or {}
    names = (known_benign or {}).get("names") or {}
    inv = raw.get("inventory_ips") or {}
    flows = (raw.get("internal") or {}).get("flows") or []
    viol = {(v["src"], v["dst"], v["port"], v["proto"]): v for v in (analysis or {}).get("violations") or []}
    scanners = {s["src"]: s for s in (raw.get("internal") or {}).get("scans") or []}
    hrisk = {h["ip"]: h for h in (risk_result or {}).get("hosts") or [] if h.get("ip")}

    def internal(ip):
        z = zone_of(ip, zones)
        return z and z not in ("internet", "")

    def cls(ip):
        d = devices.get(ip) or {}
        return classes.get(d.get("mac", "")) or classes.get(ip) or ""

    def name(ip):
        if ip.endswith(".1"):
            return names.get(ip) or f"gateway ({zone_of(ip, zones)})"
        d = devices.get(ip) or {}
        return d.get("name") or inv.get(ip) or names.get(ip) or ip

    edges = {}
    for f in flows:
        s, t = f["src"], f["dst"]
        if not (internal(s) and internal(t)) or s == t or t.endswith(".255") or t.startswith("224."):
            continue
        sc, dc = cls(s), cls(t)
        key = (s, t, f["port"], f["proto"])
        v = viol.get(key)
        if v:
            lvl, why = v["severity"], v["reason"]
        elif f["proto"] == "tcp" and f["port"] in sens and not f["answered"] and f["conns"] >= 5 and not t.endswith(".1"):
            lvl, why = "medium", f"{f['conns']} failed attempts at admin/lateral port {f['port']}"
        elif s in scanners and f["proto"] == "tcp" and not f["answered"] and not t.endswith(".1"):
            lvl, why = "medium", f"part of internal scan by {name(s)}"
        else:
            aw = _allowed(f, sc, dc, allow)
            if f["port"] in sens and f["answered"]:
                lvl, why = ("allowed-admin", f"admin port, allowed: {aw}") if aw else ("low", f"admin port {f['port']}")
            else:
                lvl, why = "normal", aw or ("discovery/gateway service" if (f["port"] in disc or t.endswith(".1")) else "")
        e = edges.setdefault((s, t), {"src": s, "dst": t, "src_zone": f["src_zone"], "dst_zone": f["dst_zone"],
                                      "conns": 0, "answered": 0, "bytes": 0.0, "ports": [], "level": "normal"})
        e["conns"] += f["conns"]
        e["answered"] += f["answered"]
        e["bytes"] += f["bytes"] or 0
        e["ports"].append({"port": f["port"], "proto": f["proto"], "service": f.get("service") or "",
                           "conns": f["conns"], "answered": f["answered"], "bytes": f["bytes"],
                           "level": lvl, "why": why})
        if ORDER.index(lvl) < ORDER.index(e["level"]):
            e["level"] = lvl

    nodes = {}
    for e in edges.values():
        for ip in (e["src"], e["dst"]):
            if ip not in nodes:
                h = hrisk.get(ip) or {}
                nodes[ip] = {"id": ip, "name": name(ip), "zone": zone_of(ip, zones), "class": cls(ip),
                             "gateway": ip.endswith(".1"), "known": bool((devices.get(ip) or {}).get("known")),
                             "risk": h.get("score", 0), "rank": h.get("rank"), "in_risky": 0, "out_risky": 0,
                             "in_conns": 0, "out_conns": 0}
    for e in edges.values():
        e["ports"].sort(key=lambda p: (ORDER.index(p["level"]), -p["conns"]))
        dimp = (hrisk.get(e["dst"]) or {}).get("impact", 3)
        e["score"] = round(SEV_W[e["level"]] * (0.6 + 0.2 * dimp) * (1 + min(e["conns"], 1000) / 1000), 2)
        risky = e["level"] in ("high", "medium", "low")
        nodes[e["src"]]["out_conns"] += e["conns"]
        nodes[e["dst"]]["in_conns"] += e["conns"]
        if risky:
            nodes[e["src"]]["out_risky"] += 1
            nodes[e["dst"]]["in_risky"] += 1
    el = sorted(edges.values(), key=lambda e: (ORDER.index(e["level"]), -e["score"], -e["conns"]))
    counts = {lvl: sum(1 for e in el if e["level"] == lvl) for lvl in ORDER}
    return {"nodes": list(nodes.values()), "edges": el, "counts": counts,
            "zones": sorted({n["zone"] for n in nodes.values()})}
