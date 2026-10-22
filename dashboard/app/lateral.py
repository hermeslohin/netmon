"""Lateral-movement graph: internal-only host-to-host connections classified by risk.

Nodes are internal hosts (grouped by zone); edges are aggregated src->dst flows
from raw.internal.flows (Zeek conn, internal<->internal only - the internet is
never mapped). Each port on an edge is classified:

  high / medium / low   - segmentation-policy violation (analysis.violations)
  medium                - repeated failed attempts at an admin/lateral port
  medium                - part of an internal scan
  allowed-admin         - admin/lateral port explicitly allowed in the network policy (More → Settings)
  normal                - everything else (discovery, gateway services, media...)

Admin sessions (SSH, RDP, PsExec/SMB, WMI, WinRM/PS remoting, VNC, ...) from raw.admin_access are merged
per (src, dst, protocol) with their login outcomes. Failures raise the risk:
  high    - password guessing (>= 10 failed logins or >= 3 invalid users), or >= 3 failures then a success on one account
  medium  - any failed login, or >= 5 refused/unanswered connections to an admin port
  low     - 1-4 refused connections, or a successful admin session not covered by the network policy (More → Settings) "allow"
  allowed-admin - successful sessions that policy allows
"""
from risk import zone_of, _host_ip, seg_is_cleared, seg_cleared
import adminproto as AP

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


def _resolver(raw):
    devices = raw.get("devices") or {}
    inv = {str(v).lower(): k for k, v in (raw.get("inventory_ips") or {}).items()}

    def resolve(x):
        x = str(x or "").strip()
        if not x:
            return ""
        if x.count(".") == 3 and x.replace(".", "").isdigit():
            return x
        return _host_ip(x, devices) or inv.get(x.lower()) or inv.get(x.lower().split(".")[0]) or ""
    return resolve


def admin_sessions(raw, policy):
    """Admin sessions with a risk level and reason; used by build() and by risk.compute()."""
    pol = policy or {}
    allow, classes, devices = pol.get("allow") or [], pol.get("device_classes") or {}, raw.get("devices") or {}
    zones = pol.get("zones") or {}
    cls = lambda ip: classes.get((devices.get(ip) or {}).get("mac", "")) or classes.get(ip) or ""
    out = []
    for r in AP.sessions(raw.get("admin_access") or {}, _resolver(raw)):
        s, d = r["src"], r["dst"]
        if s == d or s.startswith("127.") or d.startswith("127."):
            continue
        r["src_zone"], r["dst_zone"] = zone_of(s, zones), zone_of(d, zones)
        fails, ok, refused = r["auth_fail"], r["auth_ok"], r["conn_failed"]
        guessed = [u for u, c in r["users"].items() if c["fail"] >= 3 and c["ok"]]  # a typo or two is not guessing
        if fails >= 10 or r["invalid_user"] >= 3:
            lvl, why = "high", f"{fails} failed logins" + (f" ({r['invalid_user']} invalid user names)" if r["invalid_user"] else "") + " - password guessing"
        elif guessed:
            lvl, why = "high", f"{fails} failed then successful login(s) for {', '.join(guessed)} - check it was really you"
        elif fails:
            lvl, why = "medium", f"{fails} failed login(s)"
        elif refused >= 5:
            lvl, why = "medium", f"{refused} refused/unanswered connections to {r['protocol']}"
        elif refused:
            lvl, why = "low", f"{refused} refused/unanswered connection(s) to {r['protocol']}"
        elif r["category"] == "database":
            lvl, why = "normal", "database client traffic"
        else:
            port = (r["ports"] or [None])[0]
            f = {"src": s, "dst": d, "src_zone": r["src_zone"], "dst_zone": r["dst_zone"], "port": port, "proto": "tcp"}
            aw = _allowed(f, cls(s), cls(d), allow) if port else None
            if not aw and port and seg_is_cleared(seg_cleared(pol), s, d, port, devices):
                aw = "segmentation flow cleared by a user"  # failed logins on it still escalate above
            lvl, why = ("allowed-admin", f"allowed: {aw}") if aw else ("low", "admin session not covered by the policy allow list")
        if r["auth_fail"] and r["auth_ok"] and lvl != "high":
            why += f"; {ok} successful"
        r["level"], r["why"] = lvl, why
        r["outcome"] = ("failed" if (fails or refused) and not (ok or r["connected"]) else
                        "mixed" if (fails or refused) else "success" if (ok or r["connected"] or r["tools"]) else "unknown")
        out.append(r)
    out.sort(key=lambda r: (ORDER.index(r["level"]), -(r["auth_fail"] + r["conn_failed"]), -(r["attempts"] + r["auth_ok"])))
    return out


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
    cleared = seg_cleared(pol)
    viol = {(v["src"], v["dst"], v["port"], v["proto"]): v for v in (analysis or {}).get("violations") or []
            if not seg_is_cleared(cleared, v["src"], v["dst"], v["port"], raw.get("devices") or {})}
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
        if not v and seg_is_cleared(cleared, s, t, f["port"], devices):
            lvl, why = "allowed-admin", "segmentation flow cleared by a user"
        elif v:
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

    # admin sessions: attach to edges (creating edges seen only in login logs) and raise the edge level
    admin = admin_sessions(raw, pol)
    for a in admin:
        s, t = a["src"], a["dst"]
        if not internal(t):
            continue
        e = edges.setdefault((s, t), {"src": s, "dst": t, "src_zone": a["src_zone"], "dst_zone": a["dst_zone"],
                                      "conns": 0, "answered": 0, "bytes": 0.0, "ports": [], "level": "normal"})
        e.setdefault("admin", []).append(a)
        if not e["ports"] or not any(p["port"] in a["ports"] for p in e["ports"]):
            e["ports"].append({"port": (a["ports"] or [0])[0], "proto": "tcp", "service": a["protocol"], "conns": a["attempts"] or a["auth_ok"] + a["auth_fail"],
                               "answered": a["connected"] or a["auth_ok"], "bytes": a["bytes"], "level": a["level"], "why": a["why"]})
        for p in e["ports"]:  # admin evidence overrides the generic port classification when it is worse
            if p["port"] in a["ports"] and ORDER.index(a["level"]) < ORDER.index(p["level"]):
                p["level"], p["why"] = a["level"], a["why"]
        if ORDER.index(a["level"]) < ORDER.index(e["level"]):
            e["level"] = a["level"]
        e["auth_fail"] = e.get("auth_fail", 0) + a["auth_fail"]
        e["auth_ok"] = e.get("auth_ok", 0) + a["auth_ok"]

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
        fails = e.get("auth_fail", 0) + sum(a["conn_failed"] for a in e.get("admin", []))
        e["score"] = round(SEV_W[e["level"]] * (0.6 + 0.2 * dimp) * (1 + min(e["conns"], 1000) / 1000) * (1 + min(fails, 50) / 25), 2)
        risky = e["level"] in ("high", "medium", "low")
        nodes[e["src"]]["out_conns"] += e["conns"]
        nodes[e["dst"]]["in_conns"] += e["conns"]
        if risky:
            nodes[e["src"]]["out_risky"] += 1
            nodes[e["dst"]]["in_risky"] += 1
    el = sorted(edges.values(), key=lambda e: (ORDER.index(e["level"]), -e["score"], -e["conns"]))
    counts = {lvl: sum(1 for e in el if e["level"] == lvl) for lvl in ORDER}
    return {"nodes": list(nodes.values()), "edges": el, "counts": counts, "admin": admin,
            "admin_sources": (raw.get("admin_access") or {}).get("sources"), "admin_collected": "admin_access" in raw,
            "zones": sorted({n["zone"] for n in nodes.values()})}



def merge_periods(datas):
    """Combine the broker's 'lateral' sections of several time periods into ONE raw/analysis pair, so build() draws the
    existing graph and tables for all periods together: flows are summed per (src, dst, port, proto), admin evidence is
    concatenated (the session merger adds it up), violations are summed per flow, scans keep the worst per source."""
    flows, viol, scans, adm = {}, {}, {}, {"conns": [], "logins": [], "tools": [], "sources": {}, "errors": {}}
    devices, inv = {}, {}
    for d in datas:
        for f in (d.get("internal") or {}).get("flows") or []:
            k = (f["src"], f["dst"], f["port"], f["proto"])
            m = flows.get(k)
            if not m:
                flows[k] = dict(f)
            else:
                for c in ("conns", "answered", "bytes"):
                    m[c] = (m[c] or 0) + (f[c] or 0)
        for v in d.get("violations") or []:
            k = (v["src"], v["dst"], v["port"], v["proto"])
            m = viol.get(k)
            if not m:
                viol[k] = dict(v)
            else:
                for c in ("conns", "answered", "bytes"):
                    m[c] = (m.get(c) or 0) + (v.get(c) or 0)
                if ORDER.index(v["severity"]) < ORDER.index(m["severity"]):
                    m["severity"], m["reason"] = v["severity"], v["reason"]
        for s in (d.get("internal") or {}).get("scans") or []:
            if s["src"] not in scans or s["failed_conns"] > scans[s["src"]]["failed_conns"]:
                scans[s["src"]] = s
        a = d.get("admin_access") or {}
        for k in ("conns", "logins", "tools"):
            adm[k] += a.get(k) or []
        for k, v in (a.get("sources") or {}).items():
            adm["sources"][k] = adm["sources"].get(k, 0) + (v or 0)
        adm["errors"].update(a.get("errors") or {})
        devices.update(d.get("devices") or {})
        inv.update(d.get("inventory_ips") or {})
    raw = {"devices": devices, "inventory_ips": inv, "internal": {"flows": list(flows.values()), "scans": list(scans.values())}, "admin_access": adm}
    return raw, {"violations": list(viol.values())}
