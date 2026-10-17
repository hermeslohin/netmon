"""Event correlation: links every event in a snapshot window to the other events (and vulnerabilities) it is
probably part of, so an analyst can pivot from one to the next.

Events (each gets a stable id the dashboard can rebuild from the row it already shows):
  alert|<db id>                     watcher alerts (15-min) whose time falls in the window (+- SLACK)
  f|<kind>|<device>|<detail>        behaviour findings (analysis.findings)
  ids|<signature>                   IDS signatures (raw.alerts.signatures)
  adm|<src>|<dst>|<protocol>        admin sessions (lateral.admin_sessions)
  hf|<key>                          endpoint / host findings (raw.hosts.findings)
  ti|in|<ip>, ti|out|<ip>, ti|dom|<domain>   threat-intel hits
  iss|<key>                         open fix-list issues = vulnerabilities / misconfigurations (time-less state)
  gw|<time>|<key>|<src>|<dst>       UniFi gateway events (raw.unifi.events: IPS threats, high-severity, WAN, devices, VPN)

Two events are related when they share an entity (internal host, external IP, domain, user account) and are
close in time; vulnerabilities relate by host alone (a weakness on a host that is being attacked or is doing
something odd). Score = sum over shared entities of a rarity-weighted value (an IP that appears in half the
events says little) + time proximity + shared ATT&CK technique. Only pairs that share at least one entity
are ever considered, so unrelated events are never linked just for being close in time.
"""
import math
import re
from collections import defaultdict
from datetime import datetime, timezone

SLACK_S = 2 * 3600          # alerts this far outside the snapshot window still count
TOP = 10                    # related events kept per event
MIN_SCORE = 1.5
_IP = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_TECH = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_DOM = re.compile(r"\b((?:[a-z0-9-]+\.)+(?:com|net|org|io|ru|cn|xyz|top|info|biz|us|co|me|app|dev|cloud|online|site))\b", re.I)
W = {"ip": 3.0, "ext": 4.0, "dom": 3.5, "user": 2.0}

# "topic" = the same underlying problem seen by different detectors (e.g. the fix-list issue "SSH password login"
# and an admin session with failed SSH logins). Sharing a topic AND a host is a strong link.
_FINDING_TOPIC = [(r"^ti-", "threat-intel"), (r"^malicious-ja3", "ja3"), (r"^dns-doh", "doh"), (r"^dns-new-resolver", "dns-ext"),
                  (r"^legacy-tls", "tls-legacy"), (r"software", "software"), (r"^segmentation|^new-internal-peer", "segmentation"),
                  (r"^inbound-exposure|^new-listening-port|^new-port", "exposure"), (r"^failed-conns|^port-spike|^internal-scan", "scan"),
                  (r"^beacon", "beacon"), (r"^dns-tunnel|^nxdomain|^dns-long", "dns-tunnel"), (r"^new-device", "new-device")]
_ISSUE_TOPIC = {"ti-in": "threat-intel", "ja3": "ja3", "doh": "doh", "dns-ext": "dns-ext", "tls-legacy": "tls-legacy", "sw": "software",
                "seg": "segmentation", "sshpw": "ssh-auth", "authfail": "auth-fail", "inv": "new-device", "defend": "edr", "agent": "edr"}
TOPIC_NAME = {"threat-intel": "threat-listed IPs", "ssh-auth": "SSH logins", "auth-fail": "failed logins", "segmentation": "segmentation",
              "exposure": "exposed services", "scan": "scanning", "software": "outdated software", "edr": "endpoint protection",
              "dns-ext": "DNS bypassing the local resolver", "doh": "DNS over HTTPS", "ja3": "malware-like TLS fingerprint",
              "tls-legacy": "old TLS", "new-device": "unknown device", "beacon": "beaconing", "dns-tunnel": "DNS tunnelling"}


def _topics_finding(kind):
    return {t for rx, t in _FINDING_TOPIC if re.search(rx, kind)}


def _topics_key(key):
    p = key.split("|")
    t = set()
    if p[0] in _ISSUE_TOPIC:
        t.add(_ISSUE_TOPIC[p[0]])
    if p[0] == "syslog" and len(p) > 2:
        t.add("syslog:" + p[2].lower())
    return t


def _ts(v):
    if v is None or v == "":
        return None
    if isinstance(v, (int, float)):
        return float(v)
    try:
        dt = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
    except ValueError:
        return None
    return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).timestamp()


def gw_id(g):
    """Stable id of one UniFi gateway event (same format as gwId() in static/app.js)."""
    return f"gw|{g.get('time') or ''}|{g.get('key') or ''}|{g.get('src') or ''}|{g.get('dst') or ''}"


def build(raw, analysis, alerts, issues, admin, internal, resolve, techniques, latest=False, cleared=frozenset()):
    """raw/analysis = snapshot; alerts = store.alerts_recent(); issues = open fix-list issues; admin = lateral.admin_sessions();
    internal(ip) -> bool; resolve(host name) -> internal IP or ""; techniques(source, text) -> [ATT&CK ids].
    latest = this is the newest snapshot, so watcher alerts raised after it (up to now) are included too."""
    gen = _ts(raw.get("generated")) or 0
    w0, w1 = gen - 3600 * (raw.get("hours") or 24), gen
    devices = raw.get("devices") or {}
    mac2ip = {str(d.get("mac", "")).lower(): ip for ip, d in devices.items() if d.get("mac")}
    names = {ip: (d.get("name") or ip) for ip, d in devices.items()}
    names.update({mac: names.get(ip, ip) for mac, ip in mac2ip.items()})
    _MAC = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$", re.I)
    ev = {}

    def ents_from_text(text, base=()):
        e = set(base)
        for ip in _IP.findall(text or ""):
            if ip.startswith(("0.", "255.", "127.")) or ip.endswith(".255"):
                continue
            e.add(("ip" if internal(ip) else "ext", ip))
        for d in _DOM.findall(text or ""):
            if not d.lower().endswith((".lan", ".local", ".hades")):
                e.add(("dom", d.lower()))
        return e

    def add(eid, typ, label, t0, t1, ents, tech=(), link="", sev="", vuln=False, topics=()):
        ents = {(k, v) for k, v in ents if v and not (k == "ip" and str(v).endswith(".1"))}  # gateway interfaces link everything
        ev[eid] = {"id": eid, "type": typ, "label": label[:160], "t0": t0, "t1": t1 if t1 is not None else t0, "ents": ents,
                   "tech": set(tech), "link": link, "sev": sev, "vuln": vuln, "topics": set(topics)}

    def host_ents(h):
        ip = resolve(h or "")
        return {("ip", ip)} if ip else set()

    # --- watcher alerts in/near the window
    for a in alerts:
        ts = float(a.get("ts") or 0)
        if not (w0 - SLACK_S <= ts and (latest or ts <= w1 + SLACK_S)):
            continue
        e = ents_from_text(a.get("text", ""))
        for t in a.get("targets") or []:
            k, _, v = str(t).partition(":")
            if k == "ip":
                e.add(("ip" if internal(v) else "ext", v))
            elif k == "mac" and mac2ip.get(v):
                e.add(("ip", mac2ip[v]))
            elif k == "host":
                e |= host_ents(v)
        for u in re.findall(r"accounts? ([a-z_][a-z0-9_.-]{0,31})", a.get("text", "")):
            e.add(("user", u))
        k = a.get("key", "")
        kp = k.split("|")
        top = set()
        if kp[0] == "admin":
            top |= {"auth-fail"} | ({"ssh-auth"} if "SSH" in k else set())
        elif kp[0] in ("tiip", "tidom"):
            top.add("threat-intel")
        elif kp[0] == "inport":
            top.add("exposure")
        elif kp[0] in ("newmac", "newip"):
            top.add("new-device")
        elif kp[0] == "host" and len(kp) > 1:
            top |= _topics_key("|".join(kp[1:2] + kp[2:]))
            if kp[1] in ("syslog",) and len(kp) > 3:
                top.add("syslog:" + kp[3].lower())
            if kp[1] in ("agent-off", "agent-deg", "defend-pol"):
                top.add("edr")
        add(f"alert|{a['id']}", "alert", a.get("text", ""), ts, ts, e, _TECH.findall(a.get("text", "")) + techniques("alert", k),
            f"#/alerts?ev=alert|{a['id']}", a.get("severity", ""), topics=top)

    # --- behaviour findings (whole window)
    from risk import seg_key_finding
    for f in (analysis or {}).get("findings") or []:
        dev = f.get("device") or ""
        if cleared and seg_key_finding(f) in cleared:
            continue
        base = ({("ip" if internal(dev) else "ext", dev)} if dev.count(".") == 3 else
                {("ip", mac2ip[dev.lower()])} if _MAC.match(dev) and mac2ip.get(dev.lower()) else host_ents(dev))
        e = ents_from_text(f.get("detail", ""), base)
        eid = f"f|{f['kind']}|{dev}|{f.get('detail', '')}"
        add(eid, "finding", f"{f['kind']}: {names.get(dev, dev)} - {f.get('detail', '')}", w0, w1, e, techniques("analysis", f["kind"]),
            "#/security?ev=" + eid, f.get("severity", ""), topics=_topics_finding(f["kind"]))

    # --- IDS signatures
    for s in (raw.get("alerts") or {}).get("signatures") or []:
        if (s.get("severity") or 3) >= 3 and s.get("count", 0) > 5000:  # chatty info rules (STUN etc.) would tie everything together
            continue
        e = set()
        for ip in list((s.get("src") or {}))[:6] + list((s.get("dst") or {}))[:6]:
            e.add(("ip" if internal(ip) else "ext", ip))
        add(f"ids|{s['name']}", "ids", f"IDS: {s['name']} x{s.get('count', 0)}", _ts(s.get("first")) or w0, _ts(s.get("last")) or w1, e,
            _TECH.findall(" ".join(map(str, s.get("mitre") or []))), "#/security?ev=" + f"ids|{s['name']}", {1: "high", 2: "medium"}.get(s.get("severity"), "low"),
            topics={t for rx, t in ((r"SCAN", "scan"), (r"CINS|Poor Reputation|DROP|Compromised|Dshield", "threat-intel"), (r"\bSSH\b", "ssh-auth"),
                                    (r"TLS|SSL", "tls-legacy" if re.search(r"SSLv|TLSv1\.[01]", s["name"]) else "_")) if re.search(rx, s["name"])} - {"_"})

    # --- admin sessions
    for a in admin:
        e = {("ip" if internal(a["src"]) else "ext", a["src"]), ("ip", a["dst"])} | {("user", u) for u in a.get("users") or {}}
        eid = f"adm|{a['src']}|{a['dst']}|{a['protocol']}"
        add(eid, "admin", f"{a['protocol']} {names.get(a['src'], a['src'])} -> {names.get(a['dst'], a['dst'])}: {a['why']}",
            _ts(a.get("first")) or w0, _ts(a.get("last")) or w1, e, techniques("admin", f"{a['protocol']} | {a['why']}"),
            "#/lateral?at=admin-list&ev=" + eid, a["level"],
            topics=({"ssh-auth"} if a["protocol"] == "SSH" else set()) | ({"auth-fail"} if a["auth_fail"] else set()) | ({"scan"} if a["conn_failed"] >= 5 else set())
            | ({"segmentation"} if a.get("src_zone") != a.get("dst_zone") else set()))

    # --- host / endpoint findings
    for f in (raw.get("hosts") or {}).get("findings") or []:
        key, text = f.get("key", ""), f.get("text", "")
        parts = key.split("|")
        e = ents_from_text(text)
        for p in parts[1:3]:
            e |= host_ents(p)
        top = _topics_key(key) | ({"ssh-auth"} if parts[0].startswith("login") and "ssh" in key.lower() else set()) \
            | ({"edr"} if parts[0] in ("agent-off", "agent-deg", "defend-pol", "silent") else set())
        add(f"hf|{key}", "host", text, w0, w1, e, techniques("host", f"{key}|{text}"), "#/security?ev=hf|" + key,
            "high" if f.get("priority") == "Investigate" else "medium", topics=top)

    # --- threat intel
    ti = raw.get("threat_intel") or {}
    for h in ti.get("ip_hits_in") or []:
        e = {("ext", h["ip"])} | {("ip", t) for t in (h.get("targets") or {})}
        add(f"ti|in|{h['ip']}", "ti", f"Listed IP {h['ip']} ({', '.join(h.get('feeds', []))}) -> ports {h.get('ports')}", w0, w1, e,
            ["T1595"], "#/threatintel?ev=ti|in|" + h["ip"], "medium", topics={"threat-intel"})
    for h in ti.get("ip_hits_out") or []:
        e = ents_from_text(str(h), {("ext", h.get("ip", ""))})
        add(f"ti|out|{h.get('ip')}", "ti", f"Outbound to listed IP {h.get('ip')} ({', '.join(h.get('feeds', []))})", w0, w1, e,
            ["T1071"], "#/threatintel?ev=ti|out|" + str(h.get("ip")), "high", topics={"threat-intel"})
    for h in ti.get("domain_hits") or []:
        e = ents_from_text(str(h), {("dom", str(h.get("domain", "")).lower())})
        add(f"ti|dom|{h.get('domain')}", "ti", f"Listed domain {h.get('domain')}", w0, w1, e, ["T1071"], "#/threatintel?ev=ti|dom|" + str(h.get("domain")), "high", topics={"threat-intel"})

    # --- UniFi gateway events (the Posture "Gateway events" card; ids match gwId() in app.js)
    uev = ((raw.get("unifi") or {}).get("events") or {})
    for g in [x for k in ("high_severity", "threats", "devices", "wan", "vpn") for x in (uev.get(k) or [])]:
        t = _ts(g.get("time"))
        if t is None or not (w0 - SLACK_S <= t <= w1 + SLACK_S):
            continue
        eid = gw_id(g)
        if eid in ev:
            continue  # high_severity and threats overlap
        key, msg = str(g.get("key") or ""), str(g.get("message") or "")
        e = ents_from_text(msg)
        for side in ("src", "dst"):
            ip = g.get(side)
            if ip:
                e.add(("ip" if internal(ip) else "ext", ip))
        threat = key.startswith("THREAT") or "INTRUSION" in str(g.get("subcategory") or "")
        sev = {"HIGH": "high", "CRITICAL": "high", "MEDIUM": "medium", "LOW": "low"}.get(str(g.get("severity") or "").upper(), "low")
        add(eid, "gw", f"Gateway {key}: {msg}", t, t, e, ["T1595"] if threat else [], "#/security?at=gateway-security&ev=" + eid, sev,
            topics={"scan"} if threat else ({"wan"} if "INTERNET" in str(g.get("subcategory") or "") or key.startswith(("ISP", "WAN")) else set()))

    # --- vulnerabilities / misconfigurations (open issues): time-less, relate by host
    for i in issues:
        e = ents_from_text(" ".join(str(i.get(k) or "") for k in ("key", "title", "target", "evidence")))
        if i.get("ip"):
            e.add(("ip", i["ip"]))
        for h in (i.get("host"), i.get("target")):
            if h and not _IP.fullmatch(str(h)):
                e |= host_ents(h)
        add(f"iss|{i['key']}", "vuln", f"{i.get('title', '')} - {i.get('target', '')}", None, None, e, techniques("issue", i["key"]),
            "#/issues?ev=iss|" + i["key"], i.get("severity", ""), vuln=True, topics=_topics_key(i["key"]))

    # --- score pairs that share an entity
    idx = defaultdict(set)
    for eid, x in ev.items():
        for en in x["ents"]:
            idx[en].add(eid)
    n = max(len(ev), 1)
    rarity = {en: W[en[0]] * (1 / (1 + math.log2(1 + len(ids) / 4))) for en, ids in idx.items()}

    def label_ent(en):
        k, v = en
        return {"ip": f"host {names.get(v, v)}", "ext": f"external IP {v}", "dom": f"domain {v}", "user": f"account {v}"}[k]

    related = defaultdict(list)
    for eid, x in ev.items():
        cand = set()
        for en in x["ents"]:
            if len(idx[en]) <= max(60, n // 2):  # an entity on most events is noise, not a link
                cand |= idx[en]
        cand.discard(eid)
        for oid in cand:
            y = ev[oid]
            shared = x["ents"] & y["ents"]
            s = sum(rarity[en] for en in shared)
            why = [label_ent(en) for en in sorted(shared, key=lambda en: -rarity[en])[:3]]
            if x["vuln"] or y["vuln"]:
                if x["vuln"] and y["vuln"]:
                    s *= 0.5  # two weaknesses on one host: context, not an incident chain
                    why.append("another weakness on the same host")
                elif any(en[0] == "ip" for en in shared):
                    s += 1.5  # an event on a host with a known weakness is what an analyst most needs to see
                    why.append("vulnerability on the same host")
            elif x["t0"] is not None and y["t0"] is not None:
                gap = max(0.0, max(x["t0"], y["t0"]) - min(x["t1"], y["t1"]))  # 0 when the time spans overlap
                if gap <= 900:
                    s += 2; why.append("within 15 min" if (x["t1"] - x["t0"] < 7200 and y["t1"] - y["t0"] < 7200) else "same time window")
                elif gap <= 3600:
                    s += 1; why.append("within 1 h")
                elif gap > 6 * 3600:
                    s -= 1.5
            top = x["topics"] & y["topics"]
            if top and shared:
                s += 2; why.insert(0, "same problem: " + ", ".join(TOPIC_NAME.get(t, t.replace("syslog:", "system error: ")) for t in sorted(top)[:2]))
            tech = x["tech"] & y["tech"]
            if tech:
                s += 1; why.append("same ATT&CK technique " + ", ".join(sorted(tech)[:2]))
            if s >= MIN_SCORE:
                related[eid].append({"id": oid, "score": round(s, 2), "why": why})
    out = {}
    for eid, lst in related.items():  # best first, at most 4 of any one type so one noisy type cannot crowd out the rest
        lst.sort(key=lambda r: -r["score"])
        per, keep = defaultdict(int), []
        for r in lst:
            t = ev[r["id"]]["type"]
            if per[t] < 4:
                per[t] += 1; keep.append(r)
            if len(keep) >= TOP:
                break
        out[eid] = keep
    events = {eid: {k: x[k] for k in ("type", "label", "link", "sev", "t0")} for eid, x in ev.items()}
    return {"events": events, "related": out, "window": [w0, w1], "counts": {t: sum(1 for x in ev.values() if x["type"] == t) for t in
                                                                              ("alert", "finding", "ids", "admin", "host", "ti", "vuln", "gw")}}
