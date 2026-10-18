#!/usr/bin/python3
"""MITRE ATT&CK mapping for netmon (catalog: intel/attack_enterprise.json, built from MITRE's official STIX bundle).

Two relations:
  observed  - behaviour actually seen (IDS alert, host finding, threat-intel hit, beacon...) = possible technique in use
  exposure  - a vulnerability / misconfiguration / visibility gap that ENABLES a technique (nothing seen happening)

Sources and how they are mapped:
  * Suricata alerts      -> the rule's own metadata (rule.metadata.mitre_technique_id), collected by collect_ids()
  * SO detections / Elastic Defend alerts -> their threat.technique.* fields (collect_ids())
  * everything netmon itself produces (baseline findings, host findings, fix-list issues, UniFi, triage alarms)
    -> the curated RULES table below (regex on a "kind|key|text" string). Edit RULES to tune; run
       `mitre.py check` to validate every ID against the catalog.

map_all(snap, analysis, triage, issues) is pure (no ES) so report.py and the dashboard can both call it.
"""
import json, os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__))
CATALOG = os.path.join(HERE, "intel", "attack_enterprise.json")
_cat = None


def catalog():
    global _cat
    if _cat is None:
        try:
            _cat = json.load(open(CATALOG))
        except Exception:
            _cat = {"version": None, "tactic_order": [], "tactics": {}, "techniques": {}}
    return _cat


# (source, regex on "kind|key|text", relation, [technique ids], why)
# source: analysis | host | issue | unifi | alarm | ids  ("*" = any)
RULES = [
    # ---- network baseline findings (analyze.py kinds) ----
    ("analysis", r"^beacon", "observed", ["T1071", "T1029"], "regular automated check-ins = application-layer C2 / scheduled transfer"),
    ("analysis", r"^ti-ip|^ti-dom|threat-intel", "observed", ["T1071"], "traffic with a threat-listed host"),
    ("analysis", r"^ti-ip-in", "observed", ["T1595", "T1190"], "listed attacker probing an Internet-exposed service"),
    ("analysis", r"^malicious-ja3", "observed", ["T1071.001", "T1573"], "TLS client fingerprint associated with malware"),
    ("analysis", r"^internal-scan", "observed", ["T1046"], "host scanning the internal network"),
    ("analysis", r"^failed-conns|^port-spike", "observed", ["T1046"], "many failed / new-port connections = service discovery"),
    ("analysis", r"^upload-spike", "observed", ["T1041", "T1048"], "unusual outbound volume = possible exfiltration"),
    ("analysis", r"^volume-spike", "observed", ["T1030"], "unusual transfer volume"),
    ("analysis", r"^dns-tunnel|^nxdomain-spike", "observed", ["T1071.004", "T1568.002"], "DNS tunnelling / DGA symptoms"),
    ("analysis", r"^dns-new-qtype", "observed", ["T1071.004"], "unusual DNS record types (TXT/NULL tunnelling)"),
    ("analysis", r"^dns-doh", "observed", ["T1572", "T1071.001"], "DNS over HTTPS hides lookups from DNS logging"),
    ("analysis", r"^dns-new-resolver", "observed", ["T1071.004"], "device bypassing the gateway resolver"),
    ("analysis", r"^dns-new-tld|^dns-new-heavy-domain|^iot-new-domain|^new-asn|^new-country", "observed", ["T1071"], "new external destination class (context for C2)"),
    ("analysis", r"^new-tls-client", "observed", ["T1071.001"], "new TLS client software talking out"),
    ("analysis", r"^odd-hours", "observed", ["T1029"], "activity outside the device's normal hours"),
    ("analysis", r"^new-internal-peer|^segmentation", "observed", ["T1021"], "cross-zone/internal connections = lateral-movement path"),
    ("analysis", r"^new-listening-port|^new-port|^service-mix", "exposure", ["T1133", "T1205"], "new listening service (remote access / port-knock surface)"),
    ("analysis", r"^inbound-exposure", "exposure", ["T1190", "T1133"], "service reachable from the Internet"),
    ("analysis", r"^outdated-software|^new-software", "exposure", ["T1190", "T1203"], "vulnerable/unknown software version"),
    ("analysis", r"^legacy-tls", "exposure", ["T1557", "T1040"], "deprecated TLS allows interception/downgrade"),
    ("analysis", r"^new-device", "observed", ["T1200"], "new device on the network (hardware additions)"),
    ("analysis", r"^new-signature|^signature-spike", "n/a", [], "IDS signature change - mapped from the rule's own ATT&CK metadata"),
    # ---- host findings (hosts.py keys) ----
    ("host", r"^defend\|", "n/a", [], "Elastic Defend alert - mapped from the alert's threat.* fields"),
    ("host", r"^login-src\|", "observed", ["T1078", "T1021.004"], "valid-account login from an unexpected source"),
    ("host", r"^login-new\|.*ssh", "observed", ["T1021.004", "T1078"], "first-seen SSH login"),
    ("host", r"^login-new\|.*cockpit", "observed", ["T1078"], "first-seen web console login"),
    ("host", r"^authfail\|", "observed", ["T1110"], "repeated authentication failures = brute force"),
    ("host", r"^acct\|.*(wheel|sudo|admin|docker|libvirt|kvm|root)", "observed", ["T1098", "T1136.001"], "account added to a privileged group"),
    ("host", r"^acct\|", "observed", ["T1136.001", "T1098"], "local account created/modified"),
    ("host", r"^sudo-susp\|", "observed", ["T1548.003", "T1059.004"], "suspicious command run via sudo"),
    ("host", r"^sudo-err\|", "observed", ["T1548.003"], "sudo refused (privilege-escalation attempt or typo)"),
    ("host", r"^proc\|.*memfd", "observed", ["T1620", "T1059"], "memfd_create = fileless / reflective code loading"),
    ("host", r"^proc\|.*(temp|hidden)", "observed", ["T1564.001", "T1059.004"], "binary run from temp/hidden path"),
    ("host", r"^proc\|.*network service", "observed", ["T1505.003", "T1059.004"], "shell spawned by a network service = web shell"),
    ("host", r"^proc\|", "observed", ["T1059"], "suspicious command line"),
    ("host", r"^exec-new\|", "observed", ["T1204", "T1059"], "first-seen executable"),
    ("host", r"^file\|.*authorized_keys", "observed", ["T1098.004"], "SSH authorized_keys modified"),
    ("host", r"^file\|.*(sudoers)", "observed", ["T1548.003"], "sudoers modified"),
    ("host", r"^file\|.*(shadow|passwd)", "observed", ["T1003.008", "T1136.001"], "/etc/passwd or /etc/shadow touched"),
    ("host", r"^file\|.*ld\.so\.preload", "observed", ["T1574.006"], "dynamic-linker hijack file"),
    ("host", r"^file\|.*cron", "observed", ["T1053.003"], "cron persistence location changed"),
    ("host", r"^file\|.*(systemd|rc\.local)", "observed", ["T1543.002", "T1037.004"], "systemd unit / rc script persistence"),
    ("host", r"^file\|.*(profile\.d|bashrc)", "observed", ["T1546.004"], "shell profile persistence"),
    ("host", r"^file\|.*pam\.d", "observed", ["T1556.003"], "PAM configuration changed"),
    ("host", r"^file\|.*Launch(Daemons|Agents)", "observed", ["T1543.001", "T1543.004"], "macOS launch agent/daemon persistence"),
    ("host", r"^hnet-proc\|", "observed", ["T1059", "T1105", "T1071.001"], "shell/interpreter talking to the Internet = reverse shell / tool download"),
    ("host", r"^hnet-interp\|", "observed", ["T1105"], "interpreter downloading from the Internet"),
    ("host", r"^hnet-ti\||^hnet-dns-ti\|", "observed", ["T1071"], "host process contacted a threat-listed IP/domain"),
    ("host", r"^hnet-port\|", "observed", ["T1571", "T1090.003"], "connection on a non-standard / C2 / Tor port"),
    ("host", r"^hnet-in\|", "exposure", ["T1133", "T1190"], "host accepting Internet connections"),
    ("host", r"^hnet-newlisten\|", "exposure", ["T1205", "T1133"], "new listening service on the host"),
    ("host", r"^hnet-dns-long\|", "observed", ["T1568.002", "T1071.004"], "random-looking DNS names = DGA / DNS tunnel"),
    ("host", r"^net-new\|", "observed", ["T1071"], "process contacted a new external destination"),
    ("host", r"^syslog\|.*(unsigned kernel module)", "observed", ["T1547.006"], "unsigned kernel module loaded"),
    ("host", r"^syslog\|.*(Elastic Agent stopped|auditd stopped)", "observed", ["T1685"], "security tooling stopped"),
    ("host", r"^syslog\|.*(OOM|out of memory)", "observed", ["T1496"], "resource exhaustion (rule out cryptomining / resource hijack)"),
    ("host", r"^syslog\|.*(NIC|NetworkManager|I/O error|fs error|XFS|Hardware Error|call trace|segfault|SELinux)", "n/a", [], "operational/health - no adversary technique"),
    ("host", r"^silent\||^agent-off\|", "exposure", ["T1685", "T1070"], "host stopped reporting = blind spot (or logging tampered)"),
    ("host", r"^agent-deg\||^defend-pol\|", "exposure", ["T1685"], "endpoint protection/telemetry not running = defense gap"),
    # ---- admin access (watcher #7 / lateral.admin_sessions); text = "<protocol> | <why>" ----
    ("admin", r"guessing|invalid user", "observed", ["T1110.001", "T1110.003"], "password guessing / spraying against an admin service"),
    ("admin", r"failed then successful", "observed", ["T1110", "T1078"], "failed logins followed by a success = possibly guessed credentials"),
    ("admin", r"failed login|refused", "observed", ["T1110"], "failed authentication attempts"),
    ("admin", r"^SSH\b", "observed", ["T1021.004"], "remote service: SSH"),
    ("admin", r"^RDP", "observed", ["T1021.001"], "remote service: RDP"),
    ("admin", r"^SMB|^NetBIOS|Windows network logon", "observed", ["T1021.002", "T1570"], "SMB / admin shares (PsExec)"),
    ("admin", r"^RPC|DCOM", "observed", ["T1021.003", "T1047"], "DCOM / WMI"),
    ("admin", r"^WinRM", "observed", ["T1021.006"], "remote service: WinRM / PowerShell remoting"),
    ("admin", r"^VNC|TeamViewer|AnyDesk|RustDesk", "observed", ["T1021.005", "T1219"], "VNC / remote access software"),
    # ---- fix-list issues (dashboard issues.py keys) ----
    ("issue", r"^seg\|", "exposure", ["T1021", "T1570"], "flat/permissive segmentation enables lateral movement"),
    ("issue", r"^sw\|", "exposure", ["T1190", "T1203"], "outdated software"),
    ("issue", r"^ja3\|", "observed", ["T1071.001"], "malware-associated TLS fingerprint"),
    ("issue", r"^ti-in\|", "exposure", ["T1190", "T1595.002"], "exposed service probed by listed attackers"),
    ("issue", r"^scan\|", "observed", ["T1046"], "internal scanning"),
    ("issue", r"^dns-ext\|", "exposure", ["T1071.004", "T1572"], "devices bypass the gateway resolver (DNS blind spot)"),
    ("issue", r"^doh\|", "exposure", ["T1572", "T1071.001"], "DNS over HTTPS bypasses DNS monitoring"),
    ("issue", r"^tls-legacy\|", "exposure", ["T1557", "T1040"], "deprecated TLS"),
    ("issue", r"^plain\|", "exposure", ["T1040", "T1557", "T1552.001"], "plaintext protocol exposes credentials to sniffing"),
    ("issue", r"^inv\|", "exposure", ["T1200"], "unmanaged device not in inventory"),
    ("issue", r"^agent\||^defend\|", "exposure", ["T1685"], "endpoint agent/protection unhealthy"),
    ("issue", r"^syslog\|", "exposure", ["T1499"], "host health problem (availability)"),
    ("issue", r"^sshpw\|", "exposure", ["T1110.001", "T1110.003", "T1021.004"], "SSH password auth (root) open to guessing"),
    ("issue", r"^authfail\|", "observed", ["T1110"], "repeated authentication failures"),
    ("issue", r"^unifi\|ips-mode", "exposure", ["T1190", "T1595.002"], "IPS in detect-only mode: exploit attempts are logged, not blocked"),
    ("issue", r"^unifi\|endpoint-scan", "observed", ["T1046"], "device scanning other endpoints"),
    ("issue", r"^unifi\|devices-offline", "n/a", [], "availability - no adversary technique"),
    ("issue", r"^unifi\|unprotected", "exposure", ["T1685"], "network segment not inspected by IPS"),
    ("issue", r"^unifi\|admin-src", "observed", ["T1078", "T1133"], "gateway admin login from unexpected source"),
    ("issue", r"capture|sensor", "exposure", ["T1685"], "sensor capture loss = network blind spot"),
    # ---- UniFi gateway ----
    ("unifi", r"admin.*(login|unexpected)", "observed", ["T1078", "T1133"], "gateway admin login"),
    ("unifi", r"(scan|probe|recon)", "observed", ["T1595"], "Internet scanning of exposed services"),
    ("unifi", r"(intrusion|threat_detected|exploit)", "observed", ["T1190", "T1595.002"], "intrusion attempt against an exposed service"),
    ("unifi", r"(firewall|port.?forward|config).*(change|chang)", "observed", ["T1686.002"], "gateway firewall/port-forward change (verify it was you)"),
    # ---- triage alarm titles (LLM-written; best effort) ----
    ("alarm", r"brute|password guess|auth.*fail", "observed", ["T1110"], ""),
    ("alarm", r"beacon|c2|command.and.control", "observed", ["T1071"], ""),
    ("alarm", r"exfil|upload spike", "observed", ["T1041"], ""),
    ("alarm", r"scan", "observed", ["T1595"], ""),
    ("alarm", r"capture loss|blind|agent.*(degraded|offline|cannot ship)|defend", "exposure", ["T1685"], ""),
    ("alarm", r"admin login", "observed", ["T1078"], ""),
    ("alarm", r"intrusion|exploit|game server|25565", "observed", ["T1190"], ""),
    ("alarm", r"miner|coinminer", "observed", ["T1496"], ""),
    ("alarm", r"split-horizon|dns", "exposure", ["T1071.004"], ""),
]
_COMPILED = [(s, re.compile(rx, re.I), rel, ids, why) for s, rx, rel, ids, why in RULES]


def rules_for(source, text):
    """All matching rules (first match per relation wins within a source, plus explicit overrides)."""
    out = []
    for s, rx, rel, ids, why in _COMPILED:
        if s in (source, "*") and rx.search(text):
            out.append((rel, ids, why))
            break  # RULES are ordered specific -> generic
    return out


def tech(tid):
    c = catalog()["techniques"]
    t = c.get(tid) or c.get(tid.split(".")[0]) or {}
    return t


def _norm_ids(v):
    if not v:
        return []
    v = v if isinstance(v, list) else [v]
    return [str(x).strip() for x in v if re.match(r"^T\d{4}(\.\d{3})?$", str(x).strip())]


# --------------------------------------------------------------------------- ES collection (collect.py job)
def collect_ids(hours=24):
    """Technique IDs carried natively by the SOC data: Suricata rule metadata, SO detections, Defend alerts."""
    sys.path.insert(0, HERE)
    from esq import q
    import window
    R = window.since_h(hours)
    out = {"ids": [], "detections": [], "defend": []}
    r = q("logs-suricata.alerts-so", {"size": 0, "query": {"bool": {"filter": [R, {"exists": {"field": "rule.metadata.mitre_technique_id"}}]}},
          "aggs": {"t": {"terms": {"field": "rule.metadata.mitre_technique_id", "size": 100}, "aggs": {
              "sig": {"terms": {"field": "rule.name", "size": 10}}, "src": {"terms": {"field": "source.ip", "size": 5}},
              "dst": {"terms": {"field": "destination.ip", "size": 5}}, "tac": {"terms": {"field": "rule.metadata.mitre_tactic_name", "size": 3}},
              "sev": {"min": {"field": "rule.severity"}}}}}})
    for b in r["aggregations"]["t"]["buckets"]:
        out["ids"].append({"technique": b["key"], "count": b["doc_count"], "tactics": [x["key"] for x in b["tac"]["buckets"]],
                           "min_severity": b["sev"]["value"], "signatures": {x["key"]: x["doc_count"] for x in b["sig"]["buckets"]},
                           "src": [x["key"] for x in b["src"]["buckets"]], "dst": [x["key"] for x in b["dst"]["buckets"]]})
    for ix, key in (("logs-detections.alerts-so", "detections"), ("logs-endpoint.alerts-*", "defend")):
        try:
            r = q(ix, {"size": 0, "query": R, "aggs": {"t": {"terms": {"field": "threat.technique.id", "size": 50}, "aggs": {
                "s": {"terms": {"field": "threat.technique.subtechnique.id", "size": 5}},
                "n": {"terms": {"field": "rule.name", "size": 5}}, "h": {"terms": {"field": "host.name", "size": 5}}}}}})
            for b in (r.get("aggregations") or {}).get("t", {}).get("buckets", []):
                out[key].append({"technique": b["key"], "subtechniques": [x["key"] for x in b["s"]["buckets"]], "count": b["doc_count"],
                                 "rules": [x["key"] for x in b["n"]["buckets"]], "hosts": [x["key"] for x in b["h"]["buckets"]]})
        except Exception as e:
            out[key + "_error"] = f"{type(e).__name__}: {e}"
    return out


# --------------------------------------------------------------------------- mapping
def map_all(snap, analysis=None, triage=None, issues=None, acks=None):
    """Returns {version, techniques: {tid: {...items}}, tactics: {short: {...}}, items: [...], unmapped: [...]}."""
    cat = catalog()
    acks = acks or {}
    items, unmapped = [], []

    def add(source, rel, ids, why, title, ref="", sev="", count=1, who="", native=False, acked=False):
        if rel == "n/a":
            return  # deliberately not an ATT&CK behaviour (health noise, or mapped natively elsewhere)
        ids = [i for i in ids if i]
        if not ids:
            unmapped.append({"source": source, "title": title, "ref": ref})
            return
        items.append({"source": source, "relation": rel, "techniques": ids, "why": why, "title": title, "ref": ref,
                      "severity": sev, "count": count, "who": who, "native": native, "acked": acked})

    # Suricata / detections / Defend - native ATT&CK metadata
    m = (snap or {}).get("mitre_ids") or {}
    for x in m.get("ids", []):
        if not _norm_ids(x.get("technique")):
            continue  # malformed rule metadata - never pass it into HTML/links
        top = sorted(x["signatures"].items(), key=lambda i: -i[1])
        add("ids", "observed", [x["technique"]], "Suricata rule metadata", top[0][0] if top else x["technique"],
            ref=", ".join(f"{k} ({v})" for k, v in top[:4]), sev=f"sev {int(x['min_severity'])}" if x.get("min_severity") else "",
            count=x["count"], who=", ".join(x.get("src", [])[:3]), native=True)
    for x in m.get("detections", []) + m.get("defend", []):
        add("detection", "observed", _norm_ids(x.get("subtechniques")) or _norm_ids(x.get("technique")), "detection rule metadata",
            ", ".join(x.get("rules", [])[:3]) or x["technique"], count=x["count"], who=", ".join(x.get("hosts", [])), native=True)

    # network baseline findings
    for f in (analysis or {}).get("findings", []):
        key = f"{f.get('kind')}|{f.get('device')}|{f.get('detail', '')}"
        for rel, ids, why in rules_for("analysis", key):
            add("analysis", rel, ids, why, f"{f.get('kind')}: {f.get('detail', '')}"[:220], ref=f.get("kind"), sev=f.get("severity", ""),
                who=f.get("device", ""), acked=False)
        if not rules_for("analysis", key):
            unmapped.append({"source": "analysis", "title": f"{f.get('kind')}: {f.get('detail', '')}"[:160], "ref": f.get("kind")})

    # host findings
    hk = (acks.get("host") or {})
    for f in ((snap or {}).get("hosts") or {}).get("findings", []) or []:
        s = f"{f['key']}|{f['text']}"
        r = rules_for("host", s)
        if not r:
            unmapped.append({"source": "host", "title": f["text"][:160], "ref": f["key"].split("|")[0]})
        for rel, ids, why in r:
            if f["key"].startswith("defend|"):
                continue  # Defend alerts carried natively via mitre_ids
            add("host", rel, ids, why, f["text"][:220], ref=f["key"], sev=f.get("priority", ""), who=f["key"].split("|")[1] if "|" in f["key"] else "",
                acked=f["key"] in hk or bool(f.get("investigated")))

    # fix-list issues
    ik = (acks.get("issue") or {})
    for i in (issues or {}).get("open", []):
        s = f"{i.get('key')}|{i.get('title')}"
        r = rules_for("issue", s)
        if not r:
            unmapped.append({"source": "issue", "title": i.get("title"), "ref": i.get("key")})
        for rel, ids, why in r:
            add("issue", rel, ids, why, i.get("title", ""), ref=i.get("key", ""), sev=i.get("severity", ""),
                who=i.get("host") or i.get("ip") or "", acked=i.get("key") in ik)

    # UniFi gateway: IDS/threat events + admin logins + config changes
    uf = (snap or {}).get("unifi") or {}
    ev = uf.get("events") or {}
    grp = {}
    for t in ev.get("threats") or []:
        k = t.get("key") or ""
        msg = t.get("message") or ""
        if "BLOCKED" in k or "was blocked" in msg:
            continue  # firewall doing its job (policy drop), not an attack technique
        g = grp.setdefault((t.get("src"), t.get("dst"), k), {"n": 0, "t": t})
        g["n"] += 1
    for (src, dst, k), g in grp.items():
        t = g["t"]
        for rel, ids, why in rules_for("unifi", f"ids {k} {t.get('message', '')}"):
            add("unifi", rel, ids, why, f"UniFi IPS: {t.get('message', '')}"[:200], ref=k, sev=t.get("severity", ""), count=g["n"],
                who=f"{src} -> {t.get('dst_name') or dst}")
    adm = uf.get("admin") or {}
    seen = set()
    for l in adm.get("logins") or []:
        if l.get("unexpected_source") and l.get("ip") not in seen:
            seen.add(l.get("ip"))
            add("unifi", "observed", ["T1078", "T1133"], "gateway admin login from unexpected source",
                f"UniFi admin login {l.get('admin', '')} from {l.get('ip', '')} {l.get('ip_name', '')}", who=l.get("ip", ""))
    for c in adm.get("changes") or []:
        if c.get("security_relevant") or c.get("unexpected_source"):
            add("unifi", "observed", ["T1686.002"], "security-relevant gateway config change (verify it was you)",
                f"UniFi change: {c.get('section', '')} {c.get('object', '')} ({c.get('operation', '')})", who=c.get("admin") or "")

    # triage alarms (LLM) - only if nothing else mapped the same thing; best effort, flagged as such
    ak = (acks.get("alarm") or {})
    for a in (triage or {}).get("alarms", []):
        for rel, ids, why in rules_for("alarm", a.get("title", "")):
            add("alarm", rel, ids, why or "triage alarm keyword match", a.get("title", ""), sev=a.get("priority", ""), who=a.get("who", ""))

    # roll up
    T = {}
    for it in items:
        for tid in it["techniques"]:
            t = tech(tid)
            e = T.setdefault(tid, {"id": tid, "name": t.get("name") or "?", "tactics": t.get("tactics", []), "url": t.get("url", ""),
                                   "observed": 0, "exposure": 0, "open": 0, "items": [], "in_catalog": bool(t)})
            e[it["relation"]] += 1
            e["open"] += 0 if it["acked"] else 1
            e["items"].append(it)
    tactics = {}
    for short in cat["tactic_order"]:
        tt = [T[k] for k in T if short in T[k]["tactics"]]
        tactics[short] = {"id": cat["tactics"].get(short, {}).get("id"), "name": cat["tactics"].get(short, {}).get("name", short),
                          "techniques": sorted((x["id"] for x in tt), key=lambda k: (-(T[k]["observed"]), k)),
                          "observed": sum(1 for x in tt if x["observed"]), "exposure": sum(1 for x in tt if x["exposure"] and not x["observed"])}
    return {"version": cat.get("version"), "tactic_order": cat["tactic_order"], "tactics": tactics, "techniques": T,
            "items": items, "unmapped": unmapped,
            "summary": {"techniques": len(T), "observed": sum(1 for x in T.values() if x["observed"]),
                        "exposure_only": sum(1 for x in T.values() if x["exposure"] and not x["observed"]),
                        "items": len(items), "unmapped": len(unmapped)}}


def tags_for(source, text):
    """Short ' [T1110 Brute Force]' suffix for alert lines (watcher)."""
    ids = [i for rel, ids, why in rules_for(source, text) for i in ids][:2]
    return (" [ATT&CK " + ", ".join(f"{i} {tech(i).get('name', '')}".strip() for i in ids) + "]") if ids else ""


def check():
    bad = []
    for s, rx, rel, ids, why in RULES:
        for i in ids:
            if i not in catalog()["techniques"]:
                bad.append((s, rx, i))
    return bad


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "check"
    if cmd == "check":
        b = check()
        print(f"ATT&CK v{catalog()['version']}: {len(catalog()['techniques'])} techniques; {len(RULES)} rules; invalid IDs: {b or 'none'}")
    elif cmd == "refresh":  # rebuild intel/attack_enterprise.json from MITRE's STIX bundle (new ATT&CK release)
        import urllib.request
        url = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
        d = json.load(urllib.request.urlopen(url, timeout=300))
        objs = d["objects"]
        tech, tac = {}, {}
        for o in objs:
            if o.get("revoked") or o.get("x_mitre_deprecated"):
                continue
            ref = next((r for r in o.get("external_references", []) if r.get("source_name") == "mitre-attack"), None)
            if not ref:
                continue
            if o["type"] == "attack-pattern":
                tech[ref["external_id"]] = {"name": o["name"], "url": ref["url"], "platforms": o.get("x_mitre_platforms", []),
                                            "tactics": [k["phase_name"] for k in o.get("kill_chain_phases", []) if k["kill_chain_name"] == "mitre-attack"]}
            elif o["type"] == "x-mitre-tactic":
                tac[o["x_mitre_shortname"]] = {"id": ref["external_id"], "name": o["name"], "url": ref["url"]}
        idmap = {o["id"]: o for o in objs if o["type"] == "x-mitre-tactic"}
        mx = next(o for o in objs if o["type"] == "x-mitre-matrix")
        col = next((o for o in objs if o["type"] == "x-mitre-collection"), {})
        json.dump({"version": col.get("x_mitre_version"), "tactic_order": [idmap[r]["x_mitre_shortname"] for r in mx["tactic_refs"]],
                   "tactics": tac, "techniques": tech}, open(CATALOG, "w"))
        _cat = None
        print(f"ATT&CK v{col.get('x_mitre_version')}: {len(tech)} techniques; invalid rule IDs now: {check() or 'none'}")
    elif cmd == "map":  # mitre.py map <snapshot.json>
        p = sys.argv[2]
        snap = json.load(open(p))
        load = lambda s: json.load(open(p[:-5] + s)) if os.path.exists(p[:-5] + s) else {}
        r = map_all(snap, load(".analysis.json"), load(".triage.json"))
        print(json.dumps(r["summary"]))
        for short in r["tactic_order"]:
            t = r["tactics"][short]
            if t["techniques"]:
                print(f"{t['name']:<22} " + ", ".join(f"{k}{'*' if r['techniques'][k]['observed'] else ''}" for k in t["techniques"]))
