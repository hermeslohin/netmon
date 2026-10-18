#!/usr/bin/python3
"""Osquery (Elastic osquery_manager pack `netmon-host-posture`) results -> host posture + change findings.

Pack definition: osquery_pack.json (import in Kibana > Osquery > Packs, assign to the Linux agent policies).
Results index: logs-osquery_manager.result-*; one doc per row, columns under `osquery.*`,
query id in `action_data.id` (fallback: suffix of `action_id` = "pack_<pack>_<query>").
All queries are snapshots: for each (host, query) only the newest run is used.

results(minutes)            -> {host: {query: [rows]}, "_meta": {...}}
posture(res)                -> {host: [ {item, value, status(ok|warn|bad), note} ]}
findings(res, base)         -> [(key, priority, text)]   (base = host baseline from store.py; keys under host["osq"])
update_baseline(res, base)  -> mutates base
"""
import json, os, re, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from esq import q  # noqa: E402

PACK = "netmon-host-posture"
POL = os.path.join(os.path.dirname(os.path.abspath(__file__)), "host_policy.json")
try:
    POLICY = json.load(open(POL)).get("osquery", {})
except Exception:
    POLICY = {}
SYS_BIN = tuple(POLICY.get("package_managed_prefixes", ["/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "/usr/lib", "/lib"]))
USER_WRITABLE = ("/home/", "/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/")


def hn(h):
    return (h or "").lower()


def _qid(src):
    ad = src.get("action_data") or {}
    if ad.get("id"):
        return ad["id"]
    aid = src.get("action_id") or ""
    if f"_{PACK}_" in aid:
        return aid.split(f"_{PACK}_", 1)[1]
    return aid.rsplit("_", 1)[-1] or "?"


def results(minutes=26 * 60):
    """Newest snapshot per (host, query). Rows of one run share a timestamp; keep rows within 5 min of the newest."""
    idx = "logs-osquery_manager.result-*"
    import window
    body = {"size": 0, "query": window.since(minutes),
            "aggs": {"h": {"terms": {"field": "host.name", "size": 50}, "aggs": {
                "a": {"terms": {"field": "action_id", "size": 100}, "aggs": {"t": {"max": {"field": "@timestamp"}}}}}}}}
    r = q(idx, body)
    out = {"_meta": {"docs": r["hits"]["total"]["value"] if isinstance(r["hits"]["total"], dict) else r["hits"]["total"]}}
    for hb in ((r.get("aggregations") or {}).get("h") or {}).get("buckets", []):  # no index yet -> no aggs
        host = hn(hb["key"])
        for ab in hb["a"]["buckets"]:
            if PACK not in ab["key"]:
                continue
            newest = ab["t"]["value_as_string"]
            rr = q(idx, {"size": 5000, "query": {"bool": {"filter": [
                {"term": {"host.name": hb["key"]}}, {"term": {"action_id": ab["key"]}},
                {"range": {"@timestamp": {"gte": f"{newest}||-5m", "lte": newest}}}]}},
                "_source": ["osquery", "action_data", "action_id", "@timestamp"]})
            rows = []
            qid = None
            for h in rr["hits"]["hits"]:
                s = h["_source"]
                qid = qid or _qid(s)
                rows.append({k: (str(v) if v is not None else "") for k, v in (s.get("osquery") or {}).items()})
            if qid:
                out.setdefault(host, {})[qid] = rows
                out.setdefault("_meta", {}).setdefault("at", {})[f"{host}|{qid}"] = newest
    return out


# ------------------------------------------------------------------ identity of a row per query (for baselining)
IDENT = {
    "listening": lambda r: f"{r.get('name')}:{r.get('protocol')}/{r.get('port')}@{r.get('address')}",
    "proc_nonsystem": lambda r: r.get("path"),
    "uid0": lambda r: r.get("username"),
    "login_users": lambda r: f"{r.get('username')}:{r.get('shell')}",
    "authorized_keys": lambda r: f"{r.get('username')}:{r.get('algorithm')}:...{r.get('key_tail')} {r.get('comment')}",
    "sudoers": lambda r: f"{r.get('source')}: {r.get('header')} {r.get('rule_details')}".strip(),
    "suid": lambda r: r.get("path"),
    "kernel_modules": lambda r: r.get("name"),
    "crontab": lambda r: f"{r.get('path')}: {r.get('minute')} {r.get('hour')} {r.get('day_of_month')} {r.get('month')} {r.get('day_of_week')} {r.get('command')}",
    "systemd_custom": lambda r: f"{r.get('id')} ({r.get('fragment_path')})",
    "docker": lambda r: f"{r.get('name')} {r.get('image')}",
    "packages_deb": lambda r: r.get("name"),
    "packages_rpm": lambda r: r.get("name"),
}
# priority when a NEW item appears vs baseline
NEW_PRI = {"uid0": "Investigate", "authorized_keys": "Investigate", "sudoers": "Investigate", "suid": "Investigate",
           "listening": "Review", "proc_nonsystem": "Review", "login_users": "Review", "kernel_modules": "Review",
           "crontab": "Review", "systemd_custom": "Review", "docker": "Review", "packages_deb": "Info", "packages_rpm": "Info"}
LABEL = {"uid0": "UID-0 account", "authorized_keys": "SSH authorized key", "sudoers": "sudoers rule", "suid": "setuid binary",
         "listening": "network listener", "proc_nonsystem": "running binary outside system paths", "login_users": "login-shell account",
         "kernel_modules": "kernel module", "crontab": "cron entry", "systemd_custom": "local systemd unit", "docker": "container",
         "packages_deb": "package", "packages_rpm": "package"}


def _yes(v):
    return str(v).strip().lower() in ("1", "yes", "true")


def host_exceptions(host):
    ex = POLICY.get("host_exceptions", {})
    return ex.get(host, {}) | ex.get(host.split(".")[0], {})


def posture(res):
    """Current misconfigurations per host. status: bad (fix), warn (weak/default), ok."""
    out = {}
    for host, Q in res.items():
        if host.startswith("_"):
            continue
        ex = host_exceptions(host)
        P = []

        def add(item, value, status, note="", crit=False):
            if item in ex:  # accepted risk for this host
                status, note, crit = "ok", f"accepted: {ex[item]}", False
            P.append({"item": item, "value": str(value)[:120], "status": status, "note": note, "crit": crit})

        # sshd (augeas only sees explicit lines; first match wins in sshd, conf.d is included at the top on Ubuntu/RHEL)
        if "sshd_config" in Q:
            cfg = {}
            for r in sorted(Q["sshd_config"], key=lambda r: (0 if "sshd_config.d" in r.get("path", "") else 1, r.get("path", ""))):
                cfg.setdefault(r.get("label"), r.get("value"))
            v = cfg.get("PermitRootLogin", "prohibit-password (default)")
            add("ssh PermitRootLogin", v, "bad" if v.lower() == "yes" else "ok", "root password login over SSH" if v.lower() == "yes" else "")
            v = cfg.get("PasswordAuthentication", "yes (default)")
            add("ssh PasswordAuthentication", v, "warn" if v.lower().startswith("yes") else "ok",
                "passwords accepted over SSH - prefer keys only" if v.lower().startswith("yes") else "")
            v = cfg.get("PermitEmptyPasswords", "no (default)")
            add("ssh PermitEmptyPasswords", v, "bad" if v.lower() == "yes" else "ok")
            v = cfg.get("X11Forwarding", "no (default)")
            add("ssh X11Forwarding", v, "warn" if v.lower() == "yes" else "ok", "X11 forwarding enabled" if v.lower() == "yes" else "")
            for k in ("GatewayPorts", "PermitTunnel"):
                if cfg.get(k, "no").lower() in ("yes", "clientspecified", "point-to-point", "ethernet"):
                    add(f"ssh {k}", cfg[k], "warn", "lets SSH clients expose/tunnel networks")
        # firewall
        if "firewall" in Q:
            fw = {(r.get("src"), r.get("name")): r.get("value", "") for r in Q["firewall"]}
            ufw = fw.get(("ufw.conf", "ENABLED"))
            ipt_in = fw.get(("iptables", "filter:INPUT"), "")
            m = re.match(r"(\w+) rules=(\d+)", ipt_in)
            ipt_filtering = bool(m) and (m.group(1) in ("DROP", "REJECT") or int(m.group(2)) > 0)
            fwd = bool(fw.get(("firewalld", "DefaultZone")))
            svc = {r.get("id"): r.get("active_state") for r in Q.get("security_services", [])}
            fwd_on = fwd and svc.get("firewalld.service") == "active"
            if ufw is not None:
                on = _yes(ufw)
                add("host firewall (ufw)", f"ENABLED={ufw}", "ok" if on else "bad", "" if on else "ufw installed but disabled")
            elif fwd:
                add("host firewall (firewalld)", f"zone {fw[('firewalld', 'DefaultZone')]}, {svc.get('firewalld.service', '?')}",
                    "ok" if fwd_on else "bad", "" if fwd_on else "firewalld not running")
            else:
                add("host firewall", f"iptables INPUT {ipt_in or 'n/a'}", "ok" if ipt_filtering else "warn",
                    "" if ipt_filtering else "no ufw/firewalld config and no legacy-iptables INPUT rules (nftables not visible to osquery)")
        # services
        if "security_services" in Q:
            svc = {r.get("id"): r.get("active_state") for r in Q["security_services"]}
            deb = "packages_deb" in Q and bool(Q["packages_deb"])
            if svc.get("auditd.service") != "active":
                add("auditd", svc.get("auditd.service", "not installed"), "warn", "no kernel audit trail")
            if deb and svc.get("unattended-upgrades.service") != "active":
                add("automatic security updates", f"unattended-upgrades {svc.get('unattended-upgrades.service', 'not installed')}", "warn",
                    "security patches not applied automatically")
            for s_, why in (("xrdp.service", "RDP desktop exposed"), ("cups.service", "print server"), ("avahi-daemon.service", "mDNS advertising")):
                if svc.get(s_) == "active":
                    add(s_.replace(".service", ""), "active", "warn", why)
            for s_ in ("elastic-agent.service", "ElasticEndpoint.service"):
                if s_ in svc and svc[s_] != "active":
                    add(s_.replace(".service", ""), svc[s_], "bad", "security sensor not running")
        # sysctl
        want = POLICY.get("sysctl_expect", {})
        for r in Q.get("sysctl", []):
            n, v = r.get("name"), str(r.get("current_value", "")).strip()
            if n in want and v not in [str(x) for x in want[n]["ok"]]:
                add(f"sysctl {n}", v, want[n].get("sev", "warn"), want[n].get("why", f"expected {want[n]['ok']}"))
        # exposed listeners
        for r in Q.get("listening", []):
            addr = r.get("address", "")
            if addr in ("0.0.0.0", "::", "*") or not addr.startswith(("127.", "::1", "fe80")):
                name = f"{r.get('name')} {r.get('protocol') == '6' and 'tcp' or r.get('protocol') == '17' and 'udp' or r.get('protocol')}/{r.get('port')}"
                risky = POLICY.get("risky_exposed_ports", {}).get(str(r.get("port")))
                add(f"listener {name}", f"on {addr} ({r.get('path')}, uid {r.get('uid')})", "warn" if risky else "ok", risky or "reachable from the LAN")
        # containers
        for r in Q.get("docker", []):
            bad = []
            if _yes(r.get("privileged")):
                bad.append("privileged")
            mnts = r.get("mounts") or ""
            if "/var/run/docker.sock" in mnts or "/run/docker.sock" in mnts:
                bad.append("docker.sock mounted")
            if re.search(r"(^| )/:[^ ]*:(1|true)", mnts):
                bad.append("host / mounted rw")
            add(f"container {r.get('name')}", f"{r.get('image')} {r.get('state')}", "bad" if bad else "ok", ", ".join(bad))
        # integrity checks that are always bad
        for r in Q.get("uid0", []):
            if r.get("username") != "root":
                add(f"extra UID-0 account {r.get('username')}", r.get("username"), "bad", "second root-equivalent account", crit=True)
        for r in Q.get("ld_preload", []):
            if r.get("src") == "file" and str(r.get("value")) not in ("0", ""):
                add("/etc/ld.so.preload", f"{r.get('value')} bytes", "bad", "global library injection (rootkit technique)", crit=True)
            elif r.get("src") == "env" and not any(r.get("value", "").startswith(a) for a in POLICY.get("ld_preload_allow", [])):
                add(f"LD_PRELOAD in {r.get('target')}", r.get("value"), "bad", "library injection", crit=True)
        for r in Q.get("sudoers", []):
            if "NOPASSWD" in (r.get("rule_details") or "") and not any(a in (r.get("rule_details") or "") for a in POLICY.get("nopasswd_allow", [])):
                add("sudo NOPASSWD", f"{r.get('source')}: {r.get('header')} {r.get('rule_details')}", "warn", "passwordless root")
        dels = [r for r in Q.get("proc_deleted", []) if not any(r.get("path", "").startswith(a) for a in POLICY.get("deleted_allow", []))]
        for r in dels[:10]:
            sysp = r.get("path", "").startswith(SYS_BIN)
            add(f"deleted binary still running {r.get('path')}", f"pid {r.get('pid')} {r.get('name') or ''}".strip(), "warn" if sysp else "bad",
                "replaced by an update; restart it" if sysp else "binary removed after start (fileless/malware technique)", crit=not sysp)
        for r in Q.get("proc_nonsystem", []):
            if r.get("username") == "root" and r.get("path", "").startswith(USER_WRITABLE):
                add(f"root binary in user-writable dir {r.get('path')}", r.get("path"), "bad", "root process launched from a directory a user can modify", crit=True)
        if "os" in Q and Q["os"]:
            o = Q["os"][0]
            try:
                up = int(float(o.get("uptime_s") or 0)) // 86400
            except ValueError:
                up = 0
            add("OS / kernel", f"{o.get('name')} {o.get('version')}, kernel {o.get('kernel')}, up {up}d",
                "warn" if up > POLICY.get("max_uptime_days", 45) else "ok", "long uptime - kernel updates not applied" if up > POLICY.get("max_uptime_days", 45) else "")
        out[host] = P
    return out


def findings(res, base, nightly=True):
    F = []
    add = lambda k, p, t: F.append((k, p, t))
    try:
        import extras
    except Exception:
        extras = None
    for host, Q in res.items():
        if host.startswith("_"):
            continue
        hb = base.get(host, {}).get("osq", {})
        # change detection vs baseline (only once the host+query has a baseline)
        for qid, ident in IDENT.items():
            if qid not in Q or qid not in hb:
                continue
            cur = {ident(r): r for r in Q[qid]}
            new = [k for k in cur if k not in hb[qid]]
            if qid.startswith("packages_"):
                if new:
                    add(f"osq-pkg|{host}|{','.join(sorted(new)[:5])}", "Info", f"{host}: {len(new)} new package(s): {', '.join(sorted(new)[:15])}")
                continue
            for k in new[:12]:
                add(f"osq-new|{host}|{qid}|{k}", NEW_PRI[qid], f"{host}: new {LABEL[qid]}: {k}")
            gone = [k for k in hb[qid] if k not in cur]
            if qid in ("uid0", "authorized_keys", "sudoers", "systemd_custom", "crontab") and gone and nightly:
                add(f"osq-gone|{host}|{qid}|{','.join(gone[:3])}", "Info", f"{host}: {LABEL[qid]} removed: {', '.join(gone[:5])}")
        # posture: new problems only (all current ones are in the posture table)
        seen = hb.get("_posture", {})
        for p in posture({host: Q}).get(host, []):
            if p["status"] in ("bad", "warn") and p["item"] not in seen:
                add(f"osq-posture|{host}|{p['item']}", "Investigate" if p.get("crit") else "Review",
                    f"{host} misconfiguration: {p['item']} = {p['value']}" + (f" - {p['note']}" if p["note"] else ""))
        # hashes of running non-system binaries -> MHR
        if extras and nightly:
            shas = {r.get("sha256"): r.get("path") for r in Q.get("proc_nonsystem", []) if r.get("sha256")}
            try:
                hits = extras.mhr_many(sorted(shas))
            except Exception:
                hits = {}
            for sha, pct in hits.items():
                if pct:
                    add(f"osq-mhr|{host}|{sha}", "Investigate", f"{host}: running binary {shas[sha]} matches known malware (Team Cymru MHR {pct}%) sha256 {sha}")
    return F


def update_baseline(res, base):
    today = time.strftime("%Y-%m-%d")
    for host, Q in res.items():
        if host.startswith("_"):
            continue
        hb = base.setdefault(host, {}).setdefault("osq", {})
        for qid, ident in IDENT.items():
            if qid in Q:
                d = hb.setdefault(qid, {})
                cur = {ident(r) for r in Q[qid]}
                for k in cur:
                    d.setdefault(k, today)
                if qid in ("uid0", "authorized_keys", "sudoers", "systemd_custom", "crontab"):
                    for k in [k for k in d if k not in cur]:  # removals: forget so a re-add alerts again
                        d.pop(k)
        ps = hb.setdefault("_posture", {})
        cur = {p["item"] for p in posture({host: Q}).get(host, []) if p["status"] in ("bad", "warn")}
        for k in cur:
            ps.setdefault(k, today)
        for k in [k for k in ps if k not in cur]:  # fixed -> re-alert if it regresses
            ps.pop(k)
    return base


def summary(res):
    """Compact per-host coverage for the report."""
    out = {}
    for host, Q in res.items():
        if not host.startswith("_"):
            out[host] = {qid: len(rows) for qid, rows in Q.items()}
    return out


if __name__ == "__main__":
    r = results(int(sys.argv[1]) if len(sys.argv) > 1 else 26 * 60)
    print(json.dumps(summary(r), indent=1))
    for h, P in posture(r).items():
        for p in P:
            if p["status"] != "ok":
                print(f"[{p['status']}] {h}: {p['item']} = {p['value']} {p['note']}")
