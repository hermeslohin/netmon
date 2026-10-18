#!/usr/bin/python3
"""Host-based telemetry (Elastic Agent / Fleet / Elastic Defend) for netmon. Read-only ES queries.

collect(hours)  -> dict for the nightly snapshot (`snap["hosts"]`), also updates the host baseline (store.py / SQLite)
findings(minutes, baseline) -> list of (key, priority, text) host anomalies; used by both the nightly
                               report and the 15-minute watcher (watch.py, no baseline update there).

Sources: .fleet-agents, metrics-endpoint.policy-default, logs-endpoint.alerts-*, logs-endpoint.events.*,
logs-system.auth-default, logs-system.syslog-default.
NOTE: `message` is a keyword field (ignore_above 1024) - match_phrase/match do NOT work on it; use
case-insensitive wildcard queries.
"""
import collections, json, os, re, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from esq import q  # noqa: E402

NM = os.environ.get("NETMON_DIR") or os.path.dirname(os.path.abspath(__file__))
BASE = os.path.join(NM, "baseline", "hosts_seen.json")  # legacy (pre-SQLite) - use load_base()/store.hosts_save
POL = os.path.join(os.path.dirname(os.path.abspath(__file__)), "host_policy.json")


def load_base():
    """Host baseline (formerly baseline/hosts_seen.json) from the SQLite store."""
    import store
    return store.hosts_load()


def load(p, d):
    try:
        return json.load(open(p))
    except Exception:
        return d


POLICY = load(POL, {})
ADMIN_SRC = POLICY.get("admin_sources", {})          # ip or prefix -> label
PKG_PROCS = set(POLICY.get("package_processes", []))
EXEC_ALLOW = POLICY.get("exec_allow_prefixes", [])
SENSITIVE = POLICY.get("sensitive_paths", [])
SUSP_CMD = [re.compile(p, re.I) for p in POLICY.get("suspicious_cmdline", [])]
SUSP_DIRS = POLICY.get("suspicious_exec_dirs", ["/tmp/", "/var/tmp/", "/dev/shm/"])
SYSLOG_PATTERNS = POLICY.get("syslog_patterns", {})  # name -> {"q": wildcard, "sev": ..., "watch": bool}
TRUSTED = POLICY.get("trusted_tool_paths", [])        # fnmatch globs: known AI/dev tools living in hidden dirs
SVC_PARENTS = [re.compile(x) for x in POLICY.get("service_parents", [r"/(httpd|nginx|php-fpm|java|postgres|mysqld)$"])]
SVC_CHILD = re.compile(POLICY.get("service_child_suspicious", r"/(ba|da|z|k|c)?sh$"))
SYS_PREFIX = tuple(POLICY.get("package_managed_prefixes", ["/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "/usr/lib", "/lib"]))
USER_WRITABLE = tuple(POLICY.get("user_writable_dirs", ["/home/", "/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/"]))


def trusted(path):
    import fnmatch
    return any(fnmatch.fnmatch(path or "", g) for g in TRUSTED)


def susp_location(path):
    """temp dir or hidden directory, unless the path is an allow-listed tool install."""
    path = path or ""
    return (any(path.startswith(d) for d in SUSP_DIRS) or "/." in path) and not trusted(path)


def rng(minutes):
    import window  # now, or the end of a dashboard time range
    return window.since(minutes)


def B(agg):
    return (agg or {}).get("buckets", [])


def hn(h):
    return (h or "").lower()


def src_label(ip):
    if not ip:
        return "local"
    for k, v in ADMIN_SRC.items():
        if ip == k or (k.endswith(".") and ip.startswith(k)):
            return v
    return None


def is_private(ip):
    return bool(re.match(r"^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|::1|fe80:|fd)", ip or ""))


def safe(fn, *a, default=None):
    try:
        return fn(*a)
    except Exception as e:  # missing index etc.
        return default if default is not None else {"error": f"{type(e).__name__}: {e}"}


# ---------------------------------------------------------------- Fleet / Defend health
def fleet_agents():
    r = q(".fleet-agents", {"size": 200, "query": {"term": {"active": True}},
                            "_source": ["local_metadata.host.hostname", "local_metadata.elastic.agent.version",
                                        "last_checkin_status", "last_checkin", "unhealthy_reason", "policy_id",
                                        "components.id", "components.status", "components.message"]})
    best = {}
    for h in r["hits"]["hits"]:
        s = h["_source"]
        name = ((s.get("local_metadata") or {}).get("host") or {}).get("hostname") or "?"
        if name not in best or (s.get("last_checkin") or "") > (best[name].get("last_checkin") or ""):
            best[name] = s
    out = []
    now = time.time()
    for name, s in sorted(best.items()):
        lc = s.get("last_checkin")
        age = (now - time.mktime(time.strptime(lc[:19], "%Y-%m-%dT%H:%M:%S")) + time.timezone) / 60 if lc else None
        bad = [f"{c.get('id')}={c.get('status')}" for c in s.get("components") or [] if c.get("status") != "HEALTHY"]
        out.append({"host": name, "status": s.get("last_checkin_status"), "last_checkin": lc,
                    "minutes_since_checkin": round(age, 1) if age is not None else None,
                    "unhealthy_reason": s.get("unhealthy_reason"), "policy": s.get("policy_id"),
                    "version": ((s.get("local_metadata") or {}).get("elastic") or {}).get("agent", {}).get("version"),
                    "bad_components": bad})
    return out


def defend_policy():
    r = q("metrics-endpoint.policy-default", {"size": 50, "sort": [{"@timestamp": "desc"}], "collapse": {"field": "agent.id"},
                                              "query": rng(24 * 60 * 3)})
    # macOS Endpoint reports a drifting/garbled host.name (same agent.id) - name rows from the Fleet registry instead
    try:
        fr = q(".fleet-agents", {"size": 200, "_source": ["local_metadata.host.hostname"]})
        fname = {h["_id"]: h["_source"]["local_metadata"]["host"]["hostname"] for h in fr["hits"]["hits"]}
    except Exception:
        fname = {}
    out = []
    for h in r["hits"]["hits"]:
        s = h["_source"]
        s["host"]["name"] = hn(fname.get((s.get("agent") or {}).get("id"), s["host"]["name"]))
        p = s["Endpoint"]["policy"]["applied"]
        cfg = {k: v.get("status") for k, v in ((p.get("response") or {}).get("configurations") or {}).items()}
        acts = p.get("actions") or []
        if isinstance(acts, dict):
            acts = [dict(name=k, **v) for k, v in acts.items()]
        out.append({"host": s["host"]["name"], "status": p.get("status"), "at": s["@timestamp"],
                    "failed_protections": sorted(k for k, v in cfg.items() if v != "success"),
                    "problems": [{"action": a.get("name"), "status": a.get("status"), "message": a.get("message")}
                                 for a in acts if a.get("status") != "success"][:12]})
    return out


# ---------------------------------------------------------------- detections
def endpoint_alerts(minutes):
    r = q("logs-endpoint.alerts-*", {"size": 50, "sort": [{"@timestamp": "desc"}], "query": rng(minutes),
                                     "_source": ["@timestamp", "host.name", "event.code", "event.action", "event.outcome",
                                                 "rule.name", "message", "file.path", "process.executable",
                                                 "process.command_line", "user.name", "Endpoint.policy.applied.name"]})
    return [h["_source"] for h in r["hits"]["hits"]]


# ---------------------------------------------------------------- authentication
def auth(minutes):
    A = "logs-system.auth-default"
    R = rng(minutes)
    out = {}
    r = q(A, {"size": 500, "sort": [{"@timestamp": "desc"}], "query": {"bool": {"filter": [R], "should": [
        {"term": {"event.action": "ssh_login"}}, {"term": {"process.name": "cockpit-session"}}], "minimum_should_match": 1}},
        "_source": ["@timestamp", "host.name", "event.outcome", "user.name", "source.ip", "system.auth.ssh.method",
                    "process.name", "message"]})
    logins = collections.OrderedDict()
    for h in r["hits"]["hits"]:
        s = h["_source"]
        msg = s.get("message", "")
        if s.get("process", {}).get("name") == "cockpit-session":
            if "session opened" not in msg and "authentication failure" not in msg:
                continue
            m = re.search(r"rhost=(?:::ffff:)?(\S+)", msg)
            ip = m.group(1) if m else (s.get("source") or {}).get("ip")
            outcome = "failure" if "failure" in msg else "success"
            user = re.search(r"user[= ](\w+)", msg)
            user = user.group(1) if user else (s.get("user") or {}).get("name")
            via = "cockpit"
        else:
            ip, outcome, user = (s.get("source") or {}).get("ip"), (s.get("event") or {}).get("outcome"), (s.get("user") or {}).get("name")
            via = "ssh/" + (((s.get("system") or {}).get("auth") or {}).get("ssh") or {}).get("method", "?")
        k = (hn(s["host"]["name"]), (user or "").strip(), ip or "local", outcome, via)
        e = logins.setdefault(k, {"host": k[0], "user": k[1], "src": k[2], "outcome": outcome, "via": via, "count": 0,
                                  "last": s["@timestamp"], "src_label": src_label(ip)})
        e["count"] += 1
    out["logins"] = list(logins.values())
    # failures from pam (covers sudo/su/console too)
    r = q(A, {"size": 0, "query": {"bool": {"filter": [R, {"term": {"event.outcome": "failure"}}]}},
              "aggs": {"h": {"terms": {"field": "host.name", "size": 20}, "aggs": {
                  "s": {"terms": {"field": "source.ip", "size": 10}},
                  "p": {"terms": {"field": "process.name", "size": 6}}, "u": {"terms": {"field": "user.name", "size": 6}}}}}})
    out["failures"] = [{"host": hn(b["key"]), "count": b["doc_count"], "sources": {x["key"]: x["doc_count"] for x in B(b["s"])},
                        "processes": {x["key"]: x["doc_count"] for x in B(b["p"])},
                        "users": {x["key"].strip(): x["doc_count"] for x in B(b["u"])}} for b in B(r["aggregations"]["h"])]
    for f in out["failures"]:
        loc = f["count"] - sum(f["sources"].values())
        if loc > 0:
            f["sources"]["local"] = loc
    r = q(A, {"size": 300, "sort": [{"@timestamp": "desc"}], "query": {"bool": {"filter": [R, {"exists": {"field": "system.auth.sudo.command"}}]}},
              "_source": ["@timestamp", "host.name", "user.name", "system.auth.sudo"]})
    sudo = collections.OrderedDict()
    for h in r["hits"]["hits"]:
        s = h["_source"]
        su = s["system"]["auth"]["sudo"]
        k = (hn(s["host"]["name"]), (s.get("user") or {}).get("name", "").strip(), su.get("command", ""))
        e = sudo.setdefault(k, {"host": k[0], "user": k[1], "as": su.get("user"), "command": k[2][:200], "count": 0,
                                "last": s["@timestamp"], "error": su.get("error")})
        e["count"] += 1
    out["sudo"] = list(sudo.values())
    r = q(A, {"size": 200, "sort": [{"@timestamp": "desc"}], "query": {"bool": {"filter": [R, {"terms": {"process.name": [
        "useradd", "usermod", "userdel", "passwd", "chpasswd", "gpasswd", "groupmod", "chage", "visudo"]}}]}},
        "_source": ["@timestamp", "host.name", "process.name", "message"]})
    out["account_changes"] = [{"at": h["_source"]["@timestamp"], "host": hn(h["_source"]["host"]["name"]),
                               "process": h["_source"]["process"]["name"], "message": h["_source"].get("message", "")[:200]}
                              for h in r["hits"]["hits"]]
    return out


# ---------------------------------------------------------------- endpoint process / network / file events
def processes(minutes):
    P = "logs-endpoint.events.process-default"
    R = rng(minutes)
    r = q(P, {"size": 0, "query": {"bool": {"filter": [R, {"terms": {"event.action": ["exec", "start", "fork"]}}]}},
              "aggs": {"h": {"terms": {"field": "host.name", "size": 20}, "aggs": {"e": {"terms": {"field": "process.executable", "size": 400},
                       "aggs": {"u": {"terms": {"field": "user.name", "size": 3}}, "p": {"terms": {"field": "process.parent.executable", "size": 3}},
                                "sha": {"terms": {"field": "process.hash.sha256", "size": 1}}}}}}}})
    execs = {}
    for b in B(r["aggregations"]["h"]):
        execs[hn(b["key"])] = {e["key"]: {"count": e["doc_count"], "users": [x["key"] for x in B(e["u"])],
                                          "parents": [x["key"] for x in B(e["p"])],
                                          "sha256": (B(e["sha"]) or [{}])[0].get("key")} for e in B(b["e"])}
    # raw recent exec events for command-line heuristics
    r = q(P, {"size": 2000, "sort": [{"@timestamp": "desc"}], "query": {"bool": {"filter": [R], "must_not": [
        {"term": {"event.action": "already_running"}}, {"term": {"event.action": "end"}}]}},
        "_source": ["@timestamp", "host.name", "event.action", "process.executable", "process.command_line", "process.name",
                    "process.parent.executable", "process.parent.name", "user.name", "process.hash.sha256"]})
    susp = {}
    for h in r["hits"]["hits"]:
        s = h["_source"]
        p = s.get("process") or {}
        exe, cmd = p.get("executable") or "", p.get("command_line") or ""
        par = (p.get("parent") or {}).get("executable") or ""
        act = s.get("event", {}).get("action")
        act = act[0] if isinstance(act, list) else act
        why = []
        user = (s.get("user") or {}).get("name")
        if susp_location(exe):
            why.append("binary in temp/hidden path")
        if user == "root" and exe.startswith(USER_WRITABLE) and act in ("exec", "start", "fork"):
            why.append("root running a binary from a user-writable path")
        for rx in SUSP_CMD:
            if rx.search(cmd):
                why.append(f"cmdline matches /{rx.pattern}/")
                break
        if act == "memfd_create" and not any(exe.startswith(a) for a in POLICY.get("memfd_allow", [])):
            why.append("memfd_create (fileless exec technique)")
        if any(rx.search(par) for rx in SVC_PARENTS) and SVC_CHILD.search(exe):
            why.append("shell/download tool spawned by a network or AI service")
        if why:
            k = (hn(s["host"]["name"]), exe, tuple(why))
            if k in susp:  # events are newest-first: keep newest sample, track first time and count
                susp[k]["count"] += 1
                susp[k]["first"] = s["@timestamp"]
                continue
            susp[k] = {"at": s["@timestamp"], "first": s["@timestamp"], "count": 1, "host": k[0], "exe": exe, "cmd": cmd[:250],
                       "parent": par, "user": user, "sha256": p.get("hash", {}).get("sha256"), "why": why}
    return {"execs": execs, "suspicious": list(susp.values())}


NET_IN = {"connection_accepted", "connection_accepted_ipv6"}


def net_events(minutes, cap=10000):
    """Per host -> per process: outbound destinations (ip:port/transport), DNS names looked up, inbound accepts.
    Built from raw Defend network events (connection_attempted/accepted, disconnect_received, lookup_*)."""
    r = q("logs-endpoint.events.network-default", {"size": cap, "sort": [{"@timestamp": "desc"}], "query": rng(minutes),
          "_source": ["@timestamp", "host.name", "event.action", "process.executable", "process.name", "user.name",
                      "source.ip", "source.port", "destination.ip", "destination.port", "network.transport",
                      "network.direction", "dns.question.name", "dns.resolved_ip", "network.community_id",
                      "process.entity_id"]})
    # Interpreters running our own trusted scripts (e.g. /usr/bin/python3 collect.py in the netmon folder) are
    # attributed via the process start event (cwd/args), since network events carry no args.
    tdirs = POLICY.get("trusted_script_dirs", [])
    self_ents = set()
    if tdirs:
        import fnmatch
        ents = list({(h["_source"].get("process") or {}).get("entity_id") for h in r["hits"]["hits"]
                     if (h["_source"].get("destination") or {}).get("ip")
                     and not is_private(h["_source"]["destination"]["ip"])} - {None})[:1000]
        if ents:
            try:
                pr = q("logs-endpoint.events.process-default", {"size": len(ents), "query": {"bool": {"filter": [
                    {"terms": {"process.entity_id": ents}}, {"term": {"event.action": "exec"}}]}},
                    "_source": ["process.entity_id", "process.args", "process.working_directory"]})
                for h in pr["hits"]["hits"]:
                    p = h["_source"].get("process") or {}
                    cands = [p.get("working_directory") or ""] + [a for a in (p.get("args") or []) if "/" in a]
                    if any(fnmatch.fnmatch(c, g) for c in cands for g in tdirs):
                        self_ents.add(p.get("entity_id"))
            except Exception:
                pass
    out = {}
    for h in r["hits"]["hits"]:
        s = h["_source"]
        if (s.get("process") or {}).get("entity_id") in self_ents:
            continue  # our own monitoring/collector scripts
        act = s.get("event", {}).get("action")
        act = act[0] if isinstance(act, list) else act
        p = (s.get("process") or {}).get("executable") or (s.get("process") or {}).get("name") or "?"
        e = out.setdefault(hn(s["host"]["name"]), {}).setdefault(p, {"events": 0, "dst": [], "dns": [], "ports": [], "flows": {},
                                                                    "inbound": {}, "user": (s.get("user") or {}).get("name")})
        e["events"] += 1
        dst, src = (s.get("destination") or {}), (s.get("source") or {})
        dname = ((s.get("dns") or {}).get("question") or {}).get("name")
        if dname and dname not in e["dns"]:
            e["dns"].append(dname)
        if act and act.startswith("lookup"):
            continue
        # Defend labels the remote side's FIN on an outbound connection (disconnect_received) as ingress
        # with source = remote server: only accept/ingress *connection* events count as inbound.
        inbound = act in NET_IN or ((s.get("network") or {}).get("direction") in ("ingress", "incoming")
                                    and not (act or "").startswith("disconnect"))
        if inbound:
            k = f"{src.get('ip')}->:{dst.get('port')}"
            f = e["inbound"].setdefault(k, {"src": src.get("ip"), "port": dst.get("port"), "n": 0, "last": s["@timestamp"]})
        else:
            if dst.get("ip") and dst["ip"] not in e["dst"]:
                e["dst"].append(dst["ip"])
            if dst.get("port") is not None and dst["port"] not in e["ports"]:
                e["ports"].append(dst["port"])
            k = f"{dst.get('ip')}:{dst.get('port')}/{(s.get('network') or {}).get('transport', '')}"
            f = e["flows"].setdefault(k, {"dst": dst.get("ip"), "port": dst.get("port"), "n": 0, "last": s["@timestamp"],
                                          "community_id": (s.get("network") or {}).get("community_id")})
        f["n"] += 1
    return {"hosts": out, "events": len(r["hits"]["hits"]), "capped": len(r["hits"]["hits"]) >= cap}


def net_findings(net, base, feeds=None, watch=False):
    """Host network anomalies from Defend network events, process-attributed."""
    F = []
    if not isinstance(net, dict) or "hosts" not in net:
        return F
    shells = re.compile(POLICY.get("net_suspicious_procs", r"/(ba|da|z|k|c)?sh$|/(nc|ncat|netcat|socat|telnet|perl|ruby|php|python[0-9.]*|node|osascript)$"))
    bad_ports = set(POLICY.get("net_suspicious_ports", []))
    quiet = tuple(POLICY.get("net_quiet_procs", []))
    interps = re.compile(r"/(perl|ruby|php|python[0-9.]*|node|osascript)$")
    interp_ok = POLICY.get("net_interpreter_ok", {})  # host -> [exe prefixes] whose web traffic is expected
    seeded = bool(base.get("_meta"))
    for host, procs in net["hosts"].items():
        known = base.get(host, {}).get("net", {})
        known_listen = base.get(host, {}).get("listen", {})
        hseeded = seeded and seasoned(base, host)
        newlisten = {}
        web_interp = {}
        for p, v in procs.items():
            pname = os.path.basename(p)
            susp_path = susp_location(p)
            shell_like = bool(shells.search(p)) and not trusted(p)
            for k, f in v["flows"].items():
                ip, port = f["dst"], f["port"]
                if not ip or is_private(ip):
                    continue
                tag = f"{host}|{p}|{ip}:{port}"
                if feeds:
                    try:
                        import extras
                        hit = extras.match_ip(ip, feeds)
                    except Exception:
                        hit = None
                    if hit:
                        F.append((f"hnet-ti|{tag}", "Investigate", f"{host}: {p} connected to threat-listed {ip}:{port} ({', '.join(hit)}) x{f['n']}"))
                if susp_path or shell_like:
                    if interps.search(p) and not susp_path and port in (80, 443):
                        web_interp.setdefault(p, []).append(f"{ip}:{port}")
                    else:
                        F.append((f"hnet-proc|{tag}", "Investigate", f"{host}: {'temp/hidden-path binary' if susp_path else 'shell/interpreter/netcat'} "
                                  f"{p} (user {v['user']}) opened an Internet connection to {ip}:{port} x{f['n']} - possible reverse shell / download"))
                if port in bad_ports:
                    F.append((f"hnet-port|{tag}", "Investigate", f"{host}: {p} connected to {ip} on suspicious port {port} (C2/Tor/IRC/mining) x{f['n']}"))
            newlisten = {}
            for k, f in v["inbound"].items():
                src = f["src"]
                lk = f"{pname}:{f['port']}"
                if src and not is_private(src):
                    new = hseeded and lk not in known_listen
                    F.append((f"hnet-in|{host}|{lk}|{src}", "Investigate" if new or susp_path or shell_like else "Review",
                              f"{host}: {p} accepted an Internet connection from {src} on port {f['port']} x{f['n']}"
                              + (" - NEW listener for this process" if new else "")))
                elif hseeded and known_listen and lk not in known_listen and not (src or "").startswith(("127.", "::1")) \
                        and not (isinstance(f["port"], int) and f["port"] >= 32768):  # skip loopback + ephemeral ports
                    newlisten.setdefault(lk, set()).add(src)
            for lk, srcs in newlisten.items():
                F.append((f"hnet-newlisten|{host}|{lk}", "Review", f"{host}: {p} accepted connections on port {lk.split(':')[-1]} "
                          f"for the first time (from {', '.join(sorted(map(str, srcs))[:4])})"))
            for d in v["dns"]:
                if feeds:
                    try:
                        import extras
                        dom, lists = extras.match_domain(d, feeds)
                    except Exception:
                        dom, lists = None, []
                    if dom:
                        F.append((f"hnet-dns-ti|{host}|{d}", "Investigate", f"{host}: {p} looked up threat-listed domain {d} ({dom} on {', '.join(lists)})"))
                lab = d.split(".")[0]
                if len(lab) >= 30:
                    try:
                        import extras
                        ent = extras.entropy(lab)
                    except Exception:
                        ent = 0
                    if ent >= 3.8:
                        F.append((f"hnet-dns-long|{host}|{p}|{'.'.join(d.split('.')[-2:])}", "Review",
                                  f"{host}: {p} looked up a long random-looking name {d[:90]} (entropy {ent:.1f}) - DGA/tunnel check"))
            if p in web_interp and not any(p.startswith(x) for x in interp_ok.get(host, [])):
                d_ = web_interp[p]
                F.append((f"hnet-interp|{host}|{p}", "Review", f"{host}: interpreter {p} (user {v['user']}) made HTTPS/HTTP connections to "
                          f"{len(d_)} Internet destination(s): {', '.join(d_[:5])} - expected for scripts/package tools; confirm if unfamiliar"))
            if hseeded and known and not p.startswith(quiet):
                new = [x for x in v["dst"] + v["dns"] if f"{p}->{x}" not in known and not (re.match(r"[\d.:a-f]+$", x) and is_private(x))]
                if new:
                    F.append((f"net-new|{host}|{p}|{','.join(sorted(new)[:3])}", "Review",
                              f"{host}: {p} contacted new destination(s) {', '.join(new[:6])} ports {v['ports'][:5]}"))
    return F


def file_events(minutes):
    if not SENSITIVE:
        return []
    should = [{"wildcard": {"file.path": {"value": p, "case_insensitive": True}}} for p in SENSITIVE]
    r = q("logs-endpoint.events.file-default", {"size": 200, "sort": [{"@timestamp": "desc"}], "query": {"bool": {
        "filter": [rng(minutes)], "should": should, "minimum_should_match": 1}},
        "_source": ["@timestamp", "host.name", "event.action", "file.path", "process.executable", "user.name"]})
    out = []
    for h in r["hits"]["hits"]:
        s = h["_source"]
        exe = (s.get("process") or {}).get("executable") or ""
        act = s["event"]["action"]
        out.append({"at": s["@timestamp"], "host": hn(s["host"]["name"]), "path": s["file"]["path"],
                    "action": act[0] if isinstance(act, list) else act, "process": exe,
                    "user": (s.get("user") or {}).get("name"), "package_manager": os.path.basename(exe) in PKG_PROCS})
    return out


# ---------------------------------------------------------------- syslog health / tamper signals
def syslog(minutes):
    S = "logs-system.syslog-default"
    out = {}
    for name, spec in SYSLOG_PATTERNS.items():
        flt = [rng(minutes), {"wildcard": {"message": {"value": spec["q"], "case_insensitive": True}}}]
        if spec.get("process"):
            flt.append({"term": {"process.name": spec["process"]}})
        r = q(S, {"size": 300, "sort": [{"@timestamp": "desc"}], "query": {"bool": {"filter": flt}},
                  "_source": ["@timestamp", "host.name", "message"],
                  "aggs": {"h": {"terms": {"field": "host.name", "size": 20}, "aggs": {
                      "first": {"min": {"field": "@timestamp"}}, "last": {"max": {"field": "@timestamp"}}}}}})
        for b in B(r["aggregations"]["h"]):
            samples = [x["_source"]["message"] for x in r["hits"]["hits"] if x["_source"]["host"]["name"] == b["key"]]
            ifs = collections.Counter(m for s in samples for m in re.findall(r"\b(eno\d+|enp\w+|eth\d+|ens\w+|vnet\d+|sd[a-z]\d*|nvme\w+|dm-\d+)\b", s)[:1])
            out.setdefault(hn(b["key"]), {})[name] = {"count": b["doc_count"], "first": b["first"].get("value_as_string"),
                                                     "last": b["last"].get("value_as_string"), "sev": spec.get("sev", "Review"),
                                                     "devices": dict(ifs.most_common(5)), "sample": samples[0][:220] if samples else ""}
    return out


def telemetry(minutes):
    """Last event per host per source, and volume vs the previous equal window (silent host = possible tamper/outage)."""
    out = {}
    for ix in ["logs-system.syslog-default", "logs-system.auth-default", "logs-endpoint.events.process-default",
               "logs-elastic_agent-default"]:
        r = q(ix, {"size": 0, "query": rng(minutes * 2), "aggs": {"h": {"terms": {"field": "host.name", "size": 30}, "aggs": {
            "last": {"max": {"field": "@timestamp"}},
            "now": {"filter": rng(minutes)}}}}})
        for b in B(r["aggregations"]["h"]):
            prev = b["doc_count"] - b["now"]["doc_count"]
            out.setdefault(hn(b["key"]), {})[ix.replace("logs-", "").replace("-default", "")] = {
                "last": b["last"].get("value_as_string"), "count": b["now"]["doc_count"], "prev_window": prev}
    return out


# ---------------------------------------------------------------- baseline
def seasoned(base, host):
    """True once a host has at least one prior day of baseline (avoids 'everything is new' on newly enrolled hosts)."""
    first = (base.get(host) or {}).get("_first") or ((base.get("_meta") or {}).get("seeded") if host in base else None)
    return bool(first) and first < time.strftime("%Y-%m-%d")


def update_baseline(snap):
    base = load_base()
    today = time.strftime("%Y-%m-%d")
    for h in set((snap.get("processes") or {}).get("execs", {})) | set(((snap.get("network") or {}).get("hosts") or {})):
        base.setdefault(h, {}).setdefault("_first", today)
    for host, ex in (snap.get("processes") or {}).get("execs", {}).items():
        d = base.setdefault(host, {}).setdefault("exec", {})
        hs = base[host].setdefault("exec_sha", {})
        for e, v in ex.items():
            d.setdefault(e, today)
            if v.get("sha256") and not e.startswith(SYS_PREFIX):
                hs[e] = v["sha256"]
    for host, procs in ((snap.get("network") or {}).get("hosts") or {}).items():
        d = base.setdefault(host, {}).setdefault("net", {})
        ls = base[host].setdefault("listen", {})
        for p, v in procs.items():
            for dst in v["dst"] + v["dns"]:
                d.setdefault(f"{p}->{dst}", today)
            for f in v["inbound"].values():
                ls.setdefault(f"{os.path.basename(p)}:{f['port']}", today)
    for l in (snap.get("auth") or {}).get("logins", []):
        if l["outcome"] == "success":
            base.setdefault(l["host"], {}).setdefault("login", {}).setdefault(f"{l['user']}@{l['src']}/{l['via']}", today)
    for s in (snap.get("auth") or {}).get("sudo", []):
        base.setdefault(s["host"], {}).setdefault("sudo", {}).setdefault(f"{s['user']}:{s['command'][:120]}", today)
    oq = snap.get("osquery")
    if isinstance(oq, dict) and "error" not in oq:
        import osq
        osq.update_baseline(oq, base)
    base.setdefault("_meta", {})["updated"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    base["_meta"].setdefault("seeded", today)
    import store
    store.hosts_save(base)
    return base


# ---------------------------------------------------------------- findings
def findings(data, base, nightly=True):
    """data = output of gather(); base = hosts_seen baseline (may be {}). Returns [(key, priority, text)]."""
    F = []
    add = lambda k, p, t: F.append((k, p, t))
    seeded = bool(base.get("_meta"))
    # Defend detections - always top priority
    for a in data.get("endpoint_alerts") or []:
        if isinstance(a, dict) and a.get("@timestamp"):
            add(f"defend|{a.get('host', {}).get('name')}|{(a.get('rule') or {}).get('name') or a.get('message')}|{a['@timestamp'][:13]}",
                "Investigate", f"Elastic Defend alert on {a.get('host', {}).get('name')}: {(a.get('rule') or {}).get('name') or a.get('message')}"
                f" ({(a.get('event') or {}).get('action')}/{(a.get('event') or {}).get('outcome')}) "
                f"proc {(a.get('process') or {}).get('executable', '-')} file {(a.get('file') or {}).get('path', '-')}")
    au = data.get("auth") or {}
    for l in au.get("logins", []):
        lbl = src_label(l["src"]) if l["src"] != "local" else "console/local"
        if l["outcome"] == "success" and not lbl:
            add(f"login-src|{l['host']}|{l['user']}|{l['src']}", "Investigate",
                f"Successful {l['via']} login as {l['user']} on {l['host']} from UNEXPECTED source {l['src']}"
                f"{' (Internet!)' if not is_private(l['src']) else ''} x{l['count']}")
        elif l["outcome"] == "success" and seeded and f"{l['user']}@{l['src']}/{l['via']}" not in base.get(l["host"], {}).get("login", {}):
            add(f"login-new|{l['host']}|{l['user']}|{l['src']}|{l['via']}", "Review",
                f"First-seen login: {l['user']} on {l['host']} via {l['via']} from {lbl} ({l['src']})")
    for f in au.get("failures", []):
        for src, n in f["sources"].items():
            ext = src != "local" and not is_private(src)
            thr = POLICY.get("failure_threshold", 8)
            if ext or n >= thr:
                add(f"authfail|{f['host']}|{src}", "Investigate" if ext or not src_label(src) else "Review",
                    f"{n} authentication failures on {f['host']} from {src_label(src) or 'unknown'} {src} "
                    f"(users {', '.join(f['users'])}; via {', '.join(f['processes'])})")
    for c in au.get("account_changes", []):
        m = c["message"]
        if re.search(r"nologin|shell=/bin/false", m) and "new user" in m:
            continue  # service accounts created by package installs
        pri = "Investigate" if re.search(r"group '?(wheel|sudo|admin|docker|libvirt|kvm|root)'?|sudoers|UID=0\b", m) else "Review"
        add(f"acct|{c['host']}|{m[:80]}", pri, f"Account change on {c['host']}: {c['process']}: {m}")
    for s in au.get("sudo", []):
        if s.get("error"):
            add(f"sudo-err|{s['host']}|{s['user']}", "Review", f"sudo refused on {s['host']} for {s['user']}: {s['error']} ({s['command'][:80]})")
        elif any(rx.search(s["command"]) for rx in SUSP_CMD):
            add(f"sudo-susp|{s['host']}|{s['command'][:60]}", "Investigate", f"Suspicious sudo command on {s['host']} by {s['user']}: {s['command']}")
    pr = data.get("processes") or {}
    for s in pr.get("suspicious", []):
        n = s.get("count", 1)
        add(f"proc|{s['host']}|{s['exe']}|{'/'.join(s['why'])}", "Investigate",
            f"Suspicious process on {s['host']}: {s['exe']} ({'; '.join(s['why'])}) user {s['user']} parent {s['parent']}"
            + (f" x{n} ({s['first'][5:16].replace('T', ' ')} to {s['at'][5:16].replace('T', ' ')}Z)" if n > 1 else "")
            + f" cmd: {s['cmd'][:140]}")
    if seeded:
        for host, ex in pr.get("execs", {}).items():
            known = base.get(host, {}).get("exec", {})
            if not known or not seasoned(base, host):
                continue
            new = [e for e in ex if e not in known and not any(e.startswith(a) for a in EXEC_ALLOW)]
            for e in new[:15]:
                v = ex[e]
                add(f"exec-new|{host}|{e}", "Review", f"New executable on {host}: {e} (x{v['count']}, user {','.join(v['users'])}, "
                    f"parent {','.join(v['parents'][:2])}, sha256 {str(v['sha256'])[:16]})")
    for host, ex in pr.get("execs", {}).items():
        shas = base.get(host, {}).get("exec_sha", {})
        for e, v in ex.items():
            old = shas.get(e)
            if old and v.get("sha256") and v["sha256"] != old:
                add(f"exec-sha|{host}|{e}|{v['sha256'][:16]}", "Review",
                    f"Binary changed on {host}: {e} sha256 {old[:16]} -> {v['sha256'][:16]} (not a package-managed path - "
                    f"expected only after a tool update; user {','.join(v['users'])}, parent {','.join(v['parents'][:2])})")
    for m in data.get("exec_mhr") or []:
        add(f"exec-mhr|{m['host']}|{m['sha256']}", "Investigate",
            f"Known-malware hash executed on {m['host']}: {m['exe']} sha256 {m['sha256']} (Team Cymru MHR {m['pct']}% AV detection)")
    try:
        import extras
        feeds = extras.load_feeds()
    except Exception:
        feeds = None
    F.extend(net_findings(data.get("network"), base, feeds, watch=not nightly))
    for f in data.get("files") or []:
        if f["package_manager"]:
            continue
        add(f"file|{f['host']}|{f['path']}", "Investigate" if re.search(r"authorized_keys|sudoers|shadow|ld\.so\.preload|passwd", f["path"]) else "Review",
            f"Sensitive file {f['action']} on {f['host']}: {f['path']} by {f['process']} ({f['user']})")
    for host, pats in (data.get("syslog") or {}).items():
        for name, v in pats.items():
            if not nightly and not SYSLOG_PATTERNS.get(name, {}).get("watch"):
                continue
            if v["count"] < SYSLOG_PATTERNS.get(name, {}).get("min", 1):
                continue
            dev = f" on {', '.join(f'{k} x{n}' for k, n in v['devices'].items())}" if v["devices"] else ""
            add(f"syslog|{host}|{name}", v["sev"], f"{host}: {name} x{v['count']}{dev} ({v['first'][5:16].replace('T', ' ')} to {v['last'][5:16].replace('T', ' ')}Z). e.g. {v['sample'][:150]}")
    # agent / sensor health
    for a in data.get("fleet") or []:
        if a["host"].startswith("FleetServer-"):
            continue
        stale = (a["minutes_since_checkin"] or 0) > POLICY.get("agent_stale_minutes", 30)
        if stale or (a["status"] or "").lower() in ("offline", "error"):
            add(f"agent-off|{a['host']}", "Investigate", f"Elastic Agent on {a['host']} not checking in ({a['status']}, last {a['last_checkin']}) - host down, network cut, or agent killed")
        elif nightly and (a["status"] or "").lower() not in ("online", "starting", "updating"):
            add(f"agent-deg|{a['host']}", "Review", f"Elastic Agent on {a['host']} is {a['status']} (reason {a['unhealthy_reason']}; {', '.join(a['bad_components']) or 'components healthy'})")
    if nightly:
        for p in data.get("defend") or []:
            if p["status"] != "success":
                fails = "; ".join(f"{x['action']}: {x['message']}" for x in p["problems"][:5])
                add(f"defend-pol|{p['host']}", "Review", f"Elastic Defend on {p['host']} is NOT protecting (policy {p['status']}; failed: "
                    f"{', '.join(p['failed_protections'])}). {fails}")
    oq = data.get("osquery")
    if nightly and isinstance(oq, dict) and "error" not in oq:
        import osq
        F.extend(osq.findings(oq, base, nightly=nightly))
    for host, srcs in (data.get("telemetry") or {}).items():
        sl = srcs.get("system.syslog")
        if sl and sl["count"] == 0 and sl["prev_window"] >= POLICY.get("silent_min_prev", 50):
            add(f"silent|{host}", "Investigate", f"{host} stopped sending syslog (0 events this window vs {sl['prev_window']} before; last {sl['last']}) - logging stopped or host down")
    seen_k = set()
    F = [f for f in F if not (f[0] in seen_k or seen_k.add(f[0]))]
    order = {"Investigate": 0, "Review": 1, "Info": 2}
    return sorted(F, key=lambda x: order.get(x[1], 3))


def gather(minutes, nightly=True):
    d = {"window_minutes": minutes}
    d["fleet"] = safe(fleet_agents, default=[])
    d["endpoint_alerts"] = safe(endpoint_alerts, minutes, default=[])
    d["auth"] = safe(auth, minutes)
    d["processes"] = safe(processes, minutes)
    d["network"] = safe(net_events, minutes)
    d["files"] = safe(file_events, minutes, default=[])
    d["syslog"] = safe(syslog, minutes)
    d["telemetry"] = safe(telemetry, minutes)
    if nightly:
        d["defend"] = safe(defend_policy, default=[])
        d["exec_mhr"] = safe(exec_mhr, d.get("processes"), default=[])
        d["osquery"] = safe(osquery_results, max(minutes, 26 * 60))
        d["details"] = safe(details, minutes)
    return d


def details(minutes):
    """Event-level auth-failure / sudo / Defend detail for the dashboard drill-down."""
    import hostdetail, window
    return hostdetail.collect(minutes, window.end())


def osquery_results(minutes):
    import osq
    return osq.results(minutes)


def exec_mhr(pr):
    """Team Cymru MHR lookup for every executed binary outside package-managed paths (cached in intel/)."""
    import extras
    todo = {}
    for host, ex in ((pr or {}).get("execs") or {}).items():
        for e, v in ex.items():
            if v.get("sha256") and not e.startswith(SYS_PREFIX):
                todo.setdefault(v["sha256"], []).append((host, e))
    res = extras.mhr_many(sorted(todo)) if todo else {}
    return [{"host": h, "exe": e, "sha256": sha, "pct": pct} for sha, pct in res.items() if pct for h, e in todo[sha]]


def collect(hours=24, update=True):
    """Nightly entry point (collect.py collect_extras job 'hosts')."""
    d = gather(hours * 60, nightly=True)
    base = load_base()
    try:
        import hosts_ack
        acks = hosts_ack.load()
    except Exception:
        acks = {}
    d["findings"] = [{"key": k, "priority": p, "text": t, "investigated": acks.get(k)} for k, p, t in findings(d, base, nightly=True)]
    d["baseline_seeded"] = (base.get("_meta") or {}).get("seeded")
    if update:
        update_baseline(d)
    # trim bulky exec map in the snapshot to counts
    d["exec_counts"] = {h: len(v) for h, v in ((d.get("processes") or {}).get("execs") or {}).items()}
    if isinstance(d.get("processes"), dict):
        d["processes"].pop("execs", None)
    oq = d.get("osquery")
    if isinstance(oq, dict) and "error" not in oq:  # keep posture + coverage, drop raw rows (packages are large)
        import osq
        d["posture"] = osq.posture(oq)
        d["osquery"] = {"coverage": osq.summary(oq), "docs": (oq.get("_meta") or {}).get("docs", 0)}
    return d


if __name__ == "__main__":
    mins = int(sys.argv[1]) if len(sys.argv) > 1 else 1440
    d = gather(mins, nightly=True)
    for k, p, t in findings(d, load_base(), nightly=True):
        print(f"[{p}] {t}")
