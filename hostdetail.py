"""Event-level detail for endpoint auth failures, sudo and Elastic Defend policy health.

Run by the nightly collector (hosts.gather -> d["details"]) so the dashboard can drill down without any
Elasticsearch credentials of its own. Read-only (_search only). Uses the same key as the rest of netmon.
"""
import collections, json, os, re, ssl, sys, time, urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import site_cfg as SITE  # noqa: E402  network-specific values live in site.json (git-ignored)

ES = os.environ.get("ES_URL", SITE.get("es_url"))
def _key():
    if os.environ.get("ES_API_KEY"):
        return os.environ["ES_API_KEY"]
    try:
        return next(l.split("=", 1)[1].strip().strip("'\"") for l in open(os.path.join(os.environ.get("HERMES_HOME") or os.path.expanduser("~/.hermes"), ".env"))
                    if l.startswith("MCP_SO_ELASTICSEARCH_API_KEY="))
    except (OSError, StopIteration):
        return ""


KEY = _key()
AUTH = "logs-system.auth-default"
POLICY = "metrics-endpoint.policy-default"
_ctx = ssl._create_unverified_context()  # SO uses its own CA

# remediation hints for Elastic Defend policy actions (macOS / Linux / Windows)
DEFEND_FIX = {
    "connect_kernel": "macOS: approve the Elastic Endpoint system extension (System Settings › General › Login Items & Extensions › Endpoint Security Extensions), or push a System Extension policy via MDM.",
    "configure_kernel": "The kernel/system extension could not be configured — usually follows connect_kernel failing. Fix that first, then restart the agent.",
    "full_disk_access": "macOS: grant Full Disk Access to 'ElasticEndpoint' and 'co.elastic.systemextension' (System Settings › Privacy & Security › Full Disk Access), or deploy a PPPC profile.",
    "detect_file_write_events": "File-write monitoring needs the system extension + Full Disk Access.",
    "detect_process_events": "Process monitoring needs the system extension to be approved and running.",
    "detect_network_events": "macOS: allow the Elastic network content filter (System Settings › Network › Filters) or deploy a content-filter profile.",
    "configure_network_events": "Network events depend on the network extension / content filter being allowed.",
    "configure_file_events": "File events depend on the system extension + Full Disk Access.",
    "configure_process_events": "Process events depend on the system extension.",
    "configure_dns_events": "DNS events depend on the network extension.",
    "configure_malicious_behavior": "Behaviour protection needs process, file and network events working.",
    "agent_connectivity": "Endpoint can't talk to Elastic Agent — check `elastic-agent status` and restart the agent.",
    "download_user_artifacts": "Artifacts download from Fleet failed — check the host can reach Fleet Server (8220).",
    "download_global_artifacts": "Global artifacts download failed — check internet / Fleet artifact URL reachability.",
}


def configured():
    return bool(KEY)


def q(index, body):
    req = urllib.request.Request(f"{ES}/{index}/_search", data=json.dumps(body).encode(),
                                 headers={"Authorization": f"ApiKey {KEY}", "Content-Type": "application/json"})
    return json.load(urllib.request.urlopen(req, context=_ctx, timeout=60))


def _host(h):
    return {"term": {"host.name": {"value": h, "case_insensitive": True}}}


def _range(end_iso, minutes):
    if end_iso:
        return {"range": {"@timestamp": {"gte": f"{end_iso}||-{int(minutes)}m", "lte": end_iso}}}
    return {"range": {"@timestamp": {"gte": f"now-{int(minutes)}m"}}}


def _B(a):
    return (a or {}).get("buckets", [])


def _interval(minutes):
    return "15m" if minutes <= 1440 else "1h" if minutes <= 4320 else "3h"


def auth_failures(host, end, minutes):
    F = [_range(end, minutes), {"term": {"event.outcome": "failure"}}] + ([_host(host)] if host else [])
    r = q(AUTH, {"size": 300, "sort": [{"@timestamp": "desc"}], "query": {"bool": {"filter": F}},
                 "_source": ["@timestamp", "host.name", "user.name", "source.ip", "source.port", "process.name", "event.action",
                             "system.auth.ssh", "message"],
                 "aggs": {"t": {"date_histogram": {"field": "@timestamp", "fixed_interval": _interval(minutes)}},
                          "u": {"terms": {"field": "user.name", "size": 15}}, "s": {"terms": {"field": "source.ip", "size": 15}},
                          "p": {"terms": {"field": "process.name", "size": 10}}, "a": {"terms": {"field": "event.action", "size": 10}},
                          "h": {"terms": {"field": "host.name", "size": 20}}}})
    ev = []
    for h in r["hits"]["hits"]:
        s = h["_source"]
        ev.append({"at": s["@timestamp"], "host": (s.get("host") or {}).get("name", "").lower(), "user": ((s.get("user") or {}).get("name") or "").strip(),
                   "src": (s.get("source") or {}).get("ip") or "", "process": (s.get("process") or {}).get("name", ""),
                   "action": (s.get("event") or {}).get("action", ""), "method": (((s.get("system") or {}).get("auth") or {}).get("ssh") or {}).get("method", ""),
                   "message": (s.get("message") or "")[:300]})
    a = r["aggregations"]
    # what happened next: successful logins from the same sources/users in the same window
    srcs = [b["key"] for b in _B(a["s"])]
    users = [b["key"].strip() for b in _B(a["u"]) if b["key"].strip()]
    follow = []
    if srcs or users:
        should = ([{"terms": {"source.ip": srcs}}] if srcs else []) + ([{"terms": {"user.name": users}}] if users else [])
        r2 = q(AUTH, {"size": 60, "sort": [{"@timestamp": "desc"}], "query": {"bool": {"filter": [_range(end, minutes), {"term": {"event.outcome": "success"}},
                {"terms": {"event.action": ["ssh_login", "logged-on"]}}] + ([_host(host)] if host else []), "should": should, "minimum_should_match": 1}},
                "_source": ["@timestamp", "host.name", "user.name", "source.ip", "system.auth.ssh.method", "message"]})
        for h in r2["hits"]["hits"]:
            s = h["_source"]
            follow.append({"at": s["@timestamp"], "host": (s.get("host") or {}).get("name", "").lower(), "user": ((s.get("user") or {}).get("name") or "").strip(),
                           "src": (s.get("source") or {}).get("ip") or "", "method": (((s.get("system") or {}).get("auth") or {}).get("ssh") or {}).get("method", ""),
                           "message": (s.get("message") or "")[:200]})
    # group into attempts: same host/user/src within 2 minutes
    bursts, cur = [], None
    for e in sorted(ev, key=lambda x: x["at"]):
        t = time.mktime(time.strptime(e["at"][:19], "%Y-%m-%dT%H:%M:%S"))
        k = (e["host"], e["user"], e["src"])
        if cur and cur["k"] == k and t - cur["t1"] <= 120:
            cur["n"] += 1; cur["t1"] = t; cur["last"] = e["at"]
        else:
            cur = {"k": k, "host": k[0], "user": k[1], "src": k[2] or "local", "first": e["at"], "last": e["at"], "n": 1, "t1": t}
            bursts.append(cur)
    for b in bursts:
        b.pop("k"); b.pop("t1")
        b["then_success"] = any(f["host"] == b["host"] and f["user"] == b["user"] and (f["src"] or "local") == b["src"] and f["at"] >= b["last"] for f in follow)
    return {"total": r["hits"]["total"]["value"], "events": ev, "timeline": [[b["key_as_string"], b["doc_count"]] for b in _B(a["t"])],
            "users": {b["key"].strip() or "(none)": b["doc_count"] for b in _B(a["u"])}, "sources": {b["key"]: b["doc_count"] for b in _B(a["s"])},
            "processes": {b["key"]: b["doc_count"] for b in _B(a["p"])}, "actions": {b["key"]: b["doc_count"] for b in _B(a["a"])},
            "hosts": {b["key"].lower(): b["doc_count"] for b in _B(a["h"])}, "bursts": sorted(bursts, key=lambda b: b["last"], reverse=True),
            "successes": follow}


def sudo(host, end, minutes):
    F = [_range(end, minutes), {"exists": {"field": "system.auth.sudo.command"}}] + ([_host(host)] if host else [])
    r = q(AUTH, {"size": 400, "sort": [{"@timestamp": "desc"}], "query": {"bool": {"filter": F}},
                 "_source": ["@timestamp", "host.name", "user.name", "system.auth.sudo", "message"],
                 "aggs": {"t": {"date_histogram": {"field": "@timestamp", "fixed_interval": _interval(minutes)}},
                          "u": {"terms": {"field": "user.name", "size": 15}}, "as": {"terms": {"field": "system.auth.sudo.user", "size": 10}},
                          "err": {"terms": {"field": "system.auth.sudo.error", "size": 10}}, "h": {"terms": {"field": "host.name", "size": 20}},
                          "c": {"terms": {"field": "system.auth.sudo.command", "size": 40}}}})
    ev = []
    for h in r["hits"]["hits"]:
        s = h["_source"]
        su = ((s.get("system") or {}).get("auth") or {}).get("sudo") or {}
        ev.append({"at": s["@timestamp"], "host": (s.get("host") or {}).get("name", "").lower(), "user": ((s.get("user") or {}).get("name") or "").strip(),
                   "as": su.get("user", ""), "command": su.get("command", "")[:400], "pwd": su.get("pwd", ""), "tty": su.get("tty", ""),
                   "error": su.get("error") or "", "message": (s.get("message") or "")[:300]})
    a = r["aggregations"]
    return {"total": r["hits"]["total"]["value"], "events": ev, "timeline": [[b["key_as_string"], b["doc_count"]] for b in _B(a["t"])],
            "users": {b["key"].strip(): b["doc_count"] for b in _B(a["u"])}, "as": {b["key"]: b["doc_count"] for b in _B(a["as"])},
            "errors": {b["key"]: b["doc_count"] for b in _B(a["err"])}, "hosts": {b["key"].lower(): b["doc_count"] for b in _B(a["h"])},
            "commands": {b["key"][:200]: b["doc_count"] for b in _B(a["c"])},
            "interactive": sum(1 for e in ev if re.search(r"/(ba|z|da|k|c|fi)?sh$|/su$", e["command"].split()[0] if e["command"] else "")),
            "no_tty": sum(1 for e in ev if not e["tty"])}


def defend(host, end, minutes):
    minutes = max(minutes, 3 * 1440)
    F = [_range(end, minutes)] + ([_host(host)] if host else [])
    r = q(POLICY, {"size": 20, "sort": [{"@timestamp": "desc"}], "collapse": {"field": "host.name"}, "query": {"bool": {"filter": F}},
                   "_source": ["@timestamp", "host.name", "host.os.full", "host.os.kernel", "agent.version", "Endpoint.policy.applied"],
                   "aggs": {"h": {"terms": {"field": "host.name", "size": 20}, "aggs": {
                       "t": {"date_histogram": {"field": "@timestamp", "fixed_interval": "3h"},
                             "aggs": {"s": {"terms": {"field": "Endpoint.policy.applied.status", "size": 3}}}},
                       "first_fail": {"filter": {"term": {"Endpoint.policy.applied.status": "failure"}}, "aggs": {"m": {"min": {"field": "@timestamp"}}}},
                       "last_ok": {"filter": {"term": {"Endpoint.policy.applied.status": "success"}}, "aggs": {"m": {"max": {"field": "@timestamp"}}}}}}}})
    hist = {}
    for b in _B(r["aggregations"]["h"]):
        hist[b["key"].lower()] = {"timeline": [[t["key_as_string"], {s["key"]: s["doc_count"] for s in _B(t["s"])}] for t in _B(b["t"])],
                                  "first_failure": b["first_fail"]["m"].get("value_as_string"), "last_success": b["last_ok"]["m"].get("value_as_string")}
    out = []
    for h in r["hits"]["hits"]:
        s = h["_source"]
        p = ((s.get("Endpoint") or {}).get("policy") or {}).get("applied") or {}
        acts = p.get("actions") or []
        if isinstance(acts, dict):
            acts = [dict(name=k, **v) for k, v in acts.items()]
        cfg = ((p.get("response") or {}).get("configurations") or {})
        actions = [{"name": a.get("name"), "status": a.get("status"), "message": a.get("message"), "fix": DEFEND_FIX.get(a.get("name"), "")} for a in acts]
        bad = {a["name"] for a in actions if a["status"] != "success"}
        prot = [{"protection": k, "status": v.get("status"), "blocking": sorted(set(v.get("concerned_actions") or []) & bad),
                 "depends_on": v.get("concerned_actions") or []} for k, v in sorted(cfg.items())]
        name = (s.get("host") or {}).get("name", "").lower()
        out.append({"host": name, "at": s["@timestamp"], "status": p.get("status"), "policy": p.get("name"), "policy_version": p.get("version"),
                    "os": ((s.get("host") or {}).get("os") or {}).get("full"), "kernel": ((s.get("host") or {}).get("os") or {}).get("kernel"),
                    "agent_version": (s.get("agent") or {}).get("version"), "protections": prot,
                    "actions": sorted(actions, key=lambda a: (a["status"] == "success", a["status"] != "failure", a["name"] or "")),
                    "history": hist.get(name, {})})
    out.sort(key=lambda x: (x["status"] == "success", x["host"]))
    return {"hosts": out}


def run(kind, host, end, minutes):
    if not configured():
        return {"error": "Elasticsearch key not found"}
    minutes = max(15, min(int(minutes or 1440), 30 * 1440))
    host = (host or "").strip()[:120]
    fn = {"authfail": auth_failures, "sudo": sudo, "defend": defend}.get(kind)
    if not fn:
        return {"error": "unknown kind"}
    t = time.time()
    res = fn(host, end, minutes)
    res.update(kind=kind, host=host, end=end, minutes=minutes, took_ms=int((time.time() - t) * 1000))
    return res


def collect(minutes, end=None):
    """Snapshot payload: all three drill-downs across all hosts for the report window."""
    out = {}
    for k in ("authfail", "sudo", "defend"):
        try:
            out[k] = run(k, "", end, minutes)
        except Exception as e:
            out[k] = {"error": f"{type(e).__name__}: {e}"[:300]}
    return out
