#!/usr/bin/python3
"""Kubernetes security monitoring for netmon - read-only Elasticsearch queries against Security Onion ONLY.

Everything here comes from what the Elastic Agent Kubernetes integration ships to Security Onion; netmon never talks
to the cluster (no kubectl, no API server, no kubeconfig). Sources (default SO data streams):

  logs-kubernetes.container_logs-*     container stdout/stderr (filestream /var/log/containers/*.log)
  metrics-kubernetes.event-*           Kubernetes events (Warning: BackOff, Unhealthy, FailedMount, Evicted ...)
  metrics-kubernetes.apiserver-*       API server request counters (401/403, exec/attach/portforward, secrets, RBAC)
  metrics-kubernetes.pod-* / .container-* / .node-*   pod / container / node inventory (names, IPs, start times)
  metrics-kubernetes.state_*           kube-state-metrics (coverage check only)
  .fleet-agents                        Elastic Agent health on the cluster nodes
  logs-detections.alerts-so, logs-suricata.alerts-so   SO alerts that involve a node or pod IP

overview(minutes)              -> dict for the Devices > Kubernetes page (also the nightly snapshot `snap["k8s"]`)
pod(ns, pod, minutes, ...)     -> one pod: its log lines, security hits, events, alerts (pivot from the page)
findings(data, nightly)        -> [(key, priority, text)]; the 15-minute watcher (watch.py check 8) uses nightly=False
collect(hours, update)         -> overview + the container-image baseline (store docs table "k8s/images")

API server counters are cumulative (Prometheus): the increase in a window is max - min of each series, and a process
restart (kubernetes.apiserver.process.started.sec changes) falls back to max.
`message` in container_logs is match_only_text: match_phrase works (unlike system.* where message is a keyword).
"""
import os, re, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from esq import q as _esq  # noqa: E402  ES access through integrations.py (dashboard settings) - Security Onion only


def q(index, body):
    """esq.q that fails loudly on shard failures (a bad field type in one data stream would otherwise drop it silently)."""
    r = _esq(index, body)
    sh = r.get("_shards") or {}
    if sh.get("failed"):
        why = ((sh.get("failures") or [{}])[0].get("reason") or {}).get("reason", "")
        raise RuntimeError(f"{sh['failed']} of {sh.get('total')} shards failed on {index}: {why[:200]}")
    return r

LOGS = "logs-kubernetes.container_logs-*"
EVENTS = "metrics-kubernetes.event-*"
APISERVER = "metrics-kubernetes.apiserver-*"
POD = "metrics-kubernetes.pod-*"
CONTAINER = "metrics-kubernetes.container-*"
NODE = "metrics-kubernetes.node-*"
STATE = "metrics-kubernetes.state_*"
ALERT_IX = ("logs-detections.alerts-so", "logs-suricata.alerts-so")
DATASETS = ["kubernetes.container_logs", "kubernetes.event", "kubernetes.apiserver", "kubernetes.pod", "kubernetes.container",
            "kubernetes.node", "kubernetes.system", "kubernetes.volume", "kubernetes.proxy", "kubernetes.state_pod"]
STALE_MIN = 60          # a source with no arrivals for this long is stale (container logs: the main security source)
MAX_POD_LOGS = 500

# Container-log security patterns: (key, label, severity, phrases). Phrases use match_phrase on `message`.
SEC_PATTERNS = [
    ("cmd", "Suspicious command / reverse shell", "high",
     ["/dev/tcp/", "bash -i", "nc -e", "ncat -e", "sh -i", "chmod +x /tmp", "chmod 777 /tmp", "base64 -d |", "curl | sh", "wget -O- |",
      "python -c 'import socket", "socat exec"]),
    ("miner", "Crypto-miner indicators", "high", ["xmrig", "stratum+tcp", "stratum+ssl", "cryptonight", "minerd", "nicehash"]),
    ("webattack", "Web attack payloads seen by an app", "high",
     ["${jndi:", "union select", "/etc/passwd", "../../..", "wp-login.php", "GET /.env", "GET /.git/config"]),
    ("secret", "Secret material written to a log", "medium",
     ["BEGIN RSA PRIVATE KEY", "BEGIN OPENSSH PRIVATE KEY", "BEGIN PRIVATE KEY", "BEGIN EC PRIVATE KEY", "aws_secret_access_key"]),
    ("authfail", "Authentication failures", "medium",
     ["authentication failed", "login failed", "invalid password", "invalid credentials", "failed password", "bad credentials",
      "incorrect password", "password authentication failed", "invalid token", "token expired", "invalid api key"]),
    ("denied", "Access denied / forbidden", "low",
     ["permission denied", "access denied", "forbidden", "unauthorized", "not authorized", "is forbidden"]),
    ("tls", "TLS / certificate errors", "low",
     ["x509:", "certificate has expired", "certificate signed by unknown authority", "tls: bad certificate", "TLS handshake error"]),
    ("crash", "Crashes / OOM", "low", ["panic:", "segmentation fault", "SIGSEGV", "OOMKilled", "out of memory", "fatal error:"]),
]
SEV_ORDER = {"high": 3, "medium": 2, "low": 1}
# Warning-event reasons that matter for security (the rest are availability noise, still listed on the page)
SEC_EVENT_REASONS = {"FailedCreate", "Failed", "FailedScheduling", "Evicted", "OOMKilling", "NodeNotReady", "Rebooted",
                     "FailedMount", "FailedAttachVolume", "InspectFailed", "ErrImageNeverPull", "PolicyViolation"}
SEC_EVENT_WORDS = ("forbidden", "podsecurity", "violates", "unauthorized", "denied", "admission webhook", "privileged",
                   "hostpath", "imagepull", "x509")
# API server request series worth watching
API_SUBRES = {"exec", "attach", "portforward", "proxy", "ephemeralcontainers", "token"}
API_RBAC = {"roles", "rolebindings", "clusterroles", "clusterrolebindings", "serviceaccounts", "certificatesigningrequests",
            "mutatingwebhookconfigurations", "validatingwebhookconfigurations", "secrets", "nodes", "namespaces"}
API_WRITE = {"CREATE", "POST", "UPDATE", "PUT", "PATCH", "DELETE", "DELETECOLLECTION", "APPLY"}


def policy():
    """host_policy "k8s" (Settings > Endpoint policy): signal_exempt {namespace: [pattern kinds] or ["*"]}, exec_alert, deny_alert."""
    try:
        import store
        hp = store.jload(os.path.join(os.path.dirname(os.path.abspath(__file__)), "host_policy.json")) or {}
    except Exception:  # noqa: BLE001
        hp = {}
    k = hp.get("k8s") or {}
    return {"signal_exempt": k.get("signal_exempt") or {}, "exec_alert": int(k.get("exec_alert", 1)), "deny_alert": int(k.get("deny_alert", 20))}


def exempt(ns, kind, pol=None):
    """Reason text when the namespace's container logs are exempt from this pattern kind (threat-intel / scanner apps
    legitimately log IOC strings such as 'xmrig' or '${jndi:'), else ''."""
    ex = (pol or policy())["signal_exempt"].get(ns)
    if not ex:
        return ""
    kinds = ex.get("kinds", ex) if isinstance(ex, dict) else ex
    if "*" in kinds or kind in kinds:
        return (ex.get("reason") if isinstance(ex, dict) else "") or "exempt in Endpoint policy (k8s.signal_exempt)"
    return ""


_END = {"v": None}  # explicit window end (ISO) for dashboard requests through the host broker


def rng(minutes):
    if _END["v"]:
        m = max(1, int(round(minutes)))
        return {"range": {"@timestamp": {"gte": f"{_END['v']}||-{m}m", "lte": _END["v"]}}}
    import window  # now, or the end of a collect.py time range / the watcher's arrival window
    return window.since(minutes)


def set_end(end):
    """Dashboard time picker: queries cover [end - minutes, end]. None = now. Raises ValueError for a bad timestamp."""
    if end:
        import datetime as dt
        t = dt.datetime.fromisoformat(str(end).replace("Z", "+00:00"))
        if not t.tzinfo:
            raise ValueError("end needs a UTC offset")
        end = t.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    _END["v"] = end or None


def B(agg):
    return (agg or {}).get("buckets", [])


def safe(fn, *a, default=None):
    try:
        return fn(*a)
    except Exception as e:  # noqa: BLE001 - missing index, timeout: report, never raise
        return {"error": f"{type(e).__name__}: {str(e)[:300]}"} if default is None else default


def _minutes_since(iso):
    if not iso:
        return None
    try:
        t = time.mktime(time.strptime(str(iso)[:19], "%Y-%m-%dT%H:%M:%S")) - time.timezone
        return round((time.time() - t) / 60, 1)
    except ValueError:
        return None


def _phrases(ph):
    return {"bool": {"should": [{"match_phrase": {"message": p}} for p in ph], "minimum_should_match": 1}}


def _sev_of(key):
    return next((s for k, _, s, _ in SEC_PATTERNS if k == key), "low")


# ---------------------------------------------------------------- coverage: is Security Onion receiving the data?
def coverage():
    r = q("logs-kubernetes.*,metrics-kubernetes.*", {"size": 0, "query": {"range": {"@timestamp": {"gte": "now-7d"}}},
          "aggs": {"ds": {"terms": {"field": "data_stream.dataset", "size": 60},
                          "aggs": {"ing": {"max": {"field": "event.ingested"}}, "ts": {"max": {"field": "@timestamp"}},
                                   "d24": {"filter": {"range": {"@timestamp": {"gte": "now-24h"}}}},
                                   "err": {"filter": {"exists": {"field": "error.message"}},
                                           "aggs": {"m": {"top_hits": {"size": 1, "sort": [{"@timestamp": "desc"}], "_source": ["error.message"]}}}}}}}})
    # (error.message is text in some data streams: a terms agg on it fails those shards silently, so top_hits)
    seen = {b["key"]: b for b in B(r["aggregations"]["ds"])}
    out = []
    for ds in sorted(set(DATASETS) | set(seen)):
        b = seen.get(ds)
        if not b:
            out.append({"dataset": ds, "docs_24h": 0, "last": None, "minutes": None, "state": "missing", "error": ""})
            continue
        last = b["ing"].get("value_as_string") or b["ts"].get("value_as_string")
        m = _minutes_since(last)
        err_n = b["err"]["doc_count"]
        eh = b["err"]["m"]["hits"]["hits"]
        err = str(((eh[0]["_source"].get("error") or {}).get("message") if eh else "") or "")
        state = "stale" if m is None or m > STALE_MIN else "error" if err_n and err_n >= b["doc_count"] * 0.9 else "ok"
        out.append({"dataset": ds, "docs_24h": b["d24"]["doc_count"], "last": last, "minutes": m, "state": state,
                    "error": err[:240] if err_n else "", "error_docs": err_n})
    return out


def agents(nodes):
    import hosts  # Fleet agent health (same reader as Devices > Endpoints)
    names = {n.lower() for n in nodes}
    return [a for a in hosts.fleet_agents() if (a.get("host") or "").lower() in names]


# ---------------------------------------------------------------- inventory
def inventory(minutes):
    R = rng(minutes)
    nodes = q(NODE + "," + POD + "," + CONTAINER, {"size": 0, "query": R, "aggs": {
        "n": {"terms": {"field": "kubernetes.node.name", "size": 200},
              "aggs": {"ip": {"terms": {"field": "metadata.input.beats.host.ip", "size": 1}}, "last": {"max": {"field": "@timestamp"}}}}}})
    node_rows = [{"node": b["key"], "ip": (B(b["ip"]) or [{}])[0].get("key", ""), "last": b["last"].get("value_as_string")}
                 for b in B(nodes["aggregations"]["n"])]
    pods = q(POD, {"size": 0, "query": R, "aggs": {"p": {"composite": {"size": 2000, "sources": [
        {"ns": {"terms": {"field": "kubernetes.namespace"}}}, {"pod": {"terms": {"field": "kubernetes.pod.name"}}}]},
        "aggs": {"top": {"top_hits": {"size": 1, "sort": [{"@timestamp": "desc"}],
                                      "_source": ["kubernetes.node.name", "kubernetes.pod.ip", "kubernetes.pod.start_time", "@timestamp",
                                                  "kubernetes.deployment.name", "kubernetes.statefulset.name", "kubernetes.daemonset.name",
                                                  "kubernetes.replicaset.name", "kubernetes.job.name"]}}}}}})
    prow = {}
    for b in B(pods["aggregations"]["p"]):
        s = b["top"]["hits"]["hits"][0]["_source"]
        k = s.get("kubernetes") or {}
        owner = next((f"{kind}/{(k.get(kind) or {}).get('name')}" for kind in ("deployment", "statefulset", "daemonset", "job", "replicaset")
                      if (k.get(kind) or {}).get("name")), "")
        prow[(b["key"]["ns"], b["key"]["pod"])] = {"ns": b["key"]["ns"], "pod": b["key"]["pod"], "node": (k.get("node") or {}).get("name", ""),
                                                   "ip": (k.get("pod") or {}).get("ip", ""), "owner": owner, "last": s.get("@timestamp"),
                                                   "start": (k.get("pod") or {}).get("start_time"), "containers": [], "images": [],
                                                   "logs": 0, "stderr": 0, "restarts": 0}
    # containers: start times inside the window = (re)starts
    cr = q(CONTAINER, {"size": 0, "query": R, "aggs": {"p": {"composite": {"size": 3000, "sources": [
        {"ns": {"terms": {"field": "kubernetes.namespace"}}}, {"pod": {"terms": {"field": "kubernetes.pod.name"}}},
        {"c": {"terms": {"field": "kubernetes.container.name"}}}]},
        "aggs": {"st": {"cardinality": {"field": "kubernetes.container.start_time"}}, "last_st": {"max": {"field": "kubernetes.container.start_time"}}}}}})
    for b in B(cr["aggregations"]["p"]):
        p = prow.setdefault((b["key"]["ns"], b["key"]["pod"]), {"ns": b["key"]["ns"], "pod": b["key"]["pod"], "node": "", "ip": "", "owner": "",
                                                                "last": None, "start": None, "containers": [], "images": [], "logs": 0,
                                                                "stderr": 0, "restarts": 0})
        if b["key"]["c"] not in p["containers"]:
            p["containers"].append(b["key"]["c"])
        p["restarts"] += max(0, int(b["st"]["value"] or 0) - 1)
    # container logs: volume per pod + images
    lg = q(LOGS, {"size": 0, "query": R, "aggs": {"p": {"composite": {"size": 3000, "sources": [
        {"ns": {"terms": {"field": "kubernetes.namespace"}}}, {"pod": {"terms": {"field": "kubernetes.pod.name"}}}]},
        "aggs": {"err": {"filter": {"term": {"stream": "stderr"}}}, "img": {"terms": {"field": "container.image.name", "size": 10}},
                 "c": {"terms": {"field": "kubernetes.container.name", "size": 20}}, "last": {"max": {"field": "@timestamp"}},
                 "node": {"terms": {"field": "kubernetes.node.name", "size": 1}}, "ip": {"terms": {"field": "kubernetes.pod.ip", "size": 1}}}}}})
    images = {}
    for b in B(lg["aggregations"]["p"]):
        p = prow.setdefault((b["key"]["ns"], b["key"]["pod"]), {"ns": b["key"]["ns"], "pod": b["key"]["pod"], "node": "", "ip": "", "owner": "",
                                                                "last": None, "start": None, "containers": [], "images": [], "logs": 0,
                                                                "stderr": 0, "restarts": 0})
        p["logs"], p["stderr"] = b["doc_count"], b["err"]["doc_count"]
        p["node"] = p["node"] or (B(b["node"]) or [{}])[0].get("key", "")
        p["ip"] = p["ip"] or (B(b["ip"]) or [{}])[0].get("key", "")
        p["log_last"] = b["last"].get("value_as_string")
        for c in B(b["c"]):
            if c["key"] not in p["containers"]:
                p["containers"].append(c["key"])
        for i in B(b["img"]):
            p["images"].append(i["key"])
            im = images.setdefault(i["key"], {"image": i["key"], "pods": 0, "namespaces": set(), "logs": 0})
            im["pods"] += 1
            im["namespaces"].add(b["key"]["ns"])
            im["logs"] += i["doc_count"]
    img_rows = []
    for im in images.values():
        im["namespaces"] = sorted(im["namespaces"])
        im["risk"] = image_risk(im["image"])
        img_rows.append(im)
    pods_l = sorted(prow.values(), key=lambda p: (p["ns"], p["pod"]))
    ns = {}
    for p in pods_l:
        n = ns.setdefault(p["ns"], {"ns": p["ns"], "pods": 0, "logs": 0, "stderr": 0, "restarts": 0})
        n["pods"] += 1
        n["logs"] += p["logs"]
        n["stderr"] += p["stderr"]
        n["restarts"] += p["restarts"]
    return {"nodes": node_rows, "pods": pods_l, "namespaces": sorted(ns.values(), key=lambda n: -n["pods"]),
            "images": sorted(img_rows, key=lambda i: -i["pods"])}


def image_risk(image):
    """Supply-chain hints from the image reference alone: no tag / :latest (mutable), no digest pin."""
    name = image.split("@")[0]
    last = name.rsplit("/", 1)[-1]
    out = []
    if "@sha256:" not in image:
        if ":" not in last:
            out.append("no tag (implicit :latest)")
        elif last.endswith(":latest"):
            out.append(":latest tag")
    return out


# ---------------------------------------------------------------- container-log security signals
def log_signals(minutes, ns=None, pod=None):
    f = [rng(minutes)]
    if ns:
        f.append({"term": {"kubernetes.namespace": ns}})
    if pod:
        f.append({"term": {"kubernetes.pod.name": pod}})
    aggs = {k: {"filter": _phrases(ph), "aggs": {
        "p": {"composite": {"size": 200, "sources": [{"ns": {"terms": {"field": "kubernetes.namespace"}}},
                                                     {"pod": {"terms": {"field": "kubernetes.pod.name"}}},
                                                     {"c": {"terms": {"field": "kubernetes.container.name"}}}]},
              "aggs": {"first": {"min": {"field": "@timestamp"}}, "last": {"max": {"field": "@timestamp"}},
                       "ex": {"top_hits": {"size": 2, "sort": [{"@timestamp": "desc"}], "_source": ["message", "@timestamp", "stream"]}}}}}}
            for k, _, _, ph in SEC_PATTERNS}
    r = q(LOGS, {"size": 0, "query": {"bool": {"filter": f}}, "aggs": aggs})
    rows, pol = [], policy()
    for k, label, sev, _ in SEC_PATTERNS:
        for b in B(r["aggregations"][k]["p"]):
            rows.append({"kind": k, "exempt": exempt(b["key"]["ns"], k, pol), "label": label, "severity": sev, "ns": b["key"]["ns"], "pod": b["key"]["pod"], "container": b["key"]["c"],
                         "count": b["doc_count"], "first": b["first"].get("value_as_string"), "last": b["last"].get("value_as_string"),
                         "examples": [str(h["_source"].get("message", ""))[:400] for h in b["ex"]["hits"]["hits"]]})
    rows.sort(key=lambda x: (bool(x["exempt"]), -SEV_ORDER[x["severity"]], -x["count"]))
    return rows


# ---------------------------------------------------------------- Kubernetes events
def events(minutes, ns=None, pod=None):
    f = [rng(minutes), {"term": {"kubernetes.event.type": "Warning"}}]
    if ns:
        f.append({"term": {"kubernetes.event.metadata.namespace": ns}})
    if pod:
        f.append({"term": {"kubernetes.event.involved_object.name": pod}})
    r = q(EVENTS, {"size": 300, "sort": [{"@timestamp": "desc"}], "collapse": {"field": "kubernetes.event.metadata.uid"},
                   "query": {"bool": {"filter": f}}, "_source": ["@timestamp", "kubernetes.event"]})
    out = []
    for h in r["hits"]["hits"]:
        e = (h["_source"].get("kubernetes") or {}).get("event") or {}
        md, io, ts = e.get("metadata") or {}, e.get("involved_object") or {}, e.get("timestamp") or {}
        msg = str(e.get("message") or "")
        sec = e.get("reason") in SEC_EVENT_REASONS or any(w in msg.lower() for w in SEC_EVENT_WORDS)
        out.append({"at": ts.get("last_occurrence") or h["_source"].get("@timestamp"), "first": ts.get("first_occurrence"),
                    "ns": md.get("namespace", ""), "kind": io.get("kind", ""), "object": io.get("name", ""), "reason": e.get("reason", ""),
                    "count": e.get("count") or 1, "source": (e.get("source") or {}).get("host") or (e.get("source") or {}).get("component", ""),
                    "message": msg[:500], "security": sec})
    return out


# ---------------------------------------------------------------- API server (request counters -> increases)
def apiserver(minutes):
    R = rng(minutes)
    r = q(APISERVER, {"size": 0, "query": {"bool": {"filter": [R, {"exists": {"field": "kubernetes.apiserver.request.count"}}]}},
                      "aggs": {"restart": {"cardinality": {"field": "kubernetes.apiserver.process.started.sec"}},
                               "s": {"composite": {"size": 5000, "sources": [
                                   {"verb": {"terms": {"field": "kubernetes.apiserver.request.verb", "missing_bucket": True}}},
                                   {"res": {"terms": {"field": "kubernetes.apiserver.request.resource", "missing_bucket": True}}},
                                   {"sub": {"terms": {"field": "kubernetes.apiserver.request.subresource", "missing_bucket": True}}},
                                   {"code": {"terms": {"field": "kubernetes.apiserver.request.code", "missing_bucket": True}}},
                                   {"comp": {"terms": {"field": "kubernetes.apiserver.request.component", "missing_bucket": True}}}]},
                                     "aggs": {"mx": {"max": {"field": "kubernetes.apiserver.request.count"}},
                                              "mn": {"min": {"field": "kubernetes.apiserver.request.count"}}}}}})
    restarted = (r["aggregations"]["restart"]["value"] or 0) > 1
    codes, rows = {}, []
    for b in B(r["aggregations"]["s"]):
        k = b["key"]
        mx, mn = b["mx"]["value"] or 0, b["mn"]["value"] or 0
        inc = int(mx if restarted and mx < mn else mx - mn)
        if inc <= 0:
            continue
        code = str(k.get("code") or "")
        codes[code] = codes.get(code, 0) + inc
        verb, res, sub = (k.get("verb") or "").upper(), k.get("res") or "", k.get("sub") or ""
        why = ("denied" if code in ("401", "403") else "exec" if sub in API_SUBRES and res == "pods"
               else "rbac" if res in API_RBAC and verb in API_WRITE else "secrets-read" if res == "secrets" and verb in ("GET", "LIST", "WATCH")
               else "error" if code.startswith("5") else "")
        if why:
            rows.append({"why": why, "verb": verb, "resource": res, "subresource": sub, "code": code, "component": k.get("comp") or "", "count": inc})
    rows.sort(key=lambda x: -x["count"])
    tot = sum(codes.values())
    return {"restarted": restarted, "requests": tot, "codes": dict(sorted(codes.items(), key=lambda kv: -kv[1])),
            "denied": sum(v for c, v in codes.items() if c in ("401", "403")), "throttled": codes.get("429", 0),
            "errors": sum(v for c, v in codes.items() if c.startswith("5")),
            "exec": sum(x["count"] for x in rows if x["why"] == "exec" and x["subresource"] in ("exec", "attach", "portforward", "ephemeralcontainers")),
            "rbac_writes": sum(x["count"] for x in rows if x["why"] == "rbac"), "rows": rows[:200]}


# ---------------------------------------------------------------- Security Onion alerts on node / pod IPs
def so_alerts(minutes, nodes, ips):
    ips = sorted({i for i in ips if i})[:500]
    names = sorted({n for n in nodes if n})[:200]
    if not (ips or names):
        return []
    sh = []
    if ips:
        sh += [{"terms": {"source.ip": ips}}, {"terms": {"destination.ip": ips}}]
    if names:
        sh += [{"terms": {"host.name": names}}, {"terms": {"observer.name": names}}]
    r = q(",".join(ALERT_IX), {"size": 0, "query": {"bool": {"filter": [rng(minutes)], "should": sh, "minimum_should_match": 1}},
                               "aggs": {"r": {"terms": {"field": "rule.name", "size": 50},
                                              "aggs": {"sev": {"terms": {"field": "event.severity_label", "size": 1}},
                                                       "ds": {"terms": {"field": "event.module", "size": 1}},
                                                       "src": {"terms": {"field": "source.ip", "size": 5}},
                                                       "dst": {"terms": {"field": "destination.ip", "size": 5}},
                                                       "host": {"terms": {"field": "host.name", "size": 5}},
                                                       "last": {"max": {"field": "@timestamp"}}}}}})
    return [{"rule": b["key"], "count": b["doc_count"], "severity": (B(b["sev"]) or [{}])[0].get("key", ""),
             "source": (B(b["ds"]) or [{}])[0].get("key", ""), "src": [x["key"] for x in B(b["src"])], "dst": [x["key"] for x in B(b["dst"])],
             "hosts": [x["key"] for x in B(b["host"])], "last": b["last"].get("value_as_string")} for b in B(r["aggregations"]["r"])]


# ---------------------------------------------------------------- page / snapshot
def overview(minutes):
    t0 = time.time()
    d = {"minutes": minutes, "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "source": "Security Onion Elasticsearch"}
    d["end"] = _END["v"]
    if not d["end"]:
        import window
        d["end"] = window.end()
    d["coverage"] = safe(coverage, default=[])
    inv = safe(inventory, minutes)
    d["inventory"] = inv if "error" not in inv else {"nodes": [], "pods": [], "namespaces": [], "images": [], "error": inv["error"]}
    nodes = [n["node"] for n in d["inventory"]["nodes"]]
    d["agents"] = safe(agents, nodes, default=[])
    d["signals"] = safe(log_signals, minutes, default=[])
    d["events"] = safe(events, minutes, default=[])
    d["apiserver"] = safe(apiserver, minutes)
    ips = [n["ip"] for n in d["inventory"]["nodes"]] + [p["ip"] for p in d["inventory"]["pods"]]
    d["alerts"] = safe(so_alerts, minutes, nodes, ips, default=[])
    d["findings"] = [{"key": k, "priority": p, "text": t} for k, p, t in findings(d, nightly=True)]
    d["seconds"] = round(time.time() - t0, 1)
    return d


def pod(ns, pod_name, minutes=1440, text="", container="", stream="", size=200, before=""):
    """One pod for the pivot page: newest log lines (filtered), per-container counts, security hits, events, alerts."""
    if not (ns and pod_name) or not re.match(r"^[a-z0-9.-]{1,253}$", ns) or not re.match(r"^[A-Za-z0-9._-]{1,253}$", pod_name):
        raise ValueError("bad namespace or pod name")
    size = max(1, min(int(size or 200), MAX_POD_LOGS))
    f = [rng(minutes), {"term": {"kubernetes.namespace": ns}}, {"term": {"kubernetes.pod.name": pod_name}}]
    if container:
        f.append({"term": {"kubernetes.container.name": str(container)[:120]}})
    if stream in ("stdout", "stderr"):
        f.append({"term": {"stream": stream}})
    if before:
        f.append({"range": {"@timestamp": {"lt": str(before)[:40]}}})
    must = [{"simple_query_string": {"query": str(text)[:300], "fields": ["message"], "default_operator": "and"}}] if text else []
    r = q(LOGS, {"size": size, "sort": [{"@timestamp": "desc"}], "track_total_hits": True,
                 "query": {"bool": {"filter": f, "must": must}},
                 "_source": ["@timestamp", "message", "stream", "kubernetes.container.name", "container.image.name", "kubernetes.node.name",
                             "kubernetes.pod.ip", "log.file.path", "container.id"],
                 "aggs": {"c": {"terms": {"field": "kubernetes.container.name", "size": 30},
                                "aggs": {"img": {"terms": {"field": "container.image.name", "size": 3}}, "err": {"filter": {"term": {"stream": "stderr"}}},
                                         "last": {"max": {"field": "@timestamp"}}}},
                          "h": {"date_histogram": {"field": "@timestamp", "fixed_interval": "15m" if minutes <= 1440 else "1h", "min_doc_count": 1},
                                "aggs": {"err": {"filter": {"term": {"stream": "stderr"}}}}}}})
    lines, meta = [], {}
    for h in r["hits"]["hits"]:
        s = h["_source"]
        k = s.get("kubernetes") or {}
        meta = meta or {"node": (k.get("node") or {}).get("name", ""), "ip": (k.get("pod") or {}).get("ip", "")}
        lines.append({"at": s.get("@timestamp"), "stream": s.get("stream", ""), "container": (k.get("container") or {}).get("name", ""),
                      "message": str(s.get("message", ""))[:4000]})
    a = r.get("aggregations") or {}
    cont = [{"container": b["key"], "logs": b["doc_count"], "stderr": b["err"]["doc_count"], "last": b["last"].get("value_as_string"),
             "images": [i["key"] for i in B(b["img"])]} for b in B(a.get("c"))]
    hist = [[b["key_as_string"], b["doc_count"], b["err"]["doc_count"]] for b in B(a.get("h"))]
    if not meta:  # no log lines matched: take node/IP from the pod metrics
        pm = safe(lambda: q(POD, {"size": 1, "sort": [{"@timestamp": "desc"}], "query": {"bool": {"filter": f[1:3]}},
                                  "_source": ["kubernetes.node.name", "kubernetes.pod.ip"]})["hits"]["hits"], default=[])
        if pm:
            k = pm[0]["_source"].get("kubernetes") or {}
            meta = {"node": (k.get("node") or {}).get("name", ""), "ip": (k.get("pod") or {}).get("ip", "")}
    d = {"ns": ns, "pod": pod_name, "minutes": minutes, "node": meta.get("node", ""), "ip": meta.get("ip", ""),
         "total": r["hits"]["total"]["value"], "lines": lines, "containers": cont, "histogram": hist,
         "filter": {"text": text, "container": container, "stream": stream, "before": before}}
    d["signals"] = safe(log_signals, minutes, ns, pod_name, default=[])
    d["events"] = safe(events, minutes, ns, pod_name, default=[])
    d["alerts"] = safe(so_alerts, minutes, [d["node"]] if d["node"] else [], [d["ip"]] if d["ip"] else [], default=[])
    return d


# ---------------------------------------------------------------- findings (nightly + 15-minute watcher)
def findings(d, nightly=True):
    F, pol = [], policy()
    ksm = []
    for c in d.get("coverage") or []:
        if c["dataset"] == "kubernetes.container_logs" and c["state"] in ("stale", "missing"):
            F.append((f"k8s-cov|{c['dataset']}", "Review",
                      f"Kubernetes container logs are not reaching Security Onion (last arrival {c['last'] or 'never'}): "
                      f"container-log security checks are blind - check the Kubernetes integration's 'Collect Kubernetes container logs' input in the Fleet policy"))
        elif c["dataset"] in ("kubernetes.event", "kubernetes.apiserver") and c["state"] in ("stale", "missing"):
            F.append((f"k8s-cov|{c['dataset']}", "Review", f"{c['dataset']} is not reaching Security Onion (last arrival {c['last'] or 'never'})"))
        elif c["state"] == "error" and c["dataset"].startswith("kubernetes.state_"):
            ksm.append(c)
    if nightly and ksm:
        F.append(("k8s-cov|kube-state-metrics", "Review", f"{len(ksm)} kube-state-metrics data sets only return errors ({ksm[0]['error'][:160]}) - "
                                                          f"install kube-state-metrics or remove those metricsets from the Fleet policy"))
    for a in d.get("agents") or []:
        if a.get("minutes_since_checkin") is not None and a["minutes_since_checkin"] > 30:
            F.append((f"k8s-agent|{a['host']}", "Review", f"Elastic Agent on node {a['host']} has not checked in for {a['minutes_since_checkin']:.0f} min"))
    for s in d.get("signals") or []:
        if s.get("exempt"):
            continue
        if s["severity"] == "high" or s["kind"] == "secret":
            pri = "Investigate" if s["severity"] == "high" else "Review"
            F.append((f"k8s-log|{s['kind']}|{s['ns']}|{_stable_pod(s['pod'])}|{s['container']}", pri,
                      f"{s['label']} in container logs of {s['ns']}/{s['pod']} ({s['container']}): {s['count']}x - e.g. {s['examples'][0][:200] if s['examples'] else ''}"))
        elif nightly and s["kind"] == "authfail" and s["count"] >= 20:
            F.append((f"k8s-log|authfail|{s['ns']}|{_stable_pod(s['pod'])}|{s['container']}", "Review",
                      f"{s['count']} authentication failures logged by {s['ns']}/{s['pod']} ({s['container']})"))
    a = d.get("apiserver") or {}
    if isinstance(a, dict) and "error" not in a:
        if a.get("exec", 0) >= pol["exec_alert"]:
            F.append(("k8s-api|exec", "Review", f"{a['exec']} pod exec/attach/port-forward request(s) to the Kubernetes API server "
                                                f"(interactive access into containers) - confirm they were you"))
        if a.get("denied", 0) >= pol["deny_alert"]:
            top = ", ".join(f"{x['verb']} {x['resource']}{'/' + x['subresource'] if x['subresource'] else ''} {x['code']} x{x['count']}"
                            for x in a["rows"] if x["why"] == "denied")[:240]
            F.append(("k8s-api|denied", "Review", f"{a['denied']} unauthorized/forbidden (401/403) API server responses: {top}"))
    for e in d.get("events") or []:
        if e["security"] and any(w in e["message"].lower() for w in ("forbidden", "podsecurity", "violates", "unauthorized", "denied")):
            F.append((f"k8s-ev|{e['ns']}|{e['reason']}|{_stable_pod(e['object'])}", "Review",
                      f"Kubernetes {e['reason']} on {e['kind']} {e['ns']}/{e['object']}: {e['message'][:200]}"))
    for al in d.get("alerts") or []:
        if al["severity"] in ("high", "critical"):
            F.append((f"k8s-alert|{al['rule']}", "Investigate", f"Security Onion alert on a Kubernetes node/pod: {al['rule']} x{al['count']} "
                                                                f"({', '.join(al['hosts'] or al['src'])[:120]})"))
    for im in (d.get("new_images") or []):
        F.append((f"k8s-img|{im}", "Review", f"New container image running in Kubernetes: {im}"))
    seen, out = set(), []
    for f in F:  # one finding per key (several pods of one ReplicaSet share a key)
        if f[0] not in seen:
            seen.add(f[0])
            out.append(f)
    return out


def _stable_pod(name):
    """Pod name without the ReplicaSet / random suffix, so a restarted pod keeps the same finding key."""
    return re.sub(r"(-[a-f0-9]{8,10})?-[a-z0-9]{5}$", "", name or "")


# ---------------------------------------------------------------- nightly collector + image baseline
def collect(hours=24, update=True):
    d = overview(hours * 60)
    try:
        import store
        base = store.doc_get("k8s/images", {}) or {}
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        cur = [i["image"] for i in d["inventory"].get("images") or []]
        new = [i for i in cur if i not in base]
        d["new_images"] = new if base else []  # the first run seeds the baseline silently
        if update:
            for i in cur:
                base.setdefault(i, {"first": now})["last"] = now
            store.doc_put("k8s/images", base)
        d["findings"] = [{"key": k, "priority": p, "text": t} for k, p, t in findings(d, nightly=True)]
    except Exception as e:  # noqa: BLE001
        d["image_baseline_error"] = f"{type(e).__name__}: {e}"
    return d


def watch_findings(minutes):
    """15-minute watcher: the cheap, urgent subset (no inventory): logs, API server, events, coverage, new images.
    Returns (findings, failed part names); watch.py keeps its arrival bookmark when a part failed, so a failed
    container-log query is retried next run instead of skipping that window."""
    d, errs = {}, []
    for k, fn in (("coverage", coverage), ("signals", lambda: log_signals(minutes)), ("events", lambda: events(minutes)),
                  ("apiserver", lambda: apiserver(minutes)), ("new_images", lambda: _new_images(minutes))):
        try:
            d[k] = fn()
        except Exception as e:  # noqa: BLE001 - reported to the watcher, which keeps the window
            errs.append(f"{k}: {type(e).__name__}: {str(e)[:160]}")
    return findings(d, nightly=False), errs


def _new_images(minutes):
    import store
    base = store.doc_get("k8s/images", {}) or {}
    if not base:  # no nightly baseline yet: nothing is "new"
        return []
    r = q(LOGS, {"size": 0, "query": rng(minutes), "aggs": {"i": {"terms": {"field": "container.image.name", "size": 500}}}})
    return [b["key"] for b in B(r["aggregations"]["i"]) if b["key"] not in base]


if __name__ == "__main__":
    import json
    m = int(sys.argv[1]) if len(sys.argv) > 1 else 1440
    out = overview(m)
    print(json.dumps({k: (v if k in ("coverage", "findings", "apiserver") else len(v) if isinstance(v, list) else
                          {kk: len(vv) for kk, vv in v.items()} if isinstance(v, dict) and k == "inventory" else v)
                      for k, v in out.items()}, indent=1, default=str)[:8000])
