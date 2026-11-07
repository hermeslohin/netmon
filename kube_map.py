#!/usr/bin/python3
"""Kubernetes map data (Devices > Kubernetes map) from the read-only Kubernetes API (kube_api.py).

build() -> {generated, namespaces[{name, psa, pods, services, ingresses, netpols}], nodes[],
            ingresses[], services[], workloads[], pods[], edges[{from, to, kind}], cis_by_object{}}
Object ids: "ing:<ns>/<name>", "svc:<ns>/<name>", "wl:<ns>/<Kind>/<name>", "pod:<ns>/<name>".
Edges: ingress -> service (backend), service -> pod (selector), workload -> pod (owner).
Per container: image, ports, security context summary (privileged, root, privilege escalation, capabilities),
restarts, state, resources. No secrets, no ConfigMaps, no logs (logs come from Security Onion, k8s.py).
"""
import os, re, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import kube_api  # noqa: E402

LIST_CAP = 4000


def _sel_match(sel, labels):
    return bool(sel) and all(labels.get(k) == v for k, v in sel.items())


def _sec(pod, c):
    sc, ps = c.get("securityContext") or {}, (pod.get("spec") or {}).get("securityContext") or {}
    caps = sc.get("capabilities") or {}
    root = not (sc.get("runAsNonRoot") or ps.get("runAsNonRoot") or (sc.get("runAsUser", ps.get("runAsUser")) or 0) > 0)
    flags = []
    if sc.get("privileged"):
        flags.append("privileged")
    if root:
        flags.append("may run as root")
    if sc.get("allowPrivilegeEscalation") is not False:
        flags.append("privilege escalation allowed")
    if caps.get("add"):
        flags.append("adds " + ",".join(caps["add"]))
    if "ALL" not in (caps.get("drop") or []):
        flags.append("capabilities not dropped")
    if not sc.get("readOnlyRootFilesystem"):
        flags.append("writable root filesystem")
    if ((sc.get("seccompProfile") or ps.get("seccompProfile") or {}).get("type")) not in ("RuntimeDefault", "Localhost"):
        flags.append("no seccomp profile")
    return {"privileged": bool(sc.get("privileged")), "root": root, "flags": flags,
            "run_as_user": sc.get("runAsUser", ps.get("runAsUser")), "read_only_root": bool(sc.get("readOnlyRootFilesystem"))}


def _owner(pod):
    ref = next((o for o in (pod.get("metadata") or {}).get("ownerReferences") or [] if o.get("controller")), None)
    return (ref.get("kind"), ref.get("name")) if ref else (None, None)


def build(cli=None, cluster=None):
    t0 = time.time()
    cli = cli or kube_api.Client(cluster=cluster)
    nss = cli.items("/api/v1/namespaces")
    pods = cli.items("/api/v1/pods")
    svcs = cli.items("/api/v1/services")
    ings = cli.items("/apis/networking.k8s.io/v1/ingresses")
    routes = cli.try_items("/apis/traefik.io/v1alpha1/ingressroutes")
    netpols = cli.items("/apis/networking.k8s.io/v1/networkpolicies") + cli.try_items("/apis/crd.projectcalico.org/v1/networkpolicies")
    rs = {(r["metadata"]["namespace"], r["metadata"]["name"]): r for r in cli.items("/apis/apps/v1/replicasets")}
    jobs = {(j["metadata"]["namespace"], j["metadata"]["name"]): j for j in cli.items("/apis/batch/v1/jobs")}
    nodes = cli.items("/api/v1/nodes")

    np_by_ns = {}
    for n in netpols:
        np_by_ns.setdefault(n["metadata"]["namespace"], []).append(n["metadata"]["name"])
    out_pods, wl, edges = [], {}, []
    for p in pods[:LIST_CAP]:
        md, sp, st = p["metadata"], p.get("spec") or {}, p.get("status") or {}
        ns, name = md["namespace"], md["name"]
        kind, oname = _owner(p)
        if kind == "ReplicaSet":  # ReplicaSet -> its Deployment
            r = rs.get((ns, oname))
            k2 = next((o for o in (r or {}).get("metadata", {}).get("ownerReferences") or [] if o.get("controller")), None)
            if k2:
                kind, oname = k2["kind"], k2["name"]
        elif kind == "Job":
            j = jobs.get((ns, oname))
            k2 = next((o for o in (j or {}).get("metadata", {}).get("ownerReferences") or [] if o.get("controller")), None)
            if k2:
                kind, oname = k2["kind"], k2["name"]
        cst = {c["name"]: c for c in (st.get("containerStatuses") or []) + (st.get("initContainerStatuses") or [])}
        conts = []
        for kindc, c in [("init", c) for c in sp.get("initContainers") or []] + [("", c) for c in sp.get("containers") or []]:
            s = cst.get(c["name"]) or {}
            state = next(iter(s.get("state") or {}), "")
            reason = ((s.get("state") or {}).get(state) or {}).get("reason", "")
            last = (s.get("lastState") or {}).get("terminated") or {}
            conts.append({"name": c["name"], "init": kindc == "init", "image": c.get("image", ""), "image_id": s.get("imageID", ""),
                          "ports": [f"{x.get('containerPort')}/{x.get('protocol', 'TCP')}" + (f" ({x['name']})" if x.get("name") else "")
                                    for x in c.get("ports") or []],
                          "ready": s.get("ready"), "restarts": s.get("restartCount", 0), "state": state, "reason": reason,
                          "last_termination": {k: last.get(k) for k in ("reason", "exitCode", "finishedAt")} if last else None,
                          "resources": c.get("resources") or {}, "security": _sec(p, c),
                          "env_secrets": sorted({(e.get("valueFrom") or {}).get("secretKeyRef", {}).get("name") for e in c.get("env") or []
                                                 if (e.get("valueFrom") or {}).get("secretKeyRef")} |
                                                {e["secretRef"].get("name") for e in c.get("envFrom") or [] if e.get("secretRef")}),
                          "mounts": [m.get("mountPath") for m in c.get("volumeMounts") or []][:20]})
        vols = []
        for v in sp.get("volumes") or []:
            t = next((k for k in v if k != "name"), "")
            vols.append({"name": v["name"], "type": t, "detail": (v.get("hostPath") or {}).get("path") or (v.get("persistentVolumeClaim") or {}).get("claimName")
                         or (v.get("secret") or {}).get("secretName") or (v.get("configMap") or {}).get("name") or ""})
        pid = f"pod:{ns}/{name}"
        wid = f"wl:{ns}/{kind}/{oname}" if kind else ""
        if wid:
            w = wl.setdefault(wid, {"id": wid, "ns": ns, "kind": kind, "name": oname, "pods": 0, "ready": 0, "restarts": 0, "images": set()})
            w["pods"] += 1
            w["ready"] += all(c.get("ready") for c in conts if not c["init"]) and st.get("phase") == "Running"
            w["restarts"] += sum(c["restarts"] for c in conts)
            w["images"] |= {c["image"] for c in conts}
            edges.append({"from": wid, "to": pid, "kind": "owns"})
        out_pods.append({"id": pid, "ns": ns, "name": name, "workload": wid, "node": sp.get("nodeName", ""), "ip": st.get("podIP", ""),
                         "phase": st.get("phase", ""), "start": st.get("startTime"), "labels": md.get("labels") or {},
                         "service_account": sp.get("serviceAccountName", "default"),
                         "automount_token": sp.get("automountServiceAccountToken") is not False,
                         "host_network": bool(sp.get("hostNetwork")), "host_pid": bool(sp.get("hostPID")), "host_ipc": bool(sp.get("hostIPC")),
                         "containers": conts, "volumes": vols, "qos": st.get("qosClass", ""),
                         "risk": sorted({f for c in conts for f in c["security"]["flags"] if f in ("privileged", "may run as root", "adds NET_ADMIN", "adds SYS_ADMIN")}
                                        | ({"hostNetwork"} if sp.get("hostNetwork") else set()) | ({"hostPath"} if any(v["type"] == "hostPath" for v in vols) else set()))})
    out_svcs = []
    for s in svcs:
        md, sp = s["metadata"], s.get("spec") or {}
        ns, sid = md["namespace"], f"svc:{md['namespace']}/{md['name']}"
        sel = sp.get("selector") or {}
        targets = [p["id"] for p in out_pods if p["ns"] == ns and _sel_match(sel, p["labels"])]
        for t in targets:
            edges.append({"from": sid, "to": t, "kind": "selects"})
        lb = [i.get("ip") or i.get("hostname") for i in ((s.get("status") or {}).get("loadBalancer") or {}).get("ingress") or []]
        out_svcs.append({"id": sid, "ns": ns, "name": md["name"], "type": sp.get("type", "ClusterIP"), "cluster_ip": sp.get("clusterIP", ""),
                         "external": lb + (sp.get("externalIPs") or []),
                         "ports": [f"{x.get('port')}{'→' + str(x.get('targetPort')) if x.get('targetPort') not in (None, x.get('port')) else ''}/{x.get('protocol', 'TCP')}"
                                   + (f" node:{x['nodePort']}" if x.get("nodePort") else "") for x in sp.get("ports") or []],
                         "selector": sel, "pods": len(targets), "exposed": sp.get("type") in ("NodePort", "LoadBalancer") or bool(sp.get("externalIPs"))})
    svc_ids = {s["id"] for s in out_svcs}
    out_ing = []
    for i in ings:
        md, sp = i["metadata"], i.get("spec") or {}
        ns, iid = md["namespace"], f"ing:{md['namespace']}/{md['name']}"
        backs, hosts = set(), []
        tls_hosts = {h for t in sp.get("tls") or [] for h in t.get("hosts") or []}
        db = ((sp.get("defaultBackend") or {}).get("service") or {}).get("name")
        if db:
            backs.add(db)
        paths = []
        for r in sp.get("rules") or []:
            hosts.append(r.get("host", "*"))
            for pth in ((r.get("http") or {}).get("paths") or []):
                svc = (pth.get("backend") or {}).get("service") or {}
                if svc.get("name"):
                    backs.add(svc["name"])
                    paths.append(f"{r.get('host', '*')}{pth.get('path', '/')} → {svc['name']}:{(svc.get('port') or {}).get('number') or (svc.get('port') or {}).get('name', '')}")
        for b in backs:
            if f"svc:{ns}/{b}" in svc_ids:
                edges.append({"from": iid, "to": f"svc:{ns}/{b}", "kind": "routes"})
        out_ing.append({"id": iid, "ns": ns, "name": md["name"], "kind": "Ingress", "class": sp.get("ingressClassName", ""), "hosts": hosts,
                        "tls": sorted(tls_hosts), "no_tls": sorted(set(hosts) - tls_hosts), "paths": paths,
                        "annotations": {k: v for k, v in (md.get("annotations") or {}).items() if "kubectl.kubernetes.io" not in k}})
    for r in routes:  # Traefik IngressRoute CRDs
        md, sp = r["metadata"], r.get("spec") or {}
        ns, iid = md["namespace"], f"ing:{md['namespace']}/{md['name']}"
        paths, backs = [], set()
        for rr in sp.get("routes") or []:
            for s in rr.get("services") or []:
                if s.get("name"):
                    backs.add(s["name"])
                    paths.append(f"{rr.get('match', '')} → {s['name']}:{s.get('port', '')}")
        for b in backs:
            if f"svc:{ns}/{b}" in svc_ids:
                edges.append({"from": iid, "to": f"svc:{ns}/{b}", "kind": "routes"})
        hosts = re.findall(r"Host\(`([^`]+)`\)", " ".join(x.get("match", "") for x in sp.get("routes") or []))
        out_ing.append({"id": iid, "ns": ns, "name": md["name"], "kind": "IngressRoute", "class": "traefik", "hosts": hosts,
                        "tls": hosts if sp.get("tls") else [], "no_tls": [] if sp.get("tls") else hosts, "paths": paths,
                        "entry_points": sp.get("entryPoints") or [], "annotations": {}})
    out_ns = []
    for n in nss:
        name, lab = n["metadata"]["name"], n["metadata"].get("labels") or {}
        out_ns.append({"name": name, "psa": lab.get("pod-security.kubernetes.io/enforce", ""), "created": n["metadata"].get("creationTimestamp"),
                       "pods": sum(1 for p in out_pods if p["ns"] == name), "services": sum(1 for s in out_svcs if s["ns"] == name),
                       "ingresses": sum(1 for i in out_ing if i["ns"] == name), "netpols": sorted(np_by_ns.get(name, []))})
    out_nodes = [{"name": x["metadata"]["name"], "roles": sorted(k.split("/", 1)[1] for k in (x["metadata"].get("labels") or {}) if k.startswith("node-role.kubernetes.io/")),
                  "ip": next((a["address"] for a in (x.get("status") or {}).get("addresses") or [] if a["type"] == "InternalIP"), ""),
                  "kubelet": ((x.get("status") or {}).get("nodeInfo") or {}).get("kubeletVersion", ""),
                  "arch": ((x.get("status") or {}).get("nodeInfo") or {}).get("architecture", ""),
                  "os": ((x.get("status") or {}).get("nodeInfo") or {}).get("osImage", ""),
                  "ready": any(c["type"] == "Ready" and c["status"] == "True" for c in (x.get("status") or {}).get("conditions") or [])} for x in nodes]
    cis = {}
    try:
        import kube_cis
        for r in kube_cis.latest(getattr(cli, "name", "default")).get("results") or []:
            if r["status"] != "fail":
                continue
            for it in r.get("items") or []:
                m = re.match(r"^([a-z0-9.-]+)/(\w+)/([^ ]+)", it)
                if m:
                    cis.setdefault(f"wl:{m.group(1)}/{m.group(2)}/{m.group(3)}", []).append(f"{r['id']} {r['title']}")
                elif re.match(r"^[a-z0-9.-]+$", it):
                    cis.setdefault(f"ns:{it}", []).append(f"{r['id']} {r['title']}")
    except Exception:  # noqa: BLE001 - the map works without CIS results
        cis = {}
    for w in wl.values():
        w["images"] = sorted(w["images"])
        w["cis"] = sorted(set(cis.get(w["id"], [])))
    return {"generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "api": cli.used, "cluster": getattr(cli, "name", "default"), "namespaces": sorted(out_ns, key=lambda n: n["name"]),
            "nodes": out_nodes, "ingresses": out_ing, "services": out_svcs, "workloads": sorted(wl.values(), key=lambda w: w["id"]),
            "pods": out_pods, "edges": edges, "cis_ns": {k[3:]: sorted(set(v)) for k, v in cis.items() if k.startswith("ns:")}, "seconds": round(time.time() - t0, 1)}


if __name__ == "__main__":
    import json
    d = build()
    print(json.dumps({k: (len(v) if isinstance(v, list) else v) for k, v in d.items()}, indent=1, default=str))
