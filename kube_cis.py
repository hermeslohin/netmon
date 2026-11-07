#!/usr/bin/python3
"""CIS Kubernetes Benchmark checks through the read-only Kubernetes API (kube_api.py) - no agent, no node access.

What a read-only API account can see decides what is checked:
  1.2-1.4  control plane flags: read from the kube-apiserver / controller-manager / scheduler static pods (kube-system)
  3.2      audit policy flag
  5.x      policies: RBAC (5.1), pod security (5.2, checked on the running pods), network policies (5.3), secrets (5.4),
           general (5.7)
  Manual   sections 1.1 (file permissions), 2 (etcd), 4 (kubelet) and the CIS "Manual" items need node or kubelet
           access (nodes/proxy), which this account deliberately does not have. They are listed with what the
           platform does by default, never reported as passed.

Each result: {id, section, title, status, level, detail, items[], scored}. status:
  pass | fail | warn (manual review: evidence listed) | accepted (fail you accepted in host_policy k8s.cis_accept) | manual
Failed checks become findings "k8s-cis|<id>" (k8s.findings -> nightly host findings, Posture, the review job).

run() -> {generated, version, url, summary{pass,fail,warn,manual,accepted}, results[]}; saved to store doc "k8s/cis".
Tuning (Settings > Endpoint policy > k8s): cis_skip_namespaces (system namespaces left out of the workload checks,
default kube-system, kube-public, kube-node-lease), cis_accept {id: reason}.
"""
import os, re, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import kube_api  # noqa: E402

SKIP_NS = ["kube-system", "kube-public", "kube-node-lease"]
MAX_ITEMS = 60
SYSTEM_PREFIX = ("system:",)


def _pol():
    try:
        import k8s
        hp = k8s.policy_raw()
    except Exception:  # noqa: BLE001
        hp = {}
    return {"skip": hp.get("cis_skip_namespaces") or SKIP_NS, "accept": hp.get("cis_accept") or {}}


# ---------------------------------------------------------------- helpers
def flags(pod):
    """--k=v / --k flags of the first container of a static control-plane pod."""
    c = ((pod.get("spec") or {}).get("containers") or [{}])[0]
    out = {}
    for a in (c.get("command") or []) + (c.get("args") or []):
        if a.startswith("--"):
            k, _, v = a[2:].partition("=")
            out[k] = v if _ else "true"
    return out


def owner(pod):
    """'<ns>/<kind>/<name>' of the controlling workload (ReplicaSet -> Deployment name), else the pod."""
    md = pod.get("metadata") or {}
    ref = next((o for o in md.get("ownerReferences") or [] if o.get("controller")), None)
    if not ref:
        return f"{md.get('namespace')}/pod/{md.get('name')}"
    kind, name = ref.get("kind", ""), ref.get("name", "")
    if kind == "ReplicaSet" and re.search(r"-[a-z0-9]{8,10}$", name):
        kind, name = "Deployment", re.sub(r"-[a-z0-9]{8,10}$", "", name)
    if kind == "Job" and re.search(r"-\d{8,}$", name):
        kind, name = "CronJob", re.sub(r"-\d{8,}$", "", name)
    return f"{md.get('namespace')}/{kind}/{name}"


def containers(pod):
    sp = pod.get("spec") or {}
    return [("init", c) for c in sp.get("initContainers") or []] + [("", c) for c in sp.get("containers") or []] \
        + [("ephemeral", c) for c in sp.get("ephemeralContainers") or []]


def psa(ns_obj):
    lab = (ns_obj.get("metadata") or {}).get("labels") or {}
    return lab.get("pod-security.kubernetes.io/enforce", "")


def R(cid, section, title, status, detail="", items=None, level=1, scored=True):
    items = sorted(set(items or []))
    return {"id": cid, "section": section, "title": title, "status": status, "level": level, "scored": scored,
            "detail": detail, "count": len(items), "items": items[:MAX_ITEMS]}


def _flag_check(cid, title, comps, fn, detail_ok="", sect="1.2 API server"):
    """fn(flags) -> (ok: bool|None, why). Fails when any control-plane instance fails."""
    bad, why, none = [], "", True
    for node, fl in comps.items():
        ok, w = fn(fl)
        if ok is None:
            continue
        none = False
        if not ok:
            bad.append(node)
            why = w
    if none:
        return R(cid, sect, title, "manual", detail_ok or "not visible from the API")
    return R(cid, sect, title, "fail" if bad else "pass", why if bad else detail_ok, [f"{n}" for n in bad])


def _has(k):
    return lambda f: (k in f and f[k] not in ("", "false"), f"--{k} is not set")


def _eq(k, v, default_ok=False):
    return lambda f: ((f.get(k, v if default_ok else None) == v), f"--{k}={f.get(k, '(not set)')}, expected {v}")


def _ge(k, n):
    def fn(f):
        try:
            return int(f.get(k, "0")) >= n, f"--{k}={f.get(k, '(not set)')}, expected >= {n}"
        except ValueError:
            return False, f"--{k}={f.get(k)} is not a number"
    return fn


def _plugins(f):
    return set(filter(None, f.get("enable-admission-plugins", "").split(","))), set(filter(None, f.get("disable-admission-plugins", "").split(",")))


# ---------------------------------------------------------------- RBAC model
def rbac_index(cli):
    roles = {("", r["metadata"]["name"]): r for r in cli.items("/apis/rbac.authorization.k8s.io/v1/clusterroles")}
    for r in cli.items("/apis/rbac.authorization.k8s.io/v1/roles"):
        roles[(r["metadata"]["namespace"], r["metadata"]["name"])] = r
    binds = cli.items("/apis/rbac.authorization.k8s.io/v1/clusterrolebindings") + cli.items("/apis/rbac.authorization.k8s.io/v1/rolebindings")
    return roles, binds


def _role_of(b, roles):
    ref, ns = b.get("roleRef") or {}, (b.get("metadata") or {}).get("namespace", "")
    return roles.get((ns, ref.get("name"))) if ref.get("kind") == "Role" else roles.get(("", ref.get("name")))


def _subj(s, bns):
    if s.get("kind") == "ServiceAccount":
        return f"sa:{s.get('namespace') or bns}/{s.get('name')}"
    return f"{s.get('kind', '').lower()}:{s.get('name')}"


def _is_system(subject, bind_name, role_name):
    """Built-in Kubernetes identities and bindings (system:*), not something an operator added."""
    return subject.split(":", 1)[1].startswith(SYSTEM_PREFIX) or (bind_name.startswith(SYSTEM_PREFIX) and role_name.startswith(SYSTEM_PREFIX))


def grants(roles, binds, test, skip_system=True):
    """[(subject, binding, role, scope)] whose bound role has a rule matching test(rule)."""
    out = []
    for b in binds:
        role = _role_of(b, roles)
        if not role:
            continue
        rules = role.get("rules") or []
        if not any(test(r) for r in rules):
            continue
        md = b.get("metadata") or {}
        scope = md.get("namespace") or "cluster"
        for s in b.get("subjects") or []:
            sub = _subj(s, md.get("namespace", ""))
            if skip_system and _is_system(sub, md.get("name", ""), role["metadata"]["name"]):
                continue
            out.append((sub, md.get("name", ""), role["metadata"]["name"], scope))
    return out


def rule_has(verbs, resources, groups=None):
    verbs, resources = set(verbs), set(resources)

    def t(r):
        rv, rr, rg = set(r.get("verbs") or []), set(r.get("resources") or []), set(r.get("apiGroups") or [])
        return bool(("*" in rv or rv & verbs) and ("*" in rr or rr & resources) and (groups is None or "*" in rg or rg & set(groups)))
    return t


def _fmt_grants(gs):
    return [f"{s} via {b} -> {r} ({sc})" for s, b, r, sc in gs]


# ---------------------------------------------------------------- the checks
def run(cli=None):
    t0 = time.time()
    cli = cli or kube_api.Client()
    pol = _pol()
    skip = set(pol["skip"])
    ver = cli.version()
    nss = cli.items("/api/v1/namespaces")
    pods = cli.items("/api/v1/pods")
    sas = cli.items("/api/v1/serviceaccounts")
    services = cli.items("/api/v1/services")
    netpols = cli.items("/apis/networking.k8s.io/v1/networkpolicies")
    cnetpols = cli.try_items("/apis/crd.projectcalico.org/v1/networkpolicies")
    gnetpols = cli.try_items("/apis/crd.projectcalico.org/v1/globalnetworkpolicies")
    roles, binds = rbac_index(cli)
    res = []

    # ---- 1.2-1.4 control plane (static pods)
    cp = {"kube-apiserver": {}, "kube-controller-manager": {}, "kube-scheduler": {}}
    for p in pods:
        md = p.get("metadata") or {}
        comp = ((md.get("labels") or {}).get("component") or "")
        if md.get("namespace") == "kube-system" and comp in cp:
            cp[comp][(p.get("spec") or {}).get("nodeName", md.get("name"))] = flags(p)
    A, C, Sch = cp["kube-apiserver"], cp["kube-controller-manager"], cp["kube-scheduler"]
    if not A:
        res.append(R("1.2", "1.2 API server", "API server flags", "manual", "No kube-apiserver static pods visible in kube-system (managed control plane?)."))
    else:
        res += [
            _flag_check("1.2.1", "--anonymous-auth is false", A, _eq("anonymous-auth", "false")),
            _flag_check("1.2.2", "--token-auth-file is not set", A, lambda f: ("token-auth-file" not in f, "--token-auth-file is set")),
            _flag_check("1.2.3", "DenyServiceExternalIPs admission plugin is set", A,
                        lambda f: ("DenyServiceExternalIPs" in _plugins(f)[0], "DenyServiceExternalIPs is not in --enable-admission-plugins")),
            _flag_check("1.2.4", "--kubelet-client-certificate and --kubelet-client-key are set", A,
                        lambda f: ("kubelet-client-certificate" in f and "kubelet-client-key" in f, "kubelet client certificate/key not set")),
            _flag_check("1.2.5", "--kubelet-certificate-authority is set", A, _has("kubelet-certificate-authority")),
            _flag_check("1.2.6", "--authorization-mode is not AlwaysAllow", A,
                        lambda f: (("AlwaysAllow" not in f.get("authorization-mode", "")) if "authorization-mode" in f else None, "authorization-mode includes AlwaysAllow"),
                        "set by --authorization-config file"),
            _flag_check("1.2.7", "--authorization-mode includes Node", A,
                        lambda f: (("Node" in f.get("authorization-mode", "").split(",")) if "authorization-mode" in f else None, "Node not in --authorization-mode"),
                        "set by --authorization-config file"),
            _flag_check("1.2.8", "--authorization-mode includes RBAC", A,
                        lambda f: (("RBAC" in f.get("authorization-mode", "").split(",")) if "authorization-mode" in f else None, "RBAC not in --authorization-mode"),
                        "set by --authorization-config file"),
            _flag_check("1.2.10", "AlwaysAdmit admission plugin is not set", A, lambda f: ("AlwaysAdmit" not in _plugins(f)[0], "AlwaysAdmit is enabled")),
            _flag_check("1.2.13", "ServiceAccount admission plugin is not disabled", A, lambda f: ("ServiceAccount" not in _plugins(f)[1], "ServiceAccount is disabled")),
            _flag_check("1.2.14", "NamespaceLifecycle admission plugin is not disabled", A, lambda f: ("NamespaceLifecycle" not in _plugins(f)[1], "NamespaceLifecycle is disabled")),
            _flag_check("1.2.15", "NodeRestriction admission plugin is set", A, lambda f: ("NodeRestriction" in _plugins(f)[0], "NodeRestriction is not enabled")),
            _flag_check("1.2.16", "--profiling is false", A, _eq("profiling", "false")),
            _flag_check("1.2.17", "--audit-log-path is set", A, _has("audit-log-path")),
            _flag_check("1.2.18", "--audit-log-maxage is 30 or more", A, _ge("audit-log-maxage", 30)),
            _flag_check("1.2.19", "--audit-log-maxbackup is 10 or more", A, _ge("audit-log-maxbackup", 10)),
            _flag_check("1.2.20", "--audit-log-maxsize is 100 or more", A, _ge("audit-log-maxsize", 100)),
            _flag_check("1.2.22", "--service-account-lookup is not false", A, lambda f: (f.get("service-account-lookup", "true") != "false", "--service-account-lookup=false")),
            _flag_check("1.2.23", "--service-account-key-file is set", A, _has("service-account-key-file")),
            _flag_check("1.2.24", "--etcd-certfile and --etcd-keyfile are set", A, lambda f: ("etcd-certfile" in f and "etcd-keyfile" in f, "etcd client certificate/key not set")),
            _flag_check("1.2.25", "--tls-cert-file and --tls-private-key-file are set", A, lambda f: ("tls-cert-file" in f and "tls-private-key-file" in f, "TLS certificate/key not set")),
            _flag_check("1.2.26", "--client-ca-file is set", A, _has("client-ca-file")),
            _flag_check("1.2.27", "--etcd-cafile is set", A, _has("etcd-cafile")),
            _flag_check("1.2.28", "--encryption-provider-config is set", A, _has("encryption-provider-config")),
            _flag_check("1.2.30", "Strong TLS: --tls-cipher-suites set or TLS 1.3 only", A,
                        lambda f: ("tls-cipher-suites" in f or f.get("tls-min-version") == "VersionTLS13", "neither strong cipher suites nor TLS 1.3 minimum")),
            _flag_check("3.2.1", "A minimal audit policy is created (--audit-policy-file)", A, _has("audit-policy-file"), sect="3.2 Logging"),
        ]
        # 1.2.6-1.2.8 with a structured authorization config: prove RBAC denies from this very account
        denied = cli.can_i("list", "secrets")
        for r in res:
            if r["id"] == "1.2.6" and r["status"] == "manual" and denied is False:
                r.update(status="pass", detail="Authorization chain is in --authorization-config; it is not AlwaysAllow: this read-only account is refused 'list secrets'.")
    if C:
        res += [
            _flag_check("1.3.2", "--profiling is false", C, _eq("profiling", "false"), sect="1.3 Controller manager"),
            _flag_check("1.3.3", "--use-service-account-credentials is true", C, _eq("use-service-account-credentials", "true"), sect="1.3 Controller manager"),
            _flag_check("1.3.4", "--service-account-private-key-file is set", C, _has("service-account-private-key-file"), sect="1.3 Controller manager"),
            _flag_check("1.3.5", "--root-ca-file is set", C, _has("root-ca-file"), sect="1.3 Controller manager"),
            _flag_check("1.3.6", "RotateKubeletServerCertificate is not disabled", C,
                        lambda f: ("RotateKubeletServerCertificate=false" not in f.get("feature-gates", ""), "feature gate disabled"), sect="1.3 Controller manager"),
            _flag_check("1.3.7", "--bind-address is 127.0.0.1", C, _eq("bind-address", "127.0.0.1"), sect="1.3 Controller manager"),
        ]
    if Sch:
        res += [_flag_check("1.4.1", "--profiling is false", Sch, _eq("profiling", "false"), sect="1.4 Scheduler"),
                _flag_check("1.4.2", "--bind-address is 127.0.0.1", Sch, _eq("bind-address", "127.0.0.1"), sect="1.4 Scheduler")]
    res += [R("1.1", "1.1 Control plane files", "Control plane configuration file permissions", "manual",
              "Needs node file access. On an immutable OS (Talos) these files are owned by the OS and not writable by workloads.", scored=False),
            R("2", "2 etcd", "etcd configuration (certificates, client auth, peer TLS)", "manual",
              "etcd is not visible to the Kubernetes API (on Talos it runs as an OS service with mutual TLS).", scored=False),
            R("4", "4 Worker nodes", "kubelet configuration (anonymous auth, authorization mode, read-only port, certificate rotation)", "manual",
              "Needs the kubelet API (nodes/proxy), which the read-only account deliberately lacks: that permission can be abused to run commands in pods.", scored=False)]

    # ---- 5.1 RBAC
    ca = [(s, b, r, sc) for s, b, r, sc in grants(roles, binds, lambda r: True, skip_system=False)
          if r == "cluster-admin" and not s.startswith("group:system:masters")]
    ca_ext = [g for g in ca if not g[0].split(":", 1)[1].startswith(SYSTEM_PREFIX)]
    res.append(R("5.1.1", "5.1 RBAC", "cluster-admin is only used where required", "warn" if ca_ext else "pass",
                 "Subjects bound to cluster-admin (besides system:masters). Each one can do anything in the cluster: confirm it needs to.", _fmt_grants(ca_ext), scored=False))
    g = grants(roles, binds, rule_has(["get", "list", "watch"], ["secrets"], [""]))
    res.append(R("5.1.2", "5.1 RBAC", "Access to secrets is minimized", "warn" if g else "pass", "Non-system subjects that can read secrets.", _fmt_grants(g), scored=False))
    wild = []
    for (ns, name), r in roles.items():
        if name.startswith(SYSTEM_PREFIX) or name in ("cluster-admin", "admin", "edit", "view"):
            continue
        if any("*" in (x.get("verbs") or []) or "*" in (x.get("resources") or []) or "*" in (x.get("apiGroups") or []) for x in r.get("rules") or []):
            wild.append(f"{'Role ' + ns + '/' if ns else 'ClusterRole '}{name}")
    res.append(R("5.1.3", "5.1 RBAC", "Wildcards in Roles and ClusterRoles are minimized", "warn" if wild else "pass", "Roles with * in verbs, resources or API groups.", wild, scored=False))
    g = grants(roles, binds, rule_has(["create"], ["pods"], [""]))
    res.append(R("5.1.4", "5.1 RBAC", "Access to create pods is minimized", "warn" if g else "pass", "Creating a pod lets a subject run code with any service account in that namespace.", _fmt_grants(g), scored=False))
    dflt = [f"{s['metadata']['namespace']}/default" for s in sas if s["metadata"]["name"] == "default" and s.get("automountServiceAccountToken") is not False
            and s["metadata"]["namespace"] not in skip]
    used = sorted({f"{b['metadata'].get('namespace', 'cluster')}/{b['metadata']['name']}" for b in binds for s in b.get("subjects") or []
                   if s.get("kind") == "ServiceAccount" and s.get("name") == "default" and not b["metadata"]["name"].startswith(SYSTEM_PREFIX)})
    res.append(R("5.1.5", "5.1 RBAC", "Default service accounts are not actively used", "fail" if dflt or used else "pass",
                 "Default service accounts that still auto-mount a token (set automountServiceAccountToken: false), and bindings that grant the default account rights.",
                 [f"automount: {x}" for x in dflt] + [f"bound: {x}" for x in used]))
    mounted = [owner(p) for p in pods if (p["metadata"]["namespace"] not in skip) and (p.get("spec") or {}).get("automountServiceAccountToken") is not False
               and not any(s["metadata"]["name"] == (p.get("spec") or {}).get("serviceAccountName", "default") and s["metadata"]["namespace"] == p["metadata"]["namespace"]
                           and s.get("automountServiceAccountToken") is False for s in sas)]
    res.append(R("5.1.6", "5.1 RBAC", "Service account tokens are only mounted where necessary", "warn" if mounted else "pass",
                 "Workloads that mount an API token. Apps that never call the Kubernetes API should set automountServiceAccountToken: false.", mounted, scored=False))
    sm = [f"{b['metadata'].get('namespace', 'cluster')}/{b['metadata']['name']}" for b in binds for s in b.get("subjects") or []
          if s.get("kind") == "Group" and s.get("name") == "system:masters"
          and not (b["metadata"]["name"] == "cluster-admin" and not b["metadata"].get("namespace"))]  # the built-in default binding
    res.append(R("5.1.7", "5.1 RBAC", "The system:masters group is not used", "fail" if sm else "manual",
                 "Extra bindings to system:masters." if sm else "No extra RBAC bindings to system:masters. Client certificates issued in that group "
                 "(often the bootstrap admin kubeconfig) cannot be seen from the API and cannot be revoked by RBAC: keep them offline.", sm, scored=False))
    g = grants(roles, binds, rule_has(["bind", "impersonate", "escalate"], ["*", "roles", "clusterroles", "users", "groups", "serviceaccounts"]))
    res.append(R("5.1.8", "5.1 RBAC", "Bind, impersonate and escalate permissions are limited", "warn" if g else "pass", "", _fmt_grants(g), scored=False))
    for cid, title, verbs, resources, groups in (
            ("5.1.9", "Access to create persistent volumes is minimized", ["create"], ["persistentvolumes"], [""]),
            ("5.1.10", "Access to the proxy sub-resource of nodes is minimized", ["get", "create", "*"], ["nodes/proxy"], [""]),
            ("5.1.11", "Access to approve certificate signing requests is minimized", ["update", "patch"], ["certificatesigningrequests/approval"], ["certificates.k8s.io"]),
            ("5.1.12", "Access to webhook configuration objects is minimized", ["create", "update", "patch", "delete"],
             ["validatingwebhookconfigurations", "mutatingwebhookconfigurations"], ["admissionregistration.k8s.io"]),
            ("5.1.13", "Access to service account token creation is minimized", ["create"], ["serviceaccounts/token"], [""])):
        g = grants(roles, binds, rule_has(verbs, resources, groups))
        res.append(R(cid, "5.1 RBAC", title, "warn" if g else "pass", "Non-system subjects with this permission.", _fmt_grants(g), scored=False))

    # ---- 5.2 pod security (running pods; PSA-privileged namespaces are a deliberate choice and are listed, not failed)
    nsmap = {n["metadata"]["name"]: n for n in nss}
    work = [p for p in pods if p["metadata"]["namespace"] not in skip and (p.get("status") or {}).get("phase") not in ("Succeeded", "Failed")]
    priv_ns = {n for n, o in nsmap.items() if psa(o) == "privileged"}
    no_psa = sorted(n for n, o in nsmap.items() if n not in skip and not psa(o))
    res.append(R("5.2.1", "5.2 Pod security", "Every namespace has a pod security enforcement level", "fail" if no_psa else "pass",
                 "Namespaces without a pod-security.kubernetes.io/enforce label (they fall back to the cluster-wide admission default). "
                 "Label them baseline or restricted so the level is explicit.", no_psa, scored=False))

    def podcheck(cid, title, test, why):
        bad, acc = set(), set()
        for p in work:
            for kind, c in containers(p):
                if test(p, c):
                    (acc if p["metadata"]["namespace"] in priv_ns else bad).add(owner(p) + (f" [{c.get('name')}]" if kind != "ephemeral" else " [ephemeral]"))
                    break
        r = R(cid, "5.2 Pod security", title, "fail" if bad else "pass", why + (f" {len(acc)} more in namespaces deliberately labelled privileged." if acc else ""), bad)
        r["accepted_items"] = sorted(acc)[:MAX_ITEMS]
        return r
    sc = lambda c: c.get("securityContext") or {}  # noqa: E731
    psc = lambda p: (p.get("spec") or {}).get("securityContext") or {}  # noqa: E731
    sp = lambda p: p.get("spec") or {}  # noqa: E731
    res += [
        podcheck("5.2.2", "Privileged containers are minimized", lambda p, c: sc(c).get("privileged") is True, "Containers with privileged: true."),
        podcheck("5.2.3", "Containers sharing the host process ID namespace are minimized", lambda p, c: sp(p).get("hostPID") is True, "Pods with hostPID."),
        podcheck("5.2.4", "Containers sharing the host IPC namespace are minimized", lambda p, c: sp(p).get("hostIPC") is True, "Pods with hostIPC."),
        podcheck("5.2.5", "Containers sharing the host network namespace are minimized", lambda p, c: sp(p).get("hostNetwork") is True, "Pods with hostNetwork."),
        podcheck("5.2.6", "allowPrivilegeEscalation is minimized", lambda p, c: sc(c).get("allowPrivilegeEscalation") is not False,
                 "Containers that do not set allowPrivilegeEscalation: false."),
        podcheck("5.2.7", "Root containers are minimized", lambda p, c: not (sc(c).get("runAsNonRoot") or psc(p).get("runAsNonRoot")
                                                                             or (sc(c).get("runAsUser", psc(p).get("runAsUser")) or 0) > 0),
                 "Containers that may run as root (no runAsNonRoot and no non-zero runAsUser)."),
        podcheck("5.2.8", "Containers with the NET_RAW capability are minimized",
                 lambda p, c: not {"ALL", "NET_RAW"} & set((sc(c).get("capabilities") or {}).get("drop") or []), "Containers that do not drop NET_RAW (or ALL)."),
        podcheck("5.2.9", "Containers with added capabilities are minimized", lambda p, c: bool((sc(c).get("capabilities") or {}).get("add")), "Containers that add capabilities."),
        podcheck("5.2.10", "Containers with capabilities assigned are minimized",
                 lambda p, c: "ALL" not in ((sc(c).get("capabilities") or {}).get("drop") or []), "Containers that do not drop ALL capabilities."),
        podcheck("5.2.12", "HostPath volumes are minimized", lambda p, c: any("hostPath" in v for v in sp(p).get("volumes") or []), "Pods with hostPath volumes."),
        podcheck("5.2.13", "Containers which use host ports are minimized", lambda p, c: any(x.get("hostPort") for x in c.get("ports") or []), "Containers with hostPort."),
    ]

    # ---- 5.3 network policies
    cni = "Calico" if any(p["metadata"]["namespace"] == "calico-system" for p in pods) else ""
    res.append(R("5.3.1", "5.3 Network policies", "The CNI in use supports network policies", "pass" if cni else "manual",
                 f"{cni} enforces NetworkPolicy." if cni else "Could not identify the CNI.", scored=False))
    covered = {n["metadata"]["namespace"] for n in netpols + cnetpols}
    has_global = bool(gnetpols)
    with_pods = {p["metadata"]["namespace"] for p in work}
    nonp = sorted(n for n in with_pods if n not in covered)
    res.append(R("5.3.2", "5.3 Network policies", "All namespaces have network policies defined", "fail" if nonp else "pass",
                 "Namespaces with running pods and no NetworkPolicy: every pod there can reach and be reached by anything."
                 + (f" ({len(gnetpols)} Calico GlobalNetworkPolicies exist and may cover some of them - check their selectors.)" if has_global else ""),
                 nonp, scored=False))

    # ---- 5.4 secrets
    env_sec = []
    for p in work:
        for kind, c in containers(p):
            if any(((e.get("valueFrom") or {}).get("secretKeyRef")) for e in c.get("env") or []) or any(e.get("secretRef") for e in c.get("envFrom") or []):
                env_sec.append(owner(p) + f" [{c.get('name')}]")
    res.append(R("5.4.1", "5.4 Secrets", "Secrets are used as files, not environment variables", "fail" if env_sec else "pass",
                 "Containers that receive secrets as environment variables (these leak into crash dumps, child processes and logs).", env_sec, scored=False))
    res.append(R("5.4.2", "5.4 Secrets", "External secret storage is considered", "manual", "Organisational decision.", scored=False))

    # ---- 5.7 general
    seccomp = [owner(p) + f" [{c.get('name')}]" for p in work for kind, c in containers(p)
               if ((sc(c).get("seccompProfile") or psc(p).get("seccompProfile") or {}).get("type") not in ("RuntimeDefault", "Localhost"))]
    res.append(R("5.7.2", "5.7 General", "The seccomp profile is set to RuntimeDefault", "fail" if seccomp else "pass",
                 "Containers without a RuntimeDefault (or Localhost) seccomp profile.", seccomp, scored=False))
    dflt_use = [owner(p) for p in pods if p["metadata"]["namespace"] == "default"] + \
               [f"default/Service/{s['metadata']['name']}" for s in services if s["metadata"]["namespace"] == "default" and s["metadata"]["name"] != "kubernetes"]
    res.append(R("5.7.4", "5.7 General", "The default namespace is not used", "fail" if dflt_use else "pass",
                 "Workloads and services in the default namespace.", dflt_use, scored=False))

    for r in res:  # accepted risks
        if r["status"] in ("fail", "warn") and r["id"] in pol["accept"]:
            r["status"], r["accepted"] = "accepted", str(pol["accept"][r["id"]])[:300]
    summ = {k: sum(1 for r in res if r["status"] == k) for k in ("pass", "fail", "warn", "manual", "accepted")}
    return {"generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "version": ver.get("gitVersion"), "url": cli.used,
            "benchmark": "CIS Kubernetes Benchmark (API-visible checks)", "skip_namespaces": sorted(skip),
            "summary": summ, "results": res, "seconds": round(time.time() - t0, 1)}


def run_and_save(cli=None):
    import store
    try:
        d = run(cli)
    except kube_api.NotConfigured as e:
        d = {"generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "error": str(e), "not_configured": True, "results": []}
    except Exception as e:  # noqa: BLE001 - keep the previous results, record the error
        prev = store.doc_get("k8s/cis", {}) or {}
        prev["error"], prev["error_at"] = f"{type(e).__name__}: {str(e)[:300]}", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        store.doc_put("k8s/cis", prev)
        return prev
    store.doc_put("k8s/cis", d)
    return d


def latest():
    import store
    return store.doc_get("k8s/cis", {}) or {}


def findings(d=None):
    """[(key, priority, text)] for failed CIS checks (warn = manual review, shown on the page only)."""
    d = d if d is not None else latest()
    out = []
    for r in d.get("results") or []:
        if r["status"] == "fail":
            ex = ", ".join(r["items"][:4]) + (f" (+{r['count'] - 4} more)" if r["count"] > 4 else "")
            out.append((f"k8s-cis|{r['id']}", "Review", f"CIS Kubernetes {r['id']} failed: {r['title']}" + (f" - {r['count']}: {ex}" if r["count"] else f" - {r['detail'][:160]}")))
    return out


if __name__ == "__main__":
    import json
    d = run_and_save() if "--save" in sys.argv else run()
    print(json.dumps({"summary": d.get("summary"), "error": d.get("error"),
                      "results": [(r["id"], r["status"], r["count"], r["title"]) for r in d.get("results") or []]}, indent=1))
