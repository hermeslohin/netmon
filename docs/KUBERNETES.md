# Kubernetes monitoring

netmon can watch one or more Kubernetes clusters. It uses two separate, read-only paths:

| Path | What it reads | Needs | Feeds |
|---|---|---|---|
| **Security Onion / Elasticsearch** | container logs, Kubernetes warning events, API server request metrics, pod / container / node metrics, IDS and detection alerts on node and pod IPs | the Elastic Agent **Kubernetes integration** in each cluster, shipping to the same Elasticsearch | Devices → Kubernetes (signals, events, API server, pods), the watcher (every event window, default 10 min), Open events |
| **Kubernetes API** (one read-only account per cluster) | cluster configuration: namespaces, workloads, pods, services, ingresses, network policies, RBAC, control-plane flags, running image digests | a ServiceAccount token with get/list/watch only | CIS benchmark, Kubernetes map, container image updates and CVEs |

The two paths are independent. A cluster without the Elastic Agent still gets the CIS benchmark, the map and the image
checks. A cluster without an API account still gets the log, event and alert monitoring.

netmon never changes a cluster. It does not read secrets, ConfigMaps or pod logs through the API (logs come only from
Elasticsearch), and it cannot exec into pods.

## Setup

### Logs, events and metrics (Elasticsearch)

Add the Elastic Agent **Kubernetes** integration to the cluster's Fleet policy with these inputs:

- **Container logs** (`kubernetes.container_logs`): the main security source.
- **Events** (`kubernetes.event`).
- **API server metrics** (`kubernetes.apiserver`).
- **Pod, container and node metrics** (`kubernetes.pod`, `kubernetes.container`, `kubernetes.node`).

kube-state-metrics is optional. When it is missing, the *Security Onion data coverage* box lists the `state_*` data
sets as errors, and the nightly run reports them once.

Elasticsearch documents from Kubernetes carry no cluster name, so netmon attributes each document to the cluster that
owns the node that sent it. For that matching to work, the cluster also needs an API account (next section).

### Read-only API account (per cluster)

1. Apply `docs/kubernetes-readonly.yaml` in the cluster. It creates:
   - the `netmon-readonly` namespace with pod security set to `restricted`;
   - a ServiceAccount, with the default account's token automount turned off;
   - a long-lived token Secret;
   - a ClusterRole and binding with **get / list / watch** on named resources only.

   The role does **not** include `secrets`, `configmaps`, `pods/log`, `pods/exec`, `pods/attach`,
   `pods/portforward`, `nodes/proxy` (the kubelet API, which can be abused to run commands) or
   `serviceaccounts/token`.
2. Read the token and the cluster CA:
   ```sh
   kubectl -n netmon-readonly get secret netmon-readonly-token -o jsonpath='{.data.token}' | base64 -d
   kubectl config view --raw --minify -o jsonpath='{.clusters[0].cluster.certificate-authority-data}' | base64 -d
   ```
3. In **Settings → Configuration → Integrations**, fill in the **Kubernetes API: add a cluster** card:
   - a short name;
   - the API server URL(s), comma-separated, one per control-plane node;
   - the token and the CA.
4. Click **Test connection**. It shows the version and node count. It also asks the API server
   (SelfSubjectAccessReview) whether the token may list secrets, create pods, exec, use nodes/proxy, delete or update.
   If any answer is yes, Test reports that the token is **not read-only**.
5. Turn on **Enabled** (and **Run CIS benchmark checks**), then click **Save**.

The token is write-only: it is stored on the server and never shown again. The API server certificate is always
verified. Each configured cluster has its own card, and **Remove cluster** deletes the cluster and its token.

## What netmon checks

### From Elasticsearch (`k8s.py`)

- **Coverage:** last arrival and collector errors per Kubernetes data set. Stale container logs are a finding.
- **Container-log signals:** log lines matching:
  - reverse shells and suspicious commands;
  - crypto-miner indicators;
  - web-attack payloads;
  - private keys written to logs;
  - authentication failures, access denied, TLS errors and crashes.

  Namespaces whose logs legitimately contain such text (a threat-intel platform, a scanner) can be exempted per
  pattern kind in `host_policy` → `k8s.signal_exempt`.
- **API server:** per-window increases of the request counters: 401/403 responses, pod exec / attach / port-forward,
  writes to RBAC objects, secrets, webhooks and nodes, throttling and 5xx. These are counters, not audit logs, so they
  have no user names.
- **Warning events** and **Security Onion alerts** on node and pod IPs.
- **New images:** an image not seen in the nightly baseline.

**Pod pivot.** Click a pod anywhere to open its page. It shows the pod notes, links to Kibana, the log volume (stderr marked) and the newest container logs with text, container and stream filters, plus its security hits, warning events and alerts. A workload name (from a pod note or the Risk page) shows all its pods.

### Through the API

- **CIS Kubernetes Benchmark** (`kube_cis.py`), every 6 hours and on **Run now**. It covers:
  - control-plane flags (1.2–1.4, 3.2), read from the control-plane static pods when the control plane runs as pods;
  - RBAC (5.1);
  - pod security on the running pods (5.2);
  - network policies (5.3);
  - secrets in environment variables (5.4);
  - seccomp and use of the default namespace (5.7).

  File permissions (1.1), etcd (2) and the kubelet (4) need node access and are listed as *manual*, never as passed.
  Pods in namespaces labelled `pod-security.kubernetes.io/enforce=privileged` are listed but do not fail the
  pod-security checks. You can accept a failed check with a reason in `host_policy` → `k8s.cis_accept`.
- **Kubernetes map** (`kube_map.py`): namespaces with their ingresses → services → pods → containers, and each
  container's security context. Details on click.
- **Container images** (`kube_images.py`), daily at 04:00 UTC and on **Scan now**. For each running image digest:
  - the newest tag of the same form in its registry (anonymous pull token; pre-releases are skipped);
  - a [Trivy](https://trivy.dev) scan of the running digest and of the newest tag (`aquasec/trivy` in Docker, images
    read straight from the registry);
  - which CVEs updating would fix, and which critical/high CVEs a rebuild alone would fix (fixed package versions).

  Results are cached per digest for 24 hours. The Trivy database is kept in `~/netmon-trivy-cache` (about 3 GB).

## Risk page

Every workload (Deployment, StatefulSet, DaemonSet, Job, bare pod) is scored with the same model as hosts and ranked in
the same list. **Show** switches between hosts and containers, hosts only, and containers only.

- **Likelihood** is the sum of five parts:
  - *Exposure:* ingress hosts (more without TLS), NodePort / LoadBalancer services, hostNetwork.
  - *Weaknesses:* critical/high CVEs in the running image, privileged, host namespaces / hostPath, secrets in
    environment variables, root, failed CIS pod checks.
  - *Threat:* container-log signals that are not exempt, security events, IDS alerts on the pod IPs. Alerts on a
    hostNetwork pod's IP count for its node, not the pod.
  - *Reach:* node access, no NetworkPolicy in the namespace, a mounted API token.
  - *Visibility:* the cluster sends no container logs to Elasticsearch, or images are not scanned.
- **Impact:**
  - 5 when the workload can take over its node, or is cluster infrastructure (`kube-*`, CNI, storage,
    cert-manager…);
  - 4 when it holds secrets or serves users;
  - 3 otherwise.

  Override it per namespace or per `namespace/workload` in `host_policy` → `k8s.impact`, for example
  `{"apps/billing": [5, "payment data"]}`.

**Container vulnerabilities ranked by risk** lists each weakness per workload, with how to fix it. Workloads with an
ingress or an external service weigh 1.4×. Workload names link to the pod pivot page.

## Pod notes

Pods are temporary: they get a new name on every restart, rollout or reschedule. So a pod note is not stored on a pod. It is
stored on the object that **creates** the pods - its Deployment, StatefulSet, DaemonSet, CronJob or Job - and applies to every
pod that object makes, today's and the ones it creates later. The subject is `pod:<cluster>/<namespace>/<kind>/<name>`, for
example `pod:talos/opencti/deployment/opencti-worker`. A pod nothing creates (a static pod such as `kube-apiserver-<node>`) keeps
its notes under kind `pod` and its own name. The owner comes from the Security Onion pod fields (a ReplicaSet maps to its
Deployment, a CronJob's Job to its CronJob). Notes written with the older subject `pod:<cluster>/<namespace>/<workload>` are still read.

In the dashboard:

- **Pods table** (Kubernetes page): the **Created by** column names each pod's owner and its kind, links to all its pods, and
  shows 📝 *n* when that owner has notes.
- **Pod page**: the card is titled **Notes on <Kind> <name>**. A banner says the notes belong to that object, not to the pod, and
  lists the pods it runs now. **Add note to <Kind>** stores the note there. **View all its pods** opens
  `#/k8spod/<ns>/<name>?owner=<kind>`, which shows logs, hits and events of all its pods together.
- **Notes page**: pod notes show the owner kind and "all its pods".

- **People** add notes on the pod page. These are authoritative for the AI.
- **The AI reads them:**
  - the event reviewer sees them as `pod note` lines for every event about that workload (container-log hits and
    Kubernetes events);
  - event research gets them as `pod_notes`.
- **The AI writes them:**
  - event research records what it learns about a workload (`subject: pod.subject`);
  - the event reviewer files its *expected* judgements on the workload as well as on the hosts.

  AI notes are marked ✨, can be accepted or rejected by a defender, and can be deleted.

## Findings and events

Every result above becomes a host finding with a key starting `k8s-`. So the correlation, the review job, auto-close,
Posture and **Open events** handle them like any other endpoint finding.

| Key | Priority | Raised by |
|---|---|---|
| `k8s-log\|cmd/miner/webattack\|…` | Investigate | watcher + nightly |
| `k8s-log\|secret\|…`, `k8s-api\|exec`, `k8s-api\|denied`, `k8s-cov\|…`, `k8s-img\|…` | Review | watcher + nightly |
| `k8s-ev\|…` forbidden / PodSecurity events | Review | watcher + nightly |
| `k8s-ev\|…` other warning events, `k8s-log\|…` auth / denied / TLS / crash hits | Info (low in Open events) | nightly snapshot only |
| `k8s-alert\|<rule>` high Security Onion alert on a node or pod | Investigate | nightly |

Failed CIS checks and container images with critical/high CVEs fixed by an available update are things to fix, not
events. They go to **Security → Fix list** (`k8s-cis|<cluster>|<id>`, `k8s-imgcve|<repo>`, with how to fix them), not to
endpoint findings or Open events. Accepted checks (`k8s.cis_accept`) are
left out, and a check that passes again moves to *Fixed*.

## Several clusters

Every Kubernetes page has a **Cluster** selector at the top: *All clusters* or one cluster. The choice is kept in the
browser.

- Security Onion data is filtered by the selected cluster's node names.
- The map shows each namespace box labelled by its cluster.
- The CIS benchmark has one box per cluster.
- Images list the clusters and namespaces that run them.

## Components

| Module | Runs in | Access |
|---|---|---|
| `k8s.py` | host (broker, watcher, collector) | Elasticsearch read-only |
| `kube_api.py` | host | Kubernetes API: GET + SelfSubjectAccessReview, TLS verified, fails over between API server URLs |
| `kube_cis.py`, `kube_map.py` | host (broker, collector) | through `kube_api.py` |
| `kube_images.py` | host (scheduler job `k8simages`, broker **Scan now**) | `kube_api.py`, registries (anonymous HTTPS), Docker for Trivy |
| `static/k8s.js`, `static/k8smap.js` | dashboard | `/api/k8s*` → host broker `/k8s` |

The dashboard holds neither the Elasticsearch key nor any Kubernetes token. Everything goes through the loopback host
broker (`/k8s`, actions `overview`, `pod`, `clusters`, `map`, `cis`, `cis_run`, `images`, `image`, `images_run`).
