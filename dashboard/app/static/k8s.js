// Devices > Kubernetes: security monitoring of the Kubernetes cluster from Security Onion data only (container logs,
// Kubernetes events, API server metrics, pod inventory, SO alerts on node/pod IPs). /api/k8s and /api/k8s/pod go
// through the host broker (k8s.py); netmon never talks to the cluster itself.
// #/k8s            overview (window select, findings, coverage, signals, API server, events, alerts, pods, images, nodes)
// #/k8spod/<ns>/<pod>?text=&container=&stream=   pivot into one pod: its logs, security hits, events, alerts, Kibana
// #/k8spod/<ns>/<name>?owner=<kind>              every pod one Deployment / StatefulSet / DaemonSet / CronJob / Job creates (pod notes live there)
const K8S = { win: "1440", ns: "", cache: {} };
const K8S_WINS = [["60", "1 hour"], ["360", "6 hours"], ["1440", "24 hours"], ["4320", "3 days"], ["10080", "7 days"]];
const K8S_KIND = { cmd: "Suspicious command", miner: "Crypto-miner", webattack: "Web attack", secret: "Secret in log", authfail: "Auth failure",
  denied: "Access denied", tls: "TLS error", crash: "Crash / OOM" };

function k8sWindow() {  // a snapshot time range (header picker) wins; otherwise the page's own select, ending now
  if (S.snap?.range && S.range) {
    const m = Math.max(15, Math.round((Date.parse(S.range.end) - Date.parse(S.range.start)) / 6e4));
    return { minutes: String(Math.min(m, 10080)), end: S.range.end, fixed: true };
  }
  return { minutes: K8S.win, end: "", fixed: false };
}
async function k8sGet(path, params, maxAge = 60e3) {
  const qs = new URLSearchParams(Object.entries(params).filter(([, v]) => v !== "" && v != null)).toString(), key = path + "?" + qs;
  const c = K8S.cache[key];
  if (c && Date.now() - c.t < maxAge) return c.d;
  const d = await api(key);
  if (d.error) throw new Error(d.error);
  K8S.cache = { [key]: { t: Date.now(), d } };  // one entry: the page refetches on navigation, not on every auto-refresh
  return d;
}
const k8sPodHref = (ns, pod, extra) => "#/k8spod/" + encodeURIComponent(ns) + "/" + encodeURIComponent(pod) + (extra ? "?" + new URLSearchParams(extra) : "");
const k8sPodLink = (ns, pod) => `<a href="${k8sPodHref(ns, pod)}" title="Open this pod: logs and security events">${esc(pod)}</a>`;
// pod notes live on the object that creates the pods (Deployment, StatefulSet, DaemonSet, CronJob, Job; "pod" = nothing owns it)
const K8S_OWNER = { deployment: "Deployment", statefulset: "StatefulSet", daemonset: "DaemonSet", cronjob: "CronJob", job: "Job", replicaset: "ReplicaSet", pod: "Pod" };
const k8sOwnerHref = (ns, kind, name, cl) => k8sPodHref(ns, name, { owner: kind, ...(cl ? { cluster: cl } : {}) });
async function k8sNoteCounts() {  // {subject: notes} of every pod-creating object with notes (cached 60 s)
  if (!K8S._nc || Date.now() - K8S._nc.t > 60e3) { let c = {}; try { c = (await api("/api/kb/pods")).counts || {}; } catch (_) { /* notes unavailable */ } K8S._nc = { t: Date.now(), c }; }
  return K8S._nc.c;
}
const k8sSev = (s) => `<span class="badge ${s === "high" ? "sev-high" : s === "medium" ? "sev-medium" : "sev-low"}">${esc(s)}</span>`;
const k8sState = (s) => `<span class="badge ${s === "ok" ? "good" : s === "error" ? "sev-medium" : "sev-high"}">${esc(s)}</span>`;
function k8sKb(kql, minutes, end, label) {  // Kibana Discover deep link (site settings kibana_url); "" when not configured
  if (!window.kibanaQueryUrl) return "";
  const to = end || "now", from = end ? new Date(Date.parse(end) - minutes * 6e4).toISOString() : `now-${minutes}m`;
  const u = window.kibanaQueryUrl({ kql, from, to });
  return u ? `<a href="${esc(u)}" target="_blank" rel="noopener" title="Open in Kibana Discover">${esc(label || "Kibana ↗")}</a>` : "";
}
function k8sBox(title, ...parts) {  // card() with several parts: HTML strings and elements (table() returns an element)
  const c = card(title, "");
  parts.forEach((p) => { if (typeof p === "string") c.insertAdjacentHTML("beforeend", p); else if (p) c.appendChild(p); });
  return c;
}
const k8sQ = (v) => '"' + String(v).replace(/\\/g, "\\\\").replace(/"/g, '\\"') + '"';

// CIS Kubernetes benchmark (kube_cis.py through the read-only Kubernetes API account) - not Security Onion data
// ---- cluster filter (all Kubernetes pages): "" = all clusters; kept in this browser
K8S.cluster = localStorage.getItem("k8s.cluster") || "";
async function k8sClusterList() {
  if (!K8S._cl || Date.now() - K8S._cl.t > 300e3) {
    let L = [];
    try { L = ((await api("/api/k8s/clusters")).clusters || []).filter((c) => c.usable).map((c) => c.name); } catch (_) { /* no API integration */ }
    K8S._cl = { t: Date.now(), L };
  }
  if (K8S.cluster && !K8S._cl.L.includes(K8S.cluster)) K8S.cluster = "";
  return K8S._cl.L;
}
// <select> for the top of a Kubernetes page; onchange(cluster) re-renders the page
async function k8sClusterBar(onchange) {
  const L = await k8sClusterList(), w = document.createElement("span");
  if (L.length < 2) { w.innerHTML = L.length ? `<span class="muted small">Cluster: ${esc(L[0])}</span>` : ""; return w; }
  w.innerHTML = `<label class="muted">Cluster</label> <select class="k8s-cl"><option value="">All clusters (${L.length})</option>${L.map((c) => `<option value="${esc(c)}" ${K8S.cluster === c ? "selected" : ""}>${esc(c)}</option>`).join("")}</select>`;
  w.querySelector("select").onchange = (e) => { K8S.cluster = e.target.value; localStorage.setItem("k8s.cluster", K8S.cluster); K8S.cache = {}; onchange(K8S.cluster); };
  return w;
}
const k8sClTag = (c) => (c && (K8S._cl?.L || []).length > 1 ? ` <span class="badge" title="cluster">${esc(c)}</span>` : "");

// CIS Kubernetes benchmark (kube_cis.py through the read-only Kubernetes API account) - one box per cluster
async function k8sCisCard(run, cluster) {
  let C;
  const qs = new URLSearchParams({ cluster: cluster || "", ...(run ? { run: "1" } : {}) });
  try { C = await api("/api/k8s/cis?" + qs); } catch (e) { C = { error: String(e.message || e) }; }
  const title = "CIS Kubernetes benchmark", clTag = cluster ? `<div style="margin:-4px 0 6px"><span class="badge">cluster ${esc(cluster)}</span></div>` : "";
  if (C.not_configured || (!C.results?.length && C.error)) return card(title, clTag + `<div class="muted">${esc(C.error || "Not configured")}. Set up the read-only account under <a href="#/config">Configuration → Integrations → Kubernetes API</a>.</div>`);
  const sm = C.summary || {}, st = { pass: "good", fail: "sev-high", warn: "sev-medium", manual: "sev-low", accepted: "sev-low" };
  const t = table(null, [{ k: "id", t: "Check", sort: (r) => r.id.split(".").map((x) => x.padStart(3, "0")).join(".") }, { k: "status", t: "Result", fmt: (v) => `<span class="badge ${st[v] || ""}">${esc(v)}</span>`, sort: (r) => ({ fail: 0, warn: 1, accepted: 2, manual: 3, pass: 4 })[r.status] },
    { k: "section", t: "Section", cls: "small" }, { k: "title", t: "Recommendation" }, { k: "count", t: "Items", num: true },
    { k: "detail", t: "Detail", cls: "small", fmt: (v, r) => esc(r.accepted ? "Accepted: " + r.accepted : v) + (r.items?.length ? `<details><summary class="muted">${r.count} item(s)</summary>${r.items.map((x) => `<div class="mono small">${esc(x)}</div>`).join("")}${r.count > r.items.length ? `<div class="muted small">+${r.count - r.items.length} more</div>` : ""}</details>` : "") }],
  C.results, { sort: "status", dir: 1 });
  const c = k8sBox(title, clTag, kpis([["Failed", sm.fail || 0, sm.fail ? "bad" : "good"], ["Review (warn)", sm.warn || 0, sm.warn ? "warn" : ""], ["Passed", sm.pass || 0, "good"], ["Manual / not visible", sm.manual || 0], ["Accepted", sm.accepted || 0]]),
    `<div class="muted small">${esc(C.benchmark || "")} · Kubernetes ${esc(C.version || "")} · checked ${esc(ft(C.generated))}${C.error ? ` · <span class="sev-high">last run failed: ${esc(C.error)}</span>` : ""} · <button class="k8sCisRun">Run now</button>
    · Failed checks go to the <a href="#/issues">Fix list</a> (k8s-cis|cluster|id). Accept a check in Settings → Endpoint policy → k8s → cis_accept. Sections 1.1, 2 and 4 need node access and are listed as manual.</div>`, t);
  c.querySelector(".k8sCisRun").onclick = async (e) => { e.target.disabled = true; e.target.textContent = "Running…"; const n = await k8sCisCard(true, cluster); c.replaceWith(n); };
  return c;
}

// Container images: newer tags in the registry and the CVEs they fix (kube_images.py: Trivy, daily + Scan now)
const K8S_SEV = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
const k8sSevCnt = (c, keys = ["CRITICAL", "HIGH"]) => (c ? keys.map((k) => `<span class="badge ${k === "CRITICAL" ? "sev-high" : k === "HIGH" ? "sev-medium" : "sev-low"}" title="${k}">${k[0]} ${c[k] || 0}</span>`).join(" ") : '<span class="muted">—</span>');
async function k8sImagesCard(cluster, run) {
  let I;
  try { I = await api("/api/k8s/images" + (run ? "?run=1" : "")); } catch (e) { I = { error: String(e.message || e) }; }
  const rows = (I.images || []).filter((r) => !cluster || (r.clusters || []).includes(cluster)).map((r) => ({ ...r,
    _crit: r.current?.counts?.CRITICAL || 0, _high: r.current?.counts?.HIGH || 0, _fix: ((r.fixed_by_update?.counts || {}).CRITICAL || 0) * 1000 + ((r.fixed_by_update?.counts || {}).HIGH || 0) }));
  const upd = rows.filter((r) => r.update), fixC = rows.reduce((s, r) => s + ((r.fixed_by_update?.counts || {}).CRITICAL || 0), 0), fixH = rows.reduce((s, r) => s + ((r.fixed_by_update?.counts || {}).HIGH || 0), 0);
  const detail = document.createElement("div");
  const t = rows.length ? table(null, [{ k: "image", t: "Image", cls: "mono small", fmt: (v, r) => esc(v) + (r.tag === "latest" || (!r.tag && !r.digest) ? ' <span class="badge sev-low" title="mutable tag">:latest</span>' : "") },
    { k: "namespaces", t: "Where", cls: "small", fmt: (v) => esc((v || []).join(", ")) }, { k: "pods", t: "Pods", num: true },
    { k: "update", t: "Update available", fmt: (v, r) => (v ? `<b>${esc(v)}</b>${r.update_major && r.update_major !== v ? ` <span class="muted small">(same major: ${esc(r.update_major)})</span>` : ""}` : r.errors?.some((e) => e.startsWith("tags")) ? '<span class="muted small" title="' + esc(r.errors.join("; ")) + '">registry not readable</span>' : '<span class="muted">up to date</span>'), sort: (r) => (r.update ? 1 : 0) },
    { k: "_crit", t: "CVEs now", fmt: (v, r) => k8sSevCnt(r.current?.counts) + (r.errors?.some((e) => e.startsWith("scan")) ? ' <span class="sev-medium small" title="' + esc(r.errors.join("; ")) + '">scan failed</span>' : ""), sort: (r) => r._crit * 1000 + r._high },
    { k: "_fix", t: "Fixed by updating", fmt: (v, r) => (r.fixed_by_update ? k8sSevCnt(r.fixed_by_update.counts) : '<span class="muted">—</span>'), sort: (r) => r._fix },
    { k: "fixable_in_place", t: "Fix by rebuild", num: true, title: "Critical/high CVEs with a fixed package version (rebuild the image even without a new tag)" }],
  rows, { sort: "_fix", onclick: (r) => k8sImageDetail(detail, r) }) : null;
  const c = k8sBox("Container images: updates and CVEs", cluster ? `<div style="margin:-4px 0 6px"><span class="badge">cluster ${esc(cluster)}</span></div>` : "",
    kpis([["Images", rows.length], ["Update available", upd.length, upd.length ? "warn" : "good"], ["Critical CVEs fixed by updating", fixC, fixC ? "bad" : "good"], ["High CVEs fixed by updating", fixH, fixH ? "warn" : "good"],
      ["Critical CVEs running", rows.reduce((s, r) => s + r._crit, 0), rows.some((r) => r._crit) ? "bad" : "good"]]),
    `<div class="muted small">Every image running in ${cluster ? "this cluster" : "the clusters"}, read through the read-only Kubernetes API. For each one netmon looks in its registry for a newer tag of the same form, and scans the running image and the newest tag with Trivy: "Fixed by updating" are CVEs in the running image that the newest tag no longer has. Scanned daily at 04:00 UTC${I.generated ? ` · last scan ${esc(ft(I.generated))} (${esc(I.seconds)} s)` : " · not scanned yet"}${I.running ? ' · <b>scan running…</b>' : ""} · <button class="k8sImgRun" ${I.running ? "disabled" : ""}>Scan now</button>
    · Click an image for its CVE list. Critical CVEs fixed by an update become findings (k8s-imgcve).</div>`
    + (I.error ? `<pre>${esc(I.error)}</pre>` : "") + (Object.keys(I.errors || {}).length ? `<div class="sev-medium small">${esc(Object.entries(I.errors).map(([k, v]) => k + ": " + v).join("; "))}</div>` : ""),
    t || `<div class="muted">${I.generated ? "No images in this cluster." : "No scan yet. Click Scan now (a first scan of every image takes several minutes)."}</div>`, detail);
  c.querySelector(".k8sImgRun").onclick = async (e) => { e.target.disabled = true; e.target.textContent = "Starting…"; c.replaceWith(await k8sImagesCard(cluster, true)); };
  return c;
}
async function k8sImageDetail(box, r) {
  box.innerHTML = '<div class="loading">Loading CVEs…</div>';
  let D;
  try { D = await api("/api/k8s/image?" + new URLSearchParams({ image: r.image, digest: r.digest || "" })); if (D.error) throw new Error(D.error); }
  catch (e) { box.innerHTML = `<pre>${esc(e.message || e)}</pre>`; return; }
  const V = (D.current?.vulns || []).filter((v) => v.severity !== "UNKNOWN");
  box.innerHTML = `<h3 style="margin-top:14px">${esc(D.image)}</h3><div class="small">${esc(D.current?.os || "")} · digest <span class="mono">${esc((D.digest || "").slice(0, 19))}…</span> · scanned ${esc(ft(D.current?.scanned))}
    ${D.update ? ` · newest tag <b>${esc(D.update)}</b>: ${k8sSevCnt(D.newest?.counts, K8S_SEV)}` : " · no newer tag"} · used in ${esc((D.namespaces || []).join(", "))}</div>`;
  box.appendChild(table(null, [{ k: "severity", t: "Sev", fmt: (v) => badge(v.toLowerCase()), sort: (x) => K8S_SEV.indexOf(x.severity) },
    { k: "id", t: "CVE", fmt: (v) => `<a href="https://nvd.nist.gov/vuln/detail/${encodeURIComponent(v)}" target="_blank" rel="noopener">${esc(v)}</a>` },
    { k: "pkg", t: "Package", cls: "mono small" }, { k: "installed", t: "Installed", cls: "mono small" }, { k: "fixed", t: "Fixed in package", cls: "mono small" },
    { k: "fixed_by_update", t: "Gone in newest tag", fmt: (v) => (v ? '<span class="badge good">yes</span>' : "") , sort: (x) => (x.fixed_by_update ? 1 : 0) }, { k: "title", t: "Title", cls: "small" }],
  V, { sort: "severity", dir: 1 }));
}

V.k8s = async (el) => {
  const W = k8sWindow();
  el.innerHTML = `<h1>Kubernetes</h1><div class="sub">Security monitoring of the Kubernetes cluster from <b>Security Onion</b> data only: container logs, Kubernetes events,
    API server metrics and pod inventory shipped by the Elastic Agent Kubernetes integration, plus Security Onion alerts on node and pod IPs. netmon never connects to the cluster.
    Click a pod to see its logs and security events.</div>
    <div class="tbltools"><label class="muted">Window</label>${W.fixed ? `<span>${esc(ft(S.range.start))} – ${esc(ft(S.range.end))} (time picker)</span>`
      : `<select id="k8sWin">${K8S_WINS.map(([v, l]) => `<option value="${v}" ${K8S.win === v ? "selected" : ""}>last ${l}</option>`).join("")}</select>`}
      <button id="k8sRefresh" title="Query Security Onion again">Refresh</button></div><div class="loading">Loading from Security Onion…</div>`;
  el.querySelector(".tbltools").prepend(await k8sClusterBar(() => rerender()));
  const ws = el.querySelector("#k8sWin"); if (ws) ws.onchange = () => { K8S.win = ws.value; K8S.cache = {}; rerender(); };
  el.querySelector("#k8sRefresh").onclick = () => { K8S.cache = {}; rerender(); };
  let D;
  try { D = await k8sGet("/api/k8s", { minutes: W.minutes, end: W.end, cluster: K8S.cluster }); }
  catch (e) { el.querySelector(".loading").outerHTML = `<div class="card"><h2>Kubernetes data unavailable</h2><pre>${esc(e.message || e)}</pre></div>`; return; }
  el.querySelector(".loading").remove();
  const inv = D.inventory || {}, A = D.apiserver && !D.apiserver.error ? D.apiserver : null, sig = D.signals || [], live = sig.filter((s) => !s.exempt);
  const cov = D.coverage || [], logs = cov.find((c) => c.dataset === "kubernetes.container_logs") || { state: "missing" };
  const warn = (D.events || []), secEv = warn.filter((e) => e.security);
  el.insertAdjacentHTML("beforeend", kpis([
    ["Container logs → SO", logs.state === "ok" ? "flowing" : logs.state, logs.state === "ok" ? "good" : "bad"],
    ["Findings", (D.findings || []).length, (D.findings || []).some((f) => f.priority === "Investigate") ? "bad" : (D.findings || []).length ? "warn" : "good"],
    ["Log security hits", fn(live.reduce((s, x) => s + x.count, 0)), live.some((x) => x.severity === "high") ? "bad" : live.length ? "warn" : "good"],
    ["Pod exec / attach", A ? fn(A.exec) : "?", A?.exec ? "warn" : "good"], ["API 401/403", A ? fn(A.denied) : "?", A?.denied ? "warn" : "good"],
    ["Warning events", warn.length, secEv.length ? "warn" : ""], ["SO alerts", (D.alerts || []).reduce((s, a) => s + a.count, 0), (D.alerts || []).length ? "warn" : "good"],
    ["Nodes", (inv.nodes || []).length], ["Pods", (inv.pods || []).length], ["Namespaces", (inv.namespaces || []).length], ["Images", (inv.images || []).length]]));
  const tw = `Window ${esc(ft(D.end ? new Date(Date.parse(D.end) - D.minutes * 6e4).toISOString() : new Date(Date.parse(D.generated) - D.minutes * 6e4).toISOString()))} – ${esc(ft(D.end || D.generated))} · queried in ${esc(D.seconds)} s`;
  el.insertAdjacentHTML("beforeend", `<div class="muted small" style="margin:-4px 0 8px">${tw}</div>`);

  el.appendChild((D.findings || []).length ? k8sBox("Kubernetes findings", table(null, [{ k: "priority", t: "Priority", fmt: (v) => badge(v) }, { k: "text", t: "Finding" }],
    D.findings, { search: false }), `<div class="muted small">Also raised by the 15-minute watcher (Alerts) and fed to the event review as host findings (key prefix k8s-). Tune in Settings → Endpoint policy → k8s.</div>`)
    : card("Kubernetes findings", `<div class="muted">No Kubernetes findings in this window.</div>`));

  if (K8S.cluster && !(D.inventory?.nodes || []).length) el.appendChild(card("No Security Onion data for this cluster", `<div class="muted">None of ${esc(K8S.cluster)}'s nodes ship Kubernetes logs or metrics to Security Onion: install the Elastic Agent Kubernetes integration in it. The CIS benchmark and image checks below use the Kubernetes API and work without it.</div>`));
  for (const cl of (K8S.cluster ? [K8S.cluster] : await k8sClusterList())) el.appendChild(await k8sCisCard(false, cl));
  if (!(await k8sClusterList()).length) el.appendChild(await k8sCisCard(false, ""));
  el.appendChild(k8sBox("Security Onion data coverage", table(null, [{ k: "dataset", t: "Data set" }, { k: "state", t: "State", fmt: k8sState },
    { k: "docs_24h", t: "Docs (24 h)", num: true, fmt: fn }, { k: "last", t: "Last arrival", fmt: (v, r) => v ? `${esc(ft(v))} <span class="muted">(${esc(r.minutes)} min)</span>` : "never" },
    { k: "error", t: "Collector error", cls: "small", fmt: (v) => esc(v || "") }], cov, { search: false, sort: "state", dir: 1 }),
    `<div class="muted small">What the Elastic Agent Kubernetes integration delivers to Security Onion. Stale container logs mean the log-based checks below are blind; error rows (kube-state-metrics, kube-proxy) are collectors that run but cannot reach their target.</div>`));

  const sigCols = [{ k: "severity", t: "Sev", fmt: k8sSev, sort: (x) => ({ high: 3, medium: 2, low: 1 })[x.severity] }, { k: "kind", t: "Signal", fmt: (v) => esc(K8S_KIND[v] || v) },
    { k: "ns", t: "Namespace" }, { k: "pod", t: "Pod", fmt: (v, r) => k8sPodLink(r.ns, v) }, { k: "container", t: "Container" }, { k: "count", t: "Lines", num: true, fmt: fn },
    { k: "last", t: "Last", fmt: (v) => esc(ft(v)) }, { k: "examples", t: "Example", cls: "mono small", fmt: (v, r) => (r.exempt ? `<span class="muted" title="${esc(r.exempt)}">[exempt] </span>` : "") + esc((v || [])[0] || "").slice(0, 300) }];
  el.appendChild(card("Container-log security signals", sig.length ? table(null, sigCols, sig, { onclick: (r) => go(k8sPodHref(r.ns, r.pod, { text: "", sig: r.kind }).slice(2)), rowClass: (r) => (r.exempt ? "muted" : "") })
    : `<div class="muted">${logs.state === "ok" ? "No security patterns in the container logs of this window." : "No container logs in Security Onion for this window."}</div>`));

  if (A) {
    const codes = Object.entries(A.codes || {});
    el.appendChild(grid("g2",
      k8sBox("API server security", kpis([["Requests", fn(A.requests)], ["401/403", fn(A.denied), A.denied ? "warn" : "good"], ["exec / attach / port-forward", fn(A.exec), A.exec ? "warn" : "good"],
        ["RBAC / secrets writes", fn(A.rbac_writes), A.rbac_writes ? "warn" : ""], ["Throttled (429)", fn(A.throttled)], ["5xx", fn(A.errors)]]),
        A.rows.length ? table(null, [{ k: "why", t: "Why" }, { k: "verb", t: "Verb" }, { k: "resource", t: "Resource" }, { k: "subresource", t: "Sub" }, { k: "code", t: "Code" },
          { k: "count", t: "Requests", num: true, fmt: fn }], A.rows, { search: false, sort: "count" }) : "",
        `<div class="muted small">From the API server's request counters (metrics, not audit logs): they show what kind of request and its result, not who sent it.${A.restarted ? " The API server restarted in this window." : ""}</div>`),
      chartCard("API server responses by code", doughnutCfg(Object.fromEntries(codes)))));
  } else if (D.apiserver?.error) el.appendChild(card("API server security", `<pre>${esc(D.apiserver.error)}</pre>`));

  el.appendChild(card("Kubernetes warning events", warn.length ? table(null, [{ k: "at", t: "Last", fmt: (v) => esc(ft(v)) }, { k: "ns", t: "Namespace" },
    { k: "object", t: "Object", fmt: (v, r) => (r.kind === "Pod" ? k8sPodLink(r.ns, v) : esc(v)) + ` <span class="muted small">${esc(r.kind)}</span>` },
    { k: "reason", t: "Reason", fmt: (v, r) => esc(v) + (r.security ? ' <span class="badge sev-medium" title="Security-relevant reason or message">sec</span>' : "") },
    { k: "count", t: "Count", num: true }, { k: "message", t: "Message", cls: "small" }], warn, { sort: "at" }) : `<div class="muted">No warning events.</div>`));

  if ((D.alerts || []).length) el.appendChild(card("Security Onion alerts on nodes and pods", table(null, [{ k: "severity", t: "Sev", fmt: (v) => badge(v) }, { k: "rule", t: "Rule" },
    { k: "source", t: "Source" }, { k: "count", t: "Count", num: true }, { k: "src", t: "From", fmt: (v) => (v || []).map((x) => ipLink(x)).join(" ") },
    { k: "dst", t: "To", fmt: (v) => (v || []).map((x) => ipLink(x)).join(" ") }, { k: "last", t: "Last", fmt: (v) => esc(ft(v)) }], D.alerts, { sort: "count" })));

  const nsl = (inv.namespaces || []).map((n) => n.ns);
  const pods = (inv.pods || []).filter((p) => !K8S.ns || p.ns === K8S.ns);
  const nCount = await k8sNoteCounts();  // 📝 = notes on the pod's owner; they apply to every pod it creates
  const k8sOwnerCell = (r) => { const [kind, ...rest] = String(r.owner || "").split("/"), name = rest.join("/"); if (!name) return "";
    const n = nCount[`pod:${r.cluster || K8S.cluster || "default"}/${r.ns}/${kind}/${name}`.toLowerCase()] || 0;
    return `<a href="${k8sOwnerHref(r.ns, kind, name, r.cluster)}" title="All pods this ${esc(K8S_OWNER[kind] || kind)} creates, and its notes">${esc(name)}</a> <span class="muted">${esc(K8S_OWNER[kind] || kind)}</span>`
      + (n ? ` <span class="badge sev-info" title="${n} note(s) on this ${esc(K8S_OWNER[kind] || kind)}: they apply to all its pods">📝 ${n}</span>` : ""); };
  const sigBy = {}; live.forEach((s) => { const k = s.ns + "/" + s.pod; sigBy[k] = (sigBy[k] || 0) + s.count; });
  const pc = k8sBox("Pods", `<div class="tbltools"><label class="muted">Namespace</label><select id="k8sNs"><option value="">all (${nsl.length})</option>${nsl.map((n) => `<option ${K8S.ns === n ? "selected" : ""}>${esc(n)}</option>`).join("")}</select></div>`,
    table(null, [{ k: "ns", t: "Namespace" }, { k: "pod", t: "Pod", fmt: (v, r) => k8sPodLink(r.ns, v) + k8sClTag(r.cluster) }, { k: "owner", t: "Created by", cls: "small", fmt: (v, r) => k8sOwnerCell(r) }, { k: "node", t: "Node" },
      { k: "ip", t: "Pod IP", fmt: (v) => (v ? ipLink(v, false) : "") }, { k: "containers", t: "Containers", cls: "small", fmt: (v) => esc((v || []).join(", ")) },
      { k: "_sig", t: "Sec hits", num: true, sort: (r) => sigBy[r.ns + "/" + r.pod] || 0, fmt: (v, r) => (sigBy[r.ns + "/" + r.pod] ? `<b>${fn(sigBy[r.ns + "/" + r.pod])}</b>` : "") },
      { k: "restarts", t: "Restarts", num: true }, { k: "logs", t: "Log lines", num: true, bar: true, fmt: fn }, { k: "stderr", t: "stderr", num: true, fmt: fn }],
    pods, { sort: "_sig", onclick: (r) => go(k8sPodHref(r.ns, r.pod).slice(2)) }));
  el.appendChild(pc);
  pc.querySelector("#k8sNs").onchange = (e) => { K8S.ns = e.target.value; rerender(); };

  el.appendChild(grid("g2",
    card("Nodes", table(null, [{ k: "node", t: "Node", fmt: (v, r) => hostLink(v) + k8sClTag(r.cluster) }, { k: "ip", t: "IP", fmt: (v) => (v ? ipLink(v) : "") },
      { k: "_agent", t: "Elastic Agent", fmt: (v, r) => { const a = (D.agents || []).find((x) => x.host === r.node); return a ? badge(a.status) + ` <span class="muted small">${esc(a.minutes_since_checkin)} min</span>` : "—"; } },
      { k: "_bad", t: "Unhealthy inputs", cls: "small", fmt: (v, r) => { const a = (D.agents || []).find((x) => x.host === r.node); return esc((a?.bad_components || []).join(", ")); } }], inv.nodes || [], { search: false }))));
  el.appendChild(await k8sImagesCard(K8S.cluster));
};

V.k8spod = async (el, arg) => {
  const [ns, ...rest] = String(arg || "").split("/"), pod = rest.join("/"), W = k8sWindow(), P = hq();
  const ownK = (P.get("owner") || "").toLowerCase(), ownL = K8S_OWNER[ownK] || "";  // ?owner=<kind>: every pod that object creates
  const f = { text: P.get("text") || "", container: P.get("container") || "", stream: P.get("stream") || "", before: P.get("before") || "" };
  el.innerHTML = `<div class="crumbs"><a href="#/k8s">Kubernetes</a> › ${esc(ns)} › ${esc(pod)}</div><h1>${esc(pod)}${ownL ? ` <span class="badge" title="Kubernetes object that creates pods">${esc(ownL)}</span>` : ""}</h1>
    <div class="sub">${ownL ? `All pods this ${esc(ownL)} creates · ` : ""}Namespace ${esc(ns)} · logs and security events from Security Onion · window ${W.fixed ? esc(ft(S.range.start)) + " – " + esc(ft(S.range.end))
      : "last " + esc((K8S_WINS.find(([v]) => v === W.minutes) || [, W.minutes + " min"])[1])}</div><div class="loading">Loading from Security Onion…</div>`;
  let D;
  try { D = await k8sGet("/api/k8s/pod", { ns, pod, owner: ownK, minutes: W.minutes, end: W.end, ...f, cluster: P.get("cluster") || K8S.cluster, size: 300 }, 15e3); }
  catch (e) { el.querySelector(".loading").outerHTML = `<div class="card"><h2>Pod data unavailable</h2><pre>${esc(e.message || e)}</pre></div>`; return; }
  el.querySelector(".loading").remove();
  const live = (D.signals || []).filter((s) => !s.exempt), m = +W.minutes;
  el.insertAdjacentHTML("beforeend", kpis([["Node", D.node ? hostLink(D.node) : "—"], ["Pod IP", D.ip ? ipLink(D.ip, false) : "—"], ["Containers", (D.containers || []).length],
    ["Matching log lines", fn(D.total)], ["Security hits", fn(live.reduce((s, x) => s + x.count, 0)), live.length ? "warn" : "good"],
    ["Warning events", (D.events || []).length, (D.events || []).length ? "warn" : ""], ["SO alerts", (D.alerts || []).reduce((s, a) => s + a.count, 0), (D.alerts || []).length ? "bad" : "good"]]));
  // pivots: Kibana for the raw documents, netmon pages for the pod IP / node
  const podK = `kubernetes.namespace:${k8sQ(ns)} and kubernetes.pod.name:${ownK && ownK !== "pod" && /^[a-z0-9.-]+$/.test(pod) ? pod + "-*" : k8sQ(pod)}`;
  const piv = [k8sKb(podK, m, W.end, ownL ? `All logs of its pods` : "All logs of this pod"), k8sKb(podK + " and stream:\"stderr\"", m, W.end, "stderr only"),
    D.ip && k8sKb(`source.ip:${k8sQ(D.ip)} or destination.ip:${k8sQ(D.ip)}`, m, W.end, "Network logs of the pod IP (Zeek / Suricata)"),
    k8sKb(`kubernetes.event.involved_object.name:${k8sQ(pod)}`, m, W.end, "Kubernetes events"),
    D.node && `<a href="#/endpoint/${encodeURIComponent(D.node)}">Node ${esc(D.node)} (Endpoints)</a>`, D.ip && `<a href="#/device/${encodeURIComponent(D.ip)}">Pod IP as a network device</a>`].filter(Boolean);
  // Pod notes: filed on the object that creates the pods (Deployment / StatefulSet / DaemonSet / CronJob / Job), so they apply to
  // every pod it makes, today's and the ones it creates after restarts, rollouts and rescheduling. People and the AI read and write them.
  if (window.kbCard) {
    const cl = D.cluster || P.get("cluster") || K8S.cluster || "default", o = D.owner || { kind: "pod", name: D.workload || pod };
    const kl = K8S_OWNER[o.kind] || o.kind, subj = `pod:${cl}/${ns}/${o.kind}/${o.name}`.toLowerCase();
    const nc = kbCard([subj, `pod:${cl}/${ns}/${D.workload || pod}`.toLowerCase()], subj);  // + old per-workload subject (read only)
    const t = [...nc.querySelector("h2").childNodes].find((n) => n.nodeType === 3 && n.textContent.trim());
    if (t) t.textContent = t.textContent.replace(/^(\s*)Notes/, `$1Notes on ${kl} ${o.name}`);
    const op = D.owner_pods || [], here = op.map((x) => x.pod === pod && !ownK ? `<b>${esc(x.pod)}</b> (this pod)` : `<a href="${k8sPodHref(ns, x.pod, cl !== "default" ? { cluster: cl } : null)}">${esc(x.pod)}</a>`);
    const scope = o.kind === "pod"
      ? `<div class="k8s-owner-scope">📌 Nothing creates this pod (a static pod): these notes stay with pod <b>${esc(o.name)}</b> only.</div>`
      : `<div class="k8s-owner-scope">🔗 Pod notes belong to <b>${esc(kl)} ${esc(ns)}/${esc(o.name)}</b>, not to one pod: they apply to <b>all ${op.length || ""} pod${op.length === 1 ? "" : "s"}</b> it runs now${op.length ? ` (${here.slice(0, 12).join(", ")}${op.length > 12 ? `, +${op.length - 12} more` : ""})` : ""} and to every pod it creates later.`
        + (ownK ? "" : ` <a href="${k8sOwnerHref(ns, o.kind, o.name, cl !== "default" ? cl : "")}">View all its pods</a>`) + `</div>`;
    nc.querySelector(".kb-list").insertAdjacentHTML("beforebegin", scope);
    nc.querySelector(".kb-text").placeholder = `Add a note about ${kl} ${ns}/${o.name}: applies to all its pods (what it does, what is normal in its logs, decisions)…`;
    nc.querySelector('.kb-form button[type="submit"]').textContent = o.kind === "pod" ? "Add note" : `Add note to ${kl}`;
    el.appendChild(nc);
  }
  el.appendChild(card("Pivot", piv.join(" · ") || `<span class="muted">Set kibana_url in Settings → Site for Kibana links.</span>`));
  if ((D.signals || []).length) el.appendChild(card("Container-log security signals", table(null, [{ k: "severity", t: "Sev", fmt: k8sSev }, { k: "kind", t: "Signal", fmt: (v) => esc(K8S_KIND[v] || v) },
    { k: "container", t: "Container" }, { k: "count", t: "Lines", num: true }, { k: "last", t: "Last", fmt: (v) => esc(ft(v)) },
    { k: "examples", t: "Example", cls: "mono small", fmt: (v, r) => (r.exempt ? `<span class="muted" title="${esc(r.exempt)}">[exempt] </span>` : "") + esc((v || [])[0] || "") }], D.signals,
  { search: false, onclick: (r) => { const ex = String((r.examples || [])[0] || "").match(/[A-Za-z0-9_.:/${}-]{4,}/); location.hash = k8sPodHref(ns, pod, { text: ex ? ex[0] : "", container: r.container }); } })));
  if ((D.events || []).length) el.appendChild(card("Kubernetes warning events", table(null, [{ k: "at", t: "Last", fmt: (v) => esc(ft(v)) }, { k: "reason", t: "Reason" }, { k: "count", t: "Count", num: true },
    { k: "source", t: "Reported by" }, { k: "message", t: "Message", cls: "small" }], D.events, { search: false })));
  if ((D.alerts || []).length) el.appendChild(card("Security Onion alerts on this pod / node", table(null, [{ k: "severity", t: "Sev", fmt: (v) => badge(v) }, { k: "rule", t: "Rule" },
    { k: "count", t: "Count", num: true }, { k: "src", t: "From", fmt: (v) => (v || []).map((x) => ipLink(x)).join(" ") }, { k: "dst", t: "To", fmt: (v) => (v || []).map((x) => ipLink(x)).join(" ") },
    { k: "last", t: "Last", fmt: (v) => esc(ft(v)) }], D.alerts, { search: false })));
  if ((D.histogram || []).length) el.appendChild(chartCard("Log volume", { type: "bar", data: { labels: D.histogram.map((h) => ft(h[0])),
    datasets: [{ label: "stdout", data: D.histogram.map((h) => h[1] - h[2]), backgroundColor: PALETTE[0], stack: "s" }, { label: "stderr", data: D.histogram.map((h) => h[2]), backgroundColor: PALETTE[3] || "#e55", stack: "s" }] },
  options: { responsive: true, maintainAspectRatio: false, scales: { x: { stacked: true, ticks: { maxTicksLimit: 12 } }, y: { stacked: true } }, plugins: { legend: { display: true } } } }, "", "short"));
  // log viewer with filters (kept in the address: the view is bookmarkable)
  const lc = k8sBox("Container logs", `<form id="k8sLf" class="tbltools"><input name="text" placeholder="search text (all words)" value="${esc(f.text)}" style="min-width:240px">
    <select name="container"><option value="">all containers</option>${(D.containers || []).map((c) => `<option ${f.container === c.container ? "selected" : ""} value="${esc(c.container)}">${esc(c.container)} (${fn(c.logs)})</option>`).join("")}</select>
    <select name="stream"><option value="">stdout + stderr</option><option ${f.stream === "stderr" ? "selected" : ""}>stderr</option><option ${f.stream === "stdout" ? "selected" : ""}>stdout</option></select>
    <button>Filter</button>${f.text || f.container || f.stream || f.before ? `<a href="${k8sPodHref(ns, pod)}">clear</a>` : ""}</form>
    <div class="muted small">${fn(D.total)} matching lines, newest first${D.lines.length < D.total ? `, showing ${D.lines.length}` : ""}.${(D.containers || []).map((c) => ` ${esc(c.container)}: ${esc((c.images || []).join(", "))}`).join(" ·")}</div>
    <div class="k8slog">${D.lines.map((l) => `<div class="${l.stream === "stderr" ? "err" : ""}"><span class="muted">${esc(ft(l.at))}</span> <span class="badge">${esc(l.container)}</span> ${esc(l.message)}</div>`).join("") || '<div class="muted">No log lines.</div>'}</div>
    ${D.lines.length && D.lines.length < D.total ? `<a href="${k8sPodHref(ns, pod, { ...f, before: D.lines[D.lines.length - 1].at })}">Older lines ›</a>` : ""}`);
  el.appendChild(lc);
  lc.querySelector("#k8sLf").onsubmit = (e) => { e.preventDefault(); const fd = new FormData(e.target); location.hash = k8sPodHref(ns, pod, Object.fromEntries([...fd].filter(([, v]) => v))); };
};
