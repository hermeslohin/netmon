// Devices > Kubernetes: security monitoring of the Kubernetes cluster from Security Onion data only (container logs,
// Kubernetes events, API server metrics, pod inventory, SO alerts on node/pod IPs). /api/k8s and /api/k8s/pod go
// through the host broker (k8s.py); netmon never talks to the cluster itself.
// #/k8s            overview (window select, findings, coverage, signals, API server, events, alerts, pods, images, nodes)
// #/k8spod/<ns>/<pod>?text=&container=&stream=   pivot into one pod: its logs, security hits, events, alerts, Kibana
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

V.k8s = async (el) => {
  const W = k8sWindow();
  el.innerHTML = `<h1>Kubernetes</h1><div class="sub">Security monitoring of the Kubernetes cluster from <b>Security Onion</b> data only: container logs, Kubernetes events,
    API server metrics and pod inventory shipped by the Elastic Agent Kubernetes integration, plus Security Onion alerts on node and pod IPs. netmon never connects to the cluster.
    Click a pod to see its logs and security events.</div>
    <div class="tbltools"><label class="muted">Window</label>${W.fixed ? `<span>${esc(ft(S.range.start))} – ${esc(ft(S.range.end))} (time picker)</span>`
      : `<select id="k8sWin">${K8S_WINS.map(([v, l]) => `<option value="${v}" ${K8S.win === v ? "selected" : ""}>last ${l}</option>`).join("")}</select>`}
      <button id="k8sRefresh" title="Query Security Onion again">Refresh</button></div><div class="loading">Loading from Security Onion…</div>`;
  const ws = el.querySelector("#k8sWin"); if (ws) ws.onchange = () => { K8S.win = ws.value; K8S.cache = {}; rerender(); };
  el.querySelector("#k8sRefresh").onclick = () => { K8S.cache = {}; rerender(); };
  let D;
  try { D = await k8sGet("/api/k8s", { minutes: W.minutes, end: W.end }); }
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
  const sigBy = {}; live.forEach((s) => { const k = s.ns + "/" + s.pod; sigBy[k] = (sigBy[k] || 0) + s.count; });
  const pc = k8sBox("Pods", `<div class="tbltools"><label class="muted">Namespace</label><select id="k8sNs"><option value="">all (${nsl.length})</option>${nsl.map((n) => `<option ${K8S.ns === n ? "selected" : ""}>${esc(n)}</option>`).join("")}</select></div>`,
    table(null, [{ k: "ns", t: "Namespace" }, { k: "pod", t: "Pod", fmt: (v, r) => k8sPodLink(r.ns, v) }, { k: "owner", t: "Owner", cls: "small" }, { k: "node", t: "Node" },
      { k: "ip", t: "Pod IP", fmt: (v) => (v ? ipLink(v, false) : "") }, { k: "containers", t: "Containers", cls: "small", fmt: (v) => esc((v || []).join(", ")) },
      { k: "_sig", t: "Sec hits", num: true, sort: (r) => sigBy[r.ns + "/" + r.pod] || 0, fmt: (v, r) => (sigBy[r.ns + "/" + r.pod] ? `<b>${fn(sigBy[r.ns + "/" + r.pod])}</b>` : "") },
      { k: "restarts", t: "Restarts", num: true }, { k: "logs", t: "Log lines", num: true, bar: true, fmt: fn }, { k: "stderr", t: "stderr", num: true, fmt: fn }],
    pods, { sort: "_sig", onclick: (r) => go(k8sPodHref(r.ns, r.pod).slice(2)) }));
  el.appendChild(pc);
  pc.querySelector("#k8sNs").onchange = (e) => { K8S.ns = e.target.value; rerender(); };

  el.appendChild(grid("g2",
    k8sBox("Container images", table(null, [{ k: "image", t: "Image", cls: "mono small" }, { k: "pods", t: "Pods", num: true }, { k: "namespaces", t: "Namespaces", cls: "small", fmt: (v) => esc((v || []).join(", ")) },
      { k: "risk", t: "Supply-chain", fmt: (v) => (v || []).map((x) => `<span class="badge sev-low">${esc(x)}</span>`).join(" ") }], inv.images || [], { sort: "pods" }),
      `<div class="muted small">Images seen in container logs. A new image (not in the nightly baseline) raises a finding; mutable tags (:latest / no tag) are flagged.</div>`),
    card("Nodes", table(null, [{ k: "node", t: "Node", fmt: (v) => hostLink(v) }, { k: "ip", t: "IP", fmt: (v) => (v ? ipLink(v) : "") },
      { k: "_agent", t: "Elastic Agent", fmt: (v, r) => { const a = (D.agents || []).find((x) => x.host === r.node); return a ? badge(a.status) + ` <span class="muted small">${esc(a.minutes_since_checkin)} min</span>` : "—"; } },
      { k: "_bad", t: "Unhealthy inputs", cls: "small", fmt: (v, r) => { const a = (D.agents || []).find((x) => x.host === r.node); return esc((a?.bad_components || []).join(", ")); } }], inv.nodes || [], { search: false }))));
};

V.k8spod = async (el, arg) => {
  const [ns, ...rest] = String(arg || "").split("/"), pod = rest.join("/"), W = k8sWindow(), P = hq();
  const f = { text: P.get("text") || "", container: P.get("container") || "", stream: P.get("stream") || "", before: P.get("before") || "" };
  el.innerHTML = `<div class="crumbs"><a href="#/k8s">Kubernetes</a> › ${esc(ns)} › ${esc(pod)}</div><h1>${esc(pod)}</h1>
    <div class="sub">Namespace ${esc(ns)} · logs and security events from Security Onion · window ${W.fixed ? esc(ft(S.range.start)) + " – " + esc(ft(S.range.end))
      : "last " + esc((K8S_WINS.find(([v]) => v === W.minutes) || [, W.minutes + " min"])[1])}</div><div class="loading">Loading from Security Onion…</div>`;
  let D;
  try { D = await k8sGet("/api/k8s/pod", { ns, pod, minutes: W.minutes, end: W.end, ...f, size: 300 }, 15e3); }
  catch (e) { el.querySelector(".loading").outerHTML = `<div class="card"><h2>Pod data unavailable</h2><pre>${esc(e.message || e)}</pre></div>`; return; }
  el.querySelector(".loading").remove();
  const live = (D.signals || []).filter((s) => !s.exempt), m = +W.minutes;
  el.insertAdjacentHTML("beforeend", kpis([["Node", D.node ? hostLink(D.node) : "—"], ["Pod IP", D.ip ? ipLink(D.ip, false) : "—"], ["Containers", (D.containers || []).length],
    ["Matching log lines", fn(D.total)], ["Security hits", fn(live.reduce((s, x) => s + x.count, 0)), live.length ? "warn" : "good"],
    ["Warning events", (D.events || []).length, (D.events || []).length ? "warn" : ""], ["SO alerts", (D.alerts || []).reduce((s, a) => s + a.count, 0), (D.alerts || []).length ? "bad" : "good"]]));
  // pivots: Kibana for the raw documents, netmon pages for the pod IP / node
  const podK = `kubernetes.namespace:${k8sQ(ns)} and kubernetes.pod.name:${k8sQ(pod)}`;
  const piv = [k8sKb(podK, m, W.end, "All logs of this pod"), k8sKb(podK + " and stream:\"stderr\"", m, W.end, "stderr only"),
    D.ip && k8sKb(`source.ip:${k8sQ(D.ip)} or destination.ip:${k8sQ(D.ip)}`, m, W.end, "Network logs of the pod IP (Zeek / Suricata)"),
    k8sKb(`kubernetes.event.involved_object.name:${k8sQ(pod)}`, m, W.end, "Kubernetes events"),
    D.node && `<a href="#/endpoint/${encodeURIComponent(D.node)}">Node ${esc(D.node)} (Endpoints)</a>`, D.ip && `<a href="#/device/${encodeURIComponent(D.ip)}">Pod IP as a network device</a>`].filter(Boolean);
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
