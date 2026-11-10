// Devices > Kubernetes map: namespaces as boxes holding ingresses -> services -> pods (with their containers), from the
// read-only Kubernetes API account (/api/k8s/map -> host broker -> kube_map.py). Pick which namespaces to show (saved
// in this browser); click any ingress, service, pod or container for details. Container logs / security hits come
// from Security Onion (k8s.js pod page), linked from the details panel.
const K8M = { D: null, sec: null, sel: null, q: "", hidden: null, zoom: null };
const K8M_SYS = /^(kube-|cattle-|calico-|tigera-|fleet-|cluster-fleet-|p-[a-z0-9]{5}$|local$|user-|cert-manager$|longhorn-system$|elastic-agent$|netmon-readonly$|traefik$)/;
const K8M_C = { ing: "#bc8cff", svc: "#39c5cf", exp: "#ffa657", pod: "#7fa8d9", bad: "#e06a5f", warn: "#e1a948", ok: "#6cc287", dim: "#a3a3a6" };

function k8mHiddenLoad(D) {
  // namespaces never seen before (a new cluster, a new app) get the default: system / empty namespaces hidden
  const isDefaultHidden = (n) => !n.pods || K8M_SYS.test(n.name);
  let known = new Set(); try { known = new Set(JSON.parse(localStorage.getItem("k8smap.known") || "[]")); } catch (_) { /* none */ }
  const fresh = D.namespaces.filter((n) => !known.has(n.key));
  localStorage.setItem("k8smap.known", JSON.stringify(D.namespaces.map((n) => n.key)));
  if (K8M.hidden) { fresh.filter(isDefaultHidden).forEach((n) => K8M.hidden.add(n.key)); k8mSave(); return; }
  try { const v = JSON.parse(localStorage.getItem("k8smap.hidden") || "null"); if (Array.isArray(v) && v.every((x) => String(x).includes("|"))) { K8M.hidden = new Set(v); fresh.filter(isDefaultHidden).forEach((n) => K8M.hidden.add(n.key)); k8mSave(); return; } } catch (_) { /* first visit */ }
  K8M.hidden = new Set(D.namespaces.filter(isDefaultHidden).map((n) => n.key)); k8mSave();  // default: application namespaces only
}
function k8mSave() { localStorage.setItem("k8smap.hidden", JSON.stringify([...K8M.hidden])); }

// one map from several clusters: every id gets the cluster ("pod:talos|ns/name"), namespaces a key "talos|ns"
function k8mMerge(list) {
  const out = { namespaces: [], ingresses: [], services: [], workloads: [], pods: [], edges: [], nodes: [], cis_ns: {}, api: [], generated: "" };
  for (const [cl, D] of list) {
    const px = (id) => String(id || "").replace(/^(\w+):/, `$1:${cl}|`);
    D.namespaces.forEach((n) => out.namespaces.push({ ...n, cluster: cl, key: cl + "|" + n.name }));
    for (const k of ["ingresses", "services", "pods", "workloads"]) (D[k] || []).forEach((o) => out[k].push({ ...o, cluster: cl, id: px(o.id), nk: cl + "|" + o.ns, ...(k === "pods" ? { workload: o.workload ? px(o.workload) : "" } : {}) }));
    (D.edges || []).forEach((e) => out.edges.push({ ...e, from: px(e.from), to: px(e.to) }));
    (D.nodes || []).forEach((n) => out.nodes.push({ ...n, cluster: cl }));
    Object.entries(D.cis_ns || {}).forEach(([ns, v]) => (out.cis_ns[cl + "|" + ns] = v));
    out.api.push(cl + ": " + (D.api || "")); out.generated = D.generated;
  }
  out.namespaces.sort((a, b) => a.key.localeCompare(b.key));
  return out;
}

function k8mPodState(p) {  // colour of a pod: red = risky settings / not running, amber = restarts / root, green = fine
  const restarts = p.containers.reduce((s, c) => s + (c.restarts || 0), 0);
  if (p.risk.some((r) => r !== "may run as root") || (p.phase !== "Running" && p.phase !== "Succeeded")) return K8M_C.bad;
  if (restarts > 3 || p.risk.length || K8M.sec?.[p.ns + "/" + p.name]) return K8M_C.warn;
  return K8M_C.ok;
}
function k8mCtrState(c) { return c.security.privileged ? K8M_C.bad : c.state !== "running" && !c.init ? K8M_C.warn : c.security.root ? K8M_C.warn : K8M_C.ok; }

function k8mLayout(D) {
  const vis = D.namespaces.filter((n) => !K8M.hidden.has(n.key) && (!K8S.cluster || n.cluster === K8S.cluster)), q = K8M.q.toLowerCase();
  const match = (s) => !q || String(s).toLowerCase().includes(q);
  const PW = 170, SW = 150, IW = 170, GAP = 14, PER = 5, PAD = 14, HEAD = 34;
  const boxes = [];
  for (const n of vis) {
    const ing = D.ingresses.filter((x) => x.nk === n.key), svc = D.services.filter((x) => x.nk === n.key), pods = D.pods.filter((x) => x.nk === n.key);
    const podH = (p) => 26 + 15 * p.containers.length;
    const rowsOf = (arr) => { const r = []; for (let i = 0; i < arr.length; i += PER) r.push(arr.slice(i, i + PER)); return r; };
    const ir = rowsOf(ing), sr = rowsOf(svc), pr = rowsOf(pods);
    const w = Math.max(260, ...[ir.map((r) => r.length * (IW + GAP)), sr.map((r) => r.length * (SW + GAP)), pr.map((r) => r.length * (PW + GAP))].flat()) + 2 * PAD - GAP;
    let y = HEAD; const pos = {};
    const place = (rows, W, H, kind) => { for (const r of rows) { const rh = typeof H === "function" ? Math.max(...r.map(H)) : H;
      r.forEach((o, i) => { pos[o.id] = { x: PAD + i * (W + GAP), y, w: W, h: typeof H === "function" ? H(o) : H, kind, o }; }); y += rh + GAP; } if (rows.length) y += 10; };
    place(ir, IW, 40, "ing"); place(sr, SW, 40, "svc"); place(pr, PW, podH, "pod");
    boxes.push({ n, w, h: Math.max(y + 4, HEAD + 30), pos, hit: !q || match(n.name) || [...ing, ...svc, ...pods].some((o) => match(o.name) || (o.containers || []).some((c) => match(c.image) || match(c.name))) });
  }
  // shelf packing into rows of ~1900 px
  const MAXW = Math.max(1900, ...boxes.map((b) => b.w)); let x = 0, y = 0, rowH = 0;
  boxes.sort((a, b) => b.h - a.h).forEach((b) => { if (x && x + b.w > MAXW) { x = 0; y += rowH + 30; rowH = 0; } b.x = x; b.y = y; x += b.w + 30; rowH = Math.max(rowH, b.h); });
  return { boxes, W: Math.max(MAXW, 400), H: y + rowH + 20 };
}

function k8mRender(box) {
  const D = K8M.D, L = k8mLayout(D), at = {};
  L.boxes.forEach((b) => Object.entries(b.pos).forEach(([id, p]) => { at[id] = { x: b.x + p.x, y: b.y + p.y, w: p.w, h: p.h, b }; }));
  const svg = svgEl("svg", { viewBox: K8M.zoom || `0 0 ${L.W} ${L.H}`, width: "100%", style: `display:block;cursor:grab;user-select:none;height:${Math.min(1400, Math.max(420, L.H * 0.6))}px` });
  const root = svgEl("g"), gE = svgEl("g"), gB = svgEl("g"); root.append(gB, gE); svg.appendChild(root);
  const txt = (p, s, a) => { const t = svgEl("text", a); t.textContent = s; p.appendChild(t); return t; };
  const short = (s, n) => (String(s).length > n ? String(s).slice(0, n - 1) + "…" : String(s));
  const sel = K8M.sel?.id, rel = new Set();
  if (sel) D.edges.forEach((e) => { if (e.from === sel || e.to === sel) { rel.add(e.from); rel.add(e.to); } });
  for (const b of L.boxes) {
    const g = svgEl("g", { transform: `translate(${b.x},${b.y})`, style: `opacity:${b.hit ? 1 : 0.2}` });
    const cisN = (D.cis_ns?.[b.n.key] || []).length;
    g.appendChild(svgEl("rect", { width: b.w, height: b.h, rx: 12, fill: K8M_C.pod, "fill-opacity": 0.04, stroke: b.n.netpols.length ? "#7fa8d9" : K8M_C.warn, "stroke-opacity": 0.7, "stroke-width": 1.5, "stroke-dasharray": b.n.netpols.length ? "none" : "6 4" }));
    const hd = svgEl("g", { style: "cursor:pointer" }); hd.dataset.k8m = "ns:" + b.n.key;
    txt(hd, b.n.name + (D.multi ? "  · " + b.n.cluster : ""), { x: 14, y: 22, "font-size": 15, "font-weight": 700, fill: "#e9e7e2" });
    txt(hd, `${b.n.pods} pods · ${b.n.services} svc · PSA ${b.n.psa || "default"} · ${b.n.netpols.length ? b.n.netpols.length + " netpol" : "no network policy"}${cisN ? ` · CIS ${cisN}` : ""}`,
      { x: b.w - 12, y: 22, "text-anchor": "end", "font-size": 11, fill: b.n.netpols.length && !cisN ? K8M_C.dim : K8M_C.warn });
    g.appendChild(hd);
    for (const [id, p] of Object.entries(b.pos)) {
      const o = p.o, dimmed = sel && !rel.has(id) && sel !== id, n = svgEl("g", { transform: `translate(${p.x},${p.y})`, style: `cursor:pointer;opacity:${dimmed ? 0.35 : 1}` });
      n.dataset.k8m = id;
      const selS = sel === id ? { stroke: "#fff", "stroke-width": 2.5 } : {};
      if (p.kind === "ing") {
        const c = o.no_tls.length ? K8M_C.bad : K8M_C.ing;
        n.appendChild(svgEl("rect", { width: p.w, height: p.h, rx: 18, fill: c, "fill-opacity": 0.15, stroke: c, "stroke-width": 1.5, ...selS }));
        txt(n, "⇄ " + short(o.name, 20), { x: 10, y: 16, "font-size": 12, "font-weight": 600, fill: "#e9e7e2" });
        txt(n, short((o.hosts || []).join(", ") || "*", 26) + (o.no_tls.length ? " (no TLS)" : ""), { x: 10, y: 31, "font-size": 10, fill: K8M_C.dim });
      } else if (p.kind === "svc") {
        const c = o.exposed ? K8M_C.exp : K8M_C.svc;
        n.appendChild(svgEl("rect", { width: p.w, height: p.h, rx: 6, fill: c, "fill-opacity": 0.13, stroke: c, "stroke-width": 1.5, ...selS }));
        txt(n, "◆ " + short(o.name, 18), { x: 8, y: 16, "font-size": 12, "font-weight": 600, fill: "#e9e7e2" });
        txt(n, short(`${o.type} ${o.ports.join(" ")}`, 24), { x: 8, y: 31, "font-size": 10, fill: K8M_C.dim });
      } else {
        const c = k8mPodState(o);
        n.appendChild(svgEl("rect", { width: p.w, height: p.h, rx: 6, fill: "#16161a", stroke: c, "stroke-width": 1.5, ...selS }));
        txt(n, short(o.name.replace(/-[a-z0-9]{8,10}-[a-z0-9]{5}$/, "-…"), 22), { x: 8, y: 16, "font-size": 11, "font-weight": 600, fill: "#e9e7e2" });
        const hits = K8M.sec?.[o.ns + "/" + o.name];
        if (hits) { const bdg = svgEl("g", { transform: `translate(${p.w - 12},10)` }); bdg.appendChild(svgEl("circle", { r: 8, fill: K8M_C.warn })); txt(bdg, hits > 99 ? "99" : String(hits), { "text-anchor": "middle", dy: 3, "font-size": 8, "font-weight": 700, fill: "#0b0b0c" }); const t = svgEl("title"); t.textContent = hits + " security hits in its container logs (Security Onion)"; bdg.appendChild(t); n.appendChild(bdg); }
        o.containers.forEach((ct, i) => {
          const r = svgEl("g", { transform: `translate(6,${24 + i * 15})` }); const cid = o.id.replace(/^pod:/, "ctr:") + "/" + ct.name; r.dataset.k8m = cid;
          r.appendChild(svgEl("rect", { width: p.w - 12, height: 13, rx: 3, fill: k8mCtrState(ct), "fill-opacity": sel === cid ? 0.5 : 0.18 }));
          txt(r, (ct.init ? "◌ " : "▣ ") + short(ct.name, 15) + (ct.restarts ? ` ↻${ct.restarts}` : ""), { x: 4, y: 10, "font-size": 9.5, fill: "#e9e7e2" });
          n.appendChild(r);
        });
      }
      g.appendChild(n);
    }
    gB.appendChild(g);
  }
  for (const e of D.edges) {  // ingress -> service -> pod (workload->pod "owns" edges are implied by the pod list)
    if (e.kind === "owns") continue;
    const a = at[e.from], z = at[e.to]; if (!a || !z) continue;
    const on = sel && (e.from === sel || e.to === sel);
    gE.appendChild(svgEl("path", { d: `M${a.x + a.w / 2},${a.y + a.h} C${a.x + a.w / 2},${a.y + a.h + 24} ${z.x + z.w / 2},${z.y - 24} ${z.x + z.w / 2},${z.y}`,
      stroke: e.kind === "routes" ? K8M_C.ing : K8M_C.svc, "stroke-width": on ? 2.5 : 1.2, "stroke-opacity": sel && !on ? 0.12 : 0.6, fill: "none", "pointer-events": "none" }));
  }
  box.replaceChildren(svg);
  // pan + zoom on the viewBox (the same feel as the network map); a click without a drag selects
  let drag = null; const vb = () => svg.getAttribute("viewBox").split(" ").map(Number);
  svg.addEventListener("wheel", (ev) => { ev.preventDefault(); const [x, y, w, h] = vb(), r = svg.getBoundingClientRect(), f = ev.deltaY > 0 ? 1.15 : 1 / 1.15;
    const px = x + ((ev.clientX - r.left) / r.width) * w, py = y + ((ev.clientY - r.top) / r.height) * h;
    K8M.zoom = `${px - (px - x) * f} ${py - (py - y) * f} ${w * f} ${h * f}`; svg.setAttribute("viewBox", K8M.zoom); }, { passive: false });
  svg.addEventListener("pointerdown", (ev) => { drag = { x: ev.clientX, y: ev.clientY, vb: vb(), moved: false }; svg.style.cursor = "grabbing"; });
  svg.addEventListener("pointermove", (ev) => { if (!drag) return; const r = svg.getBoundingClientRect(), dx = ev.clientX - drag.x, dy = ev.clientY - drag.y;
    if (Math.abs(dx) + Math.abs(dy) > 4) drag.moved = true; if (!drag.moved) return;
    const [x, y, w, h] = drag.vb; K8M.zoom = `${x - (dx * w) / r.width} ${y - (dy * h) / r.height} ${w} ${h}`; svg.setAttribute("viewBox", K8M.zoom); });
  svg.addEventListener("pointerup", (ev) => { svg.style.cursor = "grab"; const d = drag; drag = null; if (d?.moved) return;
    const t = ev.target.closest("[data-k8m]"); K8M.sel = t ? { id: t.dataset.k8m } : null; k8mRender(box); k8mPanel(); });
}

function k8mKV(rows) { return `<div class="idgrid">${rows.filter((r) => r && r[1] !== undefined && r[1] !== "" && r[1] !== null).map(([k, v]) => `<span class="k">${esc(k)}</span><span>${v}</span>`).join("")}</div>`; }
const k8mList = (a) => (a && a.length ? a.map((x) => `<div class="mono small">${esc(x)}</div>`).join("") : '<span class="muted">—</span>');
const k8mFlags = (f) => (f || []).map((x) => `<span class="badge ${/privileged|root|adds/.test(x) ? "sev-high" : "sev-low"}">${esc(x)}</span>`).join(" ") || '<span class="badge good">hardened</span>';

function k8mPanel() {
  const el = document.getElementById("k8mPanel"); if (!el) return;
  const D = K8M.D, id = K8M.sel?.id || "";
  if (!id) { el.innerHTML = `<h3>Details</h3><div class="muted small">Click a namespace title, ingress (⇄), service (◆), pod or container (▣) on the map.</div>
    <h3>Legend</h3><div class="small"><div><span class="badge" style="background:${K8M_C.ing}">⇄</span> ingress (red = a host without TLS)</div><div><span class="badge" style="background:${K8M_C.svc}">◆</span> service (orange = NodePort / LoadBalancer, reachable from outside)</div>
    <div>Pod border / container: <span style="color:${K8M_C.ok}">■ fine</span> <span style="color:${K8M_C.warn}">■ restarts, root or security hits in its logs</span> <span style="color:${K8M_C.bad}">■ privileged / host access / not running</span></div><div>Dashed namespace border = no network policy.</div><div>↻n = container restarts; a number badge = security hits in its container logs (Security Onion).</div></div>`; return; }
  const [kind, rest] = [id.split(":")[0], id.slice(id.indexOf(":") + 1)];
  let h = "";
  if (kind === "ns") {
    const n = D.namespaces.find((x) => x.key === rest); if (!n) return;
    h = `<h3>Namespace ${esc(n.name)}</h3>` + k8mKV([["Cluster", esc(n.cluster)], ["Pods", n.pods], ["Services", n.services], ["Ingresses", n.ingresses], ["Pod security", esc(n.psa || "cluster default (no label)")],
      ["Network policies", n.netpols.length ? k8mList(n.netpols) : '<span class="sev-medium">none: every pod can talk to anything</span>'], ["Created", esc(ft(n.created))]])
      + ((D.cis_ns?.[n.key] || []).length ? `<h3>CIS findings</h3>${k8mList(D.cis_ns[n.key])}` : "")
      + `<p><button id="k8mHideNs">Hide this namespace</button> <a href="#/k8s">Security Onion data ›</a></p>`;
  } else if (kind === "ing") {
    const o = D.ingresses.find((x) => x.id === id); if (!o) return;
    h = `<h3>${esc(o.kind)} ${esc(o.ns)}/${esc(o.name)}</h3>` + k8mKV([["Class", esc(o.class)], ["Hosts", k8mList(o.hosts)], ["TLS", o.tls.length ? k8mList(o.tls) : ""],
      ["Without TLS", o.no_tls.length ? `<span class="sev-high">${esc(o.no_tls.join(", "))}</span>` : ""], ["Entry points", esc((o.entry_points || []).join(", "))], ["Routes", k8mList(o.paths)],
      ["Annotations", Object.keys(o.annotations || {}).length ? k8mList(Object.entries(o.annotations).map(([k, v]) => `${k}: ${String(v).slice(0, 120)}`)) : ""]])
      + `<h3>Routes to</h3>${k8mList(D.edges.filter((e) => e.from === id).map((e) => e.to.slice(4)))}`
      + (o.hosts.length ? `<p class="small">${o.hosts.map((x) => k8sKb(`(dns.query.name:${k8sQ(x)} or ssl.server_name:${k8sQ(x)})`, 1440, "", "Who connects to " + x)).filter(Boolean).join(" · ")}</p>` : "");
  } else if (kind === "svc") {
    const o = D.services.find((x) => x.id === id); if (!o) return;
    const tg = D.edges.filter((e) => e.from === id).map((e) => e.to.slice(4));
    h = `<h3>Service ${esc(o.ns)}/${esc(o.name)}</h3>` + k8mKV([["Type", o.exposed ? `<span class="sev-medium">${esc(o.type)} (reachable from outside the cluster)</span>` : esc(o.type)], ["Cluster IP", esc(o.cluster_ip)],
      ["External", o.external.length ? o.external.map((x) => ipLink(x)).join(" ") : ""], ["Ports", k8mList(o.ports)], ["Selector", k8mList(Object.entries(o.selector).map(([k, v]) => k + "=" + v))],
      ["Pods", tg.length ? tg.map((p) => { const [ns, pn] = p.split("/"); return `<div><a href="#" data-k8msel="pod:${esc(p)}">${esc(pn)}</a></div>`; }).join("") : '<span class="muted">none (no selector match)</span>'],
      ["From ingress", k8mList(D.edges.filter((e) => e.to === id).map((e) => e.from.slice(4)))]])
      + (o.cluster_ip && o.cluster_ip !== "None" ? `<p class="small">${k8sKb(`destination.ip:${k8sQ(o.cluster_ip)}`, 1440, "", "Connections to the cluster IP")}</p>` : "");
  } else if (kind === "pod" || kind === "ctr") {
    const cut = rest.lastIndexOf("/"), podId = kind === "pod" ? id : "pod:" + rest.slice(0, cut), cname = kind === "ctr" ? rest.slice(cut + 1) : "";
    const pod = D.pods.find((x) => x.id === podId); if (!pod) return;
    const w = D.workloads.find((x) => x.id === pod.workload), svcs = D.edges.filter((e) => e.to === pod.id && e.kind === "selects").map((e) => e.from.slice(4));
    const ctrHtml = (c) => `<h3>Container ${esc(c.name)}${c.init ? " (init)" : ""}</h3>` + k8mKV([["Image", `<span class="mono small">${esc(c.image)}</span>`], ["Image ID", c.image_id ? `<span class="mono small">${esc(c.image_id.split("@").pop().slice(0, 24))}…</span>` : ""],
      ["State", esc(c.state + (c.reason ? " (" + c.reason + ")" : "")) + (c.ready === false && !c.init ? ' <span class="sev-medium">not ready</span>' : "")], ["Restarts", c.restarts || 0],
      ["Last exit", c.last_termination ? esc(`${c.last_termination.reason || ""} code ${c.last_termination.exitCode} at ${ft(c.last_termination.finishedAt)}`) : ""],
      ["Ports", c.ports.length ? k8mList(c.ports) : ""], ["Security", k8mFlags(c.security.flags)], ["Runs as user", c.security.run_as_user ?? ""],
      ["Secrets in env", c.env_secrets.length ? `<span class="sev-medium">${esc(c.env_secrets.join(", "))}</span>` : ""],
      ["Requests", esc(Object.entries(c.resources.requests || {}).map(([k, v]) => k + " " + v).join(", "))], ["Limits", Object.keys(c.resources.limits || {}).length ? esc(Object.entries(c.resources.limits).map(([k, v]) => k + " " + v).join(", ")) : '<span class="muted">none</span>'],
      ["Mounts", c.mounts.length ? k8mList(c.mounts) : ""]])
      + `<p class="small"><a href="${k8sPodHref(pod.ns, pod.name, { container: c.name, cluster: pod.cluster })}">Logs and security events of this container ›</a></p>`;
    const cn = kind === "ctr" ? pod.containers.find((c) => c.name === cname) : null;
    h = `<h3>Pod ${esc(pod.name)}</h3><p><a href="${k8sPodHref(pod.ns, pod.name, { cluster: pod.cluster })}"><b>Logs, security hits and alerts (Security Onion) ›</b></a></p>`
      + k8mKV([["Cluster", esc(pod.cluster)], ["Namespace", esc(pod.ns)], ["Workload", w ? `${esc(w.kind)} ${esc(w.name)} (${w.ready}/${w.pods} ready)` : "none (bare pod)"], ["Phase", esc(pod.phase)], ["Node", pod.node ? hostLink(pod.node) : ""],
        ["Pod IP", pod.ip ? ipLink(pod.ip, false) : ""], ["Started", esc(ft(pod.start))], ["Service account", esc(pod.service_account) + (pod.automount_token ? ' <span class="badge sev-low">token mounted</span>' : "")],
        ["Host access", [pod.host_network && "hostNetwork", pod.host_pid && "hostPID", pod.host_ipc && "hostIPC"].filter(Boolean).map((x) => `<span class="badge sev-high">${x}</span>`).join(" ")],
        ["Risk", pod.risk.length ? pod.risk.map((x) => `<span class="badge sev-medium">${esc(x)}</span>`).join(" ") : ""], ["QoS", esc(pod.qos)],
        ["Services", svcs.length ? svcs.map((s) => `<div><a href="#" data-k8msel="svc:${esc(s)}">${esc(s.split("/")[1])}</a></div>`).join("") : ""],
        ["Volumes", k8mList(pod.volumes.map((v) => `${v.name}: ${v.type}${v.detail ? " " + v.detail : ""}`))], ["CIS", w?.cis?.length ? k8mList(w.cis) : ""]])
      + (cn ? ctrHtml(cn) : pod.containers.map(ctrHtml).join(""));
  }
  el.innerHTML = h;
  el.querySelectorAll("[data-k8msel]").forEach((a) => (a.onclick = (e) => { e.preventDefault(); K8M.sel = { id: a.dataset.k8msel }; k8mRender(document.getElementById("k8mGraph")); k8mPanel(); }));
  const hb = el.querySelector("#k8mHideNs"); if (hb) hb.onclick = () => { K8M.hidden.add(rest); k8mSave(); K8M.sel = null; K8M.zoom = null; k8mDraw(); };
}

function k8mNsPicker(el) {
  const D = K8M.D, wrap = document.createElement("details"); wrap.className = "k8m-ns";
  const NS = D.namespaces.filter((n) => !K8S.cluster || n.cluster === K8S.cluster);
  const shown = NS.filter((n) => !K8M.hidden.has(n.key)).length;
  wrap.innerHTML = `<summary>Namespaces: ${shown} of ${NS.length} shown ▾</summary><div class="k8m-nsbox">
    <div class="tbltools"><button data-a="all">All</button><button data-a="none">None</button><button data-a="apps">Applications only</button><button data-a="pods">With pods</button></div>
    ${NS.map((n) => `<label class="small"><input type="checkbox" value="${esc(n.key)}" ${K8M.hidden.has(n.key) ? "" : "checked"}> ${esc(n.name)}${D.multi ? ` <span class="badge">${esc(n.cluster)}</span>` : ""} <span class="muted">${n.pods}</span></label>`).join("")}</div>`;
  wrap.addEventListener("change", (e) => { const v = e.target.value; if (!v) return; e.target.checked ? K8M.hidden.delete(v) : K8M.hidden.add(v); k8mSave(); K8M.zoom = null; k8mDraw(true); });
  wrap.querySelectorAll("[data-a]").forEach((b) => (b.onclick = () => {
    const a = b.dataset.a; K8M.hidden = new Set(D.namespaces.filter((n) => a === "none" || (a === "apps" && (!n.pods || K8M_SYS.test(n.name))) || (a === "pods" && !n.pods)).map((n) => n.key));
    k8mSave(); K8M.zoom = null; k8mDraw(true); }));
  el.replaceChildren(wrap);
  return wrap;
}

function k8mDraw(keepOpen) {
  const open = keepOpen && document.querySelector(".k8m-ns")?.open;
  const w = k8mNsPicker(document.getElementById("k8mNs")); if (open) w.open = true;
  k8mRender(document.getElementById("k8mGraph")); k8mPanel();
}

V.k8smap = async (el) => {
  el.innerHTML = `<h1>Kubernetes map</h1><div class="sub">Namespaces with their ingresses → services → pods and containers, read live through the read-only Kubernetes API account
    (Configuration → Integrations → Kubernetes). Choose which namespaces to show; the choice is kept in this browser. Click anything for details; pod pages show logs and security events from Security Onion.
    Drag to pan, scroll to zoom.</div><div class="loading">Loading from the Kubernetes API…</div>`;
  let D;
  try {
    const L = await k8sClusterList(), want = K8S.cluster ? [K8S.cluster] : L.length ? L : [""];
    const got = await Promise.all(want.map(async (cl) => { const x = await api("/api/k8s/map?" + new URLSearchParams({ cluster: cl })); if (x.error) throw new Error((cl ? cl + ": " : "") + x.error); return [x.cluster || cl || "default", x]; }));
    D = k8mMerge(got); D.multi = L.length > 1;
  }
  catch (e) { el.querySelector(".loading").outerHTML = `<div class="card"><h2>Kubernetes map unavailable</h2><pre>${esc(e.message || e)}</pre><div class="muted small">Set up the read-only account under Configuration → Integrations → Kubernetes API.</div></div>`; return; }
  K8M.D = D; k8mHiddenLoad(D);
  el.querySelector(".loading").remove();
  el.insertAdjacentHTML("beforeend", kpis([["Namespaces", D.namespaces.length], ["Pods", D.pods.length], ["Services", D.services.length], ["Exposed services", D.services.filter((s) => s.exposed).length, D.services.some((s) => s.exposed) ? "warn" : ""],
    ["Ingresses", D.ingresses.length], ["Hosts without TLS", D.ingresses.reduce((s, i) => s + i.no_tls.length, 0), D.ingresses.some((i) => i.no_tls.length) ? "bad" : "good"],
    ["Namespaces without network policy", D.namespaces.filter((n) => n.pods && !n.netpols.length).length, "warn"], ["Privileged / host-access pods (incl. system)", D.pods.filter((p) => p.risk.some((r) => r !== "may run as root")).length]]));
  const ctr = document.createElement("div"); ctr.className = "tbltools";
  ctr.innerHTML = `<span id="k8mNs"></span><input id="k8mQ" placeholder="find pod, image, service…" value="${esc(K8M.q)}" style="min-width:220px"><button id="k8mReset">Reset view</button>
    <span class="muted small">API ${esc(D.api.join(" · "))} · ${esc(ft(D.generated))}</span>`;
  ctr.prepend(await k8sClusterBar(() => { K8M.sel = null; K8M.zoom = null; rerender(); }));
  el.appendChild(ctr);
  const wrap = document.createElement("div"); wrap.className = "lmwrap";
  const g = card("", "<div id='k8mGraph'></div>"); g.style.padding = "6px";
  const p = card("", "<div id='k8mPanel'></div>"); p.classList.add("lmpanel");
  wrap.append(g, p); el.appendChild(wrap);
  ctr.querySelector("#k8mQ").oninput = (e) => { K8M.q = e.target.value; k8mRender(document.getElementById("k8mGraph")); };
  ctr.querySelector("#k8mReset").onclick = () => { K8M.zoom = null; K8M.sel = null; k8mDraw(); };
  k8mDraw();
  // Security Onion overlay: security hits per pod (from the Kubernetes page data; optional)
  api("/api/k8s?minutes=1440").then((S0) => { const m = {}; (S0.signals || []).filter((s) => !s.exempt).forEach((s) => { const k = s.ns + "/" + s.pod; m[k] = (m[k] || 0) + s.count; });
    K8M.sec = m; if (document.getElementById("k8mGraph")) k8mRender(document.getElementById("k8mGraph")); }).catch(() => {});
};
