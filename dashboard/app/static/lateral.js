/* Lateral-movement graph view (internal hosts only, grouped by zone). Uses helpers from app.js. */
"use strict";

const LM_LEVELS = {
  high: { c: "#f85149", l: "High" }, medium: { c: "#d29922", l: "Medium" }, low: { c: "#e3b341", l: "Low" },
  "allowed-admin": { c: "#58a6ff", l: "Allowed admin" }, normal: { c: "#6e7681", l: "Normal" },
};
const LM_ZONE_COL = { lan: "#58a6ff", servers: "#bc8cff", ai: "#3fb950", dmz: "#f85149", k8s: "#39c5cf", vlan3: "#ffa657", vlan4: "#ff9bce", vlan21: "#d2a8ff" };
const LM_FILTERS = [["risky", "High / medium / low risk"], ["high", "High + medium only"], ["admin", "Risky + allowed admin"], ["all", "All internal connections"]];
const LM = { filter: "risky", gateways: false, labels: true, focus: null, sel: null, data: null, pos: {} };
const SVGNS = "http://www.w3.org/2000/svg";
const svgEl = (t, a = {}) => { const e = document.createElementNS(SVGNS, t); for (const [k, v] of Object.entries(a)) e.setAttribute(k, v); return e; };

function lmVisible(D) {
  const lv = { risky: ["high", "medium", "low"], high: ["high", "medium"], admin: ["high", "medium", "low", "allowed-admin"], all: Object.keys(LM_LEVELS) }[LM.filter];
  let edges = D.edges.filter((e) => lv.includes(e.level));
  if (!LM.gateways) edges = edges.filter((e) => !e.src.endsWith(".1") && !e.dst.endsWith(".1"));
  if (LM.focus) edges = edges.filter((e) => e.src === LM.focus || e.dst === LM.focus);
  const ids = new Set(edges.flatMap((e) => [e.src, e.dst]));
  if (LM.focus) ids.add(LM.focus);
  const nodes = D.nodes.filter((n) => ids.has(n.id));
  return { nodes, edges };
}

/* deterministic seeded random so the layout is stable between renders */
function lmRand(seed) { let s = 0; for (const c of seed) s = (s * 31 + c.charCodeAt(0)) >>> 0; return () => ((s = (s * 1664525 + 1013904223) >>> 0) / 4294967296); }

function lmLayout(nodes, edges, W, H) {
  const byZone = {}; nodes.forEach((n) => (byZone[n.zone] = byZone[n.zone] || []).push(n));
  const zs = Object.keys(byZone).sort((a, b) => byZone[b].length - byZone[a].length);
  const zr = Object.fromEntries(zs.map((z) => [z, Math.max(70, 34 * Math.sqrt(byZone[z].length) + 30)]));
  // place zones: biggest at centre, the rest on a ring around it
  const zc = {}; const cx = W / 2, cy = H / 2;
  if (zs.length === 1) zc[zs[0]] = [cx, cy];
  else {
    zc[zs[0]] = [cx, cy];
    const rest = zs.slice(1), ringR = zr[zs[0]] + Math.max(...rest.map((z) => zr[z])) + 60;
    rest.forEach((z, i) => { const a = -Math.PI / 2 + (2 * Math.PI * i) / rest.length; zc[z] = [cx + ringR * Math.cos(a) * 1.35, cy + ringR * Math.sin(a)]; });
  }
  const rnd = lmRand(nodes.map((n) => n.id).join());
  const P = {};
  nodes.forEach((n) => { const [x, y] = zc[n.zone]; P[n.id] = LM.pos[n.id] ? { ...LM.pos[n.id], fixed: true } : { x: x + (rnd() - 0.5) * zr[n.zone], y: y + (rnd() - 0.5) * zr[n.zone] }; });
  const rad = (n) => 7 + Math.sqrt(n.risk || 0) * 2.6;
  for (let it = 0; it < 320; it++) {
    const k = 1 - it / 320;
    for (let i = 0; i < nodes.length; i++) {
      const a = nodes[i], pa = P[a.id];
      for (let j = i + 1; j < nodes.length; j++) {
        const b = nodes[j], pb = P[b.id];
        let dx = pa.x - pb.x, dy = pa.y - pb.y, d2 = dx * dx + dy * dy + 0.01, d = Math.sqrt(d2);
        const min = rad(a) + rad(b) + (LM.labels ? 26 : 10);
        const f = (a.zone === b.zone ? 900 : 2200) / d2 + (d < min ? (min - d) * 0.5 : 0);
        dx = (dx / d) * f; dy = (dy / d) * f;
        if (!pa.fixed) { pa.x += dx; pa.y += dy; } if (!pb.fixed) { pb.x -= dx; pb.y -= dy; }
      }
      // pull toward own zone centre, keep inside zone circle
      const [zx, zy] = zc[a.zone]; const dx = zx - pa.x, dy = zy - pa.y, d = Math.hypot(dx, dy);
      if (!pa.fixed) { pa.x += dx * 0.04 * k + (d > zr[a.zone] - rad(a) ? dx * 0.15 : 0); pa.y += dy * 0.04 * k + (d > zr[a.zone] - rad(a) ? dy * 0.15 : 0); }
    }
  }
  // zone hulls from final positions
  const hull = {};
  for (const z of zs) {
    const ps = byZone[z].map((n) => P[n.id]); const mx = ps.reduce((s, p) => s + p.x, 0) / ps.length, my = ps.reduce((s, p) => s + p.y, 0) / ps.length;
    const r = Math.max(48, ...byZone[z].map((n) => Math.hypot(P[n.id].x - mx, P[n.id].y - my) + rad(n) + (LM.labels ? 22 : 12)));
    hull[z] = { x: mx, y: my, r, n: byZone[z].length };
  }
  return { P, hull, rad };
}

function lmRenderGraph(box, D) {
  const { nodes, edges } = lmVisible(D);
  box.innerHTML = "";
  if (!nodes.length) { box.innerHTML = `<div class="empty" style="padding:40px">No connections at this filter level. Try "All internal connections".</div>`; return; }
  const narrow = window.matchMedia("(max-width: 900px)").matches, boxW = box.clientWidth || box.parentElement?.clientWidth || 1200;
  const W = Math.max(900, boxW), H = Math.max(620, Math.min(1000, 380 + nodes.length * 7));
  const viewH = narrow ? Math.round(Math.min(window.innerHeight * 0.68, 560)) : H;  // on screen; the layout itself stays W x H
  const { P, hull, rad } = lmLayout(nodes, edges, W, H);
  // fit to viewBox
  const xs = Object.values(hull).flatMap((h) => [h.x - h.r, h.x + h.r]), ys = Object.values(hull).flatMap((h) => [h.y - h.r - 18, h.y + h.r]);
  let x0 = Math.min(...xs) - 20, x1 = Math.max(...xs) + 20; const y0 = Math.min(...ys) - 20, y1 = Math.max(...ys) + 20;
  // text keeps a readable on-screen size when the whole map is shrunk onto a phone
  const TS = Math.min(2.2, Math.max(1, 1 / Math.min(boxW / (x1 - x0), viewH / (y1 - y0)))), FS = (px) => Math.round(px * TS * 10) / 10;
  if (LM.labels) for (const n of nodes) {  // widen the frame so edge labels are not cut off
    const half = (Math.min(28, (n.name || "").length) * FS(11) * 0.56) / 2 + 6, p = P[n.id]; if (!p) continue;
    x0 = Math.min(x0, p.x - half); x1 = Math.max(x1, p.x + half); }
  const vb = [x0, y0, x1 - x0, y1 - y0];
  const svg = svgEl("svg", { viewBox: vb.join(" "), width: "100%", height: viewH, style: "display:block;cursor:grab;touch-action:none;user-select:none" });
  const defs = svgEl("defs"); svg.appendChild(defs);
  for (const [k, v] of Object.entries(LM_LEVELS)) {
    const m = svgEl("marker", { id: "lm-arrow-" + k, viewBox: "0 0 10 10", refX: 9, refY: 5, markerWidth: 11, markerHeight: 11, markerUnits: "userSpaceOnUse", orient: "auto-start-reverse" });
    m.appendChild(svgEl("path", { d: "M0,0 L10,5 L0,10 z", fill: v.c })); defs.appendChild(m);
  }
  const root = svgEl("g"); svg.appendChild(root);
  const gZ = svgEl("g"), gE = svgEl("g"), gN = svgEl("g"); root.append(gZ, gE, gN);
  for (const [z, h] of Object.entries(hull)) {
    const c = LM_ZONE_COL[z] || "#8b949e";
    gZ.appendChild(svgEl("circle", { cx: h.x, cy: h.y, r: h.r, fill: c, "fill-opacity": 0.07, stroke: c, "stroke-opacity": 0.55, "stroke-width": 1.5, "stroke-dasharray": "6 4" }));
    const t = svgEl("text", { x: h.x, y: h.y - h.r - 6, "text-anchor": "middle", fill: c, "font-size": FS(14), "font-weight": 700 }); t.textContent = `${z.toUpperCase()} · ${h.n}`; gZ.appendChild(t);
  }
  const maxC = Math.max(1, ...edges.map((e) => e.conns));
  const pair = new Set(edges.map((e) => e.src + ">" + e.dst));
  const edgeEls = [];
  const edgePath = (e) => {
    const a = P[e.src], b = P[e.dst], na = nodes.find((n) => n.id === e.src), nb = nodes.find((n) => n.id === e.dst);
    const dx = b.x - a.x, dy = b.y - a.y, d = Math.hypot(dx, dy) || 1;
    const bend = pair.has(e.dst + ">" + e.src) ? 0.18 : 0.08; // separate A->B and B->A
    const mx = (a.x + b.x) / 2 - dy * bend, my = (a.y + b.y) / 2 + dx * bend;
    const ra = rad(na) + 2, rb = rad(nb) + 4;
    const sa = Math.hypot(mx - a.x, my - a.y) || 1, sb = Math.hypot(b.x - mx, b.y - my) || 1;
    const x1 = a.x + ((mx - a.x) / sa) * ra, y1 = a.y + ((my - a.y) / sa) * ra, x2 = b.x - ((b.x - mx) / sb) * rb, y2 = b.y - ((b.y - my) / sb) * rb;
    return `M${x1},${y1} Q${mx},${my} ${x2},${y2}`;
  };
  for (const e of edges) {
    const lv = LM_LEVELS[e.level];
    const w = 1.2 + 4 * Math.sqrt(e.conns / maxC) + (e.level === "high" ? 1.5 : 0);
    const p = svgEl("path", { d: edgePath(e), fill: "none", stroke: lv.c, "stroke-width": w, "stroke-opacity": e.level === "normal" ? 0.35 : 0.85, "marker-end": `url(#lm-arrow-${e.level})`, style: "cursor:pointer" });
    if (e.level === "high") p.setAttribute("stroke-dasharray", "none");
    if (!e.answered) p.setAttribute("stroke-dasharray", "4 3");
    const hit = svgEl("path", { d: edgePath(e), fill: "none", stroke: "transparent", "stroke-width": Math.max(10, w + 6), style: "cursor:pointer" });
    const title = svgEl("title"); title.textContent = `${lmName(D, e.src)} → ${lmName(D, e.dst)}\n${LM_LEVELS[e.level].l} · ${fn(e.conns)} conns (${fn(e.answered)} answered)\n` + e.ports.slice(0, 6).map((p) => `${p.port}/${p.proto} ${p.service} [${p.level}] ${p.why}`).join("\n");
    hit.appendChild(title);
    hit.onclick = (ev) => { ev.stopPropagation(); LM.sel = { edge: e }; lmRenderPanel(D); };
    gE.append(p, hit); edgeEls.push({ e, p, hit });
  }
  const nodeEls = [];
  for (const n of nodes) {
    const g = svgEl("g", { transform: `translate(${P[n.id].x},${P[n.id].y})`, style: "cursor:pointer" });
    const r = rad(n), rc = n.risk >= 40 ? "#f85149" : n.risk >= 20 ? "#d29922" : n.risk >= 8 ? "#e3b341" : "#3fb950";
    const zc = LM_ZONE_COL[n.zone] || "#8b949e";
    g.appendChild(svgEl("circle", { r, fill: n.gateway ? "#30363d" : rc, "fill-opacity": n.gateway ? 1 : 0.85, stroke: n.id === LM.focus ? "#fff" : zc, "stroke-width": n.id === LM.focus ? 3 : 2 }));
    if (n.gateway) { const t = svgEl("text", { "text-anchor": "middle", dy: 4, "font-size": FS(10), fill: "#c9d1d9" }); t.textContent = "GW"; g.appendChild(t); }
    else if (n.risk >= 8) { const t = svgEl("text", { "text-anchor": "middle", dy: 4, "font-size": Math.min(12, r * 0.9), "font-weight": 700, fill: "#0d1117" }); t.textContent = Math.round(n.risk); g.appendChild(t); }
    if (!n.known && !n.gateway) g.appendChild(svgEl("circle", { r: r + 4, fill: "none", stroke: "#d29922", "stroke-width": 1, "stroke-dasharray": "2 2" }));
    if (LM.labels) { const t = svgEl("text", { "text-anchor": "middle", y: r + 4 + FS(9), "font-size": FS(11), fill: "#c9d1d9", stroke: "#0d1117", "stroke-width": 3, "paint-order": "stroke", style: "paint-order:stroke" }); t.textContent = n.name.length > 24 ? n.name.slice(0, 23) + "…" : n.name; g.appendChild(t); }
    const title = svgEl("title"); title.textContent = `${n.name} (${n.id})\nzone ${n.zone}${n.class ? " · " + n.class : ""}\nrisk ${n.risk}${n.rank ? " (rank " + n.rank + ")" : ""}\nrisky out ${n.out_risky} · risky in ${n.in_risky}`; g.appendChild(title);
    g.onmouseenter = () => lmHighlight(n.id, edgeEls, nodeEls);
    g.onmouseleave = () => lmHighlight(null, edgeEls, nodeEls);
    gN.appendChild(g); nodeEls.push({ n, g });
    // drag to reposition; click (no drag) selects
    let drag = null;
    g.addEventListener("pointerdown", (ev) => { ev.stopPropagation(); drag = { x: ev.clientX, y: ev.clientY, moved: false }; g.setPointerCapture(ev.pointerId); });
    g.addEventListener("pointermove", (ev) => {
      if (!drag) return; const ctm = svg.getScreenCTM(); const dx = (ev.clientX - drag.x) / ctm.a, dy = (ev.clientY - drag.y) / ctm.d;
      if (Math.abs(dx) + Math.abs(dy) > 2) drag.moved = true; drag.x = ev.clientX; drag.y = ev.clientY;
      P[n.id].x += dx; P[n.id].y += dy; LM.pos[n.id] = { x: P[n.id].x, y: P[n.id].y };
      g.setAttribute("transform", `translate(${P[n.id].x},${P[n.id].y})`);
      edgeEls.filter((x) => x.e.src === n.id || x.e.dst === n.id).forEach((x) => { const d = edgePath(x.e); x.p.setAttribute("d", d); x.hit.setAttribute("d", d); });
    });
    g.addEventListener("pointerup", () => { if (drag && !drag.moved) { LM.sel = { node: n }; lmRenderPanel(D); lmHighlight(n.id, edgeEls, nodeEls);
      if (narrow) document.getElementById("lmPanel")?.scrollIntoView({ behavior: "smooth", block: "start" }); } drag = null; });
    g.addEventListener("pointercancel", () => { drag = null; });
    g.addEventListener("click", (ev) => ev.stopPropagation());
    g.addEventListener("dblclick", () => { if (!n.gateway && S.snap.raw.devices?.[n.id]) go("device/" + n.id); });
  }
  // pan & zoom
  let view = { x: 0, y: 0, k: 1 }, pan = null;
  const apply = () => root.setAttribute("transform", `translate(${view.x},${view.y}) scale(${view.k})`);
  svg.addEventListener("wheel", (ev) => { ev.preventDefault(); const pt = svg.createSVGPoint(); pt.x = ev.clientX; pt.y = ev.clientY; const p = pt.matrixTransform(svg.getScreenCTM().inverse());
    const k2 = Math.min(4, Math.max(0.4, view.k * (ev.deltaY < 0 ? 1.12 : 1 / 1.12))); view.x = p.x - ((p.x - view.x) * k2) / view.k; view.y = p.y - ((p.y - view.y) * k2) / view.k; view.k = k2; apply(); }, { passive: false });
  const zoomAt = (cx, cy, k2) => { const pt = svg.createSVGPoint(); pt.x = cx; pt.y = cy; const p = pt.matrixTransform(svg.getScreenCTM().inverse());
    k2 = Math.min(6, Math.max(0.4, k2)); view.x = p.x - ((p.x - view.x) * k2) / view.k; view.y = p.y - ((p.y - view.y) * k2) / view.k; view.k = k2; apply(); };
  const pts = new Map(); let pinch = null;  // active pointers on the background: 1 = pan, 2 = pinch-zoom
  svg.addEventListener("pointerdown", (ev) => { pts.set(ev.pointerId, { x: ev.clientX, y: ev.clientY }); svg.setPointerCapture?.(ev.pointerId);
    if (pts.size === 2) { const [a, b] = [...pts.values()]; pinch = { d: Math.hypot(a.x - b.x, a.y - b.y), k: view.k }; pan = null; }
    else { pan = { x: ev.clientX, y: ev.clientY }; svg.style.cursor = "grabbing"; } });
  svg.addEventListener("pointermove", (ev) => {
    if (!pts.has(ev.pointerId)) return; pts.set(ev.pointerId, { x: ev.clientX, y: ev.clientY });
    if (pinch && pts.size === 2) { const [a, b] = [...pts.values()]; zoomAt((a.x + b.x) / 2, (a.y + b.y) / 2, pinch.k * Math.hypot(a.x - b.x, a.y - b.y) / (pinch.d || 1)); return; }
    if (!pan) return; const ctm = svg.getScreenCTM(); view.x += (ev.clientX - pan.x) / ctm.a; view.y += (ev.clientY - pan.y) / ctm.d; pan = { x: ev.clientX, y: ev.clientY }; apply(); });
  const up = (ev) => { pts.delete(ev.pointerId); if (pts.size < 2) pinch = null;
    if (pts.size === 1) { const [a] = [...pts.values()]; pan = { x: a.x, y: a.y }; } else { pan = null; svg.style.cursor = "grab"; } };
  svg.addEventListener("pointerup", up); svg.addEventListener("pointercancel", up);
  const zb = document.createElement("div"); zb.className = "lmzoom";
  zb.innerHTML = `<button data-z="in" title="Zoom in" aria-label="Zoom in">+</button><button data-z="out" title="Zoom out" aria-label="Zoom out">−</button><button data-z="fit" title="Fit" aria-label="Fit to screen">⤢</button>`;
  zb.onclick = (ev) => { const z = ev.target.dataset.z; if (!z) return; const r = svg.getBoundingClientRect();
    if (z === "fit") { view = { x: 0, y: 0, k: 1 }; apply(); } else zoomAt(r.left + r.width / 2, r.top + r.height / 2, view.k * (z === "in" ? 1.4 : 1 / 1.4)); };
  box.style.position = "relative"; box.appendChild(zb);
  svg.addEventListener("click", () => { if (LM.sel) { LM.sel = null; lmRenderPanel(D); } });
  box.appendChild(svg);
}

function lmHighlight(id, edgeEls, nodeEls) {
  if (!id) { edgeEls.forEach(({ p, e }) => p.setAttribute("stroke-opacity", e.level === "normal" ? 0.35 : 0.85)); nodeEls.forEach(({ g }) => (g.style.opacity = 1)); return; }
  const nb = new Set([id]);
  edgeEls.forEach(({ e, p }) => { const on = e.src === id || e.dst === id; if (on) { nb.add(e.src); nb.add(e.dst); } p.setAttribute("stroke-opacity", on ? 1 : 0.07); });
  nodeEls.forEach(({ n, g }) => (g.style.opacity = nb.has(n.id) ? 1 : 0.2));
}
const lmName = (D, ip) => D.nodes.find((n) => n.id === ip)?.name || ip;
function lmNodeLink(D, ip) {
  const n = D.nodes.find((x) => x.id === ip);
  const nm = esc(n?.name || ip);
  return S.snap.raw.devices?.[ip] && !ip.endsWith(".1") ? `<a href="#/device/${ip}">${nm}</a> <span class="muted small">${esc(ip)}</span>` : `${nm} <span class="muted small">${esc(ip)}</span>`;
}
const lmLevel = (l) => `<span class="badge" style="background:${LM_LEVELS[l].c}26;color:${LM_LEVELS[l].c};border-color:${LM_LEVELS[l].c}55">${esc(LM_LEVELS[l].l)}</span>`;

function lmPortsTable(e) {
  return table(null, [{ k: "port", t: "Port", fmt: (v, p) => `${v}/${esc(p.proto)}` }, { k: "service", t: "Svc" }, { k: "level", t: "Risk", fmt: lmLevel, sort: (p) => Object.keys(LM_LEVELS).indexOf(p.level) },
    { k: "conns", t: "Conns", num: true, fmt: fn }, { k: "answered", t: "Ans", num: true, fmt: fn }, { k: "bytes", t: "Bytes", num: true, fmt: fb }, { k: "why", t: "Why", cls: "small" }], e.ports, { sort: "level", dir: 1, search: false, short: true });
}
function lmRenderPanel(D) {
  const el = document.getElementById("lmPanel"); if (!el) return;
  el.innerHTML = "";
  const sel = LM.sel;
  if (!sel) { el.innerHTML = `<h2>Details</h2><div class="muted small">${window.matchMedia("(pointer: coarse)").matches
      ? "Tap a host bubble to see its connections here. Drag a bubble to move it, drag the background to pan, pinch or use + / − to zoom, ⤢ to fit."
      : "Click a host bubble or a link. Hover a host to isolate its connections, drag bubbles to rearrange, scroll or use + / − to zoom, drag the background to pan, double-click a host to open its device page."}</div>
    <h3>Legend</h3><div class="small">${Object.entries(LM_LEVELS).map(([k, v]) => `<div><svg width="30" height="10"><line x1="0" y1="5" x2="30" y2="5" stroke="${v.c}" stroke-width="3"/></svg> ${v.l}</div>`).join("")}
    <div><svg width="30" height="10"><line x1="0" y1="5" x2="30" y2="5" stroke="#8b949e" stroke-width="2" stroke-dasharray="4 3"/></svg> never answered (attempt/scan)</div>
    <div style="margin-top:6px">Bubble size and colour = host risk score (number inside); outline colour = zone; dashed amber ring = not in inventory; GW = gateway interface.</div></div>`; return; }
  if (sel.edge) {
    const e = sel.edge;
    el.insertAdjacentHTML("beforeend", `<h2>${lmLevel(e.level)} Connection</h2><div class="idgrid"><span class="k">From</span><span>${lmNodeLink(D, e.src)} <span class="chip">${esc(e.src_zone)}</span></span><span class="k">To</span><span>${lmNodeLink(D, e.dst)} <span class="chip">${esc(e.dst_zone)}</span></span>
      <span class="k">Conns</span><span>${fn(e.conns)} (${fn(e.answered)} answered)</span><span class="k">Bytes</span><span>${fb(e.bytes)}</span><span class="k">Score</span><span>${e.score}</span></div><h3>Ports</h3>`);
    el.appendChild(lmPortsTable(e));
    return;
  }
  const n = sel.node;
  const out = D.edges.filter((e) => e.src === n.id), inn = D.edges.filter((e) => e.dst === n.id);
  el.insertAdjacentHTML("beforeend", `<h2>${esc(n.name)}</h2><div class="idgrid"><span class="k">IP</span><span class="mono">${esc(n.id)}</span><span class="k">Zone</span><span>${esc(n.zone)}${n.class ? " · " + esc(n.class) : ""}</span>
    <span class="k">Host risk</span><span>${riskBadge(n.risk)}${n.rank ? ` rank ${n.rank}` : ""}</span><span class="k">Risky out / in</span><span>${n.out_risky} / ${n.in_risky}</span></div>
    <div style="margin:8px 0;display:flex;gap:6px;flex-wrap:wrap"><button id="lmFocus">${LM.focus === n.id ? "Show everything" : "Focus on this host"}</button>${S.snap.raw.devices?.[n.id] && !n.gateway ? `<a href="#/device/${n.id}"><button>Device page →</button></a>` : ""}</div>`);
  const mini = (list, dir) => table(null, [{ k: dir, t: dir === "dst" ? "To" : "From", fmt: (v) => lmNodeLink(D, v) }, { k: "level", t: "Risk", fmt: lmLevel, sort: (e) => Object.keys(LM_LEVELS).indexOf(e.level) },
    { k: "ports", t: "Ports", cls: "small", fmt: (v) => esc(v.slice(0, 4).map((p) => p.port + "/" + p.proto).join(", ") + (v.length > 4 ? " …" : "")), sort: (e) => e.ports.length }, { k: "conns", t: "Conns", num: true, fmt: fn }], list, { sort: "level", dir: 1, search: false, short: true, onclick: (e) => { LM.sel = { edge: e }; lmRenderPanel(D); } });
  el.insertAdjacentHTML("beforeend", `<h3>Outgoing (${out.length})</h3>`); el.appendChild(mini(out, "dst"));
  el.insertAdjacentHTML("beforeend", `<h3>Incoming (${inn.length})</h3>`); el.appendChild(mini(inn, "src"));
  document.getElementById("lmFocus").onclick = () => { LM.focus = LM.focus === n.id ? null : n.id; lmDraw(); };
}

let _lmDraw = null;
function lmDraw() { _lmDraw && _lmDraw(); }

V.lateral = async (el, arg) => {
  if (arg) { LM.focus = arg; if (!["all", "admin"].includes(LM.filter)) LM.filter = "admin"; }
  el.innerHTML = `<h1>Lateral movement</h1><div class="sub">Host-to-host connections inside the network only (internet hosts are never mapped), grouped by zone. Links are classified against the segmentation policy: policy violations, failed admin-port attempts and internal scans are risky; admin access you've allowed in policy.json is shown separately.</div><div class="loading">Loading…</div>`;
  let D;
  try { D = S.lateral && S.lateral._snap === S.snap.id ? S.lateral : await api("/api/lateral?id=" + encodeURIComponent(S.snap.id)); D._snap = S.snap.id; S.lateral = D; }
  catch (e) { el.querySelector(".loading").outerHTML = `<pre>${esc(e)}</pre>`; return; }
  LM.data = D;
  el.querySelector(".loading").remove();
  const c = D.counts;
  el.insertAdjacentHTML("beforeend", kpis([["High-risk links", c.high, c.high ? "bad" : "good"], ["Medium-risk links", c.medium, c.medium ? "warn" : "good"], ["Low-risk links", c.low], ["Allowed admin links", c["allowed-admin"]], ["Normal links", c.normal], ["Internal hosts", D.nodes.filter((n) => !n.gateway).length]]));
  const ctr = document.createElement("div"); ctr.className = "tbltools";
  ctr.innerHTML = `<label class="muted">Show</label><select id="lmFilter">${LM_FILTERS.map(([k, l]) => `<option value="${k}" ${LM.filter === k ? "selected" : ""}>${l}</option>`).join("")}</select>
    <label><input type="checkbox" id="lmGw" ${LM.gateways ? "checked" : ""}> gateway interfaces</label><label><input type="checkbox" id="lmLab" ${LM.labels ? "checked" : ""}> labels</label>
    <select id="lmFocusSel"><option value="">Focus host: (none)</option>${[...D.nodes].filter((n) => !n.gateway).sort((a, b) => b.risk - a.risk).map((n) => `<option value="${esc(n.id)}" ${LM.focus === n.id ? "selected" : ""}>${esc(n.name)} (${esc(n.id)})</option>`).join("")}</select>
    <button id="lmReset">Reset layout</button>`;
  el.appendChild(ctr);
  const wrap = document.createElement("div"); wrap.className = "lmwrap";
  const gcard = card("", "<div id='lmGraph'></div>"); gcard.style.padding = "6px";
  const pcard = card("", "<div id='lmPanel'></div>"); pcard.classList.add("lmpanel");
  wrap.append(gcard, pcard); el.appendChild(wrap);
  const tcard = document.createElement("div"); el.appendChild(tcard);
  _lmDraw = () => {
    if (LM.focus && !LM.sel) { const n = D.nodes.find((x) => x.id === LM.focus); if (n) LM.sel = { node: n }; }
    lmRenderGraph(document.getElementById("lmGraph"), D); lmRenderPanel(D);
    const vis = lmVisible(D).edges;
    tcard.innerHTML = "";
    tcard.appendChild(card(`Connections shown (${vis.length})`, table(null, [
      { k: "level", t: "Risk", fmt: lmLevel, sort: (e) => Object.keys(LM_LEVELS).indexOf(e.level) }, { k: "score", t: "Score", num: true, bar: true },
      { k: "src", t: "From", fmt: (v) => lmNodeLink(D, v), sort: (e) => lmName(D, e.src) }, { k: "src_zone", t: "Zone" }, { k: "dst", t: "To", fmt: (v) => lmNodeLink(D, v), sort: (e) => lmName(D, e.dst) }, { k: "dst_zone", t: "Zone" },
      { k: "ports", t: "Risky ports / reason", cls: "small", fmt: (v) => v.filter((p) => p.level !== "normal").slice(0, 3).map((p) => `${p.port}/${p.proto} — ${esc(p.why)}`).join("<br>") || esc(v.slice(0, 4).map((p) => p.port + "/" + p.proto).join(", ")), sort: (e) => e.ports.length },
      { k: "conns", t: "Conns", num: true, fmt: fn }, { k: "answered", t: "Answered", num: true, fmt: fn }, { k: "bytes", t: "Bytes", num: true, fmt: fb }], vis, { sort: "score", onclick: (e) => { LM.sel = { edge: e }; lmRenderPanel(D); window.scrollTo({ top: 0, behavior: "smooth" }); } })));
  };
  document.getElementById("lmFilter").onchange = (e) => { LM.filter = e.target.value; LM.sel = null; lmDraw(); };
  document.getElementById("lmGw").onchange = (e) => { LM.gateways = e.target.checked; lmDraw(); };
  document.getElementById("lmLab").onchange = (e) => { LM.labels = e.target.checked; LM.pos = {}; lmDraw(); };
  document.getElementById("lmFocusSel").onchange = (e) => { LM.focus = e.target.value || null; LM.sel = null; lmDraw(); };
  document.getElementById("lmReset").onclick = () => { LM.pos = {}; LM.focus = null; LM.sel = null; document.getElementById("lmFocusSel").value = ""; lmDraw(); };
  lmDraw();
  // redraw when the width really changes (rotation, window resize), not on mobile URL-bar height jitter
  let lastW = innerWidth, t = null;
  const onResize = () => { clearTimeout(t); t = setTimeout(() => { if (!document.getElementById("lmGraph")) { removeEventListener("resize", onResize); return; }
    if (Math.abs(innerWidth - lastW) > 40) { lastW = innerWidth; lmRenderGraph(document.getElementById("lmGraph"), D); } }, 250); };
  addEventListener("resize", onResize);
};
