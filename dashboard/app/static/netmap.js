/* Network map: gateway -> zones -> hosts (internal only). Uses helpers from app.js / lateral.js. */
"use strict";

const NM_CLASS = {
  server: { g: "S", c: "#bc8cff", l: "Server" }, infra: { g: "N", c: "#39c5cf", l: "Network infra" }, k8s: { g: "K", c: "#56d4dd", l: "Kubernetes" },
  work: { g: "W", c: "#58a6ff", l: "Work" }, personal: { g: "P", c: "#a5d6ff", l: "Personal" }, camera: { g: "C", c: "#ffa657", l: "Camera" },
  iot: { g: "I", c: "#e3b341", l: "IoT" }, media: { g: "M", c: "#ff9bce", l: "Media" }, game: { g: "G", c: "#7ee787", l: "Game" }, "": { g: "?", c: "#8b949e", l: "Unclassified" },
};
const NM_ZONE_ORDER = ["servers", "ai", "k8s", "dmz", "vlan3", "vlan4", "vlan21", "other", "lan"];
// Display names where the DHCP export only has an OS hostname (from the home-network-devices inventory)
const NM_NAMES = new Proxy({}, { get: (_, ip) => (SITE.display_names || {})[ip] });  // display-name overrides from site.json
const NM = { color: "risk", inactive: true, q: "", sel: null };

function nmRiskColor(r) { return r >= 40 ? "#f85149" : r >= 20 ? "#d29922" : r >= 8 ? "#e3b341" : "#3fb950"; }

function nmHosts() {
  const raw = S.snap.raw, devs = raw.devices || {}, inv = raw.inventory_ips || {}, seen = S.reg.devices_seen || {};
  const names = S.reg.known_benign?.names || {}, cls = S.reg.policy?.device_classes || {};
  const risk = Object.fromEntries((S.risk?.hosts || []).filter((h) => h.ip).map((h) => [h.ip, h]));
  const iss = {}; for (const i of S.issues?.open || []) if (i.ip && !acked("issue", i)) iss[i.ip] = (iss[i.ip] || 0) + 1;
  const H = {};
  const add = (ip, o) => {
    if (!ip || ip.endsWith(".255") || ip.endsWith(".0")) return;
    const z = zoneOf(ip); if (!z || z === "internet") return;
    H[ip] = { ...(H[ip] || { ip, zone: z === "private" ? "other" : z, sources: [] }), ...Object.fromEntries(Object.entries(o).filter(([, v]) => v !== undefined && v !== "")) };
  };
  // registry first (oldest info), then inventory, then the live snapshot wins
  const macLatestIp = {};
  for (const [k, v] of entries(seen)) {
    const ip = (v.ips || []).slice(-1)[0]; if (!ip) continue;
    if (v.mac) macLatestIp[v.mac] = ip;
    add(ip, { name: v.name, mac: v.mac, vendor: v.oui !== "unknown" ? v.oui : "", hostname: v.hostname, known: v.known, first_seen: v.first_seen, last_seen: v.last_seen, days_seen: v.days_seen });
    H[ip] && H[ip].sources.push("baseline");
  }
  for (const [ip, nm] of entries(inv)) { add(ip, { inv_name: nm, known: true }); H[ip] && H[ip].sources.push("DHCP"); }
  for (const c of raw.unifi?.clients?.not_in_inventory || []) { add(c.ip, { name: c.name, mac: c.mac, vendor: c.vendor }); H[c.ip] && H[c.ip].sources.push("UniFi"); }
  for (const [ip, d] of entries(devs)) {
    add(ip, { live_name: d.name, mac: d.mac, vendor: d.oui !== "unknown" ? d.oui : "", hostname: d.hostname, known: !!d.known, active: true, total: d.total_bytes || 0, conns: (d.orig_conns || 0) + (d.resp_conns || 0) });
    H[ip] && H[ip].sources.push("traffic");
  }
  // drop stale IPs whose MAC has moved to another address
  for (const [ip, h] of entries(H)) if (h.mac && macLatestIp[h.mac] && macLatestIp[h.mac] !== ip && !h.active && H[macLatestIp[h.mac]]) delete H[ip];
  const out = [];
  for (const h of Object.values(H)) {
    const gw = h.ip.endsWith(".1");
    if (gw) continue; // gateway interfaces are drawn as zone uplinks
    h.name = NM_NAMES[h.ip] || h.live_name || names[h.ip] || h.inv_name || h.name || HOST_NAME_BY_IP()[h.ip] || h.ip;
    h.cls = cls[h.mac] || cls[h.ip] || "";
    h.risk = risk[h.ip]?.score || 0; h.rank = risk[h.ip]?.rank;
    h.issues = iss[h.ip] || 0;
    h.agent = (S.idx?.ipHosts?.[h.ip] || []).length > 0;
    h.honeypot = (SITE.honeypot_ips || []).includes(h.ip);
    out.push(h);
  }
  return out;
}

function nmZones(hosts) {
  const zcfg = S.reg.policy?.zones || {};
  const Z = {};
  for (const h of hosts) (Z[h.zone] = Z[h.zone] || []).push(h);
  // include configured zones even when empty so the topology is complete
  for (const z of Object.keys(zcfg)) Z[z] = Z[z] || [];
  const order = (z) => { const i = NM_ZONE_ORDER.indexOf(z); return i < 0 ? 50 : i; };
  return Object.keys(Z).sort((a, b) => order(a) - order(b) || a.localeCompare(b)).map((z) => {
    const hs = Z[z].sort((a, b) => (a.cls || "zz").localeCompare(b.cls || "zz") || String(a.name).localeCompare(String(b.name)));
    const cidr = zcfg[z] || "";
    const gw = cidr ? cidr.split("/")[0].replace(/\.0$/, ".1") : "";
    return { id: z, cidr, gw, gwName: S.reg.known_benign?.names?.[gw] || "", hosts: hs, active: hs.filter((h) => h.active).length,
      unknown: hs.filter((h) => !h.known).length, maxRisk: Math.max(0, ...hs.map((h) => h.risk)), issues: hs.reduce((s, h) => s + h.issues, 0) };
  });
}

function nmRender(box, zones) {
  box.innerHTML = "";
  const CW = 118, CH = 78, PAD = 16, HEAD = 46, MAXW = 1500, GAP = 34;
  const visible = (h) => NM.inactive || h.active;
  // size zones
  for (const z of zones) {
    const n = z.hosts.filter(visible).length;
    const maxCols = z.id === "lan" ? 11 : n > 12 ? 6 : 4;
    z.cols = Math.max(2, Math.min(maxCols, n || 1));
    z.rows = Math.max(1, Math.ceil(n / z.cols));
    z.w = z.cols * CW + PAD * 2; z.h = HEAD + z.rows * CH + PAD;
  }
  // pack zones into rows
  const rows = []; let cur = [], cw = 0;
  for (const z of zones) {
    if (cur.length && (cw + z.w + GAP > MAXW || z.id === "lan")) { rows.push(cur); cur = []; cw = 0; }
    cur.push(z); cw += z.w + GAP;
    if (z.id === "lan") { rows.push(cur); cur = []; cw = 0; }
  }
  if (cur.length) rows.push(cur);
  const W = Math.max(MAXW, ...rows.map((r) => r.reduce((s, z) => s + z.w + GAP, -GAP))) + 80;
  const TRUNK = 26, top0 = 210;
  let y = top0;
  for (const r of rows) {
    const rw = r.reduce((s, z) => s + z.w + GAP, -GAP); let x = 60 + (W - 60 - rw) / 2;
    const rh = Math.max(...r.map((z) => z.h));
    for (const z of r) { z.x = x; z.y = y; x += z.w + GAP; }
    r.bus = y - 34; r.h = rh; y += rh + 80;
  }
  const H = y;
  const svg = svgEl("svg", { viewBox: `0 0 ${W} ${H}`, width: "100%", style: "display:block;cursor:grab;max-height:none" });
  const root = svgEl("g"); svg.appendChild(root);
  const gL = svgEl("g"), gZ = svgEl("g"), gN = svgEl("g"); root.append(gL, gZ, gN);
  const txt = (p, s, a) => { const t = svgEl("text", a); t.textContent = s; p.appendChild(t); return t; };

  // internet + gateway
  const gx = W / 2, gy = 120;
  const cloud = svgEl("g", { transform: `translate(${gx},40)` });
  cloud.appendChild(svgEl("ellipse", { rx: 70, ry: 24, fill: "#21262d", stroke: "#8b949e", "stroke-dasharray": "4 3" }));
  txt(cloud, "Internet", { "text-anchor": "middle", dy: 5, fill: "#8b949e", "font-size": 14 });
  gN.appendChild(cloud);
  gL.appendChild(svgEl("line", { x1: gx, y1: 64, x2: gx, y2: gy - 26, stroke: "#8b949e", "stroke-width": 2, "stroke-dasharray": "4 3" }));
  const hl = S.snap.raw.unifi?.health || {};
  const gw = svgEl("g", { transform: `translate(${gx},${gy})`, style: "cursor:pointer" });
  gw.appendChild(svgEl("rect", { x: -110, y: -26, width: 220, height: 52, rx: 10, fill: "#30363d", stroke: "#58a6ff", "stroke-width": 2 }));
  txt(gw, "UniFi gateway / firewall", { "text-anchor": "middle", y: -4, fill: "#e6edf3", "font-size": 14, "font-weight": 700 });
  txt(gw, [hl.isp, hl.wan_ip].filter(Boolean).join(" · ") || "routes all zones", { "text-anchor": "middle", y: 14, fill: "#8b949e", "font-size": 11 });
  gw.onclick = (e) => { e.stopPropagation(); NM.sel = { gateway: true }; nmPanel(zones); };
  gN.appendChild(gw);

  // trunk + buses + uplinks
  const trunkX = 30;
  const lastBus = rows[rows.length - 1].bus;
  gL.appendChild(svgEl("path", { d: `M${gx},${gy + 26} V${rows[0].bus}`, stroke: "#58a6ff", "stroke-width": 2.5, fill: "none" }));
  if (rows.length > 1) gL.appendChild(svgEl("path", { d: `M${gx},${rows[0].bus} H${trunkX} V${lastBus}`, stroke: "#58a6ff", "stroke-width": 2.5, fill: "none" }));
  for (const r of rows) {
    const xs = r.map((z) => z.x + z.w / 2);
    const x1 = Math.min(...xs, rows.length > 1 ? trunkX : gx), x2 = Math.max(...xs, r === rows[0] ? gx : trunkX);
    gL.appendChild(svgEl("line", { x1, y1: r.bus, x2, y2: r.bus, stroke: "#58a6ff", "stroke-width": 2.5 }));
    for (const z of r) {
      const cx = z.x + z.w / 2, zc = LM_ZONE_COL[z.id] || "#8b949e";
      gL.appendChild(svgEl("line", { x1: cx, y1: r.bus, x2: cx, y2: z.y, stroke: zc, "stroke-width": 2 }));
      if (z.gw) txt(gL, z.gw, { x: cx + 5, y: r.bus + 17, fill: "#8b949e", "font-size": 10 });
    }
  }

  // zones + hosts
  const q = NM.q.toLowerCase();
  for (const z of zones) {
    const zc = LM_ZONE_COL[z.id] || "#8b949e";
    const g = svgEl("g", { transform: `translate(${z.x},${z.y})` });
    g.appendChild(svgEl("rect", { width: z.w, height: z.h, rx: 12, fill: zc, "fill-opacity": 0.06, stroke: zc, "stroke-opacity": 0.7, "stroke-width": 1.5 }));
    txt(g, z.id.toUpperCase(), { x: 14, y: 22, fill: zc, "font-size": 15, "font-weight": 700 });
    txt(g, `${z.cidr}  ·  ${z.hosts.length} hosts, ${z.active} active${z.unknown ? `, ${z.unknown} unknown` : ""}`, { x: 14, y: 37, fill: "#8b949e", "font-size": 11 });
    if (z.maxRisk >= 8) { const b = svgEl("g", { transform: `translate(${z.w - 16},20)` }); b.appendChild(svgEl("circle", { r: 11, fill: nmRiskColor(z.maxRisk) })); txt(b, Math.round(z.maxRisk), { "text-anchor": "middle", dy: 4, "font-size": 10, "font-weight": 700, fill: "#0d1117" }); const t = svgEl("title"); t.textContent = "highest host risk in zone"; b.appendChild(t); g.appendChild(b); }
    gZ.appendChild(g);
    const hs = z.hosts.filter(visible);
    if (!hs.length) txt(g, "no hosts seen", { x: z.w / 2, y: HEAD + 30, "text-anchor": "middle", fill: "#6e7681", "font-size": 12, "font-style": "italic" });
    hs.forEach((h, i) => {
      const cx = z.x + PAD + (i % z.cols) * CW + CW / 2, cy = z.y + HEAD + Math.floor(i / z.cols) * CH + 22;
      const cl = NM_CLASS[h.cls] || NM_CLASS[""];
      const fill = NM.color === "risk" ? nmRiskColor(h.risk) : NM.color === "class" ? cl.c : h.active ? "#3fb950" : "#6e7681";
      const r = 13 + (NM.color === "risk" ? Math.min(7, Math.sqrt(h.risk)) : 0);
      const hit = !q || [h.name, h.ip, h.mac, h.vendor, h.hostname, h.cls].some((v) => String(v || "").toLowerCase().includes(q));
      const n = svgEl("g", { transform: `translate(${cx},${cy})`, style: `cursor:pointer;opacity:${hit ? 1 : 0.15}` });
      n.appendChild(svgEl("circle", { r, fill: h.active ? fill : "#161b22", "fill-opacity": h.active ? 0.9 : 1, stroke: h.active ? (NM.sel?.host?.ip === h.ip ? "#fff" : zc) : fill, "stroke-width": NM.sel?.host?.ip === h.ip ? 3 : 1.5, "stroke-dasharray": h.active ? "none" : "3 2" }));
      txt(n, cl.g, { "text-anchor": "middle", dy: 4, "font-size": 12, "font-weight": 700, fill: h.active ? "#0d1117" : fill });
      if (!h.known) n.appendChild(svgEl("circle", { r: r + 4, fill: "none", stroke: "#d29922", "stroke-width": 1, "stroke-dasharray": "2 2" }));
      if (h.agent) { n.appendChild(svgEl("circle", { cx: -r + 2, cy: -r + 2, r: 5, fill: "#3fb950", stroke: "#0d1117", "stroke-width": 1.5 })); }
      if (h.issues) { const b = svgEl("g", { transform: `translate(${r - 1},${-r + 1})` }); b.appendChild(svgEl("circle", { r: 7, fill: "#f85149", stroke: "#0d1117", "stroke-width": 1.5 })); txt(b, h.issues, { "text-anchor": "middle", dy: 3, "font-size": 9, "font-weight": 700, fill: "#fff" }); n.appendChild(b); }
      const nm = String(h.name); txt(n, nm.length > 17 ? nm.slice(0, 16) + "…" : nm, { "text-anchor": "middle", y: r + 14, "font-size": 11, fill: h.active ? "#c9d1d9" : "#8b949e" });
      txt(n, h.ip, { "text-anchor": "middle", y: r + 26, "font-size": 9, fill: "#6e7681" });
      const t = svgEl("title"); t.textContent = `${h.name}\n${h.ip}${h.mac ? " · " + h.mac : ""}\n${cl.l}${h.vendor ? " · " + h.vendor : ""}\n${h.active ? "active in this snapshot" : "not seen in this snapshot"}\nrisk ${h.risk}${h.issues ? ` · ${h.issues} open issues` : ""}`; n.appendChild(t);
      n.onclick = (e) => { e.stopPropagation(); NM.sel = { host: h }; nmPanel(zones); nmRender(box, zones); };
      n.ondblclick = () => S.snap.raw.devices?.[h.ip] && go("device/" + h.ip);
      gN.appendChild(n);
    });
  }
  // pan & zoom (keeps state across re-renders)
  NM.view = NM.view || { x: 0, y: 0, k: 1 }; const view = NM.view; let pan = null;
  const apply = () => root.setAttribute("transform", `translate(${view.x},${view.y}) scale(${view.k})`); apply();
  svg.addEventListener("wheel", (ev) => { ev.preventDefault(); const pt = svg.createSVGPoint(); pt.x = ev.clientX; pt.y = ev.clientY; const p = pt.matrixTransform(svg.getScreenCTM().inverse());
    const k2 = Math.min(5, Math.max(0.5, view.k * (ev.deltaY < 0 ? 1.12 : 1 / 1.12))); view.x = p.x - ((p.x - view.x) * k2) / view.k; view.y = p.y - ((p.y - view.y) * k2) / view.k; view.k = k2; apply(); }, { passive: false });
  svg.addEventListener("pointerdown", (ev) => { pan = { x: ev.clientX, y: ev.clientY }; svg.style.cursor = "grabbing"; });
  svg.addEventListener("pointermove", (ev) => { if (!pan) return; const ctm = svg.getScreenCTM(); view.x += (ev.clientX - pan.x) / ctm.a; view.y += (ev.clientY - pan.y) / ctm.d; pan = { x: ev.clientX, y: ev.clientY }; apply(); });
  svg.addEventListener("pointerup", () => { pan = null; svg.style.cursor = "grab"; });
  svg.addEventListener("click", () => { if (NM.sel) { NM.sel = null; nmPanel(zones); nmRender(box, zones); } });
  box.appendChild(svg);
}

function nmPanel(zones) {
  const el = document.getElementById("nmPanel"); if (!el) return;
  const s = NM.sel;
  if (!s) {
    el.innerHTML = `<h2>Details</h2><div class="muted small">Click a host or the gateway. Double-click a host to open its device page. Scroll to zoom, drag to pan.</div>
      <h3>Legend</h3><div class="small">
      <div class="chips" style="margin-bottom:6px">${Object.entries(NM_CLASS).map(([k, v]) => `<span class="chip"><b style="color:${v.c}">${v.g}</b> ${v.l}</span>`).join("")}</div>
      <div>Fill colour: ${NM.color === "risk" ? "host risk (green → red), bigger = riskier" : NM.color === "class" ? "device class" : "green = active, grey = not seen"}</div>
      <div>Dashed hollow bubble = known but not seen in this snapshot</div><div>Dashed amber ring = not in DHCP inventory</div>
      <div><span style="color:#3fb950">●</span> top-left dot = Elastic agent installed</div><div><span style="color:#f85149">●</span> top-right number = open fix-list issues</div>
      <div>Zone badge = highest host risk in that zone</div></div>`;
    return;
  }
  if (s.gateway) {
    el.innerHTML = `<h2>UniFi gateway</h2>${unifiHealthHtml()}<h3>Zone interfaces</h3>` +
      zones.map((z) => `<div class="small"><b style="color:${LM_ZONE_COL[z.id] || "#8b949e"}">${esc(z.id)}</b> ${esc(z.gw)} <span class="muted">${esc(z.cidr)}</span></div>`).join("");
    return;
  }
  const h = s.host, cl = NM_CLASS[h.cls] || NM_CLASS[""];
  const hasDev = !!S.snap.raw.devices?.[h.ip];
  const iss = (S.issues?.open || []).filter((i) => i.ip === h.ip && !acked("issue", i));
  el.innerHTML = `<h2>${esc(h.name)}</h2><div class="idgrid">
    <span class="k">IP</span><span class="mono">${esc(h.ip)}</span><span class="k">MAC</span><span class="mono">${esc(h.mac || "—")}</span>
    <span class="k">Vendor</span><span>${esc(h.vendor || "—")}</span><span class="k">Hostname</span><span>${esc(h.hostname || "—")}</span>
    <span class="k">Zone / class</span><span>${esc(h.zone)} / ${esc(cl.l)}</span><span class="k">Status</span><span>${h.active ? badge("active") : '<span class="badge sev-unknown">not seen this snapshot</span>'}</span>
    <span class="k">In inventory</span><span>${h.known ? "yes" : '<span class="badge sev-medium">no</span>'}</span><span class="k">Elastic agent</span><span>${h.agent ? (S.idx.ipHosts[h.ip] || []).map(hostLink).join(", ") : "—"}</span>
    <span class="k">First / last seen</span><span>${ft(h.first_seen) || "—"} / ${ft(h.last_seen) || "—"}</span><span class="k">Sources</span><span>${esc([...new Set(h.sources)].join(", "))}</span>
    ${h.active ? `<span class="k">Traffic</span><span>${fb(h.total)} · ${fn(h.conns)} conns</span>` : ""}
    <span class="k">Risk</span><span>${riskBadge(h.risk)}${h.rank ? ` rank ${h.rank}` : ""}</span></div>
    ${iss.length ? `<h3>Open issues (${iss.length})</h3>` + iss.slice(0, 6).map((i) => `<div class="small">${badge(i.severity)} ${esc(i.title)}</div>`).join("") : ""}
    <div style="margin-top:10px;display:flex;gap:6px;flex-wrap:wrap">${hasDev ? `<a href="#/device/${h.ip}"><button>Device page →</button></a><a href="#/lateral/${h.ip}"><button>Lateral graph →</button></a>` : ""}</div>`;
}

V.netmap = (el) => {
  const hosts = nmHosts(), zones = nmZones(hosts);
  el.innerHTML = `<h1>Network map</h1><div class="sub">Every internal host we know about (live traffic, DHCP inventory, baseline registry and UniFi), placed in its zone behind the UniFi gateway. Internet hosts are not mapped.</div>`;
  el.insertAdjacentHTML("beforeend", kpis([["Zones", zones.length], ["Hosts", hosts.length], ["Active this snapshot", hosts.filter((h) => h.active).length, "good"],
    ["Not seen", hosts.filter((h) => !h.active).length], ["Not in inventory", hosts.filter((h) => !h.known).length, hosts.some((h) => !h.known) ? "warn" : "good"], ["With Elastic agent", hosts.filter((h) => h.agent).length]]));
  const ctr = document.createElement("div"); ctr.className = "tbltools";
  ctr.innerHTML = `<label class="muted">Colour by</label><select id="nmColor">${[["risk", "Risk"], ["class", "Device class"], ["activity", "Activity"]].map(([k, l]) => `<option value="${k}" ${NM.color === k ? "selected" : ""}>${l}</option>`).join("")}</select>
    <label><input type="checkbox" id="nmInactive" ${NM.inactive ? "checked" : ""}> show hosts not seen this snapshot</label>
    <input id="nmQ" type="search" placeholder="Find host (name, IP, MAC, vendor)…" value="${esc(NM.q)}"><button id="nmReset">Reset view</button>`;
  el.appendChild(ctr);
  const wrap = document.createElement("div"); wrap.style.cssText = "display:grid;grid-template-columns:minmax(0,1fr) 340px;gap:14px;align-items:start";
  const gcard = card("", "<div id='nmGraph'></div>"); gcard.style.padding = "6px";
  const pcard = card("", "<div id='nmPanel'></div>"); pcard.style.cssText = "position:sticky;top:64px;max-height:calc(100vh - 80px);overflow:auto";
  wrap.append(gcard, pcard); el.appendChild(wrap);
  const box = document.getElementById("nmGraph");
  const draw = () => { nmRender(box, zones); nmPanel(zones); };
  document.getElementById("nmColor").onchange = (e) => { NM.color = e.target.value; draw(); };
  document.getElementById("nmInactive").onchange = (e) => { NM.inactive = e.target.checked; draw(); };
  document.getElementById("nmQ").oninput = (e) => { NM.q = e.target.value; nmRender(box, zones); };
  document.getElementById("nmReset").onclick = () => { NM.view = null; NM.q = ""; document.getElementById("nmQ").value = ""; draw(); };
  draw();
  // zone summary + full host list
  el.appendChild(card("Zones", table(null, [
    { k: "id", t: "Zone", fmt: (v) => `<b style="color:${LM_ZONE_COL[v] || "#8b949e"}">${esc(v)}</b>` }, { k: "cidr", t: "Subnet", cls: "mono" }, { k: "gw", t: "Gateway", cls: "mono" },
    { k: "n", t: "Hosts", num: true }, { k: "active", t: "Active", num: true }, { k: "unknown", t: "Unknown", num: true }, { k: "issues", t: "Open issues", num: true },
    { k: "maxRisk", t: "Max risk", num: true, fmt: (v) => (v ? riskBadge(v) : "") }, { k: "top", t: "Riskiest host", fmt: (v, z) => (v ? ipLink(v.ip) : "") , sort: (z) => z.maxRisk },
  ], zones.map((z) => ({ ...z, n: z.hosts.length, top: [...z.hosts].sort((a, b) => b.risk - a.risk)[0] })), { search: false, sort: "maxRisk" })));
  el.appendChild(card(`All hosts (${hosts.length})`, table(null, [
    { k: "zone", t: "Zone" }, { k: "name", t: "Host", fmt: (v, h) => (S.snap.raw.devices?.[h.ip] ? `<a href="#/device/${h.ip}">${esc(v)}</a>` : esc(v)) }, { k: "ip", t: "IP", cls: "mono", sort: (h) => ip2n(h.ip) },
    { k: "mac", t: "MAC", cls: "mono" }, { k: "vendor", t: "Vendor", cls: "small" }, { k: "cls", t: "Class" }, { k: "active", t: "Active", fmt: (v) => (v ? "✓" : ""), sort: (h) => (h.active ? 1 : 0) },
    { k: "known", t: "Inventory", fmt: (v) => (v ? "✓" : '<span class="badge sev-medium">no</span>'), sort: (h) => (h.known ? 1 : 0) }, { k: "agent", t: "Agent", fmt: (v) => (v ? "✓" : ""), sort: (h) => (h.agent ? 1 : 0) },
    { k: "risk", t: "Risk", num: true, fmt: (v) => (v ? riskBadge(v) : "") }, { k: "issues", t: "Issues", num: true }, { k: "last_seen", t: "Last seen", fmt: ft },
  ], hosts, { sort: "risk", onclick: (h) => { NM.sel = { host: h }; draw(); window.scrollTo({ top: 0, behavior: "smooth" }); } })));
};
