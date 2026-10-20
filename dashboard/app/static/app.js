/* netmon dashboard SPA — vanilla JS + Chart.js */
"use strict";

// Endpoint (Elastic agent) hostname -> IP hints, from the server's site config (/api/site; never hard-coded here).
const HOST_IP_HINTS = {};
const SITE = { site_name: "", internal_prefixes: [], display_names: {}, honeypot_ips: [] };
const isInternal = (ip) => SITE.internal_prefixes.some((p) => String(ip).startsWith(p));

const S = { snaps: [], snap: null, hist: [], reg: {}, charts: [], idx: null, acks: {}, showAcked: {}, me: { role: "user" } };
// roles (docs/ACCESS_CONTROL.md): the server enforces them; the UI only hides what a role can't use
const isAdmin = () => S.me.role === "admin", isUserRole = () => S.me.role === "user";
const USER_VIEWS = new Set(["alerts", "my", "account"]);
const $ = (s, r = document) => r.querySelector(s);
const PALETTE = ["#58a6ff", "#3fb950", "#d29922", "#f85149", "#bc8cff", "#39c5cf", "#ff9bce", "#e3b341",
  "#7ee787", "#a5d6ff", "#ffa657", "#d2a8ff", "#56d4dd", "#ff7b72", "#8b949e"];

/* ---------- formatting ---------- */
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
function fb(n) {
  n = +n || 0; const u = ["B", "KB", "MB", "GB", "TB"]; let i = 0;
  while (Math.abs(n) >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return (i ? n.toFixed(n < 10 ? 2 : n < 100 ? 1 : 0) : n.toFixed(0)) + " " + u[i];
}
const fn = (n) => (n == null || n === "" ? "" : (+n).toLocaleString());
const ft = (t) => { if (!t) return ""; const d = new Date(t); return isNaN(d) ? esc(t) : d.toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }); };
const sevCls = (s) => "sev-" + String(s ?? "unknown").toLowerCase().replace(/[^a-z]/g, "");
const badge = (s) => `<span class="badge ${sevCls(s)}">${esc(s ?? "—")}</span>`;
const sevRank = (s) => ({ critical: 0, very_high: 0, investigate: 0, high: 1, review: 2, medium: 2, low: 3, info: 4, fyi: 4 }[String(s).toLowerCase()] ?? 5);
const entries = (o) => Object.entries(o || {});
const sortDesc = (o) => entries(o).sort((a, b) => (typeof b[1] === "object" ? (b[1].bytes ?? b[1].conns ?? 0) - (a[1].bytes ?? a[1].conns ?? 0) : b[1] - a[1]));

/* ---------- networking ---------- */
function toLogin() { sessionStorage.setItem("netmon_next", location.hash || ""); location.href = "/login"; }
async function api(p) { const r = await fetch(p, { cache: "no-store" }); if (r.status === 401) { toLogin(); throw new Error("login required"); } if (!r.ok) throw new Error(p + " → " + r.status); return r.json(); }
async function apiPost(p, body) {
  const r = await fetch(p, { method: "POST", headers: { "Content-Type": "application/json", "X-Netmon": "1" }, body: JSON.stringify(body) });
  if (r.status === 401 && p !== "/api/users") { toLogin(); throw new Error("login required"); }
  const j = await r.json().catch(() => ({})); if (!r.ok) throw new Error(j.error || r.status); return j;
}

/* ---------- zones / policy ---------- */
function ip2n(ip) { const p = String(ip).split(".").map(Number); return p.length === 4 && p.every((x) => x >= 0 && x < 256) ? ((p[0] << 24) >>> 0) + (p[1] << 16) + (p[2] << 8) + p[3] : null; }
function zoneOf(ip) {
  const n = ip2n(ip); if (n == null) return "";
  for (const [z, cidr] of entries(S.reg.policy?.zones)) {
    const [base, bits] = cidr.split("/"); const b = ip2n(base); const m = bits == 0 ? 0 : (~0 << (32 - bits)) >>> 0;
    if (b != null && ((n & m) >>> 0) === ((b & m) >>> 0)) return z;
  }
  const p = String(ip).split(".").map(Number);
  if (p[0] === 10 || (p[0] === 172 && p[1] >= 16 && p[1] < 32) || (p[0] === 192 && p[1] === 168)) return "private";
  return "internet";
}

/* ---------- index the snapshot for drill-downs ---------- */
function buildIndex() {
  const b = S.snap, raw = b.raw || {}, an = b.analysis || {}, tr = b.triage || {};
  const devs = raw.devices || {};
  const seen = S.reg.devices_seen || {};
  const seenByIp = {};
  for (const [k, v] of entries(seen)) for (const ip of v.ips || []) seenByIp[ip] = { key: k, ...v };
  const nameOf = (ip) => devs[ip]?.name || raw.inventory_ips?.[ip] || seenByIp[ip]?.name || HOST_NAME_BY_IP()[ip] || (devs[ip] && /\.1$/.test(ip) ? `gateway (${zoneOf(ip)})` : "");
  // endpoint host <-> ip
  const fleet = raw.hosts?.fleet || [];
  const hostNames = new Set([...fleet.map((f) => f.host), ...Object.keys(raw.hosts?.telemetry || {}), ...Object.keys(raw.hosts?.syslog || {}), ...Object.keys(raw.hosts?.network?.hosts || {})]);
  const hostIp = {}, ipHosts = {};
  for (const h of hostNames) {
    let ip = HOST_IP_HINTS[h.toLowerCase()];
    if (!ip) {
      const short = h.toLowerCase().split(".")[0];
      for (const [dip, d] of entries(devs)) {
        const nm = String(d.name || "").toLowerCase().split(/[ .]/)[0], hn = String(d.hostname || "").toLowerCase().split(".")[0];
        if (short && short.length > 3 && (nm === short || hn === short)) { ip = dip; break; }
      }
    }
    if (ip) { hostIp[h] = ip; (ipHosts[ip] = ipHosts[ip] || []).push(h); }
  }
  // per-device rows
  const findings = an.findings || [];
  const rows = entries(devs).map(([ip, d]) => {
    const f = findings.filter((x) => x.device === ip);
    const worst = f.length ? f.map((x) => x.severity).sort((a, c) => sevRank(a) - sevRank(c))[0] : "";
    return {
      ip, name: d.name || seenByIp[ip]?.name || HOST_NAME_BY_IP()[ip] || (/\.1$/.test(ip) ? `gateway (${zoneOf(ip)})` : ""), mac: d.mac || seenByIp[ip]?.mac || "", oui: d.oui || "", hostname: d.hostname || "",
      known: !!d.known, zone: zoneOf(ip), cls: deviceClass(ip, d.mac), total: d.total_bytes || 0, sent: d.total_sent || 0, recv: d.total_recv || 0,
      conns: (d.orig_conns || 0) + (d.resp_conns || 0), ext_peers: d.ext_peers || 0, ext_out: d.ext_out_bytes || 0, peers: d.peers || 0,
      rejected: d.rejected_conns || 0, dnsq: d.dns?.queries || 0, nx: d.dns?.nxdomain || 0, findings: f.length, worst,
      note: tr.device_notes?.[ip] || "", hosts: ipHosts[ip] || [], first: seenByIp[ip]?.first_seen || d.zeek_first_seen || "",
    };
  });
  S.idx = { rows, byIp: Object.fromEntries(rows.map((r) => [r.ip, r])), nameOf, hostIp, ipHosts, seenByIp };
}
let _hnbi = null;
function HOST_NAME_BY_IP() { if (!_hnbi) { _hnbi = {}; for (const [h, ip] of entries(HOST_IP_HINTS)) if (!_hnbi[ip]) _hnbi[ip] = h; } return _hnbi; }
function deviceClass(ip, mac) { const dc = S.reg.policy?.device_classes || {}; return dc[mac] || dc[ip] || dc[String(mac || "").toLowerCase()] || ""; }

/* ---------- link helpers ---------- */
function ipLink(ip, withName = true) {
  if (!ip) return "";
  const z = zoneOf(ip), internal = z && z !== "internet";
  const nm = withName ? S.idx?.nameOf(ip) : "";
  const label = nm ? `${esc(nm)} <span class="muted small">${esc(ip)}</span>` : esc(ip);
  return internal && S.snap?.raw?.devices?.[ip] ? `<a href="#/device/${encodeURIComponent(ip)}">${label}</a>` : label;
}
const hostLink = (h) => `<a href="#/endpoint/${encodeURIComponent(h)}">${esc(h)}</a>`;
const DOM_RE = /\b((?:[a-z0-9-]+\.)+(?:com|net|org|io|ru|cn|xyz|top|info|biz|us|co|me|app|dev|cloud|online|site))\b/gi;
const isInternalDom = (d) => /\.(lan|local|hades)$/i.test(d);
const extNoteBtn = (kind, v) => `<button type="button" class="extnote-btn" data-ext${kind}="${esc(v)}" title="Your notes on ${kind === "ip" ? "external IP" : "domain"} ${esc(v)}">📝</button>`;
const domFmt = (d) => `${esc(d)}${!isUserRole() && !isInternalDom(String(d)) ? " " + extNoteBtn("dom", String(d).toLowerCase()) : ""}`;
function linkifyIps(text) {
  const seenIp = new Set(), seenDom = new Set(), U = isUserRole();
  let html = esc(text).replace(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g, (m) => {
    if (isInternal(m)) return S.snap?.raw?.devices?.[m] ? `<a href="#/device/${m}">${m}</a>` : m;
    if (U || seenIp.has(m)) return m;
    seenIp.add(m);
    return `${m} ${extNoteBtn("ip", m)}`;
  });
  if (!U) html = html.replace(DOM_RE, (m) => {
    const d = m.toLowerCase();
    if (isInternalDom(d) || seenDom.has(d)) return m;
    seenDom.add(d);
    return `${m} ${extNoteBtn("dom", d)}`;
  });
  return html;
}

/* ---------- chart drill-down: charts link to lists filtered via hash query params ---------- */
const hq = () => new URLSearchParams(location.hash.split("?")[1] || "");
const eqi = (a, b) => String(a ?? "").toLowerCase() === String(b ?? "").toLowerCase();
function hashWith(view, params) { const p = new URLSearchParams(); entries(params).forEach(([k, v]) => v != null && v !== "" && p.set(k, v)); const s = p.toString(); return "#/" + view + (s ? "?" + s : ""); }
function hashWithout(keys) { const p = hq(); [].concat(keys).forEach((k) => p.delete(k)); const s = p.toString(); return location.hash.split("?")[0] + (s ? "?" + s : ""); }
function drill(view, params) { location.hash = hashWith(view, params); }
// same view, merge params into the current query (keeps e.g. ?host=)
function drillHere(params) { const p = hq(); entries(params).forEach(([k, v]) => p.set(k, v)); location.hash = location.hash.split("?")[0] + "?" + p.toString(); }
const clickable = (fn) => ({ onClick: (e, els) => els.length && fn(els[0].index, els[0].datasetIndex), onHover: (e, els) => (e.native.target.style.cursor = els.length ? "pointer" : "default") });

/* ---------- AI provenance flare: every piece of LLM-written text says which model wrote it ---------- */
// g = {model, via, at}. Unknown provenance still gets a flare ("AI") so LLM text is never mistaken for raw data.
function aiFlare(g, fallbackVia = "") {
  if (!g) return "";
  const m = String(g.model || "").trim(), via = g.via || fallbackVia, at = g.at ? " · " + ft(g.at) : "";
  const short = !m || m === "unknown" ? "AI" : m.replace(/^.*\//, "").replace(/-(qat|gguf|instruct)$/i, "");
  return `<span class="ai-flare" title="${esc(`AI-generated${m && m !== "unknown" ? " by " + m : " (model not recorded)"}${via ? " · " + via : ""}${at}. Verify before acting.`)}">✨ ${esc(short)}</span>`;
}
const trFlare = () => (S.snap?.triage ? aiFlare(S.snap.triage.generated_by || {}, "AI triage") : "");

/* ---------- correlation (related.js fills the cells once /api/correlate is loaded) ---------- */
const relCol = (idFn) => ({ k: "_rel", t: "Related", sort: (x) => (S.corr?.related?.[idFn(x)] || []).length,
  fmt: (v, x) => { const i = idFn(x); return i ? `<button type="button" class="rel-btn" data-rel="${esc(i)}" title="Related events">${S.corr ? (S.corr.related?.[i] || []).length || "–" : "…"}</button>` : ""; } });
const evLabel = (id) => { const e = S.corr?.events?.[id]; const l = e ? e.label : String(id).split("|").slice(1).join(" "); return l.length > 70 ? l.slice(0, 68) + "…" : l; };

/* ---------- table component ---------- */
// cols: [{k, t, num, fmt(v,row)->html, sort(row)->val, cls}]
// opts.urlFilter: {param: [label, (row, value) => bool]} — hash query params filter the rows (chart drill-down) and show removable chips
// opts.evId(row) -> correlation event id ("f|...", "ids|...", "adm|...", "iss|...", "alert|...", "hf|...", "ti|...").
// Adds a "Related" column (filled by related.js) and the ?ev=<id> drill-down filter for rows of that type.
function table(id, cols, rows, opts = {}) {
  const st = { key: opts.sort ?? null, dir: opts.dir ?? -1, q: "" };
  const wrap = document.createElement("div");
  if (opts.evId) {
    cols = [...cols, relCol(opts.evId)];
    const evv = hq().get("ev") || "", pre = (opts.evId(rows[0] || {}) || "").split("|")[0];
    if (evv && rows.length && evv.split("|")[0] === pre && !(evv.startsWith("ti|") && evv.split("|")[1] !== (opts.evId(rows[0]) || "").split("|")[1]))
      opts = { ...opts, urlFilter: { ...(opts.urlFilter || {}), ev: ["Event", (x, v) => opts.evId(x) === v] } };
  }
  const P = hq(), act = entries(opts.urlFilter || {}).filter(([p]) => P.has(p)); let chipHtml = "";
  if (act.length) {
    const before = rows;
    rows = rows.filter((x) => act.every(([p, [, f]]) => f(x, P.get(p))));
    if (!rows.length && act.length === 1 && act[0][0] === "ev") {  // the event lives in another list on this page
      wrap.innerHTML = `<div class="muted small">The selected event is in another list on this page. <a href="${esc(hashWithout("ev"))}">Show this list</a></div>`;
      return wrap;
    }
    void before;
    chipHtml = `<div class="fchips">Filtered: ${act.map(([p, [l]]) => `<span class="chip">${esc(l)}: <b${p === "ev" ? ` data-ev="${esc(P.get(p))}"` : ""}>${esc(p === "ev" ? evLabel(P.get(p)) : P.get(p))}</b> <a href="${esc(hashWithout(p))}" title="Remove filter">✕</a></span>`).join(" ")}${act.length > 1 ? ` <a href="${esc(hashWithout(act.map(([p]) => p)))}" class="small">clear all</a>` : ""}</div>`;
    if (!S._noScroll && !S._scrolled) { S._scrolled = true; setTimeout(() => (wrap.closest(".card") || wrap).scrollIntoView({ block: "start" }), 0); }
  }
  // mobile list layout (see listMode below): which column is the row title, which are badges / action buttons
  const lc = {}, TITLE = ["name", "label", "title", "text", "detail", "signature", "sig", "a_label", "device", "host", "hostname", "domain", "ip", "src", "key", "k"],
    BADGE = ["severity", "priority", "status", "level", "related", "verdict", "result", "state", "sev"];
  const labelled = cols.filter((c) => c.t && !c.k.startsWith("_"));
  const tcol = opts.titleKey ? cols.find((c) => c.k === opts.titleKey) : (TITLE.map((k) => labelled.find((c) => c.k === k && !c.num)).find(Boolean) || labelled.find((c) => !c.num && !BADGE.includes(c.k)));
  cols.forEach((c) => { lc[c.k] = c === tcol ? "lc-title" : !c.t || c.k === "_rel" || c.k === "_ack" ? "lc-act" : BADGE.includes(c.k) ? "lc-badge" : ""; });
  // search text per row: raw values (object keys for maps such as sources/destinations) plus the visible text of formatted cells
  const hayC = new Map(), txt = document.createElement("template");
  const hay = (x) => { let h = hayC.get(x); if (h != null) return h;
    h = cols.filter((c) => c.k !== "_rel" && c.k !== "_ack").map((c) => { const v = c.sort ? c.sort(x) : x[c.k]; let o = v != null && typeof v === "object" ? Object.keys(v).join(" ") : String(v ?? "");
      if (c.fmt) { try { txt.innerHTML = String(c.fmt(x[c.k], x) ?? ""); o += " " + txt.content.textContent; } catch (e) { /* ignore */ } } return o; }).join(" \n").toLowerCase();
    hayC.set(x, h); return h; };
  const render = () => {
    let r = rows;
    if (st.q) { const qs = st.q.toLowerCase().split(/\s+/).filter(Boolean); r = r.filter((x) => { const h = hay(x); return qs.every((q) => h.includes(q)); }); }
    if (st.key != null) {
      const c = cols.find((c) => c.k === st.key); const g = c?.sort || ((x) => x[st.key]);
      r = [...r].sort((a, b) => { const A = g(a), B = g(b); return (typeof A === "number" && typeof B === "number" ? A - B : String(A ?? "").localeCompare(String(B ?? ""))) * st.dir; });
    }
    const lim = opts.limit && !st.q ? r.slice(0, st.showAll ? undefined : opts.limit) : r;
    const max = {}; cols.filter((c) => c.bar).forEach((c) => (max[c.k] = Math.max(1, ...r.map((x) => +x[c.k] || 0))));
    wrap.querySelector("tbody").innerHTML = lim.length ? lim.map((x) => `<tr class="${opts.onclick ? "click" : ""} ${opts.rowClass ? opts.rowClass(x) : ""}" data-i="${rows.indexOf(x)}">` + cols.map((c) => {
      const v = x[c.k]; let h = c.fmt ? c.fmt(v, x) : esc(v);
      if (c.bar) h = `<div style="display:flex;gap:8px;align-items:center;justify-content:flex-end"><span>${h}</span><div class="bar" style="width:70px"><span style="width:${(100 * (+v || 0)) / max[c.k]}%"></span></div></div>`;
      return `<td class="${c.num ? "num" : ""} ${c.cls || ""} ${lc[c.k] || ""}"${c.t ? ` data-l="${esc(c.t)}"` : ""}>${h}</td>`;
    }).join("") + "</tr>").join("") : `<tr><td colspan="${cols.length}" class="empty">No data</td></tr>`;
    const more = wrap.querySelector(".more");
    if (more) more.innerHTML = opts.limit && r.length > opts.limit && !st.q ? `<button>${st.showAll ? "Show top " + opts.limit : "Show all " + r.length}</button>` : `<span class="muted small">${r.length} rows</span>`;
    wrap.querySelectorAll("th").forEach((th) => { th.classList.remove("sorted-asc", "sorted-desc"); if (th.dataset.k === String(st.key)) th.classList.add(st.dir > 0 ? "sorted-asc" : "sorted-desc"); });
  };
  wrap.innerHTML = chipHtml + (opts.search !== false && (opts.filter || rows.length > 8) ? `<div class="tbltools"><input placeholder="Filter…" type="search" aria-label="Filter list"><span class="more"></span></div>` : `<div class="tbltools" style="margin:0"><span class="more"></span></div>`) +
    `<div class="tblwrap ${opts.short ? "short" : ""}"><table><thead><tr>${cols.map((c) => `<th data-k="${esc(c.k)}" class="${c.num ? "num" : ""}">${esc(c.t)}</th>`).join("")}</tr></thead><tbody></tbody></table></div>`;
  wrap.querySelector("thead").onclick = (e) => { const k = e.target.closest("th")?.dataset.k; if (!k) return; st.dir = st.key === k ? -st.dir : (cols.find((c) => c.k === k)?.num ? -1 : 1); st.key = k; render(); };
  const inp = wrap.querySelector("input"); if (inp) inp.oninput = () => { st.q = inp.value; render(); };
  wrap.addEventListener("click", (e) => { if (e.target.closest(".more button")) { st.showAll = !st.showAll; render(); return; }
    if (opts.onclick && !e.target.closest("a, input, button, summary")) { const tr = e.target.closest("tr[data-i]"); if (tr) opts.onclick(rows[+tr.dataset.i]); } });
  render();
  listMode(wrap, cols, st, render);
  return wrap;
}
// Phones: a table that would need a lot of sideways scrolling becomes a list of cards (like the triage alarms):
// title line, badges + action buttons, then "Label: value" lines. Decided per table from its real width, re-checked
// on resize/rotation; a "Sort" picker replaces the hidden column headers.
const LIST_MQ = window.matchMedia("(max-width: 900px)");
function listMode(wrap, cols, st, render) {
  if (wrap.dataset.lm) return; wrap.dataset.lm = "1";
  const tw = () => wrap.querySelector(".tblwrap"), tbl = () => wrap.querySelector("table");
  let lastW = 0, sortSel = null;
  const sortable = cols.filter((c) => c.t && !c.k.startsWith("_"));
  const decide = () => {
    const w = wrap.clientWidth; if (!w || !tw()) return;
    if (w === lastW) return; lastW = w;
    const t = tw();
    t.classList.remove("as-list");
    const wide = LIST_MQ.matches && tbl().scrollWidth > t.clientWidth + 40;
    t.classList.toggle("as-list", wide);
    if (wide && !sortSel && sortable.length > 1) {
      sortSel = document.createElement("select"); sortSel.className = "lm-sort"; sortSel.setAttribute("aria-label", "Sort list");
      [...sortable.map((c) => [c.k, "Sort: " + c.t]), ["__dir", "⇅ Reverse order"]].forEach(([v, t]) => sortSel.add(new Option(t, v)));
      sortSel.onchange = () => { if (sortSel.value === "__dir") st.dir = -st.dir; else { st.dir = st.key === sortSel.value ? st.dir : (cols.find((c) => c.k === sortSel.value)?.num ? -1 : 1); st.key = sortSel.value; }
        sortSel.value = st.key ?? sortable[0].k; render(); };
      (wrap.querySelector(".tbltools") || wrap).prepend(sortSel);
    }
    if (sortSel) { sortSel.hidden = !wide; if (st.key != null) sortSel.value = st.key; }
  };
  new ResizeObserver(decide).observe(wrap);
  LIST_MQ.addEventListener("change", () => { lastW = 0; decide(); });
}
// object {k: number | {conns,bytes,..}} -> table
function kvTable(obj, keyTitle, valTitle, valFmt = fn, keyFmt = esc, opts = {}) {
  const rows = entries(obj).map(([k, v]) => ({ k, v: typeof v === "object" && v ? (v.bytes ?? v.conns ?? 0) : v }));
  return table(null, [{ k: "k", t: keyTitle, fmt: (v) => keyFmt(v) }, { k: "v", t: valTitle, num: true, bar: true, fmt: valFmt }], rows, { sort: "v", search: rows.length > 12, short: true, ...opts });
}

/* ---------- layout helpers ---------- */
// A string body becomes one wrapper <div> (not loose top-level nodes): .cc-body (cards.js) is a flex column, so any
// stray top-level text/button sitting directly in a card - e.g. an inline note icon 📝 next to an IP in prose - would
// become its own flex item and get stretched to the full card width (align-items:stretch) instead of flowing inline.
function card(title, body, cls = "") { const c = document.createElement("div"); c.className = "card " + cls; c.innerHTML = title ? `<h2>${title}</h2>` : "";
  if (typeof body === "string") { const w = document.createElement("div"); w.innerHTML = body; c.appendChild(w); } else if (body) c.appendChild(body);
  return markWaiting(c); }
// Time ranges load section by section (sections.js): the sections a card's data read while it was being built that have not
// arrived yet (recorded by the S.snap proxies) put a "loading" overlay on that card until they do.
function takeWaiting() { if (!S._t || !S._t.size) return null; const w = [...S._t]; S._t.clear(); return w; }
function markWaiting(c) { const w = takeWaiting(); if (w) { c.classList.add("sec-loading"); c.dataset.wait = w.join(","); } return c; }
function grid(cls, ...cards) { const g = document.createElement("div"); g.className = "grid " + cls; cards.filter(Boolean).forEach((c) => g.appendChild(c)); return g; }
function kpis(list) { const w = takeWaiting(); return `<div class="kpis${w ? " sec-loading-kpis" : ""}">${list.map(([l, v, c]) => `<div class="kpi ${c || ""}"><div class="v">${v}</div><div class="l">${esc(l)}</div></div>`).join("")}</div>`; }
function chartCard(title, cfg, cls = "", h = "") { const c = card(title, `<div class="chart ${h}"><canvas></canvas></div>`, cls); if (!c.classList.contains("sec-loading")) queueChart(c.querySelector("canvas"), cfg); return c; }
const _pending = [];
function queueChart(canvas, cfg) { _pending.push([canvas, cfg]); }
function flushCharts() { while (_pending.length) { const [cv, cfg] = _pending.shift(); if (cv.isConnected) S.charts.push(new Chart(cv, cfg)); } }

Chart.defaults.color = "#8b949e"; Chart.defaults.borderColor = "#2a323d"; Chart.defaults.font.family = "system-ui, sans-serif";
Chart.defaults.maintainAspectRatio = false; Chart.defaults.resizeDelay = 150; Chart.defaults.plugins.legend.labels.boxWidth = 12;
const bytesAxis = { ticks: { callback: (v) => fb(v) } };
const bytesTip = { callbacks: { label: (c) => `${c.dataset.label || c.label}: ${fb(c.parsed.y ?? c.parsed.x ?? c.parsed)}` } };
function barCfg(labels, data, { label = "", bytes = false, horizontal = true, color = PALETTE[0], onClick } = {}) {
  return { type: "bar", data: { labels, datasets: [{ label, data, backgroundColor: color, borderRadius: 3 }] },
    options: { indexAxis: horizontal ? "y" : "x", plugins: { legend: { display: false }, tooltip: bytes ? { callbacks: { label: (c) => fb(horizontal ? c.parsed.x : c.parsed.y) } } : {} },
      scales: { [horizontal ? "x" : "y"]: bytes ? bytesAxis : {}, [horizontal ? "y" : "x"]: { ticks: { autoSkip: false, font: { size: 11 }, ...(horizontal ? { callback(v) { const l = String(this.getLabelForValue(v)), n = innerWidth < 700 ? 26 : 48; return l.length > n ? l.slice(0, n - 1) + "…" : l; } } : {}) } } },
      onClick: onClick ? (e, els) => els.length && onClick(els[0].index) : undefined, onHover: onClick ? (e, els) => (e.native.target.style.cursor = els.length ? "pointer" : "default") : undefined } };
}
function doughnutCfg(obj, { bytes = false, top = 8, onClick } = {}) {
  const e = sortDesc(obj).map(([k, v]) => [k, typeof v === "object" ? v.bytes ?? v.conns : v]);
  const head = e.slice(0, top), rest = e.slice(top).reduce((s, [, v]) => s + v, 0);
  if (rest > 0) head.push(["other", rest]);
  return { type: "doughnut", data: { labels: head.map((x) => x[0]), datasets: [{ data: head.map((x) => x[1]), backgroundColor: PALETTE, borderColor: "#161b22" }] },
    options: { cutout: "58%", plugins: { legend: { position: "right" }, tooltip: { callbacks: { label: (c) => `${c.label}: ${bytes ? fb(c.parsed) : fn(c.parsed)}`, ...(onClick ? { footer: (it) => (it[0]?.label !== "other" ? "click to list" : "") } : {}) } } },
      ...(onClick ? { onClick: (e, els) => { const l = els.length && head[els[0].index][0]; if (l && l !== "other") onClick(l); }, onHover: (e, els) => (e.native.target.style.cursor = els.length && head[els[0].index][0] !== "other" ? "pointer" : "default") } : {}) } };
}
function hourLabels() {
  const ks = Object.keys(S.snap.raw?.totals?.hourly || {}).sort();
  const hrs = []; for (const k of ks) { const h = k.slice(11, 13); if (!hrs.includes(h)) hrs.push(h); }
  return hrs.length ? hrs : Array.from({ length: 24 }, (_, i) => String(i).padStart(2, "0"));
}

/* ---------- check-off (acknowledge) ---------- */
function fnv(str) { let h = 0x811c9dc5; for (let i = 0; i < str.length; i++) { h ^= str.charCodeAt(i); h = Math.imul(h, 0x01000193) >>> 0; } return h.toString(36); }
const alarmEvId = (a) => `alarm|${fnv(`${a.title}|${a.who || ""}`)}`;  // must match correlate.py build()'s alarm eid
const ACK = {
  alarm: (a) => fnv(`${a.title}|${a.who || ""}`),
  finding: (f) => fnv(`${f.device}|${f.kind}|${f.detail}`),
  issue: (i) => i.key,
  host: (f) => f.key,
  admin: (s) => `${s.src}|${s.dst}|${s.protocol}`,  // lateral admin sessions
  violation: (v) => `${v.src}|${v.dst}|${v.port}`,  // fallback only; normally mapped to the shared "seg" flow key
};
const ACK_LABEL = { alarm: "Triage alarm", finding: "Baseline finding", issue: "Fix-list / vulnerability", host: "Endpoint finding", admin: "Admin session", seg: "Cleared segmentation flow" };
// Segmentation findings / Fix-list "seg|" issues / lateral violations share ONE stable flow key ("<src MAC or IP>|<dst>|<port>",
// ack type "seg"), so clearing it anywhere clears it everywhere and it stays cleared on later snapshots.
const SEG_RE = /\s*(.*?)\s*\((\d+\.\d+\.\d+\.\d+)\)\s*(\d+)\/(\w+)/;
// flow key for a src IP: reuse a key that is already cleared (IP or MAC form), else the one the baseline finding
// uses, else the MAC form (follows the device through DHCP changes); matches lateral.js and risk.seg_is_cleared
function segFlowKey(src, dst, port) {
  const ks = [src, S.snap?.raw?.devices?.[src]?.mac].filter(Boolean).map((v) => `${String(v).toLowerCase()}|${dst}|${port}`);
  const seen = (S.snap?.analysis?.findings || []).map((f) => segKey("finding", f)).find((v) => ks.includes(v));
  return ks.find((v) => S.acks?.seg?.[v]) || seen || ks[ks.length - 1];
}
function segKey(type, x) {
  if (type === "finding" && x.kind === "segmentation") { const m = String(x.detail || "").split("->").pop().match(SEG_RE); return m ? `${String(x.device || "").toLowerCase()}|${m[2]}|${m[3]}` : null; }
  if (type === "violation") return segFlowKey(x.src, x.dst, x.port);
  if (type === "issue" && String(x.key || "").startsWith("seg|")) { const p = x.key.split("|"); return p.length >= 4 ? `${p[1].toLowerCase()}|${p[2]}|${p[3]}` : null; }
  return null;
}
const ackRef = (type, x) => { const sk = segKey(type, x); return sk ? ["seg", sk] : [type, ACK[type](x)]; };
const acked = (type, x) => { const [t, k] = ackRef(type, x); return !!S.acks?.[t]?.[k]; };
const ackInfo = (type, x) => { const [t, k] = ackRef(type, x); return S.acks?.[t]?.[k]; };
function ackBox(type, x, label) {
  const [t, k] = ackRef(type, x), a = S.acks?.[t]?.[k]; type = t;
  if (t === "seg") { const [src, dst, port] = k.split("|"), macIp = (m) => entries(S.snap?.raw?.devices || {}).find(([, d]) => String(d.mac || "").toLowerCase() === m)?.[0];
    const sip = src.includes(":") ? macIp(src) || src : src; label = `Segmentation: ${S.idx?.nameOf?.(sip) || sip} → ${S.idx?.nameOf?.(dst) || dst}:${port}`; }
  if (t === "seg") return `<input type="checkbox" class="ack-cb" data-t="seg" data-k="${esc(k)}" data-l="${esc(label || "")}" ${a ? "checked" : ""} title="${a ? "Cleared " + esc(ft(a.at)) + " — uncheck to bring it back" : "Clear: this flow is expected (hides it everywhere and stops it counting toward risk)"}">`;
  return `<input type="checkbox" class="ack-cb" data-t="${type}" data-k="${esc(k)}" data-l="${esc(label || "")}" ${a ? "checked" : ""} title="${a ? "Checked off " + esc(ft(a.at)) + " — uncheck to restore" : "Check off (hide)"}">`;
}
// split rows into open / checked and decide what to show for a section
function ackSplit(type, rows, sec) {
  const open = rows.filter((x) => !acked(type, x)), done = rows.filter((x) => acked(type, x));
  const show = S.showAcked[sec] || hq().has("ev") ? [...open, ...done] : open;
  const toggle = done.length ? ` <a href="#" class="ack-toggle small" data-s="${sec}">${S.showAcked[sec] ? "hide" : "show"} ${done.length} checked</a>` : "";
  return { open, done, show, toggle };
}
const ackCol = (type, labelFn) => ({ k: "_ack", t: "✓", fmt: (v, x) => ackBox(type, x, labelFn(x)), sort: (x) => (acked(type, x) ? 1 : 0) });
const ackRowCls = (type) => (x) => (acked(type, x) ? "acked" : "");

/* ----- "Ask AI" about one specific vulnerability / attack / finding ----- */
const ASK = new Map(); let askSeq = 0;
const ASK_Q = {
  vuln: ["What is this and how serious is it for my network?", "How do I fix this, step by step?", "Is this being exploited in the wild right now?"],
  attack: ["Is this a real attack or a false positive?", "What should I do right now?", "What else did the devices involved do around that time?"],
  technique: ["Explain this technique and how it applies to my network", "How do I detect or prevent it here?", "Which of my devices are most exposed to it?"],
};
const ASK_KIND = { vulnerability: "vuln", misconfiguration: "vuln", "security suggestion": "vuln", "risky host": "vuln", "ATT&CK technique": "technique", "ATT&CK mapping": "technique" };
function askClean(o, depth = 0) {  // compact copy of the item for the prompt: drop UI-only keys, cap sizes
  if (o == null || typeof o !== "object") return typeof o === "string" ? o.slice(0, 600) : o;
  if (depth > 3) return "…";
  if (Array.isArray(o)) return o.slice(0, 15).map((x) => askClean(x, depth + 1));
  const r = {}; for (const [k, v] of Object.entries(o)) if (!k.startsWith("_") && v !== "" && v != null && k !== "investigated") r[k] = askClean(v, depth + 1);
  return r;
}
function askBtn(kind, title, item) {
  const id = "a" + ++askSeq; ASK.set(id, { kind, title: String(title || "").slice(0, 300), item });
  if (ASK.size > 4000) ASK.delete(ASK.keys().next().value);
  return `<button type="button" class="askh" data-ask="${id}" title="Ask AI about this" aria-label="Ask AI about this">💬</button>`;
}
// "compare models" button (compare.js): same registry idea as askBtn
const CMP = new Map(); let cmpSeq = 0;
function cmpBtn(kind, title, item, eid) {
  const id = "c" + ++cmpSeq; CMP.set(id, { kind, title: String(title || "").slice(0, 300), item, eid });
  if (CMP.size > 4000) CMP.delete(CMP.keys().next().value);
  return `<button type="button" class="cmph" data-icmp="${id}" title="Compare models on this" aria-label="Compare models on this">⇄</button>`;
}
const askCmpCol = (kind, titleFn) => ({ k: "_ask", t: "", cls: "askcell", fmt: (v, x) => askBtn(kind, titleFn(x), x) + cmpBtn(kind, titleFn(x), x) });
const pivBtn = (kind, x) => (typeof pivotBtn === "function" ? pivotBtn(kind, x) : "");
const askCmpPivCol = (kind, titleFn, piv) => ({ k: "_ask", t: "", cls: "askcell", fmt: (v, x) => askBtn(kind, titleFn(x), x) + cmpBtn(kind, titleFn(x), x) + pivBtn(piv, x) });
const askPivCol = (kind, titleFn, piv) => ({ k: "_ask", t: "", cls: "askcell", fmt: (v, x) => askBtn(kind, titleFn(x), x) + pivBtn(piv, x) });
const askCol = (kind, titleFn) => ({ k: "_ask", t: "", cls: "askcell", fmt: (v, x) => askBtn(typeof kind === "function" ? kind(x) : kind, titleFn(x), x) });
// model picker for Ask AI (chat page + "Ask about this" dialog); choice kept per browser in localStorage
const CHAT_MODEL_KEY = "netmonChatModel";
let _llmModels = null;
const chatModel = () => { try { return JSON.parse(localStorage.getItem(CHAT_MODEL_KEY) || "null"); } catch (_) { return null; } };
async function chatModelPicker() {
  const wrap = document.createElement("span"); wrap.className = "chatm";
  try { _llmModels = _llmModels || await api("/api/llm/models"); } catch (_) { return wrap; }
  const M = _llmModels; if (!M.admin) return wrap;
  const sel = document.createElement("select"); sel.className = "chatm-sel"; sel.setAttribute("aria-label", "Model for Ask AI");
  sel.add(new Option("Default (set on AI review > Models)", ""));
  for (const [label, prov, list] of [...(M.custom || []).map((g) => [g.name, g.provider, g.models]), ["Local (LM Studio)", "lmstudio", M.local || []]]) {
    if (!list.length) continue;
    const g = document.createElement("optgroup"); g.label = label;
    list.forEach((m) => g.appendChild(new Option(m.id + (m.loaded ? " (loaded)" : prov === "lmstudio" ? " (not loaded)" : ""), `${prov}|${m.id}`)));
    sel.appendChild(g);
  }
  const cur = chatModel(); sel.value = cur ? `${cur.provider}|${cur.model}` : "";
  if (sel.selectedIndex < 0) sel.value = "";
  sel.onchange = () => { if (!sel.value) localStorage.removeItem(CHAT_MODEL_KEY); else { const [provider, ...m] = sel.value.split("|"); localStorage.setItem(CHAT_MODEL_KEY, JSON.stringify({ provider, model: m.join("|") })); }
    document.querySelectorAll(".chatm-sel").forEach((o) => { if (o !== sel) o.value = sel.value; }); };
  wrap.append(Object.assign(document.createElement("span"), { className: "muted small", textContent: "Model " }), sel);
  return wrap;
}
function askOpen(a) {
  document.getElementById("askDlg")?.remove();
  let details = ""; try { details = JSON.stringify(askClean(a.item), null, 1).slice(0, 3000); } catch (_) { /* ignore */ }
  const qs = ASK_Q[ASK_KIND[a.kind] || "attack"];
  const d = document.createElement("div"); d.id = "askDlg"; d.className = "askdlg-scrim";
  d.innerHTML = `<div class="askdlg card" role="dialog" aria-modal="true" aria-labelledby="askT">
    <div class="askdlg-h"><span class="avatar">⚕︎</span><div><b id="askT">Ask AI about this ${esc(a.kind)}</b><div class="muted small askdlg-item">${esc(a.title)}</div></div><button type="button" class="askdlg-x" aria-label="Close">✕</button></div>
    <details class="small"><summary class="muted">What the AI will be given</summary><pre class="mono">${esc(details)}</pre></details>
    <div class="askdlg-q">${qs.map((q) => `<button type="button" data-q="${esc(q)}">${esc(q)}</button>`).join("")}</div>
    <form><textarea rows="3" maxlength="2000" placeholder="Or type your own question about this ${esc(a.kind)}…"></textarea>
    <div class="askdlg-f"><span class="muted small">Opens in Ask AI as a new chat.</span><button type="submit">Ask AI ➤</button></div></form></div>`;
  document.body.appendChild(d);
  chatModelPicker().then((p) => d.querySelector(".askdlg-f").prepend(p));
  const ta = d.querySelector("textarea");
  const onKey = (e) => { if (e.key === "Escape") close(); };
  const close = () => { d.remove(); removeEventListener("keydown", onKey); };
  addEventListener("keydown", onKey);
  const ask = (q) => { q = q.trim(); if (!q) return ta.focus();
    sessionStorage.setItem("askPending", JSON.stringify({ q, ctx: { kind: a.kind, title: a.title, details } })); close();
    if (location.hash.startsWith("#/chat")) rerender(); else location.hash = "#/chat"; };
  d.onclick = (e) => { if (e.target === d || e.target.closest(".askdlg-x")) close(); const b = e.target.closest("[data-q]"); if (b) ask(b.dataset.q); };
  d.querySelector("form").onsubmit = (e) => { e.preventDefault(); ask(ta.value); };
  ta.addEventListener("keydown", (e) => { if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) ask(ta.value); });
  if (!matchMedia("(pointer: coarse)").matches) ta.focus();
}
document.addEventListener("click", (e) => {  // capture phase: beats table-row navigation handlers
  const b = e.target.closest("[data-ask]"); if (!b) return;
  e.preventDefault(); e.stopPropagation(); const a = ASK.get(b.dataset.ask); if (a) askOpen(a);
}, true);
async function setAck(type, key, checked, label) {
  S.acks = await apiPost("/api/acks", { type, key, checked, label });
}
document.addEventListener("change", async (e) => {
  const cb = e.target.closest(".ack-cb"); if (!cb) return;
  cb.disabled = true;
  try { await setAck(cb.dataset.t, cb.dataset.k, cb.checked, cb.dataset.l); } catch (err) { alert(err); cb.checked = !cb.checked; }
  if (cb.dataset.t === "seg") {  // cleared flows change server-side risk, lateral and correlation results
    S.lateral = null; S.corr = null;
    try { S.risk = await api("/api/risk?id=" + encodeURIComponent(S.snap.id)); } catch (_) {}
  }
  rerender();
});
document.addEventListener("click", (e) => {
  const t = e.target.closest(".ack-toggle"); if (!t) return;
  e.preventDefault(); S.showAcked[t.dataset.s] = !S.showAcked[t.dataset.s]; rerender();
});
function rerender() { const y = window.scrollY; route(true).then(() => requestAnimationFrame(() => window.scrollTo(0, y))); }

/* ---------- views ---------- */
const V = {};

V.overview = (el) => {
  const raw = S.snap.raw, an = S.snap.analysis || {}, tr = S.snap.triage || {}, T = raw.totals || {};
  const fsev = {}; (an.findings || []).forEach((f) => (fsev[f.severity] = (fsev[f.severity] || 0) + 1));
  const alarms = tr.alarms || [];
  const inv = alarms.filter((a) => /investigate/i.test(a.priority) && !acked("alarm", a)).length;
  const fleet = raw.hosts?.fleet || [];
  const unhealthy = fleet.filter((f) => !/online|healthy/i.test(f.status)).length;
  el.innerHTML = `<h1>Network overview</h1><div class="sub">Window: ${ft(S.range.start)} – ${ft(S.range.end)} (${esc(+(+raw.hours).toFixed(1))} h${S.snap.range ? ", collected for this range; volumes compared with the 24 h baseline scaled to the range" : ""}) · baseline ${esc(an.baseline_days ?? "?")} days${an.baseline_ready ? " (ready)" : " (warming up)"}</div>` +
    kpis([["Devices seen", fn(Object.keys(raw.devices || {}).length)], ["Total traffic", fb(T.ip_bytes)], ["Internet traffic", fb(T.internet_ip_bytes)], ["Connections", fn(T.conns)],
      ["IDS alerts", fn(raw.alerts?.total), raw.alerts?.total ? "warn" : ""], ["High findings", `<a href="#/security?severity=high">${fn(fsev.high || 0)}</a>`, fsev.high ? "bad" : "good"],
      ["Triage: investigate", `<a href="#/security?at=sec-alarms-card">${fn(inv)}</a>`, inv ? "bad" : "good"], ["Endpoints unhealthy", `${unhealthy}/${fleet.length}`, unhealthy ? "warn" : "good"],
      ["TI hits (in/out)", `${(raw.threat_intel?.ip_hits_in || []).length}/${(raw.threat_intel?.ip_hits_out || []).length + (raw.threat_intel?.domain_hits || []).length}`], ["Capture loss", fb(T.missed_bytes), T.missed_bytes > 1e9 ? "warn" : ""],
      ["Recurring issues to fix", `<a href="#/issues">${(S.issues?.open || []).filter((x) => x.recurring).length}</a>`, (S.issues?.open || []).some((x) => x.recurring && x.severity === "high") ? "bad" : "warn"],
      ["Highest-risk host", S.risk?.hosts?.[0] ? `<a href="#/risk" style="font-size:16px">${esc(S.risk.hosts[0].name)} · ${S.risk.hosts[0].score}</a>` : "—", S.risk?.hosts?.[0]?.score >= 40 ? "bad" : "warn"],
      ["Issues fixed", `<a href="#/issues">${(S.issues?.fixed || []).length}</a>`, "good"]]);
  if (tr.summary) el.appendChild(card(`Triage summary ${trFlare()}`, `<div>${linkifyIps(tr.summary)}</div>`));
  const hl = Object.keys(T.hourly || {}).sort();
  el.appendChild(grid("g2",
    chartCard("Traffic per hour", { type: "line", data: { labels: hl.map((k) => k.slice(11, 16)), datasets: [
      { label: "bytes", data: hl.map((k) => T.hourly[k]), borderColor: PALETTE[0], backgroundColor: "#58a6ff33", fill: true, tension: 0.3 },
      { label: "missed (capture loss)", data: hl.map((k) => T.hourly_missed?.[k] || 0), borderColor: PALETTE[3], backgroundColor: "#f8514922", fill: true, tension: 0.3 }] },
      options: { scales: { y: bytesAxis }, plugins: { tooltip: bytesTip } } }),
    topTalkersChart(12)));
  el.appendChild(grid("g3",
    chartCard("Findings by severity", doughnutCfg(fsev, { onClick: (l) => drill("security", { severity: l }) })),
    chartCard("Finding kinds", doughnutCfg((an.findings || []).reduce((o, f) => ((o[f.kind] = (o[f.kind] || 0) + 1), o), {}), { top: 10, onClick: (l) => drill("security", { kind: l }) })),
    chartCard("Devices by zone", doughnutCfg(S.idx.rows.reduce((o, r) => ((o[r.zone || "?"] = (o[r.zone || "?"] || 0) + 1), o), {}), { onClick: (l) => drill("devices", { zone: l }) }))));
  if (alarms.length) { const A = ackSplit("alarm", alarms, "ov-alarms"); const lst = A.show.slice().sort((a, b) => (acked("alarm", a) - acked("alarm", b)) || sevRank(a.priority) - sevRank(b.priority));
    const c = card(`Triage alarms (${A.open.length} open) ${trFlare()}${A.toggle}`, alarmsHtml(lst.slice(0, S.showAcked["ov-alarms"] ? 50 : 6)) || `<div class="empty">All alarms checked off.</div>`); if (A.show.length > 6) c.insertAdjacentHTML("beforeend", `<a href="#/security">All alarms →</a>`); el.appendChild(c); }
  el.appendChild(grid("g2", card("Endpoint fleet", fleetTable()), card("Gateway health", unifiHealthHtml())));
  const brief = S.snap.briefing?.items || [];
  if (brief.length) el.appendChild(card(`Security news briefing ${aiFlare(S.snap.briefing.generated_by || {}, "AI news research")}`, brief.map((i) => `<div class="alarm info"><div class="t"><span class="chip">${esc(i.category)}</span> <a href="${esc(i.url)}" target="_blank" rel="noopener">${esc(i.title)}</a></div><p>${esc(i.summary)}</p></div>`).join("")));
};

function topTalkersChart(n) {
  const top = [...S.idx.rows].sort((a, b) => b.total - a.total).slice(0, n);
  return chartCard("Top talkers (click to drill down)", { type: "bar", data: { labels: top.map((r) => r.name || r.ip), datasets: [
    { label: "sent", data: top.map((r) => r.sent), backgroundColor: PALETTE[1] }, { label: "received", data: top.map((r) => r.recv), backgroundColor: PALETTE[0] }] },
    options: { indexAxis: "y", scales: { x: { stacked: true, ...bytesAxis }, y: { stacked: true, ticks: { autoSkip: false, font: { size: 11 } } } }, plugins: { tooltip: { callbacks: { label: (c) => `${c.dataset.label}: ${fb(c.parsed.x)}` } } },
      onClick: (e, els) => els.length && go("device/" + top[els[0].index].ip), onHover: (e, els) => (e.native.target.style.cursor = els.length ? "pointer" : "default") } }, "", "tall");
}

function alarmsHtml(list) {
  return list.map((a) => `<div class="alarm ${esc(String(a.priority).toLowerCase())} ${acked("alarm", a) ? "acked" : ""}"><div class="t">${ackBox("alarm", a, a.title)} ${badge(a.priority)} ${esc(a.title)} ${askBtn("alarm", a.title, a)}${cmpBtn("triage alarm", a.title, a)}${pivBtn("alarm", a)}<button type="button" class="rel-btn" data-rel="${esc(alarmEvId(a))}" title="Related events">…</button>${acked("alarm", a) ? ` <span class="muted small">checked ${esc(ft(ackInfo("alarm", a).at))}</span>` : ""}</div>
    ${a.who ? `<p><span class="k">Who:</span> ${linkifyIps(a.who)}</p>` : ""}${a.evidence ? `<p><span class="k">Evidence:</span> ${linkifyIps(a.evidence)}</p>` : ""}
    ${a.why ? `<p><span class="k">Why:</span> ${linkifyIps(a.why)}</p>` : ""}${a.context ? `<p><span class="k">Context:</span> ${linkifyIps(a.context)}</p>` : ""}
    ${a.next ? `<p><span class="k">Next:</span> ${linkifyIps(a.next)} ${trFlare()}</p>` : ""}
    ${(a.links || []).length ? `<p class="small">${a.links.map((l) => `<a href="${esc(l.url)}" target="_blank" rel="noopener">${esc(l.title)}</a>`).join(" · ")}</p>` : ""}</div>`).join("");
}
function fleetTable(filterHost) {
  const f = (S.snap.raw.hosts?.fleet || []).filter((x) => !filterHost || x.host === filterHost);
  return table(null, [{ k: "host", t: "Host", fmt: (v) => hostLink(v) }, { k: "status", t: "Status", fmt: badge }, { k: "minutes_since_checkin", t: "Check-in (min ago)", num: true, fmt: (v) => (v ?? "").toString() },
    { k: "unhealthy_reason", t: "Reason", fmt: (v, r) => esc([v, ...(r.bad_components || []).map((b) => (typeof b === "string" ? b : b.id || b.name || JSON.stringify(b)))].filter(Boolean).join(", ")) },
    { k: "version", t: "Agent" }, { k: "policy", t: "Policy", cls: "small" }], f, { search: false, onclick: (r) => go("endpoint/" + r.host) });
}
function unifiHealthHtml() {
  const h = S.snap.raw.unifi?.health; if (!h) return `<div class="empty">No UniFi data</div>`;
  return `<div class="chips" style="margin-bottom:10px">${entries(h.status).map(([k, v]) => `<span class="chip">${esc(k)} ${badge(v)}</span>`).join("")}</div>
  <div class="idgrid"><span class="k">ISP</span><span>${esc(h.isp)}</span><span class="k">WAN IP</span><span class="mono">${esc(h.wan_ip)}</span><span class="k">Latency</span><span>${esc(h.latency_ms)} ms</span>
  <span class="k">Drops</span><span>${fn(h.drops)}</span><span class="k">Uptime</span><span>${(h.uptime_s / 86400).toFixed(1)} days</span>
  <span class="k">Clients online</span><span>${fn(S.snap.raw.unifi?.clients?.online)} (${entries(S.snap.raw.unifi?.clients?.by_network).map(([k, v]) => esc(k) + ": " + v).join(", ")})</span></div>`;
}

/* ----- Devices list ----- */
const devRaw = (r) => S.snap.raw.devices?.[r.ip] || {};
const DEV_FILTERS = {
  zone: ["Zone", (r, v) => eqi(r.zone || "?", v)], cls: ["Class", (r, v) => eqi(r.cls, v)], vendor: ["Vendor", (r, v) => eqi(r.oui, v)],
  known: ["Known", (r, v) => String(!!r.known) === v], severity: ["Worst finding", (r, v) => eqi(r.worst, v)],
  country: ["Internet traffic to country", (r, v) => !!devRaw(r).countries?.[v]], asn: ["Traffic to ASN", (r, v) => !!devRaw(r).asns?.[v]],
  proto: ["Uses protocol / service", (r, v) => !!devRaw(r).protocols?.[v]], qtype: ["DNS query type", (r, v) => !!devRaw(r).dns?.qtypes?.[v]],
  tls: ["TLS version", (r, v) => !!S.snap.raw.tls?.devices?.[r.ip]?.versions?.[v]],
};
V.devices = (el) => {
  const rows = S.idx.rows;
  el.innerHTML = `<h1>Hosts</h1><div class="sub">${rows.length} internal addresses with traffic in this time range. Click a row for full detail.</div>` +
    kpis([["Known", `<a href="#/devices?known=true">${rows.filter((r) => r.known).length}</a>`, "good"], ["Unknown", `<a href="#/devices?known=false">${rows.filter((r) => !r.known).length}</a>`, rows.some((r) => !r.known) ? "warn" : ""],
      ["New in this range", (S.snap.analysis?.new_devices || []).length], ["With high findings", `<a href="#/devices?severity=high">${rows.filter((r) => r.worst === "high").length}</a>`, "bad"]]);
  el.appendChild(card(`All hosts (${rows.length})`, table("devs", [
    { k: "name", t: "Name", fmt: (v, r) => `<a href="#/device/${r.ip}">${esc(v || "(unnamed)")}</a>${r.known ? "" : ' <span class="badge sev-medium">unknown</span>'}${r.hosts.length ? ' <span class="badge sev-info">agent</span>' : ""}` },
    { k: "ip", t: "IP", cls: "mono", sort: (r) => ip2n(r.ip) }, { k: "mac", t: "MAC", cls: "mono" }, { k: "oui", t: "Vendor", cls: "small" },
    { k: "zone", t: "Zone" }, { k: "cls", t: "Class" },
    { k: "total", t: "Total", num: true, bar: true, fmt: fb }, { k: "sent", t: "Sent", num: true, fmt: fb }, { k: "recv", t: "Recv", num: true, fmt: fb },
    { k: "conns", t: "Conns", num: true, fmt: fn }, { k: "ext_peers", t: "Ext peers", num: true, fmt: fn }, { k: "dnsq", t: "DNS q", num: true, fmt: fn },
    { k: "findings", t: "Findings", num: true, fmt: (v, r) => (v ? `${v} ${badge(r.worst)}` : "") , sort: (r) => r.findings * 10 + (5 - sevRank(r.worst)) },
  ], rows, { sort: "total", onclick: (r) => go("device/" + r.ip), urlFilter: DEV_FILTERS })));
  const nd = S.snap.analysis?.new_devices || [], ud = S.snap.analysis?.unknown_devices || [];
  el.appendChild(grid("g2",
    card("New devices (first ever seen in this time range)", table(null, [{ k: "ip", t: "Device", fmt: (v) => ipLink(v) }, { k: "mac", t: "MAC", cls: "mono" }, { k: "hostname", t: "Hostname" }, { k: "first_seen", t: "First seen", fmt: ft }, { k: "total", t: "Bytes", num: true, fmt: fb }], nd, { search: false })),
    card("Unknown devices (not in inventory)", table(null, [{ k: "ip", t: "Device", fmt: (v) => ipLink(v) }, { k: "total", t: "Bytes", num: true, fmt: fb }, { k: "ext_peers", t: "Ext peers", num: true, fmt: fn }], ud, { search: false }))));
};

/* ----- Device detail ----- */
V.device = (el, ip) => {
  const raw = S.snap.raw, d = raw.devices?.[ip];
  if (!d) { el.innerHTML = `<h1>${esc(ip)}</h1><div class="empty">Not present in this time range.</div>`; return; }
  const r = S.idx.byIp[ip], an = S.snap.analysis || {}, tr = S.snap.triage || {}, seen = S.idx.seenByIp[ip] || {};
  const findings = (an.findings || []).filter((f) => f.device === ip);
  const alarms = (tr.alarms || []).filter((a) => [a.who, a.title, a.evidence].join(" ").includes(ip) || (r.name && [a.who, a.title].join(" ").includes(r.name)));
  el.innerHTML = `<div class="crumbs"><a href="#/devices">Devices</a> › ${esc(ip)}</div><h1>${esc(r.name || ip)} ${r.known ? badge("known") : '<span class="badge sev-medium">unknown</span>'} ${r.worst ? badge(r.worst) : ""}</h1>`;
  const id = card("Identity", `<div class="idgrid">
    <span class="k">IP</span><span class="mono">${esc(ip)}</span><span class="k">MAC</span><span class="mono">${esc(r.mac || "—")}</span>
    <span class="k">Vendor (OUI)</span><span>${esc(r.oui || "—")}</span><span class="k">Hostname</span><span>${esc(r.hostname || "—")}</span>
    <span class="k">Zone / class</span><span>${esc(r.zone)} / ${esc(r.cls || "—")}</span><span class="k">Inventory name</span><span>${esc(raw.inventory_ips?.[ip] || "—")}</span>
    <span class="k">First seen</span><span>${ft(seen.first_seen || d.zeek_first_seen)}</span><span class="k">Last seen</span><span>${ft(seen.last_seen)}</span>
    <span class="k">Days seen</span><span>${esc(seen.days_seen ?? "—")}</span><span class="k">Other IPs</span><span>${esc((seen.ips || []).filter((x) => x !== ip).join(", ") || "—")}</span>
    <span class="k">Elastic agent</span><span>${r.hosts.length ? r.hosts.map(hostLink).join(", ") : "—"}</span></div>
    ${r.note ? `<div class="note">${trFlare()} ${linkifyIps(r.note)}</div>` : ""}`);
  el.appendChild(id);
  el.appendChild(kbCard([r.mac && "mac:" + String(r.mac).toLowerCase(), "ip:" + ip, ...r.hosts.map((h) => "host:" + String(h).toLowerCase().split(".")[0])], r.mac ? "mac:" + String(r.mac).toLowerCase() : "ip:" + ip));
  el.insertAdjacentHTML("beforeend", kpis([["Total", fb(d.total_bytes)], ["Sent", fb(d.total_sent)], ["Received", fb(d.total_recv)], ["Out conns", fn(d.orig_conns)], ["In conns", fn(d.resp_conns)],
    ["Peers", fn(d.peers)], ["Internet peers", fn(d.ext_peers)], ["Internet up", fb(d.ext_out_bytes)], ["Internet down", fb(d.ext_in_bytes)], ["Rejected", fn(d.rejected_conns), d.rejected_conns > 1000 ? "warn" : ""],
    ["Inbound ext sources", fn(d.inbound_ext_sources), d.inbound_ext_sources ? "warn" : ""], ["DNS queries", fn(d.dns?.queries)], ["NXDOMAIN", fn(d.dns?.nxdomain)], ["Capture loss", fb(d.missed_bytes)]]));
  const rk = (S.risk?.hosts || []).find((h) => h.ip === ip);
  if (rk) el.appendChild(riskCard(rk));
  const devIss = (S.issues?.open || []).filter((x) => x.ip === ip || (r.mac && x.dev === r.mac));
  const DI = ackSplit("issue", devIss, "dev-iss");
  if (devIss.length) el.appendChild(card(`Open issues to fix (${DI.open.length}) · <a href="#/issues">all</a>${DI.toggle}`, issueTable(DI.show, { short: true })));
  if (findings.length || alarms.length) {
    const DF = ackSplit("finding", findings, "dev-find"), DA = ackSplit("alarm", alarms, "dev-alarm");
    const c = card(`Findings (${DF.open.length})${DF.toggle}`, DF.show.length ? table(null, [ackCol("finding", (x) => `${x.kind}: ${x.detail}`), askCmpPivCol("baseline finding", (x) => `${x.kind}: ${x.detail}`, "baseline finding"), { k: "severity", t: "Severity", fmt: badge, sort: (x) => sevRank(x.severity) }, { k: "kind", t: "Kind" }, { k: "detail", t: "Detail", fmt: linkifyIps }], DF.show, { sort: "severity", dir: 1, search: false, rowClass: ackRowCls("finding") }) : "");
    if (alarms.length) c.insertAdjacentHTML("beforeend", `<h3>Triage alarms (${DA.open.length}) ${trFlare()}${DA.toggle}</h3>` + alarmsHtml(DA.show));
    el.appendChild(c);
  }
  const hrs = hourLabels();
  el.appendChild(grid("g2",
    chartCard("Activity by hour", { type: "bar", data: { labels: hrs.map((h) => h + ":00"), datasets: [
      { label: "bytes", data: hrs.map((h) => d.hourly_bytes?.[h] || 0), backgroundColor: PALETTE[0], yAxisID: "y" },
      { type: "line", label: "conns", data: hrs.map((h) => d.hourly_conns?.[h] || 0), borderColor: PALETTE[2], yAxisID: "y1", tension: 0.3 }] },
      options: { scales: { y: bytesAxis, y1: { position: "right", grid: { display: false } } }, plugins: { tooltip: { callbacks: { label: (c) => c.dataset.label === "bytes" ? "bytes: " + fb(c.parsed.y) : "conns: " + fn(c.parsed.y) } } } } }),
    historyChartForDevice(ip, r.mac)));
  el.appendChild(grid("g3",
    chartCard("Internet traffic by country <span class=\"muted small\">· click: all devices to it</span>", doughnutCfg(d.countries, { bytes: true, onClick: (l) => drill("devices", { country: l }) })),
    chartCard("By ASN", (() => { const a = sortDesc(d.asns); return barCfg(a.map((x) => x[0]), a.map((x) => x[1]), { bytes: true, color: PALETTE[4], onClick: (i) => drill("devices", { asn: a[i][0] }) }); })()),
    chartCard("By protocol / service", doughnutCfg(d.protocols, { bytes: true, onClick: (l) => drill("devices", { proto: l }) }))));
  el.appendChild(grid("g3",
    card("Top destinations", kvTable(d.top_dst, "Destination", "Bytes", fb, (k) => ipLink(k))),
    card("Remote ports (bytes)", kvTable(d.ports, "Port", "Bytes", fb)),
    card("Internet dest ports (conns)", kvTable(d.ext_dports, "Port", "Conns"))));
  el.appendChild(grid("g2",
    card("Outbound by destination port", table(null, [{ k: "p", t: "Port/proto" }, { k: "service", t: "Service" }, { k: "conns", t: "Conns", num: true, fmt: fn }, { k: "ext_conns", t: "Internet", num: true, fmt: fn }, { k: "bytes", t: "Bytes", num: true, bar: true, fmt: fb }],
      entries(d.dports_out).map(([p, v]) => ({ p, ...v })), { sort: "conns", short: true })),
    card("Outbound by service", table(null, [{ k: "s", t: "Service" }, { k: "conns", t: "Conns", num: true, fmt: fn }, { k: "bytes", t: "Bytes", num: true, bar: true, fmt: fb }],
      entries(d.services_out).map(([s, v]) => ({ s, ...v })), { sort: "bytes", short: true, search: false }))));
  if (d.resp_conns != null) el.appendChild(card("Served / listening ports (inbound)", `<div class="small muted" style="margin-bottom:6px">Inbound conns ${fn(d.resp_conns)} from ${fn(d.resp_sources)} sources · ${fb(d.resp_in_bytes)} in / ${fb(d.resp_out_bytes)} out · internet-exposed ports: ${esc((d.inbound_ext_ports || []).join(", ") || "none")}</div>`))
    .appendChild(table(null, [{ k: "p", t: "Port/proto" }, { k: "service", t: "Service" }, { k: "conns", t: "Conns", num: true, bar: true, fmt: fn }, { k: "sources", t: "Sources", num: true, fmt: fn }, { k: "ext_conns", t: "From internet", num: true, fmt: (v) => (v ? `<b style="color:var(--warn)">${fn(v)}</b>` : "0") }],
      entries(d.served_ports).map(([p, v]) => ({ p, ...v })), { sort: "conns", short: true, search: false }));
  // DNS
  const dns = d.dns || {};
  if (dns.queries) {
    const c = card("DNS", kpis([["Queries", fn(dns.queries)], ["Unique names", fn(dns.unique_names)], ["Unique domains", fn(dns.unique_domains)], ["NXDOMAIN", fn(dns.nxdomain)], ["SERVFAIL", fn(dns.servfail)], ["Avg name len", (+dns.avg_len || 0).toFixed(1)]]), "span");
    el.appendChild(c);
    el.appendChild(grid("g3", card("Top domains", kvTable(dns.top_domains, "Domain", "Queries", fn, domFmt)), card("NXDOMAIN domains", kvTable(dns.nx_domains, "Domain", "Queries", fn, domFmt)),
      chartCard("Query types", doughnutCfg(dns.qtypes, { onClick: (l) => drill("devices", { qtype: l }) }))));
    el.appendChild(grid("g3", card("Resolvers used", kvTable(dns.resolvers, "Resolver", "Queries", fn, (k) => ipLink(k))), card("TLDs", kvTable(dns.tlds, "TLD", "Queries")),
      card("Other DNS signals", `<div class="idgrid"><span class="k">External resolvers</span><span>${esc(Object.keys(dns.external_resolvers || {}).join(", ") || "none")}</span>
        <span class="k">DoH</span><span>${esc(JSON.stringify(dns.doh ?? "none"))}</span><span class="k">mDNS</span><span>${esc(JSON.stringify(dns.mdns ?? "none"))}</span>
        <span class="k">Max name len</span><span>${esc(dns.max_len)}</span><span class="k">Long names</span><span class="mono small">${esc(JSON.stringify(dns.long_names || []).slice(0, 600))}</span>
        <span class="k">Subdomain-heavy</span><span class="mono small">${esc(JSON.stringify(dns.subdomain_heavy || {}).slice(0, 600))}</span></div>`)));
  }
  // TLS / IoT
  const tls = raw.tls?.devices?.[ip], iot = raw.iot_dest?.[ip];
  if (tls || iot) el.appendChild(grid("g3",
    tls?.ja3 && card("TLS client fingerprints (JA3) · <a href=\"#/tls\">all</a>", kvTable(tls.ja3, "JA3", "Conns", fn, (k) => { const m = (S.snap.raw.tls?.malicious_ja3 || []).find((x) => x.ja3 === k); const j = (S.snap.raw.tls?.ja3 || []).find((x) => x.ja3 === k); return `<a href="#/threatintel?q=${k}" class="mono small">${esc(k)}</a>${m ? ' <span class="badge sev-high">SSLBL</span>' : ""}${j ? `<br><span class="muted small">${j.clients} device(s) · ${esc((j.servers || []).slice(0, 2).join(", "))}</span>` : ""}`; })),
    tls && card("TLS client fingerprints (JA4)", kvTable(tls.ja4, "JA4", "Conns", fn, (k) => `<span class="mono">${esc(k)}</span>`)),
    tls && chartCard("TLS versions", doughnutCfg(tls.versions, { onClick: (l) => drill("devices", { tls: l }) })),
    tls && (tls.bad_certs || []).length && card("Bad certificates", `<pre>${esc(JSON.stringify(tls.bad_certs, null, 1))}</pre>`),
    iot && card("IoT: domains contacted", kvTable(iot.domains, "Domain", "Conns", fn, domFmt)),
    iot && card("IoT: SNI", kvTable(iot.sni, "SNI", "Conns")),
    iot && card("IoT: ASNs", kvTable(iot.asns, "ASN", "Bytes", fb))));
  const dcerts = (S.snap.raw.tls?.certs || []).filter((c) => c.clients?.[ip]);
  if (dcerts.length) el.appendChild(card(`Certificates this device received (${dcerts.length}) · <a href="#/tls">all</a>`, table(null, [{ k: "flags", t: "Flags", fmt: (v, c) => certFlags(c), sort: (c) => -c.flags.length }, { k: "subject", t: "Subject", fmt: (v) => esc(certCN(v)) }, { k: "issuer", t: "Issuer", cls: "small", fmt: (v) => esc(certCN(v)) }, { k: "days_left", t: "Days left", num: true }, { k: "_n", t: "Times", num: true, fmt: (v, c) => fn(c.clients[ip]), sort: (c) => c.clients[ip] }], dcerts, { sort: "flags", dir: 1, short: true, search: dcerts.length > 8 })));
  // internal flows
  const flows = raw.internal?.flows || [];
  const fout = flows.filter((f) => f.src === ip), fin = flows.filter((f) => f.dst === ip);
  const fcols = (k) => [{ k, t: k === "dst" ? "To" : "From", fmt: (v) => ipLink(v) }, { k: "port", t: "Port", num: true }, { k: "proto", t: "Proto" }, { k: "service", t: "Svc" },
    { k: "conns", t: "Conns", num: true, fmt: fn }, { k: "answered", t: "Answered", num: true, fmt: fn }, { k: "bytes", t: "Bytes", num: true, bar: true, fmt: fb }];
  el.insertAdjacentHTML("beforeend", `<div style="margin:4px 0 10px"><a href="#/lateral/${encodeURIComponent(ip)}">View this host on the lateral-movement graph →</a></div>`);
  el.appendChild(grid("g2", card(`Internal flows out (${fout.length})`, table(null, fcols("dst"), fout, { sort: "conns", short: true })), card(`Internal flows in (${fin.length})`, table(null, fcols("src"), fin, { sort: "conns", short: true }))));
  // security context
  const sigs = (raw.alerts?.signatures || []).filter((s) => s.src?.[ip] || s.dst?.[ip]).map((s) => ({ ...s, role: s.src?.[ip] ? "src" : "dst", here: s.src?.[ip] || s.dst?.[ip] }));
  const beacons = (raw.beacons?.candidates || []).filter((b) => b.src === ip);
  const viol = (an.violations || []).filter((v) => v.src === ip || v.dst === ip);
  const ti = (raw.threat_intel?.ip_hits_in || []).filter((t) => t.targets?.[ip]).concat((raw.threat_intel?.ip_hits_out || []).filter((t) => JSON.stringify(t).includes('"' + ip + '"')));
  const files = (raw.files?.files || []).filter((f) => f.receiver === ip || f.sender === ip);
  const sw = (raw.files?.software || []).filter((s) => s.ip === ip);
  const weird = (raw.weird || []).filter((w) => w.src?.[ip]).map((w) => ({ name: w.name, count: w.src[ip] }));
  const tun = (raw.dns_tunnel || []).filter((t) => t.sources?.[ip]);
  const sec = [];
  if (sigs.length) sec.push(card(`IDS alerts (${sigs.length})`, table(null, [{ k: "name", t: "Signature" }, { k: "severity", t: "Sev", num: true }, { k: "role", t: "Role" }, { k: "here", t: "Hits", num: true, fmt: fn }, { k: "last", t: "Last", fmt: ft }], sigs, { sort: "here", short: true })));
  if (viol.length) sec.push(card(`Segmentation violations (${viol.length})`, table(null, [{ k: "severity", t: "Sev", fmt: badge }, { k: "src", t: "Src", fmt: (v) => ipLink(v) }, { k: "dst", t: "Dst", fmt: (v) => ipLink(v) }, { k: "port", t: "Port" }, { k: "conns", t: "Conns", num: true, fmt: fn }, { k: "reason", t: "Reason", cls: "small" }], viol, { search: false })));
  if (beacons.length) sec.push(card("Beacon candidates", table(null, [{ k: "_piv", t: "", cls: "askcell", fmt: (v, b) => pivBtn("beacon", b) }, { k: "dst", t: "Dst", fmt: (v, b) => `${esc(v)} <span class="muted small">${esc(b.name || "")}</span>` }, { k: "port", t: "Port" }, { k: "interval_s", t: "Interval s", num: true }, { k: "jitter_s", t: "Jitter s", num: true }, { k: "conns", t: "Conns", num: true }, { k: "score", t: "Score", num: true }], beacons, { sort: "score", search: false })));
  if (ti.length) sec.push(card("Threat-intel matches", `<pre>${esc(JSON.stringify(ti, null, 1))}</pre>`));
  if (tun.length) sec.push(card("DNS-tunnel scoring", table(null, [{ k: "domain", t: "Domain" }, { k: "score", t: "Score", num: true }, { k: "queries", t: "Queries", num: true }, { k: "unique_subdomains", t: "Uniq subs", num: true }, { k: "entropy", t: "Entropy", num: true }], tun, { sort: "score", search: false })));
  if (files.length) sec.push(card(`Files transferred (${files.length})`, table(null, [{ k: "time", t: "Time", fmt: ft }, { k: "mime", t: "MIME" }, { k: "size", t: "Size", num: true, fmt: fb }, { k: "host", t: "Host" }, { k: "exec", t: "Exec", fmt: (v) => (v ? badge("high") : "") }, { k: "mhr_detect_pct", t: "MHR %", num: true }], files, { short: true })));
  if (sw.length) sec.push(card(`Software observed (${sw.length})`, table(null, [{ k: "name", t: "Name" }, { k: "version", t: "Version" }, { k: "type", t: "Type", cls: "small" }, { k: "unparsed", t: "Raw", cls: "small mono" }], sw, { short: true })));
  if (weird.length) sec.push(card("Zeek weird", kvTable(Object.fromEntries(weird.map((w) => [w.name, w.count])), "Name", "Count")));
  if (sec.length) { el.insertAdjacentHTML("beforeend", "<h3>Security context</h3>"); el.appendChild(grid("g2", ...sec)); }
  // endpoint telemetry
  for (const h of r.hosts) { el.insertAdjacentHTML("beforeend", `<h3>Endpoint telemetry · ${hostLink(h)}</h3>`); endpointSections(el, h); }
  const det = document.createElement("details"); det.innerHTML = `<summary>Raw JSON for this device</summary><pre>${esc(JSON.stringify({ device: d, tls, iot, registry: seen }, null, 1))}</pre>`; el.appendChild(det);
};

function historyChartForDevice(ip, mac) {
  const pts = S.hist.map((h) => ({ t: h.generated, d: h.devices?.[mac] || h.devices?.[ip] || Object.values(h.devices || {}).find((x) => x.ip === ip) })).filter((p) => p.d);
  if (!pts.length) return card("Across snapshots", `<div class="empty">No baseline history for this device yet.</div>`);
  return chartCard("Across snapshots (24h windows)", { type: "line", data: { labels: pts.map((p) => ft(p.t)), datasets: [
    { label: "sent", data: pts.map((p) => p.d.sent), borderColor: PALETTE[1], tension: 0.3 }, { label: "received", data: pts.map((p) => p.d.recv), borderColor: PALETTE[0], tension: 0.3 },
    { label: "internet up", data: pts.map((p) => p.d.ext_out), borderColor: PALETTE[3], borderDash: [4, 3], tension: 0.3 }] },
    options: { scales: { y: bytesAxis }, plugins: { tooltip: bytesTip } } });
}

/* ----- Endpoints ----- */
function endpointHosts() {
  const H = S.snap.raw.hosts || {}; const s = new Set();
  (H.fleet || []).forEach((f) => s.add(f.host)); Object.keys(H.telemetry || {}).forEach((h) => s.add(h)); Object.keys(H.syslog || {}).forEach((h) => s.add(h));
  return [...s];
}
function hostMatch(h, name) { const a = String(h || "").toLowerCase(), b = String(name || "").toLowerCase(); return a === b || a.split(".")[0] === b.split(".")[0]; }
V.endpoints = (el, arg) => {
  const H = S.snap.raw.hosts || {};
  const hq = new URLSearchParams(location.hash.split("?")[1] || "").get("host"); if (hq !== null) EP.host = hq; else if (!arg) EP.host = "";
  const kpiLink = (kind, v) => `<a href="#/endpoints/${kind}?host=" title="Click for details">${v} <span style="font-size:13px">›</span></a>`;
  el.innerHTML = `<h1>Endpoints</h1><div class="sub">Elastic Agent / Security Onion host telemetry (window ${ft(S.range.start)} – ${ft(S.range.end)}). Click a host for detail.</div>`;
  const hf = H.findings || [];
  const HF = ackSplit("host", hf, "ep-find"), hfo = HF.open;
  el.insertAdjacentHTML("beforeend", kpis([["Agents", (H.fleet || []).length], ["Open host findings", `<a href="#/security?to=sec-hostfind" title="Listed on Posture">${hfo.length} <span style="font-size:13px">›</span></a>`, hfo.length ? "warn" : "good"], ["Investigate (open)", hfo.filter((f) => /investigate/i.test(f.priority)).length, "bad"], ["Checked off", `<a href="#/checked">${HF.done.length}</a>`],
    ["Auth failures", kpiLink("authfail", (H.auth?.failures || []).reduce((s, f) => s + (f.count || 0), 0))], ["sudo events", kpiLink("sudo", (H.auth?.sudo || []).reduce((s, f) => s + (f.count || 0), 0))],
    ["Defend failures", kpiLink("defend", (H.defend || []).filter((d) => d.status !== "success").length), (H.defend || []).some((d) => d.status !== "success") ? "bad" : "good"]]));
  if (EP_KINDS[arg]) epDrill(arg, el);
  el.appendChild(card("Fleet", fleetTable()));
  const hosts = endpointHosts();
  const rows = hosts.map((h) => ({ host: h, ip: S.idx.hostIp[h] || "", findings: hfo.filter((f) => f.text?.toLowerCase().includes(h.toLowerCase()) || f.key?.toLowerCase().includes(h.toLowerCase())).length,
    syslog: entries(H.syslog?.[h]).reduce((s, [, v]) => s + (v.count || 0), 0), events: entries(H.telemetry?.[h]).reduce((s, [, v]) => s + (v.count || 0), 0), exec: H.exec_counts?.[h] ?? "" }));
  el.appendChild(grid("g2",
    card("Hosts", table(null, [{ k: "host", t: "Host", fmt: hostLink }, { k: "ip", t: "Network device", fmt: (v) => ipLink(v) }, { k: "findings", t: "Findings", num: true }, { k: "events", t: "Telemetry docs", num: true, bar: true, fmt: fn }, { k: "syslog", t: "Notable syslog", num: true, fmt: fn }, { k: "exec", t: "Execs", num: true }], rows, { sort: "findings", search: false, onclick: (r) => go("endpoint/" + r.host) })),
    chartCard("Telemetry volume by host", barCfg(rows.map((r) => r.host), rows.map((r) => r.events), { onClick: (i) => go("endpoint/" + rows[i].host) }))));
};
V.endpoint = (el, h) => {
  const ip = S.idx.hostIp[h];
  el.innerHTML = `<div class="crumbs"><a href="#/endpoints">Endpoints</a> › ${esc(h)}</div><h1>${esc(h)}</h1>${ip ? `<div class="sub">Network device: ${ipLink(ip)}</div>` : ""}`;
  const rk = (S.risk?.hosts || []).find((x) => (ip && x.ip === ip) || (!x.ip && hostMatch(x.id, h)));
  if (rk) el.appendChild(riskCard(rk));
  const emac = ip && S.idx.byIp[ip]?.mac ? "mac:" + String(S.idx.byIp[ip].mac).toLowerCase() : "";
  el.appendChild(kbCard(["host:" + String(h).toLowerCase().split(".")[0], emac, ip && "ip:" + ip], "host:" + String(h).toLowerCase().split(".")[0]));
  endpointSections(el, h);
};
function endpointSections(el, h) {
  const H = S.snap.raw.hosts || {};
  const f = (H.fleet || []).find((x) => hostMatch(x.host, h));
  const hf = (H.findings || []).filter((x) => (x.text + x.key).toLowerCase().includes(h.toLowerCase()));
  const cards = [];
  if (f) cards.push(card("Agent", `<div class="idgrid"><span class="k">Status</span><span>${badge(f.status)}</span><span class="k">Last check-in</span><span>${ft(f.last_checkin)} (${esc(f.minutes_since_checkin)} min)</span>
    <span class="k">Version</span><span>${esc(f.version)}</span><span class="k">Policy</span><span>${esc(f.policy)}</span><span class="k">Unhealthy reason</span><span>${esc(f.unhealthy_reason || "—")}</span>
    <span class="k">Bad components</span><span class="mono small">${esc(JSON.stringify(f.bad_components || []))}</span></div>`));
  const tel = H.telemetry?.[h];
  if (tel) cards.push(card("Telemetry streams", table(null, [{ k: "s", t: "Dataset" }, { k: "count", t: "Docs", num: true, bar: true, fmt: fn }, { k: "prev_window", t: "Prev window", num: true, fmt: fn }, { k: "last", t: "Last", fmt: ft }], entries(tel).map(([s, v]) => ({ s, ...v })), { sort: "count", search: false })));
  const dfd = (H.defend || []).filter((x) => hostMatch(x.host, h));
  for (const x of dfd) cards.push(card("Elastic Defend" + ` <a class="small" href="#/endpoints/defend?host=${encodeURIComponent(h)}">details ›</a>`, `<div>${badge(x.status)} at ${ft(x.at)}</div><div class="chips" style="margin:8px 0">${(x.failed_protections || []).map((p) => `<span class="chip">${esc(p)}</span>`).join("")}</div>` +
    (x.problems || []).map((p) => `<div class="small">${badge(p.status)} <b>${esc(p.action)}</b> — ${esc(p.message)}</div>`).join("")));
  if (hf.length) { const EF = ackSplit("host", hf, "epd-find-" + h);
    cards.push(card(`Findings (${EF.open.length} open)${EF.toggle}`, EF.show.length ? table(null, [ackCol("host", (x) => x.text), askCmpPivCol("host finding", (x) => x.text, "host finding"), { k: "priority", t: "Priority", fmt: badge, sort: (x) => sevRank(x.priority) }, { k: "text", t: "Finding", fmt: linkifyIps }], EF.show, { sort: "priority", dir: 1, short: true, rowClass: ackRowCls("host") }) : `<div class="empty">All findings for this host checked off.</div>`)); }
  const sl = H.syslog?.[h];
  if (sl) cards.push(card("Notable syslog", table(null, [{ k: "cat", t: "Category" }, { k: "sev", t: "Sev", fmt: badge }, { k: "count", t: "Count", num: true, fmt: fn }, { k: "last", t: "Last", fmt: ft }, { k: "sample", t: "Sample", cls: "mono small" }], entries(sl).map(([cat, v]) => ({ cat, ...v })), { sort: "count", search: false })));
  const au = H.auth || {};
  const logins = (au.logins || []).filter((x) => hostMatch(x.host, h)), fails = (au.failures || []).filter((x) => hostMatch(x.host, h)), sudo = (au.sudo || []).filter((x) => hostMatch(x.host, h));
  if (logins.length) cards.push(card("Logins", table(null, [{ k: "user", t: "User" }, { k: "src", t: "From", fmt: (v, r) => (zoneOf(v) && zoneOf(v) !== "internet" ? ipLink(v) : esc(v)) }, { k: "via", t: "Via" }, { k: "outcome", t: "Outcome", fmt: badge }, { k: "count", t: "Count", num: true }, { k: "last", t: "Last", fmt: ft }], logins, { search: false })));
  const more = (k) => ` <a class="small" href="#/endpoints/${k}?host=${encodeURIComponent(h)}">details ›</a>`;
  if (fails.length) cards.push(card("Auth failures" + more("authfail"), fails.map((x) => `<div class="idgrid"><span class="k">Count</span><span>${fn(x.count)}</span><span class="k">Sources</span><span>${entries(x.sources).map(([k, v]) => (k === "local" ? "local" : ipLink(k)) + " ×" + v).join(", ")}</span><span class="k">Users</span><span>${esc(entries(x.users).map(([k, v]) => k + " ×" + v).join(", "))}</span><span class="k">Processes</span><span>${esc(entries(x.processes).map(([k, v]) => k + " ×" + v).join(", "))}</span></div>`).join("<hr>")));
  if (sudo.length) cards.push(card("sudo" + more("sudo"), table(null, [{ k: "user", t: "User" }, { k: "as", t: "As" }, { k: "command", t: "Command", cls: "mono small" }, { k: "count", t: "Count", num: true }, { k: "error", t: "Error", cls: "small" }, { k: "last", t: "Last", fmt: ft }], sudo, { sort: "count", short: true })));
  const net = H.network?.hosts?.[h];
  if (net) cards.push(card("Network connections by process", table(null, [{ k: "proc", t: "Process", cls: "mono small" }, { k: "events", t: "Events", num: true, bar: true, fmt: fn }, { k: "ndst", t: "Destinations", num: true }, { k: "dsts", t: "Sample destinations", cls: "small", fmt: (v) => v.slice(0, 8).map((x) => ipLink(x, false)).join(", ") + (v.length > 8 ? " …" : "") }],
    entries(net).map(([proc, v]) => ({ proc, events: v.events, dsts: v.dst || [], ndst: (v.dst || []).length })), { sort: "events" }), "span"));
  const hs = S.reg.hosts_seen?.[h];
  if (hs) for (const [k, v] of entries(hs)) if (v && typeof v === "object") cards.push(card(`Baseline: ${esc(k)} (${Object.keys(v).length})`, table(null, [{ k: "x", t: k, cls: "mono small" }, { k: "d", t: "First seen" }], entries(v).map(([x, d]) => ({ x, d: typeof d === "object" ? JSON.stringify(d) : d })), { sort: "d", short: true })));
  if (!cards.length) cards.push(card("", `<div class="empty">No endpoint telemetry for ${esc(h)} in this time range.</div>`));
  el.appendChild(grid("g2", ...cards));
}

/* ----- Risk ranking ----- */
const RISK_COMP = [["exposure", "Exposure", 25, PALETTE[3]], ["weaknesses", "Weaknesses", 30, PALETTE[2]], ["threat", "Threat activity", 25, PALETTE[4]], ["reach", "Lateral reach", 10, PALETTE[5]], ["visibility", "Visibility gaps", 10, PALETTE[14]]];
const riskCls = (s) => (s >= 40 ? "sev-high" : s >= 20 ? "sev-medium" : s >= 8 ? "sev-low" : "sev-unknown");
const riskBadge = (s) => `<span class="badge ${riskCls(s)}">${(+s).toFixed(0)}</span>`;
function riskHostLink(h) {
  if (h.ip && S.snap?.raw?.devices?.[h.ip]) return `<a href="#/device/${encodeURIComponent(h.ip)}">${esc(h.name)}</a>`;
  const eh = endpointHosts().find((x) => hostMatch(x, h.id));
  return eh ? hostLink(eh) : esc(h.name);
}
function riskCard(rk) {
  const n = S.risk.hosts.length;
  return card(`Risk to the network: ${riskBadge(rk.score)} <span class="muted small">rank ${rk.rank} of ${n} · <a href="#/risk">all</a></span>`,
    `<div class="idgrid" style="margin-bottom:8px"><span class="k">Likelihood</span><span>${rk.likelihood} / 100</span><span class="k">Impact</span><span>${rk.impact} / 5 — ${esc(rk.impact_why)}</span></div>` +
    RISK_COMP.map(([k, l, mx, c]) => `<div style="display:grid;grid-template-columns:120px 1fr 50px;gap:8px;align-items:center;font-size:12px"><span class="k">${l}</span><div class="bar"><span style="width:${(100 * (rk.components[k] || 0)) / mx}%;background:${c}"></span></div><span class="num">${rk.components[k] || 0}/${mx}</span></div>`).join("") +
    (rk.drivers.length ? `<h3>Why</h3><ul class="small" style="margin:0;padding-left:18px">${rk.drivers.map((d) => `<li><span class="chip">${esc(d.type)}</span> ${linkifyIps(d.text)}</li>`).join("")}</ul>` : ""));
}
V.risk = (el) => {
  const R = S.risk;
  el.innerHTML = `<h1>Risk ranking</h1><div class="sub">Hosts and vulnerabilities ranked by the risk they pose to the whole network. <b>Host risk</b> = likelihood (exposure, weaknesses from the fix list, threat activity, lateral reach, visibility gaps) × impact (how much a compromise would hurt the network). <b>Vulnerability risk</b> = severity × kind × exposure of the affected host × recurrence. Recomputed for whichever snapshot is selected.</div>`;
  if (!R) { el.insertAdjacentHTML("beforeend", `<div class="empty">Risk data unavailable.</div>`); return; }
  const H = R.hosts, Vn = R.vulns;
  const top5 = H.slice(0, 5).reduce((s, h) => s + h.score, 0) / Math.max(1, Math.min(5, H.length));
  el.insertAdjacentHTML("beforeend", kpis([["Network risk index (top-5 avg)", top5.toFixed(0), top5 >= 40 ? "bad" : top5 >= 20 ? "warn" : "good"],
    ["High-risk hosts (≥40)", H.filter((h) => h.score >= 40).length, H.some((h) => h.score >= 40) ? "bad" : "good"], ["Medium-risk hosts (20–40)", H.filter((h) => h.score >= 20 && h.score < 40).length, "warn"],
    ["Hosts scored", H.length], ["Critical vulns (≥60)", Vn.filter((v) => v.score >= 60).length, Vn.some((v) => v.score >= 60) ? "bad" : "good"], ["Open vulns", Vn.length]]));
  const th = H.slice(0, 15);
  el.appendChild(grid("g2",
    chartCard("Top 15 hosts — risk by component (impact-weighted, click to drill down)", { type: "bar", data: { labels: th.map((h) => h.name),
      datasets: RISK_COMP.map(([k, l, , c]) => ({ label: l, data: th.map((h) => +(((h.components[k] || 0) * h.impact) / 5).toFixed(1)), backgroundColor: c })) },
      options: { indexAxis: "y", scales: { x: { stacked: true, max: 100 }, y: { stacked: true, ticks: { autoSkip: false, font: { size: 11 } } } },
        onClick: (e, els) => { if (!els.length) return; const h = th[els[0].index]; location.hash = riskHostLink(h).match(/href="([^"]+)"/)?.[1] || "#/risk"; },
        onHover: (e, els) => (e.native.target.style.cursor = els.length ? "pointer" : "default") } }, "", "tall"),
    chartCard("Likelihood × impact (bubble size = open vulns)", { type: "bubble", data: { datasets: [{ label: "hosts", data: H.map((h) => ({ x: h.likelihood, y: h.impact + (Math.random() - 0.5) * 0.3, r: 4 + Math.min(14, 2 * h.vulns), h })),
      backgroundColor: H.map((h) => (h.score >= 40 ? "#f85149aa" : h.score >= 20 ? "#d29922aa" : "#58a6ff88")) }] },
      options: { plugins: { legend: { display: false }, tooltip: { callbacks: { label: (c) => `${c.raw.h.name}: risk ${c.raw.h.score} (L ${c.raw.h.likelihood}, I ${c.raw.h.impact})` } } },
        scales: { x: { title: { display: true, text: "likelihood" }, min: 0, max: 100 }, y: { title: { display: true, text: "impact" }, min: 0.5, max: 5.5, ticks: { stepSize: 1 } } },
        onClick: (e, els) => { if (!els.length) return; const h = H[els[0].index]; location.hash = riskHostLink(h).match(/href="([^"]+)"/)?.[1] || "#/risk"; } } }, "", "tall")));
  el.appendChild(card(`Hosts ranked by risk (${H.length})`, table(null, [
    askCol("risky host", (h) => `${h.name}${h.ip ? " (" + h.ip + ")" : ""}, risk ${h.score}`), { k: "rank", t: "#", num: true }, { k: "name", t: "Host", fmt: (v, h) => riskHostLink(h) + (h.ip ? ` <span class="muted small">${esc(h.ip)}</span>` : "") },
    { k: "score", t: "Risk", num: true, bar: true, fmt: riskBadge }, { k: "likelihood", t: "Likelihood", num: true }, { k: "impact", t: "Impact", num: true, fmt: (v, h) => `<span title="${esc(h.impact_why)}">${v}</span>` },
    { k: "zone", t: "Zone" }, { k: "class", t: "Class" }, { k: "vulns", t: "Vulns", num: true },
    { k: "drivers", t: "Top drivers", cls: "small", fmt: (v) => v.slice(0, 3).map((d) => `<span class="chip">${esc(d.type)}</span> ${esc(d.text)}`).join("<br>"), sort: (h) => h.drivers.length },
  ], H, { sort: "score", limit: 30 })));
  const tv = Vn.slice(0, 15);
  el.appendChild(chartCard("Top 15 vulnerabilities by risk (click to drill down)", barCfg(tv.map((v) => `${v.title.slice(0, 50)} — ${String(v.target).slice(0, 22)}`), tv.map((v) => v.score), { color: tv.map((v) => (v.score >= 60 ? "#f85149" : v.score >= 30 ? "#d29922" : "#58a6ff")), onClick: (i) => drill("risk", { vuln: tv[i].title, where: tv[i].target }) }), "", "tall"));
  const VA = ackSplit("issue", Vn, "risk-vulns");
  el.appendChild(card(`Vulnerabilities ranked by risk (${VA.open.length})${VA.toggle}`, table(null, [
    ackCol("issue", (x) => `${x.title} — ${x.target || ""}`), askCol("vulnerability", (x) => `${x.title} — ${x.target || ""}`), { k: "rank", t: "#", num: true }, { k: "score", t: "Risk", num: true, bar: true, fmt: riskBadge }, { k: "severity", t: "Sev", fmt: badge, sort: (v) => sevRank(v.severity) },
    { k: "title", t: "Vulnerability", fmt: (v, x) => `<b>${esc(v)}</b><br><span class="muted small">${esc(x.category)} · seen ${x.occurrences}×${x.recurring ? " · recurring" : ""}</span>` },
    { k: "target", t: "Where", fmt: (v, x) => issueTarget(x) },
    { k: "drivers", t: "Score drivers", cls: "small", fmt: (v) => esc(v.join(" · ")), sort: (x) => x.score },
    { k: "fix", t: "How to fix", cls: "small", fmt: (v, x) => `${esc(v)}<details><summary>evidence</summary><span class="mono">${linkifyIps(x.evidence)}</span></details>` },
  ], VA.show, { sort: "score", limit: 40, rowClass: ackRowCls("issue"), urlFilter: ISSUE_FILTERS, evId: (x) => x.key && `iss|${x.key}` })));
  el.appendChild(card("Scoring model", `<div class="small"><p><b>Host likelihood</b> (0–100) = exposure (≤25: internet-facing services, threat-listed probes, DMZ) + weaknesses (≤30: combined fix-list items on the host) + threat activity (≤25: behaviour anomalies, non-benign IDS alerts, beacons, threat-intel contacts) + lateral reach (≤10: other zones reached, policy violations) + visibility gaps (≤10: unknown device, missing/degraded EDR, DNS bypass).</p>
    <p><b>Impact</b> (1–5): the sensor, the gateway and the crown-jewel hosts configured in site.json = 5; servers/AI = 5; k8s and work machines = 4; personal devices, DMZ = 3; IoT, cameras, media, consoles = 2. Score = likelihood × impact / 5.</p>
    <p><b>Vulnerability</b> = severity base (high ${R.model.sev_base.high}, medium ${R.model.sev_base.medium}, low ${R.model.sev_base.low}) × kind factor × host exposure (internet-facing 1.4, DMZ 1.3, server 1.15) × recurrence (+8% per repeat, max +40%). Weights live in <span class="mono">dashboard/app/risk.py</span>.</p></div>`));
};

/* ----- Recurring issues / fix list ----- */
const ISSUE_FILTERS = { severity: ["Severity", (x, v) => eqi(x.severity, v)], category: ["Category", (x, v) => eqi(x.category, v)],
  vuln: ["Vulnerability", (x, v) => eqi(x.title, v)], where: ["Where", (x, v) => eqi(x.target, v)] };
function issueTarget(x) {
  if (x.ip && S.snap?.raw?.devices?.[x.ip]) return `<a href="#/device/${encodeURIComponent(x.ip)}">${esc(x.target)}</a>`;
  if (x.host && endpointHosts().some((h) => hostMatch(h, x.host))) return hostLink(endpointHosts().find((h) => hostMatch(h, x.host)));
  return esc(x.target || x.host || x.ip);
}
function issueTable(rows, opts = {}) {
  const fixedMode = opts.fixed;
  const cols = [
    ...(fixedMode ? [] : [ackCol("issue", (x) => `${x.title} — ${x.target || ""}`)]),
    askCol((x) => (/vulnerab/i.test(x.category || "") ? "vulnerability" : (x.category || "vulnerability").toLowerCase()), (x) => `${x.title} — ${x.target || ""}`),
    { k: "severity", t: "Sev", fmt: badge, sort: (x) => sevRank(x.severity) },
    { k: "title", t: "Issue", fmt: (v, x) => `<b>${esc(v)}</b><br><span class="muted small">${esc(x.category)}</span>` },
    { k: "target", t: "Where", fmt: (v, x) => issueTarget(x) },
    { k: "occurrences", t: "Seen", num: true, fmt: (v, x) => `${v}/${x.checked}`, sort: (x) => x.occurrences },
    { k: "first_seen", t: "First seen", fmt: ft },
    fixedMode ? { k: "fixed_at", t: "Fixed (gone since)", fmt: ft } : { k: "last_seen", t: "Last seen", fmt: (v, x) => ft(v) + (x.status !== "open" ? `<br><span class="badge sev-unknown">${esc(x.status.replace(/^open /, ""))}</span>` : "") },
    { k: "fix", t: fixedMode ? "What it was" : "How to fix", cls: "small", fmt: (v, x) => (fixedMode ? esc(x.evidence) : `${esc(v)}<details><summary>evidence</summary><span class="mono">${linkifyIps(x.evidence)}</span></details>`) },
  ];
  return table(null, cols, rows, { sort: "severity", dir: 1, rowClass: ackRowCls("issue"), ...(fixedMode ? {} : { evId: (x) => x.key && `iss|${x.key}` }), ...opts });
}
V.issues = (el) => {
  const I = S.issues;
  el.innerHTML = `<h1>Fix list</h1><div class="sub">Misconfigurations and security suggestions recomputed from all ${I ? I.snapshots : "?"} snapshots. An item is <b>recurring</b> once it shows up in ${I?.min_occurrences ?? 2}+ snapshots. When a later snapshot that could check it no longer finds it, it moves to <b>Fixed</b> on its own. Items whose device or data source was missing from the latest snapshot stay open and are marked "not re-checked".</div>`;
  if (!I) { el.insertAdjacentHTML("beforeend", `<div class="empty">Issue tracker unavailable.</div>`); return; }
  const allRec = I.open.filter((x) => x.recurring), allWatch = I.open.filter((x) => !x.recurring);
  const RA = ackSplit("issue", allRec, "iss-rec"), WA = ackSplit("issue", allWatch, "iss-new");
  const rec = RA.open, watch = WA.open;
  const by = (arr, f) => arr.reduce((o, x) => ((o[f(x)] = (o[f(x)] || 0) + 1), o), {});
  el.insertAdjacentHTML("beforeend", kpis([["Recurring open", rec.length, rec.length ? "warn" : "good"], ["High severity", rec.filter((x) => x.severity === "high").length, rec.some((x) => x.severity === "high") ? "bad" : "good"],
    ["Misconfigurations", rec.filter((x) => x.category === "Misconfiguration").length], ["Security suggestions", rec.filter((x) => x.category === "Security suggestion").length],
    ["New / seen once", watch.length], ["Fixed", I.fixed.length, "good"], ["Checked off", `<a href="#/checked">${RA.done.length + WA.done.length}</a>`]]));
  el.appendChild(grid("g3", chartCard("Recurring by severity", doughnutCfg(by(rec, (x) => x.severity), { onClick: (l) => drill("issues", { severity: l }) })), chartCard("Recurring by category", doughnutCfg(by(rec, (x) => x.category), { onClick: (l) => drill("issues", { category: l }) })),
    chartCard("Open vs fixed", { type: "bar", data: { labels: ["recurring", "new", "fixed"], datasets: [{ data: [rec.length, watch.length, I.fixed.length], backgroundColor: [PALETTE[2], PALETTE[0], PALETTE[1]], borderRadius: 3 }] }, options: { plugins: { legend: { display: false } }, ...clickable((i) => drill("issues", { at: ["iss-rec", "iss-new", "iss-fixed"][i] })) } }, "", "short")));
  const uf = { urlFilter: ISSUE_FILTERS };
  el.appendChild(card(`Recurring: fix these (${rec.length})${RA.toggle}`, issueTable(RA.show, uf))).id = "iss-rec";
  el.appendChild(card(`New / seen once (${watch.length}) <span class="muted small">— these move to the list above if they show up again</span>${WA.toggle}`, issueTable(WA.show, { short: true, ...uf }))).id = "iss-new";
  el.appendChild(card(`Fixed (${I.fixed.length})`, issueTable(I.fixed, { fixed: true, short: true, sort: "fixed_at", dir: -1, ...uf }))).id = "iss-fixed";
};

/* ----- Users ----- */
V.users = async (el) => {
  el.innerHTML = `<h1>Users</h1><div class="sub">Every account has a role. <b>Admin</b>: everything, including users, settings and AI models. <b>Network defender</b>: sees everything and can check off, annotate and ask about events, but can't change settings, users or models. <b>User</b>: sees only the alerts and events of the devices assigned to them. ${isAdmin() ? "" : "<b>Only admins can change accounts — this page is read-only for you.</b> "}Passwords are stored as salted scrypt hashes in <span class="mono">dashboard/state/users.json</span>; changing a password signs that user out everywhere. See <span class="mono">docs/ACCESS_CONTROL.md</span>.</div><div class="loading">Loading…</div>`;
  let U; try { U = await api("/api/users"); } catch (e) { el.querySelector(".loading").textContent = String(e); return; }
  el.querySelector(".loading").remove();
  const min = U.min_password || 10;
  const msg = (box, text, ok) => { box.innerHTML = `<div style="color:${ok ? "var(--good)" : "var(--bad)"};margin-top:8px">${esc(text)}</div>`; };
  const P = U.prefs || {}, CAT = U.devices || [], byId = Object.fromEntries(CAT.map((d) => [d.id, d]));
  const devCount = (n) => (P[n]?.mode === "some" ? P[n].devices.length : -1);
  const devSummary = (n) => { const p = P[n]; if (!p || p.mode !== "some") return '<span class="muted">All devices</span>';
    const names = p.devices.map((id) => byId[id]?.name || byId[id]?.ips?.[0] || id);
    return `<span title="${esc(names.join("\n"))}"><b>${names.length}</b> device${names.length === 1 ? "" : "s"}${names.length ? `: ${esc(names.slice(0, 3).join(", "))}${names.length > 3 ? "…" : ""}` : ""}</span>`; };
  const ROLE_OPTS = [["admin", "Admin"], ["defender", "Network defender"], ["user", "User"]], roleOf = Object.fromEntries(U.users.map((x) => [x.username, x.role]));
  const roleSel = (u) => isAdmin() && u.username !== U.me
    ? `<select data-role="${esc(u.username)}">${ROLE_OPTS.map(([v, t]) => `<option value="${v}" ${u.role === v ? "selected" : ""}>${t}</option>`).join("")}</select>`
    : `<b>${esc((ROLE_OPTS.find(([v]) => v === u.role) || [, u.role])[1])}</b>`;
  const list = card(`Accounts (${U.users.length})`, table(null, [
    { k: "username", t: "Username", fmt: (v) => `<b>${esc(v)}</b>${v === U.me ? ' <span class="badge sev-info">you</span>' : ""}` },
    { k: "role", t: "Role", fmt: (v, u) => roleSel(u) + (u.role === "user" && devCount(u.username) < 1 ? ' <span class="badge sev-medium" title="A User sees nothing until devices are assigned">no devices</span>' : "") },
    { k: "created", t: "Created", fmt: ft }, { k: "last_login", t: "Last sign-in", fmt: (v) => ft(v) || '<span class="muted">never</span>' }, { k: "pw_changed", t: "Password changed", fmt: ft },
    { k: "_d", t: "Assigned devices", sort: (u) => devCount(u.username), fmt: (v, u) => `${u.role === "user" && devCount(u.username) < 0 ? '<span class="muted">None</span>' : devSummary(u.username)}${isAdmin() ? ` <button data-dev="${esc(u.username)}" class="small">Assign…</button>` : ""}` },
    { k: "_a", t: "", fmt: (v, u) => !isAdmin() ? "" : `<button data-pw="${esc(u.username)}">${u.username === U.me ? "Change my password" : "Reset password"}</button> ${u.username === U.me ? "" : `<button data-del="${esc(u.username)}" style="border-color:#f8514955;color:var(--bad)">Delete</button>`}` },
  ], U.users, { search: false, sort: "username", dir: 1 }));
  const pwBox = document.createElement("div"); list.appendChild(pwBox);
  el.appendChild(list);
  list.addEventListener("change", async (e) => {
    const rs = e.target.closest("[data-role]"); if (!rs) return;
    const name = rs.dataset.role, role = rs.value;
    if (!confirm(`Change ${name}'s role to ${rs.selectedOptions[0].text}? It takes effect immediately.`)) { rs.value = roleOf[name]; return; }
    try { await apiPost("/api/users", { action: "role", username: name, role }); rerender(); } catch (x) { rs.value = roleOf[name]; msg(pwBox, x.message); }
  });
  list.addEventListener("click", async (e) => {
    const del = e.target.closest("[data-del]"), pw = e.target.closest("[data-pw]"), dv = e.target.closest("[data-dev]");
    if (dv) {
      const name = dv.dataset.dev, wrap = document.createElement("div"); wrap.style.marginTop = "12px";
      const close = () => (pwBox.innerHTML = "");
      const lim = roleOf[name] === "user";
      wrap.appendChild(devicePicker({ prefs: lim ? { mode: "some", devices: P[name]?.mode === "some" ? P[name].devices : [] } : (P[name] || { mode: "all", devices: [] }), devices: CAT, title: `Assign devices to ${name}`, someLabel: "Only the devices assigned below", cancel: close, noAll: lim,
        intro: lim ? `<b>${esc(name)}</b> is a <b>User</b>: these are the only devices whose alerts and events they can see, and the only ones they get push notifications for. They can't change this themselves.`
          : `The devices <b>${esc(name)}</b> is responsible for. They get push notifications and the 🔔 count only for these (applies on every browser/phone they enabled). Alerts not tied to a device go only to users on All devices. ${name === U.me ? "This is you; the same setting is on the Alerts page." : `${esc(name)} can still change it on their Alerts page.`} (They can still see everything — that's their role.)`,
        save: async (mode, devs) => { await apiPost("/api/users", { action: "devices", username: name, mode, devices: devs }); P[name] = { mode, devices: devs }; setTimeout(rerender, 900);
          return mode === "all" ? `Saved — ${name} gets every urgent alert.` : `Saved — ${devs.length} device${devs.length === 1 ? "" : "s"} assigned to ${name}.`; } }));
      pwBox.replaceChildren(wrap); wrap.scrollIntoView({ block: "nearest" }); return;
    }
    if (del) {
      const name = del.dataset.del; if (!confirm(`Delete user "${name}"? They will be signed out immediately.`)) return;
      try { await apiPost("/api/users", { action: "delete", username: name }); rerender(); } catch (x) { msg(pwBox, x.message); }
    }
    if (pw) {
      const name = pw.dataset.pw, self = name === U.me;
      if (self) { location.hash = "#/account"; return; }  // own password: self-service page (keeps this session)
      pwBox.innerHTML = `<form class="card" style="margin-top:12px;max-width:420px"><h2>${self ? "Change your password" : `Reset password for ${esc(name)}`}</h2>
        ${self ? `<input type="password" name="cur" placeholder="Current password" autocomplete="current-password" required style="width:100%;margin-bottom:8px">` : ""}
        <input type="password" name="p1" placeholder="New password (min ${min} chars)" autocomplete="new-password" minlength="${min}" required style="width:100%;margin-bottom:8px">
        <input type="password" name="p2" placeholder="Repeat new password" autocomplete="new-password" required style="width:100%;margin-bottom:8px">
        <button type="submit">Save password</button> <button type="button" data-cancel>Cancel</button><div class="out"></div></form>`;
      const f = pwBox.querySelector("form"); f.querySelector("input").focus();
      f.querySelector("[data-cancel]").onclick = () => (pwBox.innerHTML = "");
      f.onsubmit = async (ev) => {
        ev.preventDefault(); const out = f.querySelector(".out");
        if (f.p1.value !== f.p2.value) return msg(out, "Passwords don't match");
        try { await apiPost("/api/users", { action: "password", username: name, password: f.p1.value, current: self ? f.cur.value : "" });
          if (self) { msg(out, "Password changed. Signing you in again…", true); setTimeout(toLogin, 1200); } /* legacy path; self-service lives on #/account */ else { msg(out, `Password for ${name} reset. They've been signed out.`, true); setTimeout(rerender, 1500); }
        } catch (x) { msg(out, x.message); }
      };
    }
  });
  if (!isAdmin()) return;
  const add = card("Add user", `<form style="display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:8px;max-width:1000px;align-items:center">
    <input name="u" placeholder="Username" autocomplete="off" required pattern="[A-Za-z0-9._@\-]{2,40}" title="2-40 chars: letters, digits . _ @ -">
    <select name="role" title="Role">${ROLE_OPTS.map(([v, t]) => `<option value="${v}" ${v === "user" ? "selected" : ""}>${t}</option>`).join("")}</select>
    <input name="p1" type="password" placeholder="Password (min ${min} chars)" autocomplete="new-password" minlength="${min}" required>
    <input name="p2" type="password" placeholder="Repeat password" autocomplete="new-password" required>
    <button type="submit">Add user</button></form><div class="out"></div>`);
  el.appendChild(add);
  const af = add.querySelector("form");
  af.onsubmit = async (ev) => {
    ev.preventDefault(); const out = add.querySelector(".out");
    if (af.p1.value !== af.p2.value) return msg(out, "Passwords don't match");
    try { await apiPost("/api/users", { action: "add", username: af.u.value.trim(), password: af.p1.value, role: af.role.value });
      msg(out, `User ${af.u.value.trim()} added${af.role.value === "user" ? " — now assign their devices (Assign… in the list), they see nothing until you do" : ""}.`, true); setTimeout(rerender, af.role.value === "user" ? 2500 : 1000); } catch (x) { msg(out, x.message); }
  };
  el.appendChild(card("Locked out?", `<div class="small">On the dashboard host run <span class="mono">docker exec -it netmon-dashboard python /app/server.py set-password &lt;username&gt;</span> to set a password (or create the user) from the command line.</div>`));
};

/* ----- Checked-off items ----- */
/* ---------- cleared segmentation flows (a separate list, wherever segmentation is shown) ---------- */
function segClearedCard() {
  const C = entries(S.acks?.seg || {}); if (!C.length) return null;
  const raw = S.snap?.raw || {}, macIp = {}; entries(raw.devices || {}).forEach(([ip, d]) => d.mac && (macIp[String(d.mac).toLowerCase()] = ip));
  const viol = S.snap?.analysis?.violations || [];
  const rows = C.map(([k, a]) => { const [src, dst, port] = k.split("|"); const sip = src.includes(":") ? macIp[src] : src;
    const v = viol.find((x) => x.src === sip && x.dst === dst && String(x.port) === port);
    return { key: k, at: a.at, label: a.label || k, src: sip || src, dst, port, by: a.note || "", seen: v ? `${fn(v.conns)} conns in this time range` : "not seen in this time range", reason: v?.reason || "" }; });
  const c = card(`Cleared segmentation (${rows.length})`, `<div class="small muted" style="margin-bottom:6px">Flows you marked as expected. They are hidden from Posture, the Fix list and Risk, shown as allowed on Lateral movement, left out of correlation and the PDF report, and stay cleared on future snapshots. Uncheck to bring one back. To make it permanent for everyone (and the nightly analysis), add it to <span class="mono">policy.json</span> <span class="mono">allow</span>.</div>`);
  c.appendChild(table(null, [
    { k: "_ack", t: "✓", fmt: (v, r) => `<input type="checkbox" class="ack-cb" data-t="seg" data-k="${esc(r.key)}" data-l="${esc(r.label)}" checked title="Uncheck to bring it back">` },
    { k: "label", t: "Flow", fmt: (v, r) => `${esc(v)}<div class="small muted mono">${S.idx?.nameOf?.(r.src) ? esc(S.idx.nameOf(r.src)) + " " : ""}${esc(r.src)} → ${esc(r.dst)}:${esc(r.port)}</div>` },
    { k: "reason", t: "Why it was flagged", cls: "small" }, { k: "seen", t: "Activity", cls: "small" }, { k: "at", t: "Cleared", fmt: ft }], rows, { sort: "at", search: rows.length > 8 }));
  c.id = "seg-cleared"; return c;
}

V.checked = (el) => {
  el.innerHTML = `<h1>Checked off</h1><div class="sub">Everything you've checked off, newest first. Checked items are hidden from their lists; uncheck here (or use "show N checked" on any list) to bring them back. Saved on the dashboard host in the netmon SQLite store (<span class="mono">dashboard/state/netmon.db</span>), so it survives restarts and works from any browser.</div>`;
  // resolve current details where we can
  const tr = S.snap.triage || {}, an = S.snap.analysis || {}, I = S.issues || { open: [], fixed: [] };
  const lookup = { alarm: Object.fromEntries((tr.alarms || []).map((a) => [ACK.alarm(a), a])), finding: Object.fromEntries((an.findings || []).map((f) => [ACK.finding(f), f])),
    host: Object.fromEntries((S.snap.raw.hosts?.findings || []).map((f) => [f.key, f])),
    admin: S.lateral && S.lateral._snap === S.snap.id ? Object.fromEntries((S.lateral.admin || []).map((s) => [ACK.admin(s), s])) : {},
    issue: Object.fromEntries([...I.open.map((i) => [i.key, { ...i, _st: "open" }]), ...I.fixed.map((i) => [i.key, { ...i, _st: "fixed" }])]) };
  const rows = [];
  for (const [type, m] of entries(S.acks)) for (const [key, a] of entries(m)) {
    const cur = lookup[type]?.[key];
    rows.push({ type, key, at: a.at, label: a.label || key, note: a.note || "", cur, state: cur ? (cur._st === "fixed" ? "fixed" : "still present") : "not in this time range" });
  }
  rows.sort((a, b) => String(b.at).localeCompare(String(a.at)));
  el.insertAdjacentHTML("beforeend", kpis(Object.keys(ACK_LABEL).map((t) => [ACK_LABEL[t] + "s", rows.filter((r) => r.type === t).length])));
  const segC = segClearedCard(); if (segC) el.appendChild(segC);  // segmentation flows get their own section
  rows.splice(0, rows.length, ...rows.filter((r) => r.type !== "seg"));
  el.appendChild(card(`Checked items (${rows.length})`, table(null, [
    { k: "_ack", t: "✓", fmt: (v, r) => `<input type="checkbox" class="ack-cb" data-t="${r.type}" data-k="${esc(r.key)}" data-l="${esc(r.label)}" checked title="Uncheck to restore">` },
    { k: "at", t: "Checked", fmt: ft }, { k: "type", t: "Type", fmt: (v) => esc(ACK_LABEL[v] || v) }, { k: "label", t: "Item", fmt: (v, r) => linkifyIps(v) + (r.note.startsWith("auto-closed:") ? ` <span class="badge sev-info" title="${esc(r.note)}">auto-closed · ${esc((r.note.match(/AI verdict (\w+)/) || [])[1] || "AI")}</span>` : "") },
    { k: "state", t: "Status in selected time range", fmt: (v) => `<span class="badge ${v === "still present" ? "sev-medium" : v === "fixed" ? "sev-good" : "sev-unknown"}">${esc(v)}</span>` },
  ], rows, { sort: "at" })));
};

/* ----- Security ----- */
// triage research_notes: list of strings (schema), but tolerate a single string (paragraphs) or other junk
const researchNotes = (v) => (Array.isArray(v) ? v : typeof v === "string" ? v.split(/\n\s*\n|\n(?=\s*[-*•] )/) : [])
  .map((n) => (typeof n === "string" ? n : JSON.stringify(n)).replace(/^\s*[-*•]\s+/, "").trim()).filter(Boolean);
V.security = (el) => {
  const raw = S.snap.raw, an = S.snap.analysis || {}, tr = S.snap.triage || {}, ti = raw.threat_intel || {};
  el.innerHTML = `<h1>Posture</h1>`;
  { const to = new URLSearchParams(location.hash.split("?")[1] || "").get("to"); if (to) setTimeout(() => { const c = document.getElementById(to); if (!c) return; c.classList.remove("collapsed"); c.scrollIntoView({ block: "start" }); }, 50); }
  if (tr.summary) el.appendChild(card(`Triage summary ${trFlare()}`, linkifyIps(tr.summary)));
  if ((tr.alarms || []).length) { const A = ackSplit("alarm", tr.alarms, "sec-alarms");
    { const ac = card(`Triage alarms (${A.open.length} open) ${trFlare()}${A.toggle}`, alarmsHtml(A.show.slice().sort((a, b) => (acked("alarm", a) - acked("alarm", b)) || sevRank(a.priority) - sevRank(b.priority))) || `<div class="empty">All alarms checked off.</div>`); ac.id = "sec-alarms-card"; el.appendChild(ac); } }
  { const rn = researchNotes(tr.research_notes); if (rn.length) el.appendChild(card(`Research notes ${trFlare()}`, "<ul>" + rn.map((n) => `<li>${linkifyIps(n)} ${cmpBtn("triage research note", n, { note: n, triage_summary: tr.summary })}</li>`).join("") + "</ul>")); }
  const BF = ackSplit("finding", an.findings || [], "sec-find");
  el.appendChild(card(`Baseline findings (${BF.open.length} open)${BF.toggle}`, table(null, [ackCol("finding", (x) => `${x.kind}: ${x.detail}`), askCmpPivCol("baseline finding", (x) => `${x.kind}: ${x.detail}`, "baseline finding"), { k: "severity", t: "Severity", fmt: badge, sort: (x) => sevRank(x.severity) }, { k: "kind", t: "Kind" }, { k: "device", t: "Device", fmt: (v) => ipLink(v) }, { k: "detail", t: "Detail", fmt: linkifyIps }], BF.show, { filter: true, sort: "severity", dir: 1, rowClass: ackRowCls("finding"), evId: (x) => x.kind && `f|${x.kind}|${x.device || ""}|${x.detail || ""}`, onclick: (r) => r.device && S.snap.raw.devices?.[r.device] && go("device/" + r.device),
    urlFilter: { severity: ["Severity", (x, v) => eqi(x.severity, v)], kind: ["Kind", (x, v) => eqi(x.kind, v)], device: ["Device", (x, v) => eqi(x.device, v)] } })));
  { // endpoint / host findings (Elastic Agent, osquery, syslog); moved here from Endpoints
    const hf = (S.snap.raw.hosts || {}).findings || [];
    const HF = ackSplit("host", hf, "ep-find"), hfo = HF.open;
    const hc = card(`Host findings (${hfo.length} open)${HF.toggle}`, HF.show.length ? table(null, [ackCol("host", (x) => x.text), askCmpPivCol("host finding", (x) => x.text, "host finding"), { k: "priority", t: "Priority", fmt: badge, sort: (x) => sevRank(x.priority) }, { k: "text", t: "Finding", fmt: (v, x) => linkifyIps(v) + (acked("host", x) ? ` <span class="muted small">checked ${esc(ft(ackInfo("host", x).at))}</span>` : "") }], HF.show, { filter: true, sort: "priority", dir: 1, rowClass: ackRowCls("host"), evId: (x) => x.key && `hf|${x.key}` }) : `<div class="empty">All host findings checked off.</div>`);
    hc.id = "sec-hostfind"; el.appendChild(hc);
    if (HF.done.length) el.appendChild(card(`Host findings checked off (${HF.done.length})`, table(null, [ackCol("host", (x) => x.text), { k: "_at", t: "Checked", fmt: (v, x) => esc(ft(ackInfo("host", x)?.at)), sort: (x) => ackInfo("host", x)?.at || "" }, { k: "priority", t: "Priority", fmt: badge }, { k: "text", t: "Finding", fmt: linkifyIps }], HF.done, { sort: "_at", rowClass: ackRowCls("host"), search: false })));
  }
  const sigs = raw.alerts?.signatures || [];
  el.appendChild(grid("g2",
    chartCard("IDS signatures (top 15 by count)", barCfg(sigs.slice(0, 15).map((s) => s.name.slice(0, 60)), sigs.slice(0, 15).map((s) => s.count), { color: PALETTE[2], onClick: (i) => drill("security", { sig: sigs[i].name }) }), "", "tall"),
    chartCard("IDS alerts by category", doughnutCfg(sigs.reduce((o, s) => ((o[s.category] = (o[s.category] || 0) + s.count), o), {}), { onClick: (l) => drill("security", { category: l }) }))));
  el.appendChild(card(`IDS signatures (${sigs.length}, ${fn(raw.alerts?.total)} alerts)`, table(null, [askPivCol("IDS signature", (x) => x.name, "IDS signature"), { k: "name", t: "Signature" }, { k: "category", t: "Category", cls: "small" }, { k: "severity", t: "Sev", num: true }, { k: "count", t: "Count", num: true, bar: true, fmt: fn },
    { k: "src", t: "Sources", fmt: (v) => sortDesc(v).slice(0, 4).map(([k, n]) => ipLink(k) + " ×" + fn(n)).join("<br>"), sort: (r) => Object.keys(r.src || {}).join() }, { k: "dst", t: "Destinations", fmt: (v) => sortDesc(v).slice(0, 4).map(([k, n]) => ipLink(k) + " ×" + fn(n)).join("<br>"), sort: (r) => Object.keys(r.dst || {}).join() },
    { k: "dport", t: "Ports", fmt: (v) => esc((v || []).join(", ")) }, { k: "last", t: "Last", fmt: ft }], sigs, { filter: true, sort: "count", evId: (x) => x.name && `ids|${x.name}`, urlFilter: { sig: ["Signature", (x, v) => x.name === v], category: ["Category", (x, v) => eqi(x.category, v)] } })));
  const SV = ackSplit("violation", an.violations || [], "sec-viol");
  el.appendChild(grid("g2",
    card(`Segmentation violations (${SV.open.length} open)${SV.toggle}`, SV.show.length ? table(null, [{ k: "_ack", t: "Clear", sort: (x) => (acked("violation", x) ? 1 : 0),
      fmt: (v, x) => `<label class="seg-clr${acked("violation", x) ? " on" : ""}">${ackBox("violation", x, "")}<span>${acked("violation", x) ? "Cleared" : "Clear"}</span></label>` },
      askCol("segmentation violation", (x) => `${x.src} → ${x.dst}:${x.port} ${x.reason || ""}`), { k: "severity", t: "Sev", fmt: badge, sort: (x) => sevRank(x.severity) }, { k: "src", t: "Src", fmt: (v) => ipLink(v) }, { k: "dst", t: "Dst", fmt: (v) => ipLink(v) }, { k: "port", t: "Port" }, { k: "proto", t: "Proto" }, { k: "conns", t: "Conns", num: true, fmt: fn }, { k: "answered", t: "Ans", num: true, fmt: fn }, { k: "reason", t: "Reason", cls: "small" }], SV.show, { sort: "severity", dir: 1, rowClass: ackRowCls("violation") }) : `<div class="empty">All segmentation violations cleared. Use “show checked” in the card title to bring them back.</div>`),
    card(`Beacon candidates (${(raw.beacons?.candidates || []).length} of ${fn(raw.beacons?.pairs_scored)} pairs)`, table(null, [askPivCol("beacon", (b) => `${b.src} → ${b.dst}:${b.port} every ${b.interval_s}s`, "beacon"), { k: "src", t: "Src", fmt: (v) => ipLink(v) }, { k: "dst", t: "Dst", fmt: (v, b) => `${esc(v)}:${esc(b.port)}<br><span class="muted small">${esc(b.name || "")} ${esc(b.asn || "")}</span>` }, { k: "interval_s", t: "Every (s)", num: true }, { k: "jitter_s", t: "Jitter", num: true }, { k: "conns", t: "Conns", num: true }, { k: "coverage_h", t: "Hours", num: true }, { k: "score", t: "Score", num: true }], raw.beacons?.candidates || [], { sort: "score" }))));
  el.appendChild(grid("g3",
    (() => { const c = card("Threat-intel feeds", table(null, [{ k: "f", t: "Feed" }, { k: "s", t: "Status", cls: "small" }], entries(ti.feed_status).map(([f, s]) => ({ f, s })), { search: false }));
      c.insertAdjacentHTML("beforeend", `<div class="small muted" style="margin-top:6px">Indicators: ${entries(ti.feed_sizes).map(([k, v]) => esc(k) + " " + fn(v)).join(" · ")}</div>`); return c; })(),
    card(`Inbound hits from listed IPs (${(ti.ip_hits_in || []).length})`, table(null, [askCol("threat-intel hit", (x) => `inbound from listed IP ${x.ip}`), { k: "ip", t: "Source", cls: "mono" }, { k: "feeds", t: "Feeds", fmt: (v) => esc((v || []).join(", ")) }, { k: "conns", t: "Conns", num: true }, { k: "targets", t: "Targets", fmt: (v) => entries(v).map(([k, n]) => ipLink(k) + " ×" + n).join("<br>") }, { k: "ports", t: "Ports", fmt: (v) => esc((v || []).join(",")) }], ti.ip_hits_in || [], { search: false })),
    card("Outbound TI hits / newly-registered domains", table(null, [askCol("threat-intel hit", (x) => `outbound to ${x.domain || x.ip}`), { k: "domain", t: "Domain/IP", fmt: (v, r) => (v ? domFmt(v) : esc(r.ip)) }, { k: "age_days", t: "Age (d)", num: true }, { k: "queries", t: "Queries", num: true }, { k: "sources", t: "Sources", fmt: (v) => entries(v).map(([k, n]) => ipLink(k) + " ×" + n).join("<br>") }],
      [...(ti.ip_hits_out || []), ...(ti.domain_hits || []), ...(ti.new_domains || [])], { search: false }))));
  el.appendChild(grid("g2",
    card(`DNS-tunnel scoring (${(raw.dns_tunnel || []).length})`, table(null, [askCol("DNS-tunnel candidate", (x) => x.domain), { k: "domain", t: "Domain", fmt: domFmt }, { k: "score", t: "Score", num: true, bar: true }, { k: "queries", t: "Queries", num: true }, { k: "unique_subdomains", t: "Uniq subs", num: true }, { k: "entropy", t: "Entropy", num: true }, { k: "nxdomain", t: "NX", num: true }, { k: "sources", t: "Sources", fmt: (v) => entries(v).map(([k, n]) => ipLink(k) + " ×" + n).join("<br>") }], raw.dns_tunnel || [], { sort: "score" })),
    card("Malicious JA3 / internal scans / detections", `<h3>Malicious JA3</h3>` + ((raw.tls?.malicious_ja3 || []).map((m) => `<div class="small"><span class="mono">${esc(m.ja3)}</span> — ${esc(m.malware)} ×${fn(m.count)} from ${entries(m.sources).map(([k]) => ipLink(k)).join(", ")} → ${esc((m.servers || []).join(", "))}</div>`).join("") || '<div class="empty">none</div>') +
      `<h3>Internal scans</h3>` + ((raw.internal?.scans || []).map((s) => `<div class="small">${ipLink(s.src)}: ${fn(s.failed_conns)} failed conns to ${s.hosts} hosts / ${s.ports} ports (top ${esc((s.top_ports || []).join(", "))})</div>`).join("") || '<div class="empty">none</div>') +
      `<h3>SO detections</h3>` + ((raw.detections || []).map((d) => `<div class="small">${ft(d.time)} ${esc(d.rule)} ${esc(d.host || "")} ${esc(d.message || "")}</div>`).join("") || '<div class="empty">none</div>'))));
  el.appendChild(grid("g3",
    card("Zeek notices", table(null, [{ k: "note", t: "Notice" }, { k: "count", t: "Count", num: true, fmt: fn }], raw.notices || [], { search: false })),
    card("Zeek weird", table(null, [{ k: "name", t: "Name" }, { k: "count", t: "Count", num: true, bar: true, fmt: fn }, { k: "src", t: "Top sources", fmt: (v) => sortDesc(v).slice(0, 3).map(([k, n]) => ipLink(k) + " ×" + fn(n)).join("<br>") }], raw.weird || [], { filter: true, sort: "count", short: true })),
    card(`Files (${(raw.files?.files || []).length}, PE: ${fn(raw.files?.pe_count)})`, table(null, [{ k: "time", t: "Time", fmt: ft }, { k: "mime", t: "MIME", cls: "small" }, { k: "receiver", t: "Receiver", fmt: (v) => ipLink(v) }, { k: "host", t: "Host", cls: "small" }, { k: "size", t: "Size", num: true, fmt: fb }, { k: "mhr_detect_pct", t: "MHR%", num: true }], raw.files?.files || [], { short: true }))));
  el.appendChild(card(`Software inventory from traffic (${(raw.files?.software || []).length})`, table(null, [{ k: "ip", t: "Device", fmt: (v) => ipLink(v) }, { k: "name", t: "Name" }, { k: "version", t: "Version" }, { k: "type", t: "Type", cls: "small" }, { k: "unparsed", t: "Raw", cls: "mono small" }], raw.files?.software || [], { sort: "ip", dir: 1 })));
};

/* ----- Traffic ----- */
V.traffic = (el) => {
  const raw = S.snap.raw, rows = S.idx.rows;
  el.innerHTML = `<h1>Traffic map</h1>`;
  const agg = (field) => { const o = {}; for (const d of Object.values(raw.devices || {})) for (const [k, v] of entries(d[field])) o[k] = (o[k] || 0) + (typeof v === "object" ? v.bytes || 0 : v); return o; };
  const ctry = agg("countries"), asn = agg("asns"), proto = agg("protocols");
  const topAsn = sortDesc(asn).slice(0, 15);
  el.appendChild(grid("g2", topTalkersChart(20), chartCard("Internet upload by device (top 15)", (() => { const t = [...rows].sort((a, b) => b.ext_out - a.ext_out).slice(0, 15); return barCfg(t.map((r) => r.name || r.ip), t.map((r) => r.ext_out), { bytes: true, color: PALETTE[3], onClick: (i) => go("device/" + t[i].ip) }); })(), "", "tall")));
  el.appendChild(grid("g3", chartCard("Internet bytes by country", doughnutCfg(ctry, { bytes: true, onClick: (l) => drill("devices", { country: l }) })), chartCard("Top ASNs", barCfg(topAsn.map((x) => x[0]), topAsn.map((x) => x[1]), { bytes: true, color: PALETTE[4], onClick: (i) => drill("devices", { asn: topAsn[i][0] }) })), chartCard("Protocols", doughnutCfg(proto, { bytes: true, onClick: (l) => drill("devices", { proto: l }) }))));
  // zone matrix heatmap
  const M = raw.internal?.matrix || {}; const zs = [...new Set(Object.keys(M).flatMap((k) => k.split(" -> ")))].sort();
  const mx = Math.max(1, ...Object.values(M).map((v) => v.conns));
  let h = `<div class="tblwrap"><table class="heat"><thead><tr><th>from \\ to</th>${zs.map((z) => `<th class="num">${esc(z)}</th>`).join("")}</tr></thead><tbody>`;
  for (const a of zs) { h += `<tr><th>${esc(a)}</th>`; for (const b of zs) { const c = M[`${a} -> ${b}`]; const a2 = c ? 0.12 + 0.75 * Math.sqrt(c.conns / mx) : 0;
    h += `<td class="num" style="background:rgba(88,166,255,${a2})" title="${c ? esc(entries(c.ports).map(([p, n]) => p + ": " + n).join("\n")) : ""}">${c ? `${fn(c.conns)}<br><span class="small">${fb(c.bytes)}</span>` : ""}</td>`; } h += "</tr>"; }
  el.appendChild(card("Zone-to-zone matrix (conns / bytes; hover for top ports)", h + "</tbody></table></div>"));
  el.appendChild(card(`Internal flows (${(raw.internal?.flows || []).length})`, table(null, [{ k: "src", t: "From", fmt: (v) => ipLink(v) }, { k: "src_zone", t: "Zone" }, { k: "dst", t: "To", fmt: (v) => ipLink(v) }, { k: "dst_zone", t: "Zone" }, { k: "port", t: "Port", num: true }, { k: "proto", t: "Proto" }, { k: "service", t: "Svc" }, { k: "conns", t: "Conns", num: true, fmt: fn }, { k: "answered", t: "Answered", num: true, fmt: fn }, { k: "bytes", t: "Bytes", num: true, bar: true, fmt: fb }], raw.internal?.flows || [], { sort: "conns", limit: 100 })));
  el.appendChild(grid("g2", card("All ASNs", kvTable(asn, "ASN", "Bytes", fb)), card("All countries", kvTable(ctry, "Country", "Bytes", fb))));
};

/* ----- DNS & TLS ----- */
V.dns = (el) => {
  const raw = S.snap.raw, devs = raw.devices || {};
  el.innerHTML = `<h1>DNS &amp; TLS</h1>`;
  const agg = (f) => { const o = {}; for (const d of Object.values(devs)) for (const [k, v] of entries(d.dns?.[f])) o[k] = (o[k] || 0) + v; return o; };
  const dom = agg("top_domains"), nx = agg("nx_domains"), qt = agg("qtypes"), res = agg("resolvers"), tld = agg("tlds");
  const rows = S.idx.rows.filter((r) => r.dnsq);
  el.appendChild(grid("g2", chartCard("DNS queries by device (top 15)", (() => { const t = [...rows].sort((a, b) => b.dnsq - a.dnsq).slice(0, 15); return barCfg(t.map((r) => r.name || r.ip), t.map((r) => r.dnsq), { color: PALETTE[5], onClick: (i) => go("device/" + t[i].ip) }); })(), "", "tall"),
    chartCard("NXDOMAIN by device (top 15)", (() => { const t = [...rows].sort((a, b) => b.nx - a.nx).slice(0, 15); return barCfg(t.map((r) => r.name || r.ip), t.map((r) => r.nx), { color: PALETTE[3], onClick: (i) => go("device/" + t[i].ip) }); })(), "", "tall")));
  el.appendChild(grid("g3", card("Top domains (all devices)", kvTable(dom, "Domain", "Queries", fn, domFmt)), card("NXDOMAIN domains", kvTable(nx, "Domain", "Queries", fn, domFmt)), chartCard("Query types", doughnutCfg(qt, { onClick: (l) => drill("devices", { qtype: l }) }))));
  el.appendChild(grid("g2", card("Resolvers", kvTable(res, "Resolver", "Queries", fn, (k) => ipLink(k))), card("TLDs", kvTable(tld, "TLD", "Queries"))));
  const tls = raw.tls?.devices || {}; const ja4 = {}, ver = {};
  for (const t of Object.values(tls)) { for (const [k, v] of entries(t.ja4)) ja4[k] = (ja4[k] || 0) + v; for (const [k, v] of entries(t.versions)) ver[k] = (ver[k] || 0) + v; }
  const legacy = Object.entries(tls).map(([ip, t]) => ({ ip, legacy: entries(t.versions).filter(([k]) => !/TLSv13|TLSv12/.test(k)).reduce((s, [, v]) => s + v, 0), bad: (t.bad_certs || []).length, ja4n: Object.keys(t.ja4 || {}).length })).filter((x) => x.legacy || x.bad);
  tlsSection(el);
  el.appendChild(grid("g2", card(`JA4 client fingerprints (${fn(Object.keys(ja4).length)} distinct)`, kvTable(ja4, "JA4", "Conns", fn, (k) => `<span class="mono small">${esc(k)}</span>`)),
    card("Devices using legacy TLS or bad certs", table(null, [{ k: "ip", t: "Device", fmt: (v) => ipLink(v) }, { k: "legacy", t: "Legacy conns", num: true }, { k: "bad", t: "Bad certs", num: true }], legacy, { search: false }))));
};

/* ----- UniFi ----- */
// UniFi gateway data is shown inside other sections (no standalone page): flows/blocks on Traffic map,
// IPS/admin/events on Posture, client inventory gaps on Hosts. Health is on Overview and Network map.
const secHead = (id, title, sub = "") => { const h = document.createElement("div"); h.className = "sec-head"; h.id = id; h.innerHTML = `<h2>${title}</h2>${sub ? `<div class="sub">${sub}</div>` : ""}`; return h; };
function gatewayTraffic(el) {
  const U = S.snap.raw.unifi; if (!U) return; const fl = U.flows || {};
  el.appendChild(secHead("gateway", "Gateway (UniFi)", "Firewall flows and blocks seen by the UniFi gateway."));
  el.insertAdjacentHTML("beforeend", kpis([["Clients online", fn(U.clients?.online)], ["Known clients", fn(U.clients?.known_total)], ["Flows logged", fn(fl.total)], ["Blocked", fn(fl.actions?.blocked)]]));
  el.appendChild(grid("g3", card("Gateway health", unifiHealthHtml()), chartCard("Blocks by policy", doughnutCfg(fl.blocked_by_policy)), chartCard("Clients by network", doughnutCfg(U.clients?.by_network))));
  el.appendChild(grid("g2",
    card("Top blocked clients", table(null, [{ k: "client", t: "Client" }, { k: "count", t: "Blocks", num: true, bar: true, fmt: fn }, { k: "top_domains", t: "Top blocked domains", cls: "small", fmt: (v) => (v || []).map(([d, n]) => esc(d) + " ×" + n).join("<br>") }], fl.top_blocked_clients || [], { sort: "count", search: false })),
    card("Region blocks", table(null, [{ k: "client", t: "Client" }, { k: "dst", t: "Dst", cls: "mono" }, { k: "region", t: "Region" }, { k: "direction", t: "Dir" }, { k: "count", t: "Count", num: true, bar: true, fmt: fn }], fl.region_blocks || [], { sort: "count", short: true }))));
  if ((fl.risky || []).length) el.appendChild(card("Risky flows", `<pre>${esc(JSON.stringify(fl.risky, null, 1))}</pre>`));
}
// stable id of a UniFi gateway event (same format as correlate.gw_id)
const gwId = (g) => `gw|${g.time || ""}|${g.key || ""}|${g.src || ""}|${g.dst || ""}`;
function gatewaySecurity(el) {
  const U = S.snap.raw.unifi; if (!U) return; const ev = U.events || {}, st = U.settings || {};
  el.appendChild(secHead("gateway-security", "Gateway security (UniFi)", "IPS configuration, security events, admin sign-ins and config changes on the gateway."));
  el.insertAdjacentHTML("beforeend", kpis([["Security events", fn(ev.counts?.SECURITY)], ["Admin logins", (U.admin?.logins || []).length], ["Config changes", (U.admin?.changes || []).length], ["IPS mode", esc(st.ips_mode ?? "?")]]));
  const evrows = [...(ev.high_severity || []), ...(ev.threats || []), ...(ev.devices || []), ...(U.threats_30d || []).map((t) => ({ ...t, key: "30d" }))];
  const seen = new Set(); const uniq = evrows.filter((e) => { const k = e.time + e.message; if (seen.has(k)) return false; seen.add(k); return true; });
  el.appendChild(grid("g2",
    card("Gateway protection settings", `<div class="idgrid"><span class="k">IPS mode</span><span>${esc(st.ips_mode)}</span><span class="k">Categories</span><span>${esc(st.categories)}</span><span class="k">Protected nets</span><span>${esc((st.protected_networks || []).join(", "))}</span>
      <span class="k">Honeypot</span><span>${esc(st.honeypot_enabled)} ${esc(JSON.stringify(st.honeypots || []))}</span><span class="k">DNS filtering</span><span>${esc(st.dns_filtering)}</span><span class="k">Ad blocking nets</span><span>${esc(st.ad_blocking_networks)}</span>
      <span class="k">Endpoint scanning</span><span>${esc(st.endpoint_scanning)}</span><span class="k">DPI</span><span>${esc(st.dpi)}</span></div>`),
    card(`Gateway events (${uniq.length})`, table(null, [{ k: "_piv", t: "", cls: "askcell", fmt: (v, x) => pivBtn("gateway", x) }, { k: "time", t: "Time", fmt: ft }, { k: "severity", t: "Severity", fmt: badge, sort: (x) => sevRank(String(x.severity).toLowerCase()) }, { k: "key", t: "Type", cls: "small" }, { k: "message", t: "Message", fmt: linkifyIps }], uniq, { sort: "time", short: true, evId: (x) => (x.key === "30d" ? "" : gwId(x)) }))));
  el.appendChild(grid("g2",
    card("Gateway admin logins", table(null, [{ k: "time", t: "Time", fmt: ft }, { k: "admin", t: "Admin" }, { k: "ip", t: "From", cls: "mono" }, { k: "platform", t: "Platform" }, { k: "unexpected_source", t: "Unexpected", fmt: (v) => (v ? badge("high") : "") }], U.admin?.logins || [], { sort: "time", short: true })),
    card("Gateway config changes", table(null, [{ k: "time", t: "Time", fmt: ft }, { k: "actor", t: "Actor" }, { k: "section", t: "Section", cls: "small" }, { k: "object", t: "Object" }, { k: "operation", t: "Op" }], U.admin?.changes || [], { sort: "time", short: true }))));
}
function gatewayClients(el) {
  const U = S.snap.raw.unifi; if (!U) return; const ni = U.clients?.not_in_inventory || [], fs = U.clients?.first_seen_in_window || [];
  if (!ni.length && !fs.length) return;
  el.appendChild(grid("g2",
    card(`Gateway clients not in inventory (${ni.length})`, table(null, [{ k: "ip", t: "IP", fmt: (v) => ipLink(v) }, { k: "name", t: "Name" }, { k: "mac", t: "MAC", cls: "mono" }, { k: "network", t: "Network" }], ni, { search: false, short: true })),
    card(`Gateway clients first seen in window (${fs.length})`, table(null, [{ k: "mac", t: "MAC", cls: "mono" }, { k: "ip", t: "IP", fmt: (v) => (v ? ipLink(v) : "") }, { k: "name", t: "Name" }, { k: "first_seen", t: "First seen", fmt: ft }], fs, { search: false, short: true }))));
}
V.unifi = () => location.replace("#/traffic?at=gateway");  // old bookmarks

/* ----- History ----- */

// ---------- MITRE ATT&CK matrix ----------
V.attack = async (el, arg) => {
  el.innerHTML = `<h1>MITRE ATT&amp;CK coverage</h1><div class="sub">Every alert, finding, vulnerability and misconfiguration in this time range mapped to ATT&amp;CK Enterprise.
    <b>Observed</b> = behaviour seen (possible technique in use). <b>Exposure</b> = a weakness that enables the technique (nothing seen happening). Checked-off items are greyed.</div><div class="loading">Mapping…</div>`;
  let M;
  try { M = await api("/api/mitre?id=" + encodeURIComponent(S.snap.id)); } catch (e) { el.querySelector(".loading").textContent = "Mapping failed: " + e; return; }
  el.querySelector(".loading").remove();
  const T = M.techniques, sm = M.summary;
  el.insertAdjacentHTML("beforeend", kpis([["Techniques", sm.techniques], ["Observed", sm.observed, sm.observed ? "warn" : "good"], ["Exposure only", sm.exposure_only], ["Mapped items", sm.items], ["Unmapped", sm.unmapped, sm.unmapped ? "warn" : "good"], ["ATT&CK version", "v" + (M.version || "?")]]));
  const sel = arg && T[arg] ? arg : null;
  const cell = (id) => { const t = T[id]; const cls = t.open === 0 ? "att-done" : t.observed ? "att-obs" : "att-exp";
    return `<a class="att-cell ${cls}${sel === id ? " att-sel" : ""}" href="#/attack/${id}" title="${esc(t.name)} — ${t.observed} observed, ${t.exposure} exposure, ${t.open} open"><span class="mono">${id}</span><br>${esc(t.name)}<span class="att-n">${t.items.length}</span></a>`; };
  const cols = M.tactic_order.map((k) => { const tc = M.tactics[k]; return `<div class="att-col"><div class="att-h" title="${esc(tc.id || "")}">${esc(tc.name)}<br><span class="muted small">${tc.techniques.length || "—"}</span></div>${tc.techniques.map(cell).join("")}</div>`; }).join("");
  el.appendChild(card(`Matrix <span class="muted small"><span class="att-key att-obs"></span> observed <span class="att-key att-exp"></span> exposure only <span class="att-key att-done"></span> all checked off · click a technique</span>`, `<div class="att-matrix">${cols}</div>`));
  const rows = (sel ? T[sel].items : Object.values(T).flatMap((t) => t.items)).filter((v, i, a) => a.indexOf(v) === i)
    .map((it) => ({ ...it, _t: it.techniques.map((x) => `<a href="#/attack/${x}" class="mono">${x}</a>${T[x] ? " " + esc(T[x].name) : ""}`).join("<br>") }));
  const srcName = { ids: "Suricata IDS", detection: "SO / Defend detection", analysis: "Network baseline", host: "Endpoint", issue: "Fix list", unifi: "UniFi gateway", alarm: "Triage alarm" };
  const title = sel ? `<a href="${esc(T[sel].url)}" target="_blank" rel="noopener">${sel} ${esc(T[sel].name)} ↗</a> · ${esc(T[sel].tactics.join(", "))} · <a href="#/attack">clear</a> ${askBtn("ATT&CK technique", `${sel} ${T[sel].name}`, { id: sel, name: T[sel].name, tactics: T[sel].tactics, observed: T[sel].observed, exposure: T[sel].exposure, items: T[sel].items.slice(0, 12).map((i) => ({ relation: i.relation, title: i.title, who: i.who, severity: i.severity })) })}` : "All mapped items";
  el.appendChild(card(`${title} (${rows.length})`, table(null, [
    askCol("ATT&CK mapping", (r) => `${r.techniques.map((x) => x + (T[x] ? " " + T[x].name : "")).join(", ")}: ${r.title}`),
    { k: "relation", t: "Type", fmt: (v) => `<span class="badge ${v === "observed" ? "sev-high" : "sev-info"}">${v}</span>` },
    { k: "_t", t: "Technique(s)", fmt: (v) => v, sort: (r) => r.techniques[0] },
    { k: "source", t: "Source", fmt: (v, r) => esc(srcName[v] || v) + (r.native ? ' <span class="muted small">(rule metadata)</span>' : "") },
    { k: "title", t: "Item", fmt: (v, r) => `<span class="${r.acked ? "muted" : ""}" style="${r.acked ? "text-decoration:line-through" : ""}">${linkifyIps(v)}</span>${r.ref && r.source !== "host" ? `<div class="muted small">${esc(String(r.ref).slice(0, 160))}</div>` : ""}` },
    { k: "who", t: "Host / source", fmt: (v) => linkifyIps(v || "") },
    { k: "severity", t: "Sev", fmt: (v) => (v ? badge(v) : "") },
    { k: "count", t: "Count", num: true },
    { k: "why", t: "Why this technique", cls: "small" }], rows, { sort: "relation", dir: 1 })));
  if (M.unmapped.length) el.appendChild(card(`Not mapped (${M.unmapped.length}) <span class="muted small">— add a rule in netmon/mitre.py if these should map</span>`, table(null, [{ k: "source", t: "Source" }, { k: "ref", t: "Kind", cls: "mono small" }, { k: "title", t: "Item" }], M.unmapped, { short: true })));
};

function historyNetwork(el) {
  const H = S.hist; if (!H.length) return; const lab = H.map((h) => ft(h.generated));
  el.appendChild(secHead("trend", "Trend across snapshots", `${H.length} banked baseline snapshots (each a 24h window)${S.histInRange ? " inside the selected time range" : " — fewer than two inside the selected range, so all are shown"}.`));
  el.appendChild(grid("g2",
    chartCard("Total bytes per snapshot", { type: "line", data: { labels: lab, datasets: [{ label: "total", data: H.map((h) => Object.values(h.devices).reduce((s, d) => s + (d.total || 0), 0)), borderColor: PALETTE[0], tension: 0.3 }, { label: "internet up", data: H.map((h) => Object.values(h.devices).reduce((s, d) => s + (d.ext_out || 0), 0)), borderColor: PALETTE[3], tension: 0.3 }] }, options: { scales: { y: bytesAxis }, plugins: { tooltip: bytesTip } } }),
    chartCard("Hosts & connections per snapshot", { type: "bar", data: { labels: lab, datasets: [{ label: "hosts", data: H.map((h) => Object.keys(h.devices).length), backgroundColor: PALETTE[1], yAxisID: "y" }, { type: "line", label: "conns", data: H.map((h) => Object.values(h.devices).reduce((s, d) => s + (d.conns || 0), 0)), borderColor: PALETTE[2], yAxisID: "y1" }] }, options: { scales: { y1: { position: "right", grid: { display: false } } } } })));
}
function historyHosts(el) {
  const H = S.hist; if (!H.length) return; const lab = H.map((h) => ft(h.generated));
  el.appendChild(secHead("trend", "Host trends across snapshots", `${H.length} banked 24h baseline snapshots${S.histInRange ? " inside the selected time range" : " (all; fewer than two inside the selected range)"}.`));
  const keys = new Set(H.flatMap((h) => Object.keys(h.devices)));
  const series = [...keys].map((k) => { const pts = H.map((h) => h.devices[k]?.total || 0); const last = [...H].reverse().map((h) => h.devices[k]).find(Boolean) || {}; return { k, ip: last.ip, name: last.name || last.ip || k, pts, sum: pts.reduce((a, b) => a + b, 0), known: last.known }; }).sort((a, b) => b.sum - a.sum);
  const top = series.slice(0, 10);
  el.appendChild(chartCard("Top 10 hosts over time (total bytes, click a line to drill down)", { type: "line", data: { labels: lab, datasets: top.map((s, i) => ({ label: s.name, data: s.pts, borderColor: PALETTE[i % PALETTE.length], tension: 0.3 })) }, options: { scales: { y: bytesAxis }, plugins: { tooltip: bytesTip }, ...clickable((i, ds) => { const ip = top[ds]?.ip; if (ip && S.snap.raw.devices?.[ip]) go("device/" + ip); }) } }, "", "tall"));
  const spark = (pts) => { const m = Math.max(1, ...pts), w = 120, hh = 24; const p = pts.map((v, i) => `${(i * w) / Math.max(1, pts.length - 1)},${hh - (v / m) * (hh - 2) - 1}`).join(" "); return `<svg class="spark" width="${w}" height="${hh}"><polyline fill="none" stroke="#58a6ff" stroke-width="1.5" points="${p}"/></svg>`; };
  el.appendChild(card("Per-host trend", table(null, [{ k: "name", t: "Host", fmt: (v, r) => (r.ip && S.snap.raw.devices?.[r.ip] ? `<a href="#/device/${r.ip}">${esc(v)}</a>` : esc(v)) }, { k: "k", t: "Key", cls: "mono small" }, { k: "pts", t: "Trend", fmt: spark, sort: (r) => r.pts[r.pts.length - 1] - r.pts[0] }, { k: "last", t: "Latest", num: true, fmt: fb }, { k: "sum", t: "Sum", num: true, bar: true, fmt: fb }],
    series.map((s) => ({ ...s, last: s.pts[s.pts.length - 1] })), { sort: "sum", limit: 25 })));
}
V.history = () => location.replace("#/traffic?at=trend");  // old bookmarks
// attach the consolidated sections to their new homes
{ const sec = V.security, tr = V.traffic, dv = V.devices;
  V.security = (el, a) => { sec(el, a); gatewaySecurity(el); };
  V.traffic = (el, a) => { tr(el, a); gatewayTraffic(el); historyNetwork(el); };
  V.devices = (el, a) => { dv(el, a); gatewayClients(el); historyHosts(el); }; }

/* ---------- router ---------- */
function go(r) { location.hash = "#/" + r; }
// audit log: report each page the user opens (fire and forget; the server records user, time and route)
let _lastView = "";
function auditView(h) { if (h === _lastView) return; _lastView = h;
  fetch("/api/audit/view", { method: "POST", headers: { "Content-Type": "application/json", "X-Netmon": "1" }, body: JSON.stringify({ route: String(h).slice(0, 200) }) }).catch(() => {}); }
async function route(keep) {
  S.charts.forEach((c) => c.destroy()); S.charts = []; S._scrolled = false; S._noScroll = !!keep;
  if (S.pending?.size) { S._t = new Set(); S._order = []; }  // sections.js: record which not-yet-loaded sections each card reads
  let [view, ...rest] = (location.hash.replace(/^#\/?/, "").split("?")[0] || (isUserRole() ? "my" : "overview")).split("/");
  if (isUserRole() && !USER_VIEWS.has(view)) { view = "my"; rest = []; }
  const arg = decodeURIComponent(rest.join("/"));
  document.querySelectorAll("#nav a").forEach((a) => a.classList.toggle("active", a.dataset.r === view || (a.dataset.r + "s" === view + "s" && false) || (view === "device" && a.dataset.r === "devices") || (view === "endpoint" && a.dataset.r === "endpoints") || (view === "tls" && a.dataset.r === "dns")));
  document.querySelectorAll("#nav .ngroup").forEach((g) => { g.classList.toggle("active", !!g.querySelector("a.active")); g.classList.remove("open"); });
  const el = $("#main"); el.innerHTML = "";
  if (!keep) auditView(location.hash || "#/" + view);
  let p;
  try { p = (V[view] || V.overview)(el, arg); S._t = null; if (p && p.then) p.then(() => flushCharts(), () => {}); }  // async views queue charts after the first flush
  catch (e) { console.error(e); el.innerHTML = `<div class="card"><h2>Render error</h2><pre>${esc(e.stack || e)}</pre></div>`; }
  flushCharts(); if (!keep && !S._scrolled) window.scrollTo(0, 0);
  const at = !keep && hq().get("at"); if (at) setTimeout(() => document.getElementById(at)?.scrollIntoView({ block: "start" }), 0);
  if (p && p.then) await p.catch(() => {});  // let callers (rerender) know the view's own content is actually in the DOM
}

async function loadSnap(id) {
  $("#main").innerHTML = `<div class="loading">Loading ${id.startsWith("r") ? "time range" : "snapshot " + esc(id)}…</div>`;
  const [snap, hist, reg, iss, rsk, acks] = await Promise.all([api("/api/snapshot?id=" + encodeURIComponent(id)), api("/api/history"), api("/api/registry"), api("/api/issues").catch(() => null), api("/api/risk?id=" + encodeURIComponent(id)).catch(() => null), api("/api/acks").catch(() => ({}))]);
  S.acks = acks || {};
  S.snap = snap; S.reg = reg; S.issues = iss; S.risk = rsk;
  window.sectionsSetup?.(snap);  // a time range still being collected: placeholders + proxies, sections arrive after the first render
  // the time range: a collected range carries its own; a nightly snapshot covers generated - hours .. generated
  const gen = Date.parse(snap.raw.generated);
  S.range = snap.range ? { start: snap.range.start, end: snap.range.end } : { start: new Date(gen - (+snap.raw.hours || 24) * 36e5).toISOString(), end: new Date(gen).toISOString() };
  // trend charts: the baseline records inside the range when there are at least two, else all of them
  const rs = Date.parse(S.range.start), re = Date.parse(S.range.end) + 6e5, inR = hist.filter((h) => { const t = Date.parse(h.generated); return t >= rs && t <= re; });
  S.hist = inR.length >= 2 ? inR : hist; S.histInRange = inR.length >= 2;
  window.rangeLabel?.();
  const ic = $("#issueCount"); const nrec = (iss?.open || []).filter((x) => x.recurring).length;
  if (ic) { ic.textContent = nrec; ic.style.display = nrec ? "" : "none"; } _hnbi = null; window.sectionsBuildIndex ? window.sectionsBuildIndex() : buildIndex();
  $("#foot").textContent = snap.range
    ? `time range ${new Date(snap.range.start).toLocaleString()} – ${new Date(snap.range.end).toLocaleString()} (collected for this range) · alarms and AI triage from nightly report ${snap.base || "—"}`
    : `snapshot ${snap.id} · generated ${new Date(snap.raw.generated).toLocaleString()} · companions: ${["analysis", "triage", "briefing", "sources"].filter((c) => snap[c]).join(", ") || "none"}`;
  route();
  window.sectionsStart?.();
}
async function init() {
  try {  // site-specific names/IPs come from the server after login
    Object.assign(SITE, await api("/api/site")); Object.assign(HOST_IP_HINTS, SITE.host_ips || {});
    if (SITE.site_name) { document.querySelectorAll(".brand small").forEach((e) => (e.textContent = SITE.site_name)); document.title = "netmon · " + SITE.site_name; }
  } catch (_) { /* not signed in yet */ }
  S.me = await api("/api/me"); document.body.dataset.role = S.me.role;
  { const b = document.getElementById("userBox"); if (b && S.me.user) { b.innerHTML = `<a href="#/account" title="My account / change password">👤 ${esc(S.me.user)}</a> <span class="badge sev-info" title="Your access level">${esc(S.me.role_name || S.me.role)}</span> <button id="logout">Sign out</button>`;
    document.getElementById("logout").onclick = async () => { await apiPost("/api/logout", {}).catch(() => {}); location.href = "/login"; }; } }
  if (isUserRole()) {  // assigned-devices view only: no snapshot data is loaded (the server would refuse it anyway)
    $("#nav").innerHTML = `<a href="#/my" data-r="my">My devices</a><a href="#/alerts" data-r="alerts">Alerts <span class="alert-count badge sev-high" style="display:none"></span></a>`;
    document.querySelectorAll("header .snap").forEach((e) => e.id !== "userBox" && (e.style.display = "none"));
    $("#foot").textContent = "";
    return route();
  }
  if (!isAdmin()) document.querySelectorAll('#nav a[data-r="config"]').forEach((a) => (a.textContent = "Configuration (view)"));
  if (!isAdmin()) document.querySelectorAll("#nav a.admin-only").forEach((a) => a.remove());
  S.snaps = await api("/api/snapshots");
  // ⟳: newer nightly report available and the newest one was shown -> show the new one; otherwise reload the same range
  $("#reload").onclick = async () => { const wasLatest = S.snap?.id === S.snaps[S.snaps.length - 1]?.id; S.snaps = await api("/api/snapshots");
    if (wasLatest) return window.rangeSelectSnapshot(S.snaps[S.snaps.length - 1].id); loadSnap(S.snap.id); };
  if (!S.snaps.length) { $("#main").innerHTML = `<div class="loading">No snapshots found in netmon/data.</div>`; return; }
  await window.initRange();
}
window.addEventListener("hashchange", () => (S.snap || isUserRole() || location.hash.startsWith("#/users")) && route());

/* ----- My devices (User role): the events of the devices an admin assigned to this account ----- */
V.my = async (el) => {
  el.innerHTML = `<h1>My devices</h1><div class="sub">You can see the alerts and security events for the devices assigned to your account. Ask an admin if a device is missing.</div><div class="loading">Loading…</div>`;
  let M; try { M = await api("/api/my"); } catch (e) { el.querySelector(".loading").textContent = String(e.message || e); return; }
  el.querySelector(".loading").remove();
  if (!M.devices.length) { el.appendChild(card("No devices assigned", `<div class="empty">No devices are assigned to your account yet, so there is nothing to show. Ask an admin to assign your devices on the Users page.</div>`)); return; }
  el.appendChild(card(`Assigned devices (${M.devices.length})`, table(null, [{ k: "name", t: "Device", fmt: (v, d) => `<b>${esc(v || d.ips[0] || d.mac || d.id)}</b>${d.endpoint ? ' <span class="badge sev-info">endpoint</span>' : ""}` },
    { k: "ips", t: "IP", cls: "mono", fmt: (v) => esc((v || []).join(", ")) }, { k: "mac", t: "MAC", cls: "mono" }, { k: "last_seen", t: "Last seen", fmt: ft }], M.devices, { sort: "name", dir: 1, search: false })));
  const TY = { finding: "Finding", ids: "IDS", admin: "Admin login", host: "Endpoint", ti: "Threat intel", vuln: "Vulnerability", gw: "Gateway" };
  el.appendChild(card(`Security events (${M.events.length}) <span class="muted small">— snapshot ${esc(M.snapshot || "–")}</span>`, M.events.length ? table(null, [
    { k: "sev", t: "Severity", fmt: badge, sort: (x) => sevRank(x.sev) }, { k: "type", t: "Type", fmt: (v) => esc(TY[v] || v) },
    { k: "t0", t: "When", fmt: (v) => (v ? esc(new Date(v * 1000).toLocaleString()) : '<span class="muted">ongoing</span>'), sort: (x) => x.t0 || 0 },
    { k: "label", t: "Event", fmt: (v) => esc(v) }, { k: "ips", t: "Device", cls: "mono small", fmt: (v) => esc((v || []).join(", ")) },
    { k: "id", t: "Notes", sort: false, fmt: (v) => { const ns = M.unotes?.[v] || [], p = ns.some((x) => x.status === "pending");
      return `<button type="button" class="unote-btn${ns.length ? " has" : ""}" data-unote="${esc(v)}" title="Add a note for the network defenders">${ns.length ? `📝 ${ns.length}${p ? " ⏳" : ""}` : "📝"}</button>`; } }], M.events, { sort: "t0" })
    : `<div class="empty">No security events for your devices in the latest snapshot.</div>`));
  // kbnotes.js's 📝 popover reads S.corr: give it just this user's events and their own notes (a User never loads correlations)
  S.corr = { events: Object.fromEntries(M.events.map((e) => [e.id, e])), unotes: M.unotes || {} };
  if (M.events.length) el.appendChild(card("Notes on your events", `<div class="small">Click 📝 on an event to tell the network defenders what it was (for example "that was me setting up a new TV"). A defender or admin reviews each note (⏳ until then); the AI only reads notes they approve. You see only your own notes.</div>`));
  el.appendChild(card("Urgent alerts", `<div class="small">Urgent alerts for your devices are on the <a href="#/alerts">Alerts</a> page, where you can also turn on push notifications.</div>`));
};
init().catch((e) => ($("#main").innerHTML = `<div class="card"><h2>Failed to load</h2><pre>${esc(e.stack || e)}</pre></div>`));
