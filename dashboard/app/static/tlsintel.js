/* TLS / JA3 & certificates view + Threat intel view. Uses helpers from app.js. */
"use strict";

const CERT_SEV = (c, f) => {
  if (/expired|not yet valid|weak key|weak signature/.test(f)) return "high";
  if (f === "self-signed") return /CN=WebRTC/.test(c.subject) || Object.keys(c.clients || {}).length === 0 ? "info" : "medium";
  return "low";
};
const certCN = (dn) => (String(dn || "").split(",").find((p) => p.startsWith("CN=")) || "").slice(3) || dn || "";
const certFlags = (c) => (c.flags || []).map((f) => `<span class="badge sev-${CERT_SEV(c, f)}">${esc(f)}</span>`).join(" ") || '<span class="muted small">ok</span>';
const clientsHtml = (o, n = 4) => sortDesc(o).slice(0, n).map(([ip, k]) => `${ipLink(ip)} <span class="muted small">×${fn(k)}</span>`).join("<br>") + (Object.keys(o || {}).length > n ? `<br><span class="muted small">+${Object.keys(o).length - n} more</span>` : "");
const ja3Fmt = (h, mal) => `<span class="mono small">${esc(h)}</span>${mal ? ` <span class="badge sev-high" title="${esc(mal)}">SSLBL</span>` : ""}`;
const TLS = { sel: null, certFlag: "", ja3Rare: false };

// Rendered inside the DNS & TLS view (V.dns); #/tls deep-links there and scrolls to this section.
function tlsSection(el) {
  const T = S.snap.raw.tls || {};
  el.insertAdjacentHTML("beforeend", `<h1 id="tls-section" style="margin-top:28px;padding-top:14px;border-top:1px solid var(--border)">TLS: JA3 fingerprints &amp; certificates</h1><div class="sub">JA3 = TLS <b>client</b> fingerprint (which app/library opened the connection). JA3S = <b>server</b> response fingerprint. Certificates are every x509 cert Zeek saw in this window, matched to the internal clients that requested those names (SNI).</div>`);
  if (!T.ja3) { el.insertAdjacentHTML("beforeend", `<div class="card"><div class="empty">This snapshot predates JA3/certificate collection. Pick a newer snapshot — every nightly report from now on includes it.</div></div>`); return; }
  const certs = T.certs || [], val = T.validation || [];
  const hiCerts = certs.filter((c) => c.flags.some((f) => CERT_SEV(c, f) === "high"));
  const legacy = entries(T.versions).filter(([k]) => !/TLSv1[23]|DTLSv12/.test(k)).reduce((s, [, v]) => s + v, 0);
  el.insertAdjacentHTML("beforeend", kpis([["Distinct JA3 (clients)", fn(T.distinct_ja3)], ["Distinct JA3S (servers)", fn(T.distinct_ja3s)],
    ["Malicious JA3 (SSLBL)", (T.malicious_ja3 || []).length, (T.malicious_ja3 || []).length ? "bad" : "good"], ["Certificates seen", certs.length],
    ["Certs with serious flags", hiCerts.length, hiCerts.length ? "bad" : "good"], ["Cert validation failures", fn(val.reduce((s, v) => s + v.count, 0)), val.length ? "warn" : "good"],
    ["Legacy TLS sessions", fn(legacy), legacy ? "warn" : "good"]]));
  const selBox = document.createElement("div"); el.appendChild(selBox);
  const showSel = () => { selBox.innerHTML = ""; if (TLS.sel) selBox.appendChild(tlsDetail(TLS.sel, T)); };
  // charts
  const iss = {}; certs.forEach((c) => { const k = certCN(c.issuer) || "?"; iss[k] = (iss[k] || 0) + 1; });
  const keys = {}; certs.forEach((c) => { const k = `${(c.key_type || "?").toUpperCase()} ${c.key_length || ""}`; keys[k] = (keys[k] || 0) + 1; });
  const exp = { expired: 0, "<7d": 0, "<30d": 0, "<90d": 0, "<1y": 0, ">1y": 0 };
  const expBucket = (d) => (d == null ? null : d < 0 ? "expired" : d < 7 ? "<7d" : d < 30 ? "<30d" : d < 90 ? "<90d" : d < 365 ? "<1y" : ">1y");
  certs.forEach((c) => { const b = expBucket(c.days_left); if (b) exp[b]++; });
  const topIss = sortDesc(iss).slice(0, 10);
  el.appendChild(grid("g4", chartCard("TLS versions (sessions)", doughnutCfg(T.versions, { onClick: (l) => drill("devices", { tls: l }) })), chartCard("Certificate key types", doughnutCfg(keys, { onClick: (l) => drill("tls", { certkey: l }) })),
    chartCard("Certificates by days to expiry", barCfg(Object.keys(exp), Object.values(exp), { horizontal: false, color: Object.keys(exp).map((k) => (k === "expired" ? "#f85149" : k === "<7d" ? "#d29922" : "#58a6ff")), onClick: (i) => drill("tls", { expiry: Object.keys(exp)[i] }) })),
    chartCard("Top certificate issuers", barCfg(topIss.map((x) => x[0].slice(0, 32)), topIss.map((x) => x[1]), { color: PALETTE[4], onClick: (i) => drill("tls", { issuer: topIss[i][0] }) }))));
  if ((T.malicious_ja3 || []).length) {
    const mc = card(`Malicious JA3 matches (${T.malicious_ja3.length})`, `<div class="small muted" style="margin-bottom:6px">SSLBL lists JA3 hashes of malware TLS stacks. Old entries (pre-2022) commonly collide with legitimate libraries — check the SNI/destination before worrying.</div>`);
    mc.appendChild(table(null, [{ k: "ja3", t: "JA3", fmt: (v, r) => ja3Fmt(v, r.malware) }, { k: "malware", t: "Listed as" }, { k: "count", t: "Conns", num: true }, { k: "sources", t: "Clients", fmt: (v) => clientsHtml(v) }, { k: "servers", t: "SNI", fmt: (v) => esc((v || []).join(", ")) }, { k: "dsts", t: "Dst", cls: "mono small", fmt: (v) => esc((v || []).join(", ")) }], T.malicious_ja3, { search: false }));
    el.appendChild(mc);
  }
  // certs with problems + full cert table
  const flagSet = [...new Set(certs.flatMap((c) => c.flags))].sort();
  const cwrap = card(`Certificates (${certs.length})`, `<div class="tbltools"><label class="muted">Flag</label><select id="tlsFlag"><option value="">All</option><option value="__any">Any flag</option><option value="__high">Serious (expired / weak / not yet valid)</option>${flagSet.map((f) => `<option ${TLS.certFlag === f ? "selected" : ""}>${esc(f)}</option>`).join("")}</select></div>`);
  const ctab = document.createElement("div"); cwrap.appendChild(ctab);
  const drawCerts = () => {
    const f = TLS.certFlag;
    const rows = certs.filter((c) => !f || (f === "__any" ? c.flags.length : f === "__high" ? c.flags.some((x) => CERT_SEV(c, x) === "high") : c.flags.includes(f)));
    ctab.innerHTML = ""; ctab.appendChild(table(null, [
      { k: "flags", t: "Flags", fmt: (v, c) => certFlags(c), sort: (c) => -c.flags.reduce((s, f) => s + { high: 10, medium: 3, low: 1, info: 0 }[CERT_SEV(c, f)], 0) },
      { k: "subject", t: "Subject (CN)", fmt: (v, c) => `<b>${esc(certCN(v))}</b>${c.ca ? ' <span class="badge sev-info">CA</span>' : ""}` }, { k: "issuer", t: "Issuer", cls: "small", fmt: (v) => esc(certCN(v)) },
      { k: "key_length", t: "Key", fmt: (v, c) => esc(`${(c.key_type || "").toUpperCase()} ${v || ""}`) }, { k: "sig_alg", t: "Signature", cls: "small" },
      { k: "days_left", t: "Days left", num: true, fmt: (v) => (v == null ? "" : v < 0 ? `<b style="color:var(--bad)">${v}</b>` : v < 30 ? `<b style="color:var(--warn)">${v}</b>` : fn(v)) }, { k: "validity_days", t: "Validity (d)", num: true, fmt: fn },
      { k: "clients", t: "Internal clients", fmt: (v) => clientsHtml(v, 3), sort: (c) => Object.keys(c.clients || {}).length }, { k: "count", t: "Seen", num: true, fmt: fn },
    ], rows, { sort: "flags", dir: 1, limit: 60, urlFilter: { certkey: ["Key type", (c, v) => eqi(`${(c.key_type || "?").toUpperCase()} ${c.key_length || ""}`, v)], expiry: ["Expiry", (c, v) => expBucket(c.days_left) === v], issuer: ["Issuer", (c, v) => eqi(certCN(c.issuer) || "?", v)] }, onclick: (c) => { TLS.sel = { cert: c }; showSel(); selBox.scrollIntoView({ behavior: "smooth" }); } }));
  };
  el.appendChild(cwrap); drawCerts();
  cwrap.querySelector("#tlsFlag").value = TLS.certFlag;
  cwrap.querySelector("#tlsFlag").onchange = (e) => { TLS.certFlag = e.target.value; drawCerts(); };
  el.appendChild(card(`Certificate validation failures (${val.length})`, table(null, [
    { k: "status", t: "Status", fmt: (v) => `<span class="badge ${/expired|revoked|mismatch/i.test(v) ? "sev-high" : "sev-medium"}">${esc(v)}</span>` }, { k: "sni", t: "Server name", fmt: (v) => esc(v || "(no SNI)") },
    { k: "dst", t: "Destination", fmt: (v, r) => (r.internal ? ipLink(v) : `<span class="mono">${esc(v)}</span>`) }, { k: "clients", t: "Clients", fmt: (v) => clientsHtml(v), sort: (r) => Object.keys(r.clients).length },
    { k: "count", t: "Sessions", num: true, bar: true, fmt: fn }], val, { sort: "count", short: true })));
  // JA3 catalogue
  const jwrap = card(`JA3 client fingerprints (${fn(T.distinct_ja3)} distinct; showing busiest + single-client)`, `<div class="tbltools"><label><input type="checkbox" id="ja3Rare" ${TLS.ja3Rare ? "checked" : ""}> only fingerprints used by a single device (rare = more interesting)</label></div>`);
  const jtab = document.createElement("div"); jwrap.appendChild(jtab);
  const drawJa3 = () => {
    const rows = T.ja3.filter((j) => !TLS.ja3Rare || j.clients === 1);
    jtab.innerHTML = ""; jtab.appendChild(table(null, [
      { k: "ja3", t: "JA3", fmt: (v, r) => ja3Fmt(v, r.malware) }, { k: "count", t: "Conns", num: true, bar: true, fmt: fn }, { k: "clients", t: "Devices", num: true },
      { k: "sources", t: "Used by", fmt: (v) => clientsHtml(v, 3), sort: (r) => Object.keys(r.sources).join() }, { k: "servers", t: "Top server names", cls: "small", fmt: (v) => esc((v || []).slice(0, 4).join(", ")) },
      { k: "ja4", t: "JA4", cls: "mono small", fmt: (v) => esc((v || [])[0] || "") }, { k: "last", t: "Last seen", fmt: ft }], rows, { sort: "count", limit: 50, onclick: (j) => { TLS.sel = { ja3: j }; showSel(); selBox.scrollIntoView({ behavior: "smooth" }); } }));
  };
  el.appendChild(jwrap); drawJa3();
  jwrap.querySelector("#ja3Rare").onchange = (e) => { TLS.ja3Rare = e.target.checked; drawJa3(); };
  el.appendChild(grid("g2",
    card(`JA3S server fingerprints (${T.ja3s.length})`, table(null, [{ k: "ja3s", t: "JA3S", cls: "mono small" }, { k: "count", t: "Sessions", num: true, bar: true, fmt: fn }, { k: "servers", t: "Servers", num: true }, { k: "clients", t: "Clients", num: true },
      { k: "sni", t: "Example server names", cls: "small", fmt: (v) => esc((v || []).slice(0, 3).join(", ")) }, { k: "versions", t: "Ver", cls: "small", fmt: (v) => esc((v || []).join(", ")) }], T.ja3s, { sort: "count", short: true })),
    card("Cipher suites (sessions)", kvTable(T.ciphers, "Cipher", "Sessions"))));
  showSel();
}
V.tls = (el) => { V.dns(el); if (!S._scrolled) setTimeout(() => document.getElementById("tls-section")?.scrollIntoView(), 50); };

function tlsDetail(sel, T) {
  if (sel.cert) {
    const c = sel.cert;
    return card(`Certificate: ${esc(certCN(c.subject))} <a href="#" class="small" id="tlsClose">close</a>`, `<div class="idgrid">
      <span class="k">Flags</span><span>${certFlags(c)}</span><span class="k">Subject</span><span class="mono small">${esc(c.subject)}</span><span class="k">Issuer</span><span class="mono small">${esc(c.issuer)}</span>
      <span class="k">Valid</span><span>${ft(c.not_before * 1000)} → ${ft(c.not_after * 1000)} (${fn(c.validity_days)} days; ${c.days_left} left)</span>
      <span class="k">Key / signature</span><span>${esc((c.key_type || "").toUpperCase())} ${esc(c.key_length)} · ${esc(c.sig_alg)}</span><span class="k">CA cert</span><span>${c.ca ? "yes" : "no"}</span>
      <span class="k">SAN DNS</span><span class="small">${esc((c.san_dns || []).join(", ") || "—")}</span><span class="k">Matched server names</span><span class="small">${esc((c.sni || []).join(", ") || "—")}</span>
      <span class="k">Internal clients</span><span>${clientsHtml(c.clients, 8) || "—"}</span><span class="k">SHA-256</span><span class="mono small">${esc(c.sha256)}</span><span class="k">Serial</span><span class="mono small">${esc(c.serial)}</span>
      <span class="k">Seen</span><span>${fn(c.count)}× · ${ft(c.first)} → ${ft(c.last)}</span></div>`, "", (e) => e);
  }
  const j = sel.ja3, srv = T.ja3s.filter((s) => (s.ja3 || []).includes(j.ja3));
  return card(`JA3 ${esc(j.ja3)} <a href="#" class="small" id="tlsClose">close</a>`, `<div class="idgrid">
    <span class="k">Threat intel</span><span>${j.malware ? `<span class="badge sev-high">SSLBL: ${esc(j.malware)}</span>` : "not listed in SSLBL"}</span>
    <span class="k">Connections</span><span>${fn(j.count)} from ${j.clients} device(s) · ${ft(j.first)} → ${ft(j.last)}</span>
    <span class="k">Used by</span><span>${clientsHtml(j.sources, 10)}</span><span class="k">Server names</span><span class="small">${esc((j.servers || []).join(", "))}</span>
    <span class="k">Destinations</span><span class="mono small">${esc((j.dsts || []).join(", "))}</span><span class="k">JA4</span><span class="mono small">${esc((j.ja4 || []).join(", "))}</span>
    <span class="k">Server replies (JA3S)</span><span class="mono small">${esc(srv.map((s) => s.ja3s).join(", ") || "—")}</span></div>
    <div class="small muted" style="margin-top:6px">Look it up: <a href="https://sslbl.abuse.ch/ja3-fingerprints/${esc(j.ja3)}/" target="_blank" rel="noopener">SSLBL</a> · <a href="#/threatintel?q=${esc(j.ja3)}">threat-intel lookup</a></div>`);
}
document.addEventListener("click", (e) => { if (e.target.id === "tlsClose") { e.preventDefault(); TLS.sel = null; rerender(); } });

/* ---------------- Threat intel ---------------- */
const TI = { trend: null, feeds: null, q: "" };
V.threatintel = async (el, arg) => {
  const raw = S.snap.raw, ti = raw.threat_intel || {}, T = raw.tls || {};
  const qs = new URLSearchParams((location.hash.split("?")[1]) || ""); if (qs.get("q")) TI.q = qs.get("q");
  el.innerHTML = `<h1>Threat intelligence</h1><div class="sub">Feeds are downloaded by the nightly collector and matched against every DNS name, TLS server name, JA3 and internet IP seen in the window. Window: ${ft(S.range.start)} – ${ft(S.range.end)}.</div><div class="loading">Loading feeds…</div>`;
  try { [TI.feeds, TI.trend] = await Promise.all([api("/api/ti/feeds"), api("/api/ti/trend")]); } catch (e) { el.querySelector(".loading").textContent = String(e); return; }
  el.querySelector(".loading").remove();
  const sigs = raw.alerts?.signatures || [];
  const MAL = /trojan|malware|command and control|c2|exploit|botnet|coin|ransom|phish|compromised|attempted admin|attempted user|web application attack/i;
  const malSigs = sigs.filter((s) => MAL.test(`${s.category} ${s.name}`) || s.severity <= 1);
  const stale = TI.feeds.filter((f) => f.age_h == null || f.age_h > 26);
  const totalInd = TI.feeds.reduce((s, f) => s + f.entries, 0);
  const outHits = (ti.ip_hits_out || []).length + (ti.domain_hits || []).length;
  el.insertAdjacentHTML("beforeend", kpis([["Feeds healthy", `${TI.feeds.length - stale.length}/${TI.feeds.length}`, stale.length ? "warn" : "good"], ["Indicators loaded", fn(totalInd)],
    ["Outbound hits (C2/malware)", outHits, outHits ? "bad" : "good"], ["Inbound from listed IPs", (ti.ip_hits_in || []).length, (ti.ip_hits_in || []).length ? "warn" : "good"],
    ["Malicious JA3", (T.malicious_ja3 || []).length, (T.malicious_ja3 || []).length ? "warn" : "good"], ["Malware-class IDS alerts", fn(malSigs.reduce((s, x) => s + x.count, 0)), malSigs.length ? "warn" : "good"],
    ["Newly registered domains", (ti.new_domains || []).length, (ti.new_domains || []).length ? "warn" : ""], ["Beacon candidates", (raw.beacons?.candidates || []).length]]));
  // lookup
  const lk = card("Indicator lookup", `<form id="tiForm" class="tbltools"><input id="tiQ" placeholder="IP, domain or JA3 hash…" value="${esc(TI.q)}" style="flex:1"><button>Check</button></form><div id="tiRes"></div>`);
  el.appendChild(lk);
  const runLookup = async () => {
    const q = document.getElementById("tiQ").value.trim(); TI.q = q; const box = document.getElementById("tiRes"); if (!q) { box.innerHTML = ""; return; }
    box.innerHTML = '<div class="muted">Checking…</div>';
    const r = await api("/api/ti/lookup?q=" + encodeURIComponent(q)).catch((e) => ({ error: String(e) }));
    box.innerHTML = tiLookupHtml(q.toLowerCase(), r);
  };
  document.getElementById("tiForm").onsubmit = (e) => { e.preventDefault(); runLookup(); };
  if (TI.q) runLookup();
  // trend
  const tr = TI.trend || [];
  el.appendChild(grid("g2",
    chartCard("Threat-intel signals per snapshot", { type: "line", data: { labels: tr.map((r) => ft(r.generated)), datasets: [
      ["Inbound listed IPs", "in_ips", 3], ["Outbound IP hits", "out_ips", 0], ["Domain hits", "domains", 4], ["New domains", "new_domains", 2], ["Malicious JA3", "mal_ja3", 5], ["UniFi IPS threats", "unifi_threats", 1]]
      .map(([l, k, c]) => ({ label: l, data: tr.map((r) => r[k]), borderColor: PALETTE[c], backgroundColor: PALETTE[c], tension: 0.3 })) }, options: { scales: { y: { beginAtZero: true, ticks: { precision: 0 } } } } }),
    chartCard("Inbound connections from listed IPs, by target port", (() => { const o = {}, port = {}; (ti.ip_hits_in || []).forEach((h) => (h.ports || []).forEach((p) => { const k = `${p} → ${Object.keys(h.targets).map((t) => S.idx.nameOf(t) || t).join(",")}`; o[k] = (o[k] || 0) + h.conns; port[k] = p; })); const e = sortDesc(o).slice(0, 10); return barCfg(e.map((x) => x[0]), e.map((x) => x[1]), { color: PALETTE[3], onClick: (i) => drill("threatintel", { port: port[e[i][0]] }) }); })())));
  // feeds
  el.appendChild(card("Feeds", table(null, [{ k: "feed", t: "Feed", fmt: (v, f) => `<a href="${esc(f.url)}" target="_blank" rel="noopener">${esc(v)}</a>` }, { k: "kind", t: "Type" },
    { k: "serious", t: "Outbound hit means", fmt: (v) => (v ? '<span class="badge sev-high">malware / C2</span>' : '<span class="badge sev-low">scanner / reputation</span>') },
    { k: "entries", t: "Entries", num: true, bar: true, fmt: fn }, { k: "updated", t: "Updated", fmt: ft }, { k: "age_h", t: "Age (h)", num: true, fmt: (v) => (v == null ? '<span class="badge sev-high">missing</span>' : v > 26 ? `<b style="color:var(--warn)">${v}</b>` : v) }],
    TI.feeds, { search: false, sort: "entries" })));
  el.appendChild(grid("g2",
    card(`Outbound to listed IPs (${(ti.ip_hits_out || []).length})`, (ti.ip_hits_out || []).length ? table(null, [askCol("threat-intel hit", (x) => `outbound to listed IP ${x.ip}`), { k: "ip", t: "Destination", cls: "mono" }, { k: "feeds", t: "Feeds", fmt: (v) => esc((v || []).join(", ")) }, { k: "conns", t: "Conns", num: true }, { k: "bytes", t: "Bytes", num: true, fmt: fb }, { k: "sources", t: "Internal sources", fmt: (v) => clientsHtml(v) }], ti.ip_hits_out, { search: false, evId: (x) => `ti|out|${x.ip}` }) : `<div class="empty" style="color:var(--good)">None — no internal host talked to a listed malware/C2 IP.</div>`),
    card(`Listed domains / server names (${(ti.domain_hits || []).length})`, (ti.domain_hits || []).length ? table(null, [askCol("threat-intel hit", (x) => `listed domain ${x.domain}`), { k: "domain", t: "Domain", fmt: domFmt }, { k: "feeds", t: "Feeds", fmt: (v) => esc((v || []).join(", ")) }, { k: "queries", t: "Queries", num: true }, { k: "sources", t: "Internal sources", fmt: (v) => clientsHtml(v) }], ti.domain_hits, { search: false, evId: (x) => `ti|dom|${x.domain}` }) : `<div class="empty" style="color:var(--good)">None — no DNS lookup or TLS server name matched a malware/phishing domain feed.</div>`)));
  el.appendChild(card(`Inbound from listed IPs (${(ti.ip_hits_in || []).length})`, table(null, [askCol("threat-intel hit", (x) => `inbound from listed IP ${x.ip}`), { k: "ip", t: "Source", cls: "mono" }, { k: "feeds", t: "Feeds", fmt: (v) => esc((v || []).join(", ")) }, { k: "conns", t: "Conns", num: true, bar: true }, { k: "bytes", t: "Bytes", num: true, fmt: fb },
    { k: "targets", t: "Targets", fmt: (v) => clientsHtml(v) }, { k: "ports", t: "Ports", fmt: (v) => esc((v || []).join(", ")) }, { k: "_", t: "", fmt: (v, r) => `<a href="#" class="ti-q" data-q="${esc(r.ip)}">lookup</a>` }], ti.ip_hits_in || [], { sort: "conns", evId: (x) => `ti|in|${x.ip}`, urlFilter: { port: ["Target port", (r, v) => (r.ports || []).map(String).includes(String(v))] } })));
  el.appendChild(grid("g2",
    card(`Newly registered domains (${(ti.new_domains || []).length})`, `<div class="small muted" style="margin-bottom:6px">Domains under ~90 days old looked up from inside the network (RDAP, cached ${fn(ti.rdap?.known_age)} of ${fn(ti.rdap?.domains)} domains; ${fn(ti.rdap?.looked_up_now)} new lookups this run).</div>`)
      .appendChild(table(null, [{ k: "domain", t: "Domain", fmt: (v) => `<a href="#" class="ti-q" data-q="${esc(v)}">${esc(v)}</a>` }, { k: "registered", t: "Registered" }, { k: "age_days", t: "Age (d)", num: true }, { k: "queries", t: "Queries", num: true }, { k: "sources", t: "Who", fmt: (v) => clientsHtml(v) }], ti.new_domains || [], { search: false })).parentNode,
    card(`Malicious JA3 (${(T.malicious_ja3 || []).length})`, table(null, [{ k: "ja3", t: "JA3", fmt: (v) => `<a href="#" class="ti-q" data-q="${esc(v)}">${ja3Fmt(v)}</a>` }, { k: "malware", t: "Listed as", cls: "small" }, { k: "count", t: "Conns", num: true }, { k: "sources", t: "Clients", fmt: (v) => clientsHtml(v) }, { k: "servers", t: "SNI", cls: "small", fmt: (v) => esc((v || []).join(", ")) }], T.malicious_ja3 || [], { search: false }))));
  el.appendChild(card(`Malware / exploit-class IDS signatures (${malSigs.length})`, table(null, [{ k: "name", t: "Signature" }, { k: "category", t: "Category", cls: "small" }, { k: "severity", t: "Sev", num: true }, { k: "count", t: "Alerts", num: true, bar: true, fmt: fn },
    { k: "src", t: "Sources", fmt: (v) => clientsHtml(v, 3), sort: (r) => Object.keys(r.src || {}).length }, { k: "dst", t: "Destinations", fmt: (v) => clientsHtml(v, 3), sort: (r) => Object.keys(r.dst || {}).length }, { k: "last", t: "Last", fmt: ft },
    { k: "_", t: "Tuned benign?", fmt: (v, r) => { const kb = entries(S.reg.known_benign?.signatures).find(([k]) => r.name.toLowerCase().includes(k.toLowerCase())); return kb ? `<span class="badge sev-low" title="${esc(kb[1])}">yes</span>` : ""; } }], malSigs, { sort: "count" })));
  const u = raw.unifi || {}, uth = [...(u.events?.threats || []), ...(u.threats_30d || [])];
  const seen = new Set(); const uthU = uth.filter((t) => { const k = t.time + t.message; if (seen.has(k)) return false; seen.add(k); return true; });
  el.appendChild(grid("g2",
    card(`UniFi IPS / firewall threat events (${uthU.length})`, table(null, [{ k: "time", t: "Time", fmt: ft }, { k: "severity", t: "Sev", fmt: badge }, { k: "key", t: "Type", cls: "small" }, { k: "message", t: "Message", fmt: linkifyIps }], uthU, { sort: "time", short: true })),
    card(`Region blocks (${(u.flows?.region_blocks || []).length})`, table(null, [{ k: "client", t: "Client" }, { k: "dst", t: "Remote", cls: "mono" }, { k: "region", t: "Region" }, { k: "direction", t: "Dir" }, { k: "count", t: "Count", num: true, bar: true }], u.flows?.region_blocks || [], { sort: "count", short: true }))));
  const mhr = (raw.files?.files || []).filter((f) => f.mhr_detect_pct > 0);
  const tunAll = S.snap.analysis?.dns_tunnel || raw.dns_tunnel || [], tunS = tunAll.filter((t) => t.level && !t.benign), TS = ackSplit("dnstunnel", tunS, "ti-dnstun"), tun = TS.show;
  el.appendChild(grid("g2",
    card(`Files flagged by Team Cymru MHR (${mhr.length} of ${(raw.files?.files || []).length})`, mhr.length ? table(null, [{ k: "time", t: "Time", fmt: ft }, { k: "receiver", t: "Receiver", fmt: (v) => ipLink(v) }, { k: "mime", t: "MIME" }, { k: "host", t: "From" }, { k: "mhr_detect_pct", t: "AV %", num: true }, { k: "sha1", t: "SHA1", cls: "mono small" }], mhr, { search: false }) : `<div class="empty" style="color:var(--good)">No transferred file matched known-malware hashes.</div>`),
    card(`DNS-tunnel suspects (${TS.open.length} open of ${tunAll.length} scored)${TS.toggle}`, tun.length ? table(null, [ackCol("dnstunnel", (x) => `DNS tunnel score: ${x.domain}`), { k: "domain", t: "Domain" }, { k: "level", t: "Level", fmt: badge }, { k: "score", t: "Score", num: true }, { k: "queries", t: "Queries", num: true }, { k: "sources", t: "Sources", fmt: (v) => clientsHtml(v) }, pivotCol("DNS-tunnel domain")], tun, { search: false, rowClass: ackRowCls("dnstunnel") }) : `<div class="empty" style="color:var(--good)">None — ${tunAll.length} high-entropy domains were scored and all were cleared as benign (e.g. Team Cymru hash lookups, CDN names).</div>`)));
  el.addEventListener("click", (e) => { const a = e.target.closest(".ti-q"); if (!a) return; e.preventDefault(); document.getElementById("tiQ").value = a.dataset.q; runLookup(); lk.scrollIntoView({ behavior: "smooth" }); });
};

function tiLookupHtml(q, r) {
  if (r.error) return `<pre>${esc(r.error)}</pre>`;
  const raw = S.snap.raw, T = raw.tls || {}, ti = raw.threat_intel || {};
  const listed = (r.feeds || []).length;
  let h = `<div class="alarm ${listed ? "investigate" : "info"}"><div class="t">${listed ? badge("listed") : '<span class="badge sev-good">not listed</span>'} ${esc(r.q)} <span class="muted small">(${esc(r.type)})</span></div>`;
  if (listed) h += `<p>Feeds: ${r.feeds.map((f) => `<span class="chip">${esc(f)}</span>`).join(" ")}${r.matched && r.matched !== r.q ? ` — matched parent <b>${esc(r.matched)}</b>` : ""}${r.detail ? ` — ${esc(r.detail)}` : ""}</p>`;
  if (r.rdap) h += `<p><span class="k">Registered:</span> ${esc(r.rdap.registered)} (${esc(r.rdap.domain)})</p>`;
  if (r.private) h += `<p class="muted">Private address — internal. ${raw.devices?.[r.q] ? `<a href="#/device/${esc(r.q)}">Open device page</a>` : ""}</p>`;
  // sightings in this snapshot
  const sight = [];
  for (const [ip, d] of entries(raw.devices)) {
    if (r.type === "ip" && d.top_dst?.[r.q]) sight.push([ip, `top destination (${fb(d.top_dst[r.q])})`]);
    if (r.type === "domain") { const hit = entries(d.dns?.top_domains).find(([k]) => k === q || k.endsWith("." + q) || q.endsWith("." + k)); if (hit) sight.push([ip, `DNS ${hit[0]} ×${hit[1]}`]); }
    if (r.type === "ja3" && T.devices?.[ip]?.ja3?.[q]) sight.push([ip, `TLS client fingerprint ×${T.devices[ip].ja3[q]}`]);
  }
  if (r.type === "ja3") { const j = (T.ja3 || []).find((x) => x.ja3 === q); if (j) for (const [ip, n] of entries(j.sources)) if (!sight.some((s) => s[0] === ip)) sight.push([ip, `TLS client fingerprint ×${n}`]); }
  if (r.type === "ip") (ti.ip_hits_in || []).filter((x) => x.ip === q).forEach((x) => entries(x.targets).forEach(([t, n]) => sight.push([t, `inbound from it ×${n} (ports ${x.ports.join(",")})`])));
  if (r.type === "domain") (T.certs || []).filter((c) => (c.san_dns || []).some((s) => s === q || s.endsWith("." + q) || (s.startsWith("*.") && q.endsWith(s.slice(1))))).forEach((c) => entries(c.clients).forEach(([ip, n]) => sight.push([ip, `TLS cert ${certCN(c.subject)} ×${n}`])));
  h += sight.length ? `<p><span class="k">Seen in this time range:</span><br>${sight.slice(0, 15).map(([ip, w]) => `${ipLink(ip)} — ${esc(w)}`).join("<br>")}</p>` : `<p class="muted">Not seen in the selected time ranot's top destinations / DNS / TLS data.</p>`;
  const ext = r.type === "ip" ? `<a href="https://www.abuseipdb.com/check/${esc(r.q)}" target="_blank" rel="noopener">AbuseIPDB</a> · <a href="https://www.virustotal.com/gui/ip-address/${esc(r.q)}" target="_blank" rel="noopener">VirusTotal</a> · <a href="https://www.shodan.io/host/${esc(r.q)}" target="_blank" rel="noopener">Shodan</a>`
    : r.type === "domain" ? `<a href="https://www.virustotal.com/gui/domain/${esc(r.q)}" target="_blank" rel="noopener">VirusTotal</a> · <a href="https://urlhaus.abuse.ch/browse.php?search=${esc(r.q)}" target="_blank" rel="noopener">URLhaus</a> · <a href="https://threatfox.abuse.ch/browse.php?search=ioc%3A${esc(r.q)}" target="_blank" rel="noopener">ThreatFox</a>`
    : r.type === "ja3" ? `<a href="https://sslbl.abuse.ch/ja3-fingerprints/${esc(r.q)}/" target="_blank" rel="noopener">SSLBL</a>` : "";
  if (ext) h += `<p class="small">External (opens in a new tab, sends the indicator to that site): ${ext}</p>`;
  return h + "</div>";
}
