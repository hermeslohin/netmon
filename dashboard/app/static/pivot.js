// Pivot links: a 🔎 button on Security rows (baseline findings, IDS signatures, host findings, beacons, triage alarms,
// gateway events) that opens a popover of deep links into Kibana Discover - and, for gateway events, the UniFi web app.
// Base URLs come from /api/site (the site settings (More → Settings): kibana_url, kibana_data_view, unifi_web_url, unifi_paths); never hard-coded.
const PIV = new Map(); let pivSeq = 0;
function pivotBtn(kind, item) {
  if (!SITE.kibana_url && !(kind === "gateway" && SITE.unifi_web_url)) return "";
  const id = "p" + ++pivSeq; PIV.set(id, { kind, item });
  if (PIV.size > 4000) PIV.delete(PIV.keys().next().value);
  return `<button type="button" class="pivh" data-piv="${id}" title="Open the related events in Kibana${kind === "gateway" ? " / UniFi" : ""}" aria-label="Open related events">🔎</button>`;
}
const pivotCol = (kind) => ({ k: "_piv", t: "", cls: "askcell", fmt: (v, x) => pivotBtn(kind, x) });

(() => {
  const IP_RE = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g, DOM_RE = /\b[a-z0-9][a-z0-9.-]{1,200}\.[a-z]{2,12}\b/gi;  // domain-like tokens (single quantifier: no ReDoS)
  const COLS = { ids: ["rule.name", "source.ip", "destination.ip", "destination.port", "rule.category"],
    conn: ["source.ip", "destination.ip", "destination.port", "network.transport", "network.bytes", "connection.state"],
    dns: ["source.ip", "dns.query.name", "dns.answers.name", "dns.response_code"], ssl: ["source.ip", "destination.ip", "ssl.server_name"],
    host: ["host.name", "event.dataset", "message"], proc: ["host.name", "process.executable", "process.args", "user.name"],
    net: ["host.name", "process.executable", "destination.ip", "destination.port", "destination.domain"], file: ["host.name", "event.action", "file.path"],
    auth: ["host.name", "user.name", "source.ip", "event.outcome", "message"] };
  const rison = (s) => "'" + String(s).replace(/!/g, "!!").replace(/'/g, "!'") + "'";
  const q = (v) => '"' + String(v).replace(/\\/g, "\\\\").replace(/"/g, '\\"') + '"';
  const iso = (t) => new Date(t).toISOString();
  const uniq = (a) => [...new Set(a.filter(Boolean))];
  function win() {  // snapshot window: [generated - hours, generated] (or the item's own window, see open())
    if (window.__pivWin) return window.__pivWin;
    const r = S.snap?.raw || {}, end = Date.parse(r.generated) || Date.now(), h = Number(r.hours) || 24;
    return [end - h * 3600e3, end];
  }
  function span(a, b, padMin = 5) {  // item time span (padded), falling back to the snapshot window
    const [w0, w1] = win(), x = Date.parse(a), y = Date.parse(b || a);
    return [isNaN(x) ? w0 : x - padMin * 60e3, isNaN(y) ? w1 : y + padMin * 60e3];
  }
  function kb(kql, [from, to] = win(), cols) {
    const base = String(SITE.kibana_url || "").replace(/\/?$/, "/"), dv = SITE.kibana_data_view || "logs-*";
    const g = `(time:(from:${rison(iso(from))},to:${rison(iso(to))}))`;
    const a = `(${cols ? `columns:!(${cols.map(rison).join(",")}),` : ""}dataSource:(dataViewId:${rison(dv)},type:dataView),query:(language:kuery,query:${rison(kql)}),sort:!(!('@timestamp',desc)))`;
    return `${base}app/discover#/?_g=${encodeURIComponent(g)}&_a=${encodeURIComponent(a)}`;
  }
  const either = (ip) => `(source.ip:${q(ip)} or destination.ip:${q(ip)})`;
  const between = (a, b) => `((source.ip:${q(a)} and destination.ip:${q(b)}) or (source.ip:${q(b)} and destination.ip:${q(a)}))`;
  const hostQ = (h) => `(host.name:${q(h)} or host.hostname:${q(h)})`;
  const macIp = (m) => entries(S.snap?.raw?.devices || {}).find(([, d]) => String(d.mac || "").toLowerCase() === String(m).toLowerCase())?.[0];
  const label = (ip) => { const n = S.idx?.nameOf?.(ip); return n ? `${n} (${ip})` : ip; };
  function ipLinks(ip, t) {
    return [[`IDS alerts involving ${label(ip)}`, kb(`event.dataset:"suricata.alert" and ${either(ip)}`, t, COLS.ids)],
      [`Zeek connections of ${label(ip)}`, kb(`event.dataset:"zeek.conn" and ${either(ip)}`, t, COLS.conn)],
      [`All Zeek logs of ${label(ip)}`, kb(`event.module:"zeek" and ${either(ip)}`, t)]];
  }
  function hostLinks(h, t, extra) {
    const ip = S.idx?.hostIp?.[h] || HOST_IP_HINTS[h], L = [];
    if (extra) L.push(extra);
    L.push([`All endpoint / syslog events on ${h}`, kb(hostQ(h), t, COLS.host)]);
    if (ip) L.push(...ipLinks(ip, t).slice(0, 2));
    return L;
  }
  const textIps = (s) => uniq(String(s || "").match(IP_RE) || []).slice(0, 5);
  const knownHosts = (s) => { const t = String(s || "").toLowerCase(); return uniq(Object.keys({ ...HOST_IP_HINTS, ...(S.idx?.hostIp || {}) }).filter((h) => h.length > 3 && t.includes(h.toLowerCase()))).slice(0, 3); };
  function hfSpan(text) {  // "(10-17 18:49 to 10-17 18:53Z)" in host-finding text
    const m = String(text || "").match(/\((\d\d-\d\d \d\d:\d\d) to (\d\d-\d\d \d\d:\d\d)Z\)/); if (!m) return undefined;
    const y = String(S.snap?.raw?.generated || new Date().toISOString()).slice(0, 4), p = (s) => `${y}-${s.replace(" ", "T")}:00Z`;
    return span(p(m[1]), p(m[2]), 10);
  }

  const B = {
    "IDS signature": (x) => { const t = span(x.first, x.last), sig = `event.dataset:"suricata.alert" and rule.name:${q(x.name)}`;
      return [[`All "${x.name}" alerts`, kb(sig, t, COLS.ids)],
        ...sortDesc(x.src || {}).slice(0, 3).map(([ip, n]) => [`… from ${label(ip)} (×${fn(n)})`, kb(`${sig} and source.ip:${q(ip)}`, t, COLS.ids)]),
        ...sortDesc(x.dst || {}).slice(0, 3).map(([ip, n]) => [`… to ${label(ip)} (×${fn(n)})`, kb(`${sig} and destination.ip:${q(ip)}`, t, COLS.ids)])]; },
    beacon: (b) => { const t = win(), L = [[`Zeek connections ${label(b.src)} → ${b.dst}:${b.port}`, kb(`event.dataset:"zeek.conn" and source.ip:${q(b.src)} and destination.ip:${q(b.dst)}${b.port ? ` and destination.port:${Number(b.port)}` : ""}`, t, COLS.conn)],
        [`IDS alerts between ${label(b.src)} and ${b.dst}`, kb(`event.dataset:"suricata.alert" and ${between(b.src, b.dst)}`, t, COLS.ids)]];
      if (b.name) L.push([`DNS lookups of ${b.name} by ${label(b.src)}`, kb(`event.dataset:"zeek.dns" and source.ip:${q(b.src)} and dns.query.name:${q(b.name)}`, t, COLS.dns)],
        [`TLS sessions to ${b.name}`, kb(`event.dataset:"zeek.ssl" and ssl.server_name:${q(b.name)}`, t, COLS.ssl)]);
      L.push([`All Zeek logs of ${label(b.src)}`, kb(`event.module:"zeek" and ${either(b.src)}`, t)]); return L; },
    "DNS-tunnel domain": (x) => { const t = win(), d = String(x.domain || ""), base = `event.dataset:"zeek.dns" and dns.highest_registered_domain:${q(d)}`;
      return [[`All DNS lookups of ${d} (whole window)`, kb(base, t, COLS.dns)],
        [`NXDOMAIN answers for ${d}`, kb(`${base} and dns.response.code_name:"NXDOMAIN"`, t, COLS.dns)],
        [`TXT / NULL / ANY queries for ${d}`, kb(`${base} and dns.query.type_name:("TXT" or "NULL" or "ANY")`, t, COLS.dns)],
        ...sortDesc(x.sources || {}).slice(0, 4).map(([ip, n]) => [`… by ${label(ip)} (×${fn(n)})`, kb(`${base} and source.ip:${q(ip)}`, t, COLS.dns)]),
        [`TLS sessions to ${d}`, kb(`event.dataset:"zeek.ssl" and ssl.server_name:(${q(d)} or *.${d})`, t, COLS.ssl)]]; },
    "baseline finding": (f) => { const t = win(), dev = String(f.device || ""), ip = /^[\d.]+$/.test(dev) ? dev : macIp(dev) || (/^[\d.]+$/.test(f.name || "") ? f.name : "");
      const L = ip ? ipLinks(ip, t) : [];
      if (ip) textIps(f.detail).filter((o) => o !== ip).forEach((o) => L.push([`Zeek connections ${label(ip)} ↔ ${o}`, kb(`event.dataset:"zeek.conn" and ${between(ip, o)}`, t, COLS.conn)]));
      else textIps(f.detail).forEach((o) => L.push(...ipLinks(o, t).slice(0, 2)));
      uniq((String(f.detail || "").match(DOM_RE) || []).map((d) => d.toLowerCase())).slice(0, 3).forEach((d) => {
        L.push([`DNS lookups of ${d}${ip ? ` by ${label(ip)}` : ""}`, kb(`event.dataset:"zeek.dns" and dns.query.name:${q(d)}${ip ? ` and source.ip:${q(ip)}` : ""}`, t, COLS.dns)],
          [`TLS sessions to ${d}${ip ? ` from ${label(ip)}` : ""}`, kb(`event.dataset:"zeek.ssl" and ssl.server_name:${q(d)}${ip ? ` and source.ip:${q(ip)}` : ""}`, t, COLS.ssl)]); });
      return L; },
    "host finding": (x) => { const p = String(x.key || "").split("|"), typ = p[0], h = p[1] || "", t = hfSpan(x.text) || win(), H = hostQ(h);
      const ds = (d, extra, cols, ttl) => [ttl, kb(`event.dataset:${q(d)} and ${H}${extra || ""}`, t, cols)];
      let e = null;
      if (typ === "syslog") e = ds("system.syslog", "", COLS.host, `Syslog on ${h}`);
      else if (/^(login-src|login-new|authfail|acct|sudo-err|sudo-susp)$/.test(typ)) {
        const ex = (typ.startsWith("login") || typ.startsWith("sudo-err")) && p[2] ? ` and user.name:${q(p[2])}` : "";
        const src = typ.startsWith("login") ? p[3] : typ === "authfail" ? p[2] : ""; e = ds("system.auth", ex + (src && /^[\d.:a-f]+$/i.test(src) ? ` and source.ip:${q(src)}` : ""), COLS.auth, `Auth log on ${h}`); }
      else if (/^(proc|exec-new|exec-sha)$/.test(typ)) e = ds("endpoint.events.process", p[2] ? ` and process.executable:${q(p[2])}` : "", COLS.proc, `Process events: ${p[2] || "?"} on ${h}`);
      else if (typ === "exec-mhr") e = ds("endpoint.events.process", ` and process.hash.sha256:${q(p[2])}`, COLS.proc, `Process events with SHA-256 ${String(p[2]).slice(0, 12)}…`);
      else if (/^(net-new|hnet-interp)$/.test(typ)) e = ds("endpoint.events.network", p[2] ? ` and process.executable:${q(p[2])}` : "", COLS.net, `Network events of ${p[2] || "?"} on ${h}`);
      else if (typ === "file") e = ds("endpoint.events.file", ` and file.path:${q(p[2])}`, COLS.file, `File events on ${p[2]}`);
      else if (typ === "defend") e = [`Elastic Defend alerts on ${h}`, kb(`event.dataset:"endpoint.alerts" and ${H}`, t)];
      else if (/^(agent-off|agent-deg|defend-pol|silent)$/.test(typ)) e = [`Elastic Agent logs from ${h}`, kb(`event.dataset:elastic_agent* and ${H}`, t, COLS.host)];
      return h ? hostLinks(h, t, e) : textIps(x.text).flatMap((ip) => ipLinks(ip, t)); },
    alarm: (a) => { const t = win(), txt = [a.title, a.who, a.evidence].join(" "), L = [];
      knownHosts(txt).forEach((h) => L.push([`All endpoint / syslog events on ${h}`, kb(hostQ(h), t, COLS.host)]));
      textIps(txt).forEach((ip) => L.push(...ipLinks(ip, t)));
      return L; },
    gateway: (g) => { const t = span(g.time, g.time, 15), L = [];
      if (SITE.kibana_url && g.src && g.dst) L.push([`Zeek connections ${g.src} ↔ ${label(g.dst)} (±15 min)`, kb(`event.dataset:"zeek.conn" and ${between(g.src, g.dst)}`, t, COLS.conn)],
        [`IDS alerts ${g.src} ↔ ${label(g.dst)} (±15 min)`, kb(`event.dataset:"suricata.alert" and ${between(g.src, g.dst)}`, t, COLS.ids)]);
      else if (SITE.kibana_url) textIps(g.message).forEach((ip) => L.push(...ipLinks(ip, t).slice(0, 2)));
      if (SITE.kibana_url && g.src) L.push([`All Zeek logs of ${g.src} (whole window)`, kb(`event.module:"zeek" and ${either(g.src)}`, win())]);
      const ub = String(SITE.unifi_web_url || "").replace(/\/?$/, "/");
      if (SITE.unifi_web_url) entries(SITE.unifi_paths || {}).forEach(([n, p]) => L.push([`UniFi: ${n}${g.src ? ` (search ${g.src})` : ""}`, ub + String(p).replace(/^\//, ""), "unifi"]));
      return L; },
  };

  let pop = null;
  const close = () => { pop?.remove(); pop = null; };
  function open(btn) {
    close(); const P = PIV.get(btn.dataset.piv); if (!P) return;
    let links = []; window.__pivWin = P.item && P.item._win || null;
    try { links = (B[P.kind] || B.alarm)(P.item) || []; } catch (e) { links = []; console.warn("pivot", e); } finally { window.__pivWin = null; }
    const seen = new Set(); links = links.filter(([, u]) => u && !seen.has(u) && seen.add(u));
    pop = document.createElement("div"); pop.className = "rel-pop piv-pop"; pop.setAttribute("role", "dialog");
    pop.innerHTML = `<div class="rel-head"><b>Open in ${P.kind === "gateway" ? "Kibana / UniFi" : "Kibana"}</b> <span class="muted small">time range: this event or the selected range</span><button type="button" class="rel-x" aria-label="Close">✕</button></div>
      ${links.length ? links.map(([t, u, src]) => `<a class="rel-item" href="${esc(u)}" target="_blank" rel="noopener noreferrer"><span class="badge ${src === "unifi" ? "sev-low" : "sev-medium"}">${src === "unifi" ? "UniFi" : "Kibana"}</span> <span class="rel-l">${esc(t)}</span></a>`).join("")
        : `<div class="empty" style="padding:10px">No IPs, hosts or signatures in this item to search for.</div>`}`;
    document.body.appendChild(pop);
    const r = btn.getBoundingClientRect(), w = Math.min(460, innerWidth - 16); pop.style.width = w + "px";
    pop.style.left = Math.max(8, Math.min(innerWidth - w - 8, r.left)) + "px";
    const below = r.bottom + 6, h = pop.offsetHeight;
    pop.style.top = (below + h > innerHeight - 8 && r.top - h - 6 > 8 ? r.top - h - 6 : Math.min(below, innerHeight - Math.min(h, innerHeight - 16) - 8)) + "px";
  }
  document.addEventListener("click", (e) => {  // capture phase: beats table-row navigation handlers
    const b = e.target.closest("[data-piv]");
    if (b) { e.preventDefault(); e.stopPropagation(); if (pop && pop.dataset.for === b.dataset.piv) return close(); open(b); if (pop) pop.dataset.for = b.dataset.piv; return; }
    if (pop && (e.target.closest(".rel-x") || !e.target.closest(".piv-pop"))) close();
  }, true);
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") close(); });
  addEventListener("hashchange", close);
  // Kibana Discover link for an AI search artifact (esk.py descriptor: kql, from, to) - used by the Related / Research popovers
  const tm = (t, d) => { const v = String(t || ""); return /^now/.test(v) ? v : isNaN(Date.parse(v)) ? d : iso(Date.parse(v)); };
  window.kibanaQueryUrl = (d) => {
    if (!SITE.kibana_url || !d || typeof d.kql !== "string") return "";
    const base = String(SITE.kibana_url).replace(/\/?$/, "/"), dv = SITE.kibana_data_view || "logs-*";
    const g = `(time:(from:${rison(tm(d.from, "now-24h"))},to:${rison(tm(d.to, "now"))}))`;
    const a = `(dataSource:(dataViewId:${rison(dv)},type:dataView),query:(language:kuery,query:${rison(d.kql)}),sort:!(!('@timestamp',desc)))`;
    return `${base}app/discover#/?_g=${encodeURIComponent(g)}&_a=${encodeURIComponent(a)}`;
  };
  window.__pivotLinks = (kind, item) => (B[kind] || B.alarm)(item);  // for tests
})();
