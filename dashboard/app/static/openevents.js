// Open events (#/events): every event nobody has checked off yet, whatever its age; the time range does not apply.
// Same cards, columns and tools as the Posture page: check-off (+ suppress), Ask AI, compare models, Kibana pivot,
// related events, AI research verdicts / classification / your notes (drawn by related.js from window.__oeExtra).
// Server: eventstore.open_events (sqlite table `events`).
(() => {
  const TYPES = [
    ["finding", "Baseline findings", "baseline finding", "baseline finding"],
    ["host", "Endpoint (host) findings", "host finding", "host finding"],
    ["ids", "IDS signatures", "IDS signature", "IDS signature"],
    ["gw", "Gateway events", "gateway event", "gateway"],
    ["admin", "Admin sessions", "admin session", "alarm"],
    ["ti", "Threat intel hits", "threat-intel hit", "alarm"],
    ["vuln", "Fix list (vulnerabilities / misconfigurations)", "vulnerability", "alarm"],
    ["alert", "Alerts", "alert", "alarm"],
    ["alarm", "Triage alarms", "alarm", "alarm"],
  ];
  const OE = { f: { type: "", sev: "" } };
  const parts = (eid) => String(eid).split("|");
  const topKeys = (o, n = 3) => Object.entries(o || {}).sort((a, b) => (b[1]?.conns ?? b[1] ?? 0) - (a[1]?.conns ?? a[1] ?? 0)).slice(0, n).map(([k]) => k);

  // the source row of the event; rebuilt from the event id for rows stored before the source was kept
  function itemOf(x) {
    if (x.item && typeof x.item === "object") return x.item;
    const p = parts(x.eid);
    if (x.type === "finding") return { kind: p[1], device: p[2], detail: p.slice(3).join("|"), severity: x.sev };
    if (x.type === "host") return { key: p.slice(1).join("|"), text: x.label, priority: x.sev === "high" ? "Investigate" : "Review" };
    if (x.type === "ids") return { name: p.slice(1).join("|") };
    if (x.type === "gw") return { key: p[1], message: x.label, time: x.t0 ? new Date(x.t0 * 1000).toISOString() : "" };
    return { title: x.label, who: (x.ips || []).join(" "), evidence: x.label };
  }
  const pivItem = (x) => {
    const it = { ...itemOf(x) };
    if (["admin", "ti", "vuln", "alert"].includes(x.type)) { it.title = x.label; it.who = (x.ips || []).join(" "); it.evidence = [it.src, it.dst, it.ip, it.domain].filter(Boolean).join(" "); }
    if (x.t0 && x.t1) it._win = [x.t0 * 1000 - 300000, x.t1 * 1000 + 300000];  // Kibana opens on the event's own time, not the loaded snapshot's
    return it;
  };
  const when = (v) => (v ? ft(v) : "");

  const ackCell = (x) => {
    const [a, ...more] = x.acks || [];
    if (!a) return "";
    const sup = ["admin", "defender"].includes(S.me?.role) && window.suppressDialog
      ? `<button type="button" class="sup-btn" data-t="${esc(a.type)}" data-k="${esc(a.key)}" data-l="${esc(x.label)}" title="Suppress: hide it like a check-off, but as a rule by signature name (and optionally an artifact). Listed under Checked/suppressed; still correlated.">🚫</button>` : "";
    return `<input type="checkbox" class="ack-cb" data-t="${esc(a.type)}" data-k="${esc(a.key)}" data-l="${esc(x.label)}" data-more="${esc(JSON.stringify(more))}" title="Check off${x.repeats > 1 ? ` (all ${x.repeats} variants of this)` : ""}">${sup}`;
  };

  function colsFor(t, askKind, pivKind) {
    const title = (x) => x.label;
    const ack = { k: "_ack", t: "✓", fmt: (v, x) => ackCell(x), sort: () => 0 };
    const tools = { k: "_ask", t: "", cls: "askcell", fmt: (v, x) => askBtn(askKind, title(x), itemOf(x)) + cmpBtn(askKind, title(x), itemOf(x), x.eid) + pivBtn(pivKind, pivItem(x)) };
    const sev = { k: "sev", t: "Severity", fmt: (v) => badge(v || "low"), sort: (x) => sevRank(x.sev) };
    const seen = { k: "n", t: "Seen", num: true, fmt: (v, x) => `${v}×${x.repeats > 1 ? ` <span class="muted small" title="same condition, different numbers each night">${x.repeats} variants</span>` : ""}` };
    const times = [{ k: "first_seen", t: "First seen", fmt: when }, { k: "last_seen", t: "Last seen", fmt: when }, seen];
    const label = { k: "label", t: "Event", fmt: (v) => linkifyIps(v) };
    const hosts = { k: "ips", t: "Hosts", fmt: (v) => (v || []).slice(0, 3).map((ip) => ipLink(ip)).join(" "), sort: (x) => (x.ips || [])[0] || "~" };
    const by = {
      finding: [{ k: "kind", t: "Kind", fmt: (v, x) => esc(itemOf(x).kind || ""), sort: (x) => itemOf(x).kind || "" }, { k: "device", t: "Device", fmt: (v, x) => ipLink(itemOf(x).device || ""), sort: (x) => itemOf(x).device || "" },
        { k: "detail", t: "Detail", fmt: (v, x) => linkifyIps(itemOf(x).detail || x.label), sort: (x) => itemOf(x).detail || "" }],
      host: [{ k: "text", t: "Finding", fmt: (v, x) => linkifyIps(itemOf(x).text || x.label), sort: (x) => itemOf(x).text || "" }],
      ids: [{ k: "name", t: "Signature", fmt: (v, x) => esc(itemOf(x).name || x.label), sort: (x) => itemOf(x).name || "" },
        { k: "count", t: "Count", num: true, fmt: (v, x) => fn(itemOf(x).count || 0), sort: (x) => itemOf(x).count || 0 },
        { k: "src", t: "From", fmt: (v, x) => topKeys(itemOf(x).src).map((ip) => ipLink(ip)).join(" "), sort: (x) => topKeys(itemOf(x).src, 1)[0] || "~" },
        { k: "dst", t: "To", fmt: (v, x) => topKeys(itemOf(x).dst).map((ip) => ipLink(ip)).join(" "), sort: (x) => topKeys(itemOf(x).dst, 1)[0] || "~" }],
      gw: [{ k: "time", t: "Time", fmt: (v, x) => when(itemOf(x).time), sort: (x) => itemOf(x).time || "" }, { k: "evt", t: "Event", fmt: (v, x) => linkifyIps(`${itemOf(x).key || ""}: ${itemOf(x).message || x.label}`) }],
      admin: [label, hosts],
      ti: [label, hosts],
      vuln: [{ k: "title", t: "Issue", fmt: (v, x) => esc(itemOf(x).title || x.label), sort: (x) => itemOf(x).title || "" }, { k: "target", t: "Target", fmt: (v, x) => ipLink(itemOf(x).target || itemOf(x).ip || ""), sort: (x) => itemOf(x).target || "" }],
      alert: [label, hosts],
    }[t] || [label, hosts];
    return [ack, tools, sev, ...by, ...times];
  }

  async function paintCount() {
    try { const r = await api("/api/events/open?limit=0"); const n = r.total || 0;
      document.querySelectorAll(".oe-count").forEach((e) => { e.textContent = n > 999 ? "999+" : n; e.style.display = n ? "" : "none"; }); } catch (_) { /* logged out */ }
  }
  window.oePaintCount = paintCount;
  setInterval(paintCount, 120000); paintCount();

  V.events = async (el) => {
    el.innerHTML = `<div class="loading">Loading…</div>`;
    let r; try { r = await api("/api/events/open?limit=5000"); } catch (e) { el.innerHTML = `<div class="empty">${esc(e.message || e)}</div>`; return; }
    window.__oeExtra = r.extra || {};
    el.innerHTML = "";
    const f = OE.f, c = r.counts || {};
    const rows = r.events.filter((x) => (!f.type || x.type === f.type) && (!f.sev || (x.sev || "").toLowerCase() === f.sev));
    el.insertAdjacentHTML("beforeend", `<div class="muted small">Every event stays here until it is checked off, however old — the time range does not apply. Fix-list items leave when the issue is fixed. Repeats of one condition are one row.</div>`);
    el.insertAdjacentHTML("beforeend", kpis([["Open events", r.total], ...TYPES.filter(([t]) => c[t]).map(([t, name]) => [name.replace(/ \(.*/, ""), c[t]])]));
    const bar = document.createElement("div"); bar.className = "fchips";
    bar.innerHTML = `<select id="oeT"><option value="">All types</option>${TYPES.map(([t, n]) => `<option value="${t}" ${f.type === t ? "selected" : ""}>${esc(n.replace(/ \(.*/, ""))}${c[t] ? " (" + c[t] + ")" : ""}</option>`).join("")}</select> ` +
      `<select id="oeS"><option value="">Any severity</option>${["high", "medium", "low"].map((s) => `<option ${f.sev === s ? "selected" : ""}>${s}</option>`).join("")}</select>`;
    el.appendChild(bar);
    bar.querySelector("#oeT").onchange = (e) => { f.type = e.target.value; V.events(el); };
    bar.querySelector("#oeS").onchange = (e) => { f.sev = e.target.value; V.events(el); };
    if (!rows.length) { el.appendChild(card("Open events", `<div class="empty">Nothing open — everything is checked off.</div>`)); return; }
    for (const [t, name, askKind, pivKind] of TYPES) {
      const list = rows.filter((x) => x.type === t);
      if (!list.length) continue;
      el.appendChild(card(`${esc(name)} (${list.length} open)`, table(null, colsFor(t, askKind, pivKind), list,
        { filter: true, sort: "sev", dir: 1, evId: (x) => x.eid, onclick: (x) => x.link && (location.hash = x.link) })));
    }
  };
})();
