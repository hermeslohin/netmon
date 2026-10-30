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
    const verdict = { k: "_verdict", t: "Verdict", fmt: (v, x) => chips(x), sort: (x) => (window.__oeExtra?.classes?.[x.eid]?.label || "~") };
    const notes = { k: "_unote", t: "Notes", fmt: (v, x) => noteBtn(x.eid), sort: (x) => (S.corr?.unotes?.[x.eid] || []).length };
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
    return [ack, sev, verdict, notes, ...by, ...times];
  }


  // suspicious / benign labels shown on the row; the row opens the detail window (click anywhere but the check box)
  const vcls = (v) => String(v || "").replace(/[^a-z-]/g, "");
  function chips(x) {
    const X = window.__oeExtra || {}, c = X.classes?.[x.eid], n = X.notes?.[x.eid], rn = X.related_n?.[x.eid] || 0;
    return (c ? `<span class="note-v v-${vcls(c.label)}" title="AI classification: ${esc(c.reason || "")}">${esc(c.label)}</span> ` : "")
      + (n && n.verdict ? `<span class="note-v v-${vcls(n.verdict)}" title="Research note verdict">📝 ${esc(n.verdict)}</span> ` : "")
      + (rn ? `<span class="muted small" title="related events">${rn} related</span>` : "");
  }
  // your notes on an event (kbnotes.js popover: add a note or a verdict, send to research); also used in the detail window
  function noteBtn(eid) {
    const ns = S.corr?.unotes?.[eid] || [], n = ns.length, p = ns.some((x) => x.status === "pending");
    return `<button type="button" class="unote-btn${n ? " has" : ""}" data-unote="${esc(eid)}" title="Add a note or verdict on this event (the AI reads approved notes)">${n ? `📝 ${n}${p ? " ⏳" : ""}` : "📝"}</button>`;
  }
  const secs = (t) => (t ? new Date(t * 1000).toISOString() : "");
  const kindOf = (t) => TYPES.find((r) => r[0] === t) || [];

  // one block per time the event fired (recorded one per report): what happened, then that event's related events, the artifacts
  // (with their note buttons) and the Elasticsearch queries the AI used for it. Related lists are keyed by event id, so
  // firings of the same id show the same links.
  function firesHtml(d, x) {
    const U = window.relUi || {}, EV = d.events || {}, BY = d.by_event || {};
    let F = d.fires || [];
    if (!F.length) F = (d.occurrences || []).map((o) => ({ eid: o.eid, sid: "", seen: o.last_seen, t1: o.t1, label: o.label }));
    const note = d.fires_since ? `Recorded since ${when(d.fires_since)}.` : "Recording starts now.";
    const earlier = Math.max(0, (x.n || 0) - (d.fires || []).length);
    const body = (f) => {
      const rel = BY[f.eid] || [], me = EV[f.eid] || {};
      const own = U.ipArts ? U.ipArts(me, []) : [];  // artifacts read from the event itself
      const seenA = new Set(), arts = [], qs = [];
      for (const a of [...own, ...rel.flatMap((r) => r.llm_artifacts || [])]) { const k = a.kind + ":" + a.value; if (seenA.has(k)) continue; seenA.add(k); (a.kind === "query" ? qs : arts).push(a); }
      const relHtml = rel.length ? rel.map((r) => { const e = EV[r.id] || { label: r.id, type: "", link: "" };
        const conf = r.llm === "yes" ? `<span class="rel-ai yes" title="Confirmed link (confidence ${Math.round((r.llm_conf || 0) * 100)}%)">✓ ${Math.round((r.llm_conf || 0) * 100)}%</span>` : `<span class="rel-ai pend">pending</span>`;
        return `<div class="oe-rel"><span class="badge">${esc(e.type || "")}</span> ${conf} <span class="rel-l">${esc(e.label.length > 140 ? e.label.slice(0, 138) + "…" : e.label)}</span>
          ${e.link ? `<a class="small" href="${esc(e.link)}" title="Open this event's source page">open ↗</a>` : ""}${r.variants > 1 ? ` <span class="small muted">${r.variants} occurrences</span>` : ""}
          ${r.llm_reason ? `<span class="rel-why small">${esc(r.llm_reason)}</span>` : ""}</div>`; }).join("") : `<div class="small muted">None yet - the reviewer adds them as it links events.</div>`;
      return `<details class="oe-det oe-sub" ${rel.length ? "open" : ""}><summary>${rel.length} related event${rel.length === 1 ? "" : "s"}</summary>${relHtml}</details>
        <details class="oe-det oe-sub"><summary>${arts.length} artifact${arts.length === 1 ? "" : "s"}</summary>${arts.length && U.artifactsHtml ? U.artifactsHtml(arts, "Click 📝 on an artifact to add a note") : `<div class="small muted">None yet.</div>`}</details>
        <details class="oe-det oe-sub"><summary>${qs.length} Elasticsearch ${qs.length === 1 ? "query" : "queries"} used</summary>${qs.length && U.artifactsHtml ? U.artifactsHtml(qs, "Click a query to open it in Kibana") : `<div class="small muted">None yet.</div>`}</details>`;
    };
    return (F.length ? F.map((f, i) => `<div class="oe-fire"><div class="oe-fire-h"><b>${when(f.seen)}</b>
        ${f.t1 ? `<span class="small muted">event time ${esc(ft(secs(f.t1)))}</span>` : ""} ${f.sid ? `<span class="small muted">report ${esc(f.sid)}</span>` : ""}</div>
        <div class="oe-fire-w">${linkifyIps(f.label)}</div>${body(f)}</div>`).join("") : `<div class="empty">No individual firings recorded yet.</div>`)
      + `<div class="small muted" style="margin-top:3px">${note}${earlier ? ` ${earlier} earlier appearance${earlier > 1 ? "s were" : " was"} counted before individual times were kept.` : ""}</div>`;
  }

  async function openDetail(x) {
    document.querySelector(".oe-back")?.remove();
    const X = window.__oeExtra || {}, c = X.classes?.[x.eid], n = X.notes?.[x.eid], cev = X.clef_ev?.[x.eid];
    const [, , askKind, pivKind] = kindOf(x.type);
    const back = document.createElement("div"); back.className = "modal-back oe-back";
    const close = () => { back.remove(); document.removeEventListener("keydown", onKey, true); removeEventListener("hashchange", close); };
    const onKey = (e) => { if (e.key === "Escape" && !document.querySelector(".askdlg-scrim, dialog[open]")) close(); };
    document.addEventListener("keydown", onKey, true); addEventListener("hashchange", close);
    const verdictHtml = (c || n) ? `<div class="oe-verdict">
        ${c ? `<div><span class="note-v v-${vcls(c.label)}">${esc(c.label)}</span> <span class="small muted">AI classification · confidence ${Math.round((c.confidence || 0) * 100)}%</span>
          ${cev ? ` <span class="small muted">decision model p(suspicious) ${Math.round((cev.p_suspicious || 0) * 100)}%</span>` : ""}
          ${c.reason ? `<div class="small">${esc(c.reason)}</div>` : ""}</div>` : ""}
        ${n ? `<div style="margin-top:6px"><span class="note-v v-${vcls(n.verdict)}">📝 ${esc(n.verdict || "note")}</span> <span class="small muted">research note</span>
          ${n.summary ? `<div class="small"><b>${esc(n.summary)}</b></div>` : ""}</div>` : ""}</div>` : "";
    back.innerHTML = `<div class="modal oe-modal" role="dialog" aria-label="Event detail">
      <div class="oe-head"><div style="flex:1;min-width:0"><div class="oe-title">${linkifyIps(x.label)}</div>
        <div class="small muted">${badge(x.sev || "low")} ${esc(kindOf(x.type)[1] || x.type)} · first seen ${when(x.first_seen)} · last seen ${when(x.last_seen)} · seen ${x.n}×</div></div>
        <div class="oe-tools">${noteBtn(x.eid)}${askBtn(askKind, x.label, itemOf(x))}${cmpBtn(askKind, x.label, itemOf(x), x.eid)}${pivBtn(pivKind, pivItem(x))}
          ${x.link ? `<a class="small" href="${esc(x.link)}" title="Open the page this event comes from">open source ↗</a>` : ""}
          <button type="button" class="oe-x" aria-label="Close">✕</button></div></div>
      ${verdictHtml}
      <div class="oe-body"><div class="loading">Loading…</div></div></div>`;
    document.body.appendChild(back);
    back.onclick = (e) => { if (e.target === back || e.target.closest(".oe-x")) close(); };
    let d;
    try { d = await api("/api/events/detail?e=" + encodeURIComponent(x.eid)); }
    catch (e) { back.querySelector(".oe-body").innerHTML = `<div class="empty">${esc(e.message || e)}</div>`; return; }
    if (!back.isConnected) return;
    back.querySelector(".oe-body").innerHTML = `<h4>When it fired (${(d.fires || []).length || (d.occurrences || []).length}${(d.fires || []).length >= 1000 ? "+" : ""})</h4>${firesHtml(d, x)}`;
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
    S.corr = S.corr || {}; S.corr.events = S.corr.events || {}; S.corr.unotes = { ...(S.corr.unotes || {}), ...(window.__oeExtra.unotes || {}) };
    for (const x of r.events) if (!S.corr.events[x.eid]) S.corr.events[x.eid] = { label: x.label, type: x.type };  // the notes popover reads the event label from here
    window.__oeMembers = Object.fromEntries(r.events.map((x) => [x.eid, x.members || []]));
    el.innerHTML = "";
    const f = OE.f, c = r.counts || {};
    const rows = r.events.filter((x) => (!f.type || x.type === f.type) && (!f.sev || (x.sev || "").toLowerCase() === f.sev));
    el.insertAdjacentHTML("beforeend", `<div class="muted small">Every event stays here until it is checked off, however old — the time range does not apply. Fix-list items leave when the issue is fixed. Repeats of one condition are one row. Click a row for every occurrence and its related events.</div>`);
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
        { filter: true, sort: "sev", dir: 1, onclick: openDetail })));
    }
  };
})();
