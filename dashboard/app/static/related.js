// Related events: fills the "Related" column (table opts.evId) from /api/correlate and shows a popover of the
// linked events / vulnerabilities on click. Each item links to its own list filtered to that one event (?ev=<id>).
(() => {
  const main = document.getElementById("main"); if (!main) return;
  const TYPE = { alert: ["Alert", "sev-high"], finding: ["Finding", "sev-medium"], ids: ["IDS", "sev-medium"], admin: ["Admin", "sev-low"],
    host: ["Endpoint", "sev-low"], ti: ["Threat intel", "sev-high"], vuln: ["Vulnerability", "sev-critical"], gw: ["Gateway", "sev-medium"],
    alarm: ["Triage alarm", "sev-high"] };
  let loading = null;
  // Detection settings behind a finding (upload-spike, beacon-*, internal-scan): current values + description, from /api/tuning
  let TUNE = null, tuneAt = 0;
  function loadTuning() { if (Date.now() - tuneAt < 30000) return; tuneAt = Date.now(); api("/api/tuning").then((d) => { TUNE = d.settings || {}; }).catch(() => {}); }
  function tuneFor(id) {
    const m = /^f\|([^|]+)\|/.exec(String(id || "")); if (!m || !TUNE) return null;
    for (const t of Object.values(TUNE)) if (new RegExp(t.kinds).test(m[1])) return t;
    return null;
  }
  function tuneHtml(id) {
    const t = tuneFor(id); if (!t) return "";
    const v = Object.entries(t.values || {}).map(([k, x]) => `<code>${esc(k)}</code> = <b>${esc(Array.isArray(x) ? x.join(", ") : x)}</b>`).join(" · ");
    return `<details class="tune-box small" style="margin:4px 0 0"><summary class="muted">⚙ Detection setting: ${esc(t.title)} — ${v}</summary><div class="muted" style="margin:4px 0">${esc(t.doc || "")}</div><span class="tune-go" data-href="${esc(t.link)}" style="cursor:pointer;text-decoration:underline">Adjust in Settings →</span></details>`;
  }
  document.addEventListener("click", (e) => {  // the box sits inside a link row: toggle / navigate without following the row's link
    const sm = e.target.closest?.(".tune-box > summary"), go = e.target.closest?.(".tune-go");
    if (!sm && !go) return;
    e.preventDefault(); e.stopPropagation();
    if (sm) sm.parentNode.open = !sm.parentNode.open; else { close(); location.hash = go.dataset.href; }
  }, true);
  function ensure() {
    loadTuning();
    const sid = S.snap?.id; if (!sid) return;
    if (S.corr && S.corr._snap === sid) return fill();
    if (loading === sid) return;
    loading = sid;
    api("/api/correlate?id=" + encodeURIComponent(sid)).then((d) => { d._snap = sid; S.corr = d; }).catch(() => { S.corr = { _snap: sid, related: {}, events: {}, error: true }; })
      .finally(() => { loading = null; fill(); relabelChips(); main.querySelectorAll('.tfrow input').forEach((i) => i.value && i.dispatchEvent(new Event('input'))); });
  }
  const pendingEv = (id) => (S.corr?.related?.[id] || []).some((r) => r.llm === "pending");
  window.netmonPendingReview = pendingEv;
  // rows whose event is no longer in the loaded correlation (checked off, aged out of the snapshot) still get their saved research note
  const orphanAsked = new Set(), orphanNotes = {};
  function fetchOrphans() {
    const ids = [...new Set([...main.querySelectorAll(".rel-btn")].map((b) => b.dataset.rel))].filter((id) => id && !S.corr.notes?.[id] && !S.corr.events?.[id] && !orphanAsked.has(id));
    if (!ids.length) return;
    ids.forEach((i) => orphanAsked.add(i));
    for (let i = 0; i < ids.length; i += 20) {
      api("/api/notes/by-event?" + ids.slice(i, i + 20).map((x) => "e=" + encodeURIComponent(x)).join("&")).then((N) => {
        if (!N || !Object.keys(N).length || !S.corr) return; Object.assign(orphanNotes, N); S.corr.notes = { ...(S.corr.notes || {}), ...N }; fill(); }).catch(() => {});
    }
  }
  function fill() {
    if (!S.corr || S.corr._snap !== S.snap?.id) return;
    for (const [k, v] of Object.entries(orphanNotes)) if (!S.corr.notes?.[k] && !S.corr.events?.[k]) (S.corr.notes = S.corr.notes || {})[k] = v;
    const X = location.hash.startsWith("#/events") ? window.__oeExtra : null;  // Open events page: AI notes, classifications, your notes, times seen
    if (X) for (const m of ["notes", "classes", "unotes", "seen", "clef_ev"]) S.corr[m] = { ...(S.corr[m] || {}), ...(X[m] || {}) };
    fetchOrphans();
    main.querySelectorAll(".rel-btn").forEach((b) => {
      // rows older than the loaded snapshot (Open events): the count of stored related verdicts; details load on click
      const n = (S.corr.related?.[b.dataset.rel] || []).length || (X?.related_n?.[b.dataset.rel] || 0);
      const t = n ? String(n) : "–";
      if (b.textContent !== t) b.textContent = t;
      b.classList.toggle("has", n > 0); b.disabled = !n;
      // AI research note for this event: a "✨ notes" button right after the Related count
      const note = S.corr.notes?.[b.dataset.rel]; let nb = b.nextElementSibling?.classList.contains("note-btn") ? b.nextElementSibling : null;
      if (note && !nb) { nb = document.createElement("button"); nb.type = "button"; nb.className = "note-btn"; nb.dataset.note = b.dataset.rel; b.after(nb); }
      if (!note && nb) nb.remove();
      if (note && nb) { const t = "✨ " + (note.verdict || "notes"); if (nb.textContent !== t) nb.textContent = t;
        nb.className = "note-btn v-" + String(note.verdict || "").replace(/[^a-z-]/g, ""); nb.title = (note.summary || "Research notes").slice(0, 200); }
      // AI classification (suspicious / benign / expected): flair after the notes button, once the event's correlation review is done
      const cl = S.corr.classes?.[b.dataset.rel]; const pre = nb || b; let cb = pre.nextElementSibling?.classList.contains("cls-btn") ? pre.nextElementSibling : null;
      if (cl && !cb) { cb = document.createElement("button"); cb.type = "button"; cb.className = "cls-btn"; cb.dataset.cls = b.dataset.rel; pre.after(cb); }
      if (!cl && cb) cb.remove();
      if (cl && cb) { const t = "🏷 " + cl.label; if (cb.textContent !== t) cb.textContent = t; cb.className = "cls-btn v-" + String(cl.label).replace(/[^a-z-]/g, ""); cb.title = (cl.reason || "AI classification").slice(0, 200); }
      // people's notes on this event (kbnotes.js opens them): a 📝 button after the AI note, on every event row
      const after = (b.parentNode.querySelector(`.cls-btn[data-cls="${CSS.escape(b.dataset.rel)}"]`)) || nb || b; let ub = after.nextElementSibling?.classList.contains("unote-btn") ? after.nextElementSibling : null;
      if (!ub) { ub = document.createElement("button"); ub.type = "button"; ub.className = "unote-btn"; ub.dataset.unote = b.dataset.rel; ub.title = "Your notes on this event (the AI reads them)"; after.after(ub); }
      const uns = S.corr.unotes?.[b.dataset.rel] || [], un = uns.length, ut = un ? `📝 ${un}${uns.some((x) => x.status === "pending") ? " ⏳" : ""}` : "📝";
      if (ub.textContent !== ut) ub.textContent = ut;
      ub.classList.toggle("has", un > 0);
      // times seen: "👁 N×" after the Related count (snapshots the event was present in; alerts: times raised)
      const sn = S.corr.seen?.[b.dataset.rel]; let sb = b.parentNode.querySelector(`.seen-flair[data-seen="${CSS.escape(b.dataset.rel)}"]`);
      if (sn && !sb) { sb = document.createElement("span"); sb.className = "seen-flair small muted"; sb.dataset.seen = b.dataset.rel; (ub.nextElementSibling?.classList.contains("pend-flair") ? ub.nextElementSibling : ub).after(sb); }
      if (!sn && sb) sb.remove();
      if (sn && sb) { const t = ` 👁 ${sn.n}×`; if (sb.textContent !== t) sb.textContent = t; sb.title = `Seen ${sn.n} time${sn.n === 1 ? "" : "s"}${sn.first ? " · first " + sn.first : ""}${sn.last ? " · last " + sn.last : ""}`; }
      // "pending review": the correlation job has not finished this event yet (at least one candidate link still undecided)
      const isP = pendingEv(b.dataset.rel); let pf = ub.nextElementSibling?.classList.contains("pend-flair") ? ub.nextElementSibling : null;
      if (isP && !pf) { pf = document.createElement("span"); pf.className = "pend-flair"; pf.textContent = "⏳ pending review"; pf.title = "The correlation job has not reviewed this event's candidate links yet"; ub.after(pf); }
      if (!isP && pf) pf.remove();
    });
  }
  function relabelChips() {  // drill-down chip shows the event's label once correlations are loaded
    main.querySelectorAll(".fchips b[data-ev]").forEach((b) => { b.textContent = evLabel(b.dataset.ev); });
  }
  const llmLine = () => { const L = S.corr?.llm;
    if (!L || !L.enabled) return "Linked by shared hosts, IPs, domains or accounts, time, ATT&CK technique and vulnerabilities on the hosts involved. (Local LLM review is off.)";
    return `The script proposes links (shared hosts/IPs/accounts, time, ATT&CK, vulnerabilities); the correlation reviewer (${L.model || "?"}) decides, and event research on request (its verdicts replace the reviewer's). `
      + `${L.confirmed} confirmed, ${L.rejected} rejected, ${L.pending} awaiting review${L.busy ? " (reviewing now)" : ""}${L.error ? ` · last error: ${L.error}` : ""}.`; };
  // while reviews are pending, refresh the verdicts every 2 minutes so counts and badges catch up
  setInterval(() => { if (S.corr?.llm?.pending && !document.hidden && main.querySelector(".rel-btn")) { S.corr._snap = null; ensure(); } }, 120000);
  let pop = null;
  const close = () => { pop?.remove(); pop = null; };
  const ART_ICON = { file: "📄", process: "⚙️", user: "👤", ip: "🌐", dns: "🔎" };
  // an AI Elasticsearch search kept as an artifact: click to open the same search in Kibana Discover
  function queryArtHtml(a) {
    const d = a.query || {}, url = window.kibanaQueryUrl?.(d) || "";
    const hits = d.total != null ? `${Number(d.total).toLocaleString()} hits` : "";
    const tip = `${d.by === "research" ? "Event research" : "Reviewer"} search${d.index ? " of " + d.index : ""}${d.from ? ` · ${String(d.from).slice(0, 16)} → ${String(d.to || "").slice(0, 16)}` : ""}${d.approx ? " · opens an approximation (aggregations / complex clauses are not in the link)" : ""}`;
    return `<li><span class="art-k" title="${esc(tip)}">🔭 query</span> ${url ? `<button type="button" class="kib-btn" data-kib="${esc(url)}" title="${esc(tip)}: open in Kibana Discover"><code>${esc(a.value)}</code> ↗</button>` : `<code title="${esc(tip)}">${esc(a.value)}</code>`}
      ${hits ? `<span class="small muted">${esc(hits)}</span>` : ""}${d.approx ? ` <span class="small muted" title="${esc(tip)}">≈</span>` : ""} ${a.model ? aiFlare({ model: a.model, via: "Elasticsearch search", at: a.at ? new Date(a.at * 1000).toISOString() : "" }) : ""}
      ${a.relation ? `<span class="small muted">${esc(a.relation)}</span>` : ""}</li>`;
  }
  // artifacts of a related event, known before any review: host / destination IPs plus the users, processes, files and
  // DNS names the correlation script read from the event itself (e.arts); the reviewer's own artifacts replace same kind:value
  function ipArts(e, arts) {
    const have = new Set((arts || []).map((a) => a.kind + ":" + a.value)), out = [];
    const add = (kind, value, relation) => { const k = kind + ":" + value; if (!have.has(k)) { have.add(k); out.push({ kind, value, relation, decision: "info" }); } };
    for (const [list, rel] of [[e.host_ips, "host IP"], [e.dst_ips, "destination IP"]]) for (const ip of list || []) add("ip", ip, rel);
    for (const [kind, value, relation] of e.arts || []) add(kind, value, relation);
    return [...out, ...(arts || [])];
  }
  function artifactsHtml(arts, title = "Correlated artifacts") {
    if (!arts?.length) return "";
    return `<div class="note-arts"><b class="small">${esc(title)}</b><ul>${arts.map((a) => a.kind === "query" ? queryArtHtml(a) : `<li><span class="art-k" title="${esc(a.kind)}">${ART_ICON[a.kind] || "•"} ${esc(a.kind)}</span> <code>${esc(a.value)}</code> <button type="button" class="extnote-btn" data-extart="${esc(a.kind + ":" + a.value)}" title="Your notes on this ${esc(a.kind)} artifact (the AI reads them)">📝</button>
      <span class="note-v v-${esc(String(a.decision).replace(/[^a-z-]/g, ""))}">${esc(a.decision)}</span> ${!a.model ? "" : aiFlare({ model: a.model, via: "correlation review", at: a.at ? new Date(a.at * 1000).toISOString() : "" })}
      ${a.relation ? `<span class="small muted">${esc(a.relation)}</span>` : ""}</li>`).join("")}</ul></div>`;
  }
  document.addEventListener("click", (e) => {  // capture phase: the artifact sits inside a link row, so stop that navigation
    const b = e.target.closest?.(".kib-btn");
    if (!b) return;
    e.preventDefault(); e.stopPropagation();
    window.open(b.dataset.kib, "_blank", "noopener,noreferrer");
  }, true);
  // event time: epoch seconds (t0, optional t1 span end); vulnerabilities are timeless (open until fixed)
  const evTime = (e) => {
    const f = (t) => new Date(t * 1000).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" });
    if (e.type === "vuln" || !e.t0) return "ongoing (no event time)";
    return e.t1 && e.t1 - e.t0 >= 60 ? `${f(e.t0)} → ${f(e.t1)}` : f(e.t0);
  };
  // decision model (clef) chips: event label (p suspicious / p expected) and per-link p(related)
  const pct = (p) => Math.round((p || 0) * 100) + "%";
  const clefEvHtml = (c) => !c ? "" : `<span class="note-v v-${esc(String(c.label || "").replace(/[^a-z-]/g, ""))}" title="Decision model (${esc(c.model || "clef")}) event label: p(suspicious) ${pct(c.p_suspicious)}, p(expected) ${pct(c.p_expected)}">clef: ${esc(c.label || "?")}</span> <span class="small muted">p sus ${pct(c.p_suspicious)} · p exp ${pct(c.p_expected)}</span>`;
  const clefLinkHtml = (r) => r.clef ? `<span class="rel-ai ${r.clef.related ? "yes" : "pend"}" title="Decision model (${esc(r.clef.model || "clef")}) p(related) = ${(r.clef.p_related || 0).toFixed(3)}">clef ${pct(r.clef.p_related)} related</span>`
    : `<span class="rel-ai pend" title="Decided before the decision model (clef) ran: ${esc(r.llm_model || "reviewer")} verdict">no clef decision</span>`;
  window.relUi = { artifactsHtml, ipArts, queryArtHtml };  // used by the Open events window (openevents.js)
  const loadingRel = new Set();
  function openStored(btn) {  // Open events row outside the loaded snapshot: fetch its stored links, then open
    const id = btn.dataset.rel; if (loadingRel.has(id)) return; loadingRel.add(id);
    const ms = (window.__oeMembers?.[id] || []).slice(-12);
    btn.textContent = "…";
    api("/api/events/related?e=" + encodeURIComponent(id) + ms.map((m) => "&m=" + encodeURIComponent(m)).join("")).then((d) => {
      if (!S.corr) return;
      S.corr.related = S.corr.related || {}; S.corr.events = S.corr.events || {};
      if (d.related?.length) S.corr.related[id] = d.related;
      for (const [k, v] of Object.entries(d.events || {})) if (!S.corr.events[k]) S.corr.events[k] = v;
      if (d.clef_ev) (S.corr.clef_ev = S.corr.clef_ev || {})[id] = d.clef_ev;
    }).catch(() => {}).finally(() => { loadingRel.delete(id); fill(); if (btn.isConnected && S.corr?.related?.[id]?.length) { open(btn); if (pop) pop._for = btn; } });
  }
  function open(btn) {
    close();
    const id = btn.dataset.rel, rel = S.corr?.related?.[id] || [], me = S.corr?.events?.[id];
    if (!rel.length) { if (window.__oeExtra?.related_n?.[id] && location.hash.startsWith("#/events")) openStored(btn); return; }
    const cev = S.corr?.clef_ev?.[id];
    pop = document.createElement("div"); pop.className = "rel-pop"; pop.setAttribute("role", "dialog");
    pop.innerHTML = `<div class="rel-head"><b>Related events</b> <span class="muted small">${esc(me ? me.label.slice(0, 90) : "")}</span><button type="button" class="rel-x" aria-label="Close">✕</button></div>
      ${cev ? `<div class="small" style="padding:4px 10px">${clefEvHtml(cev)}</div>` : ""}
      ${(window.__oeExtra?.related_n?.[id] || 0) > rel.length ? `<div class="small muted" style="padding:4px 10px">showing the ${rel.length} most confident of ${window.__oeExtra.related_n[id]} related events</div>` : ""}
      ${tuneHtml(id) ? `<div style="padding:4px 10px">${tuneHtml(id)}</div>` : ""}
      ${rel.map((r) => { const e = S.corr.events[r.id] || { label: r.id, type: "", link: "#" }; const [tl, tc] = TYPE[e.type] || TYPE[{ f: "finding" }[e.type]] || [e.type, ""];
        const ai = r.llm === "yes" ? `<span class="rel-ai yes" title="Confirmed (confidence ${Math.round((r.llm_conf || 0) * 100)}%)">✓ confirmed</span> ${clefLinkHtml(r)} ${aiFlare({ model: r.llm_model, via: "correlation review" })}`
          : `<span class="rel-ai pend" title="The decision model has not decided this link yet">AI review pending</span>`;
        return `<a class="rel-item" href="${esc(e.link || "#")}"><span class="badge ${tc}">${esc(tl)}</span> <span class="rel-pair small muted" title="event pair">${esc(pairText(me?.type, e.type))}</span> ${ai} <span class="rel-l">${esc(e.label.length > 120 ? e.label.slice(0, 118) + "…" : e.label)}</span>
          <span class="rel-time small muted">🕒 ${esc(evTime(e))}</span>
          ${tuneHtml(r.id)}
          ${r.llm_reason ? `<span class="rel-why small">${esc(r.llm_reason)}</span>` : ""}
          ${artifactsHtml(ipArts(e, r.llm_artifacts))}
          ${(r.why || []).length ? `<span class="rel-why small muted">${r.llm_reason ? "Script: " : ""}${esc(r.why.join(" · "))}</span>` : ""}</a>`; }).join("")}
      <div class="small muted" style="padding:6px 10px">${esc(llmLine())}</div>`;
    document.body.appendChild(pop);
    const r = btn.getBoundingClientRect(), w = Math.min(520, innerWidth - 16);
    pop.style.width = w + "px";
    pop.style.left = Math.max(8, Math.min(innerWidth - w - 8, r.right - w)) + "px";
    const below = r.bottom + 6, h = pop.offsetHeight;
    pop.style.top = (below + h > innerHeight - 8 && r.top - h - 6 > 8 ? r.top - h - 6 : Math.min(below, innerHeight - Math.min(h, innerHeight - 16) - 8)) + "px";
    pop.querySelector(".rel-x").onclick = close;
  }
  const safeUrl = (u) => /^https?:\/\//i.test(String(u || "")) ? u : "";
  function openNote(btn) {
    close();
    const id = btn.dataset.note, n = S.corr?.notes?.[id] || window.__ckNotes?.[id], me = S.corr?.events?.[id] || (n ? { label: n.label || String(id).split("|").slice(1).join(" · ") } : null);
    if (!n) return;
    const links = (n.links || []).filter((l) => safeUrl(l.url));
    pop = document.createElement("div"); pop.className = "rel-pop note-pop"; pop.setAttribute("role", "dialog");
    pop.innerHTML = `<div class="rel-head"><b>Research notes</b> ${aiFlare({ model: n.model, via: n.via || "event enrichment", at: n.at ? new Date(n.at * 1000).toISOString() : "" })}
        <span class="muted small">${esc(me ? me.label.slice(0, 90) : "")}</span><button type="button" class="rel-x" aria-label="Close">✕</button></div>
      <div class="note-body">
        <div><span class="note-v v-${esc(String(n.verdict || "").replace(/[^a-z-]/g, ""))}">${esc(n.verdict || "")}</span> <span class="badge">${esc(n.priority || "")}</span>
          ${n.same_event ? "" : `<span class="small muted">written for an earlier run of this finding (${esc(n.snapshot || "")}); numbers may differ</span>`}</div>
        ${n.summary ? `<p><b>${esc(n.summary)}</b></p>` : ""}
        ${n.research ? `<div class="note-research">${esc(n.research)}</div>` : ""}
        ${artifactsHtml((n.queries || []).map((d) => ({ kind: "query", value: d.kql || d.index || "search", relation: d.why, model: n.model, at: n.at, query: d })), "Elasticsearch searches (open in Kibana)")}
        ${links.length ? `<div class="small"><b>Sources</b><ol class="note-links">${links.map((l) => `<li><a href="${esc(safeUrl(l.url))}" target="_blank" rel="noopener noreferrer">${esc(l.title || l.url)}</a></li>`).join("")}</ol></div>` : ""}
        <div class="small muted">AI research (on request, or copied by the reviewer). Verify before acting. ${cmpBtn("event research note", me ? me.label : id, { event: me ? me.label : id, event_type: me?.type, severity: me?.sev, note: { verdict: n.verdict, priority: n.priority, summary: n.summary, research: n.research, model: n.model } }, id)} compare models</div>
      </div>`;
    document.body.appendChild(pop);
    const r = btn.getBoundingClientRect(), w = Math.min(560, innerWidth - 16);
    pop.style.width = w + "px";
    pop.style.left = Math.max(8, Math.min(innerWidth - w - 8, r.right - w)) + "px";
    const below = r.bottom + 6, h = pop.offsetHeight;
    pop.style.top = (below + h > innerHeight - 8 && r.top - h - 6 > 8 ? r.top - h - 6 : Math.min(below, innerHeight - Math.min(h, innerHeight - 16) - 8)) + "px";
    pop.querySelector(".rel-x").onclick = close;
  }
  function openClass(btn) {
    close();
    const id = btn.dataset.cls, c = S.corr?.classes?.[id], me = S.corr?.events?.[id];
    if (!c) return;
    pop = document.createElement("div"); pop.className = "rel-pop note-pop"; pop.setAttribute("role", "dialog");
    pop.innerHTML = `<div class="rel-head"><b>AI classification</b> ${aiFlare({ model: c.model, via: "event classification", at: c.at ? new Date(c.at * 1000).toISOString() : "" })}
        <span class="muted small">${esc(me ? me.label.slice(0, 90) : "")}</span><button type="button" class="rel-x" aria-label="Close">✕</button></div>
      <div class="note-body"><div><span class="note-v v-${esc(String(c.label).replace(/[^a-z-]/g, ""))}">${esc(c.label)}</span> <span class="small muted">confidence ${Math.round((c.confidence || 0) * 100)}%</span></div>
        ${S.corr?.clef_ev?.[id] ? `<div style="margin-top:4px">${clefEvHtml(S.corr.clef_ev[id])}</div>` : ""}
        <p>${esc(c.reason || "")}</p>
        <div class="small muted">Label from the decision model (clef) once all of this event's links were decided; the reason is the reviewer's. Verify before acting.</div></div>`;
    document.body.appendChild(pop);
    const r = btn.getBoundingClientRect(), w = Math.min(460, innerWidth - 16);
    pop.style.width = w + "px";
    pop.style.left = Math.max(8, Math.min(innerWidth - w - 8, r.right - w)) + "px";
    const below = r.bottom + 6, h = pop.offsetHeight;
    pop.style.top = (below + h > innerHeight - 8 && r.top - h - 6 > 8 ? r.top - h - 6 : Math.min(below, innerHeight - Math.min(h, innerHeight - 16) - 8)) + "px";
    pop.querySelector(".rel-x").onclick = close;
  }
  // ---- event pair label ("Alarm – IDS") and "never send to the AI" rules for watcher alerts (shared with alerts.js / aireview.js)
  const PAIR_NAME = { alert: "Alert", finding: "Finding", f: "Finding", ids: "IDS", admin: "Admin", adm: "Admin", host: "Endpoint", hf: "Endpoint", ti: "Threat intel", vuln: "Vulnerability", iss: "Vulnerability", gw: "Gateway", alarm: "Triage alarm" };
  window.pairText = (a, b) => `${PAIR_NAME[a] || a} – ${PAIR_NAME[b] || b}`;
  window.pairKey = (a, b) => [a, b].sort().join("-");
  const canMute = () => ["admin", "defender"].includes(S.me?.role);
  const alertName = (label) => { const g = String(label || "").replace(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g, "*").replace(/\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b/gi, "*").replace(/\d+(?:[.,:]\d+)*/g, "*").replace(/\*(?:[\s,/()-]*\*)+/g, "*"); return "*" + g.replace(/…$/, "").trim().replace(/^\*+|\*+$/g, "") + "*"; };
  const alertHost = (label) => (String(label || "").match(/\b\d{1,3}(?:\.\d{1,3}){3}\b/) || String(label || "").match(/\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b/i) || [""])[0];
  window.alertMuteHtml = (label) => { return ""; /* never-send mute rules removed */ if (!canMute()) return ""; const h = alertHost(label);
    return `<span class="mute-btns small" data-label="${esc(label)}"><button type="button" class="mute-btn" data-mute="name" title="Mute alerts like this: never send them to the AI, clear the ones already raised and clear future ones automatically. You can edit the pattern.">mute name…</button>`
      + `<button type="button" class="mute-btn" data-mute="host" ${h ? "" : "disabled"} title="${h ? `Only for host ${esc(h)}` : "no host in this alert"}">mute name + host…</button>`
      + `<button type="button" class="mute-btn" data-mute="suppress" title="Suppress: hide alerts like this from the feed but keep them in correlation, research and review. You can edit the pattern and pick an artifact of the alert or of its correlated events.">🚫 suppress…</button></span>`; };
  // ---- Suppress dialog (button next to a check-off box): hide an event by signature name (+ one artifact), keep it in correlation
  let lastClick = null; document.addEventListener("click", (e) => { lastClick = e.target; }, true);
  const globRe = (g) => new RegExp("^" + String(g).replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".") + "$", "i");
  window.suppressDialog = (type, key, fallbackLabel, from) => suppressOpen(type, key, fallbackLabel, from).catch((e) => {
    try { fetch("/api/audit/view", { method: "POST", headers: { "Content-Type": "application/json", "X-Netmon": "1" }, body: JSON.stringify({ route: `suppress:error ${type}|${String(key).slice(0, 80)} ${String(e && (e.stack || e.message) || e).slice(0, 300)}` }) }).catch(() => {}); } catch (_) {}
    alert("Could not open the suppress dialog: " + (e.message || e));
  });
  const suppressOpen = async (type, key, fallbackLabel, from) => {
    const trig = from && from.isConnected ? from : lastClick && lastClick.isConnected ? lastClick : null;
    const cardOf = () => trig && (trig.closest(".card") || trig.closest("section, details, .panel") || null);
    const card = cardOf();
    // open the dialog right away (inside the tap) and fill the artifact list when /suggest answers: on iPhone the
    // 0.5-3 s wait before anything appeared left the tap looking dead, and the dialog sometimes never showed
    const diag = (stage, info) => { try { fetch("/api/audit/view", { method: "POST", headers: { "Content-Type": "application/json", "X-Netmon": "1" }, body: JSON.stringify({ route: `suppress:${stage} ${type}|${String(key).slice(0, 80)}${info ? " " + String(info).slice(0, 200) : ""}` }) }).catch(() => {}); } catch (_) {} };
    const sg = { label: fallbackLabel || "", artifacts: [] };
    let A = [];
    const TL = { ip: "🌐 IP", domain: "🔗 domain", user: "👤 user", process: "⚙️ process", port: "🔌 port", file: "📄 file" };
    const grp = (src, title) => { const l = A.filter((a) => a.from === src); return l.length ? `<optgroup label="${src === "event" ? "📍" : "🔗"} ${title}">${l.map((a) => `<option value="${A.indexOf(a)}">${esc(TL[a.type] || a.type)}: ${esc(a.value.length > 70 ? a.value.slice(0, 70) + "…" : a.value)}</option>`).join("")}</optgroup>` : ""; };
    const d = document.createElement("div"); d.className = "modal-back";
    d.innerHTML = `<div class="modal" role="dialog" aria-modal="true">
      <h3>🚫 Suppress this finding</h3>
      <div class="small muted" style="margin-bottom:8px">Instead of checking it off, suppress it: it is hidden everywhere and listed under <b>Checked/suppressed</b>, and alerts like it stop appearing. It still goes through correlation, research and review, but the reviewer never un-suppresses it. Edit the signature (<span class="mono">*</span> any text, <span class="mono">?</span> one character) and optionally require one artifact of this event or of the events correlated with it.</div>
      <div class="small mono sp-label" style="margin-bottom:6px;opacity:.8">${esc(sg.label)}</div>
      <input class="sp-name" value="${esc(alertName(sg.label))}" style="width:100%;box-sizing:border-box" title="Signature name">
      <div style="display:flex;gap:6px;margin-top:6px;flex-wrap:wrap;align-items:center"><span class="small">Only when it involves</span>
        <select class="sp-pick" style="max-width:100%"><option value="">(no artifact: name only)</option><option value="" disabled class="sp-loading">loading artifacts…</option><option value="other">other…</option></select></div>
      <div class="sp-other" style="display:none;gap:6px;margin-top:6px;flex-wrap:wrap"><select class="sp-type"><option value="ip">🌐 IP</option><option value="domain">🔗 domain</option><option value="user">👤 user</option><option value="process">⚙️ process</option><option value="port">🔌 port</option><option value="file">📄 file</option></select>
        <input class="sp-val" placeholder="value (* ? allowed)" size="30"></div>
      <div class="small muted sp-rel" style="margin-top:4px"></div>
      <div class="actions"><button type="button" class="sp-ok primary">Suppress</button><button type="button" class="sp-cancel">Cancel</button><span class="small sp-msg"></span></div></div>`;
    document.body.appendChild(d);
    const q = (c) => d.querySelector(c), close = () => d.remove();
    q(".sp-pick").onchange = () => { const v = q(".sp-pick").value; q(".sp-other").style.display = v === "other" ? "flex" : "none";
      const a = v && v !== "other" ? A[+v] : null; q(".sp-rel").textContent = a?.from === "correlated" ? `From the correlated event: ${a.rel}` : ""; };
    q(".sp-cancel").onclick = close; window.backdropClose(d, close);
    q(".sp-ok").onclick = async () => {
      const name = q(".sp-name").value.trim(), pv = q(".sp-pick").value;
      const a = pv === "other" ? { type: q(".sp-type").value, value: q(".sp-val").value.trim() } : pv ? A[+pv] : { type: "", value: "" };
      if (!name.replace(/[*?]/g, "").trim()) { q(".sp-msg").textContent = "Enter some text that is not just wildcards."; return; }
      q(".sp-ok").disabled = true; q(".sp-msg").textContent = "saving…";
      try { await apiPost("/api/llm/review-limits", { suppress: { name, art_type: a.type, art: a.value } }); S.acks = await api("/api/acks"); S.corr = null;
        // also check off every other event in the same card that this suppression matches
        if (card) {
          const re = name.includes("*") || name.includes("?") ? globRe(name) : globRe("*" + name + "*"), av = (a.value || "").trim(), are = av ? globRe(/[*?]/.test(av) ? av : "*" + av + "*") : null;
          const todo = [...card.querySelectorAll("input.ack-cb:not(:checked)")].filter((i) => i.dataset.t !== "seg" && re.test(i.dataset.l || "") && (!are || are.test(i.dataset.l || "")));
          for (const i of todo) { try { S.acks = await apiPost("/api/acks", { type: i.dataset.t, key: i.dataset.k, checked: true, label: i.dataset.l, note: "suppressed: rule " + name }); } catch (_) {} }
        }
        close(); rerender(); }
      catch (e) { q(".sp-ok").disabled = false; q(".sp-msg").textContent = "error: " + (e.message || e); }
    };
    if (!window.touchUI()) q(".sp-name").focus();  // phones: no keyboard pop-up / zoom that shifts the dialog under the finger
    if (window.touchUI()) { const r = d.querySelector(".modal").getBoundingClientRect(); diag("open", `vp=${innerWidth}x${innerHeight} vv=${Math.round(visualViewport?.width || 0)}x${Math.round(visualViewport?.height || 0)}@${(visualViewport?.scale || 1).toFixed(2)} top=${Math.round(r.top)} h=${Math.round(r.height)}`); }
    let edited = false; q(".sp-name").addEventListener("input", () => { edited = true; }, { once: true });
    try {
      const got = await api(`/api/suppress/suggest?type=${encodeURIComponent(type)}&key=${encodeURIComponent(key)}`);
      if (!d.isConnected) return;
      if (got.label) { sg.label = got.label; q(".sp-label").textContent = got.label; if (!edited) q(".sp-name").value = alertName(got.label); }
      A = got.artifacts || [];
      q(".sp-loading").insertAdjacentHTML("afterend", grp("event", "This event") + grp("correlated", "Correlated events"));
    } catch (e) { diag("suggest-error", e.message || e); }
    if (d.isConnected) q(".sp-loading").remove();
  };
  // Mute: opens an editable pattern (wildcards * ?, no wildcard = "contains"); saving also clears alerts already raised
  document.addEventListener("click", async (e) => {
    const b = e.target.closest(".mute-btn"), cancel = e.target.closest(".mute-cancel"), ok = e.target.closest(".mute-ok");
    if (!b && !cancel && !ok) return;
    e.preventDefault(); e.stopPropagation();
    const wrap = (b || cancel || ok).closest(".mute-btns"), label = wrap.dataset.label;
    if (b && b.dataset.mute === "suppress") { window.suppressDialog("alert", label, label); return; }  // same dialog as findings: artifacts of the alert and of its correlated events
    if (b) {
      const host = b.dataset.mute === "host" ? alertHost(label) : "";
      wrap.dataset.orig = wrap.innerHTML; wrap.dataset.host = host; wrap.dataset.mode = b.dataset.mute === "suppress" ? "suppress" : "";
      wrap.style.cssText = "display:inline-flex;flex-wrap:wrap;gap:4px;align-items:center";
      wrap.innerHTML = `<input class="mute-pat" value="${esc(alertName(label))}" size="46" title="Part of the alert text. Use * for any text, ? for one character."> ${host ? `<span class="small">only host <b>${esc(host)}</b></span>` : ""}
        ${b.dataset.mute === "suppress" ? `<select class="mute-art"><option value="">no artifact</option><option value="ip">IP</option><option value="user">user</option><option value="process">process</option><option value="port">port</option><option value="file">file</option></select><input class="mute-artv" placeholder="artifact value" size="16">` : ""}
        <button type="button" class="mute-ok">${b.dataset.mute === "suppress" ? "Suppress" : "Mute &amp; clear existing"}</button><button type="button" class="mute-cancel">Cancel</button>
        <span class="muted small" style="flex-basis:100%">Edit the pattern to match less or more (e.g. <span class="mono">*New device*</span>). Saving keeps this as a mute rule (see Alerts › Alert mute rules): matching alerts are cleared now and automatically whenever they arrive; Show cleared lists them.</span>`;
      wrap.querySelector(".mute-pat").focus(); return;
    }
    if (cancel) { wrap.innerHTML = wrap.dataset.orig; return; }
    const pat = wrap.querySelector(".mute-pat").value.trim();
    if (!pat.replace(/[*?]/g, "").trim()) { alert("Enter some text that is not just wildcards."); return; }
    if (wrap.dataset.mode === "suppress") {
      ok.disabled = true;
      try {
        const sup = { name: pat, art_type: wrap.querySelector(".mute-art")?.value || "", art: wrap.querySelector(".mute-artv")?.value.trim() || "" };
        const r = await apiPost("/api/llm/review-limits", { suppress: sup });
        wrap.innerHTML = `<span class="muted">suppressed ✓ ${esc(pat)}${sup.art_type ? " + " + esc(sup.art_type) + " " + esc(sup.art) : ""} · hid ${r.cleared_alerts || 0} alert(s)${r.cleared_open ? ", closed " + r.cleared_open + " open finding(s)" : ""}; still correlated</span>`; S.corr = null;
        if (/^#\/(alerts|aireview|events)/.test(location.hash)) setTimeout(() => refreshData(), 1200);
      } catch (err) { ok.disabled = false; alert(String(err.message || err)); }
      return;
    }
    const rule = { name: pat, scope: "both" }; if (wrap.dataset.host) rule.host = wrap.dataset.host;
    ok.disabled = true;
    try {
      const r = await apiPost("/api/llm/review-limits", { rule, clear_alerts: true });
      wrap.innerHTML = `<span class="muted">muted ✓ ${esc(pat)}${rule.host ? " @ " + esc(rule.host) : ""} · cleared ${r.cleared_alerts || 0} alert(s)</span>`; S.corr = null;
      if (/^#\/(alerts|aireview|events)/.test(location.hash)) setTimeout(() => refreshData(), 1200);
    } catch (err) { ok.disabled = false; alert(String(err.message || err)); }
  }, true);
  // Triage alarm title -> the best-matching underlying event (host finding, new device, IDS, gateway, TI, admin ...)
  const GO_RANK = { host: 3, finding: 3, admin: 3, gw: 2, ti: 2, alert: 2, ids: 1, vuln: 0 };
  function alarmTarget(id) {
    const rel = (S.corr?.related?.[id] || []).filter((r) => S.corr.events?.[r.id] && S.corr.events[r.id].type !== "alarm" && S.corr.events[r.id].link);
    rel.sort((a, b) => ((GO_RANK[S.corr.events[b.id].type] ?? 0) + (b.llm === "yes" ? 3 : 0) + (b.score || 0)) - ((GO_RANK[S.corr.events[a.id].type] ?? 0) + (a.llm === "yes" ? 3 : 0) + (a.score || 0)));
    return rel[0] ? S.corr.events[rel[0].id] : null;
  }
  document.addEventListener("click", (e) => {
    const go = e.target.closest(".alarm-go");
    if (go) {
      e.preventDefault(); e.stopPropagation();
      const t = alarmTarget(go.dataset.alarmEv);
      if (t) { location.hash = t.link.replace(/^#/, ""); return; }
      const b = go.closest(".alarm")?.querySelector(".rel-btn");
      go.title = S.corr ? "No matching event found for this alarm" : "Correlations still loading - try again";
      if (b && !b.disabled) open(b); else go.classList.add("nomatch");
      return;
    }
    const cbt = e.target.closest(".cls-btn");
    if (cbt) { e.stopPropagation(); e.preventDefault(); if (pop && pop._for === cbt) return close(); openClass(cbt); if (pop) pop._for = cbt; return; }
    const nbt = e.target.closest(".note-btn");
    if (nbt) { e.stopPropagation(); e.preventDefault(); if (pop && pop._for === nbt) return close(); openNote(nbt); if (pop) pop._for = nbt; return; }
    if (pop && pop.classList.contains("note-pop") && e.target.closest(".note-pop a")) return;
    const b = e.target.closest(".rel-btn");
    if (b) { e.stopPropagation(); e.preventDefault(); if (pop && pop._for === b) return close(); open(b); if (pop) pop._for = b; return; }
    if (pop && !e.target.closest(".rel-pop")) close();
    if (e.target.closest(".rel-item")) close();
  }, true);
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") close(); });
  addEventListener("scroll", close, { passive: true });
  addEventListener("hashchange", close);
  let q = false;
  new MutationObserver(() => { if (q) return; q = true; setTimeout(() => { q = false; if (main.querySelector(".rel-btn")) ensure(); }, 30); }).observe(main, { childList: true, subtree: true });
})();
