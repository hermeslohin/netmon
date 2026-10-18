// Related events: fills the "Related" column (table opts.evId) from /api/correlate and shows a popover of the
// linked events / vulnerabilities on click. Each item links to its own list filtered to that one event (?ev=<id>).
(() => {
  const main = document.getElementById("main"); if (!main) return;
  const TYPE = { alert: ["Alert", "sev-high"], finding: ["Finding", "sev-medium"], ids: ["IDS", "sev-medium"], admin: ["Admin", "sev-low"],
    host: ["Endpoint", "sev-low"], ti: ["Threat intel", "sev-high"], vuln: ["Vulnerability", "sev-critical"], gw: ["Gateway", "sev-medium"] };
  let loading = null;
  function ensure() {
    const sid = S.snap?.id; if (!sid) return;
    if (S.corr && S.corr._snap === sid) return fill();
    if (loading === sid) return;
    loading = sid;
    api("/api/correlate?id=" + encodeURIComponent(sid)).then((d) => { d._snap = sid; S.corr = d; }).catch(() => { S.corr = { _snap: sid, related: {}, events: {}, error: true }; })
      .finally(() => { loading = null; fill(); relabelChips(); });
  }
  function fill() {
    if (!S.corr || S.corr._snap !== S.snap?.id) return;
    main.querySelectorAll(".rel-btn").forEach((b) => {
      const n = (S.corr.related?.[b.dataset.rel] || []).length;
      const t = n ? String(n) : "–";
      if (b.textContent !== t) b.textContent = t;
      b.classList.toggle("has", n > 0); b.disabled = !n;
      // Claude research note for this event: a "✨ notes" button right after the Related count
      const note = S.corr.notes?.[b.dataset.rel]; let nb = b.nextElementSibling?.classList.contains("note-btn") ? b.nextElementSibling : null;
      if (note && !nb) { nb = document.createElement("button"); nb.type = "button"; nb.className = "note-btn"; nb.dataset.note = b.dataset.rel; b.after(nb); }
      if (!note && nb) nb.remove();
      if (note && nb) { const t = "✨ " + (note.verdict || "notes"); if (nb.textContent !== t) nb.textContent = t;
        nb.className = "note-btn v-" + String(note.verdict || "").replace(/[^a-z-]/g, ""); nb.title = (note.summary || "Research notes").slice(0, 200); }
      // people's notes on this event (kbnotes.js opens them): a 📝 button after the AI note, on every event row
      const after = nb || b; let ub = after.nextElementSibling?.classList.contains("unote-btn") ? after.nextElementSibling : null;
      if (!ub) { ub = document.createElement("button"); ub.type = "button"; ub.className = "unote-btn"; ub.dataset.unote = b.dataset.rel; ub.title = "Your notes on this event (the AI reads them)"; after.after(ub); }
      const un = (S.corr.unotes?.[b.dataset.rel] || []).length, ut = un ? `📝 ${un}` : "📝";
      if (ub.textContent !== ut) ub.textContent = ut;
      ub.classList.toggle("has", un > 0);
    });
  }
  function relabelChips() {  // drill-down chip shows the event's label once correlations are loaded
    main.querySelectorAll(".fchips b[data-ev]").forEach((b) => { b.textContent = evLabel(b.dataset.ev); });
  }
  const llmLine = () => { const L = S.corr?.llm;
    if (!L || !L.enabled) return "Linked by shared hosts, IPs, domains or accounts, time, ATT&CK technique and vulnerabilities on the hosts involved. (Local LLM review is off.)";
    return `The script proposes links (shared hosts/IPs/accounts, time, ATT&CK, vulnerabilities); the local LLM (${L.model || "?"}) decides, and Claude re-reviews important events twice a day (its verdicts replace the local model's). `
      + `${L.confirmed} confirmed, ${L.rejected} rejected, ${L.pending} awaiting review${L.busy ? " (reviewing now)" : ""}${L.error ? ` · last error: ${L.error}` : ""}.`; };
  // while reviews are pending, refresh the verdicts every 2 minutes so counts and badges catch up
  setInterval(() => { if (S.corr?.llm?.pending && !document.hidden && main.querySelector(".rel-btn")) { S.corr._snap = null; ensure(); } }, 120000);
  let pop = null;
  const close = () => { pop?.remove(); pop = null; };
  function open(btn) {
    close();
    const id = btn.dataset.rel, rel = S.corr?.related?.[id] || [], me = S.corr?.events?.[id];
    if (!rel.length) return;
    pop = document.createElement("div"); pop.className = "rel-pop"; pop.setAttribute("role", "dialog");
    pop.innerHTML = `<div class="rel-head"><b>Related events</b> <span class="muted small">${esc(me ? me.label.slice(0, 90) : "")}</span><button type="button" class="rel-x" aria-label="Close">✕</button></div>
      ${rel.map((r) => { const e = S.corr.events[r.id] || { label: r.id, type: "", link: "#" }; const [tl, tc] = TYPE[e.type] || [e.type, ""];
        const ai = r.llm === "yes" ? `<span class="rel-ai yes" title="Confirmed (confidence ${Math.round((r.llm_conf || 0) * 100)}%)">✓ confirmed</span> ${aiFlare({ model: r.llm_model, via: "correlation review" })}`
          : `<span class="rel-ai pend" title="The local LLM has not reviewed this link yet">AI review pending</span>`;
        return `<a class="rel-item" href="${esc(e.link)}"><span class="badge ${tc}">${esc(tl)}</span> ${ai} <span class="rel-l">${esc(e.label.length > 120 ? e.label.slice(0, 118) + "…" : e.label)}</span>
          ${r.llm_reason ? `<span class="rel-why small">${esc(r.llm_reason)}</span>` : ""}
          <span class="rel-why small muted">${r.llm_reason ? "Script: " : ""}${esc(r.why.join(" · "))}</span></a>`; }).join("")}
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
    const id = btn.dataset.note, n = S.corr?.notes?.[id], me = S.corr?.events?.[id];
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
        ${links.length ? `<div class="small"><b>Sources</b><ol class="note-links">${links.map((l) => `<li><a href="${esc(safeUrl(l.url))}" target="_blank" rel="noopener noreferrer">${esc(l.title || l.url)}</a></li>`).join("")}</ol></div>` : ""}
        <div class="small muted">AI research from the twice-daily Hermes run. Verify before acting. ${cmpBtn("event research note", me ? me.label : id, { event: me ? me.label : id, event_type: me?.type, severity: me?.sev, note: { verdict: n.verdict, priority: n.priority, summary: n.summary, research: n.research, model: n.model } }, id)} compare models</div>
      </div>`;
    document.body.appendChild(pop);
    const r = btn.getBoundingClientRect(), w = Math.min(560, innerWidth - 16);
    pop.style.width = w + "px";
    pop.style.left = Math.max(8, Math.min(innerWidth - w - 8, r.right - w)) + "px";
    const below = r.bottom + 6, h = pop.offsetHeight;
    pop.style.top = (below + h > innerHeight - 8 && r.top - h - 6 > 8 ? r.top - h - 6 : Math.min(below, innerHeight - Math.min(h, innerHeight - 16) - 8)) + "px";
    pop.querySelector(".rel-x").onclick = close;
  }
  document.addEventListener("click", (e) => {
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
  new MutationObserver(() => { if (q) return; q = true; requestAnimationFrame(() => { q = false; if (main.querySelector(".rel-btn")) ensure(); }); }).observe(main, { childList: true, subtree: true });
})();
