// Related events: fills the "Related" column (table opts.evId) from /api/correlate and shows a popover of the
// linked events / vulnerabilities on click. Each item links to its own list filtered to that one event (?ev=<id>).
(() => {
  const main = document.getElementById("main"); if (!main) return;
  const TYPE = { alert: ["Alert", "sev-high"], finding: ["Finding", "sev-medium"], ids: ["IDS", "sev-medium"], admin: ["Admin", "sev-low"],
    host: ["Endpoint", "sev-low"], ti: ["Threat intel", "sev-high"], vuln: ["Vulnerability", "sev-critical"] };
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
    });
  }
  function relabelChips() {  // drill-down chip shows the event's label once correlations are loaded
    main.querySelectorAll(".fchips b[data-ev]").forEach((b) => { b.textContent = evLabel(b.dataset.ev); });
  }
  let pop = null;
  const close = () => { pop?.remove(); pop = null; };
  function open(btn) {
    close();
    const id = btn.dataset.rel, rel = S.corr?.related?.[id] || [], me = S.corr?.events?.[id];
    if (!rel.length) return;
    pop = document.createElement("div"); pop.className = "rel-pop"; pop.setAttribute("role", "dialog");
    pop.innerHTML = `<div class="rel-head"><b>Related events</b> <span class="muted small">${esc(me ? me.label.slice(0, 90) : "")}</span><button type="button" class="rel-x" aria-label="Close">✕</button></div>
      ${rel.map((r) => { const e = S.corr.events[r.id] || { label: r.id, type: "", link: "#" }; const [tl, tc] = TYPE[e.type] || [e.type, ""];
        return `<a class="rel-item" href="${esc(e.link)}"><span class="badge ${tc}">${esc(tl)}</span> <span class="rel-l">${esc(e.label.length > 120 ? e.label.slice(0, 118) + "…" : e.label)}</span>
          <span class="rel-why small muted">${esc(r.why.join(" · "))}</span></a>`; }).join("")}
      <div class="small muted" style="padding:6px 10px">Linked by shared hosts, IPs, domains or accounts, closeness in time, the same ATT&amp;CK technique, and known vulnerabilities on the hosts involved.</div>`;
    document.body.appendChild(pop);
    const r = btn.getBoundingClientRect(), w = Math.min(520, innerWidth - 16);
    pop.style.width = w + "px";
    pop.style.left = Math.max(8, Math.min(innerWidth - w - 8, r.right - w)) + "px";
    const below = r.bottom + 6, h = pop.offsetHeight;
    pop.style.top = (below + h > innerHeight - 8 && r.top - h - 6 > 8 ? r.top - h - 6 : Math.min(below, innerHeight - Math.min(h, innerHeight - 16) - 8)) + "px";
    pop.querySelector(".rel-x").onclick = close;
  }
  document.addEventListener("click", (e) => {
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
