// Nightly PDF reports: list + download/open (#/reports). Files come from the server's read-only reports folder.
(() => {
  const kb = (n) => (n >= 1048576 ? (n / 1048576).toFixed(1) + " MB" : Math.round(n / 1024) + " KB");
  const when = (stamp) => { const d = new Date(stamp.replace(/T(\d\d)(\d\d)Z$/, "T$1:$2:00Z")); return isNaN(d) ? stamp : d.toLocaleString(); };
  V.reports = async (el) => {
    el.innerHTML = `<h1>Reports</h1><div class="sub">Nightly network behavior reports (PDF), newest first. <b>Download</b> saves the file; <b>Open</b> views it in the browser. The report matching the selected snapshot is highlighted.</div><div class="loading">Loading…</div>`;
    let R; try { R = await api("/api/reports"); } catch (e) { el.querySelector(".loading").textContent = String(e); return; }
    el.querySelector(".loading").remove();
    const rows = R.reports, cur = S.snap?.id, latest = rows[0];
    el.insertAdjacentHTML("beforeend", kpis([["Reports", rows.length], ["Latest", latest ? esc(when(latest.stamp)) : "—"],
      ["Total size", kb(rows.reduce((a, r) => a + r.size, 0))]]));
    if (latest) {
      el.appendChild(card("Latest report", `<div style="display:flex;gap:10px;flex-wrap:wrap;align-items:center">
        <b>${esc(when(latest.stamp))}</b><span class="muted small">${esc(latest.name)} · ${kb(latest.size)}</span>
        <a href="/reports/${encodeURIComponent(latest.name)}" download><button>⬇ Download</button></a>
        <a href="/reports/${encodeURIComponent(latest.name)}?view=1" target="_blank" rel="noopener"><button>Open</button></a></div>`));
    }
    el.appendChild(card(`All reports (${rows.length})`, rows.length ? table(null, [
      { k: "stamp", t: "Report", fmt: (v, r) => `<b>${esc(when(v))}</b>${v === cur ? ' <span class="badge sev-info">selected snapshot</span>' : ""}<div class="muted small mono">${esc(r.name)}</div>` },
      { k: "size", t: "Size", num: true, fmt: kb },
      { k: "has_snapshot", t: "Snapshot", fmt: (v, r) => (v ? `<a href="javascript:void 0" data-snap="${esc(r.stamp)}">view data</a>` : '<span class="muted">—</span>') },
      { k: "_a", t: "", fmt: (v, r) => `<a href="/reports/${encodeURIComponent(r.name)}" download><button>⬇ Download</button></a> <a href="/reports/${encodeURIComponent(r.name)}?view=1" target="_blank" rel="noopener"><button>Open</button></a>` },
    ], rows, { sort: "stamp", search: rows.length > 10, rowClass: (r) => (r.stamp === cur ? "unread" : "") })
      : `<div class="empty">No reports yet. They're produced nightly.</div>`));
    el.addEventListener("click", (e) => {  // jump the dashboard to that report's snapshot
      const a = e.target.closest("[data-snap]"); if (!a) return;
      window.rangeSelectSnapshot(a.dataset.snap);
    });
  };
})();
