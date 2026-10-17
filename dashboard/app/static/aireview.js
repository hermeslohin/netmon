// AI review (#/aireview): status of the local LLM that confirms or rejects correlation links (corr_llm.py).
// Worker health, queue + ETA, throughput, and every verdict with the model's reason; people can override a verdict
// (confirm / reject) or send it back to the model for another look.
(() => {
  const TYPE = { alert: "Alert", finding: "Finding", ids: "IDS", admin: "Admin", host: "Endpoint", ti: "Threat intel", vuln: "Vulnerability",
    f: "Finding", adm: "Admin", hf: "Endpoint", iss: "Vulnerability" };
  const ago = (ts) => { if (!ts) return "never"; const s = Date.now() / 1000 - ts; return s < 90 ? "just now" : s < 5400 ? Math.round(s / 60) + " min ago" : s < 129600 ? Math.round(s / 3600) + " h ago" : Math.round(s / 86400) + " d ago"; };
  const evCell = (lbl, typ, link) => `<span class="badge sev-info">${esc(TYPE[typ] || typ)}</span> ${link ? `<a href="${esc(link)}">${esc(lbl.length > 110 ? lbl.slice(0, 108) + "…" : lbl)}</a>` : `<span class="muted">${esc(lbl.length > 110 ? lbl.slice(0, 108) + "…" : lbl)}</span>`}`;
  const FILTERS = {
    verdict: ["Verdict", (r, v) => (v === "confirmed" ? r.related : v === "rejected" ? !r.related : v === "manual" ? r.manual : true)],
    type: ["Event type", (r, v) => (TYPE[r.a_type] || r.a_type) === v || (TYPE[r.b_type] || r.b_type) === v],
    conf: ["Confidence", (r, v) => (v === "low" ? (r.confidence ?? 1) < 0.7 : v === "high" ? (r.confidence ?? 0) >= 0.9 : true)],
    scope: ["Snapshot", (r, v) => (v === "current" ? r.current : true)],
  };

  const aiColors = (cfg) => { const C = { Confirmed: "#3fb950", Rejected: "#f85149", "Set by a person": "#58a6ff" };
    cfg.data.datasets[0].backgroundColor = cfg.data.labels.map((l) => C[l] || "#8b949e"); return cfg; };
  V.aireview = async (el) => {
    el.innerHTML = `<h1>AI review</h1><div class="sub">The correlation script proposes links between events and vulnerabilities. The local LLM decides whether each link is real. Rejected links are hidden from the Related column; confirmed ones show the model's reason. Here you can watch the review, check its decisions and override them.</div><div class="loading">Loading…</div>`;
    let D; try { D = await api("/api/aireview"); } catch (e) { el.querySelector(".loading").outerHTML = `<pre>${esc(e)}</pre>`; return; }
    el.querySelector(".loading").remove();
    const st = D.status, q = D.queue, T = D.totals;
    const health = !st.enabled ? ["Off", "sev-unknown"] : st.error ? ["Error", "sev-high"] : st.busy ? ["Reviewing", "sev-good"] : q.pending ? ["Waiting", "sev-medium"] : ["Idle · up to date", "sev-good"];
    el.insertAdjacentHTML("beforeend", kpis([
      ["Status", `<span class="badge ${health[1]}" style="font-size:14px">${health[0]}</span>`],
      ["Awaiting review", `<a href="#/aireview?at=ai-queue">${fn(q.pending)}</a>`, q.pending ? "warn" : "good"],
      ["Confirmed (this snapshot)", `<a href="#/aireview?verdict=confirmed&scope=current&at=ai-list">${fn(q.confirmed)}</a>`, "good"],
      ["Rejected (this snapshot)", `<a href="#/aireview?verdict=rejected&scope=current&at=ai-list">${fn(q.rejected)}</a>`, q.rejected ? "bad" : ""],
      ["Reviews / hour", fn(T.rate_per_hour)], ["Done in", q.eta_min == null ? (q.pending ? "?" : "—") : q.eta_min < 90 ? `~${q.eta_min} min` : `~${(q.eta_min / 60).toFixed(1)} h`]]));

    const pct = q.pending + q.confirmed + q.rejected ? Math.round((100 * (q.confirmed + q.rejected)) / (q.pending + q.confirmed + q.rejected)) : 100;
    const info = card("Reviewer", `<div class="idgrid">
        <span class="k">Model</span><span class="mono">${esc(st.model || "auto (loaded model)")}</span>
        <span class="k">Endpoint</span><span class="mono">${esc(D.url)}</span>
        <span class="k">Settings</span><span>${D.workers} parallel · reasoning ${esc(D.reasoning)}</span>
        <span class="k">Activity</span><span>${st.busy ? `<b>reviewing now</b> · ${fn(st.decided_this_run)} decided this pass` : st.last_run ? `last pass finished ${esc(ago(st.last_run))}` : "starting (first pass begins ~15 s after the dashboard starts)"}</span>
        <span class="k">Snapshot</span><span class="mono">${esc(D.snapshot)}</span>
        ${st.error ? `<span class="k">Last error</span><span class="bad">${esc(st.error)}</span>` : ""}
        ${!st.enabled ? `<span class="k">Disabled</span><span>Set <span class="mono">NETMON_LLM=on</span> in dashboard/.env and redeploy.</span>` : ""}</div>
      <div id="ai-queue" style="margin-top:12px"><div class="small muted">Current snapshot: ${pct}% reviewed (${fn(q.confirmed + q.rejected)} of ${fn(q.pending + q.confirmed + q.rejected)} links)</div>
        <div class="bar" style="height:10px;margin-top:4px"><span style="width:${pct}%"></span></div></div>`);
    el.appendChild(grid("g3", info,
      chartCard("Verdicts per hour (last 24 h)", { type: "bar", data: { labels: D.per_hour.map((_, i) => (i === 23 ? "now" : `-${23 - i}h`)), datasets: [{ data: D.per_hour, backgroundColor: PALETTE[0], borderRadius: 3 }] },
        options: { plugins: { legend: { display: false } }, scales: { x: { ticks: { autoSkip: true, maxTicksLimit: 8 } } } } }),
      chartCard("All verdicts", aiColors(doughnutCfg({ Confirmed: T.related - (D.verdicts.filter((v) => v.manual && v.related).length), Rejected: T.rejected - (D.verdicts.filter((v) => v.manual && !v.related).length), "Set by a person": T.manual },
        { onClick: (l) => drill("aireview", { verdict: { Confirmed: "confirmed", Rejected: "rejected", "Set by a person": "manual" }[l], at: "ai-list" }) })))));

    const lst = card(`Decisions (${fn(D.verdicts.length)}${D.verdicts.length >= 3000 ? ", newest 3,000" : ""})`, table(null, [
      { k: "ts", t: "When", fmt: (v) => esc(ago(v)), sort: (r) => r.ts },
      { k: "related", t: "Verdict", fmt: (v, r) => `<span class="badge ${v ? "sev-good" : "sev-high"}">${v ? "Related" : "Not related"}</span>${r.manual ? ' <span class="badge sev-info">person</span>' : ""}`, sort: (r) => (r.related ? 1 : 0) },
      { k: "confidence", t: "Conf.", num: true, fmt: (v) => (v == null ? "" : Math.round(v * 100) + "%") },
      { k: "a_label", t: "Event", fmt: (v, r) => evCell(v, r.a_type, r.a_link) },
      { k: "b_label", t: "Linked to", fmt: (v, r) => evCell(v, r.b_type, r.b_link) },
      { k: "reason", t: "Reason", cls: "small" },
      { k: "_a", t: "", fmt: (v, r) => `<span class="ai-acts">${r.related ? `<button data-ai="reject" data-p="${esc(r.pair)}" title="Mark as not related">✗</button>` : `<button data-ai="confirm" data-p="${esc(r.pair)}" title="Mark as related">✓</button>`}<button data-ai="rereview" data-p="${esc(r.pair)}" title="Ask the model again">↻</button></span>` },
    ], D.verdicts, { sort: "ts", limit: 100, urlFilter: FILTERS }));
    lst.id = "ai-list"; lst.dataset.open = "1"; el.appendChild(lst);
    const chips = document.createElement("div"); chips.className = "tbltools small";
    chips.innerHTML = `<span class="muted">Show:</span> ${[["All", {}], ["Confirmed", { verdict: "confirmed" }], ["Rejected", { verdict: "rejected" }], ["Set by a person", { verdict: "manual" }], ["Low confidence (<70%)", { conf: "low" }], ["This snapshot only", { scope: "current" }]]
      .map(([l, p]) => `<a href="${esc(hashWith("aireview", { ...p, at: "ai-list" }))}">${esc(l)}</a>`).join(" · ")}`;
    lst.insertBefore(chips, lst.children[1]);

    el.addEventListener("click", async (e) => {
      const b = e.target.closest("[data-ai]"); if (!b) return;
      b.disabled = true;
      try { await apiPost("/api/aireview", { action: b.dataset.ai, pair: b.dataset.p }); S.corr = null;
        const tr = b.closest("tr"); if (tr) tr.style.opacity = 0.45;
        b.closest(".ai-acts").innerHTML = `<span class="small muted">${b.dataset.ai === "rereview" ? "queued for the model" : "saved"}</span>`; }
      catch (err) { b.disabled = false; alert(String(err)); }
    });
    // live refresh while the model is working (only if the user is not in the middle of something)
    if (st.busy || q.pending) { const t = setTimeout(() => { if (location.hash.startsWith("#/aireview") && !document.hidden && !document.querySelector(".rel-pop")) rerender(); }, 60000);
      addEventListener("hashchange", () => clearTimeout(t), { once: true }); }
  };
})();
