// AI review (#/aireview): status of the local LLM that confirms or rejects correlation links (corr_llm.py).
// Worker health, queue + ETA, throughput, and every verdict with the model's reason; people can override a verdict
// (confirm / reject) or send it back to the model for another look.
(() => {
  const TYPE = { alert: "Alert", finding: "Finding", ids: "IDS", admin: "Admin", host: "Endpoint", ti: "Threat intel", vuln: "Vulnerability", gw: "Gateway",
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
  // Claude (Hermes cron) triage + enrichment: job state exported by claude_status.py, run log + coverage from enrich.py
  const until = (ts) => { if (!ts) return "—"; const s = ts - Date.now() / 1000; return s < 0 ? "due now" : s < 5400 ? `in ${Math.round(s / 60)} min` : `in ${(s / 3600).toFixed(1)} h`; };
  const dur = (s) => (s == null ? "" : s < 90 ? `${s} s` : `${Math.round(s / 60)} min`);
  const clock = (ts) => (ts ? new Date(ts * 1000).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }) : "");
  function claudeCard(C) {
    if (C.error) return card("Claude triage &amp; enrichment", `<div class="bad">Status unavailable: ${esc(C.error)}</div>`);
    const J = (C.jobs || [])[0], N = C.notes || {}, L = C.links || {}, R = C.runs || [];
    const now = Date.now() / 1000, stale = C.exported && now - C.exported > 3600;
    const lastRun = J && (J.runs || []).find((r) => r.status !== "running" && r.status !== "claimed");
    const health = !J ? ["No job found", "sev-unknown"] : !J.enabled ? ["Paused", "sev-unknown"] : J.running ? ["Running now", "sev-good"]
      : lastRun && lastRun.status === "failed" ? ["Last run failed", "sev-high"] : J.failure_streak ? ["Failing", "sev-high"] : ["Idle · scheduled", "sev-good"];
    const cov = N.current_events ? Math.round((100 * N.current_with_note) / N.current_events) : 0;
    const sum = J && J.summary ? `<details style="margin-top:10px"><summary>Latest run summary ${aiFlare({ model: J.model, via: "Hermes triage + enrichment", at: new Date(J.summary.at * 1000).toISOString() })} <span class="muted small">${esc(ago(J.summary.at))}</span></summary>
        <div class="note-research" style="margin-top:6px">${esc(J.summary.text)}</div></details>` : "";
    const c = card("Claude triage &amp; enrichment (every 4 h)", `
      <div class="idgrid">
        <span class="k">Status</span><span><span class="badge ${health[1]}">${health[0]}</span>${J && J.running ? ` · started ${esc(ago(J.running.started))}${J.running.progress ? `, last activity ${esc(ago(J.running.progress))}` : ""}` : ""}</span>
        ${J ? `<span class="k">Job</span><span>${esc(J.name || J.id)} · <span class="mono">${esc(J.model || "default model")}</span></span>
        <span class="k">Schedule</span><span><span class="mono">${esc(J.schedule || "")}</span> UTC · PDF only on the 05:00 UTC run · next run ${esc(until(J.next_run))} (${esc(clock(J.next_run))})</span>
        <span class="k">Last run</span><span>${lastRun ? `${esc(ago(lastRun.finished || lastRun.started))} · ${esc(lastRun.status)}${lastRun.duration_s ? ` in ${esc(dur(lastRun.duration_s))}` : ""}` : "never"}${J.failure_streak ? ` · <span class="bad">${fn(J.failure_streak)} failure(s) in a row</span>` : ""}</span>
        ${J.last_error ? `<span class="k">Last error</span><span class="bad">${esc(J.last_error)}</span>` : ""}` : `<span class="k">Job</span><span>No Hermes cron job with the home-network-report skill was found.</span>`}
        <span class="k">Research notes</span><span>${fn(N.total || 0)} stored · ${fn(N.last_24h || 0)} in the last 24 h${Object.keys(N.by_verdict || {}).length ? " · " + Object.entries(N.by_verdict).map(([k, v]) => `${esc(k)} ${fn(v)}`).join(" · ") : ""}</span>
        <span class="k">Correlation</span><span>${fn(L.total || 0)} link verdicts by Claude (${fn(L.related || 0)} related) · ${fn(L.last_24h || 0)} in the last 24 h${L.last ? ` · last ${esc(ago(L.last))}` : ""}</span>
        ${stale ? `<span class="k">Note</span><span class="warn">Job status last refreshed ${esc(ago(C.exported))} (the 15-minute watcher refreshes it).</span>` : ""}
      </div>
      <div style="margin-top:12px"><div class="small muted">Current snapshot: ${cov}% of events have a Claude note (${fn(N.current_with_note || 0)} of ${fn(N.current_events || 0)})</div>
        <div class="bar" style="height:10px;margin-top:4px"><span style="width:${cov}%"></span></div></div>
      ${sum}
      <div style="margin-top:12px;display:grid;grid-template-columns:repeat(auto-fit,minmax(380px,1fr));gap:12px">
        <div class="cl-runs"><div class="small"><b>Recent runs</b></div></div>
        <div class="cl-enr"><div class="small"><b>Enrichment passes</b></div></div>
      </div>`);
    c.id = "ai-claude";
    const U = (J && J.usage) || [];
    if (U.length) {  // time + token use of each research run
      const lbl = U.map((u) => new Date(u.at * 1000).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }) + (u.pdf_run ? " (PDF)" : ""));
      // usage_audit's prompt count sums the whole re-sent conversation over every API call of the run; ~95% of it
      // is prompt-cache reads (~10% of the input price). claude_status.py adds the split from Hermes's session DB.
      const M = (v) => +((v || 0) / 1e6).toFixed(3), sum = (f) => U.reduce((a, u) => a + (f(u) || 0), 0);
      const split = (u) => u.cache_read != null;
      const mins = sum((u) => u.duration_s) / 60, cost = sum((u) => u.cost_usd), nCost = U.filter((u) => u.cost_usd != null).length;
      const work = sum((u) => split(u) ? u.fresh + u.cache_write + u.completion : u.total), reads = sum((u) => u.cache_read);
      const chart = document.createElement("div");
      const hd = chart.appendChild(Object.assign(document.createElement("div"), { className: "small" })); hd.style.marginTop = "12px";
      hd.append(Object.assign(document.createElement("b"), { textContent: "Time and tokens per research run" }), " ",
        Object.assign(document.createElement("span"), { className: "muted", textContent: `last ${U.length} runs · ${Math.round(mins)} min in total, ${Math.round(mins / U.length)} min per run · ` +
          `${(work / 1e6).toFixed(1)} M tokens new input + cache writes + output, plus ${(reads / 1e6).toFixed(0)} M cache re-reads (~10% price; hidden, click the legend to show)` +
          (nCost ? ` · est. $${cost.toFixed(2)} at API list prices ($${(cost / nCost).toFixed(2)} per run)` : "") }));
      chart.appendChild(Object.assign(document.createElement("div"), { className: "chart" })).appendChild(document.createElement("canvas"));
      c.appendChild(chart);
      queueChart(chart.querySelector("canvas"), { type: "bar", data: { labels: lbl, datasets: [
        { label: "New input (M)", data: U.map((u) => M(split(u) ? u.fresh : null)), backgroundColor: "#58a6ff", stack: "t", yAxisID: "y" },
        { label: "Cache writes (M)", data: U.map((u) => M(split(u) ? u.cache_write : null)), backgroundColor: "#d29922", stack: "t", yAxisID: "y" },
        { label: "Input, no cache split (M)", data: U.map((u) => M(split(u) ? null : u.prompt)), backgroundColor: "#8b949e", stack: "t", yAxisID: "y" },
        { label: "Output (M)", data: U.map((u) => M(u.completion)), backgroundColor: "#bc8cff", stack: "t", yAxisID: "y" },
        { label: "Cache re-reads (M)", data: U.map((u) => M(u.cache_read)), backgroundColor: "#58a6ff33", stack: "t", yAxisID: "y", hidden: true },
        { label: "Run time (min)", type: "line", data: U.map((u) => +(u.duration_s / 60).toFixed(1)), borderColor: "#3fb950", backgroundColor: "#3fb950",
          pointRadius: 3, tension: 0.2, yAxisID: "y1" }] },
        options: { interaction: { mode: "index", intersect: false }, scales: { x: { stacked: true, ticks: { maxRotation: 50, autoSkip: true } },
          y: { stacked: true, beginAtZero: true, title: { display: true, text: "tokens (millions)" } },
          y1: { position: "right", beginAtZero: true, grid: { drawOnChartArea: false }, title: { display: true, text: "minutes" } } },
          plugins: { tooltip: { callbacks: { footer: (it) => { const u = U[it[0].dataIndex];
            return `Input incl. cache re-reads: ${(u.prompt / 1e6).toFixed(2)} M` + (u.cost_usd != null ? ` · est. $${u.cost_usd.toFixed(2)}` : "") +
              ` · ${u.model || ""}${u.error ? " · failed" : ""}`; } } } } } });
    }
    const runs = (J && J.runs) || [];
    c.querySelector(".cl-runs").appendChild(runs.length ? table(null, [
      { k: "started", t: "Started", fmt: (v) => esc(clock(v)), sort: (r) => r.started || 0 },
      { k: "status", t: "Result", fmt: (v, r) => `<span class="badge ${v === "completed" ? "sev-good" : v === "running" || v === "claimed" ? "sev-medium" : "sev-high"}">${esc(v === "claimed" ? "starting" : v)}</span>${r.error ? ` <span class="small bad">${esc(r.error)}</span>` : ""}` },
      { k: "pdf_run", t: "Type", fmt: (v, r) => `${v ? "Triage + PDF" : "Triage + enrichment"}${r.trigger === "manual" ? ' <span class="muted small">(manual)</span>' : ""}` },
      { k: "duration_s", t: "Took", num: true, fmt: (v, r) => esc(r.status === "running" ? `${dur(Math.round(now - r.started))} so far` : dur(v)) },
    ], runs, { sort: "started", limit: 12 }) : Object.assign(document.createElement("div"), { className: "empty", textContent: "No runs recorded yet." }));
    c.querySelector(".cl-enr").appendChild(R.length ? table(null, [
      { k: "started", t: "When", fmt: (v) => esc(clock(v)), sort: (r) => r.started || 0 },
      { k: "snapshot", t: "Snapshot", fmt: (v) => `<span class="mono small">${esc(v || "")}</span>` },
      { k: "todo", t: "Needed notes", num: true, fmt: (v, r) => (v == null ? "" : `${fn(v)} of ${fn(r.note_keys)}`) },
      { k: "notes", t: "Notes written", num: true, fmt: (v, r) => (r.stored ? fn(v) : `<span class="muted">${r.started && now - r.started > 7200 ? "not stored" : "researching…"}</span>`) },
      { k: "links", t: "Links reviewed", num: true, fmt: (v, r) => (r.stored ? fn(v) : "") },
      { k: "rejected", t: "Rejected ids", num: true, fmt: (v) => (v ? `<span class="bad">${fn(v)}</span>` : v === 0 ? "0" : "") },
    ], R, { sort: "started", limit: 10 }) : Object.assign(document.createElement("div"), { className: "empty", textContent: "No enrichment passes logged yet (the log starts with the next run)." }));
    return c;
  }

  // ---- model choice (correlation reviewer + research job) and per-decision model comparison
  let MODELS = null;
  const loadModels = async () => (MODELS = MODELS || await api("/api/llm/models"));
  const PROV = { lmstudio: "Local (LM Studio)", anthropic: "Anthropic" };
  const optKey = (p, m) => `${p}|${m}`;
  function modelSelect(M, cur) {
    const sel = document.createElement("select"); sel.className = "llm-sel";
    const groups = [["lmstudio", (M.local || []).map((m) => [m.id, m.id + (m.loaded ? " (loaded)" : "")])], ["anthropic", (M.anthropic || []).map((m) => [m.id, m.id])]];
    for (const [prov, items] of groups) {
      if (!items.length) continue;
      const g = document.createElement("optgroup"); g.label = PROV[prov];
      items.forEach(([id, label]) => g.appendChild(new Option(label, optKey(prov, id))));
      sel.appendChild(g);
    }
    if (cur && cur.model) { const k = optKey(cur.provider, cur.model); if (![...sel.options].some((o) => o.value === k)) sel.add(new Option(`${cur.model} (current, unavailable)`, k)); sel.value = k; }
    return sel;
  }
  function modelsCard(D) {
    const c = card("Models", "");
    c.id = "ai-models";
    const body = c.appendChild(document.createElement("div"));
    body.className = "llm-grid";
    const note = c.appendChild(Object.assign(document.createElement("div"), { className: "small muted" }));
    note.textContent = D.admin ? "Correlation reviewer: decides every proposed link, continuously (Anthropic models are billed per decision batch; local models are free but need LM Studio). Research job: the 4-hourly triage and event research (local models are much slower and weaker at web research)."
      : "Only an admin can change models.";
    const rows = [["correlation", "Correlation reviewer", D.config?.correlation || {}], ["research", "Research job (every 4 h)", D.research && !D.research.error ? D.research : {}]];
    loadModels().then((M) => {
      if (M.error) note.textContent = M.error + " - only local models can be chosen. " + note.textContent;
      for (const [sec, label, cur] of rows) {
        const r = body.appendChild(document.createElement("div")); r.className = "llm-row";
        r.appendChild(Object.assign(document.createElement("span"), { className: "k", textContent: label }));
        const sel = r.appendChild(modelSelect(M, cur)); sel.disabled = !D.admin;
        const btn = r.appendChild(Object.assign(document.createElement("button"), { type: "button", textContent: "Save" })); btn.disabled = true;
        const msg = r.appendChild(Object.assign(document.createElement("span"), { className: "small muted" }));
        msg.textContent = cur.model ? `now: ${PROV[cur.provider] || cur.provider} · ${cur.model}` : (sec === "research" && D.research?.error ? D.research.error : "now: auto (model loaded in LM Studio)");
        sel.onchange = () => { btn.disabled = !D.admin || sel.value === optKey(cur.provider, cur.model); };
        btn.onclick = async () => {
          const [provider, ...rest] = sel.value.split("|"), model = rest.join("|");
          btn.disabled = true; msg.textContent = "saving…";
          try { const r2 = await apiPost("/api/llm/config", { section: sec, provider, model }); const now = r2[sec] || {};
            cur.provider = now.provider; cur.model = now.model; msg.textContent = `saved: ${PROV[now.provider] || now.provider} · ${now.model}`; }
          catch (e) { msg.textContent = "error: " + e.message; btn.disabled = false; }
        };
      }
    }).catch((e) => { note.textContent = "Model list unavailable: " + e.message; });
    return c;
  }

  // compare dialog: one decision, up to 4 models side by side; a person can adopt one answer
  let dlg = null;
  function verdictBadge(rel) { const b = document.createElement("span"); b.className = "badge " + (rel ? "sev-good" : "sev-high"); b.textContent = rel ? "Related" : "Not related"; return b; }
  function resultTable(rows, pairKey, adoptable) {
    const t = document.createElement("table"); t.className = "cmp-tbl";
    t.createTHead().insertRow().append(...["Model", "Verdict", "Conf.", "Reason", "Time", "Tokens", ""].map((h) => Object.assign(document.createElement("th"), { textContent: h })));
    const tb = t.createTBody();
    for (const x of rows) {
      const tr = tb.insertRow();
      const m = tr.insertCell(); m.append(Object.assign(document.createElement("div"), { textContent: x.model }), Object.assign(document.createElement("div"), { className: "small muted", textContent: PROV[x.provider] || x.provider || "" }));
      const v = tr.insertCell(); if (x.error) { v.colSpan = 3; v.className = "bad small"; v.textContent = x.error; } else { v.appendChild(verdictBadge(x.related)); tr.insertCell().textContent = x.confidence == null ? "" : Math.round(x.confidence * 100) + "%"; tr.insertCell().textContent = x.reason || ""; }
      tr.insertCell().textContent = x.seconds == null ? "" : `${(+x.seconds).toFixed(1)} s`;
      const u = x.usage || { prompt: x.prompt_tokens, completion: x.completion_tokens };
      tr.insertCell().textContent = u.prompt == null ? "" : `${fn(u.prompt)} in · ${fn(u.completion)} out`;
      const a = tr.insertCell();
      if (adoptable && !x.error) {
        const b = a.appendChild(Object.assign(document.createElement("button"), { type: "button", textContent: "Use this", title: "Store this model's answer as the decision" }));
        b.onclick = async () => { b.disabled = true; try { await apiPost("/api/aireview", { action: "adopt", pair: pairKey, related: x.related, confidence: x.confidence, reason: x.reason, model: x.model }); b.textContent = "✓ used"; S.corr = null; } catch (e) { b.textContent = e.message; } };
      }
    }
    return t;
  }
  async function openCompare(r, D) {
    dlg?.remove();
    dlg = document.body.appendChild(document.createElement("dialog")); dlg.className = "cmp-dlg";
    const h = dlg.appendChild(document.createElement("div")); h.className = "cmp-head";
    h.append(Object.assign(document.createElement("b"), { textContent: "Compare models on this decision" }));
    const x = h.appendChild(Object.assign(document.createElement("button"), { type: "button", className: "rel-x", textContent: "✕", ariaLabel: "Close" })); x.onclick = () => dlg.close();
    const info = dlg.appendChild(document.createElement("div")); info.className = "idgrid small";
    const kv = (k, v) => info.append(Object.assign(document.createElement("span"), { className: "k", textContent: k }), Object.assign(document.createElement("span"), { textContent: v }));
    kv("Event", `${TYPE[r.a_type] || r.a_type}: ${r.a_label}`); kv("Linked to", `${TYPE[r.b_type] || r.b_type}: ${r.b_label}`);
    kv("Current decision", `${r.related ? "Related" : "Not related"} · ${r.confidence == null ? "" : Math.round(r.confidence * 100) + "% · "}${r.model}${r.reason ? " - " + r.reason : ""}`);
    const pick = dlg.appendChild(document.createElement("div")); pick.className = "cmp-pick";
    const go = Object.assign(document.createElement("button"), { type: "button", textContent: "Run comparison" });
    const out = document.createElement("div"); out.className = "cmp-out";
    const hist = document.createElement("details"); hist.className = "small";
    dlg.showModal();
    if (!D.admin) { pick.textContent = "Only an admin can run comparisons."; }
    else {
      pick.textContent = "Loading models…";
      let M; try { M = await loadModels(); } catch (e) { pick.textContent = e.message; return; }
      pick.textContent = "";
      pick.appendChild(Object.assign(document.createElement("div"), { className: "small muted", textContent: "Pick up to 4 models. Each gets exactly the prompt the correlation reviewer uses, for this one link." }));
      const cor = D.config?.correlation || {}, curLocal = cor.model || D.status.model || (M.local || []).find((m) => m.loaded)?.id || "";
      const def = new Set([optKey(cor.provider, curLocal), "anthropic|claude-sonnet-5-5", "anthropic|claude-opus-5-5"]);
      const all = [...(M.local || []).map((m) => ["lmstudio", m.id, m.loaded ? " (loaded)" : " (not loaded: LM Studio loads it first, slow)"]), ...(M.anthropic || []).map((m) => ["anthropic", m.id, ""])];
      for (const [prov, id, extra] of all) {
        const l = pick.appendChild(document.createElement("label")); l.className = "cmp-opt";
        const cb = l.appendChild(Object.assign(document.createElement("input"), { type: "checkbox", value: optKey(prov, id), checked: def.has(optKey(prov, id)) }));
        l.append(` ${id}`, Object.assign(document.createElement("span"), { className: "muted small", textContent: ` ${PROV[prov]}${extra}` }));
        cb.onchange = () => { const n = pick.querySelectorAll("input:checked").length; if (n > 4) cb.checked = false; };
      }
      pick.appendChild(go);
    }
    dlg.append(out, hist);
    const loadHist = async () => { try { const H = (await api("/api/aireview/compare?pair=" + encodeURIComponent(r.pair))).history || [];
      hist.replaceChildren(Object.assign(document.createElement("summary"), { textContent: `Earlier comparisons (${H.length})` }));
      if (H.length) hist.appendChild(resultTable(H.map((h) => ({ ...h, related: h.related == null ? null : !!h.related, model: `${h.model} · ${new Date(h.ts * 1000).toLocaleString()}` })), r.pair, false)); } catch (_) {} };
    loadHist();
    go.onclick = async () => {
      const targets = [...pick.querySelectorAll("input:checked")].map((c) => { const [provider, ...m] = c.value.split("|"); return { provider, model: m.join("|") }; });
      if (!targets.length) return;
      go.disabled = true; out.textContent = `Asking ${targets.length} model(s)…`;
      try { const R = await apiPost("/api/aireview/compare", { pair: r.pair, targets });
        out.replaceChildren(resultTable(R.results, r.pair, true));
        if ((R.evidence || []).length) out.appendChild(Object.assign(document.createElement("div"), { className: "small muted", textContent: "Script evidence given to every model: " + R.evidence.join("; ") }));
        loadHist(); }
      catch (e) { out.textContent = "Error: " + e.message; }
      go.disabled = false;
    };
  }

  V.aireview = async (el) => {
    el.innerHTML = `<h1>AI review</h1><div class="sub">The correlation script proposes links between events and vulnerabilities. The local LLM decides whether each link is real, and every 4 hours Claude researches the important events and re-reviews their links (its verdicts replace the local model's). Rejected links are hidden from the Related column; confirmed ones show the model's reason. Here you can watch the review, check its decisions and override them.</div><div class="loading">Loading…</div>`;
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

    el.appendChild(modelsCard(D));
    el.appendChild(claudeCard(D.claude || {}));

    const pct = q.pending + q.confirmed + q.rejected ? Math.round((100 * (q.confirmed + q.rejected)) / (q.pending + q.confirmed + q.rejected)) : 100;
    const info = card("Reviewer", `<div class="idgrid">
        <span class="k">Model</span><span class="mono">${esc(st.model || "auto (loaded model)")}</span><span class="k">Provider</span><span>${esc(PROV[st.provider || D.config?.correlation?.provider] || "Local (LM Studio)")} · <a href="#/aireview?at=ai-models">change</a></span>
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
      { k: "reason", t: "Reason", cls: "small", fmt: (v, r) => `${esc(v)} ${r.manual ? "" : aiFlare({ model: r.model, via: "correlation review", at: new Date(r.ts * 1000).toISOString() })}` },
      { k: "_a", t: "", fmt: (v, r) => `<span class="ai-acts">${r.current ? `<button data-cmp="${esc(r.pair)}" title="Compare models on this decision">⇄</button>` : ""}${r.related ? `<button data-ai="reject" data-p="${esc(r.pair)}" title="Mark as not related">✗</button>` : `<button data-ai="confirm" data-p="${esc(r.pair)}" title="Mark as related">✓</button>`}<button data-ai="rereview" data-p="${esc(r.pair)}" title="Ask the model again">↻</button></span>` },
    ], D.verdicts, { sort: "ts", limit: 100, urlFilter: FILTERS }));
    lst.id = "ai-list"; lst.dataset.open = "1"; el.appendChild(lst);
    lst.addEventListener("click", (e) => { const b = e.target.closest("[data-cmp]"); if (!b) return; e.preventDefault(); e.stopPropagation();
      const r = D.verdicts.find((x) => x.pair === b.dataset.cmp); if (r) openCompare(r, D); });
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
