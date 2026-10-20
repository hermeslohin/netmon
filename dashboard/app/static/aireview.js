// AI review (#/aireview): the correlation reviewer that confirms or rejects correlation links (corr_llm.py), the
// research job (review.py) and the AI providers / models / cost caps they use.
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
  // research job (review.py) triage + enrichment: settings + run state from research_cfg / research_job.json, run log + coverage from enrich.py
  const until = (ts) => { if (!ts) return "—"; const s = ts - Date.now() / 1000; return s < 0 ? "due now" : s < 5400 ? `in ${Math.round(s / 60)} min` : `in ${(s / 3600).toFixed(1)} h`; };
  const dur = (s) => (s == null ? "" : s < 90 ? `${s} s` : `${Math.round(s / 60)} min`);
  const clock = (ts) => (ts ? new Date(ts * 1000).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }) : "");
  // "every 4 h" from the job's interval in minutes
  const every = (_, mins) => { const n = mins;
    return !n ? "scheduled" : n === 720 ? "twice a day" : n === 1440 ? "daily" : n % 60 ? `every ${n} min` : `every ${n / 60} h`; };
  function researchCard(C, D) {  // returns [status box, time/token box (only when usage exists)]
    if (C.error) return [card("AI triage &amp; enrichment", `<div class="bad">Status unavailable: ${esc(C.error)}</div>`)];
    const J = (C.jobs || [])[0], N = C.notes || {}, L = C.links || {}, R = C.runs || [];
    const now = Date.now() / 1000, stale = C.exported && now - C.exported > 3600;
    const lastRun = J && (J.runs || []).find((r) => r.status !== "running" && r.status !== "claimed");
    const health = !J ? ["No job found", "sev-unknown"] : !J.model ? ["No model chosen", "sev-unknown"] : !J.enabled ? ["Paused", "sev-unknown"] : J.running ? ["Running now", "sev-good"]
      : J.requested ? ["Starting (requested)", "sev-medium"]
      : lastRun && lastRun.status === "failed" ? ["Last run failed", "sev-high"] : J.failure_streak ? ["Failing", "sev-high"] : ["Idle · scheduled", "sev-good"];
    const cov = N.current_events ? Math.round((100 * N.current_with_note) / N.current_events) : 0;
    const sum = J && J.summary ? `<details style="margin-top:10px"><summary>Latest run summary ${aiFlare({ model: J.summary.model || J.model, via: "research job", at: new Date(J.summary.at * 1000).toISOString() })} <span class="muted small">${esc(ago(J.summary.at))}</span></summary>
        <div class="note-research" style="margin-top:6px">${esc(J.summary.text)}</div></details>` : "";
    const c = card(`AI triage &amp; enrichment (${every(null, J && J.interval_minutes)})`, `
      <div class="idgrid">
        <span class="k">Status</span><span><span class="badge ${health[1]}">${health[0]}</span>${J && J.running ? ` · started ${esc(ago(J.running.started))}${J.running.progress ? `, last activity ${esc(ago(J.running.progress))}` : ""}` : ""}</span>
        ${J ? `<span class="k">Job</span><span>${esc(J.name || J.id)} · <span class="mono">${esc(J.model || "no model chosen - pick one in the Models box")}</span>${J.provider ? ` <span class="muted small">${esc(PROV[J.provider] || J.provider)}</span>` : ""}</span>
        <span class="k">Schedule</span><span>${esc(every(null, J.interval_minutes))}, on a grid anchored at 05:00 UTC · PDF on the first run after 05:00 UTC · next run ${J.enabled ? `${esc(until(J.next_run))} (${esc(clock(J.next_run))})` : "paused"}
          ${D.admin ? ` · <button type="button" class="rj-run"${J.running || J.requested || !J.model ? " disabled" : ""}>Run now</button> <button type="button" class="rj-toggle">${J.enabled ? "Pause" : "Resume"}</button> <span class="small muted rj-msg"></span>` : ""}</span>
        <span class="k">Last run</span><span>${lastRun ? `${esc(ago(lastRun.finished || lastRun.started))} · ${esc(lastRun.status)}${lastRun.duration_s ? ` in ${esc(dur(lastRun.duration_s))}` : ""}` : "never"}${J.failure_streak ? ` · <span class="bad">${fn(J.failure_streak)} failure(s) in a row</span>` : ""}</span>
        ${J.last_error ? `<span class="k">Last error</span><span class="bad">${esc(J.last_error)}</span>` : ""}` : `<span class="k">Job</span><span>Research job status unavailable.</span>`}
        <span class="k">Research notes</span><span>${fn(N.total || 0)} stored · ${fn(N.last_24h || 0)} in the last 24 h${Object.keys(N.by_verdict || {}).length ? " · " + Object.entries(N.by_verdict).map(([k, v]) => `${esc(k)} ${fn(v)}`).join(" · ") : ""}</span>
        <span class="k">Correlation</span><span>${fn(L.total || 0)} link verdicts by the research job (${fn(L.related || 0)} related) · ${fn(L.last_24h || 0)} in the last 24 h${L.last ? ` · last ${esc(ago(L.last))}` : ""}</span>
        ${stale && J && J.running ? `<span class="k">Note</span><span class="warn">No progress reported for ${esc(ago(C.exported))} - check logs/research.log on the host.</span>` : ""}
      </div>
      <div style="margin-top:12px"><div class="small muted">Current snapshot: ${cov}% of events have a research note (${fn(N.current_with_note || 0)} of ${fn(N.current_events || 0)})</div>
        <div class="bar" style="height:10px;margin-top:4px"><span style="width:${cov}%"></span></div></div>
      ${sum}
      <div style="margin-top:12px;display:grid;grid-template-columns:repeat(auto-fit,minmax(380px,1fr));gap:12px">
        <div class="cl-runs"><div class="small"><b>Recent runs</b></div></div>
        <div class="cl-enr"><div class="small"><b>Enrichment passes</b></div></div>
      </div>`);
    c.id = "ai-research";
    if (D.admin && J) {
      const m = c.querySelector(".rj-msg");
      c.querySelector(".rj-run")?.addEventListener("click", async (ev) => { ev.target.disabled = true; m.textContent = "requesting…";
        try { await apiPost("/api/llm/research", { action: "run" }); m.textContent = "requested - the scheduler starts it within 20 s"; }
        catch (e) { m.textContent = "error: " + e.message; ev.target.disabled = false; } });
      c.querySelector(".rj-toggle")?.addEventListener("click", async (ev) => { ev.target.disabled = true;
        try { const r = await apiPost("/api/llm/research", { enabled: !J.enabled }); J.enabled = r.research.enabled; ev.target.textContent = J.enabled ? "Pause" : "Resume";
          m.textContent = J.enabled ? "resumed" : "paused - no scheduled runs until resumed"; }
        catch (e) { m.textContent = "error: " + e.message; } ev.target.disabled = false; });
    }
    const U = (J && J.usage) || [];
    let uc = null;
    USAGE = null;
    if (U.length) {  // time + token use of each research run
      const lbl = U.map((u) => new Date(u.at * 1000).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }) + (u.pdf_run ? " (PDF)" : ""));
      // the prompt count sums the whole re-sent conversation over every API call of the run; most of it can be
      // prompt-cache reads (a fraction of the input price) when the provider caches. review.py records the split.
      const M = (v) => +((v || 0) / 1e6).toFixed(3), sum = (f) => U.reduce((a, u) => a + (f(u) || 0), 0);
      const split = (u) => u.cache_read != null;
      const mins = sum((u) => u.duration_s) / 60, cost = sum((u) => u.cost_usd), nCost = U.filter((u) => u.cost_usd != null).length;
      const S = U.filter(split), nRaw = U.length - S.length;
      const tokAll = sum((u) => split(u) ? u.fresh + u.cache_write + u.completion : (u.prompt || 0) + (u.completion || 0)), readsAll = sum((u) => u.cache_read);
      const tpm = mins > 0 ? Math.round(tokAll / mins) : 0, tpmR = mins > 0 ? Math.round((tokAll + readsAll) / mins) : 0;
      const work = S.reduce((a, u) => a + u.fresh + u.cache_write + u.completion, 0), reads = S.reduce((a, u) => a + u.cache_read, 0);
      // own box (user request): title is the card h2, the summary line sits under it
      uc = card("Time and tokens per research run", "");
      uc.id = "ai-usage";
      const chart = uc;  // header + .chart as direct children so cards.js marks it cc-chart (no phone height cap)
      const hd = chart.appendChild(Object.assign(document.createElement("div"), { className: "small" }));
      hd.append(Object.assign(document.createElement("span"), { className: "muted", textContent: `last ${U.length} runs · ${Math.round(mins)} min in total, ${Math.round(mins / U.length)} min per run · ` +
          (tpm ? `avg ${tpm.toLocaleString()} tokens/min (${tpmR.toLocaleString()} incl. cache re-reads) · ` : "") +
          (S.length ? `${(work / S.length / 1e6).toFixed(2)} M tokens new input + cache writes + output per run, plus ${(reads / S.length / 1e6).toFixed(1)} M cache re-reads (~10% price; hidden, click the legend to show)` : "") +
          (nRaw ? ` · ${nRaw} run${nRaw > 1 ? "s" : ""} without cache split (grey)` : "") +
          (nCost ? ` · est. $${cost.toFixed(2)} at the prices entered for the model ($${(cost / nCost).toFixed(2)} per run)` : "") }));
      const pv = chart.appendChild(Object.assign(document.createElement("div"), { className: "small cost-preview", style: "margin-top:4px" }));
      chart.appendChild(Object.assign(document.createElement("div"), { className: "chart phone4x" })).appendChild(document.createElement("canvas"));
      const cfg = { type: "bar", data: { labels: lbl, datasets: [
        { label: "New input (M)", data: U.map((u) => M(split(u) ? u.fresh : null)), backgroundColor: "#58a6ff", stack: "t", yAxisID: "y" },
        { label: "Cache writes (M)", data: U.map((u) => M(split(u) ? u.cache_write : null)), backgroundColor: "#d29922", stack: "t", yAxisID: "y" },
        { label: "Input, no cache split (M)", data: U.map((u) => M(split(u) ? null : u.prompt)), backgroundColor: "#8b949e", stack: "t", yAxisID: "y" },
        { label: "Output (M)", data: U.map((u) => M(u.completion)), backgroundColor: "#bc8cff", stack: "t", yAxisID: "y" },
        { label: "Cache re-reads (M)", data: U.map((u) => M(u.cache_read)), backgroundColor: "#58a6ff33", stack: "t", yAxisID: "y", hidden: true },
        { label: "Run time (min)", type: "line", data: U.map((u) => +(u.duration_s / 60).toFixed(1)), borderColor: "#3fb950", backgroundColor: "#3fb950",
          pointRadius: 3, tension: 0.2, yAxisID: "y1" },
        { label: "Est. cost ($)", type: "line", data: U.map((u) => u.cost_usd), borderColor: "#f85149", backgroundColor: "#f85149",
          pointRadius: 3, tension: 0.2, yAxisID: "y2" },
        { label: "Cost with selected model ($)", type: "line", data: U.map(() => null), borderColor: "#ff7b72", backgroundColor: "#ff7b72", borderDash: [6, 4],
          pointRadius: 2, tension: 0.2, yAxisID: "y2", hidden: true }] },
        options: { interaction: { mode: "index", intersect: false }, scales: { x: { stacked: true, ticks: { maxRotation: 50, autoSkip: true } },
          y: { stacked: true, beginAtZero: true, title: { display: true, text: "tokens (millions)" } },
          y1: { position: "right", beginAtZero: true, grid: { drawOnChartArea: false }, title: { display: true, text: "minutes" } },
          y2: { position: "right", beginAtZero: true, grid: { drawOnChartArea: false }, title: { display: true, text: "US $" }, ticks: { callback: (v) => "$" + v } } },
          plugins: { tooltip: { callbacks: { footer: (it) => { const u = U[it[0].dataIndex];
            const p = USAGE && USAGE.preview, pc = p ? runCost(u, p.price) : null;
            return `Input incl. cache re-reads: ${(u.prompt / 1e6).toFixed(2)} M` + (u.cost_usd != null ? ` · est. $${u.cost_usd.toFixed(2)}` : "") +
              ` · ${u.model || ""}${u.error ? " · failed" : ""}` + (pc != null ? `\nWith ${p.model}: ~$${pc.toFixed(2)}` : ""); } } } } } };
      queueChart(chart.querySelector("canvas"), cfg);
      // the chart may not exist yet (queued until the page is laid out): the preview edits this dataset object directly
      const tot = S.reduce((a, u) => a + u.fresh + u.cache_write + u.cache_read, 0);
      const mix = tot ? { fresh: S.reduce((a, u) => a + u.fresh, 0) / tot, cache_write: S.reduce((a, u) => a + u.cache_write, 0) / tot, cache_read: reads / tot } : null;
      USAGE = { U, mix, canvas: chart.querySelector("canvas"), pv, preview: null, ds: cfg.data.datasets[cfg.data.datasets.length - 1] };
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
    return uc ? [c, uc] : [c];
  }

  // ---- research cost preview: re-price the recorded runs' tokens with the model picked in the Models box
  let USAGE = null;  // {U, canvas, pv, preview} set by researchCard when the usage chart exists
  // $ for one run's tokens at a price {in, out, cache_read, cache_write} per 1 M. A missing cache price falls back to the
  // input price (OpenAI bills cache writes as plain input). Runs without a cache split use the average split of the
  // runs that have one (pricing all their input as new input would overstate them ~10x).
  function runCost(u, p) {
    if (!p) return 0;
    const ip = p.in || 0, cr = p.cache_read ?? ip, cw = p.cache_write ?? ip, op = p.out || 0, mx = USAGE && USAGE.mix;
    const t = u.cache_read != null ? u.fresh * ip + u.cache_write * cw + u.cache_read * cr + u.completion * op
      : mx ? u.prompt * (mx.fresh * ip + mx.cache_write * cw + mx.cache_read * cr) + u.completion * op : u.prompt * ip + u.completion * op;
    return +(t / 1e6).toFixed(2);
  }
  function previewResearchCost(provider, model, M, current) {
    if (!USAGE) return;
    const ch = Chart.getChart(USAGE.canvas), ds = USAGE.ds;
    // The recorded runs may have used another model than the one now configured, so the configured model gets an
    // estimate too; only "no model" hides the preview.
    const same = !model, chosen = !!current && provider === current.provider && model === current.model;
    const grp = (M.custom || []).find((g) => g.provider === provider);
    const price = provider === "lmstudio" ? { in: 0, out: 0 } : ((grp ? grp.models : []).find((m) => m.id === model) || {}).price;
    USAGE.preview = same ? null : { provider, model, price };
    if (same) { USAGE.pv.textContent = ""; }
    else if (!price) { USAGE.pv.innerHTML = `<span class="warn">No price entered for ${esc(model)} (AI providers > edit > Models), so its cost can't be estimated.</span>`; }
    else {
      const perDay = current && current.interval_minutes ? 1440 / current.interval_minutes : 2;
      const v = USAGE.U.map((u) => runCost(u, price)), avg = v.reduce((a, x) => a + x, 0) / (v.length || 1);
      const rec = USAGE.U.filter((u) => u.cost_usd != null), recAvg = rec.length ? rec.reduce((a, u) => a + u.cost_usd, 0) / rec.length : null;
      USAGE.pv.innerHTML = `With <b>${esc(model)}</b>${chosen ? " (the research job's model)" : ""}: about <b>$${avg.toFixed(2)} per run</b>` +
        (recAvg != null ? ` (the recorded runs averaged $${recAvg.toFixed(2)})` : "") +
        ` · ~$${(avg * 30 * perDay).toFixed(0)} a month at ${+perDay.toFixed(1)} run${perDay === 1 ? "" : "s"} a day. <span class="muted">Same token counts as the recorded runs re-priced at ` +
        `${esc(model)}'s price ($${price.in}/M in, $${price.out}/M out${price.cache_read != null ? `, $${price.cache_read}/M cache reads` : ""}); ` +
        `a different model would use a different number of tokens, so treat this as a rough guide.${chosen ? "" : " Press Save to switch."}</span>`;
    }
    const data = same || !price ? USAGE.U.map(() => null) : USAGE.U.map((u) => runCost(u, price));
    ds.data = data; ds.label = same || !price ? "Cost with selected model ($)" : `Cost with ${model} ($)`; ds.hidden = same || !price;
    if (ch) ch.update();
  }

  // ---- model choice (correlation reviewer + research job) and per-decision model comparison
  let MODELS = null;
  const loadModels = async () => { MODELS = MODELS || await api("/api/llm/models"); for (const g of MODELS.custom || []) PROV[g.provider] = g.name; return MODELS; };
  // the local server; admin-added API-key providers ("api:<id>") get their names from /api/aireview + /api/llm/models
  const PROV = { lmstudio: "Local (LM Studio)" };
  const optKey = (p, m) => `${p}|${m}`;
  function modelSelect(M, cur, placeholder) {
    const sel = document.createElement("select"); sel.className = "llm-sel";
    if (placeholder) sel.add(new Option(placeholder, ""));
    const groups = [["lmstudio", (M.local || []).map((m) => [m.id, m.id + (m.loaded ? " (loaded)" : "")])], ...(M.custom || []).map((g) => [g.provider, g.models.map((m) => [m.id, m.id])])];
    for (const [prov, items] of groups) {
      if (!items.length) continue;
      items.forEach(([id, label]) => sel.add(new Option(`${label} · ${PROV[prov] || prov}`, optKey(prov, id))));
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
    note.textContent = D.admin ? "Correlation reviewer: decides every proposed link, continuously (cloud models are billed per decision batch; local models are free but need LM Studio). Research job: the scheduled triage, event research and daily report - needs a reasoning-capable model (it works through several tool calls per event and decides what to do next between them); give it some extra reasoning tokens on its AI providers row, or pick a local reasoning model (Qwen, DeepSeek-R1...) in LM Studio. Chat: the Ask AI assistant, works on any model. Add cloud models in the AI providers box."
      : "Only an admin can change models.";
    const rows = [["correlation", "Correlation reviewer", D.config?.correlation || {}], ["research", `Research job (${every(null, D.research?.interval_minutes)}) · needs reasoning`, D.research && !D.research.error ? D.research : {}],
      ["chat", "Chat (Ask AI)", D.chat || {}]];
    loadModels().then((M) => {
      if (!(M.custom || []).length && !(M.local || []).length) note.textContent = "No models available yet: add an AI provider below, or start LM Studio. " + note.textContent;
      const reasoningTokens = (provider) => (provider === "lmstudio" ? null : ((M.custom || []).find((g) => g.provider === provider) || {}).reasoning_tokens ?? null);
      for (const [sec, label, cur] of rows) {
        const r = body.appendChild(document.createElement("div")); r.className = "llm-row";
        r.appendChild(Object.assign(document.createElement("span"), { className: "k", textContent: label }));
        const sel = r.appendChild(modelSelect(M, cur, sec === "correlation" ? null : "— choose a model —")); sel.disabled = !D.admin;
        const msg = r.appendChild(Object.assign(document.createElement("span"), { className: "small muted" }));
        const warn = sec === "research" ? r.appendChild(Object.assign(document.createElement("span"), { className: "small warn" })) : null;
        const showWarn = (provider) => { if (!warn) return; const rt = reasoningTokens(provider);
          warn.textContent = rt === 0 ? " ⚠ this provider has 0 reasoning tokens set (AI providers > edit) - research quality will suffer" : ""; };
        msg.textContent = cur.model ? `now: ${PROV[cur.provider] || cur.provider} · ${cur.model}` : sec === "research" ? (D.research?.error || "not set: the research job does not run until a reasoning-capable model is chosen")
          : sec === "chat" ? "not set: chat is off until a model is chosen" : "now: auto (model loaded in LM Studio)";
        if (sec === "research") showWarn(cur.provider);
        if (sec === "research" && cur.model) previewResearchCost(cur.provider, cur.model, M, cur);
        // picking a model applies it straight away (no Save button)
        sel.onchange = async () => {
          if (!D.admin || !sel.value || sel.value === optKey(cur.provider, cur.model)) return;
          const [provider, ...rest] = sel.value.split("|"), model = rest.join("|");
          if (sec === "research") { previewResearchCost(provider, model, M, cur); showWarn(provider); }
          sel.disabled = true; msg.textContent = "switching…";
          try { const r2 = await apiPost("/api/llm/config", { section: sec, provider, model }); const now = r2[sec] || {};
            cur.provider = now.provider; cur.model = now.model; msg.textContent = `now using: ${PROV[now.provider] || now.provider} · ${now.model}`;
            if (sec === "research") { previewResearchCost(now.provider, now.model, M, cur); showWarn(now.provider); } }
          catch (e) { msg.textContent = "error: " + e.message; sel.value = optKey(cur.provider, cur.model); }
          sel.disabled = !D.admin;
        };
      }
      body.appendChild(esQueriesRow(D));
    }).catch((e) => { note.textContent = "Model list unavailable: " + e.message; });
    return c;
  }
  // Elasticsearch look-ups by the correlation reviewer: on/off + the most it may run for one event review (admin)
  function esQueriesRow(D) {
    const cfg = D.config?.es_queries || { enabled: false, max: 3, limit: 20 };
    const r = document.createElement("div"); r.className = "llm-row";
    r.appendChild(Object.assign(document.createElement("span"), { className: "k", textContent: "Elasticsearch queries" }));
    const lab = r.appendChild(document.createElement("label")); lab.className = "small";
    const chk = lab.appendChild(Object.assign(document.createElement("input"), { type: "checkbox", checked: !!cfg.enabled }));
    lab.append(" reviewer may search the logs for more context");
    const lab2 = r.appendChild(document.createElement("label")); lab2.className = "small";
    lab2.append("max per event ");
    const num = lab2.appendChild(Object.assign(document.createElement("input"), { type: "number", min: 1, max: cfg.limit || 20, step: 1, value: cfg.max || 3 }));
    num.style.width = "4.5em"; num.setAttribute("aria-label", "Maximum Elasticsearch queries per event");
    const btn = r.appendChild(Object.assign(document.createElement("button"), { type: "button", textContent: "Save" })); btn.disabled = true;
    const msg = r.appendChild(Object.assign(document.createElement("span"), { className: "small muted" }));
    const show = (c) => (c.enabled ? `now: on · up to ${c.max} per event` : "now: off") + (c.by ? ` (${c.by})` : "");
    msg.textContent = D.admin ? show(cfg) : show(cfg) + " · only an admin can change this";
    chk.disabled = num.disabled = !D.admin;
    const dirty = () => { num.disabled = !D.admin; btn.disabled = !D.admin || (chk.checked === !!cfg.enabled && +num.value === cfg.max); };
    chk.onchange = num.oninput = dirty;
    btn.onclick = async () => {
      const mx = Math.round(+num.value), lim = cfg.limit || 20;
      if (!(mx >= 1 && mx <= lim)) { msg.textContent = `Enter 1-${lim} queries per event.`; return; }
      btn.disabled = true; msg.textContent = "saving…";
      try { const r2 = await apiPost("/api/llm/esqueries", { enabled: chk.checked, max: mx }); Object.assign(cfg, r2.es_queries || {}); msg.textContent = "saved · " + show(cfg) + " (from the next review)"; }
      catch (e) { msg.textContent = "error: " + e.message; btn.disabled = false; }
    };
    r.title = "When on, the correlation reviewer may ask for read-only searches of the Security Onion logs (Zeek, Suricata, detections, endpoint, auth) before it decides an event's links. Each search is one bounded query built and run by the host broker; the model never writes Elasticsearch DSL. The limit counts all searches for one event review (one anchor event and its up to 10 candidates).";
    return r;
  }
  function esCard(D) {
    const E = D.es_queries || { total: 0, last_day: 0, recent: [] }, on = D.config?.es_queries?.enabled;
    const fq = (q) => { if (!q || typeof q !== "object") return esc(String(q || ""));
      const m = Object.entries(q.match || {}).map(([k, v]) => `${k}=${Array.isArray(v) ? v.join("|") : v}`).join(" ");
      return `<span class="mono">${esc(q.source || "?")}</span> ${esc(m)}${q.text ? ` "${esc(q.text)}"` : ""}${q.group_by ? ` <span class="muted">top ${esc(q.group_by)}</span>` : ""}` +
        `${q.start ? ` <span class="muted small">${esc(String(q.start).slice(5, 16))}→${esc(String(q.end || "").slice(5, 16))}</span>` : ""}${q.why ? `<div class="small muted">${esc(q.why)}</div>` : ""}`; };
    const c = card(`Reviewer searches (${fn(E.last_day)} in 24 h · ${fn(E.total)} total)`, E.recent.length ? "" :
      `<div class="small muted">${on ? "The reviewer has not searched Elasticsearch yet." : "Off. Turn on <b>Elasticsearch queries</b> in the Models box to let the reviewer search the logs for more context."}</div>`);
    c.id = "ai-es";
    if (E.recent.length) c.appendChild(table(null, [
      { k: "ts", t: "When", fmt: (v) => esc(ago(v)), sort: (r) => r.ts },
      { k: "anchor_label", t: "Event under review", fmt: (v, r) => (r.anchor_link ? `<a href="${esc(r.anchor_link)}">${esc(v)}</a>` : esc(v)) },
      { k: "query", t: "Search", fmt: (v) => fq(v) },
      { k: "total", t: "Hits", num: true, fmt: (v, r) => (r.error ? `<span class="bad small">${esc(r.error)}</span>` : fn(v)) },
      { k: "model", t: "Model", cls: "small mono" },
    ], E.recent, { sort: "ts", limit: 20 }));
    return c;
  }
  // ---- review limits (admin or network defender): link types and events that are never sent to the correlation reviewer
  const TYPE_INFO = {
    alert: "Watcher alerts: the 15-minute watcher's urgent notices (new device, host notice, policy breach). The most numerous event type.",
    vuln: "Open fix-list issues: vulnerabilities and misconfigurations (code scan findings, endpoint protection off, recurring system errors). Time-less state, related to events by host.",
    finding: "Behaviour findings from the analysis: new signatures, port spikes, threat-intel contacts and other anomalies per device.",
    seg: "Segmentation: cross-zone traffic (e.g. DMZ or server zone reaching into another zone) reported as issues and findings, one per port. Very high volume.",
    ids: "Suricata IDS signatures seen in the window, one event per signature.",
    host: "Endpoint host findings from the agents (new network destinations, processes, policy drift).",
    alarm: "AI triage alarms: rollups the research job writes over the events above.",
    ti: "Threat-intel hits: traffic to or from IPs and domains on blocklists.",
    gw: "UniFi gateway events: IPS threats, WAN, VPN and device events.",
    adm: "Admin sessions (SSH, RDP and similar) between hosts.",
  };
  const tip = (t) => `<span class="info-i" tabindex="0" data-tip="${esc(TYPE_INFO[t] || t)}" role="button" aria-label="About ${esc(t)} events" style="cursor:help;display:inline-block;width:1.2em;height:1.2em;line-height:1.2em;text-align:center;border-radius:50%;background:var(--line,#555);color:#fff;font-size:11px;margin-left:3px">i</span>`;
  if (!window._infoTip) {
    window._infoTip = true;
    let b = null;
    const hide = () => { b?.remove(); b = null; };
    const show = (el) => {
      hide();
      b = document.createElement("div");
      b.textContent = el.dataset.tip;
      b.style.cssText = "position:fixed;z-index:9999;max-width:320px;padding:8px 10px;border-radius:6px;background:#1c2128;color:#e6edf3;border:1px solid #6e7681;font-size:13px;line-height:1.35;box-shadow:0 4px 14px rgba(0,0,0,.5)";
      document.body.appendChild(b);
      const r = el.getBoundingClientRect();
      b.style.left = Math.max(8, Math.min(innerWidth - b.offsetWidth - 8, r.left)) + "px";
      b.style.top = (r.bottom + 6 + b.offsetHeight > innerHeight ? Math.max(8, r.top - b.offsetHeight - 6) : r.bottom + 6) + "px";
    };
    document.addEventListener("click", (e) => { const i = e.target.closest?.(".info-i"); if (i) { e.preventDefault(); e.stopPropagation(); b && b._for === i ? hide() : (show(i), b._for = i); } else hide(); }, true);
    document.addEventListener("mouseover", (e) => { const i = e.target.closest?.(".info-i"); if (i) { show(i); b._for = i; } });
    document.addEventListener("mouseout", (e) => { if (e.target.closest?.(".info-i")) hide(); });
    document.addEventListener("keydown", (e) => { if (e.key === "Escape") hide(); });
    addEventListener("hashchange", hide);
  }
  const pairTip = (pr) => pr.split("-").map((t) => `<span class="mono small">${esc(t)}</span>${tip(t)}`).join(" – ");
  function limitsCard(D) {
    const Lm = D.limits || { pairs: [], top_events: [], excluded: [] };
    const c = card(`Review limits (${fn(Lm.total || 0)} candidate links)`, `
      <div class="small muted">Links that are skipped or excluded here (or set to <b>test</b>, which only lists them as <i>testing</i>) are never sent to the reviewer (no model call) and leave the queue. Links that already have a verdict are kept.
        Changes apply from the next review round.</div>
      <div style="margin:10px 0 4px"><b>Max links per event</b> <input type="number" class="rl-max" min="0" max="${Lm.limit_range || 200}" step="1" style="width:5em">
        <button type="button" class="rl-maxsave">Save</button>
        <span class="small muted">Each event is reviewed against at most this many links, best-scoring first (0 = no cap). Applies to links without a verdict; a link needs room at both of its events.</span></div>
      <h3 style="margin:10px 0 4px">Event types</h3>
      <div class="rl-pairs" style="display:grid;grid-template-columns:auto auto auto;gap:4px 14px;justify-content:start"></div>
      <h3 style="margin:12px 0 4px">Events with the most links</h3><div class="rl-top"></div>
      <h3 style="margin:12px 0 4px">Never send (${(Lm.rules || []).length} rules)</h3>
      <div class="small muted">Stop sending a class of events to the AI by name, or by host and ID. Fill in one field or several (all must match). Name: part of the event text, or a pattern with * ?.
        Host: an IP, or text that appears in the event. ID: the event id, e.g. <span class="mono">ids|ET DNS*</span> or <span class="mono">iss|seg|*</span>. Scope: the research job, the correlation reviewer, or both.</div>
      <div class="rl-form" style="display:${D.can_limit ? "flex" : "none"};gap:6px;flex-wrap:wrap;margin:6px 0"><input name="name" placeholder="name contains…" style="width:14em"><input name="host" placeholder="host / IP" style="width:11em">
        <input name="id" placeholder="event ID pattern" style="width:16em"><select name="scope"><option value="both">research + review</option><option value="research">research only</option><option value="review">review only</option></select>
        <button type="button" class="rl-add">Add rule</button></div>
      <div class="rl-rules"></div>
      <h3 style="margin:12px 0 4px">Excluded (${(Lm.excluded || []).length})</h3><div class="rl-ex"></div>
      <div class="small muted rl-msg" style="margin-top:6px">${D.can_limit ? "" : "Only an admin or network defender can change these limits."}</div>`);
    c.id = "ai-limits";
    const msg = c.querySelector(".rl-msg");
    const post = async (b) => { msg.textContent = "saving…";
      try { await apiPost("/api/llm/review-limits", b); location.reload(); }
      catch (e) { msg.textContent = "error: " + e.message; } };
    const mx = c.querySelector(".rl-max"), mxb = c.querySelector(".rl-maxsave");
    mx.value = Lm.max_links || 0; mx.disabled = mxb.disabled = !D.can_limit;
    mxb.onclick = () => post({ max_links: mx.value === "" ? 0 : +mx.value });
    const pairs = c.querySelector(".rl-pairs");
    pairs.innerHTML = (Lm.pairs || []).map((p) => `<span>${pairTip(p.pair)}</span><span class="small">${fn(p.links)} links</span>
      <select data-pair="${esc(p.pair)}">${["review", "skip", "test"].map((m) => `<option value="${m}"${p.mode === m ? " selected" : ""}>${m}</option>`).join("")}</select>`).join("");
    for (const s of pairs.querySelectorAll("select")) { s.disabled = !D.can_limit;
      s.onchange = () => post({ pair_modes: Object.fromEntries([...pairs.querySelectorAll("select")].map((x) => [x.dataset.pair, x.value])) }); }
    const top = c.querySelector(".rl-top");
    top.innerHTML = (Lm.top_events || []).map((e, i) => `<div class="small" style="display:flex;gap:8px;align-items:center;margin:2px 0">
      <span style="width:3.5em;text-align:right"><b>${fn(e.links)}</b></span><span class="mono muted" style="width:6em">${esc(e.type)}${tip(e.type)}</span><span style="flex:1">${esc(e.label)}</span>
      ${D.can_limit ? (e.excluded || e.family_excluded ? '<span class="muted">excluded</span>' : `<button type="button" data-i="${i}" data-mode="event">exclude</button><button type="button" data-i="${i}" data-mode="family" title="same kind of event: ports and alert numbers ignored">exclude similar</button>`) : ""}</div>`).join("");
    for (const b of top.querySelectorAll("button")) b.onclick = () => { const e = Lm.top_events[+b.dataset.i]; post({ exclude: { id: e.id, mode: b.dataset.mode, label: e.label } }); };
    const rf = c.querySelector(".rl-form"), rr = c.querySelector(".rl-rules");
    c.querySelector(".rl-add").onclick = () => { const f = (n) => rf.querySelector(`[name=${n}]`).value; post({ rule: { name: f("name"), host: f("host"), id: f("id"), scope: f("scope") } }); };
    rr.innerHTML = (Lm.rules || []).length ? Lm.rules.map((x, i) => `<div class="small" style="display:flex;gap:8px;align-items:center;margin:2px 0">
      <span class="mono muted" style="width:9em">${esc(x.scope)}</span><span style="flex:1">${[x.name && `name: <b>${esc(x.name)}</b>`, x.host && `host: <b>${esc(x.host)}</b>`, x.id && `id: <b class="mono">${esc(x.id)}</b>`].filter(Boolean).join(" · ")}</span>
      <span class="muted">${esc(x.by || "")}</span>${D.can_limit ? `<button type="button" data-i="${i}">remove</button>` : ""}</div>`).join("") : '<div class="small muted">None.</div>';
    for (const b of rr.querySelectorAll("button")) b.onclick = () => post({ unrule: Lm.rules[+b.dataset.i].key });
    const ex = c.querySelector(".rl-ex");
    ex.innerHTML = (Lm.excluded || []).length ? Lm.excluded.map((x, i) => `<div class="small" style="display:flex;gap:8px;align-items:center;margin:2px 0">
      <span class="mono muted" style="width:5em">${esc(x.mode)}</span><span style="flex:1">${esc(x.label)}</span><span class="muted">${esc(x.by || "")}</span>
      ${D.can_limit ? `<button type="button" data-i="${i}">remove</button>` : ""}</div>`).join("") : '<div class="small muted">None.</div>';
    for (const b of ex.querySelectorAll("button")) b.onclick = () => post({ unexclude: Lm.excluded[+b.dataset.i].key });
    return c;
  }
  // ---- AI providers (admin): any OpenAI-compatible or Anthropic API with a key, called by the dashboard itself
  function providersCard() {
    const c = card("AI providers", `<div class="small muted"><b>Local (LM Studio)</b> is the LM Studio server on this host (no key; its enabled flag and rate limit can be set here;
      the model list comes live from LM Studio). Add any number of other AI services that take an API key. <b>OpenAI / OpenAI-compatible</b> covers
      OpenAI itself and services with the same API (OpenRouter, Groq, Mistral, Together, DeepSeek, Gemini's OpenAI endpoint, a self-hosted vLLM...);
      <b>Anthropic</b> is Anthropic's API with an Anthropic API key. Their models can be picked for the correlation reviewer, the research job and the chat,
      and in every Compare dialog. Keys are stored on the dashboard's state volume (readable only by netmon) and never shown again.</div>
      <div class="prov-list" style="margin-top:8px"></div><div class="prov-form"></div>
      <div style="margin-top:8px"><button type="button" class="prov-add">Add provider</button> <span class="small muted prov-msg"></span></div>`);
    c.id = "ai-providers";
    const list = c.querySelector(".prov-list"), formBox = c.querySelector(".prov-form"), msg = c.querySelector(".prov-msg");
    let P = [], TYPES = {};
    const draw = () => {
      if (!P.length) { list.innerHTML = `<div class="small muted">No providers yet.</div>`; return; }
      list.replaceChildren(table(null, [
        { k: "name", t: "Name", sort: (r) => (r.local ? "0" : "1") + String(r.name).toLowerCase(),
          fmt: (v, r) => `<b>${esc(v)}</b>${r.enabled ? "" : ' <span class="badge sev-unknown">off</span>'}` },
        { k: "type_label", t: "Type" },
        { k: "base_url", t: "Base URL", cls: "small mono" },
        { k: "key_hint", t: "Key", cls: "small mono", fmt: (v, r) => (r.key_set ? esc(v) : '<span class="bad">missing</span>') },
        { k: "models", t: "Models", fmt: (v) => (v.length ? `<span title="${esc(v.join(", "))}">${v.length}: ${esc(v.slice(0, 3).join(", "))}${v.length > 3 ? "…" : ""}</span>` : '<span class="warn">none - add some</span>') },
        { k: "rate_per_hour", t: "Calls/h", num: true, fmt: (v, r) => `${fn(r.calls_last_hour)} / ${fn(v)}` },
        { k: "_a", t: "", fmt: (v, r) => `<span class="ai-acts"><button data-pe="${esc(r.id)}" title="Edit">✎</button>${r.local ? "" : `<button data-pt="${esc(r.id)}" title="Test the key">Test</button><button data-pd="${esc(r.id)}" title="Delete">✕</button>`}</span>` },
      ], P, { sort: "name", dir: 1 }));
    };
    const load = async () => { try { const d = await api("/api/llm/providers"); P = d.providers || []; TYPES = d.types || {}; draw(); } catch (e) { list.textContent = "error: " + e.message; } };
    const reloadModels = () => { MODELS = null; msg.textContent += " · reload the page to see the change in the model menus"; };
    // model rows: drop-down per model + separate price boxes; avail = ids offered in the drop-downs. Used by both forms.
    function modelPicker(p, avail) {
      const AVAIL = new Set(avail), mbox = formBox.querySelector(".pf-models");
      const optHtml = (cur) => [...new Set([...AVAIL, ...(cur ? [cur] : [])])].map((m) => `<option value="${esc(m)}"${m === cur ? " selected" : ""}>${esc(m)}</option>`).join("") +
        `<option value="__custom">Custom…</option>`;
      const addRow = (id, pr) => { const r = mbox.appendChild(document.createElement("div")); r.className = "pf-mrow"; r.style.cssText = "display:flex;gap:6px;flex-wrap:wrap;align-items:center;margin-bottom:5px";
        r.innerHTML = `<select class="m-sel mono" style="min-width:16em"><option value="">- choose a model -</option>${optHtml(id)}</select>
          <input class="m-custom mono" placeholder="model id" spellcheck="false" style="display:none;width:14em">
          <input class="m-in" type="number" min="0" step="any" placeholder="input $/M" title="Input price, $ per million tokens" style="width:8em" value="${esc((pr || [])[0] ?? "")}">
          <input class="m-out" type="number" min="0" step="any" placeholder="output $/M" title="Output price, $ per million tokens" style="width:8em" value="${esc((pr || [])[1] ?? "")}">
          <input class="m-cache" type="number" min="0" step="any" placeholder="cached $/M" title="Cached input price, $ per million tokens (optional)" style="width:8em" value="${esc((pr || [])[2] ?? "")}">
          <button type="button" class="m-del" title="Remove">✕</button>`;
        const sel = r.querySelector(".m-sel"), cu = r.querySelector(".m-custom");
        sel.onchange = () => { cu.style.display = sel.value === "__custom" ? "" : "none"; if (sel.value === "__custom") cu.focus(); };
        r.querySelector(".m-del").onclick = () => r.remove(); };
      (p.models || []).forEach((m) => addRow(m, (p.prices || {})[m]));
      if (!(p.models || []).length) addRow("", null);
      formBox.querySelector(".pf-add").onclick = () => addRow("", null);
      const modelsText = () => [...mbox.querySelectorAll(".pf-mrow")].map((r) => { const sv = r.querySelector(".m-sel").value, id = (sv === "__custom" ? r.querySelector(".m-custom").value : sv).trim().replace(/\s+/g, "");
        if (!id) return ""; const pr = [".m-in", ".m-out", ".m-cache"].map((q) => r.querySelector(q).value.trim());
        if (!pr[0] && !pr[1]) return id; return [id, pr[0] || "0", pr[1] || "0", ...(pr[2] ? [pr[2]] : [])].join("  "); }).filter(Boolean).join("\n");
      const refreshOpts = () => { for (const r2 of mbox.querySelectorAll(".pf-mrow")) { const sel = r2.querySelector(".m-sel"), cur = sel.value;
        sel.innerHTML = `<option value="">- choose a model -</option>${optHtml(cur === "__custom" ? "" : cur)}`; sel.value = cur; } };
      return { AVAIL, mbox, modelsText, refreshOpts };
    }
    function localForm(p) {
      formBox.innerHTML = `<div class="llm-grid" style="margin-top:10px;border-top:1px solid var(--border);padding-top:10px">
        <div class="llm-row"><span class="k">Local (LM Studio)</span><span class="small muted">${esc(p.base_url)} - ${(p.available || []).length} model(s) installed</span></div>
        <div class="llm-row" style="align-items:flex-start"><span class="k">Models</span>
          <span style="flex:1 1 520px"><div class="pf-models"></div>
            <button type="button" class="pf-add">+ Add model</button>
            <div class="small muted">Pick the LM Studio models that can be used, from the drop-down of what is installed. Prices are optional, $ per million tokens (empty = free).</div></span></div>
        <div class="llm-row"><span class="k">Calls per hour</span><input name="rate_per_hour" type="number" min="1" max="3000" style="width:7em">
          <span class="small muted">cap on single calls (correlation reviewer + comparisons) - limits cost/load if something loops</span></div>
        <div class="llm-row"><span class="k">Enabled</span><label class="small"><input name="enabled" type="checkbox"> its models can be picked and used</label></div>
        <div class="llm-row"><span class="k"></span><button type="button" class="pf-save">Save</button><button type="button" class="pf-cancel">Cancel</button>
          <span class="small muted pf-msg"></span></div></div>`;
      const f = (n) => formBox.querySelector(`[name="${n}"]`), fm = formBox.querySelector(".pf-msg");
      f("rate_per_hour").value = p.rate_per_hour; f("enabled").checked = p.enabled !== false;
      const { modelsText } = modelPicker(p, p.available || p.models || []);
      formBox.querySelector(".pf-cancel").onclick = () => { formBox.innerHTML = ""; };
      formBox.querySelector(".pf-save").onclick = async (ev) => {
        ev.target.disabled = true; fm.textContent = "saving…";
        try {
          const r = await apiPost("/api/llm/providers", { action: "save", id: p.id, rate_per_hour: f("rate_per_hour").value, models: modelsText(), enabled: f("enabled").checked });
          P = r.providers || P; draw(); formBox.innerHTML = ""; msg.textContent = "saved Local (LM Studio)"; reloadModels();
        } catch (e) { fm.textContent = "error: " + e.message; ev.target.disabled = false; }
      };
    }
    function form(p) {
      if (p && p.local) return localForm(p);
      p = p || { type: "openai", enabled: true, rate_per_hour: 120, reasoning_tokens: 3000, models: [] };
      formBox.innerHTML = `<div class="llm-grid" style="margin-top:10px;border-top:1px solid var(--border);padding-top:10px">
        <div class="llm-row"><span class="k">Name</span><input name="name" class="llm-sel" maxlength="60" placeholder="e.g. OpenAI, OpenRouter, Anthropic (work)"></div>
        <div class="llm-row"><span class="k">Type</span><select name="type" class="llm-sel">${Object.entries(TYPES).map(([k, t]) => `<option value="${esc(k)}">${esc(t.label)}</option>`).join("")}</select></div>
        <div class="llm-row"><span class="k">Base URL</span><input name="base_url" class="llm-sel mono" spellcheck="false"><span class="small muted">empty = the official API</span></div>
        <div class="llm-row"><span class="k">API key</span><input name="api_key" type="password" autocomplete="off" spellcheck="false" class="llm-sel"></div>
        <div class="llm-row" style="align-items:flex-start"><span class="k">Models</span>
          <span style="flex:1 1 520px"><div class="pf-models"></div>
            <button type="button" class="pf-add">+ Add model</button> <button type="button" class="pf-fetch">Fetch available models from provider</button>
            <div class="small muted">Pick each model from the drop-down (use Fetch to fill it, or choose "Custom…" to type an id). Prices are optional, in $ per million tokens; with them the dashboard estimates costs and enforces the research job's $ caps (token caps work without).</div></span></div>
        <div class="llm-row"><span class="k">Calls per hour</span><input name="rate_per_hour" type="number" min="1" max="3000" style="width:7em">
          <span class="small muted">cap on this provider's single calls (correlation reviewer + comparisons) - limits cost if something loops</span></div>
        <div class="llm-row"><span class="k">Extra reasoning tokens</span><input name="reasoning_tokens" type="number" min="0" max="32000" step="500" style="width:7em">
          <span class="small muted">added to each answer's token limit for models that think first (OpenAI gpt-5 / o-series: ~3000; others 0)</span></div>
        <div class="llm-row"><span class="k">Enabled</span><label class="small"><input name="enabled" type="checkbox"> its models can be picked and used</label></div>
        <div class="llm-row"><span class="k"></span><button type="button" class="pf-save">Save</button><button type="button" class="pf-test">Test key</button><button type="button" class="pf-cancel">Cancel</button>
          <span class="small muted pf-msg"></span></div></div>`;
      const f = (n) => formBox.querySelector(`[name="${n}"]`), fm = formBox.querySelector(".pf-msg");
      f("name").value = p.name || ""; f("type").value = p.type; f("base_url").value = p.base_url || "";
      const { AVAIL, mbox, modelsText, refreshOpts } = modelPicker(p, p.models || []);
      f("rate_per_hour").value = p.rate_per_hour; f("reasoning_tokens").value = p.reasoning_tokens; f("enabled").checked = p.enabled !== false;
      const ph = () => { f("base_url").placeholder = (TYPES[f("type").value] || {}).base_url || "";
        f("api_key").placeholder = p.key_set ? `saved (${p.key_hint}) - leave empty to keep it` : f("type").value === "anthropic" ? "sk-ant-..." : "sk-..."; };
      f("type").onchange = () => { ph(); if (!p.id) f("reasoning_tokens").value = f("type").value === "openai" ? 3000 : 0; }; ph();
      const val = () => ({ id: p.id, name: f("name").value.trim(), type: f("type").value, base_url: f("base_url").value.trim(), api_key: f("api_key").value.trim(),
        models: modelsText(), rate_per_hour: f("rate_per_hour").value, reasoning_tokens: f("reasoning_tokens").value, enabled: f("enabled").checked });
      const run = async (btn, body, what, done) => { btn.disabled = true; fm.textContent = what;
        try { done(await apiPost("/api/llm/providers", body)); } catch (e) { fm.textContent = "error: " + e.message; } btn.disabled = false; };
      formBox.querySelector(".pf-cancel").onclick = () => { formBox.innerHTML = ""; };
      formBox.querySelector(".pf-test").onclick = (ev) => run(ev.target, { ...val(), action: "test" }, "checking the key…", (r) => { fm.textContent = "✓ " + r.message; });
      formBox.querySelector(".pf-fetch").onclick = (ev) => run(ev.target, { ...val(), action: "models" }, "asking the provider for its models…", (r) => {
        r.models.forEach((m) => AVAIL.add(m)); refreshOpts();
        fm.textContent = `${r.models.length} chat models available (of ${r.all}) - pick them in the drop-downs.`; });
      formBox.querySelector(".pf-save").onclick = (ev) => run(ev.target, { ...val(), action: "save" }, "saving…", (r) => {
        P = r.providers || P; draw(); formBox.innerHTML = ""; msg.textContent = `saved ${r.provider.name}`; reloadModels(); });
      f("name").focus();
    }
    c.querySelector(".prov-add").onclick = () => form(null);
    list.addEventListener("click", async (ev) => {
      const b = ev.target.closest("button"); if (!b) return;
      const p = P.find((x) => x.id === (b.dataset.pe || b.dataset.pt || b.dataset.pd)); if (!p) return;
      if (b.dataset.pe) form(p);
      else if (b.dataset.pt) { b.disabled = true; msg.textContent = `testing ${p.name}…`;
        try { const r = await apiPost("/api/llm/providers", { action: "test", id: p.id, type: p.type, base_url: p.base_url }); msg.textContent = `${p.name}: ✓ ${r.message}`; }
        catch (e) { msg.textContent = `${p.name}: ${e.message}`; } b.disabled = false; }
      else if (b.dataset.pd && confirm(`Delete the AI provider "${p.name}" and its stored API key?`)) {
        try { const r = await apiPost("/api/llm/providers", { action: "delete", id: p.id }); P = r.providers || []; draw(); msg.textContent = `deleted ${p.name}`; reloadModels(); }
        catch (e) { msg.textContent = "error: " + e.message; } }
    });
    load();
    return c;
  }

  // ---- research job cost caps (research_cfg.py): $ per run / per day, tokens per run, research batches per run
  function costCard(D) {
    const R = D.research || {}, L = R.limits || {}, T = "Research job limits";
    if (R.error) { const e = card(T, `<div class="bad">Limits unavailable: ${esc(R.error)}</div>`); e.id = "ai-cost"; return e; }
    const U = (((D.research_status || {}).jobs || [])[0]?.usage || []).filter((u) => u.cost_usd != null).map((u) => u.cost_usd);
    const avg = U.length ? U.reduce((a, v) => a + v, 0) / U.length : null, max = U.length ? Math.max(...U) : null;
    const usd = (v) => `$${(+v).toFixed(2)}`;
    const c = card(T, `
      <div class="small muted">The research job adds up the tokens of every model call and, when the model has a price (AI providers > Models), the
        estimated cost. A run stops at the next model call once a limit below is passed; what it found until then is kept. <b>0 = no limit.</b></div>
      <div class="llm-grid" style="margin-top:10px">
        <div class="llm-row"><span class="k">$ per run</span><span>$ <input type="number" name="max_run_usd" min="0" max="1000" step="0.5" style="width:7em"></span>
          <span class="small muted" style="flex:1 1 380px">Stops one run that goes wrong (loops, huge web research).
            ${avg != null ? `Recent runs cost about <b>${usd(avg)}</b> each (highest ${usd(max)}, last ${U.length} runs).` : ""} <span class="cost-warn bad"></span></span></div>
        <div class="llm-row"><span class="k">$ per day</span><span>$ <input type="number" name="max_day_usd" min="0" max="5000" step="1" style="width:7em"></span>
          <span class="small muted" style="flex:1 1 380px">No new run starts once today's runs (UTC) cost this much. Spent today: <b>${usd(R.spent_today_usd || 0)}</b>.</span></div>
        <div class="llm-row"><span class="k">Tokens per run</span><span><input type="number" name="max_run_tokens" min="0" max="100000000" step="100000" style="width:9em"></span>
          <span class="small muted" style="flex:1 1 380px">Input + output tokens of all calls in one run. Works for models without a price, too.</span></div>
        <div class="llm-row"><span class="k">Research batches</span><span><input type="number" name="max_batches" min="0" max="40" step="1" style="width:5em"></span>
          <span class="small muted" style="flex:1 1 380px">Event-research conversations per run (8 events each). Fewer batches = cheaper runs; events left over are picked up by the next run.</span></div>
        <div class="llm-row"><span class="k">Searches per event</span><span><input type="number" name="max_searches" min="0" max="20" step="1" style="width:5em"></span>
          <span class="small muted" style="flex:1 1 380px">Web searches allowed per event in event research (a batch of 8 events shares 8 times this). Reading pages you already found is not counted. 0 = no limit. Ignored when web research is off.</span></div>
        <div class="llm-row"><span class="k">Web research</span><span><label><input type="checkbox" name="web_research"> on</label></span>
          <span class="small muted" style="flex:1 1 380px">Lets the model search and read web pages and cite them. Turn it off for cheaper, local-data-only runs (no web tools, no links or citations, and the daily news briefing is skipped).</span></div>
        <div class="llm-row"><span class="k">PDF report</span><span><label><input type="checkbox" name="pdf_report"> on</label></span>
          <span class="small muted" style="flex:1 1 380px">Renders the daily PDF on the first run after 05:00 UTC. Turn it off to stop making PDFs: that run still covers 24 h, triages and writes the briefing, and the Reports page keeps the existing files.</span></div>
        <div class="llm-row" style="align-items:flex-start"><span class="k">Events to research</span>
          <span class="rj-modes" style="display:grid;grid-template-columns:auto auto;gap:4px 14px">${(R.mode_cats || []).map((m) => `<span class="small">${esc(m.label)}</span>
            <select name="mode_${esc(m.key)}" data-cat="${esc(m.key)}">${(R.mode_options || ["research", "review", "skip"]).map((o) => `<option value="${esc(o)}">${esc(o)}</option>`).join("")}</select>`).join("")}</span>
          <span class="small muted" style="flex:1 1 380px"><b>research</b>: sent to the model (a repeat that already has a note is only rewritten if the new run contradicts it).
            <b>review</b>: never sent to the model; matched against earlier research (the event's own note and the notes of correlated events) and left alone if it was researched before.
            <b>skip</b>: ignored. <b>test</b>: queued and tagged <i>testing</i> in the lists above, but never sent to the model; use it to see what a setting would send (filters still apply). New deployments start in test. Changes apply from the next run.</span></div>
      </div>
      <div class="small muted" style="margin-top:8px">The correlation reviewer and comparisons make single calls and are capped per provider (AI providers > Calls per hour) instead;
        chat answers are capped at 600,000 tokens each. Local LM Studio models cost $0.</div>
      <div style="margin-top:8px"><button type="button" class="cost-save">Save</button> <span class="small muted cost-msg"></span></div>`);
    c.id = "ai-cost";
    const K = ["max_run_usd", "max_day_usd", "max_run_tokens", "max_batches", "max_searches"];
    const inp = (k) => c.querySelector(`input[name="${k}"]`), btn = c.querySelector(".cost-save"), msg = c.querySelector(".cost-msg");
    const modeSel = () => [...c.querySelectorAll(".rj-modes select")];
    const warn = () => { const r = +inp("max_run_usd").value || 0, over = r ? U.filter((v) => v > r).length : 0;
      c.querySelector(".cost-warn").textContent = r && avg != null && r < avg ? " Below the usual run cost: most runs would stop before finishing."
        : over ? ` ${over} of the last ${U.length} runs cost more than this.` : ""; };
    const web = c.querySelector('input[name="web_research"]');
    const pdfc = c.querySelector('input[name="pdf_report"]');
    const fill = (v) => { for (const k of K) inp(k).value = v[k] ?? 0; web.checked = v.web_research === true; pdfc.checked = v.pdf_report === true;
      for (const b of modeSel()) b.value = (v.modes || {})[b.dataset.cat] || "research"; warn(); };
    fill({ ...L, modes: R.modes, web_research: R.web_research, pdf_report: R.pdf_report });
    for (const k of K) { inp(k).disabled = !D.admin; inp(k).oninput = () => { btn.disabled = !D.admin; warn(); }; }
    web.disabled = !D.admin; web.onchange = () => { btn.disabled = !D.admin; };
    pdfc.disabled = !D.admin; pdfc.onchange = () => { btn.disabled = !D.admin; };
    for (const b of modeSel()) { b.disabled = !D.admin; b.onchange = () => { btn.disabled = !D.admin; }; }
    btn.disabled = true;
    if (!D.admin) msg.textContent = "Only an admin can change the limits.";
    btn.onclick = async () => {
      const body = {};
      for (const k of K) body[k] = inp(k).value === "" ? 0 : +inp(k).value;
      body.web_research = web.checked; body.pdf_report = pdfc.checked;
      body.modes = Object.fromEntries(modeSel().map((b) => [b.dataset.cat, b.value]));
      if (Object.values(body.modes).every((m) => m === "skip")) { msg.textContent = "error: pick research or review for at least one category"; return; }
      btn.disabled = true; msg.textContent = "saving…";
      try { const r = await apiPost("/api/llm/research", body); fill({ ...(r.research.limits || body), modes: r.research.modes || body.modes, web_research: r.research.web_research, pdf_report: r.research.pdf_report }); msg.textContent = "saved (applies from the next run)"; }
      catch (e) { msg.textContent = "error: " + e.message; btn.disabled = false; }
    };
    return c;
  }

  // research job lookback window (lookback.py, store meta "research_lookback"): hours of logs each run collects
  function lookbackCard(D) {
    const L = D.lookback || { hours: 24, min: 1, max: 24, pdf_hour: 5 };
    const iv = D.research?.interval_minutes, ivH = iv ? iv / 60 : null;
    const rec = ivH ? Math.min(L.max, Math.ceil(ivH) + 1) : null;
    const T = "Research lookback window";
    const c = card(T, `
      <div class="small muted">How many hours of logs each research run collects and reviews. Shorter windows mean fewer events and fewer
        tool calls per run, so each run costs less. Every run looks back from the moment it starts.</div>
      <div class="llm-grid" style="margin-top:10px">
        <div class="llm-row"><span class="k">Look back</span>
          <span><input type="number" name="lb_hours" min="${L.min}" max="${L.max}" step="1" style="width:5em"> hours</span>
          <span class="small muted" style="flex:1 1 380px">${ivH ? `The job runs every <b>${esc(String(+ivH.toFixed(2)))} h</b>. Suggested: <b>${rec} h</b> (the interval plus 1 h of overlap, so no event falls between two runs).`
            : "The job schedule is not known, so no suggestion can be given."}
            <span class="lb-warn"></span></span></div>
      </div>
      <ul class="small muted" style="margin:8px 0 0 18px;padding:0">
        <li>The daily PDF run (${String(L.pdf_hour).padStart(2, "0")}:00 UTC) always covers 24 h, so the report and the device baseline stay daily. Only full-day snapshots are added to the baseline.</li>
        <li>Shorter runs compare volumes with the 24 h baseline scaled down to the window, and skip the "device went silent" check.</li>
        <li>The dashboard's newest snapshot covers only this window between PDF runs. A short run can open a Fix-list item but never mark it fixed.</li>
      </ul>
      <div style="margin-top:8px"><button type="button" class="lb-save">Save</button> <span class="small muted lb-msg"></span></div>
      <div class="small muted" style="margin-top:6px">${L.at ? `Last changed by ${esc(L.by || "?")} ${esc(ago(L.at))}.` : `Not changed yet: default ${L.default ?? 24} h.`} Applies from the next run.</div>`);
    c.id = "ai-lookback";
    const inp = c.querySelector('input[name="lb_hours"]'), btn = c.querySelector(".lb-save"), msg = c.querySelector(".lb-msg"), wr = c.querySelector(".lb-warn");
    const warn = () => { const h = +inp.value;
      wr.className = "lb-warn " + (ivH && h < ivH ? "bad" : "");
      wr.textContent = ivH && h && h < ivH ? ` Shorter than the run interval: about ${+(ivH - h).toFixed(2)} h of logs between runs will never be reviewed (only the 24 h PDF run sees them).`
        : ivH && h >= 2 * ivH && h > rec ? ` Each run re-reviews about ${+(h - ivH).toFixed(1)} h that the previous run already covered.` : ""; };
    inp.value = L.hours; warn();
    inp.disabled = !D.admin; btn.disabled = true;
    inp.oninput = () => { btn.disabled = !D.admin; warn(); };
    if (!D.admin) msg.textContent = "Only an admin can change the lookback window.";
    btn.onclick = async () => {
      const h = inp.value.trim();
      if (!/^\d+$/.test(h) || +h < L.min || +h > L.max) { msg.textContent = `Enter a whole number of hours from ${L.min} to ${L.max}.`; return; }
      btn.disabled = true; msg.textContent = "saving…";
      try { const r = await apiPost("/api/config/lookback", { hours: +h }); inp.value = r.lookback.hours; warn();
        msg.textContent = `saved: ${r.lookback.hours} h per run (from the next run; the PDF run stays 24 h)`; }
      catch (e) { msg.textContent = "error: " + e.message; btn.disabled = false; }
    };
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
      const def = new Set([optKey(cor.provider, curLocal), optKey(D.research?.provider, D.research?.model)]);
      const all = [...(M.local || []).map((m) => ["lmstudio", m.id, m.loaded ? " (loaded)" : " (not loaded: LM Studio loads it first, slow)"]),
        ...(M.custom || []).flatMap((g) => g.models.map((m) => [g.provider, m.id, ""]))];
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
    el.innerHTML = `<h1>AI review</h1><div class="sub">The correlation script proposes links between events and vulnerabilities. The correlation reviewer (an AI model) decides whether each link is real, and on the research schedule the research job's model researches the important events and re-reviews their links (its verdicts replace the reviewer's). Rejected links are hidden from the Related column; confirmed ones show the model's reason. Here you can watch the review, check its decisions and override them.</div><div class="loading">Loading…</div>`;
    let D; try { D = await api("/api/aireview"); } catch (e) { el.querySelector(".loading").outerHTML = `<pre>${esc(e)}</pre>`; return; }
    el.querySelector(".loading").remove();
    Object.assign(PROV, D.provider_names || {});
    const st = D.status, q = D.queue, T = D.totals;
    const health = !st.enabled ? ["Off", "sev-unknown"] : st.error ? ["Error", "sev-high"] : st.busy ? ["Reviewing", "sev-good"] : q.pending ? ["Waiting", "sev-medium"] : ["Idle · up to date", "sev-good"];
    el.insertAdjacentHTML("beforeend", kpis([
      ["Status", `<span class="badge ${health[1]}" style="font-size:14px">${health[0]}</span>`],
      ["Awaiting research", (D.research_status || {}).queue ? (D.admin ? `<a href="#/aireview" class="rq-open">${fn(D.research_status.queue.count)}</a>` : fn(D.research_status.queue.count)) + (D.research_status.queue.testing ? ` <span class="badge sev-unknown" style="font-size:11px" title="held in test mode: listed, never sent">+${fn(D.research_status.queue.testing)} testing</span>` : "") : "?",
        (D.research_status || {}).queue?.count ? "warn" : "good"],
      ["Awaiting review", `<a href="#/aireview" class="rv-open">${fn(q.pending)}</a>` + (q.testing ? ` <span class="badge sev-unknown" style="font-size:11px" title="held in test mode: listed, never sent">+${fn(q.testing)} testing</span>` : ""), q.pending ? "warn" : "good"],
      ["Confirmed (this snapshot)", `<a href="#/aireview?verdict=confirmed&scope=current&at=ai-list">${fn(q.confirmed)}</a>`, "good"],
      ["Rejected (this snapshot)", `<a href="#/aireview?verdict=rejected&scope=current&at=ai-list">${fn(q.rejected)}</a>`, q.rejected ? "bad" : ""],
      ["Reviews / min", `${fn(T.rate_per_min ?? 0)}`, T.rate_per_min ? "good" : ""], ["Tokens / min", fn(T.tokens_per_min ?? 0), T.tokens_per_min ? "good" : ""], ["Tokens / sec", T.tokens_per_sec == null ? "—" : T.tokens_per_sec.toFixed(1), T.tokens_per_sec ? "good" : ""], ["Reviews / hour", fn(T.rate_per_hour)], ["Done in", q.eta_min == null ? (q.pending ? "?" : "—") : q.eta_min < 90 ? `~${q.eta_min} min` : `~${(q.eta_min / 60).toFixed(1)} h`]]));

    if (D.admin) {
      const bar = document.createElement("div"); bar.style.cssText = "margin:8px 0;display:flex;gap:8px;flex-wrap:wrap;align-items:center";
      bar.innerHTML = '<button type="button" class="clr-rq">Clear research queue</button><button type="button" class="clr-rv">Clear review queue</button><span class="small muted clr-msg"></span>';
      el.querySelector(".kpis").after(bar);
      const msg = bar.querySelector(".clr-msg");
      const go = async (path, warn) => {
        if (!confirm(warn)) return;
        msg.textContent = "clearing…";
        try { const r = await apiPost(path, {}); msg.textContent = `done (${fn(r.dismissed || 0)} dismissed)`; setTimeout(() => location.reload(), 800); }
        catch (e) { msg.textContent = "error: " + e.message; }
      };
      bar.querySelector(".clr-rq").onclick = () => go("/api/aireview/clear-research",
        `WARNING: this removes every event currently waiting for research (${fn((D.research_status || {}).queue?.count || 0)}) from the queue.\n\nThey will NOT be researched, even if they occur again under the same ID. Existing notes are kept. New events are still researched.\n\nThis cannot be undone from the page. Continue?`);
      bar.querySelector(".clr-rv").onclick = () => go("/api/aireview/clear-review",
        `WARNING: this marks every link currently waiting for review (${fn(q.pending)}) as "not related" without asking the model.\n\nThose links will be hidden from the Related column and never reviewed. Existing verdicts are kept. New events are still reviewed.\n\nThis cannot be undone from the page. Continue?`);
    }
    const rqa = el.querySelector(".rq-open");
    if (rqa) rqa.onclick = async (ev) => {
      ev.preventDefault();
      let box = el.querySelector("#ai-rq");
      if (box) { box.remove(); return; }
      box = card("Events awaiting research", '<div class="small muted">Loading…</div>'); box.id = "ai-rq";
      (el.querySelector(".kpis") || el.lastElementChild).after(box);
      try {
        const Q = await api("/api/aireview/research-queue");
        box.querySelector(".small").outerHTML = `<div class="small muted">${fn(Q.count || 0)} events the next run would send to the model (research mode, no note yet)${Q.testing ? `, plus ${fn(Q.testing)} tagged <i>testing</i> (test mode: listed, never sent)` : ""}. Snapshot ${esc(Q.snapshot || "")}.</div>`;
        if (Q.items?.length) box.appendChild(table(null, [
          { k: "type", t: "Type", cls: "mono small" }, { k: "sev", t: "Severity" },
          { k: "label", t: "Event", fmt: (v, r) => (r.testing ? '<span class="badge sev-unknown" title="test mode: never sent">testing</span> ' : "") + (r.link ? `<a href="${esc(r.link)}">${esc(v)}</a>` : esc(v)) },
          { k: "when", t: "When", cls: "small" }, { k: "repeats", t: "Repeats", num: true }], Q.items, { sort: "sev", limit: 50 }));
      } catch (e) { box.insertAdjacentHTML("beforeend", `<pre>${esc(e)}</pre>`); }
    };
    const rva = el.querySelector(".rv-open");
    if (rva) rva.onclick = async (ev) => {
      ev.preventDefault();
      let box = el.querySelector("#ai-rv");
      if (box) { box.remove(); return; }
      box = card("Links awaiting review", '<div class="small muted">Loading…</div>'); box.id = "ai-rv";
      (el.querySelector("#ai-rq") || el.querySelector(".kpis") || el.lastElementChild).after(box);
      try {
        const Q = await api("/api/aireview/review-queue");
        box.querySelector(".small").outerHTML = `<div class="small muted">${fn(Q.count || 0)} links the reviewer has not decided yet${Q.testing ? `, plus ${fn(Q.testing)} tagged <i>testing</i> (test mode: listed, never sent)` : ""}${Q.count > Q.items.length ? ` (showing the best-scoring ${fn(Q.items.length)})` : ""}. Links held back by Review limits are not listed.</div>`;
        const ln = (l, lk, t, id) => `<span class="mono muted small">${esc(t)}</span> ${lk ? `<a href="${esc(lk)}">${esc(l)}</a>` : esc(l)}${id ? `<div class="mono muted small" style="word-break:break-all">${esc(id)}</div>` : ""}`;
        if (Q.items?.length) box.appendChild(table(null, [
          { k: "a_label", t: "Event", fmt: (v, r) => (r.testing ? '<span class="badge sev-unknown" title="test mode: never sent">testing</span> ' : "") + ln(v, r.a_link, `${r.a_type} - ${r.b_type}`, r.a) },
          { k: "b_label", t: "Linked to", fmt: (v, r) => ln(v, r.b_link, r.b_type, r.b) },
          { k: "why", t: "Why correlated", cls: "small", fmt: (v) => esc(Array.isArray(v) ? v.join(", ") : String(v || "")) }, { k: "score", t: "Score", num: true, fmt: (v) => esc(String(Math.round(v * 100) / 100)) }],
          Q.items, { sort: "score", limit: 50 }));
      } catch (e) { box.insertAdjacentHTML("beforeend", `<pre>${esc(e)}</pre>`); }
    };
    el.appendChild(modelsCard(D));
    if (D.admin) el.appendChild(providersCard());
    el.appendChild(costCard(D));
    el.appendChild(limitsCard(D));
    el.appendChild(lookbackCard(D));
    el.appendChild(esCard(D));
    el.append(...researchCard(D.research_status || {}, D));

    const pct = q.pending + q.confirmed + q.rejected ? Math.round((100 * (q.confirmed + q.rejected)) / (q.pending + q.confirmed + q.rejected)) : 100;
    const info = card("Reviewer", `<div class="idgrid">
        <span class="k">Model</span><span class="mono">${esc(st.model || "auto (loaded model)")}</span><span class="k">Provider</span><span>${esc(PROV[st.provider || D.config?.correlation?.provider] || "Local (LM Studio)")} · <a href="#/aireview?at=ai-models">change</a></span>
        <span class="k">Endpoint</span><span class="mono">${esc(D.url)}</span>
        <span class="k">Settings</span><span>${D.workers} parallel · reasoning ${esc(D.reasoning)}</span>
        <span class="k">Elasticsearch</span><span>${D.config?.es_queries?.enabled ? `may search, up to ${D.config.es_queries.max} per event · <a href="#/aireview?at=ai-es">${fn(D.es_queries?.last_day || 0)} searches in 24 h</a>` : `no searches · <a href="#/aireview?at=ai-models">change</a>`}</span>
        <span class="k">Activity</span><span>${st.busy ? `<b>reviewing now</b> · ${fn(st.decided_this_run)} decided${st.es_queries_this_run ? `, ${fn(st.es_queries_this_run)} searches` : ""} this pass` : st.last_run ? `last pass finished ${esc(ago(st.last_run))}` : "starting (first pass begins ~15 s after the dashboard starts)"}</span>
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
    // live refresh while the model is working (only if the user is not in the middle of something: typing,
    // a popover open, or an unsaved edit in one of the Save-gated forms below)
    const midEdit = () => {
      const a = document.activeElement;
      if (a && /^(INPUT|SELECT|TEXTAREA)$/.test(a.tagName)) return true;
      if (document.querySelector(".rel-pop")) return true;
      return [...document.querySelectorAll("button.cost-save, button.pf-save")].some((b) => !b.disabled);
    };
    if (st.busy || q.pending) { const t = setTimeout(() => { if (location.hash.startsWith("#/aireview") && !document.hidden && !midEdit()) rerender(); }, 60000);
      addEventListener("hashchange", () => clearTimeout(t), { once: true }); }
  };
})();
