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
  // "every 12 h" from the job's cron grid (llm_broker.schedule_expr writes "0 H-23/N * * *") or interval minutes
  const every = (expr, mins) => { const m = /^\d+ \d+-23\/(\d+) /.exec(expr || ""); const n = m ? 60 * m[1] : mins;
    return !n ? "scheduled" : n === 720 ? "twice a day" : n === 1440 ? "daily" : n % 60 ? `every ${n} min` : `every ${n / 60} h`; };
  function claudeCard(C) {  // returns [status box, time/token box (only when usage exists)]
    if (C.error) return [card("Claude triage &amp; enrichment", `<div class="bad">Status unavailable: ${esc(C.error)}</div>`)];
    const J = (C.jobs || [])[0], N = C.notes || {}, L = C.links || {}, R = C.runs || [];
    const now = Date.now() / 1000, stale = C.exported && now - C.exported > 3600;
    const lastRun = J && (J.runs || []).find((r) => r.status !== "running" && r.status !== "claimed");
    const health = !J ? ["No job found", "sev-unknown"] : !J.enabled ? ["Paused", "sev-unknown"] : J.running ? ["Running now", "sev-good"]
      : lastRun && lastRun.status === "failed" ? ["Last run failed", "sev-high"] : J.failure_streak ? ["Failing", "sev-high"] : ["Idle · scheduled", "sev-good"];
    const cov = N.current_events ? Math.round((100 * N.current_with_note) / N.current_events) : 0;
    const sum = J && J.summary ? `<details style="margin-top:10px"><summary>Latest run summary ${aiFlare({ model: J.model, via: "Hermes triage + enrichment", at: new Date(J.summary.at * 1000).toISOString() })} <span class="muted small">${esc(ago(J.summary.at))}</span></summary>
        <div class="note-research" style="margin-top:6px">${esc(J.summary.text)}</div></details>` : "";
    const c = card(`Claude triage &amp; enrichment (${every(J && J.schedule)})`, `
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
    let uc = null;
    USAGE = null;
    if (U.length) {  // time + token use of each research run
      const lbl = U.map((u) => new Date(u.at * 1000).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }) + (u.pdf_run ? " (PDF)" : ""));
      // usage_audit's prompt count sums the whole re-sent conversation over every API call of the run; ~95% of it
      // is prompt-cache reads (~10% of the input price). claude_status.py adds the split from Hermes's session DB.
      const M = (v) => +((v || 0) / 1e6).toFixed(3), sum = (f) => U.reduce((a, u) => a + (f(u) || 0), 0);
      const split = (u) => u.cache_read != null;
      const mins = sum((u) => u.duration_s) / 60, cost = sum((u) => u.cost_usd), nCost = U.filter((u) => u.cost_usd != null).length;
      const S = U.filter(split), nRaw = U.length - S.length;
      const work = S.reduce((a, u) => a + u.fresh + u.cache_write + u.completion, 0), reads = S.reduce((a, u) => a + u.cache_read, 0);
      // own box (user request): title is the card h2, the summary line sits under it
      uc = card("Time and tokens per research run", "");
      uc.id = "ai-usage";
      const chart = uc;  // header + .chart as direct children so cards.js marks it cc-chart (no phone height cap)
      const hd = chart.appendChild(Object.assign(document.createElement("div"), { className: "small" }));
      hd.append(Object.assign(document.createElement("span"), { className: "muted", textContent: `last ${U.length} runs · ${Math.round(mins)} min in total, ${Math.round(mins / U.length)} min per run · ` +
          (S.length ? `${(work / S.length / 1e6).toFixed(2)} M tokens new input + cache writes + output per run, plus ${(reads / S.length / 1e6).toFixed(1)} M cache re-reads (~10% price; hidden, click the legend to show)` : "") +
          (nRaw ? ` · ${nRaw} run${nRaw > 1 ? "s" : ""} without cache split (grey)` : "") +
          (nCost ? ` · est. $${cost.toFixed(2)} at API list prices ($${(cost / nCost).toFixed(2)} per run)` : "") }));
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
  let USAGE = null;  // {U, canvas, pv, preview} set by claudeCard when the usage chart exists
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
    const list = { anthropic: M.anthropic, "openai-api": M.openai }[provider];
    const price = provider === "lmstudio" ? { in: 0, out: 0 } : ((list || []).find((m) => m.id === model) || {}).price;
    USAGE.preview = same ? null : { provider, model, price };
    if (same) { USAGE.pv.textContent = ""; }
    else if (!price) { USAGE.pv.innerHTML = `<span class="warn">Hermes has no price for ${esc(model)}, so its cost can't be estimated.</span>`; }
    else {
      const perDay = current && current.interval_minutes ? 1440 / current.interval_minutes : 2;
      const v = USAGE.U.map((u) => runCost(u, price)), avg = v.reduce((a, x) => a + x, 0) / (v.length || 1);
      const rec = USAGE.U.filter((u) => u.cost_usd != null), recAvg = rec.length ? rec.reduce((a, u) => a + u.cost_usd, 0) / rec.length : null;
      USAGE.pv.innerHTML = `With <b>${esc(model)}</b>${chosen ? " (the research job's model)" : ""}: about <b>$${avg.toFixed(2)} per run</b>` +
        (recAvg != null ? ` (the recorded runs averaged $${recAvg.toFixed(2)})` : "") +
        ` · ~$${(avg * 30 * perDay).toFixed(0)} a month at ${+perDay.toFixed(1)} run${perDay === 1 ? "" : "s"} a day. <span class="muted">Same token counts as the recorded runs re-priced at ` +
        `${esc(model)}'s list price ($${price.in}/M in, $${price.out}/M out${price.cache_read != null ? `, $${price.cache_read}/M cache reads` : ""}); ` +
        `a different model would use a different number of tokens, so treat this as a rough guide.${chosen ? "" : " Press Save to switch."}</span>`;
    }
    const data = same || !price ? USAGE.U.map(() => null) : USAGE.U.map((u) => runCost(u, price));
    ds.data = data; ds.label = same || !price ? "Cost with selected model ($)" : `Cost with ${model} ($)`; ds.hidden = same || !price;
    if (ch) ch.update();
  }

  // ---- model choice (correlation reviewer + research job) and per-decision model comparison
  let MODELS = null;
  const loadModels = async () => { MODELS = MODELS || await api("/api/llm/models"); for (const g of MODELS.custom || []) PROV[g.provider] = g.name; return MODELS; };
  // built-in providers; admin-added API-key providers ("api:<id>") get their names from /api/aireview + /api/llm/models
  const PROV = { lmstudio: "Local (LM Studio)", anthropic: "Anthropic (via Hermes)", "openai-api": "OpenAI (via Hermes)" };
  const optKey = (p, m) => `${p}|${m}`;
  // hermesOnly: the research job runs in Hermes, so it can't use the dashboard's own API-key providers
  function modelSelect(M, cur, hermesOnly) {
    const sel = document.createElement("select"); sel.className = "llm-sel";
    const groups = [["lmstudio", (M.local || []).map((m) => [m.id, m.id + (m.loaded ? " (loaded)" : "")])], ["anthropic", (M.anthropic || []).map((m) => [m.id, m.id])],
      ["openai-api", (M.openai || []).map((m) => [m.id, m.id])], ...(hermesOnly ? [] : (M.custom || []).map((g) => [g.provider, g.models.map((m) => [m.id, m.id])]))];
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
    note.textContent = D.admin ? "Correlation reviewer: decides every proposed link, continuously (cloud models are billed per decision batch; local models are free but need LM Studio). It can use any provider in the AI providers box. Research job: the scheduled triage and event research; it runs in Hermes, so it can only use LM Studio or Hermes' Anthropic / OpenAI models (local models are much slower and weaker at web research)."
      : "Only an admin can change models.";
    const rows = [["correlation", "Correlation reviewer", D.config?.correlation || {}], ["research", `Research job (${every(D.research?.schedule, D.research?.interval_minutes)})`, D.research && !D.research.error ? D.research : {}]];
    loadModels().then((M) => {
      if (M.error) note.textContent = M.error + " - only local models can be chosen. " + note.textContent;
      for (const [sec, label, cur] of rows) {
        const r = body.appendChild(document.createElement("div")); r.className = "llm-row";
        r.appendChild(Object.assign(document.createElement("span"), { className: "k", textContent: label }));
        const sel = r.appendChild(modelSelect(M, cur, sec === "research")); sel.disabled = !D.admin;
        const btn = r.appendChild(Object.assign(document.createElement("button"), { type: "button", textContent: "Save" })); btn.disabled = true;
        const msg = r.appendChild(Object.assign(document.createElement("span"), { className: "small muted" }));
        msg.textContent = cur.model ? `now: ${PROV[cur.provider] || cur.provider} · ${cur.model}` : (sec === "research" && D.research?.error ? D.research.error : "now: auto (model loaded in LM Studio)");
        sel.onchange = () => { btn.disabled = !D.admin || sel.value === optKey(cur.provider, cur.model);
          if (sec === "research") { const [p, ...m] = sel.value.split("|"); previewResearchCost(p, m.join("|"), M, cur); } };
        if (sec === "research" && cur.model) previewResearchCost(cur.provider, cur.model, M, cur);
        btn.onclick = async () => {
          const [provider, ...rest] = sel.value.split("|"), model = rest.join("|");
          btn.disabled = true; msg.textContent = "saving…";
          try { const r2 = await apiPost("/api/llm/config", { section: sec, provider, model }); const now = r2[sec] || {};
            cur.provider = now.provider; cur.model = now.model; msg.textContent = `saved: ${PROV[now.provider] || now.provider} · ${now.model}`;
            if (sec === "research") previewResearchCost(now.provider, now.model, M, cur); }
          catch (e) { msg.textContent = "error: " + e.message; btn.disabled = false; }
        };
      }
      body.appendChild(esQueriesRow(D));
      if (D.admin) body.appendChild(openaiKeyRow(M));
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
  // OpenAI API key (write-only): the broker checks it with OpenAI, then stores it in Hermes' .env (main + Ask Hermes profiles)
  function openaiKeyRow(M) {
    const st = M.openai_key || {};
    const r = document.createElement("div"); r.className = "llm-row";
    r.appendChild(Object.assign(document.createElement("span"), { className: "k", textContent: "OpenAI API key" }));
    const inp = r.appendChild(Object.assign(document.createElement("input"), { type: "password", autocomplete: "off", spellcheck: false,
      placeholder: st.set ? `saved (${st.hint || "set"}) - paste a new key to replace` : "sk-...", className: "llm-sel" }));
    inp.setAttribute("aria-label", "OpenAI API key");
    const save = r.appendChild(Object.assign(document.createElement("button"), { type: "button", textContent: "Save key" }));
    const del = Object.assign(document.createElement("button"), { type: "button", textContent: "Remove" });
    if (st.set) r.appendChild(del);
    const msg = r.appendChild(Object.assign(document.createElement("span"), { className: "small muted" }));
    msg.textContent = st.set ? `OpenAI models available: ${(M.openai || []).length}` : "No key saved: OpenAI models are hidden until you add one.";
    const send = async (body, what) => {
      save.disabled = del.disabled = true; msg.textContent = what;
      try { await apiPost("/api/llm/openai-key", body); MODELS = null; inp.value = ""; msg.textContent = body.remove ? "removed - reloading…" : "saved - reloading…"; setTimeout(() => location.reload(), 600); }
      catch (e) { msg.textContent = "error: " + e.message; save.disabled = del.disabled = false; }
    };
    save.onclick = () => { const k = inp.value.trim(); if (!k) { msg.textContent = "paste a key first"; return; } send({ key: k }, "checking the key with OpenAI…"); };
    del.onclick = () => { if (confirm("Remove the OpenAI API key from Hermes? OpenAI models stop working until a new key is saved.")) send({ remove: true }, "removing…"); };
    return r;
  }

  // ---- AI providers (admin): any OpenAI-compatible or Anthropic API with a key, called by the dashboard itself
  function providersCard() {
    const c = card("AI providers", `<div class="small muted">Add any number of AI services that take an API key. <b>OpenAI / OpenAI-compatible</b> covers
      OpenAI itself and services with the same API (OpenRouter, Groq, Mistral, Together, DeepSeek, Gemini's OpenAI endpoint, a self-hosted vLLM...);
      <b>Anthropic</b> is Claude with an Anthropic API key. The dashboard calls them directly (no Hermes). Their models appear in the correlation
      reviewer menu and in every Compare dialog. Keys are stored on the dashboard's state volume, readable only by the dashboard, and never shown again.</div>
      <div class="prov-list" style="margin-top:8px"></div><div class="prov-form"></div>
      <div style="margin-top:8px"><button type="button" class="prov-add">Add provider</button> <span class="small muted prov-msg"></span></div>`);
    c.id = "ai-providers";
    const list = c.querySelector(".prov-list"), formBox = c.querySelector(".prov-form"), msg = c.querySelector(".prov-msg");
    let P = [], TYPES = {};
    const draw = () => {
      if (!P.length) { list.innerHTML = `<div class="small muted">No providers yet.</div>`; return; }
      list.replaceChildren(table(null, [
        { k: "name", t: "Name", fmt: (v, r) => `<b>${esc(v)}</b>${r.enabled ? "" : ' <span class="badge sev-unknown">off</span>'}` },
        { k: "type_label", t: "Type" },
        { k: "base_url", t: "Base URL", cls: "small mono" },
        { k: "key_hint", t: "Key", cls: "small mono", fmt: (v, r) => (r.key_set ? esc(v) : '<span class="bad">missing</span>') },
        { k: "models", t: "Models", fmt: (v) => (v.length ? `<span title="${esc(v.join(", "))}">${v.length}: ${esc(v.slice(0, 3).join(", "))}${v.length > 3 ? "…" : ""}</span>` : '<span class="warn">none - add some</span>') },
        { k: "rate_per_hour", t: "Calls/h", num: true, fmt: (v, r) => `${fn(r.calls_last_hour)} / ${fn(v)}` },
        { k: "_a", t: "", fmt: (v, r) => `<span class="ai-acts"><button data-pe="${esc(r.id)}" title="Edit">✎</button><button data-pt="${esc(r.id)}" title="Test the key">Test</button><button data-pd="${esc(r.id)}" title="Delete">✕</button></span>` },
      ], P, { sort: "name" }));
    };
    const load = async () => { try { const d = await api("/api/llm/providers"); P = d.providers || []; TYPES = d.types || {}; draw(); } catch (e) { list.textContent = "error: " + e.message; } };
    const reloadModels = () => { MODELS = null; msg.textContent += " · reload the page to see the change in the model menus"; };
    function form(p) {
      p = p || { type: "openai", enabled: true, rate_per_hour: 120, reasoning_tokens: 3000, models: [] };
      formBox.innerHTML = `<div class="llm-grid" style="margin-top:10px;border-top:1px solid var(--border);padding-top:10px">
        <div class="llm-row"><span class="k">Name</span><input name="name" class="llm-sel" maxlength="60" placeholder="e.g. OpenAI, OpenRouter, Anthropic (work)"></div>
        <div class="llm-row"><span class="k">Type</span><select name="type" class="llm-sel">${Object.entries(TYPES).map(([k, t]) => `<option value="${esc(k)}">${esc(t.label)}</option>`).join("")}</select></div>
        <div class="llm-row"><span class="k">Base URL</span><input name="base_url" class="llm-sel mono" spellcheck="false"><span class="small muted">empty = the official API</span></div>
        <div class="llm-row"><span class="k">API key</span><input name="api_key" type="password" autocomplete="off" spellcheck="false" class="llm-sel"></div>
        <div class="llm-row"><span class="k">Models</span><textarea name="models" rows="4" class="llm-sel mono" spellcheck="false" placeholder="one model id per line"></textarea>
          <button type="button" class="pf-fetch">Fetch from provider</button></div>
        <div class="llm-row"><span class="k">Calls per hour</span><input name="rate_per_hour" type="number" min="1" max="3000" style="width:7em">
          <span class="small muted">cap on this provider's calls (reviewer + comparisons) - limits cost if something loops</span></div>
        <div class="llm-row"><span class="k">Extra reasoning tokens</span><input name="reasoning_tokens" type="number" min="0" max="32000" step="500" style="width:7em">
          <span class="small muted">added to each answer's token limit for models that think first (OpenAI gpt-5 / o-series: ~3000; others 0)</span></div>
        <div class="llm-row"><span class="k">Enabled</span><label class="small"><input name="enabled" type="checkbox"> its models can be picked and used</label></div>
        <div class="llm-row"><span class="k"></span><button type="button" class="pf-save">Save</button><button type="button" class="pf-test">Test key</button><button type="button" class="pf-cancel">Cancel</button>
          <span class="small muted pf-msg"></span></div></div>`;
      const f = (n) => formBox.querySelector(`[name="${n}"]`), fm = formBox.querySelector(".pf-msg");
      f("name").value = p.name || ""; f("type").value = p.type; f("base_url").value = p.base_url || ""; f("models").value = (p.models || []).join("\n");
      f("rate_per_hour").value = p.rate_per_hour; f("reasoning_tokens").value = p.reasoning_tokens; f("enabled").checked = p.enabled !== false;
      const ph = () => { f("base_url").placeholder = (TYPES[f("type").value] || {}).base_url || "";
        f("api_key").placeholder = p.key_set ? `saved (${p.key_hint}) - leave empty to keep it` : f("type").value === "anthropic" ? "sk-ant-..." : "sk-..."; };
      f("type").onchange = () => { ph(); if (!p.id) f("reasoning_tokens").value = f("type").value === "openai" ? 3000 : 0; }; ph();
      const val = () => ({ id: p.id, name: f("name").value.trim(), type: f("type").value, base_url: f("base_url").value.trim(), api_key: f("api_key").value.trim(),
        models: f("models").value, rate_per_hour: f("rate_per_hour").value, reasoning_tokens: f("reasoning_tokens").value, enabled: f("enabled").checked });
      const run = async (btn, body, what, done) => { btn.disabled = true; fm.textContent = what;
        try { done(await apiPost("/api/llm/providers", body)); } catch (e) { fm.textContent = "error: " + e.message; } btn.disabled = false; };
      formBox.querySelector(".pf-cancel").onclick = () => { formBox.innerHTML = ""; };
      formBox.querySelector(".pf-test").onclick = (ev) => run(ev.target, { ...val(), action: "test" }, "checking the key…", (r) => { fm.textContent = "✓ " + r.message; });
      formBox.querySelector(".pf-fetch").onclick = (ev) => run(ev.target, { ...val(), action: "models" }, "asking the provider for its models…", (r) => {
        const have = new Set(f("models").value.split(/\s+/).filter(Boolean));
        fm.innerHTML = ""; const box = document.createElement("div"); box.className = "prov-pick small";
        box.append(`${r.models.length} chat models (of ${r.all}). Tick the ones to offer: `);
        for (const m of r.models) { const l = box.appendChild(document.createElement("label")); l.className = "cmp-opt";
          const cb = l.appendChild(Object.assign(document.createElement("input"), { type: "checkbox", checked: have.has(m) })); l.append(" " + m);
          cb.onchange = () => { const s = new Set(f("models").value.split(/\s+/).filter(Boolean)); cb.checked ? s.add(m) : s.delete(m); f("models").value = [...s].join("\n"); }; }
        fm.appendChild(box); });
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

  // ---- cost limits: the Hermes cost_limit plugin's $ caps (plugins.entries.cost_limit.settings, via the host broker)
  function costCard(D) {
    const L = D.costlimit || {}, T = "Cost limits (estimated token cost)";
    if (L.error) { const e = card(T, `<div class="bad">Cost limits unavailable: ${esc(L.error)}</div>`); e.id = "ai-cost"; return e; }
    const U = ((D.claude?.jobs || [])[0]?.usage || []).filter((u) => u.cost_usd != null).map((u) => u.cost_usd);
    const avg = U.length ? U.reduce((a, v) => a + v, 0) / U.length : null, max = U.length ? Math.max(...U) : null;
    const usd = (v) => `$${(+v).toFixed(2)}`;
    const c = card(T, `
      <div class="small muted">Hermes estimates what every model call costs (tokens × the provider's API list price) and adds it up.
        When a limit below is passed, Hermes stops the work right after that call and blocks any tool calls still waiting.
        The check runs after each call, so the final total can go over the limit by the cost of one call. <b>0 = no limit.</b></div>
      ${!L.installed ? `<div class="bad" style="margin-top:6px">The cost_limit plugin is not installed in Hermes, so these limits have no effect.</div>`
        : !L.enabled ? `<div class="warn" style="margin-top:6px">The cost_limit plugin is installed but not enabled (<span class="mono">hermes plugins enable cost_limit</span>), so these limits have no effect.</div>` : ""}
      <div class="llm-grid" style="margin-top:10px">
        <div class="llm-row"><span class="k">Per run</span><span>$ <input type="number" name="max_run_usd" min="0" max="1000" step="0.5" style="width:7em"></span>
          <span class="small muted" style="flex:1 1 380px">A <b>run</b> is one piece of work from start to final answer: one firing of the research job, or one message
            sent to Hermes in a chat, including any subagents it starts. Use this to stop a single run that goes wrong (loops, huge web research).
            ${avg != null ? `Recent research runs cost about <b>${usd(avg)}</b> each (highest ${usd(max)}, last ${U.length} runs).` : ""}
            <span class="cost-warn bad"></span></span></div>
        <div class="llm-row"><span class="k">Per session</span><span>$ <input type="number" name="max_session_usd" min="0" max="1000" step="1" style="width:7em"></span>
          <span class="small muted" style="flex:1 1 380px">A <b>session</b> is a whole conversation: every run in it added together. Each research-job firing starts a new
            session with a single run, so for the research job the lower of the two limits is the one that counts. The session limit mainly caps
            long chats with Hermes (desktop, CLI, Discord), where many cheap runs add up.</span></div>
      </div>
      <div class="small muted" style="margin-top:8px">Covered: the research job and other Hermes (default profile) sessions. Not covered: the correlation reviewer and model
        comparisons on this page (single calls through the broker, capped at 120 Anthropic requests per hour instead) and Ask Hermes (its own profile).
        Local LM Studio models cost $0 and are never stopped; a provider Hermes has no price for also counts as $0.</div>
      <div style="margin-top:8px"><button type="button" class="cost-save">Save</button> <span class="small muted cost-msg"></span></div>
      ${(L.stops || []).length ? `<details class="small" style="margin-top:8px"><summary>Recent stops (${L.stops.length})</summary>
        ${L.stops.slice().reverse().map((s) => `<div><span class="mono">${esc(s.at)} UTC</span> · ${esc(s.reason)} <span class="muted mono">${esc(s.session)}</span></div>`).join("")}</details>`
        : `<div class="small muted" style="margin-top:8px">No run has been stopped by a cost limit yet.</div>`}`);
    c.id = "ai-cost";
    const inp = (k) => c.querySelector(`input[name="${k}"]`), btn = c.querySelector(".cost-save"), msg = c.querySelector(".cost-msg");
    const warn = () => { const r = +inp("max_run_usd").value || 0, s = +inp("max_session_usd").value || 0;
      const over = r ? U.filter((v) => v > r).length : 0;
      c.querySelector(".cost-warn").textContent = (r && avg != null && r < avg ? ` Below the usual research run cost: the research job would be stopped before it finishes most runs.`
        : over ? ` ${over} of the last ${U.length} research runs cost more than this and would have been stopped before finishing.` : "") +
        (r && s && s < r ? " The session limit is lower than the run limit, so the session limit will stop runs first." : ""); };
    const fill = (v) => { for (const k of ["max_run_usd", "max_session_usd"]) inp(k).value = v[k] ?? 0; warn(); };
    fill(L);
    for (const k of ["max_run_usd", "max_session_usd"]) { inp(k).disabled = !D.admin; inp(k).oninput = () => { btn.disabled = !D.admin; warn(); }; }
    btn.disabled = true;
    if (!D.admin) msg.textContent = "Only an admin can change cost limits.";
    btn.onclick = async () => {
      const body = {};
      for (const k of ["max_run_usd", "max_session_usd"]) { const v = inp(k).value === "" ? 0 : +inp(k).value;
        if (!(v >= 0 && v <= 1000)) { msg.textContent = "Enter an amount between 0 (no limit) and 1000 dollars."; return; } body[k] = v; }
      btn.disabled = true; msg.textContent = "saving…";
      try { const r = await apiPost("/api/llm/costlimit", body); fill(r.costlimit || body);
        msg.textContent = `saved: ${body.max_run_usd ? usd(body.max_run_usd) : "no limit"} per run · ${body.max_session_usd ? usd(body.max_session_usd) : "no limit"} per session (applies from the next model call)`; }
      catch (e) { msg.textContent = "error: " + e.message; btn.disabled = false; }
    };
    return c;
  }

  // research job lookback window (lookback.py, store meta "research_lookback"): hours of logs each run collects
  const runEveryMin = (expr) => { const m = /^\d+ \d+-23\/(\d+) /.exec(expr || ""); if (m) return 60 * m[1];
    const e = /every (\d+)\s*([mh])/.exec(expr || ""); return e ? +e[1] * (e[2] === "h" ? 60 : 1) : null; };
  function lookbackCard(D) {
    const L = D.lookback || { hours: 24, min: 1, max: 24, pdf_hour: 5 }, J = (D.claude?.jobs || [])[0];
    const iv = runEveryMin(J && J.schedule), ivH = iv ? iv / 60 : null;
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
      const def = new Set([optKey(cor.provider, curLocal), "anthropic|claude-sonnet-5-5", "anthropic|claude-opus-5-5"]);
      const all = [...(M.local || []).map((m) => ["lmstudio", m.id, m.loaded ? " (loaded)" : " (not loaded: LM Studio loads it first, slow)"]), ...(M.anthropic || []).map((m) => ["anthropic", m.id, ""]), ...(M.openai || []).map((m) => ["openai-api", m.id, ""]),
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
    el.innerHTML = `<h1>AI review</h1><div class="sub">The correlation script proposes links between events and vulnerabilities. The local LLM decides whether each link is real, and on the research schedule (twice a day; Config page) Claude researches the important events and re-reviews their links (its verdicts replace the local model's). Rejected links are hidden from the Related column; confirmed ones show the model's reason. Here you can watch the review, check its decisions and override them.</div><div class="loading">Loading…</div>`;
    let D; try { D = await api("/api/aireview"); } catch (e) { el.querySelector(".loading").outerHTML = `<pre>${esc(e)}</pre>`; return; }
    el.querySelector(".loading").remove();
    Object.assign(PROV, D.provider_names || {});
    const st = D.status, q = D.queue, T = D.totals;
    const health = !st.enabled ? ["Off", "sev-unknown"] : st.error ? ["Error", "sev-high"] : st.busy ? ["Reviewing", "sev-good"] : q.pending ? ["Waiting", "sev-medium"] : ["Idle · up to date", "sev-good"];
    el.insertAdjacentHTML("beforeend", kpis([
      ["Status", `<span class="badge ${health[1]}" style="font-size:14px">${health[0]}</span>`],
      ["Awaiting review", `<a href="#/aireview?at=ai-queue">${fn(q.pending)}</a>`, q.pending ? "warn" : "good"],
      ["Confirmed (this snapshot)", `<a href="#/aireview?verdict=confirmed&scope=current&at=ai-list">${fn(q.confirmed)}</a>`, "good"],
      ["Rejected (this snapshot)", `<a href="#/aireview?verdict=rejected&scope=current&at=ai-list">${fn(q.rejected)}</a>`, q.rejected ? "bad" : ""],
      ["Reviews / hour", fn(T.rate_per_hour)], ["Done in", q.eta_min == null ? (q.pending ? "?" : "—") : q.eta_min < 90 ? `~${q.eta_min} min` : `~${(q.eta_min / 60).toFixed(1)} h`]]));

    el.appendChild(modelsCard(D));
    if (D.admin) el.appendChild(providersCard());
    el.appendChild(costCard(D));
    el.appendChild(lookbackCard(D));
    el.appendChild(esCard(D));
    el.append(...claudeCard(D.claude || {}));

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
    // live refresh while the model is working (only if the user is not in the middle of something)
    if (st.busy || q.pending) { const t = setTimeout(() => { if (location.hash.startsWith("#/aireview") && !document.hidden && !document.querySelector(".rel-pop")) rerender(); }, 60000);
      addEventListener("hashchange", () => clearTimeout(t), { once: true }); }
  };
})();
