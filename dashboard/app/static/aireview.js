// AI review (#/aireview): the correlation reviewer that confirms or rejects correlation links (corr_llm.py), the
// review job (review.py) and the AI providers / models / cost caps they use.
// Worker health, queue + ETA, throughput, and every verdict with the model's reason; people can override a verdict
// (confirm / reject) or send it back to the model for another look.
(() => {
  const TYPE = { alert: "Alert", finding: "Finding", ids: "IDS", admin: "Admin", host: "Endpoint", ti: "Threat intel", vuln: "Vulnerability", gw: "Gateway",
    f: "Finding", adm: "Admin", hf: "Endpoint", iss: "Vulnerability" };
  const ago = (ts) => { if (!ts) return "never"; const s = Date.now() / 1000 - ts; return s < 90 ? "just now" : s < 5400 ? Math.round(s / 60) + " min ago" : s < 129600 ? Math.round(s / 3600) + " h ago" : Math.round(s / 86400) + " d ago"; };
  const evCell = (lbl, typ, link) => `<span class="badge sev-info">${esc(TYPE[typ] || typ)}</span>${typ === "alert" ? " " + alertMuteHtml(lbl) : ""} ${link ? `<a href="${esc(link)}">${esc(lbl.length > 110 ? lbl.slice(0, 108) + "…" : lbl)}</a>` : `<span class="muted">${esc(lbl.length > 110 ? lbl.slice(0, 108) + "…" : lbl)}</span>`}`;
  const FILTERS = {
    verdict: ["Verdict", (r, v) => (v === "confirmed" ? r.related : v === "rejected" ? !r.related : v === "manual" ? r.manual : true)],
    type: ["Event type", (r, v) => (TYPE[r.a_type] || r.a_type) === v || (TYPE[r.b_type] || r.b_type) === v],
    conf: ["Confidence", (r, v) => (v === "low" ? (r.confidence ?? 1) < 0.7 : v === "high" ? (r.confidence ?? 0) >= 0.9 : true)],
    pair: ["Event pair", (r, v) => pairKey(r.a_type, r.b_type) === v],
    scope: ["Snapshot", (r, v) => (v === "current" ? r.current : true)],
  };

  const aiColors = (cfg) => { const C = { Confirmed: "#3fb950", Rejected: "#f85149", "Set by a person": "#58a6ff" };
    cfg.data.datasets[0].backgroundColor = cfg.data.labels.map((l) => C[l] || "#8b949e"); return cfg; };
  // review job (review.py) reviewer: settings + run state from research_cfg / research_job.json, run log + coverage from enrich.py
  const until = (ts) => { if (!ts) return "—"; const s = ts - Date.now() / 1000; return s < 0 ? "due now" : s < 5400 ? `in ${Math.round(s / 60)} min` : `in ${(s / 3600).toFixed(1)} h`; };
  const dur = (s) => (s == null ? "" : s < 90 ? `${s} s` : `${Math.round(s / 60)} min`);
  const clock = (ts) => (ts ? new Date(ts * 1000).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }) : "");
  // "every 4 h" from the job's interval in minutes
  const every = (_, mins) => { const n = mins;
    return !n ? "scheduled" : n === 720 ? "twice a day" : n === 1440 ? "daily" : n % 60 ? `every ${n} min` : `every ${n / 60} h`; };
  function researchCard(C, D) {  // returns [status box, time/token box (only when usage exists)]
    if (C.error) return [card("AI Correlation job", `<div class="bad">Status unavailable: ${esc(C.error)}</div>`)];
    const J = (C.jobs || [])[0], N = C.notes || {}, L = C.links || {}, R = C.runs || [];
    const now = Date.now() / 1000, stale = C.exported && now - C.exported > 3600;
    const lastRun = J && (J.runs || []).find((r) => r.status !== "running" && r.status !== "claimed");
    const health = !J ? ["No job found", "sev-unknown"] : !J.model ? ["No model chosen", "sev-unknown"] : !J.enabled ? ["Paused", "sev-unknown"] : J.running ? ["Running now", "sev-good"]
      : J.requested ? ["Starting (requested)", "sev-medium"]
      : lastRun && lastRun.status === "failed" ? ["Last run failed", "sev-high"] : J.failure_streak ? ["Failing", "sev-high"] : ["Idle · scheduled", "sev-good"];
    const cov = N.current_events ? Math.round((100 * N.current_with_note) / N.current_events) : 0;
    const sum = J && J.summary ? `<details style="margin-top:10px"><summary>Latest run summary ${aiFlare({ model: J.summary.model || J.model, via: "AI Correlation job", at: new Date(J.summary.at * 1000).toISOString() })} <span class="muted small">${esc(ago(J.summary.at))}</span></summary>
        <div class="note-research" style="margin-top:6px">${esc(J.summary.text)}</div></details>` : "";
    const c = card(`AI Correlation job (${every(null, J && J.interval_minutes)})`, `
      <div class="idgrid">
        <span class="k">Status</span><span><span class="badge ${health[1]}">${health[0]}</span>${J && J.running ? ` · started ${esc(ago(J.running.started))}${J.running.progress ? `, last activity ${esc(ago(J.running.progress))}` : ""}` : ""}</span>
        ${J ? `<span class="k">Job</span><span>${esc(J.name || J.id)} · <span class="mono">${esc(J.model || "no model chosen - pick one in the Models box")}</span>${J.provider ? ` <span class="muted small">${esc(PROV[J.provider] || J.provider)}</span>` : ""}</span>
        <span class="k">Schedule</span><span>${esc(every(null, J.interval_minutes))}, on a grid anchored at 05:00 UTC · next run ${J.enabled ? `${esc(until(J.next_run))} (${esc(clock(J.next_run))})` : "paused"}
          ${D.admin ? ` · <button type="button" class="rj-run"${J.running || J.requested || !J.model ? " disabled" : ""}>Run now</button> <button type="button" class="rj-toggle">${J.enabled ? "Pause" : "Resume"}</button> <span class="small muted rj-msg"></span>` : ""}</span>
        ${D.admin ? `<span class="k">Run every</span><span class="rj-iv" style="display:inline-flex;gap:6px;align-items:center;flex-wrap:wrap"><input class="rj-m" type="number" min="5" max="1440" step="1" value="${J.interval_minutes || 0}" style="width:5.5em"> <span class="small">minutes</span> <span class="small rj-ivmsg"></span> <span class="small muted">5 to 1440 · saves automatically</span></span>` : ""}
        <span class="k">Last run</span><span>${lastRun ? `${esc(ago(lastRun.finished || lastRun.started))} · ${esc(lastRun.status)}${lastRun.duration_s ? ` in ${esc(dur(lastRun.duration_s))}` : ""}` : "never"}${J.failure_streak ? ` · <span class="bad">${fn(J.failure_streak)} failure(s) in a row</span>` : ""}</span>
        ${J.last_error ? `<span class="k">Last error</span><span class="bad">${esc(J.last_error)}</span>` : ""}` : `<span class="k">Job</span><span>AI Correlation job status unavailable.</span>`}
        <span class="k">Event notes</span><span>${fn(N.total || 0)} stored · ${fn(N.last_24h || 0)} in the last 24 h${Object.keys(N.by_verdict || {}).length ? " · " + Object.entries(N.by_verdict).map(([k, v]) => `${esc(k)} ${fn(v)}`).join(" · ") : ""}</span>
        <span class="k">Link verdicts</span><span>${fn(L.total || 0)} correlation link verdicts by this job (${fn(L.related || 0)} related) · ${fn(L.last_24h || 0)} in the last 24 h${L.last ? ` · last ${esc(ago(L.last))}` : ""}</span>
        ${stale && J && J.running ? `<span class="k">Note</span><span class="warn">No progress reported for ${esc(ago(C.exported))} - check logs/research.log on the host.</span>` : ""}
      </div>
      <div style="margin-top:12px"><div class="small muted">Current snapshot: ${cov}% of events have a research note (${fn(N.current_with_note || 0)} of ${fn(N.current_events || 0)})</div>
        <div class="bar" style="height:10px;margin-top:4px"><span style="width:${cov}%"></span></div></div>
      ${sum}
      <div style="margin-top:12px;display:grid;grid-template-columns:repeat(auto-fit,minmax(380px,1fr));gap:12px">
        <div class="cl-runs"><div class="small"><b>Recent runs</b></div></div>
      </div>`);
    c.id = "ai-research";
    if (J) { const g = c.querySelector(".cl-runs").parentNode; g.parentNode.insertBefore(lookbackCard(D), g); }  // the lookback is a setting of this job's collect + correlate step
    if (D.admin && J && c.querySelector(".rj-save")) {
      const mi = c.querySelector(".rj-m"), im = c.querySelector(".rj-ivmsg"), cur = J.interval_minutes || 0; let tm = null;
      mi.oninput = () => { clearTimeout(tm); const t = parseInt(mi.value, 10) || 0; im.className = "small sev-high";
        if (t < 5 || t > 1440) { im.textContent = "between 5 and 1440 minutes"; return; }
        if (t === cur) { im.textContent = ""; return; }
        im.className = "small"; im.textContent = "saving…";
        tm = setTimeout(async () => { try { await apiPost("/api/config/review-schedule", { hours: 0, minutes: t }); im.textContent = "saved ✓"; setTimeout(() => rerender(), 600); }
          catch (e) { im.className = "small sev-high"; im.textContent = String(e.message || e); } }, 800); };
    }
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
    const U = (J && J.usage) || [], CU = (J && J.chat_usage) || [], AL = [...U, ...CU];  // CU = Ask AI chat turns, counted in the same day totals
    let uc = null;
    USAGE = null;
    const RE = (J && J.researched) || [];
    if (AL.length || RE.length) {  // time + token use of the research job, one bar per day, and every researched event
      const dayKey = (t) => { const d = new Date(t * 1000); return `${d.getFullYear()}-${d.getMonth() + 1}-${d.getDate()}`; };
      const days = []; const byDay = {};
      for (const u of AL) { const k = dayKey(u.at); let d = byDay[k]; if (!d) { d = byDay[k] = { at: u.at, runs: [], chat: [], all: [] }; days.push(d); } (u.chat ? d.chat : d.runs).push(u); d.all.push(u); }
      days.sort((x, y) => x.at - y.at);
      const split = (u) => u.cache_read != null;
      const sumU = (rs, f) => rs.reduce((a, u) => a + (f(u) || 0), 0);
      for (const d of days) {
        d.fresh = sumU(d.all.filter(split), (u) => u.fresh); d.cache_write = sumU(d.all.filter(split), (u) => u.cache_write);
        d.cache_read = sumU(d.all.filter(split), (u) => u.cache_read); d.nosplit = sumU(d.all.filter((u) => !split(u)), (u) => u.prompt);
        d.completion = sumU(d.all, (u) => u.completion); d.mins = sumU(d.all, (u) => u.duration_s) / 60;
        const priced = d.all.filter((u) => u.cost_usd != null); d.cost = priced.length ? sumU(priced, (u) => u.cost_usd) : null;
        const cp = d.chat.filter((u) => u.cost_usd != null); d.chatCost = cp.length ? sumU(cp, (u) => u.cost_usd) : (d.chat.length ? null : 0);
        d.chatTok = sumU(d.chat, (u) => u.total); d.chatMins = sumU(d.chat, (u) => u.duration_s) / 60;
        d.models = [...new Set(d.all.map((u) => u.model).filter(Boolean))].join(", ");
      }
      // the prompt count sums the whole re-sent conversation over every API call of the run; most of it can be
      // prompt-cache reads (a fraction of the input price) when the provider caches. review.py records the split.
      const M = (v) => +((v || 0) / 1e6).toFixed(3), sum = (f) => AL.reduce((a, u) => a + (f(u) || 0), 0);
      const mins = sum((u) => u.duration_s) / 60, cost = sum((u) => u.cost_usd), nCost = AL.filter((u) => u.cost_usd != null).length;
      const S = AL.filter(split), nRaw = AL.length - S.length;
      const tokAll = sum((u) => split(u) ? u.fresh + u.cache_write + u.completion : (u.prompt || 0) + (u.completion || 0)), readsAll = sum((u) => u.cache_read);
      const tpm = mins > 0 ? Math.round(tokAll / mins) : 0, tpmR = mins > 0 ? Math.round((tokAll + readsAll) / mins) : 0;
      const work = S.reduce((a, u) => a + u.fresh + u.cache_write + u.completion, 0), reads = S.reduce((a, u) => a + u.cache_read, 0);
      // own box (user request): title is the card h2, the summary line sits under it
      uc = card("Time and tokens per research job and Ask AI chat", "");
      uc.id = "ai-usage";
      const chart = uc;  // header + .chart as direct children so cards.js marks it cc-chart (no phone height cap)
      if (AL.length) {
        const pv = chart.appendChild(Object.assign(document.createElement("div"), { className: "small cost-preview", style: "margin-top:4px" }));
        chart.appendChild(Object.assign(document.createElement("div"), { className: "chart phone4x" })).appendChild(document.createElement("canvas"));
        const lbl = days.map((d) => new Date(d.at * 1000).toLocaleDateString([], { month: "short", day: "numeric" }));
        const cfg = { type: "bar", data: { labels: lbl, datasets: [
          { label: "New input (M)", data: days.map((d) => M(d.fresh)), backgroundColor: "#58a6ff", stack: "t", yAxisID: "y" },
          { label: "Cache writes (M)", data: days.map((d) => M(d.cache_write)), backgroundColor: "#d29922", stack: "t", yAxisID: "y" },
          { label: "Input, no cache split (M)", data: days.map((d) => M(d.nosplit)), backgroundColor: "#8b949e", stack: "t", yAxisID: "y" },
          { label: "Output (M)", data: days.map((d) => M(d.completion)), backgroundColor: "#bc8cff", stack: "t", yAxisID: "y" },
          { label: "Cache re-reads (M)", data: days.map((d) => M(d.cache_read)), backgroundColor: "#58a6ff33", stack: "t", yAxisID: "y", hidden: true },
          { label: "Run time (min)", type: "line", data: days.map((d) => +d.mins.toFixed(1)), borderColor: "#3fb950", backgroundColor: "#3fb950",
            pointRadius: 3, tension: 0.2, yAxisID: "y1" },
          { label: "Est. cost ($)", type: "line", data: days.map((d) => (d.cost == null ? null : +d.cost.toFixed(2))), borderColor: "#f85149", backgroundColor: "#f85149",
            pointRadius: 3, tension: 0.2, yAxisID: "y2" },
          { label: "Ask AI chat cost ($)", type: "line", data: days.map((d) => (d.chat.length && d.chatCost != null ? +d.chatCost.toFixed(2) : null)), borderColor: "#e3b341", backgroundColor: "#e3b341", borderDash: [2, 3],
            pointRadius: 3, tension: 0.2, yAxisID: "y2" },
          { label: "Cost with selected model ($)", type: "line", data: days.map(() => null), borderColor: "#ff7b72", backgroundColor: "#ff7b72", borderDash: [6, 4],
            pointRadius: 2, tension: 0.2, yAxisID: "y2", hidden: true }] },
          options: { interaction: { mode: "index", intersect: false }, scales: { x: { stacked: true, ticks: { maxRotation: 50, autoSkip: true } },
            y: { stacked: true, beginAtZero: true, title: { display: true, text: "tokens per day (millions), research job + Ask AI chat" } },
            y1: { position: "right", beginAtZero: true, grid: { drawOnChartArea: false }, title: { display: true, text: "minutes per day" } },
            y2: { position: "right", beginAtZero: true, grid: { drawOnChartArea: false }, title: { display: true, text: "US $ per day" }, ticks: { callback: (v) => "$" + v } } },
            plugins: { tooltip: { callbacks: { footer: (it) => { const d = days[it[0].dataIndex];
              const p = USAGE && USAGE.preview, pc = p ? d.runs.reduce((a, u) => a + runCost(u, p.price), 0) : null;
              return `${d.runs.length} research run${d.runs.length === 1 ? "" : "s"}` + (d.chat.length ? ` · ${d.chat.length} Ask AI turn${d.chat.length === 1 ? "" : "s"} (${fn(d.chatTok)} tokens, ${d.chatMins.toFixed(1)} min${d.chatCost != null ? ", $" + d.chatCost.toFixed(2) : ""})` : "") + (d.cost != null ? ` · est. $${d.cost.toFixed(2)}` : "") +
                ` · ${d.models}${d.runs.some((u) => u.error) ? " · some failed" : ""}` + (pc != null ? `\nWith ${p.model}: ~$${pc.toFixed(2)}` : ""); } } } } } };
        queueChart(chart.querySelector("canvas"), cfg);
        // the chart may not exist yet (queued until the page is laid out): the preview edits this dataset object directly
        const tot = S.reduce((a, u) => a + u.fresh + u.cache_write + u.cache_read, 0);
        const mix = tot ? { fresh: S.reduce((a, u) => a + u.fresh, 0) / tot, cache_write: S.reduce((a, u) => a + u.cache_write, 0) / tot, cache_read: reads / tot } : null;
        USAGE = { U, D: days, mix, canvas: chart.querySelector("canvas"), pv, preview: null, ds: cfg.data.datasets[cfg.data.datasets.length - 1] };
      }
      // every researched event: what it cost. A batch of events shares one conversation, so its tokens and cost are split evenly.
      const evc = document.createElement("div"); evc.style.marginTop = "12px";
      evc.innerHTML = `<h3 style="margin:0 0 4px">Researched events</h3>`;
      evc.appendChild(RE.length ? table(null, [
        { k: "at", t: "When", fmt: (v) => esc(clock(v)), sort: (r) => r.at || 0 },
        { k: "label", t: "Event", fmt: (v, r) => `<span class="badge sev-info">${esc(TYPE[r.type] || r.type || "")}</span> ${esc(v || r.id || "")}`, sort: (r) => r.label || "" },
        { k: "model", t: "Model", cls: "small" },
        { k: "total", t: "Tokens", num: true, fmt: (v, r) => `${fn(v || 0)}${r.cache_read ? ` <span class="muted small" title="cache re-reads, billed at a fraction of the input price">(+${fn(r.cache_read)} cached)</span>` : ""}`, sort: (r) => r.total || 0 },
        { k: "cost_usd", t: "Cost", num: true, fmt: (v) => (v == null ? '<span class="muted" title="no price entered for this model">n/a</span>' : "$" + v.toFixed(v < 0.1 ? 3 : 2)), sort: (r) => r.cost_usd ?? -1 },
        { k: "batch", t: "Shared with", num: true, fmt: (v) => (v > 1 ? `${v - 1} other${v > 2 ? "s" : ""}` : "-"), sort: (r) => r.batch || 1 },
      ], RE, { sort: "at", limit: 25 }) : Object.assign(document.createElement("div"), { className: "small muted", textContent: "No events researched yet since this was added. Each event researched with Send to research is listed here with its tokens and cost." }));
      chart.appendChild(evc);
    }
    const runs = (J && J.runs) || [];
    c.querySelector(".cl-runs").appendChild(runs.length ? table(null, [
      { k: "started", t: "Started", fmt: (v) => esc(clock(v)), sort: (r) => r.started || 0 },
      { k: "status", t: "Result", fmt: (v, r) => `<span class="badge ${v === "completed" ? "sev-good" : v === "running" || v === "claimed" ? "sev-medium" : "sev-high"}">${esc(v === "claimed" ? "starting" : v)}</span>${r.error ? ` <span class="small bad">${esc(r.error)}</span>` : ""}` },
      { k: "pdf_run", t: "Type", fmt: (v, r) => `${v ? "Daily run (24 h)" : "Review"}${r.trigger === "manual" ? ' <span class="muted small">(manual)</span>' : ""}` },
      { k: "duration_s", t: "Took", num: true, fmt: (v, r) => esc(r.status === "running" ? `${dur(Math.round(now - r.started))} so far` : dur(v)) },
    ], runs, { sort: "started", limit: 12 }) : Object.assign(document.createElement("div"), { className: "empty", textContent: "No runs recorded yet." }));
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
      const v = USAGE.U.map((u) => runCost(u, price)), avg = v.reduce((a, x) => a + x, 0) / (v.length || 1);
      const rec = USAGE.U.filter((u) => u.cost_usd != null), recAvg = rec.length ? rec.reduce((a, u) => a + u.cost_usd, 0) / rec.length : null;
      USAGE.pv.innerHTML = `With <b>${esc(model)}</b>${chosen ? " (the AI Research job's model)" : ""}: about <b>$${avg.toFixed(2)} per run</b>` +
        (recAvg != null ? ` (the recorded runs averaged $${recAvg.toFixed(2)})` : "") +
        `. <span class="muted">Same token counts as the recorded runs re-priced at ` +
        `${esc(model)}'s price ($${price.in}/M in, $${price.out}/M out${price.cache_read != null ? `, $${price.cache_read}/M cache reads` : ""}); ` +
        `a different model would use a different number of tokens, so treat this as a rough guide.${chosen ? "" : ""}</span>`;
    }
    const data = same || !price ? USAGE.D.map(() => null) : USAGE.D.map((d) => +d.runs.reduce((a, u) => a + runCost(u, price), 0).toFixed(2));
    ds.data = data; ds.label = same || !price ? "Cost with selected model ($)" : `Cost with ${model} ($)`; ds.hidden = same || !price;
    if (ch) ch.update();
  }

  // ---- model choice (correlation reviewer + review job) and per-decision model comparison
  let MODELS = null;
  const loadModels = async () => { MODELS = MODELS || await api("/api/llm/models"); for (const g of MODELS.custom || []) PROV[g.provider] = g.name; return MODELS; };
  // the local server; admin-added API-key providers ("api:<id>") get their names from /api/aireview + /api/llm/models
  const PROV = { lmstudio: "Local (LM Studio)" };
  const optKey = (p, m) => `${p}|${m}`;
  // Settings apply as soon as they are set: the Save button is hidden and fires when the value is committed
  // (checkbox ticked, or number/text entry finished with Enter or by leaving the field).
  function autoApply(btn, inputs, run) {
    btn.style.display = "none";
    for (const i of inputs) i.addEventListener("change", () => { run ? run() : btn.onclick && btn.onclick(); });
  }
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
    note.textContent = D.admin ? "Correlation reviewer: decides every proposed link, continuously (cloud models are billed per decision batch; local models are free but need LM Studio). AI Research job: the scheduled triage, event research and daily report - needs a reasoning-capable model (it works through several tool calls per event and decides what to do next between them); give it some extra reasoning tokens on its AI providers row, or pick a local reasoning model (Qwen, DeepSeek-R1...) in LM Studio. Chat: the Ask AI assistant, works on any model. Add cloud models in the AI providers box."
      : "Only an admin can change models.";
    const rows = [["correlation", "Correlation reviewer", D.config?.correlation || {}], ["research", `AI Research job (${every(null, D.research?.interval_minutes)}) · needs reasoning`, D.research && !D.research.error ? D.research : {}],
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
        msg.textContent = cur.model ? `now: ${PROV[cur.provider] || cur.provider} · ${cur.model}` : sec === "research" ? (D.research?.error || "not set: the AI Research job does not run until a reasoning-capable model is chosen")
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
      body.appendChild(esResearchRow(D));
      body.appendChild(chatEsRow(D));
      body.appendChild(notesLimitRow(D));
      body.appendChild(notesCharsRow(D));
      body.appendChild(notesPerSubjectRow(D));
    }).catch((e) => { note.textContent = "Model list unavailable: " + e.message; });
    return c;
  }
  // Elasticsearch look-ups by the correlation reviewer: on/off + the most it may run for one event review (admin)
  function esQueriesRow(D) {
    const cfg = D.config?.es_queries || { enabled: false, max: 3, limit: 20 };
    const r = document.createElement("div"); r.className = "llm-row";
    r.appendChild(Object.assign(document.createElement("span"), { className: "k", textContent: "Elasticsearch queries · correlation review" }));
    const lab = r.appendChild(document.createElement("label")); lab.className = "small";
    const chk = lab.appendChild(Object.assign(document.createElement("input"), { type: "checkbox", checked: !!cfg.enabled }));
    lab.append(" correlation reviewer may search the logs for more context");
    const lab2 = r.appendChild(document.createElement("label")); lab2.className = "small";
    lab2.append("max per event ");
    const num = lab2.appendChild(Object.assign(document.createElement("input"), { type: "number", min: 1, max: cfg.limit || 20, step: 1, value: cfg.max || 3 }));
    num.style.width = "4.5em"; num.setAttribute("aria-label", "Maximum Elasticsearch queries per event");
    const btn = r.appendChild(Object.assign(document.createElement("button"), { type: "button", textContent: "Save" })); btn.disabled = true;
    const msg = r.appendChild(Object.assign(document.createElement("span"), { className: "small muted" }));
    const show = (c) => (c.enabled ? `now: on · up to ${c.max} per event` : "now: off") + (c.by ? ` (${c.by})` : "");
    msg.textContent = D.admin ? show(cfg) : show(cfg) + " · only an admin can change this";
    chk.disabled = num.disabled = !D.admin;
        autoApply(btn, [chk, num]);
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
  // Elasticsearch searches by the AI Research job (separate from the correlation reviewer's setting above)
  function esResearchRow(D) {
    const R = D.research && !D.research.error ? D.research : {};
    const r = document.createElement("div"); r.className = "llm-row";
    r.appendChild(Object.assign(document.createElement("span"), { className: "k", textContent: "Elasticsearch queries · AI research" }));
    const lab = r.appendChild(document.createElement("label")); lab.className = "small";
    const chk = lab.appendChild(Object.assign(document.createElement("input"), { type: "checkbox", checked: R.es_search !== false }));
    lab.append(" research AI may search the logs while researching events");
    const msg = r.appendChild(Object.assign(document.createElement("span"), { className: "small muted" }));
    const show = (on) => on ? "now: on" : "now: off";
    msg.textContent = D.admin ? show(chk.checked) : show(chk.checked) + " · only an admin can change this";
    chk.disabled = !D.admin || !D.research || !!D.research.error;
    chk.addEventListener("change", async () => {
      chk.disabled = true; msg.textContent = "saving…";
      try { const r2 = await apiPost("/api/llm/research", { es_search: chk.checked }); chk.checked = r2.research.es_search !== false; msg.textContent = "saved · " + show(chk.checked) + " (from the next run)"; }
      catch (e) { msg.textContent = "error: " + e.message; chk.checked = !chk.checked; }
      chk.disabled = !D.admin;
    });
    r.title = "When on, the AI Research job may run read-only Elasticsearch searches (es_search tool) while researching an event. Independent of the correlation reviewer's setting.";
    return r;
  }
  // Elasticsearch searches by the Ask AI chat (admin switch)
  function chatEsRow(D) {
    const cfg = D.config?.chat_es || { enabled: true };
    const r = document.createElement("div"); r.className = "llm-row";
    r.appendChild(Object.assign(document.createElement("span"), { className: "k", textContent: "Elasticsearch queries · Ask AI chat" }));
    const lab = r.appendChild(document.createElement("label")); lab.className = "small";
    const chk = lab.appendChild(Object.assign(document.createElement("input"), { type: "checkbox", checked: cfg.enabled !== false }));
    lab.append(" Ask AI may search the logs when answering");
    const msg = r.appendChild(Object.assign(document.createElement("span"), { className: "small muted" }));
    const show = (on) => on ? "now: on" : "now: off";
    msg.textContent = D.admin ? show(chk.checked) : show(chk.checked) + " · only an admin can change this";
    chk.disabled = !D.admin;
    chk.addEventListener("change", async () => {
      chk.disabled = true; msg.textContent = "saving…";
      try { const r2 = await apiPost("/api/llm/chat-es", { enabled: chk.checked }); chk.checked = r2.chat_es.enabled; msg.textContent = "saved · " + show(chk.checked) + " (from the next chat message)"; }
      catch (e) { msg.textContent = "error: " + e.message; chk.checked = !chk.checked; }
      chk.disabled = !D.admin;
    });
    r.title = "When on, the Ask AI chat may run read-only Elasticsearch searches of the Security Onion logs (elasticsearch_search tool) through the host broker. Every search is written to the audit log. Independent of the reviewer and research settings.";
    return r;
  }
  // Host / user notes given to the reviewer with each event (admin sets the cap; more notes = more tokens in)
  function notesLimitRow(D) {
    const cfg = D.config?.context_notes || { max: 7, limit: 100, default: 7 };
    const r = document.createElement("div"); r.className = "llm-row";
    r.appendChild(Object.assign(document.createElement("span"), { className: "k", textContent: "Notes per event" }));
    const lab = r.appendChild(document.createElement("label")); lab.className = "small";
    lab.append("host + user notes the reviewer sees for each event, max ");
    const num = lab.appendChild(Object.assign(document.createElement("input"), { type: "number", min: 1, max: cfg.limit, step: 1, value: cfg.max }));
    num.style.width = "4.5em"; num.setAttribute("aria-label", "Maximum host and user notes per event");
    const btn = r.appendChild(Object.assign(document.createElement("button"), { type: "button", textContent: "Save" })); btn.disabled = true;
    const msg = r.appendChild(Object.assign(document.createElement("span"), { className: "small muted" }));
    const show = (c) => `now: up to ${c.max} per event (default ${c.default}, limit ${c.limit})` + (c.by ? ` (${c.by})` : "");
    msg.textContent = D.admin ? show(cfg) : show(cfg) + " · only an admin can change this";
    num.disabled = !D.admin;
    autoApply(btn, [num]);
    btn.onclick = async () => {
      const mx = Math.round(+num.value);
      if (!(mx >= 1 && mx <= cfg.limit)) { msg.textContent = `Enter 1-${cfg.limit} notes per event.`; return; }
      btn.disabled = true; msg.textContent = "saving…";
      try { const r2 = await apiPost("/api/llm/notes", { max: mx }); Object.assign(cfg, r2.context_notes || {}); msg.textContent = "saved · " + show(cfg) + " (from the next review)"; }
      catch (e) { msg.textContent = "error: " + e.message; btn.disabled = false; }
    };
    r.title = "Host notes about the hosts an event involves and notes / profiles of the accounts it names are added to each event the reviewer sees. Raising this gives it more context (and more input tokens: see Avg tokens in / event); lowering it makes reviews cheaper.";
    return r;
  }
  // Most notes stored per host / user / domain (admin)
  function notesPerSubjectRow(D) {
    const cfg = D.config?.context_notes || {}, hi = cfg.per_subject_limit || 500, def = cfg.per_subject_default || 40;
    const r = document.createElement("div"); r.className = "llm-row";
    r.appendChild(Object.assign(document.createElement("span"), { className: "k", textContent: "Notes per host / user" }));
    const lab = r.appendChild(document.createElement("label")); lab.className = "small";
    lab.append("most notes kept for one host, user or domain, max ");
    const num = lab.appendChild(Object.assign(document.createElement("input"), { type: "number", min: 1, max: hi, step: 1, value: cfg.per_subject || def }));
    num.style.width = "4.5em"; num.setAttribute("aria-label", "Maximum notes stored per host or user");
    const btn = r.appendChild(Object.assign(document.createElement("button"), { type: "button", textContent: "Save" })); btn.disabled = true;
    const msg = r.appendChild(Object.assign(document.createElement("span"), { className: "small muted" }));
    const show = (c) => `now: up to ${c.per_subject} per host / user (default ${def}, limit ${hi})` + (c.by ? ` (${c.by})` : "");
    msg.textContent = D.admin ? show(cfg) : show(cfg) + " · only an admin can change this";
    num.disabled = !D.admin;
    autoApply(btn, [num]);
    btn.onclick = async () => {
      const v = Math.round(+num.value);
      if (!(v >= 1 && v <= hi)) { msg.textContent = `Enter 1-${hi} notes.`; return; }
      btn.disabled = true; msg.textContent = "saving…";
      try { const r2 = await apiPost("/api/llm/notes", { per_subject: v }); Object.assign(cfg, r2.context_notes || {}); msg.textContent = "saved · " + show(cfg); }
      catch (e) { msg.textContent = "error: " + e.message; btn.disabled = false; }
    };
    r.title = "How many notes the AI jobs and people can store for one host, user or domain. Once a subject is full, new notes are refused until old ones are updated or deleted. Existing notes are never removed when you lower this. This is the storage cap; 'Notes per event' above is how many the reviewer reads.";
    return r;
  }
  // Total characters of notes in one review prompt (below Notes per event)
  function notesCharsRow(D) {
    const cfg = D.config?.context_notes || {}, lo = cfg.chars_min || 1000, hi = cfg.chars_limit || 100000, def = cfg.chars_default || 6000;
    const r = document.createElement("div"); r.className = "llm-row";
    r.appendChild(Object.assign(document.createElement("span"), { className: "k", textContent: "Note characters" }));
    const lab = r.appendChild(document.createElement("label")); lab.className = "small";
    lab.append("total characters of notes in one review request, max ");
    const num = lab.appendChild(Object.assign(document.createElement("input"), { type: "number", min: lo, max: hi, step: 500, value: cfg.chars || def }));
    num.style.width = "6.5em"; num.setAttribute("aria-label", "Total note characters per review request");
    const btn = r.appendChild(Object.assign(document.createElement("button"), { type: "button", textContent: "Save" })); btn.disabled = true;
    const msg = r.appendChild(Object.assign(document.createElement("span"), { className: "small muted" }));
    const show = (c) => `now: ${c.chars} characters (default ${c.chars_default}, ${c.chars_min}-${c.chars_limit}; about ${Math.round(c.chars / 4)} tokens)` + (c.by ? ` (${c.by})` : "");
    msg.textContent = D.admin ? show(cfg) : show(cfg) + " · only an admin can change this";
    num.disabled = !D.admin;
    autoApply(btn, [num]);
    btn.onclick = async () => {
      const n = Math.round(+num.value);
      if (!(n >= lo && n <= hi)) { msg.textContent = `Enter ${lo}-${hi} characters.`; return; }
      btn.disabled = true; msg.textContent = "saving…";
      try { const r2 = await apiPost("/api/llm/notes", { chars: n }); Object.assign(cfg, r2.context_notes || {}); msg.textContent = "saved · " + show(cfg) + " (from the next review)"; }
      catch (e) { msg.textContent = "error: " + e.message; btn.disabled = false; }
    };
    r.title = "The notes picked for each event are cut off once this many characters are in the request, whatever Notes per event allows (one note is at most 300-400 characters). A request that also has several candidate events shares the budget. More characters = more input tokens and slower reviews; the single-link re-check uses a third of it.";
    return r;
  }
  // Elasticsearch searches of one AI: the correlation reviewer (structured requests) or the research AI (raw query DSL)
  function esCard(D, who) {
    const R = who === "research", E = (R ? D.es_queries?.research : D.es_queries) || { total: 0, last_day: 0, recent: [] };
    const on = R ? true : D.config?.es_queries?.enabled;
    const fq = (q) => { if (!q || typeof q !== "object") return `<span class="mono small">${esc(String(q || ""))}</span>`;
      if (q.index) return `<span class="mono">${esc(q.index)}</span><pre class="mono small" style="margin:2px 0;white-space:pre-wrap;max-width:60em">${esc(JSON.stringify(q.body || {}, null, 1).slice(0, 1500))}</pre>`;
      const m = Object.entries(q.match || {}).map(([k, v]) => `${k}=${Array.isArray(v) ? v.join("|") : v}`).join(" ");
      return `<span class="mono">${esc(q.source || "?")}</span> ${esc(m)}${q.text ? ` "${esc(q.text)}"` : ""}${q.group_by ? ` <span class="muted">top ${esc(q.group_by)}</span>` : ""}` +
        `${q.start ? ` <span class="muted small">${esc(String(q.start).slice(5, 16))}→${esc(String(q.end || "").slice(5, 16))}</span>` : ""}${q.why ? `<div class="small muted">${esc(q.why)}</div>` : ""}`; };
    const title = R ? "Research AI Elasticsearch queries" : "Reviewer Elasticsearch queries";
    const c = card(`${title} (${fn(E.last_day)} in 24 h · ${fn(E.total)} total)`, E.recent.length ? "" :
      `<div class="small muted">${R ? "The research AI has not searched Elasticsearch yet (it can run es_search while researching events)." : on ? "The reviewer has not searched Elasticsearch yet." : "Off. Turn on <b>Elasticsearch queries</b> in the Models box to let the reviewer search the logs for more context."}</div>`);
    c.id = R ? "ai-es-research" : "ai-es";
    if (E.recent.length) c.appendChild(table(null, [
      { k: "ts", t: "When", fmt: (v) => esc(ago(v)), sort: (r) => r.ts },
      { k: "anchor_label", t: R ? "Run" : "Event under review", fmt: (v, r) => (r.anchor_link ? `<a href="${esc(r.anchor_link)}">${esc(v)}</a>` : esc(v)) },
      { k: "query", t: "Query", fmt: (v) => fq(v) },
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
    seg_high: "Segmentation, high: cross-zone flows on admin / remote-control ports (SSH, RDP, SMB, WinRM, databases, Docker and Kubernetes APIs).",
    seg_medium: "Segmentation, medium: cross-zone flows on odd ports that are neither admin nor standard.",
    seg_low: "Segmentation, low: cross-zone flows on standard ports (HTTP, HTTPS, DNS, mail and similar).",
    ids: "Suricata IDS signatures seen in the window, one event per signature.",
    host: "Endpoint host findings from the agents (new network destinations, processes, policy drift).",
    alarm: "AI alarms: rollups over the events above.",
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
      <div class="small muted">Links that are skipped or excluded here are never sent to the reviewer (no model call) and leave the queue. Links that already have a verdict are kept.
        Changes apply from the next review round.</div>
      <div class="rl-class" style="margin:10px 0 4px"><label><input type="checkbox" class="rl-cls"> <b>Classify events</b></label>
        <span class="small muted">When on, once every correlation of an event has been reviewed the AI decides whether the event is <b>suspicious</b>, <b>benign</b> or <b>expected</b> and adds that flair to the event (Related column). Re-done when its links change; up to ${20} events per round, using the reviewer model.</span>
        <div class="small rl-clsinfo" style="margin-top:3px"></div></div>
      <div class="rl-win" style="margin:10px 0 4px"><b>Time window for the reviewer</b>
        only correlate events within <input type="number" class="rl-wmax" min="0" step="any" style="width:6em"> minutes before or after each other
        <button type="button" class="rl-wsave">Save</button>
        <span class="small rl-wmsg"></span>
        <span class="small muted">0 = no limit. A link is never considered (no model call, no classification) when its two events are further apart than this; events without a time, such as open vulnerabilities, always count. Links that already have a verdict are kept.</span>
        <div class="small rl-winfo" style="margin-top:3px"></div></div>
      <div class="rl-disc" style="margin:10px 0 4px"><b>Discard old verdicts</b>
        not seen for more than <input type="number" class="rl-dmax" min="0" step="any" style="width:6em"> days
        <button type="button" class="rl-dsave">Save</button>
        <span class="small rl-dmsg"></span>
        <span class="small muted">0 = keep forever. A verdict is "seen" while its two events are still a candidate link in the newest snapshot. Verdicts nobody has seen for longer than this (and their evidence) are deleted, checked hourly, to keep the database small; a link that comes back is simply reviewed again. Verdicts set by a person are kept.</span>
        <div class="small rl-dinfo" style="margin-top:3px"></div></div>
      <div style="margin:10px 0 4px"><b>Max links per event</b> <input type="number" class="rl-max" min="0" max="${Lm.limit_range || 200}" step="1" style="width:5em">
        <button type="button" class="rl-maxsave">Save</button>
        <span class="small muted">Each event is reviewed against at most this many links, best-scoring first (0 = no cap). Applies to links without a verdict; a link needs room at both of its events.</span></div>
      <h3 style="margin:10px 0 4px">Correlation Event Type Pairs</h3>
      <div class="small muted">Each cell is the pair of its row and column type (the matrix is symmetric, so only the upper triangle is shown). Click a cell to switch it between <b>review</b> (on) and <b>skip</b> (off). The number is the candidate links.</div>
      <div class="rl-pairs" style="overflow-x:auto;margin-top:6px"></div>
      <div class="small muted rl-msg" style="margin-top:6px">${D.can_limit ? "" : "Only an admin or network defender can change these limits."}</div>`);
    c.id = "ai-limits";
    const msg = c.querySelector(".rl-msg");
    const post = async (b, quiet) => { msg.textContent = "saving…";
      try { await apiPost("/api/llm/review-limits", b); msg.textContent = "saved"; if (!quiet) refresh(); }
      catch (e) { msg.textContent = "error: " + e.message; } };
    const cls = c.querySelector(".rl-cls"), clsi = c.querySelector(".rl-clsinfo"), esCfg = D.config?.es_queries || {};
    cls.checked = !!Lm.classify; cls.disabled = !D.can_limit;
    const cc = Lm.class_counts || {}, ccn = ["suspicious", "benign", "expected"].map((k) => `<span class="note-v v-${k}">${k}</span> ${fn(cc[k] || 0)}`).join(" ");
    clsi.innerHTML = `${Lm.classify ? "<b>On</b>" : "Off"} · classified so far: ${ccn}` +
      ` · Elasticsearch for the reviewer: ${esCfg.enabled ? `<b>on</b> (up to ${esCfg.max} look-ups per event, used for classification too)` : `off${D.admin ? ' <button type="button" class="rl-es">Let the reviewer use Elasticsearch</button>' : " (an admin can turn it on in the Models box)"}`}`;
    const esb = clsi.querySelector(".rl-es");
    const enableEs = async () => { await apiPost("/api/llm/esqueries", { enabled: true, max: esCfg.max || 3 }); };
    if (esb) esb.onclick = async () => { try { await enableEs(); refresh(); } catch (e) { msg.textContent = "error: " + e.message; } };
    cls.onchange = async () => {
      try {
        if (cls.checked && !esCfg.enabled && D.admin && confirm("Also let the reviewer search Elasticsearch (read-only Security Onion logs) for more context when it classifies events and reviews links?")) await enableEs();
        await post({ classify: cls.checked });
      } catch (e) { msg.textContent = "error: " + e.message; }
    };
    const wmax = c.querySelector(".rl-wmax"), wsv = c.querySelector(".rl-wsave"), wo = Lm.window_out || {};
    wmax.value = Lm.window_minutes || 0; wmax.disabled = wsv.disabled = !D.can_limit;
    c.querySelector(".rl-winfo").textContent = Lm.window_minutes ? `Now outside the window: ${fn(wo.links || 0)} candidate links.` : "No window set: events of any age gap are correlated.";
    wsv.onclick = async () => { const wm = c.querySelector(".rl-wmsg"); wm.textContent = "saving…";
      try { await apiPost("/api/llm/review-limits", { window: { minutes: +wmax.value || 0 } }); wm.textContent = "saved"; refresh(); }
      catch (e) { wm.textContent = "error: " + e.message; } };
    autoApply(wsv, [wmax]);
    const dmax = c.querySelector(".rl-dmax"), dsv = c.querySelector(".rl-dsave"), di = Lm.discard || {};
    dmax.value = Lm.discard_days || 0; dmax.disabled = dsv.disabled = !D.can_limit;
    c.querySelector(".rl-dinfo").textContent = `${fn(di.total || 0)} verdicts stored` + (Lm.discard_days ? ` · ${fn(di.would || 0)} would be discarded now` : " · retention off") +
      (di.at ? ` · last pass ${new Date(di.at * 1000).toLocaleString()}: removed ${fn(di.removed || 0)}` : "");
    dsv.onclick = async () => { const dm = c.querySelector(".rl-dmsg"); dm.textContent = "saving…";
      try { await apiPost("/api/llm/review-limits", { discard_days: +dmax.value || 0 }); dm.textContent = "saved"; refresh(); }
      catch (e) { dm.textContent = "error: " + e.message; } };
    autoApply(dsv, [dmax]);
    const mx = c.querySelector(".rl-max"), mxb = c.querySelector(".rl-maxsave");
    mx.value = Lm.max_links || 0; mx.disabled = mxb.disabled = !D.can_limit;
    mxb.onclick = () => post({ max_links: mx.value === "" ? 0 : +mx.value });
    autoApply(mxb, [mx]);
    const pairs = c.querySelector(".rl-pairs");
    {
      const pm = {}, pl = {}, MODES = ["review", "skip"], MC = { review: "#1f7a3a", skip: "#8a2a2a" };
      const ts = new Set();
      for (const p of Lm.pairs || []) { pm[p.pair] = p.mode; pl[p.pair] = p.links; for (const t of p.pair.split("-")) ts.add(t); }
      // every type is split by severity (ids_high ...); columns are grouped by type, then low / medium / high
      const ORDER = ["ids", "alert", "alarm", "admin", "ti", "gw", "host", "finding", "vuln", "seg"], SV = ["high", "medium", "low"];
      const SVC = { high: "#c0392b", medium: "#b8860b", low: "#4a7c59" };
      const parse = (t) => { const m = /^(.+)_(low|medium|high)$/.exec(t); return m ? [m[1], m[2]] : [t, ""]; };
      const oi = (b) => { const i = ORDER.indexOf(b); return i < 0 ? 99 : i; };
      const types = [...ts].sort((a, b) => { const [ba, sa] = parse(a), [bb, sb] = parse(b); return oi(ba) - oi(bb) || ba.localeCompare(bb) || SV.indexOf(sa) - SV.indexOf(sb); });
      const bases = [...new Set(types.map((t) => parse(t)[0]))];
      const cell = (k, x) => { if (!(k in pm)) return `<td style="text-align:center;color:#666;${x}">·</td>`;
        return `<td style="padding:2px;${x}"><button type="button" data-pair="${esc(k)}" class="rl-cell" ${D.can_limit ? "" : "disabled"} title="${esc(k)}: ${pm[k]}" style="width:100%;min-width:5.5em;border:1px solid ${MC[pm[k]]};background:${MC[pm[k]]}33;border-radius:4px;padding:2px 6px;cursor:pointer;color:inherit"><b>${esc(pm[k])}</b><br><span class="small muted">${fn(pl[k] || 0)}</span></button></td>`; };
      const sevTag = (t) => { const s = parse(t)[1]; return `<span class="small" style="color:${SVC[s] || "inherit"}">${esc(s || "-")}</span>`; };
      const gstyle = (i) => (i === 0 || parse(types[i])[0] !== parse(types[i - 1])[0]) ? "border-left:2px solid #555;" : "";
      const head1 = `<tr><th></th><th></th>${bases.map((b) => `<th colspan="${types.filter((t) => parse(t)[0] === b).length}" style="text-align:center;border-left:2px solid #555;padding:2px 8px"><span class="mono small">${esc(b)}</span>${tip(b)}</th>`).join("")}</tr>`;
      const head2 = `<tr><th></th><th></th>${types.map((t, i) => `<th style="text-align:center;${gstyle(i)}">${sevTag(t)}</th>`).join("")}</tr>`;
      pairs.innerHTML = `<table style="border-collapse:separate;border-spacing:3px"><thead>${head1}${head2}</thead><tbody>` +
        types.map((r, i) => { const [rb] = parse(r), first = i === 0 || parse(types[i - 1])[0] !== rb;
          return `<tr${first ? ' style="border-top:2px solid #555"' : ""}>` +
            (first ? `<th rowspan="${types.filter((t) => parse(t)[0] === rb).length}" style="text-align:right;padding-right:8px;vertical-align:middle"><span class="mono small">${esc(rb)}</span>${tip(rb)}</th>` : "") +
            `<th style="text-align:right;padding-right:6px">${sevTag(r)}</th>` +
            types.map((c, j) => j < i ? "<td></td>" : cell(pairKey(r, c), gstyle(j))).join("") + "</tr>"; }).join("") + "</tbody></table>";
      for (const b of pairs.querySelectorAll(".rl-cell")) b.onclick = () => {
        const k = b.dataset.pair; pm[k] = MODES[(MODES.indexOf(pm[k]) + 1) % MODES.length];
        b.querySelector("b").textContent = pm[k]; b.style.borderColor = MC[pm[k]]; b.style.background = MC[pm[k]] + "33"; b.title = `${k}: ${pm[k]}`;
        (pairs._chg = pairs._chg || {})[k] = pm[k];  // only the cells you touched are saved; the rest keep inheriting
        clearTimeout(pairs._t); pairs._t = setTimeout(() => { const c = pairs._chg; pairs._chg = {}; post({ pair_modes: c }, true); }, 250);  // saved at once (rapid clicks share one request); no page reload
      };
    }
    return c;
  }
  // ---- AI providers (admin): any OpenAI-compatible or Anthropic API with a key, called by the dashboard itself
  function providersCard() {
    const c = card("AI providers", `<div class="small muted"><b>Local (LM Studio)</b> is the LM Studio server on this host (no key; its enabled flag and rate limit can be set here;
      the model list comes live from LM Studio). Add any number of other AI services that take an API key. <b>OpenAI / OpenAI-compatible</b> covers
      OpenAI itself and services with the same API (OpenRouter, Groq, Mistral, Together, DeepSeek, Gemini's OpenAI endpoint, a self-hosted vLLM...);
      <b>Anthropic</b> is Anthropic's API with an Anthropic API key. Their models can be picked for the correlation reviewer, the AI Research job and the chat,
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
            <div class="small muted">Pick each model from the drop-down (use Fetch to fill it, or choose "Custom…" to type an id). Prices are optional, in $ per million tokens; with them the dashboard estimates costs and enforces the AI Research job's $ caps (token caps work without).</div></span></div>
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

  // ---- review job cost caps (research_cfg.py): $ per run / per day, tokens per run, research batches per run
  // events sent through the review phase per day (review_events: one row per event review, kept 30 days)
  function reviewVolumeCard(D) {
    const days = ((D.totals || {}).events_per_day || []), today = new Date().toLocaleDateString("sv");
    const full = days.filter((d) => d.day !== today);  // today is partial: left out of the averages
    const avg = (rows, k) => (rows.length ? rows.reduce((a, r) => a + r[k], 0) / rows.length : null);
    const f1 = (v) => (v == null ? "—" : fn(Math.round(v * 10) / 10));
    const w7 = full.slice(0, 7);
    const c = card("Events per day through review", `<div class="small muted">Events sent to the reviewer model, per day (a day is counted once it has ended; today is shown but not averaged). Kept for 30 days.</div>`);
    const sums = [["Average / day (last 7 full days)", w7], ["Average / day (all " + full.length + " full days)", full]];
    c.insertAdjacentHTML("beforeend", kpis(sums.map(([t, r]) => [t, f1(avg(r, "events"))])));
    c.appendChild(days.length ? table(null, [
      { k: "day", t: "Day", fmt: (v) => esc(v) + (v === today ? ' <span class="muted small">(so far)</span>' : "") },
      { k: "events", t: "Events reviewed", num: true, fmt: (v) => fn(v) },
      { k: "links", t: "Candidate links", num: true, fmt: (v) => fn(v) },
    ], days, { sort: "day", limit: 30 }) : Object.assign(document.createElement("div"), { className: "small muted", textContent: "No event reviews recorded yet." }));
    return c;
  }
  function costCard(D) {
    const R = D.research || {}, L = R.limits || {}, T = "Research job limits";
    if (R.error) { const e = card(T, `<div class="bad">Limits unavailable: ${esc(R.error)}</div>`); e.id = "ai-cost"; return e; }
    const U = (((D.research_status || {}).jobs || [])[0]?.usage || []).filter((u) => u.cost_usd != null).map((u) => u.cost_usd);
    const avg = U.length ? U.reduce((a, v) => a + v, 0) / U.length : null, max = U.length ? Math.max(...U) : null;
    const usd = (v) => `$${(+v).toFixed(2)}`;
    const c = card(T, `
      <div class="small muted">The AI Research job adds up the tokens of every model call and, when the model has a price (AI providers > Models), the
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
          <span class="small muted" style="flex:1 1 380px">Lets the model search and read web pages and cite them. Turn it off for cheaper, local-data-only runs (no web tools, no links or citations).</span></div>
      </div>
      <div class="small muted" style="margin-top:8px">The correlation reviewer and comparisons make single calls and are capped per provider (AI providers > Calls per hour) instead;
        chat answers are capped at 600,000 tokens each. Local LM Studio models cost $0.</div>
      <div style="margin-top:8px"><button type="button" class="cost-save">Save</button> <span class="small muted cost-msg"></span></div>`);
    c.id = "ai-cost";
    const K = ["max_run_usd", "max_day_usd", "max_run_tokens", "max_batches", "max_searches"];
    const inp = (k) => c.querySelector(`input[name="${k}"]`), btn = c.querySelector(".cost-save"), msg = c.querySelector(".cost-msg");
    const warn = () => { const r = +inp("max_run_usd").value || 0, over = r ? U.filter((v) => v > r).length : 0;
      c.querySelector(".cost-warn").textContent = r && avg != null && r < avg ? " Below the usual run cost: most runs would stop before finishing."
        : over ? ` ${over} of the last ${U.length} runs cost more than this.` : ""; };
    const web = c.querySelector('input[name="web_research"]');
    const fill = (v) => { for (const k of K) inp(k).value = v[k] ?? 0; web.checked = v.web_research === true; warn(); };
    fill({ ...L, web_research: R.web_research });
    for (const k of K) { inp(k).disabled = !D.admin; inp(k).oninput = warn; }
    web.disabled = !D.admin;
    btn.disabled = true;
    if (!D.admin) msg.textContent = "Only an admin can change the limits.";
    btn.onclick = async () => {
      const body = {};
      for (const k of K) body[k] = inp(k).value === "" ? 0 : +inp(k).value;
      body.web_research = web.checked;
      msg.textContent = "saving…";
      try { const r = await apiPost("/api/llm/research", body); fill({ ...(r.research.limits || body), web_research: r.research.web_research }); msg.textContent = "saved (applies from the next run)"; }
      catch (e) { msg.textContent = "error: " + e.message; }
    };
    autoApply(btn, [...K.map(inp), web]);
    return c;
  }

  // review job lookback window (lookback.py, store meta "research_lookback"): hours of logs each run collects
  function lookbackCard(D) {
    const L = D.lookback || { hours: 24, min: 1, max: 24, pdf_hour: 5 };
    const iv = D.research?.interval_minutes, ivH = iv ? iv / 60 : null;
    const rec = ivH ? Math.min(L.max, Math.ceil(ivH) + 1) : null;
    const c = document.createElement("div");  // a section inside the AI Research job card
    c.style.cssText = "margin-top:14px;padding-top:10px;border-top:1px solid #2a323d";
    c.innerHTML = `<h3 style="margin:0 0 4px">Lookback window</h3>
      <div class="small muted">How many hours of logs each run of the AI Research job collects and correlates. Shorter windows mean fewer events and fewer
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
      <div class="small muted" style="margin-top:6px">${L.at ? `Last changed by ${esc(L.by || "?")} ${esc(ago(L.at))}.` : `Not changed yet: default ${L.default ?? 24} h.`} Applies from the next run.</div>`;
    c.id = "ai-lookback";
    const inp = c.querySelector('input[name="lb_hours"]'), btn = c.querySelector(".lb-save"), msg = c.querySelector(".lb-msg"), wr = c.querySelector(".lb-warn");
    const warn = () => { const h = +inp.value;
      wr.className = "lb-warn " + (ivH && h < ivH ? "bad" : "");
      wr.textContent = ivH && h && h < ivH ? ` Shorter than the run interval: about ${+(ivH - h).toFixed(2)} h of logs between runs will never be reviewed (only the 24 h PDF run sees them).`
        : ivH && h >= 2 * ivH && h > rec ? ` Each run re-reviews about ${+(h - ivH).toFixed(1)} h that the previous run already covered.` : ""; };
    inp.value = L.hours; warn();
    inp.disabled = !D.admin; btn.disabled = true;
    inp.oninput = warn;
    if (!D.admin) msg.textContent = "Only an admin can change the lookback window.";
    btn.onclick = async () => {
      const h = inp.value.trim();
      if (!/^\d+$/.test(h) || +h < L.min || +h > L.max) { msg.textContent = `Enter a whole number of hours from ${L.min} to ${L.max}.`; return; }
      msg.textContent = "saving…";
      try { const r = await apiPost("/api/config/lookback", { hours: +h }); inp.value = r.lookback.hours; warn();
        msg.textContent = `saved: ${r.lookback.hours} h per run (from the next run; the PDF run stays 24 h)`; }
      catch (e) { msg.textContent = "error: " + e.message; btn.disabled = false; }
    };
    autoApply(btn, [inp]);
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

  const build = async (el, bg) => {
    el.innerHTML = `<h1>AI review</h1><div class="sub">The correlation script proposes links between events and vulnerabilities. The correlation reviewer (an AI model) decides whether each link is real, and on the research schedule the AI Research job's model researches the important events and re-reviews their links (its verdicts replace the reviewer's). Rejected links are hidden from the Related column; confirmed ones show the model's reason. Here you can watch the review, check its decisions and override them.</div><div class="loading">Loading…</div>`;
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
      ["Reviews / min", `${fn(T.rate_per_min ?? 0)}`, T.rate_per_min ? "good" : ""], ["Tokens / min", fn(T.tokens_per_min ?? 0), T.tokens_per_min ? "good" : ""], ["Tokens / sec", T.tokens_per_sec == null ? "—" : T.tokens_per_sec.toFixed(1), T.tokens_per_sec ? "good" : ""], ["Avg tokens in / event", `<span title="prompt tokens per event review, last 24 h (${fn(T.event_tokens?.day?.n || 0)} reviews). All time: ${fn(T.event_tokens?.all?.in || 0)} over ${fn(T.event_tokens?.all?.n || 0)} reviews">${T.event_tokens?.day?.n ? fn(T.event_tokens.day.in) : "—"}</span>`], ["Avg tokens out / event", `<span title="completion tokens per event review, last 24 h. All time: ${fn(T.event_tokens?.all?.out || 0)}">${T.event_tokens?.day?.n ? fn(T.event_tokens.day.out) : "—"}</span>`], ["Avg notes in / event", `<span title="notes (owner + AI: event, host, account, internet) passed to the model per event review, last 24 h. All time: ${T.event_tokens?.all?.notes ?? "—"}">${T.event_tokens?.day?.notes != null ? T.event_tokens.day.notes : "—"}</span>`], ["Reviews / hour", fn(T.rate_per_hour)], ["Done in", q.eta_min == null ? (q.pending ? "?" : "—") : q.eta_min < 90 ? `~${q.eta_min} min` : `~${(q.eta_min / 60).toFixed(1)} h`]]));

    if (D.admin) {
      const bar = document.createElement("div"); bar.style.cssText = "margin:8px 0;display:flex;gap:8px;flex-wrap:wrap;align-items:center";
      bar.innerHTML = '<button type="button" class="clr-rq">Clear research queue</button><button type="button" class="clr-rv">Clear review queue</button><span class="small muted clr-msg"></span>';
      el.querySelector(".kpis").after(bar);
      const msg = bar.querySelector(".clr-msg");
      const go = async (path, warn) => {
        if (!confirm(warn)) return;
        msg.textContent = "clearing…";
        try { const r = await apiPost(path, {}); msg.textContent = `done (${fn(r.dismissed || 0)} dismissed)`; S.corr = null; setTimeout(() => rerender(), 800); }
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
      box = card("Events awaiting research", '<div class="loading inline">Loading…</div>'); box.id = "ai-rq";
      (el.querySelector(".kpis") || el.lastElementChild).after(box);
      try {
        const Q = await api("/api/aireview/research-queue");
        box.querySelector(".loading").outerHTML = `<div class="small muted">${fn(Q.count || 0)} events the next run would send to the model (research mode, no note yet)${Q.testing ? `, plus ${fn(Q.testing)} tagged <i>testing</i> (test mode: listed, never sent)` : ""}. Snapshot ${esc(Q.snapshot || "")}.</div>`;
        if (Q.items?.length) box.appendChild(table(null, [
          { k: "type", t: "Type", cls: "mono small" }, { k: "sev", t: "Severity" },
          { k: "label", t: "Event", fmt: (v, r) => (r.testing ? '<span class="badge sev-unknown" title="test mode: never sent">testing</span> ' : "") + (r.link ? `<a href="${esc(r.link)}">${esc(v)}</a>` : esc(v)) },
          { k: "when", t: "When", cls: "small" }, { k: "repeats", t: "Repeats", num: true }], Q.items, { sort: "sev", limit: 50 }));
      } catch (e) { box.querySelector(".loading")?.remove(); box.insertAdjacentHTML("beforeend", `<pre>${esc(e)}</pre>`); }
    };
    const rva = el.querySelector(".rv-open");
    if (rva) rva.onclick = async (ev) => {
      ev.preventDefault();
      let box = el.querySelector("#ai-rv");
      if (box) { box.remove(); return; }
      box = card("Links awaiting review", '<div class="loading inline">Loading…</div>'); box.id = "ai-rv";
      (el.querySelector("#ai-rq") || el.querySelector(".kpis") || el.lastElementChild).after(box);
      try {
        const Q = await api("/api/aireview/review-queue");
        box.querySelector(".loading").outerHTML = `<div class="small muted">${fn(Q.count || 0)} links the reviewer has not decided yet${Q.testing ? `, plus ${fn(Q.testing)} tagged <i>testing</i> (test mode: listed, never sent)` : ""}${Q.count > Q.items.length ? ` (showing the best-scoring ${fn(Q.items.length)})` : ""}. Links held back by Review limits are not listed.</div>`;
        const ln = (l, lk, t, id) => `<span class="mono muted small">${esc(t)}</span> ${lk ? `<a href="${esc(lk)}">${esc(l)}</a>` : esc(l)}${id ? `<div class="mono muted small" style="word-break:break-all">${esc(id)}</div>` : ""}`;
        if (Q.items?.length) box.appendChild(table(null, [
          { k: "_p", t: "Pair", cls: "small", sort: (r) => pairKey(r.a_type, r.b_type), fmt: (v, r) => esc(pairText(r.a_type, r.b_type)) },
          { k: "a_label", t: "Event", fmt: (v, r) => (r.testing ? '<span class="badge sev-unknown" title="test mode: never sent">testing</span> ' : "") + ln(v, r.a_link, TYPE[r.a_type] || r.a_type, r.a) + (r.a_type === "alert" ? " " + alertMuteHtml(v) : "") },
          { k: "b_label", t: "Linked to", fmt: (v, r) => ln(v, r.b_link, TYPE[r.b_type] || r.b_type, r.b) + (r.b_type === "alert" ? " " + alertMuteHtml(v) : "") },
          { k: "why", t: "Why correlated", cls: "small", fmt: (v) => esc(Array.isArray(v) ? v.join(", ") : String(v || "")) }, { k: "score", t: "Score", num: true, fmt: (v) => esc(String(Math.round(v * 100) / 100)) }],
          Q.items, { sort: "score", limit: 50 }));
      } catch (e) { box.querySelector(".loading")?.remove(); box.insertAdjacentHTML("beforeend", `<pre>${esc(e)}</pre>`); }
    };
    el.appendChild(reviewVolumeCard(D));
    el.appendChild(modelsCard(D));
    if (D.admin) el.appendChild(providersCard());
    el.appendChild(costCard(D));
    el.appendChild(limitsCard(D));
    el.appendChild(esCard(D, "reviewer"));
    el.appendChild(esCard(D, "research"));
    el.append(...researchCard(D.research_status || {}, D));

    const pct = q.pending + q.confirmed + q.rejected ? Math.round((100 * (q.confirmed + q.rejected)) / (q.pending + q.confirmed + q.rejected)) : 100;
    const info = card("Reviewer", `<div class="idgrid">
        <span class="k">Model</span><span class="mono">${esc(st.model || "auto (loaded model)")}</span><span class="k">Provider</span><span>${esc(PROV[st.provider || D.config?.correlation?.provider] || "Local (LM Studio)")} · <a href="#/aireview?at=ai-models">change</a></span>
        <span class="k">Endpoint</span><span class="mono">${esc(D.url)}</span>
        <span class="k">Settings</span><span>${D.workers} parallel · reasoning ${esc(D.reasoning)}</span>
        <span class="k">Elasticsearch</span><span>${D.config?.es_queries?.enabled ? `may search, up to ${D.config.es_queries.max} per event · <a href="#/aireview?at=ai-es">${fn(D.es_queries?.last_day || 0)} queries in 24 h</a>` : `no searches · <a href="#/aireview?at=ai-models">change</a>`}</span>
        <span class="k">Research AI Elasticsearch</span><span><a href="#/aireview?at=ai-es-research">${fn(D.es_queries?.research?.last_day || 0)} queries in 24 h</a> · ${fn(D.es_queries?.research?.total || 0)} total</span>
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
      { k: "_p", t: "Pair", cls: "small", sort: (r) => pairKey(r.a_type, r.b_type), fmt: (v, r) => `<a href="${esc(hashWith("aireview", { pair: pairKey(r.a_type, r.b_type), at: "ai-list" }))}" title="Show only this event pair">${esc(pairText(r.a_type, r.b_type))}</a>` },
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
    if (st.busy || q.pending) { const t = setTimeout(() => { if (location.hash.startsWith("#/aireview") && !document.hidden && !midEdit()) refresh(); }, 60000);
      addEventListener("hashchange", () => clearTimeout(t), { once: true }); }
  };
  // Page entry: build inside a wrapper so a background refresh can swap the whole page in one step.
  V.aireview = async (el) => { const w = document.createElement("div"); el.appendChild(w); await build(w); };
  // Background refresh: an in-place re-render (app.js rerender): only the boxes whose numbers changed are swapped, the rest
  // (charts, open tables, scroll position) stay as they are.
  const refresh = () => { if (location.hash.startsWith("#/aireview")) return rerender(); };
})();
