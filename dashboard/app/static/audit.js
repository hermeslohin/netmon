// More > Audit log (#/audit, admin only): every user action and every app <-> LLM conversation, read from the
// Elasticsearch index logs-netmon (server: audit.py). Filters live in the URL (#/audit?kind=llm&range=7d...).
(() => {
  const KIND = { action: "User action", llm: "AI conversation" };
  const RANGES = [["1h", "Last hour"], ["24h", "Last 24 hours"], ["7d", "Last 7 days"], ["30d", "Last 30 days"], ["90d", "Last 90 days"], ["all", "All time"]];
  const PURPOSE = { "llm.chat": "Ask AI chat", "llm.correlation-review": "Correlation review (background)", "llm.correlation-compare": "Correlation compare",
    "llm.item-compare": "Item compare", "llm.research-input": "Research job: work list", "llm.research-result": "Research job: results",
    "llm.research-hostnotes": "Research job: host notes" };
  const outBadge = (o) => `<span class="badge ${o === "failure" ? "sev-high" : "sev-low"}">${esc(o || "—")}</span>`;
  const kindBadge = (k) => `<span class="badge ${k === "llm" ? "sev-medium" : "sev-info"}">${esc(KIND[k] || k)}</span>`;
  const when = (t) => { const d = new Date(t); return isNaN(d) ? esc(t) : esc(d.toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" })); };
  const pad = (n) => String(n).padStart(2, "0");
  const locIn = (iso) => { const d = new Date(iso); return iso && !isNaN(d) ? `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}` : ""; };
  const opt = (v, label, cur) => `<option value="${esc(v)}"${String(cur) === String(v) ? " selected" : ""}>${esc(label)}</option>`;

  function pre(text) { const p = document.createElement("pre"); p.className = "audit-pre"; p.textContent = text; return p; }
  function section(title, node) { const d = document.createElement("div"); d.className = "audit-sec"; const h = document.createElement("h3"); h.textContent = title; d.append(h, node); return d; }

  async function showDoc(box, id) {
    box.replaceChildren(); box.insertAdjacentText("beforeend", "Loading…");
    let D; try { D = (await api("/api/audit/doc?id=" + encodeURIComponent(id))).doc; } catch (e) { box.textContent = String(e.message || e); return; }
    box.replaceChildren();
    const ev = D.event || {}, g = D.gen_ai || {}, L = (D.netmon || {}).llm || {};
    const facts = [["Time", new Date(D["@timestamp"]).toLocaleString()], ["Type", KIND[ev.dataset === "netmon.llm" ? "llm" : "action"]],
      ["Action", PURPOSE[ev.action] || ev.action], ["Outcome", ev.outcome], ["User", (D.user || {}).name], ["Role", ((D.user || {}).roles || []).join(", ")],
      ["Source IP", (D.source || {}).ip], ["Request", D.http ? `${D.http.request?.method || ""} ${(D.url || {}).path || ""} → ${D.http.response?.status_code ?? ""}` : ""],
      ["Target", (D.netmon || {}).target], ["Provider", g.system], ["Model", g.request?.model], ["Chat session", L.session_id],
      ["Tokens in / out", g.usage ? `${fn(g.usage.input_tokens)} / ${fn(g.usage.output_tokens)}` : ""],
      ["Duration", ev.duration ? (ev.duration / 1e9).toFixed(2) + " s" : ""], ["Tools used", (L.tools || []).join(", ")], ["Status", L.status],
      ["Error", L.error], ["Browser", (D.user_agent || {}).original], ["Message", D.message]].filter(([, v]) => v !== undefined && v !== null && v !== "");
    const dl = document.createElement("div"); dl.className = "audit-facts";
    facts.forEach(([k, v]) => { const a = document.createElement("div"); a.className = "muted small"; a.textContent = k; const b = document.createElement("div"); b.textContent = v; dl.append(a, b); });
    box.append(dl);
    if (L.system_prompt) box.append(section("System prompt (instructions the app gave the model)", pre(L.system_prompt)));
    if (g.prompt) box.append(section(ev.action === "llm.research-input" ? "Data handed to the research job's LLM" : "Prompt (sent by the app)", pre(g.prompt)));
    if (g.completion) box.append(section(ev.action?.startsWith("llm.research") ? "Returned by the LLM" : "Answer (from the model)", pre(g.completion)));
    if ((D.netmon || {}).params) box.append(section("Request parameters (secrets redacted)", pre(JSON.stringify(D.netmon.params, null, 2))));
    const raw = document.createElement("details"); const s = document.createElement("summary"); s.textContent = "Raw Elasticsearch document";
    raw.append(s, pre(JSON.stringify(D, null, 2))); box.append(raw);
    box.closest(".card")?.scrollIntoView({ block: "start", behavior: "smooth" });
  }

  function storageCard(St, I) {
    const ok = St.connected, sp = St.spool_bytes || 0;
    const html = `<div class="small">Index <b class="mono">${esc(St.index)}</b> on the Security Onion Elasticsearch · ${ok ? `<span class="badge sev-low">connected</span> ${fn(St.docs)} entries stored` : `<span class="badge sev-high">not reachable</span> <span class="muted">${esc(St.error || St.last_error || "")}</span>`}
      ${sp ? `<div style="margin-top:6px"><span class="badge sev-medium">${fb(sp)} waiting</span> Entries are kept on the dashboard (<span class="mono">state/audit_spool.jsonl</span>) and sent as soon as Elasticsearch accepts them.</div>` : ""}
      ${St.rejected ? `<div style="margin-top:6px"><span class="badge sev-high">${fn(St.rejected)} rejected</span> <span class="muted">${esc(St.last_reject || "")}</span></div>` : ""}
      <div class="muted" style="margin-top:6px">API key: ${St.key_set ? `set <span class="mono">${esc(I?.key_hint || "")}</span>` : "<b>not set</b>"} — it only needs <span class="mono">create_doc</span> and <span class="mono">read</span> on this index, so the dashboard can add and read audit entries but never change or delete them.</div></div>
      <details style="margin-top:8px"><summary>Change the audit key or index</summary>
      <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-top:8px">
        <input id="au-key" type="password" autocomplete="off" placeholder="${St.key_set ? "keep the current key" : "Elasticsearch API key (encoded)"}" style="min-width:22em">
        <input id="au-ix" type="text" placeholder="${esc(I?.index_default || "logs-netmon")}" value="${esc(I?.index || "")}" style="width:12em">
        <button id="au-test">Test</button> <button id="au-save">Save</button> <span id="au-msg" class="small"></span></div>
      <div class="muted small" style="margin-top:6px">Create the key in Kibana (Stack Management › API keys, or Dev Tools) with role descriptor
      <span class="mono">{"netmon_audit": {"indices": [{"names": ["logs-netmon"], "privileges": ["create_doc", "read", "view_index_metadata"]}]}}</span>.</div></details>`;
    const c = card("Audit log storage", html);
    const body = () => ({ api_key: c.querySelector("#au-key").value.trim(), index: c.querySelector("#au-ix").value.trim() });
    const msg = (t, bad) => { const m = c.querySelector("#au-msg"); m.textContent = t; m.style.color = bad ? "var(--bad)" : ""; };
    c.querySelector("#au-test").onclick = async () => { msg("Testing…"); try { const R = await apiPost("/api/config/integrations/audit/test", body()); msg(R.ok ? `OK — ${fn(R.docs)} entries in ${R.index}` : R.error, !R.ok); } catch (e) { msg(String(e.message || e), true); } };
    c.querySelector("#au-save").onclick = async () => { msg("Saving…"); try { await apiPost("/api/config/integrations/audit", body()); msg("Saved."); setTimeout(() => route(true), 600); } catch (e) { msg(String(e.message || e), true); } };
    return c;
  }

  V.audit = async (el) => {
    el.innerHTML = `<h1>Audit log</h1><div class="sub">Who did what in the dashboard, and every conversation between the dashboard and an AI model. <b>User actions</b>: sign-ins (including failed ones), sign-outs, page views, check-offs, notes, chat messages, AI verdicts, settings and user changes, report downloads and every refused request. <b>AI conversations</b>: Ask Hermes chats, the background correlation reviewer, model comparisons and the research job's input and results, each with its prompt, the model's answer, model, tokens and time. Passwords and keys are never logged. Stored in Elasticsearch <span class="mono">logs-netmon</span> (also searchable in Kibana). Only admins can see this page.</div><div class="loading">Loading…</div>`;
    if (!isAdmin()) { el.querySelector(".loading").replaceWith(card("Admins only", `<div class="empty">Only an admin can read the audit log.</div>`)); return; }
    const P = hq(), F = { kind: P.get("kind") || "all", range: P.get("start") || P.get("end") ? "" : P.get("range") || "24h", start: P.get("start") || "", end: P.get("end") || "", user: P.get("user") || "", action: P.get("action") || "",
      outcome: P.get("outcome") || "", model: P.get("model") || "", q: P.get("q") || "", page: +(P.get("page") || 0) };
    const qs = new URLSearchParams(Object.entries(F).filter(([, v]) => v !== "" && v !== 0)).toString();
    const getJSON = async (u) => {  // tolerate non-JSON answers (proxy error pages) instead of a parse error
      const r = await fetch(u, { cache: "no-store" }); if (r.status === 401) { toLogin(); throw new Error("login required"); }
      const t = await r.text(); try { return JSON.parse(t); } catch { return { error: `the server answered HTTP ${r.status} without data${r.status >= 500 ? " (dashboard or proxy error)" : ""}` }; } };
    const [R, I] = await Promise.all([getJSON("/api/audit?" + qs).catch((e) => ({ error: String(e.message || e) })),
      api("/api/config/integrations").then((x) => x.audit).catch(() => null)]);
    el.querySelector(".loading").remove();
    if (R.status) el.appendChild(storageCard(R.status, I));
    if (R.error) { el.appendChild(card("Audit log unavailable", `<div class="empty">${esc(R.error)}</div>`)); return; }

    const setF = (ch) => { const n = { ...F, page: 0, ...ch }; const s = new URLSearchParams(Object.entries(n).filter(([, v]) => v !== "" && v !== 0)).toString(); location.hash = "#/audit" + (s ? "?" + s : ""); };
    const withCur = (list, cur) => (cur && !list.some((b) => b.key === cur) ? [{ key: cur, n: 0 }, ...list] : list);
    const fc = card("Filters", `<form id="au-f" style="display:flex;gap:8px;flex-wrap:wrap;align-items:center">
      <select name="kind">${opt("all", "Everything", F.kind)}${opt("action", "User actions", F.kind)}${opt("llm", "AI conversations", F.kind)}</select>
      <select name="range" title="Quick range (or set a start and end)">${opt("", "Custom range", F.range)}${RANGES.map(([v, l]) => opt(v, l, F.range)).join("")}</select>
      <label class="small muted">From <input type="datetime-local" name="startL" step="60" value="${esc(locIn(F.start))}"></label>
      <label class="small muted">To <input type="datetime-local" name="endL" step="60" value="${esc(locIn(F.end))}"></label>
      <select name="user">${opt("", "All users", F.user)}${withCur(R.users, F.user).map((b) => opt(b.key, `${b.key} (${b.n})`, F.user)).join("")}</select>
      <select name="action">${opt("", "All actions", F.action)}${withCur(R.actions, F.action).map((b) => opt(b.key, `${PURPOSE[b.key] || b.key} (${b.n})`, F.action)).join("")}</select>
      <select name="outcome">${opt("", "Any outcome", F.outcome)}${opt("success", "Success", F.outcome)}${opt("failure", "Failure / denied", F.outcome)}</select>
      <select name="model">${opt("", "All models", F.model)}${withCur(R.models, F.model).filter((b) => b.key).map((b) => opt(b.key, `${b.key} (${b.n})`, F.model)).join("")}</select>
      <input name="q" type="search" placeholder="Search text, prompts, answers…" value="${esc(F.q)}" style="min-width:16em">
      <button type="submit">Apply</button> <a href="#/audit" class="small">reset</a></form>`);
    fc.querySelector("form").onsubmit = (e) => { e.preventDefault(); const d = Object.fromEntries(new FormData(e.target));
      const s = d.startL ? new Date(d.startL) : null, en = d.endL ? new Date(d.endL) : null; delete d.startL; delete d.endL;
      if (d.range) { d.start = ""; d.end = ""; } else { d.start = s && !isNaN(s) ? s.toISOString() : ""; d.end = en && !isNaN(en) ? en.toISOString() : ""; if (!d.start && !d.end) d.range = "24h"; }
      setF(d); };
    fc.querySelectorAll("select").forEach((s) => (s.onchange = () => fc.querySelector("form").requestSubmit()));
    // typing a date switches the quick range to "Custom range"
    fc.querySelectorAll('input[type="datetime-local"]').forEach((i) => (i.onchange = () => { fc.querySelector('select[name="range"]').value = ""; }));
    el.appendChild(fc);

    const k = Object.fromEntries(R.kinds.map((b) => [b.key, b.n])), fail = (R.outcomes.find((b) => b.key === "failure") || {}).n || 0;
    el.insertAdjacentHTML("beforeend", kpis([["Entries", fn(R.total)], ["User actions", fn(k["netmon.audit"] || 0)], ["AI conversations", fn(k["netmon.llm"] || 0)],
      ["Failed / denied", fn(fail), fail ? "bad" : ""], ["Users", fn(R.users.length)], ["AI tokens in / out", `${fn(R.tokens.in)} / ${fn(R.tokens.out)}`]]));

    if (R.histogram.length > 1) {
      const lab = R.histogram.map((b) => new Date(b.ms).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }));
      el.appendChild(chartCard(`Activity over time <span class="muted small">— per ${esc(R.interval || "bucket")}</span>`, { type: "bar",
        data: { labels: lab, datasets: [{ label: "User actions", data: R.histogram.map((b) => b["netmon.audit"] || 0), backgroundColor: PALETTE[0] },
          { label: "AI conversations", data: R.histogram.map((b) => b["netmon.llm"] || 0), backgroundColor: PALETTE[2] }] },
        options: { responsive: true, maintainAspectRatio: false, scales: { x: { stacked: true }, y: { stacked: true, beginAtZero: true } } } }, "", "short"));
    }

    const detail = card("Entry details", `<div class="muted small">Click an entry to see everything recorded for it, including the full prompt and answer of AI conversations.</div>`);
    detail.id = "audit-detail";
    const pages = Math.ceil(Math.min(R.total, 10000) / R.size);
    const pager = `<div style="display:flex;gap:8px;align-items:center;margin-top:8px"><button data-pg="${F.page - 1}" ${F.page ? "" : "disabled"}>‹ Newer</button>
      <span class="small muted">page ${F.page + 1} of ${Math.max(1, pages)} · ${fn(R.total)} entries</span><button data-pg="${F.page + 1}" ${F.page + 1 < pages ? "" : "disabled"}>Older ›</button></div>`;
    const tc = card(`Entries (${fn(R.total)})`, pager);
    tc.insertBefore(R.rows.length ? table(null, [
      { k: "ts", t: "Time", fmt: when, sort: (x) => x.ts },
      { k: "kind", t: "Type", fmt: kindBadge },
      { k: "user", t: "User", fmt: (v, r) => `<b>${esc(v)}</b>${r.role ? ` <span class="muted small">${esc(r.role)}</span>` : ""}` },
      { k: "action", t: "Action", cls: "mono small", fmt: (v) => esc(PURPOSE[v] || v) },
      { k: "outcome", t: "Outcome", fmt: (v, r) => outBadge(v) + (r.status ? ` <span class="muted small">${esc(r.status)}</span>` : "") },
      { k: "message", t: "Details", fmt: (v, r) => `${esc(v)}${r.model ? `<div class="muted small">${esc(r.provider || "")} · ${esc(r.model)}${r.tokens ? ` · ${fn(r.tokens.input_tokens)}→${fn(r.tokens.output_tokens)} tokens` : ""}${r.seconds ? ` · ${r.seconds}s` : ""}</div>` : ""}${r.ip ? `<div class="muted small mono">${esc(r.ip)}</div>` : ""}` },
    ], R.rows, { sort: "ts", search: false, titleKey: "message", onclick: (r) => showDoc(detail.querySelector(".audit-box") || (() => { const b = document.createElement("div"); b.className = "audit-box"; detail.replaceChildren(detail.querySelector("h2"), b); return b; })(), r.id) })
      : (() => { const d = document.createElement("div"); d.className = "empty"; d.textContent = "No audit entries match these filters."; return d; })(), tc.lastElementChild);
    tc.addEventListener("click", (e) => { const b = e.target.closest("[data-pg]"); if (b && !b.disabled) setF({ ...F, page: +b.dataset.pg }); });
    el.appendChild(tc);
    el.appendChild(detail);
  };
})();
