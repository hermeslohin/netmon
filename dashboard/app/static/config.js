// More -> Configuration (#/config): Auto-close ("expected"/"benign" events) and Integrations (Elasticsearch, UniFi API).
(() => {
  const SRC = {
    reviewer: `the <b>correlation reviewer LLM</b> (it reviews related events and classifies each finished event as suspicious, benign or expected on the AI review page; runs often, on lighter evidence)`,
    researcher: `the <b>research model</b> (a person clicked <b>Send to research</b>; it searched the logs and wrote a note with a verdict, the “✨” button; a deeper look, so the more conservative source)`,
  };
  const KIND = {
    expected: `<b>Expected</b> — the activity is <i>supposed</i> to happen: a known device doing its known job, or something you did on purpose (a thermostat checking in with its vendor cloud, your own admin SSH logins). The detection is accurate; normal operation explains it.`,
    benign: `<b>Benign</b> — the activity <i>looked</i> suspicious but is harmless and not planned device behavior: an IDS false positive, a one-off anomaly, a device reaching a new but legitimate service. Less predictable than “expected”, so closing it is a bigger leap of trust.`,
  };
  const LBL = { reviewer: "the reviewer LLM", researcher: "the researcher" };
  const lbl = (o) => { const [s, k] = o.split("_"); return `${LBL[s]} says ${k}`; };
  const OPTS = ["reviewer_expected", "reviewer_benign", "researcher_expected", "researcher_benign"];
  const row = (k, D) => {
    const [src, kind] = k.split("_");
    const r = D[k] || {}, on = !!D.settings?.[k];
    return `<div class="cfg-opt" style="border-top:1px solid var(--line,#333);padding:12px 0">
      <label style="display:flex;gap:10px;align-items:flex-start;cursor:${D.admin ? "pointer" : "default"}">
        <input type="checkbox" class="cfg-ac" data-k="${k}" ${on ? "checked" : ""} ${D.admin ? "" : "disabled"} style="margin-top:3px">
        <span><b>Automatically move events to closed findings when ${LBL[src]} finds them ${kind}</b> ${on ? '<span class="badge sev-good">On</span>' : '<span class="badge sev-unknown">Off</span>'}
          <div class="muted small" style="margin-top:4px">${KIND[kind]}<br>Source: ${SRC[src]}.</div></span></label>
      <div class="small" style="margin:8px 0 0 28px">In the newest snapshot: <b>${r.closable || 0}</b> closable ${kind} items ·
        <b>${r.auto_closed || 0}</b> auto-closed · <b>${r.would_close || 0}</b> ${on ? "will close after the next review run (or Run now)" : "would be closed if turned on"}
        ${r.reopened_by_user ? ` · ${r.reopened_by_user} reopened by a person (left open)` : ""}
        ${r.no_checklist ? ` · <span class="muted">${r.no_checklist} more without a check-off list (IDS / alerts / gateway / threat intel — not closable)</span>` : ""}
        ${D.admin && r.auto_closed ? ` <button class="cfg-reopen" data-k="${k}" style="margin-left:6px">Reopen ${r.auto_closed} auto-closed</button>` : ""}</div></div>`;
  };
  async function paint(el, D) {
    el.querySelector("#cfg-triage")?.remove();
    const s = D.settings || {};
    const R = D.review || {}, iv = R.interval_minutes, L = D.last_run || null;
    const ivTxt = (m) => m ? `${Math.floor(m / 60) ? Math.floor(m / 60) + " h" : ""}${m % 60 ? " " + (m % 60) + " min" : ""}`.trim() : "";
    const sched = R.error ? `<div class="muted small">Review job schedule unavailable: ${esc(R.error)}</div>`
      : `<div class="cfg-sched" style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin:8px 0 4px">
          <b class="small">Review job runs every</b>
          <input id="rv-h" type="number" min="0" max="24" step="1" value="${iv ? Math.floor(iv / 60) : ""}" style="width:4.5em" ${D.admin ? "" : "disabled"}> <span class="small">hours</span>
          <input id="rv-m" type="number" min="0" max="59" step="5" value="${iv ? iv % 60 : ""}" style="width:4.5em" ${D.admin ? "" : "disabled"}> <span class="small">minutes</span>
          ${D.admin ? `<button id="rv-save" disabled>Save schedule</button>` : ""}
          <span class="muted small">next run ${esc(R.next_run_at ? ft(R.next_run_at) : "?")}${R.last_run_at ? ` · last ${esc(ft(R.last_run_at))} (${esc(R.last_status || "?")})` : ""}</span>
          <span id="rv-msg" class="small"></span></div>
        <div class="muted small">5 to 1440 minutes. Runs sit on a fixed UTC grid anchored at 05:00 UTC; the first run at or after 05:00 UTC each day covers 24 h.
          Each run collects and analyzes the logs, then the reviewer (the correlation reviewer's model, AI review > Models) copies matching earlier notes; everything else waits in the queue. Events are researched only when a person clicks <b>Send to research</b>.</div>`;
    const c = card("Auto-close", `<div class="sub" style="margin:0 0 6px">Two AI sources judge an event: the <b>reviewer LLM</b> (classifies finished correlation reviews as suspicious, benign or expected) and the <b>researcher</b>
      (event research, run when someone clicks <b>Send to research</b>${iv ? `; never on the review schedule (every ${ivTxt(iv)})` : ""}, writes a note with a verdict: malicious, suspicious, needs-review, benign or expected; the “✨” button next to an event).
      Turn on either or both: the options check off events that the chosen source found “expected” or “benign” (an event either source calls suspicious or malicious is never closed), moving them to <a href="#/checked">Checked (closed findings)</a> with the note <span class="mono">auto-closed: AI verdict …</span> naming the source.
      Applies to baseline findings, endpoint findings and fix-list issues. <b>It runs once right after a research note is stored</b> (a Send to research click), and when you press “Run now”. Reviewer verdicts are picked up on those runs too.
      Items you have already checked off are untouched; if you uncheck an auto-closed item it stays open; if a later review changes the verdict to something
      else (e.g. suspicious) the item reopens on that run. Turning an option off stops new closures — use “Reopen” to restore what was closed.</div>
      ${sched}
      ${OPTS.map((o) => row(o, D)).join("")}
      <div class="muted small" style="border-top:1px solid var(--line,#333);padding-top:8px">${D.admin ? "" : "Only an admin can change these settings. "}
        ${s.updated_by ? `Last changed by ${esc(s.updated_by)} ${esc(ft(s.updated_at))}.` : "Never changed (both off)."}
        ${L ? ` Last auto-close pass ${esc(ft(L.at))} (${esc(L.trigger || "")}): closed ${Object.entries(L.closed || {}).map(([k, v]) => `${v} ${esc(k.replace("_", " "))}`).join(", ") || "nothing"}${L.reopened ? `, reopened ${L.reopened} (verdict changed)` : ""}.` : " No auto-close pass yet."}
        ${D.admin && OPTS.some((o) => s[o]) ? ` <button id="cfg-run">Run now</button>` : ""}</div>`);
    c.id = "cfg-triage"; el.appendChild(c);
    const save = async (body, url = "/api/config/triage") => {
      c.style.opacity = 0.6;
      try { const R = await apiPost(url, body); S.acks = await api("/api/acks").catch(() => S.acks); paint(el, R); }
      catch (e) { c.style.opacity = 1; alert(String(e)); }
    };
    c.querySelectorAll(".cfg-ac").forEach((cb) => (cb.onchange = () => {
      const v = { ...Object.fromEntries(OPTS.map((o) => [o, !!s[o]])), [cb.dataset.k]: cb.checked };
      const n = D[cb.dataset.k]?.would_close || 0;
      if (cb.checked && n && !confirm(`${n} item(s) where ${lbl(cb.dataset.k)} will be closed after the next review run (or press Run now), and new ones after every run. Continue?`)) { cb.checked = false; return; }
      save(v);
    }));
    const rh = c.querySelector("#rv-h"), rm = c.querySelector("#rv-m"), rs = c.querySelector("#rv-save"), rmsg = c.querySelector("#rv-msg");
    const tot = () => (parseInt(rh.value, 10) || 0) * 60 + (parseInt(rm.value, 10) || 0);
    if (rs) {
      const chk = () => { const t = tot(); rs.disabled = t === iv || t < 30 || t > 1440;
        rmsg.className = "small sev-high"; rmsg.textContent = t && (t < 5 || t > 1440) ? "between 5 and 1440 minutes" : ""; };
      rh.oninput = rm.oninput = chk;
      rs.onclick = async () => {
        const t = tot();
        if (!confirm(`Run the review job every ${ivTxt(t)}${t < iv ? " (more often = more reviewer calls)" : ""}?`)) return;
        rmsg.className = "small"; rmsg.textContent = "Saving…";
        try { const N = await apiPost("/api/config/review-schedule", { hours: Math.floor(t / 60), minutes: t % 60 }); paint(el, N); }
        catch (e) { rmsg.className = "small sev-high"; rmsg.textContent = String(e); }
      };
    }
    const run = c.querySelector("#cfg-run");
    if (run) run.onclick = () => save({}, "/api/config/triage/run");
    c.querySelectorAll(".cfg-reopen").forEach((b) => (b.onclick = () => {
      if (confirm(`Reopen every item auto-closed because ${lbl(b.dataset.k)}? They will not be auto-closed again (the option stays ${s[b.dataset.k] ? "on for new items" : "off"}).`)) save({ kind: b.dataset.k }, "/api/config/triage/reopen");
    }));
  }
  /* ---------- Integrations: Elasticsearch (Security Onion) + UniFi API ---------- */
  const fld = (id, label, val, ph, help, type = "text") => `<label class="cfg-f" style="display:block;margin:8px 0">
      <span class="small"><b>${esc(label)}</b></span><br>
      <input id="${id}" type="${type}" value="${esc(val || "")}" placeholder="${esc(ph || "")}" autocomplete="off" spellcheck="false"
        style="width:min(560px,100%);box-sizing:border-box;padding:6px 8px;font-family:var(--mono,monospace)">
      ${help ? `<div class="muted small">${help}</div>` : ""}</label>`;
  const keyHelp = (I) => I.key_set ? `Saved key ${esc(I.key_hint)}. Leave blank to keep it; type a new one to replace it.
      <label style="margin-left:8px"><input type="checkbox" class="cfg-clr"> remove the saved key (fall back to ${esc(I.key_fallback)})</label>`
    : `Not set here, so the pipeline uses <span class="mono">${esc(I.key_fallback)}</span>${I.key_fallback_present === false ? " (missing)" : ""}. Keys are write-only: they are stored on the server (0600) and never shown again.`;
  const who = (I) => I.updated_by ? `Last saved by ${esc(I.updated_by)} ${esc(ft(I.updated_at))}.` : "Never saved here (all defaults).";
  function intCard(sec, title, intro, inner, I) {
    const c = card(title, `<div class="sub" style="margin:0 0 4px">${intro}</div>${inner}
      <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-top:10px">
        <button class="cfg-save">Save</button><button class="cfg-test">Test connection</button>
        <span class="cfg-msg small"></span></div>
      <div class="cfg-res small" style="margin-top:6px"></div>
      <div class="muted small" style="margin-top:6px">${who(I)}</div>`);
    c.dataset.sec = sec; return c;
  }
  function formBody(c, sec, I) {
    const v = (id) => c.querySelector("#" + id)?.value.trim() || "";
    const b = { url: v(sec + "-url"), api_key: v(sec + "-key"), clear_key: !!c.querySelector(".cfg-clr")?.checked };
    if (sec === "elasticsearch") b.indices = Object.fromEntries(Object.keys(I.index_defaults).map((k) => [k, v("es-ix-" + k)]));
    if (sec === "web") b.provider = c.querySelector("#web-provider")?.value || "duckduckgo";
    return b;
  }
  function wire(c, sec, I, rerender) {
    const msg = c.querySelector(".cfg-msg"), res = c.querySelector(".cfg-res");
    c.querySelector(".cfg-save").onclick = async () => {
      msg.textContent = "Saving…";
      try { const R = await apiPost(`/api/config/integrations/${sec}`, formBody(c, sec, I)); rerender(R, sec, "Saved. Collectors pick it up on their next run."); }
      catch (e) { msg.innerHTML = `<span class="sev-high">${esc(String(e))}</span>`; }
    };
    c.querySelector(".cfg-test").onclick = async () => {
      msg.textContent = "Testing…"; res.innerHTML = "";
      try {
        const R = await apiPost(`/api/config/integrations/${sec}/test`, formBody(c, sec, I));
        msg.innerHTML = R.ok ? '<span class="badge sev-good">Connected</span>' : '<span class="badge sev-high">Failed</span>';
        if (sec === "elasticsearch" && R.indices) res.innerHTML = Object.entries(R.indices).map(([k, x]) =>
          `<div>${x.ok ? "✅" : "❌"} <span class="mono">${esc(x.index)}</span> — ${x.ok ? `${Number(x.docs_24h).toLocaleString()} docs in the last 24h` : esc(x.error)}</div>`).join("");
        else if (sec === "web") res.innerHTML = R.ok ? `Search works: ${R.results} result(s) for a test query.` : esc(R.error || "");
        else res.innerHTML = R.ok ? `Reached <span class="mono">${esc(R.url)}</span>: ${R.consoles} console(s), ${R.hosts} host(s) on this account.` : esc(R.error || "");
      } catch (e) { msg.innerHTML = `<span class="sev-high">${esc(String(e))}</span>`; }
    };
  }
  function paintInt(wrap, D, flash) {
    wrap.innerHTML = `<h2 style="margin:18px 0 4px">Integrations</h2><div class="sub">Where netmon reads its data. Blank fields use the defaults shown, so
      saving an empty form changes nothing. The host jobs (review runs, event research, the watcher every 15 min) use these on their next run.</div>`;
    if (!D.admin) { wrap.insertAdjacentHTML("beforeend", `<div class="card"><div class="empty">Only an admin can view or change integrations.</div></div>`); return; }
    const E = D.elasticsearch, U = D.unifi;
    const ixRows = Object.keys(E.index_defaults).map((k) => fld("es-ix-" + k, E.index_labels[k], E.indices[k], E.index_defaults[k], `Default <span class="mono">${esc(E.index_defaults[k])}</span>. Comma-separated patterns and <span class="mono">*</span> are allowed.`)).join("");
    const ce = intCard("elasticsearch", "Elasticsearch (Security Onion)", "Read-only API key with <span class=\"mono\">read</span> + <span class=\"mono\">view_index_metadata</span> on the indices below. TLS certificates are not verified (Security Onion uses its own CA).",
      fld("elasticsearch-url", "URL", E.url, E.url_fallback || "https://so-manager:9200", `Default (the site settings (More → Settings)): <span class="mono">${esc(E.url_fallback || "not set")}</span>`)
      + fld("elasticsearch-key", "API key", "", E.key_set ? E.key_hint : "base64 id:key from Kibana › Stack Management › API keys", keyHelp(E), "password")
      + `<div class="small" style="margin-top:12px"><b>Indices to search</b></div>` + ixRows, E);
    const cu = intCard("unifi", "UniFi API", "Site Manager API key from <span class=\"mono\">unifi.ui.com › API</span>. netmon reads clients, devices and events through the console connector (read-only).",
      fld("unifi-url", "URL", U.url, U.url_fallback, `Default <span class="mono">${esc(U.url_fallback)}</span> (Ubiquiti cloud). Use your console's address only if you run a local API proxy that speaks the same paths.`)
      + fld("unifi-key", "API key", "", U.key_set ? U.key_hint : "UniFi Site Manager API key", keyHelp(U), "password"), U);
    const Wb = D.web || { provider: "duckduckgo", providers: { duckduckgo: "DuckDuckGo (no key)" } };
    const cw = intCard("web", "Web search (AI research and chat)", "Used by event research (Send to research) and the Ask AI chat to look things up and read web pages. DuckDuckGo needs no key; Firecrawl, Brave Search and Tavily need an API key from their sites (Firecrawl is also used to read pages).",
      `<label class="cfg-f" style="display:block;margin:8px 0"><span class="small"><b>Provider</b></span><br><select id="web-provider">${Object.entries(Wb.providers).map(([k, l]) =>
        `<option value="${esc(k)}"${k === Wb.provider ? " selected" : ""}>${esc(l)}</option>`).join("")}</select></label>`
      + fld("web-key", "API key", "", Wb.key_set ? Wb.key_hint : "API key (not needed for DuckDuckGo)", keyHelp(Wb), "password"), Wb);
    wrap.append(ce, cu, cw);
    const rerender = (R, sec, m) => { paintInt(wrap, R, { sec, m }); };
    wire(ce, "elasticsearch", E, rerender); wire(cu, "unifi", U, rerender); wire(cw, "web", Wb, rerender);
    if (flash) { const m = wrap.querySelector(`[data-sec="${flash.sec}"] .cfg-msg`); if (m) m.innerHTML = `<span class="badge sev-good">${esc(flash.m)}</span>`; }
  }

  V.config = async (el) => {
    el.innerHTML = `<h1>Configuration</h1><div class="sub">Dashboard-wide settings (they apply to every user).</div><div class="loading">Loading…</div>`;
    const [D, I] = await Promise.all([api("/api/config/triage").catch((e) => ({ _err: e })), api("/api/config/integrations").catch((e) => ({ _err: e }))]);
    el.querySelector(".loading").remove();
    const tri = document.createElement("div"), ints = document.createElement("div"); tri.id = "cfg-tri-wrap"; ints.id = "cfg-int-wrap";
    el.append(tri, ints);
    tri.innerHTML = `<h2 style="margin:12px 0 4px">Auto-close</h2>`;
    if (D._err) tri.insertAdjacentHTML("beforeend", `<div class="empty">${esc(String(D._err))}</div>`); else paint(tri, D);
    if (I._err) ints.innerHTML = `<div class="empty">${esc(String(I._err))}</div>`; else paintInt(ints, I);
  };
})();
