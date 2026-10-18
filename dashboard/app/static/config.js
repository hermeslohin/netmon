// More -> Configuration (#/config): Security Triage (auto-close "expected"/"benign" events) and Integrations (Elasticsearch, UniFi API).
(() => {
  const EXPLAIN = {
    expected: `<b>Expected</b> — the activity is <i>supposed</i> to happen: a known device doing its known job, or something you did on purpose. Examples: a thermostat checking in with its vendor cloud, OneDrive keeping its push channel open, your own admin SSH logins, the dashboard sending web-push notifications. The detection is accurate (the traffic really is new or unusual against the baseline), it is just explained by normal, intended operation.`,
    benign: `<b>Benign</b> — the activity <i>looked</i> suspicious and the research found it harmless, but it is not part of a device's planned behavior: an IDS rule misfiring (a false positive), a one-off anomaly, or a device reaching a new but legitimate service. Examples: Suricata flagging replies on a Mac's own outbound sessions as a "listening port", an Echo contacting a new Apple Music domain. Harmless, but less predictable than "expected", so closing it automatically is a slightly bigger leap of trust.`,
  };
  const row = (k, D) => {
    const r = D[k] || {}, on = !!D.settings?.[k];
    return `<div class="cfg-opt" style="border-top:1px solid var(--line,#333);padding:12px 0">
      <label style="display:flex;gap:10px;align-items:flex-start;cursor:${D.admin ? "pointer" : "default"}">
        <input type="checkbox" class="cfg-ac" data-k="${k}" ${on ? "checked" : ""} ${D.admin ? "" : "disabled"} style="margin-top:3px">
        <span><b>Automatically move events deemed “${k}” to closed findings</b> ${on ? '<span class="badge sev-good">On</span>' : '<span class="badge sev-unknown">Off</span>'}
          <div class="muted small" style="margin-top:4px">${EXPLAIN[k]}</div></span></label>
      <div class="small" style="margin:8px 0 0 28px">In the newest snapshot: <b>${r.closable || 0}</b> closable “${k}” items ·
        <b>${r.auto_closed || 0}</b> auto-closed · <b>${r.would_close || 0}</b> ${on ? "waiting for the next pass" : "would be closed if turned on"}
        ${r.reopened_by_user ? ` · ${r.reopened_by_user} reopened by a person (left open)` : ""}
        ${r.no_checklist ? ` · <span class="muted">${r.no_checklist} more without a check-off list (IDS / alerts / gateway / threat intel — not closable)</span>` : ""}
        ${D.admin && r.auto_closed ? ` <button class="cfg-reopen" data-k="${k}" style="margin-left:6px">Reopen ${r.auto_closed} auto-closed</button>` : ""}</div></div>`;
  };
  async function paint(el, D) {
    el.querySelector("#cfg-triage")?.remove();
    const s = D.settings || {};
    const c = card("Security Triage", `<div class="sub" style="margin:0 0 6px">Every 4 hours the Hermes research job writes a note with a verdict for each event
      (malicious, suspicious, needs-review, benign or expected; the “✨” button next to an event). These options check off the events whose verdict is
      “expected” or “benign”, moving them to <a href="#/checked">Checked (closed findings)</a> with the note <span class="mono">auto-closed: AI verdict …</span>.
      Applies to baseline findings, endpoint findings and fix-list issues; runs every 5 minutes and right after you save.
      Items you have already checked off are untouched; if you uncheck an auto-closed item it stays open; if the AI later changes the verdict to something
      else (e.g. suspicious) the item reopens by itself. Turning an option off stops new closures — use “Reopen” to restore what was closed.</div>
      ${row("expected", D)}${row("benign", D)}
      <div class="muted small" style="border-top:1px solid var(--line,#333);padding-top:8px">${D.admin ? "" : "Only an admin can change these settings. "}
        ${s.updated_by ? `Last changed by ${esc(s.updated_by)} ${esc(ft(s.updated_at))}.` : "Never changed (both off)."}
        ${D.reopened_verdict_changed ? ` ${D.reopened_verdict_changed} item(s) reopened because the verdict changed.` : ""}
        ${D.last_run ? ` Last pass ${esc(ft(D.last_run))}.` : ""}</div>`);
    c.id = "cfg-triage"; el.appendChild(c);
    const save = async (body, url = "/api/config/triage") => {
      c.style.opacity = 0.6;
      try { const R = await apiPost(url, body); S.acks = await api("/api/acks").catch(() => S.acks); paint(el, R); }
      catch (e) { c.style.opacity = 1; alert(String(e)); }
    };
    c.querySelectorAll(".cfg-ac").forEach((cb) => (cb.onchange = () => {
      const v = { expected: !!s.expected, benign: !!s.benign, [cb.dataset.k]: cb.checked };
      const n = D[cb.dataset.k]?.would_close || 0;
      if (cb.checked && n && !confirm(`This closes ${n} “${cb.dataset.k}” item(s) now and keeps doing so for new ones. Continue?`)) { cb.checked = false; return; }
      save(v);
    }));
    c.querySelectorAll(".cfg-reopen").forEach((b) => (b.onclick = () => {
      if (confirm(`Reopen every auto-closed “${b.dataset.k}” item? They will not be auto-closed again (the option stays ${s[b.dataset.k] ? "on for new items" : "off"}).`)) save({ kind: b.dataset.k }, "/api/config/triage/reopen");
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
        else res.innerHTML = R.ok ? `Reached <span class="mono">${esc(R.url)}</span>: ${R.consoles} console(s), ${R.hosts} host(s) on this account.` : esc(R.error || "");
      } catch (e) { msg.innerHTML = `<span class="sev-high">${esc(String(e))}</span>`; }
    };
  }
  function paintInt(wrap, D, flash) {
    wrap.innerHTML = `<h2 style="margin:18px 0 4px">Integrations</h2><div class="sub">Where netmon reads its data. Blank fields use the defaults shown, so
      saving an empty form changes nothing. The host collectors (snapshots every 4h, the watcher every 15 min) use these on their next run.</div>`;
    if (!D.admin) { wrap.insertAdjacentHTML("beforeend", `<div class="card"><div class="empty">Only an admin can view or change integrations.</div></div>`); return; }
    const E = D.elasticsearch, U = D.unifi;
    const ixRows = Object.keys(E.index_defaults).map((k) => fld("es-ix-" + k, E.index_labels[k], E.indices[k], E.index_defaults[k], `Default <span class="mono">${esc(E.index_defaults[k])}</span>. Comma-separated patterns and <span class="mono">*</span> are allowed.`)).join("");
    const ce = intCard("elasticsearch", "Elasticsearch (Security Onion)", "Read-only API key with <span class=\"mono\">read</span> + <span class=\"mono\">view_index_metadata</span> on the indices below. TLS certificates are not verified (Security Onion uses its own CA).",
      fld("elasticsearch-url", "URL", E.url, E.url_fallback || "https://so-manager:9200", `Default (site.json): <span class="mono">${esc(E.url_fallback || "not set")}</span>`)
      + fld("elasticsearch-key", "API key", "", E.key_set ? E.key_hint : "base64 id:key from Kibana › Stack Management › API keys", keyHelp(E), "password")
      + `<div class="small" style="margin-top:12px"><b>Indices to search</b></div>` + ixRows, E);
    const cu = intCard("unifi", "UniFi API", "Site Manager API key from <span class=\"mono\">unifi.ui.com › API</span>. netmon reads clients, devices and events through the console connector (read-only).",
      fld("unifi-url", "URL", U.url, U.url_fallback, `Default <span class="mono">${esc(U.url_fallback)}</span> (Ubiquiti cloud). Use your console's address only if you run a local API proxy that speaks the same paths.`)
      + fld("unifi-key", "API key", "", U.key_set ? U.key_hint : "UniFi Site Manager API key", keyHelp(U), "password"), U);
    wrap.append(ce, cu);
    const rerender = (R, sec, m) => { paintInt(wrap, R, { sec, m }); };
    wire(ce, "elasticsearch", E, rerender); wire(cu, "unifi", U, rerender);
    if (flash) { const m = wrap.querySelector(`[data-sec="${flash.sec}"] .cfg-msg`); if (m) m.innerHTML = `<span class="badge sev-good">${esc(flash.m)}</span>`; }
  }

  V.config = async (el) => {
    el.innerHTML = `<h1>Configuration</h1><div class="sub">Dashboard-wide settings (they apply to every user).</div><div class="loading">Loading…</div>`;
    const [D, I] = await Promise.all([api("/api/config/triage").catch((e) => ({ _err: e })), api("/api/config/integrations").catch((e) => ({ _err: e }))]);
    el.querySelector(".loading").remove();
    const tri = document.createElement("div"), ints = document.createElement("div"); tri.id = "cfg-tri-wrap"; ints.id = "cfg-int-wrap";
    el.append(tri, ints);
    tri.innerHTML = `<h2 style="margin:12px 0 4px">Security Triage</h2>`;
    if (D._err) tri.insertAdjacentHTML("beforeend", `<div class="empty">${esc(String(D._err))}</div>`); else paint(tri, D);
    if (I._err) ints.innerHTML = `<div class="empty">${esc(String(I._err))}</div>`; else paintInt(ints, I);
  };
})();
