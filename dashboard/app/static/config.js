// Settings -> Configuration (#/config): Auto-close ("expected"/"benign" events) and Integrations (Elasticsearch, UniFi API).
(() => {
  const SRC = {
    reviewer: `the <b>event reviewer LLM</b> (it reviews related events and classifies each finished event as suspicious, benign or expected on the AI pipeline monitoring page; runs often, on lighter evidence)`,
    researcher: `the <b>research model</b> (a person clicked <b>Send to research</b>; it searched the logs and wrote a note with a verdict, the “✨” button; a deeper look, so the more conservative source)`,
  };
  const KIND = {
    expected: `<b>Expected</b> — the activity is <i>supposed</i> to happen: a known device doing its known job, or something you did on purpose (a thermostat checking in with its vendor cloud, your own admin SSH logins). The detection is accurate; normal operation explains it.`,
    benign: `<b>Benign</b> — the activity <i>looked</i> suspicious but is harmless and not planned device behavior: an IDS false positive, a one-off anomaly, a device reaching a new but legitimate service. Less predictable than “expected”, so closing it is a bigger leap of trust.`,
  };
  const LBL = { reviewer: "the event reviewer LLM", researcher: "the researcher" };
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
  // Guard rails: how far AI verdicts may go on their own (min confidence, protected categories, host hold, expiry)
  const GL = { low_conf: "below the confidence bar", protected: "protected category", host: "host on hold", stale: "expired, waiting for a fresh verdict" };
  const guardBox = (D) => {
    const s = D.settings || {}, G = D.guard || {}, C = D.categories || {}, dis = D.admin ? "" : "disabled";
    const prot = new Set(s.protect || []), bc = G.by_cat || {};
    const hosts = Object.entries(G.hosts || {}).sort((a, b) => b[1] - a[1]);
    const kept = (G.kept_low_conf || 0) + (G.kept_protected || 0);
    const samp = (G.samples || []).map((x) => `<div class="small"><span class="badge sev-unknown">${esc(GL[x.guard] || x.guard)}</span> ${esc(x.label || x.eid)} <span class="muted">— ${esc(x.why)}</span></div>`).join("");
    return `<div id="cfg-guard" style="border-top:1px solid var(--line,#333);padding:12px 0">
      <b>Guard rails</b> <span class="muted small">— keep a person in control: these hold back AI verdicts (never your own ✅ Expected / 🟢 Benign).</span>
      <div style="margin:10px 0 0 0"><b class="small">1. Minimum event reviewer confidence</b>
        <input id="g-conf" type="number" min="0" max="1" step="0.05" value="${s.min_conf ?? 0.8}" style="width:5em" ${dis}>
        <div class="muted small">An event reviewer “expected/benign” closes an event only at or above this confidence (0–1), or when a research note agrees. Below it the event stays open with its 🟢 flair, sorted with the rest. 0 = off.
          Now: <b>${G.low_conf || 0}</b> open events held${G.kept_low_conf ? ` · ${G.kept_low_conf} closed earlier below the bar (left closed)` : ""}.</div></div>
      <div style="margin:10px 0 0 0"><b class="small">2. Never auto-close these categories (a person must close them)</b>
        <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:4px 16px;margin-top:4px">
        ${Object.entries(C).map(([k, l]) => `<label class="small" style="display:flex;gap:6px;align-items:flex-start"><input type="checkbox" class="g-cat" data-k="${k}" ${prot.has(k) ? "checked" : ""} ${dis}>
          <span>${esc(l)}${bc[k] ? ` <b>(${bc[k]} held)</b>` : ""}</span></label>`).join("")}</div>
        <div class="muted small">The AI still labels and annotates them. Now: <b>${G.protected || 0}</b> open events held${G.kept_protected ? ` · ${G.kept_protected} closed earlier (left closed)` : ""}.</div></div>
      <div style="margin:10px 0 0 0"><label class="small" style="display:flex;gap:6px;align-items:center"><input type="checkbox" id="g-hold" ${s.host_hold === false ? "" : "checked"} ${dis}><b>3. Hold a host after a suspicious event (${G.hold_hours || 24} h)</b></label>
        <div class="muted small">${s.host_hold === false ? "Off: only the event called suspicious or malicious stays open; other events on the same device close on their own verdicts. " : ""}When on: while an open event on a device (MAC, host name or host IP) was called suspicious or malicious — by either AI or a person — and was seen in the last ${G.hold_hours || 24} h, nothing else on that device is auto-closed, and AI closures of its events active in that window are reopened. Code-scan findings never put a device on hold. Checking off (or marking Expected) the suspicious event lifts the hold.
          ${s.host_hold === false ? "" : `Now: <b>${G.held_hosts || 0}</b> hosts on hold, <b>${G.host || 0}</b> open events held${G.reopen_host_due ? `, ${G.reopen_host_due} auto-closed events will reopen on the next pass` : ""}${G.reopened_host ? `, ${G.reopened_host} reopened` : ""}.`}
          ${hosts.length ? `<br>Held: ${hosts.slice(0, 12).map(([h, n]) => `<span class="mono">${esc(h)}</span> (${n})`).join(", ")}` : ""}</div></div>
      <div style="margin:10px 0 0 0"><b class="small">4. AI closures expire after</b>
        <input id="g-exp" type="number" min="0" max="365" step="1" value="${s.expire_days ?? 7}" style="width:5em" ${dis}> <span class="small">days</span>
        <div class="muted small">When an AI-closed event shows up again after this many days it reopens and closes again only on a verdict newer than the old closure (it is judged again). Your own closures never expire. 0 = never.
          Now: <b>${G.expire_due || 0}</b> due to expire on the next pass.</div></div>
      ${D.admin ? `<div style="margin-top:10px;display:flex;gap:8px;align-items:center;flex-wrap:wrap"><button id="g-save">Save guard rails</button>
        ${kept ? `<button id="g-reopen">Reopen ${kept} closed earlier that these rules would hold</button>` : ""}<span id="g-msg" class="small"></span></div>` : ""}
      ${samp ? `<details style="margin-top:8px"><summary class="small">Examples held back now</summary>${samp}</details>` : ""}</div>`;
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
          Each run collects and analyzes the logs, then the event reviewer (its model is set under AI pipeline configuration > Models) copies matching earlier notes; everything else waits in the queue. Events are researched only when a person clicks <b>Send to research</b>.</div>`;
    const c = card("Auto-close", `<div class="sub" style="margin:0 0 6px">Two AI sources judge an event: the <b>event reviewer LLM</b> (classifies finished correlation reviews as suspicious, benign or expected) and the <b>researcher</b>
      (event research, run when someone clicks <b>Send to research</b>${iv ? `; never on the review schedule (every ${ivTxt(iv)})` : ""}, writes a note with a verdict: malicious, suspicious, needs-review, benign or expected; the “✨” button next to an event).
      Turn on either or both: the options check off events that the chosen source found “expected” or “benign” (an event either source calls suspicious or malicious is never closed), moving them to <a href="#/checked">Checked (closed findings)</a> with the note <span class="mono">auto-closed: AI verdict …</span> naming the source.
      Applies to baseline findings, endpoint findings and fix-list issues. <b>It runs once right after a research note is stored</b> (a Send to research click), and when you press “Run now”. Event reviewer verdicts are picked up on those runs too.
      Items you have already checked off are untouched; if you uncheck an auto-closed item it stays open; if a later review changes the verdict to something
      else (e.g. suspicious) the item reopens on that run. Turning an option off stops new closures — use “Reopen” to restore what was closed.</div>
      ${sched}
      ${OPTS.map((o) => row(o, D)).join("")}
      ${guardBox(D)}
      <div class="muted small" style="border-top:1px solid var(--line,#333);padding-top:8px">${D.admin ? "" : "Only an admin can change these settings. "}
        ${s.updated_by ? `Last changed by ${esc(s.updated_by)} ${esc(ft(s.updated_at))}.` : "Never changed (both off)."}
        ${L ? ` Last auto-close pass ${esc(ft(L.at))} (${esc(L.trigger || "")}): closed ${Object.entries(L.closed || {}).map(([k, v]) => `${v} ${esc(k.replace("_", " "))}`).join(", ") || "nothing"}${L.reopened ? `, reopened ${L.reopened} (verdict changed)` : ""}${L.reopened_host ? `, reopened ${L.reopened_host} (host hold)` : ""}${L.expired ? `, ${L.expired} expired` : ""}${L.held && Object.keys(L.held).length ? `; held back ${Object.entries(L.held).map(([k, v]) => `${v} ${esc(GL[k] || k)}`).join(", ")}` : ""}.` : " No auto-close pass yet."}
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
        if (!confirm(`Run the review job every ${ivTxt(t)}${t < iv ? " (more often = more event reviewer calls)" : ""}?`)) return;
        rmsg.className = "small"; rmsg.textContent = "Saving…";
        try { const N = await apiPost("/api/config/review-schedule", { hours: Math.floor(t / 60), minutes: t % 60 }); paint(el, N); }
        catch (e) { rmsg.className = "small sev-high"; rmsg.textContent = String(e); }
      };
    }
    const gs = c.querySelector("#g-save");
    if (gs) gs.onclick = () => {
      const mc = parseFloat(c.querySelector("#g-conf").value), ed = parseInt(c.querySelector("#g-exp").value, 10);
      if (!(mc >= 0 && mc <= 1) || !(ed >= 0 && ed <= 365)) { c.querySelector("#g-msg").textContent = "confidence 0–1, days 0–365"; return; }
      save({ ...Object.fromEntries(OPTS.map((o) => [o, !!s[o]])), min_conf: mc, expire_days: ed, host_hold: !!c.querySelector("#g-hold")?.checked,
        protect: [...c.querySelectorAll(".g-cat:checked")].map((x) => x.dataset.k) });
    };
    const gr = c.querySelector("#g-reopen");
    if (gr) gr.onclick = () => {
      if (confirm(`Reopen the AI closures that today's confidence bar or protected categories would not allow? They come back to the open findings and close again only if a verdict passes the rules.`)) save({}, "/api/config/triage/reopen-guard");
    };
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
    if (sec === "web") Object.assign(b, { provider: c.querySelector("#web-provider")?.value || "duckduckgo",
      ca_pem: c.querySelector("#web-ca")?.value.trim() || "", clear_ca: !!c.querySelector("#web-ca-clr")?.checked });
    if (sec === "kubernetes") Object.assign(b, { cluster: c.dataset.cluster || v("kb-name").toLowerCase(), url: v("kubernetes-url"), enabled: !!c.querySelector("#kb-enabled")?.checked, cis: !!c.querySelector("#kb-cis")?.checked,
      ca_pem: c.querySelector("#kb-ca")?.value.trim() || "", clear_ca: !!c.querySelector("#kb-ca-clr")?.checked });
    if (sec === "opencti") {
      const ck = (id) => !!c.querySelector("#" + id)?.checked;
      Object.assign(b, { enabled: ck("oc-enabled"), pull: ck("oc-pull"), sightings: ck("oc-sight"), incidents: ck("oc-inc"),
        min_score: v("oc-min"), high_score: v("oc-high"), incident_min_sev: c.querySelector("#oc-sev")?.value || "high",
        incident_min_conf: v("oc-conf"), ca_pem: c.querySelector("#oc-ca")?.value.trim() || "", clear_ca: ck("oc-ca-clr") });
    }
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
        else if (sec === "kubernetes") res.innerHTML = R.ok ? `Reached Kubernetes ${esc(R.version)} at <span class="mono">${esc(R.url)}</span>: ${esc(R.nodes)} nodes. `
          + (R.read_only ? "✅ The account is read-only (refused: list secrets, create pods, exec, nodes/proxy, delete, update)." : `<span class="sev-high">❌ The token can do more than read: ${esc((R.too_much || []).join(", "))}. Use a read-only account.</span>`) : esc(R.error || "");
        else if (sec === "opencti") res.innerHTML = R.ok ? `Reached OpenCTI ${esc(R.version)} at <span class="mono">${esc(R.url)}</span> as ${esc(R.user)}: ${Number(R.indicators).toLocaleString()} indicators.` : esc(R.error || "");
        else res.innerHTML = R.ok ? `Reached <span class="mono">${esc(R.url)}</span>: ${R.consoles} console(s), ${R.hosts} host(s) on this account.` : esc(R.error || "");
      } catch (e) { msg.innerHTML = `<span class="sev-high">${esc(String(e))}</span>`; }
    };
  }
  /* ---------- Threat-intel feeds: on/off, URL, serious, covered by OpenCTI, custom feeds ---------- */
  function feedsCard(F, O, done) {
    const kinds = F.kinds || {}, octiOn = !!(O && O.enabled && O.pull);
    const kindSel = (id, cur) => `<select id="${id}">${Object.entries(kinds).map(([k, l]) => `<option value="${esc(k)}"${k === cur ? " selected" : ""}>${esc(l)}</option>`).join("")}</select>`;
    const row = (f, i) => `<tr data-i="${i}" data-name="${esc(f.name)}" data-builtin="${f.builtin ? 1 : 0}" data-kind="${esc(f.kind)}">
        <td><input type="checkbox" class="fd-on"${f.enabled ? " checked" : ""} title="Use this feed"></td>
        <td><span class="mono">${esc(f.name)}</span> ${f.builtin ? '<span class="badge">built-in</span>' : '<span class="badge">custom</span>'}
          ${f.active ? "" : `<div class="small"><span class="badge sev-low">${esc(f.inactive_why)}</span></div>`}</td>
        <td class="small">${esc(kinds[f.kind] || f.kind)}</td>
        <td><input class="fd-url mono" value="${esc(f.builtin && f.url === f.default_url ? "" : f.url)}" placeholder="${esc(f.default_url || "https://…")}" spellcheck="false" autocomplete="off" style="width:min(380px,40vw);font-size:12px"></td>
        <td style="text-align:center"><input type="checkbox" class="fd-ser"${f.serious ? " checked" : ""} title="An outbound hit is malware / C2 and raises an alert"></td>
        <td style="text-align:center"><input type="checkbox" class="fd-oc"${f.opencti ? " checked" : ""} title="OpenCTI already brings this data in: skip this feed while the OpenCTI pull is on"></td>
        <td>${f.builtin ? "" : '<label class="small"><input type="checkbox" class="fd-del"> delete</label>'} <button class="fd-test small" type="button">Test</button></td></tr>`;
    const c = card("Threat-intel feeds", `<div class="sub" style="margin:0 0 6px">Block lists netmon downloads (every 12 h) and matches against DNS look-ups, TLS server names and connections. Turn feeds on or off, point them at another URL (leave blank for the default), or add your own. A feed marked <b>covered by OpenCTI</b> is skipped while the OpenCTI pull is on${octiOn ? " (it is on now)" : " (it is off now, so they run)"}, so the same indicator is not matched twice. <b>Serious</b>: an outbound hit means malware / C2 and raises a Threat-intel alert; otherwise it is reputation context.</div>
      <div style="overflow-x:auto"><table class="tbl"><thead><tr><th>On</th><th>Feed</th><th>Holds</th><th>URL</th><th>Serious</th><th>Covered by OpenCTI</th><th></th></tr></thead>
        <tbody>${(F.items || []).map(row).join("")}</tbody></table></div>
      <div class="small" style="margin-top:12px"><b>Add a feed</b></div>
      <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-top:4px">
        <input id="fd-new-name" placeholder="name (e.g. my_blocklist)" spellcheck="false" style="width:170px" class="mono">
        ${kindSel("fd-new-kind", "hosts")}
        <input id="fd-new-url" placeholder="https://…" spellcheck="false" style="width:min(380px,50vw)" class="mono">
        <label class="small"><input type="checkbox" id="fd-new-ser"> serious</label>
        <button type="button" id="fd-new-test" class="small">Test</button></div>
      <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-top:10px"><button class="cfg-save">Save</button><span class="cfg-msg small"></span></div>
      <div class="cfg-res small" style="margin-top:6px"></div>
      <div class="muted small" style="margin-top:6px">${who(F)} Changes apply on the next watcher or review run.</div>`);
    c.dataset.sec = "feeds";
    const msg = c.querySelector(".cfg-msg"), res = c.querySelector(".cfg-res");
    const test = async (url, kind, label) => {
      res.textContent = `Testing ${label}…`;
      try { const R = await apiPost("/api/config/integrations/feeds/test", { url, kind });
        res.innerHTML = R.ok ? `✅ ${esc(label)}: ${Number(R.entries).toLocaleString()} entries (${Number(R.bytes).toLocaleString()} bytes)` : `❌ ${esc(label)}: ${esc(R.error || "failed")}`;
      } catch (e) { res.innerHTML = `❌ ${esc(String(e))}`; }
    };
    c.querySelectorAll("tbody tr").forEach((tr) => {
      const f = F.items[+tr.dataset.i];
      tr.querySelector(".fd-test").onclick = () => test(tr.querySelector(".fd-url").value.trim() || f.url, f.kind, f.name);
    });
    c.querySelector("#fd-new-test").onclick = () => test(c.querySelector("#fd-new-url").value.trim(), c.querySelector("#fd-new-kind").value, c.querySelector("#fd-new-name").value.trim() || "new feed");
    c.querySelector(".cfg-save").onclick = async () => {
      const items = [], del = [];
      c.querySelectorAll("tbody tr").forEach((tr) => {
        if (tr.querySelector(".fd-del")?.checked) { del.push(tr.dataset.name); return; }
        items.push({ name: tr.dataset.name, kind: tr.dataset.kind, url: tr.querySelector(".fd-url").value.trim() || (tr.dataset.builtin === "1" ? "" : F.items[+tr.dataset.i].url),
          enabled: tr.querySelector(".fd-on").checked, serious: tr.querySelector(".fd-ser").checked, opencti: tr.querySelector(".fd-oc").checked });
      });
      const nn = c.querySelector("#fd-new-name").value.trim(), nu = c.querySelector("#fd-new-url").value.trim();
      if (nn || nu) items.push({ name: nn, url: nu, kind: c.querySelector("#fd-new-kind").value, enabled: true, serious: c.querySelector("#fd-new-ser").checked, opencti: false });
      if (del.length && !confirm(`Delete ${del.join(", ")}?`)) return;
      msg.textContent = "Saving…";
      try { const R = await apiPost("/api/config/integrations/feeds", { items, delete: del }); done(R, "Saved. Feeds change on the next watcher / review run."); }
      catch (e) { msg.innerHTML = `<span class="sev-high">${esc(String(e))}</span>`; }
    };
    return c;
  }
  function paintInt(wrap, D, flash) {
    wrap.innerHTML = `<h2 style="margin:18px 0 4px">Integrations</h2><div class="sub">Where netmon reads its data. Blank fields use the defaults shown, so
      saving an empty form changes nothing. The host jobs (review runs, event research, the watcher every 15 min) use these on their next run.</div>`;
    if (!D.admin) { wrap.insertAdjacentHTML("beforeend", `<div class="card"><div class="empty">Only an admin can view or change integrations.</div></div>`); return; }
    const E = D.elasticsearch, U = D.unifi;
    const ixRows = Object.keys(E.index_defaults).map((k) => fld("es-ix-" + k, E.index_labels[k], E.indices[k], E.index_defaults[k], `Default <span class="mono">${esc(E.index_defaults[k])}</span>. Comma-separated patterns and <span class="mono">*</span> are allowed.`)).join("");
    const ce = intCard("elasticsearch", "Elasticsearch (Security Onion)", "Read-only API key with <span class=\"mono\">read</span> + <span class=\"mono\">view_index_metadata</span> on the indices below. TLS certificates are not verified (Security Onion uses its own CA).",
      fld("elasticsearch-url", "URL", E.url, E.url_fallback || "https://so-manager:9200", `Default (the site settings (Settings → Settings (policy & site))): <span class="mono">${esc(E.url_fallback || "not set")}</span>`)
      + fld("elasticsearch-key", "API key", "", E.key_set ? E.key_hint : "base64 id:key from Kibana › Stack Management › API keys", keyHelp(E), "password")
      + `<div class="small" style="margin-top:12px"><b>Indices to search</b></div>` + ixRows, E);
    const cu = intCard("unifi", "UniFi API", "Site Manager API key from <span class=\"mono\">unifi.ui.com › API</span>. netmon reads clients, devices and events through the console connector (read-only).",
      fld("unifi-url", "URL", U.url, U.url_fallback, `Default <span class="mono">${esc(U.url_fallback)}</span> (Ubiquiti cloud). Use your console's address only if you run a local API proxy that speaks the same paths.`)
      + fld("unifi-key", "API key", "", U.key_set ? U.key_hint : "UniFi Site Manager API key", keyHelp(U), "password"), U);
    const Wb = D.web || { provider: "duckduckgo", providers: { duckduckgo: "DuckDuckGo (no key)" } };
    const cw = intCard("web", "Web search (AI research and chat)", "Used by event research (Send to research) and the Ask AI chat to look things up and read web pages. DuckDuckGo needs no key; Brave Search and Tavily need an API key from their sites. Firecrawl (also used to read pages) needs a key for its cloud, or the URL of your own Firecrawl instance (a key only if you set one there).",
      `<label class="cfg-f" style="display:block;margin:8px 0"><span class="small"><b>Provider</b></span><br><select id="web-provider">${Object.entries(Wb.providers).map(([k, l]) =>
        `<option value="${esc(k)}"${k === Wb.provider ? " selected" : ""}>${esc(l)}</option>`).join("")}</select></label>`
      + fld("web-key", "API key", "", Wb.key_set ? Wb.key_hint : "API key (not needed for DuckDuckGo or a self-hosted Firecrawl)", keyHelp(Wb), "password")
      + fld("web-url", "Firecrawl URL", Wb.url || "", Wb.url_fallback || "https://api.firecrawl.dev", `Firecrawl only. Blank = Firecrawl cloud (<span class="mono">${esc(Wb.url_fallback || "https://api.firecrawl.dev")}</span>); enter your own instance's base URL to use it instead.`)
      + `<label class="cfg-f" style="display:block;margin:8px 0"><span class="small"><b>Firecrawl CA certificate (PEM, optional)</b></span><div class="muted small">Self-hosted Firecrawl only. The certificate is always verified; if your instance uses a private CA, paste that CA here.</div>
         <textarea id="web-ca" rows="3" spellcheck="false" placeholder="${Wb.ca_set ? "A CA is saved. Paste a new one to replace it." : "-----BEGIN CERTIFICATE-----"}" style="width:min(560px,100%);box-sizing:border-box;font-family:var(--mono,monospace)"></textarea>
         ${Wb.ca_set ? `<div class="muted small"><label><input type="checkbox" id="web-ca-clr"> remove the saved CA</label></div>` : ""}</label>`, Wb);
    const O = D.opencti, OS = O.status || {};
    const cb = (id, on, label, help) => `<label style="display:block;margin:6px 0"><input type="checkbox" id="${id}"${on ? " checked" : ""}> <b class="small">${label}</b>${help ? `<div class="muted small" style="margin-left:22px">${help}</div>` : ""}</label>`;
    const ocStatus = O.enabled ? `<div class="small" style="margin:6px 0">Status: ${OS.last_pull ? `${Number(OS.indicators || 0).toLocaleString()} indicators pulled (${Number(OS.high || 0).toLocaleString()} high-confidence, ${Number(OS.hashes || 0).toLocaleString()} hashes, ${Number(OS.filenames || 0).toLocaleString()} file names), last pull ${esc(ft(OS.last_pull))}` : "not pulled yet"}`
      + ` · sightings sent ${Number(OS.sightings_total || 0).toLocaleString()} · incidents ${Number(OS.incidents_total || 0).toLocaleString()}`
      + `${OS.last_error ? ` · <span class="sev-high">last error: ${esc(OS.last_error)}</span>` : ""}</div>` : "";
    const co = intCard("opencti", "OpenCTI (threat intelligence)", "Optional. netmon pulls indicators from your OpenCTI platform (IPs, domains, file hashes, file names and malware-sample hashes) into the threat-intel matcher and hands every match to the event reviewer, and reports back what it sees. Create a dedicated OpenCTI user for netmon (Settings › Security › Users) and paste its API token; it needs to read indicators and create sightings, observables and incidents.",
      ocStatus + cb("oc-enabled", O.enabled, "Enabled")
      + fld("opencti-url", "URL", O.url, "https://opencti.example.com", "Base URL of the OpenCTI platform (no /graphql).")
      + fld("opencti-key", "API token", "", O.key_set ? O.key_hint : "OpenCTI user API token", O.key_set ? keyHelp({ ...O, key_fallback: "nothing (the integration stops)" }) : "Write-only: stored on the server and never shown again.", "password")
      + `<label class="cfg-f" style="display:block;margin:8px 0"><span class="small"><b>CA certificate (PEM, optional)</b></span><div class="muted small">The certificate is always verified. If OpenCTI uses a private or self-signed CA, paste that CA here.</div>
         <textarea id="oc-ca" rows="3" spellcheck="false" placeholder="${O.ca_set ? "A CA is saved. Paste a new one to replace it." : "-----BEGIN CERTIFICATE-----"}" style="width:min(560px,100%);box-sizing:border-box;font-family:var(--mono,monospace)"></textarea>
         ${O.ca_set ? `<div class="muted small"><label><input type="checkbox" id="oc-ca-clr"> remove the saved CA</label></div>` : ""}</label>`
      + `<div class="small" style="margin-top:12px"><b>Use OpenCTI as threat intel</b></div>`
      + cb("oc-pull", O.pull, "Pull indicators into the feed matcher", "IPv4/IPv6 addresses, domains, hostnames, file hashes and file names that are not revoked or expired, plus malware-sample hashes (MalwareBazaar). Full refresh daily, changes every hour.")
      + fld("oc-min", "Minimum score", String(O.min_score), "50", "Indicators below this OpenCTI score are ignored (0–100).", "number")
      + fld("oc-high", "High-confidence score", String(O.high_score), "80", "At or above this score a hit counts as serious and raises a Threat-intel alert, like Feodo or URLhaus.", "number")
      + `<div class="small" style="margin-top:12px"><b>Report back to OpenCTI</b></div>`
      + cb("oc-sight", O.sightings, "Sightings", "Each OpenCTI indicator netmon sees in traffic gets a sighting by the identity \"netmon (site name)\", with the number of connections / look-ups.")
      + cb("oc-inc", O.incidents, "Incidents", "Open events the reviewer labelled suspicious become OpenCTI incidents, with their external IPs and domains attached (internal addresses stay in the description). Up to 25 new per run.")
      + `<label class="cfg-f" style="display:inline-block;margin:4px 16px 4px 22px"><span class="small"><b>Minimum severity</b></span><br><select id="oc-sev">${O.sevs.map((x) => `<option${x === O.incident_min_sev ? " selected" : ""}>${esc(x)}</option>`).join("")}</select></label>`
      + `<label class="cfg-f" style="display:inline-block;margin:4px 0"><span class="small"><b>Minimum reviewer confidence</b></span><br><input id="oc-conf" type="number" min="0.5" max="1" step="0.05" value="${esc(String(O.incident_min_conf))}" style="width:90px"></label>`, O);
    // Kubernetes API: one card per cluster (read-only ServiceAccount each) + one to add a cluster
    const kubeCard = (K, isNew) => {
      const c = intCard("kubernetes", isNew ? "Kubernetes API: add a cluster" : `Kubernetes API (read-only): ${esc(K.name)}`,
        isNew ? "Add another cluster. Create the read-only account in it first (docs/kubernetes-readonly.yaml), then paste its token and CA here, Test, Enable and Save."
          : "A read-only ServiceAccount token lets netmon run the CIS Kubernetes benchmark checks, draw the Kubernetes map and check container images for updates and CVEs. Logs and events come from Security Onion. Test asks the API server what the token may do and says so if it can do more than read. Example manifest: docs/kubernetes-readonly.yaml.",
        (isNew ? fld("kb-name", "Cluster name", "", "e.g. lab", "Lower-case letters, digits and dashes; shown in the cluster filter on the Kubernetes pages.") : "")
        + cb("kb-enabled", K.enabled, "Enabled") + cb("kb-cis", K.cis !== false, "Run CIS benchmark checks", "Every 6 hours (nightly run) and on demand from Devices → Kubernetes. Failed checks become Kubernetes findings.")
        + fld("kubernetes-url", "API server URL(s)", K.url || "", "https://k8s-api.example.lan:6443", "One or more https:// URLs, comma-separated (control-plane nodes); the first that answers is used.")
        + fld("kubernetes-key", "ServiceAccount token", "", K.key_set ? K.key_hint : "eyJhbGciOi… (bearer token)", K.key_set ? keyHelp({ ...K, key_fallback: "nothing (the cluster stops being checked)" }) : "Write-only: stored on the server and never shown again.", "password")
        + `<label class="cfg-f" style="display:block;margin:8px 0"><span class="small"><b>Cluster CA certificate (PEM)</b></span><div class="muted small">The API server certificate is always verified. Paste the cluster CA (certificate-authority-data from a kubeconfig, base64-decoded).</div>
           <textarea id="kb-ca" rows="3" spellcheck="false" placeholder="${K.ca_set ? "A CA is saved. Paste a new one to replace it." : "-----BEGIN CERTIFICATE-----"}" style="width:min(560px,100%);box-sizing:border-box;font-family:var(--mono,monospace)"></textarea>
           ${K.ca_set ? `<div class="muted small"><label><input type="checkbox" id="kb-ca-clr"> remove the saved CA</label></div>` : ""}</label>`, K);
      c.dataset.cluster = isNew ? "" : K.name;
      if (!isNew) {
        const del = document.createElement("button"); del.textContent = "Remove cluster"; del.className = "danger";
        c.querySelector(".cfg-test").after(del);
        del.onclick = async () => { if (!confirm(`Stop checking cluster ${K.name} and delete its saved token?`)) return;
          try { rerender(await apiPost("/api/config/integrations/kubernetes", { cluster: K.name, delete: true }), "kubernetes", "Removed."); }
          catch (e) { c.querySelector(".cfg-msg").innerHTML = `<span class="sev-high">${esc(String(e))}</span>`; } };
      }
      return c;
    };
    const kubeCards = [...((D.kubernetes || {}).clusters || []).map((K) => kubeCard(K, false)), kubeCard({ enabled: false, cis: true, url: "" }, true)];
    const cf = feedsCard(D.feeds || { items: [], kinds: {} }, O, (R, m) => paintInt(wrap, R, { sec: "feeds", m }));
    wrap.append(ce, cu, cw, co, ...kubeCards, cf);
    const rerender = (R, sec, m) => { paintInt(wrap, R, { sec, m }); };
    wire(ce, "elasticsearch", E, rerender); wire(cu, "unifi", U, rerender); wire(cw, "web", Wb, rerender); wire(co, "opencti", O, rerender); kubeCards.forEach((c) => wire(c, "kubernetes", {}, rerender));
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
