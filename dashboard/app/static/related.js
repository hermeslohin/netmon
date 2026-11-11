// Related events: fills the "Related" column (table opts.evId) from /api/correlate and shows a popover of the
// linked events / vulnerabilities on click. Each item links to its own list filtered to that one event (?ev=<id>).
(() => {
  const main = document.getElementById("main"); if (!main) return;
  const TYPE = { alert: ["Alert", "sev-high"], finding: ["Finding", "sev-medium"], ids: ["IDS", "sev-medium"], admin: ["Admin", "sev-low"],
    host: ["Endpoint", "sev-low"], ti: ["Threat intel", "sev-high"], vuln: ["Vulnerability", "sev-critical"], gw: ["Gateway", "sev-medium"],
    alarm: ["Triage alarm", "sev-high"] };
  let loading = null;
  // Detection settings behind a finding (upload-spike, beacon-*, internal-scan): current values + description, from /api/tuning
  let TUNE = null, tuneAt = 0;
  function loadTuning() { if (Date.now() - tuneAt < 30000) return; tuneAt = Date.now(); api("/api/tuning").then((d) => { TUNE = d.settings || {}; }).catch(() => {}); }
  function tuneFor(id) {
    const m = /^f\|([^|]+)\|/.exec(String(id || "")); if (!m || !TUNE) return null;
    for (const t of Object.values(TUNE)) if (new RegExp(t.kinds).test(m[1])) return t;
    return null;
  }
  function tuneHtml(id) {
    const t = tuneFor(id); if (!t) return "";
    const v = Object.entries(t.values || {}).map(([k, x]) => `<code>${esc(k)}</code> = <b>${esc(Array.isArray(x) ? x.join(", ") : x)}</b>`).join(" · ");
    return `<details class="tune-box small" style="margin:4px 0 0"><summary class="muted">⚙ Detection setting: ${esc(t.title)} — ${v}</summary><div class="muted" style="margin:4px 0">${esc(t.doc || "")}</div><span class="tune-go" data-href="${esc(t.link)}" style="cursor:pointer;text-decoration:underline">Adjust in Settings →</span></details>`;
  }
  document.addEventListener("click", (e) => {  // the box sits inside a link row: toggle / navigate without following the row's link
    const sm = e.target.closest?.(".tune-box > summary"), go = e.target.closest?.(".tune-go");
    if (!sm && !go) return;
    e.preventDefault(); e.stopPropagation();
    if (sm) sm.parentNode.open = !sm.parentNode.open; else { close(); location.hash = go.dataset.href; }
  }, true);
  function ensure() {
    loadTuning();
    const sid = S.snap?.id; if (!sid) return;
    if (S.corr && S.corr._snap === sid) return fill();
    if (loading === sid) return;
    loading = sid;
    api("/api/correlate?id=" + encodeURIComponent(sid)).then((d) => { d._snap = sid; S.corr = d; }).catch(() => { S.corr = { _snap: sid, related: {}, events: {}, error: true }; })
      .finally(() => { loading = null; fill(); relabelChips(); main.querySelectorAll('.tfrow input').forEach((i) => i.value && i.dispatchEvent(new Event('input'))); });
  }
  const pendingEv = (id) => (S.corr?.related?.[id] || []).some((r) => r.llm === "pending");
  window.netmonPendingReview = pendingEv;
  // rows whose event is no longer in the loaded correlation (checked off, aged out of the snapshot) still get their saved research note
  const orphanAsked = new Set(), orphanNotes = {};
  function fetchOrphans() {
    const ids = [...new Set([...main.querySelectorAll(".rel-btn")].map((b) => b.dataset.rel))].filter((id) => id && !S.corr.notes?.[id] && !S.corr.events?.[id] && !orphanAsked.has(id));
    if (!ids.length) return;
    ids.forEach((i) => orphanAsked.add(i));
    for (let i = 0; i < ids.length; i += 20) {
      api("/api/notes/by-event?" + ids.slice(i, i + 20).map((x) => "e=" + encodeURIComponent(x)).join("&")).then((N) => {
        if (!N || !Object.keys(N).length || !S.corr) return; Object.assign(orphanNotes, N); S.corr.notes = { ...(S.corr.notes || {}), ...N }; fill(); }).catch(() => {});
    }
  }
  function fill() {
    if (!S.corr || S.corr._snap !== S.snap?.id) return;
    for (const [k, v] of Object.entries(orphanNotes)) if (!S.corr.notes?.[k] && !S.corr.events?.[k]) (S.corr.notes = S.corr.notes || {})[k] = v;
    const X = location.hash.startsWith("#/events") ? window.__oeExtra : null;  // Open events page: AI notes, classifications, your notes, times seen
    if (X) for (const m of ["notes", "classes", "unotes", "seen"]) S.corr[m] = { ...(S.corr[m] || {}), ...(X[m] || {}) };
    fetchOrphans();
    main.querySelectorAll(".rel-btn").forEach((b) => {
      // rows older than the loaded snapshot (Open events): the count of stored related verdicts; details load on click
      const n = (S.corr.related?.[b.dataset.rel] || []).length || (X?.related_n?.[b.dataset.rel] || 0);
      const t = n ? String(n) : "–";
      if (b.textContent !== t) b.textContent = t;
      b.classList.toggle("has", n > 0); b.disabled = !n;
      // AI research note for this event: a "✨ notes" button right after the Related count
      const note = S.corr.notes?.[b.dataset.rel]; let nb = b.nextElementSibling?.classList.contains("note-btn") ? b.nextElementSibling : null;
      if (note && !nb) { nb = document.createElement("button"); nb.type = "button"; nb.className = "note-btn"; nb.dataset.note = b.dataset.rel; b.after(nb); }
      if (!note && nb) nb.remove();
      if (note && nb) { const t = "✨ " + (note.verdict || "notes"); if (nb.textContent !== t) nb.textContent = t;
        nb.className = "note-btn v-" + String(note.verdict || "").replace(/[^a-z-]/g, ""); nb.title = (note.summary || "Research notes").slice(0, 200); }
      // AI classification (suspicious / benign / expected): flair after the notes button, once the event's correlation review is done
      const cl = S.corr.classes?.[b.dataset.rel]; const pre = nb || b; let cb = pre.nextElementSibling?.classList.contains("cls-btn") ? pre.nextElementSibling : null;
      if (cl && !cb) { cb = document.createElement("button"); cb.type = "button"; cb.className = "cls-btn"; cb.dataset.cls = b.dataset.rel; pre.after(cb); }
      if (!cl && cb) cb.remove();
      if (cl && cb) { const pd = cl.label === "pending", un = cl.label === "unreviewed", t = pd ? "⏳ Pending review" : un ? "⊘ Not reviewed" : "🏷 " + cl.label; if (cb.textContent !== t) cb.textContent = t;
        cb.className = "cls-btn v-" + String(cl.label).replace(/[^a-z-]/g, "") + (cl.pending ? " pend" : ""); cb.title = pd || cl.pending ? pendTitle(cl.pending) : (cl.reason || "AI classification").slice(0, 200); }
      // people's notes on this event (kbnotes.js opens them): a 📝 button after the AI note, on every event row
      const after = (b.parentNode.querySelector(`.cls-btn[data-cls="${CSS.escape(b.dataset.rel)}"]`)) || nb || b; let ub = after.nextElementSibling?.classList.contains("unote-btn") ? after.nextElementSibling : null;
      if (!ub) { ub = document.createElement("button"); ub.type = "button"; ub.className = "unote-btn"; ub.dataset.unote = b.dataset.rel; ub.title = "Your notes on this event (the AI reads them)"; after.after(ub); }
      const uns = S.corr.unotes?.[b.dataset.rel] || [], un = uns.length, ut = un ? `📝 ${un}${uns.some((x) => x.status === "pending") ? " ⏳" : ""}` : "📝";
      if (ub.textContent !== ut) ub.textContent = ut;
      ub.classList.toggle("has", un > 0);
      // times seen: gold eye icon + "N×" after the Related count (snapshots the event was present in; alerts: times raised)
      const sn = S.corr.seen?.[b.dataset.rel]; let sb = b.parentNode.querySelector(`.seen-flair[data-seen="${CSS.escape(b.dataset.rel)}"]`);
      if (sn && !sb) { sb = document.createElement("span"); sb.className = "seen-flair small muted"; sb.dataset.seen = b.dataset.rel; (ub.nextElementSibling?.classList.contains("pend-flair") ? ub.nextElementSibling : ub).after(sb); }
      if (!sn && sb) sb.remove();
      if (sn && sb) { const t = ` ${sn.n}×`; if (sb.textContent !== t) { sb.textContent = t; sb.insertAdjacentHTML("afterbegin", ' <i class="ic ic-eye" aria-hidden="true"></i>'); } sb.title = `Seen ${sn.n} time${sn.n === 1 ? "" : "s"}${sn.first ? " · first " + sn.first : ""}${sn.last ? " · last " + sn.last : ""}`; }
      // "settles at HH:MM": the event's correlated group has not settled yet (its label button above says Pending review)
      const pp = cl?.pending, isP = !!pp || pendingEv(b.dataset.rel); let pf = ub.nextElementSibling?.classList.contains("pend-flair") ? ub.nextElementSibling : null;
      if (isP && !pf) { pf = document.createElement("span"); pf.className = "pend-flair"; ub.after(pf); }
      if (isP && pf) { const t = pp?.settles ? `settles at ${pendSettles(pp)}` : pp?.queued ? "queued" : "⏳ links deciding"; if (pf.textContent !== t) pf.textContent = t;
        pf.title = pp ? pendTitle(pp) : "The decision model has not decided this event's candidate links yet"; }
      if (!isP && pf) pf.remove();
    });
  }
  function relabelChips() {  // drill-down chip shows the event's label once correlations are loaded
    main.querySelectorAll(".fchips b[data-ev]").forEach((b) => { b.textContent = evLabel(b.dataset.ev); });
  }
  const llmLine = () => { const L = S.corr?.llm;
    if (!L || !L.enabled) return "Linked by shared hosts, IPs, domains or accounts, time, ATT&CK technique and vulnerabilities on the hosts involved. (Local LLM review is off.)";
    return `The script proposes links (shared hosts/IPs/accounts, time, ATT&CK, vulnerabilities); the event reviewer (${L.model || "?"}) decides, and event research on request (its verdicts replace the event reviewer's). `
      + `${L.confirmed} confirmed, ${L.rejected} rejected, ${L.pending} awaiting review${L.busy ? " (reviewing now)" : ""}${L.error ? ` · last error: ${L.error}` : ""}.`; };
  // while reviews are pending, refresh the verdicts every 2 minutes so counts and badges catch up
  setInterval(() => { if (S.corr?.llm?.pending && !document.hidden && main.querySelector(".rel-btn")) { S.corr._snap = null; ensure(); } }, 120000);
  let pop = null;
  const close = () => { pop?.remove(); pop = null; };
  const ART_ICON = { file: "📄", process: "⚙️", user: "👤", ip: "🌐", dns: "🔎", hash: "🧬", cert: "🔒" };
  // an AI Elasticsearch search kept as an artifact: click to open the same search in Kibana Discover
  function queryArtHtml(a) {
    const d = a.query || {}, url = window.kibanaQueryUrl?.(d) || "";
    const hits = d.total != null ? `${Number(d.total).toLocaleString()} hits` : "";
    const tip = `${d.by === "research" ? "Event research" : "Event reviewer"} search${d.index ? " of " + d.index : ""}${d.from ? ` · ${String(d.from).slice(0, 16)} → ${String(d.to || "").slice(0, 16)}` : ""}${d.approx ? " · opens an approximation (aggregations / complex clauses are not in the link)" : ""}`;
    return `<li><span class="art-k" title="${esc(tip)}">🔭 query</span> ${url ? `<button type="button" class="kib-btn" data-kib="${esc(url)}" title="${esc(tip)}: open in Kibana Discover"><code>${esc(a.value)}</code> ↗</button>` : `<code title="${esc(tip)}">${esc(a.value)}</code>`}
      ${hits ? `<span class="small muted">${esc(hits)}</span>` : ""}${d.approx ? ` <span class="small muted" title="${esc(tip)}">≈</span>` : ""} ${a.model ? aiFlare({ model: a.model, via: "Elasticsearch search", at: a.at ? new Date(a.at * 1000).toISOString() : "" }) : ""}
      ${a.relation ? `<span class="small muted">${esc(a.relation)}</span>` : ""}</li>`;
  }
  // artifacts of a related event, known before any review: host / destination IPs plus the users, processes, files and
  // DNS names the correlation script read from the event itself (e.arts); the event reviewer's own artifacts replace same kind:value
  function ipArts(e, arts) {
    const have = new Set((arts || []).map((a) => a.kind + ":" + a.value)), out = [];
    const add = (kind, value, relation) => { const k = kind + ":" + value; if (!have.has(k)) { have.add(k); out.push({ kind, value, relation, decision: "info" }); } };
    for (const [list, rel] of [[e.host_ips, "host IP"], [e.dst_ips, "destination IP"]]) for (const ip of list || []) add("ip", ip, rel);
    for (const [kind, value, relation] of e.arts || []) add(kind, value, relation);
    return [...out, ...(arts || [])];
  }
  // a web page the event reviewer cited (kind "web": value = URL, relation = page title)
  function webArtHtml(a) {
    const u = safeUrl(a.value);
    return `<li><span class="art-k" title="web page the event reviewer used">🌍 web</span> ${u ? `<a href="${esc(u)}" target="_blank" rel="noopener noreferrer" title="${esc(u)}">${esc((a.relation || u).slice(0, 90))}</a>` : `<code>${esc(a.value)}</code>`}
      <span class="small muted">${esc(u ? new URL(u).hostname : "")}</span> ${a.model ? aiFlare({ model: a.model, via: "web search", at: a.at ? new Date(a.at * 1000).toISOString() : "" }) : ""}</li>`;
  }
  function sourcesHtml(srcs) {
    const L = (srcs || []).filter((s) => safeUrl(s.url));
    return L.length ? `<div class="small oe-sources" style="margin-top:4px"><b>🌍 Web sources</b><ul style="margin:2px 0 0 1.2em;padding:0">${L.map((s) => `<li>${s.id ? `<b>[${esc(s.id)}]</b> ` : ""}<a href="${esc(s.url)}" target="_blank" rel="noopener noreferrer" title="${esc(s.url)}">${esc((s.title || s.url).slice(0, 90))}</a> <span class="muted">${esc(new URL(s.url).hostname)}</span></li>`).join("")}</ul></div>` : "";
  }
  // an AI reason with its [W1] markers turned into links to the cited pages
  function reasonHtml(reason, srcs) {
    const by = {}, loose = [];
    for (const x of srcs || []) if (safeUrl(x.url)) (x.id ? (by[x.id] = x) : loose.push(x));
    for (const id of [...new Set((String(reason || "").match(/\[W\d+\]/g) || []).map((m) => m.slice(1, -1)))]) if (!by[id] && loose.length) by[id] = loose.shift();  // older rows: no stored id, match in order
    return esc(reason || "").replace(/\[(W\d+)\]/g, (m, id) => by[id] ? `<a href="${esc(by[id].url)}" target="_blank" rel="noopener noreferrer" title="${esc(by[id].title || by[id].url)}">[${id}]</a>` : m);
  }
  function artifactsHtml(arts, title = "Correlated artifacts") {
    if (!arts?.length) return "";
    return `<div class="note-arts"><b class="small">${esc(title)}</b><ul>${arts.map((a) => a.kind === "query" ? queryArtHtml(a) : a.kind === "web" ? webArtHtml(a) : `<li><span class="art-k" title="${esc(a.kind)}">${ART_ICON[a.kind] || "•"} ${esc(a.kind)}</span> <code>${esc(a.value)}</code> <button type="button" class="extnote-btn" data-extart="${esc(a.kind + ":" + a.value)}" title="Your notes on this ${esc(a.kind === "cert" ? "TLS certificate" : a.kind)} artifact (the AI reads them)"><i class="ic ic-note" aria-hidden="true"></i></button>${window.artSearchBtn ? artSearchBtn(a.kind, a.value) : ""}
      <span class="note-v v-${esc(String(a.decision).replace(/[^a-z-]/g, ""))}">${esc(a.decision)}</span> ${!a.model ? "" : aiFlare({ model: a.model, via: "correlation review", at: a.at ? new Date(a.at * 1000).toISOString() : "" })}
      ${a.relation ? `<span class="small muted">${esc(a.relation)}</span>` : ""}</li>`).join("")}</ul></div>`;
  }
  document.addEventListener("click", (e) => {  // capture phase: the artifact sits inside a link row, so stop that navigation
    const b = e.target.closest?.(".kib-btn");
    if (!b) return;
    e.preventDefault(); e.stopPropagation();
    window.open(b.dataset.kib, "_blank", "noopener,noreferrer");
  }, true);
  // event time: epoch seconds (t0, optional t1 span end); vulnerabilities are timeless (open until fixed)
  const evTime = (e) => {
    const f = (t) => new Date(t * 1000).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" });
    if (e.type === "vuln" || !e.t0) return "ongoing (no event time)";
    return e.t1 && e.t1 - e.t0 >= 60 ? `${f(e.t0)} → ${f(e.t1)}` : f(e.t0);
  };
  // decision model (clef) chips: per-link p(related) (it decides links only; the event reviewer labels events)
  const pct = (p) => Math.round((p || 0) * 100) + "%";
  // a person's verdict weighed against the event reviewer's label (corr_llm.apply_owner): applied, held back, or agreeing
  const ownerHtml = (c) => { const o = c?.owner; if (!o) return "";
    const what = o.kind === "artifacts" ? `on matching artifacts (${esc((o.match || []).join(", "))})` : "on this event";
    return o.applied ? `<span class="small" title="A person's ${esc(o.verdict)} verdict ${what} outweighed the event reviewer (weight ${pct(o.weight)})">👤 ${esc(o.verdict)} verdict applied <span class="muted">· the event reviewer said ${esc(o.model_label || "?")} (${pct(o.model_confidence)})</span></span>`
      : o.held ? `<span class="small muted" title="A person's ${esc(o.verdict)} verdict ${what} was not applied">👤 ${esc(o.verdict)} verdict not applied: ${esc(o.held)}</span>`
      : `<span class="small muted" title="A person's ${esc(o.verdict)} verdict ${what}">👤 agrees with a person's ${esc(o.verdict)} verdict</span>`; };
  const clefLinkHtml = (r) => r.clef ? `<span class="rel-ai ${r.clef.related ? "yes" : "pend"}" title="Decision model (${esc(r.clef.model || "clef")}) p(related) = ${(r.clef.p_related || 0).toFixed(3)}">clef ${pct(r.clef.p_related)} related</span>`
    : `<span class="rel-ai pend" title="Decided before the decision model (clef) ran: ${esc(r.llm_model || "reviewer")} verdict">no clef decision</span>`;
  // the events passed in to an event's determinations (decision model: the event + every candidate with its link probability;
  // event reviewer: the related ones). decs = [{stage, at, model, label, p_suspicious, p_expected, inputs:[{id, p, sent, related}]}]
  function inputsHtml(decs, EV, opts = {}) {
    if (!decs || !decs.length) return opts.empty === false ? "" : `<div class="small muted">${esc(opts.empty || "No determination recorded.")}</div>`;
    const stageName = { decision: "Decision model", review: "Event reviewer" };
    return decs.map((d) => { const ins = d.inputs || [], sent = ins.filter((x) => x.sent).length;
      const head = d.stage === "decision"
        ? `→ <span class="note-v v-${esc(String(d.label || "").replace(/[^a-z-]/g, ""))}">${esc(d.label || "?")}</span> <span class="muted">p sus ${pct(d.p_suspicious)} · p exp ${pct(d.p_expected)}</span>`
        : d.label ? `<span class="muted">its own label:</span> ${esc(d.label)}` : "";
      const rows = ins.map((x) => { const e = (EV || {})[x.id] || { label: x.id, type: String(x.id).split("|")[0] }; const [tl, tc] = TYPE[e.type] || TYPE[{ f: "finding", adm: "admin", hf: "host", iss: "vuln" }[e.type]] || [e.type, ""];
        const lab = String(e.label || x.id);
        return `<div class="oe-in${x.sent ? "" : " oe-in-off"}"><span class="badge ${tc}">${esc(tl)}</span> <span class="rel-ai ${x.related ? "yes" : "pend"}" title="Decision model link probability with this event">${pct(x.p)} ${x.related ? "related" : "not related"}</span>
          ${x.sent ? "" : `<span class="small muted" title="Left out of the request to keep it within the model's state size">not sent</span>`}
          <span class="rel-l">${esc(lab.length > 140 ? lab.slice(0, 138) + "…" : lab)}</span>${e.t0 || e.t1 ? ` <span class="small muted">🕒 ${esc(evTime(e))}</span>` : ""}${e.link ? ` <a class="small" href="${esc(e.link)}">open ↗</a>` : ""}</div>`; }).join("");
      return `<details class="oe-det oe-sub oe-inputs"${opts.open ? " open" : ""}><summary><b>${esc(stageName[d.stage] || d.stage)}</b> <span class="muted">${esc(String(d.model || "").replace(/^.*[:/]/, ""))} · ${esc(d.at ? new Date(d.at * 1000).toLocaleString() : "")}</span> ${head}
          <span class="muted">· the event + ${sent} event${sent === 1 ? "" : "s"} passed in${ins.length > sent ? ` (${ins.length - sent} left out)` : ""}</span>${d.reconstructed ? ` <span class="small muted" title="Made before netmon recorded the inputs: rebuilt from the decision model's link decisions on this event">rebuilt</span>` : ""}</summary>
        ${rows || `<div class="small muted">No other events: decided from the event and its notes alone.</div>`}</details>`; }).join("");
  }
  // fill a placeholder (.rel-inputs[data-inputs=eid]) in a pop-up from /api/events/inputs
  function loadInputs(root) {
    const ph = root.querySelector(".rel-inputs[data-inputs]"); if (!ph) return;
    api("/api/events/inputs?e=" + encodeURIComponent(ph.dataset.inputs)).then((d) => { if (!ph.isConnected) return;
      const D = d.decisions || [];
      ph.innerHTML = D.length ? `<div class="small"><b>Events passed in to make the determination</b></div>${inputsHtml(D.slice(0, 2), { ...(S.corr?.events || {}), ...(d.events || {}) }, { open: true })}${D.length > 2 ? `<details class="oe-det oe-sub"><summary class="small">${D.length - 2} earlier determination${D.length - 2 === 1 ? "" : "s"}</summary>${inputsHtml(D.slice(2), { ...(S.corr?.events || {}), ...(d.events || {}) })}</details>` : ""}`
        : `<div class="small muted">No determination recorded for this event yet.</div>`;
      if (pop && root === pop) { const r = pop.getBoundingClientRect(); if (r.bottom > innerHeight - 8) pop.style.top = Math.max(8, innerHeight - r.height - 8) + "px"; }
    }).catch((e) => { ph.innerHTML = `<div class="small muted">${esc(e.message || e)}</div>`; });
  }
  // the analyst's advice for the device owner (advice.py): action chip, headline, steps, why
  const ADV = { no_action: ["✅", "ok"], watch: ["👀", "low"], update: ["⬆️", "low"], password: ["🔑", "low"], stop_site: ["🚫", "high"], stop_app: ["🚫", "high"], stop_device: ["⛔", "crit"] };
  const advChip = (v) => { const [i, l] = ADV[v?.action] || ["💬", "low"]; return `<span class="adv-a adv-${l}">${i} ${esc(v?.label || v?.action || "")}</span>`; };
  const advBody = (v) => `${(v.steps || []).length ? `<ol class="adv-steps">${v.steps.map((x) => `<li>${esc(x)}</li>`).join("")}</ol>` : ""}${v.why ? `<div class="small adv-why"><b>Why:</b> ${esc(v.why)}</div>` : ""}`;
  const adviceHtml = (v) => v ? `<div class="adv"><div class="adv-h">${advChip(v)} <b>${esc(v.headline || "")}</b></div>${advBody(v)}</div>` : "";
  // Open events: one collapsed arrow (summary = chip + headline)
  const adviceDetails = (v) => v ? `<details class="oe-det oe-sub adv-det"><summary>💬 Advice for the device owner: ${advChip(v)} ${esc(v.headline || "")}</summary><div class="adv">${advBody(v)}${typeof aiFlare === "function" && v.model ? `<div class="small muted">${aiFlare({ model: v.model, via: "advice for the device owner", at: v.at ? new Date(v.at * 1000).toISOString() : "" })}</div>` : ""}</div></details>` : "";
  window.relUi = { artifactsHtml, ipArts, queryArtHtml, sourcesHtml, reasonHtml, inputsHtml, ownerHtml, advChip, adviceHtml, adviceDetails };  // used by the Open events window (openevents.js)
  const loadingRel = new Set();
  function openStored(btn) {  // Open events row outside the loaded snapshot: fetch its stored links, then open
    const id = btn.dataset.rel; if (loadingRel.has(id)) return; loadingRel.add(id);
    const ms = (window.__oeMembers?.[id] || []).slice(-12);
    btn.textContent = "…";
    api("/api/events/related?e=" + encodeURIComponent(id) + ms.map((m) => "&m=" + encodeURIComponent(m)).join("")).then((d) => {
      if (!S.corr) return;
      S.corr.related = S.corr.related || {}; S.corr.events = S.corr.events || {};
      if (d.related?.length) S.corr.related[id] = d.related;
      for (const [k, v] of Object.entries(d.events || {})) if (!S.corr.events[k]) S.corr.events[k] = v;
    }).catch(() => {}).finally(() => { loadingRel.delete(id); fill(); if (btn.isConnected && S.corr?.related?.[id]?.length) { open(btn); if (pop) pop._for = btn; } });
  }
  function open(btn) {
    close();
    const id = btn.dataset.rel, rel = S.corr?.related?.[id] || [], me = S.corr?.events?.[id];
    if (!rel.length) { if (window.__oeExtra?.related_n?.[id] && location.hash.startsWith("#/events")) openStored(btn); return; }
    pop = document.createElement("div"); pop.className = "rel-pop"; pop.setAttribute("role", "dialog");
    pop.innerHTML = `<div class="rel-head"><b>Related events</b> <span class="muted small">${esc(me ? me.label.slice(0, 90) : "")}</span><button type="button" class="rel-x" aria-label="Close">✕</button></div>
      ${S.corr?.classes?.[id] ? `<div class="rel-inputs" data-inputs="${esc(id)}" style="padding:0 10px 4px"><div class="small muted">Loading the events passed in…</div></div>` : ""}
      ${(window.__oeExtra?.related_n?.[id] || 0) > rel.length ? `<div class="small muted" style="padding:4px 10px">showing the ${rel.length} most confident of ${window.__oeExtra.related_n[id]} related events</div>` : ""}
      ${tuneHtml(id) ? `<div style="padding:4px 10px">${tuneHtml(id)}</div>` : ""}
      <div class="rel-story">${rel.map((r) => { const e = S.corr.events[r.id] || { label: r.id, type: "", link: "#" }; const [tl, tc] = TYPE[e.type] || TYPE[{ f: "finding" }[e.type]] || [e.type, ""];
        const ai = r.llm === "yes" ? `<span class="rel-ai yes" title="Confirmed (confidence ${Math.round((r.llm_conf || 0) * 100)}%)">✓ confirmed</span> ${clefLinkHtml(r)} ${aiFlare({ model: r.llm_model, via: "correlation review" })}`
          : `<span class="rel-ai pend" title="The decision model has not decided this link yet">AI review pending</span>`;
        return `<a class="rel-item" href="${esc(e.link || "#")}"><span class="rel-l">${esc(e.label.length > 120 ? e.label.slice(0, 118) + "…" : e.label)}</span>
          <span class="rel-time small muted">${esc(evTime(e))} · <span class="rel-pair" title="event pair">${esc(pairText(me?.type, e.type))}</span></span>
          <span class="rel-tags"><span class="badge ${tc}">${esc(tl)}</span> ${ai}</span>
          ${tuneHtml(r.id)}
          ${r.llm_reason ? `<span class="rel-why small">${esc(r.llm_reason)}</span>` : ""}
          ${artifactsHtml(ipArts(e, r.llm_artifacts))}
          ${(r.why || []).length ? `<span class="rel-why small muted">${r.llm_reason ? "Script: " : ""}${esc(r.why.join(" · "))}</span>` : ""}</a>`; }).join("")}</div>
      <div class="small muted" style="padding:6px 10px">${esc(llmLine())}</div>`;
    document.body.appendChild(pop);
    const r = btn.getBoundingClientRect(), w = Math.min(520, innerWidth - 16);
    pop.style.width = w + "px";
    pop.style.left = Math.max(8, Math.min(innerWidth - w - 8, r.right - w)) + "px";
    const below = r.bottom + 6, h = pop.offsetHeight;
    pop.style.top = (below + h > innerHeight - 8 && r.top - h - 6 > 8 ? r.top - h - 6 : Math.min(below, innerHeight - Math.min(h, innerHeight - 16) - 8)) + "px";
    pop.querySelector(".rel-x").onclick = close;
    loadInputs(pop);
  }
  const safeUrl = (u) => /^https?:\/\//i.test(String(u || "")) ? u : "";
  function openNote(btn) {
    close();
    const id = btn.dataset.note, n = S.corr?.notes?.[id], me = S.corr?.events?.[id] || (n ? { label: n.label || String(id).split("|").slice(1).join(" · ") } : null);
    if (!n) return;
    const links = (n.links || []).filter((l) => safeUrl(l.url));
    pop = document.createElement("div"); pop.className = "rel-pop note-pop"; pop.setAttribute("role", "dialog");
    pop.innerHTML = `<div class="rel-head"><b>Research notes</b> ${aiFlare({ model: n.model, via: n.via || "event enrichment", at: n.at ? new Date(n.at * 1000).toISOString() : "" })}
        <span class="muted small">${esc(me ? me.label.slice(0, 90) : "")}</span><button type="button" class="rel-x" aria-label="Close">✕</button></div>
      <div class="note-body">
        <div><span class="note-v v-${esc(String(n.verdict || "").replace(/[^a-z-]/g, ""))}">${esc(n.verdict || "")}</span> <span class="badge">${esc(n.priority || "")}</span>
          ${n.same_event ? "" : `<span class="small muted">written for an earlier run of this finding (${esc(n.snapshot || "")}); numbers may differ</span>`}</div>
        ${n.summary ? `<p><b>${esc(n.summary)}</b></p>` : ""}
        ${n.research ? `<div class="note-research">${esc(n.research)}</div>` : ""}
        ${artifactsHtml((n.queries || []).map((d) => ({ kind: "query", value: d.kql || d.index || "search", relation: d.why, model: n.model, at: n.at, query: d })), "Elasticsearch searches (open in Kibana)")}
        ${links.length ? `<div class="small"><b>Sources</b><ol class="note-links">${links.map((l) => `<li><a href="${esc(safeUrl(l.url))}" target="_blank" rel="noopener noreferrer">${esc(l.title || l.url)}</a></li>`).join("")}</ol></div>` : ""}
        <div class="small muted">AI research (on request, or copied by the event reviewer). Verify before acting.</div>
      </div>`;
    document.body.appendChild(pop);
    const r = btn.getBoundingClientRect(), w = Math.min(560, innerWidth - 16);
    pop.style.width = w + "px";
    pop.style.left = Math.max(8, Math.min(innerWidth - w - 8, r.right - w)) + "px";
    const below = r.bottom + 6, h = pop.offsetHeight;
    pop.style.top = (below + h > innerHeight - 8 && r.top - h - 6 > 8 ? r.top - h - 6 : Math.min(below, innerHeight - Math.min(h, innerHeight - 16) - 8)) + "px";
    pop.querySelector(".rel-x").onclick = close;
  }
  // AI verdict pop-up: the 🏷 label button, and every tappable verdict badge (.vd-tap: label, Pending review, Not reviewed,
  // Posture's "🤖 AI reviewer: expected" check-off flair). Shows what the page already has at once, then GET /api/verdict
  // (loaded on tap only) adds the stored label for rows outside the loaded data and what auto-close did with the event.
  const isoAt = (t) => (t ? new Date(t * 1000).toISOString() : "");
  const AC_STATE = { closed: "checked off (closed)", reopened: "reopened by a person", "reopened-verdict": "reopened: the verdict changed", expired: "reopened: the AI closure expired (the event repeated)", suppressed: "now suppressed by a rule" };
  function verdictBody(id, c, me, V) {
    const ac = V?.autoclose || [], canAck = ["admin", "defender"].includes(S.me?.role);
    const head = !c ? `<div class="small muted">${V ? "The event reviewer has not labelled this event." : "Loading…"}</div>`
      : `<div>${c.label === "pending" ? pendBadge(c) : c.label === "unreviewed" ? unrevBadge(c) : `<span class="note-v v-${esc(String(c.label).replace(/[^a-z-]/g, ""))}">${esc(c.label)}</span>${c.confidence != null ? ` <span class="small muted">confidence ${Math.round((c.confidence || 0) * 100)}%</span>` : ""} ${pendBadge(c)}`}</div>`;
    const when = c && c.at ? `<div class="small muted" style="margin-top:4px">Reviewed ${esc(ft(isoAt(c.at)))}${c.model ? " · " + esc(String(c.model).split(" + ").pop()) + " (event reviewer)" : ""}</div>` : "";
    const why = !c ? "" : c.label === "pending" ? `<div class="small" style="margin-top:4px"><b>Why pending:</b> ${esc(pendTitle(c.pending))}${c.pending?.queued ? " Queued: the event opened after the event reviewer's last pass." : ""}</div>`
      : c.label === "unreviewed" ? `<div class="small" style="margin-top:4px"><b>Why not reviewed:</b> ${esc(c.unreviewed || c.reason || "no reason recorded")}</div>`
      : `${c.pending ? `<div class="small muted" style="margin-top:4px">${esc(pendTitle(c.pending))}</div>` : ""}${c.owner ? `<div style="margin-top:4px">${ownerHtml(c)}</div>` : ""}<p>${reasonHtml(c.reason, c.sources)}</p>${sourcesHtml(c.sources)}`;
    const acHtml = !V ? "" : !ac.length ? `<div class="small muted" style="margin-top:6px">Auto-close: has not acted on this event.</div>`
      : `<div class="small" style="margin-top:6px"><b>Auto-close</b>${ac.map((r) => `<div class="vd-ac">${r.state === "closed" ? "🤖" : "↩"} ${esc(AC_STATE[r.state] || r.state)} · ${esc(ft(r.state === "expired" ? r.closed_at || r.at : r.at))}
          · verdict <b>${esc(r.verdict || "")}</b> from the ${r.source === "person" ? "person's verdict" : r.source === "reviewer" ? "event reviewer" : "research note"}${r.refs ? ` · ${r.refs} grouped item${r.refs === 1 ? "" : "s"}` : ""}
          ${r.can_reopen && canAck ? ` <button type="button" class="vd-reopen" data-t="${esc(r.type)}" data-k="${esc(r.key)}" title="Un-check it: back to the open findings; auto-close will not close it again">Reopen</button>` : ""}</div>`).join("")}</div>`;
    // phone-push gate (pushgate.py): a suppressed push gets a small note; a held / fail-safe push says so too
    const PG = { suppressed: (r) => `📵 push suppressed (${r.verdict || "expected"})`, held: () => "⏳ phone alert held until the AI verdict",
      "pushed-unavailable": () => "📱 pushed: AI review unavailable", pushed: (r) => `📱 pushed${r.verdict ? " with verdict " + r.verdict : ""}` };
    const pgHtml = (V?.push || []).filter((r) => PG[r.state]).slice(0, 3).map((r) => `<div class="small muted vd-push" title="${esc(r.why || "")}">${esc(PG[r.state](r))}${r.at ? " · " + esc(ft(isoAt(r.at))) : ""}</div>`).join("");
    const ev = V?.event?.label ? `<div class="small muted">${V.event.link ? `<a href="${esc(V.event.link)}">${esc(V.event.label.slice(0, 120))}</a>` : esc(V.event.label.slice(0, 120))}</div>` : "";
    const eid = V?.eid || id;
    return `<div class="rel-head"><b>AI verdict</b> ${c && c.model ? aiFlare({ model: String(c.model).split(" + ").pop(), via: "event reviewer", at: isoAt(c.at) }) : ""}
        <span class="muted small">${esc(me ? me.label.slice(0, 90) : "")}</span><button type="button" class="rel-x" aria-label="Close">✕</button></div>
      <div class="note-body">${ev}${head}${when}${why}${acHtml}${pgHtml}
        ${eid ? `<div class="rel-inputs" data-inputs="${esc(eid)}"><div class="small muted">Loading the events reviewed together…</div></div>` : ""}
        <div class="small muted">Label and reason from the event reviewer once all of this event's links were decided; it labels the whole correlated group (listed above) in one call. A person's verdict outweighs it. Verify before acting.</div></div>`;
  }
  function place(btn, w0) {
    const r = btn.getBoundingClientRect(), w = Math.min(w0, innerWidth - 16);
    pop.style.width = w + "px";
    pop.style.left = Math.max(8, Math.min(innerWidth - w - 8, r.right - w)) + "px";
    const below = r.bottom + 6, h = pop.offsetHeight;
    pop.style.top = (below + h > innerHeight - 8 && r.top - h - 6 > 8 ? r.top - h - 6 : Math.min(below, innerHeight - Math.min(h, innerHeight - 16) - 8)) + "px";
  }
  function openVerdict(btn) {
    close();
    const id = btn.dataset.cls || btn.dataset.vd || "", t = btn.dataset.vdt || "", k = btn.dataset.vdk || "";
    const X = window.__oeExtra || {}, c0 = S.corr?.classes?.[id] || X.classes?.[id], me = S.corr?.events?.[id];
    pop = document.createElement("div"); pop.className = "rel-pop note-pop vd-pop"; pop.setAttribute("role", "dialog"); pop._for = btn;
    const draw = (c, V) => { pop.innerHTML = verdictBody(id, c, me, V); pop.querySelector(".rel-x").onclick = close; place(btn, 460); loadInputs(pop); };
    document.body.appendChild(pop);
    draw(c0, null);
    const mine = pop;
    api(`/api/verdict?e=${encodeURIComponent(id)}&t=${encodeURIComponent(t)}&k=${encodeURIComponent(k)}`).then((V) => {
      if (pop !== mine) return;
      draw(V.class || c0, V);
    }).catch((e) => { if (pop === mine) pop.querySelector(".note-body").insertAdjacentHTML("beforeend", `<div class="small muted">Could not load the stored verdict: ${esc(e.message || e)}</div>`); });
  }
  window.openVerdict = openVerdict;
  document.addEventListener("click", async (e) => {
    const b = e.target.closest?.(".vd-reopen"); if (!b) return;
    e.preventDefault(); e.stopPropagation(); b.disabled = true;
    try { await apiPost("/api/verdict/reopen", { type: b.dataset.t, key: b.dataset.k }); S.acks = await api("/api/acks"); b.replaceWith(Object.assign(document.createElement("span"), { className: "muted", textContent: "reopened ✓" })); rerender(); }
    catch (err) { b.disabled = false; alert(String(err.message || err)); }
  }, true);
  // ---- event pair label ("Alarm – IDS") and "never send to the AI" rules for watcher alerts (shared with alerts.js / aireview.js)
  const PAIR_NAME = { alert: "Alert", finding: "Finding", f: "Finding", ids: "IDS", admin: "Admin", adm: "Admin", host: "Endpoint", hf: "Endpoint", ti: "Threat intel", vuln: "Vulnerability", iss: "Vulnerability", gw: "Gateway", alarm: "Triage alarm" };
  window.pairText = (a, b) => `${PAIR_NAME[a] || a} – ${PAIR_NAME[b] || b}`;
  window.pairKey = (a, b) => [a, b].sort().join("-");
  const canMute = () => ["admin", "defender"].includes(S.me?.role);
  const alertName = (label) => { const g = String(label || "").replace(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g, "*").replace(/\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b/gi, "*").replace(/\d+(?:[.,:]\d+)*/g, "*").replace(/\*(?:[\s,/()-]*\*)+/g, "*"); return "*" + g.replace(/…$/, "").trim().replace(/^\*+|\*+$/g, "") + "*"; };
  const alertHost = (label) => (String(label || "").match(/\b\d{1,3}(?:\.\d{1,3}){3}\b/) || String(label || "").match(/\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b/i) || [""])[0];
  window.alertMuteHtml = (label) => { return ""; /* never-send mute rules removed */ if (!canMute()) return ""; const h = alertHost(label);
    return `<span class="mute-btns small" data-label="${esc(label)}"><button type="button" class="mute-btn" data-mute="name" title="Mute alerts like this: never send them to the AI, clear the ones already raised and clear future ones automatically. You can edit the pattern.">mute name…</button>`
      + `<button type="button" class="mute-btn" data-mute="host" ${h ? "" : "disabled"} title="${h ? `Only for host ${esc(h)}` : "no host in this alert"}">mute name + host…</button>`
      + `<button type="button" class="mute-btn mute-sup" data-mute="suppress" title="Suppress: hide alerts like this from the feed but keep them in correlation, research and review. You can edit the pattern and pick an artifact of the alert or of its correlated events."><i class="ic ic-ban" aria-hidden="true"></i> suppress…</button></span>`; };
  // ---- Suppress dialog (button next to a check-off box): hide an event by signature name (+ one artifact), keep it in correlation
  let lastClick = null; document.addEventListener("click", (e) => { lastClick = e.target; }, true);
  const globRe = (g) => new RegExp("^" + String(g).replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".") + "$", "i");
  window.suppressDialog = (type, key, fallbackLabel, from) => suppressOpen(type, key, fallbackLabel, from).catch((e) => {
    try { fetch("/api/audit/view", { method: "POST", headers: { "Content-Type": "application/json", "X-Netmon": "1" }, body: JSON.stringify({ route: `suppress:error ${type}|${String(key).slice(0, 80)} ${String(e && (e.stack || e.message) || e).slice(0, 300)}` }) }).catch(() => {}); } catch (_) {}
    alert("Could not open the suppress dialog: " + (e.message || e));
  });
  const suppressOpen = async (type, key, fallbackLabel, from) => {
    const trig = from && from.isConnected ? from : lastClick && lastClick.isConnected ? lastClick : null;
    const cardOf = () => trig && (trig.closest(".card") || trig.closest("section, details, .panel") || null);
    const card = cardOf();
    // open the dialog right away (inside the tap) and fill the artifact list when /suggest answers: on iPhone the
    // 0.5-3 s wait before anything appeared left the tap looking dead, and the dialog sometimes never showed
    const diag = (stage, info) => { try { fetch("/api/audit/view", { method: "POST", headers: { "Content-Type": "application/json", "X-Netmon": "1" }, body: JSON.stringify({ route: `suppress:${stage} ${type}|${String(key).slice(0, 80)}${info ? " " + String(info).slice(0, 200) : ""}` }) }).catch(() => {}); } catch (_) {} };
    const sg = { label: fallbackLabel || "", artifacts: [] };
    let A = [];
    const TL = { ip: "🌐 IP", domain: "🔗 domain", user: "👤 user", process: "⚙️ process", port: "🔌 port", file: "📄 file" };
    const grp = (src, title) => { const l = A.filter((a) => a.from === src); return l.length ? `<optgroup label="${src === "event" ? "📍" : "🔗"} ${title}">${l.map((a) => `<option value="${A.indexOf(a)}">${esc(TL[a.type] || a.type)}: ${esc(a.value.length > 70 ? a.value.slice(0, 70) + "…" : a.value)}</option>`).join("")}</optgroup>` : ""; };
    const d = document.createElement("div"); d.className = "modal-back";
    d.innerHTML = `<div class="modal" role="dialog" aria-modal="true">
      <h3>🚫 Suppress this finding</h3>
      <div class="small muted" style="margin-bottom:8px">Instead of checking it off, suppress it: it is hidden everywhere (the rule is listed under <b>Settings → Configuration → Suppress rules</b>), and alerts like it stop appearing. It still goes through correlation, research and review, but the event reviewer never un-suppresses it. Edit the signature (<span class="mono">*</span> any text, <span class="mono">?</span> one character) and optionally require one artifact of this event or of the events correlated with it.</div>
      <div class="small mono sp-label" style="margin-bottom:6px;opacity:.8">${esc(sg.label)}</div>
      <input class="sp-name" value="${esc(alertName(sg.label))}" style="width:100%;box-sizing:border-box" title="Signature name">
      <div style="display:flex;gap:6px;margin-top:6px;flex-wrap:wrap;align-items:center"><span class="small">Only when it involves</span>
        <select class="sp-pick" style="max-width:100%"><option value="">(no artifact: name only)</option><option value="" disabled class="sp-loading">loading artifacts…</option><option value="other">other…</option></select></div>
      <div class="sp-other" style="display:none;gap:6px;margin-top:6px;flex-wrap:wrap"><select class="sp-type"><option value="ip">🌐 IP</option><option value="domain">🔗 domain</option><option value="user">👤 user</option><option value="process">⚙️ process</option><option value="port">🔌 port</option><option value="file">📄 file</option></select>
        <input class="sp-val" placeholder="value (* ? allowed)" size="30"></div>
      <div class="small muted sp-rel" style="margin-top:4px"></div>
      <div class="actions"><button type="button" class="sp-ok primary">Suppress</button><button type="button" class="sp-cancel">Cancel</button><span class="small sp-msg"></span></div></div>`;
    document.body.appendChild(d);
    const q = (c) => d.querySelector(c), close = () => d.remove();
    q(".sp-pick").onchange = () => { const v = q(".sp-pick").value; q(".sp-other").style.display = v === "other" ? "flex" : "none";
      const a = v && v !== "other" ? A[+v] : null; q(".sp-rel").textContent = a?.from === "correlated" ? `From the correlated event: ${a.rel}` : ""; };
    q(".sp-cancel").onclick = close; window.backdropClose(d, close);
    q(".sp-ok").onclick = async () => {
      const name = q(".sp-name").value.trim(), pv = q(".sp-pick").value;
      const a = pv === "other" ? { type: q(".sp-type").value, value: q(".sp-val").value.trim() } : pv ? A[+pv] : { type: "", value: "" };
      if (!name.replace(/[*?]/g, "").trim()) { q(".sp-msg").textContent = "Enter some text that is not just wildcards."; return; }
      q(".sp-ok").disabled = true; q(".sp-msg").textContent = "saving…";
      try { await apiPost("/api/llm/review-limits", { suppress: { name, art_type: a.type, art: a.value } }); S.acks = await api("/api/acks"); S.corr = null;
        // also check off every other event in the same card that this suppression matches
        if (card) {
          const re = name.includes("*") || name.includes("?") ? globRe(name) : globRe("*" + name + "*"), av = (a.value || "").trim(), are = av ? globRe(/[*?]/.test(av) ? av : "*" + av + "*") : null;
          const todo = [...card.querySelectorAll("input.ack-cb:not(:checked)")].filter((i) => i.dataset.t !== "seg" && re.test(i.dataset.l || "") && (!are || are.test(i.dataset.l || "")));
          for (const i of todo) { try { S.acks = await apiPost("/api/acks", { type: i.dataset.t, key: i.dataset.k, checked: true, label: i.dataset.l, note: "suppressed: rule " + name }); } catch (_) {} }
        }
        close(); rerender(); }
      catch (e) { q(".sp-ok").disabled = false; q(".sp-msg").textContent = "error: " + (e.message || e); }
    };
    if (!window.touchUI()) q(".sp-name").focus();  // phones: no keyboard pop-up / zoom that shifts the dialog under the finger
    if (window.touchUI()) { const r = d.querySelector(".modal").getBoundingClientRect(); diag("open", `vp=${innerWidth}x${innerHeight} vv=${Math.round(visualViewport?.width || 0)}x${Math.round(visualViewport?.height || 0)}@${(visualViewport?.scale || 1).toFixed(2)} top=${Math.round(r.top)} h=${Math.round(r.height)}`); }
    let edited = false; q(".sp-name").addEventListener("input", () => { edited = true; }, { once: true });
    try {
      const got = await api(`/api/suppress/suggest?type=${encodeURIComponent(type)}&key=${encodeURIComponent(key)}`);
      if (!d.isConnected) return;
      if (got.label) { sg.label = got.label; q(".sp-label").textContent = got.label; if (!edited) q(".sp-name").value = alertName(got.label); }
      A = got.artifacts || [];
      q(".sp-loading").insertAdjacentHTML("afterend", grp("event", "This event") + grp("correlated", "Correlated events"));
    } catch (e) { diag("suggest-error", e.message || e); }
    if (d.isConnected) q(".sp-loading").remove();
  };
  // Mute: opens an editable pattern (wildcards * ?, no wildcard = "contains"); saving also clears alerts already raised
  document.addEventListener("click", async (e) => {
    const b = e.target.closest(".mute-btn"), cancel = e.target.closest(".mute-cancel"), ok = e.target.closest(".mute-ok");
    if (!b && !cancel && !ok) return;
    e.preventDefault(); e.stopPropagation();
    const wrap = (b || cancel || ok).closest(".mute-btns"), label = wrap.dataset.label;
    if (b && b.dataset.mute === "suppress") { window.suppressDialog("alert", label, label); return; }  // same dialog as findings: artifacts of the alert and of its correlated events
    if (b) {
      const host = b.dataset.mute === "host" ? alertHost(label) : "";
      wrap.dataset.orig = wrap.innerHTML; wrap.dataset.host = host; wrap.dataset.mode = b.dataset.mute === "suppress" ? "suppress" : "";
      wrap.style.cssText = "display:inline-flex;flex-wrap:wrap;gap:4px;align-items:center";
      wrap.innerHTML = `<input class="mute-pat" value="${esc(alertName(label))}" size="46" title="Part of the alert text. Use * for any text, ? for one character."> ${host ? `<span class="small">only host <b>${esc(host)}</b></span>` : ""}
        ${b.dataset.mute === "suppress" ? `<select class="mute-art"><option value="">no artifact</option><option value="ip">IP</option><option value="user">user</option><option value="process">process</option><option value="port">port</option><option value="file">file</option></select><input class="mute-artv" placeholder="artifact value" size="16">` : ""}
        <button type="button" class="mute-ok">${b.dataset.mute === "suppress" ? "Suppress" : "Mute &amp; clear existing"}</button><button type="button" class="mute-cancel">Cancel</button>
        <span class="muted small" style="flex-basis:100%">Edit the pattern to match less or more (e.g. <span class="mono">*New device*</span>). Saving keeps this as a mute rule (see Alerts › Alert mute rules): matching alerts are cleared now and automatically whenever they arrive; Show cleared lists them.</span>`;
      wrap.querySelector(".mute-pat").focus(); return;
    }
    if (cancel) { wrap.innerHTML = wrap.dataset.orig; return; }
    const pat = wrap.querySelector(".mute-pat").value.trim();
    if (!pat.replace(/[*?]/g, "").trim()) { alert("Enter some text that is not just wildcards."); return; }
    if (wrap.dataset.mode === "suppress") {
      ok.disabled = true;
      try {
        const sup = { name: pat, art_type: wrap.querySelector(".mute-art")?.value || "", art: wrap.querySelector(".mute-artv")?.value.trim() || "" };
        const r = await apiPost("/api/llm/review-limits", { suppress: sup });
        wrap.innerHTML = `<span class="muted">suppressed ✓ ${esc(pat)}${sup.art_type ? " + " + esc(sup.art_type) + " " + esc(sup.art) : ""} · hid ${r.cleared_alerts || 0} alert(s)${r.cleared_open ? ", closed " + r.cleared_open + " open finding(s)" : ""}; still correlated</span>`; S.corr = null;
        if (/^#\/(alerts|aireview|events)/.test(location.hash)) setTimeout(() => refreshData(), 1200);
      } catch (err) { ok.disabled = false; alert(String(err.message || err)); }
      return;
    }
    const rule = { name: pat, scope: "both" }; if (wrap.dataset.host) rule.host = wrap.dataset.host;
    ok.disabled = true;
    try {
      const r = await apiPost("/api/llm/review-limits", { rule, clear_alerts: true });
      wrap.innerHTML = `<span class="muted">muted ✓ ${esc(pat)}${rule.host ? " @ " + esc(rule.host) : ""} · cleared ${r.cleared_alerts || 0} alert(s)</span>`; S.corr = null;
      if (/^#\/(alerts|aireview|events)/.test(location.hash)) setTimeout(() => refreshData(), 1200);
    } catch (err) { ok.disabled = false; alert(String(err.message || err)); }
  }, true);
  // Triage alarm title -> the best-matching underlying event (host finding, new device, IDS, gateway, TI, admin ...)
  const GO_RANK = { host: 3, finding: 3, admin: 3, gw: 2, ti: 2, alert: 2, ids: 1, vuln: 0 };
  function alarmTarget(id) {
    const rel = (S.corr?.related?.[id] || []).filter((r) => S.corr.events?.[r.id] && S.corr.events[r.id].type !== "alarm" && S.corr.events[r.id].link);
    rel.sort((a, b) => ((GO_RANK[S.corr.events[b.id].type] ?? 0) + (b.llm === "yes" ? 3 : 0) + (b.score || 0)) - ((GO_RANK[S.corr.events[a.id].type] ?? 0) + (a.llm === "yes" ? 3 : 0) + (a.score || 0)));
    return rel[0] ? S.corr.events[rel[0].id] : null;
  }
  document.addEventListener("click", (e) => {
    const go = e.target.closest(".alarm-go");
    if (go) {
      e.preventDefault(); e.stopPropagation();
      const t = alarmTarget(go.dataset.alarmEv);
      if (t) { location.hash = t.link.replace(/^#/, ""); return; }
      const b = go.closest(".alarm")?.querySelector(".rel-btn");
      go.title = S.corr ? "No matching event found for this alarm" : "Correlations still loading - try again";
      if (b && !b.disabled) open(b); else go.classList.add("nomatch");
      return;
    }
    const cbt = e.target.closest(".cls-btn, .vd-tap");
    if (cbt) { e.stopPropagation(); e.preventDefault(); if (pop && pop._for === cbt) return close(); openVerdict(cbt); return; }
    const nbt = e.target.closest(".note-btn");
    if (nbt) { e.stopPropagation(); e.preventDefault(); if (pop && pop._for === nbt) return close(); openNote(nbt); if (pop) pop._for = nbt; return; }
    if (pop && pop.classList.contains("note-pop") && e.target.closest(".note-pop a")) return;
    const b = e.target.closest(".rel-btn");
    if (b) { e.stopPropagation(); e.preventDefault(); if (pop && pop._for === b) return close(); open(b); if (pop) pop._for = b; return; }
    if (pop && !e.target.closest(".rel-pop")) close();
    if (e.target.closest(".rel-item")) close();
  }, true);
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") close();
    const v = (e.key === "Enter" || e.key === " ") && e.target.closest?.(".vd-tap"); if (v) { e.preventDefault(); openVerdict(v); } });
  addEventListener("scroll", close, { passive: true });
  addEventListener("hashchange", close);
  let q = false;
  new MutationObserver(() => { if (q) return; q = true; setTimeout(() => { q = false; if (main.querySelector(".rel-btn")) ensure(); }, 30); }).observe(main, { childList: true, subtree: true });
})();
