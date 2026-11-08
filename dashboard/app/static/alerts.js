// Urgent alerts: in-app feed (#/alerts), unread bell, and browser/phone push notifications (service worker sw.js).
(() => {
  const A = { list: [], unread: 0, lastTop: null, mode: "all", showAll: false };
  const b64ToU8 = (s) => { const p = "=".repeat((4 - (s.length % 4)) % 4); const r = atob((s + p).replace(/-/g, "+").replace(/_/g, "/")); return Uint8Array.from(r, (c) => c.charCodeAt(0)); };
  const pushOK = () => "serviceWorker" in navigator && "PushManager" in window && "Notification" in window;
  const isIOS = /iP(hone|ad|od)/.test(navigator.userAgent), standalone = matchMedia("(display-mode: standalone)").matches || navigator.standalone;
  let swReg = null;
  if ("serviceWorker" in navigator) navigator.serviceWorker.register("/sw.js", { scope: "/" }).then((r) => { swReg = r; }).catch((e) => console.warn("sw", e));

  async function currentSub() { if (!pushOK()) return null; const r = swReg || await navigator.serviceWorker.ready; return r.pushManager.getSubscription(); }
  async function enable() {
    const perm = await Notification.requestPermission();
    if (perm !== "granted") throw new Error(perm === "denied" ? "Notifications are blocked for this site in your browser settings." : "Permission not granted.");
    const { key } = await api("/api/push/key");
    const r = swReg || await navigator.serviceWorker.ready;
    let sub = await r.pushManager.getSubscription();
    if (!sub) sub = await r.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: b64ToU8(key) });
    await apiPost("/api/push/subscribe", { subscription: sub.toJSON() });
    return sub;
  }
  window.netmonPush = { ok: pushOK, enable, current: currentSub, isIOS, standalone };  // used by the new-user walkthrough (welcome.js)
  async function disable() { const s = await currentSub(); if (s) { await apiPost("/api/push/unsubscribe", { endpoint: s.endpoint }); await s.unsubscribe(); } }

  function paintCount() {
    document.querySelectorAll(".alert-count").forEach((e) => { e.textContent = A.unread > 99 ? "99+" : A.unread; e.style.display = A.unread ? "" : "none"; });
    document.title = (A.unread ? `(${A.unread}) ` : "") + "netmon" + (SITE.site_name ? " · " + SITE.site_name : "");
  }
  async function poll() {
    try {
      const r = await api("/api/alerts?limit=200");
      A.list = r.alerts; A.mode = r.mode; A.unread = r.mode === "some" ? r.unread_mine : r.unread; paintCount();
      const top = A.list[0]?.id ?? null;
      // a new alert: refresh the page in place (rerender builds it off-screen and swaps only the boxes that changed, so
      // nothing blanks or flashes); never while a detail window is open or the tab is hidden
      if (location.hash.startsWith("#/alerts") && top !== A.lastTop && A.lastTop !== null) A.stale = true;
      if (A.stale && location.hash.startsWith("#/alerts") && !document.hidden && !document.querySelector(".oe-back, .modal-back")) { A.stale = false; rerender(); }
      A.lastTop = top;
    } catch (_) { /* logged out / offline */ }
  }
  setInterval(poll, 60000); document.addEventListener("visibilitychange", () => { if (!document.hidden) poll(); }); poll();

  // ---- device picker: which devices a user gets alerts for. Used here (self) and on the Users page (assign to a user) ----
  // o: {prefs, devices, save(mode, devs) -> message, title, intro, allLabel, someLabel}
  let pickerN = 0;
  function devicePicker(o) {
    const { prefs, devices } = o, rn = "dpm" + ++pickerN;
    let mode = prefs.mode, sel = new Set(prefs.devices), q = "";
    const c = card(o.title, "");
    const label = (d) => d.name || d.ips[0] || d.mac || d.id;
    const draw = () => {
      const vis = devices.filter((d) => !q || `${label(d)} ${d.ips.join(" ")} ${d.mac}`.toLowerCase().includes(q))
        .sort((a, b) => (sel.has(b.id) ? 1 : 0) - (sel.has(a.id) ? 1 : 0));  // chosen devices first
      c.innerHTML = `${o.title ? `<h2>${esc(o.title)}</h2>` : ""}
        <div class="small muted" style="margin-bottom:8px">${o.intro}</div>
        ${o.noAll ? "" : `<label class="dp-opt"><input type="radio" name="${rn}" value="all" ${mode === "all" ? "checked" : ""}> <b>All devices</b> — every urgent alert</label>`}
        <label class="dp-opt"><input type="radio" name="${rn}" value="some" ${mode === "some" ? "checked" : ""}> <b>${esc(o.someLabel || "Only devices I choose")}</b> ${sel.size ? `<span class="muted">(${sel.size} selected)</span>` : ""}</label>
        <div class="dp-list" style="${mode === "some" ? "" : "display:none"}">
          <div class="tbltools"><input type="search" placeholder="Filter devices…" value="${esc(q)}"><button class="dp-none" type="button">Clear</button></div>
          <div class="dp-items">${vis.map((d) => `<label class="dp-item"><input type="checkbox" value="${esc(d.id)}" ${sel.has(d.id) ? "checked" : ""}>
             <span><b>${esc(label(d))}</b>${d.endpoint ? ' <span class="badge sev-info">endpoint</span>' : ""}${d.known ? "" : ' <span class="badge sev-unknown">unknown</span>'}<br><span class="muted small mono">${esc([...d.ips.slice(0, 2), d.mac].filter(Boolean).join(" · "))}</span></span></label>`).join("") || '<div class="empty">No match.</div>'}</div>
        </div>
        <div style="margin-top:10px;display:flex;gap:8px;align-items:center"><button class="dp-save">Save</button>${o.cancel ? '<button class="dp-cancel" type="button">Cancel</button>' : ""}<span class="dp-msg small"></span></div>`;
      c.querySelector(".dp-cancel")?.addEventListener("click", o.cancel);
      c.querySelectorAll(`input[name=${rn}]`).forEach((r) => r.onchange = () => { mode = r.value; draw(); });
      const s = c.querySelector(".dp-list input[type=search]");
      s.oninput = () => { q = s.value.toLowerCase(); const pos = s.selectionStart; draw(); const n = c.querySelector(".dp-list input[type=search]"); n.focus(); n.setSelectionRange(pos, pos); };
      c.querySelectorAll(".dp-items input").forEach((b) => b.onchange = () => { b.checked ? sel.add(b.value) : sel.delete(b.value); c.querySelector(".dp-opt:nth-of-type(2) .muted")?.replaceChildren(`(${sel.size} selected)`); });
      c.querySelector(".dp-none").onclick = () => { sel.clear(); draw(); };
      c.querySelector(".dp-save").onclick = async () => {
        const m = c.querySelector(".dp-msg");
        try { m.style.color = "var(--good)"; m.textContent = await o.save(mode, [...sel]); }
        catch (e) { m.style.color = "var(--bad)"; m.textContent = String(e.message || e); }
      };
    };
    draw();
    return c;
  }
  window.devicePicker = devicePicker;
  const myPicker = async () => { const { prefs, devices, locked } = await api("/api/push/prefs"); A.myMode = "some"; A.myN = prefs.mode === "some" ? prefs.devices.length : 0;
    if (locked) return card("Your devices", devices.length  // User role: assigned by an admin, read-only
      ? `<div class="small muted" style="margin-bottom:6px">You get alerts and notifications for these devices, assigned by an admin.</div><ul style="margin:0;padding-left:18px">${devices.map((d) => `<li><b>${esc(d.name || d.ips[0] || d.mac || d.id)}</b> <span class="muted small mono">${esc([...d.ips.slice(0, 2), d.mac].filter(Boolean).join(" · "))}</span></li>`).join("")}</ul>`
      : `<div class="empty">No devices are assigned to your account yet. Ask an admin.</div>`);
    A.myMode = prefs.mode;
    return devicePicker({ prefs, devices, title: "Which devices alert me",
      intro: "Applies to your account on every browser/phone where you enabled notifications, and to the 🔔 count. Alerts that aren't tied to a specific device go only to people watching all devices. Admins can also assign devices to you on the Users page.",
      save: async (mode, devs) => { await apiPost("/api/push/prefs", { mode, devices: devs }); A.myMode = mode; A.myN = devs.length; paintBar(); await poll();
        return mode === "all" ? "Saved — you'll get every urgent alert." : `Saved — alerts only for ${devs.length} device${devs.length === 1 ? "" : "s"}.`; } }); };
  // settings live in a collapsed bar; clicking it slides the panel down
  const barSummary = async () => { const sub = pushOK() ? await currentSub().catch(() => null) : null;
    return `Push on this device: <b>${sub ? "on" : "off"}</b> · Alerting on: <b>${A.myMode === "some" ? `${A.myN} device${A.myN === 1 ? "" : "s"}` : "all devices"}</b>`; };
  async function paintBar() { const s = document.querySelector("#alSetBar .sb-sum"); if (s) s.innerHTML = await barSummary(); }

  // ---- verdicts, research and notes per alert (admin / defender): /api/alerts?extra=1 (alarm feed), ?held=1&v= (detections) ----
  const VORD = ["suspicious", "expected", "benign", "unreviewed"], VSRC = { person: "a person's verdict", ai: "event reviewer (AI)" };
  const TYPE_OF = { f: "finding", hf: "host", ids: "ids", ti: "ti", adm: "admin", iss: "vuln", gw: "gw", alert: "alert" };
  const X = () => window.__oeExtra || {};
  const mergeExtra = (e) => { const W = window.__oeExtra = window.__oeExtra || {};
    for (const [k, v] of Object.entries(e || {})) W[k] = v && typeof v === "object" && !Array.isArray(v) ? { ...(W[k] || {}), ...v } : v;
    S.corr = S.corr || {}; S.corr.events = S.corr.events || {}; S.corr.unotes = { ...(S.corr.unotes || {}), ...(e?.unotes || {}) }; };
  const vChip = (a) => a.verdict === "unreviewed" || !a.verdict ? `<span class="muted small" title="No verdict yet from a person, the event reviewer or the decision model">not reviewed</span>`
    : `<span class="note-v v-${esc(a.verdict)}" title="${esc(VSRC[a.vsrc] || "")}">${a.vsrc === "person" ? "👤 " : ""}${esc(a.verdict)}</span>${a.vsrc === "ai" ? ` <span class="small muted">AI ${Math.round((X().classes?.[a.eid]?.confidence || 0) * 100)}%</span>` : a.vsrc === "model" ? ` <span class="small muted">model</span>` : ""}`;
  // the event reviewer's paragraph (context + why the verdict + what research found), shown in full under the alert for every role
  const revOf = (a) => a.review || X().classes?.[a.eid];
  const revBlock = (a) => { const c = revOf(a), r = String(c?.reason || "");
    if (!r || /^Decision model:/.test(r)) return "";
    const body = window.relUi?.reasonHtml ? window.relUi.reasonHtml(r, c.sources) : esc(r);
    const fl = typeof aiFlare === "function" ? aiFlare({ model: String(c.model || "").split(" + ").pop(), via: "event reviewer", at: c.at ? new Date(c.at * 1000).toISOString() : "" }) : "";
    return `<div class="ai-rev small"><span class="ai-rev-h">🤖 Event reviewer${c.label ? ` · <span class="note-v v-${esc(String(c.label).replace(/[^a-z-]/g, ""))}">${esc(c.label)}</span>` : ""}</span> ${fl} ${body}</div>`; };
  const alertText = (v, x) => `<span style="${x.read === 0 ? "font-weight:600" : ""}">${linkifyIps(v)}</span>${revBlock(x)}`;
  const researchCell = (a) => { const c = X().classes?.[a.eid], n = X().notes?.[a.eid], src = c?.sources?.length || 0;
    const r = String(c?.reason || "");
    return (n ? `<span class="note-v v-${esc(String(n.verdict || "").replace(/[^a-z-]/g, ""))}" title="Research note: ${esc(n.summary || "")}">📝 ${esc(n.verdict || "researched")}</span> ` : "")
      + (r && !/^Decision model:/.test(r) ? `<span class="small muted" title="The event reviewer's explanation is shown under the alert">🤖 reviewed</span>` : "")
      + (src ? ` <span class="small" title="the event reviewer cited ${src} web page${src === 1 ? "" : "s"}">🌍${src}</span>` : "")
      + ((X().web?.[a.eid] || []).length ? ` <span class="small" title="${esc((X().web[a.eid]).map((w) => (w.kind === "page" ? "page: " : "search: ") + w.query).join("\n"))}">🔎${X().web[a.eid].length}</span>` : "")
      || `<span class="muted small">none yet</span>`; };
  const unoteBtn = (a) => { const ns = S.corr?.unotes?.[a.eid] || [], n = ns.length, p = ns.some((x) => x.status === "pending");
    S.corr = S.corr || {}; S.corr.events = S.corr.events || {};
    if (!S.corr.events[a.eid]) S.corr.events[a.eid] = { label: a.text, type: TYPE_OF[a.eid.split("|")[0]] || "alert" };
    return `<button type="button" class="unote-btn${n ? " has" : ""}" data-unote="${esc(a.eid)}" title="Add a note or verdict (Expected / Benign / Suspicious), or send to research">${n ? `📝 ${n}${p ? " ⏳" : ""}` : "📝"}</button>`; };
  const artCell = (a) => { const L = X().art_notes?.[a.eid] || [], T = X().art_note_text || {};
    return L.length ? `<span class="small" title="${esc(L.map((r) => (T[r.id]?.subject || "") + ": " + String(T[r.id]?.text || "").slice(0, 120)).join("\n"))}">🏷 ${L.length}</span>` : `<span class="muted small">–</span>`; };
  const sevOf = (v) => (v === "investigate" ? "high" : "medium");
  const openAlert = (a) => window.oeOpenDetail && window.oeOpenDetail({ eid: a.eid, type: TYPE_OF[a.eid.split("|")[0]] || "alert", label: a.text, sev: sevOf(a.severity),
    first_seen: new Date(a.ts * 1000).toISOString(), last_seen: new Date(a.ts * 1000).toISOString(), n: 1, repeats: 1, ips: (a.targets || []).filter((t) => typeof t === "string"), link: "", t0: a.ts, t1: a.ts });
  const rcCols = () => [
    { k: "verdict", t: "Verdict", fmt: (v, a) => vChip(a), sort: (a) => VORD.indexOf(a.verdict) },
    { k: "_res", t: "Research", fmt: (v, a) => researchCell(a), sort: (a) => (X().notes?.[a.eid] ? 100 : 0) + (X().classes?.[a.eid] ? 50 : 0) + (X().web?.[a.eid] || []).length },
    { k: "_un", t: "Notes", fmt: (v, a) => unoteBtn(a), sort: (a) => (S.corr?.unotes?.[a.eid] || []).length },
    { k: "_an", t: "Artifact notes", num: true, fmt: (v, a) => artCell(a), sort: (a) => (X().art_notes?.[a.eid] || []).length }];
  const vLabel = { suspicious: "Suspicious", expected: "Expected", benign: "Benign", unreviewed: "Not reviewed" };

  V.alerts = async (el) => {
    el.innerHTML = `<h1>Urgent alerts</h1><div class="sub">Raised by the 15-minute watcher : new devices, high-severity IDS hits, threat-intel matches, new Internet-facing ports, DNS tunnels and endpoint alerts. Kept 30 days.</div>
      <button id="alSetBar" class="settings-bar" aria-expanded="${A.setOpen ? "true" : "false"}" aria-controls="alSet"><span>⚙ Notification settings</span><span class="sb-sum muted small"></span><span class="sb-chev">▾</span></button>
      <div id="alSet" class="slide ${A.setOpen ? "open" : ""}"><div class="slide-in"></div></div>`;
    const bar = el.querySelector("#alSetBar"), slide = el.querySelector("#alSet"), inner = slide.querySelector(".slide-in");
    bar.onclick = () => { A.setOpen = !A.setOpen; slide.classList.toggle("open", A.setOpen); bar.setAttribute("aria-expanded", String(A.setOpen)); };
    const pc = card("Notifications on this device", `<div id="pushBox" class="muted">Checking…</div>`); inner.appendChild(pc);
    const box = pc.querySelector("#pushBox");
    const render = async () => {
      if (!pushOK()) {
        box.innerHTML = isIOS && !standalone
          ? `On iPhone/iPad, push notifications need the dashboard installed: tap <b>Share → Add to Home Screen</b>, open netmon from the home-screen icon, then come back here and tap Enable.`
          : `This browser doesn't support push notifications. The 🔔 in the header still shows new alerts while the page is open.`;
        return;
      }
      const sub = await currentSub().catch(() => null), perm = Notification.permission;
      box.innerHTML = sub
        ? `<span class="badge sev-good">On</span> This device gets a notification for every urgent alert, even when the dashboard is closed. <div style="margin-top:8px;display:flex;gap:8px;flex-wrap:wrap"><button id="pTest">Send test</button><button id="pOff">Turn off</button></div>`
        : `<span class="badge sev-unknown">Off</span> ${perm === "denied" ? "Notifications are blocked for this site — allow them in your browser's site settings, then reload." : "Get a browser/phone notification when an urgent alert fires."} <div style="margin-top:8px"><button id="pOn" ${perm === "denied" ? "disabled" : ""}>Enable notifications</button></div>`;
      box.insertAdjacentHTML("beforeend", `<div id="pMsg" class="small" style="margin-top:6px"></div>`);
      const msg = (t, bad) => { const m = box.querySelector("#pMsg"); m.textContent = t; m.style.color = bad ? "var(--bad)" : "var(--muted)"; };
      box.querySelector("#pOn")?.addEventListener("click", async () => { try { await enable(); await render(); msg("Enabled. Sending a test…"); const s = await currentSub(); const r = await apiPost("/api/push/test", { endpoint: s.endpoint }); msg(r.sent ? "Test sent — you should see it now." : "Test failed: " + (r.errors[0] || "no target"), !r.sent); } catch (e) { msg(String(e.message || e), true); } });
      box.querySelector("#pOff")?.addEventListener("click", async () => { await disable(); render(); });
      paintBar();
      box.querySelector("#pTest")?.addEventListener("click", async () => { const s = await currentSub(); const r = await apiPost("/api/push/test", { endpoint: s.endpoint }); msg(r.sent ? "Test sent." : "Test failed: " + (r.errors[0] || "no target"), !r.sent); });
    };
    render();
    inner.appendChild(await myPicker()); paintBar();
    const canMute = ["admin", "defender"].includes(S.me?.role);
    let mutes = [];
    if (canMute) { try { mutes = (await api("/api/alerts/mutes")).mutes || []; } catch (_) { /* older server */ } }
    const nCleared = mutes.reduce((a, m) => a + (m.cleared || 0), 0);
    if (canMute && (mutes.length || A.showCleared)) {
      const mc = card(`Alert mute rules (${mutes.length})`, `<div class="small muted">Alerts matching a rule are cleared automatically as they arrive: no push, no notification, not sent to the AI. They are kept, so you can still look at them with <b>Show cleared</b>. Remove a rule to bring its alerts back.</div>`);
      const mt = (mutes.length ? table(null, [
          { k: "name", t: "Alert text pattern", fmt: (v) => `<span class="mono">${esc(v)}</span>` },
          { k: "host", t: "Host", fmt: (v) => (v ? `<span class="mono">${esc(v)}</span>` : '<span class="muted">any</span>') },
          { k: "by", t: "Muted by", fmt: (v) => esc(v || "") },
          { k: "at", t: "When", fmt: (v) => esc(new Date(v * 1000).toLocaleString()), sort: (x) => x.at },
          { k: "cleared", t: "Cleared", num: true },
          { k: "id", t: "", fmt: (v) => `<button type="button" class="mute-rm" data-id="${esc(v)}">Remove rule</button>` }], mutes, { sort: "at", search: false })
        : null);
      if (mt) mc.appendChild(mt); else mc.insertAdjacentHTML("beforeend", `<div class="empty">No mute rules left. New mute rules can no longer be created: use 🚫 suppress on an alert instead.</div>`);
      mc.addEventListener("click", async (e) => { const b = e.target.closest(".mute-rm"); if (!b) return;
        if (!confirm("Remove this mute rule? The alerts it cleared come back into the feed and new matching alerts are no longer cleared.")) return;
        b.disabled = true; try { await apiPost("/api/alerts/mutes", { action: "remove", id: +b.dataset.id }); S.corr = null; poll(); rerender(); } catch (er) { b.disabled = false; alert(er.message); } });
      el.appendChild(mc);
    }
    if (A.showCleared && canMute) {
      let CL = []; try { CL = (await api("/api/alerts?cleared=1&limit=500")).alerts || []; } catch (_) { /* ignore */ }
      const cc = card(`Cleared alerts (${CL.length}) <a href="javascript:void 0" id="clTog" class="ack-toggle small">back to recent alerts</a>`,
        CL.length ? table(null, [
          { k: "ts", t: "When", fmt: (v) => esc(new Date(v * 1000).toLocaleString()), sort: (x) => x.ts },
          { k: "severity", t: "Level", fmt: (v) => `<span class="badge ${v === "investigate" ? "sev-high" : "sev-medium"}">${esc(v)}</span>` },
          { k: "text", t: "Alert", fmt: (v) => linkifyIps(v) },
          { k: "rule", t: "Cleared by rule", fmt: (v) => `<span class="mono small">${esc(v || "")}</span>` }], CL, { sort: "ts", filter: true })
          : `<div class="empty">No cleared alerts in the last 30 days.</div>`);
      el.appendChild(cc);
      cc.querySelector("#clTog").addEventListener("click", () => { A.showCleared = false; rerender(); });
      return;
    }
    const filt = A.mode === "some" && !A.showAll && !hq().has("ev");  // a drill-down to one alert must find it
    const rich = !isUserRole();
    let D = null;
    if (rich) {
      try { const R = await api("/api/alerts?limit=200&extra=1"); A.list = R.alerts; mergeExtra(R.extra); } catch (_) { /* older server: plain feed */ }
      try { D = await api("/api/alerts?held=1&limit=200" + (A.vf ? "&v=" + encodeURIComponent(A.vf) : "")); mergeExtra(D.extra); } catch (_) { D = null; }
    }
    if (rich && D?.counts) {
      const C = D.counts, tot = (v) => (C.alarms[v] || 0) + (C.detections[v] || 0);
      const tile = (v) => [`${vLabel[v]}${v === "unreviewed" ? "" : ""}`, `<a href="javascript:void 0" class="vf-kpi" data-v="${v}" title="Show the ${vLabel[v].toLowerCase()} detections">${fn(tot(v))}</a>${C.alarms[v] ? ` <span class="small muted">${fn(C.alarms[v])} alarm${C.alarms[v] === 1 ? "" : "s"}</span>` : ""}`, v === "suspicious" ? "bad" : v === "unreviewed" ? "" : "good"];
      el.insertAdjacentHTML("beforeend", kpis(VORD.map(tile)));
      el.querySelectorAll(".vf-kpi").forEach((b) => b.addEventListener("click", () => { A.vf = b.dataset.v; A.jump = true; rerender(); }));
    }
    const rows = A.list.filter((a) => !filt || a.mine).map((a) => ({ ...a, _t: a.ts }));
    const clTog = canMute && mutes.length ? ` <a href="javascript:void 0" id="clTog" class="ack-toggle small">show cleared (${nCleared})</a>` : "";
    const tog = A.mode === "some" && !isUserRole() ? `<a href="javascript:void 0" id="fTog" class="ack-toggle small">${filt ? `show all ${A.list.length}` : "only my devices"}</a>` : "";
    const ac = card(`${filt ? "Alerts for my devices" : "Recent alerts"} (${rows.length}${A.unread ? `, ${A.unread} new` : ""}) ${tog}${clTog} ${A.unread ? `<button id="markRead" class="ack-toggle">Mark all read</button>` : ""}`,
      rows.length ? table(null, [
        ...(isUserRole() ? [] : [askCol("alert", (x) => x.text)]), { k: "_t", t: "When", fmt: (v) => esc(new Date(v * 1000).toLocaleString()), sort: (x) => x.ts },
        { k: "severity", t: "Level", fmt: (v) => `<span class="badge ${v === "investigate" ? "sev-high" : "sev-medium"}">${esc(v)}</span>` },
        ...(rich && rows[0]?.eid ? rcCols().slice(0, 1) : []),
        { k: "text", t: "Alert", fmt: (v, x) => alertText(v, { ...x, read: x.read ? 1 : 0 }) },
        ...(rich && rows[0]?.eid ? rcCols().slice(1) : [])],
        rows, { sort: "_t", rowClass: (x) => (x.read ? "" : "unread"), ...(isUserRole() ? {} : { evId: (x) => `alert|${x.id}`, filter: true }),
          ...(rich && rows[0]?.eid ? { onclick: openAlert } : {}) }) : `<div class="empty">No urgent alerts in the last 30 days.</div>`);
    el.appendChild(ac);
    if (rich && D) {  // detections the watcher / scans raised that were not promoted to alarms, by verdict
      const C = D.counts.detections, chip = (v, l) => `<button type="button" class="vf-chip${(A.vf || "") === v ? " on" : ""}" data-v="${v}">${esc(l)}${v ? ` (${fn(C[v] || 0)})` : ` (${fn(D.total)})`}</button>`;
      const dc = card(`Detections by verdict (${A.vf ? `${fn(D.matching)} ${vLabel[A.vf].toLowerCase()}` : fn(D.total)}${D.alerts.length < D.matching ? `, newest ${D.alerts.length} shown` : ""})`,
        `<div class="small muted">Everything the 15-minute watcher, scans and account checks raised in the last 30 days. Only detections reviewed as suspicious at medium or high severity become alarms (above); the rest stay here with their verdict. A person's verdict (👤) wins over the event reviewer (AI), which wins over the decision model. 🔎 = web look-ups the AI ran. Click a row for the research, web research, notes and notes on its artifacts.</div>
        <div class="fchips vf-bar" style="margin:6px 0">${chip("", "All")}${VORD.map((v) => chip(v, vLabel[v])).join("")}</div>`);
      dc.id = "al-detections";
      dc.appendChild(D.alerts.length ? table(null, [
        { k: "ts", t: "When", fmt: (v) => esc(new Date(v * 1000).toLocaleString()), sort: (x) => x.ts },
        { k: "severity", t: "Level", fmt: (v) => `<span class="badge ${v === "investigate" ? "sev-high" : v === "urgent" ? "sev-medium" : "sev-low"}">${esc(v)}</span>` },
        rcCols()[0], { k: "text", t: "Detection", fmt: (v, x) => alertText(v, x) }, ...rcCols().slice(1)],
        D.alerts, { sort: "ts", filter: true, onclick: openAlert }) : (() => { const d = document.createElement("div"); d.className = "empty"; d.textContent = "No detections with this verdict."; return d; })());
      el.appendChild(dc);
      dc.querySelectorAll(".vf-chip").forEach((b) => b.addEventListener("click", () => { A.vf = b.dataset.v || ""; A.jump = true; rerender(); }));
      if (A.jump) { A.jump = false; dc.scrollIntoView({ block: "start" }); }
    }
    ac.querySelector("#clTog")?.addEventListener("click", () => { A.showCleared = true; rerender(); });
    ac.querySelector("#fTog")?.addEventListener("click", () => { A.showAll = !A.showAll; rerender(); });
    ac.querySelector("#markRead")?.addEventListener("click", async () => { await apiPost("/api/alerts/read", {}); A.unread = 0; A.list.forEach((a) => (a.read = 1)); paintCount(); rerender(); });
  };
})();
