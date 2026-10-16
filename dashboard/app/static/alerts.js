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
      if (location.hash.startsWith("#/alerts") && top !== A.lastTop && A.lastTop !== null) V.alerts($("#main"));
      A.lastTop = top;
    } catch (_) { /* logged out / offline */ }
  }
  setInterval(poll, 60000); document.addEventListener("visibilitychange", () => { if (!document.hidden) poll(); }); poll();

  // ---- which devices this user gets alerts for (applies to every device/browser they enabled) ----
  async function devicePicker() {
    const { prefs, devices } = await api("/api/push/prefs");
    let mode = prefs.mode, sel = new Set(prefs.devices), q = "";
    const c = card("Which devices alert me", "");
    const label = (d) => d.name || d.ips[0] || d.mac || d.id;
    const draw = () => {
      const vis = devices.filter((d) => !q || `${label(d)} ${d.ips.join(" ")} ${d.mac}`.toLowerCase().includes(q))
        .sort((a, b) => (sel.has(b.id) ? 1 : 0) - (sel.has(a.id) ? 1 : 0));  // chosen devices first
      c.innerHTML = `<h2>Which devices alert me</h2>
        <div class="small muted" style="margin-bottom:8px">Applies to your account on every browser/phone where you enabled notifications, and to the 🔔 count. Alerts that aren't tied to a specific device go only to people watching all devices.</div>
        <label class="dp-opt"><input type="radio" name="dpm" value="all" ${mode === "all" ? "checked" : ""}> <b>All devices</b> — every urgent alert</label>
        <label class="dp-opt"><input type="radio" name="dpm" value="some" ${mode === "some" ? "checked" : ""}> <b>Only devices I choose</b> ${sel.size ? `<span class="muted">(${sel.size} selected)</span>` : ""}</label>
        <div class="dp-list" style="${mode === "some" ? "" : "display:none"}">
          <div class="tbltools"><input type="search" placeholder="Filter devices…" value="${esc(q)}"><button class="dp-none" type="button">Clear</button></div>
          <div class="dp-items">${vis.map((d) => `<label class="dp-item"><input type="checkbox" value="${esc(d.id)}" ${sel.has(d.id) ? "checked" : ""}>
             <span><b>${esc(label(d))}</b>${d.endpoint ? ' <span class="badge sev-info">endpoint</span>' : ""}${d.known ? "" : ' <span class="badge sev-unknown">unknown</span>'}<br><span class="muted small mono">${esc([...d.ips.slice(0, 2), d.mac].filter(Boolean).join(" · "))}</span></span></label>`).join("") || '<div class="empty">No match.</div>'}</div>
        </div>
        <div style="margin-top:10px;display:flex;gap:8px;align-items:center"><button class="dp-save">Save</button><span class="dp-msg small"></span></div>`;
      c.querySelectorAll("input[name=dpm]").forEach((r) => r.onchange = () => { mode = r.value; draw(); });
      const s = c.querySelector(".dp-list input[type=search]");
      s.oninput = () => { q = s.value.toLowerCase(); const pos = s.selectionStart; draw(); const n = c.querySelector(".dp-list input[type=search]"); n.focus(); n.setSelectionRange(pos, pos); };
      c.querySelectorAll(".dp-items input").forEach((b) => b.onchange = () => { b.checked ? sel.add(b.value) : sel.delete(b.value); c.querySelector(".dp-opt:nth-of-type(2) .muted")?.replaceChildren(`(${sel.size} selected)`); });
      c.querySelector(".dp-none").onclick = () => { sel.clear(); draw(); };
      c.querySelector(".dp-save").onclick = async () => {
        const m = c.querySelector(".dp-msg");
        try { await apiPost("/api/push/prefs", { mode, devices: [...sel] }); m.style.color = "var(--good)"; m.textContent = mode === "all" ? "Saved — you'll get every urgent alert." : `Saved — alerts only for ${sel.size} device${sel.size === 1 ? "" : "s"}.`; await poll(); }
        catch (e) { m.style.color = "var(--bad)"; m.textContent = String(e.message || e); }
      };
    };
    draw();
    return c;
  }

  V.alerts = async (el) => {
    el.innerHTML = `<h1>Urgent alerts</h1><div class="sub">Raised by the 15-minute watcher : new devices, high-severity IDS hits, threat-intel matches, new Internet-facing ports, DNS tunnels and endpoint alerts. Kept 30 days.</div>`;
    const pc = card("Notifications on this device", `<div id="pushBox" class="muted">Checking…</div>`); el.appendChild(pc);
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
      box.querySelector("#pTest")?.addEventListener("click", async () => { const s = await currentSub(); const r = await apiPost("/api/push/test", { endpoint: s.endpoint }); msg(r.sent ? "Test sent." : "Test failed: " + (r.errors[0] || "no target"), !r.sent); });
    };
    render();
    el.appendChild(await devicePicker());
    const filt = A.mode === "some" && !A.showAll;
    const rows = A.list.filter((a) => !filt || a.mine).map((a) => ({ ...a, _t: a.ts }));
    const tog = A.mode === "some" ? `<a href="javascript:void 0" id="fTog" class="ack-toggle small">${filt ? `show all ${A.list.length}` : "only my devices"}</a>` : "";
    const ac = card(`${filt ? "Alerts for my devices" : "Recent alerts"} (${rows.length}${A.unread ? `, ${A.unread} new` : ""}) ${tog} ${A.unread ? `<button id="markRead" class="ack-toggle">Mark all read</button>` : ""}`,
      rows.length ? table(null, [
        askCol("alert", (x) => x.text), { k: "_t", t: "When", fmt: (v) => esc(new Date(v * 1000).toLocaleString()), sort: (x) => x.ts },
        { k: "severity", t: "Level", fmt: (v) => `<span class="badge ${v === "investigate" ? "sev-high" : "sev-medium"}">${esc(v)}</span>` },
        { k: "text", t: "Alert", fmt: (v, x) => `<span style="${x.read ? "" : "font-weight:600"}">${linkifyIps(v)}</span>` }],
        rows, { sort: "_t", rowClass: (x) => (x.read ? "" : "unread") }) : `<div class="empty">No urgent alerts in the last 30 days.</div>`);
    el.appendChild(ac);
    ac.querySelector("#fTog")?.addEventListener("click", () => { A.showAll = !A.showAll; V.alerts(el); });
    ac.querySelector("#markRead")?.addEventListener("click", async () => { await apiPost("/api/alerts/read", {}); A.unread = 0; A.list.forEach((a) => (a.read = 1)); paintCount(); V.alerts(el); });
  };
})();
