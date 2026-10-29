// New-user welcome: a guided setup shown once, the first time a brand-new account signs in (auth.add sets the flag;
// POST /api/account/welcome clears it). Steps: welcome -> your own password -> notifications -> your devices -> finding your way.
(() => {
  const ROLE = {
    admin: { what: "As an <b>Admin</b> you can see everything netmon knows and change its settings, users and AI configuration.",
      nav: [["Overview", "overview", "The latest picture of the network: traffic, devices, findings."], ["Open events", "events", "Everything nobody has checked off yet. Click a row for every occurrence and its related events."],
        ["Posture", "security", "Findings, IDS alerts, beacons and threat intel for the chosen time range (🕒 in the header)."], ["AI review", "aireview", "How the review pipeline is doing and what the models decided."],
        ["Settings", "settings", "Policy and site settings. Dashboard users are managed on their own page."]] },
    defender: { what: "As a <b>Network defender</b> you can see everything and do the analyst work: check events off, write notes, ask the AI. You can't change settings.",
      nav: [["Overview", "overview", "The latest picture of the network."], ["Open events", "events", "Everything nobody has checked off yet. Click a row for every occurrence and its related events."],
        ["Posture", "security", "Findings, IDS alerts, beacons and threat intel for the chosen time range."], ["Ask AI", "chat", "Ask questions about what you see."]] },
    user: { what: "Your account shows the <b>devices an admin assigned to you</b>: their alerts and events, and nothing else.",
      nav: [["My devices", "my", "Events for the devices assigned to you."], ["Alerts", "alerts", "Urgent alerts for your devices, and your notification settings."]] },
  };
  const el = (h) => { const d = document.createElement("div"); d.innerHTML = h.trim(); return d.firstElementChild; };

  window.welcomeShow = async () => {
    if (document.getElementById("welcome")) return;
    const me = S.me || {}, R = ROLE[me.role] || ROLE.user, P = window.netmonPush;
    const st = { i: 0, pw: false, push: false }, min = 10;
    let devs = null;
    try { const d = await api("/api/push/prefs"); devs = { locked: d.locked, list: d.devices || [] }; } catch (_) { /* optional */ }
    const dev = (d) => esc(d.name || d.ips?.[0] || d.mac || d.id);
    const steps = [
      { t: "Welcome", html: () => `<p>Hi <b>${esc(me.user)}</b>, welcome to netmon${SITE.site_name ? ` for <b>${esc(SITE.site_name)}</b>` : ""}.</p>
          <p>netmon watches the network and tells you about things that look wrong, so you don't have to read logs.</p><p>${R.what}</p>
          <p class="muted small">This takes about a minute. You can skip any step and come back later from the menu.</p>` },
      { t: "Your password", html: () => `<p>Your account was created with a password someone else chose. Pick your own now.</p>
          <form class="wz-pw" autocomplete="on"><input type="text" name="username" value="${esc(me.user)}" autocomplete="username" hidden>
            <label class="small muted">Current password<input name="cur" type="password" autocomplete="current-password" required></label>
            <label class="small muted">New password (at least ${min} characters)<input name="p1" type="password" autocomplete="new-password" minlength="${min}" required></label>
            <label class="small muted">Confirm new password<input name="p2" type="password" autocomplete="new-password" required></label>
            <label class="small"><input type="checkbox" class="wz-show"> Show passwords</label>
            <button type="submit" class="primary">${st.pw ? "Password changed ✓" : "Change password"}</button><div class="wz-out small"></div></form>`,
        bind: (b) => { const f = b.querySelector("form"), out = f.querySelector(".wz-out"), say = (t, ok) => { out.textContent = t; out.style.color = ok ? "var(--good)" : "var(--bad)"; };
          f.querySelector(".wz-show").onchange = (e) => ["cur", "p1", "p2"].forEach((n) => (f[n].type = e.target.checked ? "text" : "password"));
          if (st.pw) f.querySelector("button").disabled = true;
          f.onsubmit = async (ev) => { ev.preventDefault(); say("");
            if (f.p1.value.length < min) return say(`The new password must be at least ${min} characters.`);
            if (f.p1.value !== f.p2.value) return say("The new passwords don't match.");
            if (f.p1.value === f.cur.value) return say("The new password must be different from the current one.");
            const btn = f.querySelector("button"); btn.disabled = true;
            try { await apiPost("/api/account/password", { current: f.cur.value, password: f.p1.value }); st.pw = true; f.reset(); btn.textContent = "Password changed ✓"; say("Done. Other signed-in browsers were signed out; this one stays signed in.", true); }
            catch (x) { say(String(x.message || x)); btn.disabled = false; } }; } },
      { t: "Notifications", html: () => {
          const ios = P?.isIOS && !P?.standalone;
          return `<p>Get urgent alerts on this phone or computer, even when the dashboard isn't open.</p>
            ${!P?.ok() ? (ios ? `<p>On iPhone/iPad, first install the dashboard: tap <b>Share → Add to Home Screen</b>, open netmon from the new icon, then enable notifications from <b>Alerts → Notification settings</b>.</p>`
              : `<p class="muted">This browser doesn't support push notifications. The 🔔 in the header still shows new alerts while the page is open.</p>`)
              : `<button type="button" class="primary wz-push" ${st.push ? "disabled" : ""}>${st.push ? "Notifications on ✓" : "Turn on notifications"}</button><div class="wz-out small"></div>`}`; },
        bind: (b) => { const btn = b.querySelector(".wz-push"); if (!btn) return; const out = b.querySelector(".wz-out");
          P.current().then((s) => { if (s) { st.push = true; btn.textContent = "Notifications on ✓"; btn.disabled = true; } }).catch(() => {});
          btn.onclick = async () => { btn.disabled = true; try { await P.enable(); st.push = true; btn.textContent = "Notifications on ✓"; out.style.color = "var(--good)"; out.textContent = "Enabled on this device."; }
            catch (x) { btn.disabled = false; out.style.color = "var(--bad)"; out.textContent = String(x.message || x); } }; } },
      { t: "Your devices", html: () => me.role === "user"
          ? `<p>You'll get alerts for these devices, assigned by an admin:</p>${devs?.list?.length ? `<ul>${devs.list.map((d) => `<li>${dev(d)}</li>`).join("")}</ul>` : `<div class="empty">No devices are assigned to you yet. Ask an admin to assign some.</div>`}`
          : `<p>By default you get alerts for <b>all devices</b>. To limit them to certain devices, open <b>Alerts → Notification settings → Which devices alert me</b> at any time.</p>` },
      { t: "Finding your way", html: () => `<p>The menu at the top is where to start:</p><ul class="wz-nav">${R.nav.map(([n, r, d]) => `<li><a href="#/${r}" data-go="1"><b>${esc(n)}</b></a><div class="small muted">${esc(d)}</div></li>`).join("")}</ul>
          <p class="small muted">The 🔔 in the header shows unread urgent alerts. Your account and password live under 👤 at the top right. Look for the 💬 button on anything you want explained.</p>` },
    ];
    const root = el(`<div id="welcome" class="wz-back" role="dialog" aria-modal="true" aria-label="Welcome setup"><div class="wz"><div class="wz-dots"></div><h2 class="wz-h"></h2><div class="wz-body"></div>
      <div class="wz-foot"><button type="button" class="wz-skip linklike">Skip setup</button><span style="flex:1"></span><button type="button" class="wz-back-b">Back</button><button type="button" class="primary wz-next">Next</button></div></div></div>`);
    document.body.appendChild(root);
    const done = async () => { try { await apiPost("/api/account/welcome", {}); } catch (_) { /* shown again next time */ } root.remove(); };
    const paint = () => {
      const s = steps[st.i], last = st.i === steps.length - 1;
      root.querySelector(".wz-dots").innerHTML = steps.map((_, k) => `<i class="${k === st.i ? "on" : k < st.i ? "past" : ""}"></i>`).join("") + `<span class="small muted">Step ${st.i + 1} of ${steps.length}</span>`;
      root.querySelector(".wz-h").textContent = s.t;
      const body = root.querySelector(".wz-body"); body.innerHTML = s.html(); s.bind?.(body);
      root.querySelector(".wz-back-b").style.visibility = st.i ? "visible" : "hidden";
      root.querySelector(".wz-next").textContent = last ? "Finish" : "Next";
      root.querySelector(".wz-skip").style.display = last ? "none" : "";
    };
    root.onclick = (e) => { const a = e.target.closest("a[data-go]"); if (a) { done(); } };
    root.querySelector(".wz-next").onclick = () => { if (st.i === steps.length - 1) done(); else { st.i++; paint(); } };
    root.querySelector(".wz-back-b").onclick = () => { if (st.i) { st.i--; paint(); } };
    root.querySelector(".wz-skip").onclick = done;
    paint();
  };
})();
