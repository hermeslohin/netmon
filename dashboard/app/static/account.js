// My account: self-service password change (#/account). Other sessions are signed out; this one stays signed in.
(() => {
  V.account = async (el) => {
    el.innerHTML = `<h1>My account</h1><div class="sub">Change your own dashboard password. Your other signed-in browsers and phones are signed out; this one stays signed in.</div><div class="loading">Loading…</div>`;
    let A; try { A = await api("/api/account"); } catch (e) { el.querySelector(".loading").textContent = String(e); return; }
    el.querySelector(".loading").remove();
    const min = A.min_password || 10;
    el.insertAdjacentHTML("beforeend", kpis([["Signed in as", esc(A.user)], ["Last sign-in", esc(ft(A.last_login) || "—")], ["Password last changed", esc(ft(A.pw_changed) || "never")]]));
    const c = card("Change password", `<form class="pwf" autocomplete="on" style="max-width:420px">
      <input type="text" name="username" value="${esc(A.user)}" autocomplete="username" hidden>
      <label class="k small" for="pwCur">Current password</label>
      <input id="pwCur" name="cur" type="password" autocomplete="current-password" required style="width:100%;margin:4px 0 10px">
      <label class="k small" for="pwNew">New password <span class="muted">(at least ${min} characters)</span></label>
      <input id="pwNew" name="p1" type="password" autocomplete="new-password" required minlength="${min}" style="width:100%;margin:4px 0 4px">
      <div class="pwmeter"><span></span></div><div class="small muted pwhint" style="margin:2px 0 10px">&nbsp;</div>
      <label class="k small" for="pwNew2">Confirm new password</label>
      <input id="pwNew2" name="p2" type="password" autocomplete="new-password" required style="width:100%;margin:4px 0 8px">
      <label class="small" style="display:block;margin-bottom:12px"><input type="checkbox" class="pwshow"> Show passwords</label>
      <button type="submit">Change password</button>
      <div class="out small" style="margin-top:10px;min-height:1.2em"></div></form>`);
    el.appendChild(c);
    const f = c.querySelector("form"), out = f.querySelector(".out"), bar = f.querySelector(".pwmeter span"), hint = f.querySelector(".pwhint");
    const say = (t, ok) => { out.textContent = t; out.style.color = ok ? "var(--good)" : "var(--bad)"; };
    const score = (p) => {  // rough strength: length + character variety
      let s = Math.min(4, Math.floor(p.length / 4)); s += [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter((r) => r.test(p)).length;
      return Math.min(8, s);
    };
    f.p1.addEventListener("input", () => {
      const p = f.p1.value, s = score(p);
      bar.style.width = `${(s / 8) * 100}%`; bar.style.background = s < 4 ? "var(--bad)" : s < 6 ? "var(--warn)" : "var(--good)";
      hint.textContent = !p ? "\u00a0" : p.length < min ? `${min - p.length} more character${min - p.length === 1 ? "" : "s"} needed` : s < 6 ? "OK — longer or a passphrase is stronger" : "Strong";
    });
    f.querySelector(".pwshow").onchange = (e) => ["cur", "p1", "p2"].forEach((n) => (f[n].type = e.target.checked ? "text" : "password"));
    f.onsubmit = async (ev) => {
      ev.preventDefault(); say("");
      if (f.p1.value.length < min) return say(`The new password must be at least ${min} characters.`);
      if (f.p1.value !== f.p2.value) return say("The new passwords don't match.");
      if (f.p1.value === f.cur.value) return say("The new password must be different from the current one.");
      const btn = f.querySelector("button"); btn.disabled = true;
      try {
        await apiPost("/api/account/password", { current: f.cur.value, password: f.p1.value });
        f.reset(); bar.style.width = "0"; hint.textContent = "\u00a0";
        say("Password changed. Your other sessions have been signed out.", true);
      } catch (x) { say(String(x.message || x)); }
      btn.disabled = false;
    };
  };
})();
