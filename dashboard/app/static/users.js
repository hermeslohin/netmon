// Network > Users: accounts seen in the logs (endpoint logins, failures, sudo, admin sessions, suspicious processes) and
// their general patterns, built by accounts.py on every correlation pass. Not the dashboard's own logins (More > Dashboard users).
(() => {
  const NOTE = "Counted from the logs of every recorded report; nothing here is an AI judgement.";
  const flagCls = (f) => /fail/.test(f) ? "sev-high" : /privileged|created/.test(f) ? "sev-medium" : /new/.test(f) ? "sev-medium" : "";
  const flags = (v) => (v || []).map((f) => `<span class="badge ${flagCls(f)}">${esc(f)}</span>`).join(" ");
  const list = (a, max = 3, f = (x) => esc(x)) => { a = a || []; return a.slice(0, max).map(f).join(", ") + (a.length > max ? ` <span class="muted small">+${a.length - max}</span>` : ""); };
  const hrs = (h) => { const m = Math.max(1, ...Object.values(h || {})); return `<span class="mono" style="letter-spacing:1px" title="Activity by hour (UTC)">${Array.from({ length: 24 }, (_, i) => { const v = (h || {})[i] || 0; return v ? "▁▂▃▄▅▆▇█"[Math.min(7, Math.floor((v / m) * 7.99))] : "·"; }).join("")}</span>`; };
  const srcLink = (s) => /^\d+\.\d+\.\d+\.\d+$/.test(s) ? ipLink(s) : esc(s);
  const hostL = (h) => /^\d+\.\d+\.\d+\.\d+$/.test(h) ? ipLink(h) : hostLink(h);

  // KPI tiles are links that set ?f=<filter>; the table below reads it (urlFilter: chip + remove button) and the page scrolls to it
  const kl = (f, v, title) => `<a href="${location.hash.split("?")[0]}?f=${f}" title="${esc(title)}">${v} <span style="font-size:13px">›</span></a>`;
  const hasLogin = (r) => !r.flags.includes("no logins (service account?)");
  const LIST_F = { logins: hasLogin, privileged: (r) => r.flags.includes("privileged"), failures: (r) => r.flags.includes("mostly failures") };
  const DET_F = { ok: (r) => r.ok > 0, fail: (r) => r.fail > 0, sudo: (r) => r.kind === "sudo", hosts: (r) => !!r.host, sources: (r) => !!r.src && !r.src.startsWith("as ") };
  const uf = (M) => ({ f: ["Show", (r, v) => (M[v] ? M[v](r) : true)] });

  V.netusers = async (el, arg) => {
    const u = decodeURIComponent(arg || "");
    el.innerHTML = `<div class="crumbs">${u ? '<a href="#/netusers">Users</a> › ' + esc(u) : ""}</div><h1>${u ? esc(u) : "Users"}</h1><div class="sub">Accounts seen on the network and how each is normally used: where they log in, from where, how, and when. ${NOTE} Profiles are also written as notes on the hosts (Notes page).</div>`;
    const d = await api("/api/accounts" + (u ? "?user=" + encodeURIComponent(u) : ""));
    const us = d.users || [];
    if (u) {
      const x = us.find((r) => r.user === u);
      if (!x) { el.insertAdjacentHTML("beforeend", `<div class="empty">No account called ${esc(u)} has been seen.</div>`); return; }
      el.insertAdjacentHTML("beforeend", kpis([["Reports seen in", `${x.reports} of ${x.of}`], ["Successful", kl("ok", x.ok, "Rows with successful logins"), "good"], ["Failed", kl("fail", x.fail, "Rows with failed attempts"), x.fail ? "bad" : "good"],
        ["Sudo", kl("sudo", x.sudo, "Sudo rows"), x.sudo ? "warn" : ""], ["Hosts", kl("hosts", x.n_hosts, "Rows by host"), ""], ["Sources", kl("sources", x.n_sources, "Rows by source")]]));
      el.appendChild(card("Pattern", `<p>${esc(x.pattern)}</p><div>${flags(x.flags)}</div><div style="margin-top:8px">Active by hour (UTC) ${hrs(x.hours)} <span class="muted small mono">00 → 23</span></div><div class="muted small">First seen in report ${esc(x.first)}, last in ${esc(x.last)}.</div>`));
      const rows = d.detail?.rows || [];
      el.appendChild(card(`Where and how (${rows.length})`, table(null, [{ k: "kind", t: "Activity", fmt: (v) => `<span class="badge">${esc(v)}</span>` }, { k: "host", t: "Host", fmt: hostL },
        { k: "src", t: "From", fmt: srcLink }, { k: "via", t: "Method / command", cls: "mono small" }, { k: "ok", t: "OK", num: true, fmt: fn }, { k: "fail", t: "Failed", num: true, fmt: fn }, { k: "n", t: "Events", num: true, bar: true, fmt: fn },
        { k: "last", t: "Last report", cls: "small" }], rows, { sort: { hosts: "host", sources: "src" }[hq().get("f")] || "n", dir: ["hosts", "sources"].includes(hq().get("f")) ? 1 : -1, filter: true, urlFilter: uf(DET_F) })));
      const ev = d.events || [];
      el.appendChild(card(`Events naming this account in the latest report (${ev.length})`, ev.length ? table(null, [{ k: "type", t: "Type", fmt: (v) => `<span class="badge">${esc(v)}</span>` }, { k: "sev", t: "Sev", fmt: badge },
        { k: "label", t: "Event" }, { k: "t0", t: "When", fmt: (v) => ft(v * 1000) }], ev, { sort: "t0", onclick: (r) => r.link && (location.hash = r.link) }) : `<div class="empty">None in the latest report.</div>`));
      return;
    }
    const bad = us.filter((r) => r.flags.includes("mostly failures")).length, priv = us.filter((r) => r.flags.includes("privileged")).length;
    const n = (k) => us.filter(LIST_F[k]).length;
    el.insertAdjacentHTML("beforeend", kpis([["Accounts", `<a href="#/netusers" title="All accounts">${us.length} <span style="font-size:13px">›</span></a>`], ["With logins", kl("logins", n("logins"), "Accounts that log in")],
      ["Privileged", kl("privileged", n("privileged"), "Root / sudo accounts"), n("privileged") ? "warn" : "good"], ["Mostly failures", kl("failures", n("failures"), "Accounts with mostly failed attempts"), n("failures") ? "bad" : "good"], ["Reports", d.reports]]));
    if (!us.length) { el.appendChild(card("Accounts", `<div class="empty">No accounts recorded yet. They are collected on every correlation pass (a few seconds after a report is opened).</div>`)); return; }
    el.appendChild(card(`Accounts (${us.length})`, table(null, [
      { k: "user", t: "Account", fmt: (v) => `<a href="#/netusers/${encodeURIComponent(v)}"><b>${esc(v)}</b></a>` },
      { k: "flags", t: "Flags", fmt: flags, sort: (r) => r.flags.join() },
      { k: "ok", t: "OK", num: true, fmt: fn }, { k: "fail", t: "Failed", num: true, fmt: fn },
      { k: "hosts", t: "Hosts", fmt: (v) => list(v, 3, hostL), sort: (r) => r.n_hosts },
      { k: "sources", t: "From", fmt: (v) => list(v, 3, srcLink), sort: (r) => r.n_sources },
      { k: "methods", t: "Methods", fmt: (v) => list(v, 2), cls: "small" },
      { k: "hours", t: "Hours (UTC)", fmt: hrs, sort: (r) => r.active_hours },
      { k: "reports", t: "Reports", num: true, fmt: (v, r) => `${v}/${r.of}` },
      { k: "pattern", t: "General pattern", cls: "small" }], us, { sort: "events", filter: true, urlFilter: uf(LIST_F), onclick: (r) => go("netusers/" + encodeURIComponent(r.user)) })));
  };
})();
