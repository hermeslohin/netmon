/* Endpoint drill-downs: auth failures, sudo, Elastic Defend. Data: snapshot raw.hosts.details (collected nightly). */
"use strict";

const EP_KINDS = { authfail: "Authentication failures", sudo: "sudo activity", defend: "Elastic Defend health" };
const EP = { host: "" };

function epAdminLabel(ip) {
  if (!ip || ip === "local") return "local";
  const a = S.reg.host_policy?.admin_sources || {};
  for (const [k, v] of entries(a)) if (ip === k || (k.endsWith(".") && ip.startsWith(k))) return v;
  return "";
}
function epSrc(ip) {
  if (!ip || ip === "local") return '<span class="muted">local console / PAM</span>';
  const lab = epAdminLabel(ip), z = zoneOf(ip);
  return `${ipLink(ip)}${lab ? ` <span class="badge sev-good" title="admin source in host_policy.json">admin: ${esc(lab)}</span>` : z === "internet" ? ' <span class="badge sev-high">internet</span>' : ""}`;
}
const epHostMatch = (h) => !EP.host || hostMatch(h, EP.host);
function epTimeline(title, tl, color) {
  return chartCard(title, { type: "bar", data: { labels: tl.map((x) => new Date(x[0]).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })), datasets: [{ data: tl.map((x) => x[1]), backgroundColor: color, borderRadius: 2 }] },
    options: { plugins: { legend: { display: false } }, scales: { y: { beginAtZero: true, ticks: { precision: 0 } }, x: { ticks: { maxTicksLimit: 12 } } } } }, "", "short");
}
const epCount = (rows, k) => rows.reduce((o, r) => ((o[r[k] || "(none)"] = (o[r[k] || "(none)"] || 0) + (r._n || 1)), o), {});

function epDrill(kind, el) {
  const D = S.snap.raw.hosts?.details?.[kind];
  const wrap = document.createElement("div"); wrap.id = "ep-drill";
  const close = `<a href="#/endpoints" class="small" style="margin-left:10px">close</a>`;
  if (!D) { wrap.appendChild(card(`${EP_KINDS[kind]} ${close}`, `<div class="empty">This snapshot has only the summary. Event-level detail is collected with every nightly report from now on — pick a newer snapshot.</div>`)); el.appendChild(wrap); return; }
  if (D.error) { wrap.appendChild(card(`${EP_KINDS[kind]} ${close}`, `<pre>${esc(D.error)}</pre>`)); el.appendChild(wrap); return; }
  const hostsAll = kind === "defend" ? D.hosts.map((h) => h.host) : Object.keys(D.hosts || {});
  const win = `${(D.minutes / 60).toFixed(0)}h${D.end ? ` ending ${ft(D.end)}` : ""}`;
  const head = card(`${EP_KINDS[kind]} <span class="muted small">· ${esc(win)}</span>${close}`,
    `<div class="tbltools"><label class="muted">Host</label><select id="epHost"><option value="">All hosts</option>${hostsAll.map((h) => `<option ${EP.host && hostMatch(h, EP.host) ? "selected" : ""}>${esc(h)}</option>`).join("")}</select>
     <span class="chips">${Object.keys(EP_KINDS).map((k) => `<a class="chip" href="#/endpoints/${k}" style="${k === kind ? "border-color:var(--accent);color:var(--fg)" : ""}">${esc(EP_KINDS[k])}</a>`).join("")}</span></div>`);
  wrap.appendChild(head);
  const body = document.createElement("div"); wrap.appendChild(body);
  el.appendChild(wrap);
  const draw = () => { S.charts.forEach((c) => c.canvas.closest("#ep-drill") && c.destroy()); body.innerHTML = ""; ({ authfail: epAuth, sudo: epSudo, defend: epDefend })[kind](body, D); flushCharts(); };
  head.querySelector("#epHost").onchange = (e) => { EP.host = e.target.value; draw(); };
  draw();
}

function epAuth(el, D) {
  const ev = D.events.filter((e) => epHostMatch(e.host)), bursts = D.bursts.filter((b) => epHostMatch(b.host)), succ = D.successes.filter((s) => epHostMatch(s.host));
  const ext = ev.filter((e) => e.src && zoneOf(e.src) === "internet"), unk = ev.filter((e) => e.src && zoneOf(e.src) !== "internet" && !epAdminLabel(e.src));
  const neverOk = bursts.filter((b) => !b.then_success);
  el.insertAdjacentHTML("beforeend", kpis([["Failed attempts", fn(ev.length), ev.length ? "warn" : "good"], ["Attempt bursts", bursts.length], ["Followed by a successful login", bursts.length - neverOk.length, "good"],
    ["Never succeeded", neverOk.length, neverOk.length ? "warn" : "good"], ["From the internet", ext.length, ext.length ? "bad" : "good"], ["From non-admin internal hosts", unk.length, unk.length ? "warn" : "good"],
    ["Users targeted", Object.keys(epCount(ev, "user")).length]]));
  const verdict = ext.length ? `<div class="alarm investigate"><div class="t">Failures from internet addresses</div><p>${[...new Set(ext.map((e) => e.src))].map(epSrc).join(", ")} — check whether SSH is exposed and add fail2ban / restrict sources.</p></div>`
    : neverOk.some((b) => b.src !== "local" && !epAdminLabel(b.src)) ? `<div class="alarm review"><div class="t">Failed attempts from a non-admin source that never succeeded</div><p>Worth confirming who that was.</p></div>`
    : ev.length ? `<div class="alarm info"><div class="t">Looks like mistyped passwords</div><p>All failures came from known admin sources or the local console, and ${bursts.length - neverOk.length} of ${bursts.length} bursts were followed by a successful login by the same user from the same place.</p></div>` : "";
  if (verdict) el.insertAdjacentHTML("beforeend", verdict);
  const tl = D.timeline.map(([t, n]) => [t, ev.filter((e) => e.at >= t && e.at < new Date(new Date(t).getTime() + (D.minutes <= 1440 ? 9e5 : 36e5)).toISOString()).length]);
  el.appendChild(grid("g4", epTimeline("Failures over time", tl, PALETTE[3]), chartCard("By user", doughnutCfg(epCount(ev, "user"), { onClick: (l) => drillHere({ user: l }) })), chartCard("By source", doughnutCfg(epCount(ev.map((e) => ({ ...e, src: e.src || "local" })), "src"), { onClick: (l) => drillHere({ src: l }) })), chartCard("By process", doughnutCfg(epCount(ev, "process"), { onClick: (l) => drillHere({ process: l }) }))));
  el.appendChild(card(`Attempt bursts (${bursts.length}) <span class="muted small">— failures by the same user from the same place within 2 minutes</span>`, table(null, [
    { k: "last", t: "When", fmt: ft }, { k: "host", t: "Host", fmt: hostLink }, { k: "user", t: "User", fmt: (v) => `<b>${esc(v || "(none)")}</b>` }, { k: "src", t: "From", fmt: epSrc },
    { k: "n", t: "Failures", num: true }, { k: "then_success", t: "Outcome", fmt: (v) => (v ? '<span class="badge sev-good">logged in afterwards</span>' : '<span class="badge sev-medium">no successful login</span>'), sort: (b) => (b.then_success ? 1 : 0) },
  ], bursts, { sort: "last", search: bursts.length > 8 })));
  el.appendChild(card(`All failed events (${ev.length})`, table(null, [{ k: "at", t: "Time", fmt: ft }, { k: "host", t: "Host", fmt: hostLink }, { k: "user", t: "User" }, { k: "src", t: "Source", fmt: epSrc },
    { k: "process", t: "Process" }, { k: "action", t: "Event", cls: "small" }, { k: "method", t: "Method" }, { k: "message", t: "Log line", cls: "mono small" }], ev, { sort: "at", short: true, urlFilter: { user: ["User", (e, v) => eqi(e.user || "(none)", v)], src: ["Source", (e, v) => eqi(e.src || "local", v)], process: ["Process", (e, v) => eqi(e.process || "(none)", v)] } })));
  el.appendChild(card(`Successful logins by the same users / sources (${succ.length})`, table(null, [{ k: "at", t: "Time", fmt: ft }, { k: "host", t: "Host", fmt: hostLink }, { k: "user", t: "User" }, { k: "src", t: "From", fmt: epSrc }, { k: "method", t: "Method" }, { k: "message", t: "Log line", cls: "mono small" }], succ, { sort: "at", short: true })));
}

function epSudo(el, D) {
  const ev = D.events.filter((e) => epHostMatch(e.host));
  const shell = (c) => /\/(ba|z|da|k|c|fi)?sh$|\/su$/.test((c || "").split(" ")[0]);
  const odd = (e) => /^\/(tmp|var\/tmp|dev\/shm)\b/.test(e.pwd) || /^\/(tmp|var\/tmp|dev\/shm)\//.test(e.command) || /curl|wget|nc |ncat|base64 -d|chmod \+s|useradd|usermod|passwd|visudo|\/etc\/sudoers/.test(e.command);
  const errs = ev.filter((e) => e.error), shells = ev.filter((e) => shell(e.command)), notty = ev.filter((e) => !e.tty), weird = ev.filter(odd);
  el.insertAdjacentHTML("beforeend", kpis([["sudo commands", fn(ev.length)], ["Distinct commands", Object.keys(epCount(ev, "command")).length], ["Interactive root shells", shells.length, shells.length ? "warn" : ""],
    ["Denied / errors", errs.length, errs.length ? "warn" : "good"], ["No TTY (scripted)", notty.length], ["Unusual (temp dirs, downloads, account changes)", weird.length, weird.length ? "bad" : "good"],
    ["Users", Object.keys(epCount(ev, "user")).length]]));
  if (weird.length) el.insertAdjacentHTML("beforeend", `<div class="alarm investigate"><div class="t">Commands worth a look</div><p>${weird.slice(0, 8).map((e) => `<span class="mono">${esc(e.command)}</span> (${esc(e.user)} on ${esc(e.host)}, ${ft(e.at)})`).join("<br>")}</p></div>`);
  else if (ev.length) el.insertAdjacentHTML("beforeend", `<div class="alarm info"><div class="t">Nothing unusual</div><p>No sudo commands from temp directories, no downloads, and no account / sudoers changes.${errs.length ? ` ${errs.length} were refused (“${esc(errs[0].error)}”) — e.g. scripts probing with <span class="mono">sudo -n</span>.` : ""}</p></div>`);
  const tl = D.timeline.map(([t, n]) => [t, ev.filter((e) => e.at >= t && e.at < new Date(new Date(t).getTime() + (D.minutes <= 1440 ? 9e5 : 36e5)).toISOString()).length]);
  el.appendChild(grid("g4", epTimeline("sudo over time", tl, PALETTE[2]), chartCard("By user", doughnutCfg(epCount(ev, "user"), { onClick: (l) => drillHere({ user: l }) })), chartCard("By host", doughnutCfg(epCount(ev, "host"), { onClick: (l) => drillHere({ host: l }) })), chartCard("Outcome", doughnutCfg(epCount(ev.map((e) => ({ o: e.error ? "refused: " + e.error : "ran" })), "o"), { onClick: (l) => drillHere({ outcome: l }) }))));
  const grp = {};
  for (const e of ev) { const k = [e.host, e.user, e.as, e.command].join("\u0000"); const g = (grp[k] = grp[k] || { host: e.host, user: e.user, as: e.as, command: e.command, count: 0, errors: 0, pwds: new Set(), ttys: new Set(), first: e.at, last: e.at }); g.count++; if (e.error) g.errors++; if (e.pwd) g.pwds.add(e.pwd); g.ttys.add(e.tty || "none"); if (e.at < g.first) g.first = e.at; if (e.at > g.last) g.last = e.at; }
  const rows = Object.values(grp).map((g) => ({ ...g, pwds: [...g.pwds], ttys: [...g.ttys], shell: shell(g.command), odd: odd({ pwd: [...g.pwds][0] || "", command: g.command }) }));
  el.appendChild(card(`Commands (${rows.length})`, table(null, [
    { k: "command", t: "Command", fmt: (v, r) => `<span class="mono">${esc(v)}</span>${r.shell ? ' <span class="badge sev-medium">root shell</span>' : ""}${r.odd ? ' <span class="badge sev-high">unusual</span>' : ""}` },
    { k: "host", t: "Host", fmt: hostLink }, { k: "user", t: "User" }, { k: "as", t: "As" }, { k: "count", t: "Times", num: true, bar: true }, { k: "errors", t: "Refused", num: true, fmt: (v) => (v ? `<b style="color:var(--warn)">${v}</b>` : "") },
    { k: "pwds", t: "Working dir", cls: "mono small", fmt: (v) => esc(v.join(", ")) }, { k: "ttys", t: "TTY", cls: "small", fmt: (v) => esc(v.join(", ")) }, { k: "last", t: "Last", fmt: ft }], rows, { sort: "count" })));
  el.appendChild(card(`Every sudo event (${ev.length})`, table(null, [{ k: "at", t: "Time", fmt: ft }, { k: "host", t: "Host", fmt: hostLink }, { k: "user", t: "User" }, { k: "as", t: "As" }, { k: "command", t: "Command", cls: "mono small" },
    { k: "pwd", t: "PWD", cls: "mono small" }, { k: "tty", t: "TTY" }, { k: "error", t: "Result", fmt: (v) => (v ? `<span class="badge sev-medium">${esc(v)}</span>` : '<span class="badge sev-good">ran</span>') }], ev, { sort: "at", short: true, urlFilter: { user: ["User", (e, v) => eqi(e.user || "(none)", v)], outcome: ["Outcome", (e, v) => (e.error ? "refused: " + e.error : "ran") === v] } })));
}

function epDefend(el, D) {
  const hs = D.hosts.filter((h) => epHostMatch(h.host));
  const bad = hs.filter((h) => h.status !== "success");
  el.insertAdjacentHTML("beforeend", kpis([["Hosts with Defend", hs.length], ["Failing", bad.length, bad.length ? "bad" : "good"], ["Healthy", hs.length - bad.length, "good"],
    ["Protections down", bad.reduce((s, h) => s + h.protections.filter((p) => p.status !== "success").length, 0), bad.length ? "bad" : "good"]]));
  for (const h of [...bad, ...hs.filter((x) => x.status === "success")]) {
    const fails = h.actions.filter((a) => a.status !== "success"), down = h.protections.filter((p) => p.status !== "success");
    // root causes = failing actions that no other failing action explains; show the ones with a fix first
    const ROOT = ["agent_connectivity", "connect_kernel", "full_disk_access", "configure_kernel", "detect_network_events", "download_user_artifacts", "download_global_artifacts"];
    const rank = (a) => { const i = ROOT.indexOf(a.name); return i < 0 ? 99 : i; };
    const sorted = fails.filter((a) => a.fix).sort((x, y) => rank(x) - rank(y));
    const roots = sorted.filter((a) => rank(a) < 99), symptoms = sorted.filter((a) => rank(a) === 99);
    const hist = h.history || {};
    const c = card(`${badge(h.status)} ${hostLink(h.host)} <span class="muted small">· ${esc(h.os || "")} · agent ${esc(h.agent_version || "")} · policy ${esc(h.policy || "")} v${esc(h.policy_version ?? "")} · reported ${ft(h.at)}</span>`,
      `<div class="idgrid" style="margin-bottom:8px"><span class="k">Failing since</span><span>${hist.first_failure ? ft(hist.first_failure) : "—"}</span><span class="k">Last healthy report</span><span>${hist.last_success ? ft(hist.last_success) : h.status === "success" ? "now" : "<b style='color:var(--bad)'>none in the last 3 days</b>"}</span>
       <span class="k">Kernel</span><span class="small mono">${esc(h.kernel || "—")}</span></div>`);
    if (h.status !== "success") {
      const box = (a) => `<div class="alarm ${a.status === "failure" ? "investigate" : "review"}"><div class="t">${badge(a.status)} <span class="mono">${esc(a.name)}</span> — ${esc(a.message)}</div><p>${esc(a.fix)}</p></div>`;
      c.insertAdjacentHTML("beforeend", `<h3>Fix these first (root causes)</h3>` + (roots.length ? roots.map(box).join("") : `<div class="empty">No known root cause — see the steps below.</div>`) +
        (symptoms.length ? `<details><summary>${symptoms.length} dependent failures (should clear once the above are fixed)</summary>${symptoms.map(box).join("")}</details>` : ""));
      c.insertAdjacentHTML("beforeend", `<h3>Protections (${down.length} of ${h.protections.length} down)</h3>`);
      c.appendChild(table(null, [{ k: "protection", t: "Protection", fmt: (v) => `<b>${esc(v.replace(/_/g, " "))}</b>` }, { k: "status", t: "Status", fmt: badge, sort: (p) => (p.status === "success" ? 1 : 0) },
        { k: "blocking", t: "Blocked by failing step", cls: "mono small", fmt: (v) => esc(v.join(", ") || "—") }], h.protections, { sort: "status", dir: 1, search: false, short: true }));
      c.insertAdjacentHTML("beforeend", `<h3>Failing / warning steps (${fails.length})</h3>`);
      c.appendChild(table(null, [{ k: "name", t: "Step", cls: "mono small" }, { k: "status", t: "Status", fmt: badge }, { k: "message", t: "Message" }, { k: "fix", t: "Fix", cls: "small" }], fails, { search: false, short: true }));
    }
    const det = document.createElement("details"); det.innerHTML = `<summary>All ${h.actions.length} policy steps</summary>`;
    det.appendChild(table(null, [{ k: "name", t: "Step", cls: "mono small" }, { k: "status", t: "Status", fmt: badge }, { k: "message", t: "Message", cls: "small" }], h.actions, { search: false, short: true }));
    c.appendChild(det);
    if ((hist.timeline || []).length > 1) {
      const tl = hist.timeline; const cv = document.createElement("div"); cv.className = "chart short"; cv.innerHTML = "<canvas></canvas>"; c.appendChild(cv);
      queueChart(cv.querySelector("canvas"), { type: "bar", data: { labels: tl.map((x) => new Date(x[0]).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit" })),
        datasets: [["success", PALETTE[1]], ["warning", PALETTE[2]], ["failure", PALETTE[3]]].map(([s, col]) => ({ label: s, data: tl.map((x) => x[1][s] || 0), backgroundColor: col })) },
        options: { scales: { x: { stacked: true, ticks: { maxTicksLimit: 12 } }, y: { stacked: true, beginAtZero: true, ticks: { precision: 0 } } } } });
    }
    el.appendChild(c);
  }
}
