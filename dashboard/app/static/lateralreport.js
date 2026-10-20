/* Lateral movement: multi-period report. Pick several time periods; each is queried from Elasticsearch (through the host
   broker) and the links / admin sessions are merged, showing which periods each one appears in. Download as HTML or CSV. */
"use strict";
(() => {
  const KEY = "netmon_lm_periods", MAXP = 8;
  const pad = (n) => String(n).padStart(2, "0");
  const toLocal = (d) => `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
  const fmtD = (iso) => new Date(iso).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
  const LV = (typeof LM_LEVELS !== "undefined") ? LM_LEVELS : {};
  const lvl = (l) => `<span class="badge" style="background:${LV[l]?.c}26;color:${LV[l]?.c};border-color:${LV[l]?.c}55">${esc(LV[l]?.l || l)}</span>`;
  const STAT = { persistent: ["In every period", "sev-high"], new: ["New in latest period", "sev-medium"], recurring: ["Some periods", "sev-info"], once: ["One period", ""] };
  const st = (s) => `<span class="badge ${STAT[s][1]}">${STAT[s][0]}</span>`;
  let periods = []; try { periods = JSON.parse(sessionStorage.getItem(KEY) || "[]"); } catch (_) {}
  let last = null;
  const save = () => sessionStorage.setItem(KEY, JSON.stringify(periods));
  const mk = (h, endMs) => { const e = new Date(endMs ?? Date.now()); e.setSeconds(0, 0); return { start: toLocal(new Date(e - h * 36e5)), end: toLocal(e) }; };

  function nodeName(R, ip) { const n = R.nodes[ip]; return n ? n.name : ip; }
  const pcell = (R, m) => R.periods.map((_, i) => `<td class="c">${m.periods[i] ? `<span title="${esc(m.periods[i].level)}" style="color:${LV[m.periods[i].level]?.c}">●</span>` : '<span class="muted">·</span>'}</td>`).join("");

  function linksTable(R) {
    return table(null, [
      { k: "level", t: "Risk", fmt: lvl, sort: (m) => Object.keys(LV).indexOf(m.level) },
      { k: "status", t: "Seen", fmt: st, sort: (m) => m.seen_in.length },
      { k: "src", t: "From", fmt: (v) => `${esc(nodeName(R, v))} <span class="muted small">${esc(v)}</span>`, sort: (m) => nodeName(R, m.src) },
      { k: "dst", t: "To", fmt: (v) => `${esc(nodeName(R, v))} <span class="muted small">${esc(v)}</span>`, sort: (m) => nodeName(R, m.dst) },
      { k: "ports", t: "Ports / reason", cls: "small", fmt: (v) => v.filter((p) => p.level !== "normal").slice(0, 3).map((p) => `${p.port}/${p.proto} — ${esc(p.why)} <span class="muted">[${p.periods.map((i) => i + 1).join(",")}]</span>`).join("<br>") || esc(v.slice(0, 4).map((p) => p.port + "/" + p.proto).join(", ")), sort: (m) => m.ports.length },
      { k: "seen_in", t: "Periods", cls: "small", fmt: (v) => v.map((i) => i + 1).join(","), sort: (m) => m.seen_in.length },
      { k: "conns", t: "Conns", num: true, fmt: fn }, { k: "bytes", t: "Bytes", num: true, fmt: fb }], R.links, { sort: "level", dir: 1, short: true });
  }
  function adminTable(R) {
    return table(null, [
      { k: "level", t: "Risk", fmt: lvl, sort: (m) => Object.keys(LV).indexOf(m.level) },
      { k: "status", t: "Seen", fmt: st, sort: (m) => m.seen_in.length },
      { k: "protocol", t: "Protocol" },
      { k: "src", t: "From", fmt: (v) => `${esc(nodeName(R, v))} <span class="muted small">${esc(v)}</span>` },
      { k: "dst", t: "To", fmt: (v) => `${esc(nodeName(R, v))} <span class="muted small">${esc(v)}</span>` },
      { k: "users", t: "Accounts", fmt: (u) => Object.entries(u).map(([n, c]) => `${esc(n)}${c.fail ? ` <span class="badge sev-high">${c.fail}✗</span>` : ""}${c.ok ? ` <span class="badge sev-good">${c.ok}✓</span>` : ""}`).join(" ") },
      { k: "auth_ok", t: "Logins ✓", num: true, fmt: fn }, { k: "auth_fail", t: "Logins ✗", num: true, fmt: (v) => (v ? `<b class="bad">${fn(v)}</b>` : "0") },
      { k: "conn_failed", t: "Refused", num: true, fmt: (v) => (v ? `<b class="warn">${fn(v)}</b>` : "0") },
      { k: "seen_in", t: "Periods", cls: "small", fmt: (v) => v.map((i) => i + 1).join(",") },
      { k: "why", t: "Why", cls: "small" }], R.admin, { sort: "level", dir: 1, short: true });
  }

  function csv(R) {
    const q = (v) => `"${String(v ?? "").replace(/"/g, '""')}"`, rows = [["kind", "risk", "seen", "periods", "from", "from_ip", "to", "to_ip", "protocol_or_ports", "reason", "conns_or_logins_ok", "failed"]];
    for (const m of R.links) rows.push(["link", m.level, m.status, m.seen_in.map((i) => i + 1).join(" "), nodeName(R, m.src), m.src, nodeName(R, m.dst), m.dst, m.ports.slice(0, 6).map((p) => p.port + "/" + p.proto).join(" "), m.ports[0]?.why || "", m.conns, ""]);
    for (const m of R.admin) rows.push(["admin", m.level, m.status, m.seen_in.map((i) => i + 1).join(" "), nodeName(R, m.src), m.src, nodeName(R, m.dst), m.dst, m.protocol, m.why, m.auth_ok, m.auth_fail + m.conn_failed]);
    return rows.map((r) => r.map(q).join(",")).join("\n");
  }
  function download(name, mime, text) { const a = document.createElement("a"); a.href = URL.createObjectURL(new Blob([text], { type: mime })); a.download = name; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 2000); }
  function htmlDoc(R, body) {
    return `<!doctype html><meta charset="utf-8"><title>Lateral movement report</title><style>body{font:13px system-ui,sans-serif;margin:24px;color:#111}table{border-collapse:collapse;width:100%;margin:8px 0 18px}th,td{border:1px solid #ccc;padding:3px 6px;text-align:left;vertical-align:top}th{background:#eee}.muted{color:#777}.badge{padding:1px 5px;border:1px solid #999;border-radius:4px}input,button,.tbltools{display:none}</style>
<h1>Lateral movement report</h1><p>Generated ${new Date().toLocaleString()} · ${R.periods.length} period(s), queried from Security Onion (Elasticsearch)</p>${body}`;
  }

  function render(box, R) {
    box.innerHTML = "";
    const body = document.createElement("div"); body.id = "lmrBody";
    const T = R.totals, multi = R.periods.length > 1;
    body.insertAdjacentHTML("beforeend", kpis([["High-risk links", T.high, T.high ? "bad" : "good"], ["Medium-risk links", T.medium, T.medium ? "warn" : "good"], ["Low-risk links", T.low],
      ["Admin sessions", R.admin.length], ["Failed logins", fn(R.admin.reduce((s, a) => s + a.auth_fail, 0)), R.admin.some((a) => a.auth_fail) ? "bad" : "good"],
      ...(multi ? [["In every period", R.persistent, R.persistent ? "warn" : "good"], ["New in latest period", R.new, R.new ? "bad" : "good"]] : [])]));
    body.appendChild(card("Periods", table(null, [{ k: "n", t: "#" }, { k: "start", t: "From", fmt: fmtD }, { k: "end", t: "To", fmt: fmtD },
      { k: "hosts", t: "Hosts", num: true }, { k: "high", t: "High", num: true }, { k: "medium", t: "Medium", num: true }, { k: "low", t: "Low", num: true },
      { k: "admin_sessions", t: "Admin sessions", num: true }, { k: "logins_failed", t: "Failed logins", num: true }, { k: "refused", t: "Refused", num: true }],
      R.periods.map((p, i) => ({ n: i + 1, ...p, high: p.counts.high, medium: p.counts.medium, low: p.counts.low })), { search: false, sort: "n", dir: 1 })));
    body.appendChild(card(`Links (${R.links.length} risky or allowed-admin; ${fn(R.normal_links)} normal links not listed)`, R.links.length ? linksTable(R) : '<div class="empty">No risky links in these periods.</div>'));
    body.appendChild(card(`Admin sessions (${R.admin.length})`, R.admin.length ? adminTable(R) : '<div class="empty">No admin sessions in these periods.</div>'));
    const tools = document.createElement("div"); tools.className = "tbltools";
    tools.innerHTML = `<button id="lmrHtml">⬇ HTML report</button><button id="lmrCsv">⬇ CSV</button><button id="lmrPrint">Print</button>`;
    box.append(tools, body);
    const stamp = new Date().toISOString().slice(0, 16).replace(/[-:]/g, "");
    tools.querySelector("#lmrCsv").onclick = () => download(`lateral-movement-${stamp}.csv`, "text/csv", csv(R));
    tools.querySelector("#lmrPrint").onclick = () => window.print();
    tools.querySelector("#lmrHtml").onclick = () => {
      const pl = R.periods.map((p, i) => `<li>${i + 1}: ${esc(fmtD(p.start))} → ${esc(fmtD(p.end))} — ${p.counts.high} high, ${p.counts.medium} medium, ${p.counts.low} low links; ${p.admin_sessions} admin sessions, ${p.logins_failed} failed logins</li>`).join("");
      const dc = body.cloneNode(true); dc.querySelectorAll("input,button,select,.tbltools").forEach((x) => x.remove());
      download(`lateral-movement-${stamp}.html`, "text/html", htmlDoc(R, `<ol>${pl}</ol>` + dc.innerHTML));
    };
  }

  window.lmReportCard = function () {
    const c = card("Multi-period report", `<div class="sub small">Pick one or more time periods (local time). Each is queried directly from Security Onion's Elasticsearch; links and admin sessions are merged and marked with the periods they appear in, so you can see what persists and what is new. Download the result as HTML or CSV.</div>
      <div id="lmrRows"></div><div class="tbltools" style="margin-top:8px"><button id="lmrAdd">+ Add period</button>
      <span class="muted small">Add last</span> ${[["1h", 1], ["6h", 6], ["24h", 24], ["3d", 72], ["7d", 168]].map(([l, h]) => `<button data-h="${h}">${l}</button>`).join("")}
      <span style="flex:1"></span><button class="primary" id="lmrGo">Generate report</button><span id="lmrMsg" class="small muted"></span></div><div id="lmrOut" style="margin-top:10px"></div>`);
    const rows = c.querySelector("#lmrRows"), msg = (t, bad) => { const m = c.querySelector("#lmrMsg"); m.textContent = t; m.style.color = bad ? "var(--bad)" : ""; };
    if (!periods.length) periods = [mk(24)];
    const draw = () => {
      rows.innerHTML = periods.map((p, i) => `<div class="rp-row" style="display:flex;gap:8px;align-items:center;margin:4px 0;flex-wrap:wrap"><b>${i + 1}</b>
        <label>Start <input type="datetime-local" data-i="${i}" data-f="start" step="60" value="${esc(p.start)}"></label><label>End <input type="datetime-local" data-i="${i}" data-f="end" step="60" value="${esc(p.end)}"></label>
        <button data-del="${i}" title="Remove this period" ${periods.length < 2 ? "disabled" : ""}>✕</button></div>`).join("");
      save();
    };
    rows.addEventListener("change", (e) => { const t = e.target; if (t.dataset.f) { periods[+t.dataset.i][t.dataset.f] = t.value; save(); } });
    rows.addEventListener("click", (e) => { const d = e.target.closest("[data-del]"); if (d) { periods.splice(+d.dataset.del, 1); draw(); } });
    c.querySelector("#lmrAdd").onclick = () => { if (periods.length >= MAXP) return msg(`At most ${MAXP} periods.`, true);
      const lastEnd = periods.length ? new Date(periods[periods.length - 1].start) : new Date(); periods.push(mk(24, lastEnd)); draw(); };  // next period = the 24 h before the previous one
    c.querySelectorAll("[data-h]").forEach((b) => (b.onclick = () => { if (periods.length >= MAXP) return msg(`At most ${MAXP} periods.`, true); periods.push(mk(+b.dataset.h)); draw(); }));
    c.querySelector("#lmrGo").onclick = async () => {
      const body = [];
      for (const [i, p] of periods.entries()) {
        const s = new Date(p.start), e = new Date(p.end);
        if (isNaN(s) || isNaN(e)) return msg(`Period ${i + 1}: enter a start and an end.`, true);
        if (e <= s) return msg(`Period ${i + 1}: the end must be after the start.`, true);
        if (e - Date.now() > 6e4) return msg(`Period ${i + 1}: the end can't be in the future.`, true);
        body.push({ start: s.toISOString(), end: e.toISOString() });
      }
      const go = c.querySelector("#lmrGo"), out = c.querySelector("#lmrOut"); go.disabled = true; msg("");
      out.innerHTML = `<div class="loading">Querying Elasticsearch for ${body.length} period${body.length > 1 ? "s" : ""}…</div>`;
      try { last = await apiPost("/api/lateral/report", { periods: body }); render(out, last); }
      catch (err) { out.innerHTML = ""; msg(String(err.message || err), true); }
      go.disabled = false;
    };
    draw();
    return c;
  };
})();
