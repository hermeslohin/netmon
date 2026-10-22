// Header time picker: a start and end date/time instead of one nightly snapshot. A window matching a nightly
// report (±10 min) loads that snapshot as before; any other window is collected on the host for exactly that range
// (POST /api/range -> host broker -> collect.py --start/--end + analyze.py --readonly; progress via /api/range/status).
// Alarms (Alerts, the AI triage alarms on Posture, research notes and correlation) stay with the nightly report that
// ends inside the range; every other page shows the range.
(() => {
  const KEY = "netmon_range";
  const pad = (n) => String(n).padStart(2, "0");
  const toLocal = (d) => `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;  // datetime-local value
  const fmt = (d) => d.toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
  const PRESETS = [["1h", 1], ["6h", 6], ["24h", 24], ["3d", 72], ["7d", 168], ["30d", 720]];

  // window of a nightly snapshot: generated - hours .. generated (the snapshot list only has ids; derive from the id)
  const snapEnd = (id) => new Date(id.replace(/^(\d{4}-\d\d-\d\d)T(\d\d)(\d\d)Z$/, "$1T$2:$3:00Z"));

  let label = function (r) {
    const s = new Date(r.start), e = new Date(r.end), h = (e - s) / 36e5;
    const len = h >= 48 ? `${Math.round(h / 24)} days` : h >= 1 ? `${+h.toFixed(1)} h` : `${Math.round(h * 60)} min`;
    return `${fmt(s)} → ${fmt(e)} <span class="muted">(${len})</span>`;
  };

  function build() {
    const box = document.getElementById("rangeBox"); if (!box) return;
    box.innerHTML = `<button id="rangeBtn" type="button" aria-haspopup="true" aria-expanded="false" title="Time range shown on every page except alarms"><span class="rb-ic">🕒</span><span class="rb-cal">📅</span> <span id="rangeLbl">…</span><span class="rb-car"> ▾</span></button>
      <div id="rangePop" class="range-pop" hidden>
        <div class="rp-row"><label>Start <input type="datetime-local" id="rgStart" step="60"></label>
          <label>End <input type="datetime-local" id="rgEnd" step="60"></label></div>
        <div class="rp-row rp-pre">Last ${PRESETS.map(([l, h]) => `<button type="button" data-h="${h}">${l}</button>`).join("")}</div>
        <div class="rp-row"><label style="flex:1">Nightly report window <select id="rgSnap"></select></label></div>
        <div class="rp-row"><b class="small">Also include these periods</b> <button type="button" id="rgAddP" title="Add another time period">+ Add period</button></div>
        <div id="rgExtra"></div>
        <div class="rp-row"><button type="button" id="rgApply" class="primary">Apply</button> <button type="button" id="rgCancel">Cancel</button>
          <span id="rgMsg" class="small muted"></span></div>
        <div class="muted small rp-note">Times are your local time. Report windows load instantly; any other range is collected from Security Onion and UniFi for exactly that time (usually under a minute). Alarms (Alerts, AI triage alarms, research notes) always come from the nightly report that ends in the range. Extra periods are combined with the main range on the Lateral movement page (graph, tables and charts), queried straight from Elasticsearch.</div>
      </div>`;
    const btn = box.querySelector("#rangeBtn"), pop = box.querySelector("#rangePop"), st = box.querySelector("#rgStart"), en = box.querySelector("#rgEnd");
    const place = () => {  // keep the panel inside the viewport (the header can be wider than a phone screen)
      pop.style.left = pop.style.right = pop.style.width = "";
      const b = box.getBoundingClientRect(), vw = document.documentElement.clientWidth, w = Math.min(420, vw - 16);
      pop.style.width = w + "px"; pop.style.right = "auto";
      pop.style.left = Math.max(8, Math.min(b.right - w, vw - w - 8)) - b.left + "px"; };
    const open = (v) => { pop.hidden = !v; btn.setAttribute("aria-expanded", String(v)); if (v) { fill(); place(); } };
    window.addEventListener("resize", () => !pop.hidden && place());
    btn.onclick = () => open(pop.hidden);
    box.querySelector("#rgCancel").onclick = () => open(false);
    document.addEventListener("click", (e) => { if (!pop.hidden && !box.contains(e.target)) open(false); });
    document.addEventListener("keydown", (e) => { if (e.key === "Escape" && !pop.hidden) open(false); });
    box.querySelector(".rp-pre").onclick = (e) => { const h = +e.target.closest("[data-h]")?.dataset.h; if (!h) return;
      const end = new Date(); end.setSeconds(0, 0); en.value = toLocal(end); st.value = toLocal(new Date(end - h * 36e5)); box.querySelector("#rgSnap").value = ""; };
    box.querySelector("#rgSnap").onchange = (e) => { const id = e.target.value; if (!id) return; const end = snapEnd(id);
      en.value = toLocal(end); st.value = toLocal(new Date(end - 24 * 36e5)); };
    const xbox = box.querySelector("#rgExtra");
    const xrow = (r) => `<div class="rp-row rp-x"><label>Start <input type="datetime-local" step="60" value="${esc(r.start)}"></label><label>End <input type="datetime-local" step="60" value="${esc(r.end)}"></label><button type="button" class="rg-del" title="Remove">✕</button></div>`;
    const xfill = () => { xbox.innerHTML = (S.extra || []).map((r) => xrow({ start: toLocal(new Date(r.start)), end: toLocal(new Date(r.end)) })).join(""); };
    box.querySelector("#rgAddP").onclick = () => {  // the new row starts as the same length, directly before the previous one
      const rows = [...xbox.querySelectorAll(".rp-x")], ref = rows.length ? rows[rows.length - 1].querySelectorAll("input") : [st, en];
      const s0 = new Date(ref[0].value), e0 = new Date(ref[1].value), len = e0 - s0 > 0 ? e0 - s0 : 24 * 36e5;
      if (rows.length >= 7) return msg("At most 8 periods.", true);
      xbox.insertAdjacentHTML("beforeend", xrow({ start: toLocal(new Date(s0 - len)), end: toLocal(s0) })); };
    xbox.onclick = (e) => { e.target.closest(".rg-del")?.closest(".rp-x").remove(); };
    window.rangeXFill = xfill;
    box.querySelector("#rgApply").onclick = async () => {
      const extra = [];
      for (const row of xbox.querySelectorAll(".rp-x")) {
        const [a, b] = [...row.querySelectorAll("input")].map((i) => new Date(i.value));
        if (isNaN(a) || isNaN(b)) return msg("Fill in every extra period's start and end.", true);
        if (b <= a) return msg("An extra period's end must be after its start.", true);
        if (b - Date.now() > 6e4) return msg("An extra period can't end in the future.", true);
        extra.push({ start: a.toISOString(), end: b.toISOString() });
      }
      S.extra = extra; sessionStorage.setItem(KEY + "_x", JSON.stringify(extra));
      const s = new Date(st.value), e = new Date(en.value);
      if (isNaN(s) || isNaN(e)) return msg("Enter a start and an end.", true);
      if (e <= s) return msg("The end must be after the start.", true);
      if (e - Date.now() > 6e4) return msg("The end can't be in the future.", true);
      const snapId = box.querySelector("#rgSnap").value;
      await applyRange({ start: s.toISOString(), end: e.toISOString() }, snapId);
    };
    const msg = (t, bad) => { const m = box.querySelector("#rgMsg"); m.textContent = t; m.style.color = bad ? "var(--bad)" : ""; };
    window.rangeMsg = msg;
    function fill() {
      const r = S.range || {};
      if (r.start) { st.value = toLocal(new Date(r.start)); en.value = toLocal(new Date(r.end)); }
      const sel = box.querySelector("#rgSnap");
      sel.innerHTML = `<option value="">— choose a report —</option>` + [...S.snaps].reverse().map((s) => `<option value="${esc(s.id)}">${esc(fmt(snapEnd(s.id)))}${s.has.includes("triage") ? " ✓" : ""}</option>`).join("");
      sel.value = S.snap && !S.snap.range ? S.snap.id : "";
      msg(""); xfill();
    }
    window.closeRangePop = () => open(false);
  }

  function showLabel() { const l = document.getElementById("rangeLbl"); if (l && S.range) l.innerHTML = label(S.range) + (S.extra?.length ? ` <span class="badge sev-info">+${S.extra.length}</span>` : ""); }
  // every period the Lateral movement page combines: the main range first, then the extras
  window.rangePeriods = () => [S.range, ...(S.extra || [])].filter(Boolean);
  // phones: a compact label (dates without the year/minutes noise)
  const label0 = label;
  label = (r) => (window.matchMedia("(max-width: 900px)").matches ? (() => { const s = new Date(r.start), e = new Date(r.end), o = { month: "numeric", day: "numeric", hour: "numeric" };
    return `${s.toLocaleString([], o)}–${e.toLocaleString([], o)}`; })() : label0(r));

  // Load a time range: nightly snapshot when it matches, else collect it on the host and wait.
  async function applyRange(r, snapId) {
    const m = window.rangeMsg || (() => {});
    let R;
    try { R = await apiPost("/api/range", r); } catch (e) { m(String(e.message || e), true); return false; }
    if (R.status !== "done" && R.status !== "sections") {  // "sections": the page loads the pieces itself, one by one
      m("Collecting this time range…");
      $("#main").innerHTML = `<div class="loading">Collecting ${label(r)} from Security Onion and UniFi… <span id="rgProg"></span></div>`;
      for (let i = 0; i < 400; i++) {
        await new Promise((ok) => setTimeout(ok, 3000));
        let st; try { st = await api("/api/range/status?id=" + encodeURIComponent(R.id)); } catch (_) { continue; }
        const p = document.getElementById("rgProg"); if (p) p.textContent = st.step ? `(${st.step})` : "";
        if (st.status === "done") break;
        if (st.status === "failed") { m("Collecting failed: " + (st.error || ""), true); $("#main").innerHTML = `<div class="card"><h2>Time range failed</h2><pre>${esc(st.error || "")}</pre></div>`; return false; }
      }
    }
    S.range = R.snapshot && snapId ? rangeOfSnap(snapId) : r;
    sessionStorage.setItem(KEY, JSON.stringify({ ...S.range, id: R.id }));
    window.closeRangePop?.();
    await loadSnap(R.id);
    return true;
  }

  function rangeOfSnap(id) {
    const e = snapEnd(id); return { start: new Date(e - 24 * 36e5).toISOString(), end: e.toISOString() };
  }

  // called by init() once the snapshot list is known
  window.initRange = async () => {
    build();
    try { S.extra = JSON.parse(sessionStorage.getItem(KEY + "_x") || "[]"); } catch (_) { S.extra = []; }
    let saved = null; try { saved = JSON.parse(sessionStorage.getItem(KEY) || "null"); } catch (_) {}
    if (saved?.id && saved.start) {  // reload: same range again (cached on the server)
      S.range = { start: saved.start, end: saved.end };
      try { await loadSnap(saved.id); return; } catch (_) { sessionStorage.removeItem(KEY); }
    }
    const last = S.snaps[S.snaps.length - 1].id;
    S.range = rangeOfSnap(last);
    await loadSnap(last);
  };
  window.rangeSelectSnapshot = async (id) => { S.range = rangeOfSnap(id); sessionStorage.setItem(KEY, JSON.stringify({ ...S.range, id })); await loadSnap(id); };
  window.rangeLabel = showLabel;
  window.applyRange = applyRange;
})();
