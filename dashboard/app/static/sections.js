// Time ranges: the page opens at once and the data is queried from Elasticsearch (through the host broker) piece by piece.
// The server sends a placeholder snapshot (snap.pending = section names). Every view is rendered as usual; S.snap.raw,
// S.snap.analysis and S.idx are Proxies that record which not-yet-loaded sections a card read while it was being built, so
// that card gets a spinner (app.js markWaiting) and the page's sections are fetched in the order the cards appear - top to
// bottom, two at a time. Each arrival re-renders the page (scroll kept); sections no card on this page reads follow, and
// "analysis" (needs all the others) is last.
(() => {
  const CONCURRENCY = 2, IDX_SECS = ["devices", "hosts"];
  let raw0 = null, key2sec = {}, all = [], total = 0, timer = null, running = 0, runId = 0;
  const touch = (sec) => { if (S._t && S.pending?.has(sec)) { S._t.add(sec); if (!S._order.includes(sec)) S._order.push(sec); } };

  window.sectionsSetup = (snap) => {
    runId++; S.pending = null; S.loadingSecs = new Set(); S.secErr = {};
    if (!snap.pending?.length) return;
    S.pending = new Set(snap.pending); all = [...snap.pending]; total = all.length;
    key2sec = {}; for (const [sec, keys] of Object.entries(snap.section_keys || {})) for (const k of keys) key2sec[k] = sec;
    raw0 = snap.raw;
    const rawP = new Proxy(raw0, { get: (t, k) => { if (typeof k === "string" && key2sec[k]) touch(key2sec[k]); return t[k]; } });
    S.snap = new Proxy(snap, { get: (t, k) => (k === "raw" ? rawP : (k === "analysis" && touch("analysis"), t[k])), set: (t, k, v) => ((t[k] = v), true) });
    if (!Object.getOwnPropertyDescriptor(S, "idx")?.get) {
      Object.defineProperty(S, "idx", { get() { if (S.pending?.size) IDX_SECS.forEach(touch); return S._idx; }, set(v) { S._idx = v; }, configurable: true, enumerable: true });
    }
  };
  window.sectionsBuildIndex = () => { const t = S._t; S._t = null; try { buildIndex(); } finally { S._t = t; } };

  function progress() {
    let el = document.getElementById("secProg");
    if (!S.pending?.size) { el?.remove(); return; }
    if (!el) { el = document.createElement("div"); el.id = "secProg"; document.body.appendChild(el); }
    el.innerHTML = `<i></i> Loading data from Elasticsearch… ${total - S.pending.size}/${total}`;
  }

  function next() {
    const order = [...(S._order || []), ...all.filter((n) => !(S._order || []).includes(n))];
    const free = order.filter((n) => S.pending.has(n) && !S.loadingSecs.has(n));
    const first = free.find((n) => n !== "analysis");
    if (first) return first;
    const others = [...S.pending].some((n) => n !== "analysis");  // analysis needs every other section
    return !others && free.includes("analysis") ? "analysis" : null;
  }

  function renderSoon() {
    if (timer) return;
    timer = setTimeout(() => { timer = null; window.sectionsBuildIndex(); progress(); rerender(); }, 40);
  }

  async function worker(id) {
    running++;
    try {
      for (;;) {
        if (id !== runId || !S.pending?.size) return;
        const n = next(); if (!n) return;
        S.loadingSecs.add(n);
        let d = null;
        try { d = await api(`/api/section?id=${encodeURIComponent(S.snap.id)}&name=${encodeURIComponent(n)}`); }
        catch (e) { console.error("section", n, e); S.secErr[n] = String(e.message || e); }
        if (id !== runId) return;  // another range / snapshot was opened meanwhile
        S.loadingSecs.delete(n);
        if (d) {
          if (n === "analysis") { S.snap.analysis = d.analysis || {}; }
          else Object.assign(raw0, d);
        }
        S.pending.delete(n);
        if (n === "analysis" && d) {  // risk needs the analysis
          const sid = S.snap.id; S.risk = await api("/api/risk?id=" + encodeURIComponent(sid)).catch(() => null);
        }
        renderSoon();
        const bad = Object.keys(S.secErr);
        if (bad.length) { const f = document.getElementById("foot"); if (f && !f.dataset.secErr) { f.dataset.secErr = "1"; f.textContent += ` · failed to load: ${bad.join(", ")}`; } }
      }
    } finally { running--; }
  }

  window.sectionsStart = () => {
    if (!S.pending?.size) return;
    progress();
    const id = runId;
    for (let i = 0; i < CONCURRENCY; i++) worker(id);
  };
  // a page change re-prioritises: the new page's sections go first (route() re-records S._order, then idle workers restart)
  window.addEventListener("hashchange", () => setTimeout(() => { if (S.pending?.size && running < CONCURRENCY) { const id = runId; for (let i = running; i < CONCURRENCY; i++) worker(id); } }, 120));
})();
