// Collapsible + rearrangeable boxes: every titled .card in #main can be shrunk/expanded by clicking its title and
// dragged to a new place by its ⠿ grip (mouse or touch). Default: the first 3 boxes on a page are open, the rest collapsed.
// Boxes are also resizable from their bottom-right corner: width + height on desktop, height only on phones (<= 900px).
// Collapse state, box order and sizes are remembered per page in this browser (localStorage), saved on every change.
(() => {
  const main = document.getElementById("main"); if (!main) return;
  const KEY = "netmon_cards", OPEN_N = 3;
  let saved = {}; try { saved = JSON.parse(localStorage.getItem(KEY) || "{}"); } catch (_) {}
  const view = () => (location.hash.replace(/^#\/?/, "").split(/[/?]/)[0] || "overview");
  const title = (h) => (h.childNodes[0]?.textContent || h.textContent).replace(/\(.*?\)|\d[\d,.]*/g, "").replace(/\s+/g, " ").trim().slice(0, 80);
  const id = (c) => view() + "|" + title(c.querySelector(":scope > h2"));
  const LKEY = "netmon_layout";
  let layout = {}; try { layout = JSON.parse(localStorage.getItem(LKEY) || "{}"); } catch (_) {}
  const saveLayout = () => { try { localStorage.setItem(LKEY, JSON.stringify(layout)); } catch (_) {} };
  const SKEY = "netmon_sizes", mobile = window.matchMedia("(max-width: 900px)");
  let sizes = {}; try { sizes = JSON.parse(localStorage.getItem(SKEY) || "{}"); } catch (_) {}
  const saveSizes = () => { try { localStorage.setItem(SKEY, JSON.stringify(sizes)); } catch (_) {} };
  // top-level, titled boxes only (nested cards and the Alerts settings panel are left alone)
  const boxes = () => [...main.querySelectorAll(".card")].filter((c) => c.querySelector(":scope > h2") && !c.parentElement.closest(".card, .slide"));
  const set = (c, collapsed, remember) => {
    c.classList.toggle("collapsed", collapsed); const h = c.querySelector(":scope > h2"); if (h) h.setAttribute("aria-expanded", String(!collapsed));
    if (!collapsed) setTimeout(() => window.dispatchEvent(new Event("resize")), 0);  // charts/graphs sized while hidden
    if (remember) { saved[id(c)] = collapsed ? 1 : 0; try { localStorage.setItem(KEY, JSON.stringify(saved)); } catch (_) {} }
  };
  const at = () => new URLSearchParams(location.hash.split("?")[1] || "").get("at");
  function enhance() {
    const list = boxes(), target = at();
    // boxes inside the ?at= section (from that .sec-head to the next one) open too
    const tEl = target && document.getElementById(target), inSec = new Set();
    if (tEl?.classList.contains("sec-head")) { const all = [...main.querySelectorAll(".sec-head, .card")]; let on = false;
      for (const x of all) { if (x.classList.contains("sec-head")) on = x === tEl; else if (on) inSec.add(x); } }
    list.forEach((c, i) => {
      if (c.dataset.cc) return; c.dataset.cc = "1";
      const h = c.querySelector(":scope > h2"); h.classList.add("cc-h"); h.setAttribute("role", "button"); h.tabIndex = 0;
      const rs = document.createElement("div"); rs.className = "cc-rs"; rs.title = "Drag to resize · double-click to reset"; c.appendChild(rs);
      const g = document.createElement("span"); g.className = "cc-grip"; g.textContent = "⠿"; g.title = "Drag to move this box"; g.setAttribute("aria-hidden", "true"); h.appendChild(g);
      const k = id(c), pref = saved[k];
      // a drill-down filter or ?at= target must be visible
      const must = c.querySelector(".fchips") || inSec.has(c) || (target && (c.id === target || c.querySelector("#" + CSS.escape(target))));
      // data-open="1": a page's key box starts open even past the first 3 (the user's own toggle still wins)
      set(c, must ? false : pref != null ? !!pref : c.dataset.open === "1" ? false : i >= OPEN_N, false);
    });
    bar(list);
    snapshotKeys();  // key every container by its ORIGINAL first box now, before anything is moved
    restore();
    applySizes();
  }

  /* ---------- sizes: {view: {boxId: {h: px, w: % of its row}}} ----------
     Height: fixed px, content scrolls inside (charts stretch to fill). Width (desktop only): % of the box's row;
     a grid row with any sized box switches to flex-wrap so neighbours share the rest of the row. */
  const MIN_BASIS = { g2: 460, g3: 360, g4: 280 };
  function flexify(grid) {
    if (!grid.classList.contains("grid") || grid.classList.contains("cc-flex")) return;
    const k = Object.keys(MIN_BASIS).find((c) => grid.classList.contains(c));
    grid.style.setProperty("--cc-min", (MIN_BASIS[k] || 320) + "px"); grid.classList.add("cc-flex");
  }
  function applyOne(c, z) {
    c.style.height = z && z.h ? z.h + "px" : ""; c.classList.toggle("cc-sized", !!(z && z.h));
    const p = c.parentElement, inGrid = p.classList.contains("grid");
    if (z && z.w && !mobile.matches) {
      if (inGrid) { flexify(p); c.style.flex = `0 1 calc(${z.w}% - 14px)`; c.style.width = ""; }
      else { c.style.width = z.w + "%"; c.style.flex = ""; }
    } else { c.style.flex = ""; c.style.width = ""; }
  }
  function applySizes() {
    const S = sizes[view()] || {}, ids = uid();
    for (const [c, k] of ids) if (S[k] || c.style.height || c.style.flex || c.style.width) applyOne(c, S[k]);
    main.querySelectorAll(".grid.cc-flex").forEach((g) => {  // back to a normal grid when nothing in it is sized any more
      if (mobile.matches || ![...g.children].some((x) => x.style.flex)) g.classList.remove("cc-flex"); });
  }
  mobile.addEventListener("change", applySizes);
  let rsz = null;
  main.addEventListener("pointerdown", (e) => {
    const h = e.target.closest(".cc-rs"); if (!h || e.button > 0) return;
    const c = h.parentElement; if (c.classList.contains("collapsed")) return;
    e.preventDefault(); e.stopPropagation();
    const r = c.getBoundingClientRect(), row = c.parentElement.getBoundingClientRect();
    rsz = { c, id: e.pointerId, x: e.clientX, y: e.clientY, w: r.width, h: r.height, rowW: row.width, mob: mobile.matches };
    h.setPointerCapture?.(e.pointerId); document.body.classList.add(rsz.mob ? "cc-rs-v" : "cc-rs-on");
  });
  main.addEventListener("pointermove", (e) => {
    if (!rsz || e.pointerId !== rsz.id) return;
    const z = { h: Math.max(90, Math.round(rsz.h + e.clientY - rsz.y)) };
    if (!rsz.mob) z.w = Math.min(100, Math.max(20, Math.round(((rsz.w + e.clientX - rsz.x) / rsz.rowW) * 1000) / 10));
    else z.w = (sizes[view()] || {})[uid().get(rsz.c)]?.w;  // phones keep the desktop width setting untouched
    rsz.z = z; applyOne(rsz.c, z);
  });
  const rsEnd = (e) => {
    if (!rsz || (e && e.pointerId !== rsz.id)) return;
    const { c, z } = rsz; rsz = null; document.body.classList.remove("cc-rs-on", "cc-rs-v");
    if (!z) return;
    const k = uid().get(c); (sizes[view()] = sizes[view()] || {})[k] = z; saveSizes(); bar(boxes());
    setTimeout(() => window.dispatchEvent(new Event("resize")), 0);
  };
  main.addEventListener("pointerup", rsEnd); main.addEventListener("pointercancel", rsEnd);
  main.addEventListener("dblclick", (e) => {
    const h = e.target.closest(".cc-rs"); if (!h) return;
    const c = h.parentElement, k = uid().get(c);
    if (sizes[view()]) { delete sizes[view()][k]; if (!Object.keys(sizes[view()]).length) delete sizes[view()]; saveSizes(); }
    applyOne(c, null); applySizes(); bar(boxes()); setTimeout(() => window.dispatchEvent(new Event("resize")), 0);
  });

  /* ---------- order: units = boxes; a "container" is the box's parent (a grid row or the page itself) ----------
     Saved per page as {containerKey: [box ids in order]}. containerKey = "main" for the page, else the id of the box
     that was FIRST in that grid when the page rendered (stable across visits). Restoring refills each container's
     box slots in the saved order, so headings, KPIs and tables around the boxes stay where they are. */
  const uid = () => { const seen = {}; const m = new Map(); boxes().forEach((c) => { const k = id(c); seen[k] = (seen[k] || 0) + 1; m.set(c, seen[k] > 1 ? `${k}#${seen[k]}` : k); }); return m; };
  const ckey = (el, ids) => (el === main ? "main" : el.dataset.ccKey || (el.dataset.ccKey = ids.get([...el.children].find((x) => ids.has(x))) || ""));
  function snapshotKeys() {  // remember each container's key from its original first box
    const ids = uid(); boxes().forEach((c) => ckey(c.parentElement, ids)); return ids;
  }
  let restoring = false;
  function restore() {
    const L = layout[view()]; if (!L || restoring) return;
    const ids = snapshotKeys(), byId = new Map([...ids].map(([c, k]) => [k, c]));
    const conts = new Map(); [...ids.keys()].forEach((c) => { const p = c.parentElement; conts.set(ckey(p, ids), p); });
    restoring = true;
    try {
      for (const [k, order] of Object.entries(L)) {
        const cont = conts.get(k); if (!cont) continue;
        const want = order.map((i) => byId.get(i)).filter(Boolean);
        const here = [...cont.children].filter((x) => ids.has(x));
        const rest = here.filter((x) => !want.includes(x));   // boxes this layout doesn't mention keep their place, after
        const seq = [...want, ...rest];
        if (seq.length === here.length && seq.every((x, i) => x === here[i])) continue;  // already in order
        const slots = here.map((x) => { const m = document.createComment("slot"); x.before(m); return m; });
        seq.forEach((x, i) => { const m = slots[i]; if (m) m.before(x); else (slots[slots.length - 1] || cont.lastChild).after(x); });
        slots.forEach((m) => m.remove());
      }
    } finally { setTimeout(() => (restoring = false), 0); }
  }
  function record() {
    const ids = snapshotKeys(), L = {};
    boxes().forEach((c) => { const k = ckey(c.parentElement, ids); (L[k] = L[k] || []).push(ids.get(c)); });
    layout[view()] = L; saveLayout(); bar(boxes());
  }

  // ---- dragging (pointer events: mouse, pen and touch) ----
  let drag = null;
  main.addEventListener("pointerdown", (e) => {
    const g = e.target.closest(".cc-grip"); if (!g || e.button > 0) return;
    const c = g.closest(".card"); e.preventDefault(); e.stopPropagation();
    const r = c.getBoundingClientRect();
    const ph = document.createElement("div"); ph.className = "card cc-ph"; ph.style.height = r.height + "px";
    if (c.classList.contains("span")) ph.classList.add("span");
    c.before(ph);
    Object.assign(c.style, { position: "fixed", left: r.left + "px", top: r.top + "px", width: r.width + "px", zIndex: 70, pointerEvents: "none" });
    c.classList.add("cc-dragging"); document.body.classList.add("cc-drag-on");
    drag = { c, ph, dx: e.clientX - r.left, dy: e.clientY - r.top, id: e.pointerId, y: e.clientY };
    g.setPointerCapture?.(e.pointerId);
  });
  function place(x, y) {
    const el = document.elementFromPoint(x, y); if (!el) return;
    const t = el.closest(".card[data-cc]");
    if (t && t !== drag.c && main.contains(t) && !t.parentElement.closest(".card, .slide")) {
      const r = t.getBoundingClientRect(), p = getComputedStyle(t.parentElement);
      const inRow = ((p.display === "grid" && p.gridTemplateColumns.split(" ").length > 1) || p.display === "flex") && !t.classList.contains("span");
      const after = inRow ? x > r.left + r.width / 2 : y > r.top + r.height / 2;
      after ? t.after(drag.ph) : t.before(drag.ph);
      drag.ph.classList.toggle("span", drag.c.classList.contains("span"));
      return;
    }
    const gEl = el.closest(".grid");  // empty part of a grid row: drop at its end
    if (gEl && main.contains(gEl) && gEl !== drag.ph.parentElement && !gEl.closest(".card")) gEl.appendChild(drag.ph);
  }
  let raf = 0;
  main.addEventListener("pointermove", (e) => {
    if (!drag || e.pointerId !== drag.id) return;
    drag.c.style.left = e.clientX - drag.dx + "px"; drag.c.style.top = e.clientY - drag.dy + "px"; drag.y = e.clientY;
    place(e.clientX, e.clientY);
    if (!raf) { const tick = () => {  // auto-scroll near the top/bottom edge
      if (!drag) { raf = 0; return; }
      const edge = 70, y = drag.y, v = y < edge ? -(edge - y) / 4 : y > innerHeight - edge ? (y - innerHeight + edge) / 4 : 0;
      if (v) window.scrollBy(0, v); raf = requestAnimationFrame(tick); }; raf = requestAnimationFrame(tick); }
  });
  const end = (e) => {
    if (!drag || (e && e.pointerId !== drag.id)) return;
    const { c, ph } = drag; drag = null;
    ph.replaceWith(c); c.removeAttribute("style"); c.classList.remove("cc-dragging"); document.body.classList.remove("cc-drag-on");
    setTimeout(() => window.dispatchEvent(new Event("resize")), 0);  // charts adopt their new width
    record();
  };
  main.addEventListener("pointerup", end); main.addEventListener("pointercancel", end);
  document.addEventListener("keydown", (e) => { if (e.key === "Escape" && drag) end(); });
  addEventListener("pagehide", () => { if (drag) end(); saveLayout(); });  // saved on every move; also flush on leave
  function bar(list) {  // page-level "Expand all / Collapse all", only when there is something to toggle
    let b = main.querySelector(":scope > .cc-bar");
    if (list.length < 2) { b?.remove(); return; }
    b?.querySelector("[data-cc=reset]")?.toggleAttribute("hidden", !layout[view()] && !sizes[view()]);
    if (!b) { b = document.createElement("div"); b.className = "cc-bar small";
      b.innerHTML = `<span class="muted cc-hint">Drag ⠿ to rearrange · drag a corner to resize</span><button type="button" data-cc="reset" title="Original order and sizes">Reset layout</button><button type="button" data-cc="open">Expand all</button><button type="button" data-cc="close">Collapse all</button>`;
      const h1 = main.querySelector(":scope > h1"); let after = h1; while (after?.nextElementSibling?.classList.contains("sub")) after = after.nextElementSibling;
      after ? after.after(b) : main.prepend(b);
      b.querySelector("[data-cc=reset]").toggleAttribute("hidden", !layout[view()] && !sizes[view()]); }
  }
  main.addEventListener("click", (e) => {
    const all = e.target.closest(".cc-bar [data-cc]");
    if (all?.dataset.cc === "reset") { delete layout[view()]; saveLayout(); delete sizes[view()]; saveSizes(); typeof rerender === "function" ? rerender() : location.reload(); return; }
    if (all) { boxes().forEach((c) => set(c, all.dataset.cc === "close", true)); return; }
    const h = e.target.closest(".cc-h"); if (!h || e.target.closest("a, button, input, select, label, summary, textarea, .cc-grip")) return;
    const c = h.parentElement; set(c, !c.classList.contains("collapsed"), true);
  });
  main.addEventListener("keydown", (e) => { const h = e.target.closest?.(".cc-h"); if (h && (e.key === "Enter" || e.key === " ") && e.target === h) { e.preventDefault(); h.click(); } });
  let q = false; new MutationObserver(() => { if (q) return; q = true; requestAnimationFrame(() => { q = false; enhance(); }); }).observe(main, { childList: true, subtree: true });
  enhance();
})();
