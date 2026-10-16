// Collapsible boxes: every titled .card in #main can be shrunk/expanded by clicking its title.
// Default: the first 3 boxes on a page are open, the rest collapsed. A user's own toggle is remembered per page+box (localStorage).
(() => {
  const main = document.getElementById("main"); if (!main) return;
  const KEY = "netmon_cards", OPEN_N = 3;
  let saved = {}; try { saved = JSON.parse(localStorage.getItem(KEY) || "{}"); } catch (_) {}
  const view = () => (location.hash.replace(/^#\/?/, "").split(/[/?]/)[0] || "overview");
  const title = (h) => (h.childNodes[0]?.textContent || h.textContent).replace(/\(.*?\)|\d[\d,.]*/g, "").replace(/\s+/g, " ").trim().slice(0, 80);
  const id = (c) => view() + "|" + title(c.querySelector(":scope > h2"));
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
      const k = id(c), pref = saved[k];
      // a drill-down filter or ?at= target must be visible
      const must = c.querySelector(".fchips") || inSec.has(c) || (target && (c.id === target || c.querySelector("#" + CSS.escape(target))));
      // data-open="1": a page's key box starts open even past the first 3 (the user's own toggle still wins)
      set(c, must ? false : pref != null ? !!pref : c.dataset.open === "1" ? false : i >= OPEN_N, false);
    });
    bar(list);
  }
  function bar(list) {  // page-level "Expand all / Collapse all", only when there is something to toggle
    let b = main.querySelector(":scope > .cc-bar");
    if (list.length < 2) { b?.remove(); return; }
    if (!b) { b = document.createElement("div"); b.className = "cc-bar small";
      b.innerHTML = `<button type="button" data-cc="open">Expand all</button><button type="button" data-cc="close">Collapse all</button>`;
      const h1 = main.querySelector(":scope > h1"); let after = h1; while (after?.nextElementSibling?.classList.contains("sub")) after = after.nextElementSibling;
      after ? after.after(b) : main.prepend(b); }
  }
  main.addEventListener("click", (e) => {
    const all = e.target.closest(".cc-bar [data-cc]"); if (all) { boxes().forEach((c) => set(c, all.dataset.cc === "close", true)); return; }
    const h = e.target.closest(".cc-h"); if (!h || e.target.closest("a, button, input, select, label, summary, textarea")) return;
    const c = h.parentElement; set(c, !c.classList.contains("collapsed"), true);
  });
  main.addEventListener("keydown", (e) => { const h = e.target.closest?.(".cc-h"); if (h && (e.key === "Enter" || e.key === " ") && e.target === h) { e.preventDefault(); h.click(); } });
  let q = false; new MutationObserver(() => { if (q) return; q = true; requestAnimationFrame(() => { q = false; enhance(); }); }).observe(main, { childList: true, subtree: true });
  enhance();
})();
