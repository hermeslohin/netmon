// ⓘ info button on every titled box: what the box is, where its data comes from, how to use it.
// Texts live in cardinfo.js (window.CARD_INFO, keyed "view|normalised title", same normalisation as cards.js).
(() => {
  const main = document.getElementById("main"); if (!main) return;
  const view = () => (location.hash.replace(/^#\/?/, "").split(/[/?]/)[0] || "overview");
  const norm = (h) => (h.childNodes[0]?.textContent || h.textContent).replace(/\(.*?\)|\d[\d,.]*/g, "").replace(/\s+/g, " ").replace(/[\s·|:]+$/, "").trim().slice(0, 80);
  const ALIAS = { endpoint: "device" };  // the endpoint page reuses the host page's endpoint boxes
  function lookup(h) {
    const I = window.CARD_INFO || {}, t = norm(h), v = view();
    const hit = I[`${v}|${t}`] || (ALIAS[v] && I[`${ALIAS[v]}|${t}`]);
    if (hit) return hit;
    const any = Object.keys(I).find((k) => k.split("|")[1] === t);  // same box shown on another page
    if (any) return I[any];
    const sub = main.querySelector("h1 + .sub, .sub")?.textContent.trim();
    return { what: `${t}: part of the ${main.querySelector("h1")?.textContent.trim() || "current"} page.`, source: sub || "The selected snapshot (the last 24 hours, collected every 4 hours).", use: "Click the title to collapse or expand the box. Many rows and chart bars can be clicked to drill down." };
  }
  let pop = null, owner = null;
  const close = () => { pop?.remove(); pop = null; owner?.setAttribute("aria-expanded", "false"); owner = null; };
  // fixed position, kept next to the button while the page scrolls or boxes move
  function place() {
    if (!pop || !owner) return;
    if (!owner.isConnected) return close();
    const r = owner.getBoundingClientRect(), w = Math.min(420, innerWidth - 16);
    pop.style.width = w + "px";
    pop.style.left = Math.max(8, Math.min(r.left - 12, innerWidth - w - 8)) + "px";
    const h = pop.offsetHeight, below = r.bottom + 6;
    pop.style.top = (below + h > innerHeight - 8 && r.top - h - 6 > 8 ? r.top - h - 6 : Math.max(8, Math.min(below, innerHeight - h - 8))) + "px";
  }
  addEventListener("scroll", place, { passive: true }); addEventListener("resize", place);
  function open(btn) {
    close();
    const h = btn.closest("h2"), info = lookup(h);
    pop = document.createElement("div"); pop.className = "ci-pop"; pop.setAttribute("role", "dialog"); pop.setAttribute("aria-label", "About this box");
    const head = document.createElement("div"); head.className = "ci-head";
    const b = document.createElement("b"); b.textContent = norm(h) || "About this box";
    const x = document.createElement("button"); x.type = "button"; x.className = "rel-x"; x.textContent = "✕"; x.setAttribute("aria-label", "Close"); x.onclick = close;
    head.append(b, x); pop.appendChild(head);
    for (const [k, label] of [["what", "What it is"], ["source", "Where the data comes from"], ["use", "How to use it"]]) {
      if (!info[k]) continue;
      const s = document.createElement("div"); s.className = "ci-sec";
      const l = document.createElement("div"); l.className = "ci-l"; l.textContent = label;
      const p = document.createElement("div"); p.textContent = info[k];
      s.append(l, p); pop.appendChild(s);
    }
    document.body.appendChild(pop);
    owner = btn; pop.style.maxHeight = (innerHeight - 16) + "px"; btn.setAttribute("aria-expanded", "true");
    place();
    x.focus({ preventScroll: true });
  }
  function add() {
    for (const h of main.querySelectorAll(".card > h2")) {
      if (h.querySelector(":scope > .ci-btn") || h.closest(".card").parentElement.closest(".card, .slide")) continue;
      const b = document.createElement("button"); b.type = "button"; b.className = "ci-btn"; b.textContent = "i";
      b.title = "About this box"; b.setAttribute("aria-label", "About this box"); b.setAttribute("aria-expanded", "false");
      const first = h.childNodes[0];
      // right after the title text, before counts / toggles / badges
      if (first && first.nodeType === 3) { const tx = first.textContent, i = tx.indexOf("(");
        if (i > 0) { first.textContent = tx.slice(0, i).trimEnd(); h.insertBefore(document.createTextNode(" " + tx.slice(i)), first.nextSibling); }
        h.insertBefore(b, first.nextSibling); }
      else h.insertBefore(b, h.firstChild?.nextSibling || null);
    }
  }
  // capture phase: the click must not collapse the box (cards.js listens on the title)
  document.addEventListener("click", (e) => {
    const b = e.target.closest(".ci-btn");
    if (b) { e.preventDefault(); e.stopPropagation(); owner === b ? close() : open(b); return; }
    if (pop && !e.target.closest(".ci-pop")) close();
  }, true);
  document.addEventListener("keydown", (e) => { if (e.key === "Escape" && pop) close(); });
  addEventListener("hashchange", close);
  let t = null;
  new MutationObserver(() => { clearTimeout(t); t = setTimeout(add, 60); }).observe(main, { childList: true, subtree: true });
  add();
})();
