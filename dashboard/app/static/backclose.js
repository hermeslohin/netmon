// Back button / back gesture closes the open modal, popup or mobile menu instead of leaving the page.
// Each open overlay owns one history entry ({synModal: depth}, same URL so the hash router never sees it).
// Back pops that entry and closes the topmost overlay (the welcome wizard steps back first); closing an
// overlay any other way (✕, Cancel, Escape, backdrop) silently pops its entry so Back then navigates normally.
(() => {
  const SEL = ".modal-back, .askdlg-scrim, .wz-back, .rel-pop, .ci-pop, dialog[open]";
  const CLOSE = '.oe-x, .tls-x, .askdlg-x, .rel-x, [aria-label="Close"], .is-cancel, .ss-cancel, .sp-cancel, .dp-cancel, .mute-cancel';
  const navOpen = () => document.body.classList.contains("nav-open");
  const overlays = () => [...document.querySelectorAll(SEL)].filter((e) => e.isConnected);
  const openCount = () => overlays().length + (navOpen() ? 1 : 0);
  const depth = () => (history.state && history.state.synModal) | 0;
  let popping = 0, timer = 0;

  function closeTop() {
    const top = overlays().pop();
    if (!top) { if (navOpen()) document.getElementById("navToggle")?.click(); return; }
    if (top.matches("dialog")) { top.close(); return; }
    if (top.matches(".wz-back")) {  // welcome wizard: Back = previous step; on the first step it is "Skip setup"
      const b = top.querySelector(".wz-back-b");
      (b && b.style.visibility === "visible" ? b : top.querySelector(".wz-skip"))?.click();
      return;
    }
    const x = [...top.querySelectorAll(CLOSE)].find((b) => b.offsetParent !== null) || top.querySelector(CLOSE);
    if (x) x.click();
    else document.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true }));
    setTimeout(() => { if (top.isConnected && !top.matches(".wz-back")) top.remove(); }, 0);
  }

  function sync() {
    timer = 0;
    if (popping) return;
    const open = openCount(), d = depth();
    if (open > d) for (let i = d + 1; i <= open; i++) history.pushState({ ...(history.state || {}), synModal: i }, "", location.href);
    else if (open < d) { popping++; history.go(open - d); }
  }
  const later = () => { if (!timer) timer = setTimeout(sync, 0); };

  addEventListener("popstate", () => {
    if (popping) { popping--; later(); return; }  // our own silent pop after a modal closed
    const d = depth(), open = openCount();
    if (open > d) { closeTop(); later(); }  // user pressed Back with an overlay open (the wizard re-gets its entry in sync)
    else if (d > open) { popping++; history.go(open - d); }  // stale entry left by a link followed from a modal: skip it
  });
  new MutationObserver(later).observe(document.body, { childList: true, attributes: true, attributeFilter: ["class"] });
  later();
})();
