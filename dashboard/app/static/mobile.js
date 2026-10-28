// Mobile navigation: hamburger drawer for the section menu (<= 900px wide). No-op on desktop.
(() => {
  const btn = document.getElementById("navToggle"), nav = document.getElementById("nav"),
    scrim = document.getElementById("navScrim"), cur = document.getElementById("navCurrent");
  if (!btn || !nav) return;
  const set = (open) => {
    document.body.classList.toggle("nav-open", open);
    btn.setAttribute("aria-expanded", String(open));
  };
  btn.addEventListener("click", (e) => { e.stopPropagation(); set(!document.body.classList.contains("nav-open")); });
  scrim.addEventListener("click", () => set(false));
  nav.addEventListener("click", (e) => { if (e.target.closest("a")) set(false); });
  // desktop dropdown groups: click toggles (touch/keyboard), hover opens via CSS; outside click / Escape closes
  const closeGroups = (except) => nav.querySelectorAll(".ngroup.open").forEach((g) => { if (g !== except) { g.classList.remove("open"); g.querySelector(".ngh").setAttribute("aria-expanded", "false"); } });
  nav.addEventListener("click", (e) => { const h = e.target.closest(".ngh"); if (h) { const g = h.parentNode; closeGroups(g); const o = g.classList.toggle("open"); h.setAttribute("aria-expanded", String(o)); return; } if (e.target.closest("a")) closeGroups(); });
  document.addEventListener("click", (e) => { if (!e.target.closest(".ngroup")) closeGroups(); });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeGroups(); });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") set(false); });
  const label = () => {  // show the current section name next to the hamburger
    const v = (location.hash.replace(/^#\/?/, "").split(/[/?]/)[0] || "overview");
    const map = { device: "devices", endpoint: "endpoints", tls: "dns", unifi: "traffic", history: "traffic" };
    const a = nav.querySelector(`a[data-r="${map[v] || v}"]`);
    cur.textContent = a ? a.childNodes[0].textContent.trim() : (v === "account" ? "My account" : "");
  };
  window.addEventListener("hashchange", () => { set(false); label(); });
  // user box (name + Sign out) lives at the bottom of the drawer on mobile, back in the header on desktop
  const ub = document.getElementById("userBox"), home = ub && ub.parentNode, mq = window.matchMedia("(max-width: 900px)");
  const placeUser = () => { if (!ub) return; if (mq.matches) { nav.appendChild(ub); ub.classList.add("nav-user"); } else { home.appendChild(ub); ub.classList.remove("nav-user"); } };
  mq.addEventListener("change", () => { placeUser(); if (!mq.matches) set(false); });
  placeUser(); label();
})();

/* spinning microscope at the top while an event is being researched (Send to research) */
(() => {
  const el = document.createElement("div"); el.id = "researchSpin"; el.textContent = "🔬"; el.title = "Researching an event"; document.body.appendChild(el);
  const poll = async () => { if (document.hidden) return; try { const r = await fetch("/api/research/running", { credentials: "same-origin" }); if (r.ok) el.classList.toggle("on", !!(await r.json()).running); } catch (_) {} };
  poll(); setInterval(poll, 15000); document.addEventListener("visibilitychange", poll);
})();
