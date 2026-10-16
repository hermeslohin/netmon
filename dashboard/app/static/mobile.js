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
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") set(false); });
  const label = () => {  // show the current section name next to the hamburger
    const v = (location.hash.replace(/^#\/?/, "").split(/[/?]/)[0] || "overview");
    const map = { device: "devices", endpoint: "endpoints", tls: "dns" };
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
