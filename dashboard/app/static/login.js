"use strict";
document.getElementById("u").focus();
document.getElementById("f").addEventListener("submit", async (e) => {
  e.preventDefault();
  const err = document.getElementById("err"); err.textContent = "";
  const btn = e.target.querySelector("button"); btn.disabled = true;
  try {
    const r = await fetch("/api/login", { method: "POST", headers: { "Content-Type": "application/json", "X-Netmon": "1" },
      body: JSON.stringify({ username: document.getElementById("u").value.trim(), password: document.getElementById("p").value }) });
    const j = await r.json().catch(() => ({}));
    if (r.ok) { location.href = "/" + (location.hash || sessionStorage.getItem("netmon_next") || ""); sessionStorage.removeItem("netmon_next"); return; }
    err.textContent = j.error || "Sign-in failed";
  } catch (x) { err.textContent = String(x); }
  btn.disabled = false;
});
