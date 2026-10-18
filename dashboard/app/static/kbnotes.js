// Notes knowledge base (kb.py): host/device notes (written mostly by the AI, people may add/delete) shown on the host
// and endpoint pages and on the Notes page, plus people's event notes behind the 📝 button next to every event's
// Related count (related.js adds the button). The AI reads both before deciding (4-hourly research, correlation
// reviewer, chat assistant).
(() => {
  const CATS = ["role", "baseline", "behavior", "decision", "risk", "config", "watch", "other"];
  const when = (t) => (t ? ft(new Date(t * 1000).toISOString()) : "");
  const by = (n) => (n.author === "ai" ? aiFlare({ model: n.model, via: n.via || "AI host notes", at: n.updated ? new Date(n.updated * 1000).toISOString() : "" })
    : `<span class="kb-user" title="Written by a person">👤 ${esc(String(n.author || "").replace(/^user:/, ""))}</span>`);

  /* ---------- host / device notes card ---------- */
  // subjects: every subject whose notes belong on this page; primary: where a new note is stored
  window.kbCard = (subjects, primary) => {
    const c = card(`Notes <span class="kb-n muted small"></span>`, `<div class="kb-list"><div class="muted small">Loading notes…</div></div>
      <form class="kb-form"><select class="kb-cat" aria-label="Category">${CATS.map((x) => `<option${x === "other" ? " selected" : ""}>${x}</option>`).join("")}</select>
      <textarea class="kb-text" rows="2" maxlength="2000" placeholder="Add a note about this device (role, what is normal, decisions)…"></textarea>
      <button type="submit">Add note</button></form>
      <div class="small muted">AI runs read these notes before judging this device and add what they learn (✨). Notes by people (👤) are treated as authoritative.</div>`, "kb-card");
    const list = c.querySelector(".kb-list");
    const load = () => api("/api/kb/host?s=" + encodeURIComponent(subjects.filter(Boolean).join(","))).then((d) => {
      const ns = d.notes || [];
      c.querySelector(".kb-n").textContent = ns.length ? `(${ns.length})` : "";
      list.innerHTML = ns.length ? ns.map((n) => `<div class="kb-note"><div class="kb-meta"><span class="badge">${esc(n.category)}</span> ${by(n)}
          <span class="muted small">${esc(when(n.updated))}${subjects.length > 1 && n.subject !== primary ? " · " + esc(n.subject) : ""}</span>
          <button type="button" class="kb-del" data-id="${esc(n.id)}" title="Delete this note" aria-label="Delete note">✕</button></div>
          <div class="kb-text-v">${esc(n.text)}</div></div>`).join("")
        : `<div class="empty">No notes yet. The AI adds notes as it learns about this device; you can add your own below.</div>`;
    }).catch((e) => { list.innerHTML = `<div class="empty">Notes unavailable: ${esc(e.message)}</div>`; });
    c.addEventListener("click", (e) => {
      const b = e.target.closest(".kb-del"); if (!b) return;
      if (!confirm("Delete this note?")) return;
      apiPost("/api/kb/host", { action: "delete", id: +b.dataset.id }).then(load, (er) => alert(er.message));
    });
    c.querySelector(".kb-form").addEventListener("submit", (e) => {
      e.preventDefault();
      const t = c.querySelector(".kb-text"), txt = t.value.trim(); if (!txt) return;
      apiPost("/api/kb/host", { action: "add", subject: primary, category: c.querySelector(".kb-cat").value, text: txt }).then(() => { t.value = ""; load(); }, (er) => alert(er.message));
    });
    load();
    return c;
  };

  /* ---------- Notes page ---------- */
  const subjLink = (s, label) => {
    const [k, ...r] = String(s).split(":"), v = r.join(":");
    if (k === "host") return `<a href="#/endpoint/${encodeURIComponent(v)}">${esc(v)}</a> <span class="muted small">endpoint</span>`;
    const ip = k === "ip" ? v : Object.keys(S.idx?.byIp || {}).find((i) => String(S.idx.byIp[i].mac || "").toLowerCase() === v);
    const name = esc(label && label !== v ? label : (ip && S.idx?.byIp?.[ip]?.name) || v);
    return ip && S.snap?.raw?.devices?.[ip] ? `<a href="#/device/${encodeURIComponent(ip)}">${name}</a> <span class="muted small mono">${esc(ip)}</span>` : `${name} <span class="muted small mono">${esc(v)}</span>`;
  };
  V.notes = async (el) => {
    el.innerHTML = `<h1>Notes</h1><div class="sub">What the AI has learned about each host and device, and the notes people left on events (📝 next to an event's Related count). The 4-hourly AI research, the correlation reviewer and Ask Hermes read these before deciding.</div>`;
    const d = await api("/api/kb/all");
    const hn = d.host_notes || [], en = d.event_notes || [];
    el.insertAdjacentHTML("beforeend", kpis([["Host notes", hn.length], ["Devices with notes", new Set(hn.map((n) => n.subject)).size], ["By AI", hn.filter((n) => n.author === "ai").length], ["Event notes", en.length]]));
    el.appendChild(card(`Host notes (${hn.length})`, hn.length ? table(null, [{ k: "subject", t: "Device / host", fmt: (v, n) => subjLink(v, n.label) }, { k: "category", t: "Category", fmt: (v) => `<span class="badge">${esc(v)}</span>` },
      { k: "text", t: "Note", fmt: (v) => `<div class="kb-text-v">${esc(v)}</div>` }, { k: "author", t: "By", fmt: (v, n) => by(n) }, { k: "updated", t: "Updated", fmt: (v) => esc(when(v)) }],
      hn, { sort: "updated" }) : `<div class="empty">No host notes yet. The AI writes them during its 4-hourly research; you can add notes on any host or endpoint page.</div>`));
    el.appendChild(card(`Event notes (${en.length})`, en.length ? table(null, [{ k: "label", t: "Event", fmt: (v, n) => esc(v || n.eid) }, { k: "text", t: "Note", fmt: (v) => `<div class="kb-text-v">${esc(v)}</div>` },
      { k: "author", t: "By", fmt: (v) => `👤 ${esc(v)}` }, { k: "ts", t: "When", fmt: (v) => esc(when(v)) }],
      en, { sort: "ts" }) : `<div class="empty">No event notes yet. Click 📝 next to any event's Related count to add one.</div>`));
  };

  /* ---------- event notes popover (📝) ---------- */
  let pop = null;
  const close = () => { pop?.remove(); pop = null; };
  function refreshBtns(eid) {
    const n = (S.corr?.unotes?.[eid] || []).length;
    document.querySelectorAll(".unote-btn").forEach((b) => { if (b.dataset.unote === eid) { b.textContent = n ? `📝 ${n}` : "📝"; b.classList.toggle("has", n > 0); } });
  }
  function render(btn) {
    const eid = btn.dataset.unote, me = S.corr?.events?.[eid], ns = S.corr?.unotes?.[eid] || [];
    pop.innerHTML = `<div class="rel-head"><b>Your notes</b> <span class="muted small">${esc(me ? me.label.slice(0, 90) : eid)}</span><button type="button" class="rel-x" aria-label="Close">✕</button></div>
      <div class="note-body">
        ${ns.map((n) => `<div class="kb-note"><div class="kb-meta">👤 <b>${esc(n.author)}</b> <span class="muted small">${esc(when(n.ts))}${n.same_event ? "" : " · written on an earlier run of this event"}</span>
          <button type="button" class="kb-del" data-id="${esc(n.id)}" aria-label="Delete note" title="Delete">✕</button></div><div class="kb-text-v">${esc(n.text)}</div></div>`).join("") || `<div class="muted small">No notes on this event yet.</div>`}
        <textarea class="kb-text" rows="3" maxlength="2000" placeholder="e.g. Expected: this is my nightly backup. / Escalate if seen again from this host."></textarea>
        <div><button type="button" class="kb-save">Save note</button></div>
        <div class="small muted">The AI reads your notes on this event (and on later repeats of it) in its 4-hourly research and when deciding which events are related, and treats them as authoritative guidance.</div>
      </div>`;
    pop.querySelector(".rel-x").onclick = close;
    pop.querySelector(".kb-save").onclick = () => {
      const t = pop.querySelector(".kb-text").value.trim(); if (!t) return;
      apiPost("/api/kb/event", { action: "add", eid, label: me?.label || "", text: t }).then((r) => { (S.corr.unotes ||= {})[eid] = r.notes || []; refreshBtns(eid); render(btn); }, (er) => alert(er.message));
    };
    pop.querySelectorAll(".kb-del").forEach((b) => b.onclick = () => {
      if (!confirm("Delete this note?")) return;
      apiPost("/api/kb/event", { action: "delete", id: +b.dataset.id, eid }).then((r) => { (S.corr.unotes ||= {})[eid] = r.notes || []; refreshBtns(eid); render(btn); }, (er) => alert(er.message));
    });
  }
  function open(btn) {
    close();
    pop = document.createElement("div"); pop.className = "rel-pop note-pop unote-pop"; pop.setAttribute("role", "dialog"); pop._for = btn;
    document.body.appendChild(pop); render(btn);
    const r = btn.getBoundingClientRect(), w = Math.min(480, innerWidth - 16);
    pop.style.width = w + "px";
    pop.style.left = Math.max(8, Math.min(innerWidth - w - 8, r.right - w)) + "px";
    const below = r.bottom + 6, h = pop.offsetHeight;
    pop.style.top = (below + h > innerHeight - 8 && r.top - h - 6 > 8 ? r.top - h - 6 : Math.min(below, innerHeight - Math.min(h, innerHeight - 16) - 8)) + "px";
    pop.querySelector(".kb-text")?.focus();
  }
  document.addEventListener("click", (e) => {
    const b = e.target.closest(".unote-btn");
    if (b) { e.stopPropagation(); e.preventDefault(); if (pop && pop._for === b) return close(); return open(b); }
    if (pop && !e.target.closest(".unote-pop")) close();
  }, true);
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") close(); });
  addEventListener("hashchange", close);
})();
