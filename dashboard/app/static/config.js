// More -> Configuration (#/config). Security Triage card: auto-close events the AI research marked "expected" / "benign".
(() => {
  const EXPLAIN = {
    expected: `<b>Expected</b> — the activity is <i>supposed</i> to happen: a known device doing its known job, or something you did on purpose. Examples: a thermostat checking in with its vendor cloud, OneDrive keeping its push channel open, your own admin SSH logins, the dashboard sending web-push notifications. The detection is accurate (the traffic really is new or unusual against the baseline), it is just explained by normal, intended operation.`,
    benign: `<b>Benign</b> — the activity <i>looked</i> suspicious and the research found it harmless, but it is not part of a device's planned behavior: an IDS rule misfiring (a false positive), a one-off anomaly, or a device reaching a new but legitimate service. Examples: Suricata flagging replies on a Mac's own outbound sessions as a "listening port", an Echo contacting a new Apple Music domain. Harmless, but less predictable than "expected", so closing it automatically is a slightly bigger leap of trust.`,
  };
  const row = (k, D) => {
    const r = D[k] || {}, on = !!D.settings?.[k];
    return `<div class="cfg-opt" style="border-top:1px solid var(--line,#333);padding:12px 0">
      <label style="display:flex;gap:10px;align-items:flex-start;cursor:${D.admin ? "pointer" : "default"}">
        <input type="checkbox" class="cfg-ac" data-k="${k}" ${on ? "checked" : ""} ${D.admin ? "" : "disabled"} style="margin-top:3px">
        <span><b>Automatically move events deemed “${k}” to closed findings</b> ${on ? '<span class="badge sev-good">On</span>' : '<span class="badge sev-unknown">Off</span>'}
          <div class="muted small" style="margin-top:4px">${EXPLAIN[k]}</div></span></label>
      <div class="small" style="margin:8px 0 0 28px">In the newest snapshot: <b>${r.closable || 0}</b> closable “${k}” items ·
        <b>${r.auto_closed || 0}</b> auto-closed · <b>${r.would_close || 0}</b> ${on ? "waiting for the next pass" : "would be closed if turned on"}
        ${r.reopened_by_user ? ` · ${r.reopened_by_user} reopened by a person (left open)` : ""}
        ${r.no_checklist ? ` · <span class="muted">${r.no_checklist} more without a check-off list (IDS / alerts / gateway / threat intel — not closable)</span>` : ""}
        ${D.admin && r.auto_closed ? ` <button class="cfg-reopen" data-k="${k}" style="margin-left:6px">Reopen ${r.auto_closed} auto-closed</button>` : ""}</div></div>`;
  };
  async function paint(el, D) {
    el.querySelector("#cfg-triage")?.remove();
    const s = D.settings || {};
    const c = card("Security Triage", `<div class="sub" style="margin:0 0 6px">Every 4 hours the Hermes research job writes a note with a verdict for each event
      (malicious, suspicious, needs-review, benign or expected; the “✨” button next to an event). These options check off the events whose verdict is
      “expected” or “benign”, moving them to <a href="#/checked">Checked (closed findings)</a> with the note <span class="mono">auto-closed: AI verdict …</span>.
      Applies to baseline findings, endpoint findings and fix-list issues; runs every 5 minutes and right after you save.
      Items you have already checked off are untouched; if you uncheck an auto-closed item it stays open; if the AI later changes the verdict to something
      else (e.g. suspicious) the item reopens by itself. Turning an option off stops new closures — use “Reopen” to restore what was closed.</div>
      ${row("expected", D)}${row("benign", D)}
      <div class="muted small" style="border-top:1px solid var(--line,#333);padding-top:8px">${D.admin ? "" : "Only an admin can change these settings. "}
        ${s.updated_by ? `Last changed by ${esc(s.updated_by)} ${esc(ft(s.updated_at))}.` : "Never changed (both off)."}
        ${D.reopened_verdict_changed ? ` ${D.reopened_verdict_changed} item(s) reopened because the verdict changed.` : ""}
        ${D.last_run ? ` Last pass ${esc(ft(D.last_run))}.` : ""}</div>`);
    c.id = "cfg-triage"; el.appendChild(c);
    const save = async (body, url = "/api/config/triage") => {
      c.style.opacity = 0.6;
      try { const R = await apiPost(url, body); S.acks = await api("/api/acks").catch(() => S.acks); paint(el, R); }
      catch (e) { c.style.opacity = 1; alert(String(e)); }
    };
    c.querySelectorAll(".cfg-ac").forEach((cb) => (cb.onchange = () => {
      const v = { expected: !!s.expected, benign: !!s.benign, [cb.dataset.k]: cb.checked };
      const n = D[cb.dataset.k]?.would_close || 0;
      if (cb.checked && n && !confirm(`This closes ${n} “${cb.dataset.k}” item(s) now and keeps doing so for new ones. Continue?`)) { cb.checked = false; return; }
      save(v);
    }));
    c.querySelectorAll(".cfg-reopen").forEach((b) => (b.onclick = () => {
      if (confirm(`Reopen every auto-closed “${b.dataset.k}” item? They will not be auto-closed again (the option stays ${s[b.dataset.k] ? "on for new items" : "off"}).`)) save({ kind: b.dataset.k }, "/api/config/triage/reopen");
    }));
  }
  V.config = async (el) => {
    el.innerHTML = `<h1>Configuration</h1><div class="sub">Dashboard-wide settings (they apply to every user).</div><div class="loading">Loading…</div>`;
    let D; try { D = await api("/api/config/triage"); } catch (e) { el.querySelector(".loading").textContent = String(e); return; }
    el.querySelector(".loading").remove();
    paint(el, D);
  };
})();
