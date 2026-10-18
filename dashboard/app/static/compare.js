// Compare models on one dashboard item (triage alarm, triage research note, baseline finding, host finding, event
// research note). Buttons come from cmpBtn() (app.js); the dialog asks up to 4 models (local LM Studio or an AI provider)
// (or an admin-added API-key provider)
// for {verdict, priority, summary, reasoning} side by side. For event research notes a person can adopt an answer.
(() => {
  const PROV = { lmstudio: "Local (LM Studio)" };
  let M = null, dlg = null;
  const models = async () => { M = M || await api("/api/llm/models"); for (const g of M.custom || []) PROV[g.provider] = g.name; return M; };
  const el = (tag, props = {}, ...kids) => { const e = Object.assign(document.createElement(tag), props); e.append(...kids.filter((k) => k != null)); return e; };
  const VCLS = { malicious: "sev-high", suspicious: "sev-high", "needs-review": "sev-medium", benign: "sev-good", expected: "sev-good" };

  function results(rows, p, adoptable) {
    const t = el("table", { className: "cmp-tbl" });
    t.createTHead().insertRow().append(...["Model", "Verdict", "Priority", "Assessment", "Time", "Tokens", ""].map((h) => el("th", { textContent: h })));
    const tb = t.createTBody();
    for (const x of rows) {
      const tr = tb.insertRow();
      tr.insertCell().append(el("div", { textContent: x.model }), el("div", { className: "small muted", textContent: PROV[x.provider] || x.provider || "" }));
      if (x.error) { const c = tr.insertCell(); c.colSpan = 3; c.className = "bad small"; c.textContent = x.error; }
      else {
        tr.insertCell().append(el("span", { className: "badge " + (VCLS[x.verdict] || "sev-info"), textContent: x.verdict || "" }));
        tr.insertCell().textContent = x.priority || "";
        tr.insertCell().append(el("b", { textContent: x.summary || "" }), el("div", { className: "small", textContent: x.reasoning || "" }));
      }
      tr.insertCell().textContent = x.seconds == null ? "" : `${(+x.seconds).toFixed(1)} s`;
      const u = x.usage || { prompt: x.prompt_tokens, completion: x.completion_tokens };
      tr.insertCell().textContent = u.prompt == null ? "" : `${fn(u.prompt)} in · ${fn(u.completion)} out`;
      const a = tr.insertCell();
      if (adoptable && !x.error && p.eid) {
        const b = a.appendChild(el("button", { type: "button", textContent: "Use this", title: "Make this the event's research note" }));
        b.onclick = async () => { b.disabled = true;
          try { await apiPost("/api/compare/adopt", { event: p.eid, verdict: x.verdict, priority: x.priority, summary: x.summary, reasoning: x.reasoning, model: x.model });
            b.textContent = "✓ used"; S.corr = null; } catch (e) { b.textContent = e.message; } };
      }
    }
    return t;
  }

  async function open(p) {
    dlg?.remove();
    dlg = document.body.appendChild(el("dialog", { className: "cmp-dlg" }));
    const x = el("button", { type: "button", className: "rel-x", textContent: "✕", ariaLabel: "Close" }); x.onclick = () => dlg.close();
    dlg.append(el("div", { className: "cmp-head" }, el("b", { textContent: `Compare models on this ${p.kind}` }), x));
    dlg.append(el("div", { className: "small", textContent: p.title }));
    const pick = dlg.appendChild(el("div", { className: "cmp-pick" })), out = dlg.appendChild(el("div", { className: "cmp-out" })), hist = dlg.appendChild(el("details", { className: "small" }));
    dlg.showModal();
    let L; try { L = await models(); } catch (e) { pick.textContent = e.message; return; }
    if (!L.admin) { pick.textContent = "Only an admin can run comparisons."; }
    else {
      pick.append(el("div", { className: "small muted", textContent: "Pick up to 4 models. Each sees only this item's data (no tools or web lookups) and gives a verdict, priority and reasoning." }));
      const loaded = (L.local || []).find((m) => m.loaded)?.id;
      const def = new Set([`lmstudio|${loaded}`]);
      for (const [prov, id, extra] of [...(L.local || []).map((m) => ["lmstudio", m.id, m.loaded ? " (loaded)" : " (not loaded: LM Studio loads it first, slow)"]), ...(L.custom || []).flatMap((g) => g.models.map((m) => [g.provider, m.id, ""]))]) {
        const cb = el("input", { type: "checkbox", value: `${prov}|${id}`, checked: def.has(`${prov}|${id}`) });
        cb.onchange = () => { if (pick.querySelectorAll("input:checked").length > 4) cb.checked = false; };
        pick.append(el("label", { className: "cmp-opt" }, cb, ` ${id}`, el("span", { className: "muted small", textContent: ` ${PROV[prov]}${extra}` })));
      }
      const go = pick.appendChild(el("button", { type: "button", textContent: "Run comparison" }));
      go.onclick = async () => {
        const targets = [...pick.querySelectorAll("input:checked")].map((c) => { const [provider, ...m] = c.value.split("|"); return { provider, model: m.join("|") }; });
        if (!targets.length) return;
        go.disabled = true; out.textContent = `Asking ${targets.length} model(s)…`;
        try { const R = await apiPost("/api/compare/item", { kind: p.kind, title: p.title, item: p.item, targets }); out.replaceChildren(results(R.results, p, true)); p.key = R.key; loadHist(); }
        catch (e) { out.textContent = "Error: " + e.message; }
        go.disabled = false;
      };
    }
    const loadHist = async () => { if (!p.key) return; try { const H = (await api("/api/compare/item?key=" + encodeURIComponent(p.key))).history || [];
      hist.replaceChildren(el("summary", { textContent: `Earlier comparisons (${H.length})` }));
      if (H.length) hist.appendChild(results(H.map((h) => ({ ...h, model: `${h.model} · ${new Date(h.ts * 1000).toLocaleString()}` })), p, false)); } catch (_) {} };
    try { const h = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`${p.kind}\x1f${p.title}`));
      p.key = [...new Uint8Array(h)].map((b) => b.toString(16).padStart(2, "0")).join("").slice(0, 32); loadHist(); } catch (_) {}
  }
  window.openItemCompare = open;
  document.addEventListener("click", (e) => {
    const b = e.target.closest("[data-icmp]"); if (!b) return;
    e.preventDefault(); e.stopPropagation();
    const p = CMP.get(b.dataset.icmp); if (p) open({ ...p });
  }, true);
})();
