// Settings (#/settings/<doc>): policy, host policy, known-benign list and site values, edited as tables.
// They live in the SQLite `cfg` table (store.py cfg_*); this page is the only editor. A section is saved as a whole
// (POST /api/config/cfg {doc, path:[section], value}); the server validates it before storing.
(() => {
  const DOCS = [["policy", "Network policy"], ["host_policy", "Endpoint policy"], ["known_benign", "Known benign"], ["site", "Site"]];
  const HELP = {
    policy: "Segmentation zones, device classes, sensitive ports and the flows that are allowed between zones.",
    host_policy: "Rules for endpoint (osquery / Fleet) findings: suspicious paths, processes and ports, trusted tools, admin sources.",
    known_benign: "Signatures, names, DNS and beacon domains that are treated as benign. The review job adds to this.",
    site: "Your network's addresses, host names, URLs and display names. Dashboard-wide values (risk, crown jewels) apply after a dashboard restart; jobs pick changes up on their next run.",
  };
  const h = (tag, attrs, ...kids) => {
    const e = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) { if (k === "class") e.className = v; else if (k.startsWith("on")) e[k] = v; else if (v === true) e.setAttribute(k, ""); else if (v !== false && v != null) e.setAttribute(k, v); }
    for (const c of kids.flat()) e.append(c instanceof Node ? c : document.createTextNode(c ?? ""));
    return e;
  };
  const kind = (v) => (v === null ? "null" : Array.isArray(v) ? "array" : typeof v);
  const isObj = (v) => v && typeof v === "object" && !Array.isArray(v);
  const blankLike = (v) => (Array.isArray(v) ? [] : isObj(v) ? {} : typeof v === "number" ? 0 : typeof v === "boolean" ? false : "");

  // Each editor: { el, get() }. get() throws Error(text) when a value is invalid.
  function scalar(v, ed) {
    if (typeof v === "boolean") { const i = h("input", { type: "checkbox", disabled: !ed }); i.checked = v; return { el: i, get: () => i.checked }; }
    const long = typeof v === "string" && (v.length > 70 || v.includes("\n"));
    const i = long ? h("textarea", { rows: Math.min(6, Math.ceil(v.length / 70) + 1), disabled: !ed }) : h("input", { type: "text", disabled: !ed });
    i.value = v === null ? "" : String(v); i.style.width = "100%"; i.style.minWidth = "9em";
    const t = typeof v;
    return { el: i, get: () => {
      const s = i.value;
      if (t === "number") { if (s.trim() === "" || isNaN(Number(s))) { i.style.outline = "2px solid #f85149"; throw new Error(`"${s}" is not a number`); } i.style.outline = ""; return Number(s); }
      return v === null && s === "" ? null : s;
    } };
  }

  function editor(v, ed, key) {
    if (Array.isArray(v)) return list(v, ed, key);
    if (isObj(v)) return dict(v, ed, key);
    return scalar(v, ed);
  }

  const delBtn = (fn, ed) => h("button", { type: "button", class: "small", title: "Remove this row", onclick: fn, disabled: !ed }, "✕");

  function filterBox(tbl, n) {
    if (n <= 12) return null;
    const f = h("input", { type: "search", placeholder: `filter ${n} rows`, style: "margin:4px 0;width:16em" });
    f.oninput = () => { const q = f.value.toLowerCase(); tbl.querySelectorAll("tbody tr").forEach((tr) => { const t = [...tr.querySelectorAll("input,textarea")].map((x) => x.value).join(" ").toLowerCase(); tr.style.display = !q || t.includes(q) ? "" : "none"; }); };
    return f;
  }

  // a column some rows never had stays absent from those rows unless the user filled it in
  function cellsOut(cols, r) {
    const o = {};
    for (const c of cols) { const v = r.cells[c].get(); if (r.absent?.has(c) && JSON.stringify(v) === JSON.stringify(blankLike(v))) continue; o[c] = v; }
    return o;
  }

  function list(arr, ed, key) {
    const objs = arr.length && arr.every(isObj);
    const cols = objs ? [...new Set(arr.flatMap((o) => Object.keys(o)))] : [];
    const numeric = arr.length ? arr.every((x) => typeof x === "number") : /port/i.test(key || "");
    const tb = h("tbody"), rows = [];
    const sample = objs ? Object.fromEntries(cols.map((c) => [c, blankLike(arr.find((o) => c in o)?.[c])])) : (numeric ? 0 : "");
    const addRow = (item) => {
      const tr = h("tr"); const r = {};
      if (objs) { r.cells = {}; r.absent = new Set(cols.filter((c) => !(c in item))); cols.forEach((c) => { const e = editor(item[c] ?? blankLike(sample[c]), ed, c); r.cells[c] = e; tr.append(h("td", {}, e.el)); }); }
      else { r.e = scalar(item, ed); tr.append(h("td", {}, r.e.el)); }
      tr.append(h("td", {}, delBtn(() => { rows.splice(rows.indexOf(r), 1); tr.remove(); }, ed))); r.tr = tr; rows.push(r); tb.append(tr);
    };
    arr.forEach(addRow);
    const tbl = h("table", { class: "cfg-tbl" }, h("thead", {}, h("tr", {}, objs ? cols.map((c) => h("th", {}, c)) : h("th", {}, "Value"), h("th"))), tb);
    const add = h("button", { type: "button", class: "small", onclick: () => { addRow(objs ? JSON.parse(JSON.stringify(sample)) : sample); tb.lastChild.querySelector("input,textarea")?.focus(); }, disabled: !ed }, "+ Add row");
    const wrap = h("div", {}, filterBox(tbl, arr.length), arr.length > 30 ? h("div", { style: "max-height:420px;overflow:auto" }, tbl) : tbl, ed ? add : "");
    return { el: wrap, get: () => rows.map((r) => (objs ? cellsOut(cols, r) : r.e.get())) };
  }

  function dict(o, ed, key) {
    const entries = Object.entries(o);
    const vals = entries.filter(([k]) => !k.startsWith("_")).map(([, v]) => v);
    const matrix = vals.length > 0 && vals.every((x) => isObj(x) && Object.keys(x).length);
    const cols = matrix ? [...new Set(vals.flatMap((x) => Object.keys(x)))] : [];
    const sample = matrix ? Object.fromEntries(cols.map((c) => [c, blankLike(vals.find((x) => c in x)?.[c])])) : (vals.length ? blankLike(vals[0]) : "");
    const tb = h("tbody"), rows = [];
    const addRow = (k, v, fresh) => {
      const tr = h("tr"), r = { ro: k.startsWith("_"), orig: k };
      const ki = h("input", { type: "text", value: k, disabled: !ed || r.ro, style: "min-width:8em" });
      r.key = ki; tr.append(h("td", {}, ki));
      if (r.ro) { r.keep = v; tr.append(h("td", { colspan: matrix ? cols.length : 1, class: "muted small" }, typeof v === "string" ? v : JSON.stringify(v))); tb.append(tr); rows.push(r); return; }
      if (matrix) { r.cells = {}; r.absent = new Set(cols.filter((c) => !(c in v))); cols.forEach((c) => { const e = editor(v[c] ?? blankLike(sample[c]), ed, c); r.cells[c] = e; tr.append(h("td", {}, e.el)); }); }
      else { r.e = editor(v, ed, k); tr.append(h("td", {}, r.e.el)); }
      tr.append(h("td", {}, delBtn(() => { rows.splice(rows.indexOf(r), 1); tr.remove(); }, ed))); r.tr = tr; rows.push(r); tb.append(tr);
      if (fresh) ki.focus();
    };
    entries.forEach(([k, v]) => addRow(k, v));
    const tbl = h("table", { class: "cfg-tbl" }, h("thead", {}, h("tr", {}, h("th", {}, "Key"), matrix ? cols.map((c) => h("th", {}, c)) : h("th", {}, "Value"), h("th"))), tb);
    const add = h("button", { type: "button", class: "small", disabled: !ed, onclick: () => addRow("", matrix ? JSON.parse(JSON.stringify(sample)) : sample, true) }, "+ Add row");
    const n = entries.filter(([k]) => !k.startsWith("_")).length;
    const wrap = h("div", {}, filterBox(tbl, n), n > 30 ? h("div", { style: "max-height:420px;overflow:auto" }, tbl) : tbl, ed ? add : "");
    return { el: wrap, get: () => {
      const out = {};
      for (const r of rows) {
        const k = r.ro ? r.orig : r.key.value.trim();
        if (!k) { r.key.style.outline = "2px solid #f85149"; throw new Error("every row needs a key"); }
        if (k in out) { r.key.style.outline = "2px solid #f85149"; throw new Error(`duplicate key "${k}"`); }
        r.key.style.outline = "";
        out[k] = r.ro ? r.keep : matrix ? cellsOut(cols, r) : r.e.get();
      }
      return out;
    } };
  }

  // Auto-discover zones, zone roles and device classes from UniFi (POST /api/config/discover)
  function discoverCard(reload) {
    const out = h("div", { style: "margin-top:8px" }), msg = h("span", { class: "small", style: "margin-left:10px" });
    const tbl = (cols, rows) => h("table", { class: "cfg-tbl" }, h("thead", {}, h("tr", {}, cols.map((c) => h("th", {}, c)))), h("tbody", {}, rows.map((r) => h("tr", {}, r.map((c) => h("td", {}, c ?? ""))))));
    const call = async (body) => { msg.style.color = ""; msg.textContent = "Asking UniFi…"; try { const r = await apiPost("/api/config/discover", body); msg.textContent = ""; return r; } catch (e) { msg.style.color = "#f85149"; msg.textContent = String(e.message || e).replace(/^.*?→ \d+\s*/, ""); return null; } };
    const preview = h("button", { type: "button", onclick: async () => {
      const r = await call({}); if (!r) return;
      const d = r.detail, nz = d.zones.filter((z) => !z.existing).length;
      out.innerHTML = "";
      out.append(h("div", { class: "muted small" }, `${d.zones.length} networks (${nz} new), ${d.devices.length} devices classified. Roles: dmz = exposed, protected = servers/clusters, mgmt = IPMI/infrastructure, user, iot. Edit any of it below after applying.`),
        tbl(["Zone", "Subnet", "Role", "UniFi network", "Clients", "New"], d.zones.map((z) => [z.zone, z.cidr, z.role, z.network, z.members, z.existing ? "" : "new"])),
        h("details", {}, h("summary", {}, `${d.devices.length} device classes`),
          tbl(["Device", "IP", "Zone", "Class", "Why"], d.devices.map((x) => [x.name, x.ip, x.zone, x.class, x.why]))),
        h("div", { style: "margin-top:8px" },
          h("button", { type: "button", onclick: async () => { const a = await call({ apply: true }); if (a) { alert("Applied: " + JSON.stringify(a.applied)); reload(); } } }, "Apply (add what's missing)"), " ",
          h("button", { type: "button", onclick: async () => { if (!confirm("Overwrite your existing zone roles and device classes where UniFi disagrees?")) return; const a = await call({ apply: true, overwrite: true }); if (a) { alert("Applied: " + JSON.stringify(a.applied)); reload(); } } }, "Apply & overwrite differences")));
    } }, "Discover from UniFi");
    return card("Auto-discover from UniFi", h("div", {}, h("div", { class: "muted small" }, "Reads your UniFi networks (zones + roles), clients and UniFi's device fingerprints (device classes). Nothing is changed until you apply; existing entries are kept unless you choose overwrite."), h("div", { style: "margin-top:6px" }, preview, msg), out));
  }

  V.settings = async (el, arg) => {
    const doc = DOCS.some(([d]) => d === arg) ? arg : "policy";
    el.innerHTML = `<div class="loading">Loading…</div>`;
    let r; try { r = await api("/api/config/cfg?doc=" + doc); } catch (e) { el.innerHTML = `<div class="empty">Settings are visible to admins and defenders only.</div>`; return; }
    const ed = !!r.admin, data = r.data;
    el.innerHTML = "";
    el.append(h("div", { class: "fchips" }, DOCS.map(([d, t]) => h("a", { href: "#/settings/" + d, class: "chip" + (d === doc ? " on" : ""), style: d === doc ? "font-weight:700" : "" }, t))));
    el.append(h("div", { class: "muted small", style: "margin:6px 0" }, HELP[doc], ed ? " Each section has its own Save button." : " Read-only: only an admin can change settings."));
    if (doc === "policy" && ed) el.append(discoverCard(() => V.settings(el, doc)));
    const notes = Object.entries(data).filter(([k]) => k.startsWith("_")).map(([k, v]) => `${k.replace(/^_doc_?/, "") || "about"}: ${v}`);
    if (notes.length) el.append(h("details", { class: "muted small", style: "margin-bottom:8px" }, h("summary", {}, "Notes on these settings"), notes.map((n) => h("p", {}, n))));
    const msg = (box, text, bad) => { box.textContent = text; box.style.color = bad ? "#f85149" : "#3fb950"; };
    const save = async (path, value, box) => {
      try { await apiPost("/api/config/cfg", { doc, path, value }); msg(box, "Saved " + new Date().toLocaleTimeString()); }
      catch (e) { msg(box, String(e.message || e).replace(/^.*?→ \d+\s*/, ""), true); }
    };
    // scalar top-level values: one General table
    const gen = Object.entries(data).filter(([k, v]) => !k.startsWith("_") && !Array.isArray(v) && !isObj(v));
    if (gen.length) {
      const eds = gen.map(([k, v]) => [k, v, scalar(v, ed)]);
      const box = h("span", { class: "small", style: "margin-left:10px" });
      const tbl = h("table", { class: "cfg-tbl" }, h("thead", {}, h("tr", {}, h("th", {}, "Setting"), h("th", {}, "Value"))), h("tbody", {}, eds.map(([k, , e]) => h("tr", {}, h("td", {}, k), h("td", {}, e.el)))));
      const btn = h("button", { type: "button", disabled: !ed, onclick: async () => {
        try { for (const [k, v, e] of eds) { const nv = e.get(); if (JSON.stringify(nv) !== JSON.stringify(v)) { await save([k], nv, box); eds.find((x) => x[0] === k)[1] = nv; } } } catch (er) { msg(box, er.message, true); }
      } }, "Save");
      el.append(card("General", h("div", {}, tbl, ed ? h("div", { style: "margin-top:6px" }, btn, box) : "")));
    }
    for (const [k, v] of Object.entries(data)) {
      if (k.startsWith("_") || !(Array.isArray(v) || isObj(v))) continue;
      const e = editor(v, ed, k), box = h("span", { class: "small", style: "margin-left:10px" });
      const count = Array.isArray(v) ? v.length : Object.keys(v).filter((x) => !x.startsWith("_")).length;
      const btn = h("button", { type: "button", disabled: !ed, onclick: async () => { let val; try { val = e.get(); } catch (er) { msg(box, er.message, true); return; } await save([k], val, box); } }, "Save " + k);
      el.append(card(`${esc(k)} <span class="muted small">(${count})</span>`, h("div", {}, e.el, ed ? h("div", { style: "margin-top:6px" }, btn, box) : "")));
    }
  };
})();
