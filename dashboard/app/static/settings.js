// Settings (#/settings/<doc>): policy, host policy, known-benign list and site values, edited as tables.
// They live in the SQLite `cfg` table (store.py cfg_*); this page is the only editor. A section is saved as a whole, automatically on every edit
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

  // device_classes keys are MACs or IPs: show the host name Syn has learned for each (device registry = UniFi / DHCP /
  // device naming, then the open time range's devices, then the page's name lookup). Display only: never saved.
  const learnedHost = (key, reg, devs, nameOf) => {
    const k = String(key || "").trim().toLowerCase();
    if (!k) return "";
    const hit = (d) => d && (String(d.mac || "").toLowerCase() === k || (d.ips || []).includes(key) || (d.ip && d.ip === key));
    for (const [rk, d] of Object.entries(reg || {})) if (rk.toLowerCase() === k || hit(d)) { const n = d.hostname || d.name; if (n) return n; }
    for (const [ip, d] of Object.entries(devs || {})) if (ip === key || hit({ ...d, ip })) { const n = d.hostname || d.name; if (n) return n; }
    return (nameOf && nameOf(key)) || "";
  };
  window.learnedHost = learnedHost;
  const learnedEl = (key) => h("div", { class: "muted small cfg-learned", title: "Host name learned from UniFi / DHCP / device naming (display only)" },
    "learned: " + (learnedHost(key, S.reg?.devices_seen, S.snap?.raw?.devices, S.idx?.nameOf) || "—"));

  // Each editor: { el, get() }. get() throws Error(text) when a value is invalid.
  function scalar(v, ed) {
    if (typeof v === "boolean") { const i = h("input", { type: "checkbox", disabled: !ed }); i.checked = v; return { el: i, get: () => i.checked }; }
    const long = typeof v === "string" && (v.length > 70 || v.includes("\n"));
    const i = long ? h("textarea", { rows: Math.min(6, Math.ceil(v.length / 70) + 1), disabled: !ed }) : h("input", { type: "text", disabled: !ed });
    i.value = v === null ? "" : String(v); i.style.width = "100%"; i.style.minWidth = "9em";
    const t = typeof v;
    return { el: i, get: () => {
      const s = i.value;
      if (t === "number") { if (s.trim() === "" || isNaN(Number(s))) { i.style.outline = "2px solid #e06a5f"; throw new Error(`"${s}" is not a number`); } i.style.outline = ""; return Number(s); }
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
    f.oninput = () => { const q = f.value.toLowerCase(); tbl.querySelectorAll("tbody tr").forEach((tr) => { const t = [...tr.querySelectorAll("input,textarea,select")].map((x) => x.value).concat([...tr.querySelectorAll(".cfg-learned")].map((x) => x.textContent)).join(" ").toLowerCase(); tr.style.display = !q || t.includes(q) ? "" : "none"; }); };
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
      r.key = ki; tr.append(h("td", {}, ki, key === "device_classes" && !r.ro ? learnedEl(k) : ""));
      if (key === "device_classes" && !r.ro) ki.addEventListener("change", () => { const l = tr.querySelector(".cfg-learned"); if (l) l.replaceWith(learnedEl(ki.value.trim())); });
      if (r.ro) { r.keep = v; tr.append(h("td", { colspan: matrix ? cols.length : 1, class: "muted small" }, typeof v === "string" ? v : JSON.stringify(v))); tb.append(tr); rows.push(r); return; }
      if (matrix) { r.cells = {}; r.absent = new Set(cols.filter((c) => !(c in v))); cols.forEach((c) => { const e = editor(v[c] ?? blankLike(sample[c]), ed, c); r.cells[c] = e; tr.append(h("td", {}, e.el)); }); }
      else {
        const sc = SCOPED.includes(key) && (k === "classes" || k === "by_class");
        if (sc) ki.disabled = true;  // the scope rows keep their names
        r.e = key === "device_classes" ? classSelect(v, ed) : sc && k === "classes" ? classMulti(v, ed) : sc ? byClassEditor(v, ed, o) : editor(v, ed, k);
        tr.append(h("td", {}, r.e.el));
      }
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
        if (!k) { r.key.style.outline = "2px solid #e06a5f"; throw new Error("every row needs a key"); }
        if (k in out) { r.key.style.outline = "2px solid #e06a5f"; throw new Error(`duplicate key "${k}"`); }
        r.key.style.outline = "";
        out[k] = r.ro ? r.keep : matrix ? cellsOut(cols, r) : r.e.get();
      }
      return out;
    } };
  }

  // device_classes values: a drop-down of the defined classes (Device class definitions card)
  let CLASSES = [];
  function classSelect(v, ed) {
    const opts = CLASSES.includes(v) || !v ? CLASSES : [...CLASSES, v];
    const s = h("select", { disabled: !ed, class: "cfg-class" }, h("option", { value: "" }, "— pick a class —"), opts.map((c) => h("option", { value: c }, c)));
    s.value = v || "";
    return { el: s, get: () => { if (!s.value) { s.style.outline = "2px solid #e06a5f"; throw new Error("pick a class for every device"); } s.style.outline = ""; return s.value; } };
  }

  // Device-class scope of upload_spike / scan_thresholds / beacon (extras.SCOPED):
  //   classes  = a drop-down of class check boxes: which device classes the rule runs for (none ticked = every device)
  //   by_class = per-class overrides: a class picker plus the section's numbers (blank = use the section's value)
  const SCOPED = ["upload_spike", "scan_thresholds", "beacon"];
  const allClasses = () => [...CLASSES, "unclassified"];
  function classMulti(v, ed) {
    const sel = new Set(Array.isArray(v) ? v.filter((x) => x !== "*") : []);
    const opts = [...new Set([...allClasses(), ...sel])];
    const sum = h("summary", { class: "cfg-scope-sum" });
    const paint = () => { sum.textContent = sel.size ? `Only: ${[...sel].join(", ")}` : "All device classes"; };
    const boxes = opts.map((c) => {
      const cb = h("input", { type: "checkbox", disabled: !ed, value: c, style: "accent-color:#6cc287" }); cb.checked = sel.has(c);
      cb.addEventListener("change", () => { cb.checked ? sel.add(c) : sel.delete(c); paint(); });
      return h("label", { class: "cdef-sw", style: "display:block" }, cb, " ", c);
    });
    const clr = h("button", { type: "button", class: "small", disabled: !ed, onclick: (e) => { sel.clear(); boxes.forEach((l) => { l.firstChild.checked = false; }); paint(); e.target.dispatchEvent(new Event("change", { bubbles: true })); } }, "All classes");
    paint();
    const el = h("details", { class: "cfg-scope", title: "Apply this rule only to devices of the ticked classes (none ticked = every device)" }, sum,
      h("div", { style: "padding:4px 0" }, boxes, h("div", { style: "margin-top:4px" }, clr)));
    return { el, get: () => opts.filter((c) => sel.has(c)) };
  }
  function byClassEditor(v, ed, sec) {
    const fields = Object.entries(sec).filter(([k, x]) => !k.startsWith("_") && k !== "classes" && k !== "by_class" && (typeof x === "number" || typeof x === "string")).map(([k]) => k);
    const tb = h("tbody"), rows = [];
    const addRow = (cls, ov) => {
      const s = h("select", { disabled: !ed }, h("option", { value: "" }, "— class —"), [...new Set([...allClasses(), ...(cls ? [cls] : [])])].map((c) => h("option", { value: c }, c)));
      s.value = cls || "";
      const ins = fields.map((f) => { const i = h("input", { type: "text", disabled: !ed, placeholder: String(sec[f]), title: `blank = the section's ${f} (${sec[f]})`, style: "width:6em" }); i.value = ov && f in ov ? String(ov[f]) : ""; return [f, i]; });
      const tr = h("tr", {}, h("td", {}, s), ins.map(([, i]) => h("td", {}, i)));
      const r = { s, ins, tr };
      tr.append(h("td", {}, delBtn(() => { rows.splice(rows.indexOf(r), 1); tr.remove(); }, ed)));
      rows.push(r); tb.append(tr);
    };
    Object.entries(isObj(v) ? v : {}).filter(([c]) => !c.startsWith("_")).forEach(([c, ov]) => addRow(c, ov));
    const tbl = h("table", { class: "cfg-tbl" }, h("thead", {}, h("tr", {}, h("th", {}, "Class"), fields.map((f) => h("th", {}, f)), h("th"))), tb);
    const add = h("button", { type: "button", class: "small", disabled: !ed, onclick: () => addRow("", {}) }, "+ Class override");
    return { el: h("div", {}, h("div", { class: "muted small" }, "Different numbers for a device class (blank = the value above)."), rows.length || ed ? tbl : "", ed ? add : ""), get: () => {
      const out = {};
      for (const r of rows) {
        const vals = {};
        for (const [f, i] of r.ins) {
          const t = i.value.trim(); i.style.outline = "";
          if (!t) continue;
          if (typeof sec[f] === "number") { if (isNaN(Number(t))) { i.style.outline = "2px solid #e06a5f"; throw new Error(`${f}: "${t}" is not a number`); } vals[f] = Number(t); } else vals[f] = t;
        }
        if (!Object.keys(vals).length) continue;  // an empty override row is not saved
        if (!r.s.value) { r.s.style.outline = "2px solid #e06a5f"; throw new Error("pick a class for every override"); }
        if (r.s.value in out) { r.s.style.outline = "2px solid #e06a5f"; throw new Error(`two overrides for class ${r.s.value}`); }
        r.s.style.outline = ""; out[r.s.value] = vals;
      }
      return out;
    } };
  }

  // Device class definitions (policy.class_defs): add / rename / remove classes, 'behaves like', per-class alarm switches.
  // Every edit is one POST /api/config/classes; the server also updates device_classes / allow rules that use the class.
  function classDefsCard(data, alarms, builtin, ed, reload) {
    const defs = data.class_defs || [], dc = data.device_classes || {};
    const used = (n) => Object.entries(dc).filter(([k, v]) => !k.startsWith("_") && v === n).length;
    const box = h("span", { class: "small", style: "margin-left:10px" });
    const say = (t, bad) => { box.textContent = t; box.style.color = bad ? "#e06a5f" : "#6cc287"; };
    const post = async (body, again = true) => {
      try { box.style.color = ""; box.textContent = "Saving…"; await apiPost("/api/config/classes", body); say("✓ Saved " + new Date().toLocaleTimeString()); if (again) reload(); return true; }
      catch (e) { say("Not saved: " + String(e.message || e).replace(/^.*?→ \d+\s*/, ""), true); return false; }
    };
    const groups = [...new Set(alarms.map((a) => a.group))];
    const likeSel = (v, dis) => { const s = h("select", { disabled: dis }, builtin.map((b) => h("option", { value: b }, b))); s.value = v; return s; };
    const rowsEl = defs.map((d) => {
      const un = d.name === "unclassified", isB = builtin.includes(d.like) && d.like === d.name;
      const off = new Set(d.off || []);
      const nm = h("input", { type: "text", value: d.name, disabled: !ed || un, style: "width:9em", title: un ? "Devices with no class" : "Rename (updates every device using it)" });
      nm.onchange = async () => { const v = nm.value.trim().toLowerCase(); if (v && v !== d.name) { if (!(await post({ op: "rename", name: d.name, new: v }))) nm.value = d.name; } };
      const lk = un ? h("span", { class: "muted small" }, "—") : likeSel(d.like, !ed || isB);
      if (!un && !isB) lk.onchange = () => post({ op: "update", name: d.name, like: lk.value });
      if (!un && isB) lk.title = "A built-in class behaves like itself";
      const nOn = alarms.length - off.size;
      const sum = h("summary", { class: "small" }, `Alarms: ${nOn} of ${alarms.length} on`);
      const sw = groups.map((g) => h("div", { class: "cdef-grp" }, h("div", { class: "muted small", style: "margin-top:6px;font-weight:600" }, g),
        alarms.filter((a) => a.group === g).map((a) => {
          const cb = h("input", { type: "checkbox", disabled: !ed, "data-kind": a.id, style: "accent-color:#6cc287" }); cb.checked = !off.has(a.id);
          cb.onchange = async () => { cb.checked ? off.delete(a.id) : off.add(a.id); sum.textContent = `Alarms: ${alarms.length - off.size} of ${alarms.length} on`; if (!(await post({ op: "update", name: d.name, off: [...off] }, false))) { cb.checked = !cb.checked; cb.checked ? off.delete(a.id) : off.add(a.id); } };
          return h("label", { class: "cdef-sw", title: a.id }, cb, " ", a.label);
        })));
      const det = h("details", { class: "cdef-alarms" }, sum, h("div", { class: "cdef-sws" }, sw));
      const n = used(d.name);
      const rmArea = h("span", {});
      const rm = un ? "" : h("button", { type: "button", class: "small", title: "Remove this class", disabled: !ed, onclick: () => {
        if (!n) { if (confirm(`Remove class '${d.name}'?`)) post({ op: "remove", name: d.name }); return; }
        const mv = h("select", {}, h("option", { value: "" }, "unclassified"), defs.filter((x) => x.name !== d.name && x.name !== "unclassified").map((x) => h("option", { value: x.name }, x.name)));
        rmArea.replaceChildren(h("div", { class: "small", style: "margin-top:4px" }, `${n} device(s) use it. Move them to `, mv, " ",
          h("button", { type: "button", class: "small", onclick: () => post({ op: "remove", name: d.name, move_to: mv.value }) }, "Move and remove"), " ",
          h("button", { type: "button", class: "small", onclick: () => rmArea.replaceChildren() }, "Cancel")));
      } }, "✕");
      return h("tr", { "data-class": d.name }, h("td", {}, nm, h("div", { class: "muted small" }, un ? "devices with no class" : `${n} device(s)`)), h("td", {}, lk), h("td", {}, det), h("td", {}, rm, rmArea));
    });
    const nn = h("input", { type: "text", placeholder: "new class", style: "width:9em" }), nl = likeSel("iot", false);
    const addB = h("button", { type: "button", class: "small", onclick: () => { const v = nn.value.trim().toLowerCase(); if (v) post({ op: "add", name: v, like: nl.value }); } }, "+ Add class");
    const tbl = h("table", { class: "cfg-tbl cdef-tbl" }, h("thead", {}, h("tr", {}, h("th", {}, "Class"), h("th", {}, "Behaves like"), h("th", {}, "Alarms"), h("th"))), h("tbody", {}, rowsEl));
    const tip = data._doc_class_defs || "";
    return card(`Device class definitions <span class="muted small">(${defs.length - 1})</span>`, h("div", { id: "cdef-card" },
      tip ? h("div", { class: "muted small", style: "margin-bottom:6px" }, tip) : "", h("div", { style: "overflow-x:auto" }, tbl),
      ed ? h("div", { style: "margin-top:6px" }, nn, " behaves like ", nl, " ", addB) : "", h("div", { style: "margin-top:6px" }, box)));
  }

  // Auto-discover zones, zone roles and device classes from UniFi (POST /api/config/discover)
  function discoverCard(reload) {
    const out = h("div", { style: "margin-top:8px" }), msg = h("span", { class: "small", style: "margin-left:10px" });
    const tbl = (cols, rows) => h("table", { class: "cfg-tbl" }, h("thead", {}, h("tr", {}, cols.map((c) => h("th", {}, c)))), h("tbody", {}, rows.map((r) => h("tr", {}, r.map((c) => h("td", {}, c ?? ""))))));
    const call = async (body) => { msg.style.color = ""; msg.textContent = "Asking UniFi…"; try { const r = await apiPost("/api/config/discover", body); msg.textContent = ""; return r; } catch (e) { msg.style.color = "#e06a5f"; msg.textContent = String(e.message || e).replace(/^.*?→ \d+\s*/, ""); return null; } };
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

  // Auto-tune (GET /api/config/tune = recommendations only; POST /api/config/tune-apply writes just the accepted ones)
  function tuneCard(reload) {
    const out = h("div", { style: "margin-top:8px" }), msg = h("span", { class: "small", style: "margin-left:10px" });
    const fmt = (v) => (Array.isArray(v) ? v.join(", ") : v);
    const run = h("button", { type: "button" }, "Auto-tune thresholds");
    run.onclick = async () => {
      msg.style.color = ""; msg.textContent = "Analysing history…"; out.innerHTML = "";
      let r; try { r = await api("/api/config/tune"); } catch (e) { msg.style.color = "#e06a5f"; msg.textContent = String(e.message || e); return; }
      msg.textContent = "";
      const checks = [];
      // one tappable card per proposal (a <label> around the whole card: big touch target, works on phones)
      const rows = r.recommendations.map((x) => {
        const on = x.status === "change", opt = on && x.scope && x.title.includes("(new override)");  // a narrower alternative: offered, not pre-ticked
        // the box is only a display: the whole card is the tap target and keeps the state in JS (taps on a bare checkbox were unreliable on iOS)
        const cb = h("input", { type: "checkbox", checked: on, disabled: !on, tabindex: "-1", style: "width:18px;height:18px;min-width:18px;padding:0;margin:2px 0 0;flex:none;pointer-events:none;accent-color:#6cc287" });
        const st = { sel: on && !opt, x }; if (opt) cb.checked = false;
        if (on) checks.push(st);
        const chg = on ? Object.entries(x.changes).map(([k, v]) => h("div", {}, h("b", {}, k), ": ", fmt(x.current[k]), " → ", h("b", {}, fmt(v)))) : [h("div", { class: "muted" }, x.status === "off" ? "off" : x.status === "ok" ? "Keep as is" : "No safe change")];
        const cur = Object.entries(x.current).map(([k, v]) => k + ": " + fmt(v)).join("  ·  ");
        const card = h("div", { role: on ? "checkbox" : null, "aria-checked": on ? "true" : null, style: "display:flex;gap:12px;align-items:flex-start;padding:10px;margin:6px 0;border:1px solid var(--border);border-radius:8px;-webkit-tap-highlight-color:transparent;" + (on ? "cursor:pointer" : "opacity:.75") },
          cb, h("div", { style: "min-width:0;flex:1" }, h("div", {}, h("b", {}, x.title)), h("div", { class: "muted small" }, "Current: " + cur), h("div", { style: "margin:4px 0" }, chg), h("div", { class: "small" }, x.why)));
        if (on) card.onclick = () => { st.sel = !st.sel; cb.checked = st.sel; card.setAttribute("aria-checked", String(st.sel)); card.style.borderColor = st.sel ? "#6cc287" : ""; };
        if (on && !opt) card.style.borderColor = "#6cc287";
        return card;
      });
      const apply = h("button", { type: "button", disabled: !checks.length, style: "min-height:44px" }, "Accept selected");
      apply.onclick = async () => {
        const acc = checks.filter((c) => c.sel).map((c) => ({ id: c.x.id, changes: c.x.changes }));
        if (!acc.length) { msg.textContent = "Nothing selected."; return; }
        try { const a = await apiPost("/api/config/tune-apply", { accept: acc }); alert("Applied: " + a.applied.join(", ")); reload(); }
        catch (e) { msg.style.color = "#e06a5f"; msg.textContent = String(e.message || e).replace(/^.*?→ \d+\s*/, ""); }
      };
      out.append(h("div", { class: "muted small" }, `Based on ${r.window_days} days of per-device history and ${r.snapshots} daily snapshots. Each proposal only makes a detection less noisy and keeps its severity. Nothing is changed until you accept.`),
        h("div", {}, rows),
        h("div", { style: "margin-top:8px" }, apply, " ", h("button", { type: "button", class: "small", onclick: () => { out.innerHTML = ""; } }, "Dismiss")));
    };
    return card("Auto-tune thresholds", h("div", {}, h("div", { class: "muted small" }, "Replays your recent traffic history against the scan, beacon, upload and spike thresholds and recommends values. Nothing is saved until you accept."), h("div", { style: "margin-top:6px" }, run, msg), out));
  }

  V.settings = async (el, arg) => {
    const doc = DOCS.some(([d]) => d === arg) ? arg : "policy";
    el.innerHTML = `<div class="loading">Loading…</div>`;
    let r; try { r = await api("/api/config/cfg?doc=" + doc); } catch (e) { el.innerHTML = `<div class="empty">Settings are visible to admins and defenders only.</div>`; return; }
    const ed = !!r.admin, data = r.data;
    el.innerHTML = "";
    el.append(h("div", { class: "fchips" }, DOCS.map(([d, t]) => h("a", { href: "#/settings/" + d, class: "chip" + (d === doc ? " on" : ""), style: d === doc ? "font-weight:700" : "" }, t))));
    el.append(h("div", { class: "muted small", style: "margin:6px 0" }, HELP[doc], ed ? " Changes save automatically as you edit." : " Read-only: only an admin can change settings."));
    if (doc === "policy" && ed) el.append(discoverCard(() => V.settings(el, doc)));
    if (doc === "policy" && ed) el.append(tuneCard(() => V.settings(el, doc)));
    const notes = Object.entries(data).filter(([k]) => k.startsWith("_") && !(k.startsWith("_doc_") && k.slice(5) in data)).map(([k, v]) => `${k.replace(/^_doc_?/, "") || "about"}: ${v}`);
    if (notes.length) el.append(h("details", { class: "muted small", style: "margin-bottom:8px" }, h("summary", {}, "Notes on these settings"), notes.map((n) => h("p", {}, n))));
    // Changes are saved as soon as a field is edited (on change/blur) or a row is removed; saves run one at a time.
    let chain = Promise.resolve();
    const autosave = (root, run, box) => {
      let t = null;
      const go = () => { clearTimeout(t); t = setTimeout(() => { chain = chain.then(async () => { try { box.style.color = ""; box.textContent = "Saving…"; await run(); } catch (er) { msg(box, "Not saved: " + (er.message || er), true); } }); }, 250); };
      root.addEventListener("change", go);
      root.addEventListener("click", (ev) => { if (ev.target.closest && ev.target.closest('button[title="Remove this row"]')) go(); });
    };
    const msg = (box, text, bad) => { box.textContent = text; box.style.color = bad ? "#e06a5f" : "#6cc287"; };
    const save = async (path, value, box) => {
      try { await apiPost("/api/config/cfg", { doc, path, value }); msg(box, "✓ Saved " + new Date().toLocaleTimeString()); }
      catch (e) { throw new Error(String(e.message || e).replace(/^.*?→ \d+\s*/, "")); }
    };
    // scalar top-level values: one General table
    const gen = Object.entries(data).filter(([k, v]) => !k.startsWith("_") && !Array.isArray(v) && !isObj(v));
    if (gen.length) {
      const eds = gen.map(([k, v]) => [k, v, scalar(v, ed)]);
      const box = h("span", { class: "small", style: "margin-left:10px" });
      const tbl = h("table", { class: "cfg-tbl" }, h("thead", {}, h("tr", {}, h("th", {}, "Setting"), h("th", {}, "Value"))), h("tbody", {}, eds.map(([k, , e]) => h("tr", {}, h("td", {}, k, data["_doc_" + k] ? h("span", { class: "muted", title: data["_doc_" + k], style: "cursor:help" }, " ⓘ") : ""), h("td", {}, e.el, data["_doc_" + k] ? h("div", { class: "muted small" }, data["_doc_" + k]) : "")))));
      const sync = async () => { for (const [k, v, e] of eds) { const nv = e.get(); if (JSON.stringify(nv) !== JSON.stringify(v)) { await save([k], nv, box); eds.find((x) => x[0] === k)[1] = nv; } } };
      const root = h("div", {}, tbl); if (ed) autosave(root, sync, box);
      el.append(card("General", h("div", {}, root, ed ? h("div", { style: "margin-top:6px" }, box) : "")));
    }
    if (doc === "policy") {
      CLASSES = (data.class_defs || []).map((d) => d.name).filter((n) => n !== "unclassified");
      el.append(classDefsCard(data, r.alarms || [], r.builtin_classes || [], ed, () => V.settings(el, doc)));
    }
    for (const [k, v] of Object.entries(data)) {
      if (k.startsWith("_") || !(Array.isArray(v) || isObj(v)) || k === "class_defs") continue;
      const e = editor(v, ed, k), box = h("span", { class: "small", style: "margin-left:10px" });
      const count = Array.isArray(v) ? v.length : Object.keys(v).filter((x) => !x.startsWith("_")).length;
      const root = h("div", {}, e.el); if (ed) autosave(root, async () => { await save([k], e.get(), box); }, box);
      const tip = data["_doc_" + k];
      el.append(card(`${esc(k)} <span class="muted small">(${count})</span>` + (tip ? ` <span class="muted" title="${esc(tip)}" style="cursor:help">ⓘ</span>` : ""), h("div", {}, tip ? h("div", { class: "muted small", style: "margin-bottom:6px" }, tip) : "", root, ed ? h("div", { style: "margin-top:6px", class: "muted small" }, box) : "")));
    }
  };
})();
