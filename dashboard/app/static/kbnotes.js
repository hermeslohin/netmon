// Notes knowledge base (kb.py): host/device notes (written mostly by the AI, people may add/delete) shown on the host
// and endpoint pages and on the Notes page, plus people's event notes behind the 📝 button next to every event's
// Related count (related.js adds the button). The AI reads both before deciding (the review job, event research, correlation
// event reviewer, chat assistant).
(() => {
  const CATS = ["role", "baseline", "behavior", "decision", "risk", "config", "watch", "other"];
  const when = (t) => (t ? ft(new Date(t * 1000).toISOString()) : "");
  // event-note approval: a User-role account's notes stay "pending" (never shown to any AI) until a defender/admin approves
  const ST = { pending: ["⏳ awaiting approval", "sev-medium", "Written by a User. The AI does not see it until a network defender or admin approves it."],
    rejected: ["✕ rejected", "sev-high", "Not approved: the AI never sees this note."], approved: ["✓ approved", "sev-info", "Approved: the AI reads this note."] };
  const stBadge = (n) => { const st = n.status || "approved"; if (st === "approved" && n.role !== "user") return "";
    const [t, c, tip] = ST[st] || ST.pending; return `<span class="badge ${c}" title="${esc(tip)}${n.reviewed_by ? esc(` (${st} by ${n.reviewed_by})`) : ""}">${t}</span>`; };
  const reviewBtns = (n) => (isUserRole() || (n.status || "approved") === "approved" ? "" :
    `<button type="button" class="kb-rev" data-act="approve" data-id="${esc(n.id)}" data-eid="${esc(n.eid)}" title="Let the AI read this note">Approve</button>`
    + (n.status === "pending" ? `<button type="button" class="kb-rev" data-act="reject" data-id="${esc(n.id)}" data-eid="${esc(n.eid)}" title="Keep this note away from the AI">Reject</button>` : ""));
  window.kbStBadge = stBadge;
  // a person's verdict on an event (📝 buttons): authoritative for the AI; Expected / Benign close it (and its repeats), Suspicious reopens it
  const VBTN = [["expected", "✅", "Expected: normal for this network. Pick it, add why and the artifacts it applies to, then Save. Saved as an authoritative note; the event (and later repeats) is closed."],
    ["benign", "🟢", "Benign: harmless. Pick it, add why and the artifacts it applies to, then Save. Saved as an authoritative note; the event (and later repeats) is closed."],
    ["suspicious", "⚠️", "Suspicious: needs attention. Saved as an authoritative note; the event goes back to the open findings and is never auto-closed."]];
  const VCLS = { expected: "sev-info", benign: "sev-low", suspicious: "sev-high" };
  const vBadge = (n) => (n?.verdict ? `<span class="badge ${VCLS[n.verdict] || ""}" title="A person's verdict: the AI treats it as authoritative">${esc(n.verdict)}</span> ` : "");
  window.kbVBadge = vBadge;
  // host / internet / DNS notes: a network defender or admin accepts (authoritative for the event reviewer and event research) or rejects (kept, never sent to the AI)
  const canRev = () => ["admin", "defender"].includes(S.me?.role);
  const hnBadge = (n) => n.status === "approved" ? `<span class="badge sev-info" title="Accepted${n.reviewed_by ? " by " + esc(n.reviewed_by) : ""}: the event reviewer and event research treat this note as authoritative">✓ accepted</span>`
    : n.status === "rejected" ? `<span class="badge sev-high" title="Rejected${n.reviewed_by ? " by " + esc(n.reviewed_by) : ""}: kept here, never sent to the event reviewer or event research">✕ rejected</span>` : "";
  const hnBtns = (n) => !canRev() ? "" : (n.status === "approved" ? "" : `<button type="button" class="kb-hrev" data-act="approve" data-id="${esc(n.id)}" title="Accept: send to the event reviewer and event research as authoritative">✓ Accept</button>`)
    + (n.status === "rejected" ? "" : `<button type="button" class="kb-hrev" data-act="reject" data-id="${esc(n.id)}" title="Reject: keep the note but never send it to the event reviewer or event research">✕ Reject</button>`)
    + (n.status ? `<button type="button" class="kb-hrev" data-act="clear" data-id="${esc(n.id)}" title="Undo: back to not reviewed">↺</button>` : "");
  document.addEventListener("click", (e) => { const b = e.target.closest(".kb-hrev"); if (!b) return; e.preventDefault(); e.stopPropagation(); b.disabled = true;
    apiPost("/api/kb/host", { action: b.dataset.act, id: +b.dataset.id }).then(() => rerender(), (er) => { b.disabled = false; alert(er.message); }); }, true);

  /* artifact chips under a note: the things the AI matches events against when it picks notes (⚙️ process / file, 🌐 IP, 🔎 DNS name, 👤 account, 🔌 port) */
  const AK = { proc: ["⚙️", "process / file"], ip: ["🌐", "IP address"], dns: ["🔎", "DNS name"], user: ["👤", "account"], port: ["🔌", "port"],
    dev: ["💻", "device (MAC or host)"], find: ["🧭", "kind of finding"], sig: ["🛡️", "IDS signature"] };
  const artChips = (n) => { const a = (n.artifacts || []).slice(0, 12); return a.length ? `<div class="note-chips" title="Artifacts in this note. The event reviewer matches an event's artifacts against these to choose which notes to read.">${a.map((k) => { const i = k.indexOf(":"), kind = k.slice(0, i), [ic, nm] = AK[kind] || ["•", kind];
    return `<span class="art-chip" title="${esc(nm)}">${ic} <code>${esc(k.slice(i + 1))}</code></span>`; }).join("")}</div>` : ""; };
  // expiry: an unused note is deleted after the days set in AI pipeline configuration > Note expiry; each use restarts the clock
  const expTxt = (n) => {
    const made = n.ts ? `Created ${when(n.ts)}` : "";
    if (!n.expires) return made ? `<span class="muted small" title="${esc(made + (n.last_used ? " · last used " + when(n.last_used) : "") + " · expiry is off")}">∞</span>` : "";
    const left = (n.expires * 1000 - Date.now()) / 86400000, d = Math.max(0, Math.ceil(left));
    const txt = left <= 1 ? "expires today" : `${d} d left`, cls = d <= 3 ? "sev-high" : d <= 7 ? "sev-medium" : "";
    const tip = `${made}${n.last_used ? " · last used " + when(n.last_used) : ""} · deleted ${when(n.expires)} unless an AI reads it for an event or host first, or someone edits / accepts it (each use restarts the clock)`;
    return `<span class="badge kb-exp ${cls}" title="${esc(tip)}">⌛ ${txt}</span>`;
  };
  window.kbExpiry = expTxt;
  const by = (n) => (n.author === "ai" ? aiFlare({ model: n.model, via: n.via || "AI host notes", at: n.updated ? new Date(n.updated * 1000).toISOString() : "" })
    : `<span class="kb-user" title="Written by a person">👤 ${esc(String(n.author || "").replace(/^user:/, ""))}</span>`);

  /* ---------- host / device notes card ---------- */
  // subjects: every subject whose notes belong on this page; primary: where a new note is stored
  window.kbCard = (subjects, primary) => {
    const c = card(`Notes <span class="kb-n muted small"></span>`, `<div class="kb-list"><div class="loading inline">Loading notes…</div></div>
      <form class="kb-form"><select class="kb-cat" aria-label="Category">${CATS.map((x) => `<option${x === "other" ? " selected" : ""}>${x}</option>`).join("")}</select>
      <textarea class="kb-text" rows="2" maxlength="2000" placeholder="Add a note about this device (role, what is normal, decisions)…"></textarea>
      <button type="submit">Add note</button></form>
      <div class="small muted">AI runs read these notes before judging this device and add what they learn (✨). Notes by people (👤) and notes a defender or admin has accepted (✓) are authoritative; rejected notes (✕) are kept but never sent to the AI.</div>`, "kb-card");
    const list = c.querySelector(".kb-list");
    const load = () => api("/api/kb/host?s=" + encodeURIComponent(subjects.filter(Boolean).join(","))).then((d) => {
      const ns = d.notes || [];
      c.querySelector(".kb-n").textContent = ns.length ? `(${ns.length})` : "";
      list.innerHTML = ns.length ? ns.map((n) => `<div class="kb-note${n.status === "rejected" ? " kb-st-rejected" : ""}"><div class="kb-meta"><span class="badge">${esc(n.category)}</span> ${by(n)} ${hnBadge(n)}${hnBtns(n)}
          <span class="muted small" title="${esc(n.ts ? "Created " + when(n.ts) : "")}">${esc(when(n.updated))}${subjects.length > 1 && n.subject !== primary ? " · " + esc(n.subject) : ""}</span> ${expTxt(n)}
          <button type="button" class="kb-del" data-id="${esc(n.id)}" title="Delete this note" aria-label="Delete note">✕</button></div>
          <div class="kb-text-v">${esc(n.text)}</div>${artChips(n)}</div>`).join("")
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
    if (k === "pod") { const p = v.split("/"), [cl, ns] = p, wl = p[p.length - 1], kind = p.length === 4 ? p[2] : "";  // pod:<cluster>/<ns>/<kind>/<name> (old: pod:<cluster>/<ns>/<workload>)
      const KL = { deployment: "Deployment", statefulset: "StatefulSet", daemonset: "DaemonSet", cronjob: "CronJob", job: "Job", replicaset: "ReplicaSet", pod: "Pod" }[kind] || "pod";
      return `<a href="#/k8spod/${encodeURIComponent(ns)}/${encodeURIComponent(wl)}?cluster=${encodeURIComponent(cl)}${kind ? "&owner=" + encodeURIComponent(kind) : ""}">${esc(ns + "/" + wl)}</a> <span class="muted small" title="${kind && kind !== "pod" ? `Notes on this ${KL} apply to every pod it creates` : ""}">${esc(KL)}${kind && kind !== "pod" ? " · all its pods" : ""} · ${esc(cl)}</span>`; }
    if (k === "host") return `<a href="#/endpoint/${encodeURIComponent(v)}">${esc(v)}</a> <span class="muted small">endpoint</span>`;
    const ip = k === "ip" ? v : Object.keys(S.idx?.byIp || {}).find((i) => String(S.idx.byIp[i].mac || "").toLowerCase() === v);
    const name = esc(label && label !== v ? label : (ip && S.idx?.byIp?.[ip]?.name) || v);
    return ip && S.snap?.raw?.devices?.[ip] ? `<a href="#/device/${encodeURIComponent(ip)}">${name}</a> <span class="muted small mono">${esc(ip)}</span>` : `${name} <span class="muted small mono">${esc(v)}</span>`;
  };
  V.notes = async (el) => {
    el.innerHTML = `<h1>Notes</h1><div class="sub">What the AI has learned about each host and device, and the notes people left on events (📝 next to an event's Related count). Event research, the AI Research job, the event reviewer and Ask AI read these before deciding.</div>`;
    const d = await api("/api/kb/all");
    const hn = d.host_notes || [], en = d.event_notes || [], pend = en.filter((n) => n.status === "pending");
    el.insertAdjacentHTML("beforeend", kpis([["Host notes", hn.length], ["Devices with notes", new Set(hn.map((n) => n.subject)).size], ["By AI", hn.filter((n) => n.author === "ai").length], ["Event notes", en.length], ["Awaiting approval", pend.length]]));
    if (pend.length) {
      const pc = card(`Event notes awaiting approval (${pend.length})`, `<div class="small muted">Written by User-role accounts on events of their own devices. The AI does not see these notes until you approve them; rejected notes are never given to the AI.</div>`
        + table(null, [{ k: "label", t: "Event", fmt: (v, n) => esc(v || n.eid) }, { k: "text", t: "Note", fmt: (v) => `<div class="kb-text-v">${esc(v)}</div>` },
          { k: "author", t: "By", fmt: (v) => `👤 ${esc(v)}` }, { k: "ts", t: "When", fmt: (v) => esc(when(v)) }, { k: "id", t: "", fmt: (v, n) => reviewBtns(n) }], pend, { sort: "ts", search: false }));
      pc.addEventListener("click", (e) => { const b = e.target.closest(".kb-rev"); if (!b) return;
        apiPost("/api/kb/event", { action: b.dataset.act, id: +b.dataset.id }).then(() => V.notes(el), (er) => alert(er.message)); });
      el.appendChild(pc);
    }
    el.appendChild(card(`Host notes (${hn.length})`, hn.length ? table(null, [{ k: "subject", t: "Device / host", fmt: (v, n) => subjLink(v, n.label) }, { k: "category", t: "Category", fmt: (v) => `<span class="badge">${esc(v)}</span>` },
      { k: "text", t: "Note", fmt: (v, n) => `<div class="kb-text-v">${esc(v)}</div>${artChips(n)}` }, { k: "author", t: "By", fmt: (v, n) => by(n) }, { k: "ts", t: "Created", fmt: (v) => esc(when(v)) }, { k: "updated", t: "Updated", fmt: (v) => esc(when(v)) },
      { k: "expires", t: "Expires", fmt: (v, n) => expTxt(n) }],
      hn, { sort: "updated" }) : `<div class="empty">No host notes yet. The AI writes them when it researches an event (Send to research) or reviews correlations; you can add notes on any host or endpoint page.</div>`));
    el.appendChild(card(`Event notes (${en.length})`, en.length ? table(null, [{ k: "label", t: "Event", fmt: (v, n) => esc(v || n.eid) }, { k: "text", t: "Note", fmt: (v, n) => `<div class="kb-text-v">${esc(v)}</div>${artChips(n)}` },
      { k: "verdict", t: "Verdict", fmt: (v, n) => vBadge(n) },
      { k: "author", t: "By", fmt: (v, n) => `👤 ${esc(v)} ${stBadge(n)}` }, { k: "ts", t: "When", fmt: (v) => esc(when(v)) }],
      en, { sort: "ts" }) : `<div class="empty">No event notes yet. Click 📝 next to any event's Related count to add one.</div>`));
  };

  /* ---------- Network > DNS, TLS and IPs: notes on external IPs / ranges, domains / subdomains and TLS certificates ---------- */
  // #/netnotes/<ip | cidr | dom:<name> | cert:<sha256>> = one entry's notes; bare #/netnotes = the notes part of the DNS, TLS and IPs page
  const srch = (k, v) => (window.artSearchBtn ? artSearchBtn(k, v) : "");
  const srchLine = (k, v, what) => { const u = window.artSearchUrl?.(k, v);
    return u ? `<div class="small" style="margin:4px 0 10px"><button type="button" class="kib-btn art-kib" data-kib="${esc(u)}">🔍 Search ${esc(what)} in Elasticsearch</button> <span class="muted">Kibana Discover, last 7 days</span></div>` : ""; };
  V.netnotes = async (el, arg) => {
    const ip = decodeURIComponent(arg || "");
    if (!ip) { V.dns(el); if (!S._scrolled) setTimeout(() => document.getElementById("notes-section")?.scrollIntoView(), 600); return; }  // old link: the notes part of DNS, TLS and IPs
    if (ip.startsWith("cert:")) {  // one TLS certificate (by SHA-256 fingerprint): its notes, what the snapshot knows about it, and its names
      const sha = ip.slice(5).toLowerCase(), c = (S.snap?.raw?.tls?.certs || []).find((x) => x.sha256 === sha), cn = c ? certCN(c.subject) : "";
      el.innerHTML = `<div class="crumbs"><a href="#/dns">DNS, TLS and IPs</a> › TLS certificate › ${esc(cn || sha.slice(0, 16) + "…")}</div><h1>TLS certificate ${esc(cn)}</h1><div class="sub">Notes on this certificate (SHA-256 <span class="mono">${esc(sha)}</span>). Every event that names a server this certificate was presented for carries it as an artifact, so the event reviewer and event research read these notes when judging it.</div>${srchLine("cert", sha, "this certificate (x509 records and the TLS sessions that presented it)")}`;
      if (c) el.appendChild(tlsDetail({ cert: c }, S.snap.raw.tls || {}));
      else el.insertAdjacentHTML("beforeend", `<div class="small muted" style="margin:6px 0">Not seen in the selected time range: pick a range in which it was seen for subject, issuer and names.</div>`);
      el.querySelector("#tlsClose")?.remove();
      el.appendChild(kbCard([`art:cert:${sha}`], `art:cert:${sha}`));
      const names = c ? [...new Set([...(c.sni || []), ...(c.san_dns || []).map((d) => d.replace(/^\*\./, ""))])].slice(0, 30) : [];
      if (names.length) el.appendChild(card(`Its names: domain and subdomain notes (${names.length})`, `<div class="small muted" style="margin-bottom:6px">Notes on a name apply to every event about it; a note on a domain also covers its subdomains.</div>` + names.map((d) => `<div><a href="#/netnotes/${encodeURIComponent("dom:" + d)}" class="mono">${esc(d)}</a> <button type="button" class="extnote-btn" data-extdom="${esc(d)}" title="Notes on ${esc(d)}">📝</button>${srch("dns", d)}</div>`).join("")));
      return;
    }
    if (ip.startsWith("dom:")) {  // one domain / subdomain: its notes, the parent domains' notes that cover it, and subdomains with their own notes
      const dom = ip.slice(4), parts = dom.split("."), parents = parts.slice(1, -1).map((_, i) => parts.slice(i + 1).join("."));
      el.innerHTML = `<div class="crumbs"><a href="#/dns">DNS, TLS and IPs</a> › DNS › ${esc(dom)}</div><h1>${esc(dom)}</h1><div class="sub">DNS notes for this name. A note on a domain also covers its subdomains; a note on a subdomain only covers that name and the names below it. The event reviewer and event research read them when judging DNS activity.</div>${srchLine("dns", dom, dom + " and its subdomains")}`;
      el.appendChild(kbCard([`dom:${dom}`, `art:dns:${dom}`], `dom:${dom}`));
      if (parents.length) { el.insertAdjacentHTML("beforeend", `<div class="small muted" style="margin:10px 0 4px">Notes on parent domains that also apply: ${parents.map((p) => `<a href="#/netnotes/${encodeURIComponent("dom:" + p)}">${esc(p)}</a>`).join(", ")}</div>`);
        el.appendChild(kbCard(parents.flatMap((p) => [`dom:${p}`, `art:dns:${p}`]), `dom:${parents[0]}`)); }
      api("/api/kb/dns").then((d) => { const subs = (d.domains || []).filter((r) => r.domain.endsWith("." + dom));
        if (subs.length) el.appendChild(card(`Subdomains with their own notes (${subs.length})`, table(null, [
          { k: "domain", t: "Subdomain", fmt: (v) => `<a href="#/netnotes/${encodeURIComponent("dom:" + v)}"><b class="mono">${esc(v)}</b></a>` }, { k: "n", t: "Notes", num: true },
          { k: "notes", t: "Latest note", fmt: (v) => `<div class="kb-text-v small">${esc(String(v[0]?.text || "").replace(/^\[[^\]]*\]\s*/, "").slice(0, 200))}</div>` },
          { k: "updated", t: "Updated", fmt: (v) => esc(when(v)) }], subs, { sort: "updated" }))); }).catch(() => {});
      return;
    }
    if (ip && ip.includes("/")) {  // a CIDR range: its notes cover every address in it
      el.innerHTML = `<div class="crumbs"><a href="#/dns">DNS, TLS and IPs</a> › ${esc(ip)}</div><h1>${esc(ip)}</h1><div class="sub">Notes about this address range. They cover every address in ${esc(ip)}: the event reviewer and event research read them for each of those addresses.</div>${srchLine("net", ip, ip)}`;
      el.appendChild(kbCard([`net:${ip}`], `net:${ip}`));
      return;
    }
    if (ip) {
      el.innerHTML = `<div class="crumbs"><a href="#/dns">DNS, TLS and IPs</a> › ${esc(ip)}</div><h1>${esc(ip)}</h1><div class="sub">Notes about this external address. The event reviewer and event research read them when judging whether traffic to it is benign or expected.</div>${srchLine("ip", ip, ip)}`;
      el.appendChild(kbCard([`ip:${ip}`, `art:ip:${ip}`], `ip:${ip}`));
      api("/api/kb/covering?ip=" + encodeURIComponent(ip)).then((d) => { const rs = [...new Set((d.covering || []).map((r) => r.scope))];
        if (!rs.length) return;
        el.insertAdjacentHTML("beforeend", `<div class="small muted" style="margin:10px 0 4px">Notes on address ranges that also apply: ${rs.map((p) => `<a href="#/netnotes/${encodeURIComponent(p)}">${esc(p)}</a>`).join(", ")}</div>`);
        el.appendChild(kbCard(rs.map((p) => `net:${p}`), `net:${rs[0]}`)); }).catch(() => {});
      return;
    }
  };
  // The notes part of Network > DNS, TLS and IPs: external IPs / ranges, domains / subdomains and TLS certificates with notes.
  // An entry is listed only while it has a note: when its last note times out (unused for the expiry days) the entry is deleted.
  window.netNotesSections = async (el) => {
    const redraw = () => { el.innerHTML = ""; window.netNotesSections(el); };
    el.insertAdjacentHTML("beforeend", `<h1 id="notes-section" style="margin-top:28px;padding-top:14px;border-top:1px solid var(--border)">Notes: IPs, domains and TLS certificates</h1><div class="sub">Every external (public) IP address, DNS name and TLS certificate that has a note: what it is, who runs it and why this network talks to it. The event reviewer and event research write them as they find out, people can add or delete them, and both read them when deciding whether activity is benign or expected. Events show the notes on the IPs, domains (including parent-domain notes) and certificates they carry. 🔍 searches an entry in Elasticsearch. An entry whose notes have all timed out is deleted.</div>`);
    const d = await api("/api/kb/internet"), rows = d.ips || [];
    el.insertAdjacentHTML("beforeend", kpis([["IPs with notes", rows.filter((r) => !r.range).length], ["CIDR ranges", rows.filter((r) => r.range).length], ["Notes", rows.reduce((a, r) => a + r.n, 0)], ["By AI", rows.filter((r) => r.notes.some((n) => n.author === "ai")).length], ["With a person's note", rows.filter((r) => r.notes.some((n) => n.author !== "ai")).length]]));
    el.appendChild(card("Add a note about an external IP or CIDR range (covers every address in it)", `<form class="kb-form" id="inForm"><input class="kb-ip mono" placeholder="8.8.8.8 or 203.0.113.0/24" aria-label="External IP or CIDR range" size="22"><select class="kb-cat" aria-label="Category">${CATS.map((x) => `<option${x === "other" ? " selected" : ""}>${x}</option>`).join("")}</select><textarea class="kb-text" rows="2" maxlength="2000" placeholder="What is this address, who runs it, why do we talk to it?"></textarea><button type="submit">Add note</button></form>`));
    el.querySelector("#inForm").addEventListener("submit", (e) => { e.preventDefault();
      const f = e.target, i = f.querySelector(".kb-ip").value.trim(), t = f.querySelector(".kb-text").value.trim(); if (!i || !t) return;
      apiPost("/api/kb/host", { action: "add", subject: (i.includes("/") ? "net:" : "ip:") + i, category: f.querySelector(".kb-cat").value, text: t }).then(redraw, (er) => alert(er.message)); });
    el.appendChild(card(`External IPs and ranges (${rows.length})`, rows.length ? table(null, [
      { k: "ip", t: "IP / range", fmt: (v) => `<a href="#/netnotes/${encodeURIComponent(v)}"><b class="mono">${esc(v)}</b></a> ${srch(v.includes("/") ? "net" : "ip", v)}` },
      { k: "n", t: "Notes", num: true },
      { k: "notes", t: "Latest note", fmt: (v) => `<div class="kb-text-v small">${esc(String(v[0]?.text || "").replace(/^\[\w+:[^\]]*\]\s*/, "").slice(0, 260))}</div>`, sort: (r) => r.n },
      { k: "notes", t: "By", fmt: (v) => v[0] ? by(v[0]) : "" , sort: (r) => r.notes[0]?.author || "" },
      { k: "notes", t: "Review", fmt: (v) => { const a = v.filter((n) => n.status === "approved").length, r = v.filter((n) => n.status === "rejected").length; return (a ? `<span class="badge sev-info">✓ ${a}</span> ` : "") + (r ? `<span class="badge sev-high">✕ ${r}</span>` : ""); }, sort: (r) => r.notes.filter((n) => n.status).length },
      { k: "updated", t: "Updated", fmt: (v) => esc(when(v)) }], rows, { sort: "updated", filter: true, onclick: (r) => go("netnotes/" + encodeURIComponent(r.ip)) })
      : `<div class="empty">No external IP has a note yet. The event reviewer and event research add them as they investigate; you can add one above.</div>`));
    // ---- DNS notes: frequent DNS patterns by domain or subdomain (the event reviewer and event research write them, people can too)
    const dd = await api("/api/kb/dns").catch(() => ({ domains: [] })), drows = dd.domains || [];
    el.insertAdjacentHTML("beforeend", `<h2 style="margin:18px 0 6px">DNS notes</h2>`);
    el.insertAdjacentHTML("beforeend", kpis([["Domains with notes", drows.length], ["Notes", drows.reduce((a, r) => a + r.n, 0)], ["Subdomains", drows.filter((r) => r.parent).length], ["By AI", drows.filter((r) => r.notes.some((n) => n.author === "ai")).length]]));
    el.appendChild(card("Add a DNS note", `<form class="kb-form" id="dnsForm"><input class="kb-dom mono" placeholder="example.com, *.example.com or sub.example.com" aria-label="Domain or subdomain" size="30"><select class="kb-cat" aria-label="Category">${CATS.map((x) => `<option${x === "other" ? " selected" : ""}>${x}</option>`).join("")}</select><textarea class="kb-text" rows="2" maxlength="2000" placeholder="What is this DNS name, who queries it and how often, is it normal? A note on a domain also covers its subdomains; a note on a subdomain covers only that name."></textarea><button type="submit">Add note</button></form><div class="small muted">The event reviewer and the research job read these when judging DNS activity, and add their own as they find recurring patterns (✨).</div>`));
    el.querySelector("#dnsForm").addEventListener("submit", (e) => { e.preventDefault();
      const f = e.target, d = f.querySelector(".kb-dom").value.trim().toLowerCase().replace(/\.$/, "").replace(/^\*\./, ""), t = f.querySelector(".kb-text").value.trim(); if (!d || !t) return;
      apiPost("/api/kb/host", { action: "add", subject: "dom:" + d, category: f.querySelector(".kb-cat").value, text: t }).then(redraw, (er) => alert(er.message)); });
    el.appendChild(card(`Domains and subdomains (${drows.length})`, drows.length ? table(null, [
      { k: "domain", t: "Domain", fmt: (v) => `<a href="#/netnotes/${encodeURIComponent("dom:" + v)}"><b class="mono">${esc(v)}</b></a> ${srch("dns", v)}` },
      { k: "n", t: "Notes", num: true },
      { k: "notes", t: "Latest note", fmt: (v) => `<div class="kb-text-v small">${esc(String(v[0]?.text || "").replace(/^\[[^\]]*\]\s*/, "").slice(0, 260))}</div>`, sort: (r) => r.n },
      { k: "notes", t: "By", fmt: (v) => v[0] ? by(v[0]) : "", sort: (r) => r.notes[0]?.author || "" },
      { k: "notes", t: "Review", fmt: (v) => { const a = v.filter((n) => n.status === "approved").length, r = v.filter((n) => n.status === "rejected").length; return (a ? `<span class="badge sev-info">✓ ${a}</span> ` : "") + (r ? `<span class="badge sev-high">✕ ${r}</span>` : ""); }, sort: (r) => r.notes.filter((n) => n.status).length },
      { k: "updated", t: "Updated", fmt: (v) => esc(when(v)) }], drows, { sort: "updated", filter: true, onclick: (r) => go("netnotes/" + encodeURIComponent("dom:" + r.domain)) })
      : `<div class="empty">No DNS notes yet. The event reviewer and event research add them when they see a recurring domain; you can add one above.</div>`));
    // ---- TLS certificates (artifacts by SHA-256 fingerprint); add one with 📝 in the Certificates table above or on a certificate's page
    const cd = await api("/api/kb/certs").catch(() => ({ certs: [] })), crows = cd.certs || [], CS = S.snap?.raw?.tls?.certs || [];
    const cinfo = (sha) => CS.find((x) => x.sha256 === sha);
    el.insertAdjacentHTML("beforeend", `<h2 style="margin:18px 0 6px">TLS certificate notes</h2>`);
    el.appendChild(card(`TLS certificates (${crows.length})`, crows.length ? table(null, [
      { k: "sha256", t: "Certificate", fmt: (v) => { const c = cinfo(v); return `<a href="#/netnotes/${encodeURIComponent("cert:" + v)}"><b>${esc(c ? certCN(c.subject) : "")}</b> <span class="mono small">${esc(v.slice(0, 16))}…</span></a> ${srch("cert", v)}${c ? `<div class="small muted">${esc((c.sni || []).slice(0, 3).join(", "))}</div>` : ""}`; } },
      { k: "n", t: "Notes", num: true },
      { k: "notes", t: "Latest note", fmt: (v) => `<div class="kb-text-v small">${esc(String(v[0]?.text || "").replace(/^\[[^\]]*\]\s*/, "").slice(0, 260))}</div>`, sort: (r) => r.n },
      { k: "notes", t: "By", fmt: (v) => v[0] ? by(v[0]) : "", sort: (r) => r.notes[0]?.author || "" },
      { k: "updated", t: "Updated", fmt: (v) => esc(when(v)) }], crows, { sort: "updated", filter: true, onclick: (r) => go("netnotes/" + encodeURIComponent("cert:" + r.sha256)) })
      : `<div class="empty">No TLS certificate has a note yet. Click 📝 on a certificate in the Certificates table above (or on an event's cert artifact) to add one.</div>`));
  };

  /* ---------- event notes popover (📝) ---------- */
  let pop = null;
  const close = () => { pop?.remove(); pop = null; };
  function refreshBtns(eid) {
    const ns = S.corr?.unotes?.[eid] || [], n = ns.length, p = ns.some((x) => x.status === "pending");
    document.querySelectorAll(".unote-btn").forEach((b) => { if (b.dataset.unote === eid) { b.textContent = n ? `📝 ${n}${p ? " ⏳" : ""}` : "📝"; b.classList.toggle("has", n > 0); } });
  }
  function render(btn) {
    const eid = btn.dataset.unote, me = S.corr?.events?.[eid], ns = S.corr?.unotes?.[eid] || [], U = isUserRole();
    const cur = ns.filter((n) => n.verdict && n.status !== "rejected").sort((a, b) => b.ts - a.ts)[0];
    pop.innerHTML = `<div class="rel-head"><b>Your notes</b> <span class="muted small">${esc(me ? me.label.slice(0, 90) : eid)}</span><button type="button" class="rel-x" aria-label="Close">✕</button></div>
      <div class="note-body">
        ${ns.map((n) => `<div class="kb-note kb-st-${esc(n.status || "approved")}"><div class="kb-meta">👤 <b>${esc(n.author)}</b> ${vBadge(n)}${stBadge(n)} <span class="muted small">${esc(when(n.ts))}${n.same_event ? "" : " · written on an earlier run of this event"}</span>
          ${reviewBtns(n)}<button type="button" class="kb-del" data-id="${esc(n.id)}" aria-label="Delete note" title="Delete">✕</button></div><div class="kb-text-v">${esc(n.verdict ? String(n.text).replace(/^ANALYST VERDICT: [^)]*\)\.?\s*/, "") : n.text)}</div>${n.scope?.length ? `<div class="small muted" title="The decision model weighs this verdict very heavily on any event that shows all of these artifacts">Applies to any event with all of:</div>` : ""}${artChips(n)}</div>`).join("") || `<div class="muted small">No notes on this event yet.</div>`}
        <textarea class="kb-text" rows="3" maxlength="2000" placeholder="e.g. Expected: this is my nightly backup. / Escalate if seen again from this host."></textarea>
        <div class="kb-vrow">${VBTN.map(([v, ic, tip]) => `<button type="button" class="kb-verdict kb-v-${v}${cur?.verdict === v ? " on" : ""}" data-v="${v}" title="${esc(tip)}">${ic} ${v[0].toUpperCase() + v.slice(1)}</button>`).join(" ")}
          <button type="button" class="kb-save">Save note</button></div>
        <div class="kb-scope" hidden><div class="small"><b>Applies to</b> <span class="muted">— tick the artifacts this verdict covers. Any event that shows <i>all</i> ticked artifacts gets your verdict, weighted very heavily. Tick the device IP too to keep it to this device; tick none for this event only.</span></div>
          <div class="kb-scope-list small muted">Loading artifacts…</div></div>
        ${cur ? `<div class="small">Current verdict: ${vBadge(cur)} <span class="muted">by ${esc(String(cur.author).replace(/^user:/, ""))}, ${esc(when(cur.ts))}${cur.status === "pending" ? " (awaiting approval)" : ""}</span></div>` : ""}
        <div class="small muted">${U ? "Tell the network defenders what this event is (e.g. 'that was me installing an app'). Your note goes to them for review; the AI only reads it after a defender or admin approves it."
          : "The AI reads approved notes on this event (and on later repeats of it) in every review run, in event research and when deciding which events are related, and treats them as authoritative guidance. Notes written by User accounts need your approval first."}</div>
      </div>
      <div class="rs-box small" style="border-top:1px solid var(--line,#444);margin-top:8px;padding-top:6px"><span class="muted">Checking research status…</span></div>`;
    pop.querySelector(".rel-x").onclick = close;
    const rs = pop.querySelector(".rs-box");
    const rsShow = (r) => {
      if (r.state === "researched") rs.innerHTML = '<span class="muted">Already researched by the AI. Its findings are in the event\'s research note.</span>';
      else if (r.state === "running") rs.innerHTML = '<span class="muted">🔬 Research started. The AI is working on it now; the note appears in a few minutes.</span>';
      else if (r.state === "queued") rs.innerHTML = `<span class="muted">⏳ Queued for research${r.by ? ` (requested by ${esc(r.by)})` : ""}. ${r.note ? ` ${esc(r.note)}.` : ""} It starts as soon as the research model is free.</span>`;
      else { rs.innerHTML = (r.testing ? '<span class="badge sev-unknown" title="test mode: listed in the queue">testing</span> ' : "") + '<button type="button" class="rs-send">🔬 Send to research</button> <span class="muted">Not researched yet. Sends this event to the AI right now.</span>';
        rs.querySelector(".rs-send").onclick = () => apiPost("/api/research/request", { action: "send", eid }).then(rsShow, (er) => { rs.textContent = "error: " + er.message; }); }
    };
    apiPost("/api/research/request", { action: "status", eid }).then(rsShow, () => { rs.textContent = ""; });
    const save = (verdict) => {
      const t = pop.querySelector(".kb-text").value.trim(); if (!t && !verdict) return;
      const scope = verdict === "expected" || verdict === "benign" ? [...pop.querySelectorAll(".kb-scope-cb:checked")].map((x) => x.value) : [];
      pop.querySelectorAll(".kb-verdict, .kb-save").forEach((b) => { b.disabled = true; });
      apiPost("/api/kb/event", { action: "add", eid, label: me?.label || "", text: t, verdict, scope }).then((r) => { (S.corr.unotes ||= {})[eid] = r.notes || []; refreshBtns(eid); render(btn); }, (er) => { alert(er.message); render(btn); });
    };
    // Expected / Benign only pick the verdict: the person adds why and which artifacts it covers, then presses Save.
    // Suspicious is saved at once (it reopens the event).
    let pick = "", artsLoaded = false;
    const sv = pop.querySelector(".kb-save"), ta = pop.querySelector(".kb-text"), sc = pop.querySelector(".kb-scope");
    const loadArts = () => {
      if (artsLoaded) return; artsLoaded = true;
      apiPost("/api/kb/event", { action: "arts", eid }).then((r) => {
        const L = pop?.querySelector(".kb-scope-list"); if (!L) return;
        const a = r.arts || [];
        L.classList.remove("muted");
        L.innerHTML = a.length ? a.map((k) => { const i = k.indexOf(":"), kind = k.slice(0, i), [ic, nm] = AK[kind] || ["•", kind];
          return `<label class="art-chip kb-scope-it" title="${esc(nm)}"><input type="checkbox" class="kb-scope-cb" value="${esc(k)}"> ${ic} <code>${esc(k.slice(i + 1))}</code></label>`; }).join("")
          : `<span class="muted">No artifacts found on this event: the verdict applies to this event only.</span>`;
      }, () => { const L = pop?.querySelector(".kb-scope-list"); if (L) L.textContent = "Artifacts unavailable: the verdict applies to this event only."; });
    };
    const setPick = (v) => {
      pick = pick === v ? "" : v;
      pop.querySelectorAll(".kb-verdict").forEach((b) => b.classList.toggle("on", b.dataset.v === pick || (!pick && cur?.verdict === b.dataset.v)));
      sc.hidden = !pick;
      sv.textContent = pick ? `Save ${pick === "expected" ? "✅ Expected" : "🟢 Benign"}` : "Save note";
      ta.placeholder = pick ? `Why is this ${pick}? e.g. nightly backup job to the NAS, started by the backup service account.` : "e.g. Expected: this is my nightly backup. / Escalate if seen again from this host.";
      if (pick) { loadArts(); ta.focus(); }
    };
    sv.onclick = () => save(pick);
    pop.querySelectorAll(".kb-verdict").forEach((b) => b.onclick = () => (b.dataset.v === "suspicious" ? save("suspicious") : setPick(b.dataset.v)));
    pop.querySelectorAll(".kb-rev").forEach((b) => b.onclick = () => {
      apiPost("/api/kb/event", { action: b.dataset.act, id: +b.dataset.id, eid }).then((r) => { (S.corr.unotes ||= {})[eid] = r.notes || []; refreshBtns(eid); render(btn); }, (er) => alert(er.message));
    });
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

  /* ---------- external IP / domain notes popover (📝 inline wherever linkifyIps shows one) ---------- */
  let epop = null;
  const eclose = () => { epop?.remove(); epop = null; };
  const extInfo = (btn) => (btn.dataset.extart?.startsWith("cert:") ? { v: btn.dataset.extart.slice(5).toLowerCase(), subj: "art:" + btn.dataset.extart.toLowerCase(), what: "TLS certificate" }
    : btn.dataset.extart ? { v: btn.dataset.extart.replace(/^[^:]*:/, ""), subj: "art:" + btn.dataset.extart, what: btn.dataset.extart.split(":")[0] + " artifact" }
    : btn.dataset.extip ? { v: btn.dataset.extip, subj: "ip:" + btn.dataset.extip, what: "external IP" }
    : { v: btn.dataset.extdom, subj: "dom:" + btn.dataset.extdom, what: "domain" });
  // where a new note goes: this exact name / address, or a wider scope that covers it (a parent domain = all its subdomains,
  // a CIDR range = every address in it); the event reviewer and event research read wider-scope notes for every name / address under them
  const v4 = (ip) => { const p = String(ip).split("."); return p.length === 4 && p.every((x) => /^\d{1,3}$/.test(x)); };
  const scopes = (v, subj, what) => {
    if (what.startsWith("dns") || what === "domain") {
      const p = v.toLowerCase().replace(/^\*\./, "").split("."), parents = p.slice(1, -1).map((_, i) => p.slice(i + 1).join("."));
      return [{ s: subj, t: `${v} (this name)` }, ...parents.map((d) => ({ s: "dom:" + d, t: `*.${d} (all of ${d} and its subdomains)` }))];
    }
    if (what === "TLS certificate") {  // the certificate itself, or one of the names it was presented for / carries (domain + subdomain notes)
      const c = (S.snap?.raw?.tls?.certs || []).find((x) => x.sha256 === v), names = c ? [...new Set([...(c.sni || []), ...(c.san_dns || [])].map((d) => d.toLowerCase()))].slice(0, 12) : [];
      return [{ s: subj, t: `this certificate${c ? " (" + certCN(c.subject) + ")" : ""}` }, ...names.map((d) => d.startsWith("*.") ? { s: "dom:" + d.slice(2), t: `${d} (all of ${d.slice(2)} and its subdomains)` } : { s: "dom:" + d, t: `${d} (this name)` })];
    }
    if (v4(v)) { const o = v.split(".");
      return [{ s: subj, t: `${v} (this address)` }, { s: `net:${o.slice(0, 3).join(".")}.0/24`, t: `${o.slice(0, 3).join(".")}.0/24 (256 addresses)` },
        { s: `net:${o.slice(0, 2).join(".")}.0.0/16`, t: `${o.slice(0, 2).join(".")}.0.0/16 (65,536 addresses)` }, { s: "custom", t: "Other CIDR range…" }]; }
    return [{ s: subj, t: v }];
  };
  const covLink = (sub) => `#/netnotes/${encodeURIComponent(sub.startsWith("dom:") || sub.startsWith("art:dns:") ? "dom:" + sub.replace(/^(dom|art:dns):/, "") : sub.replace(/^(net|ip|art:ip):/, ""))}`;
  function erender(btn) {
    const { v, subj, what } = extInfo(btn), isDns = what.startsWith("dns") || what === "domain", isIp = !isDns && v4(v), sc = scopes(v, subj, what);
    const sk = btn.dataset.extip ? "ip" : btn.dataset.extdom ? "dns" : String(btn.dataset.extart || "").split(":")[0];
    const page = what === "TLS certificate" ? ` <a class="small" href="#/netnotes/${encodeURIComponent("cert:" + v)}">page</a>` : "";
    epop.innerHTML = `<div class="rel-head"><b>Notes on ${esc(what)}</b> <span class="muted small mono">${esc(what === "TLS certificate" ? v.slice(0, 16) + "…" : v)}</span>${srch(sk, v)}${page}<button type="button" class="rel-x" aria-label="Close">✕</button></div>
      <div class="note-body"><div class="loading inline">Loading notes…</div></div>`;
    epop.querySelector(".rel-x").onclick = eclose;
    const noteHtml = (n, scope) => `<div class="kb-note${n.status === "rejected" ? " kb-st-rejected" : ""}"><div class="kb-meta">${by(n)} ${hnBadge(n)}${hnBtns(n)} <span class="muted small" title="${esc(n.ts ? "Created " + when(n.ts) : "")}">${esc(when(n.updated))}</span> ${expTxt(n)}
          ${scope ? `<a class="badge" href="${covLink(n.subject)}" title="Written on a wider scope; applies to ${esc(v)} too">${isDns ? "*." : ""}${esc(scope)}</a>` : ""}
          <button type="button" class="kb-del" data-id="${esc(n.id)}" aria-label="Delete note" title="Delete">✕</button></div><div class="kb-text-v">${esc(n.text)}</div>${artChips(n)}</div>`;
    Promise.all([api("/api/kb/host?s=" + encodeURIComponent(subj)),
      (isDns || isIp) ? api("/api/kb/covering?" + (isDns ? "dom=" : "ip=") + encodeURIComponent(v)).catch(() => ({ covering: [] })) : Promise.resolve({ covering: [] })]).then(([d, cv]) => {
      const ns = d.notes || [], cov = cv.covering || [];
      epop.querySelector(".note-body").innerHTML = `
        ${ns.map((n) => noteHtml(n, "")).join("") || `<div class="muted small">No notes on this ${esc(what)} yet.</div>`}
        ${cov.length ? `<div class="small muted" style="margin:8px 0 2px">Also applies: notes on ${isDns ? "parent domains" : "address ranges"} that cover ${esc(v)}</div>${cov.map((r) => noteHtml(r.note, r.scope)).join("")}` : ""}
        <textarea class="kb-text" rows="3" maxlength="2000" placeholder="e.g. Known CDN / expected contact. / Flag if seen talking to other hosts."></textarea>
        ${sc.length > 1 ? `<div class="kb-scope-row small" style="margin:4px 0"><label>Applies to <select class="kb-scope" aria-label="Note scope">${sc.map((o) => `<option value="${esc(o.s)}">${esc(o.t)}</option>`).join("")}</select></label>
          <input class="kb-cidr mono" placeholder="${isIp ? esc(v.split(".").slice(0, 2).join(".")) + ".0.0/12" : ""}" aria-label="CIDR range" size="18" style="display:none"></div>` : ""}
        <div><button type="button" class="kb-save">Add note</button></div>
        <div class="small muted">${isDns ? "A note on a parent domain (*.example.com) covers every subdomain under it; the event reviewer and event research read it for all of them."
          : isIp ? "A note on a CIDR range covers every address in it; the event reviewer and event research read it for each of them."
          : subj.startsWith("art:") ? "The event reviewer reads these notes when it decides whether events are related and which artifacts matter." : `Treated the same as device notes: the AI reads these before judging traffic to/from this ${esc(what)}.`}</div>`;
      const sel = epop.querySelector(".kb-scope"), ci = epop.querySelector(".kb-cidr");
      if (sel) sel.onchange = () => { ci.style.display = sel.value === "custom" ? "" : "none"; if (sel.value === "custom") ci.focus(); };
      epop.querySelector(".kb-save").onclick = () => {
        const t = epop.querySelector(".kb-text").value.trim(); if (!t) return;
        let to = sel ? sel.value : subj;
        if (to === "custom") { const c = ci.value.trim(); if (!/^[\d.]+\/\d{1,2}$/.test(c)) return alert("Enter a CIDR range such as 203.0.113.0/24"); to = "net:" + c; }
        apiPost("/api/kb/host", { action: "add", subject: to, category: "watch", text: t }).then(() => erender(btn), (er) => alert(er.message));
      };
      epop.querySelectorAll(".kb-del").forEach((x) => x.onclick = () => {
        if (!confirm("Delete this note?")) return;
        apiPost("/api/kb/host", { action: "delete", id: +x.dataset.id }).then(() => erender(btn), (er) => alert(er.message));
      });
    }).catch((er) => { epop.querySelector(".note-body").innerHTML = `<div class="empty">Notes unavailable: ${esc(er.message)}</div>`; });
  }
  function eopen(btn) {
    eclose();
    epop = document.createElement("div"); epop.className = "rel-pop note-pop unote-pop"; epop.setAttribute("role", "dialog"); epop._for = btn;
    document.body.appendChild(epop); erender(btn);
    const r = btn.getBoundingClientRect(), w = Math.min(420, innerWidth - 16);
    epop.style.width = w + "px";
    epop.style.left = Math.max(8, Math.min(innerWidth - w - 8, r.right - w)) + "px";
    const below = r.bottom + 6, h = epop.offsetHeight;
    epop.style.top = (below + h > innerHeight - 8 && r.top - h - 6 > 8 ? r.top - h - 6 : Math.min(below, innerHeight - Math.min(h, innerHeight - 16) - 8)) + "px";
  }
  document.addEventListener("click", (e) => {
    const b = e.target.closest(".extnote-btn");
    if (b) { e.stopPropagation(); e.preventDefault(); if (epop && epop._for === b) return eclose(); return eopen(b); }
    if (epop && !e.target.closest(".unote-pop")) eclose();
  }, true);
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") eclose(); });
  addEventListener("hashchange", eclose);
})();
