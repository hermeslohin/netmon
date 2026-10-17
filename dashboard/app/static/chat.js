// Ask Hermes (#/chat): per-user conversations with the read-only netmon assistant, streamed from the server.
(() => {
  const C = { chats: [], cur: null, busy: false, max: 4000 };
  const SUGGEST = ["What needs my attention today?", "Explain the latest alarms in plain English", "Did any new devices join the network?",
    "Is anything unusual going on with my devices?", "What are the endpoint findings about?"];

  // Minimal, safe markdown: escape first, then add a few formats. Links only for http(s).
  const md = (src) => {
    const blocks = String(src || "").split(/```/);
    return blocks.map((b, i) => {
      if (i % 2) return `<pre class="chat-code">${esc(b.replace(/^[a-z0-9_-]*\n/i, ""))}</pre>`;
      let h = esc(b);
      h = h.replace(/`([^`\n]+)`/g, "<code>$1</code>")
        .replace(/\*\*([^*\n]+)\*\*/g, "<b>$1</b>")
        .replace(/(^|[\s(])\*([^*\n]+)\*(?=[\s).,!?:;]|$)/g, "$1<i>$2</i>")
        .replace(/\[([^\]\n]{1,200})\]\((https?:\/\/[^\s)]+)\)/g, (m, t, u) => `<a href="${u}" target="_blank" rel="noopener noreferrer">${t}</a>`)
        .replace(/(^|[\s(])(https?:\/\/[^\s<)]+)/g, (m, p, u) => `${p}<a href="${u}" target="_blank" rel="noopener noreferrer">${u}</a>`)
        .replace(/^#{1,4} (.+)$/gm, "<b>$1</b>");
      // lists: linear line-by-line pass (no backtracking regex on model output); blank lines between items keep one list
      const LI = /^[ \t]*([-*•]|\d{1,3}[.)]) (.*)$/, lines = h.split("\n"), outL = [];
      let list = null;
      const close = () => { if (list) { outL.push(`<${list.tag}${list.start ? ` start="${list.start}"` : ""}>${list.items.map((x) => `<li>${x}</li>`).join("")}</${list.tag}>`); list = null; } };
      for (let i = 0; i < lines.length; i++) {
        const ln = lines[i], m = ln.match(LI);
        if (m) {
          const ordered = /\d/.test(m[1]);
          if (!list || (list.tag === "ol") !== ordered) { close(); list = { tag: ordered ? "ol" : "ul", start: ordered ? parseInt(m[1], 10) : 0, items: [] }; }
          list.items.push(m[2]);
        } else if (list && ln.trim() === "") {
          let j = i + 1; while (j < lines.length && lines[j].trim() === "") j++;
          if (j < lines.length && LI.test(lines[j])) { i = j - 1; continue; }  // blank line inside a list
          close(); outL.push(ln);
        } else if (list && /^[ \t]{2,}\S/.test(ln)) {
          list.items[list.items.length - 1] += "<br>" + ln.trim();  // indented continuation line
        } else { close(); outL.push(ln); }
      }
      close();
      h = outL.join("\n");
      return h.split(/\n{2,}/).map((p) => (/^\s*<(ul|ol|pre)/.test(p) ? p : `<p>${p.trim().replace(/\n/g, "<br>")}</p>`)).join("");
    }).join("");
  };

  const post = async (body) => {
    const r = await fetch("/api/chat", { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json", "X-Netmon": "1" }, body: JSON.stringify(body) });
    const d = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
    return d;
  };

  const msgHTML = (m) => m.role === "user"
    ? `<div class="chat-msg me"><div class="bubble">${m.about ? `<div class="chat-about">About: ${esc(m.about)}</div>` : ""}${esc(m.text).replace(/\n/g, "<br>")}</div></div>`
    : `<div class="chat-msg bot"><div class="avatar">⚕︎</div><div class="bubble">${m.tools?.length ? `<div class="chat-tools">${[...new Set(m.tools)].map((t) => `<span>${esc(t)}</span>`).join("")}</div>` : ""}${md(m.text)}<div class="chat-by">${aiFlare({ model: m.model, via: "Ask Hermes (netmonchat profile)" })}</div></div></div>`;

  function renderList() {
    const el = document.getElementById("chatList"); if (!el) return;
    el.innerHTML = `<button class="chat-new">＋ New chat</button>` + (C.chats.length ? C.chats.map((c) =>
      `<div class="chat-item${c.id === C.cur ? " on" : ""}" data-id="${esc(c.id)}"><span class="t">${esc(c.title)}</span><span class="muted small">${esc(ft(new Date(c.updated * 1000).toISOString()))}</span><button class="chat-del" title="Delete chat" aria-label="Delete chat" data-del="${esc(c.id)}">✕</button></div>`).join("")
      : `<div class="muted small" style="padding:8px">No chats yet.</div>`);
  }

  function renderEmpty(log) {
    log.innerHTML = `<div class="chat-empty"><div class="avatar big">⚕︎</div><h2>Ask Hermes about your network</h2>
      <div class="muted small">I can read netmon's findings, alarms, devices and alerts, and search the web for context. I can't change anything: no commands, settings or firewall changes.</div>
      <div class="chat-sugg">${SUGGEST.map((s) => `<button data-sugg="${esc(s)}">${esc(s)}</button>`).join("")}</div></div>`;
  }

  async function open(id) {
    C.cur = id; renderList();
    const log = document.getElementById("chatLog"); if (!log) return;
    if (!id) return renderEmpty(log);
    log.innerHTML = `<div class="loading">Loading…</div>`;
    try {
      const d = await post({ action: "history", id });
      if (C.cur !== id) return;
      log.innerHTML = d.messages.length ? d.messages.map(msgHTML).join("") : ""; if (!d.messages.length) renderEmpty(log);
      log.scrollTop = log.scrollHeight;
    } catch (e) { log.innerHTML = `<div class="empty">${esc(e.message)}</div>`; }
    document.body.classList.remove("chat-list-open");
  }

  async function send(text, ctx) {
    text = text.trim(); if (!text || C.busy) return;
    const log = document.getElementById("chatLog"), ta = document.getElementById("chatInput"), btn = document.getElementById("chatSend");
    C.busy = true; btn.disabled = true; ta.value = ""; autosize(ta);
    try {
      if (!C.cur) { C.cur = (await post({ action: "new" })).id; }
      if (log.querySelector(".chat-empty")) log.innerHTML = "";
      log.insertAdjacentHTML("beforeend", msgHTML({ role: "user", text, about: ctx ? `${ctx.kind}: ${ctx.title}` : "" }));
      log.insertAdjacentHTML("beforeend", `<div class="chat-msg bot live"><div class="avatar">⚕︎</div><div class="bubble"><div class="chat-tools"></div><div class="chat-text"><span class="typing"><i></i><i></i><i></i></span></div></div></div>`);
      const live = log.querySelector(".chat-msg.live"), tools = live.querySelector(".chat-tools"), out = live.querySelector(".chat-text");
      log.scrollTop = log.scrollHeight;
      const r = await fetch("/api/chat", { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json", "X-Netmon": "1" },
        body: JSON.stringify({ action: "send", id: C.cur, text, ...(ctx ? { context: ctx } : {}), ...(chatModel() ? { model: chatModel() } : {}) }) });
      if (!r.ok || !(r.headers.get("Content-Type") || "").includes("event-stream")) {
        const d = await r.json().catch(() => ({})); throw new Error(d.error || `HTTP ${r.status}`);
      }
      const rd = r.body.getReader(), dec = new TextDecoder(); let buf = "", acc = "", ended = false, pending = 0;
      const paint = () => { pending = 0; out.innerHTML = md(acc) || '<span class="typing"><i></i><i></i><i></i></span>'; const near = log.scrollHeight - log.scrollTop - log.clientHeight < 140; if (near) log.scrollTop = log.scrollHeight; };
      while (!ended) {
        const { value, done } = await rd.read(); if (done) break;
        buf += dec.decode(value, { stream: true });
        let k;
        while ((k = buf.indexOf("\n\n")) >= 0) {
          const chunk = buf.slice(0, k); buf = buf.slice(k + 2);
          const ev = (chunk.match(/^event: (.+)$/m) || [])[1], data = JSON.parse((chunk.match(/^data: (.+)$/m) || [, "{}"])[1]);
          if (ev === "delta") { acc += data.t; if (!pending) pending = requestAnimationFrame(paint); }
          else if (ev === "tool") { if (![...tools.children].some((s) => s.textContent === data.name)) tools.insertAdjacentHTML("beforeend", `<span class="run">${esc(data.name)}</span>`); }
          else if (ev === "model") live.querySelector(".bubble").insertAdjacentHTML("beforeend", `<div class="chat-by">${aiFlare({ model: data.model, via: "Ask Hermes (netmonchat profile)" })}</div>`);
          else if (ev === "tool_error") tools.insertAdjacentHTML("beforeend", `<span class="bad">${esc(data.name)} failed</span>`);
          else if (ev === "end") {
            ended = true; paint(); tools.querySelectorAll(".run").forEach((s) => s.classList.remove("run"));
            if (data.status !== "completed") out.insertAdjacentHTML("beforeend", `<div class="chat-err">${esc(data.error || "The answer was interrupted.")}</div>`);
          }
        }
      }
      if (!ended) { paint(); out.insertAdjacentHTML("beforeend", `<div class="chat-err">Connection closed before the answer finished.</div>`); }
      live.classList.remove("live");
      C.chats = (await post({ action: "list" })).chats; renderList();
    } catch (e) {
      const live = log.querySelector(".chat-msg.live");
      if (live) { live.classList.remove("live"); live.querySelector(".chat-text").innerHTML = `<div class="chat-err">${esc(e.message)}</div>`; }
      else log.insertAdjacentHTML("beforeend", `<div class="chat-err">${esc(e.message)}</div>`);
    }
    C.busy = false; btn.disabled = false; ta.focus();
  }

  const autosize = (ta) => { ta.style.height = "auto"; ta.style.height = Math.min(ta.scrollHeight, 180) + "px"; };

  const fit = () => {  // the chat fills exactly the space below the header (header height varies with nav wrapping)
    const w = document.querySelector(".chat-wrap"); if (!w) { removeEventListener("resize", fit); return; }
    w.style.height = Math.max(380, innerHeight - w.getBoundingClientRect().top - 12) + "px";
  };
  V.chat = async (el) => {
    el.innerHTML = `<div class="chat-wrap">
      <aside class="chat-side card"><div class="chat-side-h"><b>Chats</b></div><div id="chatList"><div class="loading">Loading…</div></div></aside>
      <section class="chat-main card">
        <div class="chat-head"><button class="chat-listbtn" aria-label="Show chats">☰ Chats</button><b>Ask Hermes</b><span class="muted small">read-only netmon assistant</span><span class="chatm-slot"></span></div>
        <div id="chatLog" class="chat-log"></div>
        <form class="chat-form" autocomplete="off"><textarea id="chatInput" rows="1" placeholder="Ask about your network…" maxlength="4000" aria-label="Message"></textarea><button id="chatSend" type="submit" aria-label="Send">➤</button></form>
        <div class="chat-foot muted small">Answers can be wrong. Check important findings on the dashboard pages.</div>
      </section></div>`;
    window.scrollTo(0, 0); fit(); addEventListener("resize", fit); setTimeout(fit, 300);
    chatModelPicker().then((p) => el.querySelector(".chatm-slot")?.replaceChildren(p));
    const ta = el.querySelector("#chatInput"), form = el.querySelector(".chat-form");
    ta.addEventListener("input", () => autosize(ta));
    ta.addEventListener("keydown", (e) => { if (e.key === "Enter" && !e.shiftKey && !e.isComposing && !matchMedia("(pointer: coarse)").matches) { e.preventDefault(); send(ta.value); } });
    form.onsubmit = (e) => { e.preventDefault(); send(ta.value); };
    el.querySelector(".chat-listbtn").onclick = () => document.body.classList.toggle("chat-list-open");
    el.addEventListener("click", async (e) => {
      const s = e.target.closest("[data-sugg]"); if (s) return send(s.dataset.sugg);
      const d = e.target.closest("[data-del]");
      if (d) { e.stopPropagation(); if (!confirm("Delete this chat?")) return; await post({ action: "delete", id: d.dataset.del }).catch(() => {});
        C.chats = C.chats.filter((c) => c.id !== d.dataset.del); if (C.cur === d.dataset.del) open(null); else renderList(); return; }
      if (e.target.closest(".chat-new")) { if (!C.busy) open(null); document.body.classList.remove("chat-list-open"); ta.focus(); return; }
      const it = e.target.closest(".chat-item"); if (it && !C.busy) open(it.dataset.id);
    });
    try {
      const d = await post({ action: "list" }); C.chats = d.chats; C.max = d.max_input || 4000; ta.maxLength = C.max;
    } catch (e) { el.querySelector("#chatList").innerHTML = ""; el.querySelector("#chatLog").innerHTML = `<div class="empty">${esc(e.message)}</div>`; return; }
    let pend = null; try { pend = JSON.parse(sessionStorage.getItem("askPending") || "null"); } catch (_) { /* ignore */ }
    sessionStorage.removeItem("askPending");
    if (pend?.q) { C.cur = null; await open(null); send(pend.q, pend.ctx); return; }  // "Ask Hermes" from a finding: always a fresh chat
    open(C.cur && C.chats.some((c) => c.id === C.cur) ? C.cur : null);
  };
})();
