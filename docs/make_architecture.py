"""Regenerate with: python3 docs/make_architecture.py

Generate docs/architecture.svg (netmon architecture) in the architecture-diagram skill's design system."""
from html import escape as E

W, H = 1300, 1010
C = {  # semantic palette: fill, stroke
    "front": ("rgba(8,51,68,0.4)", "#22d3ee"), "back": ("rgba(6,78,59,0.4)", "#34d399"),
    "db": ("rgba(76,29,149,0.4)", "#a78bfa"), "cloud": ("rgba(120,53,15,0.3)", "#fbbf24"),
    "sec": ("rgba(136,19,55,0.4)", "#fb7185"), "bus": ("rgba(251,146,60,0.3)", "#fb923c"),
    "ext": ("rgba(30,41,59,0.5)", "#94a3b8"), "ai": ("rgba(88,28,135,0.35)", "#e879f9"),
}
FONT = "JetBrains Mono, ui-monospace, SFMono-Regular, Menlo, Consolas, monospace"
out = []
box = {}


def node(key, x, y, w, h, kind, title, subs=(), tag=None):
    f, s = C[kind]
    box[key] = (x, y, w, h)
    out.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="6" fill="#0f172a"/>')
    out.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="6" fill="{f}" stroke="{s}" stroke-width="1.5"/>')
    ty = y + 24 if subs else y + h / 2 + 4
    out.append(f'<text x="{x + w / 2}" y="{ty}" text-anchor="middle" fill="#f1f5f9" font-size="13" font-weight="700">{E(title)}</text>')
    for i, t in enumerate(subs):
        out.append(f'<text x="{x + w / 2}" y="{ty + 18 + i * 14}" text-anchor="middle" fill="#94a3b8" font-size="10">{E(t)}</text>')
    if tag:
        out.append(f'<text x="{x + w - 8}" y="{y + 13}" text-anchor="end" fill="{s}" font-size="8" letter-spacing="1">{E(tag)}</text>')


def region(x, y, w, h, label, color, dash="8,4"):
    out.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="12" fill="none" stroke="{color}" stroke-width="1.2" stroke-dasharray="{dash}" opacity="0.8"/>')
    out.append(f'<text x="{x + 14}" y="{y + 20}" fill="{color}" font-size="11" font-weight="700" letter-spacing="1.5">{E(label)}</text>')


def anchor(key, side, t=0.5):
    x, y, w, h = box[key]
    return {"l": (x, y + h * t), "r": (x + w, y + h * t), "t": (x + w * t, y), "b": (x + w * t, y + h)}[side]


arrows = []


def arrow(a, b, color="#64748b", label=None, dash=None, curve=0, lpos=0.5, both=False, ldy=-6):
    (x1, y1), (x2, y2) = a, b
    mid = f"url(#ah-{color[1:]})"
    d = f"M{x1},{y1} L{x2},{y2}"
    if curve:
        cx = (x1 + x2) / 2
        d = f"M{x1},{y1} C{cx + curve},{y1} {cx - curve},{y2} {x2},{y2}"
    attrs = f'fill="none" stroke="{color}" stroke-width="1.5" marker-end="{mid}"' + (f' marker-start="{mid}"' if both else "")
    if dash:
        attrs += f' stroke-dasharray="{dash}"'
    arrows.append(f'<path d="{d}" {attrs}/>')
    if label:
        lx, ly = x1 + (x2 - x1) * lpos, y1 + (y2 - y1) * lpos + ldy
        wlab = len(label) * 5.6 + 8
        arrows.append(f'<rect x="{lx - wlab / 2}" y="{ly - 9}" width="{wlab}" height="13" rx="3" fill="#020617" opacity="0.92"/>'
                      f'<text x="{lx}" y="{ly + 1}" text-anchor="middle" fill="{color}" font-size="9">{E(label)}</text>')


def lab2(cx, y, color, l1, l2):  # two-line label for the narrow gaps between regions
    w = max(len(l1), len(l2)) * 5.6 + 8
    arrows.append(f'<rect x="{cx - w / 2}" y="{y - 9}" width="{w}" height="26" rx="3" fill="#020617" opacity="0.92"/>'
                  f'<text x="{cx}" y="{y + 1}" text-anchor="middle" fill="{color}" font-size="9">{E(l1)}</text>'
                  f'<text x="{cx}" y="{y + 12}" text-anchor="middle" fill="{color}" font-size="9">{E(l2)}</text>')


# ---------------- regions
region(20, 70, 380, 740, "HOME NETWORK", "#34d399")
region(36, 280, 348, 290, "SECURITY ONION", "#fb7185", "4,4")
region(440, 70, 500, 740, "MONITORING HOST (local AI box)", "#22d3ee")
region(980, 70, 300, 740, "CLOUD SERVICES", "#fbbf24")

# ---------------- home network
node("ep", 50, 100, 320, 84, "back", "Endpoints · Elastic Agent", ["Elastic Defend (process / network / file)", "osquery (osquerybeat) · system auth & syslog"], "HOSTS")
node("fleet", 50, 206, 320, 52, "back", "Fleet Server", ["agent enrollment + policy"])
node("sensor", 56, 312, 308, 70, "sec", "Network sensor", ["Suricata IDS · Zeek · PCAP", "mirrors all LAN traffic"], "NSM")
node("es", 56, 430, 308, 120, "db", "Elasticsearch", ["IDS alerts · Zeek conn/dns/tls/files", "endpoint events · osquery results", "detection-rule hits", "read-only API key for netmon"], "SIEM")
node("unifi", 50, 600, 320, 70, "sec", "UniFi gateway", ["IDS/IPS · firewall · traffic flows", "admin audit · client inventory"], "EDGE")

# ---------------- monitoring host
node("llm", 460, 100, 150, 76, "ai", "Local LLM", ["LM Studio · Gemma", "on-box inference"], "LOCAL")
node("hermes", 626, 100, 294, 76, "ai", "Hermes Agent", ["\"Lady Brains\" · cron · skills", "tools · memory · runs every job"], "AGENT")
node("watch", 460, 226, 222, 82, "back", "watch.py", ["urgent watcher (no LLM)", "new devices · IDS · host anomalies"], "EVERY 15 MIN")
node("nightly", 698, 226, 222, 82, "back", "Nightly pipeline", ["collect → analyze → triage", "baseline · ATT&CK · report.py"], "05:00 UTC")
node("db", 460, 348, 222, 76, "db", "netmon data", ["SQLite (WAL) · alerts · baselines", "nightly snapshots + triage JSON"])
node("pdf", 698, 348, 222, 76, "db", "PDF reports", ["one per night, kept locally", "served for download"])
node("dash", 460, 464, 460, 104, "front", "netmon dashboard  (Docker · HTTPS)", ["Overview · Risk · Fix list · Endpoints · Lateral map", "ATT&CK · Alerts · Reports (PDF download) · Users", "Web Push urgent notifications · per-user device subscriptions"], "WEB APP")
node("mcp", 460, 608, 222, 76, "bus", "netmon MCP server", ["netmon_mcp.py · stdio", "9 read-only query tools"], "READ-ONLY")
node("chatp", 698, 608, 222, 76, "ai", "Hermes chat profile", ["netmonchat · API on loopback", "tools: web + netmon only"], "ASK HERMES")
node("ship", 460, 716, 460, 64, "sec", "ship.sh · weekly_rebuild.sh", ["weekly rebuild + scans: Semgrep · Bandit · ESLint · Trivy · Gitleaks · ZAP", "sensitive-data guard before every push"], "GATE")

# ---------------- cloud
node("claude", 1000, 100, 260, 76, "ai", "Claude  (Anthropic API)", ["nightly triage · web research", "verdicts with citations · coding"], "LLM")
node("uapi", 1000, 226, 260, 82, "cloud", "UniFi Site Manager API", ["api.ui.com cloud connector", "read-only API key"], "API")
node("users", 1000, 478, 260, 76, "front", "Family browsers & phones", ["Cloudflare tunnel → HTTPS", "PWA + push notifications"], "USERS")
node("gh", 1000, 716, 260, 64, "ext", "GitHub", ["public repo · ghcr.io image", "no site data (site.json local)"], "CODE")

# ---------------- connections
arrow(anchor("ep", "b"), anchor("fleet", "t"), "#34d399", "enroll / policy", ldy=4)
arrows.append('<path d="M50,160 C10,200 10,470 56,490" fill="none" stroke="#34d399" stroke-width="1.5" marker-end="url(#ah-34d399)"/>')
arrows.append('<rect x="2" y="318" width="34" height="40" fill="#020617" opacity="0.9"/><text x="19" y="332" text-anchor="middle" fill="#34d399" font-size="9">events</text><text x="19" y="346" text-anchor="middle" fill="#34d399" font-size="9">via</text><text x="19" y="358" text-anchor="middle" fill="#34d399" font-size="9">Fleet</text>')
arrow(anchor("sensor", "b"), anchor("es", "t"), "#fb7185", "alerts + logs", ldy=4)
# Elasticsearch read-only query bus (gap between agent row and job row) feeding both jobs
arrows.append('<path d="M364,470 C425,470 415,201 452,201 L880,201" fill="none" stroke="#a78bfa" stroke-width="1.6"/>')
arrows.append('<path d="M545,201 L545,226" fill="none" stroke="#a78bfa" stroke-width="1.6" marker-end="url(#ah-a78bfa)"/>')
arrows.append('<path d="M880,201 L880,226" fill="none" stroke="#a78bfa" stroke-width="1.6" marker-end="url(#ah-a78bfa)"/>')
arrows.append('<rect x="372" y="300" width="64" height="26" rx="3" fill="#020617" opacity="0.92"/><text x="404" y="311" text-anchor="middle" fill="#a78bfa" font-size="9">_search</text><text x="404" y="322" text-anchor="middle" fill="#a78bfa" font-size="9">read-only</text>')
# UniFi gateway -> cloud API (around the bottom/right edge) -> nightly pipeline
arrows.append('<path d="M210,670 L210,796 L1272,796 L1272,280 L1260,280" fill="none" stroke="#fbbf24" stroke-width="1.5" stroke-dasharray="6,3" marker-end="url(#ah-fbbf24)"/>')
arrows.append('<rect x="222" y="689" width="132" height="13" rx="3" fill="#020617"/><text x="288" y="699" text-anchor="middle" fill="#fbbf24" font-size="9">telemetry via UniFi cloud</text>')
arrow(anchor("uapi", "l", 0.4), (920, 259), "#fbbf24", dash="6,3")
lab2(960, 236, "#fbbf24", "events", "flows")
arrow(anchor("llm", "r"), anchor("hermes", "l"), "#e879f9", both=True)
arrow(anchor("hermes", "r"), anchor("claude", "l"), "#e879f9", both=True)
lab2(960, 114, "#e879f9", "reasoning", "triage")
arrows.append('<path d="M660,176 L660,226" fill="none" stroke="#e879f9" stroke-width="1.5" marker-end="url(#ah-e879f9)"/>')
arrows.append('<path d="M780,176 L780,226" fill="none" stroke="#e879f9" stroke-width="1.5" marker-end="url(#ah-e879f9)"/>')
arrows.append('<rect x="690" y="182" width="62" height="13" rx="3" fill="#020617"/><text x="721" y="192" text-anchor="middle" fill="#e879f9" font-size="9">runs jobs</text>')
arrow(anchor("watch", "b"), anchor("db", "t"), "#34d399", "alerts", ldy=4)
arrow((720, 308), (682, 352), "#34d399")
arrows.append('<rect x="660" y="318" width="42" height="13" rx="3" fill="#020617"/><text x="681" y="328" text-anchor="middle" fill="#34d399" font-size="9">baseline</text>')
arrow((830, 308), (830, 348), "#34d399", "report.py", ldy=4)
arrow(anchor("db", "b"), (571, 464), "#a78bfa", "reads", ldy=4)
arrow(anchor("pdf", "b"), (809, 464), "#a78bfa", "downloads", ldy=4)
arrow(anchor("dash", "r", 0.4), anchor("users", "l", 0.6), "#22d3ee", both=True)
lab2(960, 468, "#22d3ee", "HTTPS", "Web Push")
arrow(anchor("ship", "r"), anchor("gh", "l"), "#94a3b8")
lab2(960, 726, "#94a3b8", "scanned", "push")
# Ask Hermes: dashboard -> restricted chat profile -> read-only MCP server -> netmon data; chat model = Claude
arrow((809, 568), (809, 608), "#e879f9", "Ask Hermes", ldy=4)
arrow(anchor("chatp", "l"), anchor("mcp", "r"), "#fb923c", "MCP", ldy=-6)
arrows.append('<path d="M460,410 L450,410 L450,646 L460,646" fill="none" stroke="#a78bfa" stroke-width="1.6" marker-end="url(#ah-a78bfa)"/>')
lab2(450, 520, "#a78bfa", "read", "only")
arrows.append('<path d="M920,646 L990,646 L990,160 L1000,160" fill="none" stroke="#e879f9" stroke-width="1.5" stroke-dasharray="6,3" marker-end="url(#ah-e879f9)"/>')
lab2(990, 600, "#e879f9", "chat", "model")

# ---------------- legend
ly = 850
legend = [("#34d399", "data pipeline"), ("#fb7185", "security sensor / gate"), ("#a78bfa", "storage / query"),
          ("#e879f9", "AI: agent & LLMs"), ("#fbbf24", "cloud API"), ("#22d3ee", "user-facing"), ("#fb923c", "MCP tool bridge")]
out_leg = [f'<text x="20" y="{ly}" fill="#e2e8f0" font-size="11" font-weight="700" letter-spacing="1.5">LEGEND</text>']
for i, (c, t) in enumerate(legend):
    x = 20 + (i % 3) * 230
    y = ly + 22 + (i // 3) * 20
    out_leg.append(f'<rect x="{x}" y="{y - 9}" width="12" height="12" rx="2" fill="none" stroke="{c}" stroke-width="1.5"/><text x="{x + 20}" y="{y + 1}" fill="#94a3b8" font-size="10">{E(t)}</text>')
out_leg.append(f'<line x1="720" y1="{ly + 18}" x2="760" y2="{ly + 18}" stroke="#94a3b8" stroke-width="1.5"/><text x="768" y="{ly + 22}" fill="#94a3b8" font-size="10">request / data flow</text>')
out_leg.append(f'<line x1="720" y1="{ly + 38}" x2="760" y2="{ly + 38}" stroke="#94a3b8" stroke-width="1.5" stroke-dasharray="6,3"/><text x="768" y="{ly + 42}" fill="#94a3b8" font-size="10">via internet / cloud</text>')
notes = ["Elasticsearch is queried read-only; netmon never changes Security Onion, UniFi or the network.",
         "Nightly: Claude triages findings with web research; report.py renders the PDF (downloadable in the dashboard).",
         "Every 15 min: deterministic watcher → alerts table → Web Push to subscribed users. Nothing is posted to chat.",
         "Ask Hermes: dashboard chat → isolated Hermes profile (no terminal/files/memory) → read-only netmon MCP server."]
for i, t in enumerate(notes):
    out_leg.append(f'<text x="20" y="{ly + 92 + i * 16}" fill="#64748b" font-size="10">• {E(t)}</text>')

colors = sorted({"fb923c", "34d399", "fb7185", "a78bfa", "e879f9", "fbbf24", "22d3ee", "94a3b8", "64748b"})
markers = "".join(f'<marker id="ah-{c}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="#{c}"/></marker>' for c in colors)
svg = f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}" font-family="{FONT}">
<defs><pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse"><path d="M 40 0 L 0 0 0 40" fill="none" stroke="#1e293b" stroke-width="0.5"/></pattern>{markers}</defs>
<rect width="{W}" height="{H}" fill="#020617"/><rect width="{W}" height="{H}" fill="url(#grid)"/>
<circle cx="30" cy="34" r="5" fill="#22d3ee"/><text x="44" y="39" fill="#f8fafc" font-size="18" font-weight="700">netmon · home network &amp; endpoint security monitoring</text>
<text x="{W - 20}" y="39" text-anchor="end" fill="#64748b" font-size="10">Hermes agent · Security Onion · Elastic · UniFi · Claude · local LLM</text>
{"".join(arrows)}
{"".join(out)}
{"".join(out_leg)}
</svg>
'''
import os
open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "architecture.svg"), "w").write(svg)
print(len(svg))
