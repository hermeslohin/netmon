#!/usr/bin/python3
"""Render the netmon PDF: report.py [snapshot.json] -> reports/network-report-<stamp>.pdf

Inputs (same stem): <snap>.json (collect.py), <snap>.analysis.json (analyze.py),
optional <snap>.triage.json (analyst-written alarms), known_benign.json.
"""
import glob, json, os, sys
from collections import defaultdict
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import site_cfg as SITE  # noqa: E402  network-specific values live in site.json (git-ignored)
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, landscape
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether)
from reportlab.graphics.shapes import Drawing, String
from reportlab.graphics.charts.barcharts import VerticalBarChart, HorizontalBarChart

NM = os.path.expanduser("~/.hermes/netmon")
snap_path = sys.argv[1] if len(sys.argv) > 1 else sorted(
    p for p in glob.glob(f"{NM}/data/*.json") if os.path.basename(p).count(".") == 1)[-1]
stem = snap_path[:-5]
snap = json.load(open(snap_path))
ana = json.load(open(stem + ".analysis.json")) if os.path.exists(stem + ".analysis.json") else {}
tri = json.load(open(stem + ".triage.json")) if os.path.exists(stem + ".triage.json") else {}
# citation ledger written by grounded-citations sources.py (HERMES_CITATION_LEDGER=<stem>.sources.json)
SOURCES = {}
if os.path.exists(stem + ".sources.json"):
    _l = json.load(open(stem + ".sources.json"))
    for s in (_l.get("sources") if isinstance(_l, dict) else _l) or []:
        SOURCES[int(s["id"])] = s
kb = json.load(open(f"{NM}/known_benign.json"))
NAMES = kb.get("names", {})
brief = json.load(open(stem + ".briefing.json")) if os.path.exists(stem + ".briefing.json") else {}

ss = getSampleStyleSheet()
H1, H2, B = ss["Title"], ss["Heading2"], ss["BodyText"]
SM = ParagraphStyle("sm", parent=B, fontSize=7.5, leading=9)
SMB = ParagraphStyle("smb", parent=SM, fontName="Helvetica-Bold")
LNK = ParagraphStyle("lnk", parent=SM, fontSize=6.8, leading=8.4)
CTX = ParagraphStyle("ctx", parent=SM, fontSize=7, leading=8.5, textColor=colors.HexColor("#34495e"), fontName="Helvetica-Oblique")
NAVY, GRID = colors.HexColor("#1f3a5f"), colors.HexColor("#c8cdd4")
PRI = {"Investigate": colors.HexColor("#c0392b"), "Review": colors.HexColor("#d68910"), "Info": colors.HexColor("#2e86c1")}


def fmt(b):
    b = b or 0
    for u, d in (("GB", 1e9), ("MB", 1e6), ("KB", 1e3)):
        if b >= d:
            return f"{b/d:.2f} {u}" if u == "GB" else f"{b/d:.1f} {u}"
    return f"{b:.0f} B"


def name_of(ip, d):
    n = d.get("name") or NAMES.get(ip) or "(unknown)"
    if ip in NAMES and not d.get("known"):
        n = NAMES[ip]
    return n


PORT_NAMES = {"53": "dns", "443": "https", "80": "http", "123": "ntp", "67": "dhcp", "5353": "mdns", "1900": "ssdp",
              "5351": "nat-pmp", "3478": "stun", "993": "imaps", "143": "imap", "853": "dns-over-tls", "5223": "apple-push",
              "5228": "google-push", "6443": "k8s-api", "9200": "elasticsearch", "8220": "elastic-fleet", "5055": "so-agent",
              "8443": "https-alt", "25565": "minecraft", "10001": "unifi-disc", "22": "ssh", "161": "snmp", "1194": "openvpn",
              "41641": "tailscale", "3481": "teams-media", "56700": "lifx", "9999": "kasa", "33434": "traceroute", "8009": "cast"}


def port_label(k, svc=""):
    num, _, tr = k.partition("/")
    if tr == "icmp":
        return {"0": "icmp echo-reply", "3": "icmp unreachable", "8": "icmp ping", "11": "icmp ttl-exceeded"}.get(num, f"icmp {num}")
    name = svc if svc and svc not in ("unidentified",) else PORT_NAMES.get(num, "")
    name = name.replace("spicy_", "")
    return f"{k} {name}".strip()


def short(a):
    for s in (", Inc.", " Inc.", ", LLC", " LLC", " Corporation", " Technologies", " International B.V.", " B.V.", ", Ltd.", " Co.", " Services"):
        a = a.replace(s, "")
    return a[:22]


def esc(t):
    return str(t).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def P(t, st=SM):
    return Paragraph(esc(t), st)


import re as _re

LINKC = "#1a5fb4"


def A(url, label):
    return f'<a href="{esc(url)}" color="{LINKC}">{esc(label)}</a>'


def cite_links(text):
    """Escape text and turn [n] citations into clickable links to the cited source."""
    out = esc(text)
    return _re.sub(r"\[(\d+)\]", lambda m: A(SOURCES[int(m.group(1))]["url"], f"[{m.group(1)}]")
                   if int(m.group(1)) in SOURCES else m.group(0), out)


PL = lambda t, st=SM: Paragraph(cite_links(t), st)

_OWN = tuple(SITE.get("own_domains") or []) + (".local", ".localdomain", ".arpa")
_FILE_EXT = (".exe", ".php", ".json", ".py", ".zeek", ".pdf", ".csv", ".jsonl", ".html", ".md", ".sh", ".dll", ".js")
_TLDS = None


def _tld_ok(dom):
    global _TLDS
    if _TLDS is None:
        try:
            _TLDS = set(json.load(open(os.path.join(NM, "intel", "rdap_bootstrap_tlds.json"))))
        except Exception:
            try:
                _TLDS = {t for tl, _u in json.load(open(os.path.join(NM, "intel", "rdap_bootstrap.json")))["services"] for t in tl}
            except Exception:
                _TLDS = set()
        _TLDS |= {"com", "net", "org", "io", "co", "gg", "to", "us", "ai", "me", "tv", "cc", "uk", "de", "app", "dev", "icu", "xyz", "work"}
    return dom.rsplit(".", 1)[-1].lower() in _TLDS


def iocs(text):
    """External IPs, domains and hashes mentioned in free text -> lookup links."""
    text = _re.sub(r"\S+@\S+", " ", str(text))  # drop e-mail addresses
    found = []
    for ip in _re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text):
        if not (SITE.is_internal(ip) or ip.startswith(("10.", "192.168.", "172.16.", "127.", "224.", "239.", "255."))) and ip not in found:
            found.append(ip)
    for m in _re.finditer(r"\b[a-f0-9]{32}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{64}\b", text):
        h = m.group(0)
        if _re.search(r"(?i)ja3|fingerprint", text[max(0, m.start() - 40):m.start()]):
            h = "ja3:" + h
        if h not in found:
            found.append(h)
    for d in _re.findall(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", text.lower()):
        d = d.strip(".")
        if (d.endswith(_OWN) or d.endswith(_FILE_EXT) or d in found or _re.fullmatch(r"[\d.]+", d)
                or not _tld_ok(d) or d.startswith(("known_benign", "policy", "devices_seen"))):
            continue
        found.append(d)
    return found[:5]


def ioc_links(ind):
    if _re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", ind):
        return (f"{esc(ind)} " + A(f"https://www.virustotal.com/gui/ip-address/{ind}", "VT") + " " +
                A(f"https://otx.alienvault.com/indicator/ip/{ind}", "OTX") + " " +
                A(f"https://www.abuseipdb.com/check/{ind}", "AbuseIPDB") + " " +
                A(f"https://ipinfo.io/{ind}", "ipinfo"))
    if ind.startswith("ja3:"):
        j = ind[4:]
        return f"JA3 {esc(j[:12])}... " + A(f"https://sslbl.abuse.ch/ja3-fingerprints/{j}/", "SSLBL")
    if _re.fullmatch(r"[a-f0-9]{32,64}", ind):
        return (f"{esc(ind[:12])}... " + A(f"https://www.virustotal.com/gui/file/{ind}", "VT") + " " +
                A(f"https://bazaar.abuse.ch/browse.php?search=md5:{ind}", "MalwareBazaar"))
    return (f"{esc(ind)} " + A(f"https://www.virustotal.com/gui/domain/{ind}", "VT") + " " +
            A(f"https://otx.alienvault.com/indicator/domain/{ind}", "OTX") + " " +
            A(f"https://urlhaus.abuse.ch/browse.php?search={ind}", "URLhaus") + " " +
            A(f"https://urlscan.io/search/#domain:{ind}", "urlscan"))


NO_PIVOT = ("segmentation", "internal-scan", "new-internal-peer", "outdated-software", "legacy-tls", "volume", "upload",
            "fan-out", "failed-conns", "odd-hours", "silent", "port-", "new-port", "new-service", "service-mix", "new-listening")


def det_cell(f):
    cell = [P(f["detail"])]
    if not f["kind"].startswith(NO_PIVOT):
        lp = links_par((), f["detail"])
        if lp:
            cell.append(lp)
    return cell


def links_par(item_links=(), text_for_iocs="", st=None):
    """'Links:' paragraph: analyst-supplied links (title+url) followed by IOC lookup pivots."""
    parts = [A(l["url"], l.get("title") or l["url"]) for l in item_links if l.get("url")]
    piv = [ioc_links(i) for i in iocs(text_for_iocs)]
    if not parts and not piv:
        return None
    s = ""
    if parts:
        s += "<b>Links:</b> " + " | ".join(parts)
    if piv:
        s += ("<br/>" if s else "") + "<b>Look up:</b> " + " &middot; ".join(piv)
    return Paragraph(s, st or LNK)


def table(rows, widths, head_bg=NAVY, zebra=True, extra=()):
    t = Table(rows, colWidths=widths, repeatRows=1)
    st = [("BACKGROUND", (0, 0), (-1, 0), head_bg), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
          ("FONTSIZE", (0, 0), (-1, -1), 7.5), ("GRID", (0, 0), (-1, -1), 0.25, GRID),
          ("VALIGN", (0, 0), (-1, -1), "TOP"), ("TOPPADDING", (0, 0), (-1, -1), 2), ("BOTTOMPADDING", (0, 0), (-1, -1), 2)]
    if zebra:
        st += [("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f3f5f8")])]
    t.setStyle(TableStyle(st + list(extra)))
    return t


def benign_reason(sig):
    for k, v in kb["signatures"].items():
        if k.lower() in sig.lower():
            return v
    return None


story = []
gen = snap["generated"][:16].replace("T", " ")
t = snap["totals"]
alerts = snap["alerts"]
story += [Paragraph("Home Network Behavior Report", H1),
          P(f"Window: last {snap['hours']} h ending {gen} UTC (ET = UTC-4) - Source: Security Onion (Zeek + Suricata) - "
            f"Device names: {os.path.basename(snap['inventory_file'])}", B), Spacer(1, 6)]

kpi = [["Connections", "Wire bytes seen", "Internet bytes", "Missed (cap. loss)", "Suricata alerts", "Devices active"],
       [f"{t['conns']:,}", fmt(t["ip_bytes"]), fmt(t["internet_ip_bytes"]), fmt(t["missed_bytes"]), f"{alerts['total']:,}",
        str(sum(1 for ip in snap["devices"] if SITE.is_internal(ip) and not ip.endswith(".255")))]]
story += [table(kpi, [1.15 * inch] * 6, zebra=False, extra=[("FONTSIZE", (0, 1), (-1, 1), 11), ("ALIGN", (0, 0), (-1, -1), "CENTER")]),
          Spacer(1, 8)]
if tri.get("summary"):
    story += [Paragraph("<b>Bottom line:</b> " + cite_links(tri["summary"]), B), Spacer(1, 6)]

# ---------- 1. Alarms ----------
_SEC = [0]


def H(title, sub=None):
    """Numbered section header; omitted sections leave no gaps."""
    if sub:
        return Paragraph(f"{_SEC[0]}{sub}. {title}", H2)
    _SEC[0] += 1
    return Paragraph(f"{_SEC[0]}. {title}", H2)


story.append(H("Alarms worth analyzing"))
act_alarms = [a for a in tri.get("alarms", []) if a.get("priority") != "Info"]
info_alarms = [a for a in tri.get("alarms", []) if a.get("priority") == "Info"]
if act_alarms:
    rows = [["Priority", "Finding", "Evidence", "Assessment / next step"]]
    ex = []
    for i, a in enumerate(act_alarms, 1):
        cell = [P(a["why"]), P("Next: " + a["next"], SMB)]
        if a.get("context"):
            cell.append(PL("Context: " + a["context"], CTX))
        cited = [SOURCES[int(n)] for n in dict.fromkeys(_re.findall(r"\[(\d+)\]", a.get("context", ""))) if int(n) in SOURCES]
        lp = links_par(list(a.get("links", [])) + [{"url": s["url"], "title": f"[{s['id']}] {s.get('title') or s['url']}"} for s in cited],
                       a.get("evidence", "") + " " + a.get("title", ""))
        if lp:
            cell.append(lp)
        rows.append([P(a["priority"], SMB), [P(a["title"], SMB), P(a["who"])], P(a["evidence"]), cell])
        ex.append(("TEXTCOLOR", (0, i), (0, i), PRI.get(a["priority"], colors.black)))
    story.append(table(rows, [0.75 * inch, 1.75 * inch, 2.45 * inch, 2.35 * inch], extra=ex))
elif tri.get("alarms"):
    story.append(P("Nothing needs action: every finding was checked and explained.", B))
else:
    story.append(P("No analyst triage file for this snapshot; see unrecognised signatures and baseline deviations below.", B))
if info_alarms:
    story.append(Spacer(1, 3))
    story.append(Paragraph("<b>Checked and benign</b> (details kept in the triage data): " + cite_links("; ".join(a["title"] for a in info_alarms) + "."), SM))

if tri.get("research_notes"):
    story.append(Spacer(1, 4))
    story.append(Paragraph("<b>Research notes</b> (web context; numbered sources at the end of the report)", SM))
    for n in tri["research_notes"]:
        story.append(PL("- " + n, SM))

# ---------- 2. Alerts signal vs noise ----------
story.append(H("IDS alerts: signal vs. known noise"))
noise = [s for s in alerts["signatures"] if benign_reason(s["name"])]
signal = [s for s in alerts["signatures"] if not benign_reason(s["name"])]
nn = sum(s["count"] for s in noise)
story.append(P(f"{nn:,} of {alerts['total']:,} alerts ({100*nn/max(alerts['total'],1):.1f}%) match signatures already explained as benign "
               f"in this house (listed in known_benign.json). Remaining {len(signal)} signatures ({alerts['total']-nn:,} alerts):", B))
sev = {1: "High", 2: "Med", 3: "Low"}
rows = [["Count", "Sev", "Signature", "Sources", "Destinations"]]
for s in signal:
    rows.append([f"{s['count']:,}", sev.get(s["severity"], s["severity"]), P(s["name"]),
                 P(", ".join(f"{NAMES.get(k) or snap['inventory_ips'].get(k, k)} ({v})" for k, v in list(s["src"].items())[:3])),
                 P(", ".join(list(s["dst"])[:3]))])
story.append(table(rows, [0.5 * inch, 0.4 * inch, 3.0 * inch, 1.9 * inch, 1.5 * inch]))
story.append(Spacer(1, 4))
if snap.get("detections"):
    story.append(P(f"Detection-rule hits: {len(snap['detections'])} - " + "; ".join(
        sorted({f"{d['rule']}" for d in snap['detections']})) + " (see alarm list).", B))

# ---------- 2b. UniFi gateway security ----------
uf = snap.get("unifi") or {}
story.append(H("UniFi gateway: threats, admin activity, blocked traffic", "b"))


def PB(t, st=SM):  # P() with <b>..</b> kept; data is escaped, non-Latin glyphs (emoji) dropped
    t = "".join(ch for ch in str(t) if ord(ch) < 0x2000)
    return Paragraph(esc(t).replace("&lt;b&gt;", "<b>").replace("&lt;/b&gt;", "</b>"), st)


if "unifi" in (snap.get("extras_errors") or {}) or not uf:
    story.append(PB(f"UniFi collector failed: {(snap.get('extras_errors') or {}).get('unifi', 'no data')}", SM))
else:
    SECST = ParagraphStyle("secst", parent=SMB, textColor=PRI["Review"])
    def un(ip):
        return (NAMES.get(ip) or snap["inventory_ips"].get(ip) or "") if ip else ""
    def ipn(ip, n=""):
        n = n or un(ip)
        return f"{n} ({ip})" if n and ip else (ip or n or "-")
    st_ = uf.get("settings") or {}
    h_ = uf.get("health") or {}
    unprot = [n for n in st_.get("all_networks", []) if n not in st_.get("protected_networks", []) and not n.startswith("Internet")]
    story.append(PB(f"Source: UniFi gateway '{SITE.get('gateway_name')}' via unifi.ui.com (system log, admin audit, traffic flows). "
                   f"IDS/IPS mode <b>{st_.get('ips_mode', '?')}</b> ({'detect only - nothing is blocked' if st_.get('ips_mode') == 'ids' else 'blocking'}), "
                   f"{st_.get('categories', 0)} signature categories, covering {', '.join(st_.get('protected_networks', [])) or '?'}"
                   + (f"; <b>not inspected: {', '.join(unprot)}</b>" if unprot else "") +
                   f". Honeypot {'on at ' + ', '.join(st_.get('honeypots', [])) if st_.get('honeypot_enabled') else 'off'}. "
                   f"WAN {h_.get('isp', '?')} {h_.get('latency_ms', '?')} ms, {h_.get('drops', 0)} drops.", SM))
    ev = uf.get("events") or {}
    rows = [["Time (UTC)", "Sev", "Event", "Source", "Destination"]]
    for e in ev.get("threats", []):
        rows.append([e["time"][5:16].replace("T", " "), e.get("severity", ""), P(e["message"]),
                     P(ipn(e.get("src"), e.get("src_name"))), P(ipn(e.get("dst"), e.get("dst_name")))])
    if len(rows) > 1:
        story.append(Paragraph("<b>Intrusion detections (this window)</b>", SM))
        story.append(table(rows, [0.8 * inch, 0.45 * inch, 3.0 * inch, 1.5 * inch, 1.55 * inch]))
    else:
        t30 = uf.get("threats_30d") or []
        story.append(PB("<b>Intrusion detections:</b> none in this window. Last 30 days: " + (
            "; ".join(f"{x['time'][:10]} {ipn(x['src'])} -> {ipn(x['dst'])}" for x in t30[:6]) if t30 else "none") + ".", SM))
    other = [e for e in ev.get("high_severity", []) if e.get("key") not in [t["key"] for t in ev.get("threats", [])]]
    other += [e for e in ev.get("wan", []) + ev.get("devices", []) if e not in other]
    if other:
        story.append(Spacer(1, 3))
        story.append(Paragraph("<b>Gateway, WAN and device events</b>", SM))
        story.append(table([["Time (UTC)", "Sev", "Event"]] + [[e["time"][5:16].replace("T", " "), e.get("severity", ""), P(e["message"])]
                                                                for e in other[:15]], [0.8 * inch, 0.7 * inch, 5.8 * inch]))
    adm = uf.get("admin") or {}
    lg = adm.get("logins", [])
    story.append(Spacer(1, 3))
    story.append(PB(f"<b>Admin logins:</b> {len(lg)} - " + (", ".join(f"{k} x{v}" for k, v in (adm.get('login_sources') or {}).items()) or "none")
                   + ("; <b>UNEXPECTED SOURCES: " + ", ".join(f"{l['time'][5:16]} {l['ip']}" for l in lg if l.get('unexpected_source')) + "</b>"
                      if any(l.get("unexpected_source") for l in lg) else "") + ".", SM))
    ch = adm.get("changes", [])
    if ch:
        rows = [["Time (UTC)", "Admin / from", "Section", "Object", "Fields changed"]]
        ex = []
        for i, c in enumerate(ch[:20], 1):
            rows.append([c["time"][5:16].replace("T", " "), P(f"{c.get('admin') or '?'} / {ipn(c.get('ip'), c.get('ip_name'))}"),
                         P(c.get("section") or "", SECST if (c.get("security_relevant") or c.get("unexpected_source")) else SM),
                         P(f"{c.get('object') or ''} ({c.get('operation') or ''})"), P(", ".join(c.get("fields") or [])[:120])])
        story.append(table(rows, [0.8 * inch, 1.6 * inch, 1.25 * inch, 1.5 * inch, 2.15 * inch], extra=ex))
        story.append(PB("Orange section = security-relevant change (firewall, port forward, admin, networks, VPN, Wi-Fi, IPS, system).", SM))
    else:
        story.append(PB("<b>Configuration changes:</b> none.", SM))
    fl = uf.get("flows") or {}
    story.append(Spacer(1, 3))
    story.append(PB(f"<b>Traffic flows:</b> {fl.get('total', 0):,} logged" + (" (truncated)" if fl.get("truncated") else "") + " - "
                   + ", ".join(f"{k} {v:,}" for k, v in (fl.get("actions") or {}).items()) + "; risk " +
                   ", ".join(f"{k} {v:,}" for k, v in (fl.get("risk") or {}).items()) + "; blocked by policy: " +
                   (", ".join(f"{k} {v:,}" for k, v in (fl.get("blocked_by_policy") or {}).items()) or "none") + ".", SM))
    rows = [["Client", "Blocked", "Top blocked domains"]]
    for c in fl.get("top_blocked_clients", [])[:8]:
        rows.append([PB(c["client"] or "?"), f"{c['count']:,}", P(", ".join(f"{d} ({n})" for d, n in c["top_domains"]))])
    if len(rows) > 1:
        story.append(table(rows, [1.6 * inch, 0.6 * inch, 5.1 * inch], extra=[("FONTSIZE", (0, 0), (-1, -1), 6.8)]))
    rb = fl.get("region_blocks") or []
    if rb:
        agg = defaultdict(lambda: [0, set(), set()])
        for r in rb:
            k = (r["client"], r["direction"])
            agg[k][0] += r["count"]; agg[k][1].add(r["region"]); agg[k][2].add(r["dst"])
        story.append(PB("<b>Region blocking</b> (connections to/from blocked countries): " + "; ".join(
            (f"{c} outgoing x{v[0]} to {', '.join(sorted(v[1]))} ({len(v[2])} IPs)" if d != "incoming"
             else f"inbound from {c} ({', '.join(sorted(v[1]))}) x{v[0]}") for (c, d), v in sorted(agg.items(), key=lambda x: -x[1][0])[:8]) + ".", SM))
    rk = fl.get("risky") or []
    if rk:
        story.append(table([["Src", "Dst", "Port/service", "Risk", "Action", "Policies"]] + [
            [P(ipn(r.get("src"), r.get("src_name"))), P(ipn(r.get("dst"), r.get("dst_name")) + (" " + ", ".join(r.get("domains") or []) if r.get("domains") else "")),
             f"{r.get('port')}/{r.get('service')}", r.get("risk"), r.get("action"), P(", ".join(r.get("policies") or []))] for r in rk[:15]],
            [1.5 * inch, 2.2 * inch, 0.9 * inch, 0.6 * inch, 0.6 * inch, 1.5 * inch]))
    cl_ = uf.get("clients") or {}
    notes = []
    if cl_.get("ip_conflicts"):
        notes.append("IP conflicts: " + "; ".join(f"{ip} = {', '.join(m)}" for ip, m in cl_["ip_conflicts"].items()))
    if cl_.get("not_in_inventory"):
        notes.append("Online clients not in the device inventory: " + ", ".join(f"{c['name'] or '?'} {c['mac']} ({c.get('ip')}, {c.get('network')})" for c in cl_["not_in_inventory"]))
    if cl_.get("first_seen_in_window"):
        notes.append("First seen by UniFi in this window: " + ", ".join(f"{c['name'] or '?'} {c['mac']} ({c.get('ip')})" for c in cl_["first_seen_in_window"]))
    story.append(PB(f"<b>Clients:</b> {cl_.get('online', '?')} online ({', '.join(f'{k} {v}' for k, v in (cl_.get('by_network') or {}).items())}), "
                   f"{cl_.get('known_total', '?')} known. " + (" ".join(notes) if notes else "No IP conflicts or unknown clients."), SM))

# ---------- 2c. Host-based telemetry (Elastic Agent / Fleet / Defend) ----------
hs = snap.get("hosts") or {}
story.append(H("Host-based anomalies (Elastic Agent / Defend / osquery)", "c"))


def HP(t, st=SM):  # escaped text, <b> kept, non-Latin glyphs dropped
    t = "".join(ch for ch in str(t) if ord(ch) < 0x2000)
    return Paragraph(esc(t).replace("&lt;b&gt;", "<b>").replace("&lt;/b&gt;", "</b>"), st)


if "hosts" in (snap.get("extras_errors") or {}) or not hs:
    story.append(HP(f"Host collector failed: {(snap.get('extras_errors') or {}).get('hosts', 'no data')}", SM))
else:
    fl_ = [a for a in hs.get("fleet") or [] if not a["host"].startswith("FleetServer-")]
    pol_ = {p["host"].lower(): p for p in hs.get("defend") or []}
    story.append(HP(f"Sources: Fleet agent registry, Elastic Defend endpoint events/alerts, system auth + syslog. "
                    f"Host baseline seeded {hs.get('baseline_seeded') or 'today (first run - new-item rules start tomorrow)'}. "
                    f"Defend alerts in window: <b>{len(hs.get('endpoint_alerts') or [])}</b>.", SM))
    rows = [["Host", "Agent", "Last check-in", "Defend protection", "Telemetry (window)"]]
    tel = hs.get("telemetry") or {}
    for a in fl_:
        p = pol_.get(a["host"].lower())
        prot = "n/a (no Defend)" if not p else ("OK" if p["status"] == "success" else f"FAILING: {', '.join(p['failed_protections'])}")
        t_ = tel.get(a["host"].lower(), {})
        rows.append([HP(a["host"]), HP(f"{a['status']} v{a['version']}" + (f" ({a['unhealthy_reason']})" if a.get("unhealthy_reason") else "")),
                     (a.get("last_checkin") or "")[5:16].replace("T", " "),
                     HP(prot, ParagraphStyle("hpw", parent=SM, textColor=PRI["Review"]) if p and p["status"] != "success" else SM),
                     HP(", ".join(f"{k.split('.')[-1]} {v['count']:,}" for k, v in t_.items()) or "none")])
    story.append(table(rows, [1.5 * inch, 1.3 * inch, 0.85 * inch, 1.9 * inch, 1.75 * inch]))
    F_ = hs.get("findings") or []
    story.append(Spacer(1, 3))
    if F_:
        F_ = sorted(F_, key=lambda f: bool(f.get("investigated")))  # open first
        rows = [["", "Priority", "Finding"]]
        DONE = ParagraphStyle("hpd", parent=SM, textColor=colors.grey)
        for f in F_[:30]:
            iv = f.get("investigated")
            rows.append(["[x]" if iv else "[ ]",
                         HP(f["priority"], DONE if iv else ParagraphStyle("hpp", parent=SMB, textColor=PRI.get(f["priority"], colors.black))),
                         HP(f["text"] + (f" -- investigated {iv.get('at', '')}" + (f": {iv['note']}" if iv.get("note") else "") if iv else ""),
                            DONE if iv else SM)])
        story.append(table(rows, [0.35 * inch, 0.8 * inch, 6.15 * inch]))
        n_open = sum(1 for f in F_ if not f.get("investigated"))
        story.append(HP(f"<b>{n_open} open</b>, {len(F_) - n_open} checked off as investigated. Check items off in the Hermes desktop "
                        f"host-findings checklist (or: netmon/hosts_ack.py ack <key> [note]).", SM))
    else:
        story.append(HP("<b>Host findings:</b> none.", SM))
    # osquery posture (pack netmon-host-posture)
    oq_ = hs.get("osquery") or {}
    pos_ = hs.get("posture") or {}
    story.append(Spacer(1, 3))
    if isinstance(oq_, dict) and oq_.get("error"):
        story.append(HP(f"<b>Host posture (osquery):</b> query failed: {oq_['error'][:200]}", SM))
    elif not pos_:
        story.append(HP("<b>Host posture (osquery):</b> no results yet - pack 'netmon-host-posture' (~/.hermes/netmon/osquery_pack.json) "
                        "is not deployed to the agent policies, or has not run in the last 26 h.", SM))
    else:
        cov = oq_.get("coverage") or {}
        story.append(HP("<b>Host posture (osquery):</b> current weaknesses per host (bad = fix, warn = weak/default). "
                        "Reporting: " + ", ".join(f"{h.split('.')[0]} ({len(v)} checks)" for h, v in sorted(cov.items())) +
                        ". New items and changes vs. yesterday appear in the findings above.", SM))
        rows = [["Host", "Status", "Item", "Value / note"]]
        for h in sorted(pos_):
            for p in sorted(pos_[h], key=lambda p: (p["status"] != "bad", p["item"])):
                if p["status"] == "ok":
                    continue
                rows.append([HP(h.split(".")[0]), HP(p["status"].upper(), ParagraphStyle("hps", parent=SMB, textColor=PRI["Investigate"] if p["status"] == "bad" else PRI["Review"])),
                             HP(p["item"]), HP(p["value"] + (f" - {p['note']}" if p.get("note") else ""))])
        if len(rows) > 1:
            story.append(table(rows[:45], [1.0 * inch, 0.55 * inch, 2.2 * inch, 3.55 * inch]))
        else:
            story.append(HP("No weaknesses found by the posture checks.", SM))
        exp_ = [(h, p) for h in sorted(pos_) for p in pos_[h] if p["item"].startswith("listener ") and p["status"] == "ok"]
        if exp_:
            story.append(HP("<b>Other LAN-reachable listeners:</b> " + "; ".join(f"{h.split('.')[0]} {p['item'][9:]}" for h, p in exp_[:30]), SM))
    au_ = hs.get("auth") or {}
    if isinstance(au_, dict) and "logins" in au_:
        rows = [["Host", "User", "From", "Via", "Result", "Count"]]
        for l in au_["logins"][:14]:
            lbl = l.get("src_label") or ("UNEXPECTED" if l["src"] != "local" else "local")
            rows.append([HP(l["host"]), HP(l["user"]), HP(f"{lbl} ({l['src']})"), HP(l["via"]), HP(l["outcome"]), str(l["count"])])
        story.append(Spacer(1, 3))
        story.append(HP("<b>Interactive logins (SSH / Cockpit):</b>", SM))
        story.append(table(rows, [1.4 * inch, 0.8 * inch, 1.9 * inch, 1.1 * inch, 0.8 * inch, 0.6 * inch]))
        if au_.get("sudo"):
            story.append(HP("<b>sudo:</b> " + "; ".join(f"{s['host'].split('.')[0]} {s['user']}: {s['command'][:70]} x{s['count']}" for s in au_["sudo"][:12]), SM))
        if au_.get("account_changes"):
            story.append(HP(f"<b>Account changes:</b> {len(au_['account_changes'])} (" + "; ".join(
                f"{c['host'].split('.')[0]} {c['message'][:60]}" for c in au_["account_changes"][:6]) + ")", SM))

# ---------- 2d. MITRE ATT&CK mapping ----------
story.append(Paragraph("2d. MITRE ATT&amp;CK mapping", H2))
try:
    import mitre as _mitre
    try:
        import store as _store
        _acks = _store.acks_load()
    except Exception:
        _acks = {}
    MM = _mitre.map_all(snap, ana, tri, None, _acks)
    sm_ = MM["summary"]
    story.append(HP(f"ATT&CK Enterprise v{MM['version']}. <b>{sm_['techniques']} techniques</b> touched: <b>{sm_['observed']} observed</b> "
                    f"(behaviour seen - possible technique in use) and {sm_['exposure_only']} exposure-only (a weakness that enables it, "
                    f"nothing seen). {sm_['items']} items mapped, {sm_['unmapped']} unmapped. Suricata/detection mappings come from the rules' own "
                    f"ATT&CK metadata; netmon findings use the curated rules in netmon/mitre.py. Interactive matrix: dashboard > ATT&CK.", SM))
    rows = [["Tactic", "Observed techniques (open items)", "Exposure only"]]
    T_ = MM["techniques"]
    for _tshort in MM["tactic_order"]:
        tc = MM["tactics"][_tshort]
        if not tc["techniques"]:
            continue
        obs = [f"<b>{k}</b> {T_[k]['name']} ({T_[k]['open']})" for k in tc["techniques"] if T_[k]["observed"]]
        exp = [f"{k} {T_[k]['name']}" for k in tc["techniques"] if not T_[k]["observed"]]
        rows.append([HP(f"<b>{tc['name']}</b> {tc['id'] or ''}"), HP("; ".join(obs) or "-"), HP("; ".join(exp) or "-")])
    story.append(table(rows, [1.3 * inch, 3.6 * inch, 2.4 * inch]))
    _rank = {"Investigate": 0, "high": 0, "HIGH": 0, "Review": 1, "medium": 1, "MEDIUM": 1}
    top = sorted([i for i in MM["items"] if i["relation"] == "observed" and not i["acked"]],
                 key=lambda i: (_rank.get(i["severity"], 2), -i["count"]))[:12]
    if top:
        rows = [["Technique", "Item", "Why"]]
        for i in top:
            rows.append([HP(", ".join(f"{t} {T_[t]['name']}" for t in i["techniques"])), HP(i["title"][:170]), HP(i["why"])])
        story.append(Spacer(1, 3))
        story.append(table(rows, [1.8 * inch, 3.6 * inch, 1.9 * inch]))
except Exception as _e:
    story.append(HP(f"ATT&CK mapping failed: {type(_e).__name__}: {_e}", SM))

# ---------- 3. Baseline deviations ----------
story.append(H("Anomalies vs. each device's normal behavior"))
if not ana.get("baseline_ready"):
    story.append(P(f"<b>Baseline status: day {ana.get('baseline_days',0)+1} of {ana.get('min_days',3)} collected.</b> "
                   "Today's per-device behavior (volume, peers, countries, ASNs, ports and services used and served, active hours, DNS/NXDOMAIN rates, "
                   "alert signatures) has been recorded as the starting baseline. Deviation alarms (volume/upload spikes, new countries or "
                   "networks, new ports/services/listening ports, service-mix shifts, odd hours, new or silent devices, new signatures) switch on once 3 days are banked; "
                   "the profile is a rolling 30-day window.".replace("<b>", "").replace("</b>", ""), B))
if ana.get("findings"):
    rows = [["Sev", "Device", "Type", "Detail"]] + [[f["severity"], P(f["name"]), f["kind"], det_cell(f)] for f in ana["findings"]]
    story.append(table(rows, [0.5 * inch, 1.6 * inch, 1.0 * inch, 4.2 * inch]))
elif ana.get("baseline_ready"):
    story.append(P("No device deviated from its baseline.", B))
if ana.get("unknown_devices"):
    story.append(P("Devices with traffic but no DHCP inventory entry: " + ", ".join(
        f"{NAMES.get(u['ip'], u['ip'])} [{u['ip']}] {fmt(u['total'])}" for u in ana["unknown_devices"]
        if "gateway" not in NAMES.get(u["ip"], "") and "Minecraft" not in NAMES.get(u["ip"], "")), SM))

# ---------- New devices ----------
story.append(H("New devices seen"))
nds = [n for n in ana.get("new_devices", []) if "gateway" not in NAMES.get(n["ip"], "")]
inv_missing = [n for n in nds if not n["known"]]
if ana.get("registry_seeded_now"):
    story.append(P("The device registry (SQLite store, devices table) was created on this run and now tracks first/last sighting of "
                   f"every device permanently. Security Onion only had conn history back to about "
                   f"{(ana.get('zeek_retention_start') or '')[:16].replace('T',' ')} UTC, so the 'first seen' times below are when each device "
                   "first appeared in that short history - most are intermittent devices (watches, Kindles, scale) waking up, not truly new. "
                   "The strong signal is the 'In DHCP inventory = No' rows. From the next run on, only devices never seen before are listed here "
                   "and raise an alarm.", SM))
if nds:
    rows = [["Device", "IP / MAC", "Vendor / hostname", "In DHCP", "First seen UTC", "Traffic", "Services used", "Ports used"]]
    ex = []
    for i, n in enumerate(sorted(nds, key=lambda n: (n["known"], -n["total"])), 1):
        rows.append([P(n["name"] or NAMES.get(n["ip"], "(unknown)")), P(f"{n['ip']} {n.get('mac') or ''}"),
                     P(" ".join(x for x in (n.get("oui"), n.get("hostname")) if x) or "-"),
                     "Yes" if n["known"] else "No", n["first_seen"][:16].replace("T", " "), fmt(n["total"]),
                     P(", ".join(s.replace("spicy_", "") for s in list(n["services"])[:4]) or "-"),
                     P(", ".join(port_label(k) for k in list(n["dports"])[:4]) or "-")])
        if not n["known"]:
            ex.append(("TEXTCOLOR", (3, i), (3, i), PRI["Investigate"]))
    story.append(table(rows, [1.1 * inch, 1.05 * inch, 0.85 * inch, 0.5 * inch, 0.9 * inch, 0.55 * inch, 1.05 * inch, 1.3 * inch],
                       extra=ex + [("FONTSIZE", (0, 0), (-1, -1), 6.8)]))
else:
    story.append(P("No device appeared for the first time in this window.", B))
if snap.get("unknown_dhcp"):
    story.append(P("DHCP leases for MACs not in the inventory: " + ", ".join(
        f"{u['ip']} {','.join(u['macs'])} {u['hostname']}" for u in snap["unknown_dhcp"]), SM))

# ---------- 5. Traffic volume ----------
story.append(H("Traffic volume by device"))
devs = sorted(((ip, d) for ip, d in snap["devices"].items() if SITE.is_internal(ip) and not ip.endswith(".255")),
              key=lambda x: -x[1].get("total_bytes", 0))
top = devs[:15][::-1]
dr = Drawing(7.3 * inch, 3.3 * inch)
ch = HorizontalBarChart()
ch.x, ch.y, ch.width, ch.height = 1.9 * inch, 0.2 * inch, 5.1 * inch, 3.0 * inch
ch.data = [[d.get("total_recv", 0) / 1e9 for _, d in top], [d.get("total_sent", 0) / 1e9 for _, d in top]]
ch.categoryAxis.categoryNames = [name_of(ip, d)[:28] for ip, d in top]
ch.categoryAxis.labels.fontSize = 6.5
ch.valueAxis.labels.fontSize = 6.5
ch.categoryAxis.style = "stacked"
ch.bars[0].fillColor, ch.bars[1].fillColor = colors.HexColor("#5dade2"), colors.HexColor("#e67e22")
dr.add(ch)
dr.add(String(4.5 * inch, 3.25 * inch, "Top 15 devices, GB (blue = received, orange = sent)", fontSize=7.5, textAnchor="middle"))
story.append(dr)

hrs = sorted(t["hourly"])
dr2 = Drawing(7.3 * inch, 1.9 * inch)
vc = VerticalBarChart()
vc.x, vc.y, vc.width, vc.height = 0.5 * inch, 0.3 * inch, 6.6 * inch, 1.4 * inch
vc.data = [[t["hourly"][h] / 1e9 for h in hrs], [t.get("hourly_missed", {}).get(h, 0) / 1e9 for h in hrs]]
vc.categoryAxis.categoryNames = [h[11:13] for h in hrs]
vc.categoryAxis.labels.fontSize = 6
vc.valueAxis.labels.fontSize = 6
vc.bars[0].fillColor, vc.bars[1].fillColor = NAVY, colors.HexColor("#e74c3c")
dr2.add(vc)
dr2.add(String(3.8 * inch, 1.78 * inch, "Whole network by UTC hour, GB (navy = recorded wire bytes, red = bytes the sensor missed)",
               fontSize=7.5, textAnchor="middle"))
story.append(dr2)

rows = [["Device", "IP", "Total", "Sent", "Received", "To Internet", "Conns", "Ext peers", "Peak hr UTC", "Top destinations (by bytes)"]]
for ip, d in devs[:15]:
    hb = d.get("hourly_bytes") or {}
    pk = max(hb, key=hb.get) if hb else "-"
    asn = ", ".join(short(a) for a in list((d.get("asns") or {}).keys())[:2])
    rows.append([P(name_of(ip, d)), ip, fmt(d.get("total_bytes")), fmt(d.get("total_sent")), fmt(d.get("total_recv")),
                 fmt(d.get("ext_out_bytes")), f"{d.get('orig_conns',0)+d.get('resp_conns',0):,}", d.get("ext_peers", 0),
                 f"{pk}h {fmt(hb.get(pk))}" if hb else "-", P(asn or "-")])
story.append(table(rows, [1.35 * inch, 0.72 * inch, 0.58 * inch, 0.58 * inch, 0.6 * inch, 0.6 * inch, 0.5 * inch, 0.42 * inch, 0.75 * inch, 1.3 * inch],
                   extra=[("FONTSIZE", (0, 0), (-1, -1), 6.8)]))
story.append(P(f"Top 15 of {len(devs)} devices; the full per-device table stays in the snapshot. " "Bytes = Zeek client/server ip_bytes (headers included), both directions, counted for every connection the device took part in "
               "(LAN-to-LAN traffic counts for both ends). Because of capture loss these are lower bounds.", SM))

notes = tri.get("device_notes", {})
if notes:
    story.append(Spacer(1, 4))
    story.append(table([["Device", "Note"]] + [[P(NAMES.get(ip) or snap['inventory_ips'].get(ip, ip)), P(n)] for ip, n in notes.items()],
                       [1.6 * inch, 5.7 * inch]))

# ---------- 8-13. Threat intel, beaconing, segmentation, IoT, files, TLS ----------
SEVC = {"high": PRI["Investigate"], "medium": PRI["Review"], "low": PRI["Info"]}


def findings_table(kinds, empty):
    fl = [f for f in ana.get("findings", []) if any(f["kind"].startswith(k) for k in kinds)]
    if not fl:
        if empty:
            story.append(P(empty, SM))
        return
    rows = [["Sev", "Device", "Type", "Detail"]]
    ex = []
    for i, f in enumerate(fl, 1):
        rows.append([f["severity"], P(f["name"]), P(f["kind"]), det_cell(f)])
        ex.append(("TEXTCOLOR", (0, i), (0, i), SEVC.get(f["severity"], colors.black)))
    story.append(table(rows, [0.5 * inch, 1.4 * inch, 1.1 * inch, 4.3 * inch], extra=ex))


def dname(ip):
    return name_of(ip, snap["devices"].get(ip, {})) if ip in snap["devices"] else NAMES.get(ip, ip)



# ---------- 6. Port & service habits ----------
ps_dev = {f["device"] for f in ana.get("findings", []) if f["kind"] in ("new-port", "new-service", "new-listening-port", "service-mix", "port-spike")}
ps_devs = [(ip, d) for ip, d in devs if ip in ps_dev or d.get("mac") in ps_dev or any(f["name"] == name_of(ip, d) for f in ana.get("findings", []) if f["kind"] in ("new-port", "new-service", "new-listening-port", "service-mix", "port-spike"))]
if ps_devs:
  story.append(H("Port and service habits (devices with a port/service change)"))
  story.append(P("What these devices normally talk over (full per-device data stays in the snapshot). 'Services' is Zeek's protocol identification of the device's outbound "
               "connections (share of connections); 'Ports used' are destination ports it connects to; 'Ports it serves' are ports on the "
               "device that answered other hosts (Internet sources flagged). These are recorded in the baseline: a device using a port or "
               "service it has never used, answering on a new port, a big shift in its service mix, or a sudden surge on one port "
               "raises an anomaly.", SM))
  rows = [["Device", "Services (outbound, % of conns)", "Top ports used (conns)", "Ports it serves (conns / sources)"]]
  for ip, d in ps_devs:
      so = d.get("services_out") or {}
      tot = sum(v["conns"] for v in so.values()) or 1
      svc = ", ".join(f"{k.replace('spicy_', '')} {100*v['conns']/tot:.0f}%" for k, v in list(so.items())[:6] if 100 * v["conns"] / tot >= 1)
      dp = ", ".join(f"{port_label(k, v.get('service',''))} ({v['conns']:,})" for k, v in list((d.get("dports_out") or {}).items())[:6])
      sv = ", ".join(f"{port_label(k, v.get('service',''))} ({v['conns']:,}/{v['sources']}" + (f", {v['ext_conns']} from Internet" if v.get("ext_conns") else "") + ")"
                     for k, v in list((d.get("served_ports") or {}).items())[:5])
      rows.append([P(name_of(ip, d)), P(svc or "-"), P(dp or "-"), P(sv or "-")])
  story.append(table(rows, [1.4 * inch, 1.75 * inch, 2.45 * inch, 1.75 * inch], extra=[("FONTSIZE", (0, 0), (-1, -1), 6.6)]))

  findings_table(['new-port', 'new-service', 'new-listening-port', 'service-mix', 'port-spike'], "")

# ---------- 7. DNS behavior ----------
story.append(H("DNS behavior"))
dd = [(ip, d, d.get("dns") or {}) for ip, d in devs]
tq = sum(x.get("queries", 0) for _, _, x in dd)
tnx = sum(x.get("nxdomain", 0) for _, _, x in dd)
tmd = sum(x.get("mdns") or 0 for _, _, x in dd)
qt_all = {}
for _, _, x in dd:
    for k, v in (x.get("qtypes") or {}).items():
        qt_all[k] = qt_all.get(k, 0) + v
story.append(P(f"{tq:,} unicast DNS queries (port 53) from {sum(1 for *_, x in dd if x.get('queries'))} devices; "
               f"{tnx:,} NXDOMAIN ({100*tnx/max(tq,1):.1f}%). Plus {tmd:,} multicast mDNS (.local) queries, profiled separately. "
               "Record types network-wide: " + ", ".join(f"{k} {v:,}" for k, v in sorted(qt_all.items(), key=lambda x: -x[1])[:8]) + ".", SM))

# 7b tunnelling
story.append(Spacer(1, 4))
story.append(Paragraph("<b>DNS tunnelling check</b> - registered domains with the most distinct subdomains", SM))
story.append(P("Tunnels (iodine, dnscat2, DNS-based C2/exfil) encode data in subdomains, so they show thousands of one-off, long, "
               "high-entropy subdomains under one domain, often TXT/NULL/CNAME records, from one or two hosts. Score adds a point for each "
               "trait (>=150/500 distinct subdomains, avg length >=25/40, entropy >=3.5/4.0, mostly-unique sample, a label >=45 chars, "
               ">=30% TXT/NULL/CNAME/MX/ANY, <=2 source hosts). Suspect = score >=5 with >=150 subdomains; Watch = score >=3, >=50 subdomains, "
               "mostly unique. Reverse-DNS (arpa) and .local are excluded. Subs = distinct subdomains; Uniq = unique share of a random 200-query sample.", SM))
tun = ana.get("dns_tunnel") or snap.get("dns_tunnel") or []
lvl_color = {"suspect": PRI["Investigate"], "watch": PRI["Review"], "explosion": PRI["Review"]}
rows = [["Domain", "Queries", "Subs", "Avg len", "Entropy", "Uniq", "Rec types", "Sources", "Score", "Verdict"]]
ex = []
flag_tun = [c for c in tun if c.get("level")]
for i, c in enumerate(flag_tun[:15], 1):
    lv = c.get("level")
    rows.append([P(c["domain"]), f"{c['queries']:,}", f"{c['unique_subdomains']:,}", c["avg_sub_len"], c["entropy"],
                 c["sample_unique_ratio"], P(" ".join(list(c["qtypes"])[:3])),
                 P(", ".join(name_of(s, snap["devices"].get(s, {}))[:16] for s in list(c["sources"])[:2])), c["score"],
                 lv.upper() if lv else ("known-benign" if c.get("benign") else "normal")])
    if lv:
        ex.append(("TEXTCOLOR", (9, i), (9, i), lvl_color[lv]))
if flag_tun:
    story.append(table(rows, [1.15 * inch, 0.55 * inch, 0.6 * inch, 0.45 * inch, 0.5 * inch, 0.5 * inch, 0.85 * inch, 1.4 * inch, 0.4 * inch, 0.9 * inch],
                       extra=ex + [("FONTSIZE", (0, 0), (-1, -1), 6.8)]))
susp = [c for c in tun if c.get("level")]
story.append(P(("<b>Result:</b> " + ("; ".join(f"{c['domain']} = {c['level']}" for c in susp)) if susp else
                "Result: no domain shows tunnelling traits. The highest subdomain counts are CDNs and cloud services whose subdomains "
                "repeat (low unique ratio) - normal.").replace("<b>", "").replace("</b>", ""), SM))

# 7d DNS anomalies
dnsf = [f for f in ana.get("findings", []) if f["kind"].startswith("dns")]
story.append(Paragraph("<b>DNS anomalies vs baseline</b>", SM))
if dnsf:
    story.append(table([["Sev", "Device", "Type", "Detail"]] + [[f["severity"], P(f["name"]), f["kind"], det_cell(f)] for f in dnsf],
                       [0.5 * inch, 1.5 * inch, 1.2 * inch, 4.1 * inch]))
elif not ana.get("baseline_ready"):
    story.append(P("Baseline is still being built (needs 3 days). From then on each device is compared on: query volume, distinct names "
                   "(DGA-like exploration), long names, NXDOMAIN rate, new record types (TXT/NULL/ANY weighted higher), shifts in record-type mix, "
                   "new TLDs, a new domain becoming a top destination, new resolvers (external = high), and new DNS-over-HTTPS use. "
                   "Tunnel heuristics above already run every day; per-domain subdomain counts are also baselined to catch sudden explosions.", SM))
else:
    story.append(P("No device's DNS behavior deviated from its baseline.", SM))

errs = snap.get("extras_errors") or {}

# 8. Threat intelligence
story.append(H("Threat-intelligence matches"))
ti = snap.get("threat_intel") or {}
if "threat_intel" in errs:
    story.append(P(f"Collector failed: {errs['threat_intel']}", SM))
fs_ = ti.get("feed_sizes", {})
rd = ti.get("rdap", {})
story.append(P(f"Every DNS name and TLS server name looked up by a LAN device, every outbound destination IP and every inbound session "
               f"that got answered were checked against {fs_.get('domains',0):,} malicious domains (abuse.ch URLhaus, ThreatFox), "
               f"{fs_.get('ips',0):,} IPs (Feodo C2, SSLBL, ET compromised, CINS) and {fs_.get('cidrs',0):,} hijacked networks (Spamhaus DROP). "
               f"Domain age: {rd.get('known_age',0)} of {rd.get('domains',0)} registered domains have a registration date from the registry's RDAP "
               "service (cached); domains younger than 30 days raise an alarm, under 90 days are listed. CINS/ET are scanner lists, so hits only "
               "matter when we answered or initiated.", SM))
rows = [["Check", "Result"]]
rows.append(["Malicious domains looked up", P("; ".join(f"{h['name']} ({', '.join(h['feeds'])}) by {', '.join(dname(s) for s in h['sources'])}"
                                                    for h in ti.get("domain_hits", [])[:8]) or "none")])
rows.append(["Outbound to listed IPs", P("; ".join(f"{h['ip']} {h['asn']} ({', '.join(h['feeds'])}) from {', '.join(dname(s) for s in h['sources'])}, "
                                               f"{h['established']} answered" for h in ti.get("ip_hits_out", [])[:8]) or "none")])
inb = defaultdict(list)
for h in ti.get("ip_hits_in", []):
    for t_ in h["targets"]:
        inb[t_].append(h)
rows.append(["Answered inbound from listed IPs", P("; ".join(f"{dname(t_)}: {len(v)} IPs ({', '.join(sorted({f for h in v for f in h['feeds']}))}) on "
                                                           f"{sorted({p for h in v for p in h['ports']})}" for t_, v in inb.items()) or "none")])
rows.append(["Newly registered domains (<90 d)", P("; ".join(f"{n['domain']} ({n['age_days']} d) by {', '.join(dname(s) for s in n['sources'])}"
                                                           for n in ti.get("new_domains", [])[:10]) or "none")])
story.append(table(rows, [1.9 * inch, 5.4 * inch]))
findings_table(["ti-", "newly-registered"], "No threat-intelligence findings.")

# 9. Beaconing
story.append(H("Beaconing (regular check-ins / C2 detection)"))
bc = snap.get("beacons") or {}
story.append(P(f"{bc.get('pairs_scored',0)} device-to-Internet connection pairs with >= 36 connections were scored on timing regularity "
               "(interval skew and jitter), payload-size regularity and how many hours of the day they cover (RITA method). Score >= 0.75 "
               "over >= 40% of the day is a beacon. Most beacons are legitimate (NTP, push services, camera clouds); alarms fire for beacons to "
               "threat-listed or newly registered destinations, raw IPs, unusual ports, and - once the baseline exists - any beacon a device "
               "never had before. Expected check-in domains are listed in known_benign.json.", SM))
cands = bc.get("candidates", [])
bdom = set(kb.get("beacon_domains", []))
rows = [["Device", "Destination", "Network", "Port", "Every", "Jitter", "Conns", "Hours", "Score", "Status"]]
rev = [c for c in cands if not (c.get("domain") in bdom or c["port"] == 123)]
story.append(P(f"{len(cands) - len(rev)} expected check-ins (NTP, known vendor clouds) are omitted.", SM))
for c in rev[:22]:
    st = "review"
    rows.append([P(dname(c["src"])), P(c.get("name") or c["dst"]), P(short(c.get("asn") or "") + (f" {c.get('country')}" if c.get("country") else "")),
                 c["port"], f"{c['interval_s']}s", f"{c['jitter_s']}s", c["conns"], c["coverage_h"], c["score"], st])
if rev:
    story.append(table(rows, [1.2 * inch, 1.65 * inch, 1.15 * inch, 0.4 * inch, 0.5 * inch, 0.45 * inch, 0.45 * inch, 0.4 * inch, 0.45 * inch, 0.6 * inch],
                       extra=[("FONTSIZE", (0, 0), (-1, -1), 6.6)]))
findings_table(["beacon"], "No suspicious beacons.")

# 10. Internal traffic & segmentation
story.append(H("Internal traffic and segmentation"))
it = snap.get("internal") or {}
story.append(P("Traffic between internal hosts, grouped by network zone (policy.json). Flags: anything initiated from the DMZ into the house, "
               "IoT/cameras reaching servers, k8s or the monitoring host, admin/lateral-movement ports (SSH, SMB, RDP, WinRM, VNC, databases, Docker/K8s APIs) "
               "between hosts unless allow-listed, and internal scanning (one host failing to reach >= 20 hosts or >= 40 ports). "
               "Edit policy.json 'allow' to bless legitimate flows.", SM))
story.append(P("Internal scanning: " + ("; ".join(f"{dname(s['src'])} failed {s['failed_conns']} conns to {s['hosts']} hosts / {s['ports']} ports"
                                                    for s in it.get("scans", [])) or "none detected."), SM))
findings_table(["segmentation", "internal-scan", "new-internal-peer"], "No segmentation violations.")

# 11. IoT allowlists (only when broken)
iot = snap.get("iot_dest") or {}
if any(f["kind"].startswith("iot-") for f in ana.get("findings", [])):
    story.append(H("IoT destination allowlist breaks"))
    story.append(P(f"{len(iot)} IoT, camera, media and game devices have a learned destination allowlist (kept in the baseline). "
                   "These went somewhere new:", SM))
    findings_table(["iot-"], "")

# 12. Files & software
story.append(H("Downloaded files and software findings"))
fsw = snap.get("files") or {}
files = fsw.get("files", [])
story.append(P(f"Executables, installers, scripts and archives Zeek saw in clear-text transfers ({len(files)} unique; HTTPS downloads are not "
               "visible). Hashes are checked against the Team Cymru Malware Hash Registry (detection % across AV engines; 0 = not known-bad). "
               "Executables reaching IoT/media devices are always an alarm.", SM))
rows = [["Receiver", "Type", "Size", "From", "MHR"]]
risky = [f for f in files if f.get("exec") or (f.get("mhr_detect_pct") or 0) > 0]
story.append(P(f"{len(files) - len(risky)} non-executable files with no malware-hash match are omitted.", SM))
for f in sorted(risky, key=lambda f: (not f["exec"], -(f.get("size") or 0)))[:18]:
    mh = f.get("mhr_detect_pct")
    rows.append([P(dname(f["receiver"])), P((f["mime"] or "").replace("application/", "")), fmt(f.get("size")),
                 P((f.get("host") or f["sender"]) + (f.get("uri") or "")[:60]), "-" if mh is None else f"{mh}%"])
if risky:
    story.append(table(rows, [1.3 * inch, 1.4 * inch, 0.6 * inch, 3.5 * inch, 0.5 * inch], extra=[("FONTSIZE", (0, 0), (-1, -1), 6.6)]))
sw_rows = [["Device", "Software seen on the wire"]]
by = defaultdict(list)
for s in fsw.get("software", []):
    by[s["ip"]].append(f"{s['name']} {s['version']}".strip())
for ip, l in sorted(by.items(), key=lambda x: dname(x[0])):
    sw_rows.append([P(dname(ip)), P(", ".join(sorted(set(l))))])
findings_table(["malware-hash", "iot-executable", "outdated-software", "new-software"], "No file or software findings.")

# 13. TLS
story.append(H("TLS fingerprints and certificates"))
tls = snap.get("tls") or {}
story.append(P(f"{tls.get('distinct_ja3',0):,} distinct TLS client fingerprints (JA3) were compared with abuse.ch SSLBL malware fingerprints. "
               "Each device's JA4 fingerprints are baselined - a new one on an IoT device means new software on it. Also listed: legacy TLS "
               "versions and servers presenting self-signed, untrusted or expired certificates.", SM))
rows = [["Device", "JA4s", "Legacy TLS", "Certificate problems (server: status x count)"]]
for ip, d in sorted((tls.get("devices") or {}).items(), key=lambda x: -len(x[1].get("bad_certs", []))):
    legacy = ", ".join(f"{k} x{v}" for k, v in d.get("versions", {}).items() if k in ("TLSv10", "TLSv11", "SSLv3"))
    bad = "; ".join(f"{b['sni'] or b['dst']}: {b['status'].replace('certificate', 'cert')} x{b['count']}" for b in d.get("bad_certs", [])[:3])
    if not legacy and not bad:
        continue
    rows.append([P(dname(ip)), len(d.get("ja4", {})), P(legacy or "-"), P(bad or "-")])
findings_table(["malicious-ja3", "legacy-tls", "expired-cert", "new-tls-client"], "No TLS findings.")

# ---------- 6. Data quality ----------
story.append(H("Data quality and method"))
cl = next((n["count"] for n in snap.get("notices", []) if n["note"].startswith("CaptureLoss")), 0)
story.append(P(f"Capture loss: {cl} Zeek CaptureLoss notices; {fmt(t['missed_bytes'])} of payload missed vs {fmt(t['ip_bytes'])} recorded. "
               f"Zeek 'network.bytes' is inflated by the loss ({fmt(t['network_bytes'])}), so this report uses ip_bytes throughout. "
               "Alert counts are exact (summed aggregations, not the 10,000-capped hit total). Device identity: DHCP inventory by MAC, "
               "with Zeek DHCP logs for dynamic leases; randomized Apple MACs can rotate. Queries were read-only. "
               "Between reports, an urgent watcher checks every 15 minutes for high-severity IDS alerts, new devices, new Internet-facing "
               "ports, threat-intel hits and DNS-tunnel bursts and raises them immediately as dashboard alerts / push notifications."
               + (f" Collector errors this run: {errs}." if errs else ""), SM))


# ---------- 16. Daily briefing: security, bicycling & local news ----------
story.append(PageBreak())
story.append(H("Daily briefing: security, bicycling & local news"))
story.append(P("Non-network daily digest (formerly the standalone 'Daily Security News' cron job, now folded into this report): "
               "high-impact computer security news from the last 24 hours (technical depth, real risk, no clickbait), "
               "bicycling news, and a Columbia, MD item.", SM))
items = brief.get("items") or []
if items:
    by_cat = defaultdict(list)
    for it in items:
        by_cat[it.get("category") or "News"].append(it)
    for cat, its in by_cat.items():
        story.append(Spacer(1, 4))
        story.append(Paragraph(f"<b>{esc(cat)}</b>", SM))
        for it in its:
            cell = [P(it.get("title", ""), SMB), P(it.get("summary", ""))]
            if it.get("url"):
                cell.append(Paragraph(A(it["url"], it["url"]), LNK))
            story.append(KeepTogether(cell))
            story.append(Spacer(1, 3))
else:
    story.append(P("No briefing data for this run (briefing.json missing or empty).", SM))

# ---------- Sources ----------
if SOURCES:
    import re as _re
    cited = sorted({int(x) for x in _re.findall(r"\[(\d+)\]", json.dumps(tri))})
    story.append(Paragraph("Sources", H2))
    story.append(P("Web sources consulted for context in this report (numbers match the [n] markers above). "
                   "Community forum posts are user reports, not authoritative statements.", SM))
    rows = [["#", "Source", "URL"]]
    for i in cited:
        s = SOURCES.get(i)
        if s:
            rows.append([str(i), P(s.get("title") or ""), Paragraph(A(s["url"], s["url"]), SM)])
    story.append(table(rows, [0.3 * inch, 2.6 * inch, 4.4 * inch], extra=[("FONTSIZE", (0, 0), (-1, -1), 6.6)]))


def footer(c, doc):
    c.saveState()
    c.setFont("Helvetica", 7)
    c.drawString(0.5 * inch, 0.35 * inch, f"Lady Brains netmon - {gen} UTC")
    c.drawRightString(8.0 * inch, 0.35 * inch, f"Page {doc.page}")
    c.restoreState()


OUT_DIR = os.environ.get("NETMON_OUT_DIR") or os.path.expanduser("~/network_reports")
os.makedirs(OUT_DIR, exist_ok=True)
out = f"{OUT_DIR}/network-report-{os.path.basename(stem)}.pdf"
SimpleDocTemplate(out, pagesize=letter, leftMargin=0.55 * inch, rightMargin=0.55 * inch, topMargin=0.5 * inch,
                  bottomMargin=0.55 * inch, title="Home Network Behavior Report", author="Lady Brains").build(
    story, onFirstPage=footer, onLaterPages=footer)
print(out)
if not os.environ.get("NETMON_OUT_DIR"):  # real nightly run (not a test render): announce it in the dashboard
    try:
        import store
        store.alerts_add([(f"report|{os.path.basename(out)}", f"Nightly network report ready: {os.path.basename(out)} - "
                           f"download it from the dashboard (Reports).", "info", [])], source="report")
    except Exception as e:
        print(f"(report-ready notification not queued: {e})", file=sys.stderr)
