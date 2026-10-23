#!/usr/bin/python3
"""Read-only netmon data tools for the dashboard chat (dashboard/app/chat.py imports TOOLS) - also usable as a
minimal MCP server over stdio (stdlib only) by any MCP-capable AI client: `python3 netmon_mcp.py`.

Exposes the latest snapshot/analysis, recent watcher alerts, notes and the device registry as query tools.
It opens SQLite with mode=ro and only ever reads files, so the assistant can look at netmon data but cannot change
anything.
"""
import json, os, re, sqlite3, sys

NM = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(NM, "data")
_STATE = os.environ.get("STATE_DIR") if os.path.isdir(os.environ.get("STATE_DIR") or "/nonexistent") else os.path.join(NM, "dashboard", "state")
DB = os.environ.get("NETMON_DB") or os.path.join(_STATE, "netmon.db")
KB = os.path.join(os.path.dirname(DB), "kb.db")  # notes knowledge base (dashboard/app/kb.py)
MAX = 12000  # characters per tool result


def _json(p, default=None):
    try:
        with open(p) as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def _doc(name, default=None):
    """A document from the docs table (snapshots / analysis), read-only."""
    import zlib
    try:
        with _db() as c:
            r = c.execute("SELECT doc FROM docs WHERE name=?", (name,)).fetchone()
        return json.loads(zlib.decompress(r[0])) if r else default
    except sqlite3.Error:
        return default


def _latest():
    try:
        with _db() as c:
            names = [r[0] for r in c.execute("SELECT name FROM docs WHERE name GLOB 'data/????-??-??T????Z' ORDER BY name")]
    except sqlite3.Error:
        names = []
    if not names:
        return None, {}, {}, {}
    n = names[-1]
    return n.split("/", 1)[1], _doc(n, {}), _doc(n + ".analysis", {}), {}


def _db():
    return sqlite3.connect(f"file:{DB}?mode=ro", uri=True, timeout=5)


def _cap(obj):
    s = obj if isinstance(obj, str) else json.dumps(obj, indent=1, default=str)
    return s if len(s) <= MAX else s[:MAX] + f"\n…[truncated {len(s) - MAX} chars - ask a narrower question]"


# ---------------------------------------------------------------- tools
def overview(_):
    stamp, s, a, t = _latest()
    if not stamp:
        return "No netmon snapshots yet."
    sev = {}
    for f in a.get("findings", []):
        sev[f.get("severity")] = sev.get(f.get("severity"), 0) + 1
    hf = (s.get("hosts") or {}).get("findings") or []
    return {"snapshot": stamp, "window_hours": s.get("hours"),
            "network_findings_by_severity": sev, "baseline_days": a.get("baseline_days"),
            "baseline_ready": a.get("baseline_ready"), "devices_seen": len(s.get("devices") or {}),
            "new_devices": a.get("new_devices"), "unknown_devices": a.get("unknown_devices"),
            "endpoint_findings": len(hf), "ids_alert_total": (s.get("alerts") or {}).get("total")}


def findings(args):
    _, _, a, _ = _latest()
    sev = (args.get("severity") or "").lower()
    q = (args.get("device") or "").lower()
    out = [f for f in a.get("findings", []) if (not sev or f.get("severity") == sev)
           and (not q or q in (str(f.get("device")) + " " + str(f.get("name"))).lower())]
    lim = max(1, min(int(args.get("limit") or 40), 150))
    return {"count": len(out), "findings": out[:lim]}


def device(args):
    q = (args.get("query") or "").strip().lower()
    if not q:
        return "Give an IP address, MAC address or (part of a) device name."
    stamp, s, a, t = _latest()
    reg = _registry_names()
    for host, ip in (_site().get("host_ips") or {}).items():
        reg.setdefault(ip, set()).add(host)
    hits = []
    for ip, d in (s.get("devices") or {}).items():
        names = " ".join([str(d.get(k) or "") for k in ("name", "hostname", "mac")] + sorted(reg.get(ip, ()))).lower()
        if q == ip or q in names or (len(q) > 6 and q in ip):
            hits.append(ip)
    if not hits:
        return f"No device matching '{q}' in snapshot {stamp}."
    res = []
    for ip in hits[:5]:
        d = s["devices"][ip]
        res.append({
            "ip": ip, "name": d.get("name"), "also_known_as": sorted(reg.get(ip, ())), "hostname": d.get("hostname"), "mac": d.get("mac"), "known": d.get("known"),
            "traffic_24h": {"sent": d.get("total_sent"), "received": d.get("total_recv"), "external_conns": d.get("ext_conns"),
                            "external_peers": d.get("ext_peers"), "countries": d.get("countries")},
            "top_destinations": _top(d.get("top_dst"), 10), "services_out": d.get("services_out"),
            "served_ports": d.get("served_ports"), "inbound_internet_sources": d.get("inbound_ext_sources"),
            "findings": [f for f in a.get("findings", []) if f.get("device") == ip][:25],
            "host_notes": _host_notes(["ip:" + ip] + (["mac:" + str(d.get("mac")).lower()] if d.get("mac") else [])
                                      + ["host:" + h.lower().split(".")[0] for h in reg.get(ip, ()) if h and ":" not in h]),
        })
    return {"snapshot": stamp, "matches": len(hits), "devices": res}


def _kb(sql, args=()):
    if not os.path.exists(KB):
        return []
    try:
        with sqlite3.connect(f"file:{KB}?mode=ro", uri=True, timeout=5) as c:
            return c.execute(sql, args).fetchall()
    except sqlite3.Error:
        return []


def _host_notes(subjects):
    subs = [s for s in dict.fromkeys(subjects) if s]
    if not subs:
        return []
    rows = _kb(f"select subject, category, text, author, model, updated from host_notes where coalesce(status,'')!='rejected' and subject in ({','.join('?' * len(subs))}) order by updated desc", subs)
    return [{"subject": r[0], "category": r[1], "text": r[2], "by": r[3] if r[3] != "ai" else f"AI ({r[4]})"} for r in rows]


def notes(args):
    """Host notes (what the AI and the owner know about devices) + the owner's notes on events."""
    q = (args.get("query") or "").strip().lower()
    hn = [{"subject": r[0], "device": r[1], "category": r[2], "text": r[3], "by": r[4] if r[4] != "ai" else f"AI ({r[5]})"}
          for r in _kb("select subject, label, category, text, author, model from host_notes where coalesce(status,'')!='rejected' order by subject, updated desc")]
    en = [{"event": r[0], "label": r[1], "by": r[2], "text": r[3]} for r in _kb("select eid, label, author, text from event_notes where status = 'approved' order by ts desc limit 300")]
    if q:
        hn = [n for n in hn if q in json.dumps(n).lower()]
        en = [n for n in en if q in json.dumps(n).lower()]
    return {"host_notes": hn[:150], "owner_event_notes": en[:100],
            "note": "owner_event_notes are written by the network owner and are authoritative context for those events."}


def _site():
    try:
        import zlib  # noqa: F401
        sys.path.insert(0, NM)
        import store
        return store.cfg_load("site")
    except Exception:  # noqa: BLE001
        return {}


def _registry_names():
    out = {}
    try:
        with _db() as c:
            for key, name, mac, doc in c.execute("select key, name, mac, doc from devices"):
                ips = set(re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", (key or "") + " " + (doc or "")))
                for ip in ips:
                    out.setdefault(ip, set()).update(x for x in (name, mac) if x)
    except sqlite3.Error:
        pass
    return out


def _top(v, n):
    if isinstance(v, dict):
        return dict(sorted(v.items(), key=lambda kv: -(kv[1] if isinstance(kv[1], (int, float)) else 0))[:n])
    return (v or [])[:n]


def devices(args):
    _, s, _, _ = _latest()
    q = (args.get("filter") or "").lower()
    rows = []
    for ip, d in (s.get("devices") or {}).items():
        row = {"ip": ip, "name": d.get("name"), "known": d.get("known"), "bytes_total": d.get("total_bytes"),
               "bytes_sent": d.get("total_sent"), "bytes_received": d.get("total_recv")}
        if not q or q in json.dumps(row).lower():
            rows.append(row)
    rows.sort(key=lambda r: -(r["bytes_total"] or 0))
    return {"count": len(rows), "devices": rows[:200]}


def endpoints(args):
    _, s, _, _ = _latest()
    h = s.get("hosts") or {}
    q = (args.get("host") or "").lower()
    out = [{k: f.get(k) for k in ("priority", "text", "investigated")} for f in h.get("findings") or []
           if not q or q in (f.get("text") or "").lower()]
    return {"endpoint_findings": out, "fleet_agents": h.get("fleet"), "defend_status": h.get("defend")}


def recent_alerts(args):
    lim = max(1, min(int(args.get("limit") or 30), 200))
    try:
        with _db() as c:
            rows = c.execute("select ts, severity, source, text from alerts order by id desc limit ?", (lim,)).fetchall()
    except sqlite3.Error as e:
        return f"alerts unavailable: {e}"
    import datetime as dt
    fmt = lambda ts: dt.datetime.fromtimestamp(float(ts), dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC") if isinstance(ts, (int, float)) else ts
    return [{"time": fmt(r[0]), "severity": r[1], "source": r[2], "text": r[3]} for r in rows]


def ids_alerts(args):
    _, s, _, _ = _latest()
    al = s.get("alerts") or {}
    q = (args.get("filter") or "").lower()
    sig = [x for x in al.get("signatures", []) if not q or q in json.dumps(x).lower()]
    return {"total": al.get("total"), "signatures": sig[:40]}


TOOLS = {
    "netmon_overview": (overview, "Latest nightly netmon status: finding counts, baseline status, device and endpoint counts. Start here.", {}),
    "netmon_findings": (findings, "Automated network findings from the latest analysis, optionally filtered.",
                        {"severity": {"type": "string", "description": "high, medium or low"},
                         "device": {"type": "string", "description": "IP or name substring"},
                         "limit": {"type": "integer", "description": "max rows (default 40)"}}),
    "netmon_device": (device, "Everything netmon knows about one device: traffic, destinations, services, findings.",
                      {"query": {"type": "string", "description": "IP, MAC or device name (substring ok)"}}),
    "netmon_devices": (devices, "List devices seen in the last snapshot (IP, name, known/unknown, traffic), biggest first.",
                       {"filter": {"type": "string", "description": "optional substring filter"}}),
    "netmon_endpoints": (endpoints, "Endpoint (Elastic Agent / osquery) host findings, Fleet agent and Elastic Defend status.",
                         {"host": {"type": "string", "description": "optional host name filter"}}),
    "netmon_recent_alerts": (recent_alerts, "Most recent urgent alerts raised by the 15-minute watcher (newest first).",
                             {"limit": {"type": "integer", "description": "max rows (default 30)"}}),
    "netmon_ids_alerts": (ids_alerts, "Suricata IDS alert signatures from the last 24h snapshot with counts and sources.",
                          {"filter": {"type": "string", "description": "optional signature/IP substring"}}),
    "netmon_notes": (notes, "Notes knowledge base: what the AI and the owner have recorded about each device/host (role, normal behaviour, decisions) "
                     "and the owner's notes on events. Check it before judging a device or event.",
                     {"query": {"type": "string", "description": "optional IP / MAC / host name / text filter"}}),
}


# ---------------------------------------------------------------- MCP stdio (JSON-RPC 2.0, newline-delimited)
def _send(msg):
    sys.stdout.write(json.dumps(msg) + "\n")
    sys.stdout.flush()


def _handle(req):
    m, rid = req.get("method"), req.get("id")
    if m == "initialize":
        return {"protocolVersion": (req.get("params") or {}).get("protocolVersion", "2024-11-05"),
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "netmon-readonly", "version": "1.0"}}
    if m == "ping":
        return {}
    if m == "tools/list":
        return {"tools": [{"name": n, "description": d, "annotations": {"readOnlyHint": True},
                           "inputSchema": {"type": "object", "properties": p}} for n, (_, d, p) in TOOLS.items()]}
    if m == "tools/call":
        p = req.get("params") or {}
        fn = TOOLS.get(p.get("name"), (None,))[0]
        if not fn:
            raise KeyError(f"unknown tool {p.get('name')}")
        try:
            text, err = _cap(fn(p.get("arguments") or {})), False
        except Exception as e:  # report tool errors to the model instead of crashing the server
            text, err = f"error: {e.__class__.__name__}: {e}", True
        return {"content": [{"type": "text", "text": text}], "isError": err}
    if rid is None:
        return None  # notification
    raise KeyError(f"method not found: {m}")


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except ValueError:
            continue
        try:
            res = _handle(req)
            if req.get("id") is not None:
                _send({"jsonrpc": "2.0", "id": req["id"], "result": res})
        except Exception as e:
            if req.get("id") is not None:
                _send({"jsonrpc": "2.0", "id": req["id"], "error": {"code": -32601, "message": str(e)}})


if __name__ == "__main__":
    main()
