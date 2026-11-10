#!/usr/bin/python3
"""Event times from Elasticsearch: when the activity behind an event actually happened, not when netmon saw it.

netmon records an event when a report / time range lists it (events.first_seen / last_seen, event_fires.seen) and keeps
the analysis window it came from (t0..t1). Neither is the time the thing happened. This job looks up the Security Onion
records behind each event inside that window and stores the first and last @timestamp:

  events.et0 / et1       first / last record time over every window the event appeared in (Open events, Posture)
  event_fires.et0 / et1  the same for one firing (the per-occurrence list in an Open events row)
  *.et_upto              the window end already looked up (re-run only when a later window extends the event);
                         set with et0 NULL when there is nothing to look up or no record matched

IDS signatures, admin sessions and gateway events already carry real record times (t0/t1), so they are copied, not
queried. Status-type findings (agent offline, silent device, Kubernetes inventory, vulnerabilities, code scans) have
no record behind them and stay empty.

One bounded min/max aggregation per event, on the default SO indices through integrations.py (esq.q).
Run by scheduler.py every 15 minutes (`evtime`); CLI: evtime.py [--budget SECONDS] [--dry EID ...]
"""
import json, os, re, sys, time
from datetime import datetime, timezone

NM = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, NM)
sys.path.append(os.path.join(NM, "dashboard", "app"))
import store  # noqa: E402

ZEEK, SURI = "logs-zeek-so", "logs-suricata.alerts-so"
PROC, NET, FILE = "logs-endpoint.events.process-*", "logs-endpoint.events.network-*", "logs-endpoint.events.file-*"
AUTH, SYSLOG = "logs-system.auth-*", "logs-system.syslog-*"
DIRECT = {"ids", "admin", "gw"}  # t0/t1 are already Elasticsearch / UniFi record times
ALERT_BACK = 3600  # an alert's records: the watcher window before it fired
_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOM = re.compile(r"\b((?:[a-z0-9-]+\.)+[a-z]{2,24})\b", re.I)
_PORT = re.compile(r"\b(\d{1,5})/(tcp|udp)\b|\bports? \[?(\d{1,5})")
_SPAN = re.compile(r"\((\d\d-\d\d \d\d:\d\d) to (\d\d-\d\d \d\d:\d\d)Z\)")


def term(f, v):
    return {"term": {f: v}}


def anyof(*qs):
    return {"bool": {"should": list(qs), "minimum_should_match": 1}}


def ds(d):
    return term("event.dataset", d)


def either(ip):
    return anyof(term("source.ip", ip), term("destination.ip", ip))


def host(h):
    hs = list(dict.fromkeys([h, h.lower()]))
    return anyof(*[term(f, x) for f in ("host.name", "host.hostname") for x in hs])


def dom(d):
    d = d.lower().strip(".")
    return anyof(term("dns.query.name", d), term("dns.highest_registered_domain", d))


def ports(text):
    out = []
    for m in _PORT.finditer(text or ""):
        n = int(m.group(1) or m.group(3))
        if 0 < n < 65536 and n not in out:
            out.append(n)
    return out


def ext_ips(text, own=()):
    return [i for i in dict.fromkeys(_IP.findall(text or "")) if i not in own and not i.startswith(("0.", "255."))]


def domains(text):
    return [d.lower() for d in dict.fromkeys(_DOM.findall(text or "")) if not _IP.fullmatch(d) and not re.fullmatch(r"[\d.]+", d)
            and not d.lower().endswith((".lan", ".local", ".localdomain"))]


def _finding(kind, ip, detail):
    """Alternatives (index, filters), most specific first, for a baseline finding of device `ip`."""
    P, X, D = ports(detail), ext_ips(detail, (ip,)), domains(detail)
    conn = [ds("zeek.conn")]
    if kind == "silent":
        return []
    if kind in ("signature-spike", "new-signature"):
        m = re.search(r"'([^']+)'", detail)
        if not m:
            return []
        base = [ds("suricata.alert"), term("rule.name", m.group(1))]
        src = [anyof(*[either(i) for i in X[:6]])] if X else []
        return [(SURI, base + src), (SURI, base)] if src else [(SURI, base)]
    if not ip:
        return [(ZEEK, conn + [either(X[0])])] if X else []
    src = term("source.ip", ip)
    if kind in ("port-spike", "new-port") and P:
        return [(ZEEK, conn + [src, term("destination.port", P[0])]), (ZEEK, conn + [src])]
    if kind == "new-listening-port" and P:
        return [(ZEEK, conn + [term("destination.ip", ip), term("destination.port", P[0])])]
    if kind in ("inbound-exposure", "ti-ip-in"):
        q = conn + [term("destination.ip", ip), term("connection.local.originator", False)]
        return ([(ZEEK, q + [term("destination.port", P[0])])] if P else []) + [(ZEEK, q)]
    if kind in ("legacy-tls", "new-tls-client", "malicious-ja3", "expired-cert"):
        ssl = [ds("zeek.ssl"), src]
        alt = []
        m = re.search(r"\b(TLSv1\d|SSLv\d)\b", detail)
        if m:
            alt.append((ZEEK, ssl + [term("ssl.version", m.group(1))]))
        m = re.search(r"\b([0-9a-f]{32})\b", detail)
        if m:
            alt.append((ZEEK, ssl + [term("hash.ja3", m.group(1))]))
        m = re.search(r"JA4 (\S+?)\)", detail)
        if m:
            alt.append((ZEEK, ssl + [term("hash.ja4", m.group(1))]))
        if D:
            alt.append((ZEEK, ssl + [term("ssl.server_name", D[0])]))
        return alt + [(ZEEK, ssl)]
    if kind in ("new-software", "outdated-software"):
        sw = [ds("zeek.software"), src]
        m = re.search(r"(?:wire: |^)([\w.+-]+)", detail)
        return ([(ZEEK, sw + [term("software.name", m.group(1))])] if m else []) + [(ZEEK, sw)]
    if kind == "new-device-dhcp":
        return [(ZEEK, [ds("zeek.dhcp"), anyof(term("dhcp.assigned_ip", ip), term("client.address", ip))]), (ZEEK, [either(ip)])]
    if kind == "new-device":
        return [(ZEEK, [either(ip)])]
    if kind.startswith("dns") or kind in ("nxdomain-spike", "ti-domain", "iot-new-domain", "newly-registered-domain"):
        dq = [ds("zeek.dns"), src]
        alt = []
        if kind == "dns-new-resolver" and X:
            return [(ZEEK, [src, term("destination.ip", X[0])])]
        if kind == "dns-doh" and D:
            return [(ZEEK, [src, anyof(term("ssl.server_name", D[0]), dom(D[0]))])]
        if D and kind not in ("dns-volume", "dns-unique-names", "dns-long-names"):
            alt.append((ZEEK, dq + [dom(D[0])]))
        if kind == "nxdomain-spike":
            alt.append((ZEEK, dq + [term("dns.response.code_name", "NXDOMAIN")]))
        if kind == "dns-long-names":
            alt.append((ZEEK, dq + [{"range": {"dns.query.length": {"gte": 60}}}]))
        m = re.search(r"querying (\w+) records|^(\w+) is \d+% of queries", detail)
        if m:
            alt.append((ZEEK, dq + [term("dns.query.type_name", m.group(1) or m.group(2))]))
        m = re.search(r"in \.(\w+), a TLD", detail)
        if m:
            alt.append((ZEEK, dq + [term("dns.top_level_domain", m.group(1))]))
        return alt + [(ZEEK, dq)]
    if kind.startswith("beacon"):
        alt = []
        if X:
            alt.append((ZEEK, conn + [src, term("destination.ip", X[0])] + ([term("destination.port", P[0])] if P else [])))
        if D:
            alt.append((ZEEK, [ds("zeek.ssl"), src, term("ssl.server_name", D[0])]))
            alt.append((ZEEK, [ds("zeek.dns"), src, dom(D[0])]))
        if P:
            alt.append((ZEEK, conn + [src, term("destination.port", P[0])]))
        return alt + [(ZEEK, conn + [src])]
    if kind == "new-asn":
        m = re.search(r"new network '([^']+)'", detail)
        return ([(ZEEK, conn + [src, term("destination.as.organization.name", m.group(1))])] if m else []) + [(ZEEK, conn + [src])]
    if kind == "new-country":
        m = re.search(r" to ([A-Z]{2}),", detail)
        return ([(ZEEK, conn + [src, term("destination.geo.country_iso_code", m.group(1))])] if m else []) + [(ZEEK, conn + [src])]
    if X:  # segmentation, new-internal-peer, iot-raw-ip, reputation hits: the flow to the IP in the text
        q = conn + [src, term("destination.ip", X[0])]
        return ([(ZEEK, q + [term("destination.port", P[0])])] if P else []) + [(ZEEK, q), (ZEEK, conn + [either(ip), either(X[0])])]
    if kind == "failed-conns":
        return [(ZEEK, conn + [src, {"terms": {"connection.state": ["S0", "REJ", "RSTO", "RSTOS0", "SH", "OTH"]}}]), (ZEEK, conn + [src])]
    return [(ZEEK, conn + [src])]


def _hostf(key, text=""):
    p = str(key).split("|")
    typ, h = p[0], (p[1] if len(p) > 1 else "")
    a2, a3 = (p[2] if len(p) > 2 else ""), (p[3] if len(p) > 3 else "")
    if not h or typ in ("agent-off", "agent-deg", "defend-pol", "silent") or typ.startswith("k8s"):
        return []
    H = host(h)
    if typ in ("proc", "exec-new", "exec-sha"):
        return [(PROC, [H, term("process.executable", a2)]), (PROC, [H, term("process.name", os.path.basename(a2))])] if a2 else []
    if typ in ("net-new", "hnet-proc", "hnet-ti", "hnet-interp"):
        alt = []
        X = ext_ips(a3)
        if a2 and X:
            alt.append((NET, [H, term("process.executable", a2), {"terms": {"destination.ip": X[:10]}}]))
        return alt + ([(NET, [H, term("process.executable", a2)])] if a2 else [])
    if typ in ("hnet-dns-ti", "hnet-dns-long"):
        d = a2 if typ == "hnet-dns-ti" else next((x for x in domains(text) if x.endswith(a3) and x != h.lower()), a3)  # key holds only the parent domain
        return [(NET, [H, anyof(term("dns.question.name", d), term("dns.question.registered_domain", d))])] + (
            [(ZEEK, [ds("zeek.dns"), dom(d)])] if typ == "hnet-dns-ti" else [])
    if typ == "hnet-in":  # hnet-in|host|proc:port|source
        port = a2.rsplit(":", 1)[-1]
        alt = []
        if a3 and port.isdigit():
            alt += [(NET, [H, term("source.ip", a3), term("destination.port", int(port))]),
                    (ZEEK, [ds("zeek.conn"), term("source.ip", a3), term("destination.port", int(port))])]
        return alt + ([(NET, [H, term("source.ip", a3)])] if a3 else [])
    if typ == "hnet-newlisten":
        port = a2.rsplit(":", 1)[-1]
        return [(NET, [H, term("destination.port", int(port))])] if port.isdigit() else []
    if typ == "file":
        return [(FILE, [H, term("file.path", a2)])] if a2 else []
    if typ in ("login-new", "login-src"):
        q = [H] + ([term("user.name", a2)] if a2 else [])
        return ([(AUTH, q + [term("source.ip", a3)])] if _IP.fullmatch(a3 or "") else []) + [(AUTH, q)]
    if typ == "authfail":
        return [(AUTH, [H, term("source.ip", a2), term("event.outcome", "failure")]), (AUTH, [H, term("source.ip", a2)])] if _IP.fullmatch(a2) else [(AUTH, [H, term("event.outcome", "failure")])]
    if typ in ("sudo-err", "sudo-susp"):
        return [(AUTH, [H, term("user.name", a2)])] if a2 else [(AUTH, [H])]
    if typ == "acct":
        m = re.search(r"user '([^']+)'", a2)
        return [(AUTH, [H, term("user.name", m.group(1))])] if m else []
    if typ == "exec-mhr":
        return [(PROC, [H, term("process.hash.sha256", a2)])]
    if typ == "defend":
        return [("logs-endpoint.alerts-*", [H])]
    return []


def span_of(text, year):
    """Host-finding text that names its own time span: '(10-17 18:49 to 10-17 18:53Z)'."""
    m = _SPAN.search(text or "")
    if not m:
        return None
    try:
        f = lambda s: datetime.strptime(f"{year}-{s}", "%Y-%m-%d %H:%M").replace(tzinfo=timezone.utc).timestamp()
        return f(m.group(1)), f(m.group(2)) + 59
    except ValueError:
        return None


def spec(eid, typ, item=None, doc=None, label=""):
    """-> list of (index, filters) alternatives (empty: nothing to look up)."""
    item, doc = item or {}, doc or {}
    p = str(eid).split("|")
    if typ == "finding" or p[0] == "f":
        ips = doc.get("host_ips") or []
        dev = p[2] if len(p) > 2 else ""
        ip = ips[0] if ips else (dev if _IP.fullmatch(dev) else "")
        return _finding(p[1] if len(p) > 1 else "", ip, "|".join(p[3:]) or item.get("detail", ""))
    if typ == "host" or p[0] == "hf":
        return _hostf("|".join(p[1:]), label)
    if typ == "ti":
        v = "|".join(p[2:])
        if p[1] == "in":
            return [(ZEEK, [ds("zeek.conn"), term("source.ip", v)]), (ZEEK, [either(v)])]
        if p[1] == "out":
            return [(ZEEK, [ds("zeek.conn"), term("destination.ip", v)]), (ZEEK, [either(v)])]
        if p[1] == "dom":
            return [(ZEEK, [ds("zeek.dns"), dom(v)]), (ZEEK, [term("ssl.server_name", v)])]
        return []
    if typ == "alert":
        k = str(item.get("key") or "").split("|")
        kt, txt = k[0], item.get("text") or label
        if kt == "host":
            return _hostf("|".join(k[1:]), txt)
        if kt == "inport" and len(k) >= 3 and k[2].isdigit():
            return [(ZEEK, [ds("zeek.conn"), term("destination.ip", k[1]), term("destination.port", int(k[2]))])]
        if kt == "newmac":
            ip = (ext_ips(txt) or [""])[0]
            return [(ZEEK, [ds("zeek.dhcp"), term("dhcp.assigned_ip", ip)]), (ZEEK, [either(ip)])] if ip else []
        if kt == "newip" and len(k) > 1:
            return [(ZEEK, [either(k[1])])]
        if kt == "tidom" and len(k) > 1:
            src = ext_ips(txt)
            return ([(ZEEK, [ds("zeek.dns"), dom(k[1]), {"terms": {"source.ip": src}}])] if src else []) + [(ZEEK, [ds("zeek.dns"), dom(k[1])])]
        if kt == "tifile" and len(k) > 2:
            return [(FILE, [host(k[2]), term("file.name", k[1])])]
        if kt == "admin" and len(k) > 2:
            return [(ZEEK, [ds("zeek.conn"), term("source.ip", k[1]), term("destination.ip", k[2])])]
        if kt == "ids" and len(k) > 1:
            return [(SURI, [ds("suricata.alert"), term("rule.name", k[1])])]
        if kt in ("secscan",) or kt.startswith("k8s"):
            return []
        X = ext_ips(txt)
        return [(ZEEK, [either(X[0])] + ([either(X[1])] if len(X) > 1 else []))] if X else []
    return []


def lookup(index, filters, t0, t1, q=None):
    """-> (first, last, hits) epoch seconds of matching records in [t0, t1] (first/last None when none)."""
    if q is None:
        import esq
        q = esq.q
    body = {"size": 0, "track_total_hits": 1, "timeout": "20s",
            "query": {"bool": {"filter": [{"range": {"@timestamp": {"gte": int(t0 * 1000), "lte": int(t1 * 1000), "format": "epoch_millis"}}}] + filters}},
            "aggs": {"a": {"min": {"field": "@timestamp"}}, "b": {"max": {"field": "@timestamp"}}}}
    r = q(index, body)
    tot = (r.get("hits") or {}).get("total") or {}
    n = tot.get("value", 0) if isinstance(tot, dict) else int(tot or 0)
    a, b = (r.get("aggregations") or {}).get("a", {}).get("value"), (r.get("aggregations") or {}).get("b", {}).get("value")
    return (a / 1000 if a else None, b / 1000 if b else None, n)


def resolve(eid, typ, item, doc, label, t0, t1, q=None):
    """-> (et0, et1) for the window, or (None, None) when nothing matched / nothing to look up."""
    if typ in DIRECT:
        return (t0, t1 if t1 is not None else t0)
    if t1 is None:
        return (None, None)
    if typ == "alert":
        t0 = min(t0 if t0 is not None else t1, t1 - ALERT_BACK)
        t1 = t1 + 60
    if t0 is None:
        t0 = t1 - 86400
    for index, filt in spec(eid, typ, item, doc, label):
        a, b, n = lookup(index, filt, t0, t1, q)
        if n and a:
            return (a, b)
    if typ == "host":
        sp = span_of(label, time.strftime("%Y", time.gmtime(t1)))
        if sp:
            return sp
    return (None, None)


def ensure_columns():
    import eventstore
    return eventstore._c()  # adds et0/et1/et_upto and event_times


WIN_KEEP_DAYS = 120


def window_times(items, budget=60.0, q=None, log=print):
    """Posture: record times of the events of one time range. items: [{eid, type, label, t0, t1, host_ips, item}].
    Cached in event_times by (eid, window); -> {eid: [et0, et1]} for every item answered (cached or looked up now)
    and the number still missing when the budget ran out."""
    c = ensure_columns()
    out, todo = {}, []
    for it in items:
        if it.get("t1") is None:
            continue
        w0, w1 = int(it.get("t0") if it.get("t0") is not None else it["t1"]), int(it["t1"])
        r = c.execute("SELECT et0, et1 FROM event_times WHERE eid=? AND w0=? AND w1=?", (it["eid"], w0, w1)).fetchone()
        if r:
            out[it["eid"]] = [r[0], r[1]]
        else:
            todo.append((it, w0, w1))
    end, done, errs = time.time() + budget, [], 0
    for it, w0, w1 in todo:
        if time.time() > end or errs >= 5:
            break
        typ = it.get("type") or ""
        try:
            a, b = resolve(it["eid"], typ, it.get("item") or {}, {"host_ips": it.get("host_ips") or []}, it.get("label") or "", it.get("t0"), it["t1"], q)
        except Exception as e:  # noqa: BLE001
            errs += 1
            log(f"evtime: {it['eid'][:80]}: {e}")
            continue
        out[it["eid"]] = [a, b]
        done.append((it["eid"], w0, w1, a, b, time.time()))
    if done:
        with store.tx(c):
            c.executemany("INSERT OR REPLACE INTO event_times (eid,w0,w1,et0,et1,at) VALUES (?,?,?,?,?,?)", done)
            c.execute("DELETE FROM event_times WHERE at < ?", (time.time() - WIN_KEEP_DAYS * 86400,))
    return out, len(todo) - len(done)


def run(budget=240.0, limit=None, q=None, log=print):
    """Fill et0/et1 for open events and their firings whose window is not looked up yet (newest first)."""
    import eventstore
    c = ensure_columns()
    t_end = time.time() + budget
    stats = {"events": 0, "fires": 0, "found": 0, "none": 0, "errors": 0}
    work = []
    for r in c.execute("SELECT eid,type,label,t0,t1,doc,et0,et1,et_upto FROM events WHERE resolved=0 AND type!='vuln' AND t1 IS NOT NULL "
                       "AND (et_upto IS NULL OR et_upto < t1) ORDER BY t1 DESC"):
        work.append(("e", r))
    docs = {}
    for r in c.execute("SELECT f.eid,f.sid,f.t0,f.t1,f.et0,f.et1,f.et_upto,e.type,e.label,e.doc FROM event_fires f JOIN events e ON e.eid=f.eid "
                       "WHERE f.t1 IS NOT NULL AND (f.et_upto IS NULL OR f.et_upto < f.t1) ORDER BY f.t1 DESC"):
        work.append(("f", r))
    work.sort(key=lambda w: -(w[1]["t1"] or 0))
    for kind, r in work[:limit] if limit else work:
        if time.time() > t_end:
            break
        d = docs.get(r["eid"])
        if d is None:
            try:
                d = docs[r["eid"]] = json.loads(r["doc"] or "{}")
            except ValueError:
                d = docs[r["eid"]] = {}
        typ = r["type"]
        # incremental: a later window extended an event already looked up -> only the new part
        w0 = r["et_upto"] if (r["et_upto"] is not None and typ not in DIRECT) else r["t0"]
        try:
            a, b = resolve(r["eid"], typ, d.get("item") or {}, d, r["label"], w0, r["t1"], q)
        except Exception as e:  # noqa: BLE001 - ES down / bad query: retry next run
            stats["errors"] += 1
            if stats["errors"] <= 3:
                log(f"evtime: {r['eid'][:80]}: {e}")
            if stats["errors"] >= 20:
                break
            continue
        e0 = min(x for x in (r["et0"], a) if x is not None) if (r["et0"] is not None or a is not None) else None
        e1 = max(x for x in (r["et1"], b) if x is not None) if (r["et1"] is not None or b is not None) else None
        if typ in DIRECT:
            e0, e1 = a, b
        stats["found" if a else "none"] += 1
        with store.tx(c):
            if kind == "e":
                c.execute("UPDATE events SET et0=?, et1=?, et_upto=? WHERE eid=?", (e0, e1, r["t1"], r["eid"]))
                stats["events"] += 1
            else:
                c.execute("UPDATE event_fires SET et0=?, et1=?, et_upto=? WHERE eid=? AND sid=?", (e0, e1, r["t1"], r["eid"], r["sid"]))
                stats["fires"] += 1
    stats["left"] = max(0, len(work) - stats["events"] - stats["fires"] - stats["errors"])
    log(f"evtime: {json.dumps(stats)}")
    return stats


if __name__ == "__main__":
    a = sys.argv[1:]
    if a[:1] == ["--dry"]:
        import eventstore
        c = ensure_columns()
        for eid in a[1:]:
            r = c.execute("SELECT * FROM events WHERE eid=?", (eid,)).fetchone()
            d = json.loads(r["doc"] or "{}")
            print(eid, json.dumps(spec(eid, r["type"], d.get("item"), d, r["label"]))[:600])
            print("  ->", resolve(eid, r["type"], d.get("item") or {}, d, r["label"], r["t0"], r["t1"]))
        sys.exit(0)
    b = float(a[a.index("--budget") + 1]) if "--budget" in a else 240.0
    run(budget=b)
