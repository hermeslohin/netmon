"""Threat-intel helpers for the dashboard: feed health, indicator lookup, per-snapshot trend.
Reuses netmon's extras.load_feeds()/match_* against the feed files in <netmon>/intel (read-only)."""
import ipaddress, json, os, re, sys, threading, time

ROOT = os.environ.get("NETMON_DIR", "/netmon")
sys.path.insert(0, ROOT)
sys.dont_write_bytecode = True
import extras  # noqa: E402

extras.INTEL = os.path.join(ROOT, "intel")
_lock = threading.Lock()
_cache = {"sig": None, "feeds": None, "per": None}
MAL_CAT = re.compile(r"trojan|malware|command and control|c2|exploit|botnet|coin|ransom|phish|compromised|attempted admin|attempted user|web application attack", re.I)


def _sig():
    out = []
    for n in list(extras.FEEDS) + list(extras.LOCAL_FEEDS):
        p = os.path.join(extras.INTEL, n + ".txt")
        out.append((n, os.path.getmtime(p) if os.path.exists(p) else 0))
    return tuple(out)


def feeds():
    with _lock:
        s = _sig()
        if _cache["sig"] != s:
            f = extras.load_feeds()
            per = {n: 0 for n in list(extras.FEEDS) + list(extras.LOCAL_FEEDS)}
            for src in f["hosts"].values():
                for n in src:
                    per[n] += 1
            for src in f["ips"].values():
                for n in src:
                    per[n] += 1
            for c in f["cidrs"]:
                per[c[3]] += 1
            per["sslbl_ja3"] = len(f["ja3"])
            _cache.update(sig=s, feeds=f, per=per)
        return _cache["feeds"], _cache["per"]


def feed_status():
    _, per = feeds()
    rows = []
    try:
        import integrations
        octi = integrations.opencti().get("url") or ""
    except Exception:  # noqa: BLE001
        octi = ""
    rows_src = list(extras.FEEDS.items()) + [(n, (octi, k)) for n, k in extras.LOCAL_FEEDS.items()]  # written by opencti.py
    for n, (url, kind) in rows_src:
        p = os.path.join(extras.INTEL, n + ".txt")
        if n in extras.LOCAL_FEEDS and not os.path.exists(p):
            continue  # OpenCTI not set up: no rows
        mt = os.path.getmtime(p) if os.path.exists(p) else None
        rows.append({"feed": n, "kind": kind, "url": url, "entries": per.get(n, 0), "serious": n in extras.SERIOUS,
                     "updated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(mt)) if mt else None,
                     "age_h": round((time.time() - mt) / 3600, 1) if mt else None})
    return rows


def _rdap(domain):
    try:
        c = json.load(open(os.path.join(extras.INTEL, "rdap_cache.json")))
    except Exception:
        return None
    parts = domain.split(".")
    for i in range(len(parts) - 1):
        d = ".".join(parts[i:])
        if d in c:
            return {"domain": d, "registered": c[d]}
    return None


def lookup(q):
    q = (q or "").strip().lower().rstrip(".")
    f, _ = feeds()
    out = {"q": q, "type": None, "feeds": [], "detail": None}
    if not q:
        return out
    try:
        ip = ipaddress.ip_address(q)
        out["type"] = "ip"
        out["feeds"] = extras.match_ip(q, f)
        out["private"] = ip.is_private
        return out
    except ValueError:
        pass
    if re.fullmatch(r"[0-9a-f]{32}", q):
        out["type"] = "ja3"
        if q in f["ja3"]:
            out["feeds"], out["detail"] = ["sslbl_ja3"], f["ja3"][q]
        return out
    if re.fullmatch(r"[a-z0-9_.-]+\.[a-z0-9-]{2,}", q):
        out["type"] = "domain"
        m, src = extras.match_domain(q, f)
        out["feeds"], out["matched"] = src, m
        out["rdap"] = _rdap(q)
        return out
    out["type"] = "unknown"
    return out


_trend_rows = {}  # sid -> (doc mtime, row): a few hundred bytes each instead of the whole snapshot


def trend_cached(sids, mtime, load):
    """trend() over many snapshots without holding them in memory: each snapshot is loaded, reduced to its counter
    row and dropped; rows are cached by the snapshot's mtime."""
    out = []
    for sid in sids:
        mt = mtime(sid)
        if mt is None:
            continue
        hit = _trend_rows.get(sid)
        if not hit or hit[0] != mt:
            raw = load(sid)
            if not raw:
                continue
            hit = (mt, trend([(sid, raw)])[0])
            _trend_rows[sid] = hit
            del raw
        out.append(hit[1])
    for sid in set(_trend_rows) - set(sids):
        _trend_rows.pop(sid, None)
    return out


def trend(snaps):
    """snaps: [(sid, raw)] -> per-snapshot TI counters."""
    rows = []
    for sid, raw in snaps:
        ti = raw.get("threat_intel") or {}
        sigs = (raw.get("alerts") or {}).get("signatures") or []
        mal = [s for s in sigs if MAL_CAT.search(s.get("category", "") + " " + s.get("name", "")) or (s.get("severity") or 9) <= 1]
        u = raw.get("unifi") or {}
        rows.append({"id": sid, "generated": raw.get("generated"),
                     "in_ips": len(ti.get("ip_hits_in") or []), "in_conns": sum(h.get("conns", 0) for h in ti.get("ip_hits_in") or []),
                     "out_ips": len(ti.get("ip_hits_out") or []), "domains": len(ti.get("domain_hits") or []),
                     "new_domains": len(ti.get("new_domains") or []), "mal_ja3": len((raw.get("tls") or {}).get("malicious_ja3") or []),
                     "mal_alerts": sum(s.get("count", 0) for s in mal), "beacons": len((raw.get("beacons") or {}).get("candidates") or []),
                     "unifi_threats": len((u.get("events") or {}).get("threats") or [])})
    return rows
