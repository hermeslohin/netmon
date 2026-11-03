"""Threat-intel helpers for the dashboard: feed health, indicator lookup, per-snapshot trend.
Reuses netmon's extras.load_feeds()/match_* against the feed files in <netmon>/intel (read-only)."""
import ipaddress, json, os, re, sys, threading, time

ROOT = os.environ.get("NETMON_DIR", "/netmon")
sys.path.insert(0, ROOT)
sys.dont_write_bytecode = True
import extras  # noqa: E402

extras.INTEL = os.path.join(ROOT, "intel")
_lock = threading.Lock()
_cache = {"sig": None, "feeds": None, "per": None, "src": None}
# Built-in feeds that OpenCTI brings in instead (OPENCTI_COVERS): the OpenCTI author ("source" in the list meta) each
# one arrives as, so the Feeds card can say how many indicators the feed still contributes through OpenCTI.
OCTI_SOURCE = {"urlhaus_hosts": re.compile(r"^abuse\.ch$|urlhaus", re.I), "threatfox_hosts": re.compile(r"^threat ?fox", re.I),
               "feodo_ips": re.compile(r"feodo", re.I), "et_compromised": re.compile(r"emerging threats", re.I),
               "cins_badguys": re.compile(r"^cins", re.I), "spamhaus_drop": re.compile(r"^spamhaus", re.I)}


def _source(meta):
    """OpenCTI author of a list entry ('source | labels' meta). Samples carry 'labels | file ...' with no author:
    those are MalwareBazaar's."""
    head = (meta or "").split(" | ")[0].strip()
    if not head:
        return "unattributed"
    if "," in head or "malwarebazaar" in (meta or "").lower().split(" | ")[0]:
        return "MalwareBazaar"
    return head


def _sig():
    fl = extras.apply_feed_config()
    out = [("cfg", tuple((f["name"], f["url"], f["active"], f["serious"]) for f in fl))]
    for n in list(extras.ACTIVE):
        p = os.path.join(extras.INTEL, n + ".txt")
        out.append((n, os.path.getmtime(p) if os.path.exists(p) else 0))
    out.append(("local", tuple(sorted(extras.local_status().items()))))
    return tuple(out)


def feeds():
    with _lock:
        s = _sig()
        if _cache["sig"] != s:
            f = extras.load_feeds()
            per = {}  # feed -> {indicator type: count}
            for k in ("hosts", "ips", "hashes", "filenames"):
                for src in (f.get(k) or {}).values():
                    for n in src:
                        d = per.setdefault(n, {})
                        d[k] = d.get(k, 0) + 1
            for c in f["cidrs"]:
                d = per.setdefault(c[3], {})
                d["cidrs"] = d.get("cidrs", 0) + 1
            for n, (_, kind) in extras.ACTIVE.items():
                if kind == "ja3":
                    per.setdefault(n, {})["ja3"] = len(f["ja3"])
            src = {}  # OpenCTI list -> {source: {indicator type: count}}
            for n, rows in extras.local_lists().items():
                k = extras.LOCAL_FEEDS[n]
                for _, _, meta in rows:
                    d = src.setdefault(n, {}).setdefault(_source(meta), {})
                    d[k] = d.get(k, 0) + 1
            _cache.update(sig=s, feeds=f, per=per, src=src)
        return _cache["feeds"], _cache["per"]


def octi_sources():
    feeds()
    return _cache["src"] or {}


_LISTED = re.compile(r"listed in ([A-Za-z0-9_.\-]+(?:, [A-Za-z0-9_.\-]+)*)")
_hits_cache = {"key": None, "val": {}}


def feed_hits():
    """feed -> {events, sightings, indicators, last, by_type} from the event store: every event whose artifacts a feed
    lists ('listed in <feeds>' tags from correlate._ti_mark, or a ti| event's item.feeds). sightings = sum of the
    events' n (snapshots the event was seen in); indicators = distinct listed values. Cached on the store's change."""
    try:
        import eventstore
        c = eventstore._c()
        key = c.execute("SELECT COUNT(*), MAX(last_seen), SUM(n) FROM events").fetchone()
        if _hits_cache["key"] == key:
            return _hits_cache["val"]
        acc = {}
        vsrc = {}  # listed value -> OpenCTI author, to credit OpenCTI hits to the built-in feed they came from
        for rows in extras.local_lists().values():
            for v, _, meta in rows:
                vsrc[v.lower()] = _source(meta)
        for eid, typ, n, ls, doc in c.execute("SELECT eid, type, n, last_seen, doc FROM events WHERE doc LIKE '%listed in %' OR eid LIKE 'ti|%'"):
            try:
                d = json.loads(doc or "{}")
            except ValueError:
                continue
            fv = {}  # feed -> listed values in this event
            for a in d.get("arts") or []:
                m = _LISTED.search(str(a[2]) if len(a) > 2 else "")
                if m:
                    for fd in m.group(1).split(", "):
                        fv.setdefault(fd, set()).add(f"{a[0]}:{str(a[1]).lower()}")
            it = d.get("item") or {}
            if eid.startswith("ti|"):
                v = it.get("ip") or it.get("domain") or it.get("name") or eid.split("|", 2)[-1]
                for fd in it.get("feeds") or []:
                    fv.setdefault(fd, set()).add(f"{'dns' if it.get('domain') or it.get('name') else 'ip'}:{str(v).lower()}")
            for fd, vals in list(fv.items()):
                if fd.startswith("opencti_"):
                    for x in vals:
                        a = vsrc.get(x.split(":", 1)[1])
                        if a:
                            fv.setdefault("src:" + a, set()).add(x)
            for fd, vals in fv.items():
                r = acc.setdefault(fd, {"events": 0, "sightings": 0, "ind": set(), "last": None, "by_type": {}})
                r["events"] += 1
                r["sightings"] += int(n or 1)
                r["ind"] |= vals
                r["by_type"][typ] = r["by_type"].get(typ, 0) + 1
                if ls and (not r["last"] or ls > r["last"]):
                    r["last"] = ls
        val = {fd: {"events": r["events"], "sightings": r["sightings"], "indicators": len(r["ind"]), "last": r["last"], "by_type": r["by_type"]}
               for fd, r in acc.items()}
        _hits_cache.update(key=key, val=val)
        return val
    except Exception as e:  # noqa: BLE001 - the feed table works without hit counts
        print(f"tintel.feed_hits: {type(e).__name__}: {e}", file=sys.stderr)
        return {}


def feed_status():
    """Every configured feed (inactive ones say why) and the OpenCTI lists when present, with indicators per type
    and hit counts from the event store."""
    _, per = feeds()
    hits = feed_hits()
    src = octi_sources()
    rows = []
    try:
        import integrations
        octi = integrations.opencti().get("url") or ""
    except Exception:  # noqa: BLE001
        octi = ""
    src_rows = [(f["name"], f["url"], f["kind"], f["inactive_why"], not f["builtin"]) for f in extras.feed_list()]
    src_rows += [(n, octi, k, "", False) for n, k in extras.LOCAL_FEEDS.items()]  # written by opencti.py into ti_local
    local = extras.local_status()
    for n, url, kind, why, custom in [x for x in src_rows]:  # URLs are shown with long hex runs (API keys) masked
        if n in extras.LOCAL_FEEDS:
            if n not in local:
                continue  # OpenCTI not set up: no rows
            mt = local[n][1]
        else:
            p = os.path.join(extras.INTEL, n + ".txt")
            mt = os.path.getmtime(p) if os.path.exists(p) else None
        rows.append({"feed": n, "kind": kind, "url": re.sub(r"[0-9A-Fa-f]{24,}", "…", url or ""), "entries": 0 if why else sum((per.get(n) or {}).values()),
                     "by_type": {} if why else dict(per.get(n) or {}), "hits": hits.get(n) or {}, "serious": n in extras.SERIOUS,
                     "active": not why, "inactive_why": why, "custom": custom,
                     "updated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(mt)) if mt else None,
                     "age_h": round((time.time() - mt) / 3600, 1) if mt else None})
        r = rows[-1]
        if n in extras.LOCAL_FEEDS:  # which OpenCTI authors fill this list
            r["sources"] = {a: sum(t.values()) for a, t in sorted((src.get(n) or {}).items(), key=lambda x: -sum(x[1].values()))}
        elif why == "covered by OpenCTI" and n in OCTI_SOURCE and local:
            bt, lists = {}, set()
            for ln, by in src.items():
                for a, t in by.items():
                    if OCTI_SOURCE[n].search(a):
                        lists.add(ln)
                        for k, c in t.items():
                            bt[k] = bt.get(k, 0) + c
            ln_up = [local[x][1] for x in lists if x in local]
            hs = [h for k, h in hits.items() if k.startswith("src:") and OCTI_SOURCE[n].search(k[4:])]
            if hs:  # hits through OpenCTI added to the ones the feed scored itself before OpenCTI covered it
                hs.append(r["hits"] or {})
                r["hits"] = {"events": sum(h.get("events", 0) for h in hs), "sightings": sum(h.get("sightings", 0) for h in hs),
                             "indicators": sum(h.get("indicators", 0) for h in hs), "last": max(h.get("last") or "" for h in hs) or None,
                             "by_type": {}, "via_opencti": True}
            r.update(via_opencti=True, by_type=bt, entries=sum(bt.values()), opencti_lists=sorted(lists),
                     updated=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(max(ln_up))) if ln_up else r["updated"],
                     age_h=round((time.time() - max(ln_up)) / 3600, 1) if ln_up else r["age_h"])
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
