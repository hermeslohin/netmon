"""Threat-intel look-up for an event's artifacts, shared by the event reviewer (corr_llm), the decision model (clef)
and the dashboard.

hits(event) checks every IP, domain, file name, process image name and file hash the event carries (its `arts`
[kind, value, relation], `ips`, `dst_ips` and `host_ips`) against all loaded feeds: the downloaded ones in
extras.FEEDS and the OpenCTI lists that opencti.py writes. For OpenCTI entries the score, source and labels
(malware family, campaign...) come along, so the reviewer sees *why* a value is listed, not just that it is.

Feeds are re-read only when a list file changes (mtime signature), so calling this per event is cheap.
"""
import os
import re
import sys
import threading

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
import extras  # noqa: E402

_lock = threading.Lock()
_cache = {"sig": None, "feeds": None, "meta": {}}
_HEX = re.compile(r"^[0-9a-f]{32}$|^[0-9a-f]{40}$|^[0-9a-f]{64}$|^[0-9a-f]{128}$")
FEED_DESC = {"urlhaus_hosts": "URLhaus malware-distribution host", "threatfox_hosts": "ThreatFox IOC host",
             "feodo_ips": "Feodo Tracker botnet C2", "sslbl_ips": "SSLBL botnet C2", "et_compromised": "ET known-compromised host",
             "cins_badguys": "CINS scanner/attacker list", "spamhaus_drop": "Spamhaus DROP (hijacked netblock)", "sslbl_ja3": "SSLBL malicious JA3"}
MAX_HITS = 8


def _sig():
    out = []
    for n in list(extras.FEEDS) + list(extras.LOCAL_FEEDS):
        p = os.path.join(extras.INTEL, n + ".txt")
        out.append((n, os.path.getmtime(p) if os.path.exists(p) else 0))
    return tuple(out)


def _load_meta():
    """value(lowercase) -> (score, 'source | labels') from the OpenCTI lists."""
    meta = {}
    for n, kind in extras.LOCAL_FEEDS.items():
        try:
            f = open(os.path.join(extras.INTEL, n + ".txt"), encoding="utf-8")
        except OSError:
            continue
        with f:
            for line in f:
                if line.startswith("#"):
                    continue
                body, _, rest = line.rstrip("\n").partition(" # ")
                v = body.split()[1] if kind == "hosts" and len(body.split()) > 1 else body.strip()
                m = re.match(r"score (\d+)(?: \| (.*))?$", rest.strip())
                if v and m:
                    meta[v.lower()] = (int(m.group(1)), m.group(2) or "")
    return meta


def feeds():
    with _lock:
        s = _sig()
        if _cache["sig"] != s:
            _cache.update(sig=s, feeds=extras.load_feeds(), meta=_load_meta())
        return _cache["feeds"], _cache["meta"]


def _is_public_ip(v):
    import ipaddress
    try:
        a = ipaddress.ip_address(v)
    except ValueError:
        return False
    return not (a.is_private or a.is_loopback or a.is_link_local or a.is_multicast or a.is_reserved or a.is_unspecified)


def _values(ev):
    """(kind, value) pairs worth looking up, deduplicated, in the event's own order."""
    out, seen = [], set()

    def put(k, v):
        v = str(v or "").strip()
        key = (k, v.lower())
        if v and key not in seen:
            seen.add(key)
            out.append((k, v))
    for a in ev.get("arts") or []:
        if not a or len(a) < 2:
            continue
        k, v = a[0], str(a[1])
        if k == "ip":
            put("ip", v)
        elif k == "dns":
            put("dns", v.lower().rstrip("."))
        elif k == "hash":
            put("hash", v.lower())
        elif k in ("file", "process"):
            base = re.split(r"[\\/]", v.split()[0] if k == "process" and " " in v else v)[-1]
            put("file", base)
            sha = re.search(r"\b(?:sha256|md5|sha1)\s+([0-9a-f]{32,64})\b", str(a[2] if len(a) > 2 else ""), re.I)
            if sha and _HEX.match(sha.group(1).lower()):
                put("hash", sha.group(1).lower())
    for k in ("ips", "dst_ips", "host_ips"):
        for ip in ev.get(k) or []:
            if _is_public_ip(str(ip)):
                put("ip", str(ip))
    return out


def hits(ev):
    """[{kind, value, feeds, serious, score, about}] for the event's artifacts that a feed lists (at most MAX_HITS,
    serious first)."""
    f, meta = feeds()
    res = []
    for k, v in _values(ev):
        if k == "ip":
            fl = extras.match_ip(v, f) if _is_public_ip(v) else []
            m = v
        elif k == "dns":
            m, fl = extras.match_domain(v, f)
        elif k == "hash":
            fl, m = extras.match_hash(v, f), v
        else:
            fl, m = extras.match_filename(v, f), v.lower()
        if not fl:
            continue
        sc, about = meta.get(str(m).lower(), (None, ""))
        if not about:
            about = "; ".join(FEED_DESC[x] for x in fl if x in FEED_DESC)
        res.append({"kind": k, "value": v, "matched": m, "feeds": fl, "serious": bool(set(fl) & extras.SERIOUS),
                    "score": sc, "about": about[:160]})
    res.sort(key=lambda h: (not h["serious"], -(h["score"] or 0)))
    return res[:MAX_HITS]


def describe(h):
    """One line for a prompt: 'hash=ab12... listed in opencti_hashes (OpenCTI score 90; MalwareBazaar | nanocore, rat)'."""
    src = ", ".join(h["feeds"])
    extra = "; ".join(x for x in ((f"OpenCTI score {h['score']}" if h.get("score") is not None else ""), h.get("about") or "") if x)
    weak = " - file name only, weak on its own" if h["kind"] == "file" and not h["serious"] else ""
    on = f" (matched {h['matched']})" if h.get("matched") and str(h["matched"]).lower() != str(h["value"]).lower() else ""
    return f"{h['kind']}={str(h['value'])[:90]}{on} listed in {src}" + (f" ({extra})" if extra else "") + weak


def lines(ev):
    try:
        return [describe(h) for h in hits(ev)]
    except Exception as e:  # noqa: BLE001 - a review never fails because the intel is unavailable
        print(f"intelmatch: {type(e).__name__}: {e}", file=sys.stderr)
        return []


def sig(ev):
    """Short digest of the event's hits ('' when none): part of the review signature, so a new hit re-reviews it."""
    hs = sorted(f"{h['kind']}:{str(h['matched']).lower()}:{','.join(h['feeds'])}" for h in (hits(ev) if ev else []))
    if not hs:
        return ""
    import hashlib
    return hashlib.sha256("|".join(hs).encode()).hexdigest()[:8]
