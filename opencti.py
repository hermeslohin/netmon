#!/usr/bin/env python3
"""OpenCTI integration (optional; More > Configuration > Integrations > OpenCTI).

  pull       indicators (IPv4/IPv6/domain/hostname, STIX patterns, not revoked, not expired, score >= min) into the
             local feed files intel/opencti_*.txt, which extras.load_feeds() matches like any downloaded feed.
             Indicators at or above the high-confidence score go to the *_high lists, which count as SERIOUS.
             A full rebuild runs once a day; in between only indicators updated since the last pull are merged.
  sightings  watch.py hands over every match on an OpenCTI list; each becomes (or bumps) one STIX sighting of that
             indicator by netmon's own identity (attribute_count = connections / look-ups seen).
  incidents  (off by default) open events the reviewer labelled suspicious at or above the configured severity and
             confidence become OpenCTI Incidents, with their external IPs / domains attached as observables.

Settings live in the integrations document (integrations.py); sync state in the docs-table document opencti_sync.
Nothing runs unless the integration is enabled with a URL and an API token.

  opencti.py run [--full]    one sync pass (the scheduler runs it every 15 minutes)
  opencti.py check           test the connection with the saved settings
"""
import datetime as dt
import ipaddress
import json
import os
import re
import sqlite3
import ssl
import sys
import time
import urllib.error
import urllib.request

NM = os.environ.get("NETMON_DIR") or os.path.dirname(os.path.abspath(__file__))
if NM not in sys.path:
    sys.path.insert(0, NM)
import integrations  # noqa: E402
import store  # noqa: E402

INTEL = os.path.join(NM, "intel")
STATE = integrations.OPENCTI_STATE
PULL_EVERY = 3600          # incremental indicator pull
FULL_EVERY = 24 * 3600     # full rebuild (drops revoked / expired / re-scored indicators)
PAGE = 500
MAX_PAGES = 400            # 200k indicators per pull at most
OBS_TYPES = ("IPv4-Addr", "IPv6-Addr", "Domain-Name", "Hostname", "Url", "StixFile", "Artifact")
_PAT = re.compile(r"^\[(ipv4-addr|ipv6-addr|domain-name|hostname):value\s*=\s*'([^'\\]+)'\]$")
_FPAT = re.compile(r"^\[(?:file|artifact):hashes\.(?:'([A-Za-z0-9-]+)'|([A-Za-z0-9_-]+))\s*=\s*'([0-9A-Fa-f]+)'\]$")
_NPAT = re.compile(r"^\[file:name\s*=\s*'([^'\\]+)'\]$")
_UPAT = re.compile(r"^\[url:value\s*=\s*'([^'\\]+)'\]$")
SAMPLE_SCORE = 90          # a malware sample observable (MalwareBazaar) without a score of its own
PULL_VERSION = 3           # bump when the list format changes: forces one full rebuild
SEV_RANK = {"low": 1, "medium": 2, "high": 3, "urgent": 4}
OCTI_SEV = {"urgent": "critical", "high": "high", "medium": "medium", "low": "low"}
NEW_INCIDENTS_PER_RUN = 25
INCIDENT_LOOKBACK_D = 7
IDENTITY_DESC = "netmon home network monitor: sightings and incidents reported from Security Onion / UniFi telemetry."


class GraphQLError(Exception):
    pass


def err_text(e):
    if isinstance(e, urllib.error.HTTPError):
        return f"HTTP {e.code} {e.reason}"
    if isinstance(e, urllib.error.URLError):
        return f"cannot reach OpenCTI: {e.reason}"[:300]
    return str(e)[:300]


def _now_iso(t=None):
    return dt.datetime.fromtimestamp(t if t is not None else time.time(), dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _iso(s):
    """'2026-10-30T03:15:06.85+00:00' / '...Z' -> OpenCTI ISO string ('' when unparsable)."""
    try:
        return _now_iso(dt.datetime.fromisoformat(str(s).replace("Z", "+00:00")).timestamp())
    except (TypeError, ValueError):
        return ""


class Client:
    def __init__(self, cfg):
        self.url = cfg["url"].rstrip("/")
        self.key = cfg["api_key"]
        if not self.url.startswith(("https://", "http://")):
            raise ValueError("OpenCTI URL must start with https:// or http://")
        # certificates are always verified: a private CA (self-signed OpenCTI) is pasted on the card instead
        self.ctx = ssl.create_default_context(cadata=cfg["ca_pem"]) if cfg.get("ca_pem") else ssl.create_default_context()

    def q(self, query, variables=None, timeout=60):
        req = urllib.request.Request(self.url + "/graphql", json.dumps({"query": query, "variables": variables or {}}).encode(),
                                     {"Content-Type": "application/json", "Authorization": "Bearer " + self.key,
                                      "User-Agent": "netmon/1.0"}, method="POST")
        with urllib.request.urlopen(req, context=self.ctx if self.url.startswith("https://") else None, timeout=timeout) as r:  # noqa: S310
            d = json.load(r)
        if d.get("errors"):
            raise GraphQLError(d["errors"][0].get("message") or "GraphQL error")
        return d.get("data") or {}

    def check(self):
        d = self.q("query{ about{ version } me{ name user_email } indicators(first:1){ pageInfo{ globalCount } } }")
        return {"url": self.url, "version": d["about"]["version"], "user": d["me"].get("user_email") or d["me"].get("name"),
                "indicators": d["indicators"]["pageInfo"]["globalCount"]}

    # -- netmon's identity (author of everything it reports)
    def identity(self, name):
        f = {"mode": "and", "filters": [{"key": "name", "values": [name]}, {"key": "entity_type", "values": ["System"]}], "filterGroups": []}
        e = self.q("query($f:FilterGroup){ identities(first:1, filters:$f){ edges{ node{ id } } } }", {"f": f})["identities"]["edges"]
        if e:
            return e[0]["node"]["id"]
        return self.q("mutation($i:IdentityAddInput!){ identityAdd(input:$i){ id } }",
                      {"i": {"type": "System", "name": name, "description": IDENTITY_DESC}})["identityAdd"]["id"]


# ------------------------------------------------------------------ indicators -> local feed files
# list file -> kind. Each value sits in exactly one list; "high" lists hold score >= high_score and count as SERIOUS
# (extras.SERIOUS). Every hash list entry is SERIOUS: a hash match is exact. File names are a weak signal on their own.
LISTS = {"opencti_ips": "ips", "opencti_high_ips": "ips", "opencti_hosts": "hosts", "opencti_high_hosts": "hosts",
         "opencti_cidrs": "cidrs", "opencti_high_cidrs": "cidrs",
         "opencti_hashes": "hashes", "opencti_filenames": "filenames", "opencti_high_filenames": "filenames"}
# A malicious URL on one of these shared hosts says nothing about the host itself: never list the host.
SHARED_HOSTS = ("github.com", "githubusercontent.com", "gitlab.com", "bitbucket.org", "google.com", "googleapis.com",
                "googleusercontent.com", "drive.google.com", "docs.google.com", "dropbox.com", "dropboxusercontent.com",
                "onedrive.live.com", "1drv.ms", "sharepoint.com", "microsoft.com", "windows.net", "azurewebsites.net",
                "amazonaws.com", "cloudfront.net", "discord.com", "discordapp.com", "discordapp.net", "cdn.discordapp.com",
                "telegram.org", "t.me", "pastebin.com", "paste.ee", "mediafire.com", "mega.nz", "transfer.sh",
                "cloudflare.com", "workers.dev", "pages.dev", "r2.dev", "web.app", "firebaseapp.com", "appspot.com",
                "herokuapp.com", "vercel.app", "netlify.app", "glitch.me", "wordpress.com", "blogspot.com", "weebly.com",
                "wixsite.com", "000webhostapp.com", "ngrok.io", "ngrok-free.app", "trycloudflare.com", "duckdns.org",
                "archive.org", "bit.ly", "tinyurl.com", "yandex.ru", "apple.com", "icloud.com", "facebook.com", "youtube.com")
OBS_MAX_AGE_D = 7          # a feed observable (no indicator) counts while its feed re-sent it within this many days
_HEX = {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}
# names legitimate software also uses: matching them alone says nothing
GENERIC_NAMES = {"setup.exe", "install.exe", "installer.exe", "update.exe", "updater.exe", "svchost.exe", "explorer.exe", "rundll32.exe",
                 "powershell.exe", "cmd.exe", "conhost.exe", "msiexec.exe", "regsvr32.exe", "wscript.exe", "cscript.exe", "mshta.exe",
                 "invoice.pdf", "document.pdf", "file.exe", "a.exe", "1.exe", "test.exe", "run.exe", "start.exe", "main.exe", "app.exe",
                 "client.exe", "server.exe", "payload.exe", "sample.exe", "x86", "x64", "bot", "sh", "bash", "python.exe", "java.exe",
                 "index.html", "index.php", "readme.txt", "license.txt", "data.bin", "out.exe", "chrome.exe", "firefox.exe", "notepad.exe"}


def _hash(v):
    v = str(v or "").strip().lower()
    return v if len(v) in _HEX and re.fullmatch(r"[0-9a-f]+", v) and len(set(v)) > 4 else None


def _fname(v):
    """Base file name worth matching: has an extension or is long, no separators, not generic."""
    v = re.split(r"[\\/]", str(v or "").strip())[-1].strip()
    lv = v.lower()
    if not v or len(v) > 200 or "#" in v or "\n" in v or lv in GENERIC_NAMES:
        return None
    if not (re.search(r"\.[a-z0-9]{1,8}$", lv) and len(lv) >= 6) and len(lv) < 10:
        return None
    if _hash(re.sub(r"\.[a-z0-9]{1,8}$", "", lv)):  # "<hash>.exe": the hash list covers it
        return None
    return v


def _addr(v):
    """IP or CIDR text -> ("ips", ip) / ("cidrs", net) for public addresses, else None."""
    try:
        a = ipaddress.ip_network(str(v).strip(), strict=False)
    except ValueError:
        return None
    if a.is_private or a.is_loopback or a.is_multicast or a.is_reserved or a.is_link_local or a.is_unspecified:
        return None  # private / special addresses never match outside traffic usefully
    if a.num_addresses == 1:
        return "ips", str(a.network_address)
    if a.version == 4 and a.prefixlen >= 8:
        return "cidrs", str(a)
    return None


def _shared(host):
    return any(host == d or host.endswith("." + d) for d in SHARED_HOSTS)


def url_host(u):
    """Host of a malicious URL as a list entry: ("ips", ip) for an IP host, ("hosts", domain) for a domain that is not a
    shared / hosting platform, else None."""
    m = re.match(r"^[a-z][a-z0-9+.-]*://(?:[^/@]*@)?(\[[0-9a-f:]+\]|[^/:?#]+)", str(u or "").strip(), re.I)
    if not m:
        return None
    h = m.group(1).strip("[]").lower().rstrip(".")
    if re.fullmatch(r"[\d.]+|[0-9a-f:]+", h) and (":" in h or h.count(".") == 3):
        a = _addr(h)
        return a if a and a[0] == "ips" else None
    if "." not in h or " " in h or len(h) > 253 or _shared(h):
        return None
    return "hosts", h


def parse_pattern(p):
    """Single-value STIX pattern -> (kind, value) with kind ips|cidrs|hosts|hashes|filenames, or None
    (compound patterns, private addresses, URLs on shared hosting...). A URL indicator lists its host."""
    p = (p or "").strip()
    m = _PAT.match(p)
    if m:
        typ, v = m.group(1), m.group(2).strip().lower().rstrip(".")
        if typ in ("ipv4-addr", "ipv6-addr"):
            return _addr(v)
        if "." not in v or " " in v or len(v) > 253:
            return None
        return "hosts", v
    m = _UPAT.match(p)
    if m:
        return url_host(m.group(1))
    m = _FPAT.match(p)
    if m:
        h = _hash(m.group(3))
        return ("hashes", h) if h else None
    m = _NPAT.match(p)
    if m:
        n = _fname(m.group(1))
        return ("filenames", n) if n else None
    return None


def _feed_path(name):
    return os.path.join(INTEL, name + ".txt")


def _clean_meta(meta):
    return re.sub(r"[\r\n#]+", " ", str(meta or ""))[:160].strip()


def read_local():
    """Current local lists: {value: (kind, score, meta)} (meta: 'source | labels' for the reviewer)."""
    out = {}
    for name, kind in LISTS.items():
        try:
            for line in open(_feed_path(name), encoding="utf-8"):
                if line.startswith("#"):
                    continue
                body, _, rest = line.rstrip("\n").partition(" # ")
                if kind == "hosts":
                    parts = body.split()
                    v = parts[1] if len(parts) > 1 else ""
                else:
                    v = body.strip()
                m = re.match(r"score (\d+)(?: \| (.*))?$", rest.strip())
                if v:
                    out[v] = (kind, int(m.group(1)) if m else 0, (m.group(2) or "") if m else "")
        except OSError:
            pass
    return out


def write_local(entries, high):
    """entries {value: (kind, score[, meta])} -> the list files (each value in exactly one)."""
    os.makedirs(INTEL, exist_ok=True)
    files = {n: [] for n in LISTS}
    for v, e in sorted(entries.items()):
        kind, score, meta = (tuple(e) + ("",))[:3]
        n = "opencti_hashes" if kind == "hashes" else "opencti_" + ("high_" if score >= high else "") + kind
        tail = f" # score {score}" + (f" | {_clean_meta(meta)}" if meta else "")
        files[n].append(("0.0.0.0 " if kind == "hosts" else "") + v + tail)
    for n, lines in files.items():
        tmp = _feed_path(n) + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(f"# OpenCTI indicators written by netmon opencti.py at {_now_iso()}\n" + "\n".join(lines) + ("\n" if lines else ""))
        os.replace(tmp, _feed_path(n))
    return {n: len(v) for n, v in files.items()}


def remove_local():
    for n in LISTS:
        try:
            os.remove(_feed_path(n))
        except OSError:
            pass


_IND_Q = """query($a:ID, $f:FilterGroup){ indicators(first:%d, after:$a, orderBy:updated_at, orderMode:asc, filters:$f){
  pageInfo{ hasNextPage endCursor } edges{ node{ pattern x_opencti_score revoked valid_until updated_at
  createdBy{ name } objectLabel{ value } } } } }""" % PAGE
_OBS_Q = """query($a:ID, $f:FilterGroup){ stixCyberObservables(first:%d, after:$a, types:["Artifact", "StixFile"],
  orderBy:updated_at, orderMode:asc, filters:$f){ pageInfo{ hasNextPage endCursor } edges{ node{ entity_type updated_at
  x_opencti_score createdBy{ name } objectLabel{ value }
  ... on Artifact{ hashes{ algorithm hash } x_opencti_additional_names }
  ... on StixFile{ name hashes{ algorithm hash } x_opencti_additional_names } } } } }""" % PAGE


_IPOBS_Q = """query($a:ID, $f:FilterGroup){ stixCyberObservables(first:%d, after:$a, types:["IPv4-Addr", "IPv6-Addr"],
  orderBy:created_at, orderMode:asc, filters:$f){ pageInfo{ hasNextPage endCursor } edges{ node{ observable_value
  refreshed_at x_opencti_score createdBy{ name } objectLabel{ value } } } } }""" % PAGE


def _pages(cli, query, key, f):
    after = None
    for _ in range(MAX_PAGES):
        d = cli.q(query, {"a": after, "f": f}, timeout=120)[key]
        for e in d["edges"]:
            yield e["node"]
        if not d["pageInfo"]["hasNextPage"]:
            return
        after = d["pageInfo"]["endCursor"]


def fetch_indicators(cli, since=None, min_score=0):
    """Yield indicator nodes of the matchable observable types; full pulls filter server-side, incremental ones don't
    (a revoked or re-scored indicator must reach merge() so it can be dropped)."""
    flt = [{"key": "pattern_type", "values": ["stix"]}, {"key": "x_opencti_main_observable_type", "values": list(OBS_TYPES)}]
    if since:
        flt.append({"key": "updated_at", "values": [since], "operator": "gt"})
    else:
        flt += [{"key": "revoked", "values": ["false"]}, {"key": "x_opencti_score", "values": [str(min_score)], "operator": "gte"}]
    return _pages(cli, _IND_Q, "indicators", {"mode": "and", "filters": flt, "filterGroups": []})


def fetch_samples(cli, since=None):
    """Malware sample observables (MalwareBazaar Artifacts, files from reports) that carry hashes but no indicator."""
    flt = [{"key": "updated_at", "values": [since], "operator": "gt"}] if since else []
    return _pages(cli, _OBS_Q, "stixCyberObservables", {"mode": "and", "filters": flt, "filterGroups": []})


def fetch_feed_ips(cli, min_score, since=None, now=None):
    """Scored IP / CIDR observables that block-list feeds bring in without an indicator (IPsum, CINS, ET, Spamhaus
    DROP, Feodo, DShield...): the ones a feed re-sent within OBS_MAX_AGE_D days (older ones dropped off the list)."""
    floor = _now_iso((now or time.time()) - OBS_MAX_AGE_D * 86400)
    flt = [{"key": "x_opencti_score", "values": [str(min_score)], "operator": "gte"},
           {"key": "refreshed_at", "values": [max(since or "", floor)], "operator": "gt"}]
    return _pages(cli, _IPOBS_Q, "stixCyberObservables", {"mode": "and", "filters": flt, "filterGroups": []})


def merge_feed_ips(entries, nodes, min_score):
    """IP / CIDR observables -> entries; an indicator already listing the value keeps its own score and source."""
    newest = ""
    for n in nodes:
        newest = max(newest, n.get("refreshed_at") or "")
        a = _addr(n.get("observable_value"))
        score = int(n.get("x_opencti_score") or 0)
        if a and score >= min_score and a[1] not in entries:
            entries[a[1]] = (a[0], score, _meta(n))
    return entries, newest


def _meta(n, extra=""):
    src = ((n.get("createdBy") or {}).get("name") or "").strip()
    labels = ", ".join(sorted({str(x.get("value")) for x in (n.get("objectLabel") or []) if x.get("value")})[:6])
    return " | ".join(x for x in (src, labels, extra) if x)


def merge(entries, nodes, min_score, now=None):
    """Apply indicator nodes to {value: (kind, score, meta)}; returns (entries, newest updated_at seen)."""
    now = now or _now_iso()
    newest = ""
    for n in nodes:
        newest = max(newest, n.get("updated_at") or "")
        pv = parse_pattern(n.get("pattern"))
        if not pv:
            continue
        kind, v = pv
        score = int(n.get("x_opencti_score") or 0)
        expired = bool(n.get("valid_until")) and n["valid_until"] < now
        if n.get("revoked") or expired or score < min_score:
            entries.pop(v, None)
        else:
            entries[v] = (kind, score, _meta(n))
    return entries, newest


def merge_samples(entries, nodes, sample_score=SAMPLE_SCORE):
    """Sample observables -> every hash (md5/sha1/sha256) as a hash entry; the sample's file names go into the meta
    (and into the file-name list when specific enough). An indicator already listing the hash keeps its own score."""
    newest = ""
    for n in nodes:
        newest = max(newest, n.get("updated_at") or "")
        names = [x for x in ([n.get("name")] + list(n.get("x_opencti_additional_names") or [])) if x]
        score = int(n.get("x_opencti_score") or sample_score)
        meta = _meta(n, ("file " + ", ".join(map(str, names[:3]))) if names else "")
        hs = [h for h in (_hash(x.get("hash")) for x in n.get("hashes") or []) if h]
        for h in hs:
            if h not in entries:
                entries[h] = ("hashes", score, meta + (" | sample " + hs[-1][:16] if h != hs[-1] else ""))
        for nm_ in names:
            f = _fname(nm_)
            if f and f not in entries and hs:
                entries[f] = ("filenames", score, meta + f" | sha256 {hs[-1][:16]}")
    return entries, newest


def pull(cli, cfg, st, force_full=False):
    now = time.time()
    full = force_full or not st.get("last_full_ts") or now - st["last_full_ts"] > FULL_EVERY \
        or st.get("pulled_min_score") != cfg["min_score"] or st.get("pull_version") != PULL_VERSION \
        or not os.path.exists(_feed_path("opencti_ips"))
    if not full and st.get("last_pull_ts") and now - st["last_pull_ts"] < PULL_EVERY:
        return None
    if full:
        entries, newest = merge({}, fetch_indicators(cli, None, cfg["min_score"]), cfg["min_score"])
        entries, onewest = merge_samples(entries, fetch_samples(cli, None))
        entries, inewest = merge_feed_ips(entries, fetch_feed_ips(cli, cfg["min_score"]), cfg["min_score"])
        st.update(last_full_ts=now, last_full=_now_iso(now), pulled_min_score=cfg["min_score"], pull_version=PULL_VERSION)
    else:
        entries, newest = merge(read_local(), fetch_indicators(cli, st.get("cursor")), cfg["min_score"])
        entries, onewest = merge_samples(entries, fetch_samples(cli, st.get("obs_cursor")))
        entries, inewest = merge_feed_ips(entries, fetch_feed_ips(cli, cfg["min_score"], st.get("ip_cursor")), cfg["min_score"])
    sizes = write_local(entries, cfg["high_score"])
    st.update(last_pull_ts=now, last_pull=_now_iso(now), cursor=newest or st.get("cursor"), obs_cursor=onewest or st.get("obs_cursor"),
              ip_cursor=inewest or st.get("ip_cursor"), cidrs=sizes["opencti_cidrs"] + sizes["opencti_high_cidrs"],
              indicators=len(entries), high=sizes["opencti_high_ips"] + sizes["opencti_high_hosts"] + sizes["opencti_high_cidrs"] + sizes["opencti_high_filenames"],
              hashes=sizes["opencti_hashes"], filenames=sizes["opencti_filenames"] + sizes["opencti_high_filenames"])
    return {"full": full, "indicators": len(entries), **sizes}


# ------------------------------------------------------------------ sightings (called by watch.py)
def _find_indicator(cli, value):
    """The object a sighting of `value` points at: the best-scored live indicator named after it, else (hashes and
    file names of malware samples, which often have no indicator) the observable that carries it."""
    vals = sorted({value, value.lower(), value.upper()})
    f = {"mode": "and", "filters": [{"key": "name", "values": vals}, {"key": "revoked", "values": ["false"]}], "filterGroups": []}
    e = cli.q("query($f:FilterGroup){ indicators(first:1, orderBy:x_opencti_score, orderMode:desc, filters:$f){ edges{ node{ id } } } }",
              {"f": f})["indicators"]["edges"]
    if e:
        return e[0]["node"]["id"]
    if _hash(value):
        f = {"mode": "or", "filters": [{"key": "hashes." + a, "values": vals} for a in ("MD5", "SHA-1", "SHA-256", "SHA-512")], "filterGroups": []}
    elif _fname(value):
        f = {"mode": "or", "filters": [{"key": "name", "values": [value]}, {"key": "x_opencti_additional_names", "values": [value]}], "filterGroups": []}
    else:
        return None
    e = cli.q("query($f:FilterGroup){ stixCyberObservables(first:1, filters:$f){ edges{ node{ id } } } }", {"f": f})["stixCyberObservables"]["edges"]
    return e[0]["node"]["id"] if e else None


def sight(cli, ident, ind, count, first, last, desc):
    f = {"mode": "and", "filters": [{"key": "fromId", "values": [ind]}, {"key": "toId", "values": [ident]}], "filterGroups": []}
    e = cli.q("query($f:FilterGroup){ stixSightingRelationships(first:1, filters:$f){ edges{ node{ id attribute_count } } } }",
              {"f": f})["stixSightingRelationships"]["edges"]
    if e:
        n = e[0]["node"]
        cli.q("mutation($id:ID!, $i:[EditInput]!){ stixSightingRelationshipEdit(id:$id){ fieldPatch(input:$i){ id } } }",
              {"id": n["id"], "i": [{"key": "attribute_count", "value": [str(int(n.get("attribute_count") or 0) + count)]},
                                    {"key": "last_seen", "value": [last]}]})
        return "updated"
    cli.q("mutation($i:StixSightingRelationshipAddInput!){ stixSightingRelationshipAdd(input:$i){ id } }",
          {"i": {"fromId": ind, "toId": ident, "first_seen": first, "last_seen": last, "attribute_count": max(1, count),
                 "description": desc, "createdBy": ident, "x_opencti_negative": False, "confidence": 80}})
    return "created"


def report_sightings(hits, window_min=20):
    """hits: [{"value", "feeds", "count", "sources"}] matched on an OpenCTI list. Never raises (watch.py must go on)."""
    try:
        cfg = integrations.opencti()
        hits = [h for h in hits if any(f.startswith("opencti_") for f in h.get("feeds") or ())]
        if not (cfg["usable"] and cfg["sightings"] and hits):
            return {"sent": 0}
        cli, st = Client(cfg), store.jload(STATE, {}) or {}
        ident = _ident(cli, st)
        now = time.time()
        first, last = _now_iso(now - window_min * 60), _now_iso(now)
        merged = {}
        for h in hits:
            m = merged.setdefault(h["value"], {"count": 0, "sources": set()})
            m["count"] += int(h.get("count") or 1)
            m["sources"].update(map(str, h.get("sources") or ()))
        out = {"created": 0, "updated": 0, "no_indicator": 0}
        for v, m in merged.items():
            ind = _find_indicator(cli, v)
            if not ind:
                out["no_indicator"] += 1
                continue
            src = ", ".join(sorted(m["sources"])[:5])
            out[sight(cli, ident, ind, m["count"], first, last, f"netmon saw {v} in home network traffic" + (f" (from {src})" if src else ""))] += 1
        st["sightings_total"] = int(st.get("sightings_total") or 0) + out["created"] + out["updated"]
        st["last_sighting"] = _now_iso(now)
        store.jdump(st, STATE)
        return {"sent": out["created"] + out["updated"], **out}
    except Exception as e:  # noqa: BLE001
        _note_error("sightings: " + err_text(e))
        return {"sent": 0, "error": err_text(e)}


def _ident(cli, st):
    import site_cfg
    name = f"netmon ({site_cfg.get('site_name') or 'home'})"
    if st.get("identity_name") != name or not st.get("identity_id"):
        st.update(identity_id=cli.identity(name), identity_name=name)
    return st["identity_id"]


def _note_error(msg):
    try:
        st = store.jload(STATE, {}) or {}
        st.update(last_error=msg, last_error_at=_now_iso())
        store.jdump(st, STATE)
    except Exception:  # noqa: BLE001
        pass


# ------------------------------------------------------------------ incidents
def _gkey(eid):
    try:
        app = os.path.join(NM, "dashboard", "app")
        if app not in sys.path:
            sys.path.append(app)
        import eventstore
        return eventstore.gkey(eid)
    except Exception:  # noqa: BLE001
        return eid


def _is_external(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if a.is_private or a.is_loopback or a.is_link_local or a.is_multicast or a.is_reserved:
        return False
    try:
        import site_cfg
        return not site_cfg.is_internal(ip)
    except Exception:  # noqa: BLE001
        return True


def observables(doc):
    """External IPs and domain names in an event document (internal hosts stay in the description only)."""
    ips, doms = [], []
    item = doc.get("item") or {}
    for ip in (doc.get("ips") or []) + (doc.get("host_ips") or []) + (doc.get("dst_ips") or []) + [item.get("src"), item.get("dst")]:
        if ip and _is_external(str(ip)) and ip not in ips:
            ips.append(str(ip))
    for a in doc.get("arts") or []:
        if len(a) >= 2 and a[0] == "dns" and a[1] and "." in a[1] and not a[1].endswith((".lan", ".local", ".arpa", ".internal")):
            d = a[1].lower().rstrip(".")
            if d not in doms:
                doms.append(d)
    return ips[:10], doms[:10]


def candidates(cfg, now=None):
    """Open events labelled suspicious at/above the configured severity and confidence, seen in the last week."""
    now = now or time.time()
    min_rank = SEV_RANK[cfg["incident_min_sev"]]
    cutoff = dt.datetime.fromtimestamp(now - INCIDENT_LOOKBACK_D * 86400, dt.timezone.utc).isoformat()
    cls_db = os.path.join(os.path.dirname(STATE), "corr_llm.db")
    if not os.path.exists(cls_db):
        return []
    cls = sqlite3.connect(f"file:{cls_db}?mode=ro", uri=True)
    try:
        labels = {r[0]: (r[1], r[2], r[3]) for r in cls.execute("SELECT eid, label, confidence, reason FROM event_class")}
    finally:
        cls.close()
    out = []
    for r in store.connect().execute("SELECT eid, type, label, sev, first_seen, last_seen, n, doc FROM events WHERE resolved=0 AND last_seen>=?", (cutoff,)):
        eid, typ, label, sev, fs, ls, n, doc = r
        c = labels.get(eid)
        if SEV_RANK.get(str(sev).lower(), 0) < min_rank or not c or c[0] != "suspicious" or float(c[1] or 0) < cfg["incident_min_conf"]:
            continue
        try:
            d = json.loads(doc or "{}")
        except ValueError:
            d = {}
        out.append({"eid": eid, "gkey": _gkey(eid), "type": typ, "label": label, "sev": str(sev).lower(), "first_seen": fs,
                    "last_seen": ls, "n": n, "doc": d, "confidence": float(c[1]), "reason": c[2] or ""})
    out.sort(key=lambda x: x["last_seen"], reverse=True)  # newest first within a severity
    out.sort(key=lambda x: -SEV_RANK[x["sev"]])            # most severe first (stable sort)
    return out


def report_incidents(cli, cfg, st, ident):
    known = st.setdefault("incidents", {})
    made = updated = 0
    for ev in candidates(cfg):
        k = ev["gkey"]
        if k in known:
            if known[k].get("last_seen") != ev["last_seen"]:
                cli.q("mutation($id:ID!, $i:[EditInput]!){ stixDomainObjectEdit(id:$id){ fieldPatch(input:$i){ id } } }",
                      {"id": known[k]["id"], "i": [{"key": "last_seen", "value": [_iso(ev["last_seen"])]}]})
                known[k]["last_seen"] = ev["last_seen"]
                updated += 1
            continue
        if made >= NEW_INCIDENTS_PER_RUN:
            continue
        desc = (f"{ev['label']}\n\nnetmon {ev['type']} event `{ev['eid']}`, severity {ev['sev']}, seen {ev['n']} time(s) "
                f"between {ev['first_seen'][:19]} and {ev['last_seen'][:19]} UTC.\n\nReviewer ({ev['confidence']:.0%} suspicious): {ev['reason']}")
        inc = cli.q("mutation($i:IncidentAddInput!){ incidentAdd(input:$i){ id } }", {"i": {
            "name": ("netmon: " + ev["label"])[:250], "description": desc[:5000], "severity": OCTI_SEV[ev["sev"]],
            "incident_type": "alert", "source": "netmon", "first_seen": _iso(ev["first_seen"]), "last_seen": _iso(ev["last_seen"]),
            "confidence": int(round(ev["confidence"] * 100)), "objectLabel": ["netmon", "netmon-" + ev["type"]], "createdBy": ident}})["incidentAdd"]["id"]
        ips, doms = observables(ev["doc"])
        for kind, vals in (("IPv4-Addr", [i for i in ips if ":" not in i]), ("IPv6-Addr", [i for i in ips if ":" in i]), ("Domain-Name", doms)):
            arg = {"IPv4-Addr": "IPv4Addr", "IPv6-Addr": "IPv6Addr", "Domain-Name": "DomainName"}[kind]
            for v in vals:
                o = cli.q('mutation($v:%sAddInput){ stixCyberObservableAdd(type:"%s", %s:$v, createdBy:"%s", objectLabel:["netmon"]){ id } }'
                          % (arg, kind, arg, ident), {"v": {"value": v}})["stixCyberObservableAdd"]["id"]
                cli.q("mutation($i:StixCoreRelationshipAddInput!){ stixCoreRelationshipAdd(input:$i){ id } }",
                      {"i": {"fromId": o, "toId": inc, "relationship_type": "related-to", "createdBy": ident}})
        known[k] = {"id": inc, "last_seen": ev["last_seen"], "eid": ev["eid"], "at": _now_iso()}
        made += 1
    cut = _now_iso(time.time() - 90 * 86400)
    st["incidents"] = {k: v for k, v in known.items() if (v.get("at") or "") >= cut or (v.get("last_seen") or "") >= cut[:10]}
    st["incidents_total"] = len(st["incidents"])
    return {"created": made, "updated": updated}


# ------------------------------------------------------------------ one pass
def run(force_full=False):
    cfg = integrations.opencti()
    st = store.jload(STATE, {}) or {}
    if not cfg["usable"] or not cfg["pull"]:
        remove_local()  # switched off: stale indicators must not keep alerting
    if not cfg["usable"]:
        return {"enabled": False}
    out: dict = {"enabled": True}
    try:
        cli = Client(cfg)
        if cfg["pull"]:
            out["pull"] = pull(cli, cfg, st, force_full)
        if cfg["incidents"]:
            out["incidents"] = report_incidents(cli, cfg, st, _ident(cli, st))
            st["last_report"] = _now_iso()
        st["last_error"] = None
    except Exception as e:  # noqa: BLE001
        st.update(last_error=err_text(e), last_error_at=_now_iso())
        out["error"] = err_text(e)
    store.jdump(st, STATE)
    return out


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "run"
    if cmd == "check":
        c = integrations.opencti()
        print(json.dumps(Client(c).check() if c["url"] and c["api_key"] else {"error": "not configured"}, indent=1))
    elif cmd == "run":
        print(json.dumps(run(force_full="--full" in sys.argv), indent=1))
    else:
        sys.exit(__doc__)
