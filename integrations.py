#!/usr/bin/python3
"""Integration settings (dashboard: More -> Configuration -> Integrations): Elasticsearch, UniFi API, web search.

Saved by the dashboard to dashboard/state/integrations.json (git-ignored, mode 0600; the container's writable /state).
The pipeline (collect/watch/extras/mitre/esq/hostdetail/unifi) reads it first and falls back to the original places, so
an empty dashboard setting changes nothing:
  Elasticsearch URL      -> site.json es_url
  Elasticsearch API key  -> host secrets file ES_API_KEY (see below)
  indices                -> the Security Onion defaults below
  UniFi API URL          -> https://api.ui.com
  UniFi API key          -> host secrets file UNIFI_API_KEY
  web search             -> DuckDuckGo (no key); Firecrawl, Brave or Tavily with a key (AI research + chat, webtools.py)
Host secrets file: $NETMON_SECRETS (default ~/.config/netmon/secrets.env, mode 0600, KEY=value lines). It lives outside the
repo, so the dashboard container (which mounts the repo read-only) can't read it.
API keys are never sent back to the browser (public() returns a masked hint only).

CLI: integrations.py show            effective settings (keys masked) and where each value comes from
"""
import json, os, re, ssl, sys, time, urllib.error, urllib.request

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
import site_cfg as SITE  # noqa: E402

SECRETS = os.environ.get("NETMON_SECRETS") or os.path.expanduser("~/.config/netmon/secrets.env")
# the Security Onion index each collector queries; the dashboard can point each one somewhere else
INDEX_DEFAULTS = {"zeek": "logs-zeek-so", "suricata": "logs-suricata.alerts-so", "detections": "logs-detections.alerts-so"}
INDEX_LABELS = {"zeek": "Network logs (Zeek: conn, dns, ssl, dhcp, notice…)", "suricata": "IDS alerts (Suricata)",
                "detections": "Detection rule hits (Security Onion detections)"}
UNIFI_DEFAULT = "https://api.ui.com"
AUDIT_INDEX = "logs-netmon"  # dashboard audit log (dashboard/app/audit.py); its own key: create_doc + read on this index only
WEB_PROVIDERS = {"duckduckgo": "DuckDuckGo (no key)", "firecrawl": "Firecrawl", "brave": "Brave Search", "tavily": "Tavily"}
FIRECRAWL_DEFAULT = "https://api.firecrawl.dev"  # Firecrawl cloud; a self-hosted instance gets its own URL (key optional)
# OpenCTI threat-intel platform (opencti.py): pull indicators into the feed matcher, report sightings/incidents back.
OPENCTI_DEFAULTS = {"enabled": False, "ca_pem": "", "pull": True, "min_score": 50, "high_score": 80,
                    "sightings": True, "incidents": False, "incident_min_sev": "high", "incident_min_conf": 0.8}
OPENCTI_SEVS = ("urgent", "high", "medium", "low")
# Kubernetes API (kube_api.py): read-only ServiceAccount token for the CIS benchmark (kube_cis.py) and the map (kube_map.py).
KUBE_DEFAULTS = {"enabled": False, "cis": True}
OPENCTI_STATE = os.path.join(os.environ.get("STATE_DIR") or ("/state" if os.path.isdir("/state") else os.path.join(_HERE, "dashboard", "state")),
                             "opencti_sync.json")  # a docs-table document (store.DOC_FILES), never a file


def path():
    if os.environ.get("NETMON_INTEGRATIONS"):
        return os.environ["NETMON_INTEGRATIONS"]
    return os.path.join(_HERE, "dashboard", "state", "integrations.json")


_cache = {"k": None, "v": {}}


def load():
    p = path()
    try:
        import store
        mt = store.jmtime(p)
        k = (p, mt)
        if _cache["k"] != k:
            d = store.jload(p, {})
            _cache.update(k=k, v=d if isinstance(d, dict) else {})
        return _cache["v"]
    except (OSError, ValueError):
        return {}


def host_secret(name):
    """One KEY=value from the host secrets file (empty if missing or unreadable, e.g. inside the dashboard container)."""
    try:
        for line in open(SECRETS):
            if line.startswith(name + "="):
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    except OSError:
        pass
    return ""


def _env_es_key():
    return host_secret("ES_API_KEY")


def _file_unifi_key():
    return host_secret("UNIFI_API_KEY")


# ------------------------------------------------------------------ effective values (pipeline)
def es_url():
    return (os.environ.get("ES_URL") or (load().get("elasticsearch") or {}).get("url") or SITE.get("es_url") or "").rstrip("/")


def es_key():
    return os.environ.get("ES_API_KEY") or (load().get("elasticsearch") or {}).get("api_key") or _env_es_key()


def es_index(name):
    return ((load().get("elasticsearch") or {}).get("indices") or {}).get(name) or INDEX_DEFAULTS[name]


def map_index(index):
    """Translate a default Security Onion index name used in the code to the configured one."""
    rev = {v: k for k, v in INDEX_DEFAULTS.items()}
    return ",".join(es_index(rev[p]) if p in rev else p for p in str(index).split(","))


def audit_key():
    return (load().get("audit") or {}).get("api_key") or os.environ.get("NETMON_AUDIT_ES_KEY") or ""


def audit_index():
    return (load().get("audit") or {}).get("index") or AUDIT_INDEX


def audit_send(who):
    """Is the audit log (logs-netmon) written for this background actor? who: "reviewer" | "researcher". On unless switched off."""
    return (load().get("audit") or {}).get("send_" + who) is not False


def unifi_url():
    return ((load().get("unifi") or {}).get("url") or UNIFI_DEFAULT).rstrip("/")


def unifi_key():
    return (load().get("unifi") or {}).get("api_key") or _file_unifi_key()


def _web_eff(w, host_fallback=True):
    """Effective web settings from a stored/candidate section: {provider, api_key, url, ca_pem}.
    Firecrawl: url = the instance (blank = cloud). A self-hosted instance works without a key, and the host
    secrets file key (meant for the cloud) is never sent to it."""
    p = w.get("provider") if w.get("provider") in WEB_PROVIDERS else "duckduckgo"
    url = (w.get("url") or "").rstrip("/") if p == "firecrawl" else ""
    own = bool(url) and url != FIRECRAWL_DEFAULT
    k = w.get("api_key") or ""
    if not k and host_fallback and not own:
        k = host_secret({"firecrawl": "FIRECRAWL_API_KEY", "brave": "BRAVE_API_KEY", "tavily": "TAVILY_API_KEY"}.get(p, "-"))
    ok = p == "duckduckgo" or bool(k) or own
    return {"provider": p if ok else "duckduckgo", "api_key": k if ok and p != "duckduckgo" else "",
            "url": (url or FIRECRAWL_DEFAULT) if ok and p == "firecrawl" else "",
            "ca_pem": (w.get("ca_pem") or "") if ok and own else ""}


def web():
    """Web search backend for the AI research job and chat: {provider, api_key, url, ca_pem}."""
    return _web_eff(load().get("web") or {})


def opencti():
    """Effective OpenCTI settings (defaults filled in). Usable only when enabled with a URL and an API token."""
    o = {**OPENCTI_DEFAULTS, **(load().get("opencti") or {})}
    o["url"] = (o.get("url") or "").rstrip("/")
    o["api_key"] = o.get("api_key") or ""
    o["usable"] = bool(o["enabled"] and o["url"] and o["api_key"])
    return o


KUBE_NAME = re.compile(r"^[a-z0-9][a-z0-9-]{0,39}$")


def _kube_raw():
    """{name: stored cluster settings}. Older single-cluster settings (flat url/api_key) read as cluster "default"."""
    raw = load().get("kubernetes") or {}
    if "clusters" in raw:
        return dict(raw["clusters"] or {})
    return {"default": raw} if raw.get("url") or raw.get("api_key") else {}


def _kube_eff(name, k):
    k = {**KUBE_DEFAULTS, **(k or {}), "name": name}
    k["url"], k["api_key"], k["ca_pem"] = (k.get("url") or "").strip(), k.get("api_key") or "", k.get("ca_pem") or ""
    k["usable"] = bool(k["enabled"] and k["url"] and k["api_key"])
    return k


def kube_clusters():
    """Every configured Kubernetes cluster, effective settings, in name order."""
    return [_kube_eff(n, c) for n, c in sorted(_kube_raw().items())]


def kubernetes(name=None):
    """One cluster's effective settings {name, enabled, cis, url, api_key (bearer token), ca_pem, usable}; name None = the
    first usable cluster (else the first one, else an empty disabled entry)."""
    cs = kube_clusters()
    if name is not None:
        return next((c for c in cs if c["name"] == name), _kube_eff(name, {}))
    return next((c for c in cs if c["usable"]), cs[0] if cs else _kube_eff("default", {}))


# ------------------------------------------------------------------ dashboard
def _mask(k):
    return f"••••{k[-4:]}" if k and len(k) > 8 else ("••••" if k else "")


def _feeds_public(d):
    try:
        import extras
        rows = extras.feed_list()
        kinds = extras.FEED_KINDS
    except Exception:  # noqa: BLE001
        rows, kinds = [], {}
    f = d.get("feeds") or {}
    return {"items": rows, "kinds": kinds, "updated_by": f.get("updated_by"), "updated_at": f.get("updated_at")}


def public():
    """What the Configuration page shows: values + source of each, keys masked."""
    d = load()
    e, u, a, w = d.get("elasticsearch") or {}, d.get("unifi") or {}, d.get("audit") or {}, d.get("web") or {}
    oc = opencti()
    try:
        import store
        oc_status = store.jload(OPENCTI_STATE, {}) or {}
    except Exception:  # noqa: BLE001
        oc_status = {}
    in_container = bool(os.environ.get("NETMON_IN_DASHBOARD"))
    host_es, host_un = (None, None) if in_container else (bool(_env_es_key()), bool(_file_unifi_key()))
    return {
        "elasticsearch": {
            "url": e.get("url") or "", "url_fallback": SITE.get("es_url") or "",
            "key_set": bool(e.get("api_key")), "key_hint": _mask(e.get("api_key") or ""), "key_fallback": "host secrets file ES_API_KEY",
            "key_fallback_present": host_es,
            "indices": {k: (e.get("indices") or {}).get(k) or "" for k in INDEX_DEFAULTS},
            "index_defaults": INDEX_DEFAULTS, "index_labels": INDEX_LABELS,
            "updated_by": e.get("updated_by"), "updated_at": e.get("updated_at")},
        "unifi": {
            "url": u.get("url") or "", "url_fallback": UNIFI_DEFAULT,
            "key_set": bool(u.get("api_key")), "key_hint": _mask(u.get("api_key") or ""), "key_fallback": "host secrets file UNIFI_API_KEY",
            "key_fallback_present": host_un,
            "updated_by": u.get("updated_by"), "updated_at": u.get("updated_at")},
        "audit": {
            "index": a.get("index") or "", "index_default": AUDIT_INDEX, "key_set": bool(a.get("api_key") or os.environ.get("NETMON_AUDIT_ES_KEY")),
            "key_hint": _mask(a.get("api_key") or os.environ.get("NETMON_AUDIT_ES_KEY") or ""),
            "send_reviewer": audit_send("reviewer"), "send_researcher": audit_send("researcher"),
            "updated_by": a.get("updated_by"), "updated_at": a.get("updated_at")},
        "web": {
            "provider": w.get("provider") or "duckduckgo", "providers": WEB_PROVIDERS,
            "key_set": bool(w.get("api_key")), "key_hint": _mask(w.get("api_key") or ""),
            "key_fallback": "the host secrets file (FIRECRAWL_API_KEY / BRAVE_API_KEY / TAVILY_API_KEY)",
            "url": w.get("url") or "", "url_fallback": FIRECRAWL_DEFAULT, "ca_set": bool(w.get("ca_pem")),
            "updated_by": w.get("updated_by"), "updated_at": w.get("updated_at")},
        "feeds": _feeds_public(d),
        "kubernetes": {"clusters": [{"name": kb["name"], "enabled": kb["enabled"], "cis": kb["cis"], "url": kb["url"], "ca_set": bool(kb["ca_pem"]),
                                     "key_set": bool(kb["api_key"]), "key_hint": _mask(kb["api_key"]),
                                     "updated_by": kb.get("updated_by"), "updated_at": kb.get("updated_at")} for kb in kube_clusters()]},
        "opencti": {
            **{k: oc[k] for k in OPENCTI_DEFAULTS if k != "ca_pem"}, "url": oc["url"], "ca_set": bool(oc.get("ca_pem")),
            "key_set": bool(oc["api_key"]), "key_hint": _mask(oc["api_key"]), "sevs": list(OPENCTI_SEVS),
            "status": {k: oc_status.get(k) for k in ("last_pull", "last_full", "indicators", "high", "hashes", "filenames", "last_report",
                                                     "sightings_total", "incidents_total", "last_error")},
            "updated_by": (d.get("opencti") or {}).get("updated_by"), "updated_at": (d.get("opencti") or {}).get("updated_at")},
    }


def _clean_url(v):
    v = str(v or "").strip().rstrip("/")
    if v and not (v.startswith("https://") or v.startswith("http://")) or any(c in v for c in " \"'<>\n\r\t"):
        raise ValueError("URL must start with https:// (or http://) and contain no spaces or quotes")
    return v[:300]


def _clean_index(v):
    v = str(v or "").strip()
    if v and (len(v) > 200 or any(c in v for c in " \"'<>\\/?#\n\r\t") or v.startswith(("_", "-", "+"))):
        raise ValueError(f"invalid index pattern {v!r} (no spaces, slashes or quotes; comma-separated patterns and * are fine)")
    return v


def _clean_key(v):
    v = str(v or "").strip()
    if v and (len(v) > 400 or any(c.isspace() for c in v)):
        raise ValueError("API key looks wrong (spaces or too long)")
    return v


def _num(v, lo, hi, name, cast=int):
    try:
        n = cast(v)
    except (TypeError, ValueError):
        raise ValueError(f"{name} must be a number") from None
    if not lo <= n <= hi:
        raise ValueError(f"{name} must be between {lo} and {hi}")
    return n


def _clean_pem(v):
    v = str(v or "").strip()
    if v and ("-----BEGIN CERTIFICATE-----" not in v or len(v) > 20000):
        raise ValueError("CA certificate must be PEM text (-----BEGIN CERTIFICATE----- ...)")
    if v:
        ssl.create_default_context(cadata=v)  # parse check: raises ssl.SSLError on a bad certificate
    return v


def _opencti_candidate(cur, body):
    new = {"url": _clean_url(body.get("url")) if "url" in body else cur.get("url", "")}
    for b in ("enabled", "pull", "sightings", "incidents"):
        new[b] = bool(body[b]) if b in body else cur.get(b, OPENCTI_DEFAULTS[b])
    if "min_score" in body:
        new["min_score"] = _num(body["min_score"], 0, 100, "minimum score")
    if "high_score" in body:
        new["high_score"] = _num(body["high_score"], 0, 100, "high-confidence score")
    if "incident_min_conf" in body:
        new["incident_min_conf"] = _num(body["incident_min_conf"], 0.5, 1.0, "incident minimum confidence", float)
    if "incident_min_sev" in body:
        if body["incident_min_sev"] not in OPENCTI_SEVS:
            raise ValueError("unknown severity")
        new["incident_min_sev"] = body["incident_min_sev"]
    if body.get("clear_ca"):
        new["ca_pem"] = ""
    elif body.get("ca_pem"):
        try:
            new["ca_pem"] = _clean_pem(body["ca_pem"])
        except ssl.SSLError as e:
            raise ValueError(f"CA certificate is not valid: {e}") from None
    if new.get("enabled") and not new["url"]:
        raise ValueError("enter the OpenCTI URL before enabling it")
    return new


def _kube_candidate(cur, body):
    """url: one or more https:// API server URLs (comma-separated, tried in order); api_key: ServiceAccount token (write-only)."""
    new = {}
    if "url" in body:
        urls = [u.strip() for u in str(body.get("url") or "").split(",") if u.strip()]
        if len(urls) > 5:
            raise ValueError("at most 5 API server URLs")
        new["url"] = ",".join(_clean_url(u) for u in urls)
        if any(not u.startswith("https://") for u in new["url"].split(",") if u):
            raise ValueError("Kubernetes API URLs must start with https://")
    else:
        new["url"] = cur.get("url", "")
    for b in ("enabled", "cis"):
        new[b] = bool(body[b]) if b in body else cur.get(b, KUBE_DEFAULTS[b])
    tok = str(body.get("api_key") or "").strip()
    if tok and (len(tok) > 4096 or any(c.isspace() for c in tok)):
        raise ValueError("the token is one line of text (a ServiceAccount JWT)")
    new["api_key"] = "" if body.get("clear_key") else (tok or cur.get("api_key") or "")
    if body.get("clear_ca"):
        new["ca_pem"] = ""
    elif body.get("ca_pem"):
        try:
            new["ca_pem"] = _clean_pem(body["ca_pem"])
        except ssl.SSLError as e:
            raise ValueError(f"CA certificate is not valid: {e}") from None
    else:
        new["ca_pem"] = cur.get("ca_pem", "")
    if new["enabled"] and not (new["url"] and new["api_key"]):
        raise ValueError("enter the API server URL and the token before enabling it")
    return new


FEED_NAME = re.compile(r"^[a-z][a-z0-9_]{1,39}$")
MAX_CUSTOM_FEEDS = 40


def _clean_feed_url(v):
    v = str(v or "").strip()
    if v and (not v.startswith(("https://", "http://")) or any(c in v for c in " \"'<>\n\r\t") or len(v) > 500):
        raise ValueError("feed URL must start with https:// (or http://), contain no spaces or quotes, at most 500 characters")
    return v


def _feeds_candidate(cur, body):
    """body: {"items": [{name, url, kind, enabled, serious, opencti}], "delete": [names]}. Built-ins keep their kind;
    a blank URL means the built-in default. Custom feeds need a name, an http(s) URL and a kind."""
    import extras
    items = {k: dict(v) for k, v in ((cur.get("items") or {}).items())}
    for n in body.get("delete") or []:
        if n in extras.FEEDS:
            raise ValueError(f"{n} is built in: turn it off instead of deleting it")
        items.pop(n, None)
    for it in body.get("items") or []:
        n = str(it.get("name") or "").strip().lower()
        if not FEED_NAME.match(n) or n.startswith("opencti_"):
            raise ValueError(f"feed name '{n}': 2-40 characters, a-z, 0-9 and _, starting with a letter (opencti_ is reserved)")
        url = _clean_feed_url(it.get("url"))
        e = {"enabled": bool(it.get("enabled", True)), "serious": bool(it.get("serious")), "opencti": bool(it.get("opencti"))}
        if n in extras.FEEDS:
            e["url"] = "" if url == extras.FEEDS[n][0] else url
        else:
            if not url:
                raise ValueError(f"feed {n}: enter its URL")
            if it.get("kind") not in extras.FEED_KINDS:
                raise ValueError(f"feed {n}: choose what the list holds")
            e.update(url=url, kind=it["kind"], custom=True)
        items[n] = e
    if sum(1 for v in items.values() if v.get("custom")) > MAX_CUSTOM_FEEDS:
        raise ValueError(f"at most {MAX_CUSTOM_FEEDS} custom feeds")
    return {"items": items}


def candidate(section, body):
    """Merged section dict from a form post, without saving. Empty api_key keeps the current one unless clear_key."""
    cur = dict(load().get(section) or {})
    if section == "feeds":
        return _feeds_candidate(cur, body)
    if section == "kubernetes":  # body.cluster = which cluster (new name = add one); body.delete = remove it
        name = str(body.get("cluster") or "").strip().lower()
        if not KUBE_NAME.match(name):
            raise ValueError("cluster name: 1-40 lower-case letters, digits and dashes")
        cls = _kube_raw()
        if body.get("delete"):
            cls.pop(name, None)
        else:
            cls[name] = {**cls.get(name, {}), **_kube_candidate(cls.get(name, {}), body)}
        return {"clusters": cls, "_cluster": name}
    if section == "opencti":
        new = _opencti_candidate(cur, body)
        k = _clean_key(body.get("api_key"))
        new["api_key"] = "" if body.get("clear_key") else (k or cur.get("api_key") or "")
        return {**cur, **new}
    new = {} if section in ("audit", "web") else {"url": _clean_url(body.get("url"))}
    if section == "web":
        if body.get("provider") not in WEB_PROVIDERS:
            raise ValueError("unknown web search provider")
        new["provider"] = body["provider"]
        new["url"] = _clean_url(body.get("url")) if "url" in body else cur.get("url", "")
        if (new["provider"] != cur.get("provider") or new["url"] != cur.get("url", "")) and not body.get("api_key"):
            cur["api_key"] = ""  # a key belongs to one provider / Firecrawl instance: never send it to another
        if body.get("clear_ca"):
            new["ca_pem"] = ""
        elif body.get("ca_pem"):
            try:
                new["ca_pem"] = _clean_pem(body["ca_pem"])
            except ssl.SSLError as e:
                raise ValueError(f"CA certificate is not valid: {e}") from None
    k = _clean_key(body.get("api_key"))
    new["api_key"] = "" if body.get("clear_key") else (k or cur.get("api_key") or "")
    if section == "elasticsearch":
        ix = body.get("indices") or {}
        new["indices"] = {n: _clean_index(ix.get(n)) for n in INDEX_DEFAULTS}
    if section == "audit":
        if "index" in body or "api_key" in body or body.get("clear_key"):  # a switch-only post leaves the index alone
            ix = _clean_index(body.get("index"))
            if "," in ix or "*" in ix:
                raise ValueError("the audit index must be one concrete index name (no commas or wildcards)")
            new["index"] = ix
        for w in ("reviewer", "researcher"):  # on/off switches; absent from the form = keep the current value
            if "send_" + w in body:
                new["send_" + w] = bool(body["send_" + w])
    return {**cur, **new}


def save(section, body, user):
    if section not in ("elasticsearch", "unifi", "audit", "web", "opencti", "feeds", "kubernetes"):
        raise ValueError("unknown integration")
    d = load()
    c = candidate(section, body)
    stamp = {"updated_by": user, "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    if section == "kubernetes":  # stamp the cluster that changed, not the whole section
        name = c.pop("_cluster")
        if name in c["clusters"]:
            c["clusters"][name].update(stamp)
        d[section] = c
    else:
        d[section] = {**c, **stamp}
    p = path()
    import store
    store.jdump(d, p)
    _cache["k"] = None
    return public()


def _http(url, headers, data=None, timeout=15, verify=True):
    if not url.startswith(("https://", "http://")):
        raise ValueError("only http(s) URLs")
    req = urllib.request.Request(url, data=data, headers=headers, method="POST" if data is not None else "GET")
    # Security Onion ES uses its own CA (same as collect.py); everything else (UniFi) verifies TLS normally
    ctx = None if verify or not url.startswith("https://") else ssl._create_unverified_context()
    with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
        return json.load(r)


def _err(e):
    if isinstance(e, urllib.error.HTTPError):
        try:
            body = json.load(e).get("error")
            body = body.get("reason") if isinstance(body, dict) else body
        except Exception:  # noqa: BLE001
            body = ""
        return f"HTTP {e.code} {e.reason}" + (f": {str(body)[:200]}" if body else "")
    return str(getattr(e, "reason", e))[:200]


def test_feed(body):
    """Download one feed URL and count what it parses into as the chosen kind."""
    import extras
    kind = body.get("kind") or "hosts"
    if kind not in extras.FEED_KINDS:
        return {"ok": False, "error": "unknown list type"}
    try:
        url = _clean_feed_url(body.get("url"))
        if not url:
            return {"ok": False, "error": "enter a URL"}
        req = urllib.request.Request(url, headers={"User-Agent": "netmon/1.0 (home SOC)"})  # noqa: S310 - _clean_feed_url allows http(s) only
        with urllib.request.urlopen(req, timeout=30) as r:  # noqa: S310 - admin-entered http(s) URL
            data = r.read(64 * 1024 * 1024)
        n = extras.count_feed(data.decode("utf-8", "replace"), kind)
        return {"ok": n > 0, "url": url, "entries": n, "bytes": len(data),
                "error": "" if n else f"downloaded {len(data):,} bytes but found no {extras.FEED_KINDS[kind].lower()}"}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": _err(e) if isinstance(e, (urllib.error.URLError,)) else str(e)[:300]}


def test(section, body):
    """Try the settings in the form (unsaved values win; blank fields fall back like the pipeline does)."""
    c = candidate(section, body)
    if section == "elasticsearch":
        url, key = c.get("url") or SITE.get("es_url") or "", c.get("api_key") or _env_es_key()
        if not key:
            return {"ok": False, "error": "no API key here - the host secrets file can't be read from the dashboard; enter one to test"}
        out = {"ok": True, "url": url, "indices": {}}
        for n in INDEX_DEFAULTS:
            ix = (c.get("indices") or {}).get(n) or INDEX_DEFAULTS[n]
            try:
                r = _http(f"{url.rstrip('/')}/{ix}/_search", {"Authorization": f"ApiKey {key}", "Content-Type": "application/json"},
                          json.dumps({"size": 0, "track_total_hits": True, "query": {"range": {"@timestamp": {"gte": "now-24h"}}}}).encode(), verify=False)
                out["indices"][n] = {"index": ix, "ok": True, "docs_24h": (r.get("hits") or {}).get("total", {}).get("value", 0)}
            except Exception as e:  # noqa: BLE001
                out["indices"][n] = {"index": ix, "ok": False, "error": _err(e)}
                out["ok"] = False
        return out
    if section == "audit":  # the audit key must be able to read the index (search) - writing is checked by the writer
        url, key, ix = es_url(), c.get("api_key") or "", c.get("index") or AUDIT_INDEX
        if not key:
            return {"ok": False, "error": "enter the audit API key to test it"}
        try:
            r = _http(f"{url}/{ix}/_count", {"Authorization": f"ApiKey {key}"}, verify=False)
            return {"ok": True, "url": url, "index": ix, "docs": r.get("count", 0)}
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "url": url, "index": ix, "error": _err(e)}
    if section == "unifi":
        url, key = c.get("url") or UNIFI_DEFAULT, c.get("api_key") or _file_unifi_key()
        if not key:
            return {"ok": False, "error": "no API key here - the host key file can't be read from the dashboard; enter one to test"}
        try:
            r = _http(f"{url.rstrip('/')}/v1/hosts", {"X-API-KEY": key, "Accept": "application/json"})
            hosts = r.get("data") or []
            return {"ok": True, "url": url, "consoles": sum(1 for h in hosts if h.get("type") == "console"), "hosts": len(hosts)}
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "url": url, "error": _err(e)}
    if section == "web":
        import webtools
        prov = c.get("provider") or "duckduckgo"
        eff = _web_eff(c, host_fallback=False)
        if eff["provider"] != prov:
            return {"ok": False, "error": "enter the API key to test it" + (" (or the URL of a self-hosted Firecrawl)" if prov == "firecrawl" else "")}
        try:
            res = webtools.search("Security Onion documentation", 3, cfg=eff)
            return {"ok": bool(res), "provider": prov, "results": len(res), "error": "" if res else "no results"}
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "provider": prov, "error": str(e)[:300]}
    if section == "feeds":
        return test_feed(body)
    if section == "kubernetes":
        c = c["clusters"].get(c["_cluster"]) or {}
        if not c.get("url") or not c.get("api_key"):
            return {"ok": False, "error": "enter the API server URL and the ServiceAccount token to test"}
        import kube_api
        try:
            r = kube_api.check(c)
            return {"ok": True, **r, **({"error": "this token can do more than read: " + ", ".join(r["too_much"])} if r["too_much"] else {})}
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "error": str(e)[:300]}
    if section == "opencti":
        if not c.get("url") or not c.get("api_key"):
            return {"ok": False, "error": "enter the OpenCTI URL and API token to test"}
        import opencti
        try:
            return {"ok": True, **opencti.Client({**OPENCTI_DEFAULTS, **c}).check()}
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "url": c["url"], "error": opencti.err_text(e)}
    raise ValueError("unknown integration")


if __name__ == "__main__":
    if sys.argv[1:2] == ["show"]:
        p = public()
        p["effective"] = {"es_url": es_url(), "es_key": _mask(es_key()), "indices": {n: es_index(n) for n in INDEX_DEFAULTS},
                          "unifi_url": unifi_url(), "unifi_key": _mask(unifi_key())}
        print(json.dumps(p, indent=1))
    else:
        print(__doc__)
