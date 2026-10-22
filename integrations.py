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
import json, os, ssl, sys, tempfile, time, urllib.error, urllib.request

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


def web():
    """Web search backend for the AI research job and chat: {provider, api_key}."""
    w = load().get("web") or {}
    p = w.get("provider") if w.get("provider") in WEB_PROVIDERS else "duckduckgo"
    k = w.get("api_key") or host_secret({"firecrawl": "FIRECRAWL_API_KEY", "brave": "BRAVE_API_KEY", "tavily": "TAVILY_API_KEY"}.get(p, "-"))
    return {"provider": p if (p == "duckduckgo" or k) else "duckduckgo", "api_key": k if p != "duckduckgo" else ""}


# ------------------------------------------------------------------ dashboard
def _mask(k):
    return f"••••{k[-4:]}" if k and len(k) > 8 else ("••••" if k else "")


def public():
    """What the Configuration page shows: values + source of each, keys masked."""
    d = load()
    e, u, a, w = d.get("elasticsearch") or {}, d.get("unifi") or {}, d.get("audit") or {}, d.get("web") or {}
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
            "updated_by": w.get("updated_by"), "updated_at": w.get("updated_at")},
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


def candidate(section, body):
    """Merged section dict from a form post, without saving. Empty api_key keeps the current one unless clear_key."""
    cur = dict(load().get(section) or {})
    new = {} if section in ("audit", "web") else {"url": _clean_url(body.get("url"))}
    if section == "web":
        if body.get("provider") not in WEB_PROVIDERS:
            raise ValueError("unknown web search provider")
        new["provider"] = body["provider"]
        if new["provider"] != cur.get("provider") and not body.get("api_key"):
            cur["api_key"] = ""  # a key belongs to one provider: never send it to another
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
    if section not in ("elasticsearch", "unifi", "audit", "web"):
        raise ValueError("unknown integration")
    d = load()
    d[section] = {**candidate(section, body), "updated_by": user, "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
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
        if prov != "duckduckgo" and not c.get("api_key"):
            return {"ok": False, "error": "enter the API key to test it"}
        try:
            res = webtools.search("Security Onion documentation", 3, cfg={"provider": prov, "api_key": c.get("api_key") or ""})
            return {"ok": bool(res), "provider": prov, "results": len(res), "error": "" if res else "no results"}
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "provider": prov, "error": str(e)[:300]}
    raise ValueError("unknown integration")


if __name__ == "__main__":
    if sys.argv[1:2] == ["show"]:
        p = public()
        p["effective"] = {"es_url": es_url(), "es_key": _mask(es_key()), "indices": {n: es_index(n) for n in INDEX_DEFAULTS},
                          "unifi_url": unifi_url(), "unifi_key": _mask(unifi_key())}
        print(json.dumps(p, indent=1))
    else:
        print(__doc__)
