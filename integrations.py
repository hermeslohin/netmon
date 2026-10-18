#!/usr/bin/python3
"""Integration settings (dashboard: More -> Configuration -> Integrations): Elasticsearch and UniFi API.

Saved by the dashboard to dashboard/state/integrations.json (git-ignored, mode 0600; the container's writable /state).
The pipeline (collect/watch/extras/mitre/esq/hostdetail/unifi) reads it first and falls back to the original places, so
an empty dashboard setting changes nothing:
  Elasticsearch URL      -> site.json es_url
  Elasticsearch API key  -> ~/.hermes/.env MCP_SO_ELASTICSEARCH_API_KEY
  indices                -> the Security Onion defaults below
  UniFi API URL          -> https://api.ui.com
  UniFi API key          -> ~/.hermes/secrets/unifi_api_key
API keys are never sent back to the browser (public() returns a masked hint only).

CLI: integrations.py show            effective settings (keys masked) and where each value comes from
"""
import json, os, ssl, sys, tempfile, time, urllib.error, urllib.request

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
import site_cfg as SITE  # noqa: E402

HOME = os.environ.get("HERMES_HOME") or os.path.expanduser("~/.hermes")
# the Security Onion index each collector queries; the dashboard can point each one somewhere else
INDEX_DEFAULTS = {"zeek": "logs-zeek-so", "suricata": "logs-suricata.alerts-so", "detections": "logs-detections.alerts-so"}
INDEX_LABELS = {"zeek": "Network logs (Zeek: conn, dns, ssl, dhcp, notice…)", "suricata": "IDS alerts (Suricata)",
                "detections": "Detection rule hits (Security Onion detections)"}
UNIFI_DEFAULT = "https://api.ui.com"
UNIFI_KEY_FILE = os.environ.get("UNIFI_API_KEY_FILE") or os.path.join(HOME, "secrets", "unifi_api_key")
ENV_KEY = "MCP_SO_ELASTICSEARCH_API_KEY"


def path():
    if os.environ.get("NETMON_INTEGRATIONS"):
        return os.environ["NETMON_INTEGRATIONS"]
    return os.path.join(_HERE, "dashboard", "state", "integrations.json")


_cache = {"k": None, "v": {}}


def load():
    p = path()
    try:
        st = os.stat(p)
        k = (p, st.st_mtime_ns, st.st_size)
        if _cache["k"] != k:
            d = json.load(open(p))
            _cache.update(k=k, v=d if isinstance(d, dict) else {})
        return _cache["v"]
    except (OSError, ValueError):
        return {}


def _env_es_key():
    try:
        for line in open(os.path.join(HOME, ".env")):
            if line.startswith(ENV_KEY + "="):
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    except OSError:
        pass
    return ""


def _file_unifi_key():
    try:
        return open(UNIFI_KEY_FILE).read().strip()
    except OSError:
        return ""


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


def unifi_url():
    return ((load().get("unifi") or {}).get("url") or UNIFI_DEFAULT).rstrip("/")


def unifi_key():
    return (load().get("unifi") or {}).get("api_key") or _file_unifi_key()


# ------------------------------------------------------------------ dashboard
def _mask(k):
    return f"••••{k[-4:]}" if k and len(k) > 8 else ("••••" if k else "")


def public():
    """What the Configuration page shows: values + source of each, keys masked."""
    d = load()
    e, u = d.get("elasticsearch") or {}, d.get("unifi") or {}
    in_container = bool(os.environ.get("NETMON_IN_DASHBOARD"))
    host_es, host_un = (None, None) if in_container else (bool(_env_es_key()), bool(_file_unifi_key()))
    return {
        "elasticsearch": {
            "url": e.get("url") or "", "url_fallback": SITE.get("es_url") or "",
            "key_set": bool(e.get("api_key")), "key_hint": _mask(e.get("api_key") or ""), "key_fallback": f"~/.hermes/.env {ENV_KEY}",
            "key_fallback_present": host_es,
            "indices": {k: (e.get("indices") or {}).get(k) or "" for k in INDEX_DEFAULTS},
            "index_defaults": INDEX_DEFAULTS, "index_labels": INDEX_LABELS,
            "updated_by": e.get("updated_by"), "updated_at": e.get("updated_at")},
        "unifi": {
            "url": u.get("url") or "", "url_fallback": UNIFI_DEFAULT,
            "key_set": bool(u.get("api_key")), "key_hint": _mask(u.get("api_key") or ""), "key_fallback": "~/.hermes/secrets/unifi_api_key",
            "key_fallback_present": host_un,
            "updated_by": u.get("updated_by"), "updated_at": u.get("updated_at")},
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
    new = {"url": _clean_url(body.get("url"))}
    k = _clean_key(body.get("api_key"))
    new["api_key"] = "" if body.get("clear_key") else (k or cur.get("api_key") or "")
    if section == "elasticsearch":
        ix = body.get("indices") or {}
        new["indices"] = {n: _clean_index(ix.get(n)) for n in INDEX_DEFAULTS}
    return {**cur, **new}


def save(section, body, user):
    if section not in ("elasticsearch", "unifi"):
        raise ValueError("unknown integration")
    d = load()
    d[section] = {**candidate(section, body), "updated_by": user, "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    p = path()
    os.makedirs(os.path.dirname(p), exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(p), prefix=".integrations.")
    with os.fdopen(fd, "w") as f:
        json.dump(d, f, indent=1)
    os.chmod(tmp, 0o600)
    os.replace(tmp, p)
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
            return {"ok": False, "error": "no API key here - the host key in ~/.hermes/.env can't be read from the dashboard; enter one to test"}
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
    raise ValueError("unknown integration")


if __name__ == "__main__":
    if sys.argv[1:2] == ["show"]:
        p = public()
        p["effective"] = {"es_url": es_url(), "es_key": _mask(es_key()), "indices": {n: es_index(n) for n in INDEX_DEFAULTS},
                          "unifi_url": unifi_url(), "unifi_key": _mask(unifi_key())}
        print(json.dumps(p, indent=1))
    else:
        print(__doc__)
