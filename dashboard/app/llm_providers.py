"""AI providers an admin adds on the AI review page: any OpenAI-compatible or Anthropic API, reached with an API key.

The dashboard calls these APIs itself (no host broker, no Hermes). Each provider is one entry in
/state/llm_providers.json (mode 0600, atomic writes):
  {"id": "a1b2c3", "name": "OpenAI (work key)", "type": "openai" | "anthropic", "base_url": "https://api.openai.com/v1",
   "api_key": "...", "models": ["gpt-5-mini", ...], "rate_per_hour": 120, "reasoning_tokens": 3000, "enabled": true}
In model choices the provider is addressed as "api:<id>" (built-ins stay "lmstudio", "anthropic", "openai-api").
API keys never leave this module: public() returns a masked hint only, and errors are scrubbed of the key.

type "openai": POST {base_url}/chat/completions with "Authorization: Bearer <key>" - OpenAI itself, or any compatible
               service (OpenRouter, Groq, Mistral, Together, DeepSeek, Gemini's OpenAI endpoint, vLLM, ...).
type "anthropic": POST {base_url}/v1/messages with "x-api-key" + "anthropic-version".
No response_format / structured-output mode is sent (not every compatible service supports it); callers ask for
the answer format in the prompt and parse the first JSON object or tagged fields, as they do for the broker's models.
"""
import ipaddress, json, os, re, secrets, threading, time, urllib.error, urllib.parse, urllib.request

STATE = os.environ.get("STATE_DIR", "/state")
PATH = os.path.join(STATE, "llm_providers.json")
TYPES = {"openai": {"label": "OpenAI / OpenAI-compatible", "base_url": "https://api.openai.com/v1"},
         "anthropic": {"label": "Anthropic", "base_url": "https://api.anthropic.com"}}
PREFIX = "api:"
MAX_PROVIDERS, MAX_MODELS = 30, 60
RATE_DEFAULT, RATE_MAX = 120, 3000
ANTHROPIC_VERSION = "2023-06-01"
_lock = threading.Lock()
_sent = {}  # provider id -> [timestamps of calls in the last hour]
_cache = {"k": None, "v": []}


# ---------------------------------------------------------------- storage
def _load():
    try:
        st = os.stat(PATH)
        k = (st.st_mtime_ns, st.st_size)
        if _cache["k"] != k:
            d = json.load(open(PATH))
            _cache.update(k=k, v=[p for p in (d.get("providers") if isinstance(d, dict) else []) or [] if isinstance(p, dict) and p.get("id")])
        return _cache["v"]
    except (OSError, ValueError):
        return []


def _save(providers):
    tmp = PATH + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump({"providers": providers}, f, indent=1)
    os.chmod(tmp, 0o600)
    os.replace(tmp, PATH)
    _cache["k"] = None


def get(pid):
    """Provider by id or by "api:<id>"; None if unknown."""
    pid = str(pid or "")
    pid = pid[len(PREFIX):] if pid.startswith(PREFIX) else pid
    return next((p for p in _load() if p["id"] == pid), None)


def is_custom(provider):
    return isinstance(provider, str) and provider.startswith(PREFIX)


def enabled(provider):
    p = get(provider) if is_custom(provider) else None
    return bool(p and p.get("enabled", True) and p.get("api_key"))


def allowed(provider, model):
    p = get(provider) if is_custom(provider) else None
    return bool(p and p.get("enabled", True) and p.get("api_key") and model in (p.get("models") or []))


def name(provider):
    p = get(provider)
    return (p or {}).get("name") or str(provider)


# ---------------------------------------------------------------- what the browser may see
def _mask(k):
    return f"…{k[-4:]}" if k and len(k) > 12 else ("set" if k else "")


def public():
    """All providers for the admin editor, keys masked."""
    return [{"id": p["id"], "provider": PREFIX + p["id"], "name": p.get("name") or p["id"], "type": p.get("type"),
             "type_label": TYPES.get(p.get("type"), {}).get("label", p.get("type")), "base_url": p.get("base_url") or "",
             "key_set": bool(p.get("api_key")), "key_hint": _mask(p.get("api_key") or ""), "models": list(p.get("models") or []),
             "rate_per_hour": p.get("rate_per_hour") or RATE_DEFAULT, "reasoning_tokens": int(p.get("reasoning_tokens") or 0),
             "enabled": bool(p.get("enabled", True)), "by": p.get("by"), "at": p.get("at"),
             "calls_last_hour": len([t for t in _sent.get(p["id"], []) if time.time() - t < 3600])} for p in _load()]


def model_groups():
    """Usable providers for the model menus (/api/llm/models "custom"): enabled, with a key and at least one model."""
    return [{"provider": PREFIX + p["id"], "name": p.get("name") or p["id"], "type": p.get("type"),
             "models": [{"id": m} for m in p.get("models") or []]}
            for p in _load() if p.get("enabled", True) and p.get("api_key") and p.get("models")]


# ---------------------------------------------------------------- admin edits
def _base_url(typ, url):
    url = (str(url or "").strip() or TYPES[typ]["base_url"]).rstrip("/")
    u = urllib.parse.urlparse(url)
    if u.scheme not in ("http", "https") or not u.hostname or u.username or u.password or u.query or u.fragment:
        raise ValueError("base URL must be a plain http(s) URL without credentials, query or fragment")
    if u.scheme == "http":  # an API key in clear text only to this machine or the LAN (e.g. a self-hosted vLLM)
        try:
            ip = ipaddress.ip_address(u.hostname)
            ok = ip.is_loopback or ip.is_private
        except ValueError:
            ok = u.hostname == "localhost"
        if not ok:
            raise ValueError("http:// is only allowed for loopback or private (LAN) addresses - use https://")
    return url


def _models(v):
    if isinstance(v, str):
        v = re.split(r"[\s,]+", v)
    out = []
    for m in v or []:
        m = str(m).strip()
        if m and m not in out:
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/@+\-]{0,119}", m):
                raise ValueError(f"model id {m[:60]!r} has unexpected characters")
            out.append(m)
    if len(out) > MAX_MODELS:
        raise ValueError(f"at most {MAX_MODELS} models per provider")
    return out


def _int(v, lo, hi, default, what):
    if v in (None, ""):
        return default
    try:
        n = int(v)
    except (TypeError, ValueError):
        raise ValueError(f"{what} must be a whole number") from None
    if not lo <= n <= hi:
        raise ValueError(f"{what} must be {lo}-{hi}")
    return n


def save(body, user):
    """Add (no id) or update (id) a provider. An empty api_key on update keeps the stored key."""
    typ = str(body.get("type") or "")
    if typ not in TYPES:
        raise ValueError("type must be openai or anthropic")
    nm = re.sub(r"[\x00-\x1f<>]", "", str(body.get("name") or "")).strip()[:60]
    if not nm:
        raise ValueError("give the provider a name")
    key = str(body.get("api_key") or "").strip()
    if key and (len(key) > 400 or not re.fullmatch(r"[\x21-\x7e]+", key)):
        raise ValueError("that does not look like an API key")
    rec = {"name": nm, "type": typ, "base_url": _base_url(typ, body.get("base_url")), "models": _models(body.get("models")),
           "rate_per_hour": _int(body.get("rate_per_hour"), 1, RATE_MAX, RATE_DEFAULT, "calls per hour"),
           "reasoning_tokens": _int(body.get("reasoning_tokens"), 0, 32000, 3000 if typ == "openai" else 0, "extra reasoning tokens"),
           "enabled": bool(body.get("enabled", True)), "by": user, "at": time.time()}
    with _lock:
        ps = [dict(p) for p in _load()]
        pid = str(body.get("id") or "")
        if pid:
            cur = next((p for p in ps if p["id"] == pid), None)
            if not cur:
                raise ValueError("unknown provider")
            if (cur.get("type"), cur.get("base_url")) != (rec["type"], rec["base_url"]) and not key:
                raise ValueError("enter the API key again when the type or base URL changes")  # never send a key to a new host unasked
            cur.update(rec)
            if key:
                cur["api_key"] = key
        else:
            if len(ps) >= MAX_PROVIDERS:
                raise ValueError(f"at most {MAX_PROVIDERS} providers")
            if not key:
                raise ValueError("an API key is required")
            cur = {"id": secrets.token_hex(3), **rec, "api_key": key}
            ps.append(cur)
        if any(p["name"].lower() == nm.lower() and p["id"] != cur["id"] for p in ps):
            raise ValueError("another provider already has that name")
        _save(ps)
    return next(p for p in public() if p["id"] == cur["id"])


def delete(pid):
    with _lock:
        ps = [p for p in _load() if p["id"] != pid]
        if len(ps) == len(_load()):
            raise ValueError("unknown provider")
        _save(ps)


# ---------------------------------------------------------------- HTTP
def _scrub(s, key):
    s = str(s)
    if key:
        s = s.replace(key, "[key]")
    return re.sub(r"(sk-|sk-ant-)[A-Za-z0-9_\-]{8,}", r"\1…", s)


def _headers(p, key=None):
    key = key or p.get("api_key") or ""
    if p["type"] == "anthropic":
        return {"x-api-key": key, "anthropic-version": ANTHROPIC_VERSION, "Content-Type": "application/json"}
    return {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}


def _http(p, path, body=None, timeout=300, key=None):
    key = key or p.get("api_key") or ""
    url = p["base_url"].rstrip("/") + path
    req = urllib.request.Request(url, data=json.dumps(body).encode() if body is not None else None, headers=_headers(p, key))
    try:
        return json.load(urllib.request.urlopen(req, timeout=timeout))  # noqa: S310 - scheme/host validated in _base_url
    except urllib.error.HTTPError as e:
        try:
            d = json.load(e)
            msg = (d.get("error") or {}).get("message") if isinstance(d.get("error"), dict) else d.get("error") or d.get("message") or d
        except Exception:  # noqa: BLE001
            msg = e.reason
        raise RuntimeError(_scrub(f"{p.get('name') or p['type']}: HTTP {e.code}: {str(msg)[:300]}", key)) from None
    except (OSError, ValueError) as e:
        raise RuntimeError(_scrub(f"{p.get('name') or p['type']}: {type(e).__name__}: {str(e)[:200]}", key)) from None


def _models_path(p):
    return "/v1/models?limit=1000" if p["type"] == "anthropic" else "/models"


_SKIP = re.compile(r"embed|whisper|tts|transcribe|audio|realtime|image|dall-e|moderation|search|computer-use|davinci|babbage|sora|codex-mini", re.I)


def fetch_models(body):
    """Models the key can use (live list from the provider), chat models first. Uses the stored key when none is given."""
    typ = str(body.get("type") or "")
    if typ not in TYPES:
        raise ValueError("type must be openai or anthropic")
    key = str(body.get("api_key") or "").strip()
    cur = get(body.get("id")) if body.get("id") else None
    url = _base_url(typ, body.get("base_url"))
    if not key:
        if not cur or (cur.get("type"), cur.get("base_url")) != (typ, url):
            raise ValueError("enter the API key first")
        key = cur.get("api_key") or ""
    p = {"type": typ, "base_url": url, "name": str(body.get("name") or typ)}
    d = _http(p, _models_path(p), timeout=20, key=key)
    ids = [str(m.get("id")) for m in (d.get("data") or []) if isinstance(m, dict) and m.get("id")]
    chat = [m for m in ids if not _SKIP.search(m)]
    return {"ok": True, "models": sorted(chat), "all": len(ids)}


def test(body):
    """Check the key with the provider's model list (no tokens used)."""
    r = fetch_models(body)
    return {"ok": True, "message": f"key works - {r['all']} models visible to this key"}


def _rate(p):
    lim = int(p.get("rate_per_hour") or RATE_DEFAULT)
    with _lock:
        now = time.time()
        q = [t for t in _sent.get(p["id"], []) if now - t < 3600]
        if len(q) >= lim:
            _sent[p["id"]] = q
            raise RuntimeError(f"{p.get('name')}: rate limit reached ({lim} calls per hour, set on AI review > AI providers)")
        q.append(now)
        _sent[p["id"]] = q


def complete(provider, model, system, user, max_tokens):
    """One text completion -> (text, usage {prompt, completion, cache_read}, seconds)."""
    p = get(provider)
    if not p or not p.get("enabled", True) or not p.get("api_key"):
        raise RuntimeError(f"AI provider {provider} is not configured or disabled")
    if model not in (p.get("models") or []):
        raise RuntimeError(f"{model} is not enabled for {p.get('name')}")
    _rate(p)
    t = time.time()
    extra = int(p.get("reasoning_tokens") or 0)
    if p["type"] == "anthropic":
        d = _http(p, "/v1/messages", {"model": model, "max_tokens": int(max_tokens) + extra, "system": system,
                                       "messages": [{"role": "user", "content": user}]})
        txt = "".join(b.get("text") or "" for b in d.get("content") or [] if isinstance(b, dict) and b.get("type") == "text")
        u = d.get("usage") or {}
        usage = {"prompt": int(u.get("input_tokens") or 0) + int(u.get("cache_read_input_tokens") or 0) + int(u.get("cache_creation_input_tokens") or 0),
                 "completion": int(u.get("output_tokens") or 0), "cache_read": int(u.get("cache_read_input_tokens") or 0)}
        if not txt and d.get("stop_reason") == "max_tokens":
            raise RuntimeError(f"{p.get('name')}: answer cut off at max_tokens (raise 'extra reasoning tokens')")
        return txt, usage, round(time.time() - t, 2)
    body = {"model": model, "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]}
    # OpenAI's own API wants max_completion_tokens (reasoning models reject max_tokens); compatible servers mostly want max_tokens
    host = urllib.parse.urlparse(p["base_url"]).hostname or ""
    body["max_completion_tokens" if host.endswith("openai.com") else "max_tokens"] = int(max_tokens) + extra
    d = _http(p, "/chat/completions", body)
    ch = (d.get("choices") or [{}])[0]
    txt = (ch.get("message") or {}).get("content") or ""
    if not txt and ch.get("finish_reason") == "length":
        raise RuntimeError(f"{p.get('name')}: answer cut off at the token limit (raise 'extra reasoning tokens')")
    u = d.get("usage") or {}
    return txt, {"prompt": int(u.get("prompt_tokens") or 0), "completion": int(u.get("completion_tokens") or 0),
                 "cache_read": int((u.get("prompt_tokens_details") or {}).get("cached_tokens") or 0)}, round(time.time() - t, 2)
