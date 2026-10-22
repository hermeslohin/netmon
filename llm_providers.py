"""AI providers: any OpenAI-compatible or Anthropic API reached with an API key, plus the local LM Studio server.

Admins add providers on the dashboard's AI review page. Everything that uses an AI model goes through this module:
the correlation reviewer and model comparisons (dashboard container), the dashboard chat, and the scheduled research
job on the host (review.py). Providers are stored in llm_providers.json on the dashboard's state volume (mode 0600,
atomic writes; the host reads the same file at dashboard/state/):
  {"id": "a1b2c3", "name": "OpenAI (work key)", "type": "openai" | "anthropic", "base_url": "https://api.openai.com/v1",
   "api_key": "...", "models": ["gpt-5-mini", ...], "prices": {"gpt-5-mini": [0.25, 2.0, 0.025]},
   "rate_per_hour": 120, "reasoning_tokens": 3000, "enabled": true}
In model choices a provider is addressed as "api:<id>"; "lmstudio" is the built-in local server (NETMON_LLM_URL, no key).
API keys never leave this module: public() returns a masked hint only, and errors are scrubbed of the key.

type "openai": POST {base_url}/chat/completions with a Bearer key - OpenAI itself, or any compatible service
               (OpenRouter, Groq, Mistral, Together, DeepSeek, Gemini's OpenAI endpoint, vLLM, LM Studio, ...).
type "anthropic": POST {base_url}/v1/messages with "x-api-key" + "anthropic-version".
complete() is one prompt -> text; chat() is one turn of a tool-using conversation in a provider-neutral format:
  messages: [{"role": "user", "content": str} | {"role": "assistant", "content": str, "tool_calls": [{"id", "name", "args"}]}
             | {"role": "tool", "id": <tool call id>, "name": str, "content": str}]
  tools:    [{"name", "description", "parameters": <JSON schema>}]
  -> {"text", "tool_calls": [{"id", "name", "args"}], "usage": {"prompt", "completion", "cache_read", "cache_write"}, "stop", "seconds"}
prices are $ per million tokens [input, output, cached input]; cost() turns usage into dollars (None = no price known).
"""
import ipaddress, json, os, re, secrets, threading, time, urllib.error, urllib.parse, urllib.request

_HERE = os.path.dirname(os.path.abspath(__file__))
STATE = os.environ.get("STATE_DIR") or ("/state" if os.path.isdir("/state") else os.path.join(_HERE, "dashboard", "state"))
PATH = os.path.join(STATE, "llm_providers.json")
TYPES = {"openai": {"label": "OpenAI / OpenAI-compatible", "base_url": "https://api.openai.com/v1"},
         "anthropic": {"label": "Anthropic", "base_url": "https://api.anthropic.com"}}
PREFIX = "api:"
LOCAL = "lmstudio"
LMS_URL = os.environ.get("NETMON_LLM_URL", "http://127.0.0.1:1234/v1").rstrip("/")
MAX_PROVIDERS, MAX_MODELS = 30, 60
RATE_DEFAULT, RATE_MAX = 120, 3000
ANTHROPIC_VERSION = "2023-06-01"
_lock = threading.Lock()
_sent = {}  # provider id -> [timestamps of calls in the last hour]
_cache = {"k": None, "v": [], "local": {}}


# ---------------------------------------------------------------- storage
def _load_all():
    try:
        import store
        mt = store.jmtime(PATH)
        k = (mt,)
        if mt is None:
            return [], {}
        if _cache["k"] != k:
            d = store.jload(PATH, {})
            if not isinstance(d, dict):
                d = {}
            ps = [p for p in (d.get("providers") or []) if isinstance(p, dict) and p.get("id")]
            loc = d.get("local") if isinstance(d.get("local"), dict) else {}
            _cache.update(k=k, v=ps, local=loc)
        return _cache["v"], _cache.get("local") or {}
    except (OSError, ValueError):
        return [], {}


def _load():
    return _load_all()[0]


def _load_local_cfg():
    """Admin settings for the local server (enabled, rate_per_hour) - {} means the defaults below."""
    return _load_all()[1]


def _save(providers, local=None):
    if local is None:
        local = _load_local_cfg()
    import store
    store.jdump({"providers": providers, "local": local}, PATH)
    _cache["k"] = None


def local_enabled():
    """Whether an admin has switched the local server off (AI providers > Local (LM Studio))."""
    return bool(_load_local_cfg().get("enabled", True))


def _local():
    lc = _load_local_cfg()
    return {"id": LOCAL, "name": "Local (LM Studio)", "type": "openai", "base_url": LMS_URL, "api_key": "lm-studio",
            "models": [m["id"] for m in offered_local_models()], "enabled": bool(lc.get("enabled", True)),
            "rate_per_hour": int(lc.get("rate_per_hour") or RATE_MAX), "reasoning_tokens": 0,
            "by": lc.get("by"), "at": lc.get("at")}


def local_models():
    """Chat models LM Studio offers (loaded or loadable); [] when it is not running."""
    try:
        d = json.load(urllib.request.urlopen(LMS_URL.replace("/v1", "/api/v0") + "/models", timeout=5))  # noqa: S310 - admin-set local URL
        return [{"id": m["id"], "loaded": m.get("state") == "loaded"} for m in d.get("data", []) if m.get("type") in ("llm", "vlm")]
    except Exception:  # noqa: BLE001
        return []


def offered_local_models():
    """local_models() narrowed to the ones an admin picked (AI providers > Local (LM Studio)); none picked = all."""
    allm, pick = local_models(), _load_local_cfg().get("models") or []
    return [m for m in allm if m["id"] in pick] if pick else allm


def get(pid):
    """Provider by id or by "api:<id>" ("lmstudio" = the local server); None if unknown."""
    pid = str(pid or "")
    if pid == LOCAL:
        return _local()
    pid = pid[len(PREFIX):] if pid.startswith(PREFIX) else pid
    return next((p for p in _load() if p["id"] == pid), None)


def is_custom(provider):
    return isinstance(provider, str) and provider.startswith(PREFIX)


def known(provider):
    return provider == LOCAL or is_custom(provider)


def allowed(provider, model):
    p = get(provider) if known(provider) else None
    return bool(p and p.get("enabled", True) and p.get("api_key") and model in (p.get("models") or []))


def price(provider, model):
    """{in, out, cache_read} $ per million tokens, {0,0,0} for the local server, None when the admin entered no price."""
    if provider == LOCAL:
        v = (_load_local_cfg().get("prices") or {}).get(model)
        if v:
            return {"in": float(v[0]), "out": float(v[1]), "cache_read": float(v[2] if len(v) > 2 and v[2] is not None else v[0])}
        return {"in": 0.0, "out": 0.0, "cache_read": 0.0}
    p = get(provider) if is_custom(provider) else None
    v = ((p or {}).get("prices") or {}).get(model)
    if not v:
        return None
    return {"in": float(v[0]), "out": float(v[1]), "cache_read": float(v[2] if len(v) > 2 and v[2] is not None else v[0])}


def cost(provider, model, usage):
    """Dollars for one usage dict; None when no price is known."""
    pr = price(provider, model)
    if pr is None:
        return None
    u = usage or {}
    cr = int(u.get("cache_read") or 0)
    fresh = max(0, int(u.get("prompt") or 0) - cr)
    return (fresh * pr["in"] + cr * pr["cache_read"] + int(u.get("completion") or 0) * pr["out"]) / 1e6


def name(provider):
    p = get(provider)
    return (p or {}).get("name") or str(provider)


# ---------------------------------------------------------------- what the browser may see
def _mask(k):
    return f"…{k[-4:]}" if k and len(k) > 12 else ("set" if k else "")


def public():
    """All providers for the admin editor, keys masked. The local LM Studio server is always first, flagged
    "local": True so the admin UI offers it a reduced edit form (enabled + rate limit only, no key/models/url)."""
    loc = _local()
    local_row = {"id": LOCAL, "provider": LOCAL, "name": loc["name"], "type": "local", "type_label": "Local (LM Studio)",
                 "base_url": loc["base_url"], "key_set": True, "key_hint": "not needed", "models": list(loc["models"]),
                 "available": [m["id"] for m in local_models()], "prices": dict(_load_local_cfg().get("prices") or {}), "rate_per_hour": loc["rate_per_hour"], "reasoning_tokens": 0, "enabled": loc["enabled"],
                 "by": loc.get("by"), "at": loc.get("at"), "local": True,
                 "calls_last_hour": len([t for t in _sent.get(LOCAL, []) if time.time() - t < 3600])}
    return [local_row] + [{"id": p["id"], "provider": PREFIX + p["id"], "name": p.get("name") or p["id"], "type": p.get("type"),
             "type_label": TYPES.get(p.get("type"), {}).get("label", p.get("type")), "base_url": p.get("base_url") or "",
             "key_set": bool(p.get("api_key")), "key_hint": _mask(p.get("api_key") or ""), "models": list(p.get("models") or []),
             "prices": dict(p.get("prices") or {}),
             "rate_per_hour": p.get("rate_per_hour") or RATE_DEFAULT, "reasoning_tokens": int(p.get("reasoning_tokens") or 0),
             "enabled": bool(p.get("enabled", True)), "by": p.get("by"), "at": p.get("at"), "local": False,
             "calls_last_hour": len([t for t in _sent.get(p["id"], []) if time.time() - t < 3600])} for p in _load()]


def save_local(body, user):
    """Admin edit of the local server row: only enabled + rate_per_hour (no key, URL or model list - those come
    live from LM Studio / NETMON_LLM_URL)."""
    rate = _int(body.get("rate_per_hour"), 1, RATE_MAX, RATE_DEFAULT, "calls per hour")
    enabled = bool(body.get("enabled", True))
    models, prices = _models(body.get("models"))
    with _lock:
        _save(_load(), {"enabled": enabled, "rate_per_hour": rate, "models": models, "prices": prices, "by": user, "at": time.time()})
    return next(p for p in public() if p["id"] == LOCAL)


def default_target():
    """A provider+model usable as a feature's default WITHOUT requiring the local LM Studio server to be running:
    the first enabled, API-key provider with at least one model; the local server only when none is configured."""
    for g in model_groups():
        if g["models"]:
            return g["provider"], g["models"][0]["id"]
    return LOCAL, None


def model_groups():
    """Usable providers for the model menus (/api/llm/models "custom"): enabled, with a key and at least one model."""
    return [{"provider": PREFIX + p["id"], "name": p.get("name") or p["id"], "type": p.get("type"),
             "reasoning_tokens": int(p.get("reasoning_tokens") or 0),
             "models": [{"id": m, "price": price(PREFIX + p["id"], m)} for m in p.get("models") or []]}
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
    """Model list from the form: a list of ids, or text with one model per line, optionally followed by its prices
    ($ per million tokens: input output [cached input]) -> (models, prices)."""
    rows = [[str(m)] for m in v] if isinstance(v, list) else [ln.replace(",", " ").split() for ln in str(v or "").splitlines()]
    out, prices = [], {}
    for parts in rows:
        if not parts or not parts[0].strip():
            continue
        m = parts[0].strip()
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/@+\-]{0,119}", m):
            raise ValueError(f"model id {m[:60]!r} has unexpected characters")
        if m not in out:
            out.append(m)
        if len(parts) > 1:
            try:
                pr = [float(x.lstrip("$")) for x in parts[1:4]]
            except ValueError:
                raise ValueError(f"prices for {m} must be numbers: <model> <input $/M> <output $/M> [<cached input $/M>]") from None
            if len(pr) < 2 or any(x < 0 or x > 1000 for x in pr):
                raise ValueError(f"prices for {m}: give input and output $ per million tokens (0-1000)")
            prices[m] = pr
    if len(out) > MAX_MODELS:
        raise ValueError(f"at most {MAX_MODELS} models per provider")
    return out, prices


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
    if str(body.get("id") or "") == LOCAL:
        raise ValueError("use save_local for the local server row")
    typ = str(body.get("type") or "")
    if typ not in TYPES:
        raise ValueError("type must be openai or anthropic")
    nm = re.sub(r"[\x00-\x1f<>]", "", str(body.get("name") or "")).strip()[:60]
    if not nm:
        raise ValueError("give the provider a name")
    key = str(body.get("api_key") or "").strip()
    if key and (len(key) > 400 or not re.fullmatch(r"[\x21-\x7e]+", key)):
        raise ValueError("that does not look like an API key")
    models, prices = _models(body.get("models"))
    rec = {"name": nm, "type": typ, "base_url": _base_url(typ, body.get("base_url")), "models": models, "prices": prices,
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
    if pid == LOCAL:
        raise ValueError("the local server can't be deleted - disable it instead")
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


def _target(provider, model, rate):
    p = get(provider)
    if not p or not p.get("enabled", True) or not p.get("api_key"):
        raise RuntimeError(f"AI provider {provider} is not configured or disabled")
    if model not in (p.get("models") or []):
        raise RuntimeError(f"{model} is not available on {p.get('name')}")
    if rate:
        _rate(p)
    return p


def _is_openai(p):
    return (urllib.parse.urlparse(p["base_url"]).hostname or "").endswith("openai.com")


def _oa_messages(system, messages):
    out = [{"role": "system", "content": system}] if system else []
    for m in messages:
        if m["role"] == "tool":
            out.append({"role": "tool", "tool_call_id": m["id"], "content": m.get("content") or ""})
        elif m["role"] == "assistant" and m.get("tool_calls"):
            out.append({"role": "assistant", "content": m.get("content") or None,
                        "tool_calls": [{"id": t["id"], "type": "function", "function": {"name": t["name"], "arguments": json.dumps(t.get("args") or {})}}
                                       for t in m["tool_calls"]]})
        else:
            out.append({"role": m["role"], "content": m.get("content") or ""})
    return out


def _an_messages(messages, cache):
    out = []
    for m in messages:
        if m["role"] == "tool":
            blk = {"type": "tool_result", "tool_use_id": m["id"], "content": m.get("content") or ""}
            if out and out[-1]["role"] == "user" and isinstance(out[-1]["content"], list) and out[-1]["content"][0].get("type") == "tool_result":
                out[-1]["content"].append(blk)  # Anthropic wants all results of one turn in one user message
            else:
                out.append({"role": "user", "content": [blk]})
        elif m["role"] == "assistant":
            c = ([{"type": "text", "text": m["content"]}] if m.get("content") else []) + \
                [{"type": "tool_use", "id": t["id"], "name": t["name"], "input": t.get("args") or {}} for t in m.get("tool_calls") or []]
            out.append({"role": "assistant", "content": c or [{"type": "text", "text": "(no text)"}]})
        else:
            out.append({"role": "user", "content": [{"type": "text", "text": m.get("content") or ""}]})
    if cache and out:  # prompt caching: everything up to the newest message is reused by the next turn
        last = out[-1]["content"][-1]
        last["cache_control"] = {"type": "ephemeral"}
    return out


def _rs_input(messages):
    """Neutral messages -> OpenAI Responses API input items. Assistant turns keep the provider's own output items
    (reasoning with encrypted content, function calls) in m["raw"], so reasoning carries over between turns."""
    out = []
    for m in messages:
        if m["role"] == "tool":
            out.append({"type": "function_call_output", "call_id": m["id"], "output": m.get("content") or ""})
        elif m["role"] == "assistant":
            if m.get("raw"):
                out.extend(m["raw"])
                continue
            if m.get("content"):
                out.append({"role": "assistant", "content": m["content"]})
            for t in m.get("tool_calls") or []:
                out.append({"type": "function_call", "call_id": t["id"], "name": t["name"], "arguments": json.dumps(t.get("args") or {})})
        else:
            out.append({"role": "user", "content": m.get("content") or ""})
    return out


def _responses(p, model, system, messages, tools, max_tokens, temperature):
    body = {"model": model, "input": _rs_input(messages), "max_output_tokens": int(max_tokens), "store": False,
            "include": ["reasoning.encrypted_content"]}
    if system:
        body["instructions"] = system
    if tools:
        body["tools"] = [{"type": "function", "name": x["name"], "description": x.get("description", ""),
                          "parameters": x.get("parameters") or {"type": "object", "properties": {}}} for x in tools]
    if temperature is not None:
        body["temperature"] = temperature
    d = _http(p, "/responses", body)
    items = [i for i in d.get("output") or [] if isinstance(i, dict)]
    text = "".join(c.get("text") or "" for i in items if i.get("type") == "message" for c in i.get("content") or [] if c.get("type") == "output_text")
    calls = []
    for i in items:
        if i.get("type") == "function_call":
            try:
                args = json.loads(i.get("arguments") or "{}")
            except ValueError:
                args = {"_unparsed": (i.get("arguments") or "")[:2000]}
            calls.append({"id": i.get("call_id") or i.get("id"), "name": i.get("name") or "", "args": args if isinstance(args, dict) else {"value": args}})
    # store=False: message / call items are re-sent without their server ids; reasoning items need id + encrypted_content
    keep = [{k: v for k, v in i.items() if k not in ("status",) and (k != "id" or i.get("type") == "reasoning")}
            for i in items if i.get("type") in ("reasoning", "message", "function_call")]
    u = d.get("usage") or {}
    usage = {"prompt": int(u.get("input_tokens") or 0), "completion": int(u.get("output_tokens") or 0),
             "cache_read": int((u.get("input_tokens_details") or {}).get("cached_tokens") or 0), "cache_write": 0}
    inc = (d.get("incomplete_details") or {}).get("reason")
    stop = "tool_calls" if calls else ("length" if inc == "max_output_tokens" else "stop")
    return {"text": text, "tool_calls": calls, "usage": usage, "stop": stop, "raw": keep}


def chat(provider, model, system, messages, tools=None, max_tokens=4000, rate=False, temperature=None):
    """One turn of a (tool-using) conversation; see the module docstring for the formats.
    OpenAI's own API is called through /v1/responses (reasoning models only take tools there); the result then
    carries "raw" output items, which the caller stores on the assistant message (m["raw"]) for the next turn."""
    p = _target(provider, model, rate)
    t = time.time()
    extra = int(p.get("reasoning_tokens") or 0)
    if p["type"] == "openai" and _is_openai(p):
        r = _responses(p, model, system, messages, tools, int(max_tokens) + extra, temperature)
        r["seconds"] = round(time.time() - t, 2)
        return r
    if p["type"] == "anthropic":
        body = {"model": model, "max_tokens": int(max_tokens) + extra, "messages": _an_messages(messages, cache=True)}
        if system:
            body["system"] = [{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}]
        if tools:
            body["tools"] = [{"name": x["name"], "description": x.get("description", ""), "input_schema": x.get("parameters") or {"type": "object", "properties": {}}}
                             for x in tools]
        if temperature is not None:
            body["temperature"] = temperature
        d = _http(p, "/v1/messages", body)
        blocks = d.get("content") or []
        text = "".join(b.get("text") or "" for b in blocks if b.get("type") == "text")
        calls = [{"id": b["id"], "name": b["name"], "args": b.get("input") or {}} for b in blocks if b.get("type") == "tool_use"]
        u = d.get("usage") or {}
        cr, cw = int(u.get("cache_read_input_tokens") or 0), int(u.get("cache_creation_input_tokens") or 0)
        usage = {"prompt": int(u.get("input_tokens") or 0) + cr + cw, "completion": int(u.get("output_tokens") or 0), "cache_read": cr, "cache_write": cw}
        stop = {"end_turn": "stop", "tool_use": "tool_calls", "max_tokens": "length"}.get(d.get("stop_reason"), d.get("stop_reason"))
    else:
        body = {"model": model, "messages": _oa_messages(system, messages)}
        body["max_completion_tokens" if _is_openai(p) else "max_tokens"] = int(max_tokens) + extra
        if tools:
            body["tools"] = [{"type": "function", "function": {"name": x["name"], "description": x.get("description", ""),
                                                               "parameters": x.get("parameters") or {"type": "object", "properties": {}}}} for x in tools]
        if temperature is not None:
            body["temperature"] = temperature
        d = _http(p, "/chat/completions", body)
        ch = (d.get("choices") or [{}])[0]
        msg = ch.get("message") or {}
        text = msg.get("content") or ""
        calls = []
        for tc in msg.get("tool_calls") or []:
            fn = tc.get("function") or {}
            try:
                args = json.loads(fn.get("arguments") or "{}")
            except ValueError:
                args = {"_unparsed": (fn.get("arguments") or "")[:2000]}
            calls.append({"id": tc.get("id") or f"call_{len(calls)}", "name": fn.get("name") or "", "args": args if isinstance(args, dict) else {"value": args}})
        u = d.get("usage") or {}
        usage = {"prompt": int(u.get("prompt_tokens") or 0), "completion": int(u.get("completion_tokens") or 0),
                 "cache_read": int((u.get("prompt_tokens_details") or {}).get("cached_tokens") or 0), "cache_write": 0}
        stop = "tool_calls" if calls else {"stop": "stop", "length": "length"}.get(ch.get("finish_reason"), ch.get("finish_reason"))
    return {"text": text, "tool_calls": calls, "usage": usage, "stop": stop, "seconds": round(time.time() - t, 2)}


def complete(provider, model, system, user, max_tokens, rate=True):
    """One text completion -> (text, usage {prompt, completion, cache_read}, seconds)."""
    r = chat(provider, model, system, [{"role": "user", "content": user}], max_tokens=max_tokens, rate=rate,
             temperature=0 if provider == LOCAL else None)
    if not r["text"] and r["stop"] == "length":
        raise RuntimeError(f"{name(provider)}: answer cut off at the token limit (raise 'extra reasoning tokens')")
    return r["text"], r["usage"], r["seconds"]
