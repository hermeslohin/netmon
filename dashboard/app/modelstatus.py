"""AI pipeline monitoring > Models: for each model role (decision model, event reviewer, event research, Ask AI chat)
the configured model, where it is served (provider name + endpoint, never a key) and whether it is up right now.

Probes use no tokens: GET /health on the decision-model server, the provider's model list for the others (the local
server's /api/v0/models also says whether the model is loaded). Results are cached for TTL seconds so the page's live
refresh does not poll the providers once a minute per open browser.
States: up | warn (reachable, but the model is not listed) | down | off (switched off or no model chosen).
"""
import json
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor

import clef
import corr_llm
import llm_providers

TTL = 60
_cache = {"at": 0.0, "v": None}
_lock = threading.Lock()


def _row(role, label, model=None, source=None, endpoint=None, state="off", detail="", ms=None, provider=None):
    return {"role": role, "label": label, "model": model or "", "provider": provider or "", "source": source or "",
            "endpoint": endpoint or "", "state": state, "detail": detail, "ms": ms}


def _decision():
    c = clef.config()
    r = dict(role="decision", label="Decision model", model=c.get("model"), source="System One decision server", endpoint=c.get("url"))
    if not c.get("enabled"):
        return _row(**r, state="off", detail="switched off (Correlation review settings)")
    t = time.time()
    ok = clef.healthy(c.get("url"))
    ms = int((time.time() - t) * 1000)
    return _row(**r, state="up" if ok else "down", ms=ms, detail="health check ok" if ok else "no answer on /health")


def _provider(role, label, provider, model, unset, auto=False):
    if auto and provider == llm_providers.LOCAL and not model:
        model = "auto"  # the event reviewer's default: the first model the local server has loaded
    if not provider or not model:
        return _row(role, label, state="off", detail=unset)
    p = llm_providers.get(provider) if llm_providers.known(provider) else None
    if not p:
        return _row(role, label, model=model, provider=provider, state="down", detail="provider no longer exists (AI providers)")
    base = dict(role=role, label=label, model=model, provider=provider, source=p.get("name") or provider, endpoint=p.get("base_url") or "")
    if not p.get("enabled", True):
        return _row(**base, state="off", detail="provider switched off (AI providers)")
    t = time.time()
    try:
        if provider == llm_providers.LOCAL:
            url = llm_providers.LMS_URL.replace("/v1", "/api/v0") + "/models"
            d = json.load(urllib.request.urlopen(url, timeout=6))  # noqa: S310 - admin-set local URL
            found = {m.get("id"): m for m in d.get("data", []) if isinstance(m, dict)}
            ms = int((time.time() - t) * 1000)
            if model == "auto":
                m = next((x for x in found.values() if x.get("state") == "loaded"), None)
                if not m:
                    return _row(**base, state="warn", ms=ms, detail="server up, but no model is loaded (auto picks the loaded one)")
                return _row(**{**base, "model": f"auto: {m.get('id')}"}, state="up", ms=ms, detail="loaded")
            m = found.get(model)
            if not m:
                return _row(**base, state="warn", ms=ms, detail=f"server up, but {model} is not installed")
            loaded = m.get("state") == "loaded"
            return _row(**base, state="up", ms=ms, detail="loaded" if loaded else "installed, not loaded (loads on first call)")
        d = llm_providers._http(p, llm_providers._models_path(p), timeout=8)
        ids = {str(m.get("id")) for m in (d.get("data") or []) if isinstance(m, dict)}
        ms = int((time.time() - t) * 1000)
        if model not in ids:
            return _row(**base, state="warn", ms=ms, detail=f"API answers, but {model} is not in its model list")
        return _row(**base, state="up", ms=ms, detail="API answers, model listed")
    except Exception as e:  # noqa: BLE001 - any failure means down; the message is already scrubbed of keys
        return _row(**base, state="down", ms=int((time.time() - t) * 1000), detail=str(e)[:200])


def _research():
    import research_cfg
    try:
        c = research_cfg.get()
    except Exception as e:  # noqa: BLE001
        return _row("research", "Event research", state="down", detail=f"settings unavailable: {str(e)[:150]}")
    return _provider("research", "Event research", c.get("provider"), c.get("model"), "no model chosen: Send to research is unavailable")


def _compute():
    cfg = corr_llm.config()
    cor, ch = cfg.get("correlation") or {}, cfg.get("chat") or {}
    jobs = [_decision,
            lambda: _provider("reviewer", "Event reviewer", cor.get("provider"), cor.get("model"), "no model chosen", auto=True),
            _research,
            lambda: _provider("chat", "Chat (Ask AI)", ch.get("provider"), ch.get("model"), "no model chosen: chat is off")]
    with ThreadPoolExecutor(max_workers=4) as ex:
        rows = list(ex.map(lambda f: f(), jobs))
    return {"checked": time.time(), "ttl": TTL, "roles": rows}


def status(force=False):
    with _lock:
        if not force and _cache["v"] and time.time() - _cache["at"] < TTL:
            return _cache["v"]
    v = _compute()
    with _lock:
        _cache.update(at=time.time(), v=v)
    return v
