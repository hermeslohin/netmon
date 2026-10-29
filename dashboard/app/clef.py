"""Decision-model stage of the correlation review (Cloudflare clef-flash, a "System One" decision model).

The model does not write text: it reads a state (JSON) and typed questions and returns a probability per answer,
served on /v1/systemone by SGLang on the Patapsco AI cluster (default; clef_server.py) or by llama.cpp's llama-server
(host unit netmon-clef, clef.sh). netmon asks it one yes/no
("noul") question per candidate link the correlation script proposed: are the two events related? That answer is the
verdict (corr_llm.db tables `clef` + `verdicts`). The selected correlation model never decides a link: once every link
is decided it makes one call per event with all its related events and notes (corr_llm.event_pass) and writes the
suspicious / benign / expected decision and the link notes.
Settings live in llm_config (key `clef`), edited on AI review > Decision model.
"""
import json
import os
import time
import urllib.request

URL_DEFAULT = os.environ.get("NETMON_CLEF_URL", "").rstrip("/")  # empty: the server picked on AI review (_server_url)
MODEL_DEFAULT = os.environ.get("NETMON_CLEF_MODEL", "cloudflare_clef")  # full clef (27B); was cloudflare_clef-flash:2
WORKERS = max(1, int(os.environ.get("NETMON_CLEF_WORKERS", "4")))
TIMEOUT = 30  # full clef: ~3 s per answer with 4 in parallel; longer = a lost request, retried
STATS = {"timeouts": 0}
STATE_MAX = 12000  # characters of state per request (the server's slot holds ~8k tokens)

Q_RELATED = ("Are EVENT A and EVENT B genuinely related: the same incident or activity chain, cause and effect, the same "
             "underlying problem seen by two different detectors, or a vulnerability or misconfiguration that the other "
             "event's activity could exploit or is explained by? Answer no when they merely share a busy host, a common "
             "service or the same time window with no logical connection.")

Q_EVENT_SUSPICIOUS = ("Taking EVENT and all of its RELATED EVENTS together, does this activity look suspicious: possible compromise, "
                      "misuse, an unknown actor, or a real weakness being exploited, so that a person should look at it? Owner notes "
                      "saying it is normal count against suspicious, but never above concrete evidence of harm.")
Q_EVENT_EXPECTED = ("Is EVENT normal, expected activity for this device, user or task (routine service behaviour, a known job, "
                    "what the owner notes describe)?")


def event_state(e, related, when, desc, notes=None, rel_notes=None):
    """JSON state for one event with all of its related events (each: event + the decision model's link probability)."""
    rel = []
    for x, p in related[:20]:
        d = _ev(x, when(x), desc(x.get("type")), (rel_notes or {}).get(id(x)))
        d["link probability"] = round(p, 2)
        rel.append(d)
    s = {"EVENT": _ev(e, when(e), desc(e.get("type")), notes), "RELATED EVENTS": rel}
    txt = json.dumps(s, ensure_ascii=False, default=str)
    while len(txt) > STATE_MAX and len(rel) > 1:
        rel.pop()
        txt = json.dumps(s, ensure_ascii=False, default=str)
    if len(txt) > STATE_MAX:
        for d in [s["EVENT"], *rel]:
            d.pop("owner_notes", None); d["description"] = d["description"][:250]
        txt = json.dumps(s, ensure_ascii=False, default=str)[:STATE_MAX]
    return txt


def label(p_sus, p_exp, cfg=None):
    cfg = cfg or config()
    if p_sus >= cfg["suspicious_min"]:
        return "suspicious"
    return "expected" if p_exp >= 0.5 else "benign"


def _cfg_raw():
    import corr_llm
    return (corr_llm._raw_config().get("clef") or {})


PATAPSCO_URL = "http://127.0.0.1:30891"  # Patapsco AI cluster: SGLang clef via NodePort service netmon-clef-host
PATAPSCO_MODEL = "Cloudflare/clef"  # SGLang's served model name (FP8 online quantization); SGLang requires it in the body


def _server_url():
    """URL of the decision-model server picked on AI review > Decision model server (docs table, clef_server.backend):
    the Patapsco AI cluster by default, else the host llama-server on its saved port."""
    try:
        import store
        s = store.doc_get("clef_server", {}) or {}
    except Exception:  # noqa: BLE001
        s = {}
    if (s.get("backend") or "patapsco") == "patapsco":
        return PATAPSCO_URL
    return f"http://127.0.0.1:{int(s.get('port') or 8091)}"


def config():
    c = _cfg_raw()
    url = str(c.get("url") or URL_DEFAULT or _server_url()).rstrip("/")
    if not url.startswith(("http://127.0.0.1", "http://localhost")):  # loopback only: event data never leaves the host
        url = URL_DEFAULT or _server_url()

    def thr(k, d):
        try:
            return max(0.05, min(0.95, float(c.get(k, d))))
        except (TypeError, ValueError):
            return d
    return {"enabled": c.get("enabled", True) is not False, "url": url, "model": str(c.get("model") or (PATAPSCO_MODEL if url == PATAPSCO_URL else MODEL_DEFAULT)),
            "related_min": thr("related_min", 0.5), "suspicious_min": thr("suspicious_min", 0.5),
            "by": c.get("by"), "at": c.get("at")}


def set_config(user, enabled=None, related_min=None, suspicious_min=None):
    import corr_llm
    raw = corr_llm._raw_config()
    c = dict(raw.get("clef") or {})
    if enabled is not None:
        c["enabled"] = bool(enabled)
    for k, v in (("related_min", related_min), ("suspicious_min", suspicious_min)):
        if v is not None:
            v = float(v)
            if not 0.05 <= v <= 0.95:
                raise ValueError(f"{k} must be between 0.05 and 0.95")
            c[k] = round(v, 2)
    c.update(by=user, at=time.time())
    raw["clef"] = c
    corr_llm._save_config(raw)
    return config()


def ask(state, questions, url=None, timeout=TIMEOUT):
    """One /v1/systemone call -> ({question: probability of yes}, milliseconds)."""
    cfg = config()
    url = url or cfg["url"]
    body = json.dumps({"model": cfg["model"], "state": state, "questions": {k: {"type": "noul", "instructions": q} for k, q in questions.items()}}).encode()
    req = urllib.request.Request(url + "/v1/systemone", data=body, headers={"Content-Type": "application/json"})
    t = time.time()
    for attempt in range(3):  # llama-server occasionally never answers one request (seen under load): retry it, never stall the pass
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 - loopback URL enforced in config()
                d = json.loads(r.read().decode())
            break
        except TimeoutError:
            STATS["timeouts"] += 1
            if attempt == 2:
                raise
    ms = (time.time() - t) * 1000
    ans = d.get("answers") or {}
    out = {}
    for k in questions:
        v = (ans.get(k) or {}).get("noul")
        if not isinstance(v, (int, float)):
            raise RuntimeError(f"decision model gave no answer for {k}: {json.dumps(d)[:200]}")
        out[k] = float(v)
    return out, ms


def healthy(url=None):
    try:
        with urllib.request.urlopen((url or config()["url"]) + "/health", timeout=3) as r:  # noqa: S310
            return json.loads(r.read().decode()).get("status") == "ok"
    except Exception:  # noqa: BLE001
        return False


def _ev(e, when, desc, notes=None):
    d = {"type": f'{e.get("type")} ({desc})' if desc else e.get("type"), "when": when, "severity": e.get("sev") or "",
         "description": str(e.get("label") or "")[:600]}
    if e.get("ips"):
        d["hosts"] = [str(x) for x in (e.get("ips") or [])[:6]]
    arts = [f"{a[0]}={str(a[1])[:90]}" for a in (e.get("arts") or [])[:8]]
    if arts:
        d["artifacts"] = arts
    if notes:
        d["owner_notes"] = [str(n)[:300] for n in notes[:3]]
    return d


def state(a, b, r, when, desc, notes_a=None, notes_b=None, link=None):
    """The JSON state for one pair. when(e) / desc(type) format time and event type (from corr_llm)."""
    s = {"EVENT A": _ev(a, when(a), desc(a.get("type")), notes_a), "EVENT B": _ev(b, when(b), desc(b.get("type")), notes_b),
         "correlation script evidence": {"score": r.get("score", 0), "why": list(r.get("why") or [])[:6]}}
    if link:
        s["link"] = link
    txt = json.dumps(s, ensure_ascii=False, default=str)
    if len(txt) > STATE_MAX:  # drop notes first, then shorten the descriptions
        for k in ("EVENT A", "EVENT B"):
            s[k].pop("owner_notes", None)
            s[k]["description"] = s[k]["description"][:250]
        txt = json.dumps(s, ensure_ascii=False, default=str)[:STATE_MAX]
    return txt
