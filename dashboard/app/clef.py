"""Decision-model stage of the correlation review (Cloudflare clef-flash, a "System One" decision model).

The model does not write text: it reads a state (JSON) and typed questions and returns a probability per answer,
served by llama.cpp's llama-server on /v1/systemone (host unit netmon-clef, clef.sh). netmon asks it only yes/no
("noul") questions:

  1. related    - for every candidate pair the correlation script proposed: are the two events related?
                  No = the pair is rejected without the reviewer model ever seeing it.
  2. suspicious - for every pair it judged related: does the linked pair look suspicious?

Both answers are stored per unordered pair in corr_llm.db table `clef` and handed to the selected correlation model,
which writes the notes (reason, artifacts, host notes) and the event classification.
Settings live in llm_config (key `clef`), edited on AI review > Decision model.
"""
import json
import os
import time
import urllib.request

URL_DEFAULT = os.environ.get("NETMON_CLEF_URL", "http://127.0.0.1:8091").rstrip("/")
MODEL_DEFAULT = os.environ.get("NETMON_CLEF_MODEL", "cloudflare_clef-flash:2")
WORKERS = max(1, int(os.environ.get("NETMON_CLEF_WORKERS", "4")))
TIMEOUT = 30
STATE_MAX = 12000  # characters of state per request (the server's slot holds ~8k tokens)

Q_RELATED = ("Are EVENT A and EVENT B genuinely related: the same incident or activity chain, cause and effect, the same "
             "underlying problem seen by two different detectors, or a vulnerability or misconfiguration that the other "
             "event's activity could exploit or is explained by? Answer no when they merely share a busy host, a common "
             "service or the same time window with no logical connection.")
Q_SUSPICIOUS = ("EVENT A and EVENT B are related. Taken together, does this linked activity look suspicious: possible "
                "compromise, misuse, an unknown actor, or a real weakness being exploited, so that a person should look "
                "at it? Owner notes saying the activity is normal or expected count against suspicious; a note is "
                "never more important than concrete evidence of harm.")


def _cfg_raw():
    import corr_llm
    return (corr_llm._raw_config().get("clef") or {})


def config():
    c = _cfg_raw()
    url = str(c.get("url") or URL_DEFAULT).rstrip("/")
    if not url.startswith(("http://127.0.0.1", "http://localhost")):  # loopback only: event data never leaves the host
        url = URL_DEFAULT

    def thr(k, d):
        try:
            return max(0.05, min(0.95, float(c.get(k, d))))
        except (TypeError, ValueError):
            return d
    return {"enabled": c.get("enabled", True) is not False, "url": url, "model": str(c.get("model") or MODEL_DEFAULT),
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
    url = url or config()["url"]
    body = json.dumps({"state": state, "questions": {k: {"type": "noul", "instructions": q} for k, q in questions.items()}}).encode()
    req = urllib.request.Request(url + "/v1/systemone", data=body, headers={"Content-Type": "application/json"})
    t = time.time()
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 - loopback URL enforced in config()
        d = json.loads(r.read().decode())
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
