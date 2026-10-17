"""netmon LLM broker: lets the dashboard container use Anthropic models and change the research job's model.

The dashboard runs in a locked-down container without provider credentials. This small loopback-only HTTP
service runs on the host under Hermes' own runtime (so it uses Hermes' configured Anthropic credentials
through agent.auxiliary_client.call_llm - no key is copied anywhere) and offers exactly three things:

  GET  /models              local (LM Studio) + Anthropic models the dashboard may pick
  POST /complete            one chat completion {provider, model, system, user, max_tokens, json_schema?}
  GET  /research            the research cron job's current model/provider
  POST /research            {provider, model} -> `hermes cron edit <job> --model .. --provider ..`

Every request needs "Authorization: Bearer <NETMON_BROKER_KEY>" (dashboard/.env). Provider must be
"anthropic" or "lmstudio" and the model must be in /models. Run: llm_broker.sh (systemd user unit
netmon-llm-broker.service, see docs/SETUP.md).
"""
import hmac, json, os, subprocess, sys, threading, time, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

NM = os.path.dirname(os.path.abspath(__file__))
HOME = os.environ.get("HERMES_HOME") or os.path.expanduser("~/.hermes")
HOST, PORT = "127.0.0.1", int(os.environ.get("NETMON_BROKER_PORT", "8650"))
LMS = os.environ.get("NETMON_LLM_URL", "http://127.0.0.1:1234/v1").rstrip("/")
MAX_TOKENS = 4000
RATE = (120, 3600)  # anthropic completions per hour (comparisons + correlation review)
_sent, _lock = [], threading.Lock()


def _key():
    for line in open(os.path.join(NM, "dashboard", ".env")):
        if line.startswith("NETMON_BROKER_KEY="):
            return line.split("=", 1)[1].strip()
    raise SystemExit("NETMON_BROKER_KEY missing in dashboard/.env")


KEY = _key()


def anthropic_models():
    """Current Anthropic models from Hermes' own catalog (newest families first)."""
    try:
        from hermes_cli.models_catalog_static import _PROVIDER_MODELS as M  # noqa: N811
        ids = list(M.get("anthropic") or [])
    except Exception:  # noqa: BLE001
        ids = []
    keep = [m for m in ids if any(m.startswith(p) for p in ("claude-opus-5", "claude-sonnet-5", "claude-fable", "claude-haiku"))]
    for m in ("claude-sonnet-5-5", "claude-opus-5-5"):
        if m not in keep:
            keep.insert(0, m)
    return keep or ["claude-sonnet-5-5", "claude-opus-5-5", "claude-sonnet-5"]


def local_models():
    try:
        d = json.load(urllib.request.urlopen(LMS.replace("/v1", "/api/v0") + "/models", timeout=5))  # noqa: S310 - fixed loopback URL
        return [{"id": m["id"], "loaded": m.get("state") == "loaded"} for m in d.get("data", []) if m.get("type") in ("llm", "vlm")]
    except Exception:  # noqa: BLE001
        return []


def models():
    return {"anthropic": [{"id": m} for m in anthropic_models()], "local": local_models()}


def _allowed(provider, model):
    if provider == "anthropic":
        return model in anthropic_models()
    if provider == "lmstudio":
        return model in {m["id"] for m in local_models()}
    return False


def complete(b):
    from agent.auxiliary_client import call_llm
    provider, model = str(b.get("provider")), str(b.get("model"))
    if not _allowed(provider, model):
        raise ValueError("model not allowed")
    if provider == "anthropic":
        with _lock:
            now = time.time()
            _sent[:] = [t for t in _sent if now - t < RATE[1]]
            if len(_sent) >= RATE[0]:
                raise ValueError("rate limit: too many Anthropic requests this hour")
            _sent.append(now)
    msgs = [{"role": "system", "content": str(b.get("system") or "")[:20000]}, {"role": "user", "content": str(b.get("user") or "")[:60000]}]
    t = time.time()
    r = call_llm(provider=provider, model=model, messages=msgs, temperature=0, timeout=300,
                 max_tokens=max(50, min(int(b.get("max_tokens") or 1000), MAX_TOKENS)))
    u = getattr(r, "usage", None)
    return {"content": r.choices[0].message.content or "", "seconds": round(time.time() - t, 2),
            "usage": {"prompt": getattr(u, "prompt_tokens", 0) or 0, "completion": getattr(u, "completion_tokens", 0) or 0}}


def _job():
    d = json.load(open(os.path.join(HOME, "cron", "jobs.json")))
    for j in d["jobs"] if isinstance(d, dict) else d:
        if {"home-network-report", "netmon"} & set(j.get("skills") or [j.get("skill")]):
            return j
    raise ValueError("research job not found")


def research_get():
    j = _job()
    return {"job": j["id"], "name": j.get("name"), "model": j.get("model"), "provider": j.get("provider")}


def research_set(b):
    provider, model = str(b.get("provider")), str(b.get("model"))
    if not _allowed(provider, model):
        raise ValueError("model not allowed")
    j = _job()
    hermes = os.path.expanduser("~/.local/bin/hermes")
    p = subprocess.run([hermes, "cron", "edit", j["id"], "--model", model, "--provider", provider],  # noqa: S603 - fixed argv, validated values
                       capture_output=True, text=True, timeout=60)
    if p.returncode:
        raise ValueError((p.stderr or p.stdout)[-300:])
    subprocess.run(["/usr/bin/python3", os.path.join(NM, "claude_status.py")],  # noqa: S603
                   capture_output=True, timeout=60)
    return research_get()


class H(BaseHTTPRequestHandler):
    def log_message(self, fmt, *a):
        print("broker:", fmt % a, file=sys.stderr)

    def _send(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def _auth(self):
        h = self.headers.get("Authorization", "")
        return hmac.compare_digest(h.encode(), f"Bearer {KEY}".encode())

    def do_GET(self):
        if not self._auth():
            return self._send(401, {"error": "unauthorized"})
        try:
            if self.path == "/models":
                return self._send(200, models())
            if self.path == "/research":
                return self._send(200, research_get())
            return self._send(404, {"error": "not found"})
        except Exception as e:  # noqa: BLE001
            return self._send(500, {"error": f"{type(e).__name__}: {str(e)[:300]}"})

    def do_POST(self):
        if not self._auth():
            return self._send(401, {"error": "unauthorized"})
        try:
            n = int(self.headers.get("Content-Length") or 0)
            if n > 200_000:
                return self._send(413, {"error": "too large"})
            b = json.loads(self.rfile.read(n) or b"{}")
            if self.path == "/complete":
                return self._send(200, complete(b))
            if self.path == "/research":
                return self._send(200, research_set(b))
            return self._send(404, {"error": "not found"})
        except ValueError as e:
            return self._send(400, {"error": str(e)[:300]})
        except Exception as e:  # noqa: BLE001
            return self._send(502, {"error": f"{type(e).__name__}: {str(e)[:300]}"})


if __name__ == "__main__":
    print(f"netmon llm broker on http://{HOST}:{PORT}", file=sys.stderr)
    ThreadingHTTPServer((HOST, PORT), H).serve_forever()
