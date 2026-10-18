"""netmon LLM broker: lets the dashboard container use Anthropic models and change the research job's model.

The dashboard runs in a locked-down container without provider credentials. This small loopback-only HTTP
service runs on the host under Hermes' own runtime (so it uses Hermes' configured Anthropic credentials
through agent.auxiliary_client.call_llm - no key is copied anywhere) and offers exactly three things:

  GET  /models              local (LM Studio) + Anthropic + OpenAI models the dashboard may pick
  GET  /openai-key          {set, hint} - whether an OpenAI API key is configured (never the key itself)
  POST /openai-key          {key} or {remove: true} -> `hermes config set OPENAI_API_KEY` in the main and
                            netmonchat profiles (key is validated against api.openai.com first)
  POST /complete            one chat completion {provider, model, system, user, max_tokens, json_schema?}
  GET  /research            the research cron job's current model/provider
  POST /research            {provider, model} -> `hermes cron edit <job> --model .. --provider ..`
  POST /research/schedule   {hours, minutes} -> `hermes cron edit <job> --schedule ..` (30 min - 24 h)
  GET  /costlimit           Hermes cost_limit plugin: enabled?, max_run_usd, max_session_usd, recent stops
  POST /costlimit           {max_run_usd, max_session_usd} -> `hermes config set plugins.entries.cost_limit...`
  POST /range               {start, end} (UTC ISO, whole minutes) -> background `collect.py --start --end --out` +
                            `analyze.py --readonly` into dashboard/state/ranges/<id>.json (the dashboard's time
                            range picker; the container has no Elasticsearch key). Progress: <id>.status.json.

Every request needs "Authorization: Bearer <NETMON_BROKER_KEY>" (dashboard/.env). Provider must be
"anthropic", "openai-api" or "lmstudio" and the model must be in /models. Run: llm_broker.sh (systemd user unit
netmon-llm-broker.service, see docs/SETUP.md).
"""
import glob, hmac, json, os, re, subprocess, sys, threading, time, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

NM = os.path.dirname(os.path.abspath(__file__))
HOME = os.environ.get("HERMES_HOME") or os.path.expanduser("~/.hermes")
HOST, PORT = "127.0.0.1", int(os.environ.get("NETMON_BROKER_PORT", "8650"))
LMS = os.environ.get("NETMON_LLM_URL", "http://127.0.0.1:1234/v1").rstrip("/")
MAX_TOKENS = 4000
RATE = (120, 3600)  # cloud (Anthropic + OpenAI) completions per hour (comparisons + correlation review)
CLOUD = ("anthropic", "openai-api")
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


_oa_cache = {"at": 0.0, "ids": None, "key": ""}


def _openai_key():
    """Read live from Hermes' .env, so a key saved here or with `hermes config set` is seen without a restart."""
    try:
        from hermes_cli.config import get_env_value_prefer_dotenv
        return (get_env_value_prefer_dotenv("OPENAI_API_KEY") or "").strip()
    except Exception:  # noqa: BLE001
        return (os.environ.get("OPENAI_API_KEY") or "").strip()


def openai_models():
    """Hermes' curated OpenAI API list, limited to models this key can use (live /v1/models, cached 1 h).
    Empty when no OPENAI_API_KEY is configured."""
    key = _openai_key()
    if not key:
        return []
    try:
        from hermes_cli.models_catalog_static import _PROVIDER_MODELS as M  # noqa: N811
        ids = list(M.get("openai-api") or [])
    except Exception:  # noqa: BLE001
        ids = []
    ids = ids or ["gpt-5.5", "gpt-5.4", "gpt-5.4-mini", "gpt-5-mini", "gpt-4.1"]
    c = _oa_cache
    if c["key"] != key or time.time() - c["at"] > 3600:
        try:
            req = urllib.request.Request("https://api.openai.com/v1/models", headers={"Authorization": f"Bearer {key}"})
            live = {m["id"] for m in json.load(urllib.request.urlopen(req, timeout=10)).get("data", [])}  # noqa: S310 - fixed https URL
            c.update(at=time.time(), ids=live, key=key)
        except Exception:  # noqa: BLE001 - offline: fall back to the curated list
            c.update(at=time.time() - 3000, ids=None, key=key)
    return [m for m in ids if c["ids"] is None or m in c["ids"]]


def _env_files():
    return [os.path.join(HOME, ".env"), os.path.join(HOME, "profiles", "netmonchat", ".env")]


def openai_key_get():
    k = _openai_key()
    return {"set": bool(k), "hint": f"…{k[-4:]}" if len(k) > 12 else ""}


def openai_key_set(b):
    """Save (or remove) the OpenAI API key for Hermes: main profile (research job, broker) + netmonchat (Ask Hermes)."""
    hermes = os.path.expanduser("~/.local/bin/hermes")
    if b.get("remove"):
        key = ""
    else:
        key = str(b.get("key") or "").strip()
        if not re.fullmatch(r"sk-[A-Za-z0-9_\-]{20,300}", key):
            raise ValueError("that does not look like an OpenAI API key (sk-...)")
        req = urllib.request.Request("https://api.openai.com/v1/models", headers={"Authorization": f"Bearer {key}"})
        try:
            urllib.request.urlopen(req, timeout=15).read()  # noqa: S310 - fixed https URL
        except urllib.error.HTTPError as e:
            raise ValueError(f"OpenAI rejected the key (HTTP {e.code})") from None
        except OSError as e:
            raise ValueError(f"could not reach api.openai.com: {e}") from None
    for home in (HOME, os.path.join(HOME, "profiles", "netmonchat")):
        if not os.path.isdir(home):
            continue
        argv = [hermes, "config", "set", "OPENAI_API_KEY", key] if key else [hermes, "config", "unset", "OPENAI_API_KEY"]
        p = subprocess.run(argv, capture_output=True, text=True, timeout=60, env={**os.environ, "HERMES_HOME": home})  # noqa: S603 - fixed argv, validated key
        if p.returncode and key:  # unset of a missing key may fail; harmless
            raise ValueError(re.sub(r"sk-[A-Za-z0-9_\-]+", "sk-…", (p.stderr or p.stdout)[-300:]))
    if key:
        os.environ["OPENAI_API_KEY"] = key
    else:
        os.environ.pop("OPENAI_API_KEY", None)
    _oa_cache.update(at=0.0, key="")
    # Ask Hermes (netmonchat gateway) reads its .env at start; restart it so the new key is used (best effort)
    subprocess.run(["systemctl", "--user", "restart", "hermes-gateway-netmonchat.service"],  # noqa: S603, S607 - fixed argv
                   capture_output=True, timeout=120)
    return openai_key_get()


def local_models():
    try:
        d = json.load(urllib.request.urlopen(LMS.replace("/v1", "/api/v0") + "/models", timeout=5))  # noqa: S310 - fixed loopback URL
        return [{"id": m["id"], "loaded": m.get("state") == "loaded"} for m in d.get("data", []) if m.get("type") in ("llm", "vlm")]
    except Exception:  # noqa: BLE001
        return []


def chat_default():
    """Model the Ask Hermes profile (netmonchat) uses when the dashboard does not pick one."""
    out, inside = {}, False
    try:
        for line in open(os.path.join(HOME, "profiles", "netmonchat", "config.yaml")):
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            if not line[0].isspace():
                inside = line.startswith("model:")
                continue
            k, _, v = line.strip().partition(":")
            if inside and k in ("default", "provider"):
                out["model" if k == "default" else "provider"] = v.split("#")[0].strip().strip("'\"")
    except OSError:
        pass
    return out


def models():
    return {"anthropic": [{"id": m} for m in anthropic_models()], "openai": [{"id": m} for m in openai_models()],
            "local": local_models(), "chat_default": chat_default(), "openai_key": openai_key_get()}


def _allowed(provider, model):
    if provider == "anthropic":
        return model in anthropic_models()
    if provider == "openai-api":
        return model in openai_models()
    if provider == "lmstudio":
        return model in {m["id"] for m in local_models()}
    return False


def complete(b):
    from agent.auxiliary_client import call_llm
    provider, model = str(b.get("provider")), str(b.get("model"))
    if not _allowed(provider, model):
        raise ValueError("model not allowed")
    if provider in CLOUD:
        with _lock:
            now = time.time()
            _sent[:] = [t for t in _sent if now - t < RATE[1]]
            if len(_sent) >= RATE[0]:
                raise ValueError("rate limit: too many cloud model requests this hour")
            _sent.append(now)
    msgs = [{"role": "system", "content": str(b.get("system") or "")[:20000]}, {"role": "user", "content": str(b.get("user") or "")[:60000]}]
    t = time.time()
    mt = max(50, min(int(b.get("max_tokens") or 1000), MAX_TOKENS))
    if provider == "openai-api":  # GPT-5 reasoning tokens count against the same budget; leave room for the answer
        mt += 3000
    r = call_llm(provider=provider, model=model, messages=msgs, temperature=0, timeout=300, max_tokens=mt)
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
    return {"job": j["id"], "name": j.get("name"), "model": j.get("model"), "provider": j.get("provider"),
            "schedule": (j.get("schedule") or {}).get("expr") or (j.get("schedule") or {}).get("display") or j.get("schedule_display"),
            "schedule_kind": (j.get("schedule") or {}).get("kind"), "interval_minutes": interval_of(j.get("schedule") or {}),
            "next_run_at": j.get("next_run_at"), "last_run_at": j.get("last_run_at"), "last_status": j.get("last_status"),
            "enabled": j.get("enabled")}


def interval_of(s):
    """Minutes between runs for the schedules schedule_expr() writes (and the original 0 1,5,9,... cron)."""
    if s.get("kind") == "interval":
        return s.get("minutes")
    e = str(s.get("expr") or "").split()
    if len(e) != 5 or e[2:] != ["*", "*", "*"]:
        return None
    m, h = e[0], e[1]
    if m.startswith("*/") and h == "*":
        return int(m[2:])
    if m.isdigit() and h == "*":
        return 60
    if m.isdigit() and "/" in h:
        return 60 * int(h.split("/")[1])
    if m.isdigit() and "," in h:
        hs = [int(x) for x in h.split(",")]
        gaps = {(b - a) % 24 for a, b in zip(hs, hs[1:] + hs[:1])}
        return 60 * gaps.pop() if len(gaps) == 1 else None
    return None


def schedule_expr(minutes):
    """Even cron grid when the interval divides the day, anchored so 05:00 UTC (the daily PDF run) is always on it
    (4 h -> 1,5,9,13,17,21 like the original), else a plain interval."""
    if minutes < 60 and 60 % minutes == 0:
        return f"*/{minutes} * * * *"
    if minutes % 60 == 0 and 24 % (minutes // 60) == 0:
        h = minutes // 60
        return "0 * * * *" if h == 1 else f"0 {5 % h}-23/{h} * * *"
    return f"every {minutes}m"


def schedule_set(b):
    try:
        minutes = int(b.get("hours") or 0) * 60 + int(b.get("minutes") or 0)
    except (TypeError, ValueError):
        raise ValueError("hours and minutes must be whole numbers") from None
    if not 30 <= minutes <= 1440:
        raise ValueError("the review job can run every 30 minutes at most often, and at least once a day (24 h)")
    j = _job()
    hermes = os.path.expanduser("~/.local/bin/hermes")
    label = f"{minutes // 60}h" + (f"{minutes % 60:02d}m" if minutes % 60 else "") if minutes >= 60 else f"{minutes}m"
    name = re.sub(r"\((?:\d+h(?:\d+m)?|\d+m);", f"({label};", j.get("name") or "", count=1)  # "(4h; PDF 05 UTC)" label
    argv = [hermes, "cron", "edit", j["id"], "--schedule", schedule_expr(minutes)] + (["--name", name] if name and name != j.get("name") else [])
    p = subprocess.run(argv, capture_output=True, text=True, timeout=60)  # noqa: S603 - fixed argv, validated int
    if p.returncode:
        raise ValueError((p.stderr or p.stdout)[-300:])
    subprocess.run(["/usr/bin/python3", os.path.join(NM, "claude_status.py")],  # noqa: S603
                   capture_output=True, timeout=60)
    return research_get()


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


COST_KEYS = ("max_run_usd", "max_session_usd")
COST_MAX = 1000.0


def costlimit_get():
    """Settings of the Hermes cost_limit plugin (~/.hermes/plugins/cost_limit) plus its last stops from agent.log."""
    from hermes_cli.config import load_config_readonly
    pl = (load_config_readonly() or {}).get("plugins") or {}
    st = (((pl.get("entries") or {}).get("cost_limit") or {}).get("settings")) or {}
    out = {"installed": os.path.isfile(os.path.join(HOME, "plugins", "cost_limit", "__init__.py")),
           "enabled": "cost_limit" in (pl.get("enabled") or []) and "cost_limit" not in (pl.get("disabled") or [])}
    for k in COST_KEYS:
        try:
            out[k] = float(st.get(k) or 0)
        except (TypeError, ValueError):
            out[k] = 0.0
    stops = []
    for name in ("agent.log.1", "agent.log"):  # rotated file first so the newest stop ends up last
        try:
            with open(os.path.join(HOME, "logs", name), errors="replace") as f:
                for line in f:
                    if "cost_limit: stopping run" in line:
                        m = re.match(r"(\S+ \S+?)(?:,\d+)? .*?stopping run \(session ([^)]*)\): (.*)", line.strip())
                        if m:
                            stops.append({"at": m.group(1), "session": m.group(2)[:80], "reason": m.group(3)[:200]})
        except OSError:
            pass
    out["stops"] = stops[-5:]
    return out


def costlimit_set(b):
    vals = {}
    for k in COST_KEYS:
        if k not in b:
            continue
        try:
            v = round(float(b[k]), 2)
        except (TypeError, ValueError):
            raise ValueError(f"{k} must be a number of US dollars") from None
        if not 0 <= v <= COST_MAX:  # NaN fails this too
            raise ValueError(f"{k} must be between 0 (off) and {COST_MAX:.0f} USD")
        vals[k] = v
    if not vals:
        raise ValueError("nothing to change")
    hermes = os.path.expanduser("~/.local/bin/hermes")
    for k, v in vals.items():
        p = subprocess.run([hermes, "config", "set", f"plugins.entries.cost_limit.settings.{k}", f"{v:g}"],  # noqa: S603 - fixed argv, validated float
                           capture_output=True, text=True, timeout=60)
        if p.returncode:
            raise ValueError((p.stderr or p.stdout)[-300:])
    return costlimit_get()


# ------------------------------------------------------------------ dashboard time ranges
RANGES = os.path.join(NM, "dashboard", "state", "ranges")
RANGE_MAX_H, RANGE_MAX_AGE_D, RANGE_KEEP = 31 * 24, 120, 30
_range_lock = threading.Lock()
_range_running = {}


def _utc(s):
    import datetime as dt
    t = dt.datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    if not t.tzinfo:
        raise ValueError("start/end need a UTC offset")
    return t.astimezone(dt.timezone.utc).replace(second=0, microsecond=0)


def range_id(s, e):
    return "r" + s.strftime("%Y%m%dT%H%MZ") + "-" + e.strftime("%Y%m%dT%H%MZ")


def _rstatus(rid, **kw):
    p = os.path.join(RANGES, rid + ".status.json")
    cur = {}
    try:
        cur = json.load(open(p))
    except (OSError, ValueError):
        pass
    cur.update(kw, updated=time.time())
    with open(p + ".tmp", "w") as f:
        json.dump(cur, f)
    os.replace(p + ".tmp", p)
    return cur


def _prune():
    files = sorted(glob.glob(os.path.join(RANGES, "r*.json")), key=os.path.getmtime)
    ids = []
    for f in files:
        b = os.path.basename(f).split(".")[0]
        if b not in ids:
            ids.append(b)
    for b in ids[:-RANGE_KEEP]:
        for f in glob.glob(os.path.join(RANGES, b + ".*")):
            os.remove(f)


def _range_job(rid, s, e):
    out = os.path.join(RANGES, rid + ".json")
    t = time.time()
    try:
        _rstatus(rid, status="collecting", started=t, start=s.isoformat(), end=e.isoformat(), step="Querying Security Onion and UniFi")
        p = subprocess.run(["/usr/bin/python3", os.path.join(NM, "collect.py"), "--start", s.isoformat(), "--end", e.isoformat(), "--out", out],  # noqa: S603 - fixed argv, validated times
                           capture_output=True, text=True, timeout=3600, cwd=NM)
        if p.returncode or not os.path.exists(out):
            raise RuntimeError((p.stderr or p.stdout or "collect failed")[-400:])
        _rstatus(rid, status="analyzing", step="Comparing with the baseline")
        p = subprocess.run(["/usr/bin/python3", os.path.join(NM, "analyze.py"), out, "--readonly"],  # noqa: S603 - fixed argv
                           capture_output=True, text=True, timeout=900, cwd=NM)
        if p.returncode:
            raise RuntimeError((p.stderr or p.stdout or "analyze failed")[-400:])
        _rstatus(rid, status="done", step="", seconds=round(time.time() - t, 1))
        _prune()
    except Exception as ex:  # noqa: BLE001 - reported to the dashboard through the status file
        print(f"range {rid} failed: {ex}", file=sys.stderr)
        _rstatus(rid, status="failed", error=str(ex)[-400:], seconds=round(time.time() - t, 1))
    finally:
        with _range_lock:
            _range_running.pop(rid, None)


def range_start(b):
    import datetime as dt
    s, e = _utc(b.get("start")), _utc(b.get("end"))
    now = dt.datetime.now(dt.timezone.utc).replace(second=0, microsecond=0)
    e = min(e, now)
    if e <= s:
        raise ValueError("the end must be after the start (and not in the future)")
    if (e - s).total_seconds() < 15 * 60:
        raise ValueError("the range must be at least 15 minutes")
    if (e - s).total_seconds() > RANGE_MAX_H * 3600:
        raise ValueError(f"the range can be at most {RANGE_MAX_H // 24} days")
    if (now - s).days > RANGE_MAX_AGE_D:
        raise ValueError(f"the start can be at most {RANGE_MAX_AGE_D} days ago")
    os.makedirs(RANGES, exist_ok=True)
    rid = range_id(s, e)
    if os.path.exists(os.path.join(RANGES, rid + ".analysis.json")):
        return {"id": rid, "status": "done"}
    with _range_lock:
        if rid in _range_running:
            return {"id": rid, "status": "running"}
        if _range_running:
            raise ValueError("another time range is being collected - try again in a minute")
        _range_running[rid] = time.time()
    _rstatus(rid, status="queued", start=s.isoformat(), end=e.isoformat(), error="")
    threading.Thread(target=_range_job, args=(rid, s, e), daemon=True).start()
    return {"id": rid, "status": "running"}


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
            if self.path == "/costlimit":
                return self._send(200, costlimit_get())
            if self.path == "/openai-key":
                return self._send(200, openai_key_get())
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
            if self.path == "/research/schedule":
                return self._send(200, schedule_set(b))
            if self.path == "/costlimit":
                return self._send(200, costlimit_set(b))
            if self.path == "/range":
                return self._send(200, range_start(b))
            if self.path == "/openai-key":
                return self._send(200, openai_key_set(b))
            return self._send(404, {"error": "not found"})
        except ValueError as e:
            return self._send(400, {"error": str(e)[:300]})
        except Exception as e:  # noqa: BLE001
            return self._send(502, {"error": f"{type(e).__name__}: {str(e)[:300]}"})


if __name__ == "__main__":
    print(f"netmon llm broker on http://{HOST}:{PORT}", file=sys.stderr)
    ThreadingHTTPServer((HOST, PORT), H).serve_forever()
