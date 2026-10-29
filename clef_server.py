"""Decision-model server (clef) as seen from the host: settings, status and control.

Two backends (setting `backend`):
  patapsco (default): Cloudflare/clef served by SGLang on the Patapsco AI cluster on this host (ModelDeployment
            default/clef, stack netmon-clef), reached on loopback through NodePort service netmon-clef-host
            (http://127.0.0.1:30891, /v1/systemone). Start/stop scale the ModelDeployment's replicas; restart replaces the pod.
  host:     the older llama.cpp llama-server under systemd user unit netmon-clef (clef.sh) on port `port`.

Used by host_broker.py (POST /clef, for the dashboard's AI review > Decision model server box) and by clef.sh
(`python3 clef_server.py env` prints the saved settings as shell assignments). Settings live in the netmon database
(docs table, document "clef_server") - never in a file. Environment variables CLEF_* still override them.
"""
import glob
import json
import os
import shlex
import subprocess
import sys
import urllib.request

NM = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, NM)
import store  # noqa: E402

UNIT = "netmon-clef"
DOC = "clef_server"
HOME = os.path.expanduser("~")
MODELS = os.path.join(HOME, ".lmstudio", "models")
BACKENDS = os.path.join(HOME, ".lmstudio", "extensions", "backends")
DEFAULTS = {"backend": "patapsco", "gguf": "", "server": "", "port": 8091, "ctx": 32768, "parallel": 4, "batch": 8192}
BACKENDS_ALLOWED = ("patapsco", "host")
PAI_NS, PAI_MODEL, PAI_STACK, PAI_PORT = "default", "clef", "netmon-clef", 30891
PAI_URL = f"http://127.0.0.1:{PAI_PORT}"
LIMITS = {"port": (1024, 65535), "ctx": (2048, 262144), "parallel": (1, 16), "batch": (512, 32768)}


def models():
    """clef GGUFs on disk (mmproj projector files excluded), largest model family first."""
    out = []
    for p in sorted(glob.glob(os.path.join(MODELS, "*", "*clef*", "*.gguf"))):
        if os.path.basename(p).startswith("mmproj"):
            continue
        out.append({"path": p, "name": os.path.basename(p), "gb": round(os.path.getsize(p) / 1e9, 2),
                    "flash": "flash" in os.path.basename(p).lower()})
    return out


def servers():
    """llama-server binaries from LM Studio's llama.cpp backends, newest version last."""
    import re

    def ver(p):  # "...-cuda13-2.65.1/llama-server" -> (cuda first, (2, 65, 1))
        m = re.search(r"-(\d+(?:\.\d+)+)/llama-server$", p)
        return ("cuda" in p, tuple(int(x) for x in m.group(1).split(".")) if m else ())
    return sorted(glob.glob(os.path.join(BACKENDS, "llama.cpp-*", "llama-server")), key=ver)


def settings():
    s = {**DEFAULTS, **(store.doc_get(DOC, {}) or {})}
    return {k: s.get(k, v) for k, v in DEFAULTS.items()} | {"by": s.get("by"), "at": s.get("at")}


def validate(b):
    """Checked settings from a request (raises ValueError). Only files clef_server itself lists may be chosen."""
    s = {k: v for k, v in settings().items() if k in DEFAULTS}
    if "backend" in b and b["backend"] not in (None, ""):
        if b["backend"] not in BACKENDS_ALLOWED:
            raise ValueError("backend must be patapsco or host")
        s["backend"] = b["backend"]
    if "gguf" in b:
        g = str(b["gguf"] or "")
        if g and g not in {m["path"] for m in models()}:
            raise ValueError("unknown model file - pick one from the list")
        s["gguf"] = g
    if "server" in b:
        v = str(b["server"] or "")
        if v and v not in servers():
            raise ValueError("unknown llama-server - pick one from the list")
        s["server"] = v
    for k, (lo, hi) in LIMITS.items():
        if k in b and b[k] not in (None, ""):
            v = int(b[k])
            if not lo <= v <= hi:
                raise ValueError(f"{k} must be {lo}-{hi}")
            s[k] = v
    if int(s["batch"]) < 4096:  # a decision model reads its whole input in one micro-batch: smaller hangs on long events
        raise ValueError("batch must be at least 4096 (clef reads the whole input in one batch)")
    return s


def save(b, user):
    s = validate(b)
    store.doc_put(DOC, {**s, "by": user, "at": __import__("time").time()})
    return settings()


def _ctl(*args, timeout=30):
    r = subprocess.run(["systemctl", "--user", *args], capture_output=True, text=True, timeout=timeout)
    return r.returncode, (r.stdout + r.stderr).strip()


def url():
    """Where the decision model answers for the saved backend (always loopback)."""
    s = settings()
    return PAI_URL if s.get("backend") == "patapsco" else f"http://127.0.0.1:{s['port']}"


def _kubectl(*args, timeout=30):
    import shutil
    exe = shutil.which("kubectl") or "/usr/local/bin/kubectl"
    r = subprocess.run([exe, "-n", PAI_NS, *args], capture_output=True, text=True, timeout=timeout)
    return r.returncode, (r.stdout if r.returncode == 0 else r.stdout + r.stderr).strip()


def _pai_status(s):
    out = {"backend": "patapsco", "unit": f"Patapsco AI {PAI_NS}/{PAI_MODEL} (stack {PAI_STACK})", "settings": s,
           "models": [], "servers": [], "url": PAI_URL}
    rc, raw = _kubectl("get", "modeldeployment", PAI_MODEL, "-o", "json")
    if rc:
        out.update(active="missing", enabled="unknown", running=None, probe_error=raw[:200], log=[])
        return out
    md = json.loads(raw)
    reps = int((md.get("spec") or {}).get("replicas") or 0)
    ready = any(c.get("type") == "Ready" and c.get("status") == "True" for c in (md.get("status") or {}).get("conditions") or [])
    out["active"] = "active" if reps and ready else ("activating" if reps else "inactive")
    out["enabled"] = "enabled" if reps else "disabled"
    out["replicas"] = reps
    out["image"] = ((md.get("spec") or {}).get("runtimeConfig") or {}).get("image")
    try:
        with urllib.request.urlopen(PAI_URL + "/get_model_info", timeout=3) as r:  # noqa: S310 - loopback
            p = json.loads(r.read().decode())
        try:
            with urllib.request.urlopen(PAI_URL + "/get_server_info", timeout=3) as r:  # noqa: S310 - loopback
                si = json.loads(r.read().decode())
        except Exception:  # noqa: BLE001
            si = {}
        out["running"] = {"model": p.get("model_path") or "Cloudflare/clef", "slots": si.get("max_running_requests"),
                          "ctx_per_slot": si.get("context_length"), "build": "SGLang " + str(si.get("version") or "")}
    except Exception as e:  # noqa: BLE001
        out["running"] = None
        out["probe_error"] = f"{type(e).__name__}: {str(e)[:150]}"
    rc, log = _kubectl("logs", f"{PAI_STACK}-{PAI_MODEL}-lws-0", "-c", "vllm", "--tail", "400", timeout=15)
    out["log"] = [l[:300] for l in log.splitlines() if "error" in l.lower() or "supervisor" in l or "Uvicorn" in l or "fired up" in l][-12:] if not rc else [log[:300]]
    return out


def status():
    s = settings()
    if s.get("backend") == "patapsco":
        return _pai_status(s)
    rc, active = _ctl("is-active", UNIT)
    _, enabled = _ctl("is-enabled", UNIT)
    out = {"backend": "host", "unit": UNIT, "active": active.splitlines()[-1] if active else "unknown", "enabled": enabled.splitlines()[-1] if enabled else "unknown",
           "settings": s, "models": models(), "servers": servers(), "url": f"http://127.0.0.1:{s['port']}"}
    try:
        with urllib.request.urlopen(out["url"] + "/props", timeout=3) as r:  # noqa: S310 - loopback
            p = json.loads(r.read().decode())
        out["running"] = {"model": p.get("model_path"), "slots": p.get("total_slots"), "build": p.get("build_info"),
                          "ctx_per_slot": (p.get("default_generation_settings") or {}).get("n_ctx")}
    except Exception as e:  # noqa: BLE001
        out["running"] = None
        out["probe_error"] = f"{type(e).__name__}: {str(e)[:150]}"
    try:
        log = subprocess.run(["journalctl", "--user", "-u", UNIT, "-n", "400", "--no-pager", "-o", "cat"], capture_output=True, text=True, timeout=10).stdout
        out["log"] = [l[:300] for l in log.splitlines() if " E " in l or "error" in l.lower() or "clef.sh" in l or "listening" in l][-12:]
    except Exception:  # noqa: BLE001
        out["log"] = []
    return out


def control(action):
    if action not in ("start", "stop", "restart", "enable", "disable"):
        raise ValueError("action must be start, stop, restart, enable or disable")
    if settings().get("backend") == "patapsco":
        if action == "restart":
            rc, msg = _kubectl("delete", "pod", f"{PAI_STACK}-{PAI_MODEL}-lws-0", "--wait=false")
        else:
            n = 1 if action in ("start", "enable") else 0
            rc, msg = _kubectl("patch", "modeldeployment", PAI_MODEL, "--type", "merge", "-p", json.dumps({"spec": {"replicas": n}}))
        if rc:
            raise RuntimeError(f"kubectl {action} failed: {msg[:300]}")
        return {"ok": True, "action": action}
    args = ["enable", "--now", UNIT] if action == "enable" else ["disable", "--now", UNIT] if action == "disable" else [action, UNIT]
    rc, msg = _ctl(*args, timeout=60)
    if rc:
        raise RuntimeError(f"systemctl {' '.join(args)} failed: {msg[:300]}")
    return {"ok": True, "action": action}


def shell_env():
    """Saved settings as CLEF_* shell assignments for clef.sh (environment variables set by the caller win)."""
    s = settings()
    pairs = {"CLEF_GGUF": s["gguf"], "CLEF_SERVER": s["server"], "CLEF_PORT": s["port"], "CLEF_CTX": s["ctx"],
             "CLEF_PARALLEL": s["parallel"], "CLEF_BATCH": s["batch"]}
    return "\n".join(f': "${{{k}:={shlex.quote(str(v))}}}"' for k, v in pairs.items() if v not in ("", None))


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "status"
    if cmd == "env":
        try:
            print(shell_env())
        except Exception as e:  # noqa: BLE001 - clef.sh falls back to its own defaults
            print(f"# clef_server: settings unavailable: {e}", file=sys.stderr)
    else:
        print(json.dumps(status(), indent=2, default=str))
