#!/usr/bin/python3
"""Export the status of the Hermes cron jobs that run Claude triage/enrichment to the dashboard.

The dashboard container cannot read ~/.hermes/cron, so this host script copies the relevant part to
dashboard/state/claude_jobs.json (atomic write). Run by the 15-minute watcher (netmon_watch.sh) and by
enrich.sh, so the AI-review page shows: schedule, next run, whether a run is going on now, recent runs with
duration/outcome/error, and the latest run summary.

Jobs exported: Hermes cron jobs that load the home-network-report or netmon skill, or the ids in
site.json "claude_jobs" (list). Read-only on ~/.hermes/cron.
"""
import datetime as dt, glob, json, os, sqlite3, sys

HOME = os.environ.get("HERMES_HOME") or os.path.expanduser("~/.hermes")
NM = os.environ.get("NETMON_DIR") or os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(NM, "dashboard", "state", "claude_jobs.json")
SKILLS = {"home-network-report", "netmon"}


def _iso(s):
    try:
        return dt.datetime.fromisoformat(s).timestamp() if s else None
    except ValueError:
        return None


def _jobs():
    d = json.load(open(os.path.join(HOME, "cron", "jobs.json")))
    jobs = d["jobs"] if isinstance(d, dict) else d
    want = set()
    try:
        sys.path.insert(0, NM)
        import site_cfg
        want = set(site_cfg.get("claude_jobs") or [])
    except Exception:  # noqa: BLE001
        pass
    return [j for j in jobs if j.get("id") in want or SKILLS & set(j.get("skills") or [j.get("skill")])]


def _runs(job_id, n=12):
    p = os.path.join(HOME, "cron", "executions.db")
    if not os.path.exists(p):
        return []
    c = sqlite3.connect(f"file:{p}?mode=ro", uri=True, timeout=5)
    rows = c.execute("SELECT status, source, claimed_at, started_at, finished_at, progress_at, error, scheduled_instant FROM executions "
                     "WHERE job_id=? ORDER BY claimed_at DESC LIMIT ?", (job_id, n * 2)).fetchall()
    out = []
    for st, src, cl, sa, fa, pa, err, sch in rows:
        if st == "failed" and (err or "").startswith("Fire claim was not acquired"):
            continue  # duplicate fire suppressed while a run was going on: not a real run
        s, f = _iso(sa) or _iso(cl), _iso(fa)
        out.append({"status": st, "trigger": "manual" if src == "direct" else "schedule", "started": s, "finished": f,
                    "progress": _iso(pa), "duration_s": round(f - s) if s and f else None, "error": (err or "")[:300] or None,
                    "pdf_run": (sch or sa or cl or "")[11:13] == "05"})
    return out[:n]


def _summary(job_id):
    files = sorted(glob.glob(os.path.join(HOME, "cron", "output", job_id, "*.md")))
    if not files:
        return None
    t = open(files[-1], errors="replace").read()
    i = t.rfind("## Response")
    body = (t[i + len("## Response"):] if i >= 0 else t[-2000:]).strip()
    return {"at": os.path.getmtime(files[-1]), "text": body[:2000]}


def main():
    jobs = []
    for j in _jobs():
        runs = _runs(j["id"])
        jobs.append({"id": j["id"], "name": j.get("name"), "model": j.get("model"), "enabled": j.get("enabled", True),
                     "state": j.get("state"), "schedule": (j.get("schedule") or {}).get("expr") or j.get("schedule_display"),
                     "next_run": _iso(j.get("next_run_at")), "last_run": _iso(j.get("last_run_at")), "last_status": j.get("last_status"),
                     "last_error": (j.get("last_error") or "")[:300] or None, "failure_streak": j.get("failure_streak") or 0,
                     "running": next((r for r in runs if r["status"] in ("running", "claimed")), None),
                     "runs": runs, "summary": _summary(j["id"])})
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    tmp = OUT + ".tmp"
    json.dump({"exported": dt.datetime.now(dt.timezone.utc).timestamp(), "jobs": jobs}, open(tmp, "w"), indent=1)
    os.replace(tmp, OUT)
    return len(jobs)


if __name__ == "__main__":
    try:
        print("claude_jobs:", main())
    except Exception as e:  # noqa: BLE001 - status export must never break the watcher
        print("claude_status failed:", e, file=sys.stderr)
