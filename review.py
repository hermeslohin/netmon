#!/usr/bin/env python3
"""netmon review job: collect -> analyze -> reviewer -> queue. Runs on the schedule set on the AI review page.

Started by scheduler.py on the grid set on the dashboard (review_cfg.py), by Run now, or by hand:
    review.py [--trigger manual|schedule] [--skip-collect] [--daily | --no-daily]
The daily run is the first run at or after 05:00 UTC each day; it covers 24 h of logs so the device baseline stays daily.
Other runs cover the lookback window set on the AI review page.

The reviewer is the correlation reviewer's model (AI review > Models, e.g. Gemma on LM Studio). For each event in a
"review" category that has no note yet it compares the event with earlier notes (its family, correlated events, similar
labels) and copies a matching note, marked as copied. Everything it cannot match stays on AI review > Queue for a person.
The review job never writes new notes of its own.
Run state and token use go to <state>/review_job.json (AI review page). Conversations are saved under logs/review/
(git-ignored; the newest 60 are kept).
"""
import argparse, datetime as dt, fcntl, json, os, sys, time, traceback

NM = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, NM)
import aijob  # noqa: E402
from aijob import BATCH, prompt, sh, jload  # noqa: E402,F401
import agent  # noqa: E402
import review_cfg as RC  # noqa: E402

MAX_TOKENS = 25_000_000  # safety stop for one run (a local model costs nothing, but a loop must not run forever)


def reviewer_target():
    """The correlation reviewer's model (AI review > Models); raises when it is not usable."""
    import corr_llm
    return corr_llm._target()


# ------------------------------------------------------------------ run state (AI review page)
class Status:
    def __init__(self, target, trigger, daily):
        self.d = RC.status() or {}
        self.d.setdefault("runs", [])
        self.d.setdefault("usage", [])
        self.run = {"status": "running", "trigger": trigger, "started": time.time(), "finished": None, "progress": time.time(),
                    "duration_s": None, "error": None, "daily_run": daily, "phase": "starting",
                    "model": (target or {}).get("model"), "provider": (target or {}).get("provider")}
        self.d["runs"] = [self.run] + [r for r in self.d["runs"] if r.get("status") != "running"][:29]
        self.d["running"] = {"started": self.run["started"], "progress": self.run["progress"], "phase": "starting"}
        self.save()

    def phase(self, p):
        self.run.update(phase=p, progress=time.time())
        self.d["running"] = {"started": self.run["started"], "progress": time.time(), "phase": p}
        self.save()

    def finish(self, status, error, budget, summary, daily):
        now = time.time()
        self.run.update(status=status, finished=now, duration_s=round(now - self.run["started"]), error=(error or "")[:300] or None, phase=None)
        self.d["running"] = None
        u = budget.summary()
        self.d["usage"] = (self.d["usage"] + [{"at": now, "prompt": u["prompt"], "completion": u["completion"], "total": u["total"],
                                                "duration_s": self.run["duration_s"], "model": self.run["model"], "provider": self.run["provider"],
                                                "error": status != "completed", "daily_run": daily, "fresh": u["prompt"] - u["cache_read"] - u["cache_write"],
                                                "cache_read": u["cache_read"], "cache_write": u["cache_write"], "cost_usd": u["cost_usd"],
                                                "calls": u["calls"]}])[-600:]
        self.d["summary"] = {"at": now, "text": summary, "model": self.run["model"]}
        self.d["last_status"] = "ok" if status == "completed" else status
        self.d["last_error"] = self.run["error"]
        self.d["failure_streak"] = 0 if status == "completed" else int(self.d.get("failure_streak") or 0) + 1
        self.d["last_run"] = self.run["started"]
        self.save()

    def save(self):
        self.d["exported"] = time.time()
        RC.write_status(self.d)


# ------------------------------------------------------------------ the run
class Review(aijob.Job):
    LOGDIR, LABEL, SOURCE = os.path.join(NM, "logs", "review"), "Review run", "reviewer"  # its searches show with the reviewer's

    def __init__(self, target, daily, args):
        t = target or {"provider": "", "model": ""}
        super().__init__(t, args, agent.Budget(t["provider"], t["model"], MAX_TOKENS, None), web=False, es=True)
        self.daily, self.reviewer_ok = daily, bool(target)

    def queue(self):
        """Work list of the newest snapshot; review-category events without a note go to the reviewer, the rest wait in the queue."""
        out = self.stem + ".work.json"
        for attempt in range(3):  # the dashboard container may be restarting (deploy): retry instead of losing the run
            rc, o, err = sh([os.path.join(NM, "enrich.sh"), "events", out], timeout=600)
            if not rc:
                break
            time.sleep(20)
        if rc:
            raise RuntimeError(f"enrich.sh events failed: {(err or o)[-300:]}")
        d = jload(out, {})
        os.remove(out)
        items = d.get("events") or []
        self.counts["work_items"], self.counts["without_note"] = len(items), sum(1 for x in items if not x.get("note"))
        self.counts["review_only"], self.counts["review_covered"] = d.get("review_only", 0), d.get("review_covered", 0)
        todo = [x for x in items if x.get("mode") == "review" and not x.get("note")]
        self.counts["queued"] = sum(1 for x in items if x.get("mode") == "queue" and not x.get("note"))
        if not todo:
            return
        if not self.reviewer_ok:
            self.counts["queued"] += len(todo)
            self.errors.append("reviewer model unavailable (AI review > Models): review events left in the queue")
            return
        self.status.phase("reviewer")
        left = self.review_items(todo)
        self.counts["queued"] += len(left)

    def review_items(self, review):
        """Reviewer: for each item copy the most similar earlier note (marked as copied) or leave it queued.
        Returns the items left queued. Any failure leaves everything queued (nothing is silently dropped)."""
        if not review:
            return []
        decided = {}
        for b in range(0, len(review), BATCH * 2):
            batch = review[b:b + BATCH * 2]
            ids = {x["id"]: x for x in batch}

            def submit(a, ids=ids):
                n = 0
                for i, dcs in enumerate(a.get("decisions") or []):
                    if not isinstance(dcs, dict) or dcs.get("id") not in ids or dcs.get("action") not in ("copy", "queue"):
                        raise ValueError(f"decisions[{i}]: id must be one of the batch ids, action copy|queue")
                    if dcs["action"] == "copy":
                        if dcs.get("from") not in {p["id"] for p in ids[dcs["id"]].get("prior") or []}:
                            raise ValueError(f"decisions[{i}]: 'from' must be the id of one of that item's prior notes")
                        decided[dcs["id"]] = dict(id=dcs["id"], **{"from": dcs["from"]}, reason=str(dcs.get("reason") or "")[:400])
                    else:
                        decided[dcs["id"]] = None
                    n += 1
                missing = [i for i in ids if i not in decided]
                return {"ok": True, "decided": n} if not missing else f"error: stored, but no decision yet for: {missing}"
            cand = [x for x in batch if x.get("prior")]
            for x in batch:
                if not x.get("prior"):
                    decided[x["id"]] = None  # nothing earlier to compare with
            if not cand:
                continue
            ids = {x["id"]: x for x in cand}
            user = (f"Snapshot {os.path.basename(self.stem)}. {len(cand)} items to review against earlier notes:\n"
                    f"<work_items>\n{json.dumps(cand, ensure_ascii=False)[:60000]}\n</work_items>")
            T = self.tools(cand)
            T = {k: T[k] for k in ("es_search", "device_lookup", "notes_kb") if k in T}
            T["submit_review"] = (submit, "Store the copy / queue decision for every item (call once).",
                                  {"decisions": {"type": "array", "items": {"type": "object"}}}, ["decisions"])
            try:
                self.converse(f"review{b // (BATCH * 2) + 1}", prompt("analyst") + "\n\n" + prompt("reviewer"), user, T, ("submit_review",),
                              max_turns=20, max_tokens=6000)
            except agent.BudgetExceeded:
                raise
            except Exception as e:  # noqa: BLE001
                self.errors.append(f"reviewer batch {b // (BATCH * 2) + 1}: {str(e)[:200]}")
        copies = [v for v in decided.values() if v]
        if copies:
            rc, out, err = sh([os.path.join(NM, "enrich.sh"), "copy", "-"], timeout=300,
                              inp=json.dumps({"model": self.target["model"], "snapshot": os.path.basename(self.stem), "copies": copies}))
            if rc:
                self.errors.append(f"reviewer copy failed: {(err or out)[-200:]}")
                copies = []
            else:
                self.counts["review_copied"] = len(copies)
        done = {c["id"] for c in copies}
        return [x for x in review if x["id"] not in done]

    def go(self, status):
        self.status = status
        fatal = None
        for name, fn, must in (("collect + analyze", self.collect, True), ("queue", self.queue, False)):
            if fatal:
                continue
            status.phase(name)
            try:
                fn()
            except agent.BudgetExceeded as e:
                self.errors.append(f"{name}: stopped - {e}")
                fatal = fatal or str(e)
            except Exception as e:  # noqa: BLE001
                traceback.print_exc()
                self.errors.append(f"{name}: {str(e)[:300]}")
                if must:
                    fatal = str(e)
                    break
        return fatal

    def summary(self):
        c, u = self.counts, self.budget.summary()
        parts = [f"{'Daily run (24 h)' if self.daily else 'Review run'} on {os.path.basename(self.stem or '?')}"
                 + (f", reviewer {self.target['model']}." if self.reviewer_ok else ", no reviewer model.")]
        parts.append(f"Events without a note: {c.get('without_note', 0)} of {c.get('work_items', 0)}. "
                     f"Reviewer copied {c.get('review_copied', 0)} earlier notes; {c.get('queued', 0)} left in the queue.")
        parts.append(f"Tokens: {u['total']:,} in {u['calls']} calls" + (f", est. ${u['cost_usd']:.2f}" if u["cost_usd"] is not None else "") + ".")
        if self.errors:
            parts.append("Problems: " + "; ".join(self.errors)[:800])
        return " ".join(parts)


def daily_due():
    """First run at or after 05:00 UTC each day is the daily run (24 h window, feeds the device baseline)."""
    now = dt.datetime.now(dt.timezone.utc)
    if now.hour < RC.DAILY_HOUR:
        return False
    today = now.strftime("%Y-%m-%d")
    for r in (RC.status().get("runs") or []):
        if (r.get("daily_run") or r.get("pdf_run")) and r.get("status") == "completed" and time.strftime("%Y-%m-%d", time.gmtime(r.get("started") or 0)) == today:
            return False
    return True


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--daily", action="store_true", help="force the 24 h daily window")
    ap.add_argument("--no-daily", action="store_true")
    ap.add_argument("--trigger", default="manual")
    ap.add_argument("--skip-collect", action="store_true", help="use the newest existing snapshot")
    args = ap.parse_args()
    try:
        target = reviewer_target()
    except Exception as e:  # noqa: BLE001 - collect + analyze still run; review events stay queued
        print(f"reviewer model unavailable: {e}", file=sys.stderr)
        target = None
    lock = open(os.path.join(RC.STATE, ".review.lock"), "w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        print("another review run is in progress", file=sys.stderr)
        return 3
    daily = args.daily or (not args.no_daily and daily_due())
    run = Review(target, daily, args)
    st = Status(target, args.trigger, daily)
    fatal = None
    try:
        fatal = run.go(st)
    except BaseException as e:  # noqa: BLE001 - record the failure even on Ctrl-C / kill
        fatal = f"{type(e).__name__}: {e}"
        run.errors.append(fatal)
        raise
    finally:
        s = run.summary()
        st.finish("failed" if fatal else "completed", fatal or ("; ".join(run.errors)[:300] if run.errors else None), run.budget, s, daily)
        print(s)
    return 1 if fatal else 0


if __name__ == "__main__":
    sys.exit(main())
