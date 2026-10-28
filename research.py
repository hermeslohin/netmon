#!/usr/bin/env python3
"""netmon event research: researches ONE event a person sent to research. Never scheduled.

Started only by the dashboard's Send to research button (host broker -> research.py --event ID), or by hand:
    research.py --event ID [--max-batches N]
Uses the newest snapshot (no collect). The research model, cost caps, web and Elasticsearch access are the settings in
research_cfg.py (AI review > Research). The AI writes research notes, link verdicts and host notes through enrich.sh
(dashboard container); sources it cites are kept in data/<stamp>.sources.json.
Token use and cost per researched event go to <state>/research_job.json (AI review page). Conversations are saved under
logs/research/ (git-ignored; the newest 60 are kept).
"""
import argparse, fcntl, json, os, sys, time, traceback

NM = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, NM)
import aijob  # noqa: E402
from aijob import BATCH, prompt, sh, jload  # noqa: E402,F401
import agent  # noqa: E402
import llm_providers as LP  # noqa: E402
import research_cfg as RC  # noqa: E402

VIA = "netmon research"
VERDICTS = ("malicious", "suspicious", "needs-review", "benign", "expected")
PRIOS = ("Investigate", "Review", "Info")


class Usage:
    """Adds one research run's token use and the per-event records to research_job.json."""
    def __init__(self, target, eid):
        self.target, self.t0, self.researched = target, time.time(), []
        d = RC.status() or {}
        d["running"] = {"started": self.t0, "event": eid}  # header microscope (dashboard /api/research/running)
        RC.write_status(d)

    def phase(self, p):
        pass

    def finish(self, status, budget):
        d, u = RC.status() or {}, budget.summary()
        d["usage"] = ((d.get("usage") or []) + [{"at": time.time(), "prompt": u["prompt"], "completion": u["completion"], "total": u["total"],
                                                  "duration_s": round(time.time() - self.t0), "model": self.target["model"], "provider": self.target["provider"],
                                                  "error": status != "completed", "fresh": u["prompt"] - u["cache_read"] - u["cache_write"],
                                                  "cache_read": u["cache_read"], "cache_write": u["cache_write"], "cost_usd": u["cost_usd"], "calls": u["calls"],
                                                  "event_run": True}])[-600:]
        d["researched"] = ((d.get("researched") or []) + self.researched)[-500:]
        d["running"] = None
        RC.write_status(d)


class Research(aijob.Job):
    LOGDIR, LABEL, SOURCE = os.path.join(NM, "logs", "research"), "Research", "research"

    def __init__(self, target, args):
        cfg = RC.get()
        super().__init__(target, args, agent.Budget(target["provider"], target["model"], cfg["max_run_tokens"] or None, cfg["max_run_usd"] or None),
                         web=cfg.get("web_research", True), es=cfg.get("es_search", True), max_searches=cfg.get("max_searches", 3))
        self.max_batches = args.max_batches if args.max_batches is not None else cfg["max_batches"]
        self.researched = []  # one record per researched event (tokens + cost; a batch's use is split evenly over its events)

    def t_notes_factory(self, batch):
        self.es_found = []  # a new batch starts here
        ids = set()
        for it in batch:
            ids.add(it["id"])
            ids.update(it.get("other_ids") or [])
            ids.update(r.get("id") for r in it.get("related") or [] if isinstance(r, dict) and r.get("id"))

        def submit(a):
            notes = []
            for i, n in enumerate(a.get("notes") or []):
                if not isinstance(n, dict) or n.get("id") not in ids:
                    raise ValueError(f"notes[{i}]: id must be one of this batch's ids")
                if n.get("verdict") not in VERDICTS or n.get("priority") not in PRIOS:
                    raise ValueError(f"notes[{i}]: verdict {VERDICTS} and priority {PRIOS} are required")
                notes.append({"id": n["id"], "verdict": n["verdict"], "priority": n["priority"], "summary": str(n.get("summary") or "")[:600],
                              "research": str(n.get("research") or "")[:4000], "links": self._links(n.get("links"), f"notes[{i}]"),
                              "queries": self.queries_for(n["id"])})
            links = [{**l, "queries": self.queries_for(l["a"], l["b"])} for l in a.get("links") or [] if isinstance(l, dict) and l.get("a") and l.get("b")]
            doc = {"model": self.target["model"], "via": VIA, "snapshot": os.path.basename(self.stem), "notes": notes, "links": links,
                   "host_notes": [h for h in a.get("host_notes") or [] if isinstance(h, dict)],
                   "host_notes_delete": [x for x in a.get("host_notes_delete") or [] if isinstance(x, (int, str))]}
            rc, out, err = sh([os.path.join(NM, "enrich.sh"), "put", "-"], timeout=300, inp=json.dumps(doc))
            if rc:
                raise RuntimeError((err or out)[-400:])
            res = {"output": out[-600:]}
            for line in reversed(out.splitlines()):
                if line.startswith("{"):
                    try:
                        res = json.loads(line)
                        break
                    except ValueError:
                        pass
            for k in ("notes", "links", "host_notes_added", "host_notes_updated"):
                if isinstance(res.get(k), int):
                    self.counts[k] = self.counts.get(k, 0) + res[k]
            if res.get("rejected_ids"):
                return f"error: stored the rest, but these ids were rejected - fix and resubmit only those: {res['rejected_ids']}"
            return res
        return submit

    def tools(self, batch=None):
        T = super().tools(batch)
        T["submit_notes"] = (self.t_notes_factory(batch), "Store research notes, link verdicts and host notes for this batch.",
                             {"notes": {"type": "array", "items": {"type": "object"}}, "links": {"type": "array", "items": {"type": "object"}},
                              "host_notes": {"type": "array", "items": {"type": "object"}},
                              "host_notes_delete": {"type": "array", "items": {"type": "integer"}}}, ["notes"])
        return T

    def research(self):
        out = self.stem + ".work.json"
        for attempt in range(3):  # the dashboard container may be restarting (deploy): retry instead of losing the request
            rc, o, err = sh([os.path.join(NM, "enrich.sh"), "events", out, "--only", self.args.event], timeout=600)
            if not rc:
                break
            time.sleep(20)
        if rc:
            raise RuntimeError(f"enrich.sh events failed: {(err or o)[-300:]}")
        d = jload(out, {})
        os.remove(out)
        items = d.get("events") or []
        todo = [x for x in items if not x.get("note")] + [x for x in items if x.get("note") and str(x.get("id", "")).split("|")[0] in ("ids", "gw", "hf")]
        self.counts["work_items"], self.counts["without_note"] = len(items), sum(1 for x in items if not x.get("note"))
        sysmsg = prompt("analyst") + "\n\n" + prompt("enrich")
        for b in range(0, min(len(todo), self.max_batches * BATCH), BATCH):
            batch = todo[b:b + BATCH]
            user = (f"Snapshot {os.path.basename(self.stem)}. Batch of {len(batch)} work items"
                    f"{' (these already have notes: only rewrite a note if this run contradicts it)' if all(x.get('note') for x in batch) else ''}:\n"
                    f"<work_items>\n{json.dumps(batch, ensure_ascii=False)[:60000]}\n</work_items>{self.NOWEB if not self.web else ''}")
            before = self.budget.summary()
            try:
                self.converse(f"research{b // BATCH + 1}", sysmsg, user, self.tools(batch), ("submit_notes",), max_turns=40, max_tokens=8000)
                self.counts["batches"] = self.counts.get("batches", 0) + 1
            except agent.BudgetExceeded:
                raise
            except Exception as e:  # noqa: BLE001 - one bad batch must not stop the others
                self.errors.append(f"research batch {b // BATCH + 1}: {str(e)[:200]}")
            finally:
                self.record_batch(batch, before)

    def record_batch(self, batch, before):
        """Tokens and cost of one research batch, split evenly over its events (exact when one event is researched)."""
        after, n = self.budget.summary(), max(1, len(batch))
        d = {k: after[k] - before[k] for k in ("prompt", "completion", "cache_read", "cache_write")}
        usd = None if after["cost_usd"] is None else round(after["cost_usd"] - (before["cost_usd"] or 0), 4)
        now = time.time()
        for it in batch:
            self.researched.append({"at": now, "id": it.get("id"), "label": str(it.get("label") or it.get("id") or "")[:200], "type": it.get("type"),
                                    "model": self.target["model"], "provider": self.target["provider"], "batch": n,
                                    "prompt": round(d["prompt"] / n), "completion": round(d["completion"] / n),
                                    "cache_read": round(d["cache_read"] / n), "cache_write": round(d["cache_write"] / n),
                                    "total": round((d["prompt"] + d["completion"]) / n), "cost_usd": None if usd is None else round(usd / n, 4)})

    def go(self):
        try:
            self.collect()
        except Exception as e:  # noqa: BLE001
            traceback.print_exc()
            self.errors.append(f"snapshot: {str(e)[:300]}")
            return str(e)
        try:
            self.research()
        except agent.BudgetExceeded as e:
            self.errors.append(f"research: stopped - {e}")
            return str(e)
        except Exception as e:  # noqa: BLE001
            traceback.print_exc()
            self.errors.append(f"research: {str(e)[:300]}")
        return None

    def summary(self):
        c, u = self.counts, self.budget.summary()
        parts = [f"Research of {self.args.event} on {os.path.basename(self.stem or '?')} with {self.target['model']}."]
        parts.append(f"Research notes stored: {c.get('notes', 0)}, link verdicts: {c.get('links', 0)}, "
                     f"host notes added/updated: {c.get('host_notes_added', 0)}/{c.get('host_notes_updated', 0)}.")
        parts.append(f"Tokens: {u['total']:,} in {u['calls']} calls" + (f", est. ${u['cost_usd']:.2f}" if u["cost_usd"] is not None else "") + ".")
        if self.errors:
            parts.append("Problems: " + "; ".join(self.errors)[:800])
        return " ".join(parts)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--event", required=True, help="the event id a person sent to research")
    ap.add_argument("--trigger", default="manual", help="who asked (logged only)")
    ap.add_argument("--max-batches", type=int)
    args = ap.parse_args()
    args.skip_collect = True  # research works on the snapshot the person was looking at
    cfg = RC.get()
    target = {"provider": cfg["provider"], "model": cfg["model"]}
    if not LP.allowed(target["provider"], target["model"]):
        print(f"research model not configured or unavailable ({target}); pick one on AI review > Models", file=sys.stderr)
        return 2
    lock = open(os.path.join(RC.STATE, ".research-event.lock"), "w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        print("another research run is in progress", file=sys.stderr)
        return 3
    if cfg["max_day_usd"] and RC.spent_today() >= cfg["max_day_usd"]:
        print(f"daily research cost cap reached (${RC.spent_today():.2f} of ${cfg['max_day_usd']:.2f}); not starting", file=sys.stderr)
        return 4
    run, st = Research(target, args), Usage(target, args.event)
    fatal = None
    try:
        fatal = run.go()
    except BaseException as e:  # noqa: BLE001 - record the failure even on Ctrl-C / kill
        fatal = f"{type(e).__name__}: {e}"
        run.errors.append(fatal)
        raise
    finally:
        st.researched = run.researched
        st.finish("failed" if fatal else "completed", run.budget)
        print(run.summary())
    return 1 if fatal else 0


if __name__ == "__main__":
    sys.exit(main())
