"""Review log: one entry per correlation review pass (corr_llm worker) that did work or failed, and one per finished
review-job run (review.py on the host, read from <state>/review_job.json). Entries go to Elasticsearch through the
audit writer (event.dataset netmon.review, daily index logs-netmon.YYYY.MM.DD) and to an in-memory ring, which the
AI review > Review log card falls back to when Elasticsearch is unreachable.
"""
import collections
import sys
import threading
import time
from datetime import datetime, timezone

RING = collections.deque(maxlen=300)
_lock = threading.Lock()
ACTOR = "netmon (review log)"  # not an event reviewer/researcher actor: always sent, independent of those audit switches


def _iso(t):
    return datetime.fromtimestamp(float(t), timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _emit(action, outcome, t0, t1, review, message):
    doc = {"@timestamp": _iso(t1), "event": {"dataset": "netmon.review", "category": ["process"], "type": ["info"], "action": action,
                                               "outcome": outcome, "start": _iso(t0), "end": _iso(t1), "duration": int(max(0.0, t1 - t0) * 1e9)},
           "user": {"name": ACTOR}, "message": message, "netmon": {"review": {k: v for k, v in review.items() if v not in (None, "")}}}
    with _lock:
        RING.appendleft(doc)
    try:
        import audit
        audit.emit(doc)
    except Exception as e:  # noqa: BLE001 - logging must never stop a review
        print(f"reviewlog: not sent: {e}", file=sys.stderr)
    return doc


def correlation_pass(t0, t1, st, done, crashed=None):
    """st = corr_llm.STATUS after the pass. Logged when the pass decided / reviewed something or ended with a problem."""
    err = crashed or st.get("error") or ""
    links, labelled, reviewed = int(st.get("decided_this_run") or 0), int(st.get("clef_events_this_run") or 0), int(st.get("classified_this_run") or 0)
    rfail, dfail = int(st.get("review_failed_this_run") or 0), int(st.get("decision_failed_this_run") or 0)
    events = int(st.get("events_this_run") or 0)  # distinct events touched: link decided, labelled or reviewed
    if not (done or links or reviewed or labelled or err or rfail or dfail):
        return None
    status = "crashed" if crashed else "waiting" if st.get("error_kind") == "decision" else "error" if err else "partial" if (rfail or dfail) else "ok"
    msg = (f"Correlation review pass {status}: {events} events processed, {links} links decided, {labelled} events labelled, {reviewed} events reviewed"
           + (f", {rfail} event reviewer failures" if rfail else "") + (f", {dfail} decision-model failures" if dfail else "") + (f" - {str(err)[:200]}" if err else ""))
    return _emit("review.correlation_pass", "success" if status == "ok" else "failure", t0, t1,
                 {"kind": "correlation", "status": status, "events_processed": events, "links_decided": links, "events_labelled": labelled, "events_reviewed": reviewed,
                  "reviewer_failures": rfail, "decision_failures": dfail, "decision_model": st.get("clef_model"), "reviewer_model": st.get("model"),
                  "error": str(err)[:2000] or None, "pending_links": st.get("pending_after")}, msg)


def job_runs(state):
    """Log every review-job run that finished since the last call. state: a dict persisted by the caller ({"last": ts})."""
    try:
        import review_cfg as RC
        runs = (RC.status() or {}).get("runs") or []
    except Exception as e:  # noqa: BLE001
        print(f"reviewlog: review job status unreadable: {e}", file=sys.stderr)
        return 0
    last, n = float(state.get("last") or 0), 0
    new = sorted((r for r in runs if r.get("finished") and float(r.get("started") or 0) > last and r.get("status") != "running"),
                 key=lambda r: r["started"])
    if not last and new:  # first call ever: do not replay the whole history, log only the newest run
        new = new[-1:]
    for r in new:
        ok = r.get("status") == "completed"
        msg = (f"Review job run {r.get('status')} ({r.get('trigger') or '?'}{', daily 24 h' if r.get('daily_run') else ''}) in {r.get('duration_s') or 0}s"
               + (f": {r.get('events')} events processed, {r.get('events_reviewed') or 0} given a note, {r.get('events_queued') or 0} queued" if r.get("events") is not None else "")
               + (f" - {str(r.get('error'))[:200]}" if r.get("error") else ""))
        _emit("review.job_run", "success" if ok else "failure", float(r["started"]), float(r.get("finished") or r["started"]),
              {"kind": "review_job", "status": r.get("status"), "trigger": r.get("trigger"), "daily_run": bool(r.get("daily_run")),
               "reviewer_model": r.get("model"), "error": r.get("error"),
               "events_processed": r.get("events"), "events_reviewed": r.get("events_reviewed"), "events_queued": r.get("events_queued")}, msg)
        state["last"] = float(r["started"]); n += 1
    return n


def view(hours=24):
    """Card data: entries from Elasticsearch (else the in-memory ring) plus totals per kind."""
    src, rows, total, err = "elasticsearch", [], 0, ""
    try:
        import audit
        rows, total = audit.review_entries(hours)
    except Exception as e:  # noqa: BLE001
        err = str(getattr(e, "reason", e))[:200]
        cut = time.time() - hours * 3600
        with _lock:
            rows = [d for d in RING if datetime.fromisoformat(d["@timestamp"].replace("Z", "+00:00")).timestamp() >= cut]
        src, total = "memory (Elasticsearch unavailable)", len(rows)
    out = []
    for d in rows:
        R, ev = (d.get("netmon") or {}).get("review") or {}, d.get("event") or {}
        out.append({"ts": d.get("@timestamp"), "kind": R.get("kind"), "status": R.get("status"), "outcome": ev.get("outcome"),
                    "seconds": round((ev.get("duration") or 0) / 1e9, 1), "events": R.get("events_processed"), "queued": R.get("events_queued"), "links": R.get("links_decided"), "labelled": R.get("events_labelled"),
                    "reviewed": R.get("events_reviewed"), "rfail": R.get("reviewer_failures"), "dfail": R.get("decision_failures"),
                    "model": R.get("reviewer_model"), "dmodel": R.get("decision_model"), "trigger": R.get("trigger"), "error": R.get("error"),
                    "message": d.get("message")})
    summ = {}
    for k in ("correlation", "review_job"):
        rs = [r for r in out if r["kind"] == k]
        summ[k] = {"entries": len(rs), "events": sum(r["events"] or 0 for r in rs), "ok": sum(1 for r in rs if r["status"] in ("ok", "completed")),
                   "problems": sum(1 for r in rs if r["status"] not in ("ok", "completed")),
                   "last": rs[0]["ts"] if rs else None, "last_status": rs[0]["status"] if rs else None,
                   "last_problem": next((r for r in rs if r["status"] not in ("ok", "completed")), None)}
    corr = [r for r in out if r["kind"] == "correlation"]
    summ["correlation"].update(links=sum(r["links"] or 0 for r in corr), labelled=sum(r["labelled"] or 0 for r in corr),
                               reviewed=sum(r["reviewed"] or 0 for r in corr), rfail=sum(r["rfail"] or 0 for r in corr))
    return {"source": src, "error": err, "hours": hours, "total": total, "summary": summ, "rows": out[:200]}
