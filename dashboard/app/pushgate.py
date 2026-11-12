"""Phone-push gate: urgent / investigate alarms wait for the event reviewer's group verdict before they go to phones.

pushsvc.run_once() asks decide(rows) which of the unpushed alarm rows to send now, which to keep holding and which to
mark pushed without a push. Per alarm (its event = eventstore.alert_ref):
  - switch off (Settings > Site > push_wait_for_ai = false): pushed at once, as before this gate existed;
  - the group verdict is not in yet (Pending review, a provisional single-event label, or queued): held, up to
    push_hold_max_minutes (0 = auto: event window + 5 min) after the alarm was raised;
  - expected / benign AND autoclose.push_check() passes (the very same guard_rails() auto-close uses, or a person's
    expected / benign call): no push ("push suppressed by AI verdict", state 'suppressed' in push_gate);
  - any other verdict (suspicious, malicious, unknown, expected but held by a guard rail): pushed with the verdict,
    the reviewer's one-line reason and the size of the correlated group;
  - fail-safe: hold time passed, reviewer off / erroring, verdict 'Not reviewed', or the gate itself failing: pushed,
    marked "AI review unavailable". An urgent alarm is never dropped silently.
An alarm the review withdraws while it is held (sync_alarms holds / deletes it once its group is no longer
suspicious) is judged the same way from the push_gate row, so expected-but-guarded still pushes.
Every decision is a push_gate row (netmon.db), shown in the verdict pop-up and auditable.
"""
import json, sys, time

import store

GATED = ("urgent", "investigate")  # alarm severities that go to phones; others pass straight through
KINDS = ("expected", "benign")
OFF_KINDS = ("reviewer", "loop", "decision")  # corr_llm worker errors that mean no verdict is coming soon
ERR_FRESH_S = 900  # a worker error newer than this counts as "reviewer down"

_SCHEMA = {"done": ""}


def _schema(c):
    if _SCHEMA["done"] == store.db_path():
        return
    c.execute("""CREATE TABLE IF NOT EXISTS push_gate (alert_id INTEGER PRIMARY KEY, eid TEXT, first_ts REAL, state TEXT NOT NULL,
                 verdict TEXT, reason TEXT, why TEXT, decided_at REAL, text TEXT, severity TEXT, source TEXT, targets TEXT)""")
    c.execute("CREATE INDEX IF NOT EXISTS push_gate_eid ON push_gate(eid)")
    _SCHEMA["done"] = store.db_path()


def settings():
    """{'wait': bool, 'hold_min': effective minutes, 'hold_set': stored value (0 = auto)} from the cfg table (site doc)."""
    import site_cfg
    import lookback
    s = site_cfg.load()
    wait = s.get("push_wait_for_ai", True)
    wait = wait if isinstance(wait, bool) else str(wait).strip().lower() not in ("0", "false", "off", "no")
    try:
        hs = int(s.get("push_hold_max_minutes") or 0)
    except (TypeError, ValueError):
        hs = 0
    hs = hs if 0 <= hs <= 240 else 0
    return {"wait": wait, "hold_set": hs, "hold_min": hs or lookback.minutes() + 5}


def reviewer_down():
    """Why no verdict will come soon (reviewer off, or its worker failing), else None."""
    try:
        import corr_llm
    except Exception as e:  # noqa: BLE001
        return f"event reviewer unavailable ({type(e).__name__})"
    off = corr_llm.reviewer_off()
    if off:
        return off
    st = corr_llm.STATUS
    if st.get("error") and st.get("error_kind") in OFF_KINDS and time.time() - (st.get("error_at") or 0) < ERR_FRESH_S:
        return f"event reviewer error: {str(st.get('error'))[:120]}"
    return None


def verdict_of(eid):
    """The group verdict of one event: {'state': 'final'|'pending'|'unreviewed', label, confidence, reason, n}."""
    import corr_llm
    c = corr_llm.classes([eid], pending=True).get(eid)
    if not c:
        return {"state": "pending", "label": "", "reason": "queued for the event reviewer"}
    lab = c.get("label")
    if lab == "unreviewed":
        return {"state": "unreviewed", "label": lab, "reason": c.get("unreviewed") or c.get("reason") or ""}
    if lab == "pending" or c.get("pending"):
        return {"state": "pending", "label": lab, "reason": "group not settled"}
    n, fast = 1, False
    try:
        with corr_llm._db() as d:
            r = d.execute("SELECT covered FROM event_class WHERE eid=?", (eid,)).fetchone()
        cov = json.loads(r[0]) if r and r[0] else {}
        n, fast = len(cov.get("m") or []) or 1, bool(cov.get("fast"))
    except Exception as e:  # noqa: BLE001 - group size is decoration
        print(f"pushgate: group size for {eid}: {e}", file=sys.stderr)
    if fast:  # provisional single-event label: the group review replaces it
        return {"state": "pending", "label": lab, "reason": "provisional label"}
    return {"state": "final", "label": lab, "confidence": c.get("confidence"), "reason": c.get("reason") or "", "n": n}


def _line(s, n=140):
    s = str(s or "")
    if "Verdict:" in s:  # the reviewer's write-up: its verdict paragraph, cut on a word (its first sentence is often just the label)
        s = " ".join(s[s.rindex("Verdict:") + len("Verdict:"):].split())
        return s if len(s) <= n else s[:n - 1].rsplit(" ", 1)[0] + "…"
    s = " ".join(s.split())
    for cut in (". ", "; "):
        if cut in s[:n]:
            s = s[:s.index(cut, 0, n) + 1]
            break
    return s if len(s) <= n else s[:n - 1] + "…"


def context(v, unavailable=""):
    """The text the phone notification carries about the AI review."""
    if unavailable:
        return {"tag": "AI review unavailable", "line": f"AI review unavailable: {unavailable}"}
    conf = v.get("confidence")
    lab = f"{v['label']}{f' {round(conf * 100)}%' if isinstance(conf, (int, float)) else ''}"
    grp = f" Group of {v['n']} events." if (v.get("n") or 1) > 1 else ""
    guard = f" Kept: {v['guard']}." if v.get("guard") else ""
    return {"tag": "AI " + v["label"], "line": f"AI verdict: {lab} - {_line(v.get('reason'))}{grp}{guard}"}


def _check(eid, row):
    """(action, verdict dict, reason) for an alarm whose hold is being decided: action push|suppress|hold|unavailable."""
    v = verdict_of(eid)
    if v["state"] == "unreviewed":
        return "unavailable", v, "Not reviewed: " + (v["reason"] or "no reason recorded")
    if v["state"] == "pending":
        return "hold", v, v["reason"]
    if v["label"] in KINDS:
        import autoclose
        mem = []
        try:
            import corr_llm
            with corr_llm._db() as d:
                r = d.execute("SELECT covered FROM event_class WHERE eid=?", (eid,)).fetchone()
            mem = (json.loads(r[0]) if r and r[0] else {}).get("m") or []
        except Exception as e:  # noqa: BLE001 - members only narrow the check
            print(f"pushgate: group members for {eid}: {e}", file=sys.stderr)
        pc = autoclose.push_check(eid, [m for m in mem if m != eid])
        if pc["ok"]:
            return "suppress", v, f"push suppressed by AI verdict: {pc['verdict']} ({pc['source'] or 'reviewer'}), all guard rails passed"
        v = {**v, "guard": pc["why"] or pc["guard"] or "a guard rail"}
        return "push", v, f"expected/benign but held by a guard rail: {v['guard']}"
    return "push", v, f"verdict {v['label']}"


def decide(rows, now=None):
    """Split unpushed alarm rows: returns (send, mark). send = rows to push now (each with 'ai' context), mark = ids to
    mark pushed (sent + suppressed + passed through). Rows neither sent nor marked stay held (pushed=0)."""
    now = now or time.time()
    c = store._dc()
    _schema(c)
    s = settings()
    gate = {r[0]: dict(zip(("alert_id", "eid", "first_ts", "state"), r)) for r in c.execute(
        "SELECT alert_id, eid, first_ts, state FROM push_gate WHERE state='held'")}
    send, mark, logs = [], [], []
    down = None if not s["wait"] else reviewer_down()
    for r in rows:
        if r.get("severity") not in GATED or not s["wait"]:
            send.append(r)
            mark.append(r["id"])
            if r.get("severity") in GATED:
                logs.append((r, "pushed", None, "switch off: pushed at once (push_wait_for_ai is off)"))
            continue
        try:
            import eventstore
            eid = eventstore.alert_ref(r)
            g = gate.get(r["id"])
            first = g["first_ts"] if g else now  # the hold runs from when the alarm reached the gate (raised / promoted)
            act, v, why = ("unavailable", {}, down) if down else _check(eid, r)
            if act == "hold" and now - first >= s["hold_min"] * 60:
                act, why = "unavailable", f"no verdict within {s['hold_min']} min"
        except Exception as e:  # noqa: BLE001 - fail safe: a broken gate never swallows an alarm
            print(f"pushgate: {type(e).__name__}: {e}", file=sys.stderr, flush=True)
            eid, first, act, v, why = "", now, "unavailable", {}, f"push gate error ({type(e).__name__})"
        r = {**r, "eid": eid}
        if act == "hold":
            if r["id"] not in gate:
                logs.append((r, "held", v, why, first))
            continue
        if act == "suppress":
            mark.append(r["id"])
            logs.append((r, "suppressed", v, why, first))
            print(f"pushgate: alert {r['id']} {why}", file=sys.stderr, flush=True)
            continue
        r["ai"] = context(v, why if act == "unavailable" else "")
        send.append(r)
        mark.append(r["id"])
        logs.append((r, "pushed-unavailable" if act == "unavailable" else "pushed", v, why, first))
    # held alarms the review withdrew from the feed (sync_alarms held / deleted them): judged on their stored copy
    live = {r["id"] for r in rows}
    gone = [g for i, g in gate.items() if i not in live]
    if gone:
        cur = {r[0]: r for r in c.execute("SELECT id, cleared FROM alerts WHERE id IN (SELECT value FROM json_each(?))",
                                          (json.dumps([g["alert_id"] for g in gone]),))}
        for g in gone:
            full = c.execute("SELECT * FROM push_gate WHERE alert_id=?", (g["alert_id"],)).fetchone()
            row = {"id": g["alert_id"], "text": full["text"], "severity": full["severity"], "source": full["source"],
                   "targets": json.loads(full["targets"] or "[]"), "ts": g["first_ts"], "eid": g["eid"]}
            if g["alert_id"] in cur and cur[g["alert_id"]][1]:
                logs.append((row, "cleared", None, "cleared by a mute rule while held", g["first_ts"]))
                continue
            try:
                act, v, why = ("unavailable", {}, down) if down else _check(g["eid"], row)
                if act == "hold" and now - g["first_ts"] >= s["hold_min"] * 60:
                    act, why = "unavailable", f"no verdict within {s['hold_min']} min"
            except Exception as e:  # noqa: BLE001
                act, v, why = "unavailable", {}, f"push gate error ({type(e).__name__})"
            if act == "hold":
                continue
            if act == "suppress":
                logs.append((row, "suppressed", v, why, g["first_ts"]))
                continue
            row["ai"] = context(v, why if act == "unavailable" else "")
            send.append(row)
            logs.append((row, "pushed-unavailable" if act == "unavailable" else "pushed", v, why, g["first_ts"]))
    _log(c, logs, now)
    return send, mark


def _log(c, logs, now):
    if not logs:
        return
    with store.tx(c):
        for item in logs:
            r, state, v, why = item[:4]
            first = item[4] if len(item) > 4 else now
            v = v or {}
            c.execute("INSERT OR REPLACE INTO push_gate (alert_id, eid, first_ts, state, verdict, reason, why, decided_at, text, severity, source, targets) "
                      "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                      (r["id"], r.get("eid") or "", first, state, v.get("label") or "", _line(v.get("reason"), 300), str(why or "")[:400],
                       None if state == "held" else now, str(r.get("text") or "")[:2000], r.get("severity") or "", r.get("source") or "",
                       json.dumps(r.get("targets") or [])))


# ---------------------------------------------------------------- User role: verdict first, always
# Admins / defenders get the fail-safe pushes above (no verdict in time, reviewer down, switch off). A User never does:
# an alarm reaches a User (phone or Alerts page) only once the event reviewer's final group verdict is in and is
# suspicious. No time limit - an alarm still waiting for its verdict stays away from Users until it gets one (or ages
# past USER_WINDOW_S, after which it is not pushed to them at all). push_user records what each alarm did for Users.
USER_WINDOW_S = 24 * 3600
_USCHEMA = {"done": ""}


def _user_schema(c):
    if _USCHEMA["done"] == store.db_path():
        return
    new = c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='push_user'").fetchone() is None
    c.execute("CREATE TABLE IF NOT EXISTS push_user (alert_id INTEGER PRIMARY KEY, state TEXT NOT NULL, verdict TEXT, at REAL)")
    if new:  # first run: alarms already in the feed count as delivered, so Users are not flooded with old ones
        with store.tx(c):
            c.execute("INSERT OR IGNORE INTO push_user (alert_id, state, verdict, at) SELECT id, 'seeded', '', ? FROM alerts", (time.time(),))
    _USCHEMA["done"] = store.db_path()


def user_verdict(row):
    """'ready' (final verdict suspicious), 'skip' (final verdict expected / benign) or 'wait' (no final verdict yet)."""
    try:
        import eventstore
        v = verdict_of(eventstore.alert_ref(row))
    except Exception as e:  # noqa: BLE001 - fail closed for Users: no verdict, no alarm
        print(f"pushgate (user): {type(e).__name__}: {e}", file=sys.stderr, flush=True)
        return "wait", {}
    if v.get("state") != "final":
        return "wait", v
    return ("ready" if v.get("label") == "suspicious" else "skip"), v


def user_visible(rows):
    """The alarm rows a User may see on the Alerts page: those with a final suspicious verdict."""
    return [r for r in rows if user_verdict(r)[0] == "ready"]


def user_due(now=None):
    """Alarms in the feed that just became ready for Users (final suspicious verdict) and have not gone to them yet.
    Expected / benign verdicts are recorded as skipped; anything still waiting is left for the next run."""
    now = now or time.time()
    c = store._dc()
    _user_schema(c)
    rows = [store._arow(r) for r in c.execute(
        "SELECT * FROM alerts WHERE cleared=0 AND held=0 AND ts>=? AND id NOT IN (SELECT alert_id FROM push_user) ORDER BY id",
        (now - USER_WINDOW_S,))]
    due, logs = [], []
    for r in rows:
        st, v = user_verdict(r)
        if st == "wait":
            continue
        logs.append((r["id"], "sent" if st == "ready" else "skipped", v.get("label") or ""))
        if st == "ready":
            due.append(r)
    if logs:
        with store.tx(c):
            c.executemany("INSERT OR REPLACE INTO push_user (alert_id, state, verdict, at) VALUES (?,?,?,?)",
                          [(i, s, lab, now) for i, s, lab in logs])
    return due


def for_event(eid):
    """push_gate rows about one event (verdict pop-up): newest first."""
    c = store._dc()
    _schema(c)
    return [{"alert_id": r["alert_id"], "state": r["state"], "verdict": r["verdict"], "why": r["why"], "at": r["decided_at"] or r["first_ts"]}
            for r in c.execute("SELECT * FROM push_gate WHERE eid=? ORDER BY alert_id DESC LIMIT 10", (eid,))]
