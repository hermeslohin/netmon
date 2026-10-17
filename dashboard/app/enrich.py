"""Claude research notes on dashboard events, plus Claude correlation verdicts.

Every 4 hours the Hermes report job (Claude) triages the newest snapshot. Besides the triage alarms it writes:
  - a research note per event (verdict, summary, research text, links it actually read), shown by related.js
    as a "✨ notes" button next to the event's Related column;
  - correlation verdicts for candidate links (corr_llm.db, same table the local-LLM reviewer uses). Claude
    verdicts replace the local model's; manual verdicts (model "manual:<user>") are never overwritten, and
    the local worker only asks about undecided pairs, so it never overwrites Claude.

Notes are keyed by a stable event key so they carry over to later snapshots: finding ids embed the detail text
(numbers change every run), so the key masks the numbers in the detail; watcher alerts are stored per alert
family (first 3 parts of the alert key, e.g. host|hnet-interp|<host>), so one note covers repeats of the same alert.

CLI (runs inside the dashboard container; host wrapper: netmon/enrich.sh):
  enrich.py events [--sid ID] [--all] [--max N]   work list: events needing notes first (+ candidate links, notes)
  enrich.py put -                       read {"model", "notes": [...], "links": [...]} from stdin and store it
"""
import json, os, re, sqlite3, sys, time

DB = os.path.join(os.environ.get("STATE_DIR", "/state"), "enrich.db")
VERDICTS = ("malicious", "suspicious", "needs-review", "benign", "expected")
PRIORITIES = ("Investigate", "Review", "Info")
_NUM = re.compile(r"\d+(?:[.,:]\d+)*")
_URL = re.compile(r"^https?://[^\s\"'<>]+$", re.I)


def _db():
    c = sqlite3.connect(DB, timeout=10)
    c.execute("""CREATE TABLE IF NOT EXISTS notes (skey TEXT PRIMARY KEY, eid TEXT, label TEXT, verdict TEXT, priority TEXT,
                 summary TEXT, research TEXT, links TEXT, model TEXT, via TEXT, ts REAL, snapshot TEXT)""")
    return c


def _alert_keys():
    try:
        import store
        return {str(a["id"]): a.get("key") or "" for a in store.alerts_recent(2000)}
    except Exception:  # noqa: BLE001
        return {}


def skey(eid, akeys=None):
    p = str(eid).split("|")
    if p[0] == "f":  # same finding in a later run: numbers in the detail (MB, counts, ratios) are masked
        return _NUM.sub("#", str(eid))
    if p[0] == "alert" and akeys is not None and akeys.get(p[1] if len(p) > 1 else ""):
        return "alertfam|" + "|".join(akeys[p[1]].split("|")[:3])
    return str(eid)


def load(eids):
    eids, ak = list(eids), _alert_keys()
    keys = {}
    for e in eids:
        keys.setdefault(skey(e, ak), []).append(e)
    out = {}
    if not keys:
        return out
    with _db() as c:
        ks = list(keys)
        for i in range(0, len(ks), 500):
            ch = ks[i:i + 500]
            for r in c.execute(f"SELECT skey, eid, verdict, priority, summary, research, links, model, via, ts, snapshot FROM notes "
                               f"WHERE skey IN ({','.join('?' * len(ch))})", ch):
                for eid in keys[r[0]]:
                    out[eid] = {"verdict": r[2], "priority": r[3], "summary": r[4], "research": r[5], "links": json.loads(r[6] or "[]"),
                                "model": r[7], "via": r[8], "at": r[9], "snapshot": r[10], "same_event": r[1] == eid}
    return out


def apply(res):
    """Attach notes for the events of a correlation result (new dict; the cached base stays untouched)."""
    if not res or res.get("error"):
        return res
    try:
        return {**res, "notes": load((res.get("events") or {}).keys())}
    except Exception as e:  # noqa: BLE001 - notes are optional
        print(f"enrich notes unavailable: {e}", file=sys.stderr)
        return res


def _clean_links(links):
    out = []
    for l in links or []:
        u = str((l or {}).get("url", "")).strip()
        if _URL.match(u):
            out.append({"title": str(l.get("title") or u)[:200], "url": u[:1000]})
    return out[:12]


def put(doc, events=None):
    """Store notes + correlation verdicts. events = current {eid: event} (labels; unknown ids are rejected)."""
    model = str(doc.get("model") or "unknown")[:80]
    via = str(doc.get("via") or "Hermes event enrichment")[:80]
    sid = str(doc.get("snapshot") or "")[:40]
    now, rows, bad, ak = time.time(), [], [], _alert_keys()
    for n in doc.get("notes") or []:
        eid = str(n.get("id") or "")
        if not eid or (events is not None and eid not in events):
            bad.append(eid); continue
        v = str(n.get("verdict") or "needs-review").lower()
        rows.append((skey(eid, ak), eid, (events or {}).get(eid, {}).get("label", "")[:200], v if v in VERDICTS else "needs-review",
                     n.get("priority") if n.get("priority") in PRIORITIES else "Info", str(n.get("summary") or "")[:600],
                     str(n.get("research") or "")[:4000], json.dumps(_clean_links(n.get("links"))), model, via, now, sid))
    with _db() as c:
        c.executemany("INSERT OR REPLACE INTO notes VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", rows)
    import corr_llm
    lrows, kept = [], 0
    with corr_llm._db() as c:
        manual = {p for (p,) in c.execute("SELECT pair FROM verdicts WHERE model LIKE 'manual:%'")}
        for l in doc.get("links") or []:
            a, b = str(l.get("a") or ""), str(l.get("b") or "")
            if not a or not b or a == b or (events is not None and (a not in events or b not in events)):
                bad.append(f"{a} <-> {b}"); continue
            p = corr_llm.pair(a, b)
            if p in manual:
                kept += 1; continue
            lrows.append((p, 1 if l.get("related") else 0, max(0.0, min(1.0, float(l.get("confidence") or 0))),
                          str(l.get("reason") or "")[:300], model, now))
        c.executemany("INSERT OR REPLACE INTO verdicts VALUES (?,?,?,?,?,?)", lrows)
    return {"notes": len(rows), "links": len(lrows), "manual_kept": kept, "rejected_ids": bad[:50]}


RANK = {"critical": 0, "high": 1, "investigate": 1, "medium": 2, "urgent": 3, "low": 4}


def _events(sid=None, everything=False, limit=40):
    """Work list for the enrichment run: one entry per note key (alert families and repeat findings collapse),
    events without a note first, most severe first, capped at `limit` (0 = no cap)."""
    import server, corr_llm
    sid = sid or (server.snapshots() or [{"id": ""}])[-1]["id"]
    res = corr_llm.apply(server.correlation(sid))
    if not res or res.get("error"):
        return {"snapshot": sid, "error": "no correlation for snapshot"}
    E, notes, ak = res["events"], load(res["events"].keys()), _alert_keys()
    groups = {}
    for eid, e in E.items():
        if not everything and e.get("sev") in ("low", "info", "") and e["type"] not in ("ti",):
            continue
        groups.setdefault(skey(eid, ak), []).append(eid)
    out = []
    for k, ids in groups.items():
        ids.sort(key=lambda i: -(E[i].get("t0") or 0))
        eid, e, n = ids[0], E[ids[0]], notes.get(ids[0])
        rel = res["related"].get(eid) or []
        out.append({"id": eid, "type": e["type"], "sev": e.get("sev"), "label": e["label"], "link": e.get("link"),
                    "when": time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(e["t0"])) if e.get("t0") else "ongoing",
                    "repeats": len(ids), "other_ids": ids[1:6],
                    "note": ({k2: n[k2] for k2 in ("verdict", "priority", "summary", "model", "snapshot")}
                             | {"age_h": round((time.time() - n["at"]) / 3600, 1)}) if n else None,
                    "related": [{"id": r["id"], "label": (E.get(r["id"]) or {}).get("label", "")[:120], "why": r["why"],
                                 "verdict": r.get("llm"), "by": r.get("llm_model"), "reason": r.get("llm_reason")} for r in rel[:8]]})
    out.sort(key=lambda x: (x["note"] is not None, RANK.get(x["sev"], 5) - (1 if x["type"] in ("ti", "ids") else 0), -x["repeats"]))
    todo = sum(1 for x in out if not x["note"])
    return {"snapshot": sid, "total_events": len(E), "note_keys": len(out), "without_note": todo,
            "listed": min(len(out), limit) if limit else len(out),
            "llm": {k: res.get("llm", {}).get(k) for k in ("model", "confirmed", "rejected", "pending")},
            "events": out[:limit] if limit else out}


def main(argv):
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    if argv[:1] == ["events"]:
        sid = argv[argv.index("--sid") + 1] if "--sid" in argv else None
        lim = int(argv[argv.index("--max") + 1]) if "--max" in argv else 40
        print(json.dumps(_events(sid, "--all" in argv, lim), indent=1, default=str))
    elif argv[:1] == ["put"]:
        doc = json.load(sys.stdin if argv[1:2] in (["-"], []) else open(argv[1]))
        import server
        sid = doc.get("snapshot") or (server.snapshots() or [{"id": ""}])[-1]["id"]
        res = server.correlation(sid)
        print(json.dumps(put({**doc, "snapshot": sid}, (res or {}).get("events") or {})))
    else:
        print(__doc__)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
