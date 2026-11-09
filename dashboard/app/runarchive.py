"""Review-run summaries: what the dashboard keeps of a review run once its data documents are gone.

A review run (review.py: collect.py + analyze.py) writes data/<stamp> (+ .analysis, .sources). Those documents are
pipeline input only: the correlation, the event store, the Fix list and the counters read them, and the browser never
loads one (every page shows a time range). Once a run has been folded into the tables below, its documents are deleted
(`prune`), except the newest few (correlation, enrichment and the Ask AI tools read the latest run) and the 05 UTC daily
runs of the auto-tune window (tuning.py replays them).

Tables (netmon.db):
  run_summary(sid, generated, ti)       one row per review run: its threat-intel counter row (Threat intel trend)
  fix_* tables (fixlist.py)             the run's Fix-list rows (issues, devices, sources, ip->mac)
  finding_seen(key, last_seen)          newest run time each finding / host finding was in ('Last seen' column)
"""
import json, os, re, sys, threading

_ROOT = os.environ.get("NETMON_DIR", "/netmon")
if os.path.isdir(_ROOT) and _ROOT not in sys.path:
    sys.path.append(_ROOT)
import store

KEEP_RECENT = 8  # newest review runs kept as documents (2 h at a 15-minute interval)
SID_RE = re.compile(r"^\d{4}-\d\d-\d\dT\d{4}Z$")
DDL = """CREATE TABLE IF NOT EXISTS run_summary (
  sid TEXT PRIMARY KEY, generated TEXT, ti TEXT) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS finding_seen (key TEXT PRIMARY KEY, last_seen TEXT NOT NULL) WITHOUT ROWID;"""
_lock = threading.Lock()


def _c():
    return store.tl_conn("runarchive", lambda c: c.executescript(DDL))


def finding_keys(raw, an):
    """The 'last seen' keys of one run: baseline findings f|kind|dev|detail and host findings hf|key."""
    out = ["f|%s|%s|%s" % (f.get("kind"), f.get("device") or "", f.get("detail") or "") for f in (an or {}).get("findings") or []]
    out += ["hf|" + str(f.get("key")) for f in ((raw or {}).get("hosts") or {}).get("findings") or []]
    return out


def summarize(sid, raw, an):
    """Fold one review run into run_summary.ti and finding_seen (idempotent)."""
    import tintel
    gen = (raw or {}).get("generated")
    row = tintel.trend([(sid, raw or {})])[0]
    c = _c()
    with _lock, store.tx(c):
        c.execute("INSERT INTO run_summary(sid, generated, ti) VALUES (?,?,?) ON CONFLICT(sid) DO UPDATE SET generated=excluded.generated, ti=excluded.ti",
                  (sid, gen, json.dumps(row, default=str)))
        if gen:
            c.executemany("INSERT INTO finding_seen(key, last_seen) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET last_seen=MAX(last_seen, excluded.last_seen)",
                          [(k, gen) for k in finding_keys(raw, an)])


def summarized():
    """sids whose threat-intel row / finding times are stored."""
    return {r[0] for r in _c().execute("SELECT sid FROM run_summary WHERE ti IS NOT NULL")}


def ti_rows():
    return [json.loads(r[0]) for r in _c().execute("SELECT ti FROM run_summary WHERE ti IS NOT NULL ORDER BY sid")]


def finding_seen():
    return dict(_c().execute("SELECT key, last_seen FROM finding_seen"))


def stored_issue_sids():
    """Runs whose Fix-list rows are stored (fixlist.py)."""
    import fixlist
    return {r[0] for r in fixlist.conn().execute("SELECT sid FROM fix_run")}


# ---- deleting folded runs
def keep_set(sids, keep_recent=KEEP_RECENT, daily_days=None):
    """Runs whose documents stay: the newest `keep_recent` and the 05 UTC daily runs of the auto-tune window."""
    if daily_days is None:
        try:
            import tuning
            daily_days = tuning.WINDOW_DAYS
        except Exception:  # noqa: BLE001
            daily_days = 14
    sids = sorted(sids)
    keep = set(sids[-keep_recent:]) if keep_recent else set()
    keep |= set([s for s in sids if s.endswith("T0500Z")][-daily_days:]) if daily_days else set()
    return keep


def prunable(sids, ingested_upto, keep_recent=KEEP_RECENT, daily_days=None):
    """Runs that may lose their documents: folded into run_summary, the Fix-list tables and the event store."""
    done = summarized() & stored_issue_sids()
    keep = keep_set(sids, keep_recent, daily_days)
    return [s for s in sorted(sids) if s not in keep and s in done and ingested_upto and s <= ingested_upto]


def prune(sids, ingested_upto, keep_recent=KEEP_RECENT, daily_days=None, data_dir=None):
    """Delete the documents of folded runs. Returns the deleted sids."""
    data_dir = data_dir or os.path.join(_ROOT, "data")
    gone = []
    for sid in prunable(sids, ingested_upto, keep_recent, daily_days):
        for suf in ("", ".analysis", ".sources", ".briefing", ".triage"):
            try:
                store.jdelete(os.path.join(data_dir, f"{sid}{suf}.json"))
            except OSError:
                pass
        gone.append(sid)
    return gone
