"""Host note consolidation: once a night the reviewer model (AI review > Models, Correlation reviewer) reads every host's
AI-written notes and merges the ones that repeat or overlap, so a host keeps a few complete notes instead of hundreds of
near-duplicates.

What it may touch: only host notes written by the AI (author 'ai') that no person has approved or rejected. Notes written
by people, approved / rejected notes and the generated correlation profiles ([profile:...]) are never changed; the model
sees the people's notes as read-only context.

Safety:
  - kb.db is backed up before every run (/state/backup-kbnotes/, newest 7 kept).
  - The model returns groups {from: [note ids], category, text}. A group is applied only when every id belongs to the chunk,
    no id is used twice and the text fits; ids it leaves out are kept unchanged. A group of one note may rewrite it.
  - Every [reviewer:kind:value] tag of the merged notes is kept at the start of the merged note, so the artifact index and
    the reviewer's own look-ups still find it.
  - Notes are re-read inside the write transaction; a note changed by someone else since it was read is left alone.
  - A host whose notes did not change since its last consolidation is skipped.

Schedule: llm_config.json `notes_consolidate` {enabled, time 'HH:MM', tz (IANA), by, at}; the dashboard starts a run once a
day within 3 hours after that local time (server.py thread). AI review > Host note consolidation sets it and has a
"Consolidate now" button.

CLI (inside the dashboard container): notes_consolidate.py run [--all] [--subject S] [--dry-run]
"""
import datetime as dt
import hashlib
import json
import os
import re
import sqlite3
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import corr_llm
import kb

STATE = os.environ.get("STATE_DIR", "/state")
BACKUPS = os.path.join(STATE, "backup-kbnotes")
KEEP_BACKUPS = 7
CHUNK_CHARS = 12000      # note text per request (the local model has a ~24k-token context)
MAX_ROUNDS = 3           # a host with more notes than one chunk is merged again on the next round
WORKERS = 2
VIA = "notes consolidation"
DEFAULT = {"enabled": True, "time": "03:00", "tz": "America/New_York"}
WINDOW_H = 3             # a missed start (dashboard down) still runs within this many hours after the set time
_TAG = re.compile(r"\[reviewer:(?:file|process|user|ip|dns):[^\]]{1,200}\]")
_F_IP = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?(?![\d.]*\d)")
_F_DOM = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b", re.I)
_F_PORT = re.compile(r"\b\d{1,5}/(?:tcp|udp)\b", re.I)
_F_PATH = re.compile(r"(?<![\w.])/(?:[\w.+@-]+/)*[\w.+@-]+")
_F_TOKEN = re.compile(r"\b(?=[\w-]*\d)(?=[\w-]*[a-z])[\w-]{12,}\b", re.I)  # hashes, JA3/JA4, ids
_F_MAC = re.compile(r"\b[0-9a-f]{2}(?::[0-9a-f]{2}){5}\b", re.I)
MAX_GROUP = 10
_lock = threading.Lock()
STATUS = {"running": False, "trigger": "", "by": "", "started": None, "subjects_total": 0, "subjects_done": 0,
          "current": "", "notes_before": 0, "notes_after": 0, "error": ""}

SYSTEM = """You maintain a knowledge base of notes about ONE host / device / domain on a home network. Security analysts and
other AI models read these notes before judging events, so they must stay accurate and complete, but there are far too
many overlapping notes. Consolidate the EDITABLE notes you are given:
- Merge notes that describe the same behaviour, process, service, destination, account or decision into ONE note.
  Group by topic; at most 10 notes in one group.
- Keep EVERY concrete fact: IP addresses, ports, domains, process names and paths, accounts, hashes and TLS fingerprints
  (JA3/JA4), counts, dates, decisions, reasons and caveats such as 'unverified' or 'expected'. Copy identifiers
  character for character. Never invent anything. A merge that drops an identifier is rejected automatically.
- Where notes contradict, the note with the later 'updated' time wins; say what changed if it matters.
- Drop only exact repetition. Notes on unrelated topics stay separate (a group of one note; you may tidy its wording).
- Do not repeat what a FIXED note (written or approved by a person) already says, but never contradict a fixed note.
- Leave out the [reviewer:...] tags; they are re-attached automatically.
- Write plain English, at most 1500 characters per note. Category is one of: role, baseline, behavior, decision, risk,
  config, watch, other.
Every editable note id must appear in exactly one group's "from" list."""
SCHEMA = {"type": "object", "properties": {"notes": {"type": "array", "items": {"type": "object", "properties": {
    "from": {"type": "array", "items": {"type": "integer"}},
    "category": {"type": "string", "enum": list(kb.CATEGORIES)},
    "text": {"type": "string"}}, "required": ["from", "category", "text"]}}}, "required": ["notes"]}
FMT = ("Return ONLY a JSON object of the form {\"notes\": [{\"from\": [ids], \"category\", \"text\"}]} - no prose, no code fences.")


# ---------------------------------------------------------------- settings
def get_cfg():
    c = dict(DEFAULT)
    c.update({k: v for k, v in (corr_llm._raw_config().get("notes_consolidate") or {}).items() if v is not None})
    return c


def set_cfg(user, enabled=None, at_time=None, tz=None):
    c = corr_llm._raw_config()
    cur = dict(c.get("notes_consolidate") or DEFAULT)
    if enabled is not None:
        cur["enabled"] = bool(enabled)
    if at_time is not None:
        if not re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d", str(at_time)):
            raise ValueError("time must be HH:MM (24-hour)")
        cur["time"] = str(at_time)
    if tz is not None:
        try:
            from zoneinfo import ZoneInfo
            ZoneInfo(str(tz))
        except Exception:
            raise ValueError(f"unknown time zone {tz!r}")
        cur["tz"] = str(tz)
    cur.update(by=user, at=time.time())
    c["notes_consolidate"] = cur
    corr_llm._save_config(c)
    return view()


def _zone(tz):
    from zoneinfo import ZoneInfo
    try:
        return ZoneInfo(tz)
    except Exception:
        return dt.timezone.utc


def next_run(cfg=None, now=None):
    cfg = cfg or get_cfg()
    if not cfg.get("enabled"):
        return None
    z = _zone(cfg.get("tz") or "UTC")
    t = dt.datetime.fromtimestamp(now or time.time(), z)
    hh, mm = (int(x) for x in cfg["time"].split(":"))
    cand = t.replace(hour=hh, minute=mm, second=0, microsecond=0)
    last = _meta("last_scheduled_day")
    if cand <= t and (last == cand.date().isoformat() or t - cand > dt.timedelta(hours=WINDOW_H)):
        cand += dt.timedelta(days=1)
    return cand.timestamp()


def due(now=None):
    """The day's scheduled run is due: inside WINDOW_H after the set local time, and not yet started today."""
    cfg = get_cfg()
    if not cfg.get("enabled"):
        return None
    z = _zone(cfg.get("tz") or "UTC")
    t = dt.datetime.fromtimestamp(now or time.time(), z)
    hh, mm = (int(x) for x in cfg["time"].split(":"))
    start = t.replace(hour=hh, minute=mm, second=0, microsecond=0)
    if start <= t < start + dt.timedelta(hours=WINDOW_H) and _meta("last_scheduled_day") != start.date().isoformat():
        return start.date().isoformat()
    return None


# ---------------------------------------------------------------- state (kb.db)
_ready = set()


def _db():
    c = kb._db()
    if kb.DB in _ready:
        return c
    _ready.add(kb.DB)
    c.execute("CREATE TABLE IF NOT EXISTS consolidate_subjects (subject TEXT PRIMARY KEY, sig TEXT, ts REAL)")
    c.execute("""CREATE TABLE IF NOT EXISTS consolidate_runs (id INTEGER PRIMARY KEY, started REAL, ended REAL, trigger TEXT, by TEXT,
                 model TEXT, subjects INTEGER, changed INTEGER, notes_before INTEGER, notes_after INTEGER, merged INTEGER,
                 rewritten INTEGER, failed INTEGER, rejected INTEGER, error TEXT)""")
    c.execute("CREATE TABLE IF NOT EXISTS consolidate_meta (k TEXT PRIMARY KEY, v TEXT)")
    return c


def _meta(k, v=None):
    with _db() as c:
        if v is None:
            r = c.execute("SELECT v FROM consolidate_meta WHERE k=?", (k,)).fetchone()
            return r[0] if r else None
        c.execute("INSERT INTO consolidate_meta VALUES (?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (k, str(v)))


def editable(n):
    return n.get("author") == "ai" and not n.get("status") and not str(n.get("text") or "").startswith("[profile:")


def _rows(c, subject):
    cols = ("id", "subject", "label", "category", "text", "author", "model", "via", "updated", "status")
    return [dict(zip(cols, r)) for r in c.execute(f"SELECT {','.join(cols)} FROM host_notes WHERE subject=? ORDER BY category, id", (subject,))]


def _sig(notes):
    return hashlib.sha256(json.dumps(sorted((n["id"], round(n["updated"] or 0, 3)) for n in notes if editable(n))).encode()).hexdigest()[:24]


def backup():
    os.makedirs(BACKUPS, exist_ok=True)
    dst = os.path.join(BACKUPS, f"kb-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}.db")
    src = sqlite3.connect(kb.DB, timeout=30)
    out = sqlite3.connect(dst)
    with out:
        src.backup(out)
    src.close()
    out.close()
    os.chmod(dst, 0o600)
    old = sorted(f for f in os.listdir(BACKUPS) if f.startswith("kb-") and f.endswith(".db"))
    for f in old[:-KEEP_BACKUPS]:
        os.remove(os.path.join(BACKUPS, f))
    return dst


# ---------------------------------------------------------------- one subject
def _chunks(notes):
    out, cur, size = [], [], 0
    for n in notes:
        ln = len(n["text"]) + 80
        if cur and size + ln > CHUNK_CHARS:
            out.append(cur)
            cur, size = [], 0
        cur.append(n)
        size += ln
    if cur:
        out.append(cur)
    return [c for c in out if len(c) > 1]


def _prompt(subject, label, chunk, fixed):
    def ts(n):
        return time.strftime("%Y-%m-%d %H:%M", time.gmtime(n["updated"] or 0))
    parts = [f"Subject: {subject}" + (f" ({label})" if label else "")]
    if fixed:
        parts.append("FIXED notes (read-only):")
        parts += [f"<fixed category=\"{n['category']}\">{clean(n['text'])[:600]}</fixed>" for n in fixed[:15]]
    parts.append(f"EDITABLE notes ({len(chunk)}):")
    parts += [f"<note id=\"{n['id']}\" category=\"{n['category']}\" updated=\"{ts(n)}\">{clean(n['text'])}</note>" for n in chunk]
    return "\n".join(parts)


_BOILER = (re.compile(r"\s*Seen in a correlation between '.*?' and '.*?'\.", re.S),
           re.compile(r"\s*\(?(?:Reviewer|reviewer) judgement \([^)]*\),? unverified(?:; delete if wrong)?\.?\)?"),
           re.compile(r";\s*seen in '.*?' / '.*?'\.", re.S))


def clean(text):
    """A note without its tags and the reviewer's boilerplate (event labels it was seen in, model name, 'unverified')."""
    t = _TAG.sub(" ", text or "")
    for rx in _BOILER:
        t = rx.sub(" ", t)
    return re.sub(r"\s+", " ", t).strip()


def facts(text):
    """Concrete facts a merged note must keep: IPs, domains, ports, paths, MACs, hashes / fingerprints / ids."""
    t = clean(text)
    out = set()
    for rx in (_F_IP, _F_PORT, _F_PATH, _F_TOKEN, _F_MAC):
        out |= {m.lower().rstrip(".") for m in rx.findall(t)}
    out |= {m.lower() for m in _F_DOM.findall(t) if not re.fullmatch(r"[\d.]+", m) and not m.lower().endswith((".py", ".sh", ".json", ".md", ".txt", ".log"))}
    return out


def missing_facts(sources, text):
    low = clean(text).lower()
    return sorted(f for f in set().union(*(facts(x) for x in sources)) if f not in low)


def _validate(chunk, groups):
    ids = {n["id"] for n in chunk}
    used, ok = set(), []
    for g in groups if isinstance(groups, list) else []:
        src = [int(i) for i in (g.get("from") or []) if str(i).lstrip("-").isdigit()]
        text = str(g.get("text") or "").strip()
        cat = str(g.get("category") or "other").lower()
        if not src or not text or any(i not in ids for i in src) or used & set(src) or len(set(src)) != len(src) or len(src) > MAX_GROUP:
            continue  # a bad group is dropped: its notes stay as they are
        used |= set(src)
        ok.append({"from": src, "category": cat if cat in kb.CATEGORIES else "other", "text": text})
    return ok


def _apply(c, groups, by_id, model, dry, stats=None):
    """Write the groups -> (merged notes removed, notes rewritten). Each group is re-checked against the live row first."""
    removed = rewritten = 0
    stats = {} if stats is None else stats
    now = time.time()
    for g in groups:
        live = [r for r in (c.execute("SELECT id, text, updated, status, author FROM host_notes WHERE id=?", (i,)).fetchone() for i in g["from"]) if r]
        if len(live) != len(g["from"]) or any(r[3] or r[4] != "ai" or abs((r[2] or 0) - (by_id[r[0]]["updated"] or 0)) > 1e-3 for r in live):
            continue  # changed / reviewed / deleted since we read it
        tags = []
        for r in live:
            for t in _TAG.findall(r[1]):
                if t not in tags:
                    tags.append(t)
        body = _TAG.sub("", g["text"]).strip()
        if any("unverified" in r[1].lower() for r in live) and "unverified" not in body.lower():
            body += " (AI judgement, unverified.)"
        text = (" ".join(tags) + " " + body).strip() if tags else body
        if len(text) > kb.MAX_TEXT:
            continue
        lost = missing_facts([r[1] for r in live], body)
        if lost:  # the model dropped or changed a concrete fact (IP, domain, port, hash...): keep the originals
            stats["lost"] = stats.get("lost", 0) + 1
            stats.setdefault("lost_facts", []).extend(lost[:5])
            stats.setdefault("retry", []).append({"from": g["from"], "missing": lost})
            continue
        keep = min(g["from"])
        if len(g["from"]) == 1 and text == by_id[keep]["text"] and g["category"] == by_id[keep]["category"]:
            continue
        if dry:
            removed += len(g["from"]) - 1
            rewritten += 1
            continue
        c.execute("UPDATE host_notes SET category=?, text=?, model=?, via=?, updated=? WHERE id=?", (g["category"], text, model, VIA, now, keep))
        kb._index(c, keep, by_id[keep]["subject"], text)
        for i in g["from"]:
            if i != keep:
                c.execute("DELETE FROM note_artifacts WHERE note_id=?", (i,))
                c.execute("DELETE FROM host_notes WHERE id=?", (i,))
                removed += 1
        rewritten += 1
    return removed, rewritten


def _retry(target, subject, label, by_id, items, dry, log):
    rm = rw = 0
    st_all = {"lost": 0, "lost_facts": []}
    for it in items:
        notes = [by_id[i] for i in it["from"] if i in by_id]
        user = (_prompt(subject, label, notes, []) + "\n\nMerge these notes into ONE note. Your previous merge left out these identifiers; "
                "the merged text MUST contain each of them exactly: " + ", ".join(it["missing"][:40]))
        try:
            txt, _, _ = corr_llm._complete(target, SYSTEM, user, 4000, purpose="notes-consolidation", actor="netmon (note consolidation)",
                                           schemas=(SCHEMA, SCHEMA), fmts=(FMT, FMT))
            groups = [g for g in _validate(notes, (corr_llm._json(txt) or {}).get("notes")) if sorted(g["from"]) == sorted(it["from"])][:1]
        except Exception as e:  # noqa: BLE001
            if log:
                log(f"{subject}: retry failed: {type(e).__name__}: {str(e)[:150]}")
            st_all["lost"] += 1
            continue
        st = {}
        with _lock, _db() as c:
            a, b = _apply(c, groups, by_id, target["model"], dry, st)
        rm, rw = rm + a, rw + b
        if not b:
            st_all["lost"] += 1
            st_all["lost_facts"] += st.get("lost_facts", it["missing"][:3])
    return rm, rw, st_all


def consolidate_subject(subject, target, dry=False, log=None):
    """-> dict(before, after, merged, rewritten, failed). Runs up to MAX_ROUNDS passes over the subject's editable notes."""
    res = {"subject": subject, "before": 0, "after": 0, "merged": 0, "rewritten": 0, "failed": 0, "rejected": 0}
    with _db() as c:
        notes = _rows(c, subject)
    res["before"] = res["after"] = sum(editable(n) for n in notes)
    for rnd in range(MAX_ROUNDS):
        with _db() as c:
            notes = _rows(c, subject)
        ed = [n for n in notes if editable(n)]
        fixed = [n for n in notes if not editable(n) and not str(n["text"]).startswith("[profile:")]
        chunks = _chunks(ed)
        if not chunks:
            break
        label = next((n["label"] for n in notes if n.get("label")), "")
        by_id = {n["id"]: n for n in ed}
        gained = 0
        multi = len(chunks) > 1
        for ch in chunks:
            try:
                txt, usage, secs = corr_llm._complete(target, SYSTEM, _prompt(subject, label, ch, fixed), 8000, purpose="notes-consolidation",
                                                      actor="netmon (note consolidation)", schemas=(SCHEMA, SCHEMA), fmts=(FMT, FMT))
                groups = _validate(ch, (corr_llm._json(txt) or {}).get("notes"))
            except Exception as e:  # noqa: BLE001 - one bad answer must not stop the run
                res["failed"] += 1
                if log:
                    log(f"{subject}: {type(e).__name__}: {str(e)[:200]}")
                continue
            with _lock, _db() as c:
                st = {}
                rm, rw = _apply(c, groups, by_id, target["model"], dry, st)
            if st.get("retry"):  # one more try for merges that dropped an identifier, naming what is missing
                rm2, rw2, st = _retry(target, subject, label, by_id, st["retry"], dry, log)
                rm, rw = rm + rm2, rw + rw2
            res["rejected"] += st.get("lost", 0)
            if log and st.get("lost"):
                log(f"{subject}: {st['lost']} merge(s) kept unmerged - they lost a concrete fact: {', '.join(st.get('lost_facts', [])[:12])}")
            res["merged"] += rm
            res["rewritten"] += rw
            gained += rm
        if gained == 0 or dry or not multi:  # another round only re-merges across chunks of a big host
            break
    with _db() as c:
        after = _rows(c, subject)
        res["after"] = sum(editable(n) for n in after)
        if not dry:
            c.execute("INSERT INTO consolidate_subjects VALUES (?,?,?) ON CONFLICT(subject) DO UPDATE SET sig=excluded.sig, ts=excluded.ts",
                      (subject, _sig(after), time.time()))
    return res


# ---------------------------------------------------------------- a run
def _todo(full=False, only=None):
    with _db() as c:
        rows = c.execute("SELECT subject, id, updated, author, status, text FROM host_notes").fetchall()
        done = dict(c.execute("SELECT subject, sig FROM consolidate_subjects").fetchall())
    per = {}
    for s, i, u, a, st, t in rows:
        per.setdefault(s, []).append({"id": i, "updated": u, "author": a, "status": st, "text": t})
    out = []
    for s, ns in per.items():
        if only and s != only:
            continue
        if sum(editable(n) for n in ns) < 2:
            continue
        if not full and not only and done.get(s) == _sig(ns):
            continue
        out.append((s, sum(editable(n) for n in ns)))
    return [s for s, _ in sorted(out, key=lambda x: -x[1])]


def run(trigger="manual", by="", full=False, only=None, dry=False):
    if not _lock.acquire(blocking=False):
        raise RuntimeError("a consolidation is already running")
    try:
        if STATUS["running"]:
            raise RuntimeError("a consolidation is already running")
        STATUS.update(running=True, trigger=trigger, by=by, started=time.time(), subjects_total=0, subjects_done=0, current="",
                      notes_before=0, notes_after=0, error="")
    finally:
        _lock.release()
    tot = {"subjects": 0, "changed": 0, "before": 0, "after": 0, "merged": 0, "rewritten": 0, "failed": 0, "rejected": 0}
    err, model = "", ""
    try:
        target = corr_llm._target()
        model = target["model"]
        if not dry:
            backup()
        todo = _todo(full, only)
        STATUS["subjects_total"] = len(todo)

        def one(s):
            STATUS["current"] = s
            r = consolidate_subject(s, target, dry, log=lambda m: print("notes_consolidate:", m, file=sys.stderr, flush=True))
            with _lock:
                STATUS["subjects_done"] += 1
                STATUS["notes_before"] += r["before"]
                STATUS["notes_after"] += r["after"]
                tot["subjects"] += 1
                tot["changed"] += bool(r["merged"] or r["rewritten"])
                for k in ("before", "after", "merged", "rewritten", "failed", "rejected"):
                    tot[k] += r[k]
            return r
        with ThreadPoolExecutor(WORKERS) as ex:
            list(ex.map(one, todo))
    except Exception as e:  # noqa: BLE001
        err = f"{type(e).__name__}: {e}"[:300]
        STATUS["error"] = err
    finally:
        if not dry:
            with _db() as c:
                c.execute("INSERT INTO consolidate_runs (started, ended, trigger, by, model, subjects, changed, notes_before, notes_after, merged, rewritten, failed, rejected, error) "
                          "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (STATUS["started"], time.time(), trigger, by, model, tot["subjects"], tot["changed"],
                                                                  tot["before"], tot["after"], tot["merged"], tot["rewritten"], tot["failed"], tot["rejected"], err))
                c.execute("DELETE FROM consolidate_runs WHERE id NOT IN (SELECT id FROM consolidate_runs ORDER BY id DESC LIMIT 60)")
        STATUS.update(running=False, current="")
    print(f"notes_consolidate: {trigger} run by {by or '-'}: {tot} {err}", file=sys.stderr, flush=True)
    return {**tot, "error": err, "model": model}


def start(trigger="manual", by="", full=False):
    """Run in a background thread; False when one is already running."""
    if STATUS["running"]:
        return False
    threading.Thread(target=lambda: _safe_run(trigger, by, full), daemon=True, name="notes-consolidate").start()
    return True


def _safe_run(trigger, by, full):
    try:
        run(trigger, by, full)
    except Exception as e:  # noqa: BLE001
        print(f"notes_consolidate: {e}", file=sys.stderr, flush=True)


def tick(now=None):
    """Called every minute by the dashboard: start the nightly run when due."""
    day = due(now)
    if day and not STATUS["running"]:
        _meta("last_scheduled_day", day)
        start("schedule", "nightly")


def view():
    cfg = get_cfg()
    with _db() as c:
        cols = ("started", "ended", "trigger", "by", "model", "subjects", "changed", "notes_before", "notes_after", "merged", "rewritten", "failed", "rejected", "error")
        runs = [dict(zip(cols, r)) for r in c.execute(f"SELECT {','.join(cols)} FROM consolidate_runs ORDER BY id DESC LIMIT 10")]
        tot = c.execute("SELECT count(*), count(DISTINCT subject) FROM host_notes").fetchone()
        ai = sum(1 for r in c.execute("SELECT author, status, text FROM host_notes") if editable({"author": r[0], "status": r[1], "text": r[2]}))
    try:
        model = corr_llm.config()["correlation"]
    except Exception:  # noqa: BLE001
        model = {}
    return {"enabled": bool(cfg.get("enabled")), "time": cfg.get("time"), "tz": cfg.get("tz"), "by": cfg.get("by"), "at": cfg.get("at"),
            "next": next_run(cfg), "status": dict(STATUS), "runs": runs, "notes": tot[0], "subjects": tot[1], "editable": ai,
            "model": model.get("model") or "", "pending": len(_todo())}


def main(argv):
    if argv[:1] != ["run"]:
        print(__doc__)
        return 2
    only = argv[argv.index("--subject") + 1] if "--subject" in argv else None
    print(json.dumps(run("cli", "cli", full="--all" in argv, only=only, dry="--dry-run" in argv), indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
