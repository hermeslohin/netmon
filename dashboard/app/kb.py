"""Notes knowledge base: per-host/device notes (written mostly by the AI) and per-event notes (written by people).

Host notes are what the AI has learned about a device or endpoint - its role, normal behaviour, decisions made
about it, things to watch. Every AI run reads them before deciding and adds or corrects them afterwards, so the
knowledge carries over between runs instead of being re-researched. People can add and delete host notes too.

Event notes are written by people on any event row (the 📝 button next to the Related count). They are keyed by the
same stable event key as the AI research notes (enrich.skey), so a note carries over to later snapshots of the same
finding / alert family. The AI treats them as analyst guidance: the twice-daily enrichment run, the local-LLM correlation
reviewer and the chat assistant all read them.

Approval gate: notes written by an admin or network defender are approved when written. Notes written by a User-role
account (on events of their own assigned devices) start as `pending` and are NEVER given to any AI until an admin or
defender approves them (`rejected` ones never are). Every AI read path goes through event_notes(..., ai=True) / dump(),
or filters status='approved' itself (netmon_mcp.py).

Subjects (host notes):
  mac:<mac>      a network device with a known MAC (preferred - survives DHCP changes)
  ip:<ip>        a network device without a MAC in the registry
  host:<name>    an Elastic Agent endpoint (short host name, lower case)
resolve() turns an IP / MAC / host name into the canonical subject (IP -> MAC via the device registry).

CLI (inside the dashboard container; host wrapper: netmon/enrich.sh kb ...):
  kb.py dump [FILTER]                    all host notes + event notes as JSON (optional subject/text substring filter)
  kb.py put -                            {"model", "via", "host_notes": [...], "host_notes_delete": [ids]} from stdin
"""
import json, os, re, sqlite3, sys, time

DB = os.path.join(os.environ.get("STATE_DIR", "/state"), "kb.db")
CATEGORIES = ("role", "baseline", "behavior", "decision", "risk", "config", "watch", "other")
MAX_TEXT = 2000
MAX_PER_SUBJECT = 40
_MAC = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")
_IP = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _db():
    c = sqlite3.connect(DB, timeout=10)
    c.execute("""CREATE TABLE IF NOT EXISTS host_notes (id INTEGER PRIMARY KEY, subject TEXT, label TEXT, category TEXT, text TEXT,
                 author TEXT, model TEXT, via TEXT, ts REAL, updated REAL)""")
    c.execute("CREATE INDEX IF NOT EXISTS host_notes_subject ON host_notes(subject)")
    c.execute("""CREATE TABLE IF NOT EXISTS event_notes (id INTEGER PRIMARY KEY, skey TEXT, eid TEXT, label TEXT, author TEXT, text TEXT, ts REAL)""")
    c.execute("CREATE INDEX IF NOT EXISTS event_notes_skey ON event_notes(skey)")
    have = {r[1] for r in c.execute("PRAGMA table_info(event_notes)")}
    for col, decl in (("status", "TEXT NOT NULL DEFAULT 'approved'"), ("role", "TEXT"), ("reviewed_by", "TEXT"), ("reviewed_at", "REAL")):
        if col not in have:  # older kb.db: every existing note was written by an admin/defender, so it stays approved
            c.execute(f"ALTER TABLE event_notes ADD COLUMN {col} {decl}")
    return c


# ---------------------------------------------------------------- subjects
def _registry():
    try:
        import store
        return store.registry_load()
    except Exception:  # noqa: BLE001 - without the registry, IPs stay ip: subjects
        return {}


def resolve(ip=None, mac=None, host=None, subject=None, reg=None):
    """Canonical subject + display label for an IP, MAC, endpoint host name or an explicit subject."""
    if subject:
        s = str(subject).strip()
        k, _, v = s.partition(":")
        if k == "mac" and _MAC.match(v.lower()):
            return resolve(mac=v, reg=reg)
        if k == "ip" and _IP.match(v):
            return resolve(ip=v, reg=reg)
        if k == "host" and v:
            return resolve(host=v, reg=reg)
        raise ValueError(f"bad subject {s!r} (use mac:<mac>, ip:<ip> or host:<name>)")
    if host:
        h = str(host).strip().lower().split(".")[0]
        if not re.match(r"^[a-z0-9_-]{1,63}$", h):
            raise ValueError(f"bad host name {host!r}")
        return "host:" + h, h
    reg = _registry() if reg is None else reg
    if mac:
        m = str(mac).strip().lower()
        if not _MAC.match(m):
            raise ValueError(f"bad MAC {mac!r}")
        d = reg.get(m) or {}
        return "mac:" + m, d.get("name") or m
    if ip:
        i = str(ip).strip()
        if not _IP.match(i):
            raise ValueError(f"bad IP {ip!r}")
        best = None
        for k, d in reg.items():  # newest registry entry that holds this IP and has a MAC
            if i in (d.get("ips") or []) and _MAC.match(str(d.get("mac") or k).lower()):
                if best is None or str(d.get("last_seen") or "") > str(best[1].get("last_seen") or ""):
                    best = (str(d.get("mac") or k).lower(), d)
        if best:
            return "mac:" + best[0], best[1].get("name") or i
        return "ip:" + i, (reg.get(i) or {}).get("name") or i
    raise ValueError("give ip, mac, host or subject")


def subjects_for_ip(ip, reg=None):
    """Every subject that may hold notes about this IP (its MAC subject and the bare ip: subject)."""
    out = {"ip:" + ip}
    try:
        out.add(resolve(ip=ip, reg=reg)[0])
    except ValueError:
        pass
    return out


# ---------------------------------------------------------------- host notes
_COLS = ("id", "subject", "label", "category", "text", "author", "model", "via", "ts", "updated")


def host_notes(subjects=None, q=""):
    with _db() as c:
        if subjects is not None:
            subs = [s for s in subjects if s][:50]
            if not subs:
                return []
            rows = c.execute(f"SELECT {','.join(_COLS)} FROM host_notes WHERE subject IN ({','.join('?' * len(subs))}) ORDER BY updated DESC", subs).fetchall()
        else:
            rows = c.execute(f"SELECT {','.join(_COLS)} FROM host_notes ORDER BY subject, updated DESC").fetchall()
    out = [dict(zip(_COLS, r)) for r in rows]
    if q:
        ql = q.lower()
        out = [n for n in out if ql in (n["subject"] + " " + (n["label"] or "") + " " + n["text"]).lower()]
    return out


def add_host_note(subject_spec, text, category="other", author="", model="", via="", note_id=None, reg=None):
    """Add a host note, or replace note `note_id` (same subject) when given. subject_spec: {ip|mac|host|subject}."""
    subj, label = resolve(**{k: subject_spec.get(k) for k in ("ip", "mac", "host", "subject")}, reg=reg)
    text = str(text or "").strip()[:MAX_TEXT]
    if not text:
        raise ValueError("empty note")
    cat = str(category or "other").lower()
    cat = cat if cat in CATEGORIES else "other"
    now = time.time()
    with _db() as c:
        if note_id:
            r = c.execute("SELECT subject FROM host_notes WHERE id=?", (int(note_id),)).fetchone()
            if not r:
                raise ValueError(f"note {note_id} not found")
            c.execute("UPDATE host_notes SET subject=?, label=?, category=?, text=?, author=?, model=?, via=?, updated=? WHERE id=?",
                      (subj, label, cat, text, author, model, via, now, int(note_id)))
            return int(note_id)
        n = c.execute("SELECT count(*) FROM host_notes WHERE subject=?", (subj,)).fetchone()[0]
        if n >= MAX_PER_SUBJECT:
            raise ValueError(f"{subj} already has {n} notes - update or delete old ones instead of adding")
        cur = c.execute("INSERT INTO host_notes (subject, label, category, text, author, model, via, ts, updated) VALUES (?,?,?,?,?,?,?,?,?)",
                        (subj, label, cat, text, author, model, via, now, now))
        return cur.lastrowid


def delete_host_note(note_id):
    with _db() as c:
        return c.execute("DELETE FROM host_notes WHERE id=?", (int(note_id),)).rowcount


def put(doc):
    """AI write path: {"model", "via", "host_notes": [{ip|mac|host|subject, category, text, id?}], "host_notes_delete": [ids]}."""
    model = str(doc.get("model") or "unknown")[:80]
    via = str(doc.get("via") or "netmon research")[:80]
    reg, added, updated, bad = _registry(), 0, 0, []
    for n in doc.get("host_notes") or []:
        try:
            add_host_note(n, n.get("text"), n.get("category"), author="ai", model=model, via=via, note_id=n.get("id"), reg=reg)
            updated += 1 if n.get("id") else 0
            added += 0 if n.get("id") else 1
        except (ValueError, TypeError) as e:
            bad.append(f"{json.dumps({k: n.get(k) for k in ('ip', 'mac', 'host', 'subject', 'id') if n.get(k)})}: {e}")
    deleted = 0
    for i in doc.get("host_notes_delete") or []:
        try:
            deleted += delete_host_note(i)
        except (ValueError, TypeError):
            bad.append(f"delete {i!r}: bad id")
    return {"host_notes_added": added, "host_notes_updated": updated, "host_notes_deleted": deleted, "host_notes_rejected": bad[:50]}


# ---------------------------------------------------------------- event notes (people)
_ECOLS = ("id", "skey", "eid", "label", "author", "text", "ts", "status", "role", "reviewed_by", "reviewed_at")
STATUSES = ("pending", "approved", "rejected")
MAX_PENDING_PER_USER = 50


def _ekey(eid, ak):
    """Stable key for people's event notes: enrich.skey, except that IP addresses in finding ids are kept, so a note
    on one device's finding does not show up on the same kind of finding for another device."""
    import enrich
    s = str(eid)
    if s.split("|")[0] != "f":
        return enrich.skey(s, ak)
    ips = re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", s)
    k = enrich._NUM.sub("#", re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", "\x00", s))
    for ip in ips:
        k = k.replace("\x00", ip, 1)
    return k


def _skeys(eids):
    import enrich
    ak = enrich._alert_keys()
    keys = {}
    for e in eids:
        keys.setdefault(_ekey(e, ak), []).append(e)
    return keys


def event_notes(eids, ai=False, author=None):
    """{eid: [note, ...]} for the given event ids (notes carry over via the stable event key).
    ai=True: approved notes only - REQUIRED for anything that goes into an AI prompt. author: only that person's notes."""
    keys = _skeys(list(eids))
    out = {}
    if not keys:
        return out
    ks = list(keys)
    extra, xargs = "", []
    if ai:
        extra += " AND status='approved'"
    if author is not None:
        extra, xargs = extra + " AND author=?", [str(author)]
    with _db() as c:
        for i in range(0, len(ks), 500):
            ch = ks[i:i + 500]
            for r in c.execute(f"SELECT {','.join(_ECOLS)} FROM event_notes WHERE skey IN ({','.join('?' * len(ch))}){extra} ORDER BY ts", ch + xargs):
                n = dict(zip(_ECOLS, r))
                for eid in keys[n["skey"]]:
                    out.setdefault(eid, []).append({**n, "same_event": n["eid"] == eid})
    return out


def all_event_notes(limit=500, ai=False):
    with _db() as c:
        w = "WHERE status='approved' " if ai else ""
        rows = [dict(zip(_ECOLS, r)) for r in c.execute(f"SELECT {','.join(_ECOLS)} FROM event_notes {w}ORDER BY ts DESC LIMIT ?", (limit,))]
        if not ai:  # pending notes must never fall off the human review list
            seen = {n["id"] for n in rows}
            rows += [dict(zip(_ECOLS, r)) for r in c.execute(f"SELECT {','.join(_ECOLS)} FROM event_notes WHERE status='pending' ORDER BY ts DESC")
                     if r[0] not in seen]
        return rows


def get_event_note(note_id):
    with _db() as c:
        r = c.execute(f"SELECT {','.join(_ECOLS)} FROM event_notes WHERE id=?", (int(note_id),)).fetchone()
    return dict(zip(_ECOLS, r)) if r else None


def add_event_note(eid, text, author, label="", role="admin"):
    """Notes by a User-role account start 'pending' (hidden from the AI until approved); others are approved at once."""
    eid, text = str(eid or "").strip()[:600], str(text or "").strip()[:MAX_TEXT]
    if not eid or not text:
        raise ValueError("event id and text required")
    status = "pending" if role == "user" else "approved"
    k = next(iter(_skeys([eid])))
    with _db() as c:
        if status == "pending":
            n = c.execute("SELECT count(*) FROM event_notes WHERE author=? AND status='pending'", (str(author)[:60],)).fetchone()[0]
            if n >= MAX_PENDING_PER_USER:
                raise ValueError(f"you already have {n} notes waiting for approval - wait for a defender to review them")
        cur = c.execute("INSERT INTO event_notes (skey, eid, label, author, text, ts, status, role) VALUES (?,?,?,?,?,?,?,?)",
                        (k, eid, str(label or "")[:200], str(author)[:60], text, time.time(), status, str(role or "")[:20]))
        return cur.lastrowid


def review_event_note(note_id, approve, by):
    """Admin / defender decision on a note: approved notes are given to the AI, rejected ones never are."""
    with _db() as c:
        return c.execute("UPDATE event_notes SET status=?, reviewed_by=?, reviewed_at=? WHERE id=?",
                         ("approved" if approve else "rejected", str(by)[:60], time.time(), int(note_id))).rowcount


def delete_event_note(note_id, author=None):
    """author: only delete if that person wrote it (User-role accounts may only delete their own notes)."""
    with _db() as c:
        if author is not None:
            return c.execute("DELETE FROM event_notes WHERE id=? AND author=?", (int(note_id), str(author))).rowcount
        return c.execute("DELETE FROM event_notes WHERE id=?", (int(note_id),)).rowcount


def apply(res):
    """Attach people's event notes (all statuses - for admins/defenders' screens, never for an AI prompt) to a correlation result."""
    if not res or res.get("error"):
        return res
    try:
        return {**res, "unotes": event_notes((res.get("events") or {}).keys())}
    except Exception as e:  # noqa: BLE001 - notes are optional
        print(f"event notes unavailable: {e}", file=sys.stderr)
        return res


def dump(q=""):
    hn = host_notes(q=q)
    en = all_event_notes(ai=True)  # dump feeds the AI research run: approved event notes only
    if q:
        ql = q.lower()
        en = [n for n in en if ql in (n["eid"] + " " + (n["label"] or "") + " " + n["text"]).lower()]
    fmt = lambda t: time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(t)) if t else ""  # noqa: E731
    return {"host_notes": [{**n, "ts": fmt(n["ts"]), "updated": fmt(n["updated"])} for n in hn],
            "event_notes": [{k: v for k, v in {**n, "ts": fmt(n["ts"]), "reviewed_at": fmt(n["reviewed_at"])}.items() if k not in ("status", "role")} for n in en],
            "how_to_use": "event_notes are written (or approved) by the network owner / defenders: treat them as authoritative analyst guidance "
                          "(e.g. 'expected - my backup job', 'escalate if seen again'). host_notes are what earlier AI runs "
                          "(and the owner, author user:<name>) learned about each device; correct or delete stale ones."}


def main(argv):
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    # as server.py does: store.py lives in the netmon root, and must use the writable /state DB, not the read-only copy
    os.environ.setdefault("NETMON_DB", os.path.join(os.path.dirname(DB), "netmon.db"))
    root = os.environ.get("NETMON_DIR", "/netmon")
    if os.path.isdir(root) and root not in sys.path:
        sys.path.append(root)
    if argv[:1] == ["dump"]:
        print(json.dumps(dump(argv[1] if len(argv) > 1 else ""), indent=1))
    elif argv[:1] == ["put"]:
        doc = json.load(sys.stdin if argv[1:2] in (["-"], []) else open(argv[1]))
        out = put(doc)
        try:  # AI-written host notes coming back from the research job's LLM (audit log, see audit.py)
            import audit
            audit.llm("research-hostnotes", "research job", str(doc.get("model") or ""), user="netmon (research job)",
                      response=json.dumps(doc, default=str), message=f"research job: host notes from the LLM -> {json.dumps(out, default=str)[:200]}")
            audit.flush(drain=False)
        except Exception as e:  # noqa: BLE001 - never fail the job over the audit log
            print(f"audit: {e}", file=sys.stderr)
        print(json.dumps(out))
    else:
        print(__doc__)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
