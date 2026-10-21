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
  ip:<ip>        a network device without a MAC in the registry, or an external IP
  host:<name>    an Elastic Agent endpoint (short host name, lower case)
  art:<kind>:<value>  a correlated artifact (file path, process, user, ip, dns) listed by the correlation reviewer
  dom:<domain>   a DNS domain name (lower case, dot-trimmed) - internal or external
resolve() turns an IP / MAC / host name / domain into the canonical subject (IP -> MAC via the device registry).

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
_DOM = re.compile(r"^(?:[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$")


def _db():
    c = sqlite3.connect(DB, timeout=10)
    c.execute("""CREATE TABLE IF NOT EXISTS host_notes (id INTEGER PRIMARY KEY, subject TEXT, label TEXT, category TEXT, text TEXT,
                 author TEXT, model TEXT, via TEXT, ts REAL, updated REAL)""")
    c.execute("CREATE INDEX IF NOT EXISTS host_notes_subject ON host_notes(subject)")
    c.execute("""CREATE TABLE IF NOT EXISTS event_notes (id INTEGER PRIMARY KEY, skey TEXT, eid TEXT, label TEXT, author TEXT, text TEXT, ts REAL)""")
    c.execute("CREATE INDEX IF NOT EXISTS event_notes_skey ON event_notes(skey)")
    c.execute("CREATE TABLE IF NOT EXISTS note_artifacts (note_id INTEGER, art TEXT, PRIMARY KEY (note_id, art))")
    c.execute("CREATE INDEX IF NOT EXISTS note_artifacts_art ON note_artifacts(art)")
    if c.execute("PRAGMA user_version").fetchone()[0] < 1:  # first start with artifact indexing: index the notes written before
        for nid, subj, text in c.execute("SELECT id, subject, text FROM host_notes").fetchall():
            _index(c, nid, subj, text)
        c.execute("PRAGMA user_version=1")
    have = {r[1] for r in c.execute("PRAGMA table_info(event_notes)")}
    for col, decl in (("status", "TEXT NOT NULL DEFAULT 'approved'"), ("role", "TEXT"), ("reviewed_by", "TEXT"), ("reviewed_at", "REAL")):
        if col not in have:  # older kb.db: every existing note was written by an admin/defender, so it stays approved
            c.execute(f"ALTER TABLE event_notes ADD COLUMN {col} {decl}")
    return c


# ---------------------------------------------------------------- artifact index
# Every host note carries the artifacts it is about (IPs, internet IPs, DNS names, ports, processes/files, accounts), read from its
# subject, its [reviewer:<kind>:<value>] tag and its text. The correlation reviewer looks an event's artifacts up in this index
# BEFORE it chooses which notes to hand to the model (corr_llm._context_notes), so a note about a process, port or internet
# address reaches the events that show it even when it hangs on a different host.
_A_IP = re.compile(r"(?<![\d.])((?:\d{1,3}\.){3}\d{1,3})(?![\d.]*\d)")
_A_PORT = re.compile(r"(?:\bports?\s+(\d{1,5})\b|(?<=[\d\]]):(\d{2,5})\b|\b(\d{1,5})/(?:tcp|udp)\b)", re.I)
_A_DNS = re.compile(r"\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})\b", re.I)
_A_PATH = re.compile(r"(?<![\w.])(/(?:[\w.+@-]+/)*[\w.+@-]+)")
_A_PROC = re.compile(r"\b(?:process|binary|executable|daemon|service|command)\s+[`'\"]?([\w.+-]{2,40})\b", re.I)
_A_TAG = re.compile(r"\[reviewer:(file|process|user|ip|dns):([^\]]{1,200})\]")
_A_STOP_PROC = {"is", "as", "was", "that", "which", "and", "the", "for", "from", "with", "this", "runs", "ran", "named", "called", "on", "in", "to", "of", "or", "by", "at", "an", "a"}
_A_FILE_EXT = {"py", "sh", "so", "txt", "log", "conf", "cfg", "json", "yml", "yaml", "md", "html", "js", "css", "png", "jpg", "pdf", "zip", "gz", "tar", "xml", "ini", "db", "exe", "dll", "sys", "bin", "deb", "rpm", "pem", "crt", "key", "service", "local", "lan", "home", "internal", "arpa"}
ART_WEIGHT = {"ip": 3, "dns": 3, "proc": 3, "user": 2, "port": 1}  # a port alone never selects a note (needs >= MIN_ART_SCORE)
MIN_ART_SCORE = 2


def _proc_key(v):
    v = str(v).strip().rstrip(".,;:)")
    return "proc:" + v.rsplit("/", 1)[-1].lower() if v else ""


def artifact_keys(text="", subject="", kinds=None):
    """Normalised artifact keys of a note / text: ip:1.2.3.4, dns:example.com, port:443, proc:sshd (process or file base name), user:alice."""
    out = set()
    text = str(text or "")
    k, _, v = str(subject or "").partition(":")
    if k == "ip" and _IP.match(v):
        out.add("ip:" + v)
    elif k == "dom" and v:
        out.add("dns:" + v.lower().strip("."))
    elif k == "art":
        kind, _, val = v.partition(":")
        if kind == "ip":
            out.add("ip:" + val)
        elif kind == "dns":
            out.add("dns:" + val.lower().strip("."))
        elif kind in ("file", "process"):
            out.add(_proc_key(val))
        elif kind == "user" and val:
            out.add("user:" + val.lower())
    for kind, val in _A_TAG.findall(text):
        out |= artifact_keys(subject=f"art:{kind}:{val}")
    for m in _A_IP.finditer(text):
        ip = m.group(1)
        if all(int(x) <= 255 for x in ip.split(".")) and not ip.startswith(("0.", "127.", "255.")) and not ip.endswith(".255"):
            out.add("ip:" + ip)
    for m in _A_PORT.finditer(text):
        p = next(g for g in m.groups() if g)
        if 0 < int(p) < 65536:
            out.add("port:" + str(int(p)))
    for m in _A_DNS.finditer(text):
        d = m.group(1).lower()
        if d.rsplit(".", 1)[-1] not in _A_FILE_EXT and not _IP.match(d) and len(d) > 4:
            out.add("dns:" + d)
    for m in _A_PATH.finditer(text):
        if m.group(1).count("/") >= 2:
            out.add(_proc_key(m.group(1)))
    for m in _A_PROC.finditer(text):
        if m.group(1).lower() not in _A_STOP_PROC:
            out.add("proc:" + m.group(1).lower())
    out.discard("")
    return {x for x in out if not kinds or x.split(":", 1)[0] in kinds}


def event_artifact_keys(ev):
    """The artifact keys one event shows: its IPs (internal and internet), the artifacts the script read from it (files, processes,
    users, DNS, IPs) and the ports / addresses / names mentioned in its label."""
    out = set()
    for ip in [*(ev.get("ips") or []), *(ev.get("host_ips") or []), *(ev.get("dst_ips") or [])]:
        if _IP.match(str(ip)):
            out.add("ip:" + str(ip))
    for a in ev.get("arts") or []:
        if not a or len(a) < 2:
            continue
        kind, val = a[0], str(a[1])
        if kind in ("file", "process"):
            out.add(_proc_key(val))
        elif kind == "user":
            out.add("user:" + val.lower())
        elif kind == "dns":
            out.add("dns:" + val.lower().strip("."))
        elif kind == "ip":
            out.add("ip:" + val)
    out |= artifact_keys(ev.get("label") or "")
    out.discard("")
    return out


def _index(c, nid, subject, text):
    c.execute("DELETE FROM note_artifacts WHERE note_id=?", (nid,))
    c.executemany("INSERT OR IGNORE INTO note_artifacts VALUES (?,?)", [(nid, a) for a in sorted(artifact_keys(text, subject))[:60]])


def note_artifacts(ids):
    """{note_id: [artifact key, ...]} for host notes."""
    ids = [int(i) for i in ids][:2000]
    out = {}
    if ids:
        with _db() as c:
            for nid, a in c.execute(f"SELECT note_id, art FROM note_artifacts WHERE note_id IN ({','.join('?' * len(ids))}) ORDER BY art", ids):
                out.setdefault(nid, []).append(a)
    return out


def art_score(note_arts, ev_arts):
    """(score, matched keys) of one note against an event's artifact keys."""
    hit = sorted(set(note_arts) & set(ev_arts))
    return sum(ART_WEIGHT.get(h.split(":", 1)[0], 1) for h in hit), hit


def notes_by_artifacts(ev_arts, exclude_ids=(), limit=12):
    """Host notes (any subject) that carry at least one of the event's artifacts: [(score, matched, note)], best first.
    Notes scoring under MIN_ART_SCORE (a shared port only) are left out."""
    ev_arts = sorted(ev_arts)[:200]
    if not ev_arts:
        return []
    with _db() as c:
        ids = [r[0] for r in c.execute(f"SELECT DISTINCT note_id FROM note_artifacts WHERE art IN ({','.join('?' * len(ev_arts))})", ev_arts)]
    ids = [i for i in ids if i not in set(exclude_ids)]
    if not ids:
        return []
    na = note_artifacts(ids)
    with _db() as c:
        rows = [dict(zip(_COLS, r)) for r in c.execute(f"SELECT {','.join(_COLS)} FROM host_notes WHERE id IN ({','.join('?' * len(ids))})", ids)]
    out = []
    for n in rows:
        sc, hit = art_score(na.get(n["id"], []), ev_arts)
        if sc >= MIN_ART_SCORE and not str(n["text"]).startswith("[profile:"):  # generated per-host profiles list many peers: they stay with their own host
            out.append((sc, hit, n))
    out.sort(key=lambda t: (-t[0], -float(t[2].get("updated") or 0)))
    return out[:limit]


# ---------------------------------------------------------------- subjects
def _registry():
    try:
        import store
        return store.registry_load()
    except Exception:  # noqa: BLE001 - without the registry, IPs stay ip: subjects
        return {}


ART_KINDS = ("file", "process", "user", "ip", "dns")


def resolve(ip=None, mac=None, host=None, dom=None, subject=None, reg=None):
    """Canonical subject + display label for an IP, MAC, endpoint host name, DNS domain or an explicit subject."""
    if subject:
        s = str(subject).strip()
        k, _, v = s.partition(":")
        if k == "mac" and _MAC.match(v.lower()):
            return resolve(mac=v, reg=reg)
        if k == "ip" and _IP.match(v):
            return resolve(ip=v, reg=reg)
        if k == "host" and v:
            return resolve(host=v, reg=reg)
        if k == "dom" and v:
            return resolve(dom=v, reg=reg)
        if k == "art":  # a correlated artifact the reviewer listed: art:<file|process|user|ip|dns>:<value>
            ak, _, av = v.partition(":")
            av = av.strip()
            if ak in ART_KINDS and av and len(av) <= 300 and "\n" not in av:
                av = av.lower() if ak in ("ip", "dns") else av
                return f"art:{ak}:{av}", f"{ak} {av}"
        raise ValueError(f"bad subject {s!r} (use mac:<mac>, ip:<ip>, host:<name>, dom:<domain> or art:<kind>:<value>)")
    if dom:
        d = str(dom).strip().lower().rstrip(".")
        if not _DOM.match(d):
            raise ValueError(f"bad domain {dom!r}")
        return "dom:" + d, d
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
    if out:
        na = note_artifacts([n["id"] for n in out])
        for n in out:
            n["artifacts"] = na.get(n["id"], [])
    if q:
        ql = q.lower()
        out = [n for n in out if ql in (n["subject"] + " " + (n["label"] or "") + " " + n["text"]).lower()]
    return out


def add_host_note(subject_spec, text, category="other", author="", model="", via="", note_id=None, reg=None):
    """Add a host note, or replace note `note_id` (same subject) when given. subject_spec: {ip|mac|host|dom|subject}."""
    subj, label = resolve(**{k: subject_spec.get(k) for k in ("ip", "mac", "host", "dom", "subject")}, reg=reg)
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
            _index(c, int(note_id), subj, text)
            return int(note_id)
        n = c.execute("SELECT count(*) FROM host_notes WHERE subject=?", (subj,)).fetchone()[0]
        if n >= MAX_PER_SUBJECT:
            raise ValueError(f"{subj} already has {n} notes - update or delete old ones instead of adding")
        cur = c.execute("INSERT INTO host_notes (subject, label, category, text, author, model, via, ts, updated) VALUES (?,?,?,?,?,?,?,?,?)",
                        (subj, label, cat, text, author, model, via, now, now))
        _index(c, cur.lastrowid, subj, text)
        return cur.lastrowid


def delete_host_note(note_id):
    with _db() as c:
        c.execute("DELETE FROM note_artifacts WHERE note_id=?", (int(note_id),))
        return c.execute("DELETE FROM host_notes WHERE id=?", (int(note_id),)).rowcount


def is_external(ip):
    """A public address: not private / loopback / link-local / CGNAT and not in the site's internal prefixes."""
    import ipaddress
    try:
        a = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return False
    if a.version != 4 or a.is_private or a.is_loopback or a.is_link_local or a.is_multicast or a.is_reserved or a in ipaddress.ip_network("100.64.0.0/10"):
        return False
    try:
        import site_cfg
        return not site_cfg.is_internal(str(ip))
    except Exception:  # noqa: BLE001 - without the site config the standard private ranges are enough
        return True


def external_ips(ev):
    """External IPs an event involves (its destinations, artifacts and non-internal hosts), max 8."""
    out = []
    for ip in [*(ev.get("dst_ips") or []), *(ev.get("ips") or []), *(a[1] for a in ev.get("arts") or [] if a and a[0] == "ip")]:
        ip = str(ip).strip()
        if ip not in out and is_external(ip):
            out.append(ip)
    return out[:8]


def internet_notes(q=""):
    """Notes about external IPs (subject ip:<public ip> or art:ip:<public ip>), grouped per IP: [{ip, notes: [...], n, updated}]."""
    by = {}
    for n in host_notes(q=q):
        s = str(n["subject"])
        ip = s[3:] if s.startswith("ip:") else s[7:] if s.startswith("art:ip:") else None
        if ip and is_external(ip):
            by.setdefault(ip, []).append(n)
    out = [{"ip": ip, "n": len(ns), "updated": max(float(x.get("updated") or 0) for x in ns), "notes": ns} for ip, ns in by.items()]
    return sorted(out, key=lambda r: -r["updated"])


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
                n["artifacts"] = sorted(artifact_keys(n["text"]))
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
        for n in rows:
            n["artifacts"] = sorted(artifact_keys(n["text"]))
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
