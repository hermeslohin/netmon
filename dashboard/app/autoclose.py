"""Security Triage auto-close (More -> Configuration).

Four options (settings reviewer_expected, reviewer_benign, researcher_expected, researcher_benign): close events the event reviewer LLM classified expected/benign
(corr_llm event_class), and/or events whose AI research note (enrich.py) has verdict "expected"/"benign". A source calling
the event suspicious/malicious blocks closing. Events are checked off automatically, i.e. moved to the closed findings, with the note "auto-closed: AI verdict ...".

Closed: the snapshot's checklist items - baseline findings (f|...), endpoint/host findings (hf|...), fix-list issues
(iss|...; segmentation issues map to the shared "seg" flow key) - and every event on the Open events page (any age: IDS
signatures, watcher alerts, gateway events, threat intel, admin sessions, older findings), using the same check-offs
that page writes. The extra keys of a grouped event are kept in autoclose_log.refs so a reopen restores them too.

Rules:
  - an item a person already checked off is left alone;
  - an item that was auto-closed and later un-checked by a person is never auto-closed again (log state "reopened");
  - when an auto-closed item's verdict changes to something not enabled (e.g. the AI later says "suspicious"),
    it is reopened automatically;
  - turning an option off stops new closures; "reopen" (reopen_all) restores everything auto-closed.
When: right after each review (research) job stores its notes (enrich.sh put -> `python /app/autoclose.py run`), so new
verdicts are applied once per review run; every 5 minutes from the dashboard's ingest thread (so new event reviewer
classifications close without waiting for a review job); plus "Run now" on the Configuration page.
Settings live in the store's meta table (key "autoclose"); the closure log in table autoclose_log; the last pass in
meta "autoclose_last".

Guard rails (an AI verdict alone is not always enough; a person's verdict is never held back by them):
  1. confidence (setting min_conf, 0 = off): an event reviewer label closes only at or above min_conf, or when the
     research note agrees (also expected/benign). Below it the event stays open with its reviewer flair.
  2. protected categories (setting protect): attack-type events (CATS) are never closed by AI verdicts, only by a person.
  3. host hold (setting host_hold, on/off; window fixed at HOLD_HOURS): while an open event on the same host (MAC / host name / host IP) was called
     suspicious or malicious by any source and was seen in the last HOLD_HOURS, nothing on that host is auto-closed, and AI
     closures of that host's events that were active in the window are reopened. Code-scan findings (iss|sec|, NO_HOLD)
     never put a host on hold; when they are called suspicious only they stay open.
  6. expiry (setting expire_days, 0 = never): an AI closure lasts expire_days; when the event repeats after that, it is
     reopened (log state "expired") and closes again only on a verdict newer than the old closure. Person closures never expire.
Rules 1 and 2 apply to new closures; items closed before are left closed and counted (reopen them with "reopen_guard").
"""
import json, os, sys, threading, time

# store.py lives in the netmon root (/netmon in the container); add it before importing it, as server.py does.
_ROOT = os.environ.get("NETMON_DIR", "/netmon")
if os.path.isdir(_ROOT) and _ROOT not in sys.path:
    sys.path.append(_ROOT)

import enrich
import store
from risk import seg_key_finding, seg_key_issue

KINDS = ("expected", "benign")  # verdicts that close an item
SOURCES = ("reviewer", "researcher")  # who decided: the event reviewer's classification / the research note
OPTS = tuple(f"{src}_{k}" for src in SOURCES for k in KINDS)  # the four switches: reviewer_expected, reviewer_benign, ...
NOTE_PREFIX = "auto-closed: AI verdict "
PERSON_PREFIX = "auto-closed: analyst verdict "  # a person's Expected / Benign button on the event's 📝 notes (always applied)
PREFIXES = (NOTE_PREFIX, PERSON_PREFIX)
PERSON = ("person_expected", "person_benign")
_lock = threading.Lock()

HOLD_HOURS = 24  # guard 3: a recent open suspicious event holds auto-close on its host for this long (fixed)
NO_HOLD = ("iss|sec|",)  # guard 3 ignores these: code-scan findings say nothing about the host's own behaviour
CATS = {  # guard 2: attack-type event categories auto-close can be kept away from (key: label)
    "ids_high": "High-severity IDS signatures (and first-seen high-severity signatures)",
    "threat_intel": "Threat-intel hits (traffic with listed IPs, in or out)",
    "admin": "Admin access: admin sessions (not allow-listed), new logins, auth failures, sudo errors, password SSH, UniFi admin from a new source",
    "new_device": "New devices never seen before (first sighting; plain DHCP joins are not included)",
    "exposure": "New exposure: new listening ports, more inbound sources",
    "c2_exfil": "C2 / exfiltration signs: malicious TLS fingerprints, new resolver or DNS-over-HTTPS, newly registered domains, internal scans, high-severity beacons and upload spikes",
    "host_tamper": "Host tampering: suspicious processes (memfd / fileless, shells from services), changed binaries, new accounts, agent or Defender off, interpreters on the network, high-severity file and process-network findings",
    "gateway_threat": "Gateway threat blocks (THREAT_BLOCKED; already blocked by the gateway)",
    "high_sev": "Any event with high or urgent severity",
}
GUARD_DEFAULTS = {"min_conf": 0.8, "expire_days": 7, "host_hold": True,
                  "protect": ["ids_high", "threat_intel", "admin", "new_device", "exposure", "c2_exfil", "host_tamper"]}
HIGH = ("high", "urgent", "critical")


def categories(eid, sev=""):
    """Guard-2 categories of one event id (sev = its stored severity, used by the high-severity categories)."""
    p = str(eid).split("|")
    t, k, s = p[0], (p[1] if len(p) > 1 else ""), str(sev or "").lower()
    a = p[2] if len(p) > 2 else ""
    out = set()
    if (t == "ids" and s in HIGH) or (t == "f" and k == "new-signature" and s in HIGH):
        out.add("ids_high")
    if t == "ti" or (t == "f" and k == "ti-ip-in") or (t == "iss" and k == "ti-in"):
        out.add("threat_intel")
    if ((t == "adm" and s != "allowed-admin") or (t == "hf" and k in ("login-new", "authfail", "sudo-err"))
            or (t == "iss" and k == "sshpw") or (t == "iss" and k == "unifi" and a == "admin-src")):
        out.add("admin")
    if t == "f" and k == "new-device":
        out.add("new_device")
    if (t == "f" and k in ("new-listening-port", "inbound-exposure")) or (t == "hf" and k == "hnet-newlisten"):
        out.add("exposure")
    if ((t == "f" and k in ("malicious-ja3", "internal-scan", "newly-registered-domain", "dns-new-resolver", "dns-doh"))
            or (t == "f" and k in ("beacon-new", "upload-spike") and s in HIGH) or (t == "iss" and k in ("ja3", "doh"))):
        out.add("c2_exfil")
    if ((t == "hf" and k in ("proc", "exec-sha", "acct", "agent-off", "defend-pol", "hnet-interp"))
            or (t == "hf" and k in ("file", "hnet-proc") and s in HIGH) or (t == "iss" and k in ("defend", "agent"))):
        out.add("host_tamper")
    if t == "gw" and "THREAT" in (p[2] if len(p) > 2 else "").upper():
        out.add("gateway_threat")
    if s in HIGH:
        out.add("high_sev")
    return out


def _epoch(v):
    """Seconds since the epoch for a float timestamp or an ISO string (0 when unknown)."""
    if v is None or v == "":
        return 0.0
    try:
        return float(v)
    except (TypeError, ValueError):
        pass
    import datetime
    try:
        d = datetime.datetime.fromisoformat(str(v).replace("Z", "+00:00"))
        return (d if d.tzinfo else d.replace(tzinfo=datetime.timezone.utc)).timestamp()
    except ValueError:
        return 0.0


def _hosts_of(eid, doc_hosts=()):
    """Host tokens of an event: the device / host part of its id plus the doc's host_ips (never destination IPs)."""
    p = str(eid).split("|")
    out = {str(h).lower() for h in doc_hosts or () if h}
    if p[0] in ("f", "hf", "iss") and len(p) > 2 and p[2] not in ("", "-"):
        if p[0] != "iss" or p[1] not in ("sec", "sensor", "unifi"):
            out.add(p[2].lower())
    return out - {"", "-"}


def _event_index():
    """{eid: (sev, last_seen epoch, host tokens)} and {group key: newest last_seen} from the event store."""
    import eventstore
    ev, glast = {}, {}
    for eid, sev, ls, doc in eventstore._c().execute("SELECT eid, sev, last_seen, doc FROM events"):
        try:
            hs = (json.loads(doc or "{}") or {}).get("host_ips") or ()
        except ValueError:
            hs = ()
        t = _epoch(ls)
        ev[eid] = (sev or "", t, _hosts_of(eid, hs))
        g = eventstore.gkey(eid)
        if t > glast.get(g, 0):
            glast[g] = t
    return ev, glast


def _init(c):
    c.execute("""CREATE TABLE IF NOT EXISTS autoclose_log (type TEXT NOT NULL, key TEXT NOT NULL, eid TEXT, verdict TEXT,
                 model TEXT, at TEXT, state TEXT NOT NULL, PRIMARY KEY (type, key))""")
    if "source" not in {r[1] for r in c.execute("PRAGMA table_info(autoclose_log)")}:
        c.execute("ALTER TABLE autoclose_log ADD COLUMN source TEXT")  # NULL = researcher (rows written before the event reviewer option)
    if "refs" not in {r[1] for r in c.execute("PRAGMA table_info(autoclose_log)")}:
        c.execute("ALTER TABLE autoclose_log ADD COLUMN refs TEXT")  # JSON [[type, key], ...] also checked off (Open events groups)
    if "closed_at" not in {r[1] for r in c.execute("PRAGMA table_info(autoclose_log)")}:
        c.execute("ALTER TABLE autoclose_log ADD COLUMN closed_at TEXT")  # state expired: when the expired AI closure was made


def _c():
    return store.tl_conn("autoclose", _init)


def _guard(s):
    """Guard-rail settings with defaults and ranges applied."""
    try:
        mc = min(1.0, max(0.0, float(s.get("min_conf", GUARD_DEFAULTS["min_conf"]))))
    except (TypeError, ValueError):
        mc = GUARD_DEFAULTS["min_conf"]
    try:
        ed = min(365, max(0, int(s.get("expire_days", GUARD_DEFAULTS["expire_days"]))))
    except (TypeError, ValueError):
        ed = GUARD_DEFAULTS["expire_days"]
    pr = s.get("protect", GUARD_DEFAULTS["protect"])
    pr = [k for k in CATS if k in (pr if isinstance(pr, (list, tuple)) else [])]
    return {"min_conf": round(mc, 2), "expire_days": ed, "protect": pr,
            "host_hold": bool(s.get("host_hold", GUARD_DEFAULTS["host_hold"]))}


def settings(c=None):
    c = c or _c()
    r = c.execute("SELECT v FROM meta WHERE k='autoclose'").fetchone()
    s = json.loads(r[0]) if r else {}
    if not any(o in s for o in OPTS):  # saved before the event reviewer option: expected/benign meant the research note's verdict
        old = {"researcher_expected": s.get("expected"), "researcher_benign": s.get("benign")}  # very first version
        for src in SOURCES:  # intermediate version: one switch per source covered both verdicts
            if src in s:
                old.update({f"{src}_{k}": s[src] for k in KINDS})
        s = {**s, **old}
    return {**{o: bool(s.get(o)) for o in OPTS}, **_guard(s), "updated_by": s.get("updated_by"), "updated_at": s.get("updated_at")}


def set_settings(opts, user):
    """The four switches are taken as given (missing = off); guard-rail keys missing from opts keep their saved value."""
    c = _c()
    opts = opts or {}
    cur = settings(c)
    g = _guard({k: opts.get(k, cur[k]) for k in GUARD_DEFAULTS})
    s = {**{o: bool(opts.get(o)) for o in OPTS}, **g, "updated_by": user, "updated_at": store.now_iso()}
    with store.tx(c):
        c.execute("INSERT OR REPLACE INTO meta VALUES ('autoclose', ?)", (json.dumps(s),))
    return s


def fnv(s):
    """Same hash as fnv() in app.js (UTF-16 code units, base36) - ack keys for baseline findings."""
    h = 0x811c9dc5
    b = s.encode("utf-16-le")
    for i in range(0, len(b), 2):
        h ^= b[i] | (b[i + 1] << 8)
        h = (h * 0x01000193) & 0xFFFFFFFF
    d, out = "0123456789abcdefghijklmnopqrstuvwxyz", ""
    while True:
        h, r = divmod(h, 36)
        out = d[r] + out
        if not h:
            return out


def _js(v):
    return "undefined" if v is None else str(v)


def _items(raw, analysis, open_issues):
    """[(eid, ack_type, ack_key, label)] for every closable event in the snapshot."""
    out = []
    for f in (analysis or {}).get("findings") or []:
        eid = f"f|{f.get('kind')}|{f.get('device') or ''}|{f.get('detail', '')}"
        sk = seg_key_finding(f)
        out.append((eid, "seg", sk, f"Segmentation: {f.get('detail', '')}") if sk else
                   (eid, "finding", fnv(f"{_js(f.get('device'))}|{_js(f.get('kind'))}|{_js(f.get('detail'))}"),
                    f"{f.get('kind')}: {f.get('detail', '')}"))
    for f in ((raw or {}).get("hosts") or {}).get("findings") or []:
        if f.get("key"):
            out.append((f"hf|{f['key']}", "host", f["key"], f.get("text", "")))
    for i in open_issues or []:
        sk = seg_key_issue(i["key"])
        out.append((f"iss|{i['key']}", "seg" if sk else "issue", sk or i["key"], f"{i.get('title', '')} — {i.get('target', '')}"))
    return out


def last_run(c=None):
    c = c or _c()
    r = c.execute("SELECT v FROM meta WHERE k='autoclose_last'").fetchone()
    return json.loads(r[0]) if r else None


def _verdicts(eid, notes, cls, pv=None):
    """{source: verdict} - researcher = the research note's verdict, event reviewer = the event reviewer's label,
    person = a person's approved verdict note (📝 Expected / Benign / Suspicious)."""
    out = {}
    v = ((pv or {}).get(eid) or {}).get("verdict")
    if v:
        out["person"] = v
    v = (notes.get(eid) or {}).get("verdict")
    if v:
        out["researcher"] = v
    v = (cls.get(eid) or {}).get("label")
    if v:
        out["reviewer"] = v
    return out


BAD = ("suspicious", "malicious")


def _refs_of(row):
    """Extra (type, key) check-offs an autoclose_log row closed together with its own."""
    try:
        return [tuple(x) for x in json.loads((dict(row) if row else {}).get("refs") or "[]")]
    except (ValueError, TypeError):
        return []


def _host_hold(oe, g, notes, cls, pv, hosts, cut):
    """Guard 3's held hosts: {host token: label} of open events some source (or a person) called suspicious/malicious,
    seen since cut. Empty when host_hold is off."""
    sus = {}
    for e in (oe if g["host_hold"] else ()):
        mem = [e["eid"], *(e.get("members") or [])]
        if _epoch(e.get("last_seen")) < cut or str(e["eid"]).startswith(NO_HOLD):
            continue
        pn = max((pv[m] for m in mem if m in pv), key=lambda n: n["ts"] or 0, default=None)
        badv = (pn["verdict"] in BAD) if pn else any(v in BAD for m in mem for v in _verdicts(m, notes, cls).values())
        if badv:
            for h in hosts(mem):
                sus.setdefault(h, e.get("label") or e["eid"])
    return sus


def guard_rails(mem, good, g, sus, hosts, evx, info, lx=None):
    """The auto-close guard rails (module docstring 1, 2, 3, 6) for an AI expected/benign verdict on one event (mem = the
    event and its grouped members). good = the closing verdicts ["reviewer_expected", ...]; g = _guard(settings);
    sus = _host_hold(); info(src) = that source's verdict record; lx = an expired closure of the event's group.
    Returns (guard or None, why, good, held hosts, protected categories). Used by run() and by the phone-push gate
    (push_check), so both apply exactly the same rules."""
    guard, why, hh, pc = None, "", [], []
    if lx:  # guard 6: after an expired closure only a newer verdict counts
        since = _epoch(lx.get("closed_at"))
        fresh = [k for k in good if _epoch(info(k.split("_")[0]).get("at")) > since]
        if fresh:
            good = fresh
        else:
            guard, why = "stale", f"closure expired; waiting for a verdict newer than {lx.get('closed_at')}"
    hh = sorted(hosts(mem) & sus.keys()) if not guard else []
    if hh:  # guard 3
        guard, why = "host", f"held: open suspicious event on {hh[0]} ({str(sus[hh[0]])[:70]})"
    pc = sorted(set().union(*(categories(m, evx[m][0] if m in evx else "") for m in mem)) & set(g["protect"])) if not guard else []
    if pc:  # guard 2
        guard, why = "protected", "protected category: " + ", ".join(pc)
    if not guard and g["min_conf"] > 0 and not any(k.startswith("researcher_") for k in good):  # guard 1
        conf = info("reviewer").get("confidence")
        if conf is None or float(conf) < g["min_conf"]:
            guard, why = "low_conf", f"event reviewer confidence {conf if conf is not None else '?'} < {g['min_conf']} and no research note agrees"
    return guard, why, good, hh, pc


def push_check(eid, members=()):
    """Phone-push gate (pushgate.py): may an urgent alarm about this event stay off the phones? ok=True only when its
    verdict is expected/benign (a person's, or an AI verdict that passes every guard rail above, the same
    guard_rails() auto-close uses) and no source calls it suspicious/malicious. Returns {ok, verdict, source, guard, why}."""
    import corr_llm
    import eventstore
    import kb
    with _lock:
        c = _c()
        g = _guard(settings(c))
        evx, _gl = _event_index()
        mem = list(dict.fromkeys([eid, *members]))
        oe = eventstore.open_events(limit=10 ** 6)["events"]
        ids = list(dict.fromkeys(mem + [i for e in oe for i in [e["eid"], *(e.get("members") or [])]]))
        notes, cls, pv = enrich.load(ids), corr_llm.classes(ids), kb.person_verdicts(ids)

        def hosts(ms):
            out = set()
            for m in ms:
                out |= evx[m][2] if m in evx else _hosts_of(m)
            return out
        pn = max((pv[m] for m in mem if m in pv), key=lambda n: n["ts"] or 0, default=None)
        if pn:  # a person's call outranks every AI verdict and every guard rail
            ok = pn["verdict"] in KINDS
            return {"ok": ok, "verdict": pn["verdict"], "source": "person", "guard": None, "why": "" if ok else "a person called it " + pn["verdict"]}
        vs, bad = {}, None
        for m in mem:
            for k, v in _verdicts(m, notes, cls).items():
                vs.setdefault(k, v)
                bad = bad or (v if v in BAD else None)
        if bad:  # any source on any grouped member calling it suspicious / malicious always pushes
            return {"ok": False, "verdict": bad, "source": "", "guard": None, "why": f"a source calls the group {bad}"}
        good = [f"{k}_{vs[k]}" for k in SOURCES if vs.get(k) in KINDS]
        if not good:
            return {"ok": False, "verdict": vs.get("reviewer") or "", "source": "reviewer", "guard": None, "why": "no expected/benign verdict"}
        lx = next((dict(r) for r in c.execute("SELECT * FROM autoclose_log WHERE state='expired' AND eid IS NOT NULL")
                   if eventstore.gkey(r["eid"]) == eventstore.gkey(eid)), None)
        info = lambda src: (notes.get(eid) if src == "researcher" else cls.get(eid)) or {}  # noqa: E731
        guard, why, good, _hh, _pc = guard_rails(mem, good, g, _host_hold(oe, g, notes, cls, pv, hosts, time.time() - HOLD_HOURS * 3600),
                                                 hosts, evx, info, lx=lx)
        return {"ok": not guard, "verdict": good[0].split("_", 1)[1], "source": good[0].split("_", 1)[0], "guard": guard, "why": why}


def run(raw, analysis, open_issues, other_eids=(), dry=False, trigger="manual", with_open=True, reopen_guard=False):
    """Apply the enabled options to the snapshot. Returns counts (also the preview for the Configuration card).
    An item closes when an enabled source says expected/benign, no source calls it suspicious/malicious and no guard rail
    holds it (module docstring). reopen_guard: also reopen AI closures that guard 1 (confidence) or 2 (protected) would
    hold back today."""
    import corr_llm
    import eventstore
    import kb
    with _lock:
        c = _c()
        s = settings(c)
        g = _guard(s)
        protect = set(g["protect"])
        now = time.time()
        cut = now - HOLD_HOURS * 3600
        on = {o for o in OPTS if s[o]}
        on |= set(PERSON)  # a person's verdict is authoritative: applied whatever the four switches say
        res = {o: {"closable": 0, "would_close": 0, "closed_now": 0, "auto_closed": 0, "reopened_by_user": 0, "no_checklist": 0}
               for o in (*OPTS, *PERSON)}
        res["reopened_verdict_changed"] = 0
        G = res["guard"] = {"low_conf": 0, "protected": 0, "host": 0, "stale": 0, "kept_low_conf": 0, "kept_protected": 0,
                            "reopened_host": 0, "reopen_host_due": 0, "reopened_guard": 0, "expired": 0, "expire_due": 0,
                            "by_cat": {}, "hosts": {}, "samples": [], "hold_hours": HOLD_HOURS}
        evx, glast = _event_index()
        log = {(r["type"], r["key"]): dict(r) for r in c.execute("SELECT * FROM autoclose_log")}
        acks = store.acks_load(c)

        # guard 6: AI closures older than expire_days whose event repeated after that are reopened for a fresh verdict.
        # Judged per event group by its newest closure: a later repeat with its own (newer) closure keeps the group closed.
        if g["expire_days"]:
            span = g["expire_days"] * 86400
            newest = {}  # group -> (newest closure time, made by a person)
            for lg in log.values():
                if lg["state"] in ("closed", "person") and lg.get("eid"):
                    gk, at = eventstore.gkey(lg["eid"]), _epoch(lg["at"])
                    p0 = newest.get(gk, (0, False))
                    newest[gk] = (max(p0[0], at), p0[1] or (lg.get("source") or "researcher") == "person")
            for (t, k), lg in log.items():
                if lg["state"] != "closed" or (lg.get("source") or "researcher") == "person" or not lg.get("eid"):
                    continue
                gk = eventstore.gkey(lg["eid"])
                at, by_person = newest.get(gk, (_epoch(lg["at"]), False))
                if by_person or not at or now - at < span or glast.get(gk, 0) <= at + span:
                    continue
                G["expire_due"] += 1
                if dry:
                    continue
                for t2, k2 in dict.fromkeys([(t, k), *_refs_of(lg)]):
                    b = (acks.get(t2) or {}).get(k2)
                    if b and str(b.get("note") or "").startswith(NOTE_PREFIX):
                        store.ack_set(t2, k2, False, c=c)
                ts = store.now_iso()
                with store.tx(c):
                    c.execute("UPDATE autoclose_log SET state='expired', closed_at=?, at=? WHERE type=? AND key=?", (lg["at"], ts, t, k))
                lg.update(state="expired", closed_at=lg["at"], at=ts)
                G["expired"] += 1
            if G["expired"]:
                acks = store.acks_load(c)
        exp_by_g = {eventstore.gkey(lg["eid"]): lg for lg in log.values() if lg["state"] == "expired" and lg.get("eid")}

        items = _items(raw, analysis, open_issues)
        oe = eventstore.open_events(limit=10 ** 6)["events"] if with_open else []
        ids = list(dict.fromkeys([i[0] for i in items] + list(other_eids) + [i for e in oe for i in [e["eid"], *(e.get("members") or [])]]))
        notes = enrich.load(ids)
        cls = corr_llm.classes(ids)
        pv = kb.person_verdicts(ids)
        seen, handled = set(), set()
        rules = store.suppress_list(c)  # suppression outranks auto-close: a covered item is never reopened

        def hosts(mem):
            out = set()
            for m in mem:
                out |= evx[m][2] if m in evx else _hosts_of(m)
            return out

        # guard 3: hosts with an open event some source (or a person) called suspicious/malicious, seen in the last HOLD_HOURS
        # off (host_hold false): only the event called suspicious stays open; the rest of its host closes as usual
        sus = _host_hold(oe, g, notes, cls, pv, hosts, cut)

        def reopen(typ, key, a, lg, label, why):
            """Un-check an auto-closed item (own + group check-offs). False when a suppress rule keeps it hidden."""
            lab = label or str((a or {}).get("label") or "")
            if lab and any(store.suppress_match(r, lab) for r in rules):  # a suppress rule covers it: stays hidden
                with store.tx(c):
                    c.execute("UPDATE autoclose_log SET state='suppressed', at=? WHERE type=? AND key=?", (store.now_iso(), typ, key))
                return False
            for t, k in dict.fromkeys([(typ, key), *_refs_of(lg)]):
                b = (acks.get(t) or {}).get(k)
                if b and str(b.get("note") or "").startswith(PREFIXES):
                    store.ack_set(t, k, False, c=c)
            with store.tx(c):
                c.execute("UPDATE autoclose_log SET state='reopened-verdict', verdict=?, at=? WHERE type=? AND key=?",
                          (str(why)[:120], store.now_iso(), typ, key))
            lg["state"] = "reopened-verdict"
            return True

        def sample(guard, eid, label, why):
            if sum(1 for x in G["samples"] if x["guard"] == guard) < 8:
                G["samples"].append({"guard": guard, "eid": eid, "label": str(label or "")[:160], "why": why})

        def handle(eid, refs, label, members=()):
            """One closable event: refs[0] is its own check-off (logged); the rest are checked off with it."""
            typ, key = refs[0]
            others = [m for m in members if m != eid]
            mem = [eid, *others]
            vs = {k: v for k, v in _verdicts(eid, notes, cls).items()}
            for src, get in (("researcher", lambda m: notes.get(m)), ("reviewer", lambda m: cls.get(m))):
                if src not in vs:  # grouped event: its newest run is not classified yet - the latest classified repeat decides
                    best = max((get(m) for m in others if (get(m) or {}).get("verdict" if src == "researcher" else "label")),
                               key=lambda x: str(x.get("at") or ""), default=None)
                    if best:
                        vs[src] = best.get("verdict" if src == "researcher" else "label")
                        vfrom[(eid, src)] = best
            bad = any(v in BAD for v in vs.values()) or any(
                v in BAD for m in others for v in _verdicts(m, notes, cls).values())
            pn = max((pv[m] for m in mem if m in pv), key=lambda n: n["ts"] or 0, default=None)
            if pn:  # a person's call outranks every AI verdict
                vs["person"] = pn["verdict"]
                bad = pn["verdict"] in BAD
                good = [] if bad else [f"person_{pn['verdict']}"]
            else:
                good = [f"{k}_{vs[k]}" for k in SOURCES if vs.get(k) in KINDS]
            a = (acks.get(typ) or {}).get(key)
            lg = log.get((typ, key))
            auto = bool(a and str(a.get("note") or "").startswith(PREFIXES))
            if not vs and not auto:
                return False  # no verdict for this variant: let another variant of the same event decide
            if not good or bad:
                if auto and lg and lg["state"] == "closed" and not dry:  # verdict changed since: bring it back
                    if reopen(typ, key, a, lg, label, ",".join(f"{k}:{v}" for k, v in vs.items())):
                        res["reopened_verdict_changed"] += 1
                return

            def info(src):
                return vfrom.get((eid, src)) or (notes.get(eid) if src == "researcher" else cls.get(eid)) or {}

            guard, why, hh, pc = None, "", [], []
            if not pn:  # guard rails hold back AI verdicts only; a person's call always applies
                lx = lg if lg and lg["state"] == "expired" else exp_by_g.get(eventstore.gkey(eid))
                guard, why, good, hh, pc = guard_rails(mem, good, g, sus, hosts, evx, info, lx=None if auto else lx)
            if guard and auto and lg and lg["state"] == "closed" and (lg.get("source") or "researcher") != "person":
                recent = glast.get(eventstore.gkey(eid), 0) >= cut or any((evx.get(m) or (0, 0))[1] >= cut for m in mem)
                if guard == "host" and recent:
                    if dry:
                        G["reopen_host_due"] += 1
                    elif reopen(typ, key, a, lg, label, why):
                        G["reopened_host"] += 1
                        return
                elif guard in ("low_conf", "protected"):
                    if reopen_guard and not dry:
                        if reopen(typ, key, a, lg, label, "guard: " + why):
                            G["reopened_guard"] += 1
                        return
                    G["kept_" + guard] += 1
            if lg and lg["state"] == "closed" and not a:  # a person un-checked it after we closed it
                if not dry:
                    with store.tx(c):
                        c.execute("UPDATE autoclose_log SET state='reopened', at=? WHERE type=? AND key=?", (store.now_iso(), typ, key))
                lg["state"] = "reopened"
            for k in good:
                res[k]["closable"] += 1
            if lg and lg["state"] == "reopened" and pn and good and _ts(pn["ts"]) > str(lg.get("at") or ""):
                lg["state"] = "person"  # a person marked it expected/benign after it was reopened: their newer call wins
            if lg and lg["state"] == "reopened":
                for k in good:
                    res[k]["reopened_by_user"] += 1
                return
            if auto:
                src = (lg or {}).get("source") or "researcher"
                o = f"{src}_{(lg or {}).get('verdict')}"
                res[o if o in good else good[0]]["auto_closed"] += 1
                return
            if a:
                return  # checked off by a person
            if guard:
                G[guard] += 1
                if guard == "protected":
                    for k in pc:
                        G["by_cat"][k] = G["by_cat"].get(k, 0) + 1
                if guard == "host":
                    G["hosts"][hh[0]] = G["hosts"].get(hh[0], 0) + 1
                sample(guard, eid, label, why)
                return
            hit = next((k for k in good if k in on), None)
            for k in good:
                res[k]["would_close"] += 1
            if hit and not dry:
                src, v = hit.split("_")
                if src == "person":
                    who = {"model": f"person:{pn['author']}"}
                    txt = str(pn["text"] or "").split("do not contradict it)", 1)[-1].lstrip(". ")  # the person's own words
                    note = f"{PERSON_PREFIX}{v} (by {str(pn['author']).replace('user:', '')}){': ' + txt if txt else ''}"
                else:
                    who = info(src)
                    text = who.get("summary") if src == "researcher" else who.get("reason")
                    note = f"{NOTE_PREFIX}{v} ({src}, {who.get('model') or 'AI'}): {text or ''}"
                for t, k in dict.fromkeys(refs):
                    if not (acks.get(t) or {}).get(k):
                        store.ack_set(t, k, True, note, label, c=c)
                with store.tx(c):
                    c.execute("INSERT OR REPLACE INTO autoclose_log (type, key, eid, verdict, model, at, state, source, refs, closed_at) "
                              "VALUES (?,?,?,?,?,?, 'closed', ?, ?, NULL)",
                              (typ, key, eid, v, str(who.get("model") or "")[:80], store.now_iso(), src, json.dumps(refs[1:])))
                for k in good:
                    res[k]["would_close"] -= 1
                    res[k]["auto_closed"] += 1 if k == hit else 0
                res[hit]["closed_now"] += 1

        vfrom = {}  # (eid, source) -> the repeat whose verdict a grouped event used
        tried = set()
        for eid, typ, key, label in items:
            if (typ, key) in tried:
                continue
            tried.add((typ, key))
            if handle(eid, [(typ, key)], label) is not False:
                seen.add((typ, key))
        if with_open:  # every event on the Open events page, any age, closed with the check-offs that page writes
            for e in oe:
                refs = [(x["type"], x["key"]) for x in e.get("acks") or []]
                if not refs or any(r in seen for r in refs):
                    continue
                seen.update(refs)
                handled.update([e["eid"], *(e.get("members") or [])])
                handle(e["eid"], refs, e.get("label") or "", e.get("members") or ())
            # closed earlier and so no longer listed: reopen it when its verdict turned bad, its host is held (guard 3),
            # or (reopen_guard) guard 1/2 would hold it; a preview also counts what guard 1/2 would hold back today
            gone = [lg for (t, k), lg in log.items() if lg["state"] == "closed" and (t, k) not in seen and lg.get("eid")]
            if gone:
                more = [lg["eid"] for lg in gone if lg["eid"] not in notes and lg["eid"] not in cls]
                if more:
                    notes.update(enrich.load(more))
                    cls.update(corr_llm.classes(more))
                pv.update(kb.person_verdicts([lg["eid"] for lg in gone if lg["eid"] not in pv]))
                for lg in gone:
                    vs = _verdicts(lg["eid"], notes, cls, pv)
                    if not vs:
                        continue  # no verdict any more (pruned): leave it closed
                    if any(v in KINDS for v in vs.values()) and not any(v in BAD for v in vs.values()):
                        held = glast.get(eventstore.gkey(lg["eid"]), 0) >= cut and hosts([lg["eid"]]) & sus.keys()
                        if not (held or dry or reopen_guard):
                            continue  # still fine: leave it closed
                    seen.add((lg["type"], lg["key"]))
                    handle(lg["eid"], [(lg["type"], lg["key"]), *_refs_of(lg)], "")
        for eid in other_eids:  # researched events without a check-off list
            if eid in handled:
                continue
            vs = _verdicts(eid, notes, cls)
            if any(v in BAD for v in vs.values()):
                continue
            for k in SOURCES:
                if vs.get(k) in KINDS:
                    res[f"{k}_{vs[k]}"]["no_checklist"] += 1
        G["held_hosts"] = len(sus)
        res["settings"] = s
        res["categories"] = CATS
        if not dry:
            closed = {o: res[o]["closed_now"] for o in (*OPTS, *PERSON)}
            held = {k: G[k] for k in ("low_conf", "protected", "host", "stale") if G[k]}
            with store.tx(c):
                c.execute("INSERT OR REPLACE INTO meta VALUES ('autoclose_last', ?)", (json.dumps(
                    {"at": store.now_iso(), "trigger": trigger, "closed": closed, "reopened": res["reopened_verdict_changed"],
                     "held": held, "expired": G["expired"], "reopened_host": G["reopened_host"], "reopened_guard": G["reopened_guard"],
                     "enabled": sorted(on)}),))
            if trigger != "timer" or any(closed.values()) or res["reopened_verdict_changed"] or G["expired"] or G["reopened_host"]:
                print(f"autoclose ({trigger}): closed {closed}, reopened {res['reopened_verdict_changed']} (verdict changed), "
                      f"{G['reopened_host']} (host hold), {G['reopened_guard']} (guard), expired {G['expired']}, held {held}", file=sys.stderr)
        res["last_run"] = last_run(c)
        return res


def _ts(t):
    import datetime
    return datetime.datetime.fromtimestamp(float(t or 0), datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def person_marked(eid, verdict, user, inputs):
    """Right after a person saves (or a defender approves) a verdict note: Suspicious un-checks the event at once (and
    keeps auto-close off it); Expected / Benign are applied by an auto-close pass in the background."""
    import corr_llm
    if verdict == "suspicious":
        A = store.acks_load()
        keys = list(corr_llm._ack_keys(eid))
        try:
            import eventstore
            for e in eventstore.open_events(limit=10 ** 6)["events"]:
                if eid == e["eid"] or eid in (e.get("members") or []):
                    keys += [(x["type"], x["key"]) for x in e.get("acks") or []]
        except Exception:  # noqa: BLE001
            pass
        c = _c()
        for t, k in dict.fromkeys(keys):
            if k in (A.get(t) or {}) and not str((A[t][k] or {}).get("note") or "").startswith("suppressed:"):
                store.ack_set(t, k, False, c=c)
                with store.tx(c):
                    c.execute("UPDATE autoclose_log SET state='reopened-verdict', verdict=?, at=? WHERE type=? AND key=?",
                              (f"person:suspicious ({user})", store.now_iso(), t, k))
        print(f"autoclose: {user} marked {eid[:80]!r} suspicious - back in the findings", file=sys.stderr)

    def go():
        try:
            inp = inputs()  # server.autoclose_inputs (passed in: this runs inside the dashboard process)
            if inp:
                run(*inp, trigger=f"verdict by {user}")
        except Exception as e:  # noqa: BLE001
            print(f"autoclose after verdict: {type(e).__name__}: {e}", file=sys.stderr)
    threading.Thread(target=go, daemon=True).start()


def reopen_all(user, kind=None):
    """Un-check every item that auto-close closed (optionally only one option, e.g. reviewer_benign); they won't be auto-closed again."""
    with _lock:
        c = _c()
        acks = store.acks_load(c)
        rows = c.execute("SELECT type, key, source, verdict, refs FROM autoclose_log WHERE state='closed'").fetchall()
        n = 0
        for r in rows:
            if kind and f"{r['source'] or 'researcher'}_{r['verdict']}" != kind:
                continue
            for i, (t, k) in enumerate(dict.fromkeys([(r["type"], r["key"]), *_refs_of(r)])):
                a = (acks.get(t) or {}).get(k)
                if a and str(a.get("note") or "").startswith(PREFIXES):
                    store.ack_set(t, k, False, c=c)
                    n += 1 if i == 0 else 0
            with store.tx(c):
                c.execute("UPDATE autoclose_log SET state='reopened', at=? WHERE type=? AND key=?", (store.now_iso(), r["type"], r["key"]))
        print(f"autoclose: {user} reopened {n} auto-closed item(s){' (' + kind + ')' if kind else ''}", file=sys.stderr)
        return n


def reopen_one(typ, key, user):
    """Un-check one auto-closed item (and the keys closed with it); like reopen_all it is not auto-closed again."""
    with _lock:
        c = _c()
        r = c.execute("SELECT type, key, refs FROM autoclose_log WHERE type=? AND key=? AND state='closed'", (typ, key)).fetchone()
        if not r:
            return 0
        acks, n = store.acks_load(c), 0
        for i, (t, k) in enumerate(dict.fromkeys([(r["type"], r["key"]), *_refs_of(r)])):
            a = (acks.get(t) or {}).get(k)
            if a and str(a.get("note") or "").startswith(PREFIXES):
                store.ack_set(t, k, False, c=c)
                n += 1 if i == 0 else 0
        with store.tx(c):
            c.execute("UPDATE autoclose_log SET state='reopened', at=? WHERE type=? AND key=?", (store.now_iso(), typ, key))
        print(f"autoclose: {user} reopened auto-closed {typ}|{key[:80]}", file=sys.stderr)
        return n


def verdict_info(eid="", typ="", key=""):
    """Everything behind one AI verdict badge (loaded on tap): the event reviewer's label for the event (or why it is
    pending / not reviewed) and what auto-close did with it. eid may be empty when only the check-off (typ, key) is known."""
    import corr_llm
    c = _c()
    rows = []
    if typ and key:
        rows = [dict(r) for r in c.execute("SELECT * FROM autoclose_log WHERE type=? AND key=?", (typ, key))]
    eid = eid or (rows[0]["eid"] if rows else "")
    if eid:
        have = {(r["type"], r["key"]) for r in rows}
        rows += [dict(r) for r in c.execute("SELECT * FROM autoclose_log WHERE eid=?", (eid,)) if (r["type"], r["key"]) not in have]
    acks = store.acks_load(c)
    ac = []
    for r in rows:
        a = (acks.get(r["type"]) or {}).get(r["key"]) or {}
        ac.append({"type": r["type"], "key": r["key"], "verdict": r["verdict"], "source": r["source"] or "researcher", "model": r["model"] or "",
                   "at": r["at"], "closed_at": r.get("closed_at"), "state": r["state"], "refs": len(_refs_of(r)),
                   "checked": bool(a), "note": str(a.get("note") or "")[:600] if a else "",
                   "can_reopen": r["state"] == "closed" and bool(a) and str(a.get("note") or "").startswith(PREFIXES)})
    cls = corr_llm.classes([eid], pending=True).get(eid) if eid else None
    ev = {}
    if eid:
        try:
            import eventstore
            ev = eventstore._ev_view([eid]).get(eid) or {}
        except Exception as e:  # noqa: BLE001
            print(f"verdict_info: event: {type(e).__name__}: {e}", file=sys.stderr)
    push = []
    if eid:
        try:  # what the phone-push gate did with alarms about this event (held / pushed / suppressed)
            import pushgate
            push = pushgate.for_event(eid)
        except Exception as e:  # noqa: BLE001
            print(f"verdict_info: push gate: {type(e).__name__}: {e}", file=sys.stderr)
    return {"eid": eid, "event": {k: ev.get(k) for k in ("type", "label", "link", "t0", "t1")}, "class": cls, "autoclose": ac, "push": push}


if __name__ == "__main__":
    # `python /app/autoclose.py run [trigger]` - called by enrich.sh put right after the review job stores its notes
    if sys.argv[1:2] != ["run"]:
        raise SystemExit("usage: autoclose.py run [trigger]")
    import server  # noqa: E402 - sets NETMON_DB to the writable /state DB like the dashboard (no HTTP server is started)
    s = settings()
    if not any(s[o] for o in OPTS):
        print(json.dumps({"autoclose": "off"}))
        raise SystemExit(0)
    inp = server.autoclose_inputs()
    r = run(*inp, trigger=sys.argv[2] if len(sys.argv) > 2 else "review job") if inp else {"error": "no snapshot"}
    print(json.dumps({"autoclose": {k: r.get(k) for k in (*OPTS, "reopened_verdict_changed", "error") if k in r}}))
