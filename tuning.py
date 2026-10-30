"""Auto-tune recommendations for the detection thresholds (policy: scan_thresholds, beacon, upload_spike, spike_thresholds).

recommend() NEVER writes settings. It replays the retained history (daily per-device history + the daily snapshots) against
candidate thresholds and proposes values that keep each detection near a findings budget. The dashboard shows the proposals
(Settings > Network policy > Auto-tune) and the user accepts them one by one; apply() then writes only what was accepted.
Conservative by design: a detection that is already quiet is left alone (no "make it more sensitive" proposals), severity and
min_days are never changed.
"""
import itertools
import math
import os
import statistics

import store

MB = 1024 * 1024
WINDOW_DAYS = 14
BUDGET = {"upload_spike": 0.5, "spike": 1.0, "beacon": 2.0, "scan": 0.5}  # findings per day the proposal aims at
DEFAULT_SCAN = {"hosts": 20, "ports": 40}

# (rec id, history field, policy spike name or None for upload, unit divisor, label)
SERIES = (
    ("upload_spike", "sent", None, MB, "Upload spike"),
    ("fan_out", "ext_peers", "fan_out", 1, "External fan-out"),
    ("failed_conns", "rejected", "failed_conns", 1, "Failed connections"),
    ("dns_volume", "dns_q", "dns_volume", 1, "DNS query volume"),
)


def _med(v):
    return statistics.median(v) if v else 0.0


def _mad(v):
    m = _med(v)
    return _med([abs(x - m) for x in v])


def _flag(today, hist, floor, mult, madf, min_days):
    if today < floor or len(hist) < min_days:
        return False
    m, d = _med(hist), _mad(hist)
    return today > max(mult * m, m + madf * d, floor)


def _count(series, floor, mult, madf, min_days):
    """Flagged (device, day) events replaying every device's history day by day."""
    n = 0
    for vals in series:
        for i in range(1, len(vals)):
            if _flag(vals[i], vals[:i], floor, mult, madf, int(min_days)):
                n += 1
    return n


def _nice(x):
    """Round a threshold to a human-friendly number."""
    if x <= 0:
        return 0
    p = 10 ** max(0, int(math.floor(math.log10(x))) - 1)
    return int(round(x / p) * p)


def _spike_rec(rid, label, series, days, cur, budget):
    ev_now = _count(series, cur["min"], cur["times_normal"], cur["mad_factor"], cur["min_days"])
    rate_now = ev_now / days
    base = {"id": rid, "title": label, "current": {k: cur[k] for k in ("min", "times_normal", "mad_factor")}}
    if cur.get("severity") == "off":
        return {**base, "status": "off", "why": "This detection is switched off (severity off); nothing to tune."}
    if rate_now <= budget:
        return {**base, "status": "ok", "events_now": ev_now, "why": f"Would have raised {ev_now} finding(s) in {days} days ({rate_now:.1f}/day), within the {budget:g}/day target. No change."}
    best = None
    for fl, mu, md in itertools.product([cur["min"] * f for f in (1, 1.5, 2, 3, 5, 10)], (2, 3, 4, 5, 8), (3, 6, 9, 12, 20)):
        fl = _nice(fl)
        if fl < cur["min"] or mu < cur["times_normal"] or md < cur["mad_factor"]:
            continue  # only ever make the detection LESS noisy
        n = _count(series, fl, mu, md, cur["min_days"])
        if n / days > budget:
            continue
        dist = math.log(fl / max(cur["min"], 1)) + math.log(mu / cur["times_normal"]) + math.log(md / cur["mad_factor"])
        key = (-n, dist)  # keep as many findings as the budget allows, with the smallest change
        if best is None or key < best[0]:
            best = (key, fl, mu, md, n)
    if best is None:
        return {**base, "status": "none", "events_now": ev_now, "why": f"Raised {ev_now} findings in {days} days but no safe adjustment gets under the target; review the noisy devices instead."}
    _, fl, mu, md, n = best
    new = {"min": fl, "times_normal": mu, "mad_factor": md}
    ch = {k: v for k, v in new.items() if v != cur[k]}
    return {**base, "status": "change", "changes": ch, "events_now": ev_now, "events_after": n,
            "why": f"Would have raised {ev_now} findings in the last {days} days ({rate_now:.1f}/day); with these values {n} ({n / days:.1f}/day). "
                   f"Only the larger movements (above {fl:g} and {mu:g}x the device's normal) stay flagged."}


def _daily_snaps():
    c = store._dc()
    names = [r[0] for r in c.execute("SELECT name FROM docs WHERE name LIKE 'data/%T0500Z' ORDER BY name DESC LIMIT ?", (WINDOW_DAYS,))]
    out = []
    for n in names:
        try:
            d = store.jload(os.path.join(os.path.dirname(os.path.abspath(__file__)), n + ".json"))
            if d:
                out.append(d)
        except Exception:  # noqa: BLE001
            pass
    return out


def _scan_rec(snaps, cur):
    base = {"id": "scan_thresholds", "title": "Scan thresholds", "current": cur}
    rows = {}
    for s in snaps:
        for x in (s.get("internal") or {}).get("scans", []):
            rows.setdefault(x["src"], []).append((x["hosts"], x["ports"]))
    days = max(len(snaps), 1)
    total = sum(len(v) for v in rows.values())
    if not total:
        return {**base, "status": "ok", "events_now": 0, "why": f"No internal scanner was flagged in {days} daily snapshots. No change (lowering it would be a guess without below-threshold data)."}
    chronic = {k: v for k, v in rows.items() if len(v) >= max(3, days // 2)}
    if total / days <= BUDGET["scan"] or not chronic:
        return {**base, "status": "ok", "events_now": total, "why": f"{total} scan finding(s) from {len(rows)} source(s) in {days} days, none chronic. No change."}
    # chronic noisy sources: set the bar just above their steady level; a real sweep (much larger) still fires
    hosts = _nice(max(max(h for h, _ in v) for v in chronic.values()) * 1.25 + 1)
    ports = _nice(max(max(p for _, p in v) for v in chronic.values()) * 1.25 + 1)
    new = {"hosts": max(hosts, cur["hosts"]), "ports": max(ports, cur["ports"])}
    left = sum(1 for v in rows.values() for h, p in v if h >= new["hosts"] or p >= new["ports"])
    return {**base, "status": "change", "changes": {k: v for k, v in new.items() if v != cur[k]}, "events_now": total, "events_after": left,
            "why": f"{len(chronic)} source(s) are flagged on at least half the days ({', '.join(sorted(chronic)[:4])}) at a steady level, which looks like normal chatter. "
                   f"Raising the bar above their level leaves {left} of {total} findings; a broader sweep would still fire."}


def _beacon_rec(snaps, cur, benign):
    base = {"id": "beacon", "title": "Beacon detection", "current": {k: cur[k] for k in ("min_score", "unlabelled_min_score", "ignore_ports")}}
    bdom = set(benign.get("beacon_domains") or [])
    ign = set(cur["ignore_ports"])
    pairs = {}  # (src,dst,port) -> {"days": n, "score": max, "dom": str}
    for s in snaps:
        for c in (s.get("beacons") or {}).get("candidates", []):
            if (c.get("domain") or "") in bdom or c["port"] == 123 or c["port"] in ign:
                continue
            p = pairs.setdefault((c["src"], c["dst"], c["port"]), {"days": 0, "score": 0.0, "dom": c.get("domain") or "", "port": c["port"]})
            p["days"] += 1
            p["score"] = max(p["score"], c["score"])
    days = max(len(snaps), 1)
    n_day = sum(p["days"] for p in pairs.values()) / days
    if n_day <= BUDGET["beacon"]:
        return {**base, "status": "ok", "events_now": round(n_day * days), "why": f"About {n_day:.1f} beacon candidates a day pass the benign filters, within the {BUDGET['beacon']:g}/day target. No change."}
    changes, notes = {}, []
    # 1) ports where only chronic, unlabelled DNS-style pairs show up -> ignore the port
    byport = {}
    for k, p in pairs.items():
        byport.setdefault(p["port"], []).append(p)
    for port, ps in sorted(byport.items()):
        if port in (53, 853) and len(ps) >= 3 and all(not x["dom"] and x["days"] >= max(3, days // 2) for x in ps):
            changes["ignore_ports"] = sorted(ign | {port})
            notes.append(f"port {port}: {len(ps)} resolver-style pairs seen on most days with no DNS name (regular lookups to a resolver). Beaconing over this port will no longer be reported.")
    left = {k: p for k, p in pairs.items() if p["port"] not in changes.get("ignore_ports", [])}
    # 2) raise min_score until under budget
    ms = cur["min_score"]
    for cand in (0.75, 0.8, 0.85, 0.9, 0.95):
        if cand < cur["min_score"]:
            continue
        keep = sum(p["days"] for p in left.values() if p["score"] >= cand)
        ms = cand
        if keep / days <= BUDGET["beacon"]:
            break
    if ms > cur["min_score"]:
        changes["min_score"] = ms
        notes.append(f"min_score {cur['min_score']:g} -> {ms:g}: borderline-regular pairs drop out.")
    after = sum(p["days"] for p in left.values() if p["score"] >= ms) / days
    if not changes:
        return {**base, "status": "none", "events_now": round(n_day * days), "why": f"About {n_day:.1f} beacon candidates a day but no safe threshold change removes the noise; label the destinations (add to known benign) instead."}
    if "min_score" in changes and cur["unlabelled_min_score"] < ms:
        changes["unlabelled_min_score"] = ms
    return {**base, "status": "change", "changes": changes, "events_now": round(n_day * days), "events_after": round(after * days),
            "why": f"About {n_day:.1f} beacon candidates a day pass the benign filters; after the change about {after:.1f}/day. " + " ".join(notes)}


def recommend():
    import extras
    pol = store.cfg_load("policy")
    benign = store.cfg_load("known_benign")
    hist = store.history_load()[-(WINDOW_DAYS + 1):]
    days = max(len(hist) - 1, 1)
    recs = []
    spk = extras.spike_cfg(pol=pol)
    for rid, field, name, div, label in SERIES:
        series = []
        for dev in {k for h in hist for k in h.get("devices", {})}:
            v = [(h["devices"][dev].get(field) or 0) / div for h in hist if dev in h.get("devices", {})]
            if len(v) >= 2:
                series.append(v)
        if name is None:
            u = extras.upload_cfg()
            cur = {"min": u["min_mb"], "times_normal": u["times_normal"], "mad_factor": u["mad_factor"], "min_days": u["min_days"], "severity": u["severity"]}
            r = _spike_rec(rid, label, series, days, cur, BUDGET["upload_spike"])
            r["unit"] = "MB"
            sec, key = "upload_spike", None
            if "changes" in r:
                r["changes"] = {({"min": "min_mb"}.get(k, k)): v for k, v in r["changes"].items()}
            r["current"] = {({"min": "min_mb"}.get(k, k)): v for k, v in r["current"].items()}
            r["target"] = {"section": "upload_spike"}
        else:
            r = _spike_rec(rid, label, series, days, spk[name], BUDGET["spike"])
            r["target"] = {"section": "spike_thresholds", "name": name}
        recs.append(r)
    snaps = _daily_snaps()
    sc = {**DEFAULT_SCAN, **(pol.get("scan_thresholds") or {})}
    r = _scan_rec(snaps, sc)
    r["target"] = {"section": "scan_thresholds"}
    recs.append(r)
    r = _beacon_rec(snaps, extras.beacon_cfg(pol), benign)
    r["target"] = {"section": "beacon"}
    recs.append(r)
    return {"window_days": days, "snapshots": len(snaps), "budget": BUDGET, "recommendations": recs,
            "note": "Recommendations only. Nothing is changed until you accept them."}


def apply(accepted):
    """accepted = [{"id": rec id, "changes": {...}}]. Only values that the CURRENT recommendation still proposes are written
    (so a stale or tampered request cannot set anything else). Returns (applied ids, policy dict to validate+save)."""
    cur = {r["id"]: r for r in recommend()["recommendations"] if r.get("status") == "change"}
    pol = store.cfg_load("policy")
    done = []
    for a in accepted or []:
        r = cur.get(a.get("id"))
        if not r:
            continue
        t = r["target"]
        sec = pol.setdefault(t["section"], {})
        if "name" in t:
            sec = sec.setdefault(t["name"], {})
        for k, v in r["changes"].items():
            sec[k] = v
        done.append(r["id"])
    return done, pol
