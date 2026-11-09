#!/usr/bin/python3
"""Vulnerability counts over time (Fix list and Devices > Kubernetes line charts).

One row per (day, scope, metric) in table vuln_hist (netmon.db). The scheduler records today's numbers once a day
(job "vulnhist", 06:00 UTC, after the 04:00 image scan); a re-run the same day overwrites that day's rows.

Scopes and metrics:
  fixlist             open Fix list items (dashboard issue tracker incl. netmon software-scan findings):
                      total, critical, high, medium, low, info
  k8s_cis|<cluster>   CIS Kubernetes benchmark (kube_cis.latest): fail, warn, pass, manual, accepted
  k8s_cve|<cluster>   distinct CVE ids in the running container images (kube_images Trivy scan):
                      total, critical, high, medium, low, fixable (a fixed package version exists), images

Days without a daily record are backfilled once (src 'backfill') from the stored review runs (fix_run / fix_item):
the Fix list as it stood after the day's last full run (fixlist.track over the runs up to it; ~0.1-10 s a day) plus
software-scan findings open that day, and CIS failures from that run's k8s-cis|<cluster>|<id> items. Image CVE counts cannot be backfilled (only the last scan
is kept), so that line starts on the first daily record.

CLI: vulnhist.py [record] | backfill | show
"""
import datetime as dt
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import store  # noqa: E402

DDL = """CREATE TABLE IF NOT EXISTS vuln_hist (
  day TEXT NOT NULL, scope TEXT NOT NULL, metric TEXT NOT NULL, value INTEGER NOT NULL,
  src TEXT NOT NULL DEFAULT 'daily', at TEXT, PRIMARY KEY (day, scope, metric)) WITHOUT ROWID"""
SEVS = ("critical", "high", "medium", "low", "info")
CVE_SEVS = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
CIS_KEYS = ("fail", "warn", "pass", "manual", "accepted")


def init(c):
    c.execute(DDL)
    return c


def conn():
    return store.tl_conn("vulnhist", init)


def _put(c, day, scope, metrics, src, replace=True):
    at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    verb = "INSERT OR REPLACE" if replace else "INSERT OR IGNORE"
    c.executemany(f"{verb} INTO vuln_hist(day, scope, metric, value, src, at) VALUES (?,?,?,?,?,?)",  # noqa: S608
                  [(day, scope, m, int(v), src, at) for m, v in metrics.items()])


# ------------------------------------------------------------------ today's numbers
def fixlist_counts():
    """Open Fix list items by severity, exactly as the dashboard's Fix list page counts them."""
    app = os.path.join(HERE, "dashboard", "app")
    if app not in sys.path:
        sys.path.insert(0, app)
    import integrations
    # server.py defaults to the container's paths (/netmon, /state) and points integrations at /state: give it the host's
    os.environ.setdefault("NETMON_DIR", HERE)
    os.environ.setdefault("STATE_DIR", os.path.dirname(store.db_path()))
    os.environ.setdefault("NETMON_INTEGRATIONS", integrations.path())
    import server  # the dashboard's issue_tracker (fixlist SQL + software-scan findings + segmentation suppress)
    op = server.issue_tracker().get("open") or []
    out = {s: sum(1 for i in op if (i.get("severity") or "").lower() == s) for s in SEVS}
    out["total"] = len(op)
    return out


def cis_counts():
    """{cluster: {fail, warn, pass, manual, accepted}} of the newest saved CIS run per configured cluster."""
    import integrations
    import kube_cis
    out = {}
    for cl in integrations.kube_clusters():
        if not cl.get("usable"):
            continue
        d = kube_cis.latest(cl["name"])
        if d.get("results"):
            sm = d.get("summary") or {}
            out[cl["name"]] = {k: sm.get(k, 0) for k in CIS_KEYS}
    return out


def cve_counts(doc=None):
    """{cluster: {total, critical..low, fixable, images}}: distinct CVE ids in the images each cluster runs."""
    import kube_images
    d = doc if doc is not None else kube_images.latest(with_vulns=True)
    per = {}
    for im in d.get("images") or []:
        vulns = (im.get("current") or {}).get("vulns") or []
        for cl in im.get("clusters") or []:
            p = per.setdefault(cl, {"ids": {}, "fix": set(), "images": 0})
            p["images"] += 1
            for v in vulns:
                sev = v.get("severity")
                if sev not in CVE_SEVS:
                    continue
                cur = p["ids"].get(v["id"])
                if cur is None or CVE_SEVS.index(sev) < CVE_SEVS.index(cur):
                    p["ids"][v["id"]] = sev
                if v.get("fixed"):
                    p["fix"].add(v["id"])
    out = {}
    for cl, p in per.items():
        m = {s.lower(): sum(1 for x in p["ids"].values() if x == s) for s in CVE_SEVS}
        m.update(total=len(p["ids"]), fixable=len(p["fix"]), images=p["images"])
        out[cl] = m
    return out


def record(day=None, c=None):
    """Store today's numbers (replaces today's rows). Each part is independent: one failing does not stop the others."""
    c = c or conn()
    day = day or dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d")
    done, errs = {}, {}
    for name, fn in (("k8s_cis", cis_counts), ("k8s_cve", cve_counts), ("fixlist", fixlist_counts)):
        try:
            got = fn()
        except Exception as e:  # noqa: BLE001
            errs[name] = f"{type(e).__name__}: {str(e)[:200]}"
            continue
        with store.tx(c):
            if name == "fixlist":
                _put(c, day, "fixlist", got, "daily")
            else:
                c.execute("DELETE FROM vuln_hist WHERE day=? AND scope LIKE ?", (day, name + "|%"))
                for cl, m in got.items():
                    _put(c, day, f"{name}|{cl}", m, "daily")
        done[name] = got
    return {"day": day, "recorded": done, "errors": errs}


# ------------------------------------------------------------------ backfill from stored review runs
def _day_runs(c):
    """{day: sid} = the last full review run of each day (else the day's last run)."""
    best = {}
    for sid, gen, full in c.execute("SELECT sid, generated, full FROM fix_run WHERE generated IS NOT NULL ORDER BY generated"):
        d = gen[:10]
        if d not in best or full or not best[d][1]:
            best[d] = (sid, full)
    return {d: v[0] for d, v in best.items()}


def _fixlist_as_of(sid):
    """Open Fix list items by severity as the Fix list stood right after review run sid: the dashboard's own SQL
    (fixlist.track) over temp views that hide every later run. Own connection, so the views never leak."""
    import sqlite3
    app = os.path.join(HERE, "dashboard", "app")
    if app not in sys.path:
        sys.path.insert(0, app)
    import fixlist
    c = sqlite3.connect(store.db_path(), isolation_level=None, timeout=60)
    try:
        for t in fixlist.RUN_TABLES:
            c.execute(f"CREATE TEMP VIEW {t} AS SELECT * FROM main.{t} WHERE sid <= '{sid.replace(chr(39), '')}'")  # noqa: S608
        op = fixlist.track(c).get("open") or []
    finally:
        c.close()
    m = dict.fromkeys(SEVS, 0)
    for i in op:
        sev = (i.get("severity") or "").lower()
        if sev in m:
            m[sev] += 1
    return m


def backfill(c=None):
    """Fill days that have no rows yet (never overwrites a daily record). Returns the number of days filled per scope."""
    c = c or conn()
    try:
        runs = _day_runs(c)
    except Exception:  # noqa: BLE001 - no fix_run table yet
        return {}
    have = {}
    for d, s in c.execute("SELECT DISTINCT day, scope FROM vuln_hist"):
        have.setdefault(s.split("|")[0], set()).add(d)
    try:
        sec = [tuple(r) for r in c.execute("SELECT severity, first_seen, fixed_at, status FROM sec_findings")]
    except Exception:  # noqa: BLE001
        sec = []
    today = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d")
    n = {"fixlist": 0, "k8s_cis": 0}
    with store.tx(c):
        for day, sid in sorted(runs.items()):
            if day >= today:
                continue
            if day not in have.get("fixlist", set()):
                m = _fixlist_as_of(sid)
                end = day + "T23:59:59"
                for sev, first, fixed, _status in sec:  # netmon software scan findings open at the end of that day
                    if first and first[:19] <= end and (not fixed or fixed[:19] > end) and (sev or "").lower() in m:
                        m[sev.lower()] += 1
                m["total"] = sum(m[s] for s in SEVS)
                _put(c, day, "fixlist", m, "backfill", replace=False)
                n["fixlist"] += 1
            if day not in have.get("k8s_cis", set()):
                per = {}
                for (key,) in c.execute("SELECT key FROM fix_item WHERE sid=? AND key LIKE 'k8s-cis|%'", (sid,)):
                    parts = key.split("|")
                    if len(parts) == 3 and parts[2] != "error":
                        per[parts[1]] = per.get(parts[1], 0) + 1
                for cl, k in per.items():
                    _put(c, day, f"k8s_cis|{cl}", {"fail": k}, "backfill", replace=False)
                if per:
                    n["k8s_cis"] += 1
    return n


# ------------------------------------------------------------------ reading (dashboard /api/vulnhist)
def series(kind, cluster="", days=365, c=None):
    """kind 'fixlist' -> {days, src, series: {metric: [..]}}; kind 'k8s' -> {days, src, cis: {...}, cve: {...}}
    summed over clusters (or one cluster). Missing values are null so a gap shows as a gap."""
    c = c or conn()
    since = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=int(days))).strftime("%Y-%m-%d")
    if kind == "fixlist":
        rows = c.execute("SELECT day, scope, metric, value, src FROM vuln_hist WHERE scope='fixlist' AND day>=? ORDER BY day", (since,)).fetchall()
    else:
        pats = [f"k8s_cis|{cluster}", f"k8s_cve|{cluster}"] if cluster else ["k8s_cis|%", "k8s_cve|%"]
        rows = c.execute("SELECT day, scope, metric, value, src FROM vuln_hist WHERE (scope LIKE ? OR scope LIKE ?) AND day>=? ORDER BY day",
                         (*pats, since)).fetchall()
    days_l = sorted({r[0] for r in rows})
    idx = {d: i for i, d in enumerate(days_l)}
    src = {}
    groups = {}
    clusters = set()
    for day, scope, metric, value, s in rows:
        g = "series" if kind == "fixlist" else scope.split("|")[0].split("_")[1]  # cis | cve
        if "|" in scope:
            clusters.add(scope.split("|", 1)[1])
        arr = groups.setdefault(g, {}).setdefault(metric, [None] * len(days_l))
        arr[idx[day]] = (arr[idx[day]] or 0) + value
        if s == "daily" or day not in src:
            src[day] = s
    out = {"days": days_l, "src": [src.get(d, "daily") for d in days_l], "clusters": sorted(clusters)}
    if kind == "fixlist":
        out["series"] = groups.get("series", {})
    else:
        out["cis"], out["cve"] = groups.get("cis", {}), groups.get("cve", {})
    return out


def main(argv):
    import json
    cmd = argv[1] if len(argv) > 1 else "record"
    if cmd == "record":
        r = record()
        r["backfill"] = backfill()
        print(json.dumps(r, indent=1))
        return 1 if r["errors"] and not r["recorded"] else 0
    if cmd == "backfill":
        print(json.dumps(backfill()))
    elif cmd == "show":
        print(json.dumps({"fixlist": series("fixlist", days=30), "k8s": series("k8s", days=30)}, indent=1))
    else:
        print(__doc__)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
