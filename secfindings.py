#!/usr/bin/python3
"""Turn sec_scan.sh output into tracked software-security findings ("vulnerabilities") for the netmon software itself.

  secfindings.py sync [scan_dir] [--notify new|all|none] [--context "text"]
      parse -> drop reviewed exceptions (sec_accepted.json) -> store.sec_sync() -> app push alert for new/open findings
  secfindings.py accept-current [scan_dir] "reason"   add every current finding to sec_accepted.json (after human review)
  secfindings.py list                                  show open findings

Findings are fingerprinted without line numbers (rule + file + hash of the offending source line), so they survive
unrelated edits. Open findings appear in the dashboard Fix list / Risk page as category "Software vulnerability"
(dashboard/app/server.py merges them into the issue tracker) and can be checked off like any issue.
"""
import glob, hashlib, json, os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import store  # noqa: E402

SCAN = os.path.expanduser("~/.hermes/cache/scratch/sec")
ACCEPTED = os.path.join(HERE, "sec_accepted.json")
import site_cfg as SITE  # noqa: E402
NM_IP = SITE.get("self_ip")  # the host running netmon + the dashboard: alerts route to users watching it
NM_HOST = SITE.get("self_host") or "netmon-host"
SEV = {"CRITICAL": "high", "HIGH": "high", "MEDIUM": "medium", "LOW": "low", "UNKNOWN": "low", "ERROR": "high",
       "WARNING": "medium", "INFO": "low"}


def L(p, d=None):
    try:
        return json.load(open(p))
    except Exception:
        return d


def _h(s):
    return hashlib.sha256((s or "").strip().encode()).hexdigest()[:10]


def _line(path, n):
    for base in ("", HERE):
        p = os.path.join(base, path) if base else path
        try:
            return open(p, errors="replace").read().splitlines()[n - 1]
        except Exception:
            continue
    return ""


def parse(d=SCAN):
    F = []

    def add(key, tool, sev, title, location="", fix="", detail=""):
        F.append({"key": "sec|" + key, "tool": tool, "severity": sev, "title": title[:200], "location": location[:200],
                  "fix": fix[:400], "detail": detail[:400]})

    for x in L(f"{d}/trivy-image.json", {}).get("Results", []) if L(f"{d}/trivy-image.json") else []:
        for v in x.get("Vulnerabilities") or []:
            add(f"trivy|{v['PkgName']}|{v['VulnerabilityID']}", "trivy", SEV.get(v["Severity"], "low"),
                f"{v['PkgName']} {v['InstalledVersion']}: {v['VulnerabilityID']} {v.get('Title') or ''}",
                f"image netmon-dashboard ({x['Target'][:60]})",
                f"Upgrade to {v['FixedVersion']} (rebuild the image)" if v.get("FixedVersion") else "No fix released yet - monitor",
                v.get("PrimaryURL") or "")
        for s in x.get("Secrets") or []:
            add(f"trivy-secret|{x['Target']}|{s['RuleID']}", "trivy", "high", f"Secret baked into image: {s['Title']}", x["Target"],
                "Remove it from the image; mount it at runtime instead, and rotate it.")
    for x in (L(f"{d}/trivy-config.json", {}) or {}).get("Results", []):
        for m in x.get("Misconfigurations") or []:
            if m["Status"] == "FAIL":
                add(f"trivy-cfg|{x['Target']}|{m['ID']}", "trivy", SEV.get(m["Severity"], "low"), f"{m['ID']} {m['Title']}", x["Target"],
                    m.get("Resolution", ""))
    for dep in (L(f"{d}/pipaudit.json", {}) or {}).get("dependencies", []):
        for v in dep.get("vulns") or []:
            add(f"pipaudit|{dep['name']}|{v['id']}", "pip-audit", "medium", f"{dep['name']} {dep['version']}: {v['id']}",
                "dashboard Python dependencies", f"Upgrade to {', '.join(v.get('fix_versions') or []) or 'a fixed version'}",
                (v.get("description") or "")[:300])
    for r in (L(f"{d}/semgrep.json", {}) or {}).get("results", []):
        rule = r["check_id"].split(".")[-1]
        add(f"semgrep|{rule}|{r['path']}|{_h(r['extra'].get('lines'))}", "semgrep", SEV.get(r["extra"]["severity"], "low"),
            f"{rule}: {r['extra']['message'][:120]}", f"{r['path']}:{r['start']['line']}", "Review the flagged code; fix or add to sec_accepted.json with a reason.")
    for r in L(f"{d}/ruff.json", []) or []:
        if not (r["code"].startswith("S") or r["code"] in ("F821", "F811", "B023", "E999")):
            continue  # style rules are not vulnerabilities
        f = r["filename"].replace("/src/", "")
        add(f"ruff|{r['code']}|{f}|{_h(_line(f, r['location']['row']))}", "ruff", "medium" if r["code"] in ("F821", "E999") else "low",
            f"{r['code']}: {r['message'][:140]}", f"{f}:{r['location']['row']}", "Fix, or accept with a reason in sec_accepted.json.")
    for fobj in L(f"{d}/eslint.json", []) or []:
        f = "dashboard/app/static/" + os.path.basename(fobj["filePath"])
        for m in fobj["messages"]:
            if not m.get("ruleId"):
                continue
            add(f"eslint|{m['ruleId']}|{f}|{_h(_line(f, m['line']))}", "eslint", "medium" if "unsanitized" in m["ruleId"] else "low",
                f"{m['ruleId']}: possible DOM XSS sink", f"{f}:{m['line']}", "Make sure every interpolated value goes through esc()/ipLink/hostLink.")
    for x in L(f"{d}/hadolint.json", []) or []:
        add(f"hadolint|{x['code']}", "hadolint", "low", f"{x['code']}: {x['message']}", "dashboard/Dockerfile")
    for p in glob.glob(f"{d}/gl_*.json"):
        for x in L(p, []) or []:
            kname = re.split(r"[:=\s]", (x.get("Match") or "").strip(), 1)[0][:60]  # key name, stable when lines move
            add(f"gitleaks|{x['File'].replace('/scan/', '')}|{x['RuleID']}|{kname or _h(x.get('Match'))}", "gitleaks", "high",
                f"Possible secret ({x['RuleID']}) in {x['File'].replace('/scan/', '')}", f"{x['File'].replace('/scan/', '')}:{x['StartLine']}",
                "Move the secret out of the file (env/600-permission store) and rotate it.")
    z = L(f"{d}/zap/zap.json", {}) or {}
    for s in z.get("site", []):
        for a in s["alerts"]:
            if a["riskcode"] in ("0",):
                continue
            add(f"zap|{a['pluginid']}|{a['name']}", "zap", {"3": "high", "2": "medium", "1": "low"}.get(a["riskcode"], "low"),
                f"Dashboard: {a['name']}", "live dashboard https://127.0.0.1:8443", (a.get("solution") or "").replace("<p>", "").replace("</p>", " ")[:300])
    seen, out = set(), []
    for f in F:
        if f["key"] not in seen:
            seen.add(f["key"])
            out.append(f)
    return out


def accepted():
    return (L(ACCEPTED, {}) or {}).get("accepted", {})


def sync(d=SCAN, notify="new", context=""):
    acc = accepted()
    allf = parse(d)
    open_ = [f for f in allf if f["key"] not in acc]
    new, still, fixed = store.sec_sync(open_)
    by = {f["key"]: f for f in open_}
    pick = {"new": new, "all": new + still, "none": []}[notify]
    if pick:
        rows = [by[k] for k in pick]
        hi = sum(1 for r in rows if r["severity"] == "high")
        lines = "; ".join(f"[{r['severity']}] {r['title'][:90]}" for r in rows[:5]) + (f"; ...and {len(rows) - 5} more" if len(rows) > 5 else "")
        text = (f"Software security scan{(' (' + context + ')') if context else ''}: {len(rows)} "
                f"{'new ' if notify == 'new' else ''}issue(s) in netmon/dashboard on {NM_HOST} ({NM_IP}) - {lines}. See Fix list > Software vulnerability.")
        store.alerts_add([(f"secscan|{','.join(sorted(pick))[:200]}", text, "investigate" if hi else "urgent", ["ip:" + NM_IP, "host:" + NM_HOST])],
                         source="secscan")
        store.sec_mark_notified(pick)
    return {"total_raw": len(allf), "accepted": len(allf) - len(open_), "open": len(open_), "new": len(new), "fixed": len(fixed),
            "notified": len(pick), "high": sum(1 for f in open_ if f["severity"] == "high"),
            "new_high": sum(1 for k in new if by[k]["severity"] == "high")}


def accept_current(d=SCAN, reason=""):
    data = L(ACCEPTED, {}) or {}
    acc = data.setdefault("accepted", {})
    today = store.now_iso()[:10]
    n = 0
    for f in parse(d):
        if f["key"] not in acc:
            acc[f["key"]] = {"reason": reason, "date": today, "title": f["title"][:120]}
            n += 1
    data["_doc"] = ("Reviewed exceptions for sec_scan findings (fingerprint -> reason). Remove an entry to re-open it. "
                    "Only add after a human/agent review - never to silence an unreviewed finding.")
    json.dump(data, open(ACCEPTED, "w"), indent=1, sort_keys=True)
    return n


if __name__ == "__main__":
    a = sys.argv[1:]
    cmd = a[0] if a else "list"
    if cmd == "sync":
        d = a[1] if len(a) > 1 and not a[1].startswith("--") else SCAN
        notify = a[a.index("--notify") + 1] if "--notify" in a else "new"
        ctx = a[a.index("--context") + 1] if "--context" in a else ""
        print(json.dumps(sync(d, notify, ctx)))
    elif cmd == "accept-current":
        d = a[1] if len(a) > 2 else SCAN
        print("accepted", accept_current(d, a[-1]))
    elif cmd == "list":
        for f in store.sec_list("open"):
            print(f"[{f['severity']}] {f['title']}  ({f['location']})  key={f['key']}")
