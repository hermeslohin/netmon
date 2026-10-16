#!/bin/bash
# netmon security scan (read-only): Ruff/Bandit, pip-audit, Semgrep, ESLint no-unsanitized, Trivy, Hadolint, Gitleaks, ZAP baseline.
# Usage: netmon/sec_scan.sh [outdir]   - results as JSON in outdir (default ~/.hermes/cache/scratch/sec), summary on stdout.
# Do NOT add brute-force/login tests here: every request arrives via the Cloudflare tunnel as 127.0.0.1, so 8 failed
# logins lock the dashboard for everyone for 5 minutes.
set -u
NM=$HOME/.hermes/netmon; H=$HOME/.hermes
OUT=${1:-$H/cache/scratch/sec}; mkdir -p "$OUT/zap" "$OUT/es"; chmod 777 "$OUT/zap"; cd "$OUT"
export PATH=$H/tools/node-26.7.0-linux-arm64/bin:$PATH
EX="data,intel,baseline,__pycache__,state"

echo "== python (ruff S/B/F, bandit, pip-audit of the dashboard image deps)"
docker run --rm -v "$NM":/src:ro -v "$OUT":/out python:3.12-alpine sh -c '
  pip install -q ruff bandit pip-audit "pywebpush==2.*" >/dev/null 2>&1; cd /src
  ruff check --no-cache --select S,B,E9,F --exclude "*.bak*,__pycache__,data,intel,baseline" --output-format json . > /out/ruff.json
  bandit -q -r . -x ./data,./intel,./baseline,./__pycache__ -f json -o /out/bandit.json
  pip install -q --upgrade pip >/dev/null 2>&1   # audit the dashboard deps, not the scanner container own (old) pip
  pip-audit -f json -o /out/pipaudit.json 2>/dev/null' ; true

echo "== semgrep"
docker run --rm -v "$NM":/src:ro -v "$OUT":/out -w /src semgrep/semgrep semgrep scan --config p/python --config p/javascript \
  --config p/xss --config p/secrets --config p/dockerfile --exclude data --exclude intel --exclude baseline --exclude '*.bak*' \
  --exclude chart.umd.min.js --exclude state --json -o /out/semgrep.json --metrics=off -q . ; true

echo "== eslint no-unsanitized + security"
( cd es; [ -d node_modules/eslint-plugin-no-unsanitized ] || { npm init -y >/dev/null; npm i -s eslint@9 eslint-plugin-no-unsanitized eslint-plugin-security globals >/dev/null 2>&1; }
  cat > eslint.config.mjs <<'EOF'
import nounsan from "eslint-plugin-no-unsanitized"; import security from "eslint-plugin-security"; import globals from "globals";
export default [{ files: ["**/*.js"], languageOptions: { ecmaVersion: 2024, sourceType: "script", globals: { ...globals.browser, Chart: "readonly" } },
  plugins: { "no-unsanitized": nounsan, security },
  rules: { "no-unsanitized/method": "error", "no-unsanitized/property": "error",
    ...Object.fromEntries(Object.keys(security.rules).map((r) => ["security/" + r, "warn"])), "security/detect-object-injection": "off" } }];
EOF
  rm -rf src; mkdir src; cp "$NM"/dashboard/app/static/*.js src/; rm -f src/chart.umd.min.js
  npx eslint -c eslint.config.mjs --no-config-lookup -f json src > ../eslint.json ) ; true

echo "== trivy image + config, hadolint"
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "$OUT":/out -v trivycache:/root/.cache aquasec/trivy:latest \
  image -q --scanners vuln,secret,misconfig --format json -o /out/trivy-image.json netmon-dashboard:latest
docker run --rm -v "$NM"/dashboard:/src:ro -v "$OUT":/out -v trivycache:/root/.cache aquasec/trivy:latest config -q --format json -o /out/trivy-config.json /src
docker run --rm -i hadolint/hadolint:latest-debian hadolint -f json - < "$NM"/dashboard/Dockerfile > hadolint.json ; true

echo "== gitleaks (netmon, skills, memories, scripts, cron, config)"
for d in netmon skills memories scripts cron/jobs.json config.yaml; do [ -e "$H/$d" ] || continue
  docker run --rm -v "$H/$d":/scan/$d:ro -v "$OUT":/out zricethezav/gitleaks:latest dir /scan/$d --no-banner -f json \
    -r /out/gl_$(echo $d | tr / _).json --redact >/dev/null 2>&1; done

echo "== ZAP baseline (passive, unauthenticated) against the live dashboard"
docker run --rm --network host -v "$OUT"/zap:/zap/wrk:rw ghcr.io/zaproxy/zaproxy:stable zap-baseline.py \
  -t https://127.0.0.1:8443/login -m 2 -J zap.json -I >/dev/null 2>&1

/usr/bin/python3 - <<'EOF'
import json, glob, collections
def L(p, d=None):
    try: return json.load(open(p))
    except Exception: return d
r = L("ruff.json", []); print("ruff:", len(r), dict(collections.Counter(x["code"] for x in r).most_common(12)))
b = (L("bandit.json", {}) or {}).get("results", []); print("bandit:", len(b), dict(collections.Counter(f"{x['test_id']}/{x['issue_severity']}" for x in b)))
p = L("pipaudit.json", {}) or {}; print("pip-audit:", [(d["name"], d["version"], len(d["vulns"])) for d in p.get("dependencies", []) if d.get("vulns")])
s = (L("semgrep.json", {}) or {}).get("results", []); print("semgrep:", len(s), dict(collections.Counter(x["check_id"].split(".")[-1] for x in s)))
e = L("eslint.json", []) or []; print("eslint:", dict(collections.Counter(m["ruleId"] for f in e for m in f["messages"])))
t = L("trivy-image.json", {}) or {}; print("trivy image:", dict(collections.Counter(v["Severity"] for r in t.get("Results", []) for v in (r.get("Vulnerabilities") or []))))
c = L("trivy-config.json", {}) or {}; print("trivy config fails:", [m["ID"] for r in c.get("Results", []) for m in (r.get("Misconfigurations") or []) if m["Status"] == "FAIL"])
print("hadolint:", [x["code"] for x in L("hadolint.json", []) or []])
print("gitleaks:", {f[3:-5]: len(L(f, []) or []) for f in sorted(glob.glob("gl_*.json"))})
z = L("zap/zap.json", {}) or {}; print("zap:", [(a["riskdesc"].split()[0], a["name"]) for s_ in z.get("site", []) for a in s_["alerts"] if not a["riskdesc"].startswith("Info")])
EOF
