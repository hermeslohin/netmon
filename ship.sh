#!/bin/bash
# Every netmon code change goes through here:  ./ship.sh "commit message" [--deploy] [--force]
#   1. security scan (sec_scan.sh) -> new findings become in-app alerts + Software vulnerabilities
#   2. secret gate: gitleaks over exactly the files about to be committed - any hit ABORTS (never pushes secrets)
#   3. new HIGH findings abort unless --force (after review: fix them, or accept in sec_accepted.json with a reason)
#   4. git commit + push to the GitHub repo in site.json (github_repo); optional dashboard redeploy
set -u
NM=$HOME/.hermes/netmon; cd "$NM"
MSG=${1:?usage: ship.sh "commit message" [--deploy] [--force]}; shift
DEPLOY=0; FORCE=0; for a in "$@"; do [ "$a" = --deploy ] && DEPLOY=1; [ "$a" = --force ] && FORCE=1; done
SCAN=$HOME/.hermes/cache/scratch/sec

echo "== 1. security scan"
"$NM/sec_scan.sh" "$SCAN" > "$NM/baseline/secscan-last.txt" 2>&1
R=$(/usr/bin/python3 "$NM/secfindings.py" sync "$SCAN" --notify new --context "code change: $MSG") || { echo "secfindings failed"; exit 1; }
echo "   $R"

echo "== 2. secret gate on the commit"
git add -A
STAGE=$(mktemp -d); trap 'rm -rf "$STAGE"' EXIT
git diff --cached --name-only --diff-filter=ACMR -z | while IFS= read -r -d '' f; do mkdir -p "$STAGE/$(dirname "$f")"; cp "$f" "$STAGE/$f"; done
if [ -n "$(ls -A "$STAGE")" ]; then
  if ! docker run --rm -v "$STAGE":/scan:ro zricethezav/gitleaks:latest dir /scan --no-banner --redact >/dev/null 2>&1; then
    echo "   ABORT: gitleaks found a possible secret in the files being committed:"
    docker run --rm -v "$STAGE":/scan:ro zricethezav/gitleaks:latest dir /scan --no-banner --redact 2>&1 | grep -E "File|RuleID" | sed 's#/scan/#   #'
    git reset -q; exit 2
  fi
fi
echo "   clean"

echo "== 2b. sensitive-data gate (no site IPs, MACs, host/account names or private config in the repo)"
git diff --cached --name-only --diff-filter=ACMR -z | xargs -0 -r /usr/bin/python3 "$NM/repo_guard.py" || {
  echo "   ABORT: sensitive site data in the commit - move it to site.json (git-ignored) and read it via site_cfg"; git reset -q; exit 4; }
echo "   clean"

NEWHIGH=$(echo "$R" | /usr/bin/python3 -c 'import json,sys; print(json.load(sys.stdin).get("new_high", 0))' 2>/dev/null || echo 0)
if [ "${NEWHIGH:-0}" != 0 ] && [ $FORCE -ne 1 ]; then
  echo "   ABORT: $NEWHIGH new HIGH finding(s) - run secfindings.py list, fix or accept with a reason, then re-run (or --force)"
  git reset -q; exit 3
fi

echo "== 3. commit + push"
if git diff --cached --quiet; then echo "   nothing to commit"; else
  git commit -q -m "$MSG" -m "Security scan: $R" && git push -q origin HEAD 2>&1 | grep -v "^$" ; echo "   pushed $(git rev-parse --short HEAD)"
fi
if [ $DEPLOY -eq 1 ]; then echo "== 4. deploy dashboard"; "$NM/dashboard/deploy.sh" >/dev/null && sleep 5 && curl -skf https://127.0.0.1:8443/healthz && echo; fi
