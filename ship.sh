#!/bin/bash
# Every netmon code change goes through here:  ./ship.sh "commit message" [--deploy] [--force] [--skip-tests]
#   0. test gate: unit + end-to-end suite (tests/run_tests.py) and requirement traceability (tests/gen_docs.py --check);
#      any failure ABORTS (--force does not bypass it; --skip-tests does, and says so in the commit message).
#      The run regenerates docs/TEST_TRACEABILITY.md + the inventory in docs/TESTING.md, which are committed with the change.
#   1. security scan (sec_scan.sh) -> new findings become in-app alerts + Software vulnerabilities
#   2. secret gate: gitleaks over exactly the files about to be committed - any hit ABORTS (never pushes secrets)
#   3. new HIGH findings abort unless --force (after review: fix them, or accept in sec_accepted.json with a reason)
#   4. git commit + push to the GitHub repo in site.json (github_repo); optional dashboard redeploy
set -u
NM=$(cd "$(dirname "$0")" && pwd); cd "$NM"
MSG=${1:?usage: ship.sh "commit message" [--deploy] [--force] [--skip-tests]}; shift
DEPLOY=0; FORCE=0; SKIPTESTS=0
for a in "$@"; do [ "$a" = --deploy ] && DEPLOY=1; [ "$a" = --force ] && FORCE=1; [ "$a" = --skip-tests ] && SKIPTESTS=1; done
SCAN=${NETMON_SCAN_DIR:-$HOME/.cache/netmon/sec}

TESTS="not run (--skip-tests)"
if [ $SKIPTESTS -eq 1 ]; then
  echo "== 0. tests SKIPPED (--skip-tests)"
else
  echo "== 0. test gate (unit + e2e, log: baseline/tests-last.txt)"
  if ! /usr/bin/python3 "$NM/tests/run_tests.py" all > "$NM/baseline/tests-last.txt" 2>&1; then
    echo "   ABORT: tests failed or the run touched live files:"
    grep -E "^(FAIL|ERROR|UNEXPECTED)|^Ran |^FAILED|isolation check" "$NM/baseline/tests-last.txt" | head -20 | sed 's/^/   /'
    exit 7
  fi
  if ! /usr/bin/python3 "$NM/tests/gen_docs.py" --results "$NM/tests/.last_results.json" --check > /dev/null; then
    echo "   ABORT: traceability gap - a test without a REQ tag, an unknown REQ id or a requirement without a test:"
    /usr/bin/python3 "$NM/tests/gen_docs.py" --results "$NM/tests/.last_results.json" | sed 's/^/   /'
    exit 8
  fi
  TESTS=$(grep -E "^Ran |^OK" "$NM/baseline/tests-last.txt" | tr '\n' ' ' | sed 's/ *$//')
  echo "   $TESTS"
fi

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
  echo "   ABORT: sensitive site data in the commit - move it to the site settings (dashboard: More > Settings) and read it via site_cfg"; git reset -q; exit 4; }
echo "   clean"

NEWHIGH=$(echo "$R" | /usr/bin/python3 -c 'import json,sys; print(json.load(sys.stdin).get("new_high", 0))' 2>/dev/null || echo 0)
if [ "${NEWHIGH:-0}" != 0 ] && [ $FORCE -ne 1 ]; then
  echo "   ABORT: $NEWHIGH new HIGH finding(s) - run secfindings.py list, fix or accept with a reason, then re-run (or --force)"
  git reset -q; exit 3
fi

echo "== 3. commit + push"
if git diff --cached --quiet; then echo "   nothing to commit"; else git commit -q -m "$MSG" -m "Tests: $TESTS" -m "Security scan: $R"; fi
# the user also edits on github.com (README): replay local commits on top of theirs, then verify the push really landed
git fetch -q origin main && { git rebase -q origin/main || { git rebase --abort; echo "   ABORT: conflict with commits on GitHub - resolve by hand"; exit 5; }; }
git diff --name-only HEAD@{1} HEAD 2>/dev/null | xargs -r /usr/bin/python3 "$NM/repo_guard.py" >/dev/null || echo "   note: incoming GitHub changes flagged by repo_guard (review them)"
if git push -q origin HEAD:main 2>&1 | grep -v "^$"; [ "$(git rev-parse HEAD)" = "$(git ls-remote origin refs/heads/main | cut -f1)" ]; then
  echo "   pushed $(git rev-parse --short HEAD)"
else echo "   ABORT: push did not land on GitHub"; exit 6; fi
if [ $DEPLOY -eq 1 ]; then
  echo "== 4. deploy dashboard"; "$NM/dashboard/deploy.sh" >/dev/null && sleep 5 && curl -skf https://127.0.0.1:8443/healthz && echo
  echo "== 5. post-deploy check of the running container (read-only)"
  for i in 1 2 3 4 5 6 7 8 9 10 11 12; do  # docker marks it healthy only after the first HEALTHCHECK (interval 60s)
    [ "$(docker inspect -f '{{.State.Health.Status}}' netmon-dashboard 2>/dev/null)" = healthy ] && break; sleep 10; done
  if (cd "$NM/tests" && /usr/bin/python3 -m unittest discover -s e2e -t . -p test_e2e_container.py) > "$NM/baseline/tests-deploy.txt" 2>&1; then
    echo "   container checks passed"
  else echo "   WARNING: deployed container checks failed (already pushed) - see baseline/tests-deploy.txt"; exit 9; fi
fi
