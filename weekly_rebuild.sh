#!/bin/bash
# Weekly: rebuild the dashboard container with every library updated, save it as a new version, deploy it with
# automatic rollback, run the security scan, and raise any issues as in-app notifications + Software vulnerabilities.
# Run by cron (no LLM). Prints a short summary (cron output is kept locally); alerts go out via the dashboard's push.
set -u
NM=$HOME/.hermes/netmon; D=$NM/dashboard; LOG=$NM/baseline/rebuild.log
site() { /usr/bin/python3 -c "import sys; sys.path.insert(0, '$NM'); import site_cfg; print(site_cfg.get('$1') or '')"; }
REPO=$(site image_repo); GH_USER=$(site github_user)
VER=$(date -u +%Y.%m.%d)
docker image inspect netmon-dashboard:$VER >/dev/null 2>&1 && VER=$VER-$(date -u +%H%M)
PREV=$(docker inspect -f '{{.Config.Image}}' netmon-dashboard 2>/dev/null || echo netmon-dashboard:latest)
PREV_ID=$(docker image inspect -f '{{.Id}}' "$PREV" 2>/dev/null)
mkdir -p "$(dirname "$LOG")"
say() { echo "$@"; echo "$(date -u +%FT%TZ) $*" >> "$LOG"; }
alert() {  # severity text
  /usr/bin/python3 - "$1" "$2" <<'EOF'
import os, sys; sys.path.insert(0, os.path.expanduser("~/.hermes/netmon")); import store, site_cfg as S
store.alerts_add([("rebuild|" + sys.argv[2][:80], sys.argv[2], sys.argv[1], ["ip:" + S.get("self_ip"), "host:" + S.get("self_host")])], source="rebuild")
EOF
}

# 1. fresh build: newest python:3.12-alpine, apk upgrade, latest pywebpush 2.x + deps (no layer cache)
cd "$D"
if ! docker build -q --pull --no-cache -t netmon-dashboard:$VER -t netmon-dashboard:latest . >/dev/null 2>>"$LOG"; then
  say "BUILD FAILED for $VER - still running $PREV"; alert investigate "Weekly dashboard rebuild FAILED to build ($VER); still running $PREV. See baseline/rebuild.log."; exit 1
fi
{ docker run --rm --entrypoint sh netmon-dashboard:$VER -c 'python --version; echo "alpine packages:"; apk list -I 2>/dev/null'
  echo "python packages:"
  docker run --rm -i --entrypoint python netmon-dashboard:$VER - <<'PY'
import importlib.metadata as m
for n in sorted(f"{d.metadata['Name']}=={d.version}" for d in m.distributions()):
    print(n)
PY
} > "$NM/baseline/image-$VER.txt" 2>&1
NEW_ID=$(docker image inspect -f '{{.Id}}' netmon-dashboard:$VER)
CHANGED=$([ "$NEW_ID" = "$PREV_ID" ] && echo no || echo yes)

# 2. deploy the new version; roll back if it does not come up healthy
IMAGE=netmon-dashboard:$VER ./deploy.sh >/dev/null
ok=0; for i in $(seq 1 20); do sleep 3; curl -skf https://127.0.0.1:8443/healthz >/dev/null && { ok=1; break; }; done
if [ $ok -ne 1 ]; then
  docker logs --tail 30 netmon-dashboard >> "$LOG" 2>&1
  IMAGE="$PREV" ./deploy.sh >/dev/null
  say "NEW VERSION $VER UNHEALTHY - rolled back to $PREV"
  alert investigate "Weekly dashboard rebuild $VER failed its health check and was rolled back to $PREV. See baseline/rebuild.log."
  exit 1
fi
say "deployed netmon-dashboard:$VER (image changed: $CHANGED; previous $PREV)"

# 3. save the version to GitHub Container Registry (private package), keep the last 8 versions locally
if [ -n "$REPO" ] && [ -s "$HOME/.config/netmon/github_token" ]; then
  export DOCKER_CONFIG=$(mktemp -d)  # throwaway login: never leave registry credentials in ~/.docker/config.json
  trap 'rm -rf "$DOCKER_CONFIG"' EXIT
  if docker login ghcr.io -u "$GH_USER" --password-stdin < "$HOME/.config/netmon/github_token" >/dev/null 2>>"$LOG"; then
    docker tag netmon-dashboard:$VER $REPO:$VER && docker tag netmon-dashboard:$VER $REPO:latest
    if docker push -q $REPO:$VER >/dev/null 2>>"$LOG" && docker push -q $REPO:latest >/dev/null 2>>"$LOG"; then say "pushed $REPO:$VER"
    else say "WARNING: push to $REPO failed (see log)"; fi
    docker logout ghcr.io >/dev/null 2>&1
  else say "WARNING: ghcr.io login failed"; fi
  unset DOCKER_CONFIG
fi
docker images --format '{{.Tag}}' netmon-dashboard | grep -E '^[0-9]{4}\.[0-9]{2}\.[0-9]{2}' | sort -r | tail -n +9 | \
  while read t; do docker rmi netmon-dashboard:$t $REPO:$t >/dev/null 2>&1; done

# 4. security scan of the new image + code + live dashboard; raise findings in the app
"$NM/sec_scan.sh" > "$NM/baseline/secscan-last.txt" 2>&1
R=$(/usr/bin/python3 "$NM/secfindings.py" sync --notify all --context "weekly rebuild $VER")
say "security scan: $R"
echo "Weekly rebuild: netmon-dashboard:$VER deployed (libraries changed: $CHANGED). Scan: $R"
