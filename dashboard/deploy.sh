#!/bin/sh
# Rebuild and (re)start the netmon dashboard container. Data is mounted read-only.
#   ./deploy.sh                 build netmon-dashboard:latest from source and run it
#   IMAGE=<ref> ./deploy.sh     run an existing image (e.g. a weekly version tag) without building
set -e
cd "$(dirname "$0")"
mkdir -p state
[ -f .env ] || { echo "dashboard/.env missing - run ../setup.sh first (see docs/SETUP.md)"; exit 1; }
[ -f certs/dashboard.crt ] || { echo "certs/dashboard.crt missing - run ../setup.sh first"; exit 1; }
if [ -z "${IMAGE:-}" ]; then
  docker build -q -t netmon-dashboard:latest .
  IMAGE=netmon-dashboard:latest
fi
docker rm -f netmon-dashboard >/dev/null 2>&1 || true
docker run -d --name netmon-dashboard --restart unless-stopped \
  --user "$(id -u):$(id -g)" --read-only --tmpfs /tmp:rw,noexec,nosuid,size=64m --cap-drop ALL --security-opt no-new-privileges \
  --env-file .env --network host \
  -v "$(cd .. && pwd):/netmon:ro" \
  -v "$PWD/certs:/certs:ro" \
  -v "$PWD/state:/state:rw" \
  --memory 512m \
  "$IMAGE"
