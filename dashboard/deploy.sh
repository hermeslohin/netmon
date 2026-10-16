#!/bin/sh
# Rebuild and (re)start the netmon dashboard container. Data is mounted read-only.
#   ./deploy.sh                 build netmon-dashboard:latest from source and run it
#   IMAGE=<ref> ./deploy.sh     run an existing image (e.g. a weekly version tag) without building
set -e
cd "$(dirname "$0")"
if [ -z "${IMAGE:-}" ]; then
  docker build -q -t netmon-dashboard:latest .
  IMAGE=netmon-dashboard:latest
fi
docker rm -f netmon-dashboard >/dev/null 2>&1 || true
docker run -d --name netmon-dashboard --restart unless-stopped \
  --user 1000:1000 --read-only --cap-drop ALL --security-opt no-new-privileges \
  --env-file .env --network host \
  -v "$HOME/.hermes/netmon:/netmon:ro" \
  -v "$PWD/certs:/certs:ro" \
  -v "$PWD/state:/state:rw" \
  -v "$HOME/network_reports:/reports:ro" \
  --memory 512m \
  "$IMAGE"
