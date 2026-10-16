#!/usr/bin/env bash
# netmon first-time setup. Safe to re-run: never overwrites existing config, secrets or data.
#   ./setup.sh            prepare config, folders, TLS cert, dashboard login and Hermes scripts/skill
#   ./setup.sh --check    only report what is present / missing
# Full guide: docs/SETUP.md
set -euo pipefail
NM="$(cd "$(dirname "$0")" && pwd)"
H="${HERMES_HOME:-$HOME/.hermes}"
CHECK=0; [ "${1:-}" = "--check" ] && CHECK=1
ok()   { printf '  \033[32m✓\033[0m %s\n' "$*"; }
warn() { printf '  \033[33m!\033[0m %s\n' "$*"; }
bad()  { printf '  \033[31m✗\033[0m %s\n' "$*"; MISSING=1; }
MISSING=0

echo "== location"
if [ "$NM" = "$H/netmon" ]; then ok "repo is at $NM"; else
  bad "repo must live at $H/netmon (several scripts and the Hermes jobs use that path). Move it: mv '$NM' '$H/netmon'"; fi

echo "== prerequisites"
for c in python3 docker git openssl hermes; do
  if command -v "$c" >/dev/null 2>&1; then ok "$c"; else bad "$c not found"; fi
done
[ -x /usr/bin/python3 ] && ok "/usr/bin/python3 (the jobs call it explicitly)" || bad "/usr/bin/python3 missing"
/usr/bin/python3 -c 'import reportlab' 2>/dev/null && ok "reportlab (PDF reports)" || bad "reportlab missing: sudo apt install python3-reportlab   (or pip install --user reportlab)"
docker info >/dev/null 2>&1 && ok "docker usable by $(id -un)" || bad "docker not usable by $(id -un) (add the user to the docker group)"

echo "== local config (git-ignored, from *.example.json)"
for f in site policy host_policy known_benign sec_accepted; do
  if [ -f "$NM/$f.json" ]; then ok "$f.json"
  elif [ $CHECK = 1 ]; then bad "$f.json missing"
  else cp "$NM/$f.example.json" "$NM/$f.json"; chmod 600 "$NM/$f.json"; warn "$f.json created from template - EDIT IT for your network"; fi
done

echo "== folders"
for d in data baseline baseline/backup intel dashboard/state dashboard/certs "$HOME/network_reports" "$H/scripts" "$H/secrets"; do
  case "$d" in /*) p="$d";; *) p="$NM/$d";; esac
  if [ -d "$p" ]; then ok "$p"; elif [ $CHECK = 1 ]; then bad "$p missing"; else mkdir -p "$p"; ok "created $p"; fi
done
[ $CHECK = 1 ] || chmod 700 "$NM/dashboard/state" "$NM/baseline/backup" "$H/secrets"

echo "== secrets"
if grep -q '^MCP_SO_ELASTICSEARCH_API_KEY=.\+' "$H/.env" 2>/dev/null; then ok "Elasticsearch API key in $H/.env"
else bad "add MCP_SO_ELASTICSEARCH_API_KEY=<read-only ES API key> to $H/.env (docs/SETUP.md step 3)"; fi
[ -s "$H/secrets/unifi_api_key" ] && ok "UniFi API key ($H/secrets/unifi_api_key)" || warn "no UniFi API key - UniFi section is skipped (optional)"
ls "$HOME"/dhcp-export-all-*.csv >/dev/null 2>&1 && ok "device inventory CSV" || warn "no ~/dhcp-export-all-*.csv inventory - devices named from DHCP/DNS only (optional)"

echo "== dashboard TLS certificate"
if [ -f "$NM/dashboard/certs/dashboard.crt" ]; then ok "dashboard/certs/dashboard.crt"
elif [ $CHECK = 1 ]; then bad "no certificate"
else
  openssl req -x509 -newkey rsa:3072 -nodes -days 825 -subj "/CN=netmon" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
    -keyout "$NM/dashboard/certs/dashboard.key" -out "$NM/dashboard/certs/dashboard.crt" 2>/dev/null
  chmod 600 "$NM/dashboard/certs/dashboard.key"; chmod 644 "$NM/dashboard/certs/dashboard.crt"
  ok "self-signed certificate created (replace with your own if you have one)"
fi

echo "== dashboard login (dashboard/.env)"
if [ -f "$NM/dashboard/.env" ]; then ok "dashboard/.env exists"
elif [ $CHECK = 1 ]; then bad "dashboard/.env missing"
else
  PW=$(openssl rand -base64 18 | tr -d '/+=' | cut -c1-20)
  umask 077; printf 'DASH_USER=admin\nDASH_PASS=%s\n' "$PW" > "$NM/dashboard/.env"
  ok "created: first login is user 'admin', password: $PW  (change it on the My account page)"
fi

echo "== Hermes scripts + skill"
for s in netmon_watch.sh netmon_weekly_rebuild.sh; do
  if [ -f "$H/scripts/$s" ]; then ok "$H/scripts/$s"
  elif [ $CHECK = 1 ]; then bad "$H/scripts/$s missing"
  else cp "$NM/hermes/scripts/$s" "$H/scripts/$s"; chmod 755 "$H/scripts/$s"; ok "installed $H/scripts/$s"; fi
done
if [ -f "$H/skills/netmon/SKILL.md" ]; then ok "skill netmon"
elif [ $CHECK = 1 ]; then bad "skill netmon not installed"
else mkdir -p "$H/skills/netmon"; cp "$NM/hermes/skills/netmon/SKILL.md" "$H/skills/netmon/SKILL.md"; ok "installed skill netmon"; fi

echo
if [ $MISSING = 1 ]; then echo "Some items need attention (✗ above). See docs/SETUP.md."; exit 1; fi
echo "Ready. Next: edit the *.json files, then follow docs/SETUP.md from step 5 (first collection)."
