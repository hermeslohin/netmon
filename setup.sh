#!/usr/bin/env bash
# netmon first-time setup. Safe to re-run: never overwrites existing config, secrets or data.
#   ./setup.sh            prepare config, folders, TLS cert, dashboard login, host secrets file and systemd units
#   ./setup.sh --check    only report what is present / missing
# Full guide: docs/SETUP.md
set -euo pipefail
NM="$(cd "$(dirname "$0")" && pwd)"
CFG="${XDG_CONFIG_HOME:-$HOME/.config}/netmon"
SECRETS="${NETMON_SECRETS:-$CFG/secrets.env}"
UNITS="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
CHECK=0; [ "${1:-}" = "--check" ] && CHECK=1
ok()   { printf '  \033[32m✓\033[0m %s\n' "$*"; }
warn() { printf '  \033[33m!\033[0m %s\n' "$*"; }
bad()  { printf '  \033[31m✗\033[0m %s\n' "$*"; MISSING=1; }
MISSING=0

echo "== location"
ok "repo is at $NM"

echo "== prerequisites"
for c in python3 docker git openssl systemctl; do
  if command -v "$c" >/dev/null 2>&1; then ok "$c"; else bad "$c not found"; fi
done
[ -x /usr/bin/python3 ] && ok "/usr/bin/python3 (the jobs call it explicitly)" || bad "/usr/bin/python3 missing"
/usr/bin/python3 -c 'import reportlab' 2>/dev/null && ok "reportlab (PDF reports)" || bad "reportlab missing: sudo apt install python3-reportlab   (or pip install --user reportlab)"
docker info >/dev/null 2>&1 && ok "docker usable by $(id -un)" || bad "docker not usable by $(id -un) (add the user to the docker group)"

echo "== settings (SQLite cfg table; edit on the dashboard: More > Settings)"
for f in site policy host_policy known_benign; do
  if python3 -c "import sys; sys.path.insert(0,'$NM'); import store; sys.exit(0 if store.cfg_has('$f') else 1)" 2>/dev/null; then ok "$f settings"
  elif [ $CHECK = 1 ]; then bad "$f settings missing"
  else python3 "$NM/store.py" cfg-import "$f" "$NM/$f.example.json" >/dev/null && warn "$f settings loaded from the template - EDIT them for your network (dashboard: More > Settings)"; fi
done
echo "== local config (git-ignored, from *.example.json)"
for f in sec_accepted; do
  if [ -f "$NM/$f.json" ]; then ok "$f.json"
  elif [ $CHECK = 1 ]; then bad "$f.json missing"
  else cp "$NM/$f.example.json" "$NM/$f.json"; chmod 600 "$NM/$f.json"; warn "$f.json created from template"; fi
done

echo "== folders"
for d in data baseline baseline/backup intel logs dashboard/state dashboard/certs "$HOME/network_reports" "$CFG"; do
  case "$d" in /*) p="$d";; *) p="$NM/$d";; esac
  if [ -d "$p" ]; then ok "$p"; elif [ $CHECK = 1 ]; then bad "$p missing"; else mkdir -p "$p"; ok "created $p"; fi
done
[ $CHECK = 1 ] || chmod 700 "$NM/dashboard/state" "$NM/baseline/backup" "$CFG"

echo "== host secrets ($SECRETS)"
if [ ! -f "$SECRETS" ] && [ $CHECK = 0 ]; then
  umask 077; printf '# netmon host secrets (KEY=value). Dashboard settings (Configuration > Integrations) take precedence.\nES_API_KEY=\nUNIFI_API_KEY=\n' > "$SECRETS"
  warn "created $SECRETS - add the read-only Elasticsearch API key (docs/SETUP.md step 3)"
fi
if grep -q '^ES_API_KEY=.\+' "$SECRETS" 2>/dev/null; then ok "Elasticsearch API key"
else warn "no ES_API_KEY in $SECRETS - set it there or on the dashboard (Configuration > Integrations)"; fi
grep -q '^UNIFI_API_KEY=.\+' "$SECRETS" 2>/dev/null && ok "UniFi API key" || warn "no UniFi API key - UniFi section is skipped (optional)"
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

echo "== dashboard settings (dashboard/.env)"
if [ -f "$NM/dashboard/.env" ]; then ok "dashboard/.env exists"
elif [ $CHECK = 1 ]; then bad "dashboard/.env missing"
else
  PW=$(openssl rand -base64 18 | tr -d '/+=' | cut -c1-20); BK=$(openssl rand -hex 24)
  umask 077; printf 'DASH_USER=admin\nDASH_PASS=%s\nNETMON_BROKER_URL=http://127.0.0.1:8650\nNETMON_BROKER_KEY=%s\n' "$PW" "$BK" > "$NM/dashboard/.env"
  ok "created: first login is user 'admin', password: $PW  (change it on the My account page)"
fi
grep -q '^NETMON_BROKER_KEY=.\+' "$NM/dashboard/.env" 2>/dev/null && ok "host broker key" || bad "NETMON_BROKER_KEY missing in dashboard/.env (any long random string; also NETMON_BROKER_URL=http://127.0.0.1:8650)"

echo "== systemd user units (scheduler + host broker + decision model)"
for u in netmon-scheduler netmon-broker netmon-clef; do
  if [ -f "$UNITS/$u.service" ]; then ok "$u.service"
  elif [ $CHECK = 1 ]; then bad "$u.service not installed"
  else mkdir -p "$UNITS"; sed "s|%h/netmon|$NM|g" "$NM/systemd/$u.service" > "$UNITS/$u.service"; ok "installed $UNITS/$u.service"; fi
done
if [ $CHECK = 0 ]; then
  systemctl --user daemon-reload
  loginctl show-user "$(id -un)" -p Linger 2>/dev/null | grep -q yes || warn "user lingering is off: jobs stop when you log out - run: sudo loginctl enable-linger $(id -un)"
  echo "   start them with: systemctl --user enable --now netmon-broker netmon-scheduler netmon-clef   (after the first collection works)"
fi

echo
if [ $MISSING = 1 ]; then echo "Some items need attention (✗ above). See docs/SETUP.md."; exit 1; fi
echo "Ready. Next: edit the *.json files, then follow docs/SETUP.md from step 5 (first collection)."
