#!/usr/bin/env bash
# Create the restricted Hermes profile that powers the dashboard's "Ask Hermes" chat, and wire the dashboard to it.
#   hermes/chat/setup_chat_profile.sh [port]      (default port 8643, loopback only)
# The profile gets ONLY: web search/extract + the read-only netmon MCP server. No terminal, files, memory, skills,
# browser, delegation or cron. Its .env holds only an Anthropic credential (copied from your main ~/.hermes/.env)
# and, if present, a Firecrawl key for web extraction. Re-running is safe; it does not print secrets.
set -euo pipefail
NM="$(cd "$(dirname "$0")/../.." && pwd)"; H="${HERMES_HOME:-$HOME/.hermes}"; P="$H/profiles/netmonchat"; PORT="${1:-8643}"
getenv() { sed -n "s/^$1=//p" "$H/.env" 2>/dev/null | tail -1; }
# LLM credential: an Anthropic API key, else an Anthropic OAuth token; with neither, Hermes falls back to your
# Claude Code login (~/.claude/.credentials.json) if present. Change provider/model in $P/config.yaml if you like.
ANTH=$(getenv ANTHROPIC_API_KEY); ATOK=$(getenv ANTHROPIC_TOKEN)
if [ -n "$ANTH" ]; then echo "LLM: Anthropic API key"; elif [ -n "$ATOK" ]; then echo "LLM: Anthropic OAuth token"
elif [ -f "$HOME/.claude/.credentials.json" ]; then echo "LLM: no key in $H/.env - Hermes will use your Claude Code login"
else echo "WARNING: no Anthropic credential found - add ANTHROPIC_API_KEY to $P/.env (or set another provider in $P/config.yaml)"; fi

[ -d "$P" ] || hermes profile create netmonchat --no-skills --no-alias \
  --description "Read-only home-network security assistant for the netmon dashboard chat." >/dev/null
echo "profile: $P"

KEY=$(sed -n 's/^API_SERVER_KEY=//p' "$P/.env" 2>/dev/null | tail -1)
[ -n "$KEY" ] || KEY=$(openssl rand -base64 36 | tr -d '/+=' | cut -c1-43)
umask 077
{ grep -vE '^(ANTHROPIC_API_KEY|ANTHROPIC_TOKEN|FIRECRAWL_API_KEY|API_SERVER_[A-Z_]+)=' "$P/.env" 2>/dev/null || true
  [ -n "$ANTH" ] && echo "ANTHROPIC_API_KEY=$ANTH"
  [ -z "$ANTH" ] && [ -n "$ATOK" ] && echo "ANTHROPIC_TOKEN=$ATOK"
  FC=$(getenv FIRECRAWL_API_KEY); [ -n "$FC" ] && echo "FIRECRAWL_API_KEY=$FC"
  echo "API_SERVER_ENABLED=true"; echo "API_SERVER_HOST=127.0.0.1"; echo "API_SERVER_PORT=$PORT"
  echo "API_SERVER_KEY=$KEY"; echo "API_SERVER_MODEL_NAME=netmon-assistant"; } > "$P/.env.new"
mv "$P/.env.new" "$P/.env"; chmod 600 "$P/.env"

if ! grep -q "netmon dashboard chat" "$P/config.yaml"; then cat >> "$P/config.yaml" <<YAML

# --- netmon dashboard chat: restricted, read-only assistant (no terminal, files, memory, skills or delegation)
platform_toolsets:
  api_server: [web, netmon]
agent:
  disabled_toolsets: [terminal, file, code_execution, browser, computer_use, delegation, cronjob, memory, skills, session_search, image_gen, tts, connections, todo, clarify]
mcp_servers:
  netmon:
    command: /usr/bin/python3
    args: [$NM/netmon_mcp.py]
    enabled: true
gateway:
  standalone: true   # own process, isolated from your main profile's gateway, env and secrets
  api_server:
    max_concurrent_runs: 3
YAML
fi
cp "$NM/hermes/chat/SOUL.md" "$P/SOUL.md"

# dashboard side: same key, loopback URL (dashboard container runs with --network host)
D="$NM/dashboard/.env"; touch "$D"; chmod 600 "$D"
{ grep -vE '^HERMES_CHAT_(URL|KEY)=' "$D" || true; echo "HERMES_CHAT_URL=http://127.0.0.1:$PORT"; echo "HERMES_CHAT_KEY=$KEY"; } > "$D.new"
mv "$D.new" "$D"; chmod 600 "$D"

hermes -p netmonchat gateway install >/dev/null 2>&1 || true
systemctl --user restart hermes-gateway-netmonchat 2>/dev/null || hermes -p netmonchat gateway start >/dev/null 2>&1 || true
for _ in $(seq 1 20); do curl -sf "http://127.0.0.1:$PORT/health" >/dev/null && break; sleep 1; done
curl -sf "http://127.0.0.1:$PORT/health" >/dev/null && echo "chat backend up on 127.0.0.1:$PORT" || echo "chat backend not answering yet: journalctl --user -u hermes-gateway-netmonchat"
echo "now redeploy the dashboard: $NM/dashboard/deploy.sh"
