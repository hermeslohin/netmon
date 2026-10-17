#!/bin/bash
# Claude event enrichment for the dashboard (runs dashboard/app/enrich.py inside the netmon-dashboard container,
# which owns /state). Used by the 4-hourly Hermes report job.
#   enrich.sh events OUT.json [--all] [--max N] [--hosts N] [--ids N] [--gw N]   host findings (60), Suricata sev 1-2 (40), gateway events (30), other events
#   enrich.sh put NOTES.json                      store notes + correlation verdicts, prints counts
# Both steps are logged (enrich.db runs) and refresh the job status on the AI-review page (claude_status.py).
set -eu
C=${NETMON_CONTAINER:-netmon-dashboard}
NM=$(cd "$(dirname "$0")" && pwd)
status() { /usr/bin/python3 "$NM/claude_status.py" >/dev/null 2>&1 || true; }
case "${1:-}" in
  events) OUT=${2:?usage: enrich.sh events OUT.json [--all] [--max N] [--hosts N] [--ids N] [--gw N]}; shift 2
          status
          docker exec "$C" python /app/enrich.py events "$@" > "$OUT"
          python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(sys.argv[1], {k: d.get(k) for k in ("snapshot","total_events","note_keys","without_note","host_findings","host_without_note","ids_sev12","ids_sev12_without_note","gateway","gateway_without_note","listed","error")})' "$OUT" ;;
  put)    IN=${2:?usage: enrich.sh put NOTES.json}
          docker exec -i "$C" python /app/enrich.py put - < "$IN"
          status ;;
  *)      sed -n '2,7p' "$0"; exit 2 ;;
esac
