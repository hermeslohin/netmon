#!/bin/bash
# Claude event enrichment for the dashboard (runs dashboard/app/enrich.py inside the netmon-dashboard container,
# which owns /state). Used by the 4-hourly Hermes report job.
#   enrich.sh events OUT.json [--all] [--max N]   events of the newest snapshot that need notes (+ candidate links)
#   enrich.sh put NOTES.json            store notes + correlation verdicts, prints counts
set -eu
C=${NETMON_CONTAINER:-netmon-dashboard}
case "${1:-}" in
  events) OUT=${2:?usage: enrich.sh events OUT.json [--all]}; shift 2
          docker exec "$C" python /app/enrich.py events "$@" > "$OUT"
          python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(sys.argv[1], {k: d.get(k) for k in ("snapshot","total_events","note_keys","without_note","listed","error")})' "$OUT" ;;
  put)    IN=${2:?usage: enrich.sh put NOTES.json}
          docker exec -i "$C" python /app/enrich.py put - < "$IN" ;;
  *)      sed -n '2,6p' "$0"; exit 2 ;;
esac
