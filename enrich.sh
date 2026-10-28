#!/bin/bash
# AI note storage for the review job (review.py) and event research (research.py). Runs dashboard/app/enrich.py / kb.py inside the
# netmon-dashboard container, which owns /state.
#   enrich.sh events OUT.json [--all] [--max N] [--hosts N] [--ids N] [--gw N]   work items: host findings (60), Suricata sev 1-2 (40), gateway events (30), other events
#   enrich.sh put NOTES.json|-                    store notes + correlation verdicts (+ "host_notes" / "host_notes_delete"), prints counts, then runs
#                                                 the Security Triage auto-close (only when enabled on the Configuration page)
#   enrich.sh copy COPIES.json|-                  {"model", "copies": [{id, from, reason}]}: reuse an earlier note for a similar event (marked as copied)
#   enrich.sh kb [FILTER]                         notes knowledge base as JSON: AI/owner host notes per device + the
#                                                 owner's event notes (FILTER = subject/text substring)
#   enrich.sh kbput HOSTNOTES.json|-              {"model", "via", "host_notes": [{ip|mac|host|subject, category, text, id?}],
#                                                 "host_notes_delete": [ids]} - add / update (id) / delete host notes
# Both steps are logged (enrich.db runs) and shown on the AI review page.
set -eu
C=${NETMON_CONTAINER:-netmon-dashboard}
src() { if [ "$1" = "-" ]; then cat; else cat "$1"; fi; }
case "${1:-}" in
  events) OUT=${2:?usage: enrich.sh events OUT.json [--all] [--max N] [--hosts N] [--ids N] [--gw N]}; shift 2
          docker exec "$C" python /app/enrich.py events "$@" > "$OUT"
          python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(sys.argv[1], {k: d.get(k) for k in ("snapshot","total_events","note_keys","without_note","host_findings","host_without_note","ids_sev12","ids_sev12_without_note","gateway","gateway_without_note","events_with_user_notes","hosts_with_notes","listed","review_only","review_covered","error")})' "$OUT" ;;
  put)    IN=${2:?usage: enrich.sh put NOTES.json|-}
          src "$IN" | docker exec -i "$C" python /app/enrich.py put -
          docker exec "$C" python /app/autoclose.py run "review job" >&2 || echo "autoclose failed (notes were stored)" >&2 ;;
  copy)   IN=${2:?usage: enrich.sh copy COPIES.json|-}
          src "$IN" | docker exec -i "$C" python /app/enrich.py copy - ;;
  kb)     docker exec "$C" python /app/kb.py dump "${2:-}" ;;
  kbput)  IN=${2:?usage: enrich.sh kbput HOSTNOTES.json|-}
          src "$IN" | docker exec -i "$C" python /app/kb.py put - ;;
  *)      sed -n '2,12p' "$0"; exit 2 ;;
esac
