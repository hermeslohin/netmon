---
name: netmon
description: "Use when running or triaging the netmon home-network report. Pipeline, triage rules, outputs."
version: 1.1.0
---

# netmon: nightly home-network security report

netmon lives in `~/.hermes/netmon` (git repo). All network-specific values are in git-ignored local files:
`site.json` (IPs, names, domains), `policy.json` (zones, device classes, allowed flows), `host_policy.json`
(endpoint rules), `known_benign.json` (explained-benign signatures/domains). Run every script with `/usr/bin/python3`.

## Nightly run (the cron job's prompt points here)
1. `/usr/bin/python3 ~/.hermes/netmon/collect.py 24` → `data/<stamp>.json`. Check `extras_errors` in the snapshot; retry a failed collector once, report persistent failures. A `unifi: {"skipped": ...}` block just means UniFi is not configured.
2. `/usr/bin/python3 ~/.hermes/netmon/analyze.py` → `data/<stamp>.analysis.json` (findings vs each device's rolling baseline; deviation rules switch on after 3 days of baseline). Report it if it prints `store backup FAILED` or a non-`ok` integrity check.
3. Triage with read-only Elasticsearch queries: `~/.hermes/netmon/esq.py <index> '<json body>'`. Investigate every high/medium finding, every Suricata signature not in `known_benign.json`, severity 1-2 alerts, detection-rule hits, new/unknown devices, threat-intel hits (JA3-only matches are low fidelity), newly registered domains, beacons, segmentation violations, IoT allowlist breaks, risky files, TLS and DNS findings, DNS-tunnel candidates, capture loss, endpoint findings (`hosts.findings` in the snapshot), the `unifi` block (IDS events, admin logins from unexpected sources, config changes) and `admin_access` (SSH/RDP/PsExec/WMI/WinRM/VNC sessions between internal hosts; rate them with `lateral.admin_sessions()` from `dashboard/app`. Failed logins and password guessing need a verdict: the admin's own typo, or not). For each: the specific peer/domain/port/time, and a verdict - benign or worth investigating. Compare with the previous day's `*.triage.json`; mark recurring items as recurring.
4. Web research for new/unexplained items (domains, ASNs, signatures, software, CVEs). Prefer primary sources. Cite with links you actually opened.
5. Write `data/<stamp>.triage.json`:
   `{"summary": str, "alarms": [{"priority": "Investigate"|"Review"|"Info", "title", "who", "evidence", "why", "next", "context"?, "links"?: [{"title","url"}]}], "research_notes"?: str, "device_notes"?: {ip: str}}`.
   Numbers must match the snapshot. When something is conclusively benign, add it to `known_benign.json` (`signatures`, `names`, `dns_domains`, `beacon_domains`). Never edit `policy.json` allow rules yourself: propose them in the summary.
6. Optional `data/<stamp>.briefing.json`: `{"items": [{"category", "title", "summary", "url"}]}` renders as a news section at the end of the PDF.
7. `/usr/bin/python3 ~/.hermes/netmon/report.py` → `~/network_reports/network-report-<stamp>.pdf` and an in-app "report ready" alert. Verify the file exists and is non-empty. The dashboard's Reports page serves it; do not post it to chat.

## Correlation (dashboard)
Events and open vulnerabilities are linked by `dashboard/app/correlate.py`, and every proposed link is confirmed or rejected by the local LLM (`corr_llm.py`, LM Studio). Confirmed links with the model's reason are at `/api/correlate?id=<stamp>` and in each event's "Related" column. Use them as leads during triage, but verify against the data. See `docs/CORRELATION.md`.

## Rules
- Read-only: never change Security Onion, the gateway/UniFi or any device. No API keys or tokens in output.
- Code changes go through `~/.hermes/netmon/ship.sh "<message>" [--deploy]` (security scans + secret and sensitive-data gates + push). Never `git push` by hand; never commit site data.
- Never test with the live `watch.py` (it writes mute state). Use `NETMON_DB=<scratch copy>`.

## Useful indices (Security Onion 2.4)
`logs-suricata.alerts-so`, `logs-zeek-so` (data_stream.dataset zeek.conn / dns / ssl / files / dhcp ...), `logs-detections.alerts-so`,
`logs-endpoint.events.{process,network,file}-default`, `logs-endpoint.alerts-*`, `logs-system.auth-default`, `logs-system.syslog-default`,
`logs-osquery_manager.result-*`, `logs-elastic_agent-default`.
