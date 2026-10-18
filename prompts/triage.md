## Task: triage this snapshot

You get the analysis of the newest snapshot below (findings vs each device's baseline). The full snapshot (devices,
alerts, DNS, TLS, files, beacons, internal flows, UniFi, endpoint hosts...) is available through read_data.

Investigate every high and medium finding plus: every Suricata signature not explained in known_benign, severity 1-2
alerts, detection-rule hits (real source in logs-kratos-so / logs-system.auth-default), new and unknown devices,
threat-intel hits (which device, when, what else it talked to; JA3-only matches are low fidelity unless corroborated),
newly registered domains, beacons (destination, interval, what the device is), segmentation violations and internal
scans, IoT allowlist breaks, risky files, TLS and DNS findings, DNS-tunnel candidates, capture loss, endpoint findings
(snapshot `hosts.findings`), admin sessions between internal hosts (snapshot `admin_access`: SSH/RDP/PsExec/WMI/WinRM/VNC;
failed logins and password guessing need a verdict - the admin's own typo, or not) and the snapshot's `unifi` block
(IDS threat events - correlate them with Suricata/Zeek for the same IPs and time; high-severity gateway events; admin
logins from unexpected sources; security-relevant configuration changes - who, when, from where and whether it looks
intended; risky flows; clients not in the inventory; IDS coverage gaps). A `unifi: {"skipped": ...}` block just means
UniFi is not configured.

Compare with the previous triage and the one about 24 h ago (read_data previous_triage / day_ago_triage): mark
recurring known items as recurring instead of re-alarming them, and say whether an item is new since the previous run.
Windows of consecutive runs may overlap. On short-window runs, volumes are compared with the baseline scaled to the
window and the "silent device" check is skipped - that is normal.

When something is conclusively benign, record it with add_known_benign so later runs do not re-raise it. Never change
policy allow rules: propose them in the summary for the owner to approve.

Finish by calling submit_triage exactly once with:
- summary: a few sentences - the overall picture, Investigate-priority items, what is new, proposed allow rules,
  baseline status, and any collector that failed
- alarms: [{priority: Investigate | Review | Info, title, who, evidence, why, next, context? (with [n] citations),
  links? [{title, url}]}]
- research_notes?: list of strings (one note per researched item)
- device_notes?: {ip: note}
