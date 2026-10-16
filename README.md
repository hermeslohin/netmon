# netmon
Built specific to me and by an AI.  Queries Elasticsearch and Unifi to collect security events.  Presents and explains risk of events and vulnerabilities.  Allows users (my wife and kids) to subscribe to devices and get notifications of security related events near real time (Job runs every 15 minutes)

## Background
I have recently been working with Hermes Agent... and it is wild what it can do along with an LLM.  As my first test I started having it generate reports for security finding of my home network.  It pulls this information from Security Onion Solutions, LLC
Elastic and Unifi API.  For host collection it uses the builtin Elastic Fleet and OsQuery.  It started off generating a report every 24 hours with Claude and every 15 minutes it runs code and checks for "critical" events using a local LLM with a much smaller model.  It does really well at presenting useful information on security and immediately gave me actionable intel like:

Admin access between zones (recurring, awaiting allow rules): admin laptop → server 22/tcp, server 9090/tcp; server → AI host 22/tcp

iPad upload spikes = Google cloud uploads (Photos/Drive backup) from two family iPads

Domains that were recently registered, Devices bypassing DNS and more.  I did this all in under an hour.  Finds spike in usage patterns, DNS, compares events to threat intel. Warns me of changes made to devices that are relevant to security. 

I made it research attacks and summarize what is on the web and provide links to them as well so I can review them.  It also gives me "useful security news" and somehow it also decided to give me bicycling news....  I am not sure why it decided that but I kept it.

That then became... why don't I make an app out of it..  And it built netmon (it came up with the name... not me).  The app now is a simple web app that I vibe coded in under 24 hours.  

Features:
- Users (my wife and kids) can subscribe to specific devices and get push notifications to only devices they care about of events.

- App is scanned by a number of security tools and these security tools push notifications to the app (AI watching AI)..  Updates it self weekly and scans itself and fixes those issues.

- Lets me acknowledge vulnerabilities and alarms.  

- Maps vulnerabilities and attacks to Mitre Att&ck

- Calculates a risk rating of each system

- Shows lateral movement between zones and hosts.

Way more stuff that it just sorta came up with.


Is this "enterprise ready"... no probably not.  I think of most tools and they add a ton of complexity because they try to support a million different things their customer... this is designed for me.  It does things in ways that likely only make sense for me.  And perhaps that is the future of software... Significantly more customized solutions rapidly developed.  If I finding it lacking a feature... I ask for it and 10 minutes later it appears.

<img width="670" height="401" alt="Screenshot 2026-10-16 at 7 56 20 AM" src="https://github.com/user-attachments/assets/035c674b-a802-4661-ba82-b204dc17b32a" />
<img width="301" height="450" alt="Screenshot 2026-10-16 at 7 39 35 AM" src="https://github.com/user-attachments/assets/af2e18f7-9b59-49d4-b71f-04f2163bf500" />
<img width="301" height="650" alt="Screenshot 2026-10-16 at 7 41 18 AM" src="https://github.com/user-attachments/assets/3eebb19c-dc13-44ae-8f36-263dfde570cb" />
<img width="301" height="650" alt="Screenshot 2026-10-16 at 7 44 08 AM" src="https://github.com/user-attachments/assets/ac66bee9-0b9c-46c3-8aa0-e47c45f9fe51" />
<img width="301" height="300" alt="Screenshot 2026-10-16 at 8 57 59 AM" src="https://github.com/user-attachments/assets/8f7f32c1-cb61-4c58-a16b-8b31c18bb8d5" />
<img width="301" height="400" alt="Screenshot 2026-10-16 at 9 30 54 AM" src="https://github.com/user-attachments/assets/d417b9a6-2ecc-40c7-8aa7-8997a5df813b" />
<img width="301" height="400" alt="Screenshot 2026-10-16 at 9 32 35 AM" src="https://github.com/user-attachments/assets/6832b148-a61b-4de0-9f71-c25d900bec27" />
<img width="1206" height="1252" alt="image" src="https://github.com/user-attachments/assets/9544af8f-75f5-4057-a3db-e2867db1184e" />


Home-network security monitoring for the home network, run by the Hermes agent ("Lady Brains").

## Architecture

![netmon architecture: endpoints with Elastic Agent (Elastic Defend, osquery) and the Security Onion sensor feed Elasticsearch; the Hermes agent on the monitoring host runs a 15-minute watcher and a nightly pipeline that query Elasticsearch read-only and the UniFi Site Manager API, use Claude and a local LLM, and serve results through the netmon dashboard to family browsers and phones](docs/architecture.svg)

- **Data sources:** Elastic Agent on each endpoint (Elastic Defend + osquery, managed by Fleet) and the Security Onion sensor (Suricata, Zeek) write to Security Onion's Elasticsearch. The UniFi gateway is read through the UniFi Site Manager cloud API.
- **Hermes agent** schedules every job. The 15-minute watcher is deterministic and calls no model. The nightly run uses **Claude** for triage and web research. A **local LLM** (LM Studio) runs on the same machine for on-box work.
- **Outputs:** SQLite state, nightly PDF reports and the HTTPS dashboard with Web Push. Nothing is posted to chat.
- **Ask Hermes:** the dashboard's chat (and the 💬 button on every finding) talks to a separate, restricted Hermes profile (`netmonchat`) over its loopback-only API. That profile has no terminal, file or memory tools. It gets web search plus `netmon_mcp.py`, a read-only MCP server with nine query tools over the netmon data (snapshots, triage, findings, devices, endpoint findings, IDS and recent alerts, reports). The MCP server opens SQLite read-only.
- Regenerate the diagram with `python3 docs/make_architecture.py`.

## Components

- `collect.py` / `analyze.py` / `report.py`: nightly pipeline. Security Onion Elasticsearch, UniFi and Elastic Agent data go into a snapshot, which is compared against a per-device baseline and rendered as a PDF report.
- `watch.py`: 15-minute urgent watcher. It records dashboard alerts and push notifications (nothing is posted to Discord). Nightly PDFs are downloadable from the dashboard's Reports page.
- `hosts.py`, `osq.py`, `hostdetail.py`: host and endpoint telemetry (Elastic Defend, osquery).
- `mitre.py`: maps findings to MITRE ATT&CK.
- `store.py`: SQLite state store (WAL).
- `dashboard/`: HTTPS dashboard container (stdlib server, plain JS front end, Web Push).
- `sec_scan.sh`: security scan suite (Semgrep, Ruff/Bandit, pip-audit, ESLint no-unsanitized, Trivy, Hadolint, Gitleaks, ZAP).
- `netmon_mcp.py`: read-only MCP server (stdio, stdlib only) that serves netmon data to the Ask Hermes assistant.
- `ship.sh`: scan, commit and push (required for every code change).
- `weekly_rebuild.sh`: weekly container rebuild with updated libraries, a versioned image, a security scan, and in-app vulnerability alerts.

Runtime data, state, certificates and credentials are deliberately not in this repository (see `.gitignore`).
