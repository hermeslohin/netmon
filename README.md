# netmon
Built specific to me and by an AI.  Queries Elasticsearch and Unifi to collect security events.  Presents and explains risk of events and vulnerabilities.  Allows users (my wife and kids) to subscribe to devices and get notifications of security related events near real time (Job runs every 15 minutes)

## Background
I have recently been working with Hermes Agent... and it is wild what it can do along with an LLM.  As my first test I started having it generate reports for security finding of my home network.  It pulls this information from Security Onion Solutions, LLC

Elastic and Unifi API.  For host collection it uses the builtin Elastic Fleet and OsQuery.  It started off generating a report every 24 hours with Claude and every 15 minutes it runs code and checks for "critical" events using a local LLM with a much smaller model.  It does really well at presenting useful information on security and immediately gave me actionable intel like:

Admin access between zones (recurring, awaiting allow rules): admin laptop → server 22/tcp, server 9090/tcp; server → AI host 22/tcp

iPad upload spikes = Google cloud uploads (Photos/Drive backup) from two family iPads

Domains that were recently registered, Devices bypassing DNS and more.  I did this all in under an hour.  Finds spike in usage patterns, DNS, compares events to threat intel. Warns me of changes made to devices that are relevant to security. 

<img width="400" height="250" alt="bout endport fedng Ewis Agent on" src="https://github.com/user-attachments/assets/2ff50474-d65d-4c06-acca-ed9897f96287" />

<img width="160" height="310" alt="image" src="https://github.com/user-attachments/assets/86447596-e252-4dfe-ae63-78bdc6f77d2a" />

<img width="375" height="292" alt="image" src="https://github.com/user-attachments/assets/6db70b41-fc0d-41de-877b-3a58cf6165bc" />


The goal of this is to rapidly grab events and triage them. Do basic research and analysis of events and provide suggestions what to do.  The correlation capabilities are what have impressed me so far.  It has tied failures in syslog to logs in the firewall and given me detailed instructions how to correct the situation.

That then became... why don't I make an app out of it..  And it built netmon (it came up with the name... not me).  The app now is a simple web app that I vibe coded in under 24 hours.  

Features:
- Users (my wife and kids) can subscribe to specific devices and get push notifications to only devices they care about of events.

- App is scanned by a number of security tools and these security tools push notifications to the app (AI watching AI)..  Updates it self weekly and scans itself and fixes those issues.

- Lets me acknowledge vulnerabilities and alarms.  

- Maps vulnerabilities and attacks to Mitre Att&ck

- Calculates a risk rating of each system

- Shows lateral movement between zones and hosts, including every admin login (SSH, RDP, PsExec/SMB, WMI, WinRM, VNC...), successful and failed. Failed logins raise the risk and trigger the 15-minute watcher.

- Correlates events with each other and with known vulnerabilities (shared hosts, IPs, accounts, time, ATT&CK). The local LLM reviews every proposed link and decides whether it is real. Click "Related" on any event to pivot.

- The local LLM reviews each event currently, but in a vacuum, not looking at other events.  A job is run periodically that correlates events first, then sends these events off to a cloud based LLM (currently Opus) and decides if it agrees with the local LLM, enriches the event details with context around the event and researches and provides links to random things it finds on the Internet.  You can optionally have the events be cleared if the events are seen as benign or expected.

- Every chart drills down to the filtered list behind it. Boxes can be collapsed and dragged into your own layout.

- The app is very mobile friendly.  My goal was really to make it primarily a mobile app with the desktop being second.


Way more stuff that it just sorta came up with.


Is this "enterprise ready"... no probably not.  I think of most tools and they add a ton of complexity because they try to support a million different things their customer... this is designed for me.  It does things in ways that likely only make sense for me.  And perhaps that is the future of software... Significantly more customized solutions rapidly developed.  If I finding it lacking a feature... I ask for it and 10 minutes later it appears.

Home-network security monitoring for the home network, run by the Hermes agent ("Lady Brains").

## Set it up yourself

Using the dashboard? See the **[user guide](docs/USER_GUIDE.md)**.

Want to run this on your own network with your own Hermes? Follow **[docs/SETUP.md](docs/SETUP.md)**: clone to `~/.hermes/netmon`, run `./setup.sh`, describe your network in a few local JSON files, add a read-only Elasticsearch key, then start the dashboard and the Hermes jobs. Everything specific to your network stays in git-ignored local files.

## Architecture

![netmon architecture: endpoints with Elastic Agent (Elastic Defend, osquery) and the Security Onion sensor feed Elasticsearch; the Hermes agent on the monitoring host runs a 15-minute watcher and a nightly pipeline that query Elasticsearch read-only and the UniFi Site Manager API, use Claude, Firecrawl for web research and a local LLM, and serve results through the netmon dashboard to family browsers and phones](docs/architecture.svg)

- **Data sources:** Elastic Agent on each endpoint (Elastic Defend + osquery, managed by Fleet) and the Security Onion sensor (Suricata, Zeek) write to Security Onion's Elasticsearch. The UniFi gateway is read through the UniFi Site Manager cloud API.
- **Hermes agent** schedules every job. The 15-minute watcher is deterministic and calls no model. The nightly run uses **Claude** for triage and web research. A **local LLM** (LM Studio) on the same machine reviews the dashboard's event correlations: the script proposes links, the model decides (see [docs/CORRELATION.md](docs/CORRELATION.md)).
- **Outputs:** SQLite state, nightly PDF reports and the HTTPS dashboard with Web Push. Nothing is posted to chat.
- **Ask Hermes:** the dashboard's chat (and the 💬 button on every finding) talks to a separate, restricted Hermes profile (`netmonchat`) over its loopback-only API. That profile has no terminal, file or memory tools. It gets web search plus `netmon_mcp.py`, a read-only MCP server with nine query tools over the netmon data (snapshots, triage, findings, devices, endpoint findings, IDS and recent alerts, reports). The MCP server opens SQLite read-only.
- Regenerate the diagram with `python3 docs/make_architecture.py`.

## Components

- `adminproto.py`: catalog of admin / lateral-movement protocols and tools, plus the session merger (network + login + endpoint evidence).
- `dashboard/app/correlate.py`, `dashboard/app/corr_llm.py`: event correlation and the local-LLM review of every proposed link ([docs/CORRELATION.md](docs/CORRELATION.md)).
- `collect.py` / `analyze.py` / `report.py`: nightly pipeline. Security Onion Elasticsearch, UniFi and Elastic Agent data go into a snapshot, which is compared against a per-device baseline and rendered as a PDF report.
- `watch.py`: 15-minute urgent watcher (new devices, IDS, threat intel, exposed ports, DNS tunnels, host anomalies, failed admin logins). It records dashboard alerts and push notifications (nothing is posted to Discord). Nightly PDFs are downloadable from the dashboard's Reports page.
- `hosts.py`, `osq.py`, `hostdetail.py`: host and endpoint telemetry (Elastic Defend, osquery).
- `mitre.py`: maps findings to MITRE ATT&CK.
- `store.py`: SQLite state store (WAL).
- `dashboard/`: HTTPS dashboard container (stdlib server, plain JS front end, Web Push).
- `sec_scan.sh`: security scan suite (Semgrep, Ruff/Bandit, pip-audit, ESLint no-unsanitized, Trivy, Hadolint, Gitleaks, ZAP).
- `netmon_mcp.py`: read-only MCP server (stdio, stdlib only) that serves netmon data to the Ask Hermes assistant.
- `ship.sh`: scan, commit and push (required for every code change).
- `weekly_rebuild.sh`: weekly container rebuild with updated libraries, a versioned image, a security scan, and in-app vulnerability alerts.

Runtime data, state, certificates and credentials are deliberately not in this repository (see `.gitignore`).
