# netmon
## The tier one security analyst for your home or small business.
Queries Elasticsearch and Unifi to collect security events.  Presents and explains risk of events and vulnerabilities.  Allows users (my wife and kids) to subscribe to devices and get notifications of security related events near real time (Job runs every 15 minutes)

## Background
I have recently been working with an AI coding agent... and it is wild what it can do along with an LLM.  As my first test I started having it generate reports for security finding of my home network.  It pulls this information from Security Onion Solutions, LLC

Elastic and Unifi API.  For host collection it uses the builtin Elastic Fleet and OsQuery.  It started off generating a report every 24 hours with a cloud LLM and every 15 minutes it runs code and checks for "critical" events using a local LLM with a much smaller model.  It does really well at presenting useful information on security and immediately gave me actionable intel like:

Admin access between zones (recurring, awaiting allow rules): admin laptop → server 22/tcp, server 9090/tcp; server → AI host 22/tcp

iPad upload spikes = Google cloud uploads (Photos/Drive backup) from two family iPads

Domains that were recently registered, Devices bypassing DNS and more.  I did this all in under an hour.  Finds spike in usage patterns, DNS, compares events to threat intel. Warns me of changes made to devices that are relevant to security. 

<img width="400" height="250" alt="Endpoint findings from Elastic Agent" src="https://github.com/user-attachments/assets/2ff50474-d65d-4c06-acca-ed9897f96287" />

<img width="160" height="310" alt="image" src="https://github.com/user-attachments/assets/86447596-e252-4dfe-ae63-78bdc6f77d2a" />

<img width="375" height="292" alt="image" src="https://github.com/user-attachments/assets/6db70b41-fc0d-41de-877b-3a58cf6165bc" />


The goal of this is to rapidly grab events and triage them. Do basic research and analysis of events and provide suggestions what to do.  The correlation capabilities are what have impressed me so far.  It has tied failures in syslog to logs in the firewall and given me detailed instructions how to correct the situation.

That then became... why don't I make an app out of it..  And it built netmon (it came up with the name... not me).  The app now is a simple web app that I vibe coded in under 24 hours.  

Features:
- Users (my wife and kids) can subscribe to specific devices and get push notifications to only devices they care about of events.

- App is scanned by a number of security tools and these security tools push notifications to the app (AI watching AI)..  Updates it self weekly and scans itself and fixes those issues.

- Lets me acknowledge vulnerabilities and alarms.  

- Maps vulnerabilities and attacks to Mitre Att&ck

- Calculates a risk rating of each system ([how risk is scored](docs/RISK_SCORING.md))
- Role-based access: Admin, Network defender (view-only for settings) and User (only their assigned devices); see [docs/ACCESS_CONTROL.md](docs/ACCESS_CONTROL.md)

- Shows lateral movement between zones and hosts, including every admin login (SSH, RDP, PsExec/SMB, WMI, WinRM, VNC...), successful and failed. Failed logins raise the risk and trigger the 15-minute watcher.

- Correlates events with each other and with known vulnerabilities (shared hosts, IPs, accounts, time, ATT&CK). The local LLM reviews every proposed link and decides whether it is real. Click "Related" on any event to pivot.

- The local LLM reviews each event currently, but in a vacuum, not looking at other events.  A job is run periodically that correlates events first, then sends these events off to a cloud based LLM (whichever provider and model you pick on the AI review page) and decides if it agrees with the local LLM, enriches the event details with context around the event and researches and provides links to random things it finds on the Internet.  You can optionally have the events be cleared if the events are seen as benign or expected.

- Every chart drills down to the filtered list behind it. Boxes can be collapsed and dragged into your own layout.

- The app is very mobile friendly.  My goal was really to make it primarily a mobile app with the desktop being second.


Way more stuff that it just sorta came up with.


Is this "enterprise ready"... no probably not.  I think of most tools and they add a ton of complexity because they try to support a million different things their customer... this is designed for me.  It does things in ways that likely only make sense for me.  And perhaps that is the future of software... Significantly more customized solutions rapidly developed.  If I finding it lacking a feature... I ask for it and 10 minutes later it appears.

Home-network security monitoring for the home network. netmon runs on its own: a small scheduler on the monitoring host runs the jobs, and you bring an API key for any OpenAI-compatible or Anthropic provider (or a local LM Studio server) for the AI parts.

## Set it up yourself

Using the dashboard? See the **[user guide](docs/USER_GUIDE.md)**.

Want to run this on your own network? Follow **[docs/SETUP.md](docs/SETUP.md)**: clone it anywhere (e.g. `~/netmon`), run `./setup.sh`, describe your network in a few local JSON files, add a read-only Elasticsearch key, start the dashboard and the two host services (`netmon-broker`, `netmon-scheduler`), then add an AI provider and pick models on the AI review page. Everything specific to your network stays in git-ignored local files.

## Architecture

![netmon architecture: endpoints with Elastic Agent (Elastic Defend, osquery) and the Security Onion sensor feed Elasticsearch; the netmon scheduler on the monitoring host runs a 15-minute watcher and the research job, which query Elasticsearch read-only and the UniFi Site Manager API and use a cloud AI provider of your choice with web search, plus a local LLM, and serve results through the netmon dashboard to family browsers and phones; the dashboard writes its audit log of user actions and AI conversations to the Elasticsearch index logs-netmon](docs/architecture.svg)

- **Data sources:** Elastic Agent on each endpoint (Elastic Defend + osquery, managed by Fleet) and the Security Onion sensor (Suricata, Zeek) write to Security Onion's Elasticsearch. The UniFi gateway is read through the UniFi Site Manager cloud API.
- **Scheduler** (`scheduler.py`, systemd user service `netmon-scheduler`) runs every job: the 15-minute watcher, the research job (`review.py`) every 30 min to 24 h as set on the Configuration page, and the weekly rebuild. The watcher is deterministic and calls no model. The research job uses the AI provider and model chosen on **AI review → Models** for triage, the reviewer, on-request event research and the daily news briefing, with web search (DuckDuckGo by default; Firecrawl, Brave or Tavily with a key) and $ / token caps per run and per day. The first run after 05:00 UTC each day also writes the PDF report. A **local LLM** (LM Studio) on the same machine reviews the dashboard's event correlations: the script proposes links, the model decides (see [docs/CORRELATION.md](docs/CORRELATION.md)).
- **Host broker** (`host_broker.py`, systemd user service `netmon-broker`, loopback only, bearer key): lets the dashboard container ask for a custom time-range collection and run bounded read-only Elasticsearch look-ups for the correlation reviewer. The Elasticsearch key stays on the host.
- **Outputs:** SQLite state, daily PDF reports and the HTTPS dashboard with Web Push. Nothing is posted to chat.
- **Ask AI:** the dashboard's chat (and the 💬 button on every finding) runs inside the dashboard (`dashboard/app/chat.py`) with the chat model chosen on AI review → Models. It has no terminal, file or memory tools: only web search / page fetch plus the read-only `netmon_*` query tools from `netmon_mcp.py` over the netmon data (overview, triaged alarms, findings, devices, endpoint findings, IDS and recent alerts, notes, reports). Those tools open SQLite read-only.
- **Audit log:** every user action (sign-ins, page views, check-offs, notes, settings, user changes, refused requests) and every conversation between netmon and an AI model (Ask AI, the correlation reviewer, model comparisons, the research job; prompt, answer, model, tokens) is written to Security Onion's Elasticsearch, index `logs-netmon`, with an append-and-read-only key. Admins read it on **More → Audit log**. Secrets are redacted. See [docs/AUDIT_LOG.md](docs/AUDIT_LOG.md).
- Regenerate the diagram with `python3 docs/make_architecture.py`.

## Components

- `adminproto.py`: catalog of admin / lateral-movement protocols and tools, plus the session merger (network + login + endpoint evidence).
- `dashboard/app/correlate.py`, `dashboard/app/corr_llm.py`: event correlation and the local-LLM review of every proposed link ([docs/CORRELATION.md](docs/CORRELATION.md)).
- `collect.py` / `analyze.py` / `report.py`: collection, analysis and PDF. Security Onion Elasticsearch, UniFi and Elastic Agent data go into a snapshot, which is compared against a per-device baseline and rendered as a PDF report.
- `review.py`: the research job: collect + analyze, then an AI triage conversation with narrow read-only tools and the reviewer (copies earlier notes); events are researched only when a person clicks Send to research (`--event`), and on the daily PDF run a news briefing and `report.py`. Settings (model, schedule, $ and token caps, research / review / skip per event category - default everything but low/info researched; review limits and never-send rules in `corr_llm.py`, editable by admins and network defenders) in `research_cfg.py`, editable by an admin on the AI review page; the provider-agnostic tool loop is `agent.py` + `llm_providers.py`; web search and fetch in `webtools.py`.
- `scheduler.py`: runs the watcher, the research job and the weekly rebuild (systemd user service).
- `host_broker.py`: loopback-only helper for the dashboard (time-range collection, read-only Elasticsearch look-ups).
- `watch.py`: 15-minute urgent watcher (new devices, IDS, threat intel, exposed ports, DNS tunnels, host anomalies, failed admin logins). It records dashboard alerts and push notifications (nothing is posted to Discord). Daily PDFs are downloadable from the dashboard's Reports page.
- `hosts.py`, `osq.py`, `hostdetail.py`: host and endpoint telemetry (Elastic Defend, osquery).
- `mitre.py`: maps findings to MITRE ATT&CK.
- `store.py`: SQLite state store (WAL).
- `dashboard/`: HTTPS dashboard container (stdlib server, plain JS front end, Web Push).
- `sec_scan.sh`: security scan suite (Semgrep, Ruff/Bandit, pip-audit, ESLint no-unsanitized, Trivy, Hadolint, Gitleaks, ZAP).
- `netmon_mcp.py`: the read-only netmon query tools used by Ask AI; also runs as a stdio MCP server (stdlib only) for any MCP client.
- `ship.sh`: development helper: security scan, secret gate, commit and push, optional deploy. Not needed to run netmon.
- `weekly_rebuild.sh`: weekly container rebuild with updated libraries, a versioned image, a security scan, and in-app vulnerability alerts.

Runtime data, state, certificates and credentials are deliberately not in this repository (see `.gitignore`).
