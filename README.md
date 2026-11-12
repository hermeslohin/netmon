# Syn

<img src="docs/images/syn-hero.webp" width="720" alt="Syn, the Norse door-guard goddess, at the NETWORK GATE holding up a glowing shield that stops red and blue packet envelopes; SYN is written on her spear and breastplate">

## Network defender: the tier one security analyst for your home or small business.
*(formerly **netmon**)*

Syn queries Elasticsearch and UniFi to collect security events, then presents and explains the risk of events and vulnerabilities. It correlates related events into one story, has an AI analyst label each story suspicious, benign or expected, and explains it. Users (my wife and kids) subscribe to devices and get a phone notification only when the AI's final verdict on their device is suspicious, in plain language with what to do. IDS alerts and host alerts are streamed every 15 seconds; the rest is pulled once per event window (default 10 minutes).

## About the name
In Norse myth, **Syn** is the goddess who guards the doors of the hall: she shuts them against those who should not enter, and she is called on to defend people in disputes and at trial. That is the job this app does: a tier-one analyst that watches the door of your network, turns away what does not belong, and takes your side when something looks wrong.

The name is also a nod to networking: **SYN** is the first packet of every TCP connection, and **SYN-ACK** is the reply that lets it in or not. Every connection starts at Syn's door.

The project was called **netmon** until November 2026. The GitHub repository was renamed from `netmon` to `syn` at the same time (GitHub redirects the old URL). Internal names still use `netmon` for now: the install folder (`~/netmon`), the `netmon-scheduler` and `netmon-broker` services, the `netmon-dashboard` container, `netmon.db` and the `logs-netmon` audit index.

## Background
I have recently been working with an AI coding agent... and it is wild what it can do along with an LLM.  As my first test I started having it generate reports for security finding of my home network.  It pulls this information from Security Onion Solutions, LLC

Elastic and Unifi API.  For host collection it uses the builtin Elastic Fleet and OsQuery.  It started off generating a report every 24 hours with a cloud LLM and every 15 minutes it runs code and checks for "critical" events using a local LLM with a much smaller model.  It does really well at presenting useful information on security and immediately gave me actionable intel like:

Admin access between zones (recurring, awaiting allow rules): admin laptop → server 22/tcp, server 9090/tcp; server → AI host 22/tcp

iPad upload spikes = Google cloud uploads (Photos/Drive backup) from two family iPads

Domains that were recently registered, Devices bypassing DNS and more.  I did this all in under an hour.  Finds spike in usage patterns, DNS, compares events to threat intel. Warns me of changes made to devices that are relevant to security. 

<img width="400" height="250" alt="Endpoint findings from Elastic Agent" src="https://github.com/user-attachments/assets/2ff50474-d65d-4c06-acca-ed9897f96287" />

<img width="160" height="310" alt="image" src="https://github.com/user-attachments/assets/86447596-e252-4dfe-ae63-78bdc6f77d2a" />

<img width="375" height="292" alt="image" src="https://github.com/user-attachments/assets/6db70b41-fc0d-41de-877b-3a58cf6165bc" />


The goal of this is to rapidly grab events and review them. Do basic analysis of events and, on request, research them and provide suggestions what to do.  The correlation capabilities are what have impressed me so far.  It has tied failures in syslog to logs in the firewall and given me detailed instructions how to correct the situation.

That then became... why don't I make an app out of it..  And it built netmon (it came up with that name... not me; it is now called Syn, see About the name).  The app is now a web app.  

Features:
- Users (my wife and kids) can subscribe to specific devices and get push notifications only for the devices they care about. A notification waits for the AI's verdict and is sent to them only when the verdict is suspicious. It is one plain-language line ("Kitchen tablet: possible phishing or scam website visited. Look out - tap for what to do."), and tapping it shows advice written for the person using the device: one action (nothing to do, keep an eye out, update, change a password, stop visiting a site or using an app, stop using the device) and a short message that names the site or app and says what to do. Admins and defenders still see the raw alert, and they get a fail-safe push if the AI is down or slow.

- Events are correlated and triaged.  The Local AI maintains notes about artifacts like hosts, users, etc to later refer to when making decisions.  So as an example it is able to make a note that this computer often uses discord and therefore it isn't a likely C2 issue.  Notes are maintained by the LLM, but users can also add their own notes to provide context.
 
- Maps vulnerabilities and attacks to Mitre Att&ck

- Calculates a risk rating of each system ([how risk is scored](docs/RISK_SCORING.md))

- Watches one or more Kubernetes clusters: container logs, events and API server metrics from Elasticsearch, plus (with a read-only account) the CIS benchmark, a cluster map and container image updates mapped to CVEs; see [docs/KUBERNETES.md](docs/KUBERNETES.md)
  
- Role-based access: Admin, Network defender (view-only for settings) and User (only their assigned devices); see [docs/ACCESS_CONTROL.md](docs/ACCESS_CONTROL.md)

- Lists the accounts seen on the network (Network > Users) with where, how and when each is normally used, and turns those patterns into host notes the event reviewer reads. The event reviewer also writes expected-behavior notes for links it judges normal, and classifies events as suspicious, benign or expected.

- Shows lateral movement between zones and hosts, including every admin login (SSH, RDP, PsExec/SMB, WMI, WinRM, VNC...), successful and failed. Failed logins raise the risk and trigger the watcher (every event window, default 10 min).

- **Correlates events into stories.** Events are linked to each other and to known vulnerabilities when they share something concrete (a host, an external IP, a domain, an account), scored by how rare that shared thing is, by time and by ATT&CK technique. Nothing is linked just for happening at the same time, and only events within one event window (default 10 min) of each other can link. The script only proposes links; a decision model (System One API, e.g. Cloudflare clef) answers "are these two related?" for each one, and that answer is the verdict. Click "Related" on any event to pivot through the chain.

- **Reviews each correlated group as a whole, not each event in a vacuum.** Linked events form a correlated group. Once the group settles (its newest event is one window old, every link is decided, and no late Elasticsearch arrival can still join it), the event reviewer (a local LLM) makes one call for the whole group and labels every member suspicious, benign or expected with a confidence. Until then the events show **⏳ Pending review · settles at HH:MM**. A high-severity event gets a provisional label right away so alarms don't wait, and a group is reviewed again only when it gains a member. Before deciding, the reviewer can run a few read-only Elasticsearch searches and web look-ups (only public facts leave the network; a search with a LAN IP or internal name is refused), and cites what it read.

- **Writes an analyst's report for each event:** *Why it fired* (the detector or feed, and what the device actually did: domains, TLS server names, certificates, owners) and *Verdict* (the deciding reason, what to check). Click any verdict badge for the full pop-up: label, confidence, reason, sources, the group reviewed together and any auto-close.

- **People outrank the AI.** Mark an event (or just its device, signature, IP, domain, process or account) expected, benign or suspicious, and the reviewer is told to follow you; your verdict replaces its label unless the reviewer is at least 90-95% sure otherwise, or a strong threat-intel hit (a listed domain or file hash) makes it suspicious. It also reuses earlier notes for repeats.

- **Threat intel with judgement.** Indicators come from OpenCTI and the intel lists. An IP-only hit is weak on its own (weaker still on a CDN or shared host), so the hit carries the site names the device actually used and the reviewer judges the domain, not just the address. Sightings are reported back to OpenCTI.

- **Auto-close** (optional, off by default): events the AI calls expected or benign are checked off within about 10 seconds of the verdict (at 80% confidence or more by default), behind guard rails. Protected categories (admin access, threat intel, new devices, C2 signs...) always need a person, and a device with a suspicious event in the last 24 hours is held: nothing on it is auto-closed.

- **Send to research** on any event asks a cloud LLM (whichever provider and model you pick on the AI pipeline pages) whether it agrees with the reviewer, enriches the event with context and researches it on the Internet with links. Nothing is researched on a schedule, to keep token cost down.

- **Policy per device class** (IoT, phones, servers... discovered from UniFi and editable): which classes get new-domain and new-certificate findings, and per-class thresholds for upload and volume spikes, scans and beacons, with auto-tune.

- Every chart drills down to the filtered list behind it. Boxes can be collapsed and dragged into your own layout.

- The app is very mobile friendly.  My goal was really to make it primarily a mobile app with the desktop being second.


Way more stuff that it just sorta came up with.


Is this "enterprise ready"... no probably not.  I think of most tools and they add a ton of complexity because they try to support a million different things their customer... this is designed for me.  It does things in ways that likely only make sense for me.  And perhaps that is the future of software... Significantly more customized solutions rapidly developed.  If I finding it lacking a feature... I ask for it and 10 minutes later it appears.

Home-network security monitoring for the home network. Syn runs on its own: a small scheduler on the monitoring host runs the jobs, and you bring an API key for any OpenAI-compatible or Anthropic provider (or a local OpenAI-compatible model server) for the AI parts.

## Set it up yourself

Using the dashboard? See the **[user guide](docs/USER_GUIDE.md)**. Investigating something? See the **[investigation playbooks](docs/PLAYBOOKS.md)** (troubleshooting, DNS tunnelling, lateral movement, insider threat and more).

Want to run this on your own network? Follow **[docs/SETUP.md](docs/SETUP.md)**: clone it anywhere (e.g. `~/netmon`), run `./setup.sh`, describe your network on the dashboard's Settings page (stored in SQLite, never in git), add a read-only Elasticsearch key, start the dashboard and the two host services (`netmon-broker`, `netmon-scheduler`), then add an AI provider and pick models on the AI pipeline pages. Everything specific to your network stays in git-ignored local files.

## Architecture

![netmon architecture: endpoints with Elastic Agent (Elastic Defend, osquery) and the Security Onion sensor feed Elasticsearch; the netmon scheduler on the monitoring host runs a watcher (every event window, default 10 min) and the review job, which query Elasticsearch read-only and the UniFi Site Manager API and use a cloud AI provider of your choice with web search, plus a local LLM, pull threat-intel indicators from OpenCTI and report sightings back to it, and serve results through the netmon dashboard to family browsers and phones; the dashboard writes its audit log of user actions and AI conversations to the Elasticsearch index logs-netmon](docs/architecture.svg)

- **Data sources:** Elastic Agent on each endpoint (Elastic Defend + osquery, managed by Fleet) and the Security Onion sensor (Suricata, Zeek) write to Security Onion's Elasticsearch. The UniFi gateway is read through the UniFi Site Manager cloud API.
- **Scheduler** (`scheduler.py`, systemd user service `netmon-scheduler`) runs every job: the **event stream** (`stream.py`, always running: Suricata alerts, watched syslog patterns, Elastic Defend and Security Onion detections, read every 15 s by arrival time), the watcher (the full Elasticsearch pull, once per event window, default 10 min, and the fallback if the stream is down), the review job (`review.py`) every 5 min to 24 h as set on the Configuration page, and the weekly rebuild. The stream and the watcher are deterministic and call no model; both share one 12-hour mute, so each detection is stored once. Late Elasticsearch arrivals are read by arrival time and keep their event time, so they are never dropped. The review job collects and analyzes the logs, then its event reviewer copies matching earlier notes; everything else waits in the queue. **Event research** (`research.py`) runs only when a person clicks **Send to research**: it uses the research model chosen on **AI pipeline configuration → Models**, with web search (DuckDuckGo by default; Firecrawl, Brave or Tavily with a key) and $ / token caps per research run and per day. It is never scheduled.
- **Correlation review** (inside the dashboard, `corr_llm.py`): a **local LLM** (any OpenAI-compatible server) plus a decision model (System One API) on the same machine review the event correlations. The script proposes links, the decision model decides them, and once a correlated group settles the local LLM labels the whole group suspicious, benign or expected in one call and writes the analyst report (a person's verdict outweighs that label). A new streamed alert wakes the reviewer within 5 s, so a stream-only group is labelled about a minute after its window ends. Suspicious medium / high events become alarms; the push gate (`pushgate.py`) holds the phone push until the group's verdict is in. See [docs/CORRELATION.md](docs/CORRELATION.md).
- **Host broker** (`host_broker.py`, systemd user service `netmon-broker`, loopback only, bearer key): lets the dashboard container ask for a custom time-range collection, start `research.py` for one event when someone clicks Send to research, and run bounded read-only Elasticsearch look-ups for the event reviewer. The Elasticsearch key stays on the host.
- **Outputs:** SQLite state and the HTTPS dashboard with Web Push. Nothing is posted to chat.
- **Ask AI:** the dashboard's chat (and the 💬 button on every finding) runs inside the dashboard (`dashboard/app/chat.py`) with the chat model chosen on AI pipeline configuration → Models. It has no terminal, file or memory tools: only web search / page fetch plus the read-only `netmon_*` query tools from `netmon_mcp.py` over the netmon data (overview, findings, devices, endpoint findings, IDS and recent alerts, notes). Those tools open SQLite read-only.
- **Audit log:** every user action (sign-ins, page views, check-offs, notes, settings, user changes, refused requests) and every conversation between netmon and an AI model (Ask AI, the event reviewer, the review job and event research; prompt, answer, model, tokens) is written to Security Onion's Elasticsearch, index `logs-netmon`, with an append-and-read-only key. Admins read it on **More → Audit log**. Secrets are redacted. See [docs/AUDIT_LOG.md](docs/AUDIT_LOG.md).
- **More detail:** processes, trust boundaries, data flow, AI stages and storage are in **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)**.
- Regenerate the diagram with `python3 docs/make_architecture.py`.

## Components

- `adminproto.py`: catalog of admin / lateral-movement protocols and tools, plus the session merger (network + login + endpoint evidence).
- `dashboard/app/correlate.py`, `dashboard/app/corr_llm.py`: event correlation (candidate links, artifacts) and the correlation review: decision-model link verdicts, then one event reviewer call per settled correlated group ([docs/CORRELATION.md](docs/CORRELATION.md)). `window.py` holds the event window and the stream / watcher bookmarks that decide when a group has settled.
- `dashboard/app/autoclose.py`: auto-close of expected / benign events with its guard rails, applied within ~10 s of a new verdict.
- `dashboard/app/pushgate.py`, `dashboard/app/plainmsg.py`, `dashboard/app/advice.py`: the push gate (pushes wait for the group verdict; Users get only final suspicious verdicts), the plain-language alert line for Users, and the advice for the device owner.
- `collect.py` / `analyze.py`: collection and analysis. Security Onion Elasticsearch, UniFi and Elastic Agent data go into a snapshot, which is compared against a per-device baseline.
- `review.py`: the review job: collect + analyze, then the event reviewer copies earlier notes for repeat events; the rest waits in the queue. Schedule, on/off and per-category modes are in `review_cfg.py`.
- `research.py`: event research, started only by Send to research (`--event ID`). Its model, $ and token caps, web and Elasticsearch switches are in `research_cfg.py`. Both are editable by an admin on the AI pipeline pages and share `aijob.py` (tools, budget, conversation logs); the event reviewer's limits (event-type matrix, time window, never-send rules, event classification) are in `corr_llm.py`, editable by admins and network defenders; the provider-agnostic tool loop is `agent.py` + `llm_providers.py`; web search and fetch in `webtools.py`.
- `scheduler.py`: runs the event stream, the watcher, the review job and the weekly rebuild (systemd user service).
- `stream.py`, `streamchecks.py`: the event stream: tails Suricata alerts, watched syslog and host alerts every 15 s by arrival time (`python3 stream.py status`).
- `host_broker.py`: loopback-only helper for the dashboard (time-range collection, starting event research, read-only Elasticsearch look-ups).
- `watch.py`: urgent watcher (Elasticsearch pull once per event window, default 10 min) (new devices, IDS, threat intel, exposed ports, DNS tunnels, host anomalies, failed admin logins). It records dashboard alerts and push notifications (nothing is posted to Discord).
- `hosts.py`, `osq.py`, `hostdetail.py`: host and endpoint telemetry (Elastic Defend, osquery).
- `mitre.py`: maps findings to MITRE ATT&CK.
- `store.py`: SQLite state store (WAL): state tables, JSON documents (snapshots, time ranges, job state) and the settings (site, policy, host policy, known benign) that you edit on the dashboard's Settings page. No JSON state or settings files.
- `dashboard/`: HTTPS dashboard container (stdlib server, plain JS front end, Web Push).
- `sec_scan.sh`: security scan suite (Semgrep, Ruff/Bandit, pip-audit, ESLint no-unsanitized, Trivy, Hadolint, Gitleaks, ZAP).
- `netmon_mcp.py`: the read-only netmon query tools used by Ask AI; also runs as a stdio MCP server (stdlib only) for any MCP client.
- `ship.sh`: development helper: security scan, secret gate, commit and push, optional deploy. Not needed to run netmon.
- `weekly_rebuild.sh`: weekly container rebuild with updated libraries, a versioned image, a security scan, and in-app vulnerability alerts.

Runtime data, state, certificates and credentials are deliberately not in this repository (see `.gitignore`).
