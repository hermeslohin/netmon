// Generated: info texts for the (i) button on each dashboard box (cardinfo_ui.js). Key: "view|normalised title".
window.CARD_INFO = {
"audit|Audit log storage": {
"source": "Dashboard settings (integrations.json, section audit) and a live count from the Security Onion Elasticsearch index logs-netmon.",
"use": "Green 'connected' means entries are being written. If Elasticsearch is unreachable or no key is set, entries wait on the dashboard and are sent automatically later. The key only needs create_doc and read on logs-netmon. The two checkboxes switch the background reviewer's and the AI Research job's entries on or off independently.",
"what": "Where the audit log is stored and whether the dashboard can write to it."
},
"audit|Filters": {
"source": "The audit log index (logs-netmon); the lists show the users, actions and models seen in the chosen time range.",
"use": "Pick a type, time range, user, action, outcome or model, or search the text (also searches prompts and AI answers). Filters are kept in the address, so a filtered view can be bookmarked.",
"what": "Narrows the audit log entries below."
},
"audit|Activity over time": {
"source": "Audit log entries per time bucket, split into user actions and AI conversations.",
"use": "Spikes show bursts of activity (many sign-ins, a big review run). Use it to choose a narrower time range.",
"what": "Bar chart of audit activity."
},
"audit|Entries": {
"source": "Elasticsearch index logs-netmon, newest first, 50 per page.",
"use": "Click a row to see all details below. Failed sign-ins and refused requests show outcome 'failure'. Background jobs appear as user 'netmon (...)'.",
"what": "Every user action and every conversation between the dashboard and an AI model."
},
"audit|Entry details": {
"source": "The full audit document from Elasticsearch.",
"use": "For AI conversations this shows the instructions (system prompt), the exact prompt the app sent, the model's answer, tokens and time. Passwords and keys are shown as [redacted] - they are never stored.",
"what": "Everything recorded for the selected entry."
},
"account|Change password": {
"source": "The dashboard user store (auth.py). New passwords must be at least 10 characters and differ from the current one; the meter rates length and character variety.",
"use": "Enter your current password and the new one twice. Your other signed-in browsers and phones are signed out, this one stays signed in. A long passphrase is strongest.",
"what": "Self-service form to change your own dashboard password."
},
"aireview|All verdicts": {
"source": "Correlation verdict totals from the AI reviewer and manual overrides stored by the dashboard.",
"use": "A healthy mix is normal. If almost everything is confirmed or rejected, spot-check the decisions list. Click a slice to filter the Decisions table to that verdict.",
"what": "Doughnut of all stored link decisions split into Confirmed (related), Rejected (not related) and Set by a person."
},
"aireview|AI Correlation job": {
"source": "The correlation job (review.py), started by the netmon scheduler on a grid anchored at 05:00 UTC (the first run after 05:00 UTC also writes the PDF). The interval is set on this card; settings are in the netmon store, run state in research_job.json, notes and run log from enrich.py.",
"use": "Status should be Idle or Running with no failure streak. Set Run every to change how often it runs (5 to 1440 minutes; saves automatically). Run now starts a run within 20 seconds; Pause stops scheduled runs. Expand the run summary to read the latest findings.",
"what": "Status of the scheduled correlation job: each run collects and analyzes the latest logs, correlates events, and has the AI reviewer decide the proposed links and queue events for research. Shows health, model, schedule, last run, link verdicts, note coverage and recent runs. Events are researched only on request (Send to research), not on the schedule."
},
"aireview|Time and tokens per research job and Ask AI chat": {
"source": "Token counts reported by the AI provider for every call of each run, recorded by review.py (per event: the tokens of its research batch divided over the batch's events); cost estimated from the prices entered for the model under AI providers. Ask AI chat turns are recorded by chat.py in chat.db (one row per message: tokens, cost, time spent answering).",
"use": "Watch for runs that take much longer or use far more tokens than usual. Cache re-reads are hidden by default; click their legend entry to show them. Picking another research model in the Models box previews its cost.",
"what": "Stacked bars of the tokens per day used by the research job and by Ask AI chat (new input, cache writes, output; grey when the provider gave no cache split) with run time and estimated cost as lines (the dotted yellow line is the chat's share of the cost; hover a day for the research runs / chat turns split), plus a list of each researched event with its tokens and cost (a batch of events shares one conversation, so its use is split evenly)."
},
"aireview|Research job limits": {
"source": "AI Research job settings in the netmon store (research_cfg.py), enforced by review.py before every model call.",
"use": "Set a $ cap per run a bit above the usual run cost and a daily cap as a backstop. The token cap works even when no price is entered. Fewer research batches make runs cheaper; left-over events are picked up by the next run.",
"what": "Cost and size limits of the scheduled AI Research job: $ per run, $ per day, tokens per run and event-research batches per run."
},
"aireview|Research lookback window": {
"what": "How many hours of logs each run of the AI Research job collects and reviews. The daily PDF run always covers 24 hours.",
"source": "Saved in the netmon store and read by the collector when the AI Research job starts (collect.py auto).",
"use": "Set it a little longer than the run interval to cut cost per run without gaps. Shorter than the interval leaves hours unreviewed.",
},
"aireview|Decisions": {
"source": "Proposed links from correlate.py, judged by the corr_llm.py reviewer or the AI Research job, plus manual overrides; stored in the netmon store.",
"use": "Use the Show filters (e.g. low confidence under 70%) to find doubtful calls. Override with ✓ or ✗, ↻ to ask the model again, or ⇄ to compare up to 4 models on one decision and adopt the best answer.",
"what": "Every link decision (newest 3,000): verdict, confidence, the event, what it was linked to and the model's reason. Badges show which were set by a person."
},
"aireview|Models": {
"source": "Dashboard AI configuration: local models are listed from LM Studio, cloud models from the AI providers box. Only an admin can change them.",
"use": "Pick a model and press Save. Local models are free but slower and weaker at web research; cloud models are billed per call. Use the ⇄ compare button on a decision below to test models before switching.",
"what": "Which AI model each AI job uses: the correlation reviewer (decides every proposed link between events), the scheduled AI Research job (reviewer) and on-request event research and the Ask AI chat."
},
"aireview|AI providers": {
"source": "Admin-entered providers in the dashboard's state volume (llm_providers.json, readable only by netmon).",
"use": "Add provider: name, type (OpenAI / OpenAI-compatible, or Anthropic), optional base URL, API key, and the models to offer (Fetch from provider lists what the key can use; add prices after a model id for cost estimates). Test checks the key without using tokens. ✎ edits (leave the key empty to keep it), ✕ deletes. Calls per hour caps single calls if something loops.",
"what": "AI services reached with an API key, any number of them. Their models can be picked for the correlation reviewer, the AI Research job, the chat and in every Compare dialog."
},
"aireview|Reviewer": {
"source": "corr_llm.py worker inside the dashboard, reviewing links proposed by correlate.py, with the model chosen in the Models card (local LM Studio or an AI provider). The AI Research job's verdicts override it.",
"use": "The progress bar should reach 100% shortly after a new snapshot. An error, Off state or a stuck queue means Related links are not being filtered; check LM Studio is running or switch model in the Models card.",
"what": "Status of the correlation reviewer that decides whether each proposed link between two events is real: model, provider, endpoint, parallel workers, current activity and how much of this snapshot is reviewed."
},
"aireview|Verdicts per hour": {
"source": "Stored correlation verdicts from the corr_llm.py reviewer (and AI Research job re-reviews) in the netmon store.",
"use": "Bursts after each snapshot (twice a day) are normal; long gaps while links are awaiting review suggest the model is down or stalled.",
"what": "Bar chart of how many link decisions the reviewer made in each of the last 24 hours."
},
"alerts|Recent alerts": {
"source": "The 15-minute urgent watcher (watch.py, fixed rules, no AI): Suricata severity-1 or malware/C2/exploit alerts, new devices, new internet-facing ports, threat-intel hits, DNS tunnelling, endpoint problems and failed admin logins. Repeats are muted for 12 h.",
"use": "'investigate' needs a look now; 'urgent' is serious but often explainable. Use Related to see surrounding events and 💬 Ask AI for help. Mark all read clears the counter; 'only my devices' follows your device selection.",
"what": "Urgent alerts from the last 30 days, newest first, with level and text. Unread ones are bold."
},
"attack|All mapped items": {
"source": "mitre.py mapping of Suricata IDS, detections, baseline findings, endpoint findings, fix-list issues and UniFi data for the selected snapshot.",
"use": "Sort by Type to see observed items first. Checked-off items are shown struck through. Use 💬 Ask AI on a row to get an explanation of the technique in your context.",
"what": "Every alert, finding, vulnerability or misconfiguration in this snapshot that was mapped to an ATT&CK technique, with its source, host and the reason for the mapping. When a technique is selected this card lists only its items."
},
"attack|Matrix": {
"source": "mitre.py: Suricata rule metadata and Security Onion / Elastic Defend technique fields, plus a curated rule table for netmon's own findings, fix-list items and UniFi.",
"use": "Observed cells are the ones to look at first. Click a technique to filter the item list below to it and see why it was mapped; exposure cells point at hardening work.",
"what": "The MITRE ATT&CK Enterprise matrix, one column per tactic, showing only techniques that something in this snapshot maps to. Colour shows observed (behaviour seen), exposure only (a weakness that enables it) or all items checked off."
},
"attack|Not mapped": {
"source": "Leftovers from the mitre.py mapping pass over alerts, findings and issues.",
"use": "Usually harmless informational items. If something security-relevant shows up here repeatedly, add a regex rule to the RULES table in mitre.py so it maps.",
"what": "Items in this snapshot that no ATT&CK mapping rule matched, so they do not appear in the matrix."
},
"checked|Checked items": {
"source": "Check-offs stored in the netmon SQLite store, including auto-closes when the AI research verdict is expected or benign (if enabled on the Configuration page).",
"use": "Review 'still present' items now and then to make sure they really are fine, and check auto-closed ones. Uncheck an item to restore it to its original list.",
"what": "Everything checked off elsewhere (baseline findings, fix-list items, endpoint findings, gateway events), newest first, with whether each is still present, fixed or absent in the selected snapshot. Items closed automatically show an 'auto-closed' AI verdict badge."
},
"checked|Cleared segmentation": {
"source": "Your check-offs, saved in the netmon SQLite store on the dashboard host, matched against the violations analyze.py found using the zone rules in the network policy (More → Settings).",
"use": "Cleared flows are hidden from Posture, Fix list, Risk, correlation and the PDF. Uncheck one to bring it back. To make an exception permanent for everyone and the nightly analysis, add it to the network policy (More → Settings) instead.",
"what": "Network segmentation violations (traffic between zones that policy says should not happen) that you marked as expected, with why they were flagged and whether they still occur."
},
"devices|All hosts": {
"source": "Zeek conn and DNS logs from Security Onion for the last 24 h (collect.py), names from DHCP/DNS and the DHCP-export inventory, zones and classes from the network policy (More → Settings), finding counts from analyze.py baselines.",
"use": "Sort by Total or Ext peers to spot unusually busy devices; use the Known/Unknown/high-findings tiles above to filter. Click a row to open the per-host page with full detail, findings and charts.",
"what": "Every internal host netmon has ever seen (the long-term device registry), with name, MAC, vendor, zone, device class, bytes sent/received, connections, external peers, DNS queries, finding count and last seen time. Traffic columns cover the selected time range; hosts with no traffic in it show a 'not in range' badge and zero counts. An 'unknown' badge marks devices not in the inventory; 'agent' marks hosts running Elastic Agent."
},
"devices|Gateway clients first seen in window": {
"source": "UniFi gateway API (known and currently online clients), filtered on the gateway's own first-seen timestamp falling inside the snapshot window.",
"use": "Usually empty. An entry means a new device joined the network: confirm it is yours (new phone, guest, gadget). Randomised MAC addresses on phones can also appear here after a privacy-MAC change.",
"what": "Clients the gateway saw for the first time ever during the last 24-hour window, with MAC, IP, name and first-seen time."
},
"devices|Gateway clients not in inventory": {
"source": "UniFi gateway API client list (unifi.py), compared against the MAC table in the home-network-devices inventory. Refreshed with each collection run (twice a day).",
"use": "Complements the Zeek-based unknown list: it also catches devices that are connected but quiet. Recognise and name each one in the inventory; an unidentified client on a trusted network is worth checking or blocking at the gateway.",
"what": "Clients currently connected to the gateway (wired or Wi-Fi) whose MAC is not in the home device list, with name, MAC and network."
},
"devices|New devices": {
"source": "analyze.py compares each device (keyed by MAC, else IP) against the device registry in the netmon store, which remembers first and last sighting of everything Zeek has ever seen. A first-ever sighting also raises a 'new-device' finding (high if not in inventory, medium if known).",
"use": "Anything here you don't recognise deserves a look: check the vendor/MAC and hostname, then click the device to see what it talked to. Expected after adding a new gadget; worrying if it appeared unannounced or contacts many external peers.",
"what": "Devices seen on the network for the very first time during this snapshot's 24-hour window."
},
"devices|Per-host trend": {
"source": "Same baseline history as the chart above: one 24-hour record per day from analyze.py, up to 30 days, derived from Zeek conn logs.",
"use": "Scan the sparklines for spikes or hosts that suddenly went silent. Sort by the latest value to see who is busiest now; click a host name to open its detail page.",
"what": "Table of hosts with a sparkline of their daily traffic across the baseline snapshots, sorted by total volume (top 25)."
},
"devices|Top hosts over time": {
"source": "The baseline history in the netmon store: analyze.py folds in one snapshot per day (at least 23 h apart) and keeps the last 30, based on Zeek conn logs.",
"use": "Look for a sudden jump or a new line climbing into the top 10; steady lines are normal. Click a line to drill down to that host's detail page.",
"what": "Line chart of total bytes for the 10 busiest hosts across the banked baseline snapshots, one point per daily 24-hour record."
},
"devices|Unknown devices": {
"source": "collect.py marks a device known when its MAC appears in the newest UniFi DHCP export CSV inventory; analyze.py lists the rest. Traffic numbers come from Zeek conn logs, last 24 h.",
"use": "Identify each entry and add it to the inventory so it stops showing here. A device that stays unknown and talks to many external peers is the one to investigate first; click it for detail.",
"what": "Devices with traffic in this snapshot whose MAC address is not in the device inventory, with their byte total and number of external peers."
},
"device|Notes": {
"source": "The notes knowledge base (kb.py, kb.db in the dashboard state). AI notes (✨) are written by the scheduled AI Research job; notes by people (👤) are added here. Device notes are stored per MAC, endpoint notes per host name; both are shown on either page.",
"use": "Read what earlier AI runs learned about this device (its role, what is normal for it, decisions made). Add a note to tell the AI something it cannot see, e.g. 'media server, large uploads to B2 at night are expected'. Delete notes that are wrong; the AI also corrects stale ones.",
"what": "Running notes about this host or device that every AI job reads before judging it: the scheduled AI Research job, the correlation reviewer's work list and Ask AI."
},
"notes|Host notes": {
"source": "The notes knowledge base (kb.py). Written by the scheduled AI Research job (✨) and by people on the host and endpoint pages (👤).",
"use": "Search for a device, role or keyword. Click a device to open its page, where notes can be added or deleted.",
"what": "Every note about every host and device, newest first."
},
"notes|Event notes": {
"source": "Notes people left with the 📝 button next to an event's Related count. Stored per stable event key, so a note also applies to later repeats of the same finding or alert family.",
"use": "Use event notes to tell the AI what an event is or how to treat it ('expected - nightly backup', 'escalate if it happens again'). The research run and the correlation reviewer treat approved notes as authoritative guidance. Notes from User accounts (⏳) are hidden from the AI until a defender or admin approves them in 'Event notes awaiting approval'.",
"what": "All notes people wrote on events, newest first."
},
"device|Across snapshots": {
"source": "netmon history store (one record per collection run, twice a day, kept for about 30 days); the same history feeds the per-device baseline.",
"use": "Look for a step change or a single spike versus its usual level. A jump in 'internet up' is the most important (possible exfiltration or a new backup/cloud sync). Empty means no history yet for this device.",
"what": "Trend of this device's sent, received and internet-upload bytes across stored snapshots, each covering a 24 h window."
},
"device|Activity by hour": {
"source": "Zeek conn logs from Security Onion, last 24 h, bucketed by hour (UTC) for connections this device started.",
"use": "Learn the device's daily rhythm. Traffic at hours when it is normally idle, or a sudden tall bar, is worth a look; regular identical spikes can indicate scheduled jobs or beaconing. The baseline flags activity at unusual hours.",
"what": "Bytes (bars) and connections (line) this device originated per hour over the snapshot window."
},
"device|Agent": {
"source": "Elastic Fleet agent registry (.fleet-agents index) in Security Onion, read at collection time.",
"use": "Status should be online with a check-in within minutes. Offline, error, or no check-in for more than 30 minutes is flagged Investigate (host down, network cut or agent killed); a degraded status is flagged Review.",
"what": "Health of the Elastic Agent on this host: check-in status, last check-in and minutes since, version, policy, unhealthy reason and failed components."
},
"device|Auth failures": {
"source": "Elastic Agent system auth logs (logs-system.auth) in Security Onion, for the snapshot window.",
"use": "A few typos are normal. Any failure from the internet, or 8+ from one source, is flagged (Investigate if the source is not a known admin). Click 'details' to see the timeline and whether a success followed.",
"what": "Failed authentications on this host (SSH, sudo, su, console via PAM) with counts by source, user and process."
},
"device|Baseline: exec": {
"source": "netmon host baseline (SQLite store), built from Elastic Defend process events on each collection run.",
"use": "This is the learned normal. After a host's first day, a new executable not in this list (and not in an allowed path) is flagged Review. Use it to check when a program first appeared.",
"what": "Executables previously seen running on this host and the date each was first seen."
},
"device|Baseline: exec_sha": {
"source": "netmon host baseline (SQLite store), from Elastic Defend process events.",
"use": "If a binary's hash changes it is flagged 'Binary changed' (Review). That is expected after a software update, suspicious if nothing was updated.",
"what": "SHA-256 hashes last recorded for non-system executables on this host."
},
"device|Baseline: listen": {
"source": "netmon host baseline (SQLite store), from Elastic Defend network accept events.",
"use": "The learned set of listening services. A new process listening on a new port is flagged; compare against what you intentionally run.",
"what": "Program:port pairs where this host has accepted inbound connections, with first-seen date."
},
"device|Baseline: login": {
"source": "netmon host baseline (SQLite store), from Elastic Agent system auth logs.",
"use": "Any successful login not in this list is flagged 'First-seen login' (Review). Remove doubts by confirming each entry is you or an expected account.",
"what": "Successful user@source/method login combinations seen on this host, with first-seen date."
},
"device|Baseline: net": {
"source": "netmon host baseline (SQLite store), from Elastic Defend network events.",
"use": "Used to spot programs reaching new destinations. Long lists are normal for browsers; look for unexpected programs here.",
"what": "Process-to-destination pairs (IP:port or DNS name) this host has used before, with first-seen date."
},
"device|Baseline: sudo": {
"source": "netmon host baseline (SQLite store), from Elastic Agent system auth logs.",
"use": "Shows what is normal admin activity. Refused sudo attempts and suspicious commands (e.g. downloading and running scripts) are flagged regardless of the baseline.",
"what": "user:command combinations run with sudo on this host, with first-seen date."
},
"device|By ASN": {
"source": "Zeek conn logs from Security Onion, last 24 h, destination AS organisation, top 8 by bytes.",
"use": "Expect big cloud/CDN providers for most devices. A new network receiving more than about 20 MB is flagged by the baseline. Unfamiliar hosting providers deserve a check. Click a bar to see all devices using that network.",
"what": "This device's internet traffic (bytes) by destination network owner (ASN organisation)."
},
"device|By protocol / service": {
"source": "Zeek conn logs from Security Onion, last 24 h, Zeek-detected service of each connection.",
"use": "Mostly ssl/https is normal for modern devices. Plaintext protocols (http, ftp, telnet) or a large unidentified share are worth investigating. Click a slice to see all devices using that protocol.",
"what": "This device's traffic (bytes) split by application protocol as identified by Zeek (e.g. ssl, dns, http)."
},
"device|Certificates this device received": {
"source": "Zeek x509 and TLS logs from Security Onion, last 24 h; flags computed by netmon.",
"use": "Self-signed certificates are normal for home lab gear but suspicious for internet services. Expired certificates from external servers are flagged. Click 'all' for the full certificate inventory.",
"what": "Server certificates presented to this device, with risk flags (expired, expiring within 30 days, self-signed, weak key or signature, long validity), issuer and days left."
},
"device|DNS": {
"source": "Zeek DNS logs from Security Onion, last 24 h, unicast DNS on port 53 only (encrypted DNS is not visible here).",
"use": "Compare with the device's normal. Many unique names or many NXDOMAIN can indicate malware with generated domains (DGA) or misconfiguration; long average names can hint at DNS tunnelling. The baseline flags spikes.",
"what": "Summary of this device's DNS lookups: total queries, unique names and domains, NXDOMAIN (name does not exist) and SERVFAIL errors, and average name length."
},
"device|DNS-tunnel scoring": {
"source": "Zeek DNS logs from Security Onion, last 24 h. Domains with 15+ unique subdomains are sampled and scored on subdomain count, length, entropy, uniqueness, odd query types and few sources.",
"use": "Score 5+ with 150+ unique subdomains = suspect; 3+ with 50+ = watch. Many CDNs, anti-virus and telemetry services score low-to-medium legitimately; check the domain owner before worrying.",
"what": "Domains this device queried that look like possible DNS tunnels, with score, query count, unique subdomains and entropy (randomness)."
},
"device|Elastic Defend": {
"source": "Elastic Defend policy-status metrics (metrics-endpoint.policy) from Security Onion, latest per agent over the last 3 days.",
"use": "Status should be success. Anything else means protections such as malware or behaviour blocking may be off; it is flagged Review. Click 'details' for the event history and the failing actions.",
"what": "Whether Elastic Defend (the EDR) policy is applied successfully on this host, with any failed protections and the actions that failed."
},
"device|Files transferred": {
"source": "Zeek file logs from Security Onion, last 24 h (only visible for unencrypted transfers), hashes checked against Team Cymru Malware Hash Registry.",
"use": "Any MHR % above zero means known malware and is flagged high. Executables downloaded by IoT, camera, media or game devices are also flagged high. OS and app updates over HTTP are the usual benign case.",
"what": "Potentially risky files (executables, scripts, installers, archives) this device sent or received over the network, with type, size, source host and malware-hash result."
},
"device|Findings": {
"source": "analyze.py baseline over ~30 days of snapshots (needs 3 days), hosts.py/osq.py endpoint checks. Refreshed with each collection run.",
"use": "Start with high / Investigate items. Use 💬 Ask AI to have one explained, ⇄ compare with earlier snapshots, Related for linked events, and check an item off when handled (the toggle shows checked ones).",
"what": "Anomalies tied to this host. On the network page: baseline findings (deviations from its learned normal, threat intel, beacons). On the endpoint page: host findings from Elastic Agent, osquery and syslog."
},
"device|IDS alerts": {
"source": "Suricata alerts from Security Onion, last 24 h.",
"use": "Severity 1 is most serious. Many alerts are informational or known-benign; look at the signature name and whether this device is the source (it did something) or destination (it was targeted). Use the Alerts page for context.",
"what": "Suricata IDS signatures that fired with this device as source or destination, with severity, role, hit count and last time."
},
"device|Identity": {
"source": "MAC/vendor/hostname from Zeek conn and DHCP logs in Security Onion; zone and class from the network policy (More → Settings) and your inventory; first/last/days seen from the netmon device registry kept across snapshots. A note may come from the scheduled AI triage.",
"use": "Check that the vendor and hostname match what you expect for this device. 'unknown' means it is not in your inventory: identify and add it. Several other IPs, or a very recent first-seen date, deserve a second look. Click the agent link for endpoint detail.",
"what": "Who this device is: IP, MAC, vendor (from the MAC prefix), DHCP hostname, network zone and device class, inventory name, first/last seen and days seen, other IPs it has used, and any linked Elastic Agent host."
},
"device|Internal flows in": {
"source": "Zeek conn logs from Security Onion, last 24 h, internal-to-internal traffic.",
"use": "Check that each source should be talking to this device. Remote-admin ports (SSH, RDP, SMB) from unexpected devices are a lateral-movement warning sign.",
"what": "Connections other internal devices made to this device, per source, port and protocol, with answered count and bytes."
},
"device|Internal flows out": {
"source": "Zeek conn logs from Security Onion, last 24 h, internal-to-internal traffic.",
"use": "Expect your gateway, DNS, NAS, printers and media servers. Many unanswered attempts to many hosts suggests scanning; new peers (3+ answered) and policy breaks are flagged. Use the lateral-movement graph link for a visual.",
"what": "Connections this device made to other devices inside your network, per destination, port and protocol, with how many were answered and bytes."
},
"device|Internet dest ports": {
"source": "Zeek conn logs from Security Onion, last 24 h, connections to non-local responders, top 15 ports.",
"use": "Normal: 443, 80, 53, 123 and a few vendor-specific ports. Unusual ports such as 22, 23, 25 or high random ports to the internet can mean tunnelling, malware or misconfiguration.",
"what": "Destination ports this device connected to on the internet, by connection count."
},
"device|Internet traffic by country": {
"source": "Zeek conn logs from Security Onion, last 24 h, GeoIP country of external destinations, top 10 by bytes.",
"use": "Most devices talk to a few countries where their cloud services live. A country never seen before for this device with more than about 1 MB is flagged as a baseline finding. Click a slice to see all devices talking to that country.",
"what": "Share of this device's internet traffic (bytes) by destination country."
},
"device|IoT: ASNs": {
"source": "Zeek conn logs from Security Onion, last 24 h, internet traffic of IoT-class devices.",
"use": "A new network receiving more than about 200 KB is flagged 'iot-new-network' (medium); connections to IPs without ASN/geo info are flagged low.",
"what": "Networks (ASN organisations) this IoT device sent data to, by bytes."
},
"device|IoT: SNI": {
"source": "Zeek TLS logs from Security Onion, last 24 h, IoT-class devices.",
"use": "Should match the vendor's cloud services. Unfamiliar names, or a device suddenly talking to generic hosting, can mean firmware changes or compromise.",
"what": "TLS server names (SNI) this IoT device connected to, with counts."
},
"device|IoT: domains contacted": {
"source": "Zeek DNS logs from Security Onion, last 24 h, for devices classed as IoT in the network policy (More → Settings).",
"use": "IoT devices should talk to a small, stable set of vendor domains. Once the baseline has 3 days, a domain outside the learned set is flagged 'iot-new-domain' (medium).",
"what": "Every registered domain this IoT device looked up, with counts. Forms its learned destination allowlist."
},
"device|Logins": {
"source": "Elastic Agent system auth logs (logs-system.auth) in Security Onion, for the snapshot window.",
"use": "Successful logins should come from your known admin sources. A success from an unexpected source is flagged Investigate (especially from the internet); a first-seen user/source/method combination is flagged Review.",
"what": "SSH and web-console (Cockpit) logins on this host: user, source, method, outcome, count and last time."
},
"device|NXDOMAIN domains": {
"source": "Zeek DNS logs from Security Onion, last 24 h.",
"use": "A few are normal (typos, stale config, ad blocking). Many random-looking names, or a sudden NXDOMAIN spike (200+ and far above normal), can indicate malware using generated domains and is flagged by the baseline.",
"what": "Domains this device asked for that do not exist (NXDOMAIN answers), top 5."
},
"device|Network connections by process": {
"source": "Elastic Defend network events (logs-endpoint.events.network) from Security Onion, for the snapshot window.",
"use": "Expect browsers, updaters and known services. Shells, netcat, script interpreters or programs in odd locations reaching the internet are flagged; new process-to-destination pairs are compared against the host baseline.",
"what": "Which programs on this host made network connections, how many events, and a sample of destinations."
},
"device|Notable syslog": {
"source": "Elastic Agent system syslog (logs-system.syslog) in Security Onion, matched against netmon's pattern list, for the snapshot window.",
"use": "Investigate-level categories first. Occasional entries can be normal; repeated or growing counts point to a failing disk, memory pressure or a tampering attempt. The sample line shows the actual message.",
"what": "Syslog messages on this host matching notable patterns (e.g. disk or hardware errors, OOM kills, service crashes, logging or security changes), by category with severity, count, last time and a sample."
},
"device|Open issues to fix": {
"source": "issues.py runs deterministic checks on every snapshot (Zeek/Suricata data, analysis, endpoint and UniFi data) and tracks each issue across snapshots; an issue closes when a newer snapshot that ran the same check no longer finds it.",
"use": "Work through these top-down by severity. Check an item off once handled or accepted; use the toggle to show checked items. Click 'all' for the full Fix list with history.",
"what": "Fix-list items (misconfigurations and security suggestions) still open for this device, such as exposed services, legacy TLS, plaintext protocols or segmentation leaks."
},
"device|Other DNS signals": {
"source": "Zeek DNS logs (port 53 and mDNS 5353) and Zeek TLS logs matched against a list of known DoH provider names, Security Onion, last 24 h.",
"use": "DoH or external resolvers hide lookups from your monitoring; new use is flagged. Many long names or a domain with lots of random subdomains can hint at DNS tunnelling. 'none' everywhere is the healthy case.",
"what": "Extra DNS indicators: external resolvers, DNS-over-HTTPS use, mDNS volume, maximum name length, count of long names (60+ characters), and domains with many distinct subdomains."
},
"device|Outbound by destination port": {
"source": "Zeek conn logs from Security Onion, last 24 h, top 20 destination ports for connections this device started. The baseline compares this against the device's past habits.",
"use": "A port this device never used before with 20+ connections is flagged as 'new-port'; a big jump on a known port as 'port-spike'. Sort by Internet to see what reaches outside your network.",
"what": "Every destination port/protocol this device talks to (internal and internet), with service, connection count, how many went to the internet, and bytes."
},
"device|Outbound by service": {
"source": "Zeek conn logs from Security Onion, last 24 h, Zeek-detected service per connection (connections without a detected service show as 'unidentified').",
"use": "A newly used service with 10+ connections is flagged 'new-service', and a share shift of more than 30 points as 'service-mix'. Plaintext services or a large unidentified share are worth a look.",
"what": "Application protocols this device uses as a client, by connection count and bytes."
},
"device|Query types": {
"source": "Zeek DNS logs from Security Onion, last 24 h.",
"use": "A and AAAA dominate normally. A sudden share of TXT, NULL, ANY or MX can indicate DNS tunnelling or abuse; new risky types are flagged at medium. Click a slice to see all devices using that type.",
"what": "Mix of DNS record types this device requests (A, AAAA, HTTPS, PTR, TXT and so on)."
},
"device|Remote ports": {
"source": "Zeek conn logs from Security Onion, last 24 h, top 10 destination ports by bytes for connections this device started.",
"use": "443 and 80 dominate for most devices. Large volumes on unusual ports (e.g. remote access, file sharing or high random ports) deserve a check.",
"what": "Destination ports this device used, ranked by bytes transferred."
},
"device|Resolvers used": {
"source": "Zeek DNS logs from Security Onion, last 24 h, destinations of port 53 queries.",
"use": "Normally only your local resolver/gateway. An external resolver means the device bypasses your DNS filtering and logging; a resolver never used before is flagged (high if external).",
"what": "DNS servers this device sent queries to, by query count."
},
"device|Risk to the network:": {
"source": "Computed by risk.py for the selected snapshot from open Fix-list issues, IDS alerts, beacons, threat-intel hits, internal flows, exposed services and endpoint coverage. Impact comes from the device class and zone.",
"use": "Read the bars to see which component drives the score and the 'Why' list for the concrete reasons. Roughly: 40+ high, 20-39 medium, 8-19 low. Fixing the listed weaknesses lowers it. Click 'all' for the full ranking.",
"what": "This device's overall risk score (0-100) and its rank among all hosts. Score = likelihood (exposure, weaknesses, threat activity, lateral reach, visibility gaps) x impact (1-5, how much a compromise would hurt the network) / 5."
},
"device|Segmentation violations": {
"source": "Zeek internal flows from Security Onion, last 24 h, checked against zones and rules in the network policy (More → Settings).",
"use": "Each row shows source, destination, port and reason. Answered connections matter most. Either fix the firewall rule or, if expected, clear it in the policy so it stops being flagged.",
"what": "Internal connections involving this device that break your zone rules (e.g. IoT reaching servers, DMZ reaching the LAN)."
},
"device|Served / listening ports": {
"source": "Zeek conn logs from Security Onion, last 24 h, answered inbound connections only (failed/unanswered attempts are excluded).",
"use": "Make sure each port is a service you meant to run. Any 'From internet' count means the port is reachable from outside: confirm the port forward is intended. A newly answering port is flagged 'new-listening-port' (high if internet-reached).",
"what": "Ports on which this device answered incoming connections (it acts as a server), with number of sources and connections from the internet. The header shows totals and internet-exposed ports."
},
"device|Software observed": {
"source": "Zeek software logs from Security Onion, last 24 h.",
"use": "Look for outdated versions; known-outdated software is flagged low and new software on a device is flagged once the baseline has 3 days. Unexpected tools (e.g. scanners or scripting clients) deserve a check.",
"what": "Software and versions Zeek saw this device announce on the network (browser and HTTP user agents, SSH clients/servers and similar)."
},
"device|TLDs": {
"source": "Zeek DNS logs from Security Onion, last 24 h, top 15 TLDs.",
"use": "Most traffic should be in common TLDs. 20+ queries in a TLD this device never used is flagged 'dns-new-tld'; cheap or unusual TLDs are more often abused.",
"what": "Top-level domains (e.g. com, net, country codes) of this device's DNS lookups."
},
"device|TLS client fingerprints": {
"source": "Zeek TLS logs from Security Onion, last 24 h. The baseline remembers each device's fingerprints.",
"use": "The set should be stable. New fingerprints on an IoT, camera, media or game device are flagged medium (new software or tampering?); on other devices only 3+ new ones are flagged, usually an app or OS update.",
"what": "JA4 fingerprints of the TLS clients on this device, by connection count. JA4 is a newer, more precise fingerprint than JA3."
},
"device|TLS client fingerprints": {
"source": "Zeek TLS logs from Security Onion, last 24 h, checked against the abuse.ch SSLBL JA3 list.",
"use": "An SSLBL match alone is weak evidence (common TLS stacks collide with old malware entries); it only becomes high severity when the destination is also on a threat list. Click a fingerprint to look it up in Threat intel.",
"what": "JA3 fingerprints of the TLS clients (apps/libraries) on this device, with how many connections used each, how many devices share it, and an SSLBL badge if it is on the abuse.ch malicious-JA3 list."
},
"device|TLS versions": {
"source": "Zeek TLS logs from Security Onion, last 24 h.",
"use": "TLS 1.2 and 1.3 are normal. Any SSLv3, TLS 1.0 or 1.1 is deprecated and flagged 'legacy-tls'; update or replace the software or device. Click a slice to see other devices using that version.",
"what": "TLS/SSL protocol versions used by this device's encrypted connections."
},
"device|Telemetry streams": {
"source": "Elastic Agent data streams in Security Onion (system.syslog, system.auth, endpoint process events, elastic_agent), current vs previous window.",
"use": "Counts should be similar to the previous window. A stream dropping to zero (syslog from 50+ before) is flagged Investigate: logging stopped, host down, or tampering.",
"what": "Volume of logs this host sent per data stream (syslog, auth, process events, agent logs) in this window versus the previous equal window, plus the last event time."
},
"device|Top destinations": {
"source": "Zeek conn logs from Security Onion, last 24 h, top 5 destinations by bytes for connections this device started.",
"use": "Usually your NAS, backup target or a big cloud service. An unexpected internet IP at the top could mean a large upload; click it to drill into that address.",
"what": "The five destination IPs (internal or internet) that received the most bytes from this device."
},
"device|Top domains": {
"source": "Zeek DNS logs from Security Onion, last 24 h, unicast port 53 queries.",
"use": "Should match the device's purpose (its vendor cloud, OS updates, common services). A heavy domain that never was a regular for this device (200+ queries or 5% of its lookups) is flagged 'dns-new-heavy-domain'.",
"what": "The registered domains this device looks up most often (top 30)."
},
"device|Zeek weird": {
"source": "Zeek weird logs from Security Onion, last 24 h.",
"use": "Mostly harmless noise from buggy stacks or capture loss. Large counts or unusual names (e.g. evasion-like DNS or HTTP anomalies) are worth searching in Security Onion.",
"what": "Protocol oddities Zeek noticed in this device's traffic (malformed packets, unexpected protocol behaviour), with counts."
},
"dns|Certificate key types": {
"source": "Zeek x509 logs from Security Onion, last 24 h, up to 1,500 distinct certificates by SHA-256.",
"use": "RSA 2048 or larger and EC keys are fine. RSA keys under 2048 bits are flagged as weak key, a high-severity certificate flag. Click a slice to filter the Certificates table to that key type.",
"what": "Doughnut chart of public key type and size (for example RSA 2048, EC 256) for every certificate seen."
},
"dns|Certificate validation failures": {
"source": "Zeek ssl logs from Security Onion, last 24 h: every session whose ssl.validation_status is present and not ok.",
"use": "Self-signed certificates on local devices (routers, NAS, printers) are expected. Expired, revoked or name-mismatch failures (red badge) to internet hosts are more serious and can mean interception or a broken service. Click an internal destination for its host page.",
"what": "TLS sessions where Zeek could not validate the server certificate, grouped by status, server name and destination, with the clients involved."
},
"dns|Certificates": {
"source": "Zeek x509 logs from Security Onion, last 24 h, matched to internal clients through TLS server names (SNI). Flags: expired, expiring under 30 days, not yet valid, self-signed, weak RSA key under 2048, SHA-1 or MD5 signature, validity over 398 days.",
"use": "Use the Flag menu to show Serious ones (expired, weak, not yet valid). Self-signed certificates on your own devices are common, and long validity is low risk. Click a row for full details.",
"what": "Inventory of every x509 certificate seen, with risk flags, key, signature, days left, validity length and the internal clients that used it."
},
"dns|Certificates by days to expiry": {
"source": "Zeek x509 logs from Security Onion, last 24 h; days left is calculated from each certificate's not-valid-after date at collection time.",
"use": "Internet certificates usually sit in the 30 to 90 day buckets. Expired (red) or under 7 days (amber) usually means a home device or self-hosted service needs a renewal. Click a bar to filter the Certificates table.",
"what": "Bar chart counting certificates by days left before expiry: expired, under 7 days, under 30, under 90, under a year, over a year."
},
"dns|Cipher suites": {
"source": "Zeek ssl logs from Security Onion, last 24 h, top 25 ciphers for sessions from internal devices.",
"use": "Expect modern AEAD suites (AES-GCM, ChaCha20-Poly1305, TLS 1.3 suites). RC4, 3DES, NULL, EXPORT or plain CBC-SHA suites point to old devices; find them under Devices using legacy TLS or bad certs.",
"what": "Table of the TLS cipher suites negotiated, with session counts."
},
"dns|DNS queries by device": {
"source": "Zeek dns logs from Security Onion, last 24 h, unicast DNS on port 53 only (mDNS and DNS-over-HTTPS are not counted here). One query = one Zeek dns record from that device.",
"use": "Smart TVs, phones and browsers are normally chatty. Worry about a quiet device (camera, plug, printer) suddenly near the top, which can mean malware or DNS tunnelling. Click a bar to open that host's page and compare with ⇄.",
"what": "Bar chart of the 15 internal devices that sent the most DNS queries in the current snapshot."
},
"dns|Devices using legacy TLS or bad certs": {
"source": "Zeek ssl logs from Security Onion, last 24 h, per device: session count by TLS version, plus distinct failed-validation destinations (status not ok).",
"use": "Older printers, TVs and IoT gear often show up here; check for firmware updates. A laptop or phone with bad certs to internet sites deserves a look. Click the device to open its host page.",
"what": "List of devices that made legacy TLS sessions (anything other than TLS 1.2 or 1.3) or hit failed certificate validation."
},
"dns|JA client fingerprints": {
"source": "Zeek ssl logs from Security Onion, last 24 h. To keep it small it holds the 300 busiest fingerprints, up to 300 more that only one device used, and every SSLBL malware match.",
"use": "Tick 'only fingerprints used by a single device'. Rare fingerprints going to odd servers are the most interesting. Click a row for details and links to SSLBL and the threat-intel lookup.",
"what": "Catalogue of JA3 TLS client fingerprints, which identify the app or library that opened a connection, with connection count, devices using it, server names and JA4."
},
"dns|JAS server fingerprints": {
"source": "Zeek ssl logs from Security Onion, last 24 h, top 500 JA3S hashes for sessions started by internal devices.",
"use": "Mostly useful alongside JA3: the same server fingerprint behind many unrelated names usually means a CDN. A rare JA3S seen only with a rare JA3 and an unfamiliar name points to a custom or suspicious server.",
"what": "Table of JA3S server fingerprints (how servers answered the TLS handshake) with session count, distinct servers and clients, example server names and versions."
},
"dns|Malicious JA matches": {
"source": "JA3 hashes from Zeek ssl logs (Security Onion, last 24 h) checked against the SSLBL JA3 feed downloaded by the collector.",
"use": "Old SSLBL entries (before 2022) often match ordinary libraries, so check the server names (SNI) and destinations first. A match to unknown or odd destinations is worth investigating; use the threat-intel lookup or 💬 Ask AI.",
"what": "TLS client fingerprints (JA3) from your devices that match the abuse.ch SSLBL list of malware TLS fingerprints. The card only appears when there is a match."
},
"dns|NXDOMAIN by device": {
"source": "Zeek dns logs from Security Onion, last 24 h, port 53 queries whose response code was NXDOMAIN.",
"use": "A few hundred is normal (typos, search-domain suffixes, dead trackers). Thousands from one device, especially to random-looking names, can mean malware trying generated domains (DGA). Click a bar for the host page and check its DNS section.",
"what": "Bar chart of the 15 devices with the most NXDOMAIN answers, meaning they asked for names that do not exist."
},
"dns|NXDOMAIN domains": {
"source": "Zeek dns logs from Security Onion, last 24 h, port 53. Each device's top 5 failing domains are summed.",
"use": "Typical entries are local search suffixes, retired services and ad or tracking domains. Many long random-looking names, or a domain that also shows up under DNS-tunnel scoring, deserve a closer look.",
"what": "Table of registered domains that returned NXDOMAIN (name does not exist), added up across devices."
},
"dns|Query types": {
"source": "Zeek dns logs from Security Onion, last 24 h, port 53. Built from each device's top 12 query types, summed.",
"use": "A, AAAA and HTTPS should dominate. A large share of TXT, NULL or other unusual types is a classic sign of DNS tunnelling. Click a slice to open Hosts filtered to devices using that type.",
"what": "Doughnut chart of DNS record types requested (A, AAAA, HTTPS, PTR, TXT and so on)."
},
"dns|Resolvers": {
"source": "Zeek dns logs from Security Onion, last 24 h. Each device's top 6 destination resolvers, summed.",
"use": "Normally almost everything goes to your gateway or local resolver. Devices talking straight to public resolvers are bypassing your DNS filtering; click a resolver address to see what it is and which device uses it.",
"what": "Table of the DNS servers that devices sent their port 53 queries to, with query counts."
},
"dns|TLDs": {
"source": "Zeek dns logs from Security Onion, last 24 h, port 53. Each device's top 15 TLDs, summed.",
"use": "Common generic and local country TLDs are normal. Lots of queries to cheap, abuse-heavy TLDs or to countries you have no reason to contact are worth checking in Top domains and the threat-intel page.",
"what": "Table of top-level domains (com, net, org, country codes and so on) by number of queries."
},
"dns|TLS versions": {
"source": "Zeek ssl logs from Security Onion, last 24 h, sessions from internal source addresses (ssl.version field).",
"use": "TLS 1.3 and 1.2 should be almost everything. TLS 1.0, 1.1 or SSL means an old device or app with weak crypto. Click a slice to open Hosts filtered to devices using that version.",
"what": "Doughnut chart of TLS and DTLS protocol versions across all encrypted sessions started by internal devices."
},
"dns|Top certificate issuers": {
"source": "Zeek x509 logs from Security Onion, last 24 h, counting each distinct certificate once.",
"use": "Large public CAs and vendor CAs are normal. An unknown issuer that signs certificates for many popular sites can mean TLS interception (a proxy or malware). Click a bar to filter the Certificates table by that issuer.",
"what": "Bar chart of the 10 certificate authorities (issuer CN) that issued the most certificates seen."
},
"dns|Top domains": {
"source": "Zeek dns logs from Security Onion, last 24 h, port 53. Each device contributes its own top 30 registered domains, so the totals are approximate and very rare names are left out.",
"use": "Expect big cloud, CDN, OS-update and streaming domains. Use the search box to check a domain you are unsure about. Anything unfamiliar near the top is worth a threat-intel lookup or 💬 Ask AI.",
"what": "Table of the registered domains looked up most often, added up across all devices."
},
"endpoints|Fleet": {
"source": "The .fleet-agents index in Security Onion Elasticsearch (hosts.py), newest record per host, collected with each run (twice a day).",
"use": "All rows should be online and checking in within a few minutes. An offline, degraded or long-silent agent means that host is not being monitored; check the agent service on it. Click a row for the host's endpoint page.",
"what": "Health of every enrolled Elastic Agent: check-in status, minutes since last check-in, unhealthy reason or failing components, agent version and policy."
},
"endpoints|Hosts": {
"source": "Elastic Agent data in Security Onion: Fleet registry, system syslog/auth logs, Elastic Defend process events and osquery (hosts.py), plus host findings from its baseline checks.",
"use": "Start with hosts that have findings (sorted first), then check for hosts with zero or very low telemetry, which can mean an agent outage or tampering. Click a row to open the endpoint detail.",
"what": "One row per monitored endpoint with its matching network device, open host findings, telemetry document count, notable syslog events and number of distinct programs executed."
},
"endpoints|Telemetry volume by host": {
"source": "Elasticsearch aggregations in hosts.py over the logs-system.syslog, logs-system.auth, logs-endpoint.events.process and logs-elastic_agent indices in Security Onion.",
"use": "Compare hosts against each other and over time: a host that suddenly drops to little or nothing may have a stopped agent or logging problem; a big spike can mean noisy errors or unusual activity. Click a bar to open that host.",
"what": "Bar chart of how many telemetry documents each endpoint sent in the collection window (syslog, auth, Defend process events and agent logs combined)."
},
"issues|Cleared segmentation": {
"source": "Your check-offs stored in the dashboard database, compared with this snapshot's segmentation violations from analyze.py (the network policy (More → Settings)).",
"use": "Cleared flows are hidden from Posture, Fix list and Risk and shown as allowed on Lateral movement. Uncheck to bring one back. To make it permanent for everyone, add it to the allow list in the network policy (More → Settings).",
"what": "Segmentation-policy flows you marked as expected, with why they were flagged, whether they were seen in this snapshot, and when you cleared them."
},
"issues|Fixed": {
"source": "issues.py: marked fixed once a newer snapshot that could run the check no longer produces the item.",
"use": "Confirms your fixes worked. If an item returns later it reappears in the open lists.",
"what": "Items that used to be on the fix list but are no longer found, with when they disappeared and what they were."
},
"issues|New / seen once": {
"source": "issues.py checks run on every snapshot.",
"use": "Often temporary conditions; no rush unless severity is high. Tick the check box to dismiss one you accept.",
"what": "Fix-list items found in only one snapshot so far. They move up to Recurring if they show up again."
},
"issues|Open vs fixed": {
"source": "issues.py tracker across all stored snapshots: an item is fixed when a later snapshot able to run that check no longer finds it.",
"use": "A growing fixed bar and shrinking recurring bar means progress. Click a bar to jump to that list.",
"what": "Counts of recurring open items, new items seen only once, and items that have been fixed."
},
"issues|Recurring by category": {
"source": "issues.py checks across all stored snapshots, excluding checked-off items.",
"use": "Click a slice to filter the list to that category and work through one kind of problem at a time.",
"what": "Doughnut of open recurring fix-list items by category, such as Misconfiguration or Security suggestion."
},
"issues|Recurring by severity": {
"source": "issues.py: deterministic checks run on every stored snapshot (network data, analysis, endpoint and UniFi sources), excluding items you checked off.",
"use": "Click a slice to filter the list to that severity. Aim to get high to zero first.",
"what": "Doughnut of open recurring fix-list items (seen in 2 or more snapshots) by severity."
},
"issues|Recurring: fix these": {
"source": "issues.py deterministic checks over every snapshot (collection twice a day). Items whose device or data source was missing from the latest snapshot stay open and are marked not re-checked.",
"use": "Follow How to fix and open evidence for detail. Tick the check box when handled or accepted (show N checked brings them back). Use 💬 Ask AI for help on a row. Fixed items move away on their own.",
"what": "Open misconfigurations and security suggestions seen in 2 or more snapshots, with severity, where, how many times seen out of checks run, first/last seen and fix instructions."
},
"lateral|Admin sessions": {
"source": "lateral.py from Zeek, endpoint login logs and endpoint commands, last 24 h. High = 10+ failed logins, 3+ invalid users, or 3+ failures then success; medium = any failure or 5+ refused; low = few refused or not allowed by the network policy (More → Settings).",
"use": "Check high and medium rows first and confirm you recognise the accounts. Click a row to see the link in the graph panel. Tick the check box once reviewed — it moves to Checked admin sessions. Add expected admin paths to the network policy (More → Settings) allow.",
"what": "Every internal admin session (SSH, RDP, PsExec/SMB, WMI, WinRM, VNC, Docker, Kubernetes, remote support) with risk, outcome, accounts, login and connection counts, and why it was rated."
},
"lateral|Checked admin sessions": {
"source": "Your check-offs stored in the dashboard database (keyed by source, target and protocol), matched against this snapshot's admin sessions.",
"use": "Reviewed sessions live here so the main list shows only what still needs a look. Uncheck a row to move it back. Checking off does not change risk scoring; use the network policy (More → Settings) allow for that.",
"what": "Admin sessions you have checked off, with when you checked them and the same risk, outcome and login details as the main list."
},
"lateral|Cleared segmentation": {
"source": "Your check-offs stored in the dashboard database, compared with this snapshot's segmentation violations from analyze.py (the network policy (More → Settings)).",
"use": "These show as allowed on Lateral movement and are hidden from Posture, Fix list and Risk. Uncheck to bring one back; add it to the allow list in the network policy (More → Settings) to make it permanent.",
"what": "Segmentation-policy flows you marked as expected, with why they were flagged, whether they were seen in this snapshot, and when you cleared them."
},
"lateral|Connections shown": {
"source": "lateral.py over Zeek conn logs (internal to internal only, last 24 h), classified against the network policy (More → Settings): policy violations, repeated failed admin attempts and internal scans are risky, allowed admin access is separate.",
"use": "Change Show or Focus host above to filter. Sort by score; high and medium links need a look. Click a row to see details in the side panel.",
"what": "Table of the internal host-to-host links currently shown in the graph, with risk level, score, zones, the risky ports and reasons, connection counts and bytes."
},
"lateral|Logins by protocol": {
"source": "lateral.py admin-access data combining Zeek network logs, endpoint login logs (Elastic Agent: Linux auth, Windows logon events) and admin commands seen on endpoints, last 24 h.",
"use": "Mostly green is normal. Red failed logins or many orange refused connections can mean password guessing or a misconfigured script. Click a bar to list those sessions.",
"what": "Stacked bars per admin protocol (SSH, RDP, SMB, WinRM and others) showing successful logins, failed logins and refused or unanswered connections."
},
"lateral|Sessions by outcome": {
"source": "lateral.py admin-access sessions merged per source, target and protocol from Zeek and endpoint login logs, last 24 h.",
"use": "Failed + succeeded is the one to check: it can mean a guessed password. Click a slice to filter the Admin sessions list.",
"what": "Doughnut of admin sessions by outcome: failed, failed then succeeded, succeeded, or unknown (no login telemetry)."
},
"netmap|All hosts": {
"source": "Merged from Zeek traffic in the latest snapshot, the DHCP inventory, the ~30-day baseline registry and UniFi clients not in inventory; agent status from Elastic Agent; risk from risk.py.",
"use": "Watch for Inventory 'no' (unknown device) and missing agents on computers. Click a row to highlight it on the map; click the host name to open its page.",
"what": "Every internal host netmon knows about, with zone, name, IP, MAC, vendor, class, whether active this snapshot, in the inventory, running an endpoint agent, plus risk and open issues."
},
"netmap|Zones": {
"source": "Zones and subnets from the network policy (More → Settings); hosts merged from live traffic (Zeek), DHCP inventory, the baseline device registry and UniFi clients; risk from risk.py and issues from the Fix list.",
"use": "Look for zones with unknown hosts or a high max risk. Click the riskiest host to open it.",
"what": "Summary of each network zone: subnet, gateway, number of hosts, how many were active, unknown hosts, open issues, the highest risk score and the riskiest host."
},
"overview|Devices by zone": {
"source": "Device IPs from Zeek traffic in the snapshot, mapped to zones using the subnet ranges in the network policy (More → Settings). '?' means the address is outside every defined zone.",
"use": "Click a slice to open Hosts filtered to that zone. Devices in '?' or an unexpected zone may be misconfigured or unknown and are worth checking.",
"what": "How many devices seen in the window fall into each network zone, for example main, IoT, servers or guest."
},
"overview|Endpoint fleet": {
"source": "Elastic Fleet agent records (.fleet-agents) in Security Onion's Elasticsearch, read at collection time.",
"use": "Healthy and online with a check-in a few minutes ago is normal. Offline, degraded or a check-in older than 30 minutes raises a host finding. Click a row to open that endpoint.",
"what": "Health of every computer running the Elastic Agent: status, minutes since last check-in, unhealthy reason or failing components, agent version and policy."
},
"overview|Finding kinds": {
"source": "Baseline findings from analyze.py: each device's last 24 h compared with its ~30-day history, plus rule-based checks on threat intel, beacons, segmentation, files and TLS.",
"use": "Click a slice to list those findings on Posture. One kind dominating usually means one noisy change (for example a software update); unusual kinds like ti-domain, malware-hash or beacon-suspicious are worth checking first.",
"what": "The 10 most common kinds of baseline finding in this snapshot, such as new-port, volume-spike, segmentation or beacon-new."
},
"overview|Findings by severity": {
"source": "The analysis step (analyze.py) compares each device's last 24 h with its own ~30-day baseline and applies fixed rules (threat intel, beacons, segmentation, files, TLS). Baseline comparisons need at least 3 days of history.",
"use": "Click a slice to open Posture filtered to that severity. A few low and medium items is normal; any high deserves review. A warming-up baseline produces fewer findings.",
"what": "How many baseline findings in this snapshot are high, medium or low."
},
"overview|Gateway health": {
"source": "UniFi gateway API (stat/health and client list) via the UniFi cloud connector, read at collection time.",
"use": "All subsystems should show ok. High latency, rising drops or a sudden uptime reset (reboot) are worth checking. A drop in clients online can mean a network or Wi-Fi problem.",
"what": "Status of the UniFi gateway's subsystems plus ISP, WAN address, latency, packet drops, uptime and clients online per network."
},
"overview|Top talkers": {
"source": "Per-device totals from Zeek conn logs in Security Onion, last 24 h, as collected into the snapshot.",
"use": "Click a bar to open that device's page. Backup servers, media players and big downloads are normally at the top; a device that suddenly sends far more than it receives deserves a look.",
"what": "The 12 internal devices that moved the most data in the window, split into bytes sent and received."
},
"overview|Traffic per hour": {
"source": "Zeek conn logs from Security Onion, last 24 h, summed per hour (network bytes and connection.bytes.missed).",
"use": "Look for spikes at odd hours or a sudden step change. A non-zero missed line means the sensor dropped packets, so other numbers may be undercounted; the Capture loss tile turns amber above about 1 GB.",
"what": "Total bytes seen on the network per hour across the 24-hour window, plus a second line for bytes the sensor missed (capture loss)."
},
"risk|Hosts ranked by risk": {
"source": "dashboard/app/risk.py for the selected snapshot, combining fix-list issues, alerts and findings, threat intel, lateral reach and EDR/visibility data.",
"use": "40 or more is high, 20-40 medium. Read the drivers to see why, click the host to drill down, and use 💬 Ask AI for a fix plan. Hover the impact value for its reason.",
"what": "All scored hosts sorted by risk (likelihood x impact / 5), with zone, class, open vulnerability count and the top drivers behind each score (first 30 shown)."
},
"risk|Likelihood × impact": {
"source": "dashboard/app/risk.py for the selected snapshot; impact comes from the host's role (sensor, gateway, crown jewels and servers highest, IoT lowest).",
"use": "Top-right bubbles are the priority: important hosts that are also likely to be hit. Hover for the score and click a bubble to open the host.",
"what": "Every scored host plotted by likelihood (0-100, horizontal) against impact (1-5, vertical); bigger bubbles have more open vulnerabilities. Red is risk 40+, orange 20-40."
},
"risk|Scoring model": {
"source": "The weights in dashboard/app/risk.py; severity base values shown here are read from the live model.",
"use": "Use it to understand why a host or issue ranks where it does. To change the weighting, edit risk.py.",
"what": "Explains how host and vulnerability risk scores are calculated, including the component caps, impact levels and the multipliers used."
},
"risk|Top hosts — risk by component": {
"source": "dashboard/app/risk.py, recomputed for the selected snapshot from fix-list issues, alerts, findings, beacons, threat-intel hits, segmentation and endpoint coverage.",
"use": "The longest colour tells you what to fix: weaknesses means fix-list items, visibility means missing EDR or an unknown device, threat means real activity. Click a bar to open that host.",
"what": "Stacked bars for the 15 riskiest hosts, showing how each part of the likelihood score (exposure, weaknesses, threat activity, lateral reach, visibility gaps) contributes after weighting by impact."
},
"risk|Top vulnerabilities by risk": {
"source": "dashboard/app/risk.py: fix-list issues scored by severity, kind, the affected host's exposure and how often they recur.",
"use": "Start fixing from the top. Click a bar to filter the table below to that item and read its fix instructions.",
"what": "Bar chart of the 15 highest-scoring vulnerabilities and misconfigurations, labelled with the issue and where it applies. Red is 60+, orange 30+."
},
"risk|Vulnerabilities ranked by risk": {
"source": "dashboard/app/risk.py over the Fix list (issues.py), recomputed for the selected snapshot.",
"use": "Work top-down. Tick the check box once handled or accepted (show N checked brings them back), open evidence for details, and use 💬 Ask AI for step-by-step help.",
"what": "All open fix-list items ranked by risk score, with severity, category, how often seen, score drivers, how to fix and the evidence."
},
"security|Baseline findings": {
"source": "analyze.py compares the 24-hour snapshot (Zeek and Suricata data from Security Onion) with a ~30-day per-device baseline; baseline comparisons start after 3 days of history.",
"use": "Sort by severity and start with high. Tick the box when explained; it stays checked on later snapshots. Click a row for the device, or use 💬 Ask AI, ⇄ compare, Kibana and Related to investigate.",
"what": "Things each device did differently from its own normal in the last 24 h: new ports or services, traffic and DNS spikes, new countries or networks, new TLS fingerprints, plus rule hits for threat intel, beacons, segmentation, files and TLS."
},
"security|Beacon candidates": {
"source": "Zeek conn logs from Security Onion, last 24 h. RITA-style scoring of up to 400 pairs with 36+ connections on timing and size regularity and hour coverage; listed when score is 0.75 or more and active 40% of the window. STUN traffic is excluded.",
"use": "Most beacons are updates, telemetry or push services. Worry about raw IPs with no name, unusual ports, new domains or threat-listed destinations. Use 💬 Ask AI or Kibana to check.",
"what": "Connections from an internal device to the same destination and port that repeat on a regular timer, with interval, jitter, hours active and score."
},
"security|Cleared segmentation": {
"source": "Your Clear check-offs, stored in the dashboard's SQLite database, matched against this snapshot's segmentation violations from analyze.py and the network policy (More → Settings).",
"use": "Cleared flows are hidden from Posture, Fix list and Risk and stay cleared. Uncheck one to bring it back. For a permanent rule for everyone, add an allow entry to the network policy (More → Settings).",
"what": "Internal flows you marked as expected from Segmentation violations, with why they were flagged and whether they still occur in this snapshot."
},
"security|DNS-tunnel scoring": {
"source": "Zeek DNS logs from Security Onion, last 24 h: top 60 domains by distinct subdomains (15 or more), scored on subdomain count and length, randomness, uniqueness, odd record types and few sources. Score 5+ with 150+ subdomains is suspect; 3+ is watch.",
"use": "CDNs, anti-virus and telemetry services often score a little. A high score from one device to an unfamiliar domain is worth checking with 💬 Ask AI.",
"what": "Domains queried with many distinct subdomains, scored for traits typical of DNS tunnelling (hiding data inside DNS lookups), with queries, unique subdomains, entropy, NXDOMAIN count and sources."
},
"security|Files": {
"source": "Zeek file logs from Security Onion, last 24 h, filtered by file type and joined to HTTP details; hashes checked against Team Cymru Malware Hash Registry (MHR).",
"use": "Any MHR% value means antivirus engines detect the file as malware and raises a high finding. Executables downloaded by IoT, camera, media or game devices are also flagged. Updates from known vendors are normal.",
"what": "Risky file types moved over the network (executables, installers, scripts, archives, disk images), with receiver, host, size and antivirus detection rate. The title counts Windows executables (PE)."
},
"security|Gateway admin logins": {
"source": "UniFi gateway API admin-activity log via the UniFi cloud connector, last 24 h. A source is expected when it is the home WAN, the LAN or the VPN.",
"use": "Logins you made yourself are normal. Anything marked Unexpected, or a login at a time you were not using it, should be checked and the admin password changed if unexplained.",
"what": "Sign-ins to the UniFi gateway admin interface in the window, with time, admin, source address, platform and an unexpected-source flag."
},
"security|Gateway config changes": {
"source": "UniFi gateway API admin-activity log via the UniFi cloud connector, last 24 h. Changes to firewall, port forwarding, VPN, Wi-Fi, IPS or admin settings are marked security relevant.",
"use": "Make sure every change was made by you or someone you trust. Unexplained firewall, port-forward, VPN or admin changes are serious; check them in the UniFi app.",
"what": "Configuration changes made on the UniFi gateway in the window: time, actor, settings section, object and operation."
},
"security|Gateway events": {
"source": "UniFi gateway API system log via the UniFi cloud connector: last 24 h of events plus 30 days of security events.",
"use": "High-severity and blocked IPS detections against your devices matter most. Use the Kibana/UniFi button, Related and research notes to see what else happened around each event. Tick the box to check an event off (show N checked brings them back), or use 🚫 (admin / defender) to suppress events like it by name.",
"what": "Security and gateway events from the UniFi system log in the window (IPS detections, high-severity events, device events), plus security events from the last 30 days."
},
"security|Gateway protection settings": {
"source": "UniFi gateway API settings, read at each collection run via the UniFi cloud connector. Read-only.",
"use": "IPS should be in an active mode (IPS blocks, IDS only alerts) and cover all your networks. A setting that changed unexpectedly is worth checking against Gateway config changes.",
"what": "The UniFi gateway's protection setup: IPS mode, enabled threat categories, protected networks, honeypot, DNS filtering, ad blocking, endpoint scanning and DPI."
},
"security|Host findings": {
"source": "hosts.py reading Elastic Agent data in Security Onion: Elastic Defend alerts and events, osquery, auth and system logs, Fleet status, compared with a per-host baseline. The 15-minute watcher uses the same rules.",
"use": "Investigate items first. Tick the box once explained; it carries over to later snapshots. Use 💬 Ask AI, ⇄ compare, Kibana, Related and the research-note verdict to judge each one.",
"what": "Problems seen on the computers themselves: Defend alerts, unusual logins or repeated failures, account changes, suspicious sudo or processes, new executables, sensitive file changes, agent and Defend policy problems, syslog going silent."
},
"security|Host findings checked off": {
"source": "Your check-offs stored in the dashboard's SQLite database, matched against this snapshot's host findings from hosts.py (Elastic Agent data).",
"use": "These are still present in the current data. Uncheck one if it needs another look. Auto-closed items come from AI verdicts of benign or expected when that option is on in Configuration.",
"what": "Host findings that you or the auto-close rule have already checked off, with when they were checked."
},
"security|IDS alerts by category": {
"source": "Suricata alerts from Security Onion, last 24 h, counted per rule category.",
"use": "Click a slice to filter the signatures table. Categories like trojan, malware, exploit or command-and-control deserve attention; policy and protocol categories are usually informational.",
"what": "Share of Suricata alerts by rule category, for example policy violation, attempted information leak or trojan activity."
},
"security|IDS signatures": {
"source": "Suricata alerts from Security Onion (logs-suricata.alerts), last 24 h, grouped by rule name.",
"use": "Click a bar to filter the signatures table to that rule. Very frequent alerts are often noisy policy or info rules; a rule that is new or low-count but high severity matters more.",
"what": "Bar chart of the 15 Suricata rules that fired most often in the window."
},
"security|Inbound hits from listed IPs": {
"source": "Zeek conn logs from Security Onion, last 24 h, inbound connections checked against the loaded threat-intel feeds.",
"use": "Probing of an internet-exposed service by scanner-list IPs (CINS, ET) is common and low risk. Hits on internal devices, on serious feeds, or that moved data deserve a look. Use 💬 Ask AI.",
"what": "Internet addresses on a threat or scanner list that connected in to your devices, with feeds, connection count, targets and ports."
},
"security|Malicious JA / internal scans / detections": {
"source": "JA3 from Zeek TLS logs checked against the abuse.ch SSLBL JA3 list; scans from Zeek conn logs (failed connections to 20+ internal hosts or 40+ ports, thresholds in the network policy (More → Settings)); detections from Security Onion's detections index. All last 24 h.",
"use": "JA3 matches alone are weak because common TLS libraries collide with old malware entries; they matter when the destination is also threat-listed. An unexpected scanner or any detection hit needs a look.",
"what": "Three short lists: TLS client fingerprints (JA3) matching known malware, internal devices that look like they are scanning, and Security Onion detection rule hits."
},
"security|Outbound TI hits / newly-registered domains": {
"source": "Zeek DNS, TLS SNI and conn logs from Security Onion, last 24 h, checked against abuse.ch, Spamhaus, ET and CINS feeds; domain ages come from RDAP registry lookups.",
"use": "Hits on URLhaus, ThreatFox, Feodo, SSLBL or Spamhaus are serious, especially with answered connections. Domains 30 days old or less raise a finding; new domains are often legitimate but common in phishing and malware.",
"what": "Your devices contacting threat-listed IPs or domains, plus domains registered in the last 90 days, with domain age, query count and the devices involved."
},
"security|Research notes": {
"source": "Written when someone clicks Send to research (or copied by the reviewer from an earlier note), using web research and read-only queries against the snapshot data.",
"use": "Use these as context for the alarms. ⇄ compares the note with other models' opinions. Notes can be wrong or outdated; check the sources for anything important.",
"what": "Background notes on an event: what the AI looked up about signatures, domains, software or behaviour seen in this snapshot, with sources."
},
"security|Segmentation violations": {
"source": "Zeek conn logs from Security Onion, last 24 h, internal-to-internal flows checked against the network policy (More → Settings) zones, device classes, sensitive ports and allow rules. High: DMZ initiating inward, or IoT/camera reaching servers or using admin ports; medium: admin ports between hosts; low: cross-zone access.",
"use": "If a flow is expected, tick the green Clear box (it disappears; use “show checked” on the card to bring it back). Answered connections matter more than refused attempts. Use 💬 Ask AI if unsure.",
"what": "Internal connections between zones or devices that the zone policy does not allow, with severity, ports, connection counts, answered count and reason."
},
"security|Software inventory from traffic": {
"source": "Zeek software log from Security Onion, last 24 h or more.",
"use": "Look for old versions: rules flag OpenSSH below 9, Internet Explorer, Chrome below 120 and Firefox below 115 as outdated. Software new to a device raises a low finding once the baseline is ready.",
"what": "Software names and versions Zeek identified from network traffic, such as SSH servers, browsers and HTTP clients, per device."
},
"security|Threat-intel feeds": {
"source": "Public feeds refreshed at most every 12 h: abuse.ch URLhaus, ThreatFox, Feodo Tracker and SSLBL (IPs and JA3), Emerging Threats compromised IPs, CINS Army and Spamhaus DROP.",
"use": "Every feed should show a recent successful download. A failed or stale feed means matches from that source could be missed, so treat empty hit lists with caution.",
"what": "Download status of each threat-intelligence feed and how many indicators are loaded (domains, IPs, network ranges, JA3 hashes)."
},
"security|Zeek notices": {
"source": "Zeek notice log from Security Onion, last 24 h, grouped by notice type.",
"use": "Certificate notices for internal devices with self-signed certificates are usually normal. New notice types or scan notices are worth a look in Kibana.",
"what": "Notices raised by Zeek in the window, such as invalid certificates, scans or protocol policy events, with counts."
},
"security|Zeek weird": {
"source": "Zeek weird log from Security Onion, last 24 h, top 20 names with top sources.",
"use": "A steady background of weird events is normal on most networks (bad checksums, odd TCP). A large new count from one device can mean misbehaving software, a network fault or evasion attempts.",
"what": "Protocol oddities Zeek saw, such as malformed packets, unexpected protocol behaviour or broken connections, with counts and top sources."
},
"threatintel|DNS-tunnel suspects": {
"source": "Zeek DNS logs from Security Onion, last 24 h. Up to 60 domains with the most distinct subdomains are scored on subdomain count, length, entropy, uniqueness, odd query types and few sources; analyze.py rates score 5+ with 150+ subdomains as suspect, 3+ with 50+ as watch.",
"use": "Known benign patterns (CDNs, hash-lookup services) are cleared automatically. A remaining suspect queried by a single host is worth checking on that host; use the Alerts and host pages to dig further.",
"what": "Domains whose lookups look like data being smuggled through DNS: many distinct, long, random-looking subdomains. The count shows suspects out of all domains scored."
},
"threatintel|Feeds": {
"source": "Downloaded by the collector from abuse.ch (URLhaus, ThreatFox, Feodo, SSLBL IPs and JA3), Emerging Threats, CINS and Spamhaus DROP; refreshed when older than 12 hours.",
"use": "All ages should be under about 26 hours; an orange age or 'missing' means downloads are failing and matches are stale. Click a feed name to open its source list.",
"what": "The threat-intel feeds netmon uses, how many entries each holds, when it was last downloaded, and whether an outbound hit on it means malware/C2 or just scanner reputation."
},
"threatintel|Files flagged by Team Cymru MHR": {
"source": "Zeek files logs from Security Onion, last 24 h (executables, archives, scripts and similar types), with MD5/SHA1 hashes checked against the Team Cymru Malware Hash Registry over DNS (cached).",
"use": "Empty is normal. Any hit is serious: check the receiving host right away, find where the file came from, and confirm on the endpoint whether it was run.",
"what": "Files transferred over the network whose hash is known to antivirus engines as malware, with the detection percentage. The count shows flagged files out of all risky-type files seen."
},
"threatintel|Inbound connections from listed IPs, by target port": {
"source": "Zeek conn logs from Security Onion, last 24 h: internet-originated sessions that were answered (refused or unanswered scans are dropped), matched against the IP feeds.",
"use": "Click a bar to filter the Inbound table to that port. Expected only for services you deliberately expose; an unfamiliar port means something is reachable that probably should not be.",
"what": "Bar chart of answered inbound connections from blocklisted internet IPs, grouped by the port and internal host they reached (top 10)."
},
"threatintel|Inbound from listed IPs": {
"source": "Zeek conn logs from Security Onion, last 24 h: internet-originated sessions that got a reply (S0, REJ and similar failed states excluded), matched against the IP feeds.",
"use": "Mostly scanners hitting services you expose on purpose. Worry if the target or port is unexpected, or bytes are large. Use lookup to see the feeds, 💬 Ask AI on a row, or filter by port from the chart.",
"what": "Blocklisted internet IPs whose inbound connections to your network were answered, with feeds, bytes, the internal targets and ports."
},
"threatintel|Indicator lookup": {
"source": "The feed files in netmon's intel folder (abuse.ch URLhaus, ThreatFox, Feodo, SSLBL, ET compromised, CINS, Spamhaus DROP), matched by the dashboard server; domain age comes from the cached RDAP lookups.",
"use": "Type an indicator and press Check, or click any lookup link or underlined value in the tables below to fill it in. Not listed is normal; a hit on a malware or C2 feed deserves a look at which internal host talked to it.",
"what": "Checks a single IP address, domain or JA3 hash against every threat-intel feed netmon has downloaded, and shows which lists (if any) contain it, plus the domain registration date when known."
},
"threatintel|Listed domains / server names": {
"source": "Zeek dns and ssl logs from Security Onion, last 24 h, for internal clients, matched (including parent domains) against the URLhaus and ThreatFox host lists.",
"use": "Empty is normal. Any row shows which hosts looked the name up; check that host for infection and use 💬 Ask AI. A single lookup can come from a blocked ad or link, repeated lookups are more worrying.",
"what": "DNS names and TLS server names (SNI) used by internal hosts that appear on a malware or phishing domain feed."
},
"threatintel|Malicious JA": {
"source": "Zeek ssl logs from Security Onion, last 24 h, JA3 hashes matched against the SSLBL JA3 fingerprint list.",
"use": "JA3 matches can be false positives because common libraries share fingerprints. Check whether the client and server names look legitimate; repeated hits to odd servers are worth 💬 Ask AI. Click a hash to look it up.",
"what": "TLS client fingerprints (JA3) seen on your network that abuse.ch SSLBL lists as belonging to malware, with the malware name, client hosts and server names."
},
"threatintel|Malware / exploit-class IDS signatures": {
"source": "Suricata alerts from Security Onion, last 24 h, filtered by a keyword pattern on signature category and name.",
"use": "Sort by alert count and look at source and destination hosts. A 'yes' under Tuned benign means the signature is in the Known benign list (More → Settings) and has been judged harmless. Anything outbound from an internal host is the priority.",
"what": "Suricata IDS signatures in this window whose name or category points to malware, C2, exploits, botnets, mining, ransomware, phishing or admin/user compromise attempts, or with severity 1."
},
"threatintel|Newly registered domains": {
"source": "Zeek DNS logs from Security Onion, last 24 h (successful lookups only), with registration dates from RDAP queries that are cached forever once known.",
"use": "New domains are common for phishing and malware, but also for legitimate new services. Check who queried it and whether the name makes sense; click a domain to run it through Indicator lookup.",
"what": "Domains looked up from inside the network that were registered less than about 90 days ago, youngest first."
},
"threatintel|Outbound to listed IPs": {
"source": "Zeek conn logs from Security Onion, last 24 h, outbound connections only, matched against the IP and CIDR feeds; hits on malware/C2 feeds (URLhaus, ThreatFox, Feodo, SSLBL, Spamhaus) are sorted first.",
"use": "Empty is the normal state. A hit on a malware/C2 feed with established connections is serious: open the source host, use 💬 Ask AI on the row, and check Related events. Scanner-list hits alone are lower priority.",
"what": "Internet IPs on a threat feed that internal hosts connected out to, with feeds, connection counts, bytes and which hosts made them."
},
"threatintel|Region blocks": {
"source": "UniFi gateway API traffic-flow logs for the collection window, filtered to flows blocked by the Region Blocking policy.",
"use": "Incoming blocks are normal internet noise. Outgoing blocks from an internal client mean a device tried to reach a blocked country: check whether that is an app quirk or something unexpected.",
"what": "Traffic the UniFi gateway blocked because of its Region Blocking (country) policy, grouped by client, remote IP, region and direction (top 25)."
},
"threatintel|Threat-intel signals per snapshot": {
"source": "Each stored snapshot (one collection run twice a day covering the previous 24 h), combining Zeek matches against the feeds, the TLS profile and UniFi gateway security events.",
"use": "Look for a sudden jump or a series that is normally flat at zero becoming non-zero, especially outbound hits or malicious JA3. Steady inbound counts are usually internet scanning noise.",
"what": "A trend line of the main threat-intel counters per snapshot: listed inbound IPs, outbound IP hits, domain hits, newly registered domains, malicious JA3 and UniFi IPS threats."
},
"threatintel|UniFi IPS / firewall threat events": {
"source": "UniFi gateway API (system log, SECURITY category), fetched by unifi.py on each collection run.",
"use": "Read the message for the source and target; IPs are clickable. Occasional blocked inbound probes are normal. Repeated events against the same internal host, or events with an internal source, deserve investigation.",
"what": "Security events raised by the UniFi gateway's IPS/IDS and firewall, deduplicated, from the current window and the last 30 days."
},
"traffic|All ASNs": {
"source": "Zeek conn logs from Security Onion with ASN enrichment, last 24 h. It is the same sum of each device's top 8 ASNs as the Top ASNs chart, with nothing cut off.",
"use": "Use the search box to look up a provider, or sort by bytes. Small unfamiliar hosting providers are the ones to check with the threat-intel lookup or 💬 Ask AI.",
"what": "Full table of every autonomous system (network operator) in the snapshot, with bytes."
},
"traffic|All countries": {
"source": "Zeek conn logs from Security Onion with GeoIP enrichment, last 24 h; each device's top 10 countries by bytes on outbound internet connections, summed.",
"use": "Scan for countries you never expect to contact. Small amounts are often CDN or GeoIP quirks. Larger volumes are worth tracing on the Hosts page with a country filter.",
"what": "Full table of destination countries with bytes, the complete list behind the country doughnut."
},
"traffic|Blocks by policy": {
"source": "UniFi gateway traffic-flows API through the cloud connector, last 24 h (up to 20,000 flows; the count can be cut short on very busy days).",
"use": "Ad blocking, region blocking and your own firewall rules usually make up most blocks. A sudden jump in one policy, or blocks from a rule meant to isolate IoT, shows a device trying to reach somewhere it should not.",
"what": "Doughnut chart of blocked traffic flows by the gateway firewall or security policy that blocked them."
},
"traffic|Clients by network": {
"source": "UniFi Network API client list through the cloud connector, read at collection time.",
"use": "Check that counts match what you expect per network, for example no unknown devices on the trusted network and IoT kept on its own VLAN. Unknown clients are listed on the Hosts page under Gateway clients not in inventory.",
"what": "Doughnut chart of currently connected gateway clients by network or VLAN."
},
"traffic|Gateway health": {
"source": "UniFi Network API (stat/health) through the UniFi cloud connector, read during each collection run.",
"use": "Every subsystem should show ok. Rising drops, high latency or a short uptime point to ISP outages or an unexpected gateway reboot, which is worth matching against config changes on the Posture page.",
"what": "Status summary of the UniFi gateway: status per subsystem (WAN, WWW, LAN, WLAN, VPN), ISP, WAN address, latency, drops, uptime and clients online by network."
},
"traffic|Hosts & connections per snapshot": {
"source": "Baseline history built by analyze.py from Zeek conn data: one roughly 24 h record per day, about 30 days kept.",
"use": "Host counts should stay steady. A jump means new devices joined (check Hosts for unknown ones). A connection spike without more hosts often means scanning, a misbehaving app or a beaconing device.",
"what": "Chart of how many internal hosts were active (bars) and the total connections (line) in each baseline snapshot."
},
"traffic|Internal flows": {
"source": "Zeek conn logs from Security Onion, last 24 h, grouped by source, destination, port and transport (up to 5,000 groups). Answered means the connection was not rejected or left unanswered (states S0, REJ, RSTOS0, SH, OTH).",
"use": "Search for a port or device. Many connections with few or no answered ones look like scanning. Answered flows into sensitive ports (for example port 22, 445 or 3389) from unexpected devices are worth checking. Click an address for its host page.",
"what": "Table of device-to-device flows inside the network (source, destination, zones, port, protocol, service, connections, answered and bytes), showing the busiest 100."
},
"traffic|Internet bytes by country": {
"source": "Zeek conn logs from Security Onion with GeoIP enrichment, last 24 h. Each device's top 10 countries by bytes on outbound internet connections, summed.",
"use": "Most traffic usually goes to your own country and big cloud regions. A noticeable share to a country you have no link with is worth a check. Click a slice to open Hosts filtered to devices talking to that country.",
"what": "Doughnut chart of internet traffic volume by destination country."
},
"traffic|Internet upload by device": {
"source": "Zeek conn logs from Security Onion, last 24 h: bytes sent by each internal device on connections it opened to non-local addresses.",
"use": "Cloud backups, photo sync and video calls explain most large uploads. Unexpected upload from a camera, IoT device or idle PC can mean data theft or a misconfigured backup. Click a bar for the host page and compare with ⇄.",
"what": "Bar chart of the 15 devices that uploaded the most data to the internet."
},
"traffic|Protocols": {
"source": "Zeek conn logs from Security Onion, last 24 h: each device's top 10 detected protocols by bytes on connections it started, summed. Traffic Zeek cannot identify is left out.",
"use": "Encrypted web (ssl, quic) should dominate. Lots of plain http, ftp, telnet or remote-desktop style protocols is worth checking. Click a slice to open Hosts filtered to devices using that protocol.",
"what": "Doughnut chart of traffic volume by application protocol as identified by Zeek (ssl, http, dns, quic and so on)."
},
"traffic|Region blocks": {
"source": "UniFi gateway traffic-flows API through the cloud connector, last 24 h, flows blocked by the Region Blocking policy.",
"use": "Incoming blocks are usually internet scanners and mean the block is working. Outgoing blocks mean one of your devices tried to reach a blocked country, which deserves a check of that device.",
"what": "Table of flows blocked by the gateway's region (country) blocking: client, remote address, region, direction and count (top 25)."
},
"traffic|Risky flows": {
"source": "UniFi gateway traffic-flows API through the cloud connector, last 24 h; fields include time, source, destination, port, risk, action, direction, service and policies.",
"use": "Look for incoming flows that were allowed to devices that should not be reachable from the internet, and medium or high risk outgoing flows. Check whether a port forward explains them, then look at the target host.",
"what": "Raw list (up to 50) of flows the gateway rated above low risk, or incoming flows that were not blocked. The card only appears when there are any."
},
"traffic|Top ASNs": {
"source": "Zeek conn logs from Security Onion with ASN enrichment, last 24 h. Each device's top 8 ASNs by bytes on outbound internet connections, summed.",
"use": "Large CDNs, cloud and streaming providers are normal leaders. Hosting or VPS providers you do not recognise near the top deserve a look. Click a bar to open Hosts filtered to devices using that ASN.",
"what": "Bar chart of the 15 networks (autonomous systems, such as cloud or CDN providers) receiving and sending the most internet traffic."
},
"traffic|Top blocked clients": {
"source": "UniFi gateway traffic-flows API through the cloud connector, last 24 h, flows with action blocked.",
"use": "Ad and tracker domains blocked from TVs and phones are normal noise. Repeated blocks from a PC or IoT device to the same odd domain or region can mean malware calling home; open that device's host page and use Related.",
"what": "Table of the 10 clients with the most blocked flows, plus the 5 domains each was most often blocked from."
},
"traffic|Top talkers": {
"source": "Zeek conn logs from Security Onion, last 24 h: IP bytes per internal device, counting both connections it started and connections it answered, internal and internet.",
"use": "Streaming boxes, backups and game consoles usually lead. Watch for a device that is normally quiet climbing the list, or one where sent is much larger than received. Click a bar to drill down to that host.",
"what": "Stacked bar chart of the 20 devices that moved the most data, split into sent and received."
},
"traffic|Total bytes per snapshot": {
"source": "Baseline history built by analyze.py: one record of about 24 h folded in at most every 23 h, about 30 days kept. Total is the sum of every device's sent and received bytes from Zeek conn logs, so internal traffic counts at both ends.",
"use": "Look for steps or spikes, especially in internet upload, that do not match something you know about (new backup, big downloads). Find the device responsible with the host trend charts or the Top talkers chart.",
"what": "Line chart of total network bytes and internet upload for each baseline snapshot over time."
},
"traffic|Zone-to-zone matrix": {
"source": "Zeek conn logs from Security Onion, last 24 h, internal-to-internal only (broadcast and self traffic excluded); zones come from the CIDRs in the network policy (More → Settings).",
"use": "Hover a cell to see its top ports. Traffic within a zone and from trusted zones to infrastructure is normal. Cells going from IoT, cameras or guest zones into server or personal zones are what segmentation should block; see Segmentation violations on Posture.",
"what": "Heat map of internal traffic between network zones: each cell shows connections and bytes from one zone to another."
},
"users|Accounts": {
"source": "The dashboard's own user store (auth.py) and per-user notification preferences in the netmon store.",
"use": "Click Assign to limit a user's push notifications and alert count to their devices. Reset a password or delete accounts that are no longer used; deleted or reset users are signed out immediately.",
"what": "All dashboard user accounts with creation date, last sign-in, last password change and the devices each user is responsible for."
},
"users|Add user": {
"source": "Creates the account in the dashboard user store (auth.py). Usernames are 2-40 letters, digits or . _ @ -; passwords need at least 10 characters.",
"use": "Enter a username and the password twice, then press Add user. New users receive all urgent alerts until you assign them specific devices in the Accounts list.",
"what": "Form to create a new dashboard login."
},
"users|Locked out?": {
"source": "Command-line password reset built into the dashboard server (server.py set-password), run inside the dashboard container.",
"use": "On the dashboard host run the shown docker exec command with the username to set a new password or create the account. Failed sign-ins are also throttled (8 per 5 minutes per client), so waiting 5 minutes may be enough.",
"what": "Recovery instructions for when nobody can sign in, for example after a forgotten password or too many failed attempts."
}
};
