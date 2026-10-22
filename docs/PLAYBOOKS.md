# netmon investigation playbooks

How to use netmon day to day when something looks wrong, or when you want to go looking. Each playbook says where to start, what to pivot to, what normal looks like, how to decide, and what to do afterwards.

This is a companion to the [user guide](USER_GUIDE.md) (what every page shows), [CORRELATION.md](CORRELATION.md) (how events are linked), [RISK_SCORING.md](RISK_SCORING.md) (how host risk is computed) and [ACCESS_CONTROL.md](ACCESS_CONTROL.md) (who can do what). Examples use placeholders (`192.0.2.x`, `host-N`, `example.com`, `alex`); your dashboard shows your real names.

## Contents

1. [How netmon fits an investigation](#1-how-netmon-fits-an-investigation)
2. [The common method](#2-the-common-method)
3. [Troubleshooting a network problem](#3-troubleshooting-a-network-problem)
4. [Finding DNS tunnelling](#4-finding-dns-tunnelling)
5. [Researching a network or process anomaly](#5-researching-a-network-or-process-anomaly)
6. [Researching a security event](#6-researching-a-security-event)
7. [Researching lateral movement](#7-researching-lateral-movement)
8. [Finding an insider threat](#8-finding-an-insider-threat)
9. [A new or unknown device](#9-a-new-or-unknown-device)
10. [Data exfiltration](#10-data-exfiltration)
11. [Command-and-control and beaconing](#11-command-and-control-and-beaconing)
12. [A compromised IoT or camera device](#12-a-compromised-iot-or-camera-device)
13. [Brute force and account compromise](#13-brute-force-and-account-compromise)
14. [DNS bypass and resolver changes](#14-dns-bypass-and-resolver-changes)
15. [An exposed service or inbound attack](#15-an-exposed-service-or-inbound-attack)
16. [A device went silent, or the sensor is blind](#16-a-device-went-silent-or-the-sensor-is-blind)
17. [Tuning out noise without hiding real problems](#17-tuning-out-noise-without-hiding-real-problems)
18. [Quick reference](#18-quick-reference)

---

## 1. How netmon fits an investigation

netmon is a first-line analyst. It collects, baselines and correlates; it does not replace your judgement or the raw logs.

| Layer | What it gives you | Where |
|---|---|---|
| **Watcher** (every 15 min, no AI) | Fast alerts: new device, severity-1 IDS, threat-intel hit, new internet-facing port, DNS-tunnel burst, failed admin logins, host anomalies | Alerts, push notifications |
| **Snapshots** (collect + analyze) | Per-device traffic, DNS, TLS, ports, peers, detections, compared with that device's own 30-day baseline | Posture, Hosts, DNS & TLS, Traffic map |
| **Host telemetry** (Elastic Agent: Defend, osquery, system logs) | Processes, logins, sudo, listening ports, process-level network connections | Endpoints, Host findings, Network → Users |
| **Correlation** | Links between events (same host, IP, account, domain, ATT&CK technique) confirmed or rejected by a reviewer model | **Related** count on any row |
| **AI notes** | Reviewer copies of earlier verdicts; one-event research on request | ✨ verdict button, 🔬 Send to research |
| **Raw logs** | The ground truth | 🔎 **Open in Kibana** buttons |

Rule of thumb: netmon tells you **where to look and what changed**; Kibana tells you **exactly what happened**.

Limits to keep in mind:

- Network logs (Zeek) are kept only a couple of days on the sensor. Older time ranges come back mostly empty. The device registry and baselines are the long-term memory.
- Byte counts are lower bounds. If the sensor drops packets, totals are understated.
- Baseline rules need about three days of history on a device before they fire.
- DNS sent over TLS (DoT) or HTTPS (DoH) is encrypted and invisible to the DNS sensor. netmon flags the *use* of it, not the content.
- AI notes can be wrong. Check the evidence before acting on anything important.

## 2. The common method

Almost every investigation follows the same loop.

1. **Anchor.** Start from a signal: an alert, a finding, a user complaint, or a question. Write down the *device*, the *time* and the *thing that looked odd*.
2. **Set the time range.** Click 🕒 and choose a window that brackets the event (a custom range is collected on demand; at most 31 days, newest data first). Use at least a 24 h window when you want baseline comparisons, because shorter ranges are scaled up to a day.
3. **Open the device.** Devices → Hosts → the host. Read identity, zone, risk drivers, traffic, DNS/TLS habits, detections.
4. **Compare with normal.** Does the Baseline findings box say this is new? Does the Notes card say what this device is *for*? Check Network → Users if an account is involved.
5. **Pivot.** Use **Related** to see linked events and their artifacts (files, processes, users, IPs, DNS names). Use 🔎 to open raw events in Kibana. Use the Threat intel indicator lookup for any IP, domain or hash.
6. **Ask.** 💬 asks the AI about the item using netmon's data. 🔬 **Send to research** on an event gets web-researched context and links (admin-chosen model, costs tokens; use it for events that matter).
7. **Decide.** Benign, expected, or needs action. Record it.
8. **Record.** Check the item off, add a 📝 note (people's notes are authoritative for the AI), and clear segmentation flows that are expected. This is what stops the same thing re-alarming and teaches the reviewer.

Decisions that deserve a note: *why* a thing is normal ("backup job from host-4 to host-9 nightly"), what the device is for, and who owns it.

---

## 3. Troubleshooting a network problem

**Symptoms:** "the internet is slow", "the camera drops", "this website won't load", "the game lags".

netmon is not a speed tester, but it shows who is using the pipe, what is failing, and whether something upstream is blocking.

**Steps**

1. **Is it one device or everyone?** Overview → tiles and *Traffic per hour*. A flat line with a gap is an outage; a tall bar is a hog. Check **Capture loss** too: high loss means the numbers are understated, not that the network is broken.
2. **Who is using the bandwidth?** Network → Traffic map → *Top talkers* and *Internet upload by device*. Click the top bar to drill into that device. Sustained upload from a laptop or iPad is usually cloud backup (photos, drive); from a server it may be a backup, sync or a mining/exfil problem (see [section 10](#10-data-exfiltration)).
3. **What is failing?** Network → DNS & TLS → NXDOMAIN and failure counts per device. A device with thousands of NXDOMAINs is misconfigured or looking up a name that no longer exists (a common cause of "everything feels slow" for that device, and of noisy alerts). Also check *Resolvers*: a device pointed at a resolver that is down, or at a public resolver while local DNS is expected, fails in ways that look like "the internet is broken".
4. **Is the gateway blocking it?** Posture → Gateway security (UniFi): IPS blocks, region blocks, flows blocked by policy, and the top blocked clients and domains. If the failing app talks to a blocked region or category, that is your answer.
5. **Is it a segmentation block?** Posture → Segmentation violations, and Network → Lateral movement. A new rule or an IoT/guest zone restriction shows up as refused connections between zones.
6. **TLS problems.** DNS & TLS → certificates with problems and legacy TLS. Old devices that only speak TLS 1.0 to a cloud service that stopped accepting it fail silently.
7. **Did something change?** Baseline findings on the device: *new port*, *service-mix shift*, *went silent*, *new country*. Gateway security → admin changes shows configuration changes made on the gateway at that time.
8. **Raw confirmation.** 🔎 on the device's connection row to open Zeek `conn` events. Look at the connection `state`: many `S0` (SYN, no reply) means the destination is not answering or something is dropping it; `REJ`/`RSTO` means it is actively refused; `SF` is a normal completed connection.

**Quick KQL (Kibana Discover, Zeek connections for one device)**

```
event.dataset: "zeek.connection" and source.ip: "192.0.2.50" and connection.state: ("S0" or "REJ")
```

**Typical findings**

| What you see | Likely cause |
|---|---|
| One device with huge NXDOMAIN counts | Stale config pointing at a name that is gone; fix the config |
| Many `S0` to one destination | Destination down or blocked at the gateway |
| Slow only in the evening, top talker is a streaming/game device | Plain congestion |
| Internet upload at 3 am from a server | Scheduled backup; confirm against its notes |
| Device on a wrong resolver | DHCP option or hard-coded DNS; see [section 14](#14-dns-bypass-and-resolver-changes) |

If the dashboard shows nothing for a device you know is active, treat that as its own problem: see [section 16](#16-a-device-went-silent-or-the-sensor-is-blind).

---

## 4. Finding DNS tunnelling

DNS tunnelling hides data (or a command channel) inside DNS queries, usually as many random-looking subdomains of one domain the attacker controls, often with TXT/NULL queries.

**What netmon does for you**

- Every snapshot, the *DNS-tunnel scoring* box looks at the top registered domains by number of distinct subdomains. For each it samples queries and scores randomness (entropy), the share of unique names, and label length. `suspect` needs a high score and 150+ distinct subdomains; `watch` is a lower score with a high unique ratio.
- The 15-minute watcher raises an alert on a DNS-tunnel burst in the last hour.
- Per-device DNS profile rules raise findings for: query volume, many distinct names, unusually long names, a new query type (TXT/NULL/ANY are medium), a new TLD, a new heavy domain, a new external resolver (high), and DoH/DoT starting.

**Steps**

1. **Start at Posture → DNS-tunnel scoring.** Sort by score. For each row note the domain, distinct subdomain count and which devices asked.
2. **Judge the domain.** Legitimate high-cardinality domains are CDNs, cloud APIs, security products and reverse-lookup zones (`in-addr.arpa`). They have many subdomains but *repeat* them, so their unique ratio stays low. A tunnel has a **high unique ratio** (nearly every name is new), **long, high-entropy labels** (base32/base64-looking), and often few or no web connections to that domain.
3. **Open the 🔎 links on the row** (all lookups, NXDOMAIN, TXT/NULL/ANY, per source device, TLS sessions). Look at a sample of the names. Hex or base32 strings such as `mfrggzdfmztwq2lknnwg23tpobyxe43uov3ho.example.com` are tunnel-like; `a1b2.cdn.example.com` repeating all day is not.
4. **Find the source.** Which device is generating it? Open the host → DNS habits. Check its volume against its own baseline (the finding says "x times normal").
5. **Find the process (endpoint).** If the device runs the Elastic Agent, Devices → Endpoints → the host → network connections by process. A tunnel client is a process, so look for an unfamiliar binary, a script interpreter, or something running from a temp or home directory making many DNS requests.
6. **Check the answers.** TXT/NULL/CNAME answers carrying long strings suggest data coming *back* (a command channel). A tunnel that only sends is exfiltration; both ways is a C2 channel.
7. **Check how the device resolves.** DNS & TLS → *Resolvers*. A tunnel through the normal local resolver is visible to Zeek. The same traffic over DoH or DoT is **not**: look for DoH SNI use (a finding) or a device making many TLS sessions to a public resolver. That is a blind spot, not an all-clear.
8. **Check the domain's reputation.** Threat intel → Indicator lookup. Domain registration age is checked too; domains younger than 30 days are alarmed.
9. **Research.** 💬 Ask AI "is this domain a known tunnelling or C2 domain?", or 🔬 Send to research on the event.

**Kibana patterns (DNS)**

```
event.dataset: "zeek.dns" and dns.query.name: *.example.com
event.dataset: "zeek.dns" and dns.query.type_name: ("TXT" or "NULL" or "ANY") and source.ip: "192.0.2.50"
event.dataset: "zeek.dns" and dns.query.name: *.example.com and dns.response_code: "NXDOMAIN"
```

Field names follow your Security Onion version; confirm them in a Discover result before building filters.

**Known false positives**

- Reverse-lookup sweeps by smart TVs and discovery tools (`in-addr.arpa`) are excluded from scoring.
- CDN and cloud domains (video, social media, productivity suites, object storage) score 2 to 4 but stay below the watch line because they repeat names.
- Endpoint security and update services use long hashed subdomains.
- Mail-security blocklist lookups (DNSBL) produce many unique names to one domain.

**Decide and act**

- Benign: add the domain to the known-benign list (admin adds it to `dns_domains` on **More → Settings → Known benign**), check the row off, and add a 📝 note saying why.
- Suspicious: isolate or block the device at the gateway, block the domain, capture the process (command line, parent, path, hash) from Endpoints, and preserve the Kibana queries. Treat any credentials used on the device as exposed.

---

## 5. Researching a network or process anomaly

**Symptoms:** a *baseline finding* ("new port", "traffic spike", "new country"), an *unusual process* host finding, or a spike on a chart.

**Steps**

1. **Read the finding's evidence line.** It names the device, what changed and the baseline value ("12x normal", "first time port 8443").
2. **Look at the device's role first.** The Notes card on the host page says what it is. A laptop browsing new countries is normal; a printer doing so is not.
3. **Classify the anomaly.**

   | Type | Where to look | Questions |
   |---|---|---|
   | Volume spike | Host → traffic by hour, top peer for the spike hour | Is the peer a known cloud provider? Does a backup, update or sync explain it? |
   | New port or service | Host → services and ports; Baseline findings | Is something newly listening or newly connecting? An outbound port that was never used is a classic first sign |
   | New country or ASN | Host → traffic by country/ASN | A hosting/VPS ASN is more suspicious than a big cloud or CDN ASN |
   | New DNS or TLS habit | Host → DNS and TLS | New TLD, new resolver, new TLS fingerprint (JA4/JA3) = new software |
   | Went silent | Host → last seen | Powered off, moved zone, or dropped from the sensor |
   | Unusual process | Endpoints → host findings → Related | See below |

4. **For a process finding**, collect: the executable path and its hash, the command line, the parent process, the user, the start time, and any network connections it made. The point of the evidence is in the combination.

   - From a temp directory, a hidden directory, or a user's home directory run as root: suspicious.
   - A service (web server, database, LM-style local AI server) spawning a shell or `curl`/`wget`/`nc`: investigate.
   - An interpreter (python, node, powershell) opening an Internet connection: depends on the script path and who runs it; trusted tool directories are already excluded.
   - A binary that changed on disk outside a package update: the baseline tracks hashes of binaries outside package-managed paths and raises *Binary changed*. Check the file hash against the Threat intel lookup. A hash lookup against a malware-hash database is also done nightly.
   - Process memory tricks (anonymous executable memory such as `memfd_create`) show up from legitimate things too: hypervisors, crash-dump tools, message buses. Compare with what is installed.

5. **Pivot with Related.** The Related popup lists the artifacts that connect events: the same process, file, user, IP or DNS name across several events. Several unrelated findings naming one process is stronger than any single one.
6. **Check timing.** Did it begin at a reboot, an install, a package update, a scheduled job, or a user login? Anomalies that cluster at known times (job start, boot) are usually side effects.
7. **Check the baseline findings of *other* devices at the same time.** A fleet-wide change at the same moment is normally a software update, DHCP change or upstream outage, not an attack.
8. **Research.** Ask AI with 💬 ("what is this process / port / domain, and is it normal for this kind of device?"). For something that matters, 🔬 Send to research gets a web-researched note with links.
9. **Decide.** Check it off and add a note if expected. If not, follow the playbook for what it turned out to be: [C2](#11-command-and-control-and-beaconing), [exfiltration](#10-data-exfiltration), [lateral movement](#7-researching-lateral-movement).

**Useful raw queries**

```
# process network activity on one endpoint
event.dataset: "endpoint.events.network" and host.name: "host-5" and process.name: "update-helper"

# process starts from a temp directory
event.dataset: "endpoint.events.process" and process.executable: (/tmp/* or /var/tmp/* or /dev/shm/*)
```

---

## 6. Researching a security event

An IDS alert, a threat-intel hit, a gateway threat, a host finding, or a watcher alert.

**Steps**

1. **Read what it actually says.** For IDS: signature name, `sid`, severity, source, destination, port, count, first/last time. Do not rely on the name alone: many signatures describe a *class* of traffic (STUN, remote-support tools, scanners) that is normal in a home.
2. **Direction and state.** Who started it? Check the connection state before concluding. A missed SYN flips the apparent direction in Zeek: an "outbound" hit may really be a reply. Confirm with the TCP flags or `connection.history` in the raw event (a lowercase first letter means the originator is guessed).
3. **Did it succeed?** An inbound exploit signature that was only *attempted* against a closed or unpatched-irrelevant port is noise. Look for evidence of success: a response with substantial bytes, a new outbound connection from the target afterward, a new process or login on it.
4. **Scanner or targeted?** Open lists such as scanner feeds (CINS, ET compromised) only matter if your side *answered* or *initiated*. Internet background scanning of an exposed port is constant and normal.
5. **Who and what is the target?** Host page: its role, risk score, exposed ports, known vulnerabilities, whether it is a crown-jewel. A hit on a hardened, patched service is lower priority than the same hit on an unpatched one.
6. **Pull the Related events.** Same attacker IP on several devices? Same device with an IDS alert *and* a new process *and* a login? That chain is the story. The Related popup also lists the correlated artifacts with a benign/expected/suspicious call.
7. **Look up the indicators.** Threat intel → Indicator lookup for each IP, domain, hash and JA3. A JA3 hit in isolation is weak (stock Windows TLS has a JA3 shared with some malware); escalate only if the destination is *also* on a threat list.
8. **Check the ATT&CK page.** Which technique does it map to, and has that technique been seen elsewhere in the window? Exposure-only entries are weaknesses, not activity.
9. **Research.** 💬 for a quick answer; 🔬 **Send to research** for web-researched context (signature background, known false-positive patterns, threat-actor links). The reviewer copies earlier verdicts for repeat events, so research once and the family is covered.
10. **Close the loop.** Check off, annotate, and for permanent noise use the 🚫 suppress dialog (hides the finding but keeps correlation) or a *Never send* rule on AI review so the reviewer and research job skip it.

**Severity guide**

| Evidence | Treatment |
|---|---|
| Sev-1/2 IDS + success evidence + target is a crown-jewel | Act now (contain, then investigate) |
| Threat-intel IP/domain matched by an *internal* device's own lookup | Investigate this hour; find the process |
| Inbound scan or exploit attempt, no response | Log, verify exposure, patch/close the port |
| Known-benign family with a note | Check off |

**Preserve evidence** before cleaning anything: use 🔎 to open and save the Kibana queries, export the relevant events, and note times in UTC (all data is UTC; the dashboard shows your local time).

---

## 7. Researching lateral movement

Lateral movement is an attacker (or a compromised credential) moving from one internal host to another: admin protocols between hosts, new east-west connections, credentials used on many machines.

**Where**

- **Network → Lateral movement**: the host-to-host graph, zone-to-zone, and the **Admin access** list.
- **Posture → Segmentation violations**: flows the zone policy does not allow.
- **Devices → Endpoints**: logins, sudo, and processes on each host.
- **Network → Users**: the account behind it.

**What it watches:** SSH, Telnet, RDP, WinRM/PowerShell remoting, VNC, SMB/PsExec, RPC/WMI, Docker and Kubernetes APIs, database ports, remote-support tools (TeamViewer, AnyDesk), hypervisor and management interfaces (Proxmox, ESXi, IPMI, Cockpit, Webmin). Each session is assembled from network evidence, login records (accepted, failed, invalid user) and endpoint execution of admin tools.

**Steps**

1. **Start at Admin access.** Sort by failures. Ask of every session: is this source *supposed* to administer this destination? Your laptop SSHing to a server is expected; a camera, TV or guest-zone device doing it is not.
2. **Failed then successful.** Three or more failed logins followed by a success on the same account is a guessed or stuffed credential and is marked high. Ten or more failures, or three invalid user names, is high on its own.
3. **Fan-out.** One source reaching *many* internal hosts on an admin port in a short time is a sweep. Use the graph: a star pattern around a single node is an attacker pivot or a scanner. A line of hosts (A→B, then B→C) is a pivot chain.
4. **Pivot chains.** If host B received an admin login from A at 02:10 and B then started admin sessions to C at 02:25, treat A, B and C as possibly one intrusion. Widen the time range and check B's processes between those times.
5. **Check the zone crossing.** Zone-to-zone matrix: hover a cell for the top ports. IoT → servers, guest → main, DMZ → LAN are the crossings that matter. A DMZ host initiating into the LAN is the classic outcome of a compromised internet-facing server.
6. **Check the endpoint at the destination.** Endpoints → host → logins (accepted from which source IP, which account, which method), sudo use, new users or groups, new listening ports, new scheduled tasks or services. A PsExec-style service creation or a remote-exec tool on the target is strong evidence.
7. **Check the account.** Network → Users → the account page: normal hosts, normal sources, active hours. Is this the usual source and hour? Is a privileged account being used somewhere it never was before?
8. **Use several time periods.** On Lateral movement, **+ Add period** (up to 8) to compare the incident day with several normal days in one view. Connection and login counts add up and each link keeps its worst risk; a link present only in the incident period stands out.
9. **Related events.** Open Related on the admin session to find linked processes, files and DNS names.
10. **Decide.** Expected (a documented admin path): click the green **Clear** on the flow and add a 📝 note; for a permanent exception have the admin add an `allow` rule in the network policy (**More → Settings**). Not expected: contain the source, reset the account credentials and look at what the account did on each host.

**Direction caveat.** Check `connection.state` before blaming the source. Flipped-direction records can make a server reply look like it initiated the session.

**Raw queries**

```
# internal-to-internal admin traffic from one source
event.dataset: "zeek.connection" and source.ip: "192.0.2.50" and destination.port: (22 or 3389 or 5985 or 445 or 135)

# accepted SSH logins on a host
event.dataset: "system.auth" and event.action: "ssh_login" and event.outcome: "success" and host.name: "host-5"
```

**Not lateral movement (common false alarms):** hosts of one person managing each other on a schedule, a monitoring or backup server, management-network discovery broadcasts from the gateway, and UniFi controller traffic. Record each as an `allow` rule or note once confirmed.

---

## 8. Finding an insider threat

An insider is someone with legitimate access who misuses it: copying data, snooping, bypassing controls, or abusing admin rights. At home or in a small business this is a family member, a contractor, a guest, or a stolen but valid account. netmon has no HR or DLP data. It sees **behaviour that departs from that account's and device's own history**. Always treat the result as a lead for a human conversation, not proof; patterns of normal curiosity look similar to misuse.

**Handle with care.** Check who is permitted to monitor whom, tell the people involved what is logged where required, and keep findings to those who need them. The [audit log](AUDIT_LOG.md) records who viewed what in netmon itself.

**Indicators and where to see them**

| Indicator | Where in netmon |
|---|---|
| Activity at unusual hours | Network → Users → account → hour-of-day strip and active hours |
| Login to hosts the account never used | Account page → hosts, sources, methods |
| A privileged account (sudo/root) used interactively for ordinary work | Users → flag *privileged*; Endpoints → sudo events |
| Large uploads or copies to external storage, personal cloud, or unknown hosts | Traffic map → Internet upload by device; host → top peers, ASN |
| Access to data stores (file shares, databases, NAS) well above normal | Hosts → internal flows; SMB/NFS/DB port volumes on the device |
| Use of anonymising or bypass tools: VPN, Tor, DoH/DoT, proxies, personal tunnel services | Baseline findings: new resolver, DoH, new TLS fingerprint, new country; DNS & TLS |
| Disabling or tampering with security tooling | Endpoints → agent status, Defend failures, "agent-off" findings |
| Creation of accounts, groups or keys | Host findings: new user / group / authorised key |
| Attempts to reach resources outside their zone | Segmentation violations; Lateral movement |
| New removable storage or tools | Endpoint osquery/Defend events (USB, new software, new binary hash) |
| Repeated failed access to restricted systems | Admin access failures; invalid-user counts |

**Method**

1. **Define the question.** "Did account `alex` or device host-7 move or copy data between date A and B?" A specific question beats browsing.
2. **Account view.** Network → Users → `alex`. Establish the baseline: usual hosts, sources, methods, hours, how many reports the account appears in. A *new* flag means the account first appeared recently.
3. **Device view.** Map the account to its device(s). On each: traffic by hour, upload volume, top peers, countries, ASNs, DNS habits, and baseline findings from the time window.
4. **Timeline.** Put events on one timeline using the Kibana links: logins, process starts, large transfers, DNS to storage or file-sharing domains, connections to personal cloud, and any removable-device events. Use UTC throughout.
5. **Compare with peers.** Is this the only device that behaves this way, or does every similar device? Behaviour shared by the whole household is policy, not misuse.
6. **Look for evasion.** Resolver changes, DoH/DoT, VPN/Tor fingerprints, playit/ngrok-style tunnel services, a different MAC on the same IP, devices that appear only at certain hours (use New devices and the device registry).
7. **Check the intent chain.** Reconnaissance (browsing shares, listing directories, scanning), access (new logins or authentication to systems), collection (large reads), staging (archive creation), exfiltration (large upload to a destination outside the baseline). Even two links of that chain together are more meaningful than one.
8. **Get the other half.** Logs show *that* a transfer happened and where to, not *what* or *why*. Corroborate with non-technical sources before drawing a conclusion.
9. **Record carefully.** Use 📝 notes with facts and times, not conclusions about a person. Restrict the Notes visibility by role (User-role notes are held for approval before the AI reads them).

**Common benign explanations:** photo and drive backup, a work-from-home VPN, a parent-approved gaming tunnel, a new hobby tool, travel, a device upgrade, or a shared device.

---

## 9. A new or unknown device

**Trigger:** watcher alert "new device joined", a *new-device* finding, or Hosts → New devices.

**Steps**

1. **Identify.** Hosts → the device: MAC, vendor from the MAC prefix (OUI), hostname, IPs, first seen. Randomised MACs (the second hex digit of the first byte is 2, 6, A or E) are normal for phones and laptops joining Wi-Fi and look like a stranger every time.
2. **Is it in the inventory?** A device missing from the DHCP inventory raises the severity. Compare against the gateway's client list (Gateway security → clients not in the inventory, IP conflicts, first seen in window).
3. **Watch the first hour.** Its DNS names usually identify the product (vendor cloud names). Its ports, its zone and what it tries to reach tell you whether it is a phone, a TV or something scanning.
4. **Check for the same IP with a new MAC** (or vice versa). A device whose IP changed can look new when the sensor lacks the MAC. A virtual-machine host that resets its virtual-interface MACs on each reboot will raise a burst of "new device" alerts that are not rogue devices.
5. **Is it scanning?** Fan-out to many internal hosts on one port is a scan; the Lateral movement and Segmentation pages show it.
6. **Decide.** Known: add it to the inventory (name it) and write a 📝 note. Unknown: block it at the gateway, find the Wi-Fi network or switch port it joined through, and review whether the Wi-Fi password should be changed.

---

## 10. Data exfiltration

**Signals:** a big upload to a new destination; slow steady upload at odd hours; uploads to storage, paste or file-sharing services; DNS or ICMP carrying data; archives created on an endpoint.

**Steps**

1. **Traffic map → Internet upload by device.** Sort by upload. Click the top device.
2. **Compare with its baseline.** The finding states the multiple of normal. Known heavy uploaders (photo backup from a family tablet, a backup server to a cloud bucket) are explained in their notes.
3. **Where is it going?** Top peer for the spike hour: destination IP, ASN, country, and the TLS server name (SNI) or DNS name. Cloud storage and personal-drive names are common; a bare IP in a hosting ASN with no name is not.
4. **How is it going?** Over HTTPS to a cloud service, over SSH/SCP/rsync, over an unusual port, over DNS (see [section 4](#4-finding-dns-tunnelling)), or over a VPN tunnel. Encrypted content cannot be read; judge by destination, volume, timing and process.
5. **What process?** On endpoints, network connections by process. Look at archive tools (zip, tar, 7z, rar) run shortly before, and a tool such as `curl`, `scp`, `rclone` or `rsync` run to send.
6. **What data?** Directory listing/listing of file-share reads by the same account just before; file events if collected. Large internal reads from a file server by a device that does not usually read it precede most exfil.
7. **Pivot.** Related on the spike finding: the destination may also appear in threat intel, beacons, or other devices' DNS.
8. **Contain and decide.** If unexplained, block the destination at the gateway, isolate the device, and move on to a full investigation.

**Kibana**

```
event.dataset: "zeek.connection" and source.ip: "192.0.2.50" and not destination.ip: (10.0.0.0/8 or 172.16.0.0/12 or 192.168.0.0/16)
```
Then sort by `source.bytes` / `client.ip_bytes` (prefer these over total bytes when the sensor drops packets).

---

## 11. Command-and-control and beaconing

Malware that phones home on a timer. netmon's **Beacon candidates** box finds source/destination/port pairs with at least ~36 connections whose timing is regular, scored on interval skew, jitter, coverage and size.

**Steps**

1. **Posture → Beacon candidates.** Sort by score. The device, destination, port, interval and count are in the row; the same list is on the device page.
2. **Rule out the usual suspects.** NTP (123) and connectivity checks are expected. Smart-home hubs, cameras, TVs and phones all poll cloud services every few minutes: most beacons are update, telemetry or keep-alive traffic. Resolver pings to several public DNS servers in rotation are a connectivity check. A "beacon" on a very low port number may really be ICMP type/code recorded as a port.
3. **Who is the destination?** Threat intel lookup; domain age (young domains are alarmed); ASN and country; certificate (self-signed, odd subject); JA3/JA4 of the client. A vendor-owned domain on a known cloud is almost always benign. A raw IP in a VPS ASN with a self-signed certificate is not.
4. **Does the shape fit malware?** Fixed interval with small jitter, small and uniform request/response sizes, run through the night, from a device that has no reason to talk to that service.
5. **What process (endpoints)?** The beacon should map to one process. An unsigned binary, a script, or a system utility making periodic outbound connections is the lead.
6. **Check for the same destination on other devices** (Related, or search the IP in Kibana). The same unusual destination on several hosts is a campaign or a shared tool.
7. **Decide.** Check off with a note ("vendor telemetry, domain X") or contain.

---

## 12. A compromised IoT or camera device

Cheap cameras, TVs, bulbs and hubs are rarely patched and often internet-exposed.

**Signals**

- The device starts talking to **new countries or ports**, or begins receiving inbound connections from the internet.
- It starts scanning or reaching into other zones (segmentation violations).
- High upload from a camera that normally sends little.
- It joins a botnet pattern: many short connections to many IPs on one port, or DNS to random-looking names.
- Unexpected DNS resolver (cameras often hard-code public resolvers; that alone is a known habit, a *change* is not).

**Steps**

1. Hosts → the device → *iot destinations*. IoT and camera classes get an allowlist baseline of domains/ASNs/IPs; anything outside is a finding.
2. Segmentation: IoT should talk to the internet and to its hub, not to servers or admin ports.
3. Inbound: Posture → baseline *new listening port* (high when internet sources). Exposed IoT admin interfaces are a top risk.
4. Gateway IPS and region blocks: blocked outbound attempts from the device show attempted bad behaviour even when it was stopped.
5. Fix: update firmware, move it to the IoT zone, remove port forwards/UPnP, change default credentials, and where it cannot be fixed, block its internet access except to the vendor cloud.

---

## 13. Brute force and account compromise

**Signals:** many failed logins; invalid user names; failed then success; logins from unusual sources; a new key or user.

**Steps**

1. **Where is it aimed?** Lateral movement → Admin access (internal) and Posture → host findings (failed logins, sudo). For external attempts see [section 15](#15-an-exposed-service-or-inbound-attack).
2. **Source.** Internal source = a compromised or misbehaving device; external = a scanner or an attacker. Check the source in Threat intel.
3. **Pattern.** One username with many password tries (brute force), many usernames with one password (spray), a list of common names like `admin`, `root`, `pi`, `oracle` (dictionary).
4. **Did it work?** A success after failures from the same source is high risk. Check that account's activity afterwards: new processes, sudo, new keys, new users, new outbound connections.
5. **Contain.** Reset the credential and any shared ones, rotate SSH keys, disable password SSH on exposed hosts (it will also show up on the Fix list), and block the source.
6. **Prevent.** Key-only SSH, MFA where available, an allow-list of admin sources through an `allow` rule so deviations are loud.

---

## 14. DNS bypass and resolver changes

**Why it matters:** devices that skip your DNS dodge filtering and hide their lookups. Sometimes it is just the vendor; sometimes it is evasion.

**Steps**

1. DNS & TLS → *Resolvers*: external resolvers per device (flagged). Baseline findings: *new resolver* (external = high), *DoH*, *DoT start*.
2. Classify: some camera and media vendors hard-code public resolvers; recent phones and tablets automatically upgrade to encrypted DNS to their provider's resolver (via discovery of designated resolvers) so their DNS disappears from the DNS sensor. Both are habits you note once.
3. A *change* on a laptop or server to a new external resolver or to DoH is more interesting: ask who changed it and why.
4. To keep visibility, redirect port 53 to your resolver at the gateway and block known DoH/DoT endpoints for devices that should not use them.
5. Remember the blind spot: DoH/DoT traffic is seen as TLS to a resolver only; look at TLS server names and volumes instead of queries.

---

## 15. An exposed service or inbound attack

**Signals:** watcher alert "new internet-facing port"; sev-1 IDS from the internet; many connections from a single external IP; unanswered SYNs followed by an answer.

**Steps**

1. **What answered?** Baseline *new-listening-port* (high with internet sources) and the Hosts page → served ports. Only a connection that was *answered* proves the port is reachable.
2. **Is it intended?** Remote-access tunnels (a cloud tunnel daemon, a VPN server, a game server) are expected and produce inbound-looking connections from the provider's IPs. Check the host notes.
3. **Who is knocking?** Top external sources by connection count, country, ASN, and threat-intel/scanner list status. Mass scanners are constant background.
4. **Is it exploitable?** Cross-check the service version in the software inventory with the Fix list/vulnerability entries (Risk → Vulnerabilities).
5. **Reduce exposure.** Close or restrict the port, use a VPN or tunnel with authentication instead, geo-restrict, rate-limit; confirm afterwards that the finding stops recurring.
6. **Post-event check.** Look for what the target did *after* the contact: new outbound connections, new processes, new logins.

---

## 16. A device went silent, or the sensor is blind

**Signals:** "went silent" finding; a camera with no traffic; endpoint *agent-off*; sudden drop in total connections; capture loss rising.

**Steps**

1. **Is it the device or the sensor?** Compare with the gateway: if the UniFi client list still shows traffic for the device but the sensor sees none, the device moved off the capture path (a reboot of a virtualised host, a changed switch mirror or a link flap). A drop across *all* devices points at the sensor.
2. **Capture loss.** Overview → capture loss. High loss means the byte totals and some detections are incomplete, which weakens every other playbook.
3. **Agent health.** Endpoints → agent status and telemetry streams. A host that stops sending process/auth data, or whose agent is unhealthy or blocked from the fleet server, is a blind spot. Agent-off for a host with a garbled or changing hostname: pivot on the agent ID before treating it as a new host.
4. **Rule out a reboot or update.** Scheduled restarts, VM host maintenance and package updates explain gaps and are followed by "exec-new", "binary changed" and "new listening port" noise that settles.
5. **If unexplained**, treat a security agent being turned off on a host as a possible tampering event and check logins around that time.
6. **Fix and record.** Restore the capture path or agent, then confirm that the next snapshot shows the device again.

---

## 17. Tuning out noise without hiding real problems

A tool that cries wolf gets ignored. Tune with a reason and keep an exit.

| Situation | What to use | Effect |
|---|---|---|
| "I looked, it's fine, once" | ☐ Check off | Hidden, listed on Checked, carries over; **reopens** if the reviewer later classifies it suspicious |
| "This flow is allowed" | Green **Clear** on a segmentation violation | Stops counting toward risk; shown as allowed; reversible under Cleared segmentation |
| "This is permanently allowed" | `allow` rule in the network policy (admin, More → Settings) | Policy-level exception |
| "This family of events is noise" | 🚫 suppress (admin / defender) | Hides the finding, keeps correlation |
| "Don't send this to the model" | Never-send rule (AI review → Review limits) | Skipped by reviewer/research; reduces token cost |
| "This domain / signature is benign here" | Known benign list (admin, More → Settings) | Separated from signal in scoring and reports |
| "This device behaves like this on purpose" | 📝 host note (category *behavior* or *role*) | The AI reads it; people's notes are authoritative |

Guidelines:

- Write the *reason* in the note, not just "ok". Future you and the reviewer both depend on it.
- Never suppress a whole severity, a whole device or a whole port range because one item was noisy. Match as narrowly as you can (host plus ID, or a family).
- After tuning, re-check after a few days: the finding should drop, and nothing important should vanish.
- Review the Checked page and Cleared segmentation occasionally. An exception made two months ago may no longer be true.

---

## 18. Quick reference

| I want to… | Go to |
|---|---|
| See what is happening now | Overview, Alerts |
| Look at an incident window | 🕒 time range (custom range, up to 31 days) |
| Everything about a device | Devices → Hosts → host |
| What a computer is running | Devices → Endpoints → host |
| What an account normally does | Network → Users → account |
| Admin logins and sessions | Network → Lateral movement → Admin access |
| Compare an incident day with normal days | Lateral movement → **+ Add period** |
| Possible tunnelling | Posture → DNS-tunnel scoring |
| Possible C2 | Posture → Beacon candidates |
| Check an IP, domain or hash | Security → Threat intel → Indicator lookup |
| Raw logs | 🔎 on any row (needs the Kibana address in site settings) |
| What else is connected to this | **Related** count |
| What the AI thinks | ✨ verdict, 💬 Ask AI, ⇄ Compare models (admin) |
| Research one event on the web | 📝 → 🔬 Send to research |
| Which hosts are riskiest and why | Security → Risk |
| Who changed what in netmon | More → Audit log (admin) |

**Maintainers:** this file contains no site-specific IPs, hosts or account names, because the repository is public and the sensitive-data gate scans docs. Keep examples to placeholders.
