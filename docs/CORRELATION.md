# How netmon connects the dots

This page explains three features that work together: **admin-access monitoring**, **event correlation** with a
**local-LLM review**, and the dashboard tools for working through the results (drill-down, Related column,
collapsible and rearrangeable boxes). For installation see [SETUP.md](SETUP.md).

## 1. Admin access (lateral movement)

Every way an administrator, or an attacker moving sideways, gets onto another machine is tracked between
internal hosts, **successful and failed**.

| Category | Protocols (catalog in `adminproto.py`) |
|---|---|
| Remote shell / desktop | SSH, Telnet, RDP, WinRM / PowerShell remoting, VNC, rexec/rlogin/rsh, TeamViewer, AnyDesk, RustDesk |
| Remote execution / management | SMB admin shares (PsExec), RPC / DCOM (WMI, PsExec service), Docker API, Kubernetes API, kubelet, MikroTik Winbox, Proxmox, VMware ESXi, IPMI, Cockpit, Webmin |
| Databases | MSSQL, MySQL, PostgreSQL, Redis, MongoDB (failures count; successful app traffic is normal) |

**Evidence** (`extras.admin_access()`; each source is optional):

- **Network sensor (Zeek conn):** every connection to an admin port, split into *connected* and
  *refused/unanswered* (S0, REJ, RSTOS0, RSTRH, SH, SHR. OTH is not a failure).
- **Login results:** endpoint auth logs (sshd accepted / failed / invalid user), Windows 4624/4625 network and RDP
  logons (logon types 3, 10, 8), Zeek `ssh` auth_success, `rdp` result, `ntlm` / `kerberos` success, PsExec-style
  service creation (`dce_rpc` svcctl CreateService) and PSEXESVC written over SMB.
- **Commands run on endpoints:** admin client tools (ssh/scp/rsync, xfreerdp, PsExec, impacket, winrs, evil-winrm,
  PowerShell remoting, nxc...) with the machine they targeted. Local-only use is ignored. **Passwords, hashes and
  `user:pass@` are removed** from command lines before anything is stored.

Evidence is merged per *(from, to, protocol)* and rated (`lateral.admin_sessions()`, also used by the risk score,
the nightly report and the watcher):

| Level | When |
|---|---|
| High | ≥ 10 failed logins, ≥ 3 invalid user names, or ≥ 3 failures followed by a success on the same account (possible guessed password) |
| Medium | any failed login, or ≥ 5 refused connections |
| Low | 1–4 refused connections, or a successful session not covered by the network policy's `allow` list |
| Allowed | a successful session that the network policy allows |

Failures also raise **host risk**: they add to the *threat* score of the machine being logged into and to the
*reach* score of the machine trying. On the dashboard: **Network → Lateral movement → Admin access** has
stat tiles, a logins-by-protocol chart (click to filter), an outcome chart, the session list and the admin tools
seen.

**The 15-minute watcher** (`watch.py` check 7) runs the same logic over its window. It raises **Admin ALERT**
(investigate) for high and **Admin notice** for medium, tagged with ATT&CK (T1110.x brute force, T1021.x remote
services), muted for 12 h per *(from, to, protocol, level)*.

## 2. Event correlation

`dashboard/app/correlate.py` (served at `/api/correlate?id=<snapshot>`) turns every event in a snapshot into a node:

| Type | Source |
|---|---|
| Alert | watcher alerts in the window (for the newest snapshot: up to now) |
| Finding | baseline behaviour findings |
| IDS | Suricata signatures (very chatty info rules are skipped) |
| Admin | admin sessions (above) |
| Endpoint | Elastic Agent / osquery host findings |
| Gateway | UniFi gateway events: IPS threat detections, high-severity, WAN, device and VPN events (`gw|<time>|<key>|<src>|<dst>`) |
| Threat intel | inbound / outbound listed IPs, listed domains |
| Vulnerability | open Fix-list items: timeless, related by host |

Candidates are pairs that **share an entity**: an internal host (MAC addresses and endpoint host names are resolved
to the same IP; gateway interfaces ending in `.1` are ignored), an external IP, a domain or a user account. Nothing is
linked just for being close in time. An entity that sits on most events (more than 60, or half of all events) is
treated as noise and creates no candidates. Each candidate gets a score:

| Part | Points |
|---|---|
| Shared entities, weighted by rarity | weight × 1 / (1 + log₂(1 + n/4)), n = events carrying the entity. Weights: external IP 4.0, domain 3.5, internal host 3.0, account 2.0 |
| Time (events with a time, no vulnerability involved) | gap between the two time spans ≤ 15 min **+2** ("within 15 min", or "same time window" for long spans); ≤ 1 h **+1**; more than 6 h apart **−1.5** |
| Same problem seen by two detectors, and a shared entity | **+2** (e.g. the "SSH password login" vulnerability and SSH sessions with failed logins; a threat-intel finding and the IDS reputation signature for the same IP) |
| Same ATT&CK technique | **+1** |
| Vulnerability and an event that share a host | **+1.5** ("vulnerability on the same host"); time is not scored for vulnerabilities |
| Two vulnerabilities on one host | score × 0.5 (context, not an incident chain) |

Kept: score ≥ 1.5, at most 4 of any one type and 10 per event. This is only the *proposal*; the time-window setting,
the review limits and the reviewer (section 3) decide what is actually looked at.

**Artifacts read from the event itself.** While it builds the events, `correlate.py` pulls the concrete things each
event already names: accounts (`user alice`, "accounts alice (1 failed, 2 ok)", login-attempt users), processes
(executables in program directories, parent process, command line), files (paths, with a SHA-256 when the text has
one), DNS names (public domains; `.lan`/`.local` ignored), plus the event's host IP and destination IPs. Up to 10 per
event, as `[kind, value, relation]`, without any lookup and before any review. They appear in the Related popover
immediately and are handed to the reviewer as "known artifacts" of each event.

## Profiles: accounts and frequent IPs

Every correlation pass also records, without any model: the accounts seen in endpoint logins, auth failures, sudo, account changes, admin sessions and suspicious processes (**Network → Users**, `accounts.py`), and how often each IP appears in correlated events, as source or destination, with the accounts, processes and DNS names named in those events. From that it keeps host notes (category *behavior*, tagged `[profile:ip]` / `[profile:users]`, author netmon) up to date for the newest report: "frequent" is 5+ events for an internal IP and 3+ for an external one, top 25. The reviewer reads these as `ai_note`s. They are counts, not verdicts; delete a note on the Notes page and it is rewritten next pass if still true.

## 3. Correlation review (decision model + reviewer model)

The script only *proposes* links. **Models decide:** the decision model (clef) decides every link and every event's
label; the reviewer model (Gemma or whichever is selected) writes the notes. `dashboard/app/corr_llm.py` runs as a background thread in the
dashboard container. With the **decision model** on (the default, AI review → Decision model) a review pass has two
stages; with it off, the older reviewer-only flow is used (described at the end of this section).

1. **Links — decision model (clef).** For the newest snapshot (and any snapshot someone opened in the last hour, at
   most two), every undecided candidate link that the **review limits** (below) allow becomes one yes/no question to
   Cloudflare **clef**: *are these two events related?* The request holds both events (type, time, severity,
   description, hosts, artifacts, approved owner notes) and the script's score and evidence. The answer is a
   probability; `p ≥ related_min` (default 0.5) = related. **That answer is the verdict** — related and not related
   alike — stored with model name `cloudflare_clef`. 4 questions run in parallel (full clef: ~3 s each, ~70 links/min).
2. **Events — decision model label, reviewer notes.** Only once **no link of the newest snapshot is undecided**:
   - **Label (clef).** One request per event with the event and **all** its candidate events, each with its link
     probability (clef's; for links decided before clef, derived from the old verdict), plus approved owner notes.
     Two yes/no questions: *suspicious?* and *expected?*. `p(suspicious) ≥ suspicious_min` (default 0.5) →
     **suspicious**; else `p(expected) ≥ 0.5` → **expected**; else **benign**. **That label is final** and drives alarms;
     its confidence is `p(suspicious)` for suspicious, `1 − p(suspicious)` otherwise. Stored in `clef_event`.
   - **Notes (reviewer model).** One call per event with all of its clef-related events, owner / AI / artifact notes and
     (if enabled) Elasticsearch look-ups, told the decision model's label. It writes the event's **reason** (why the
     event is what clef labelled it; it starts with *Reviewer disagrees:* when the evidence clearly contradicts the
     label) and, for every related event, a **link note** (the verdict's reason, with clef's probability appended) and
     its **artifacts** (file, process, user, IP, DNS name; each benign / expected / suspicious). It also gives its own
     label, which is recorded only for the agreement figure on the AI review page — it never decides a link or a label.

   Host notes (expected behaviour), internet notes and DNS notes are written from the artifacts as before. An event is
   labelled and reviewed again when its set of link decisions changes; at most 20 events per pass, never-reviewed and
   best-connected first. If clef cannot label an event, the event waits for the next pass (the reviewer does not step
   in). Suspicious medium / high events become alarms. `event_class.model` reads `cloudflare_clef + <reviewer>`.
   Audit-log purpose: `event-review`.
3. Verdicts are stored per unordered pair in `dashboard/state/corr_llm.db` (`verdicts`; clef's probabilities in
   `clef`), so each pair is asked once and the decision applies in both directions. A person's decision (✓/✗, or an
   adopted model answer) is never overwritten. **↻ Ask again** removes both the verdict and clef's answer.
4. `/api/correlate` drops **rejected** links, marks **confirmed** ones with the link note and artifacts, and flags the
   rest as **pending**. Undecided links that the review limits skip are hidden, not shown as pending.

If the decision-model server is unreachable the pass waits and the AI review page shows the error — it never falls
back silently.

```mermaid
flowchart LR
    EV["Events + script candidates\ncorrelate.py"] --> LIM{"Review limits\ntype pairs, window,\nnever-send, cleared"}
    LIM -- "skipped" --> HID["not sent"]
    LIM -- "allowed" --> CLEF["Decision model (clef)\nyes/no per link\n= the verdict"]
    CLEF --> DB[("corr_llm.db\nverdicts, clef")]
    DB -- "no link undecided" --> CL2["Decision model (clef)\nsuspicious? expected?\nevent + all candidates"]
    CL2 --> LAB["Event label\nsuspicious / benign / expected\n(final)"]
    LAB --> REV["Reviewer model\none call per event,\nall related events"]
    NOTES["Owner / artifact / AI notes,\nuser profiles"] --> REV
    ES["Elasticsearch look-ups\n(optional)"] <--> REV
    REV --> RS["Reason for the label"]
    REV --> LN["Link notes + artifacts"]
    LN --> HN["Host / internet / DNS notes"]
    LAB --> AL["Alarms (suspicious, medium+)"]
    DB --> UI["Related popover,\nAI review page"]
```

### Decision model: clef

Cloudflare **clef** is a "System One" decision model: it writes no text, it returns the probability of *yes* for a
typed question. netmon asks it *related?* per link and *suspicious?* / *expected?* per event.

| | clef (default) | clef-flash |
|---|---|---|
| Size / file | 27B, `Cloudflare_clef-Q4_K_S.gguf`, 16.6 GB | 9B, `Cloudflare_clef-flash-Q4_K_S.gguf`, 5.7 GB |
| Speed (4 parallel, this host) | ~3.3 s per link, ~72 links/min | ~1.0 s per link, ~230–365 links/min |
| AIT-ADS benchmark, 320 links | F1 22.0, 66 false links | F1 17.0, 157 false links |

(For comparison, the reviewer model deciding links itself on the same benchmark: F1 26.2, ~28 links/min.)

**Why clef labels events.** On the same AIT-ADS benchmark (40 events: 20 attack, 20 normal):

| Who labels the event | Correct | Attacks caught /20 | Normal events flagged /20 | Speed |
|---|---|---|---|---|
| Reviewer (Gemma), deciding links itself (older flow) | 62.5 % | 13 | 8 | 3.5 events/min |
| Reviewer (Gemma), after clef decided links | 52.5 % | 17 | 16 | 7.2 events/min |
| **clef, event + all candidates, p ≥ 0.5 (used)** | **72.5 %** | 14 | **5** | 21 events/min |
| clef, event + related events only, p ≥ 0.5 | 70.0 % | 14 | 6 | 53 events/min |
| clef, related only, p ≥ 0.8 | 75.0 % | 10 | 0 | 53 events/min |
| clef-flash, related only, p ≥ 0.5 / 0.7 | 47.5 / 67.5 % | 16 / 14 | 17 / 7 | 108 events/min |

Told that every candidate is related, Gemma flags almost everything; clef separates attack from normal events better
(ranking quality 0.76–0.79 vs 0.67 for clef-flash). Raise *suspicious_min* for fewer alarms (0.8: no false alarms,
but only 10 of 20 attacks). Lab data, 40 events: differences of 2–3 events are within noise.

**The server.** LM Studio can load clef but cannot run it ("context does not support logits computation"). It runs
on the host under LM Studio's bundled llama.cpp `llama-server`, endpoint `http://127.0.0.1:8091/v1/systemone`
(loopback only), as systemd user unit **`netmon-clef`** (`clef.sh`). Manage it on **AI review → Decision model
server** (admins): status, the model actually being served, model file and llama.cpp runtime, parallel slots,
context, batch, port, Save & restart, start / stop, start-at-boot, and the recent server log. The dashboard reaches
systemd through the host broker (`POST /clef`, `clef_server.py`); settings are stored in the netmon database
(document `clef_server`), and `CLEF_*` environment variables override them. Two settings matter:

- **Batch** (`-b/-ub`, default 8192) — clef reads its whole input in one micro-batch. llama-server's default 512
  rejects longer event pairs with *input … too large*, which the client sees as a hang. Must be ≥ 4096.
- **Context / Parallel** — the context is shared by the slots: 32768 / 4 = 8192 tokens per question.

**Standing it up** (the same steps are on the AI review page under *Stand-up instructions*):

1. LM Studio → Settings → Runtime: install the llama.cpp CUDA runtime, 2.59 or newer
   (`ls ~/.lmstudio/extensions/backends/*/llama-server`).
2. Download a model into LM Studio's model folder (no mmproj file needed):
   ```bash
   mkdir -p ~/.lmstudio/models/bartowski/Cloudflare_clef-GGUF && cd $_
   curl -L -C - -O https://huggingface.co/bartowski/Cloudflare_clef-GGUF/resolve/main/Cloudflare_clef-Q4_K_S.gguf
   ```
   (clef-flash: `Cloudflare_clef-flash-GGUF/Cloudflare_clef-flash-Q4_K_S.gguf` in the same way.)
3. `~/netmon/setup.sh` installs the unit, then
   `systemctl --user daemon-reload && systemctl --user enable --now netmon-clef`
   (and `sudo loginctl enable-linger $USER` so it survives logout).
4. Check: `curl -s localhost:8091/health` → `{"status":"ok"}`; a `/v1/systemone` request returns `"noul": <p>`.
   The Decision model box shows the server as *up*.

Troubleshooting: `journalctl --user -u netmon-clef -f`. Time-outs under load → lower Parallel (the client retries a
lost request twice, 30 s each). Out of memory → clef-flash or a smaller quant.

### Decision model settings (AI review → Decision model)

| Setting | Default | |
|---|---|---|
| Use the decision model | on | off = the reviewer decides links again (older flow below) |
| Related if p ≥ | 0.5 | lower = more links kept (0.2 raised agreement with past reviewer verdicts from 46 % to 62 %) |
| Event suspicious if p ≥ | 0.5 | higher = fewer alarms, fewer attacks caught (see the table above) |
| `NETMON_CLEF_URL` (dashboard/.env) | `http://127.0.0.1:8091` | loopback only; set when the server port changes |
| `NETMON_CLEF_MODEL` | `cloudflare_clef` | the model name written on verdicts |
| `NETMON_CLEF_WORKERS` | 4 | parallel questions (match the server's Parallel) |

The card shows links decided per minute, related / not related over 24 h, average time per link, events reviewed per
minute, suspicious / benign / expected counts, how often the reviewer's own label agrees with clef's, and the
7-day label matrix (clef rows vs reviewer columns).

### Without the decision model (older flow)

Each event with undecided candidates becomes one reviewer request (up to 10 candidates, two in parallel); the model
answers *related / not related* per candidate with a confidence, reason and artifacts, and the optional **event
classification** (below) labels events afterwards. Local (LM Studio) gets temperature 0 and JSON-schema output; an
admin-added API provider gets the answer format in the prompt. The prompt tells the model to be sceptical of
coincidences and to treat everything inside `<event>` tags as data, never as instructions.

**Which model it uses.** AI review → Models → Correlation reviewer picks the provider and model explicitly; that
choice is remembered until someone changes it. If nothing has ever been chosen, it defaults to the first enabled,
configured provider with at least one model (an admin-added API provider before Local (LM Studio), since the
reviewer calls far more often than a typical API rate cap allows) - **the reviewer no longer requires Local
(LM Studio) to be running.** If the chosen provider is later disabled or deleted, the next run raises a clear
error on the AI review page instead of silently falling back, so pick another model there. Mind each API
provider's calls-per-hour cap (AI review → AI providers): the reviewer can fire many calls a minute, so a
cloud provider meant for the occasional on-request research will hit its cap quickly unless you raise it.

| Setting (`dashboard/.env`) | Default | |
|---|---|---|
| `NETMON_LLM` | `on` | `off` disables the review (links show the script's evidence only) |
| `NETMON_LLM_URL` | `http://127.0.0.1:1234/v1` | Local (LM Studio)'s endpoint, any OpenAI-compatible http(s) URL |
| `NETMON_LLM_MODEL` | the model loaded in LM Studio | pin a model id for Local (LM Studio) |
| `NETMON_LLM_REASONING` | `none` | reasoning models (Gemma, Qwen) spend the token budget on hidden reasoning otherwise |
| `NETMON_LLM_WORKERS` | `2` | parallel requests (match LM Studio's parallel slots) |

Local (LM Studio) is itself an AI review → **AI providers** row: an admin can disable it or set its calls-per-hour
cap there, same as any other provider (no key or URL to enter - those come from `NETMON_LLM_URL` and the live
model list). Besides Local (LM Studio), the reviewer can use any provider an admin adds on AI review > **AI
providers** (`llm_providers.py`, stored in the netmon database (`netmon.db`, mode 600)). These are OpenAI-compatible
(`POST {base}/chat/completions`, Bearer key) or Anthropic (`POST {base}/v1/messages`, `x-api-key`) APIs called
directly from the dashboard container; the model choice is `api:<id>` plus the model name, and each provider has
its own calls-per-hour cap.

### What the reviewer is given

Each event in a request carries its type, time, severity, label and **known artifacts** (users, processes, files, DNS
names and IPs read from the event itself, section 2). On top of that it gets context written by people and by earlier
AI work, capped per event by the **Notes per event** setting and by the **Note characters** setting (default 6,000 characters per request, up to 100,000) (a note already
shown is not repeated):

| Tag in the prompt | What it holds | Trust |
|---|---|---|
| `<owner_note>` | Approved event notes (📝), host notes written by a person for the hosts the event involves, and **user notes** for the accounts it names (subject `art:user:<account>`, 300 characters each) | trusted guidance |
| `<artifact_note>` | A person's notes on a file, process, user, IP or DNS artifact (📝 beside the artifact in the Related popover, subject `art:<kind>:<value>`), up to 25, those named in these events first | authoritative |
| `<ai_note>` | The research verdict and summary for the event, AI-written and profile host notes (including the *expected behavior* notes below), and each named account's profile from **Network → Users** (usual hosts, sources, methods, hours) | informed but unverified |

**Notes are chosen by artifact first.** Every host note (people's, AI-written, reviewer, internet and profile notes) is indexed
by the artifacts it is about: IPs (internal and internet), DNS names, ports, processes / files (by base name) and accounts. They
are read from the note's subject, its `[reviewer:<kind>:<value>]` tag and its text. Before a review prompt is built, the
reviewer collects the same kinds of artifact from each event (its host and destination IPs, the files, processes, users and DNS
names the script read from it, and the IPs, ports and names in its label) and looks them up in that index. Notes are then
ranked by match: IP, DNS name or process = 3 points, account = 2, port = 1; a note that matches only on a port (under 2 points)
is never picked. Highest score first, then the old order (decision, role, baseline, behavior, config, risk, watch, other, newest
first), and the first **Notes per event** are sent. This also pulls in notes that hang on a *different* host or subject
but name the artifact (for example a note on a backup server that mentions the process or internet address this event shows);
those are shown to the model as `(matches ip:…)`. Generated `[profile:…]` notes are only used for their own host, never
matched across hosts. Each note's artifacts are refreshed whenever it is added or edited, and existing notes were indexed once
at upgrade. Artifacts a reviewer writes into its notes (the `[reviewer:…]` tag and the value in the text) are what make the next
reviews find them. On the Notes page, the Internet notes pages and the notes cards, each note shows its artifacts as chips under the text (⚙️ process / file, 🌐 IP, 🔎 DNS name, 👤 account, 🔌 port), so you can see what the reviewer will match on.

**DNS notes.** Notes on `dom:<domain>` (or `art:dns:<domain>`) apply by suffix: a note on `example.com` covers `a.b.example.com`; a note on `b.example.com` covers only that name and below. For each event the DNS names are taken from its dns artifacts and its label (`kb.dns_names`), the matching notes are found with `kb.dns_notes_for` (most specific first, up to 6) and are shown to the reviewer as `dns note [domain]` (or `dns note [example.com covers a.b.example.com]`) and to event research as `dns_notes` on each work item. When the reviewer judges a `dns` artifact and adds a `note`, `corr_llm._note_dns` writes a host note on `dom:<name>` (one per name, tagged `[reviewer:dns:<name>]`, updated in place; the name must appear in one of the two events). `GET /api/kb/dns` lists domains with their notes.

**Note review (accept / reject).** `host_notes` has `status` ('' not reviewed, `approved`, `rejected`), `reviewed_by`, `reviewed_at` (added to `kb.db` automatically). An admin or defender sets it with `POST /api/kb/host {action: approve|reject|clear, id}`. `approved` makes `corr_llm._human()` true, so the note goes in the owner-notes group and research items carry `authoritative: true`. `rejected` notes are dropped by every AI-facing read (`kb.host_notes(..., ai=True)`, `notes_by_artifacts`, `dns_notes_for`, `kb.dump`, `netmon_mcp`) but stay on the pages. `add_host_note` raises for an `ai` author changing an approved/rejected note, and `kb.put` will not delete one, so the AI can neither edit nor recreate them. A person editing a note clears its status.

Host notes are ordered decision, role, baseline, behavior, config, risk, watch, other, then newest first; accounts come
first because they decide most "expected" calls. Unapproved User notes never reach the AI. The prompt tells the model
never to let an `<ai_note>` outweigh an owner or artifact note, or concrete evidence of harm.

### What the reviewer writes back

- **Verdict**: related or not, confidence (0–1), reason (under 25 words).
- **Artifacts** for every related link (the model is asked for at most 6 per candidate; up to 12 are kept, including searches): the file, process, user, IP or DNS name that ties the two events
  together, a relation (under 15 words) and a decision: `benign` (looks odd, harmless), `expected` (normal for this
  device or task) or `suspicious` (needs a person's eye). `benign` and `expected` must be backed by a note and the
  model must name it; without support it chooses `suspicious`. Values must come from the events, never invented.
- **Expected-behavior host notes.** For a related link with confidence ≥ 0.8, each artifact judged `expected` becomes a
  host note (category *behavior*, author `ai`, tagged `[reviewer:<kind>:<value>]`) on the host both events involve
  (up to two hosts, the shared IPs first). One note per host and artifact, updated in place, marked unverified; delete
  one on the Notes page if it is wrong. Notes whose value does not appear in either event, or that name the host's own
  IP, are not written. Later reviews and event research read them as `<ai_note>`s. Turn this off with
  `NETMON_REVIEW_HOST_NOTES=off` in `dashboard/.env`; a host holds at most 40 notes.
- **Elasticsearch searches as artifacts** (when searches are enabled, below). Every successful search is kept as a
  `query` artifact on the links it was run for (up to 12 per link): the search in KQL, its time range, the hit count
  and the model's *why*. In the Related popover it is a **🔭 query** button that opens Kibana Discover with that
  search (needs `kibana_url` / `kibana_data_view` in the site settings (More → Settings); without it the query is shown as text). A search that
  uses aggregations or clauses KQL cannot express is marked ≈ and opens a broader search than the one the model ran.

### Event classification (optional, older flow)

With the decision model on, every event is labelled in stage 2 and this switch is not needed.
**AI review → Review limits → Classify events** (off by default) makes the reviewer give every event whose correlation
review is finished one label: **suspicious** (needs a person's eye), **benign** (odd but harmless) or **expected**
(normal for this device, user or task), with a confidence and reason. An event qualifies when none of its links is
undecided and at least one is decided; the confirmed related events are the evidence. `benign` / `expected` need a
supporting owner, artifact or AI note that the reason names, otherwise it says `suspicious`. At most 20 events are
classified per pass on the newest snapshot, an event is re-classified when its set of verdicts changes, and events
that are cleared, excluded or muted are skipped. The label is a 🏷 badge next to the Related count (click for the
reason) and the page shows the totals. Turning it on offers to enable the reviewer's Elasticsearch look-ups too, which
classification uses. Audit-log purpose: `event-classify`.

### Review limits (More → AI review → Review limits)

Admins and network defenders choose which candidate links are **never sent** to the reviewer, to save tokens. Skipped
links are neither reviewed nor shown (links that already have a verdict are unaffected). The box shows how many
candidate links each setting affects.

| Limit | What it does | Default |
|---|---|---|
| **Link types** (grid) | Every event type (`ids`, `alert`, `admin`, `ti`, `gw`, `host`, `finding`, `vuln`, `seg`) × severity (`low`, `medium`, `high`) against every other: each cell is **review** or **skip**. Click a cell to flip it. Cells you never touched inherit the default. | review, except on a brand-new deployment (no verdicts yet): skip, so nothing is sent until an admin opts in |
| **Severity of `seg`** | Segmentation issues and findings are their own type. Their severity is set by the port: **high** = admin / remote-control ports (SSH, RDP, SMB, WinRM, databases, Docker and Kubernetes APIs, the policy's `sensitive_ports`), **low** = standard service ports (`standard_ports`, default web, mail, DNS, NTP, LDAP…), **medium** = any other (odd) port. All other types take the event's own severity (critical/severe/investigate = high; moderate/warning/review = medium; anything else low). | – |
| **Time window for the reviewer** | One setting, in minutes: only events that happened within X minutes of each other are correlated. The gap is measured between the two events' time spans; links further apart are skipped. Events without a time (open vulnerabilities) are never "apart". `0` = no limit. The box shows how many candidate links are outside the window now. | 0 (no limit) |
| **Max links per event** | Undecided links one event may have. Best script score first; a link needs room at both of its events; the rest are skipped. `0` = no cap, at most 200. | 0 |
| **Never send** (events and rules) | *Excluded events*: one event or its whole **family** (4–5 digit numbers such as ports are masked; watcher alerts use their alert key) from the events with the most links. *Rules*: `name` (event label), `host` (an IP of the event or the host in its label) and/or `id`, with `*` / `?` wildcards (no wildcard = contains); every field a rule has must match; scope *both*, *review* or *research*. Up to 500 exclusions and 200 rules. | none |
| **Discard old verdicts** | Delete verdicts (and artifacts) whose pair has not been a candidate link for more than N days. Runs hourly after a snapshot has refreshed the "last seen" times; person-made verdicts are kept and the freed space is returned to the disk. `0` = keep forever, at most 3650. | 0 |
| **Classify events** | See above. | off |

**Mute alerts.** Watcher alerts are by far the most numerous event type. An admin or network defender sees **mute
name…** and **mute name + host…** beside an alert on the Alerts page and on the AI review decisions. Both open an
editable pattern (the alert text with IPs, MACs and numbers replaced by `*`); **Mute & clear existing** saves a *never
send* rule for it (scope *both*, so it stays out of the queue too) and deletes the alerts that already fired and match
the rule. The rule is listed under **Never send** and can be removed there; the deleted alerts do not come back.

**Suppress findings.** Suppressing hides a finding like a check-off does, but as a *rule* by signature name, and it is
listed in its own card on More → Checked. Nothing is bypassed: the event stays in correlation, research and review.

- *How:* click the **🚫 button** next to the check-off box of an event (Posture, alarms, endpoint findings, fix list…), or
  **🚫 suppress…** on an alert. Admins and defenders only.
- *The rule:* a signature name (pre-filled from the event; `*` = any text, `?` = one character, otherwise "contains"),
  optionally plus one artifact that must be involved. The artifact dropdown is filled from the event itself (**📍 This
  event**) and from the events correlated with it (**🔗 Correlated events**, with the event each came from):
  🌐 IP (source and destination), 🔗 domain, 👤 user, ⚙️ process, 📄 file, 🔌 port. *other…* takes a typed value (wildcards allowed).
  A rule on a correlated artifact also covers findings and alerts correlated with it. Alerts get the same dropdown (🚫 suppress… on the alert).
- *Effect:* matching events with a check-off list (baseline and endpoint findings, fix-list items, triage alarms, UniFi gateway events `gw|…`, whose check-off key is the event id itself) are checked
  off with the note `suppressed: rule N: …` and leave their lists; matching alerts leave the feed and are not pushed (a new alert is checked against the rules when it arrives; its correlated artifacts are checked on the next correlation pass, a minute or so later).
- *Checked page:* the **🚫 Suppressed** card lists the rules (with how many findings and alerts each hid; *remove rule* brings
  everything back) and the suppressed findings (unticking one restores just that finding; the rule stays).
- *Reviewer does not override:* suppressed events and alerts are still researched and reviewed (their verdicts and notes are
  kept), but a *suspicious* verdict never un-suppresses them: only removing the rule (or unticking the single finding) does.
  This differs from plain check-offs, which move back to the findings when the reviewer calls them suspicious.
- *Storage:* store tables `suppress_rules` and `suppress_log`; API `GET /api/suppress`, `GET /api/suppress/suggest`, and
  `suppress` / `unsuppress` on `POST /api/llm/review-limits`.

**Checked events.** Checked-off events (Alerts, Posture, Fix list, Lateral movement… listed on the Checked page) are
reviewed and researched like any other event; nothing is skipped because it was cleared. When the reviewer classifies a
checked event as *suspicious*, it is un-checked and moves back from Checked into the findings; a later *expected* or
*benign* classification may auto-close it again (only a person's un-check keeps auto-close off an item for good). An
event a person marked **Expected** or **Benign** (📝 verdict buttons) is never reopened by the AI.

**People's verdicts.** The 📝 notes popover on every event has **✅ Expected / 🟢 Benign / ⚠️ Suspicious** buttons. Each
saves an event note (with any text typed in the box) that starts `ANALYST VERDICT: <VERDICT> (... authoritative ...)`,
so every AI prompt that reads event notes (reviewer, research, Ask AI, MCP) sees it, and the verdict is stored in the
note's `verdict` column. Expected/Benign check the event off at once and auto-close also closes later repeats of it
(same stable event key), whatever the four auto-close switches say; Suspicious un-checks it and blocks auto-close. A
person's verdict outranks every AI verdict. A User-role account's verdict waits for a defender/admin approval like any
of their notes.

**Queue behaviour.** The worker pass repeats about every minute (every 5 seconds while it finds work). It reviews the
newest snapshot first, then snapshots opened in the last hour. If the provider is down or rate-limited the links stay
*pending* and the worker backs off (3 minutes after an error). **Clear review queue** (admin, AI review page; or `docker exec netmon-dashboard
python /app/enrich.py clear-review`) gives every undecided link of the newest three snapshots the verdict *not related* by
`dismissed:<user>` ("review queue cleared by an admin") and remembers those events: undecided links between two
remembered events are never asked again, links to *new* events are. Undo by deleting verdicts whose model starts with
`dismissed:`. **Clear event queue** dismisses the current snapshot's event families from the queue (new
events and **Send to research** are unaffected). `python /app/enrich.py clear-queue --wipe` (inside the dashboard container) additionally deletes all research notes
and the model's verdicts after backing up both databases.

### Elasticsearch look-ups (optional)

Off by default. When an admin turns on **AI review → Models → Elasticsearch queries · correlation review**, the reviewer may search the
Security Onion logs for more context before it decides an event's links, for example to check whether the host
behind an IDS alert also made the failed SSH logins, or whether a domain was resolved before the connection.

| Setting (AI review → Models, admin only) | Default | |
|---|---|---|
| **Elasticsearch queries · correlation review** (checkbox) | off | lets the reviewer search the logs |
| **Elasticsearch queries · event research** (checkbox) | on | separate switch: lets event research (Send to research) search the logs (`es_search` tool) |
| **Max per event** | 3 | the total number of searches the reviewer may run for one event review (one anchor event and its up to 10 candidates), 1–20; classification uses the same budget |
| **Note characters** | 6000 | total characters of notes in one review request (1,000–100,000, `context_notes.chars`), set below Notes per event; the re-check of a single link uses a third of it |
| **Notes per event** | 7 | host + user notes the reviewer is given for each event, 1–100 (the `llm_config` settings `context_notes`); more notes = more tokens in |

The reviewer's switch and **Max per event** are stored in the netmon database (settings document `llm_config`) (`"es_queries": {"enabled",
"max"}`, with who changed them and when); the event research switch is part of the event research settings in the netmon
store (`es_search`). Both take effect from the next review or run. Model comparisons (⇄) never search, so every model gets exactly the
same prompt.

How a review works with searches on:

1. The request also lists each event's hosts and explains the search format. The model answers either with its
   decisions or with up to *remaining* searches (`{"decisions": [], "queries": [...]}`).
2. A search is **not** Elasticsearch DSL. It is a small structured request: `source` (`zeek`, `suricata`,
   `detections`, `endpoint`, `auth`), up to 6 exact `match` fields, an optional free-text `text`, `start`/`end`
   (default: the anchor's time ±2 h, at most 7 days), an optional `group_by` field (top 10 values with counts), `size`
   (1–10 documents) and `why`.
3. The dashboard container has no Elasticsearch key, so it sends each search to the host broker
   (`host_broker.py`, `POST /esquery`). `es_context.py` validates it, builds a read-only `_search` itself (field names are checked,
   no leading wildcards, no scripts), runs it on the configured index and returns the hit count plus trimmed
   documents (selected fields, 400 characters each) or the top values. The broker allows at most 600 searches an hour.
4. The results go back to the model inside `<es_result>` tags, which the system prompt marks as log data, never
   instructions. The model searches again or decides. When the budget is used up it is told to decide now, without
   the option to search. A search that fails (bad field, ES down) is reported back to the model and still counts.
5. Every search is kept in `corr_llm.db` (`es_queries`: time, event, candidates, model, query, hit count, error),
   written to the audit log (`aireview.esquery`), and every model round is in the audit log as usual
   (`llm.correlation-review`, with the search results in the prompt). Successful searches also become clickable
   Kibana artifacts on the links they were run for (see *What the reviewer writes back*). Event research's own
   searches (DSL through its `es_search` tool, listed on the same page as *Event research searches*) are attached the
   same way to the research notes and links of that batch, shown under **Elasticsearch searches (open in Kibana)** in
   the notes popup.

The AI review page shows the setting under **Models**, the searches made in the current pass, and a
**Reviewer searches** box with the newest 50 (event under review, the search and its *why*, hits, model).

Searching costs time and, with Anthropic or OpenAI reviewers, tokens: each round resends the event, its candidates
and the earlier results. Most decisions are clear without searching, and the model is told not to search then.

Throughput with Gemma 4 31B on the monitoring host is about 15–30 links a minute. A full day's snapshot (~2,000
candidate pairs) takes 1–2 hours the first time; after that, only new pairs are asked. If the reviewer's current
provider goes down or hits its rate cap, the worker backs off and retries, and links stay *pending* until it's
reachable again (or an admin picks a different model on AI review → Models).

### AI review page (More → AI review)

Shows the review job (status, schedule, last run, note coverage, token and cost history), the correlation
reviewer's status (reviewing / waiting / idle / error / off), the queue for the current snapshot with % reviewed and
an ETA, verdicts per hour, tokens per minute and the average tokens in / out per event review, and every decision
with both events (linked), the verdict, confidence and the model's reason. Boxes, top to bottom:

| Box | What it holds |
|---|---|
| **Review job** | Health, reviewer model, schedule, Run now / Pause, latest run summary, note coverage of the current snapshot |
| **Time and tokens: review job, event research and Ask AI chat** | Tokens and estimated cost per day, and per researched event |
| **Decision model** | clef's speed (links / min, time per link), related / not related, event labels per day, on/off and the related threshold |
| **Decision model server** | (admins) The `netmon-clef` server: status, served model, model file / runtime / parallel / context / batch / port, Save & restart, start / stop, log, stand-up instructions |
| **Reviewer** | The correlation reviewer's status, speed (verdicts per hour, tokens per minute, average tokens in / out per event review) and error |
| **Queue: events without a note** / **Links awaiting review** | The two queues. **Clear event queue** and **Clear review queue** (admins) sit under them and ask for confirmation |
| **Models** | Provider and model for the correlation reviewer (also the review job's reviewer), event research and chat; the Elasticsearch switches (reviewer, event research) and **Max per event**; **Notes per event** |
| **AI providers** | Added API providers, calls-per-hour caps, Local (LM Studio) on/off |
| **Review limits** | Link types grid, time window, max links per event, never-send events and rules, verdict retention, event classification (above) |
| **Event research limits** | Cost and size caps of event research (section 5) |
| **Decisions** | Filters: verdict (confirmed, rejected, set by a person), event type, event pair, confidence, this snapshot only. Per decision **✓ / ✗** overrides the model (stored as `manual:<user>`, never overwritten), **↻** deletes the verdict so the model reviews that link again, **⇄** compares models |
| **Reviewer searches** / **Event research searches** | The newest Elasticsearch searches of each AI |

## 4. Working through it on the dashboard

- **Related column** on every event list (Alerts, Posture findings, IDS, Admin sessions, Endpoint findings, Threat
  intel, Fix list, Risk). The number opens a popover listing each related event: its type, the event pair
  (e.g. *Alert – IDS*), its time, **✓ confirmed** + the model's reason and ✨ model (or *AI review pending*), the
  script's evidence, and **Correlated artifacts**: host and destination IPs plus the users, processes, files and DNS
  names read from the event, then the reviewer's own artifacts with their `benign` / `expected` / `suspicious` call and
  relation, and 🔭 query buttons that open the AI's Elasticsearch searches in Kibana. 📝 beside an artifact adds your
  note on it (the AI reads it). Each item jumps to its own list filtered to that one event (`?ev=<id>`). That event has
  its own Related count, so you can keep pivoting. Beside the count: **✨ notes** (the research note, with its
  Elasticsearch searches), **🏷 suspicious / benign / expected** (the classification, when switched on) and 📝 (your
  notes on the event).
- **Charts drill down:** clicking a chart segment or bar opens the matching list filtered (`?zone=`, `?country=`,
  `?severity=`, `?aproto=`...). Filters show as removable chips, and the URL can be bookmarked.
- **Boxes:** click a title to collapse or expand it. On first visit the first 3 boxes on a page are open. Drag the
  **⠿** grip to rearrange (mouse or touch). Drag the bottom-right corner to resize: width and height on desktop
  (neighbours in the row share the remaining width), height only on phones. Double-click the corner to reset one
  box, and use **Reset layout** to restore the page's original order and sizes. Boxes start a little shorter than the screen
  (long lists scroll inside the box with the title kept visible); drag the corner to make one taller. Scrollable
  areas show fading blue edges where more content is hidden, a visible scrollbar, and a **More below ↓** button. Collapse state, order and sizes are
  saved per page in the browser.
- **Users** page: admins assign devices to each person. That sets which devices they get push notifications and the
  🔔 count for (the same setting people edit on their own Alerts page).

## 5. The review job (`review.py`) and event research (`research.py`)

There are two separate host jobs:

- **The review job** (`review.py`) runs on the schedule (or **Run now**). It collects and analyzes a fresh snapshot, then
  its **reviewer**, which is the correlation reviewer's model (e.g. Gemma on LM Studio), copies earlier notes onto events
  that repeat. Everything else waits in the **queue**. It never researches an event, has no web access and never writes
  a note of its own.
- **Event research** (`research.py --event ID`) runs only when a person clicks **Send to research**. It uses the
  research model chosen on AI review → Models. It is never scheduled.

Both use a small set of **read-only lookup tools** (shared in `aijob.py`) plus a **validated submit tool** they must call
to write anything.

```mermaid
flowchart LR
    subgraph SRC["Where they get information from"]
        SNAP["Snapshot & analysis\nsnapshots and analysis (netmon.db docs table)"]
        KB["Notes KB\nenrich.sh kb (host + event notes)"]
        DEV["Device lookup\nnetmon_mcp (traffic, services, findings)"]
        ES["Elasticsearch\nSecurity Onion logs, via es_search tool"]
        WEB["Public internet\nweb_search / web_fetch"]
        PRIOR["Earlier notes\nsame family, correlated,\nsimilar label"]
    end

    subgraph JOB["Review job — review.py (scheduled / Run now)"]
        C["Collect + analyze\ncollect.py, analyze.py (no model)"]
        RV{"Reviewer\n(correlation reviewer's model)\nreview-mode events vs prior notes"}
        Q["Queue\nwaits for a person"]
    end

    subgraph REQ["Event research — research.py --event ID (Send to research only)"]
        R["Research\none event and its correlated events"]
    end

    subgraph OUT["What they write (validated submit_* tools only)"]
        COPY["Copied note\n(marked 'Copied by the reviewer')\nenrich.sh copy"]
        NOTES["Research note, link verdicts,\nhost notes -> enrich.sh put"]
        SRC2["sources documents (netmon.db)\ncited pages only"]
    end

    SNAP --> C
    C --> RV
    SNAP --> RV
    PRIOR --> RV
    RV -- "similar enough: copy" --> COPY
    RV -- "different / unsure / no prior" --> Q
    Q -. "person clicks Send to research" .-> R
    SNAP --> R
    KB --> R
    DEV --> R
    ES --> R
    WEB --> R
    R --> NOTES
    R --> SRC2
```

- **Collect + analyze** (`collect.py`, `analyze.py`) build the snapshot and fold it into the baseline. No model is involved.
- **Reviewer** (review job) handles events whose category is set to **review** and that have no note of their own.
  `enrich.py` attaches the candidate prior notes to each such event: the note of the same event family, notes of
  correlated events, and notes on same-type events whose label is at least 60 % similar (numbers masked). The reviewer
  (prompt `prompts/reviewer.md`; tools: Elasticsearch, device lookup, notes KB) answers per event with `submit_review`:
  **copy** (naming which prior note and why) or **queue** (leave it for a person). A copy is stored by `enrich.sh copy` /
  `enrich.py copy_notes`: the earlier verdict, priority, summary, links and research text are reused, with a first line
  `[Copied by the reviewer (<model>) from the note on <id> (<date>), researched by <model>: <reason>. Not
  re-researched.]`, and the note's source shows "reviewer (copied note)". The reviewer is told to queue an event when
  unsure, when a malicious/suspicious prior doesn't clearly match, or when the prior is old; events with no prior at all
  are queued without asking it. If the reviewer fails, or no reviewer model is usable, its events stay queued, so nothing
  is dropped. The run summary shows how many notes were copied and how many stayed queued.
- **Event research** (`research.py`) runs only on a Send to research click, for one event, with the broadest toolset:
  it can query Elasticsearch, look up a device's full history, read the notes KB, and search/fetch the open web (when
  web access is on). It may only *cite* a page after fetching it, and may only link pages it actually read. Results go
  through `submit_notes`, which shells out to `enrich.sh put` to store the note, link verdicts and host notes. The host
  broker starts it at once; if another research is running, the click waits in `research_requests` and the scheduler
  starts it as soon as the running one ends (at most two tries per click).
- Every write path is a `submit_*` tool that validates its input (ids must exist, URLs must have been fetched,
  verdicts/priorities must be from a fixed list): the model proposes, the tool enforces the schema before anything
  lands on disk.

### Review job schedule and categories

| Setting | Default | What it sets |
|---|---|---|
| Interval | 240 min | How often the review job runs, 5–1440 min, on a grid anchored at 05:00 UTC; the first run at or after 05:00 UTC each day is the **daily run** (24 h of logs) |
| Lookback | 24 h | Hours of logs a non-daily run collects, 1–24 |
| On / off | on | **Pause** on the Review job card stops scheduled runs |

The per-event-category setting (**review** / **queue** / **test** / **skip**, categories `host`, `ids12`, `gw`, `ti`,
`alert`, the three `seg_*` severities and `high` / `medium` / `low` / `info` for the rest) decides what the reviewer
considers and what shows in the queue: *review* events go to the reviewer first, *queue* events go straight to the
queue, *test* events are listed and tagged *testing*, *skip* events are ignored. New deployments start every category in
**test**. These live in the netmon store (`netmon.db`, `meta` table, keys `review_job` and `review_lookback`;
`review_cfg.py`, `lookback.py`), so the dashboard container and the host scheduler read the same values. Settings
saved before the review / research split are read from the old `research_job` record, with the old *research* mode
read as *queue*.

### Event research limits

The caps below are the **Event research limits** box on the AI review page (admins; they apply to the next Send to
research). A research run stops at its next model call once a cap is passed; what it found until then is kept.
`0` = no limit. Store meta key `research_job` (`research_cfg.py`).

| Setting | Default | What it limits |
|---|---|---|
| $ per research | 5.00 | Estimated cost of one research run (needs a price for the model on AI review → AI providers) |
| $ per day | 20.00 | Send to research is refused once today's research (UTC) cost this much |
| Tokens per research | 25,000,000 | Input + output tokens of all calls in a research run; works without prices |
| Research batches | 10 | Research conversations per run (8 events each), max 40 |
| Searches per event | 3 | Web searches per researched event, max 20; ignored when web access is off |
| Web access | off on new deployments | Lets the research model search and read web pages and cite them; off = local data only |
| Elasticsearch (Models box) | on | Lets event research's `es_search` tool run (separate from the correlation reviewer's switch) |

## 6. The reviewer — copy an earlier note or leave the event queued

The reviewer is the model step of a review-job run inside `review.py` (`Review.review_items`), using the correlation reviewer's model. Its job is to avoid
paying for research twice: when an event is the same activity as one already researched, the earlier note is reused;
everything else stays in the queue until a person sends it to research. Only events whose category is **review**
(the per-category setting kept in the store) and that have **no note of their own** enter this phase. Events set to *queue*
skip it and go straight to the queue; events set to *test* are only listed on the dashboard.

```mermaid
flowchart LR
    subgraph IN["What goes in"]
        WORK["Work items\nenrich.sh events\nmode = review, no note yet"]
        subgraph PRIORS["Candidate prior notes (enrich.py _prior)"]
            P1["Same event family\n(the event's own earlier note)"]
            P2["Correlated events\nup to 8, from section 2"]
            P3["Similar label\nsame type, >= 60% match\nnumbers masked, up to 4"]
        end
    end

    subgraph REV["Reviewer — review.py review_items"]
        NP{"Any prior\nnote?"}
        RM["Reviewer model\nprompts/reviewer.md\nbatches of 16, max 20 turns"]
        TOOLS["Read-only tools\nes_search, device_lookup, notes_kb"]
        SUB["submit_review\nvalidated decision per item"]
        DEC{"Decision"}
    end

    subgraph OUT["What happens next"]
        CP["enrich.sh copy -> copy_notes\nverdict, priority, summary, links, research reused\nfirst line: Copied by the reviewer ... Not re-researched\nsource: reviewer (copied note)"]
        RS["Queue\nwaits for a person\n(Send to research)"]
        STAT["Run summary\nnotes copied / left queued"]
    end

    WORK --> NP
    P1 --> NP
    P2 --> NP
    P3 --> NP
    NP -- "no" --> RS
    NP -- "yes" --> RM
    TOOLS <--> RM
    RM --> SUB
    SUB --> DEC
    DEC -- "copy (from = prior id, reason)" --> CP
    DEC -- "queue (different / unsure / old / loose match)" --> RS
    SUB -. "batch fails or copy step fails" .-> RS
    CP --> STAT
    RS --> STAT
```

**Step by step**

1. **Collect work items.** `enrich.sh events` lists the snapshot's work items. Review-mode items without a note are
   handed to the reviewer.
2. **Attach prior notes** (`enrich.py _prior`). Each item gets a `prior` list: the note of the same event family,
   notes of correlated events (up to 8, see section 2), and notes on same-type events whose label is at least 60 %
   similar with numbers masked (up to 4, via `difflib`). Each prior carries `how` it was found, its label, verdict,
   priority, summary, research (first 800 characters) and age in hours.
3. **No prior, no model call.** Items with nothing to compare against stay queued.
4. **Ask the reviewer.** The rest go to the model in batches of 16 (system prompt: analyst + `prompts/reviewer.md`),
   with `es_search`, `device_lookup` and `notes_kb` available to check the item's evidence against the prior note.
   It answers once through `submit_review` with `{id, action: "copy"|"queue", from?, reason}` for every item.
5. **Rules the reviewer follows.** Copy only when it is the same activity: same signature or rule, same kind of
   source and destination, same behaviour, nothing in the item's evidence or `user_notes` that contradicts the prior
   verdict. Leave it queued when hosts, ports or behaviour differ, when a malicious/suspicious prior does not clearly
   match, when the prior is old, when the match is loose, or when unsure. A wrong copy hides a real event.
6. **Validation.** `submit_review` rejects ids outside the batch, actions other than copy/queue, and a `from`
   that is not one of that item's prior note ids. If some items get no decision, the tool tells the model to fill
   them in.
7. **Store copies.** Copy decisions go to `enrich.sh copy` (`copy_notes`), which reuses the earlier verdict,
   priority, summary, links and research, prefixed with `[Copied by the reviewer (<model>) from the note on <id>
   (<date>), researched by <model>: <reason>. Not re-researched.]`. The note's source reads "reviewer (copied note)".
8. **Leave the rest queued.** Every item not copied waits in the queue; only a click on **Send to research** researches it (`research.py`).

**Failure behaviour.** Nothing is dropped. If a reviewer batch errors, its items stay queued and the error is
listed in the run's errors. If the copy step fails, no copies are stored and all items stay queued. A budget
overrun stops the run as it would anywhere else.

**Where to see it.** The run summary reports *N earlier notes copied, M left queued*. A copied note shows the
copy line first and its source on the Notes views, with the usual ✨ model flare for the reviewer's model.

## Settings reference

| Setting | Default | Stored in |
|---|---|---|
| Correlation reviewer provider + model | first enabled provider with a model | `llm_config` (netmon database) → `correlation` |
| Chat provider + model | – | `llm_config` → `chat` |
| Elasticsearch look-ups for the reviewer: on/off, max per event | off, 3 (1–20) | `llm_config` → `es_queries` |
| Notes per event | 7 (1–100) | `llm_config` → `context_notes` |
| Note characters | 6000 (1000–100000) | `llm_config` → `context_notes.chars` |
| Review limits: link-type modes, default mode | review (skip on a brand-new deployment) | `llm_config` → `review_limits.pair_modes`, `pair_default` |
| Review limits: time window (minutes) | 0 = off, max 525,600 | `review_limits.window_minutes` |
| Review limits: max links per event | 0 = no cap, max 200 | `review_limits.max_links` |
| Review limits: never-send events and rules | none (max 500 / 200) | `review_limits.excluded`, `review_limits.rules` |
| Review limits: discard verdicts after N days | 0 = keep, max 3650 | `review_limits.discard_days` |
| Review limits: classify events | off | `review_limits.classify` |
| Decision model on/off, related threshold, event suspicious threshold | on, 0.5, 0.5 | `llm_config` → `clef` |
| Decision model server: model, runtime, parallel, context, batch, port | auto, auto, 4, 32768, 8192, 8091 | netmon database document `clef_server` (`clef_server.py`) |
| Reviewer verdicts, artifacts, classifications, searches, comparisons, token logs | – | `dashboard/state/corr_llm.db` (`verdicts`, `clef`, `clef_event`, `pair_artifacts`, `event_class`, `cleared_events`, `es_queries`, `comparisons`, `review_tokens`, `review_events`) |
| Review job schedule and modes; event research settings, pending clicks, dismissed queue | see section 5 | store meta `review_job`, `review_lookback`, `research_job`, `research_requests`, `research_dismissed` |
| Research notes | – | `dashboard/state/enrich.db` |
| Host, user and artifact notes | – | `dashboard/state/kb.db` (`kb.py`; subjects `ip:`, `mac:`, `host:`, `dom:`, `art:<kind>:<value>`) |
| `NETMON_LLM`, `_URL`, `_MODEL`, `_REASONING`, `_WORKERS`, `NETMON_REVIEW_HOST_NOTES` | see section 3 | `dashboard/.env` |

## Event ids (for links and the API)

`alert|<id>` · `f|<kind>|<device>|<detail>` · `ids|<signature>` · `adm|<src>|<dst>|<protocol>` · `hf|<key>` ·
`ti|in|<ip>` · `ti|out|<ip>` · `ti|dom|<domain>` · `iss|<issue key>`

## AI provenance flares

Every piece of LLM-written text in the app carries a purple **✨ model** flare (hover for model, source and time):
research notes, device notes, Ask AI answers, and correlation-review reasons (Related popover,
AI review page). `review.py` records `generated_by: {model, via}` with what it writes. Chat answers record the model that
answered; correlation verdicts store the reviewer's model id. Fix-list "How to fix" text and risk scores are rule-based (no flare).

## Clearing segmentation findings

Tick the box on a segmentation finding (Posture), a `Segmentation:` Fix-list item, or a flagged port in a Lateral
movement link to mark the flow as expected. It is stored once as a stable flow key (`<source MAC or IP>|<dest>|<port>`,
ack type `seg`), so clearing it anywhere clears it everywhere and it stays cleared on later snapshots. Cleared flows
are hidden from Posture, the Fix list and Risk, shown as *allowed* on Lateral movement, dropped from correlation,
and no longer raise host risk. Failed admin logins on a cleared flow still escalate. They are listed in a
separate **Cleared segmentation** section (Posture, Fix list, Lateral movement, Checked); untick to bring one back.
For a permanent rule that also applies to the nightly analysis, add it to the network policy's `allow` list (More → Settings).

