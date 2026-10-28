# Setting up netmon

This guide takes you from a fresh clone to a working install: a scheduled review job (collect, analyze, correlation review), a 15-minute urgent watcher, the HTTPS dashboard with phone push alerts, and the optional **Ask AI** chat.

netmon is **read-only** against your network. It queries Elasticsearch and the UniFi cloud API, and it never changes Security Onion, the gateway or any device.

![architecture](architecture.svg)

---

## 0. What you need

| Component | Required? | Used for |
|---|---|---|
| **Linux host** with Docker, Python 3.10+ at `/usr/bin/python3`, git, openssl, systemd (user services) | yes | runs the scheduler, the host broker and the dashboard container |
| **AI provider** with an API key: any OpenAI-compatible API (OpenAI, OpenRouter, Groq, Mistral, Together, DeepSeek, Gemini's OpenAI endpoint, vLLM...) or Anthropic | recommended | the review job (reviewer and on-request event research) and the chat. Pick a strong model that supports tool calling. The 15-minute watcher uses no LLM. |
| **LM Studio** (local LLM server) | optional, recommended | the correlation reviewer; can also serve the review job or chat |
| **Security Onion 2.4** (or any Elasticsearch with the same Suricata/Zeek data streams) | yes | network sensor and data store |
| **Elastic Agent via Fleet** on your endpoints (Elastic Defend + osquery integrations) | recommended | endpoint findings, host posture |
| **UniFi gateway** + UniFi Site Manager API key | optional | gateway IDS, admin audit, flows. Skipped when missing. |
| UniFi DHCP export CSV | optional | friendly device names. Without it, names come from DHCP/DNS. |
| Cloudflare Tunnel (or any reverse proxy) | optional | reach the dashboard and receive push notifications away from home |

The host needs no extra Python packages: everything is the standard library. The dashboard image installs its own dependencies.

## 1. Clone and run setup

The repo can live anywhere; the scripts find their own folder. This guide uses `~/netmon`:

```bash
git clone <this repository's clone URL> ~/netmon
cd ~/netmon
./setup.sh
```

`setup.sh` is safe to re-run. It never overwrites existing files. It:

- checks prerequisites (`python3`, `docker`, `git`, `openssl`, `systemctl`, `/usr/bin/python3`)
- loads the `*.example.json` templates into the netmon database as your starting settings (site, policy, host policy, known benign)
- creates the data folders (including `logs/`)
- creates the host secrets file `~/.config/netmon/secrets.env` (mode 600) for your API keys
- creates a self-signed TLS certificate and `dashboard/.env` with a first dashboard login (it prints the password) and the host broker's URL and key
- installs the systemd user units `netmon-scheduler.service` and `netmon-broker.service` (from `systemd/`, with your repo path filled in); it doesn't start them yet

`./setup.sh --check` only reports what is present or missing.

## 2. Describe your network (the Settings page)

All network-specific values live in the netmon database (`dashboard/state/netmon.db`, table `cfg`), never in git and never in JSON files. `setup.sh` loads the `*.example.json` templates as a starting point; after the dashboard is running, an admin edits them as tables on **More → Settings** (tabs: Network policy, Endpoint policy, Known benign, Site). Changes save automatically as you edit (there is no Save button) and the server rejects invalid values (bad regexes, an allow rule without a source or destination, a bad network range). Jobs read the new values on their next run; a few dashboard-wide site values (crown jewels, host IPs used by risk scoring) need a dashboard restart. To load a settings file by hand: `python3 store.py cfg-import <site|policy|host_policy|known_benign> file.json`; `python3 store.py cfg-export <doc>` prints one back out.

| Settings tab | What to put in it |
|---|---|
| **Site** | Your internal CIDR and prefixes, Elasticsearch URL, sensor IP, this host's IP and name, gateway name/DNS IP, home WAN IP, VPN prefixes, honeypot IPs, Fleet host name → IP (`host_ips`), crown-jewel hosts (scored highest impact), and `sensitive_terms` (host/user names the push guard should block). Optional pivot links (🔎 buttons): `kibana_url` (Kibana base, e.g. `https://so.example.lan/kibana/`), `kibana_data_view` (Discover data view id, default `logs-*`), `unifi_web_url` (UniFi Network web app base, e.g. `https://unifi.ui.com/consoles/<console-id>/network/default/` or `https://<gateway-ip>/network/default/`) and `unifi_paths` (label → page path under it). Leave `kibana_url` empty to hide the buttons. If you'll publish your own fork, also fill in `github_user`, `github_repo` and `image_repo`. |
| **Network policy** | **Quick start: click Auto-discover from UniFi** (see below). Network **zones** (CIDR per VLAN), **zone_roles** (zone → `dmz`, `protected`, `mgmt`, `user` or `iot`), **device_classes** (MAC or IP → `iot`, `camera`, `media`, `game`, `personal`, `work`, `server`, `k8s` or `infra`), and **allow** rules for expected cross-zone flows, and the detection sensitivity tables: `scan_thresholds`, `upload_spike`, `beacon` and `spike_thresholds` (DNS long names, DNS volume, IDS signature spike, external fan-out, failed connections: a floor, a multiple of the device's normal, a variation factor, history days and a severity or off). Each is described in its ⓘ bubble and on the event cards in Related events. Anything else on a sensitive port, from the DMZ, or from IoT/cameras to servers is reported as a segmentation violation. |
| **Endpoint policy** | Endpoint rules: expected admin source IPs (`admin_sources`), Fleet host → LAN IP (`endpoint_ips`), trusted tool paths (replace `/home/YOUR_USER`), syslog patterns, osquery posture expectations and per-host exceptions. The defaults are sensible; adjust the paths and IPs. |
| **Known benign** | Suricata signatures, IP names and domains you have explained as benign. The review model can add to this (`add_known_benign`). |
| `sec_accepted.json` (file, git-ignored) | Reviewed security-scan findings (filled in by `secfindings.py accept-current`). Start empty. |

### Auto-discover from UniFi

On **More → Settings → Network policy** (admin only), **Discover from UniFi** builds a proposal from your UniFi console and shows it before anything is changed. It needs the UniFi API key (More → Configuration). Code: `discover.py` (`python3 discover.py` prints a preview; `--apply [--overwrite]` writes it).

| Discovered | From |
|---|---|
| **zones** | one per enabled UniFi network that has a subnet (`rest/networkconf`), named from the network name (`Kubeworld` → `kubeworld`) or `vlanN`. A subnet that already has a zone keeps its name. |
| **zone_roles** | the network name (dmz/untrusted, IPMI/mgmt, server/kube/AI/lab, IoT/camera/guest), UniFi's *guest* flag, then what lives in the network (mostly servers → `protected`). Anything else is `user`. |
| **device_classes** | UniFi's device fingerprint category per client (camera, game console, TV/speaker, phone/tablet/watch, laptop, VM/server…), hostname hints (`kube-`/`talos` → `k8s`, `ipmi` → `infra`, `cam` → `camera`), and the zone role for unfingerprinted hosts. UniFi's own switches, access points and gateways are `infra`. |
| **internal_prefixes** (Site) | prefixes that cover all discovered subnets, so non-10.x networks count as internal. |

**Apply** only adds what is missing; **Apply & overwrite differences** also replaces existing roles and classes where UniFi disagrees. It never deletes. Fingerprints are a guess (a smart plug may show as a camera), so review the device table and correct anything in the Settings tables afterwards. **Not discovered:** `allow` rules, which are your exceptions; add them as you review segmentation violations.

Zone roles drive the rules, so zone names are free-form: `dmz` = internet-exposed (flows from it into other zones are violations, higher risk factor), `protected` = servers/clusters (IoT/camera access and cross-zone access flagged, impact 5), `mgmt` = IPMI/infrastructure (impact 4), `user` (3), `iot` (2). Without `zone_roles`, the legacy names `dmz`, `servers`, `k8s`, `ai` are still recognised.

Optional extras:

- **Device inventory:** put a UniFi DHCP export at `~/dhcp-export-all-<date>.csv` (columns: `Name`, `IP Address`, `MAC Address`, `Hostname`, `Local DNS Record`, `Lease Type`), or point `NETMON_INVENTORY` at another file name pattern.
- **Device-name table** for UniFi client checks: a markdown table with rows `| <mac> | <ip> | <name> |` (MAC lower-case, colon-separated). Put it at `~/.config/netmon/devices.md`, or point `NETMON_DEVICE_TABLE` at it.

## 3. Secrets

| Secret | Where | Notes |
|---|---|---|
| Elasticsearch API key | `~/.config/netmon/secrets.env` → `ES_API_KEY=<key>`, or **Configuration → Integrations** | Create a **read-only** key: Kibana → Stack Management → API keys, with `read` + `view_index_metadata` on `logs-*`. |
| UniFi Site Manager API key | `~/.config/netmon/secrets.env` → `UNIFI_API_KEY=<key>`, or **Configuration → Integrations** | https://unifi.ui.com → API. Optional. |
| Web search key (optional) | `~/.config/netmon/secrets.env` → `FIRECRAWL_API_KEY`, `BRAVE_API_KEY` or `TAVILY_API_KEY` | Only if you pick that search backend (step 7c). DuckDuckGo needs no key. |
| AI provider API keys | **AI review → AI providers** on the dashboard | Stored in the netmon database (owner-only file `dashboard/state/netmon.db`, mode 600). See step 7b. |
| Dashboard login + host broker key | `dashboard/.env` | Created by `setup.sh` (`DASH_PASS`, `NETMON_BROKER_URL`, `NETMON_BROKER_KEY`). |

The secrets file is plain `KEY=value` lines, mode 600, outside the repo (set `NETMON_SECRETS` to use another path). Values saved on the dashboard's Configuration page take precedence over it. None of these are ever committed: `.gitignore` and the push gate block them.

## 4. Elastic Agent / osquery on your endpoints (recommended)

In Kibana **Fleet**, give your endpoint agent policies these integrations:

- **Elastic Defend.** On macOS, approve the system extension and grant Full Disk Access, or protections stay off and netmon will tell you so.
- **System** (auth and syslog logs).
- **Osquery Manager.** Import `osquery_pack.json` as a pack named `netmon-host-posture`, assign it to your policies and enable it.

Hosts then appear on the dashboard's **Endpoints** page after the next collection.

## 5. First collection (manual)

```bash
cd ~/netmon
/usr/bin/python3 esq.py logs-zeek-so '{"size":0}'      # connectivity test: prints hit totals
/usr/bin/python3 collect.py 24                          # → snapshot document `data/<stamp>` in the netmon database
/usr/bin/python3 analyze.py                             # → `data/<stamp>.analysis` document + baseline
```

Behaviour rules (traffic spikes, new destinations and so on) need **3 days** of baseline before they fire. Static rules (IDS, threat intel, segmentation, endpoint findings) work from day one.

## 6. Dashboard

```bash
cd ~/netmon/dashboard && ./deploy.sh
```

- It listens on **https://<host>:8443**. Sign in with the `admin` password `setup.sh` printed, then change it on the **My account** page. Add family accounts on the **More → Dashboard users** page.
- The container runs read-only, as your user, with all capabilities dropped. It mounts the repo read-only, `dashboard/state` (SQLite, users, push subscriptions) read-write.
- **Phone push notifications** need HTTPS with a certificate the phone trusts. A Cloudflare Tunnel (`cloudflared`) pointing at `https://127.0.0.1:8443` with "No TLS Verify" works well. On iPhone, add the site to the Home Screen first, then enable notifications on the Alerts page.
- The login lockout trusts `CF-Connecting-IP` only from loopback, which is how cloudflared connects.

### Audit log (Elasticsearch `logs-netmon`)

Every user action and every AI conversation is written to the Elasticsearch index `logs-netmon` and shown on **More → Audit log** (admins only, see the [user guide](USER_GUIDE.md#more--audit-log)). One-time setup with an Elasticsearch account that can manage templates (Kibana → Dev Tools, or curl):

1. Index template (fixed mapping, so prompts and answers are full-text searchable): `PUT _index_template/netmon-audit` with the body in `docs/audit_index_template.json`, then `PUT logs-netmon`.
2. A key for the dashboard that can only add and read entries:
   `POST _security/api_key {"name": "netmon-audit", "role_descriptors": {"netmon_audit": {"indices": [{"names": ["logs-netmon"], "privileges": ["create_doc", "read", "view_index_metadata"]}]}}}`
   (create it as a user, not with another API key: Elasticsearch refuses keys with privileges derived from an API key).
3. Paste the `encoded` value on **More → Audit log → Change the audit key or index**, **Test**, **Save** (stored in the netmon database). `NETMON_AUDIT_ES_KEY` in `dashboard/.env` works too.

Until a key works, entries wait in `dashboard/state/audit_spool.jsonl` (max 50 MB) and are sent automatically. Full reference: [AUDIT_LOG.md](AUDIT_LOG.md).

### Time ranges

Dashboard **time ranges** other than a review-job window are collected by the host broker (`host_broker.py`, `POST /range`: `collect.py --start --end --out dashboard/state/ranges/<id>.json` + `analyze.py --readonly`; the results are stored as `ranges/<id>…` documents in the netmon database, not as files), because the container has no Elasticsearch key. They need the broker service running (step 7); nothing else to set up.

The optional Elasticsearch look-ups of the correlation reviewer and of the research AI (AI review → Models; see [CORRELATION.md](CORRELATION.md)) also run through the broker (`POST /esquery`, `es_context.py`) for the same reason, and so does **Send to research** (`POST /research-event`).

### Local LLM for correlation review (optional, recommended)

The dashboard links related events and vulnerabilities, then asks a **local LLM** to confirm or reject each link (details in [CORRELATION.md](CORRELATION.md)). Install [LM Studio](https://lmstudio.ai), load a capable instruction model (tested with Gemma 4 31B), and enable its server on port 1234. The container uses host networking and finds the loaded model automatically. Nothing leaves the machine. LM Studio also appears as a model choice for the review job and the chat (step 7b).

```bash
lms server start && lms load google/gemma-4-31b-qat     # or load a model in the LM Studio app
curl -s http://127.0.0.1:1234/v1/models                 # the dashboard uses this endpoint
```

Optional settings in `dashboard/.env` (then `./deploy.sh`): `NETMON_LLM=off`, `NETMON_LLM_URL`, `NETMON_LLM_MODEL`, `NETMON_LLM_REASONING` (default `none`), `NETMON_LLM_WORKERS` (default 2). Without an LLM, links show the script's evidence only.

## 7. Scheduled jobs and the host broker

Two systemd **user** services run on the host. `setup.sh` installed them; start them once the first collection works:

```bash
sudo loginctl enable-linger $USER          # keep user services running when you're logged out
systemctl --user enable --now netmon-broker netmon-scheduler
systemctl --user status netmon-scheduler   # or: /usr/bin/python3 scheduler.py status (next run of each job)
```

**`netmon-scheduler`** (`scheduler.py`) runs every recurring job. All results go to the dashboard (and Web Push), never to a chat platform. Each job's output is in `logs/<job>.log`.

| Job | When | What |
|---|---|---|
| watcher | every 15 minutes | `watch.py`: urgent alerts (new devices, IDS, threat intel, exposed ports, DNS tunnels, host anomalies, failed admin logins). Deterministic, no AI. |
| review job | every N minutes, set on **Configuration → AI Research job runs every** (30 min to 24 h), on a grid anchored at 05:00 UTC; plus **Run now** on the AI review page | `review.py`: collect + analyze, the reviewer (reuses earlier research notes). |
| weekly rebuild | Sundays 03:00 UTC | `weekly_rebuild.sh`: dashboard image rebuild with updated libraries + security scan. |

Jobs never overlap with themselves. A slot missed while the host was down is not made up, except the review job, which starts late within its own slot. The review job only runs once a model is chosen for it (step 7b) and it isn't paused.

**`netmon-broker`** (`host_broker.py`) listens on `127.0.0.1:8650` only and needs the bearer key `NETMON_BROKER_KEY` from `dashboard/.env` (with `NETMON_BROKER_URL=http://127.0.0.1:8650`). The dashboard container has no Elasticsearch key, so it asks the broker for exactly three things: `POST /range` (time-range collection for the dashboard's picker), `POST /research-event` (start a one-event research run when someone clicks Send to research) and `POST /esquery` (bounded read-only Elasticsearch look-ups for the correlation reviewer, at most 600 an hour). It handles no models, keys or schedules.

### The review job

Each run of `review.py`:

1. Collects and analyzes (`collect.py` + `analyze.py`). The **daily run**, the first run at or after 05:00 UTC each day, always covers 24 hours of logs. Other runs cover the lookback window set on the AI review page (1-24 h, stored by `lookback.py`). Shorter snapshots are compared with the baseline scaled to their length, are never folded into it and never mark a Fix-list item fixed. `analyze.py` folds a snapshot into the baseline only when the last baseline record is at least 23 hours old (`FOLD_MIN_HOURS`), so the baseline stays one record per day.
2. **Reviewer, then research on request only.** A scheduled run does not research events (to keep token cost down): the reviewer copies earlier notes for repeat events and everything else waits in the queue. Event research happens when someone clicks **Send to research** on an event (`review.py --event ID`). The events go to the model in batches of 8 (`prompts/enrich.md`, at most *research batches* per run). `enrich.sh events` lists them; every endpoint host finding (own quota, `--hosts N`, default 60), every Suricata severity 1-2 signature (`--ids N`, default 40) and every UniFi gateway event family (`--gw N`, default 30) is included on top of `--max N` other events. The model's `submit_notes` results are stored with `enrich.sh put` as `{"model", "notes": [{"id", "verdict", "priority", "summary", "research", "links"}], "links": [{"a", "b", "related", "confidence", "reason"}]}` in the dashboard's `state/enrich.db`. Notes show as a "✨ verdict" button next to an event's Related count. Link verdicts go in the same table as the local LLM's and replace them; manual verdicts are kept. Gateway events (`gw|...`) are also correlation events, so the local LLM reviews their links.

Run state, tokens and estimated cost are stored in the netmon database and shown on the AI review page. The full conversations, tool calls included, are saved in `logs/research/` (the newest 60 are kept). Manual runs:

```bash
/usr/bin/python3 review.py                 # like a scheduled run
/usr/bin/python3 review.py --daily         # force the 24 h daily run; --no-daily to skip it
/usr/bin/python3 review.py --skip-collect --max-batches 2   # reuse the newest snapshot, fewer research batches
```

## 7b. AI providers, models and limits

Everything is set by an admin on the dashboard's **AI review** page; nothing on the host needs editing.

**AI providers.** **Local (LM Studio)** is always the first row - no key or URL to set (those come from
`NETMON_LLM_URL`), just an **enabled** switch and a **calls per hour** cap; disable it or lower its cap here
instead of editing `.env`. Add as many other providers as you like. Each has a type, **OpenAI / OpenAI-compatible**
(OpenAI, OpenRouter, Groq, Mistral, Together, DeepSeek, Gemini's OpenAI endpoint, vLLM, ...) or **Anthropic**, an
optional base URL (plain `http://` only for LAN or loopback addresses), an API key, and its models, one per line.
After a model id you can add prices in $ per million tokens, `model input output [cached-input]`; they are used
for cost estimates and the $ caps. **Fetch from provider** fills in the model list, **Test** lists the models
without spending tokens. Each provider also has a calls-per-hour cap (for the single calls of the correlation
reviewer and comparisons) and an optional number of extra reasoning tokens. Keys are stored in
the netmon database (`netmon.db`, mode 600), only the last 4 characters are ever shown, and they are scrubbed
from error messages. Changing a provider's type or base URL requires entering the key again. Model choices are
stored as `api:<provider id>` or `lmstudio` plus the model name.

**Models.** Three choices: the **correlation reviewer**, the **AI Research job** and the **chat (Ask AI)**. The
research job and the chat are off until you choose a model. Under the model menus an admin can also switch the
reviewer's and the research AI's read-only Elasticsearch searches on or off (**Elasticsearch queries · correlation
review** with a per-event maximum, **Elasticsearch queries · AI research**) and set **Notes per event**, the most host and
account notes the reviewer is given with each event. A provider that is in use can't be deleted (Local
(LM Studio) can only be disabled, never deleted). On any current correlation decision, the ⇄ button asks up to 4
models the same question side by side and can store one model's answer as the decision.

The **review job needs a reasoning-capable model** - it works through several tool calls per event (web search,
reading pages, checking netmon data) and decides what to do next between them, which a plain chat model does
noticeably worse at and sometimes gets stuck looping on. Pick a reasoning model (OpenAI's `o`-series / GPT-5
family, Anthropic's extended-thinking Claude models, or a local reasoning model such as Qwen/DeepSeek-R1 in LM
Studio) and give it some **extra reasoning tokens** on its provider row - 0 there effectively turns reasoning off
and will hurt research quality even on a model that supports it. The correlation reviewer and the chat don't need
this: the reviewer only ever answers one fixed-format question per call, and the chat still works, just more
superficially, on a non-reasoning model.

**Research job limits** (also on AI review): $ per run (default 5), $ per day (default 20), tokens per run (input + output, works without prices; default 25,000,000) and research batches per run (default 10), web searches per event (default 3) and the **Web research** switch (off on a new install: no web search until an admin turns it on). A run stops when it passes its caps, and no new run starts once today's runs (UTC) cost the daily cap. 0 turns a cap off. The $ caps need prices on the provider's model. The **AI Research job** card shows the job's status, schedule and next run, **Run now** / **Pause**, recent runs, and the *Time and tokens per research job* chart with a cost preview for another model.

Only dashboard **Admins** can change providers, models or limits, or run comparisons. Roles are set on the Dashboard users page ([ACCESS_CONTROL.md](ACCESS_CONTROL.md)). The settings live in the store's meta table (`research_cfg.py`) and the netmon database (settings document `llm_config`). The correlation reviewer's model is remembered once chosen; if none has ever been chosen, it defaults to the first enabled, configured provider with a model (an API provider before Local (LM Studio), since the reviewer calls far more often than a typical API rate cap allows) - it no longer requires Local (LM Studio) to be running.

## 7c. Web search (research and chat)

The AI Research job (event research) and the chat search and read the web through `webtools.py`. The backend is set under **Configuration → Integrations → Web search** (stored in the netmon database, section `web`): **DuckDuckGo** (no key, the default), **Firecrawl**, **Brave** or **Tavily** (with a key). The key can also go in the host secrets file as `FIRECRAWL_API_KEY`, `BRAVE_API_KEY` or `TAVILY_API_KEY`. When Firecrawl is configured, pages are fetched through it too. Without a working key, search falls back to DuckDuckGo.

## 8. Ask AI chat (optional)

The chat runs inside the dashboard (`dashboard/app/chat.py`) with the chat model chosen on **AI review → Models**. It has no terminal, file, memory or settings tools. It can only search and read the web and query netmon through the read-only `netmon_*` tools (from `netmon_mcp.py`, which opens SQLite read-only). Admins can also pick a model per message in the chat header.

Once a chat model is chosen, the **Ask AI** menu item and the 💬 button on every finding work. Limits are 40 messages per user per hour, 4,000 characters per message and 600,000 tokens per answer. Conversations are kept in `dashboard/state/chat.db` (mode 600).

`netmon_mcp.py` can also be run as a stdio MCP server, so any MCP client can query the same read-only netmon data.

## 9. Making changes (and publishing your fork)

- Develop with any editor or AI coding assistant; none is needed at runtime. Code changes go through `./ship.sh "<message>" [--deploy]`. It runs the security scan suite (`sec_scan.sh`: Semgrep, Ruff/Bandit, pip-audit, ESLint, Trivy, Hadolint, Gitleaks, ZAP; the scanners run in Docker), a secret gate, and **`repo_guard.py`**, which blocks commits containing your site IPs, MAC addresses, host/account names (from the site settings) or any private config file. Then it rebases on `origin/main` and pushes. `sec_scan.sh` writes to `${NETMON_SCAN_DIR:-~/.cache/netmon/sec}`; set `NODE_BIN` to a folder with `node`/`npx` for ESLint if they aren't on `PATH`, and `NETMON_SCAN_EXTRA` to extra folders for Gitleaks (space-separated).
- New scan findings show up as in-app alerts and Fix list entries. Review them, fix them, or accept them with a reason (`secfindings.py accept-current`).
- The weekly rebuild can also push a versioned image to `ghcr.io`, if `image_repo` is set and a token with `write:packages` is in `~/.config/netmon/github_token`.

## Troubleshooting

| Symptom | Check |
|---|---|
| `collect.py` errors on an index | `esq.py <index> '{"size":0}'`. Your Security Onion version may name data streams differently: adjust the index names in `collect.py`/`extras.py`. |
| Empty Endpoints page | Fleet agents healthy? `logs-endpoint.events.*` and `logs-osquery_manager.result-*` present? |
| UniFi section says "skipped" | No `UNIFI_API_KEY` in `~/.config/netmon/secrets.env` and none on Configuration → Integrations. |
| Locked out of the dashboard | 8 failed logins → 5-minute lockout. `docker restart netmon-dashboard` clears it. To reset a password: `docker exec -it netmon-dashboard python /app/server.py set-password <user>` |
| Chat says "not configured" or "unavailable" | Choose a chat model on AI review → Models; **Test** the provider on AI review → AI providers. Errors are in `docker logs netmon-dashboard`. |
| Review job never runs | `systemctl --user status netmon-scheduler`, `logs/research.log`, `/usr/bin/python3 scheduler.py status`. A model must be chosen and the job not paused; check the $ caps on AI review. Lingering on? (`loginctl show-user $USER -p Linger`) |
| Time ranges or reviewer searches fail | `systemctl --user status netmon-broker`; `NETMON_BROKER_URL` / `NETMON_BROKER_KEY` in `dashboard/.env`. |
| Push notifications never arrive | The site must be reached over a trusted HTTPS name (tunnel), not the self-signed IP. |
| Related links all say "AI review pending" | LM Studio running with a model loaded? `curl http://127.0.0.1:1234/v1/models`. The popover footer shows the last error. A first full review takes 1–2 h. |
| LLM returns empty answers | Reasoning models use the whole token budget on hidden thinking. Keep `NETMON_LLM_REASONING=none`. |
| No admin-access data | The section starts with the first snapshot after the feature was added. Login results need Elastic Agent on the target (Linux auth logs / Windows security log). Without it you still see connection attempts. |
| Watcher testing | Never run the live `watch.py` by hand to test, because it mutes alerts for 12 h. Use `NETMON_DB=/tmp/copy.db /usr/bin/python3 watch.py`. |

## File map

| Path | Role |
|---|---|
| `collect.py`, `extras.py`, `unifi.py`, `hosts.py`, `hostdetail.py`, `osq.py` | data collection (Elasticsearch, UniFi, endpoints) |
| `discover.py` | Auto-discover zones, zone roles and device classes from UniFi (Settings → Network policy) |
| `settings_docs.py` | the (i) definitions shown for every Settings section (stored as `_doc_<setting>` in each settings document; run it to refresh them) |
| `analyze.py`, `mitre.py` | baselines, findings, ATT&CK mapping |
| `adminproto.py` | admin / lateral-movement protocol + tool catalog, session merger |
| `dashboard/app/lateral.py`, `risk.py` | lateral graph, admin-session scoring, host risk ([RISK_SCORING.md](RISK_SCORING.md)) |
| `dashboard/app/correlate.py`, `corr_llm.py` | event correlation, local-LLM review ([CORRELATION.md](CORRELATION.md)) |
| `watch.py` | 15-minute urgent watcher |
| `review.py`, `research_cfg.py`, `prompts/` | the review job, its settings, and its prompts |
| `agent.py`, `llm_providers.py`, `webtools.py` | tool-using conversation loop, AI provider calls, web search / fetch |
| `scheduler.py`, `host_broker.py`, `systemd/` | job scheduler and loopback host broker, their systemd user units |
| `store.py` | SQLite state store (WAL): state tables, JSON documents (snapshots, time ranges, job state) and the settings tables |
| `netmon_mcp.py` | read-only netmon tools for the chat (also a stdio MCP server) |
| `dashboard/` | HTTPS dashboard (stdlib server, plain JS, Web Push) |
| `site_cfg.py` | site settings loader (reads the `site` settings from the database) |
| `setup.sh` | installer (config, folders, secrets file, TLS, dashboard login, systemd units) |
| `sec_scan.sh`, `secfindings.py`, `repo_guard.py`, `ship.sh`, `weekly_rebuild.sh` | security scanning and the push gate |
