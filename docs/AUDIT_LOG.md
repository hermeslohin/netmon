# Audit log

netmon records **who did what in the dashboard** and **every conversation between netmon and an AI model**. Entries go to
Security Onion's Elasticsearch, in the index `logs-netmon`. Admins read them on **More → Audit log**; they are also
searchable in Kibana and Security Onion Hunt (the fields use Elastic Common Schema names).

- [What is recorded](#what-is-recorded)
- [What is not recorded](#what-is-not-recorded)
- [The Audit log page](#the-audit-log-page)
- [How it works](#how-it-works)
- [Setup](#setup)
- [Fields](#fields)
- [Searching in Kibana](#searching-in-kibana)
- [Retention and volume](#retention-and-volume)
- [Troubleshooting](#troubleshooting)
- [Code map](#code-map)

## What is recorded

Two kinds of entries, told apart by `event.dataset`:

### User actions: `netmon.audit`

| Action (`event.action`) | When |
|---|---|
| `auth.login` | Every sign-in attempt. `outcome: failure` (HTTP 401/429) for wrong passwords and lockouts. `user.name` is the name that was typed. |
| `auth.logout` | Sign-out. |
| `page.view` | Each page the user opens (the browser reports the route, e.g. `#/devices?ev=...`). |
| `acks.check` / `acks.uncheck` | Checking an event off / restoring it. |
| `kb.event`, `kb.host` (`.add`, `.delete`, `.approve`, `.reject`) | 📝 event notes and host notes, and approving User notes. |
| `aireview.*`, `compare.item`, `compare.adopt`, `aireview.compare` | Confirming/rejecting AI correlation verdicts, running model comparisons, adopting a model's answer, **Clear review queue** / **Clear research queue** (`aireview.clear-review`, `aireview.clear-research`). |
| `aireview.esquery` | Each Elasticsearch look-up the background correlation reviewer ran (user `netmon (background reviewer)`, category `database`): the structured query, hit count and error. Written by the app, not by a person. |
| `llm.review-limits` | Changes on AI review → Review limits: link-type modes, time window, max links per event, never-send events and rules (including **mute** on an alert, which also deletes the alerts that already fired), verdict retention, event classification on/off. The entry's parameters show the new values. |
| `research.request` | **Send to research** on an event. |
| `chat.new`, `chat.send`, `chat.history`, `chat.delete` | Ask AI: new chat, message, opening an old chat, deleting one (the AI conversation itself is a separate `netmon.llm` entry). |
| `users.*` | Adding and deleting users, password resets, role changes, device assignment. Console changes (`docker exec ... server.py add-user / set-role / set-password`) are logged as user `console`. |
| `config.*`, `llm.config`, `llm.research`, `llm.providers.*`, `llm.esqueries`, `llm.notes` | Integrations (Elasticsearch, UniFi, web search, audit key), Auto-close settings, review-job schedule and lookback, model choice (reviewer, research job, chat), **Research job limits**, the research job's categories and its Elasticsearch / web-research switches (`llm.research`), "Run now" and Pause, adding / editing / testing / deleting AI providers, the reviewer's Elasticsearch look-up setting and max per event (`llm.esqueries`), notes per event (`llm.notes`). |
| `push.*`, `alerts.read`, `account.password` | Notification subscriptions and preferences, marking alerts read, changing your own password. |
| `ti.lookup`, `compare.item.history`, `aireview.compare.history` | Threat-intel lookups and opening comparison history. |
| `audit.search` / `audit.open` | Reading the audit log itself (so admins' reading is audited too). |
| `access.denied` | Any request refused with HTTP 403 (for example a User opening an admin page). |

The rule behind the table: **every POST request is an entry** (the action name is the API path plus the `action`
field of the request, e.g. `/api/users` + `{"action": "add"}` → `users.add`), plus the listed GETs and every 403.
Ordinary data loads (opening tables and charts) are covered by `page.view` and are not logged one by one.

Each user-action entry has: time, user, role, source IP (the real client IP when the dashboard is reached through the
Cloudflare tunnel), browser, HTTP method, path and status code, `success`/`failure`, the target (user name, event id,
note id, ...) and the request parameters with secrets redacted.

### AI conversations: `netmon.llm`

| Action | Who talks to the model | What is stored |
|---|---|---|
| `llm.chat` | Ask AI chat, for the signed-in user | The exact text sent to the model (including the context block of the page the 💬 was opened from), the full answer, the chat session id, the tools the model used, provider and model, tokens when reported, duration, status (`completed`, `failed`, `cancelled`, `disconnected`). |
| `llm.correlation-review` | The background correlation reviewer, user `netmon (background reviewer)` | System prompt, prompt (the anchor event, its known artifacts, the candidate links, and the host / user / artifact notes given as context), the model's JSON answer with artifacts, model, tokens, seconds. With Elasticsearch look-ups on, one entry per round (the search results are in the next prompt). |
| `llm.event-classify` | The background reviewer when **Classify events** is on, same user | The event, its confirmed related events and notes, and the label (suspicious / benign / expected) with confidence and reason. |
| `llm.correlation-compare` | AI review → compare models, for the user who ran it | Same as above, one entry per model. |
| `llm.item-compare` | "Compare models" on a single finding, for the user who ran it | System prompt, the item as sent, the model's answer, verdict in the message, tokens, seconds. One entry per model. |
| `llm.research-input` | The research job (`review.py` on the host), user `netmon (research job)` | The work list netmon handed to the job's model (`enrich.sh events`). |
| `llm.research-result` | The research job | Everything the model sent back: research notes, verdicts, correlation links (`enrich.sh put`). Written when a person sent an event to research. |
| `llm.research-copy` | The research job's reviewer step | Earlier notes it decided to reuse for similar events (`enrich.sh copy`): the decisions with their reasons. |
| `llm.research-hostnotes` | The research job | AI-written host notes it added, changed or deleted (`enrich.sh kbput`). |

Failed model calls are logged too, with `outcome: failure` and the error. Prompts and answers longer than 32,000
characters are cut (marked `… [truncated, N chars]`); system prompts at 12,000.

The review job runs on the host (`review.py`, started by `scheduler.py`), not inside the dashboard, so the audit log
sees what goes in and what comes back (provider `research job`, the name kept in the log), not the job's internal tool calls. The full
conversations, tool calls included, are saved on the host under `logs/research/` (the newest 60), and each run's
tokens and estimated cost are on the AI review page.

### Switching the AI sources off

On the Audit log page, **Audit log storage** has two checkboxes: *Send reviewer events* (user `netmon (background reviewer)`: `llm.correlation-review`, `llm.event-classify` and `aireview.esquery`) and *Send researcher events* (user `netmon (research job)`: `llm.research-input`, `-copy`, `-result`, `-hostnotes`). Each is independent and on by default; when off, those entries are dropped (not queued). Stored in the `integrations` settings section `audit` as `send_reviewer` / `send_researcher`; the status API counts them as `skipped`.

These switches are separate from the Elasticsearch look-up switches on AI review → Models, which decide whether the reviewer (`llm.esqueries`) or the research job (`llm.research`, `es_search`) may *search* Security Onion at all. The research job's own searches are kept for the AI review page and as Kibana links on its notes, but are not individual audit entries; its prompts and results are.
Comparisons (`llm.correlation-compare`, `llm.item-compare`) are tied to the person who ran them and are not affected by either switch.

## What is not recorded

- **Secrets.** Any request parameter whose name looks like a password, key, token, cookie or credential (`password`,
  `current`, `api_key`, `key`, `p256dh`, `auth`, ...) is replaced by `[redacted]` before the entry leaves the request.
  This happens in `audit.clean()`, before anything is queued or written to disk.
- Session cookies and push-subscription keys.
- Background reads that no user started (the 15-minute watcher, the nightly collectors). They don't change anything and
  don't talk to an AI model. The watcher calls no model.

## The Audit log page

**More → Audit log**, admins only. Network defenders and Users don't see the menu entry, and the API refuses them (that
refusal is itself logged).

- **Audit log storage**: whether the dashboard can write to Elasticsearch, how many entries are stored, how much is
  waiting locally, and a form to change the audit key or index (**Test** checks the key without saving it).
- **Filters**: type (everything / user actions / AI conversations), time range (a quick range from 1 hour to 90 days or
  all, or **From** / **To** dates and times), user,
  action, outcome, model, and a text search that also searches prompts and answers. Filters are kept in the page
  address (`#/audit?kind=llm&range=7d&user=alex` or `#/audit?start=2026-10-18T13:00:00.000Z&end=2026-10-18T17:00:00.000Z`), so a filtered view can be bookmarked or shared.
- **Counters**: entries, user actions, AI conversations, failed or denied, users, AI tokens in/out for the filter.
- **Activity over time**: stacked bars of user actions and AI conversations.
- **Entries**: newest first, 50 per page (Newer/Older). Click a row for **Entry details**: every field, the system prompt,
  the prompt, the answer, the request parameters, and the raw Elasticsearch document.

## How it works

```
 browser ──► dashboard (server.py) ──► audit.action() ─┐
                │                                       │   in-memory queue
                ├── Ask AI ────── chat.stream ──► audit.llm() ──┤   (never blocks a request)
                ├── corr_llm / itemcmp ─────────► audit.llm() ──┤
 review.py ────► enrich.py / kb.py (docker exec) ► audit.llm() ─┤
                                                                ▼
                                   writer thread, a bulk request every ~2 s
                                   ├─ OK ──────────► Elasticsearch  logs-netmon
                                   └─ ES down / no key ─► state/audit_spool.jsonl ─► sent when ES is back
```

- Writing never slows the dashboard down: entries go into a queue and a background thread sends them in batches with
  the `_bulk` API (`create` operations only).
- If Elasticsearch is unreachable or no key is set, batches are appended to `dashboard/state/audit_spool.jsonl` (0600,
  max 50 MB). The writer retries with back-off (up to 2 minutes) and sends the spool, oldest first, as soon as
  Elasticsearch accepts it. Batches sent before a failure are not re-sent.
- Short-lived processes (the research job's `enrich.py` / `kb.py` and the console commands) send their own entries
  before they exit, and leave the spool to the dashboard so nothing is sent twice.
- Entries rejected by Elasticsearch (a mapping problem with a single document) are counted and shown in the storage
  box, and don't block the rest.
- The page reads through the same key: `/api/audit` (search and aggregations), `/api/audit/doc` (one entry),
  `/api/audit/status`. The large text fields (prompts, answers) are left out of the list and loaded only when you open
  an entry.

## Setup

One time, with an Elasticsearch account that can manage index templates and create API keys (Kibana → Dev Tools):

1. **Index template**: fixed mapping, `dynamic: false`, so prompts and answers are full-text searchable and the field
   count can't grow. The body is in [`audit_index_template.json`](audit_index_template.json).

   ```
   PUT _index_template/netmon-audit
   { ...contents of docs/audit_index_template.json... }

   PUT logs-netmon
   ```

2. **API key for the dashboard**: allowed only to add and read entries, never to change or delete them:

   ```
   POST /_security/api_key
   {"name": "netmon-audit",
    "role_descriptors": {"netmon_audit": {"indices": [{"names": ["logs-netmon"],
      "privileges": ["create_doc", "read", "view_index_metadata"]}]}}}
   ```

   Create it as a user. Elasticsearch refuses to create a key with privileges from another API key. Without
   `role_descriptors` the key gets all of your own rights; check it with
   `GET _security/user/_has_privileges` (with the key) and `{"index": [{"names": ["logs-netmon"], "privileges": ["delete"]}]}`,
   which should answer `false`.

3. **Give the key to the dashboard**: paste the `encoded` value on **More → Audit log → Change the audit key or index**,
   press **Test**, then **Save**. It is stored in the netmon database (`integrations` document; the DB file is 0600) under
   `audit`. Alternatively set `NETMON_AUDIT_ES_KEY` in `dashboard/.env` and run `./deploy.sh`. The Elasticsearch URL
   is the one used for everything else (Configuration → Integrations, or `es_url` in the site settings).

To use another index, enter it in the same form (one concrete name, no wildcards or commas) and create the template and
index for that name.

## Fields

| Field | Meaning |
|---|---|
| `@timestamp` | When it happened (UTC). |
| `event.dataset` | `netmon.audit` (user action) or `netmon.llm` (AI conversation). |
| `event.module`, `event.kind` | Always `netmon`, `event`. |
| `event.action` | What happened, see the tables above. |
| `event.outcome` | `success` or `failure`. |
| `event.category`, `event.type` | ECS categories: `authentication`, `web`, `iam`, `file`, `process`; `access`, `change`, `info`. |
| `event.duration` | AI call duration in nanoseconds. |
| `event.id` | Unique id of the entry. |
| `user.name`, `user.roles` | Who; `admin`, `defender` or `user`. Background work is `netmon (background reviewer)` / `netmon (research job)`; console commands are `console`. |
| `source.ip`, `user_agent.original` | Client address and browser. |
| `http.request.method`, `http.response.status_code`, `url.path` | The request. |
| `message` | One-line summary (shown in the list). |
| `netmon.target` | What the action was about (`username=…`, `id=…`, `eid=…`, `route=…`). |
| `netmon.params` | Request parameters, secrets redacted (`flattened` type). |
| `gen_ai.system` | Provider: `lmstudio`, the id of an AI provider added on AI review (`api:<id>`), or `research job`. |
| `gen_ai.request.model` | Model name. |
| `gen_ai.prompt`, `gen_ai.completion` | What netmon sent and what the model answered (full text, searchable). |
| `gen_ai.usage.input_tokens`, `gen_ai.usage.output_tokens` | Tokens when the provider reports them. |
| `netmon.llm.purpose` | `chat`, `correlation-review`, `correlation-compare`, `item-compare`, `research-input`, `research-result`, `research-hostnotes`. |
| `netmon.llm.system_prompt` | The instructions given to the model. |
| `netmon.llm.session_id`, `netmon.llm.tools`, `netmon.llm.status`, `netmon.llm.error` | Chat session, tools used, how the turn ended, error text. |

## Searching in Kibana

Create a data view for `logs-netmon` with time field `@timestamp`. Useful KQL queries:

```
event.action : "auth.login" and event.outcome : "failure"           # failed sign-ins
event.outcome : "failure" and event.dataset : "netmon.audit"        # everything refused or failed
user.name : "alex" and not event.action : "page.view"               # what one person changed
event.action : users.*                                              # account and role changes
event.dataset : "netmon.llm" and gen_ai.completion : "malicious"    # AI answers that said "malicious"
event.action : "llm.chat" and gen_ai.prompt : *password*            # chat messages mentioning passwords
```

Security Onion's detection rules can alert on these too, for example on several failed `auth.login` entries from one
`source.ip`.

## Retention and volume

There is no automatic deletion yet: the index grows until you add a policy. Most entries come from the background
correlation reviewer (about one per 3–30 seconds while it is working through new events, several thousand a day on a busy
day). User actions are a few hundred a day. An entry with a prompt and answer is typically 2–10 KB.

To keep, for example, 90 days, delete old entries on a schedule with an account that can (the dashboard's key can't):

```
POST logs-netmon/_delete_by_query
{"query": {"range": {"@timestamp": {"lt": "now-90d"}}}}
```

or move to a data stream with an ILM policy if you want rollover and automatic deletion.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| Storage box: *not reachable … audit API key not configured* | No key saved yet. See [Setup](#setup). Entries are waiting locally. |
| *HTTP 401* | The key is wrong, expired or was deleted. Create a new one and save it. |
| *HTTP 403 … unauthorized … create_doc* | The key lacks `create_doc` or `read` on the index (or the index name was changed). |
| *N waiting* grows | Elasticsearch is down or refusing writes. Container log: `docker logs netmon-dashboard 2>&1 \| grep audit`. Entries are sent automatically once it works again. Over 50 MB, new entries are dropped (counted as *dropped*). |
| *N rejected* | A field didn't fit the mapping. The storage box shows the Elasticsearch error; check the template. |
| Page shows *the server answered HTTP … without data* | The dashboard or the Cloudflare tunnel answered with an error page instead of data. Check that the container is running. |
| No research-job entries | They appear when the review job runs (`enrich.sh events` / `copy`) or someone clicks **Send to research** (`put` / `kbput`), and only if *Send researcher events* is on. |
| No reviewer entries | *Send reviewer events* is off, or the reviewer is idle (no undecided links). |

On startup the container log says `audit log -> <url>/logs-netmon (key set)` or `(key NOT set - spooling)`.

## Code map

| File | Role |
|---|---|
| `dashboard/app/audit.py` | `action()` and `llm()` build entries; `clean()` redacts secrets; the writer thread, spool, `search()`, `doc()`, `status()`. |
| `dashboard/app/server.py` | `do_POST` / `do_GET` wrappers write one entry per request (`audit_action_name`, `AUDIT_GET`); the Ask AI handler writes the `llm.chat` entry; `/api/audit*` endpoints (admin only); console commands. |
| `dashboard/app/chat.py` | `stream()` fills the record of a chat turn (input, answer, tools, status). |
| `dashboard/app/corr_llm.py`, `itemcmp.py` | Wrap every model call (`_complete`, `_ask`) with an `llm.*` entry, also on errors; the reviewer's Elasticsearch look-ups write `aireview.esquery`. |
| `dashboard/app/enrich.py`, `kb.py` | Research-job input and results. |
| `integrations.py` | `audit_key()`, `audit_index()`; the `audit` section of the `integrations` document and its **Test**. |
| `dashboard/app/static/audit.js` | The More → Audit log page. `app.js` reports page views (`auditView`). |
| `docs/audit_index_template.json` | Index template (mapping). |
