# netmon access control

Every dashboard account has one of three **roles**. The server checks the role on every request; the browser only hides
what a role can't use. Hiding a button is never the protection.

| Role | Who it's for | In one line |
|---|---|---|
| **Admin** | whoever runs netmon | Can do everything. |
| **Network defender** | people who watch and work the network | Can see everything but can't change settings. |
| **User** | household members, device owners | Can only see the events for the devices assigned to them. |

## What each role can do

| Capability | Admin | Network defender | User |
|---|:-:|:-:|:-:|
| Sign in, change own password (More → My account) | ✓ | ✓ | ✓ |
| Push notifications on own browsers/phones | ✓ | ✓ | ✓ (assigned devices only) |
| Urgent alerts (Alerts page, 🔔) | all | all | assigned devices only |
| Security events for a device (correlated findings, IDS, gateway, endpoint, vulns) | all pages | all pages | **My devices** page, assigned devices only |
| Every other page: Overview, Security, Network, Devices, Notes, Reports (PDF), AI review, Checked | ✓ | ✓ | ✗ |
| Configuration and Users pages | view + change | view only | ✗ |
| Check off events, write 📝 event notes and host notes, confirm/reject AI correlation verdicts | ✓ | ✓ | ✗ |
| 📝 notes on events of own devices (pending until approved; sees only own notes) | ✓ | ✓ | ✓ (assigned devices only) |
| Approve / reject User notes so the AI may read them | ✓ | ✓ | ✗ |
| Ask Hermes (chat) | ✓ (and can pick the model) | ✓ (default model) | ✗ |
| Choose own alert devices (Alerts → Notification settings) | ✓ | ✓ | ✗ (an admin assigns them) |
| Mark alerts read | shared 🔔 for everyone | shared 🔔 for everyone | private marker, doesn't change anyone else's 🔔 |
| Add / delete users, reset passwords, change roles, assign devices | ✓ | ✗ | ✗ |
| Integrations (Elasticsearch, UniFi): view and change | ✓ | ✗ | ✗ |
| Audit log (More → Audit log): read, set its Elasticsearch key | ✓ | ✗ | ✗ |
| Security Triage settings, review-job schedule, "Run now", reopen auto-closed | ✓ | ✗ | ✗ |
| AI models (correlation reviewer, research job), model comparisons, "Use this" | ✓ | ✗ | ✗ |

**"Settings"**, which a defender can't change, means anything that changes how netmon runs or who can use it: users,
roles, device assignments, integrations, triage/auto-close, schedules and AI models. Analyst work, such as checking items
off, writing notes, confirming or rejecting an AI link and asking Hermes, is not a setting. Defenders can do it.

## The User role in detail

- A User sees **only** the devices an admin assigned to them. A new User sees nothing until an admin assigns at least one
  device (the Users page marks such accounts with **no devices**). "All devices" can't be assigned to a User.
- The dashboard shows a User two pages: **My devices** (their devices and the security events from the latest snapshot
  that involve one of the devices' IP addresses) and **Alerts** (urgent alerts whose targets include one of their
  devices: IP, MAC or endpoint host name). Their account page and push notifications also work.
- Every other API, the report PDFs and Ask Hermes return **403** for a User. The site config they receive has only the
  site name; it leaves out IP hints, internal prefixes and admin workstations.
- Event text can name the other party, for example the external IP that attacked their device or the internal host it
  talked to. They don't get the other device's own events.
- Push notifications follow the same scope: a User is only ever pushed alerts for their assigned devices.
- A User's "Mark all read" sets a private marker, so it doesn't clear the 🔔 that admins and defenders share.
- A User can add 📝 notes to the security events on **My devices** (only events that involve one of their assigned
  devices; the server re-checks this) and delete their own notes. They see only their own notes, never the notes
  admins or defenders wrote on the same event.
- **AI gate:** a User's note is stored as *pending* and is never given to any AI (research run, correlation reviewer,
  Ask Hermes / `netmon_notes`, `kb.py dump`) until an admin or network defender approves it. Pending notes show ⏳ on the
  event's 📝 button and in **Notes → Event notes awaiting approval**, with Approve / Reject. Rejected notes are kept for
  the record but never reach the AI. Notes written by admins and defenders are approved when written. Approval applies
  to the note's exact text: a User who wants to change it deletes it and writes a new one, which is pending again.
  A User can have at most 50 notes pending at once.

## Managing access (admins)

**More → Users**:

- **Role** column: pick Admin, Network defender or User. The change takes effect on the user's next request. Nobody has
  to sign out.
- **Assign…**: for a User, the devices they may see. For an admin or defender, it only chooses which devices alert them
  (they still see everything).
- **Add user**: choose the role when you create the account. The default is User, the least privilege.
- **Reset password / Delete**.

Safety rules:

- You can't demote yourself. Another admin must do it, so an admin can't lock themselves out by mistake.
- The last admin can't be demoted or deleted.
- An account with a missing or unknown role is treated as **User** (least privilege).

From the host (recovery, e.g. if every admin is locked out):

```bash
docker exec -it netmon-dashboard python /app/server.py set-role <user> admin|defender|user
docker exec -it netmon-dashboard python /app/server.py add-user <user> [admin|defender|user]   # default admin; prompts for a password
docker exec -it netmon-dashboard python /app/server.py set-password <user>
```

## Where it lives

| What | Where |
|---|---|
| Role per account | `role` field in `dashboard/state/users.json` (0600, git-ignored) |
| Device assignment | `push_prefs` table in `dashboard/state/netmon.db` (the same setting that routes alerts) |
| User-role read marker | `read_upto` field in `users.json` |
| Enforcement | `dashboard/app/server.py`: `USER_GET` / `USER_POST` allow-lists for Users, `ADMIN_POST` for admin-only changes; `auth.role_of()` |
| Push scope | `dashboard/app/pushsvc.py` |

Denied requests are logged to the container log as `access denied: <user> (<role>) POST <path>`. Role changes, user
adds and deletes are logged as `user admin: …`.

Everything is also written to the **audit log** (`dashboard/app/audit.py`, Elasticsearch index `logs-netmon`, page More →
Audit log): every sign-in attempt, every POST (with its parameters, secrets redacted), page views, report downloads,
audit-log reads, every refused request (403), console user changes (`server.py add-user / set-role / set-password`),
and every conversation between the dashboard and an AI model (prompt, answer, model, tokens, time). See
[AUDIT_LOG.md](AUDIT_LOG.md).

## Upgrade from the single-tier setup

Before roles existed, every account could see and check off everything, and `NETMON_ADMINS` in `dashboard/.env` named
the accounts allowed to change AI models. On the first start with roles, **every existing account was made an Admin**
(log line `access control: existing accounts made admins: …`), so nobody lost access. Lower accounts to Network defender or
User on the Users page as needed. `NETMON_ADMINS` is no longer read and can be removed from `.env`.
