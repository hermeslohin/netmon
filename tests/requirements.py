"""netmon requirements catalog: the single list of requirement IDs the tests trace to.

Derived from README.md and docs/ (ACCESS_CONTROL, AUDIT_LOG, RISK_SCORING, CORRELATION, SETUP, USER_GUIDE).
Each test names the requirement(s) it verifies on a line of its docstring:   REQ: AC-03, SEC-01
tests/gen_docs.py turns these tags into docs/TEST_TRACEABILITY.md.
"""

# id: (area, requirement text, source document)
REQUIREMENTS = {
    # ---- authentication ----
    "AUTH-01": ("Authentication", "Passwords are stored only as salted scrypt hashes; a wrong password never verifies.", "ACCESS_CONTROL.md"),
    "AUTH-02": ("Authentication", "Passwords shorter than 10 characters are rejected (add user, reset, self-service change).", "USER_GUIDE.md §2"),
    "AUTH-03": ("Authentication", "Usernames are 2-40 characters of letters, digits and . _ @ -; duplicates are rejected.", "ACCESS_CONTROL.md"),
    "AUTH-04": ("Authentication", "Sessions are signed tokens that expire (SESSION_HOURS) and are revoked by logout or a password change.", "ACCESS_CONTROL.md"),
    "AUTH-05": ("Authentication", "Repeated failed sign-ins from one client address are throttled.", "ACCESS_CONTROL.md"),
    "AUTH-06": ("Authentication", "On first start the first account is seeded from DASH_USER/DASH_PASS; afterwards the env vars are ignored.", "SETUP.md §6"),
    "AUTH-07": ("Authentication", "Accounts that predate roles are migrated to Admin once, so nobody loses access.", "ACCESS_CONTROL.md (Upgrade)"),
    # ---- access control ----
    "AC-01": ("Access control", "Unauthenticated requests get 401 (API) or a redirect to /login (pages); only the login/PWA shell and /healthz are public.", "ACCESS_CONTROL.md"),
    "AC-02": ("Access control", "Three roles exist (admin, defender, user); a missing or unknown role is treated as User (least privilege).", "ACCESS_CONTROL.md"),
    "AC-03": ("Access control", "A User may call only the USER_GET / USER_POST allow-lists; every other API returns 403.", "ACCESS_CONTROL.md"),
    "AC-04": ("Access control", "A Network defender can read everything and do analyst work but cannot change settings (admin-only POSTs return 403).", "ACCESS_CONTROL.md"),
    "AC-05": ("Access control", "An admin cannot demote themself, and the last admin can be neither demoted nor deleted.", "ACCESS_CONTROL.md (Safety rules)"),
    "AC-06": ("Access control", "A User sees only alerts/events of devices assigned to them, and the site config they receive omits IP hints.", "ACCESS_CONTROL.md (User role)"),
    "AC-07": ("Access control", "A User's 'mark all read' is a private marker that does not change the shared bell.", "ACCESS_CONTROL.md"),
    "AC-08": ("Access control", "Role changes, user adds/deletes and password resets are admin-only and take effect on the next request.", "ACCESS_CONTROL.md (Managing access)"),
    # ---- transport / web security ----
    "SEC-01": ("Web security", "Every response carries the security headers (CSP, HSTS, X-Frame-Options DENY, nosniff, Referrer-Policy, COOP/CORP).", "SETUP.md / server.py"),
    "SEC-02": ("Web security", "The dashboard is served over TLS 1.2+ only.", "SETUP.md §6"),
    "SEC-03": ("Web security", "The session cookie is HttpOnly, Secure and SameSite=Strict.", "ACCESS_CONTROL.md"),
    "SEC-04": ("Web security", "Site data (site IPs, MACs, host/account names, private config, DBs, keys) can never be committed to git (repo_guard).", "SETUP.md §9"),
    "SEC-05": ("Web security", "Static file serving cannot escape the static directory (no path traversal) and unknown paths return 404.", "server.py"),
    "SEC-06": ("Web security", "The state database and its WAL files are owner-only (0600).", "ACCESS_CONTROL.md (Where it lives)"),
    # ---- audit ----
    "AUD-01": ("Audit log", "Every POST is audited with user, role, outcome and parameters, with secrets redacted.", "AUDIT_LOG.md"),
    "AUD-02": ("Audit log", "Every sign-in attempt and every refused (403) request is audited.", "AUDIT_LOG.md"),
    "AUD-03": ("Audit log", "Audit entries spool locally while Elasticsearch is unreachable; auditing never breaks a request.", "AUDIT_LOG.md (How it works)"),
    # ---- store ----
    "STO-01": ("Store", "Snapshots, ranges and job/config state are JSON documents in the SQLite docs table (jload/jdump/jglob drop-ins).", "store.py"),
    "STO-02": ("Store", "Configuration (site, policy, host_policy, known_benign) is stored as flattened cfg rows that round-trip exactly.", "SETUP.md §2"),
    "STO-03": ("Store", "Check-offs (acks) persist with note and label and can be set/cleared in bulk.", "USER_GUIDE.md §5"),
    "STO-04": ("Store", "Mute ('Never send') rules match alerts by name glob and optional host, and clear matching alerts.", "USER_GUIDE.md §4"),
    "STO-05": ("Store", "Suppression rules (artifact, segmentation flow, IDS signature) hide only what they match.", "PLAYBOOKS.md §17"),
    "STO-06": ("Store", "Alerts are stored once, can be promoted/held/deleted, and track pushed/read state.", "USER_GUIDE.md §4"),
    "STO-07": ("Store", "Per-user device assignment (push prefs) decides which alerts a user is targeted by.", "ACCESS_CONTROL.md"),
    "STO-08": ("Store", "Auto-close checks off every open event (any type or age) an enabled AI source calls expected/benign, never one called suspicious, never re-closes one a person reopened, and reopens it when the verdict turns bad.", "autoclose.py"),
    "STO-10": ("Store", "Open events older than the loaded snapshot keep their related events: the count, linked events, artifacts and the decision model's (clef) p(related) and event label come from the stored verdicts.", "eventstore.py / corr_llm.related_view"),
    "STO-09": ("Store", "Nightly host note consolidation merges only unreviewed AI notes, keeps every [reviewer:] tag and identifier (IPs, domains, ports, paths, hashes) or leaves the notes unchanged, never touches person-written notes, skips unchanged hosts, and runs once a day at the time set on AI review.", "notes_consolidate.py"),
    # ---- analysis / scoring ----
    "ANA-01": ("Baseline analysis", "analyze.py learns a per-device baseline (keyed by MAC) and flags volume/upload/count spikes only after MIN_DAYS of history.", "analyze.py / RISK_SCORING.md"),
    "RISK-01": ("Risk scoring", "Vulnerability risk is 0-100 from severity base x kind factor x host exposure, plus recurrence.", "RISK_SCORING.md"),
    "RISK-02": ("Risk scoring", "Host risk is 0-100, the sum of capped components (exposure, weaknesses, threat, lateral, visibility).", "RISK_SCORING.md"),
    "RISK-03": ("Risk scoring", "IPs map to policy zones by CIDR; segmentation flows are keyed by device MAC so DHCP changes follow.", "RISK_SCORING.md"),
    "RISK-04": ("Risk scoring", "Cleared segmentation flows stay cleared under both their IP and MAC form.", "CORRELATION.md (Clearing segmentation)"),
    "ISS-01": ("Fix list", "The fix list flags plaintext services, legacy TLS and other weaknesses found in a snapshot.", "USER_GUIDE.md (Fix list)"),
    "ISS-02": ("Fix list", "Issues are tracked across snapshots (first/last seen, occurrences) and only recurring ones are kept.", "RISK_SCORING.md (Recurrence)"),
    "LAT-01": ("Lateral movement", "Admin sessions between zones get a risk level; allow rules downgrade them to allowed-admin.", "CORRELATION.md §1"),
    "LAT-02": ("Lateral movement", "Lateral data from several periods merge into one graph (flows summed per src/dst/port/proto).", "CORRELATION.md §1"),
    "COR-01": ("Correlation", "Concrete artifacts (files, processes, users, domains) are extracted from event text without lookups.", "CORRELATION.md §2"),
    "COR-02": ("Correlation", "Event ids are stable hashes (FNV-1a base36) identical in Python and app.js.", "CORRELATION.md (Event ids)"),
    "COR-03": ("Correlation", "Events sharing hosts/IPs/accounts/time/ATT&CK are linked when the score passes the threshold, capped per event.", "CORRELATION.md §2"),
    "MIT-01": ("ATT&CK", "Findings map to MITRE ATT&CK techniques by rule; every rule references a technique in the catalog.", "README.md"),
    "LLM-01": ("AI", "Model answers are parsed defensively: the first JSON object is used and unknown verdicts/priorities fall back to safe values.", "USER_GUIDE.md §7"),
    "LLM-02": ("AI", "The dashboard runs fully with the local LLM switched off (NETMON_LLM=off).", "SETUP.md §6"),
    "LLM-03": ("AI", "With the decision model on, clef decides every candidate link and, once no link is undecided, labels each event suspicious / benign / expected from the event and all its candidates; the selected reviewer then writes the reason, link notes and artifacts - it never decides a link or a label (its own label is only recorded for comparison).", "CORRELATION.md"),
    "CFG-01": ("Configuration", "Site settings fall back to safe defaults; the browser receives only the public subset.", "SETUP.md §2"),
    "CFG-02": ("Configuration", "The research lookback is an integer number of hours within 1-24; invalid values are rejected.", "CORRELATION.md §5"),
    "CFG-03": ("Configuration", "Collection windows end 'now' or at NETMON_WINDOW_END and produce Elasticsearch range filters.", "SETUP.md (Time ranges)"),
    # ---- dashboard ----
    "DASH-01": ("Dashboard", "The single-page app and its assets are served with a build hash for cache busting.", "USER_GUIDE.md §3"),
    "DASH-02": ("Dashboard", "The JSON API serves snapshots and their derived views (overview, issues, risk, ATT&CK, lateral) from stored data.", "USER_GUIDE.md §6"),
    "DASH-03": ("Dashboard", "Any signed-in user can see their account and change their own password.", "USER_GUIDE.md §2"),
    "DASH-04": ("Dashboard", "/healthz answers without authentication for the container health check.", "SETUP.md §6"),
    "DASH-05": ("Dashboard", "Check-offs made on the dashboard are persisted and reflected in later reads.", "USER_GUIDE.md §5"),
    "DASH-06": ("Dashboard", "Every script and stylesheet referenced by the HTML pages exists in the static directory.", "USER_GUIDE.md §3"),
    # ---- operations ----
    "OPS-01": ("Operations", "Console recovery commands (server.py set-role / add-user / set-password) work without the web UI.", "ACCESS_CONTROL.md"),
    "OPS-02": ("Operations", "The dashboard container runs read-only, non-root, with a passing health check.", "SETUP.md §6"),
    "OPS-03": ("Operations", "The scheduler runs the watcher every 15 minutes, the research job on its grid and the weekly rebuild on Sunday.", "SETUP.md §7"),
    "OPS-06": ("Operations", "The review job (review.py) never researches events: its reviewer (the correlation reviewer's model) only copies matching earlier notes or leaves events queued; event research (research.py) runs only for a person's Send to research click and is never scheduled.", "review.py / research.py / scheduler.py"),
    "OPS-04": ("Operations", "store.py CLI (check / stats) verifies and reports on the database.", "store.py"),
    "OPS-05": ("Operations", "The dashboard's parsed-document cache is bounded (LRU), so walking every snapshot cannot exhaust the container's memory.", "server.py"),
}
