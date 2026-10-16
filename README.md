# netmon
Built specific to me and by an AI.  Queries Elasticsearch and Unifi to collect security events.  Presents and explains risk of events and vulnerabilities.  Allows users (my wife and kids) to subscribe to devices and get notifications of security related events near real time (Job runs every 15 minutes)

<img width="603" height="972" alt="Screenshot 2026-10-16 at 7 39 35 AM" src="https://github.com/user-attachments/assets/524626a7-9ad7-4e0a-9b6f-c30659399f7d" />

<img width="603" height="1311" alt="Screenshot 2026-10-16 at 7 41 18 AM" src="https://github.com/user-attachments/assets/78d189b9-b3d7-4795-884f-b1c1b774db37" />

<img width="603" height="1311" alt="Screenshot 2026-10-16 at 7 44 08 AM" src="https://github.com/user-attachments/assets/83f62b6e-f884-4912-a288-bf21edc3b543" />

<img width="1341" height="802" alt="Screenshot 2026-10-16 at 7 56 20 AM" src="https://github.com/user-attachments/assets/0c845447-9b5d-4e26-aa4e-8841fe28acd4" />

Home-network security monitoring for the home network, run by the Hermes agent ("Lady Brains").

- `collect.py` / `analyze.py` / `report.py`: nightly pipeline. Security Onion Elasticsearch, UniFi and Elastic Agent data go into a snapshot, which is compared against a per-device baseline and rendered as a PDF report.
- `watch.py`: 15-minute urgent watcher. It records dashboard alerts and push notifications (nothing is posted to Discord). Nightly PDFs are downloadable from the dashboard's Reports page.
- `hosts.py`, `osq.py`, `hostdetail.py`: host and endpoint telemetry (Elastic Defend, osquery).
- `mitre.py`: maps findings to MITRE ATT&CK.
- `store.py`: SQLite state store (WAL).
- `dashboard/`: HTTPS dashboard container (stdlib server, plain JS front end, Web Push).
- `sec_scan.sh`: security scan suite (Semgrep, Ruff/Bandit, pip-audit, ESLint no-unsanitized, Trivy, Hadolint, Gitleaks, ZAP).
- `ship.sh`: scan, commit and push (required for every code change).
- `weekly_rebuild.sh`: weekly container rebuild with updated libraries, a versioned image, a security scan, and in-app vulnerability alerts.

Runtime data, state, certificates and credentials are deliberately not in this repository (see `.gitignore`).
