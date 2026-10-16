
# netmon
Built specific to me and by an AI.  Queries Elasticsearch and Unifi to collect security events.  Presents and explains risk of events and vulnerabilities.  Allows users (my wife and kids) to subscribe to devices and get notifications of security related events near real time (Job runs every 15 minutes)

<img width="670" height="401" alt="Screenshot 2026-10-16 at 7 56 20 AM" src="https://github.com/user-attachments/assets/035c674b-a802-4661-ba82-b204dc17b32a" />
<img width="301" height="450" alt="Screenshot 2026-10-16 at 7 39 35 AM" src="https://github.com/user-attachments/assets/af2e18f7-9b59-49d4-b71f-04f2163bf500" />
<img width="301" height="650" alt="Screenshot 2026-10-16 at 7 41 18 AM" src="https://github.com/user-attachments/assets/3eebb19c-dc13-44ae-8f36-263dfde570cb" />
<img width="301" height="650" alt="Screenshot 2026-10-16 at 7 44 08 AM" src="https://github.com/user-attachments/assets/ac66bee9-0b9c-46c3-8aa0-e47c45f9fe51" />
<img width="301" height="650" alt="Screenshot 2026-10-16 at 8 57 59 AM" src="https://github.com/user-attachments/assets/8f7f32c1-cb61-4c58-a16b-8b31c18bb8d5" />

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
