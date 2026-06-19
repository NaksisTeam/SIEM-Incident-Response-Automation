# SIEM Incident Response Automation (SOAR-lite)

A lightweight, rule-driven Security Orchestration, Automation & Response
(SOAR) pipeline that ingests SIEM alerts, classifies them by severity and
MITRE ATT&CK technique, triggers automated response playbooks, sends
notifications, and generates audit-ready incident reports — all from a
clean, config-driven Python codebase.

This project simulates the core workflow a SOC (Security Operations
Center) automation engineer would build to reduce Mean Time to Respond
(MTTR) for common attack patterns.

---

## Why this project

Manually triaging every SIEM alert doesn't scale. This pipeline
demonstrates how repetitive, well-understood incident types (brute force
logins, malware detections, data exfiltration, privilege escalation,
etc.) can be automatically detected, classified, and responded to —
freeing analysts to focus on novel or ambiguous threats.

---

## Architecture

```
                 ┌────────────────────┐
                 │   SIEM Alerts      │
                 │  (JSON / sample)   │
                 └─────────┬──────────┘
                           │
                           ▼
                 ┌────────────────────┐
                 │    Rule Engine     │  <-- config/rules.yaml
                 │ (severity + MITRE  │
                 │  classification)   │
                 └─────────┬──────────┘
                           │ matched rule
                           ▼
                 ┌────────────────────┐
                 │   Playbook Runner  │  --> block_ip / isolate_host /
                 │   (simulated SOAR  │      disable_account / log_only
                 │      actions)      │
                 └─────────┬──────────┘
                           │
                 ┌─────────┴──────────┐
                 ▼                    ▼
        ┌────────────────┐   ┌──────────────────┐
        │   Notifier     │   │  Report Generator │
        │ (Email/Slack   │   │ (Markdown + CSV   │
        │   simulated)   │   │     reports)       │
        └────────────────┘   └──────────────────┘
```

**Pipeline flow:**
1. **Ingest** — alerts are read from `sample_logs/siem_alerts.json` (this
   would be a live SIEM API/webhook feed in production — Splunk, Sentinel,
   QRadar, Elastic, etc.)
2. **Detect & Classify** — `rule_engine.py` matches each alert against
   `config/rules.yaml`, assigning a severity score (1-10) and a
   MITRE ATT&CK-mapped classification.
3. **Respond** — `playbooks.py` executes the response actions tied to the
   matched rule (block IP, isolate host, disable account, notify, or log).
4. **Notify** — `notifier.py` dispatches simulated email + Slack alerts to
   the SOC team, with severity-based escalation logic.
5. **Report** — `report_generator.py` writes a per-incident Markdown
   report and a batch-level CSV summary into `reports/`.

---

## Project Structure

```
siem-incident-response-automation/
├── src/
│   ├── main.py              # Pipeline orchestrator / entry point
│   ├── rule_engine.py        # Loads rules.yaml, matches alerts to rules
│   ├── playbooks.py          # Simulated automated response actions
│   ├── notifier.py           # Simulated email/Slack notifications
│   └── report_generator.py   # Markdown + CSV incident reporting
├── config/
│   └── rules.yaml            # Detection rules, severity bands, notification config
├── sample_logs/
│   └── siem_alerts.json      # 10 realistic simulated SIEM alerts
├── reports/                  # Auto-generated incident reports (output)
├── tests/
│   ├── test_rule_engine.py
│   └── test_playbooks.py
├── docs/
│   └── DESIGN_NOTES.md       # Design decisions & how to extend this project
├── requirements.txt
└── README.md
```

---

## Detection Rules Included

| Rule | Detects | Severity | MITRE Mapping | Playbook |
|---|---|---|---|---|
| RULE-001 | Brute force login attempts | 7 (High) | T1110 - Brute Force | Block IP + Notify |
| RULE-002 | Login success after multiple failures | 8 (High) | Possible Compromised Credentials | Isolate User + Notify |
| RULE-003 | Malware signature detected | 9 (Critical) | T1204 - User Execution | Isolate Host + Notify |
| RULE-004 | Unusual large outbound transfer | 9 (Critical) | T1041 - Exfiltration | Block IP + Isolate Host |
| RULE-005 | Privilege escalation | 8 (High) | T1068 - Privilege Escalation | Disable Account + Notify |
| RULE-006 | Port scanning | 4 (Medium) | T1046 - Network Service Scanning | Log + Notify |
| RULE-007 | Known malicious IP (threat intel match) | 9 (Critical) | T1071 - Command & Control | Block IP + Notify |
| RULE-008 | Suspicious encoded PowerShell | 8 (High) | T1059.001 - PowerShell | Isolate Host + Notify |
| RULE-009 | Security control disabled (EDR tampering) | 9 (Critical) | T1562 - Impair Defenses | Isolate Host + Notify |
| RULE-010 | Generic low-severity anomaly | 2 (Low) | Informational | Log Only |

All rules are defined declaratively in `config/rules.yaml` — adding a new
detection doesn't require touching any Python code.

---

## How to Run

### 1. Install dependencies
```bash
pip install -r requirements.txt
```

### 2. Run the pipeline against the sample alerts
```bash
python src/main.py
```

This will:
- Process all 10 sample alerts in `sample_logs/siem_alerts.json`
- Print simulated email/Slack notifications to the console
- Write a Markdown report per incident into `reports/`
- Write a CSV summary of the whole batch into `reports/`

### 3. Run with your own alert file
```bash
python src/main.py path/to/your_alerts.json config/rules.yaml
```

### 4. Run the test suite
```bash
pytest tests/ -v
```

---

## Sample Output

```
[MATCH] ALERT-1003 -> Rule RULE-003 (Malware Signature Detected) | Severity: 9 (CRITICAL)

--- [SIMULATED EMAIL] ---
To: soc-team@example.com
Subject: [CRITICAL] Incident ALERT-1003 - Execution (MITRE T1204 - User Execution)
...
--- [END EMAIL] ---

         Report generated: reports/incident_ALERT-1003.md
```

Each generated report looks like this:

```markdown
# Incident Report: ALERT-1003

| Field | Value |
|---|---|
| Severity | 9/10 (CRITICAL) |
| Classification | Execution (MITRE T1204 - User Execution) |
| Playbook Executed | isolate_host_and_notify |
...

## Automated Actions Taken
- isolate_host on `WS-HR-009` — EDR command issued to isolate host
- notify_team on `SOC Team` — Notification sent to SOC team
```

---

## Design Notes (Why It's Built This Way)

- **Config-driven detection** — rules live in YAML, not hardcoded in
  Python, so a SOC team could update detection logic without a code
  deploy.
- **Simulated actions, real logic** — playbook actions (block IP, isolate
  host, etc.) are simulated rather than wired to live infrastructure,
  so the project is safe to run anywhere while still demonstrating the
  exact decision-making and audit-trail logic a real SOAR tool needs.
  Swapping a simulated function for a real firewall/EDR API call is a
  small, isolated change (see `docs/DESIGN_NOTES.md`).
- **MITRE ATT&CK mapping** — every rule is tagged with a relevant
  technique ID, which is how real SOC teams communicate and report on
  threats.
- **Auditability** — every incident produces a timestamped action trail
  and a standalone Markdown report, mirroring what would be attached to
  a real ticket (ServiceNow, Jira, etc.).

See `docs/DESIGN_NOTES.md` for how to extend this into a production-grade
system (real SIEM API integration, real firewall/EDR calls, a ticketing
system connector, and a proper test/CI setup).

---

## Tech Stack

- **Python 3.10+**
- **PyYAML** — rule configuration
- **pytest** — unit testing
- Standard library only beyond that (`json`, `csv`, `datetime`, `pathlib`)

---

## Disclaimer

This is a **portfolio / educational project**. All response actions
(blocking IPs, isolating hosts, disabling accounts) are **simulated** —
no real network, firewall, EDR, or Active Directory calls are made. The
sample alert data is synthetic and does not represent any real
organization, person, or incident.
