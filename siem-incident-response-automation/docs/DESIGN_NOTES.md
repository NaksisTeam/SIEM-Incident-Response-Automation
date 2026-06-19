# Design Notes & Extension Guide

This document explains the key design decisions behind this project and
how each simulated piece would be swapped for a real integration in a
production SOC environment. Useful as talking points in an interview.

---

## 1. Why rules live in YAML, not Python

`config/rules.yaml` is the single source of truth for detection logic.
This mirrors how real SIEM/SOAR platforms (Splunk SOAR, Microsoft
Sentinel Playbooks, Palo Alto XSOAR) separate "detection content" from
"engine code" — security analysts who aren't software engineers can
update thresholds or add new rules without a code deployment.

**Trade-off:** the matching logic in `rule_engine.py` (`Rule.matches`)
has to explicitly support whatever match conditions appear in YAML
(`threshold_count`, `bytes_threshold`, etc.). A more advanced version
could use a generic expression evaluator (e.g. a safe subset of Python,
or a library like `simpleeval`) so YAML could express arbitrary
conditions without engine code changes for every new field.

---

## 2. Why actions are simulated

Every action in `playbooks.py` (block_ip, isolate_host, disable_account)
just constructs a dictionary describing what *would* happen and appends
it to the incident's audit trail. This was a deliberate choice:

- The project runs anywhere, with no cloud credentials, firewall access,
  or AD environment required.
- It's safe to demo without risk of someone running it against a real
  network.
- The actual decision-making logic (which action, in what order, with
  what audit record) is identical to what a production version would do.

### How to make it real

| Simulated function | Real-world replacement |
|---|---|
| `block_ip()` | Call a firewall/cloud security group API — e.g. AWS Security Group `revoke_ingress`/`authorize_ingress`, Palo Alto PAN-OS XML API, or a Cloudflare WAF rule via their REST API |
| `isolate_host()` | Call an EDR API — e.g. CrowdStrike Falcon's `/devices/entities/devices-actions/v2` (contain host), Microsoft Defender for Endpoint's `isolate machine` API |
| `disable_account()` | Call Active Directory via `pyad`/LDAP, or Azure AD Graph API `PATCH /users/{id}` with `accountEnabled: false` |
| `notify_team()` | Real `smtplib`/SES for email, real `requests.post` to a Slack incoming webhook URL (the env var plumbing for this is already in `notifier.py`) |

In each case, the function signature and the audit-trail append stay the
same — only the body changes from "print + simulate" to "call API,
handle errors/retries, record the real API response."

---

## 3. Why a Markdown + CSV report instead of a dashboard

A Markdown report-per-incident is the simplest artifact to attach to a
ticket (Jira, ServiceNow) or paste into a SOC handoff doc. The CSV
summary is for trend analysis (e.g. pulling into Excel/Power BI to chart
incident volume by classification over a month).

**Extension path:** swap `report_generator.py`'s file-writing for:
- A POST to a ticketing system's API (create a Jira issue per incident)
- A write to a database table for a proper incident-history dashboard
- A push to a SIEM's case-management module if one exists (e.g. Splunk
  Enterprise Security notable events, Sentinel incidents)

---

## 4. Why alerts are read from a static JSON file

This keeps the project fully runnable offline with zero external
dependencies. In production, `main.py`'s `load_alerts()` would be
replaced with one of:

- A polling loop against a SIEM's REST API (Splunk's `/services/search/jobs`,
  Sentinel's Log Analytics query API, Elastic's `_search`)
- A webhook receiver (e.g. a small Flask/FastAPI endpoint that the SIEM
  pushes alerts to in real time)
- A message queue consumer (Kafka/SQS) if alerts are streamed through an
  event bus

The rest of the pipeline (rule matching → playbook → notify → report)
would not need to change at all — this is the benefit of having ingestion
as a clean, swappable boundary.

---

## 5. Things intentionally left out (and why)

- **No real credentials/secrets handling** — a production version would
  need a secrets manager (AWS Secrets Manager, HashiCorp Vault) for API
  keys; intentionally out of scope for a safe, runnable demo.
- **No deduplication/correlation across alerts** — e.g. recognizing that
  ALERT-1003 (malware) and ALERT-1004 (exfiltration) from the same host
  are part of one larger incident. A production SOAR would have an
  incident correlation layer grouping related alerts before triggering
  playbooks.
- **No retry/backoff logic** — real API calls to firewalls/EDR tools can
  fail transiently; production code would need retry logic and dead-letter
  handling for failed automated actions.

---

## 6. Suggested next steps if extending this project further

1. Add a `correlation.py` module that groups alerts by host/user within
   a time window before playbook execution.
2. Add a simple Flask/FastAPI wrapper so alerts can be POSTed in via
   HTTP instead of only reading a static file.
3. Add GitHub Actions CI to run `pytest` on every push.
4. Add a basic web dashboard (even a static HTML page reading the CSV)
   to visualize incident volume by severity/classification over time.
