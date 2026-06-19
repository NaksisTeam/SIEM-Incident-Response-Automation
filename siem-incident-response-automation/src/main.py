"""
main.py
-------
Entry point for the SIEM Incident Response Automation pipeline.

Pipeline flow:
    1. Load SIEM alerts (JSON) from sample_logs/
    2. Evaluate each alert against rules.yaml via the RuleEngine
    3. Build an "incident" record with severity + classification
    4. Execute the matched automated response playbook
    5. Dispatch simulated notifications (email/Slack)
    6. Generate a Markdown incident report per alert
    7. Generate a CSV summary across the full batch

Run with:
    python src/main.py
"""

import json
import sys
from pathlib import Path

from rule_engine import RuleEngine
from playbooks import execute_playbook
from notifier import dispatch_notifications
from report_generator import generate_markdown_report, generate_summary_csv


def load_alerts(path: str) -> list:
    with open(path, "r") as f:
        return json.load(f)


def build_incident(alert: dict, rule, severity_label: str) -> dict:
    incident = dict(alert)  # copy all original alert fields
    incident["severity"] = rule.severity
    incident["severity_label"] = severity_label
    incident["classification"] = rule.classification
    incident["rule_id"] = rule.id
    incident["rule_name"] = rule.name
    incident["playbook"] = rule.playbook
    incident["actions_taken"] = []
    return incident


def process_alerts(alerts_path: str, rules_path: str):
    engine = RuleEngine(rules_path)
    alerts = load_alerts(alerts_path)

    print(f"Loaded {len(alerts)} alerts from {alerts_path}")
    print(f"Loaded {len(engine.rules)} detection rules from {rules_path}\n")
    print("=" * 70)

    incidents = []

    for alert in alerts:
        rule = engine.evaluate(alert)

        if rule is None:
            print(f"[SKIP] No matching rule for alert {alert.get('alert_id')}")
            continue

        severity_label = engine.severity_label(rule.severity)
        incident = build_incident(alert, rule, severity_label)

        print(f"[MATCH] {incident['alert_id']} -> Rule {rule.id} "
              f"({rule.name}) | Severity: {rule.severity} ({severity_label})")

        # Execute automated response
        execute_playbook(rule.playbook, incident)

        # Send notifications
        dispatch_notifications(incident, engine.notification_config)

        # Generate per-incident report
        report_path = generate_markdown_report(incident)
        print(f"         Report generated: {report_path}")

        incidents.append(incident)
        print("-" * 70)

    if incidents:
        summary_path = generate_summary_csv(incidents)
        print(f"\nBatch complete. Summary CSV: {summary_path}")
        print(f"Total incidents processed: {len(incidents)}")
    else:
        print("\nNo incidents matched any rules.")

    return incidents


if __name__ == "__main__":
    base_dir = Path(__file__).resolve().parent.parent
    alerts_file = base_dir / "sample_logs" / "siem_alerts.json"
    rules_file = base_dir / "config" / "rules.yaml"

    # Allow overriding paths via CLI args for flexibility
    if len(sys.argv) >= 3:
        alerts_file = Path(sys.argv[1])
        rules_file = Path(sys.argv[2])

    process_alerts(str(alerts_file), str(rules_file))
