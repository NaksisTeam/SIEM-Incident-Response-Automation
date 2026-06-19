"""
notifier.py
-----------
Simulated notification dispatcher for email and Slack channels.
In production this would integrate with smtplib / a real Slack webhook
(requests.post to SLACK_WEBHOOK_URL). For this portfolio project, calls
are simulated and printed/logged so the project can run anywhere
without needing live credentials.
"""

import os
from datetime import datetime, timezone


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def send_email_notification(incident: dict, recipients: list) -> dict:
    subject = f"[{incident['severity_label']}] Incident {incident['alert_id']} - {incident['classification']}"
    body = (
        f"A new security incident has been detected and processed by the "
        f"automated response pipeline.\n\n"
        f"Alert ID: {incident['alert_id']}\n"
        f"Severity: {incident['severity']} ({incident['severity_label']})\n"
        f"Classification: {incident['classification']}\n"
        f"Host: {incident.get('host', 'N/A')}\n"
        f"Source IP: {incident.get('source_ip', 'N/A')}\n"
        f"Username: {incident.get('username', 'N/A')}\n"
        f"Playbook executed: {incident['playbook']}\n"
    )

    print(f"\n--- [SIMULATED EMAIL] ---")
    print(f"To: {', '.join(recipients)}")
    print(f"Subject: {subject}")
    print(body)
    print("--- [END EMAIL] ---\n")

    return {
        "channel": "email",
        "recipients": recipients,
        "subject": subject,
        "sent_at": _timestamp(),
        "status": "simulated_sent",
    }


def send_slack_notification(incident: dict) -> dict:
    webhook_url = os.environ.get("SLACK_WEBHOOK_URL", "<not configured>")
    message = (
        f":rotating_light: *New Incident* `{incident['alert_id']}`\n"
        f"*Severity:* {incident['severity_label']} ({incident['severity']}/10)\n"
        f"*Classification:* {incident['classification']}\n"
        f"*Host:* {incident.get('host', 'N/A')} | *Source IP:* {incident.get('source_ip', 'N/A')}\n"
        f"*Playbook:* {incident['playbook']}"
    )

    print(f"\n--- [SIMULATED SLACK MESSAGE] ---")
    print(f"Webhook: {webhook_url}")
    print(message)
    print("--- [END SLACK MESSAGE] ---\n")

    return {
        "channel": "slack",
        "webhook": webhook_url,
        "message": message,
        "sent_at": _timestamp(),
        "status": "simulated_sent",
    }


def dispatch_notifications(incident: dict, notification_config: dict) -> list:
    """
    Reads the notification config block from rules.yaml and fires
    the appropriate simulated notifications.
    """
    results = []
    channels = notification_config.get("channels", [])

    for channel in channels:
        if not channel.get("enabled"):
            continue
        if channel["type"] == "email":
            results.append(
                send_email_notification(incident, channel.get("recipients", []))
            )
        elif channel["type"] == "slack":
            results.append(send_slack_notification(incident))

    return results
