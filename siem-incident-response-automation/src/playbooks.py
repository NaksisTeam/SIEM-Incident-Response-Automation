"""
playbooks.py
------------
Simulated SOAR response actions. In a real production environment these
functions would call out to a firewall API, EDR API, Active Directory,
or a ticketing system. Here they are SAFE, SIMULATED actions that:

    1. Print/log what action *would* be taken
    2. Record the action into the incident's audit trail

This keeps the project runnable/demonstrable without needing real
infrastructure credentials, while still showing the automation logic
a recruiter or SOC team would expect to see.
"""

from datetime import datetime, timezone


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def block_ip(ip: str, incident: dict) -> dict:
    action = {
        "action": "block_ip",
        "target": ip,
        "status": "simulated_success",
        "detail": f"Firewall rule created to block traffic from {ip}",
        "timestamp": _timestamp(),
    }
    incident["actions_taken"].append(action)
    return action


def isolate_host(host: str, incident: dict) -> dict:
    action = {
        "action": "isolate_host",
        "target": host,
        "status": "simulated_success",
        "detail": f"EDR command issued to isolate host {host} from network",
        "timestamp": _timestamp(),
    }
    incident["actions_taken"].append(action)
    return action


def disable_account(username: str, incident: dict) -> dict:
    action = {
        "action": "disable_account",
        "target": username,
        "status": "simulated_success",
        "detail": f"Active Directory account '{username}' disabled pending investigation",
        "timestamp": _timestamp(),
    }
    incident["actions_taken"].append(action)
    return action


def notify_team(incident: dict) -> dict:
    action = {
        "action": "notify_team",
        "target": "SOC Team (email + Slack)",
        "status": "simulated_success",
        "detail": (
            f"Notification sent for incident {incident['alert_id']} "
            f"[Severity: {incident['severity_label']}] - {incident['classification']}"
        ),
        "timestamp": _timestamp(),
    }
    incident["actions_taken"].append(action)
    return action


def log_event(incident: dict) -> dict:
    action = {
        "action": "log_only",
        "target": incident.get("host") or incident.get("source_ip") or "N/A",
        "status": "simulated_success",
        "detail": "Event recorded for trend analysis. No active response required.",
        "timestamp": _timestamp(),
    }
    incident["actions_taken"].append(action)
    return action


# Maps playbook names (from rules.yaml) to the sequence of actions to run.
PLAYBOOK_MAP = {
    "block_ip_and_notify": lambda incident: [
        block_ip(incident.get("source_ip", "unknown"), incident),
        notify_team(incident),
    ],
    "isolate_user_and_notify": lambda incident: [
        disable_account(incident.get("username", "unknown"), incident),
        notify_team(incident),
    ],
    "isolate_host_and_notify": lambda incident: [
        isolate_host(incident.get("host", "unknown"), incident),
        notify_team(incident),
    ],
    "block_ip_and_isolate_host": lambda incident: [
        block_ip(incident.get("source_ip", "unknown"), incident),
        isolate_host(incident.get("host", "unknown"), incident),
        notify_team(incident),
    ],
    "disable_account_and_notify": lambda incident: [
        disable_account(incident.get("username", "unknown"), incident),
        notify_team(incident),
    ],
    "log_and_notify": lambda incident: [
        log_event(incident),
        notify_team(incident),
    ],
    "log_only": lambda incident: [
        log_event(incident),
    ],
}


def execute_playbook(playbook_name: str, incident: dict) -> list:
    """
    Looks up and executes the playbook function chain for a given
    playbook name. Returns the list of actions taken.
    """
    handler = PLAYBOOK_MAP.get(playbook_name, PLAYBOOK_MAP["log_only"])
    return handler(incident)
