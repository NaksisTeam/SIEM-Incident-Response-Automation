"""
test_playbooks.py
------------------
Unit tests for simulated playbook execution.
Run with: pytest tests/
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from playbooks import execute_playbook


def make_test_incident():
    return {
        "alert_id": "TEST-0001",
        "severity_label": "HIGH",
        "classification": "Test Classification",
        "source_ip": "1.2.3.4",
        "host": "TEST-HOST",
        "username": "test.user",
        "actions_taken": [],
    }


def test_block_ip_and_notify_playbook():
    incident = make_test_incident()
    actions = execute_playbook("block_ip_and_notify", incident)

    assert len(actions) == 2
    assert actions[0]["action"] == "block_ip"
    assert actions[0]["target"] == "1.2.3.4"
    assert actions[1]["action"] == "notify_team"
    assert len(incident["actions_taken"]) == 2


def test_isolate_host_and_notify_playbook():
    incident = make_test_incident()
    actions = execute_playbook("isolate_host_and_notify", incident)

    assert actions[0]["action"] == "isolate_host"
    assert actions[0]["target"] == "TEST-HOST"


def test_disable_account_and_notify_playbook():
    incident = make_test_incident()
    actions = execute_playbook("disable_account_and_notify", incident)

    assert actions[0]["action"] == "disable_account"
    assert actions[0]["target"] == "test.user"


def test_log_only_playbook():
    incident = make_test_incident()
    actions = execute_playbook("log_only", incident)

    assert len(actions) == 1
    assert actions[0]["action"] == "log_only"


def test_unknown_playbook_defaults_to_log_only():
    incident = make_test_incident()
    actions = execute_playbook("nonexistent_playbook_name", incident)

    assert len(actions) == 1
    assert actions[0]["action"] == "log_only"


def test_all_actions_have_simulated_success_status():
    incident = make_test_incident()
    actions = execute_playbook("block_ip_and_isolate_host", incident)

    for action in actions:
        assert action["status"] == "simulated_success"
