"""
test_rule_engine.py
--------------------
Basic unit tests for RuleEngine matching logic.
Run with: pytest tests/
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from rule_engine import RuleEngine


RULES_PATH = Path(__file__).resolve().parent.parent / "config" / "rules.yaml"


def get_engine():
    return RuleEngine(str(RULES_PATH))


def test_rules_load_successfully():
    engine = get_engine()
    assert len(engine.rules) == 10


def test_brute_force_rule_matches():
    engine = get_engine()
    alert = {
        "event_type": "authentication_failure",
        "failure_count": 7,
    }
    rule = engine.evaluate(alert)
    assert rule is not None
    assert rule.id == "RULE-001"


def test_brute_force_rule_does_not_match_below_threshold():
    engine = get_engine()
    alert = {
        "event_type": "authentication_failure",
        "failure_count": 2,
    }
    rule = engine.evaluate(alert)
    assert rule is None


def test_malware_rule_matches():
    engine = get_engine()
    alert = {"event_type": "malware_detected"}
    rule = engine.evaluate(alert)
    assert rule is not None
    assert rule.id == "RULE-003"
    assert rule.severity == 9


def test_powershell_rule_requires_all_flags():
    engine = get_engine()
    alert = {
        "event_type": "suspicious_process",
        "process_name": "powershell.exe",
        "flags": ["encoded_command"],  # missing "download_string"
    }
    rule = engine.evaluate(alert)
    assert rule is None

    alert["flags"] = ["encoded_command", "download_string"]
    rule = engine.evaluate(alert)
    assert rule is not None
    assert rule.id == "RULE-008"


def test_severity_label_mapping():
    engine = get_engine()
    assert engine.severity_label(9) == "CRITICAL"
    assert engine.severity_label(7) == "HIGH"
    assert engine.severity_label(5) == "MEDIUM"
    assert engine.severity_label(1) == "LOW"


def test_unmatched_alert_returns_none():
    engine = get_engine()
    alert = {"event_type": "totally_unknown_event_type"}
    rule = engine.evaluate(alert)
    assert rule is None
