"""
rule_engine.py
---------------
Loads detection/response rules from config/rules.yaml and evaluates
incoming SIEM alerts against those rules to determine:
    - severity score
    - MITRE-mapped classification
    - which automated playbook should be triggered

This is the "brain" of the SOAR-lite automation pipeline.
"""

import yaml
from pathlib import Path
from typing import Optional


class Rule:
    def __init__(self, rule_dict: dict):
        self.id = rule_dict.get("id")
        self.name = rule_dict.get("name")
        self.match = rule_dict.get("match", {})
        self.severity = rule_dict.get("severity", 1)
        self.classification = rule_dict.get("classification", "Unclassified")
        self.playbook = rule_dict.get("playbook", "log_only")

    def matches(self, alert: dict) -> bool:
        """
        Checks whether a given alert satisfies this rule's match conditions.
        Supports simple field equality plus a few special threshold keys
        used by specific rules (failure counts, byte thresholds, etc.)
        """
        expected_event_type = self.match.get("event_type")
        if expected_event_type and alert.get("event_type") != expected_event_type:
            return False

        # Rule-specific threshold checks
        if "threshold_count" in self.match:
            if alert.get("failure_count", 0) < self.match["threshold_count"]:
                return False

        if "preceding_failures_min" in self.match:
            if alert.get("preceding_failures", 0) < self.match["preceding_failures_min"]:
                return False

        if "bytes_threshold" in self.match:
            if alert.get("bytes_transferred", 0) < self.match["bytes_threshold"]:
                return False

        if "unique_ports_threshold" in self.match:
            if alert.get("unique_ports_scanned", 0) < self.match["unique_ports_threshold"]:
                return False

        if "process_name" in self.match:
            if alert.get("process_name") != self.match["process_name"]:
                return False

        if "flags" in self.match:
            alert_flags = set(alert.get("flags", []))
            required_flags = set(self.match["flags"])
            if not required_flags.issubset(alert_flags):
                return False

        return True


class RuleEngine:
    def __init__(self, rules_path: str = "config/rules.yaml"):
        self.rules_path = Path(rules_path)
        self.rules: list[Rule] = []
        self.severity_bands: dict = {}
        self.notification_config: dict = {}
        self._load_rules()

    def _load_rules(self):
        with open(self.rules_path, "r") as f:
            config = yaml.safe_load(f)

        self.rules = [Rule(r) for r in config.get("rules", [])]
        self.severity_bands = config.get("severity_bands", {})
        self.notification_config = config.get("notification", {})

    def evaluate(self, alert: dict) -> Optional[Rule]:
        """
        Returns the first matching rule for a given alert.
        Rules are evaluated in the order defined in rules.yaml,
        so more specific rules should be listed before generic ones.
        """
        for rule in self.rules:
            if rule.matches(alert):
                return rule
        return None

    def severity_label(self, severity: int) -> str:
        for label, band in self.severity_bands.items():
            if band["min"] <= severity <= band["max"]:
                return label.upper()
        return "UNKNOWN"
