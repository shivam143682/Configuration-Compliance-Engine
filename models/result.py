"""
models/result.py

Defines the ComplianceResult class, representing the outcome of evaluating
a single ComplianceRule against a device configuration.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class RuleStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    ERROR = "ERROR"  # rule could not be evaluated (e.g. bad regex)


@dataclass
class ComplianceResult:
    rule_name: str
    status: RuleStatus
    severity: str
    evidence: str = ""

    def to_dict(self) -> dict:
        return {
            "rule": self.rule_name,
            "status": self.status.value if isinstance(self.status, RuleStatus) else self.status,
            "severity": self.severity,
            "evidence": self.evidence,
        }
