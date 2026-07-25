"""
models/rule.py

Defines the ComplianceRule class and the RuleType enum used to describe
a single compliance requirement (e.g. "SSH Version 2 must be enabled").
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class RuleType(str, Enum):
    """Supported rule evaluation strategies.

    Stored as a str Enum so values serialize cleanly to/from JSON and so
    comparisons against plain strings (e.g. "contains") still work.
    """

    CONTAINS = "contains"
    NOT_CONTAINS = "not_contains"
    STARTS_WITH = "starts_with"
    ENDS_WITH = "ends_with"
    REGEX = "regex"
    EQUALS = "equals"

    @classmethod
    def values(cls) -> list:
        return [member.value for member in cls]


class InvalidRuleError(ValueError):
    """Raised when a rule dict is malformed or references an unsupported type."""


@dataclass
class ComplianceRule:
    """A single compliance requirement.

    Attributes:
        name: Human readable rule name, e.g. "SSH Enabled".
        rule_type: One of RuleType (contains, not_contains, starts_with,
            ends_with, regex, equals).
        value: The expected value / pattern used during evaluation.
        description: Optional longer explanation of the rule's intent.
        severity: One of LOW / MEDIUM / HIGH / CRITICAL (free text, but we
            validate against a known set for consistency).
    """

    name: str
    rule_type: RuleType
    value: str
    description: str = ""
    severity: str = "MEDIUM"

    VALID_SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")

    def __post_init__(self):
        if not self.name or not isinstance(self.name, str):
            raise InvalidRuleError("Rule 'name' must be a non-empty string.")

        if not self.value or not isinstance(self.value, str):
            raise InvalidRuleError(
                f"Rule '{self.name}': 'value' must be a non-empty string."
            )

        # Normalize/validate rule_type (accept RuleType or raw string).
        if isinstance(self.rule_type, RuleType):
            pass
        elif isinstance(self.rule_type, str):
            normalized = self.rule_type.strip().lower()
            if normalized not in RuleType.values():
                raise InvalidRuleError(
                    f"Rule '{self.name}': unsupported rule type "
                    f"'{self.rule_type}'. Supported types: {RuleType.values()}"
                )
            self.rule_type = RuleType(normalized)
        else:
            raise InvalidRuleError(
                f"Rule '{self.name}': 'rule_type' must be a string or RuleType."
            )

        # Normalize/validate severity.
        if not isinstance(self.severity, str) or self.severity.upper() not in self.VALID_SEVERITIES:
            raise InvalidRuleError(
                f"Rule '{self.name}': severity must be one of {self.VALID_SEVERITIES}."
            )
        self.severity = self.severity.upper()

    @classmethod
    def from_dict(cls, data: dict) -> "ComplianceRule":
        """Build a ComplianceRule from a raw dict (as loaded from JSON).

        Accepts either the legacy key 'type' or 'rule_type', and either
        'value' or 'expected_value' for flexibility with hand-written JSON.
        """
        if not isinstance(data, dict):
            raise InvalidRuleError("Rule definition must be a JSON object.")

        try:
            name = data["name"]
        except KeyError:
            raise InvalidRuleError("Rule definition is missing required field 'name'.")

        rule_type = data.get("rule_type", data.get("type"))
        if rule_type is None:
            raise InvalidRuleError(f"Rule '{name}' is missing required field 'type'.")

        value = data.get("value", data.get("expected_value"))
        if value is None:
            raise InvalidRuleError(f"Rule '{name}' is missing required field 'value'.")

        return cls(
            name=name,
            rule_type=rule_type,
            value=value,
            description=data.get("description", ""),
            severity=data.get("severity", "MEDIUM"),
        )

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "type": self.rule_type.value,
            "value": self.value,
            "severity": self.severity,
        }
