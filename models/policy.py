"""
models/policy.py

Defines the CompliancePolicy class, which groups multiple ComplianceRule
objects together (e.g. "Enterprise Router Policy" containing SSH, NTP,
Logging, AAA, SNMP rules).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

from models.rule import ComplianceRule, InvalidRuleError


class InvalidPolicyError(ValueError):
    """Raised when a policy is malformed or contains no rules."""


@dataclass
class CompliancePolicy:
    name: str
    rules: List[ComplianceRule] = field(default_factory=list)
    description: str = ""

    def __post_init__(self):
        if not self.name or not isinstance(self.name, str):
            raise InvalidPolicyError("Policy 'name' must be a non-empty string.")

        if not self.rules:
            raise InvalidPolicyError(
                f"Policy '{self.name}' has no rules. A policy must contain at least one rule."
            )

        for rule in self.rules:
            if not isinstance(rule, ComplianceRule):
                raise InvalidPolicyError(
                    f"Policy '{self.name}' contains an object that is not a ComplianceRule."
                )

    @classmethod
    def from_dict(cls, data: dict) -> "CompliancePolicy":
        if not isinstance(data, dict):
            raise InvalidPolicyError("Policy definition must be a JSON object.")

        try:
            name = data["name"]
        except KeyError:
            raise InvalidPolicyError("Policy definition is missing required field 'name'.")

        raw_rules = data.get("rules")
        if not raw_rules:
            raise InvalidPolicyError(f"Policy '{name}' is missing a non-empty 'rules' list.")
        if not isinstance(raw_rules, list):
            raise InvalidPolicyError(f"Policy '{name}': 'rules' must be a list.")

        rules = []
        for raw_rule in raw_rules:
            try:
                rules.append(ComplianceRule.from_dict(raw_rule))
            except InvalidRuleError as exc:
                raise InvalidPolicyError(
                    f"Policy '{name}' contains an invalid rule: {exc}"
                ) from exc

        return cls(name=name, rules=rules, description=data.get("description", ""))

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "rules": [rule.to_dict() for rule in self.rules],
        }
