"""
engine/evaluator.py

Contains the logic to evaluate a single ComplianceRule against a device's
configuration text and produce a ComplianceResult.
"""

from __future__ import annotations

import logging
import re

from models.rule import ComplianceRule, RuleType
from models.result import ComplianceResult, RuleStatus

logger = logging.getLogger("compliance_engine.evaluator")


def evaluate_rule(rule: ComplianceRule, config_text: str) -> ComplianceResult:
    """Evaluate a single rule against the given configuration text.

    Args:
        rule: The ComplianceRule to evaluate.
        config_text: The full device configuration as a single string.

    Returns:
        A ComplianceResult describing PASS / FAIL / ERROR with evidence.
    """
    logger.info("Evaluating rule '%s' (%s)", rule.name, rule.rule_type.value)

    try:
        if rule.rule_type == RuleType.CONTAINS:
            found = rule.value in config_text
            status = RuleStatus.PASS if found else RuleStatus.FAIL
            evidence = (
                f"Found '{rule.value}' in configuration."
                if found
                else f"'{rule.value}' not found in configuration."
            )

        elif rule.rule_type == RuleType.NOT_CONTAINS:
            found = rule.value in config_text
            status = RuleStatus.FAIL if found else RuleStatus.PASS
            evidence = (
                f"Found forbidden value '{rule.value}' in configuration."
                if found
                else f"'{rule.value}' correctly absent from configuration."
            )

        elif rule.rule_type == RuleType.STARTS_WITH:
            matched_line = next(
                (line for line in config_text.splitlines() if line.strip().startswith(rule.value)),
                None,
            )
            status = RuleStatus.PASS if matched_line else RuleStatus.FAIL
            evidence = (
                f"Line starting with '{rule.value}' found: '{matched_line.strip()}'"
                if matched_line
                else f"No line starts with '{rule.value}'."
            )

        elif rule.rule_type == RuleType.ENDS_WITH:
            matched_line = next(
                (line for line in config_text.splitlines() if line.rstrip().endswith(rule.value)),
                None,
            )
            status = RuleStatus.PASS if matched_line else RuleStatus.FAIL
            evidence = (
                f"Line ending with '{rule.value}' found: '{matched_line.strip()}'"
                if matched_line
                else f"No line ends with '{rule.value}'."
            )

        elif rule.rule_type == RuleType.REGEX:
            match = re.search(rule.value, config_text, re.MULTILINE)
            status = RuleStatus.PASS if match else RuleStatus.FAIL
            evidence = (
                f"Pattern '{rule.value}' matched: '{match.group(0).strip()}'"
                if match
                else f"Pattern '{rule.value}' did not match configuration."
            )

        elif rule.rule_type == RuleType.EQUALS:
            matched_line = next(
                (line for line in config_text.splitlines() if line.strip() == rule.value.strip()),
                None,
            )
            status = RuleStatus.PASS if matched_line else RuleStatus.FAIL
            evidence = (
                f"Exact line match found: '{matched_line.strip()}'"
                if matched_line
                else f"No line exactly equals '{rule.value}'."
            )

        else:
            # Should not happen since ComplianceRule validates rule_type,
            # but guard defensively for future rule types.
            logger.error("Unsupported rule type encountered: %s", rule.rule_type)
            return ComplianceResult(
                rule_name=rule.name,
                status=RuleStatus.ERROR,
                severity=rule.severity,
                evidence=f"Unsupported rule type: {rule.rule_type}",
            )

    except re.error as exc:
        logger.error("Invalid regex in rule '%s': %s", rule.name, exc)
        return ComplianceResult(
            rule_name=rule.name,
            status=RuleStatus.ERROR,
            severity=rule.severity,
            evidence=f"Invalid regex pattern '{rule.value}': {exc}",
        )
    except Exception as exc:  # defensive catch-all so one bad rule doesn't crash a whole run
        logger.error("Unexpected error evaluating rule '%s': %s", rule.name, exc)
        return ComplianceResult(
            rule_name=rule.name,
            status=RuleStatus.ERROR,
            severity=rule.severity,
            evidence=f"Unexpected error during evaluation: {exc}",
        )

    if status == RuleStatus.FAIL:
        logger.warning("Rule '%s' FAILED: %s", rule.name, evidence)
    else:
        logger.info("Rule '%s' %s", rule.name, status.value)

    return ComplianceResult(
        rule_name=rule.name,
        status=status,
        severity=rule.severity,
        evidence=evidence,
    )
