"""
engine/compliance_engine.py

The ComplianceEngine ties everything together:
    Load Config -> Load Policy -> Evaluate every rule -> Build Report

It is deliberately kept thin: loading is delegated to the model classes,
evaluation is delegated to engine.evaluator, and this module just
orchestrates the pipeline and assembles the final report dict.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from typing import List

from models.device import Device, ConfigLoadError
from models.policy import CompliancePolicy, InvalidPolicyError
from models.result import ComplianceResult, RuleStatus
from engine.evaluator import evaluate_rule

logger = logging.getLogger("compliance_engine")


class PolicyLoadError(Exception):
    """Raised when a policy JSON file cannot be loaded or parsed."""


class ComplianceEngine:
    def __init__(self, device: Device, policy: CompliancePolicy):
        self.device = device
        self.policy = policy
        self.results: List[ComplianceResult] = []

    # ------------------------------------------------------------------
    # Loading helpers (class methods so callers can build an engine
    # directly from file paths without touching the model classes).
    # ------------------------------------------------------------------
    @classmethod
    def load_policy_from_file(cls, path: str) -> CompliancePolicy:
        """Load and validate a CompliancePolicy from a JSON file."""
        if not os.path.isfile(path):
            raise PolicyLoadError(f"Policy file not found: {path}")

        with open(path, "r", encoding="utf-8") as f:
            raw_text = f.read()

        if not raw_text.strip():
            raise PolicyLoadError(f"Policy file is empty: {path}")

        try:
            data = json.loads(raw_text)
        except json.JSONDecodeError as exc:
            raise PolicyLoadError(f"Policy file '{path}' contains invalid/corrupted JSON: {exc}") from exc

        try:
            policy = CompliancePolicy.from_dict(data)
        except InvalidPolicyError as exc:
            raise PolicyLoadError(str(exc)) from exc

        logger.info("Loaded policy '%s' with %d rule(s) from %s", policy.name, len(policy.rules), path)
        return policy

    @classmethod
    def load_device_from_file(cls, path: str, device_name: str = None) -> Device:
        """Load a Device configuration from a file, wrapping loader errors."""
        try:
            device = Device.from_file(path, device_name=device_name)
        except ConfigLoadError:
            raise
        logger.info("Loaded configuration for device '%s' from %s", device.name, path)
        return device

    @classmethod
    def from_files(cls, config_path: str, policy_path: str, device_name: str = None) -> "ComplianceEngine":
        """Convenience constructor: build a fully-loaded engine from two file paths."""
        device = cls.load_device_from_file(config_path, device_name=device_name)
        policy = cls.load_policy_from_file(policy_path)
        return cls(device=device, policy=policy)

    # ------------------------------------------------------------------
    # Evaluation
    # ------------------------------------------------------------------
    def run(self) -> List[ComplianceResult]:
        """Evaluate every rule in the policy against the device config."""
        logger.info(
            "Starting compliance run: device='%s' policy='%s' (%d rules)",
            self.device.name,
            self.policy.name,
            len(self.policy.rules),
        )
        self.results = []
        for rule in self.policy.rules:
            result = evaluate_rule(rule, self.device.config_text)
            self.results.append(result)
        logger.info("Compliance run complete for device '%s'.", self.device.name)
        return self.results

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------
    def generate_report(self) -> dict:
        """Build the final JSON-serializable compliance report.

        Runs the evaluation first if it hasn't been run yet.
        """
        if not self.results:
            self.run()

        pass_count = sum(1 for r in self.results if r.status == RuleStatus.PASS)
        fail_count = sum(1 for r in self.results if r.status == RuleStatus.FAIL)
        error_count = sum(1 for r in self.results if r.status == RuleStatus.ERROR)

        # Overall status: FAIL if any rule failed or errored, else PASS.
        overall_status = "PASS" if fail_count == 0 and error_count == 0 else "FAIL"

        report = {
            "device": self.device.name,
            "policy": self.policy.name,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "overall_status": overall_status,
            "summary": {
                "total": len(self.results),
                "pass": pass_count,
                "fail": fail_count,
                "error": error_count,
            },
            "results": [r.to_dict() for r in self.results],
        }
        return report

    def save_report(self, output_path: str) -> str:
        """Generate the report and write it to disk as JSON. Returns the path written."""
        report = self.generate_report()
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        logger.info("Report written to %s", output_path)
        return output_path
