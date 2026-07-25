#!/usr/bin/env python3
"""
main.py

Command-line entry point for the Compliance Engine.

Usage:
    python main.py --config sample_configs/Branch-R1.cfg \
                    --policy rules/enterprise_router_policy.json \
                    --output reports/branch_r1_report.json

    python main.py --config sample_configs/HQ-Router1.cfg \
                    --policy rules/enterprise_router_policy.json

If --output is omitted, the report is printed to stdout only.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys

from engine.compliance_engine import ComplianceEngine, PolicyLoadError
from models.device import ConfigLoadError
from models.policy import InvalidPolicyError
from models.rule import InvalidRuleError


def configure_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Evaluate a Cisco device configuration against a compliance policy."
    )
    parser.add_argument("--config", required=True, help="Path to the device configuration file.")
    parser.add_argument("--policy", required=True, help="Path to the compliance policy JSON file.")
    parser.add_argument("--device-name", default=None, help="Optional friendly device name (defaults to filename).")
    parser.add_argument("--output", default=None, help="Path to write the JSON report to.")
    parser.add_argument("--verbose", action="store_true", help="Enable DEBUG level logging.")
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    configure_logging(args.verbose)
    logger = logging.getLogger("compliance_engine.main")

    try:
        engine = ComplianceEngine.from_files(
            config_path=args.config,
            policy_path=args.policy,
            device_name=args.device_name,
        )
    except ConfigLoadError as exc:
        logger.error("Failed to load device configuration: %s", exc)
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    except (PolicyLoadError, InvalidPolicyError, InvalidRuleError) as exc:
        logger.error("Failed to load compliance policy: %s", exc)
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    report = engine.generate_report()

    print(json.dumps(report, indent=2))

    if args.output:
        engine.save_report(args.output)
        print(f"\nReport written to: {args.output}", file=sys.stderr)

    # Exit code reflects compliance status: 0 = PASS, 2 = FAIL. This makes
    # the engine usable in CI/CD pipelines that gate on exit codes.
    return 0 if report["overall_status"] == "PASS" else 2


if __name__ == "__main__":
    sys.exit(main())
