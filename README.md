
# Compliance Engine

A rule-driven engine for checking Cisco IOS device configurations against

compliance policies (for example "SSH must be v2" "Telnet must be disabled"

"NTP must be configured") and producing a JSON report.

---

## 1. Design Overview

The engine follows a linear pipeline:

```

Load Config -> Load Policy -> Evaluate every rule -> Collect results -> Generate report

```

**Core concepts**

| Concept | Class | Description |

|---|---|---|

| Rule | `ComplianceRule` | One requirement, for example "SSH Enabled" (`contains: ip ssh version 2`) |

| Policy | `CompliancePolicy` | A named group of rules for example "Enterprise Router Policy" |

Device | `Device` | A devices name plus raw configuration text |

| Result | `ComplianceResult` | Outcome of evaluating one rule (`PASS` / `FAIL` / `ERROR`) with evidence |

| Engine | `ComplianceEngine` | Orchestrates loading, evaluation and report generation |

**Supported rule types**

- `contains`. Passes if the value appears anywhere in the config

- `not_contains`. Passes if the value does not appear (used for things like disabling Telnet)

- `starts_with`. Passes if any config line starts with the value

- `ends_with`. Passes if any config line ends with the value

- `regex`. Passes if the pattern matches anywhere in the config (multiline)

- `equals`. Passes if any config line exactly equals the value (after trimming)

Rule types are defined once in `models/rule.py` (`RuleType` enum) and dispatched

in `engine/evaluator.py` so adding a new rule type later means adding one enum

value and one `elif` branch. Nothing else in the codebase needs to change.

**Why the split between `models/` and `engine/`?**

- `models/` only knows about data: what a valid rule/policy/device/result

looks like and how to load/validate them from JSON. Each model raises a

exception (`InvalidRuleError` `InvalidPolicyError` `ConfigLoadError`)

when given bad input.

- `engine/` only knows about behavior: how to evaluate a rule against text

(`evaluator.py`) and how to run a policy against a device and build a

report (`compliance_engine.py`).

This separation makes it easy to unit test evaluation logic (`test_evaluator.py`)

independently of file loading (`test_engine.py`) and independently of

validation (`test_rule.py` `test_policy.py`).

---

## 2. Folder Structure

```

compliance_engine/

│

├── models/

│   ├── device.py         # Device:. Config text/lines, from_file() loader

│   ├── rule.py           # ComplianceRule, RuleType enum, InvalidRuleError

│   ├── policy.py         # CompliancePolicy, InvalidPolicyError

│   └── result.py         # ComplianceResult, RuleStatus enum (PASS/FAIL/ERROR)

│

├── engine/

│   ├── evaluator.py            # evaluate_rule(): the PASS/FAIL logic per rule type

│   └── compliance_engine.py    # ComplianceEngine: load -> run -> generate_report -> save_report

│

├── rules/

│   ├── security_rules.json             # Full library of 10 individual rules

│   └── enterprise_router_policy.json   # A policy grouping 6 of those rules

│

├── sample_configs/

│   ├── HQ-Router1.cfg    # Fully compliant sample config (all rules PASS)

│   └── Branch-R1.cfg     # Non-compliant sample config (several rules FAIL)

│

├── reports/              # Generated JSON reports land here

│

├── tests/

│   ├── test_rule.py       # Rule loading/validation

│   ├── test_policy.py     # Policy loading/validation

│   ├── test_evaluator.py  # contains / not_contains / regex / etc. Evaluation

│   └── test_engine.py     # End-to-end engine + report generation + error handling

│

├── main.py                # CLI entry point

└── README.md

```

---

## 3. How to Run

No third-party dependencies are required. The engine only uses the Python

library (`json` `re` `logging` `argparse` `dataclasses`).

**Run against the -compliant sample device:**

```bash

python3 main.py \

--config sample_configs/Branch-R1.cfg \

--policy rules/enterprise_router_policy.json \

--output reports/branch_r1_report.json

```

**Run against the compliant sample device:**

```bash

python3 main.py \

--config sample_configs/HQ-Router1.cfg \

--policy rules/enterprise_router_policy.json \

--output reports/hq_router1_report.json

```

**Options:**

- `--config` (required). Path to the device configuration file

- `--policy` (required). Path to the compliance policy JSON file

- `--device-name` (optional). Override the device name (defaults to filename)

- `--output` (optional). Write the JSON report to this path (also always printed to stdout)

- `--verbose`. Enable DEBUG-level logging

**Exit codes** (useful for CI/CD pipelines): `0` = PASS, `2` = overall

FAIL `1` = a loading error occurred (bad file, corrupted JSON, etc.)

**Run the unit tests:**

```bash

python3 -m unittest discover -s tests -v

```

---

## 4. Sample Input / Output

**Input. `Sample_configs/Branch-R1.cfg` (excerpt):**

```

hostname Branch-R1

ip ssh version 2

service timestamps

logging host 10.1.1.1

line vty 0 4

transport input telnet ssh

```

**Output. `Reports/branch_r1_report.json` (excerpt):**

```json

{

"device": "Branch-R1"

"policy": "Enterprise Router Policy"

"overall_status": "

"summary": {

"total": 6

"pass": 2

"fail": 4

"error": 0

}

"results": [

{

"rule": "SSH Enabled"

"status": "PASS"

"severity": "

"evidence": "Found 'ip ssh version 2' in configuration."

}

{

"rule": "Telnet Disabled"

"status": "FAIL"

"severity": "CRITICAL"

"evidence": "Found forbidden value 'transport input telnet' in configuration."

}

{

"rule": "NTP Configured"

"status": "FAIL"

"severity": "

"evidence": "'ntp server' not found in configuration."

}

]

}

```

**Log excerpt (stderr, via `logging`):**

```

2026-07-25 05:10:58 INFO     compliance_engine.evaluator: Evaluating rule 'AAA Enabled' (contains)

2026-07-25 05:10:58 WARNING  compliance_engine.evaluator: Rule 'AAA Enabled' FAILED: 'aaa model' not found in configuration.

2026-07-25 05:10:58 INFO     compliance_engine: Compliance run complete for device 'Branch-R1'.

```

---

## 5. Exception Handling

| Scenario | Where its caught | Exception raised |

|---|---|---|

Missing config file | `Device.from_file` | `ConfigLoadError` |

| Empty config file | `Device.from_file` | `ConfigLoadError` |

| Missing policy file | `ComplianceEngine.load_policy_from_file` | `PolicyLoadError` |

| Empty policy file | `ComplianceEngine.load_policy_from_file` | `PolicyLoadError` |

| Corrupted/invalid JSON | `ComplianceEngine.load_policy_from_file` | `PolicyLoadError` (wraps `json.JSONDecodeError`) |

Empty policy (no rules) | `CompliancePolicy.from_dict` | `InvalidPolicyError` |

| Invalid rule format (missing name/type/value) | `ComplianceRule.from_dict` | `InvalidRuleError` |

| Unsupported rule type | `ComplianceRule.from_dict` | `InvalidRuleError` |

| Bad regex pattern at evaluation time | `evaluator.evaluate_rule` | Caught internally -> `ComplianceResult` with status `ERROR` (does not crash the run) |

`main.py` catches all loading-time exceptions and prints a ERROR:...`

message with a non-zero exit code instead of a raw traceback.

---

## 6. Future Enhancements

- **Additional output formats**. HTML (styled report) Excel/CSV export for

audit teams since `generate_report()` already returns a dict/JSON

structure thats trivial to feed into other renderers.

- **More rule types**. `Range` (for example thresholds, like ACL count)

all_of / any_of composite rules, absent_line_count.

- **Multi-device / bulk scanning**. Direct the engine to a folder of configs. Generate one combined report with breakdowns for each device.

- **Vendor abstraction**. Currently set up for Cisco IOS syntax; a platform field on rules or policies could let the engine check Juniper, Arista or Fortinet configs.

- **Policy inheritance**. Let policies build on or replace a "base" policy (for example "Enterprise Router Policy" builds on "Global Baseline Policy").

- **Remediation hints**. Add a suggested CLI command to each rule so a failed report can also act as a to-do list for network engineers.

- **REST API wrapper**. Make ComplianceEngine available, through a FastAPI/Flask service so configs can be uploaded and checked without running main.py.
