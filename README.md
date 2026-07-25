# Compliance Engine

This is my implementation of Task 2 — a Python compliance engine that takes a
Cisco device config, checks it against a set of rules (SSH enabled, Telnet
disabled, NTP configured, etc.), and spits out a PASS/FAIL report. Basically
the thing every NCM (Network Configuration Management) tool does under the
hood, just stripped down to the essentials.

The idea driving the design: instead of manually eyeballing every router
config against a checklist, you describe the checklist once as JSON rules,
group them into a policy, and the engine does the boring part.

---

## 1. Design Overview

Following the workflow from the spec pretty closely:

```
Cisco Config File
      │
      ▼
Device Object  (parsed config: name + raw text + lines)
      │
      ▼
Compliance Engine
      │
      ├── loads Compliance Rules (from JSON)
      └── loads Compliance Policy (a named group of rules)
      │
      ▼
Rule Evaluation  (loop through every rule, run it, collect result)
      │
      ▼
Compliance Report (JSON)
```

**The main classes:**

- `ComplianceRule` — one requirement. Has a `name`, `description`,
  `rule_type`, `expected_value`, and `severity`. Rule type is an enum so it's
  not just a random string floating around — `CONTAINS`, `NOT_CONTAINS`,
  `STARTS_WITH`, `ENDS_WITH`, `REGEX`, `EQUALS`.
- `CompliancePolicy` — just a `name` + list of `ComplianceRule` objects.
  "Enterprise Router Policy" = SSH + NTP + Logging + AAA + SNMP bundled
  together, so you evaluate a whole policy at once instead of rule by rule.
- `Device` — wraps the loaded config (name + raw text + line list) so the
  rest of the code isn't passing bare strings around.
- `ComplianceResult` — the outcome of checking one rule: `rule_name`,
  `status` (PASS/FAIL/ERROR), `severity`, and `evidence` (a short string
  explaining *why* it passed or failed — makes the report actually useful
  instead of just a yes/no).
- `ComplianceEngine` — orchestrates the whole thing: load config, load
  policy, loop through `policy.rules`, evaluate each one, collect results,
  build the report.

**Why models/ and engine/ are separate folders:** `models/` only cares about
what valid data looks like — a rule, a policy, a device. If something's
malformed (missing a field, bad JSON, unsupported rule type) it should fail
right there during loading with a clear exception, not silently cause weird
behavior three steps later during evaluation. `engine/` only cares about
*doing* something with that already-validated data — actually running the
CONTAINS/REGEX/etc. checks and building the report. Splitting it this way
also made unit testing way more straightforward, since I could test "is this
rule JSON valid" completely separately from "does the contains-check
actually work correctly."

**Rule types implemented** (matches the spec's list):

| Type | Meaning |
|---|---|
| `CONTAINS` | the value appears somewhere in the config |
| `NOT_CONTAINS` | the value must NOT appear (e.g. Telnet transport line) |
| `STARTS_WITH` | some config line starts with the value |
| `ENDS_WITH` | some config line ends with the value |
| `REGEX` | pattern matches anywhere in the config |
| `EQUALS` | some config line matches the value exactly |

New rule types are cheap to add later — one more entry in the `RuleType`
enum, one more branch in the evaluator, nothing else changes. That's the
"strategy pattern, informally" bit — each rule type is really its own small
strategy for deciding PASS/FAIL, they just live in one function instead of
separate classes since there are only six of them right now.

---

## 2. Folder Structure

```
compliance_engine/
│
├── models/
│   ├── device.py       # Device: name + config text/lines, from_file() loader
│   ├── rule.py         # ComplianceRule + RuleType enum, validation
│   ├── policy.py       # CompliancePolicy, validation
│   └── result.py       # ComplianceResult + RuleStatus enum
│
├── engine/
│   ├── evaluator.py            # evaluate_rule() — the actual PASS/FAIL logic
│   └── compliance_engine.py    # ComplianceEngine: load -> run -> report
│
├── rules/
│   ├── security_rules.json             # all 10 rules from the spec (hostname, SSH,
│   │                                    #   telnet, logging, NTP, AAA, banner, SNMP,
│   │                                    #   interface descriptions, interface IPs)
│   └── enterprise_router_policy.json   # a policy grouping SSH/Telnet/NTP/Logging/AAA/SNMP
│
├── sample_configs/
│   ├── HQ-Router1.cfg   # clean config — should pass everything
│   └── Branch-R1.cfg    # config with Telnet on, no NTP/AAA/SNMP — fails several rules
│
├── reports/             # generated JSON reports land here
│
├── tests/
│   ├── test_rule.py       # rule loading / validation
│   ├── test_policy.py     # policy loading / validation
│   ├── test_evaluator.py  # CONTAINS / NOT_CONTAINS / REGEX / etc.
│   └── test_engine.py     # end-to-end run + report generation + error handling
│
├── main.py               # CLI entry point
└── README.md
```

---

## 3. How to Run

Pure standard library — no pip installs needed (`json`, `re`, `logging`,
`argparse`, `dataclasses`, `enum`). Should run on Python 3.8+.

**Check a non-compliant device:**

```bash
python3 main.py \
  --config sample_configs/Branch-R1.cfg \
  --policy rules/enterprise_router_policy.json \
  --output reports/branch_r1_report.json
```

**Check a compliant one:**

```bash
python3 main.py \
  --config sample_configs/HQ-Router1.cfg \
  --policy rules/enterprise_router_policy.json \
  --output reports/hq_router1_report.json
```

**Flags:**

- `--config` (required) — path to the device config file
- `--policy` (required) — path to the policy JSON
- `--device-name` (optional) — override the device name, defaults to the filename
- `--output` (optional) — where to save the JSON report (it prints to stdout regardless)
- `--verbose` — turns on DEBUG-level logging if you want to see everything

Exit codes are meaningful, so this drops cleanly into a CI pipeline:
`0` = compliant, `2` = not compliant, `1` = something wrong with the inputs
(bad file, corrupted JSON, etc).

**Run the tests:**

```bash
python3 -m unittest discover -s tests -v
```

---

## 4. Sample Input / Output

**Input config** (`sample_configs/Branch-R1.cfg`, trimmed):

```
hostname Branch-R1
ip ssh version 2
service timestamps
logging host 10.1.1.1
line vty 0 4
 transport input telnet ssh
```

**Rule evaluation, matching the spec's example directly:**

| Rule | Type | Value | Result |
|---|---|---|---|
| SSH Enabled | CONTAINS | `ip ssh version 2` | **PASS** — found in config |
| NTP Configured | CONTAINS | `ntp server` | **FAIL** — not found |
| Telnet Disabled | NOT_CONTAINS | `transport input telnet` | **FAIL** — telnet is there |

**Resulting report** (`reports/branch_r1_report.json`):

```json
{
  "device": "Branch-R1",
  "policy": "Enterprise Router Policy",
  "overall_status": "FAIL",
  "summary": {
    "pass": 2,
    "fail": 4,
    "error": 0
  },
  "results": [
    {
      "rule": "SSH Enabled",
      "status": "PASS",
      "severity": "HIGH",
      "evidence": "Found 'ip ssh version 2' in configuration."
    },
    {
      "rule": "NTP Configured",
      "status": "FAIL",
      "severity": "HIGH",
      "evidence": "'ntp server' not found in configuration."
    },
    {
      "rule": "Telnet Disabled",
      "status": "FAIL",
      "severity": "CRITICAL",
      "evidence": "Found forbidden value 'transport input telnet' in configuration."
    }
  ]
}
```

**Logging output** (stderr, via Python's `logging` module — matches the
INFO/WARNING/ERROR examples from the spec):

```
2026-07-25 05:10:58 INFO     compliance_engine: Loaded configuration for device 'Branch-R1'
2026-07-25 05:10:58 INFO     compliance_engine: Loaded policy 'Enterprise Router Policy' with 6 rule(s)
2026-07-25 05:10:58 INFO     compliance_engine.evaluator: Evaluating rule 'SSH Enabled'
2026-07-25 05:10:58 WARNING  compliance_engine.evaluator: Rule 'NTP Configured' FAILED: 'ntp server' not found in configuration.
2026-07-25 05:10:58 INFO     compliance_engine: Compliance run complete for device 'Branch-R1'.
```

**Exception handling** — covers everything the spec calls out:

- Missing config file → clean error, no traceback dumped on the user
- Empty config file → same
- Corrupted/invalid policy JSON → caught and reported clearly
- Empty policy (zero rules) → rejected at load time
- Invalid rule format (missing name/type/value) → rejected at load time
- Unsupported rule type → rejected at load time
- A broken regex pattern in a rule → doesn't crash the whole run, that one
  rule just comes back as `ERROR` status with the reason in the evidence
  field, and everything else still evaluates normally

---

## 5. Future Enhancements

- **HTML/CSV/Excel report output** — the spec mentions this as a later step,
  and it's an easy add since `generate_report()` already just returns a
  plain dict — any of those formats is just a different renderer on top of
  the same data.
- **More rule types** — numeric range checks (e.g. "ACL entry count under
  X"), or composite rules like "any_of" / "all_of" for cases where more than
  one config line could satisfy the same requirement.
- **SNMP "not public" style checks** — right now SNMP is checked with a
  simple CONTAINS on `snmp-server`, but the real-world example in the spec
  calls out checking that the community string *isn't* the default
  `"public"`. That's a good candidate for a small `NOT_CONTAINS` rule
  (`snmp-server community public`) once default-credential checks become a
  priority.
- **Scan a whole folder of configs at once** instead of one device per run,
  with a single combined report across all of them.
- **Abstract base class for rule strategies** — right now all six rule types
  live as branches inside one evaluator function, which is fine at this
  scale. If the list of rule types keeps growing, splitting each into its
  own strategy class (proper Strategy Pattern) would keep the evaluator from
  turning into a giant if/elif chain.
- **Policy inheritance** — let a policy extend a shared baseline instead of
  re-listing every rule every time.
- **Remediation hints** — attach a suggested config snippet to each rule so
  a FAIL result doubles as a fix suggestion, not just a diagnosis.
- **Small REST API wrapper** (FastAPI/Flask) so configs can be uploaded and
  checked without needing the CLI.
