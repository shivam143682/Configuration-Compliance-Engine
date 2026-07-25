import unittest

from models.rule import ComplianceRule
from models.result import RuleStatus
from engine.evaluator import evaluate_rule


SAMPLE_CONFIG = """
hostname Router1
ip ssh version 2
service timestamps
logging host 10.1.1.1
interface GigabitEthernet0/1
 description Uplink to Core
 ip address 10.1.1.1 255.255.255.0
line vty 0 4
 transport input ssh
"""


class TestEvaluator(unittest.TestCase):
    def test_contains_pass(self):
        rule = ComplianceRule.from_dict({"name": "SSH", "type": "contains", "value": "ip ssh version 2", "severity": "HIGH"})
        result = evaluate_rule(rule, SAMPLE_CONFIG)
        self.assertEqual(result.status, RuleStatus.PASS)

    def test_contains_fail(self):
        rule = ComplianceRule.from_dict({"name": "NTP", "type": "contains", "value": "ntp server", "severity": "HIGH"})
        result = evaluate_rule(rule, SAMPLE_CONFIG)
        self.assertEqual(result.status, RuleStatus.FAIL)
        self.assertIn("not found", result.evidence)

    def test_not_contains_pass(self):
        rule = ComplianceRule.from_dict({
            "name": "Telnet Disabled", "type": "not_contains",
            "value": "transport input telnet", "severity": "CRITICAL"
        })
        result = evaluate_rule(rule, SAMPLE_CONFIG)
        self.assertEqual(result.status, RuleStatus.PASS)

    def test_not_contains_fail(self):
        config_with_telnet = SAMPLE_CONFIG + "\n transport input telnet"
        rule = ComplianceRule.from_dict({
            "name": "Telnet Disabled", "type": "not_contains",
            "value": "transport input telnet", "severity": "CRITICAL"
        })
        result = evaluate_rule(rule, config_with_telnet)
        self.assertEqual(result.status, RuleStatus.FAIL)

    def test_regex_pass(self):
        rule = ComplianceRule.from_dict({
            "name": "Hostname exists", "type": "regex",
            "value": r"^hostname\s+\S+", "severity": "LOW"
        })
        result = evaluate_rule(rule, SAMPLE_CONFIG)
        self.assertEqual(result.status, RuleStatus.PASS)

    def test_regex_fail(self):
        rule = ComplianceRule.from_dict({
            "name": "No such pattern", "type": "regex",
            "value": r"^enable secret \S+", "severity": "LOW"
        })
        result = evaluate_rule(rule, SAMPLE_CONFIG)
        self.assertEqual(result.status, RuleStatus.FAIL)

    def test_regex_invalid_pattern_returns_error(self):
        rule = ComplianceRule.from_dict({
            "name": "Broken regex", "type": "regex",
            "value": r"(unclosed_group", "severity": "LOW"
        })
        result = evaluate_rule(rule, SAMPLE_CONFIG)
        self.assertEqual(result.status, RuleStatus.ERROR)

    def test_starts_with_pass(self):
        rule = ComplianceRule.from_dict({
            "name": "Starts with hostname", "type": "starts_with",
            "value": "hostname", "severity": "LOW"
        })
        result = evaluate_rule(rule, SAMPLE_CONFIG)
        self.assertEqual(result.status, RuleStatus.PASS)

    def test_ends_with_pass(self):
        rule = ComplianceRule.from_dict({
            "name": "Ends with ssh", "type": "ends_with",
            "value": "input ssh", "severity": "LOW"
        })
        result = evaluate_rule(rule, SAMPLE_CONFIG)
        self.assertEqual(result.status, RuleStatus.PASS)

    def test_equals_pass(self):
        rule = ComplianceRule.from_dict({
            "name": "Exact SSH line", "type": "equals",
            "value": "ip ssh version 2", "severity": "HIGH"
        })
        result = evaluate_rule(rule, SAMPLE_CONFIG)
        self.assertEqual(result.status, RuleStatus.PASS)

    def test_equals_fail(self):
        rule = ComplianceRule.from_dict({
            "name": "Exact wrong line", "type": "equals",
            "value": "ip ssh version 1", "severity": "HIGH"
        })
        result = evaluate_rule(rule, SAMPLE_CONFIG)
        self.assertEqual(result.status, RuleStatus.FAIL)


if __name__ == "__main__":
    unittest.main()
