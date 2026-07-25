import unittest

from models.rule import ComplianceRule, RuleType, InvalidRuleError


class TestRuleLoading(unittest.TestCase):
    def test_valid_rule_from_dict(self):
        rule = ComplianceRule.from_dict({
            "name": "SSH Enabled",
            "type": "contains",
            "value": "ip ssh version 2",
            "severity": "HIGH",
        })
        self.assertEqual(rule.name, "SSH Enabled")
        self.assertEqual(rule.rule_type, RuleType.CONTAINS)
        self.assertEqual(rule.severity, "HIGH")

    def test_default_severity_applied(self):
        rule = ComplianceRule.from_dict({
            "name": "Banner Configured",
            "type": "contains",
            "value": "banner motd",
        })
        self.assertEqual(rule.severity, "MEDIUM")

    def test_severity_case_insensitive(self):
        rule = ComplianceRule.from_dict({
            "name": "Telnet Disabled",
            "type": "not_contains",
            "value": "transport input telnet",
            "severity": "critical",
        })
        self.assertEqual(rule.severity, "CRITICAL")

    def test_missing_name_raises(self):
        with self.assertRaises(InvalidRuleError):
            ComplianceRule.from_dict({"type": "contains", "value": "x"})

    def test_missing_type_raises(self):
        with self.assertRaises(InvalidRuleError):
            ComplianceRule.from_dict({"name": "X", "value": "x"})

    def test_missing_value_raises(self):
        with self.assertRaises(InvalidRuleError):
            ComplianceRule.from_dict({"name": "X", "type": "contains"})

    def test_unsupported_rule_type_raises(self):
        with self.assertRaises(InvalidRuleError):
            ComplianceRule.from_dict({"name": "X", "type": "fuzzy_match", "value": "x"})

    def test_invalid_severity_raises(self):
        with self.assertRaises(InvalidRuleError):
            ComplianceRule.from_dict({
                "name": "X", "type": "contains", "value": "x", "severity": "SUPER_HIGH"
            })

    def test_non_dict_input_raises(self):
        with self.assertRaises(InvalidRuleError):
            ComplianceRule.from_dict(["not", "a", "dict"])

    def test_regex_rule_type_accepted(self):
        rule = ComplianceRule.from_dict({
            "name": "Hostname exists",
            "type": "regex",
            "value": r"^hostname\s+\S+",
            "severity": "LOW",
        })
        self.assertEqual(rule.rule_type, RuleType.REGEX)


if __name__ == "__main__":
    unittest.main()
