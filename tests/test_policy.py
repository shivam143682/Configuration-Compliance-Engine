import unittest

from models.policy import CompliancePolicy, InvalidPolicyError


VALID_POLICY_DICT = {
    "name": "Enterprise Router Policy",
    "description": "Baseline policy",
    "rules": [
        {"name": "SSH Enabled", "type": "contains", "value": "ip ssh version 2", "severity": "HIGH"},
        {"name": "Telnet Disabled", "type": "not_contains", "value": "transport input telnet", "severity": "CRITICAL"},
    ],
}


class TestPolicyLoading(unittest.TestCase):
    def test_valid_policy_loads_with_rules(self):
        policy = CompliancePolicy.from_dict(VALID_POLICY_DICT)
        self.assertEqual(policy.name, "Enterprise Router Policy")
        self.assertEqual(len(policy.rules), 2)

    def test_missing_name_raises(self):
        data = {"rules": VALID_POLICY_DICT["rules"]}
        with self.assertRaises(InvalidPolicyError):
            CompliancePolicy.from_dict(data)

    def test_empty_rules_list_raises(self):
        data = {"name": "Empty Policy", "rules": []}
        with self.assertRaises(InvalidPolicyError):
            CompliancePolicy.from_dict(data)

    def test_missing_rules_key_raises(self):
        data = {"name": "No Rules Key"}
        with self.assertRaises(InvalidPolicyError):
            CompliancePolicy.from_dict(data)

    def test_rules_not_a_list_raises(self):
        data = {"name": "Bad Rules", "rules": {"name": "x"}}
        with self.assertRaises(InvalidPolicyError):
            CompliancePolicy.from_dict(data)

    def test_invalid_rule_inside_policy_raises(self):
        data = {
            "name": "Bad Inner Rule",
            "rules": [{"name": "X", "type": "unsupported_type", "value": "x"}],
        }
        with self.assertRaises(InvalidPolicyError):
            CompliancePolicy.from_dict(data)

    def test_non_dict_input_raises(self):
        with self.assertRaises(InvalidPolicyError):
            CompliancePolicy.from_dict("not-a-dict")


if __name__ == "__main__":
    unittest.main()
