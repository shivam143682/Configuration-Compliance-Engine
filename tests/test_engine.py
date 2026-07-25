import json
import os
import tempfile
import unittest

from engine.compliance_engine import ComplianceEngine, PolicyLoadError
from models.device import Device, ConfigLoadError
from models.policy import CompliancePolicy


SAMPLE_CONFIG_TEXT = """
hostname Branch-R1
ip ssh version 2
service timestamps
logging host 10.1.1.1
line vty 0 4
 transport input telnet ssh
"""

VALID_POLICY_JSON = {
    "name": "Mini Policy",
    "rules": [
        {"name": "SSH Enabled", "type": "contains", "value": "ip ssh version 2", "severity": "HIGH"},
        {"name": "Telnet Disabled", "type": "not_contains", "value": "transport input telnet", "severity": "CRITICAL"},
        {"name": "NTP Configured", "type": "contains", "value": "ntp server", "severity": "HIGH"},
    ],
}


class TestComplianceEngine(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.config_path = os.path.join(self.tmpdir.name, "device.cfg")
        self.policy_path = os.path.join(self.tmpdir.name, "policy.json")

        with open(self.config_path, "w") as f:
            f.write(SAMPLE_CONFIG_TEXT)
        with open(self.policy_path, "w") as f:
            json.dump(VALID_POLICY_JSON, f)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_from_files_builds_engine(self):
        engine = ComplianceEngine.from_files(self.config_path, self.policy_path)
        self.assertEqual(engine.device.name, "device")
        self.assertEqual(engine.policy.name, "Mini Policy")

    def test_run_produces_expected_results(self):
        engine = ComplianceEngine.from_files(self.config_path, self.policy_path)
        results = engine.run()
        self.assertEqual(len(results), 3)
        statuses = {r.rule_name: r.status.value for r in results}
        self.assertEqual(statuses["SSH Enabled"], "PASS")
        self.assertEqual(statuses["Telnet Disabled"], "FAIL")  # telnet present -> fails not_contains
        self.assertEqual(statuses["NTP Configured"], "FAIL")   # ntp server absent

    def test_generate_report_summary_counts(self):
        engine = ComplianceEngine.from_files(self.config_path, self.policy_path)
        report = engine.generate_report()
        self.assertEqual(report["summary"]["total"], 3)
        self.assertEqual(report["summary"]["pass"], 1)
        self.assertEqual(report["summary"]["fail"], 2)
        self.assertEqual(report["overall_status"], "FAIL")

    def test_save_report_writes_file(self):
        engine = ComplianceEngine.from_files(self.config_path, self.policy_path)
        out_path = os.path.join(self.tmpdir.name, "report.json")
        engine.save_report(out_path)
        self.assertTrue(os.path.isfile(out_path))
        with open(out_path) as f:
            saved = json.load(f)
        self.assertEqual(saved["policy"], "Mini Policy")

    def test_missing_config_file_raises(self):
        with self.assertRaises(ConfigLoadError):
            ComplianceEngine.load_device_from_file(os.path.join(self.tmpdir.name, "nope.cfg"))

    def test_empty_config_file_raises(self):
        empty_path = os.path.join(self.tmpdir.name, "empty.cfg")
        with open(empty_path, "w") as f:
            f.write("")
        with self.assertRaises(ConfigLoadError):
            ComplianceEngine.load_device_from_file(empty_path)

    def test_missing_policy_file_raises(self):
        with self.assertRaises(PolicyLoadError):
            ComplianceEngine.load_policy_from_file(os.path.join(self.tmpdir.name, "nope.json"))

    def test_corrupted_policy_json_raises(self):
        bad_path = os.path.join(self.tmpdir.name, "bad.json")
        with open(bad_path, "w") as f:
            f.write("{ this is not valid json ,,, ")
        with self.assertRaises(PolicyLoadError):
            ComplianceEngine.load_policy_from_file(bad_path)

    def test_empty_policy_file_raises(self):
        empty_policy_path = os.path.join(self.tmpdir.name, "empty_policy.json")
        with open(empty_policy_path, "w") as f:
            f.write("")
        with self.assertRaises(PolicyLoadError):
            ComplianceEngine.load_policy_from_file(empty_policy_path)


if __name__ == "__main__":
    unittest.main()
