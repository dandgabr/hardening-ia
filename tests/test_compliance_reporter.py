"""Unit tests for Enterprise Compliance and Governance Reporting Engine."""

import unittest
import json
from pathlib import Path
import shutil

from src.core.compliance_reporter import ComplianceReporter, FRAMEWORK_MAPPINGS
from src.core.verifier import PolicyVerificationReport, CheckResult
from src.core.models import HardeningPolicy, ToolMeta, OSPaths


class TestComplianceReporter(unittest.TestCase):
    def setUp(self):
        self.test_dir = Path(__file__).resolve().parent / ".tmp_reporter_test"
        self.test_dir.mkdir(parents=True, exist_ok=True)

        self.mock_report1 = PolicyVerificationReport(
            tool_name="antigravity",
            vendor="google",
            is_installed=True,
            settings_file_exists=True,
            rules_dir_exists=True,
            total_checks=3,
            passed_checks=3,
            failed_checks=0,
            compliance_score=100.0,
            checks=[
                CheckResult(key="telemetry.enabled", expected=False, actual=False, passed=True, description="Telemetry disabled"),
                CheckResult(key="mcp.requireConsent", expected=True, actual=True, passed=True, description="MCP Consent"),
                CheckResult(key="dlp.maskSecrets", expected=True, actual=True, passed=True, description="DLP Secrets")
            ]
        )

        self.mock_report2 = PolicyVerificationReport(
            tool_name="cursor",
            vendor="anysphere",
            is_installed=True,
            settings_file_exists=True,
            rules_dir_exists=True,
            total_checks=2,
            passed_checks=1,
            failed_checks=1,
            compliance_score=50.0,
            checks=[
                CheckResult(key="telemetry.enabled", expected=False, actual=False, passed=True, description="Telemetry disabled"),
                CheckResult(key="sandbox.enabled", expected=True, actual=False, passed=False, description="Sandbox enabled")
            ]
        )

        self.reporter = ComplianceReporter([self.mock_report1, self.mock_report2])

    def tearDown(self):
        if self.test_dir.exists():
            shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_calculate_overall_compliance(self):
        """Reporter should aggregate global compliance statistics accurately."""
        stats = self.reporter.calculate_overall_compliance()
        self.assertEqual(stats["total_tools"], 2)
        self.assertEqual(stats["installed_tools"], 2)
        self.assertEqual(stats["total_checks"], 5)
        self.assertEqual(stats["passed_checks"], 4)
        self.assertEqual(stats["failed_checks"], 1)
        self.assertEqual(stats["global_score"], 80.0)

    def test_generate_json(self):
        """JSON output should be valid schema with statistics and framework mappings."""
        raw_json = self.reporter.generate_json()
        data = json.loads(raw_json)
        self.assertEqual(data["report_type"], "Hardening IA Enterprise Compliance Audit")
        self.assertEqual(len(data["tools"]), 2)
        self.assertIn("telemetry", data["framework_mappings"])

    def test_generate_sarif(self):
        """SARIF output should adhere to OASIS SARIF 2.1.0 specification with findings."""
        raw_sarif = self.reporter.generate_sarif()
        data = json.loads(raw_sarif)
        self.assertEqual(data["version"], "2.1.0")
        self.assertEqual(len(data["runs"]), 1)
        # Should record the 1 failed check
        self.assertEqual(len(data["runs"][0]["results"]), 1)

    def test_generate_html(self):
        """HTML output should contain executive summary, CSS styles, and tool table."""
        html = self.reporter.generate_html()
        self.assertIn("<!DOCTYPE html>", html)
        self.assertIn("Global Compliance Score", html)
        self.assertIn("google/antigravity", html)
        self.assertIn("anysphere/cursor", html)
        self.assertIn("OWASP Top 10 for LLM", html)

    def test_export_report_files(self):
        """Exporting reports to disk in multiple formats should create valid files."""
        html_file = self.test_dir / "report.html"
        sarif_file = self.test_dir / "report.sarif"
        json_file = self.test_dir / "report.json"
        md_file = self.test_dir / "report.md"

        self.reporter.export_report(html_file, "html")
        self.reporter.export_report(sarif_file, "sarif")
        self.reporter.export_report(json_file, "json")
        self.reporter.export_report(md_file, "markdown")

        self.assertTrue(html_file.exists())
        self.assertTrue(sarif_file.exists())
        self.assertTrue(json_file.exists())
        self.assertTrue(md_file.exists())


if __name__ == "__main__":
    unittest.main()
