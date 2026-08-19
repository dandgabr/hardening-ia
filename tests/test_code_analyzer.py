"""Unit tests for OpenGrep SAST & SCA Vulnerability Analyzer."""

import unittest
import shutil
from pathlib import Path
from src.core.code_analyzer import CodeVulnerabilityScanner


class TestCodeVulnerabilityScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = CodeVulnerabilityScanner()
        self.test_dir = Path(__file__).resolve().parent / ".tmp_analyzer_test"
        self.test_dir.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        if self.test_dir.exists():
            shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_detects_hardcoded_secret(self):
        """Scanner should flag hardcoded API keys."""
        test_file = self.test_dir / "app.py"
        test_file.write_text('api_key = "AIzaSyD1234567890abcdef1234567890"\n', encoding="utf-8")

        findings = self.scanner.scan_path(test_file)
        self.assertTrue(any("CWE-798" in f.get("cwe", "") for f in findings), "Expected CWE-798 secret detection")

    def test_detects_command_injection(self):
        """Scanner should flag shell=True command execution."""
        test_file = self.test_dir / "exec.py"
        test_file.write_text('import subprocess\nsubprocess.run(user_input, shell=True)\n', encoding="utf-8")

        findings = self.scanner.scan_path(test_file)
        self.assertTrue(any("CWE-78" in f.get("cwe", "") for f in findings), "Expected CWE-78 command injection detection")

    def test_clean_file_passes_without_findings(self):
        """Safe code should produce zero findings."""
        test_file = self.test_dir / "safe.py"
        test_file.write_text('import os\nval = os.environ.get("SAFE_VAR", "default")\nprint(val)\n', encoding="utf-8")

        findings = self.scanner.scan_path(test_file)
        self.assertEqual(len(findings), 0, "Expected zero findings on clean code file")


if __name__ == "__main__":
    unittest.main()
