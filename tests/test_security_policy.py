"""Unit tests for SecurityPolicyManager, dangerous paths restrictions, rate limits, timeouts, and strict mode."""

import unittest
from src.core.security_policy import (
    SecurityPolicyManager,
    DANGEROUS_PATHS_BY_OS,
    CRITICAL_DENIED_PATTERNS_BY_OS,
    DEFAULT_RATE_LIMIT,
    DEFAULT_TIMEOUT
)
from src.core.command_classifier import CommandRiskClassifier, RiskLevel


class TestSecurityPolicy(unittest.TestCase):
    def test_dangerous_paths_structure(self):
        """Ensure dangerous paths are defined for Linux, Windows, and macOS."""
        for os_name in ("linux", "windows", "macos"):
            paths = SecurityPolicyManager.get_dangerous_paths_for_os(os_name)
            self.assertGreater(len(paths), 10, f"Expected more than 10 dangerous paths for {os_name}")
            # Ensure credential paths are covered
            self.assertTrue(any(".ssh" in p for p in paths), f"Expected .ssh path in {os_name}")
            self.assertTrue(any(".aws" in p for p in paths), f"Expected .aws path in {os_name}")

    def test_is_dangerous_path_linux(self):
        """Test dangerous path detection on Linux."""
        self.assertTrue(SecurityPolicyManager.is_dangerous_path("/etc/shadow", "linux"))
        self.assertTrue(SecurityPolicyManager.is_dangerous_path("/etc/sudoers", "linux"))
        self.assertTrue(SecurityPolicyManager.is_dangerous_path("/boot/vmlinuz", "linux"))
        self.assertTrue(SecurityPolicyManager.is_dangerous_path("~/.ssh/id_rsa", "linux"))
        self.assertTrue(SecurityPolicyManager.is_dangerous_path("~/.aws/credentials", "linux"))
        self.assertFalse(SecurityPolicyManager.is_dangerous_path("/home/user/project/src/main.py", "linux"))
        self.assertFalse(SecurityPolicyManager.is_dangerous_path("./relative_dir/file.txt", "linux"))

    def test_is_dangerous_path_windows(self):
        """Test dangerous path detection on Windows."""
        self.assertTrue(SecurityPolicyManager.is_dangerous_path(r"C:\Windows\System32\cmd.exe", "windows"))
        self.assertTrue(SecurityPolicyManager.is_dangerous_path(r"C:\Program Files\App\secret.dll", "windows"))
        self.assertTrue(SecurityPolicyManager.is_dangerous_path(r"%USERPROFILE%\.ssh\id_ed25519", "windows"))
        self.assertFalse(SecurityPolicyManager.is_dangerous_path(r"C:\Projects\my-app\src\index.ts", "windows"))

    def test_is_dangerous_path_macos(self):
        """Test dangerous path detection on macOS."""
        self.assertTrue(SecurityPolicyManager.is_dangerous_path("/System/Library/CoreServices", "macos"))
        self.assertTrue(SecurityPolicyManager.is_dangerous_path("~/Library/Keychains/login.keychain", "macos"))
        self.assertTrue(SecurityPolicyManager.is_dangerous_path("~/.zshrc", "macos"))
        self.assertFalse(SecurityPolicyManager.is_dangerous_path("/Users/dev/workspace/app.py", "macos"))

    def test_check_path_access_standard_vs_strict(self):
        """In standard mode, accessing a dangerous path asks the user; in strict mode it blocks immediately."""
        # Standard mode: ask before access
        blocked_std, msg_std = SecurityPolicyManager.check_path_access("/etc/shadow", "linux", strict_mode=False)
        self.assertFalse(blocked_std, "Standard mode should prompt user, not block immediately without prompt.")
        self.assertIn("HUMAN-IN-THE-LOOP", msg_std)

        # Strict mode: block immediately without asking
        blocked_strict, msg_strict = SecurityPolicyManager.check_path_access("/etc/shadow", "linux", strict_mode=True)
        self.assertTrue(blocked_strict, "Strict mode must block immediately without prompting.")
        self.assertIn("STRICT BLOCKED", msg_strict)

    def test_rate_limit_and_timeout_configurations(self):
        """Verify default rate limit and timeout constants."""
        self.assertEqual(DEFAULT_RATE_LIMIT["max_requests_per_minute"], 30)
        self.assertEqual(DEFAULT_RATE_LIMIT["burst_limit"], 10)
        self.assertEqual(DEFAULT_TIMEOUT["command_timeout_seconds"], 30)
        self.assertEqual(DEFAULT_TIMEOUT["execution_timeout_seconds"], 60)
        self.assertEqual(DEFAULT_TIMEOUT["network_timeout_seconds"], 15)

    def test_command_classifier_strict_mode_blocks_critical_and_dangerous_paths(self):
        """Verify CommandRiskClassifier in strict mode blocks critical commands and dangerous path accesses."""
        # 1. Critical destructive anti-pattern in standard mode vs strict mode
        crit_cmd = "rm -rf /"
        risk_std, req_approval_std, reason_std = CommandRiskClassifier.classify_command(crit_cmd, "linux", strict_mode=False)
        self.assertEqual(risk_std, RiskLevel.CRITICAL)
        self.assertTrue(req_approval_std, "Standard mode requires operator confirmation")

        risk_strict, req_approval_strict, reason_strict = CommandRiskClassifier.classify_command(crit_cmd, "linux", strict_mode=True)
        self.assertEqual(risk_strict, RiskLevel.CRITICAL)
        self.assertFalse(req_approval_strict, "Strict mode must block immediately without asking for approval")
        self.assertIn("STRICT BLOCKED", reason_strict)

        # 2. Accessing a dangerous path in standard mode vs strict mode
        danger_cmd = "cat /etc/shadow"
        risk_danger_std, req_danger_std, reason_danger_std = CommandRiskClassifier.classify_command(danger_cmd, "linux", strict_mode=False)
        self.assertEqual(risk_danger_std, RiskLevel.HIGH)
        self.assertTrue(req_danger_std, "Standard mode requires confirmation before accessing sensitive path")

        risk_danger_strict, req_danger_strict, reason_danger_strict = CommandRiskClassifier.classify_command(danger_cmd, "linux", strict_mode=True)
        self.assertEqual(risk_danger_strict, RiskLevel.CRITICAL)
        self.assertFalse(req_danger_strict, "Strict mode must block immediately without asking")
        self.assertIn("STRICT BLOCKED", reason_danger_strict)

    def test_generate_security_policy_rule_content(self):
        """Verify markdown rule generation for all OS platforms."""
        for os_name in ("linux", "windows", "macos"):
            content_std = SecurityPolicyManager.generate_security_policy_rule(os_name, strict_mode=False)
            self.assertIn(os_name.upper(), content_std)
            self.assertIn("30 requests per minute", content_std)
            self.assertIn("30 seconds max", content_std)
            self.assertIn("MANDATORY CONFIRMATION", content_std)

            content_strict = SecurityPolicyManager.generate_security_policy_rule(os_name, strict_mode=True)
            self.assertIn("STRICT RESTRICTIVE MODE", content_strict)
            self.assertIn("STRICT DENIAL", content_strict)
            self.assertIn("DENIED PATTERNS", content_strict)


if __name__ == "__main__":
    unittest.main()
