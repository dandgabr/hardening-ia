"""Unit test suite for validating all 14 YAML hardening policies."""

import unittest
from src.core.config_loader import ConfigLoader


class TestHardeningPolicies(unittest.TestCase):
    def setUp(self):
        self.loader = ConfigLoader()
        self.policies = self.loader.discover_policies()

    def test_total_policies_count(self):
        """Ensure all 14 AI tools have discovered policy configurations."""
        self.assertEqual(len(self.policies), 14, "Expected exactly 14 AI tool policies.")

    def test_required_fields_presence(self):
        """Ensure every policy defines schema, tool metadata, paths, and policies."""
        for p in self.policies:
            self.assertIsNotNone(p.tool.name, f"Policy missing tool name: {p}")
            self.assertIsNotNone(p.tool.vendor, f"Policy missing vendor: {p}")
            self.assertIn(p.tool.category, ["cli", "ide", "agentic", "extension", "security"], f"Invalid category for {p.tool.name}")

            # Paths check
            self.assertIn("windows", p.paths, f"Missing Windows paths in {p.tool.name}")
            self.assertIn("linux", p.paths, f"Missing Linux paths in {p.tool.name}")
            self.assertIn("macos", p.paths, f"Missing macOS paths in {p.tool.name}")

            # Policies check
            self.assertIn("telemetry", p.policies, f"Missing telemetry policy in {p.tool.name}")
            self.assertIn("native_settings_override", p.policies, f"Missing native overrides in {p.tool.name}")

    def test_zero_telemetry_enforced(self):
        """Ensure all policies disable telemetry by default."""
        for p in self.policies:
            telemetry_enabled = p.policies.get("telemetry", {}).get("enable_telemetry", True)
            self.assertFalse(telemetry_enabled, f"Telemetry must be disabled by default in {p.tool.name}")

    def test_claude_code_security_controls(self):
        """Ensure Claude Code policy contains all Anthropic security controls in standard and strict modes."""
        claude_policy = next((p for p in self.policies if p.tool.name == "claude-code"), None)
        self.assertIsNotNone(claude_policy, "Claude Code policy must be present in discovered policies.")

        native = claude_policy.policies.get("native_settings_override", {})
        strict = claude_policy.policies.get("strict_rules", {}).get("native_overrides", {})

        # Permissions baseline
        self.assertEqual(native.get("permissions", {}).get("defaultMode"), "manual")
        self.assertEqual(native.get("permissions", {}).get("disableBypassPermissionsMode"), "disable")
        self.assertEqual(native.get("permissions", {}).get("disableAutoMode"), "disable")
        
        # Deny rules must include WebDAV/UNC, SSRF metadata, and sandbox bypass
        deny_list = native.get("permissions", {}).get("deny", [])
        self.assertIn("Read(\\\\*)", deny_list)
        self.assertIn("WebFetch(domain:169.254.169.254)", deny_list)
        self.assertIn("Bash(dangerouslyDisableSandbox:true)", deny_list)

        # Sandbox standard mode
        self.assertTrue(native.get("sandbox", {}).get("enabled"))
        self.assertFalse(native.get("sandbox", {}).get("allowUnsandboxedCommands"))
        self.assertTrue(native.get("sandbox", {}).get("autoAllowBashIfSandboxed"))
        self.assertFalse(native.get("sandbox", {}).get("network", {}).get("strictAllowlist"))

        # Sandbox strict mode overrides
        self.assertFalse(strict.get("sandbox", {}).get("autoAllowBashIfSandboxed"))
        self.assertTrue(strict.get("sandbox", {}).get("network", {}).get("strictAllowlist"))
        self.assertEqual(strict.get("permissions", {}).get("allow"), [])

        # Additional security flags
        self.assertTrue(native.get("permissionExplainerEnabled"))
        self.assertEqual(native.get("disableDeepLinkRegistration"), "disable")
        self.assertTrue(native.get("disableSkillShellExecution"))
        self.assertTrue(native.get("disableRemoteControl"))
        self.assertEqual(native.get("env", {}).get("DO_NOT_TRACK"), "1")
        self.assertEqual(native.get("env", {}).get("CLAUDE_CODE_SUBPROCESS_ENV_SCRUB"), "1")


if __name__ == "__main__":
    unittest.main()

