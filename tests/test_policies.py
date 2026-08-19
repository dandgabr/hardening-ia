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


if __name__ == "__main__":
    unittest.main()
