"""Unit tests for Real-time Security Watchdog Daemon."""

import unittest
import json
import shutil
from pathlib import Path

from src.core.watchdog import SecurityWatchdog
from src.core.config_loader import ConfigLoader
from src.core.engine import HardeningEngine
from src.core.verifier import HardeningVerifier
from src.core.models import HardeningPolicy, ToolMeta, OSPaths


class TestSecurityWatchdog(unittest.TestCase):
    def setUp(self):
        self.test_dir = Path(__file__).resolve().parent / ".tmp_watchdog_test"
        self.test_dir.mkdir(parents=True, exist_ok=True)

        self.settings_file = self.test_dir / "watchdog_settings.json"
        self.settings_file.write_text(json.dumps({
            "telemetry.enabled": False,
            "mcp.requireConsent": True
        }), encoding="utf-8")

        self.mock_policy = HardeningPolicy(
            schema_version="1.0",
            tool=ToolMeta(name="watchdog-tool", vendor="test-vendor", category="cli", description="Test"),
            paths={
                "linux": OSPaths(settings_file=str(self.settings_file)),
                "macos": OSPaths(settings_file=str(self.settings_file)),
                "windows": OSPaths(settings_file=str(self.settings_file))
            },
            policies={
                "native_settings_override": {
                    "telemetry.enabled": False,
                    "mcp.requireConsent": True
                }
            },
            is_installed=True
        )

        class MockLoader:
            def __init__(self, p):
                self.p = p
            def load_all_policies(self):
                return [self.p]

        self.mock_loader = MockLoader(self.mock_policy)
        self.watchdog = SecurityWatchdog(
            config_loader=self.mock_loader,
            poll_interval=0.1,
            auto_remediate=False,
            installed_only=False
        )

    def tearDown(self):
        if self.test_dir.exists():
            shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_compute_file_hash_and_initialize(self):
        """Watchdog should compute SHA-256 hashes and track monitored paths."""
        h = self.watchdog.compute_file_hash(self.settings_file)
        self.assertIsNotNone(h)
        self.assertEqual(len(h), 64)

        hashes = self.watchdog.initialize_fingerprints()
        self.assertIn(str(self.settings_file), hashes)

    def test_detect_configuration_drift(self):
        """Watchdog should detect unauthorized modifications to configuration files."""
        self.watchdog.initialize_fingerprints()

        # Tamper with file (enable telemetry)
        self.settings_file.write_text(json.dumps({
            "telemetry.enabled": True,
            "mcp.requireConsent": True
        }), encoding="utf-8")

        drifts = self.watchdog.scan_cycle()
        self.assertGreaterEqual(len(drifts), 1)
        self.assertEqual(drifts[0]["tool"], "test-vendor/watchdog-tool")
        self.assertFalse(drifts[0]["remediated"])

    def test_auto_remediation_workflow(self):
        """When auto_remediate is enabled, watchdog should automatically restore compliance."""
        self.watchdog.auto_remediate = True
        self.watchdog.initialize_fingerprints()

        # Tamper with file
        self.settings_file.write_text(json.dumps({
            "telemetry.enabled": True,
            "mcp.requireConsent": False
        }), encoding="utf-8")

        drifts = self.watchdog.scan_cycle()
        self.assertGreaterEqual(len(drifts), 1)
        self.assertTrue(drifts[0]["remediated"])

        # Check that file was patched back
        patched_data = json.loads(self.settings_file.read_text(encoding="utf-8"))
        self.assertEqual(patched_data["telemetry.enabled"], False)


if __name__ == "__main__":
    unittest.main()
