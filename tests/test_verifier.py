"""Unit tests for Hardening Verification & Compliance Audit Engine."""

import unittest
import json
import shutil
from pathlib import Path

from src.core.verifier import HardeningVerifier
from src.core.models import HardeningPolicy, ToolMeta, OSPaths


class TestHardeningVerifier(unittest.TestCase):
    def setUp(self):
        self.verifier = HardeningVerifier()
        self.test_dir = Path(__file__).resolve().parent / ".tmp_verifier_test"
        self.test_dir.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        if self.test_dir.exists():
            shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_verify_compliant_configuration(self):
        """Verifier should report compliance when settings match policy."""
        settings_file = self.test_dir / "settings.json"
        settings_file.write_text(json.dumps({
            "telemetry.enabled": False,
            "enableTerminalSandbox": True,
            "allowNonWorkspaceAccess": False
        }), encoding="utf-8")

        mock_policy = HardeningPolicy(
            schema_version="1.0",
            tool=ToolMeta(name="test-tool", vendor="test-vendor", category="cli", description="Test"),
            paths={
                self.verifier.os_type: OSPaths(settings_file=str(settings_file))
            },
            policies={
                "native_settings_override": {
                    "telemetry.enabled": False,
                    "enableTerminalSandbox": True,
                    "allowNonWorkspaceAccess": False
                }
            },
            is_installed=True
        )

        report = self.verifier.verify_policy(mock_policy)
        self.assertGreaterEqual(report.compliance_score, 75.0)
        self.assertTrue(report.settings_file_exists)
        self.assertEqual(sum(1 for c in report.checks if not c.passed and c.key != "env_do_not_track"), 0)

    def test_claude_code_verification_standard_and_strict(self):
        """Verifier should audit standard and strict Claude Code configurations."""
        from src.core.config_loader import ConfigLoader
        from src.core.engine import HardeningEngine
        loader = ConfigLoader()
        claude_policy = loader.get_policy("anthropic", "claude-code")
        self.assertIsNotNone(claude_policy)

        settings_file = self.test_dir / "claude_verify_settings.json"
        claude_policy.paths[self.verifier.os_type] = OSPaths(settings_file=str(settings_file))
        engine = HardeningEngine()

        # 1. Apply standard mode and verify
        engine.apply_policy(claude_policy, dry_run=False, strict_mode=False)
        report_std = self.verifier.verify_policy(claude_policy, strict_mode=False)
        self.assertGreaterEqual(report_std.compliance_score, 90.0)

        # 2. Apply strict mode and verify
        engine.apply_policy(claude_policy, dry_run=False, strict_mode=True)
        report_strict = self.verifier.verify_policy(claude_policy, strict_mode=True)
        self.assertGreaterEqual(report_strict.compliance_score, 90.0)

    def test_unified_zai_verification_standard_and_strict(self):
        """Verifier should audit standard and strict unified zAI configurations across multi-location settings."""
        from src.core.config_loader import ConfigLoader
        from src.core.engine import HardeningEngine
        loader = ConfigLoader()
        engine = HardeningEngine()

        zai_policy = loader.get_policy("zai", "zai")
        self.assertIsNotNone(zai_policy)

        cli_settings = self.test_dir / "zai_cli_settings.json"
        zcode_settings = self.test_dir / "zcode_settings.json"
        zai_policy.paths[self.verifier.os_type] = OSPaths(
            settings_file=str(cli_settings),
            secondary_settings_files=[str(zcode_settings)]
        )

        # 1. Apply standard mode and verify across both locations
        res_std = engine.apply_policy(zai_policy, dry_run=False, strict_mode=False)
        self.assertTrue(res_std.success)
        self.assertTrue(cli_settings.exists())
        self.assertTrue(zcode_settings.exists())

        report_std = self.verifier.verify_policy(zai_policy, strict_mode=False)
        self.assertGreaterEqual(report_std.compliance_score, 90.0)

        # 2. Apply strict mode and verify
        res_strict = engine.apply_policy(zai_policy, dry_run=False, strict_mode=True)
        self.assertTrue(res_strict.success)
        report_strict = self.verifier.verify_policy(zai_policy, strict_mode=True)
        self.assertGreaterEqual(report_strict.compliance_score, 90.0)

    def test_windsurf_verification(self):
        """Verifier should audit Windsurf / Codeium configurations."""
        from src.core.config_loader import ConfigLoader
        from src.core.engine import HardeningEngine
        loader = ConfigLoader()
        engine = HardeningEngine()

        p = loader.get_policy("codeium", "windsurf")
        self.assertIsNotNone(p)

        settings = self.test_dir / "windsurf_settings.json"
        codeium_cfg = self.test_dir / "codeium_config.json"
        p.paths[self.verifier.os_type] = OSPaths(
            settings_file=str(settings),
            secondary_settings_files=[str(codeium_cfg)]
        )

        res = engine.apply_policy(p, dry_run=False, strict_mode=False)
        self.assertTrue(res.success)
        self.assertTrue(settings.exists())

        report = self.verifier.verify_policy(p, strict_mode=False)
        self.assertGreaterEqual(report.compliance_score, 90.0)


if __name__ == "__main__":
    unittest.main()
