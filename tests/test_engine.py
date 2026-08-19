"""Unit tests for Hardening Engine backup, apply, and surgical rollback operations."""

import unittest
import json
import shutil
from pathlib import Path

from src.core.engine import HardeningEngine
from src.core.models import HardeningPolicy, ToolMeta, OSPaths


class TestHardeningEngine(unittest.TestCase):
    def setUp(self):
        self.engine = HardeningEngine()
        self.test_dir = Path(__file__).resolve().parent / ".tmp_engine_test"
        self.test_dir.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        if self.test_dir.exists():
            shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_apply_and_surgical_rollback_preserves_custom_providers(self):
        """
        Verify that applying hardening creates backups, and removing hardening
        restores original settings while preserving all custom AI providers, API keys, and user settings.
        """
        settings_file = self.test_dir / "settings.json"
        
        # Initial user configuration with custom AI providers, custom keys, and themes
        initial_config = {
            "workbench.colorTheme": "Catppuccin Mocha",
            "editor.fontSize": 14,
            "openai.apiKey": "sk-user-custom-key-12345",
            "anthropic.apiKey": "sk-ant-custom-key-67890",
            "custom.aiProviders": [
                {"name": "Ollama Local", "url": "http://localhost:11434"},
                {"name": "OpenRouter", "model": "anthropic/claude-3.5-sonnet"}
            ],
            "telemetry.enabled": True  # User had telemetry ON before hardening
        }
        settings_file.write_text(json.dumps(initial_config, indent=2), encoding="utf-8")

        mock_policy = HardeningPolicy(
            schema_version="1.0",
            tool=ToolMeta(name="test-engine-tool", vendor="test-vendor", category="cli", description="Test"),
            paths={
                self.engine.os_type: OSPaths(settings_file=str(settings_file))
            },
            policies={
                "native_settings_override": {
                    "telemetry.enabled": False,        # Should override True -> False
                    "security.enableSandbox": True     # Should inject new key
                }
            },
            is_installed=True
        )

        # 1. APPLY HARDENING
        apply_res = self.engine.apply_policy(mock_policy, dry_run=False)
        self.assertTrue(apply_res.success)

        hardened_config = json.loads(settings_file.read_text(encoding="utf-8"))
        self.assertFalse(hardened_config["telemetry.enabled"])
        self.assertTrue(hardened_config["security.enableSandbox"])
        # Custom providers must be preserved
        self.assertEqual(hardened_config["openai.apiKey"], "sk-user-custom-key-12345")
        self.assertEqual(hardened_config["anthropic.apiKey"], "sk-ant-custom-key-67890")
        self.assertEqual(len(hardened_config["custom.aiProviders"]), 2)

        # Verify backup files were created in backups/
        backup_dir = self.engine._get_tool_backup_dir("test-vendor", "test-engine-tool")
        self.assertTrue((backup_dir / "settings_backup_latest.json").exists())
        self.assertTrue((backup_dir / "restore_manifest.json").exists())

        # 2. REMOVE / REVERT HARDENING
        remove_res = self.engine.remove_policy(mock_policy, dry_run=False)
        self.assertTrue(remove_res.success)

        restored_config = json.loads(settings_file.read_text(encoding="utf-8"))
        # Injected key removed
        self.assertNotIn("security.enableSandbox", restored_config)
        # Overridden key restored to exact original value (True)
        self.assertTrue(restored_config["telemetry.enabled"])
        # All custom providers and user settings remain 100% intact
        self.assertEqual(restored_config["workbench.colorTheme"], "Catppuccin Mocha")
        self.assertEqual(restored_config["editor.fontSize"], 14)
        self.assertEqual(restored_config["openai.apiKey"], "sk-user-custom-key-12345")
        self.assertEqual(restored_config["anthropic.apiKey"], "sk-ant-custom-key-67890")
        self.assertEqual(len(restored_config["custom.aiProviders"]), 2)


if __name__ == "__main__":
    unittest.main()
