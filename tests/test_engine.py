"""Unit tests for Hardening Engine apply and remove/rollback operations."""

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

    def test_apply_and_remove_policy_lifecycle(self):
        """Engine should apply overrides and cleanly remove them upon rollback."""
        settings_file = self.test_dir / "settings.json"
        settings_file.write_text(json.dumps({
            "existing_user_setting": "keep_me"
        }), encoding="utf-8")

        mock_policy = HardeningPolicy(
            schema_version="1.0",
            tool=ToolMeta(name="engine-test-tool", vendor="test-vendor", category="cli", description="Test"),
            paths={
                self.engine.os_type: OSPaths(settings_file=str(settings_file))
            },
            policies={
                "native_settings_override": {
                    "telemetry.enabled": False,
                    "enableSandbox": True
                }
            },
            is_installed=True
        )

        # 1. Apply Policy
        apply_res = self.engine.apply_policy(mock_policy, dry_run=False)
        self.assertTrue(apply_res.success)
        self.assertEqual(len(apply_res.diffs), 2)

        content = json.loads(settings_file.read_text(encoding="utf-8"))
        self.assertFalse(content["telemetry.enabled"])
        self.assertTrue(content["enableSandbox"])
        self.assertEqual(content["existing_user_setting"], "keep_me")

        # 2. Remove Policy
        remove_res = self.engine.remove_policy(mock_policy, dry_run=False)
        self.assertTrue(remove_res.success)
        self.assertEqual(len(remove_res.diffs), 2)

        content_after = json.loads(settings_file.read_text(encoding="utf-8"))
        self.assertNotIn("telemetry.enabled", content_after)
        self.assertNotIn("enableSandbox", content_after)
        self.assertEqual(content_after["existing_user_setting"], "keep_me")


if __name__ == "__main__":
    unittest.main()
