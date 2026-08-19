"""Unit tests for Enterprise Administrator System-Wide Hardening & Permissions Locking."""

import unittest
import json
import shutil
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

from src.core.admin_manager import AdminManager
from src.core.models import HardeningPolicy, ToolMeta, OSPaths


class TestAdminManager(unittest.TestCase):
    def setUp(self):
        self.admin_mgr = AdminManager()
        self.test_dir = Path(tempfile.mkdtemp(prefix="admin_mgr_test_"))

    def tearDown(self):
        if self.test_dir.exists():
            shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_check_admin_privileges_boolean(self):
        """Privilege check must return a valid boolean."""
        res = self.admin_mgr.check_admin_privileges()
        self.assertIsInstance(res, bool)

    def test_get_all_user_profiles_returns_paths(self):
        """User profile discovery must return a non-empty list of valid Path objects."""
        profiles = self.admin_mgr.get_all_user_profiles()
        self.assertIsInstance(profiles, list)
        self.assertGreater(len(profiles), 0)
        for p in profiles:
            self.assertIsInstance(p, Path)

    def test_resolve_user_tool_path(self):
        """Path templates with ~ or environment variables must be resolved relative to user home."""
        user_home = Path("/home/testuser")
        if self.admin_mgr.os_type == "windows":
            resolved = self.admin_mgr.resolve_user_tool_path("%USERPROFILE%\\.gemini\\settings.json", user_home)
            self.assertEqual(resolved, user_home / ".gemini" / "settings.json")
        else:
            resolved = self.admin_mgr.resolve_user_tool_path("~/.gemini/settings.json", user_home)
            self.assertEqual(resolved, user_home / ".gemini" / "settings.json")

    def test_apply_admin_read_only_permissions_dry_run(self):
        """Dry-run permissions application returns success message without error."""
        test_file = self.test_dir / "test.json"
        test_file.write_text("{}", encoding="utf-8")

        ok, msg = self.admin_mgr.apply_admin_read_only_permissions(test_file, dry_run=True)
        self.assertTrue(ok)
        self.assertIn("DRY RUN", msg)

    @patch.object(AdminManager, "check_admin_privileges", return_value=True)
    def test_apply_admin_system_wide_policy(self, mock_is_admin):
        """AdminManager must deploy settings across discovered user directories and lock them."""
        user1 = self.test_dir / "user1"
        user2 = self.test_dir / "user2"
        user1.mkdir()
        user2.mkdir()

        with patch.object(self.admin_mgr, "get_all_user_profiles", return_value=[user1, user2]):
            mock_policy = HardeningPolicy(
                schema_version="1.0",
                tool=ToolMeta(name="antigravity", vendor="google", category="agentic", description="Test"),
                paths={
                    self.admin_mgr.os_type: OSPaths(
                        settings_file="~/.gemini/antigravity-cli/settings.json",
                        rules_dir="~/.gemini/antigravity-cli/rules"
                    )
                },
                policies={
                    "native_settings_override": {
                        "telemetry.enabled": False,
                        "enableTerminalSandbox": True
                    },
                    "strict_rules": {
                        "native_overrides": {
                            "autoApplyEdits": False
                        }
                    }
                },
                is_installed=True
            )

            res = self.admin_mgr.apply_admin_system_wide_policy(mock_policy, strict_mode=True, dry_run=False)
            self.assertEqual(res["users_count"], 2)

            # Check that settings.json was written for user1 and user2
            s1 = user1 / ".gemini" / "antigravity-cli" / "settings.json"
            s2 = user2 / ".gemini" / "antigravity-cli" / "settings.json"
            self.assertTrue(s1.exists())
            self.assertTrue(s2.exists())

            data1 = json.loads(s1.read_text(encoding="utf-8"))
            self.assertEqual(data1.get("telemetry.enabled"), False)
            self.assertEqual(data1.get("autoApplyEdits"), False)
            self.assertEqual(data1.get("security.strict_mode"), True)

    @patch.object(AdminManager, "check_admin_privileges", return_value=False)
    def test_elevation_required_exception(self, mock_is_admin):
        """Attempting system-wide enforcement without elevation must raise PermissionError."""
        mock_policy = HardeningPolicy(
            schema_version="1.0",
            tool=ToolMeta(name="antigravity", vendor="google", category="agentic", description="Test"),
            paths={},
            policies={},
            is_installed=True
        )
        with self.assertRaises(PermissionError):
            self.admin_mgr.apply_admin_system_wide_policy(mock_policy)


if __name__ == "__main__":
    unittest.main()
