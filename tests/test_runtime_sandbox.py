"""Unit test suite for Runtime Sandbox & Process Isolation Engine."""

import unittest
import shutil
from pathlib import Path
from src.core.runtime_sandbox import RuntimeSandboxManager, SandboxProfile, BLOCKED_SSRF_ENDPOINTS, DANGEROUS_SYSCALLS_DENIED


class TestRuntimeSandboxManager(unittest.TestCase):
    def setUp(self):
        self.sm = RuntimeSandboxManager()
        self.profile = SandboxProfile(
            tool_name="test-agent",
            workspace_dir=Path("/home/user/project"),
            allow_network=False
        )

    def test_ssrf_endpoints_present(self):
        """Verify standard AWS, GCP, Alibaba, and ECS metadata endpoints are defined."""
        self.assertIn("169.254.169.254", BLOCKED_SSRF_ENDPOINTS)
        self.assertIn("metadata.google.internal", BLOCKED_SSRF_ENDPOINTS)
        self.assertIn("100.100.100.200", BLOCKED_SSRF_ENDPOINTS)

    def test_dangerous_syscalls_list(self):
        """Verify critical dangerous kernel syscalls are denied."""
        self.assertIn("ptrace", DANGEROUS_SYSCALLS_DENIED)
        self.assertIn("mount", DANGEROUS_SYSCALLS_DENIED)
        self.assertIn("chroot", DANGEROUS_SYSCALLS_DENIED)
        self.assertIn("reboot", DANGEROUS_SYSCALLS_DENIED)

    def test_seccomp_filter_spec_generation(self):
        """Seccomp filter spec must return valid SCMP_ACT_ERRNO on denied syscalls."""
        spec = self.sm.generate_seccomp_filter_spec(self.profile)
        self.assertEqual(spec["defaultAction"], "SCMP_ACT_ALLOW")
        self.assertTrue(len(spec["syscalls"]) > 0)
        self.assertEqual(spec["syscalls"][0]["action"], "SCMP_ACT_ERRNO")
        self.assertIn("ptrace", spec["syscalls"][0]["names"])

    def test_landlock_rules_generation(self):
        """Landlock rules must restrict workspace and system paths."""
        rules = self.sm.generate_landlock_rules(self.profile)
        self.assertEqual(rules["version"], 1)
        self.assertTrue(len(rules["rules"]) >= 3)
        paths = [r["path"] for r in rules["rules"]]
        self.assertIn(str(self.profile.workspace_dir), paths)
        self.assertIn("/tmp", paths)
        self.assertIn("/usr", paths)

    def test_bubblewrap_command_construction(self):
        """Bubblewrap command builder should enforce unsharing and bind mounts."""
        cmd = self.sm.build_bubblewrap_command(["python", "script.py"], self.profile)
        self.assertIn("--unshare-pid", cmd)
        self.assertIn("--unshare-net", cmd)
        self.assertIn("--unshare-ipc", cmd)
        self.assertIn(str(self.profile.workspace_dir.resolve()), cmd)
        self.assertEqual(cmd[-2:], ["python", "script.py"])

    def test_ai_jail_command_construction(self):
        """ai-jail command builder should construct CLI invocation with workspace."""
        cmd = self.sm.build_ai_jail_command(["claude", "run"], self.profile)
        self.assertIn("--no-network", cmd)
        self.assertIn("--workspace", cmd)
        self.assertIn("--", cmd)
        self.assertEqual(cmd[-2:], ["claude", "run"])

    def test_get_sandbox_diagnostics(self):
        """Diagnostics should return dictionary with OS, bwrap, and seccomp information."""
        diag = self.sm.get_sandbox_diagnostics()
        self.assertIn("os", diag)
        self.assertIn("bubblewrap_available", diag)
        self.assertIn("ai_jail_available", diag)
        self.assertIn("seccomp_supported", diag)
        self.assertIn("landlock_supported", diag)


if __name__ == "__main__":
    unittest.main()
