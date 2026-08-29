"""Unit test suite for validating all 21 YAML hardening policies."""

import unittest
from src.core.config_loader import ConfigLoader


class TestHardeningPolicies(unittest.TestCase):
    def setUp(self):
        self.loader = ConfigLoader()
        self.policies = self.loader.discover_policies()

    def test_total_policies_count(self):
        """Ensure all 21 AI tools have discovered policy configurations."""
        self.assertEqual(len(self.policies), 21, f"Expected exactly 21 AI tool policies, got {len(self.policies)}")

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

    def test_antigravity_security_controls(self):
        """Ensure Google Antigravity policy contains MCP, subagents, and sandbox guardrails."""
        antigravity_policy = next((p for p in self.policies if p.tool.name == "antigravity"), None)
        self.assertIsNotNone(antigravity_policy)
        native = antigravity_policy.policies.get("native_settings_override", {})
        self.assertFalse(native.get("telemetry.enabled"))
        self.assertTrue(native.get("enableTerminalSandbox"))
        self.assertFalse(native.get("allowNonWorkspaceAccess"))
        self.assertTrue(native.get("mcp.requireConsent"))
        self.assertFalse(native.get("mcp.allowUnsandboxedServers"))
        self.assertTrue(native.get("subagents.requireParentApproval"))
        self.assertFalse(native.get("subagents.allowAutonomousSpawning"))
        self.assertTrue(native.get("dlp.maskSecrets"))

    def test_cursor_security_controls(self):
        """Ensure Cursor policy disables YOLO auto-execution and enables privacy/MCP controls."""
        cursor_policy = next((p for p in self.policies if p.tool.name == "cursor"), None)
        self.assertIsNotNone(cursor_policy)
        native = cursor_policy.policies.get("native_settings_override", {})
        self.assertTrue(native.get("cursor.privacyMode"))
        self.assertEqual(native.get("cursor.general.privacy"), "no-retention")
        self.assertFalse(native.get("cursor.agent.yoloMode"))
        self.assertFalse(native.get("cursor.composer.autoApply"))
        self.assertTrue(native.get("cursor.mcp.requireConsent"))
        self.assertTrue(native.get("cursor.terminal.sandbox"))
        self.assertIn("**/.docker/config.json", native.get("cursor.indexer.ignorePatterns", []))

    def test_copilot_security_controls(self):
        """Ensure GitHub Copilot policy restricts auto-approvals and terminal commands."""
        copilot_policy = next((p for p in self.policies if p.tool.name == "copilot"), None)
        self.assertIsNotNone(copilot_policy)
        native = copilot_policy.policies.get("native_settings_override", {})
        self.assertFalse(native.get("chat.tools.global.autoApprove"))
        self.assertEqual(native.get("chat.tools.eligibleForAutoApproval"), [])
        self.assertEqual(native.get("chat.tools.confirm"), "always")
        self.assertFalse(native.get("github.copilot.chat.terminal.autoExecute"))
        self.assertFalse(native.get("github.copilot.chat.autoApplyEdits"))

    def test_cline_security_controls(self):
        """Ensure Cline policy enforces autoApprove mode never and MCP consent."""
        cline_policy = next((p for p in self.policies if p.tool.name == "cline"), None)
        self.assertIsNotNone(cline_policy)
        native = cline_policy.policies.get("native_settings_override", {})
        self.assertEqual(native.get("autoApprove.mode"), "never")
        self.assertFalse(native.get("autoApproveExecution"))
        self.assertTrue(native.get("mcp.requireConsent"))
        self.assertFalse(native.get("mcp.autoApprove"))
        self.assertFalse(native.get("diff.autoApply"))

    def test_unified_zai_security_controls(self):
        """Ensure unified zAI Developer Platform policy contains CLI, ADE Desktop, MCP, and DLP controls across primary and secondary paths."""
        zai_policy = next((p for p in self.policies if p.tool.name == "zai"), None)
        self.assertIsNotNone(zai_policy)
        self.assertEqual(zai_policy.tool.vendor, "zai")

        linux_paths = zai_policy.paths.get("linux")
        self.assertIsNotNone(linux_paths)
        self.assertIn("~/.config/zai/config.json", linux_paths.settings_file)
        self.assertTrue(any("~/.zcode" in s for s in linux_paths.secondary_settings_files))
        self.assertTrue(any("~/.zcode/rules" in r for r in linux_paths.secondary_rules_dirs))

        # Alias lookup test
        self.assertIsNotNone(self.loader.get_policy("zai", "zai-cli"))
        self.assertIsNotNone(self.loader.get_policy("zai", "zcode"))

    def test_windsurf_security_controls(self):
        """Ensure Windsurf policy enforces privacyMode, Cascade approval, and MCP consent."""
        p = self.loader.get_policy("codeium", "windsurf")
        self.assertIsNotNone(p)
        native = p.policies.get("native_settings_override", {})
        self.assertTrue(native.get("windsurf.privacyMode"))
        self.assertFalse(native.get("windsurf.cascade.autoExecute"))
        self.assertFalse(native.get("windsurf.cascade.yoloMode"))
        self.assertTrue(native.get("windsurf.cascade.requireApproval"))
        self.assertTrue(native.get("mcp.requireConsent"))
        self.assertEqual(native.get("telemetry.telemetryLevel"), "off")

    def test_continue_security_controls(self):
        """Ensure Continue.dev policy enforces zero telemetry and prompt secret masking."""
        p = self.loader.get_policy("continuedev", "continue")
        self.assertIsNotNone(p)
        native = p.policies.get("native_settings_override", {})
        self.assertFalse(native.get("allowAnonymousTelemetry"))
        self.assertTrue(native.get("maskSecretsInPrompts"))
        self.assertTrue(native.get("blockLocalSSRF"))
        self.assertTrue(native.get("mcp.requireConsent"))

    def test_aider_security_controls(self):
        """Ensure Aider policy disables analytics, verifies SSL, and requires push confirmation."""
        p = self.loader.get_policy("aider", "aider")
        self.assertIsNotNone(p)
        native = p.policies.get("native_settings_override", {})
        self.assertFalse(native.get("analytics"))
        self.assertTrue(native.get("verify-ssl"))
        self.assertTrue(native.get("auto-commits"))
        self.assertTrue(native.get("require-confirmation-on-push"))
        self.assertTrue(native.get("mask-api-keys"))

    def test_amazon_q_security_controls(self):
        """Ensure Amazon Q Developer policy opts out of training and requires command approvals."""
        p = self.loader.get_policy("amazon", "amazon-q")
        self.assertIsNotNone(p)
        native = p.policies.get("native_settings_override", {})
        self.assertFalse(native.get("telemetry.enabled"))
        self.assertFalse(native.get("amazonQ.shareCodeForTraining"))
        self.assertFalse(native.get("amazonQ.autoExecuteCommands"))
        self.assertTrue(native.get("amazonQ.requireUserApproval"))

    def test_tabnine_security_controls(self):
        """Ensure Tabnine policy enforces local models and disables cloud sharing."""
        p = self.loader.get_policy("tabnine", "tabnine")
        self.assertIsNotNone(p)
        native = p.policies.get("native_settings_override", {})
        self.assertFalse(native.get("cloud_sharing_enabled"))
        self.assertFalse(native.get("anonymous_telemetry"))
        self.assertTrue(native.get("enterprise_mode"))
        self.assertTrue(native.get("local_model_only"))
        self.assertTrue(native.get("mask_secrets"))

    def test_augment_security_controls(self):
        """Ensure Augment Code policy opts out of code training and enables sandboxing."""
        p = self.loader.get_policy("augment", "augment")
        self.assertIsNotNone(p)
        native = p.policies.get("native_settings_override", {})
        self.assertFalse(native.get("telemetry.enabled"))
        self.assertTrue(native.get("code_training_opt_out"))
        self.assertTrue(native.get("require_write_confirmation"))
        self.assertTrue(native.get("mask_detected_secrets"))
        self.assertTrue(native.get("sandbox_isolation"))


if __name__ == "__main__":
    unittest.main()
