"""Generates detailed English tool documentation under docs/tools/ mapping all official security keys."""

from pathlib import Path

TOOL_DOCS = [
    {
        "vendor": "google",
        "name": "antigravity",
        "title": "Google Antigravity Security & Hardening Guide",
        "category": "Agentic Platform (CLI, IDE, MCP, SDK)",
        "summary": "Google Antigravity is an agent-first developer platform featuring IDE workspace orchestration, CLI execution, subagents, and Model Context Protocol (MCP) integrations.",
        "settings_map": [
            {"key": "toolPermissions", "default_hardened": "'request-review'", "purpose": "Ensures the agent prompts for approval on all mutating actions."},
            {"key": "enableTerminalSandbox", "default_hardened": "true", "purpose": "Restricts agent-initiated terminal commands to a secure OS container."},
            {"key": "allowNonWorkspaceAccess", "default_hardened": "false", "purpose": "Blocks the agent from accessing files outside defined project directories."},
            {"key": "hooks.enforceGuardrails", "default_hardened": "true", "purpose": "Enforces deterministic security checks before/after tool calls."},
            {"key": "mcp.requireConsent", "default_hardened": "true", "purpose": "Mandates user confirmation before executing Model Context Protocol tools."},
            {"key": "mcp.allowUnsandboxedServers", "default_hardened": "false", "purpose": "Prohibits execution of MCP servers outside the sandbox container."},
            {"key": "subagents.requireParentApproval", "default_hardened": "true", "purpose": "Ensures child subagents cannot perform mutating tasks without verification."},
            {"key": "subagents.allowAutonomousSpawning", "default_hardened": "false", "purpose": "Prevents runaway recursion in subagent task spawning."},
            {"key": "dlp.maskSecrets", "default_hardened": "true", "purpose": "Masks API keys, tokens, and credentials in prompt context pipelines."},
            {"key": "telemetry.enabled", "default_hardened": "false", "purpose": "Disables usage and prompt transmission to external telemetry."},
            {"key": "crashReporting.enabled", "default_hardened": "false", "purpose": "Prevents memory dumps from sending code fragments to external servers."}
        ]
    },
    {
        "vendor": "anthropic",
        "name": "claude-code",
        "title": "Claude Code CLI Security & Hardening Guide",
        "category": "CLI Agent & Enterprise Sandboxing",
        "summary": "Claude Code is an agentic terminal coding assistant capable of editing repositories, running bash commands, managing development workflows, and executing in OS-level sandboxes.",
        "settings_map": [
            {"key": "permissions.defaultMode", "default_hardened": "'manual'", "purpose": "Prompts for confirmation on all terminal and filesystem actions."},
            {"key": "permissions.disableBypassPermissionsMode", "default_hardened": "'disable'", "purpose": "Disallows '--dangerously-skip-permissions' flag and bypass mode."},
            {"key": "permissions.disableAutoMode", "default_hardened": "'disable'", "purpose": "Blocks autonomous execution without supervision."},
            {"key": "permissions.deny", "default_hardened": "[destructive commands, DLP secrets, WebDAV \\*, SSRF metadata]", "purpose": "Explicit deny list rejecting risky operations without prompting."},
            {"key": "permissions.ask", "default_hardened": "['Bash(*)', 'PowerShell(*)', 'Edit(*)', 'Write(*)', 'WebFetch(*)']", "purpose": "Human-in-the-loop confirmation on all mutating operations."},
            {"key": "sandbox.enabled", "default_hardened": "true", "purpose": "Enforces OS process and filesystem sandboxing."},
            {"key": "sandbox.autoAllowBashIfSandboxed", "default_hardened": "true (standard) / false (strict)", "purpose": "Controls whether commands inside the sandbox auto-execute or require human confirmation."},
            {"key": "sandbox.allowUnsandboxedCommands", "default_hardened": "false", "purpose": "Blocks fallback to 'dangerouslyDisableSandbox' when a command fails."},
            {"key": "sandbox.failIfUnavailable", "default_hardened": "true", "purpose": "Halts execution if sandbox dependencies (bubblewrap, socat, seatbelt) are unavailable."},
            {"key": "sandbox.network.strictAllowlist", "default_hardened": "false (standard) / true (strict)", "purpose": "In strict mode, automatically denies any network access outside allowedDomains without prompting."},
            {"key": "sandbox.network.deniedDomains", "default_hardened": "['169.254.169.254', 'metadata.google.internal', 'localhost']", "purpose": "Blocks SSRF and cloud metadata access."},
            {"key": "sandbox.filesystem.denyWrite", "default_hardened": "[C:\\Windows, /etc, /boot, /root, /sys, /proc]", "purpose": "Isolates critical OS directories from modification."},
            {"key": "sandbox.filesystem.denyRead", "default_hardened": "[~/.ssh, ~/.aws, **/.env*, ~/.credentials.json]", "purpose": "Blocks sensitive credentials and API keys from file reading."},
            {"key": "permissionExplainerEnabled", "default_hardened": "true", "purpose": "Enables Ctrl+E risk analysis in interactive confirmation prompts."},
            {"key": "disableDeepLinkRegistration", "default_hardened": "'disable'", "purpose": "Blocks registration of 'claude-cli://' URL scheme handlers."},
            {"key": "disableSkillShellExecution", "default_hardened": "true", "purpose": "Disables inline shell execution in custom skills and prompts."},
            {"key": "disableRemoteControl", "default_hardened": "true", "purpose": "Blocks remote web-to-CLI control sessions."},
            {"key": "env.DO_NOT_TRACK", "default_hardened": "'1'", "purpose": "Opt-out from usage and interaction tracking."},
            {"key": "env.CLAUDE_CODE_SUBPROCESS_ENV_SCRUB", "default_hardened": "'1'", "purpose": "Strips sensitive credentials from subprocess environments."}
        ]
    },
    {
        "vendor": "github",
        "name": "copilot",
        "title": "GitHub Copilot Security & Hardening Guide",
        "category": "IDE Extension & Copilot Chat/Edits",
        "summary": "GitHub Copilot provides real-time AI code completions, chat, and agentic edits in VS Code, JetBrains, and Visual Studio.",
        "settings_map": [
            {"key": "chat.tools.global.autoApprove", "default_hardened": "false", "purpose": "Disables automatic tool and command approval in Copilot Chat Agent mode."},
            {"key": "chat.tools.eligibleForAutoApproval", "default_hardened": "[]", "purpose": "Ensures no tools or shell actions are eligible for automatic bypass."},
            {"key": "chat.tools.confirm", "default_hardened": "'always'", "purpose": "Enforces interactive user confirmation before any tool execution."},
            {"key": "github.copilot.chat.terminal.autoExecute", "default_hardened": "false", "purpose": "Prevents Copilot from auto-running commands in the integrated terminal."},
            {"key": "github.copilot.chat.autoApplyEdits", "default_hardened": "false", "purpose": "Requires manual inspection of file diffs before changes are accepted."},
            {"key": "chat.agent.allowTerminal", "default_hardened": "false", "purpose": "Restricts autonomous terminal invocation by agent subroutines."},
            {"key": "github.copilot.enable.plaintext", "default_hardened": "false", "purpose": "Disables completions in unformatted text files."},
            {"key": "github.copilot.enable.markdown", "default_hardened": "false", "purpose": "Disables completions in markdown documents to prevent prompt injection."},
            {"key": "github.copilot.enable.scminput", "default_hardened": "false", "purpose": "Prevents AI completions in Git commit message fields."},
            {"key": "github.copilot.enable..env", "default_hardened": "false", "purpose": "Prevents code suggestions or context reading in environment secret files."},
            {"key": "telemetry.telemetryLevel", "default_hardened": "'off'", "purpose": "Disables editor and extension diagnostic telemetry."}
        ]
    },
    {
        "vendor": "anysphere",
        "name": "cursor",
        "title": "Cursor IDE Security & Hardening Guide",
        "category": "AI-Native IDE",
        "summary": "Cursor is an AI-powered code editor with agentic terminal execution, Composer multi-file editing, and codebase indexing.",
        "settings_map": [
            {"key": "cursor.privacyMode", "default_hardened": "true", "purpose": "Enforces Zero Data Retention (ZDR); code is not stored or used for model training."},
            {"key": "cursor.general.privacy", "default_hardened": "'no-retention'", "purpose": "Guarantees prompts and file contents are erased immediately after generation."},
            {"key": "cursor.agent.yoloMode", "default_hardened": "false", "purpose": "Explicitly disables YOLO unprompted auto-execution mode."},
            {"key": "cursor.composer.autoApply", "default_hardened": "false", "purpose": "Requires manual review before applying multi-file code modifications."},
            {"key": "cursor.composer.requireUserApproval", "default_hardened": "true", "purpose": "Mandates user confirmation on each Composer change set."},
            {"key": "cursor.mcp.requireConsent", "default_hardened": "true", "purpose": "Enforces interactive consent before invoking MCP server tools."},
            {"key": "cursor.terminal.autoExecute", "default_hardened": "false", "purpose": "Requires explicit approval before any shell command is run by the agent."},
            {"key": "cursor.terminal.sandbox", "default_hardened": "true", "purpose": "Enforces process isolation for terminal executions."},
            {"key": "cursor.indexer.ignorePatterns", "default_hardened": "[.env*, *.pem, *.key, ~/.ssh/**, ~/.aws/**, ~/.docker/**]", "purpose": "Prevents indexing sensitive secrets into the semantic database."}
        ]
    },
    {
        "vendor": "cline",
        "name": "cline",
        "title": "Cline Security & Hardening Guide",
        "category": "Agentic IDE Assistant",
        "summary": "Cline is an autonomous coding agent for VS Code capable of multi-step terminal, file, browser, and MCP tool execution.",
        "settings_map": [
            {"key": "autoApprove.mode", "default_hardened": "'never'", "purpose": "Strictly disables global auto-approval for all tool invocations."},
            {"key": "alwaysApproveResubmit", "default_hardened": "false", "purpose": "Requires operator consent on every retry loop."},
            {"key": "autoApproveExecution", "default_hardened": "false", "purpose": "Disables automated shell command execution without review."},
            {"key": "allowNonWorkspaceAccess", "default_hardened": "false", "purpose": "Blocks reading or writing files outside the open project directory."},
            {"key": "restrictSecretAccess", "default_hardened": "true", "purpose": "Excludes `.env` and credential files from context collection."},
            {"key": "mcp.requireConsent", "default_hardened": "true", "purpose": "Mandates approval before invoking local MCP server tools."},
            {"key": "diff.autoApply", "default_hardened": "false", "purpose": "Requires manual inspection of file diffs before saving to disk."}
        ]
    },
    {
        "vendor": "openai",
        "name": "codex",
        "title": "OpenAI Codex CLI Security & Hardening Guide",
        "category": "CLI Agent / Engine",
        "summary": "OpenAI Codex CLI provides automated code generation, refactoring, and command execution.",
        "settings_map": [
            {"key": "telemetry", "default_hardened": "false", "purpose": "Disables usage and prompt data sharing."},
            {"key": "code_telemetry", "default_hardened": "false", "purpose": "Prevents source code telemetry ingestion."},
            {"key": "auto_execute", "default_hardened": "false", "purpose": "Mandates confirmation before running shell commands."},
            {"key": "enforce_sandboxing", "default_hardened": "true", "purpose": "Restricts execution environment to local sandbox."},
            {"key": "trusted_workspaces_only", "default_hardened": "true", "purpose": "Blocks execution in untrusted external folders."},
            {"key": "prompt_secret_masking", "default_hardened": "true", "purpose": "Masks API keys and passwords in prompt pipelines."},
            {"key": "mcp_consent_required", "default_hardened": "true", "purpose": "Requires user confirmation for MCP server calls."}
        ]
    },
    {
        "vendor": "opencode",
        "name": "opencode",
        "title": "OpenCode Security & Hardening Guide",
        "category": "Open-Source CLI Agent",
        "summary": "OpenCode is an open-source terminal coding assistant executing local models and remote LLM APIs.",
        "settings_map": [
            {"key": "analytics.enabled", "default_hardened": "false", "purpose": "Disables telemetry metrics collection."},
            {"key": "agent.confirm_actions", "default_hardened": "true", "purpose": "Prompts operator before applying diffs or executing scripts."},
            {"key": "agent.auto_apply_edits", "default_hardened": "false", "purpose": "Disables automatic write operations on source files."},
            {"key": "permission_mode", "default_hardened": "'prompt'", "purpose": "Enforces human confirmation for each tool execution."},
            {"key": "sandbox.strict_mode", "default_hardened": "true", "purpose": "Enforces filesystem isolation and read-only container mount."},
            {"key": "dlp.mask_credentials", "default_hardened": "true", "purpose": "Redacts sensitive credentials from LLM context."}
        ]
    },
    {
        "vendor": "nousresearch",
        "name": "hermes-agent",
        "title": "Hermes Agent Security & Hardening Guide",
        "category": "Autonomous Agent",
        "summary": "Hermes Agent provides deep reasoning and autonomous tool execution with local memory persistence.",
        "settings_map": [
            {"key": "safe_mode", "default_hardened": "true", "purpose": "Enforces strict safety rails during multi-step reasoning."},
            {"key": "human_in_the_loop", "default_hardened": "true", "purpose": "Pauses execution to obtain operator confirmation on mutating tools."},
            {"key": "blocked_tools", "default_hardened": "['system_admin', 'raw_exec', 'disk_partition', 'network_raw']", "purpose": "Denies critical system tools."},
            {"key": "max_recursive_steps", "default_hardened": "10", "purpose": "Prevents infinite reasoning and tool invocation loops."},
            {"key": "network_egress_restricted", "default_hardened": "true", "purpose": "Restricts external network connectivity."}
        ]
    },
    {
        "vendor": "qoder",
        "name": "qoder",
        "title": "Qoder Security & Hardening Guide",
        "category": "Enterprise Agent",
        "summary": "Qoder is an enterprise coding companion providing semantic search and workflow automation.",
        "settings_map": [
            {"key": "telemetry.shareData", "default_hardened": "false", "purpose": "Disables enterprise codebase sharing."},
            {"key": "security.executionConsent", "default_hardened": "'always'", "purpose": "Requires approval on every automated action."},
            {"key": "security.autoApplyEdits", "default_hardened": "false", "purpose": "Requires confirmation before applying suggested diffs."},
            {"key": "mcp.requireUserConfirmation", "default_hardened": "true", "purpose": "Enforces consent before executing MCP tools."}
        ]
    },
    {
        "vendor": "kilo",
        "name": "kilo-code",
        "title": "Kilo Code Security & Hardening Guide",
        "category": "CLI Developer Suite",
        "summary": "Kilo Code is a command-line tool designed for fast code indexing and agentic refactoring.",
        "settings_map": [
            {"key": "privacy.telemetry", "default_hardened": "false", "purpose": "Disables usage and crash telemetry."},
            {"key": "execution.require_confirmation", "default_hardened": "true", "purpose": "Requires confirmation on file and shell operations."},
            {"key": "execution.auto_accept_edits", "default_hardened": "false", "purpose": "Prevents unprompted modification of code."},
            {"key": "mcp.requireConsent", "default_hardened": "true", "purpose": "Mandates user review of MCP actions."}
        ]
    },
    {
        "vendor": "clinepass",
        "name": "clinepass",
        "title": "ClinePass Security & Hardening Guide",
        "category": "Security Wrapper & Vault",
        "summary": "ClinePass provides managed authentication, an encrypted credential vault, and security proxy for Cline agents.",
        "settings_map": [
            {"key": "vault.enforce_encryption", "default_hardened": "true", "purpose": "Encrypts stored LLM API keys at rest."},
            {"key": "vault.zero_plaintext_cache", "default_hardened": "true", "purpose": "Prevents caching credentials in plaintext memory."},
            {"key": "proxy.block_unapproved_hosts", "default_hardened": "true", "purpose": "Blocks outgoing connections to unapproved endpoints."},
            {"key": "proxy.block_ssrf_metadata", "default_hardened": "true", "purpose": "Blocks SSRF requests to cloud metadata endpoints."}
        ]
    },
    {
        "vendor": "codebuddy",
        "name": "codebuddy",
        "title": "CodeBuddy Security & Hardening Guide",
        "category": "IDE Assistant",
        "summary": "CodeBuddy provides interactive code explanations and suggestions in the developer environment.",
        "settings_map": [
            {"key": "share_code_snippets", "default_hardened": "false", "purpose": "Disables snippet telemetry."},
            {"key": "telemetry", "default_hardened": "'off'", "purpose": "Disables tracking and diagnostic logging."},
            {"key": "auto_run_commands", "default_hardened": "false", "purpose": "Blocks automated shell command execution."},
            {"key": "auto_apply_diffs", "default_hardened": "false", "purpose": "Requires manual acceptance for code diffs."}
        ]
    },
    {
        "vendor": "moonshot",
        "name": "kimi",
        "title": "Kimi Security & Hardening Guide",
        "category": "CLI / Context Assistant",
        "summary": "Kimi CLI is an agentic assistant for processing large documents and codebases with Moonshot AI models.",
        "settings_map": [
            {"key": "telemetry.enabled", "default_hardened": "false", "purpose": "Disables interaction logging."},
            {"key": "privacy.data_retention", "default_hardened": "false", "purpose": "Ensures prompt data is not retained for model training."},
            {"key": "agent.auto_write", "default_hardened": "false", "purpose": "Requires user confirmation before writing files."},
            {"key": "prompt.mask_secrets", "default_hardened": "true", "purpose": "Masks detected tokens before transmission."}
        ]
    },
    {
        "vendor": "xai",
        "name": "grok",
        "title": "Grok / xAI Developer CLI Security & Hardening Guide",
        "category": "CLI Assistant",
        "summary": "Grok CLI connects developers with xAI models for reasoning and software generation.",
        "settings_map": [
            {"key": "telemetry", "default_hardened": "false", "purpose": "Disables user prompt analytics."},
            {"key": "share_prompts", "default_hardened": "false", "purpose": "Opt out of model retraining."},
            {"key": "auto_edit_files", "default_hardened": "false", "purpose": "Requires approval before writing changes to disk."},
            {"key": "sandbox_strict", "default_hardened": "true", "purpose": "Enforces strict process sandboxing."}
        ]
    },
    {
        "vendor": "zai",
        "name": "zai",
        "title": "z.ai Developer Platform (CLI, ADE & Desktop) Security & Hardening Guide",
        "category": "Unified Agentic Platform (CLI, ADE & Desktop)",
        "summary": "z.ai Developer Platform is a unified ecosystem providing an Autonomous CLI Coding Agent (zai-cli), an Agentic Development Environment (zcode ADE / Desktop), and IDE extensions powered by GLM models.",
        "settings_map": [
            {"key": "telemetry", "default_hardened": "false", "purpose": "Disables prompt analytics and interaction tracking across CLI and ADE."},
            {"key": "privacy.data_retention", "default_hardened": "false", "purpose": "Enforces zero data retention for source code and prompts."},
            {"key": "agent.auto_execute_commands", "default_hardened": "false", "purpose": "Requires user approval before running any shell command."},
            {"key": "agent.require_confirmation", "default_hardened": "true", "purpose": "Enforces interactive confirmation on all mutating operations."},
            {"key": "agent.auto_apply_edits", "default_hardened": "false", "purpose": "Requires manual inspection of file diffs before saving."},
            {"key": "terminal.auto_execute", "default_hardened": "false", "purpose": "Blocks unprompted terminal command execution in the ADE."},
            {"key": "terminal.sandbox", "default_hardened": "true", "purpose": "Isolates terminal execution inside a local sandbox container."},
            {"key": "composer.auto_apply", "default_hardened": "false", "purpose": "Requires operator review before applying Composer diffs."},
            {"key": "composer.require_approval", "default_hardened": "true", "purpose": "Mandates explicit user confirmation for multi-file edits."},
            {"key": "mcp.requireConsent", "default_hardened": "true", "purpose": "Mandates confirmation before invoking Model Context Protocol tools."},
            {"key": "mcp.allow_unsandboxed", "default_hardened": "false", "purpose": "Restricts MCP servers to sandboxed execution environments."},
            {"key": "dlp.mask_secrets", "default_hardened": "true", "purpose": "Redacts API keys, credentials, and tokens from prompt contexts."},
            {"key": "dlp.block_sensitive_paths", "default_hardened": "true", "purpose": "Excludes .env, cloud keys, and SSH credentials from AI context."}
        ]
    }
]

def generate_docs():
    root = Path(__file__).resolve().parent.parent.parent
    for item in TOOL_DOCS:
        content = f"""# {item['title']}

## 1. Overview
- **Vendor:** `{item['vendor']}`
- **Tool Name:** `{item['name']}`
- **Category:** `{item['category']}`

{item['summary']}

---

## 2. Hardened Security Settings Reference

The following table lists the official configuration keys and their recommended safe defaults applied by the **Hardening IA** policy:

| Setting Key | Hardened Value (Default) | Security Purpose |
| :--- | :--- | :--- |
"""
        for s in item["settings_map"]:
            content += f"| `{s['key']}` | `{s['default_hardened']}` | {s['purpose']} |\n"

        content += f"""
---

## 3. Configuration Policy
Declarative policy file: [`configs/tools/{item['vendor']}/{item['name']}/hardening_policy.yaml`](file:///configs/tools/{item['vendor']}/{item['name']}/hardening_policy.yaml)

### 🚀 Enforcement Commands
```bash
# Apply hardening policy:
python main.py --tool {item['vendor']}/{item['name']} --apply

# Dry run simulation:
python main.py --tool {item['vendor']}/{item['name']} --apply --dry-run
```
"""
        dest = root / "docs" / "tools" / item["vendor"] / item["name"] / f"{item['name']}.md"
        dest.parent.mkdir(parents=True, exist_ok=True)
        with open(dest, "w", encoding="utf-8") as f:
            f.write(content.strip() + "\n")
        print(f"[OK] Generated documentation: {item['vendor']}/{item['name']}.md")

if __name__ == "__main__":
    generate_docs()
