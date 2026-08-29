"""Generates detailed English tool documentation under docs/tools/ mapping all official security keys for all 21 tools."""

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
            {"key": "permissions.deny", "default_hardened": "[destructive commands, DLP secrets, WebDAV \*, SSRF metadata]", "purpose": "Explicit deny list rejecting risky operations without prompting."},
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
            {"key": "telemetry.telemetryLevel", "default_hardened": "'off'", "purpose": "Disables diagnostic data transmission to external servers."}
        ]
    },
    {
        "vendor": "anysphere",
        "name": "cursor",
        "title": "Cursor IDE Security & Hardening Guide",
        "category": "AI-Native IDE & Composer Agent",
        "summary": "Cursor is an AI-powered code editor with agentic Composer, terminal execution, and local codebase indexing.",
        "settings_map": [
            {"key": "cursor.privacyMode", "default_hardened": "true", "purpose": "Enforces zero retention and disallows cloud training on user code."},
            {"key": "cursor.general.privacy", "default_hardened": "'no-retention'", "purpose": "Opt-out from prompt and code snippet logging."},
            {"key": "cursor.terminal.autoExecute", "default_hardened": "false", "purpose": "Requires confirmation before running terminal commands."},
            {"key": "cursor.terminal.sandbox", "default_hardened": "true", "purpose": "Enforces sandboxed terminal execution."},
            {"key": "cursor.agent.yoloMode", "default_hardened": "false", "purpose": "Disables YOLO unprompted auto-execution in Composer and Agent modes."},
            {"key": "cursor.composer.autoApply", "default_hardened": "false", "purpose": "Requires manual review before applying AI-generated code edits."},
            {"key": "cursor.composer.requireUserApproval", "default_hardened": "true", "purpose": "Ensures operator approval on all multi-file modifications."},
            {"key": "cursor.mcp.requireConsent", "default_hardened": "true", "purpose": "Prompts for approval before executing MCP tools."},
            {"key": "cursor.indexer.ignorePatterns", "default_hardened": "[.env*, *.pem, ~/.aws, ~/.ssh, ~/.kube]", "purpose": "Prevents indexing and exfiltration of sensitive secrets and credentials."},
            {"key": "telemetry.telemetryLevel", "default_hardened": "'off'", "purpose": "Disables diagnostic and usage telemetry."}
        ]
    },
    {
        "vendor": "cline",
        "name": "cline",
        "title": "Cline Security & Hardening Guide",
        "category": "Agentic IDE Assistant",
        "summary": "Cline is an autonomous coding assistant for VS Code with terminal execution, file editing, and MCP capabilities.",
        "settings_map": [
            {"key": "autoApprove.mode", "default_hardened": "'never'", "purpose": "Prevents autonomous bypass of human confirmation."},
            {"key": "autoApproveExecution", "default_hardened": "false", "purpose": "Requires approval before running shell commands."},
            {"key": "allowNonWorkspaceAccess", "default_hardened": "false", "purpose": "Restricts Cline to files within the active workspace root."},
            {"key": "mcp.requireConsent", "default_hardened": "true", "purpose": "Mandates confirmation before invoking Model Context Protocol tools."},
            {"key": "mcp.autoApprove", "default_hardened": "false", "purpose": "Disallows automatic tool execution for MCP servers."},
            {"key": "diff.autoApply", "default_hardened": "false", "purpose": "Requires manual review of file changes before applying diffs."},
            {"key": "restrictSecretAccess", "default_hardened": "true", "purpose": "Prevents the agent from reading secret keys and credentials."}
        ]
    },
    {
        "vendor": "openai",
        "name": "codex",
        "title": "OpenAI Codex CLI Security & Hardening Guide",
        "category": "CLI Agent & Code Engine",
        "summary": "OpenAI Codex CLI agent handles automated code synthesis, command line execution, and workflow automation.",
        "settings_map": [
            {"key": "telemetry", "default_hardened": "false", "purpose": "Disables diagnostic telemetry and prompt tracking."},
            {"key": "auto_execute", "default_hardened": "false", "purpose": "Requires operator consent before executing terminal commands."},
            {"key": "enforce_sandboxing", "default_hardened": "true", "purpose": "Executes shell commands in a restricted container."},
            {"key": "trusted_workspaces_only", "default_hardened": "true", "purpose": "Restricts execution to verified workspaces."},
            {"key": "allow_network", "default_hardened": "false", "purpose": "Restricts unapproved external network connections."},
            {"key": "prompt_secret_masking", "default_hardened": "true", "purpose": "Masks detected secrets from outbound API prompts."}
        ]
    },
    {
        "vendor": "opencode",
        "name": "opencode",
        "title": "OpenCode CLI Security & Hardening Guide",
        "category": "Open-Source AI Coding Agent",
        "summary": "OpenCode is an open-source terminal coding agent offering interactive development and multi-model support.",
        "settings_map": [
            {"key": "analytics.enabled", "default_hardened": "false", "purpose": "Disables analytics and telemetry tracking."},
            {"key": "agent.confirm_actions", "default_hardened": "true", "purpose": "Requires operator confirmation for all tool actions."},
            {"key": "agent.auto_apply_edits", "default_hardened": "false", "purpose": "Requires manual confirmation before writing file changes."},
            {"key": "permission_mode", "default_hardened": "'prompt'", "purpose": "Enforces interactive permission prompts for all operations."},
            {"key": "sandbox.strict_mode", "default_hardened": "true", "purpose": "Isolates subprocesses and prevents dangerous command execution."},
            {"key": "dlp.mask_credentials", "default_hardened": "true", "purpose": "Redacts passwords, tokens, and API keys."}
        ]
    },
    {
        "vendor": "nousresearch",
        "name": "hermes-agent",
        "title": "Hermes Agent Security & Hardening Guide",
        "category": "Autonomous Reasoning Agent",
        "summary": "Hermes Agent is an open-weights reasoning and autonomous execution agent capable of complex multi-step coding tasks.",
        "settings_map": [
            {"key": "enable_telemetry", "default_hardened": "false", "purpose": "Disables telemetry data collection."},
            {"key": "human_in_the_loop", "default_hardened": "true", "purpose": "Mandates human confirmation at critical execution branches."},
            {"key": "safe_mode", "default_hardened": "true", "purpose": "Enforces safe execution guardrails and blocks high-risk tools."},
            {"key": "max_recursive_steps", "default_hardened": "10", "purpose": "Limits maximum subagent recursion to prevent runaway loops."},
            {"key": "sandbox_container", "default_hardened": "true", "purpose": "Runs agent subprocesses in an isolated environment."},
            {"key": "blocked_tools", "default_hardened": "['system_admin', 'raw_exec', 'disk_partition']", "purpose": "Disables dangerous system tools."}
        ]
    },
    {
        "vendor": "qoder",
        "name": "qoder",
        "title": "Qoder Security & Hardening Guide",
        "category": "Enterprise Agent & IDE Companion",
        "summary": "Qoder is an enterprise AI coding assistant with repository-level code understanding and autonomous refactoring.",
        "settings_map": [
            {"key": "telemetry.shareData", "default_hardened": "false", "purpose": "Disables telemetry and code sharing."},
            {"key": "security.executionConsent", "default_hardened": "'always'", "purpose": "Requires user consent before executing commands or modifying files."},
            {"key": "security.autoApplyEdits", "default_hardened": "false", "purpose": "Requires manual inspection of file diffs before saving."},
            {"key": "security.sandbox", "default_hardened": "true", "purpose": "Isolates execution inside a process sandbox."},
            {"key": "mcp.requireUserConfirmation", "default_hardened": "true", "purpose": "Requires explicit approval for MCP tool calls."}
        ]
    },
    {
        "vendor": "kilo",
        "name": "kilo-code",
        "title": "Kilo Code CLI Security & Hardening Guide",
        "category": "High-Performance CLI Developer Suite",
        "summary": "Kilo Code is a fast, terminal-based AI assistant designed for rapid software engineering and code generation.",
        "settings_map": [
            {"key": "privacy.telemetry", "default_hardened": "false", "purpose": "Disables usage tracking and metrics transmission."},
            {"key": "execution.require_confirmation", "default_hardened": "true", "purpose": "Requires approval before running shell commands."},
            {"key": "execution.auto_accept_edits", "default_hardened": "false", "purpose": "Requires manual diff inspection before accepting file changes."},
            {"key": "sandbox.enabled", "default_hardened": "true", "purpose": "Restricts execution to a sandbox environment."},
            {"key": "indexing.exclude_hidden_and_secrets", "default_hardened": "true", "purpose": "Excludes secret files from codebase indexing."}
        ]
    },
    {
        "vendor": "clinepass",
        "name": "clinepass",
        "title": "ClinePass Security & Hardening Guide",
        "category": "Security Wrapper & Credential Vault",
        "summary": "ClinePass provides a secure proxy, credential vault, and guardrails wrapper for autonomous coding agents.",
        "settings_map": [
            {"key": "vault.enforce_encryption", "default_hardened": "true", "purpose": "Enforces AES-256 encryption on all stored API keys."},
            {"key": "vault.zero_plaintext_cache", "default_hardened": "true", "purpose": "Prevents credentials from ever being written to disk unencrypted."},
            {"key": "proxy.block_unapproved_hosts", "default_hardened": "true", "purpose": "Blocks outbound connections to untrusted endpoints."},
            {"key": "proxy.block_ssrf_metadata", "default_hardened": "true", "purpose": "Blocks access to cloud metadata IP 169.254.169.254."},
            {"key": "proxy.mask_tokens_in_logs", "default_hardened": "true", "purpose": "Masks secrets in audit logs."}
        ]
    },
    {
        "vendor": "codebuddy",
        "name": "codebuddy",
        "title": "CodeBuddy Security & Hardening Guide",
        "category": "IDE Programming Companion",
        "summary": "CodeBuddy is an interactive AI programming companion for refactoring, test generation, and bug fixing.",
        "settings_map": [
            {"key": "share_code_snippets", "default_hardened": "false", "purpose": "Prevents sending code snippets to external telemetry."},
            {"key": "telemetry", "default_hardened": "'off'", "purpose": "Disables diagnostic data collection."},
            {"key": "auto_run_commands", "default_hardened": "false", "purpose": "Requires user approval before running terminal commands."},
            {"key": "auto_apply_diffs", "default_hardened": "false", "purpose": "Requires manual inspection of diffs before applying changes."},
            {"key": "sandbox_isolated", "default_hardened": "true", "purpose": "Restricts execution to an isolated sandbox environment."}
        ]
    },
    {
        "vendor": "moonshot",
        "name": "kimi",
        "title": "Kimi CLI Security & Hardening Guide",
        "category": "High-Context CLI & Workspace Agent",
        "summary": "Kimi is Moonshot AI's high-context conversational and coding assistant supporting large-context reasoning.",
        "settings_map": [
            {"key": "telemetry.enabled", "default_hardened": "false", "purpose": "Disables telemetry and tracking."},
            {"key": "privacy.data_retention", "default_hardened": "false", "purpose": "Opt-out from server-side prompt and code retention."},
            {"key": "agent.auto_write", "default_hardened": "false", "purpose": "Requires operator confirmation before modifying files."},
            {"key": "security.require_write_confirmation", "default_hardened": "true", "purpose": "Requires interactive confirmation on all writes."},
            {"key": "sandbox.enabled", "default_hardened": "true", "purpose": "Enforces sandboxed process execution."}
        ]
    },
    {
        "vendor": "xai",
        "name": "grok",
        "title": "Grok / xAI CLI Security & Hardening Guide",
        "category": "Developer CLI & Reasoning Interface",
        "summary": "Grok Developer CLI provides direct terminal access to xAI reasoning models with tool execution capabilities.",
        "settings_map": [
            {"key": "telemetry", "default_hardened": "false", "purpose": "Disables telemetry and prompt logging."},
            {"key": "audit_logs", "default_hardened": "true", "purpose": "Enables local audit logging of all actions."},
            {"key": "sandbox_strict", "default_hardened": "true", "purpose": "Enforces strict process sandboxing."},
            {"key": "share_prompts", "default_hardened": "false", "purpose": "Disables prompt sharing and telemetry."},
            {"key": "auto_edit_files", "default_hardened": "false", "purpose": "Requires human confirmation before applying file edits."}
        ]
    },
    {
        "vendor": "zai",
        "name": "zai",
        "title": "z.ai Developer Platform Security & Hardening Guide",
        "category": "Unified Agentic Platform (CLI, ADE Desktop & IDE)",
        "summary": "z.ai Developer Platform is a unified AI engineering suite encompassing CLI Agent (zai-cli), ADE Desktop (zcode), and IDE plugins.",
        "settings_map": [
            {"key": "telemetry", "default_hardened": "false", "purpose": "Disables all telemetry and tracking across CLI and ADE Desktop."},
            {"key": "privacy.data_retention", "default_hardened": "false", "purpose": "Opt-out from cloud training and prompt retention."},
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
    },
    {
        "vendor": "codeium",
        "name": "windsurf",
        "title": "Windsurf (Codeium) Security & Hardening Guide",
        "category": "Cascade ADE Desktop, CLI & IDE Extensions",
        "summary": "Windsurf is Codeium's AI-native IDE featuring Cascade ADE, automated workflows, and multi-file code editing.",
        "settings_map": [
            {"key": "windsurf.privacyMode", "default_hardened": "true", "purpose": "Enforces zero retention and prevents cloud training on proprietary code."},
            {"key": "codeium.enableTelemetry", "default_hardened": "false", "purpose": "Disables diagnostic telemetry and prompt metrics transmission."},
            {"key": "codeium.enterprise.zeroDataRetention", "default_hardened": "true", "purpose": "Enforces zero data retention on enterprise AI gateways."},
            {"key": "windsurf.cascade.autoExecute", "default_hardened": "false", "purpose": "Requires interactive user confirmation before Cascade executes commands."},
            {"key": "windsurf.cascade.yoloMode", "default_hardened": "false", "purpose": "Disables unprompted YOLO auto-execution in Cascade ADE."},
            {"key": "windsurf.cascade.requireApproval", "default_hardened": "true", "purpose": "Requires explicit review on multi-file modifications."},
            {"key": "mcp.requireConsent", "default_hardened": "true", "purpose": "Mandates confirmation before invoking Model Context Protocol tools."},
            {"key": "telemetry.telemetryLevel", "default_hardened": "'off'", "purpose": "Disables telemetry reporting in VS Code/Windsurf base."}
        ]
    },
    {
        "vendor": "continuedev",
        "name": "continue",
        "title": "Continue.dev Security & Hardening Guide",
        "category": "Headless Agent, CLI & IDE Extensions",
        "summary": "Continue is an open-source AI code assistant providing customizable autocomplete, chat, and agentic workflows.",
        "settings_map": [
            {"key": "allowAnonymousTelemetry", "default_hardened": "false", "purpose": "Disables anonymous usage statistics and crash reporting."},
            {"key": "maskSecretsInPrompts", "default_hardened": "true", "purpose": "Redacts API keys, credentials, and .env secrets from outgoing LLM requests."},
            {"key": "mcp.requireConsent", "default_hardened": "true", "purpose": "Prompts for user approval before invoking MCP tools."},
            {"key": "blockLocalSSRF", "default_hardened": "true", "purpose": "Blocks SSRF probes against cloud metadata (169.254.169.254) and local loopback."},
            {"key": "disableIndexing", "default_hardened": "false", "purpose": "Enforces local-only codebase indexing."}
        ]
    },
    {
        "vendor": "aider",
        "name": "aider",
        "title": "Aider Pair Programming CLI Security & Hardening Guide",
        "category": "Git AI Pair Programming CLI",
        "summary": "Aider is a terminal-based AI pair programming tool that edits local files directly in Git repositories with automatic commit tracking.",
        "settings_map": [
            {"key": "analytics", "default_hardened": "false", "purpose": "Disables analytics and external usage reporting."},
            {"key": "verify-ssl", "default_hardened": "true", "purpose": "Enforces strict SSL/TLS certificate verification on all API endpoints."},
            {"key": "auto-commits", "default_hardened": "true", "purpose": "Ensures every AI modification is committed with an isolated git revision for instant rollbacks."},
            {"key": "attribute-author", "default_hardened": "false", "purpose": "Prevents AI authorship metadata attribution in public commits."},
            {"key": "require-confirmation-on-push", "default_hardened": "true", "purpose": "Requires operator consent before pushing git commits to remotes."},
            {"key": "mask-api-keys", "default_hardened": "true", "purpose": "Masks LLM API tokens in chat transcript logs."}
        ]
    },
    {
        "vendor": "amazon",
        "name": "amazon-q",
        "title": "Amazon Q Developer Security & Hardening Guide",
        "category": "AWS CLI ('q'), IDE Extensions & ADE Chat",
        "summary": "Amazon Q Developer is an AWS AI assistant providing code completion, terminal commands, security vulnerability remediation, and app transformation.",
        "settings_map": [
            {"key": "telemetry.enabled", "default_hardened": "false", "purpose": "Disables telemetry transmission to AWS telemetry servers."},
            {"key": "amazonQ.shareCodeForTraining", "default_hardened": "false", "purpose": "Opt-out from code and prompt sharing for service improvement."},
            {"key": "amazonQ.autoExecuteCommands", "default_hardened": "false", "purpose": "Requires user approval before running shell commands suggested by Amazon Q."},
            {"key": "amazonQ.requireUserApproval", "default_hardened": "true", "purpose": "Mandates confirmation before applying code transformation diffs."},
            {"key": "amazonQ.workspace.trust", "default_hardened": "true", "purpose": "Enforces workspace trust boundaries before indexing projects."}
        ]
    },
    {
        "vendor": "tabnine",
        "name": "tabnine",
        "title": "Tabnine Security & Hardening Guide",
        "category": "Privacy-First AI Assistant (CLI, IDE & ADE)",
        "summary": "Tabnine is an AI coding assistant built with privacy-first principles for enterprises, supporting air-gapped and local model deployments.",
        "settings_map": [
            {"key": "cloud_sharing_enabled", "default_hardened": "false", "purpose": "Disables cloud code sharing and telemetry."},
            {"key": "anonymous_telemetry", "default_hardened": "false", "purpose": "Disables anonymous analytics collection."},
            {"key": "enterprise_mode", "default_hardened": "true", "purpose": "Locks down team configuration policies."},
            {"key": "local_model_only", "default_hardened": "true", "purpose": "Forces code completions to use strictly on-premise / local models."},
            {"key": "mask_secrets", "default_hardened": "true", "purpose": "Redacts credentials and secrets from prompt payloads."}
        ]
    },
    {
        "vendor": "augment",
        "name": "augment",
        "title": "Augment Code Security & Hardening Guide",
        "category": "Workspace Agent & IDE Companion",
        "summary": "Augment Code provides codebase-aware AI assistance with enterprise contextual search and deep repository comprehension.",
        "settings_map": [
            {"key": "telemetry.enabled", "default_hardened": "false", "purpose": "Disables telemetry and diagnostics collection."},
            {"key": "code_training_opt_out", "default_hardened": "true", "purpose": "Ensures proprietary codebase data is never used for model training."},
            {"key": "require_write_confirmation", "default_hardened": "true", "purpose": "Requires developer confirmation before applying file modifications."},
            {"key": "mask_detected_secrets", "default_hardened": "true", "purpose": "Prevents secrets from entering prompt context windows."},
            {"key": "sandbox_isolation", "default_hardened": "true", "purpose": "Isolates subprocess operations inside local sandboxes."}
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
