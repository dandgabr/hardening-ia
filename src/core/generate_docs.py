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
            {"key": "telemetry.enabled", "default_hardened": "false", "purpose": "Disables usage and prompt transmission to external telemetry."},
            {"key": "crashReporting.enabled", "default_hardened": "false", "purpose": "Prevents memory dumps from sending code fragments to Google."}
        ]
    },
    {
        "vendor": "anthropic",
        "name": "claude-code",
        "title": "Claude Code CLI Security & Hardening Guide",
        "category": "CLI Agent",
        "summary": "Claude Code is an agentic terminal coding assistant capable of editing repositories, running bash commands, and managing development workflows.",
        "settings_map": [
            {"key": "permissionMode", "default_hardened": "'manual'", "purpose": "Prompts for confirmation on all terminal and filesystem actions."},
            {"key": "autoApprove", "default_hardened": "[]", "purpose": "Empty auto-approve list ensuring human-in-the-loop validation."},
            {"key": "acceptEdits", "default_hardened": "false", "purpose": "Disallows automatic file modification without explicit diff inspection."},
            {"key": "dangerouslySkipPermissions", "default_hardened": "false", "purpose": "Strictly blocks permission bypass mode."},
            {"key": "disableTelemetry", "default_hardened": "true", "purpose": "Disables interaction metrics and analytics transmission."},
            {"key": "maxCostThresholdUSD", "default_hardened": "10.0", "purpose": "Protects against runaway agent loops and cost spikes."}
        ]
    },
    {
        "vendor": "github",
        "name": "copilot",
        "title": "GitHub Copilot Security & Hardening Guide",
        "category": "IDE Extension",
        "summary": "GitHub Copilot provides real-time AI code completions and chat in VS Code, JetBrains, and Visual Studio.",
        "settings_map": [
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
        "summary": "Cursor is an AI-powered code editor with agentic terminal execution and codebase indexing.",
        "settings_map": [
            {"key": "cursor.privacyMode", "default_hardened": "true", "purpose": "Enforces Zero Data Retention (ZDR); code is not stored or used for model training."},
            {"key": "cursor.general.privacy", "default_hardened": "'no-retention'", "purpose": "Guarantees prompts and file contents are erased immediately after generation."},
            {"key": "cursor.terminal.autoExecute", "default_hardened": "false", "purpose": "Requires explicit approval before any shell command is run by the agent."},
            {"key": "cursor.terminal.sandbox", "default_hardened": "true", "purpose": "Enforces process isolation for terminal executions."},
            {"key": "cursor.indexer.ignorePatterns", "default_hardened": "[.env*, *.pem, *.key, ~/.ssh/**, ~/.aws/**]", "purpose": "Prevents indexing sensitive secrets into the semantic database."}
        ]
    },
    {
        "vendor": "cline",
        "name": "cline",
        "title": "Cline Security & Hardening Guide",
        "category": "Agentic IDE Assistant",
        "summary": "Cline is an autonomous coding agent for VS Code capable of multi-step terminal, file, browser, and MCP tool execution.",
        "settings_map": [
            {"key": "alwaysApproveResubmit", "default_hardened": "false", "purpose": "Requires operator consent on every retry loop."},
            {"key": "autoApproveExecution", "default_hardened": "false", "purpose": "Disables automated shell command execution without review."},
            {"key": "allowNonWorkspaceAccess", "default_hardened": "false", "purpose": "Blocks reading or writing files outside the open project directory."},
            {"key": "restrictSecretAccess", "default_hardened": "true", "purpose": "Excludes `.env` and credential files from context collection."},
            {"key": "mcp.requireConsent", "default_hardened": "true", "purpose": "Mandates approval before invoking local MCP server tools."}
        ]
    },
    {
        "vendor": "openai",
        "name": "codex",
        "title": "OpenAI Codex CLI Security & Hardening Guide",
        "category": "CLI Agent / Engine",
        "summary": "OpenAI Codex CLI provides automated code generation, refactoring, and command execution.",
        "settings_map": [
            {"key": "telemetry", "default_hardened": "false", "purpose": "Disables usage data sharing."},
            {"key": "auto_execute", "default_hardened": "false", "purpose": "Mandates confirmation before running shell commands."},
            {"key": "enforce_sandboxing", "default_hardened": "true", "purpose": "Restricts execution environment to local sandbox."},
            {"key": "prompt_secret_masking", "default_hardened": "true", "purpose": "Masks API keys and passwords in prompt pipelines."}
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
            {"key": "sandbox.strict_mode", "default_hardened": "true", "purpose": "Enforces filesystem isolation and read-only container mount."}
        ]
    },
    {
        "vendor": "nousresearch",
        "name": "hermes-agent",
        "title": "Hermes Agent Security & Hardening Guide",
        "category": "Autonomous Agent",
        "summary": "Hermes Agent provides deep reasoning and autonomous tool execution.",
        "settings_map": [
            {"key": "safe_mode", "default_hardened": "true", "purpose": "Enforces strict safety rails during multi-step reasoning."},
            {"key": "human_in_the_loop", "default_hardened": "true", "purpose": "Pauses execution to obtain operator confirmation."},
            {"key": "max_recursive_steps", "default_hardened": "10", "purpose": "Prevents infinite reasoning loops."}
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
            {"key": "security.executionConsent", "default_hardened": "'always'", "purpose": "Requires approval on every automated action."}
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
            {"key": "execution.require_confirmation", "default_hardened": "true", "purpose": "Requires confirmation on file and shell operations."}
        ]
    },
    {
        "vendor": "clinepass",
        "name": "clinepass",
        "title": "ClinePass Security & Hardening Guide",
        "category": "Security Wrapper & Vault",
        "summary": "ClinePass provides managed authentication and a secure credential proxy for Cline agents.",
        "settings_map": [
            {"key": "vault.enforce_encryption", "default_hardened": "true", "purpose": "Encrypts stored LLM API keys at rest."},
            {"key": "proxy.block_unapproved_hosts", "default_hardened": "true", "purpose": "Blocks outgoing connections to unapproved endpoints."}
        ]
    },
    {
        "vendor": "codebuddy",
        "name": "codebuddy",
        "title": "CodeBuddy Security & Hardening Guide",
        "category": "IDE Assistant",
        "summary": "CodeBuddy provides interactive code explanations and suggestions.",
        "settings_map": [
            {"key": "share_code_snippets", "default_hardened": "false", "purpose": "Disables snippet telemetry."},
            {"key": "telemetry", "default_hardened": "'off'", "purpose": "Disables tracking and logging."}
        ]
    },
    {
        "vendor": "moonshot",
        "name": "kimi",
        "title": "Kimi Security & Hardening Guide",
        "category": "CLI / Context Assistant",
        "summary": "Kimi CLI is an agentic assistant for processing large documents and codebases.",
        "settings_map": [
            {"key": "telemetry.enabled", "default_hardened": "false", "purpose": "Disables interaction logging."},
            {"key": "privacy.data_retention", "default_hardened": "false", "purpose": "Ensures prompt data is not retained by the API."},
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
            {"key": "sandbox_strict", "default_hardened": "true", "purpose": "Enforces strict process sandboxing."}
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
Declarative policy file: [`configs/tools/{item['vendor']}/{item['name']}/hardening_policy.yaml`](file:///B:/Code/hardening-ia/configs/tools/{item['vendor']}/{item['name']}/hardening_policy.yaml)

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
