# z.ai Developer Platform (CLI, ADE & Desktop) Security & Hardening Guide

## 1. Overview
- **Vendor:** `zai`
- **Tool Name:** `zai`
- **Category:** `Unified Agentic Platform (CLI, ADE & Desktop)`

z.ai Developer Platform is a unified ecosystem providing an Autonomous CLI Coding Agent (zai-cli), an Agentic Development Environment (zcode ADE / Desktop), and IDE extensions powered by GLM models.

---

## 2. Hardened Security Settings Reference

The following table lists the official configuration keys and their recommended safe defaults applied by the **Hardening IA** policy:

| Setting Key | Hardened Value (Default) | Security Purpose |
| :--- | :--- | :--- |
| `telemetry` | `false` | Disables prompt analytics and interaction tracking across CLI and ADE. |
| `privacy.data_retention` | `false` | Enforces zero data retention for source code and prompts. |
| `agent.auto_execute_commands` | `false` | Requires user approval before running any shell command. |
| `agent.require_confirmation` | `true` | Enforces interactive confirmation on all mutating operations. |
| `agent.auto_apply_edits` | `false` | Requires manual inspection of file diffs before saving. |
| `terminal.auto_execute` | `false` | Blocks unprompted terminal command execution in the ADE. |
| `terminal.sandbox` | `true` | Isolates terminal execution inside a local sandbox container. |
| `composer.auto_apply` | `false` | Requires operator review before applying Composer diffs. |
| `composer.require_approval` | `true` | Mandates explicit user confirmation for multi-file edits. |
| `mcp.requireConsent` | `true` | Mandates confirmation before invoking Model Context Protocol tools. |
| `mcp.allow_unsandboxed` | `false` | Restricts MCP servers to sandboxed execution environments. |
| `dlp.mask_secrets` | `true` | Redacts API keys, credentials, and tokens from prompt contexts. |
| `dlp.block_sensitive_paths` | `true` | Excludes .env, cloud keys, and SSH credentials from AI context. |

---

## 3. Configuration Policy
Declarative policy file: [`configs/tools/zai/zai/hardening_policy.yaml`](file:///configs/tools/zai/zai/hardening_policy.yaml)

### 🚀 Enforcement Commands
```bash
# Apply hardening policy:
python main.py --tool zai/zai --apply

# Dry run simulation:
python main.py --tool zai/zai --apply --dry-run
```
