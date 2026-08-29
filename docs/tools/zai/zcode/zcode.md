# z.ai ZCode Desktop & ADE Security & Hardening Guide

## 1. Overview
- **Vendor:** `zai`
- **Tool Name:** `zcode`
- **Category:** `Agentic Development Environment (ADE)`

ZCode is an integrated Agentic Development Environment (ADE) with chat interface, file explorer, workspace terminal, and MCP tool orchestration for GLM models.

---

## 2. Hardened Security Settings Reference

The following table lists the official configuration keys and their recommended safe defaults applied by the **Hardening IA** policy:

| Setting Key | Hardened Value (Default) | Security Purpose |
| :--- | :--- | :--- |
| `telemetry.enabled` | `false` | Disables interaction tracking and telemetry transmission. |
| `privacy.data_retention` | `false` | Enforces zero data retention for source code and prompts. |
| `terminal.auto_execute` | `false` | Blocks unprompted terminal command execution by the agent. |
| `terminal.sandbox` | `true` | Isolates terminal execution inside a local sandbox container. |
| `composer.auto_apply` | `false` | Requires operator review before applying Composer diffs. |
| `composer.require_approval` | `true` | Mandates explicit user confirmation for multi-file edits. |
| `mcp.require_consent` | `true` | Requires approval before executing external MCP server tools. |
| `mcp.allow_unsandboxed` | `false` | Restricts MCP servers to sandboxed execution environments. |
| `dlp.block_sensitive_paths` | `true` | Excludes .env, credentials, and cloud keys from AI context. |

---

## 3. Configuration Policy
Declarative policy file: [`configs/tools/zai/zcode/hardening_policy.yaml`](file:///configs/tools/zai/zcode/hardening_policy.yaml)

### 🚀 Enforcement Commands
```bash
# Apply hardening policy:
python main.py --tool zai/zcode --apply

# Dry run simulation:
python main.py --tool zai/zcode --apply --dry-run
```
