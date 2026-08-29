# OpenAI Codex CLI Security & Hardening Guide

## 1. Overview
- **Vendor:** `openai`
- **Tool Name:** `codex`
- **Category:** `CLI Agent / Engine`

OpenAI Codex CLI provides automated code generation, refactoring, and command execution.

---

## 2. Hardened Security Settings Reference

The following table lists the official configuration keys and their recommended safe defaults applied by the **Hardening IA** policy:

| Setting Key | Hardened Value (Default) | Security Purpose |
| :--- | :--- | :--- |
| `telemetry` | `false` | Disables usage and prompt data sharing. |
| `code_telemetry` | `false` | Prevents source code telemetry ingestion. |
| `auto_execute` | `false` | Mandates confirmation before running shell commands. |
| `enforce_sandboxing` | `true` | Restricts execution environment to local sandbox. |
| `trusted_workspaces_only` | `true` | Blocks execution in untrusted external folders. |
| `prompt_secret_masking` | `true` | Masks API keys and passwords in prompt pipelines. |
| `mcp_consent_required` | `true` | Requires user confirmation for MCP server calls. |

---

## 3. Configuration Policy
Declarative policy file: [`configs/tools/openai/codex/hardening_policy.yaml`](file:///configs/tools/openai/codex/hardening_policy.yaml)

### 🚀 Enforcement Commands
```bash
# Apply hardening policy:
python main.py --tool openai/codex --apply

# Dry run simulation:
python main.py --tool openai/codex --apply --dry-run
```
