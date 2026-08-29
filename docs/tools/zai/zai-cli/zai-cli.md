# z.ai CLI Security & Hardening Guide

## 1. Overview
- **Vendor:** `zai`
- **Tool Name:** `zai-cli`
- **Category:** `CLI Coding Agent`

z.ai CLI is an autonomous command line developer agent powered by GLM models for codebase refactoring, terminal execution, and automation.

---

## 2. Hardened Security Settings Reference

The following table lists the official configuration keys and their recommended safe defaults applied by the **Hardening IA** policy:

| Setting Key | Hardened Value (Default) | Security Purpose |
| :--- | :--- | :--- |
| `telemetry` | `false` | Disables prompt analytics and telemetry collection. |
| `agent.auto_execute_commands` | `false` | Requires user approval before running any shell command. |
| `agent.require_confirmation` | `true` | Enforces interactive confirmation on all mutating operations. |
| `agent.auto_apply_edits` | `false` | Requires manual inspection of file diffs before saving. |
| `sandbox.enabled` | `true` | Executes shell commands in a contained process environment. |
| `mcp.requireConsent` | `true` | Mandates confirmation before invoking Model Context Protocol tools. |
| `dlp.mask_secrets` | `true` | Redacts API keys and credentials from prompt contexts. |

---

## 3. Configuration Policy
Declarative policy file: [`configs/tools/zai/zai-cli/hardening_policy.yaml`](file:///configs/tools/zai/zai-cli/hardening_policy.yaml)

### 🚀 Enforcement Commands
```bash
# Apply hardening policy:
python main.py --tool zai/zai-cli --apply

# Dry run simulation:
python main.py --tool zai/zai-cli --apply --dry-run
```
