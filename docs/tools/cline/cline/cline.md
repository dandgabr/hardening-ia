# Cline Security & Hardening Guide

## 1. Overview
- **Vendor:** `cline`
- **Tool Name:** `cline`
- **Category:** `Agentic IDE Assistant`

Cline is an autonomous coding agent for VS Code capable of multi-step terminal, file, browser, and MCP tool execution.

---

## 2. Hardened Security Settings Reference

The following table lists the official configuration keys and their recommended safe defaults applied by the **Hardening IA** policy:

| Setting Key | Hardened Value (Default) | Security Purpose |
| :--- | :--- | :--- |
| `autoApprove.mode` | `'never'` | Strictly disables global auto-approval for all tool invocations. |
| `alwaysApproveResubmit` | `false` | Requires operator consent on every retry loop. |
| `autoApproveExecution` | `false` | Disables automated shell command execution without review. |
| `allowNonWorkspaceAccess` | `false` | Blocks reading or writing files outside the open project directory. |
| `restrictSecretAccess` | `true` | Excludes `.env` and credential files from context collection. |
| `mcp.requireConsent` | `true` | Mandates approval before invoking local MCP server tools. |
| `diff.autoApply` | `false` | Requires manual inspection of file diffs before saving to disk. |

---

## 3. Configuration Policy
Declarative policy file: [`configs/tools/cline/cline/hardening_policy.yaml`](file:///configs/tools/cline/cline/hardening_policy.yaml)

### 🚀 Enforcement Commands
```bash
# Apply hardening policy:
python main.py --tool cline/cline --apply

# Dry run simulation:
python main.py --tool cline/cline --apply --dry-run
```
