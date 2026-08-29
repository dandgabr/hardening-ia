# Cline Security & Hardening Guide

## 1. Overview
- **Vendor:** `cline`
- **Tool Name:** `cline`
- **Category:** `Agentic IDE Assistant`

Cline is an autonomous coding assistant for VS Code with terminal execution, file editing, and MCP capabilities.

---

## 2. Hardened Security Settings Reference

The following table lists the official configuration keys and their recommended safe defaults applied by the **Hardening IA** policy:

| Setting Key | Hardened Value (Default) | Security Purpose |
| :--- | :--- | :--- |
| `autoApprove.mode` | `'never'` | Prevents autonomous bypass of human confirmation. |
| `autoApproveExecution` | `false` | Requires approval before running shell commands. |
| `allowNonWorkspaceAccess` | `false` | Restricts Cline to files within the active workspace root. |
| `mcp.requireConsent` | `true` | Mandates confirmation before invoking Model Context Protocol tools. |
| `mcp.autoApprove` | `false` | Disallows automatic tool execution for MCP servers. |
| `diff.autoApply` | `false` | Requires manual review of file changes before applying diffs. |
| `restrictSecretAccess` | `true` | Prevents the agent from reading secret keys and credentials. |

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
