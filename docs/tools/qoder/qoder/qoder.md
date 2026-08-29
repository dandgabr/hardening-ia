# Qoder Security & Hardening Guide

## 1. Overview
- **Vendor:** `qoder`
- **Tool Name:** `qoder`
- **Category:** `Enterprise Agent & IDE Companion`

Qoder is an enterprise AI coding assistant with repository-level code understanding and autonomous refactoring.

---

## 2. Hardened Security Settings Reference

The following table lists the official configuration keys and their recommended safe defaults applied by the **Hardening IA** policy:

| Setting Key | Hardened Value (Default) | Security Purpose |
| :--- | :--- | :--- |
| `telemetry.shareData` | `false` | Disables telemetry and code sharing. |
| `security.executionConsent` | `'always'` | Requires user consent before executing commands or modifying files. |
| `security.autoApplyEdits` | `false` | Requires manual inspection of file diffs before saving. |
| `security.sandbox` | `true` | Isolates execution inside a process sandbox. |
| `mcp.requireUserConfirmation` | `true` | Requires explicit approval for MCP tool calls. |

---

## 3. Configuration Policy
Declarative policy file: [`configs/tools/qoder/qoder/hardening_policy.yaml`](file:///configs/tools/qoder/qoder/hardening_policy.yaml)

### 🚀 Enforcement Commands
```bash
# Apply hardening policy:
python main.py --tool qoder/qoder --apply

# Dry run simulation:
python main.py --tool qoder/qoder --apply --dry-run
```
