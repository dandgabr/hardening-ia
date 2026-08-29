# CodeBuddy Security & Hardening Guide

## 1. Overview
- **Vendor:** `codebuddy`
- **Tool Name:** `codebuddy`
- **Category:** `IDE Programming Companion`

CodeBuddy is an interactive AI programming companion for refactoring, test generation, and bug fixing.

---

## 2. Hardened Security Settings Reference

The following table lists the official configuration keys and their recommended safe defaults applied by the **Hardening IA** policy:

| Setting Key | Hardened Value (Default) | Security Purpose |
| :--- | :--- | :--- |
| `share_code_snippets` | `false` | Prevents sending code snippets to external telemetry. |
| `telemetry` | `'off'` | Disables diagnostic data collection. |
| `auto_run_commands` | `false` | Requires user approval before running terminal commands. |
| `auto_apply_diffs` | `false` | Requires manual inspection of diffs before applying changes. |
| `sandbox_isolated` | `true` | Restricts execution to an isolated sandbox environment. |

---

## 3. Configuration Policy
Declarative policy file: [`configs/tools/codebuddy/codebuddy/hardening_policy.yaml`](file:///configs/tools/codebuddy/codebuddy/hardening_policy.yaml)

### 🚀 Enforcement Commands
```bash
# Apply hardening policy:
python main.py --tool codebuddy/codebuddy --apply

# Dry run simulation:
python main.py --tool codebuddy/codebuddy --apply --dry-run
```
