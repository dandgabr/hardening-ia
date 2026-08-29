# CodeBuddy Security & Hardening Guide

## 1. Overview
- **Vendor:** `codebuddy`
- **Tool Name:** `codebuddy`
- **Category:** `IDE Assistant`

CodeBuddy provides interactive code explanations and suggestions in the developer environment.

---

## 2. Hardened Security Settings Reference

The following table lists the official configuration keys and their recommended safe defaults applied by the **Hardening IA** policy:

| Setting Key | Hardened Value (Default) | Security Purpose |
| :--- | :--- | :--- |
| `share_code_snippets` | `false` | Disables snippet telemetry. |
| `telemetry` | `'off'` | Disables tracking and diagnostic logging. |
| `auto_run_commands` | `false` | Blocks automated shell command execution. |
| `auto_apply_diffs` | `false` | Requires manual acceptance for code diffs. |

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
