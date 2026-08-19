# CodeBuddy Security & Hardening Guide

## 1. Overview
- **Vendor:** `codebuddy`
- **Tool Name:** `codebuddy`
- **Category:** `IDE Assistant`

CodeBuddy provides interactive code explanations and suggestions.

---

## 2. Hardened Security Settings Reference

The following table lists the official configuration keys and their recommended safe defaults applied by the **Hardening IA** policy:

| Setting Key | Hardened Value (Default) | Security Purpose |
| :--- | :--- | :--- |
| `share_code_snippets` | `false` | Disables snippet telemetry. |
| `telemetry` | `'off'` | Disables tracking and logging. |

---

## 3. Configuration Policy
Declarative policy file: [`configs/tools/codebuddy/codebuddy/hardening_policy.yaml`](file:///B:/Code/hardening-ia/configs/tools/codebuddy/codebuddy/hardening_policy.yaml)

### 🚀 Enforcement Commands
```bash
# Apply hardening policy:
python main.py --tool codebuddy/codebuddy --apply

# Dry run simulation:
python main.py --tool codebuddy/codebuddy --apply --dry-run
```
