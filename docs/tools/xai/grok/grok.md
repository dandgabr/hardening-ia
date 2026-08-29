# Grok / xAI CLI Security & Hardening Guide

## 1. Overview
- **Vendor:** `xai`
- **Tool Name:** `grok`
- **Category:** `Developer CLI & Reasoning Interface`

Grok Developer CLI provides direct terminal access to xAI reasoning models with tool execution capabilities.

---

## 2. Hardened Security Settings Reference

The following table lists the official configuration keys and their recommended safe defaults applied by the **Hardening IA** policy:

| Setting Key | Hardened Value (Default) | Security Purpose |
| :--- | :--- | :--- |
| `telemetry` | `false` | Disables telemetry and prompt logging. |
| `audit_logs` | `true` | Enables local audit logging of all actions. |
| `sandbox_strict` | `true` | Enforces strict process sandboxing. |
| `share_prompts` | `false` | Disables prompt sharing and telemetry. |
| `auto_edit_files` | `false` | Requires human confirmation before applying file edits. |

---

## 3. Configuration Policy
Declarative policy file: [`configs/tools/xai/grok/hardening_policy.yaml`](file:///configs/tools/xai/grok/hardening_policy.yaml)

### 🚀 Enforcement Commands
```bash
# Apply hardening policy:
python main.py --tool xai/grok --apply

# Dry run simulation:
python main.py --tool xai/grok --apply --dry-run
```
