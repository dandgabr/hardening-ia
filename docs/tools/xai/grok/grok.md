# Grok / xAI Developer CLI Security & Hardening Guide

## 1. Overview
- **Vendor:** `xai`
- **Tool Name:** `grok`
- **Category:** `CLI Assistant`

Grok CLI connects developers with xAI models for reasoning and software generation.

---

## 2. Hardened Security Settings Reference

The following table lists the official configuration keys and their recommended safe defaults applied by the **Hardening IA** policy:

| Setting Key | Hardened Value (Default) | Security Purpose |
| :--- | :--- | :--- |
| `telemetry` | `false` | Disables user prompt analytics. |
| `share_prompts` | `false` | Opt out of model retraining. |
| `auto_edit_files` | `false` | Requires approval before writing changes to disk. |
| `sandbox_strict` | `true` | Enforces strict process sandboxing. |

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
