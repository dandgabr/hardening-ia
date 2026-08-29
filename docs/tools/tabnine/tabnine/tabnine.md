# Tabnine Security & Hardening Guide

## 1. Overview
- **Vendor:** `tabnine`
- **Tool Name:** `tabnine`
- **Category:** `Privacy-First AI Assistant (CLI, IDE & ADE)`

Tabnine is an AI coding assistant built with privacy-first principles for enterprises, supporting air-gapped and local model deployments.

---

## 2. Hardened Security Settings Reference

The following table lists the official configuration keys and their recommended safe defaults applied by the **Hardening IA** policy:

| Setting Key | Hardened Value (Default) | Security Purpose |
| :--- | :--- | :--- |
| `cloud_sharing_enabled` | `false` | Disables cloud code sharing and telemetry. |
| `anonymous_telemetry` | `false` | Disables anonymous analytics collection. |
| `enterprise_mode` | `true` | Locks down team configuration policies. |
| `local_model_only` | `true` | Forces code completions to use strictly on-premise / local models. |
| `mask_secrets` | `true` | Redacts credentials and secrets from prompt payloads. |

---

## 3. Configuration Policy
Declarative policy file: [`configs/tools/tabnine/tabnine/hardening_policy.yaml`](file:///configs/tools/tabnine/tabnine/hardening_policy.yaml)

### 🚀 Enforcement Commands
```bash
# Apply hardening policy:
python main.py --tool tabnine/tabnine --apply

# Dry run simulation:
python main.py --tool tabnine/tabnine --apply --dry-run
```
