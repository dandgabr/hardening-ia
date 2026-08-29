# Augment Code Security & Hardening Guide

## 1. Overview
- **Vendor:** `augment`
- **Tool Name:** `augment`
- **Category:** `Workspace Agent & IDE Companion`

Augment Code provides codebase-aware AI assistance with enterprise contextual search and deep repository comprehension.

---

## 2. Hardened Security Settings Reference

The following table lists the official configuration keys and their recommended safe defaults applied by the **Hardening IA** policy:

| Setting Key | Hardened Value (Default) | Security Purpose |
| :--- | :--- | :--- |
| `telemetry.enabled` | `false` | Disables telemetry and diagnostics collection. |
| `code_training_opt_out` | `true` | Ensures proprietary codebase data is never used for model training. |
| `require_write_confirmation` | `true` | Requires developer confirmation before applying file modifications. |
| `mask_detected_secrets` | `true` | Prevents secrets from entering prompt context windows. |
| `sandbox_isolation` | `true` | Isolates subprocess operations inside local sandboxes. |

---

## 3. Configuration Policy
Declarative policy file: [`configs/tools/augment/augment/hardening_policy.yaml`](file:///configs/tools/augment/augment/hardening_policy.yaml)

### 🚀 Enforcement Commands
```bash
# Apply hardening policy:
python main.py --tool augment/augment --apply

# Dry run simulation:
python main.py --tool augment/augment --apply --dry-run
```
