# Kimi Security & Hardening Guide

## 1. Overview
- **Vendor:** `moonshot`
- **Tool Name:** `kimi`
- **Category:** `CLI / Context Assistant`

Kimi CLI is an agentic assistant for processing large documents and codebases with Moonshot AI models.

---

## 2. Hardened Security Settings Reference

The following table lists the official configuration keys and their recommended safe defaults applied by the **Hardening IA** policy:

| Setting Key | Hardened Value (Default) | Security Purpose |
| :--- | :--- | :--- |
| `telemetry.enabled` | `false` | Disables interaction logging. |
| `privacy.data_retention` | `false` | Ensures prompt data is not retained for model training. |
| `agent.auto_write` | `false` | Requires user confirmation before writing files. |
| `prompt.mask_secrets` | `true` | Masks detected tokens before transmission. |

---

## 3. Configuration Policy
Declarative policy file: [`configs/tools/moonshot/kimi/hardening_policy.yaml`](file:///configs/tools/moonshot/kimi/hardening_policy.yaml)

### 🚀 Enforcement Commands
```bash
# Apply hardening policy:
python main.py --tool moonshot/kimi --apply

# Dry run simulation:
python main.py --tool moonshot/kimi --apply --dry-run
```
