# Kimi CLI Security & Hardening Guide

## 1. Overview
- **Vendor:** `moonshot`
- **Tool Name:** `kimi`
- **Category:** `High-Context CLI & Workspace Agent`

Kimi is Moonshot AI's high-context conversational and coding assistant supporting large-context reasoning.

---

## 2. Hardened Security Settings Reference

The following table lists the official configuration keys and their recommended safe defaults applied by the **Hardening IA** policy:

| Setting Key | Hardened Value (Default) | Security Purpose |
| :--- | :--- | :--- |
| `telemetry.enabled` | `false` | Disables telemetry and tracking. |
| `privacy.data_retention` | `false` | Opt-out from server-side prompt and code retention. |
| `agent.auto_write` | `false` | Requires operator confirmation before modifying files. |
| `security.require_write_confirmation` | `true` | Requires interactive confirmation on all writes. |
| `sandbox.enabled` | `true` | Enforces sandboxed process execution. |

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
