# OpenCode Security & Hardening Guide

## 1. Overview
- **Vendor:** `opencode`
- **Tool Name:** `opencode`
- **Category:** `Open-Source CLI Agent`

OpenCode is an open-source terminal coding assistant executing local models and remote LLM APIs.

---

## 2. Hardened Security Settings Reference

The following table lists the official configuration keys and their recommended safe defaults applied by the **Hardening IA** policy:

| Setting Key | Hardened Value (Default) | Security Purpose |
| :--- | :--- | :--- |
| `analytics.enabled` | `false` | Disables telemetry metrics collection. |
| `agent.confirm_actions` | `true` | Prompts operator before applying diffs or executing scripts. |
| `agent.auto_apply_edits` | `false` | Disables automatic write operations on source files. |
| `permission_mode` | `'prompt'` | Enforces human confirmation for each tool execution. |
| `sandbox.strict_mode` | `true` | Enforces filesystem isolation and read-only container mount. |
| `dlp.mask_credentials` | `true` | Redacts sensitive credentials from LLM context. |

---

## 3. Configuration Policy
Declarative policy file: [`configs/tools/opencode/opencode/hardening_policy.yaml`](file:///configs/tools/opencode/opencode/hardening_policy.yaml)

### 🚀 Enforcement Commands
```bash
# Apply hardening policy:
python main.py --tool opencode/opencode --apply

# Dry run simulation:
python main.py --tool opencode/opencode --apply --dry-run
```
