# OpenCode CLI Security & Hardening Guide

## 1. Overview
- **Vendor:** `opencode`
- **Tool Name:** `opencode`
- **Category:** `Open-Source AI Coding Agent`

OpenCode is an open-source terminal coding agent offering interactive development and multi-model support.

---

## 2. Hardened Security Settings Reference

The following table lists the official configuration keys and their recommended safe defaults applied by the **Hardening IA** policy:

| Setting Key | Hardened Value (Default) | Security Purpose |
| :--- | :--- | :--- |
| `analytics.enabled` | `false` | Disables analytics and telemetry tracking. |
| `agent.confirm_actions` | `true` | Requires operator confirmation for all tool actions. |
| `agent.auto_apply_edits` | `false` | Requires manual confirmation before writing file changes. |
| `permission_mode` | `'prompt'` | Enforces interactive permission prompts for all operations. |
| `sandbox.strict_mode` | `true` | Isolates subprocesses and prevents dangerous command execution. |
| `dlp.mask_credentials` | `true` | Redacts passwords, tokens, and API keys. |

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
