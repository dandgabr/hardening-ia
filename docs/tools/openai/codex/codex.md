# OpenAI Codex CLI Security & Hardening Guide

## 1. Overview
- **Vendor:** `openai`
- **Tool Name:** `codex`
- **Category:** `CLI Agent & Code Engine`

OpenAI Codex CLI agent handles automated code synthesis, command line execution, and workflow automation.

---

## 2. Hardened Security Settings Reference

The following table lists the official configuration keys and their recommended safe defaults applied by the **Hardening IA** policy:

| Setting Key | Hardened Value (Default) | Security Purpose |
| :--- | :--- | :--- |
| `telemetry` | `false` | Disables diagnostic telemetry and prompt tracking. |
| `auto_execute` | `false` | Requires operator consent before executing terminal commands. |
| `enforce_sandboxing` | `true` | Executes shell commands in a restricted container. |
| `trusted_workspaces_only` | `true` | Restricts execution to verified workspaces. |
| `allow_network` | `false` | Restricts unapproved external network connections. |
| `prompt_secret_masking` | `true` | Masks detected secrets from outbound API prompts. |

---

## 3. Configuration Policy
Declarative policy file: [`configs/tools/openai/codex/hardening_policy.yaml`](file:///configs/tools/openai/codex/hardening_policy.yaml)

### 🚀 Enforcement Commands
```bash
# Apply hardening policy:
python main.py --tool openai/codex --apply

# Dry run simulation:
python main.py --tool openai/codex --apply --dry-run
```
