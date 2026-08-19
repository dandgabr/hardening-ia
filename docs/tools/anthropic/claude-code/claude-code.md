# Claude Code CLI Security & Hardening Guide

## 1. Overview
- **Vendor:** `anthropic`
- **Tool Name:** `claude-code`
- **Category:** `CLI Agent`

Claude Code is an agentic terminal coding assistant capable of editing repositories, running bash commands, and managing development workflows.

---

## 2. Hardened Security Settings Reference

The following table lists the official configuration keys and their recommended safe defaults applied by the **Hardening IA** policy:

| Setting Key | Hardened Value (Default) | Security Purpose |
| :--- | :--- | :--- |
| `permissionMode` | `'manual'` | Prompts for confirmation on all terminal and filesystem actions. |
| `autoApprove` | `[]` | Empty auto-approve list ensuring human-in-the-loop validation. |
| `acceptEdits` | `false` | Disallows automatic file modification without explicit diff inspection. |
| `dangerouslySkipPermissions` | `false` | Strictly blocks permission bypass mode. |
| `disableTelemetry` | `true` | Disables interaction metrics and analytics transmission. |
| `maxCostThresholdUSD` | `10.0` | Protects against runaway agent loops and cost spikes. |

---

## 3. Configuration Policy
Declarative policy file: [`configs/tools/anthropic/claude-code/hardening_policy.yaml`](../../../../configs/tools/anthropic/claude-code/hardening_policy.yaml)

### 🚀 Enforcement Commands
```bash
# Apply hardening policy:
python main.py --tool anthropic/claude-code --apply

# Dry run simulation:
python main.py --tool anthropic/claude-code --apply --dry-run
```
