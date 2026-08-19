# Hermes Agent Security & Hardening Guide

## 1. Overview
- **Vendor:** `nousresearch`
- **Tool Name:** `hermes-agent`
- **Category:** `Autonomous Agent`

Hermes Agent provides deep reasoning and autonomous tool execution.

---

## 2. Hardened Security Settings Reference

The following table lists the official configuration keys and their recommended safe defaults applied by the **Hardening IA** policy:

| Setting Key | Hardened Value (Default) | Security Purpose |
| :--- | :--- | :--- |
| `safe_mode` | `true` | Enforces strict safety rails during multi-step reasoning. |
| `human_in_the_loop` | `true` | Pauses execution to obtain operator confirmation. |
| `max_recursive_steps` | `10` | Prevents infinite reasoning loops. |

---

## 3. Configuration Policy
Declarative policy file: [`configs/tools/nousresearch/hermes-agent/hardening_policy.yaml`](../../../../configs/tools/nousresearch/hermes-agent/hardening_policy.yaml)

### 🚀 Enforcement Commands
```bash
# Apply hardening policy:
python main.py --tool nousresearch/hermes-agent --apply

# Dry run simulation:
python main.py --tool nousresearch/hermes-agent --apply --dry-run
```
