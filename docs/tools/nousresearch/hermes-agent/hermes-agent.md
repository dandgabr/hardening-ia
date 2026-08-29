# Hermes Agent Security & Hardening Guide

## 1. Overview
- **Vendor:** `nousresearch`
- **Tool Name:** `hermes-agent`
- **Category:** `Autonomous Reasoning Agent`

Hermes Agent is an open-weights reasoning and autonomous execution agent capable of complex multi-step coding tasks.

---

## 2. Hardened Security Settings Reference

The following table lists the official configuration keys and their recommended safe defaults applied by the **Hardening IA** policy:

| Setting Key | Hardened Value (Default) | Security Purpose |
| :--- | :--- | :--- |
| `enable_telemetry` | `false` | Disables telemetry data collection. |
| `human_in_the_loop` | `true` | Mandates human confirmation at critical execution branches. |
| `safe_mode` | `true` | Enforces safe execution guardrails and blocks high-risk tools. |
| `max_recursive_steps` | `10` | Limits maximum subagent recursion to prevent runaway loops. |
| `sandbox_container` | `true` | Runs agent subprocesses in an isolated environment. |
| `blocked_tools` | `['system_admin', 'raw_exec', 'disk_partition']` | Disables dangerous system tools. |

---

## 3. Configuration Policy
Declarative policy file: [`configs/tools/nousresearch/hermes-agent/hardening_policy.yaml`](file:///configs/tools/nousresearch/hermes-agent/hardening_policy.yaml)

### 🚀 Enforcement Commands
```bash
# Apply hardening policy:
python main.py --tool nousresearch/hermes-agent --apply

# Dry run simulation:
python main.py --tool nousresearch/hermes-agent --apply --dry-run
```
