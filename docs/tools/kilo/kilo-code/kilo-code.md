# Kilo Code CLI Security & Hardening Guide

## 1. Overview
- **Vendor:** `kilo`
- **Tool Name:** `kilo-code`
- **Category:** `High-Performance CLI Developer Suite`

Kilo Code is a fast, terminal-based AI assistant designed for rapid software engineering and code generation.

---

## 2. Hardened Security Settings Reference

The following table lists the official configuration keys and their recommended safe defaults applied by the **Hardening IA** policy:

| Setting Key | Hardened Value (Default) | Security Purpose |
| :--- | :--- | :--- |
| `privacy.telemetry` | `false` | Disables usage tracking and metrics transmission. |
| `execution.require_confirmation` | `true` | Requires approval before running shell commands. |
| `execution.auto_accept_edits` | `false` | Requires manual diff inspection before accepting file changes. |
| `sandbox.enabled` | `true` | Restricts execution to a sandbox environment. |
| `indexing.exclude_hidden_and_secrets` | `true` | Excludes secret files from codebase indexing. |

---

## 3. Configuration Policy
Declarative policy file: [`configs/tools/kilo/kilo-code/hardening_policy.yaml`](file:///configs/tools/kilo/kilo-code/hardening_policy.yaml)

### 🚀 Enforcement Commands
```bash
# Apply hardening policy:
python main.py --tool kilo/kilo-code --apply

# Dry run simulation:
python main.py --tool kilo/kilo-code --apply --dry-run
```
