# Kilo Code Security & Hardening Guide

## 1. Overview
- **Vendor:** `kilo`
- **Tool Name:** `kilo-code`
- **Category:** `CLI Developer Suite`

Kilo Code is a command-line tool designed for fast code indexing and agentic refactoring.

---

## 2. Hardened Security Settings Reference

The following table lists the official configuration keys and their recommended safe defaults applied by the **Hardening IA** policy:

| Setting Key | Hardened Value (Default) | Security Purpose |
| :--- | :--- | :--- |
| `privacy.telemetry` | `false` | Disables usage and crash telemetry. |
| `execution.require_confirmation` | `true` | Requires confirmation on file and shell operations. |

---

## 3. Configuration Policy
Declarative policy file: [`configs/tools/kilo/kilo-code/hardening_policy.yaml`](../../../../configs/tools/kilo/kilo-code/hardening_policy.yaml)

### 🚀 Enforcement Commands
```bash
# Apply hardening policy:
python main.py --tool kilo/kilo-code --apply

# Dry run simulation:
python main.py --tool kilo/kilo-code --apply --dry-run
```
