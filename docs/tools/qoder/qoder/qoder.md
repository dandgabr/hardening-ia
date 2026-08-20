# Qoder Security & Hardening Guide

## 1. Overview
- **Vendor:** `qoder`
- **Tool Name:** `qoder`
- **Category:** `Enterprise Agent`

Qoder is an enterprise coding companion providing semantic search and workflow automation.

---

## 2. Hardened Security Settings Reference

The following table lists the official configuration keys and their recommended safe defaults applied by the **Hardening IA** policy:

| Setting Key | Hardened Value (Default) | Security Purpose |
| :--- | :--- | :--- |
| `telemetry.shareData` | `false` | Disables enterprise codebase sharing. |
| `security.executionConsent` | `'always'` | Requires approval on every automated action. |

---

## 3. Configuration Policy
Declarative policy file: [`configs/tools/qoder/qoder/hardening_policy.yaml`](file:///B:/Code/hardening-ia/configs/tools/qoder/qoder/hardening_policy.yaml)

### 🚀 Enforcement Commands
```bash
# Apply hardening policy:
python main.py --tool qoder/qoder --apply

# Dry run simulation:
python main.py --tool qoder/qoder --apply --dry-run
```
