# Amazon Q Developer Security & Hardening Guide

## 1. Overview
- **Vendor:** `amazon`
- **Tool Name:** `amazon-q`
- **Category:** `AWS CLI ('q'), IDE Extensions & ADE Chat`

Amazon Q Developer is an AWS AI assistant providing code completion, terminal commands, security vulnerability remediation, and app transformation.

---

## 2. Hardened Security Settings Reference

The following table lists the official configuration keys and their recommended safe defaults applied by the **Hardening IA** policy:

| Setting Key | Hardened Value (Default) | Security Purpose |
| :--- | :--- | :--- |
| `telemetry.enabled` | `false` | Disables telemetry transmission to AWS telemetry servers. |
| `amazonQ.shareCodeForTraining` | `false` | Opt-out from code and prompt sharing for service improvement. |
| `amazonQ.autoExecuteCommands` | `false` | Requires user approval before running shell commands suggested by Amazon Q. |
| `amazonQ.requireUserApproval` | `true` | Mandates confirmation before applying code transformation diffs. |
| `amazonQ.workspace.trust` | `true` | Enforces workspace trust boundaries before indexing projects. |

---

## 3. Configuration Policy
Declarative policy file: [`configs/tools/amazon/amazon-q/hardening_policy.yaml`](file:///configs/tools/amazon/amazon-q/hardening_policy.yaml)

### 🚀 Enforcement Commands
```bash
# Apply hardening policy:
python main.py --tool amazon/amazon-q --apply

# Dry run simulation:
python main.py --tool amazon/amazon-q --apply --dry-run
```
