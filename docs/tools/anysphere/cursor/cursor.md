# Cursor IDE Security & Hardening Guide

## 1. Overview
- **Vendor:** `anysphere`
- **Tool Name:** `cursor`
- **Category:** `AI-Native IDE`

Cursor is an AI-powered code editor with agentic terminal execution and codebase indexing.

---

## 2. Hardened Security Settings Reference

The following table lists the official configuration keys and their recommended safe defaults applied by the **Hardening IA** policy:

| Setting Key | Hardened Value (Default) | Security Purpose |
| :--- | :--- | :--- |
| `cursor.privacyMode` | `true` | Enforces Zero Data Retention (ZDR); code is not stored or used for model training. |
| `cursor.general.privacy` | `'no-retention'` | Guarantees prompts and file contents are erased immediately after generation. |
| `cursor.terminal.autoExecute` | `false` | Requires explicit approval before any shell command is run by the agent. |
| `cursor.terminal.sandbox` | `true` | Enforces process isolation for terminal executions. |
| `cursor.indexer.ignorePatterns` | `[.env*, *.pem, *.key, ~/.ssh/**, ~/.aws/**]` | Prevents indexing sensitive secrets into the semantic database. |

---

## 3. Configuration Policy
Declarative policy file: [`configs/tools/anysphere/cursor/hardening_policy.yaml`](../../../../configs/tools/anysphere/cursor/hardening_policy.yaml)

### 🚀 Enforcement Commands
```bash
# Apply hardening policy:
python main.py --tool anysphere/cursor --apply

# Dry run simulation:
python main.py --tool anysphere/cursor --apply --dry-run
```
