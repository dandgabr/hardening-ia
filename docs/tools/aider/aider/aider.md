# Aider Pair Programming CLI Security & Hardening Guide

## 1. Overview
- **Vendor:** `aider`
- **Tool Name:** `aider`
- **Category:** `Git AI Pair Programming CLI`

Aider is a terminal-based AI pair programming tool that edits local files directly in Git repositories with automatic commit tracking.

---

## 2. Hardened Security Settings Reference

The following table lists the official configuration keys and their recommended safe defaults applied by the **Hardening IA** policy:

| Setting Key | Hardened Value (Default) | Security Purpose |
| :--- | :--- | :--- |
| `analytics` | `false` | Disables analytics and external usage reporting. |
| `verify-ssl` | `true` | Enforces strict SSL/TLS certificate verification on all API endpoints. |
| `auto-commits` | `true` | Ensures every AI modification is committed with an isolated git revision for instant rollbacks. |
| `attribute-author` | `false` | Prevents AI authorship metadata attribution in public commits. |
| `require-confirmation-on-push` | `true` | Requires operator consent before pushing git commits to remotes. |
| `mask-api-keys` | `true` | Masks LLM API tokens in chat transcript logs. |

---

## 3. Configuration Policy
Declarative policy file: [`configs/tools/aider/aider/hardening_policy.yaml`](file:///configs/tools/aider/aider/hardening_policy.yaml)

### 🚀 Enforcement Commands
```bash
# Apply hardening policy:
python main.py --tool aider/aider --apply

# Dry run simulation:
python main.py --tool aider/aider --apply --dry-run
```
