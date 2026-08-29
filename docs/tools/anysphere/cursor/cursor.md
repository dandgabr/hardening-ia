# Cursor IDE Security & Hardening Guide

## 1. Overview
- **Vendor:** `anysphere`
- **Tool Name:** `cursor`
- **Category:** `AI-Native IDE & Composer Agent`

Cursor is an AI-powered code editor with agentic Composer, terminal execution, and local codebase indexing.

---

## 2. Hardened Security Settings Reference

The following table lists the official configuration keys and their recommended safe defaults applied by the **Hardening IA** policy:

| Setting Key | Hardened Value (Default) | Security Purpose |
| :--- | :--- | :--- |
| `cursor.privacyMode` | `true` | Enforces zero retention and disallows cloud training on user code. |
| `cursor.general.privacy` | `'no-retention'` | Opt-out from prompt and code snippet logging. |
| `cursor.terminal.autoExecute` | `false` | Requires confirmation before running terminal commands. |
| `cursor.terminal.sandbox` | `true` | Enforces sandboxed terminal execution. |
| `cursor.agent.yoloMode` | `false` | Disables YOLO unprompted auto-execution in Composer and Agent modes. |
| `cursor.composer.autoApply` | `false` | Requires manual review before applying AI-generated code edits. |
| `cursor.composer.requireUserApproval` | `true` | Ensures operator approval on all multi-file modifications. |
| `cursor.mcp.requireConsent` | `true` | Prompts for approval before executing MCP tools. |
| `cursor.indexer.ignorePatterns` | `[.env*, *.pem, ~/.aws, ~/.ssh, ~/.kube]` | Prevents indexing and exfiltration of sensitive secrets and credentials. |
| `telemetry.telemetryLevel` | `'off'` | Disables diagnostic and usage telemetry. |

---

## 3. Configuration Policy
Declarative policy file: [`configs/tools/anysphere/cursor/hardening_policy.yaml`](file:///configs/tools/anysphere/cursor/hardening_policy.yaml)

### 🚀 Enforcement Commands
```bash
# Apply hardening policy:
python main.py --tool anysphere/cursor --apply

# Dry run simulation:
python main.py --tool anysphere/cursor --apply --dry-run
```
