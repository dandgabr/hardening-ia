# Continue.dev Security & Hardening Guide

## 1. Overview
- **Vendor:** `continuedev`
- **Tool Name:** `continue`
- **Category:** `Headless Agent, CLI & IDE Extensions`

Continue is an open-source AI code assistant providing customizable autocomplete, chat, and agentic workflows.

---

## 2. Hardened Security Settings Reference

The following table lists the official configuration keys and their recommended safe defaults applied by the **Hardening IA** policy:

| Setting Key | Hardened Value (Default) | Security Purpose |
| :--- | :--- | :--- |
| `allowAnonymousTelemetry` | `false` | Disables anonymous usage statistics and crash reporting. |
| `maskSecretsInPrompts` | `true` | Redacts API keys, credentials, and .env secrets from outgoing LLM requests. |
| `mcp.requireConsent` | `true` | Prompts for user approval before invoking MCP tools. |
| `blockLocalSSRF` | `true` | Blocks SSRF probes against cloud metadata (169.254.169.254) and local loopback. |
| `disableIndexing` | `false` | Enforces local-only codebase indexing. |

---

## 3. Configuration Policy
Declarative policy file: [`configs/tools/continuedev/continue/hardening_policy.yaml`](file:///configs/tools/continuedev/continue/hardening_policy.yaml)

### 🚀 Enforcement Commands
```bash
# Apply hardening policy:
python main.py --tool continuedev/continue --apply

# Dry run simulation:
python main.py --tool continuedev/continue --apply --dry-run
```
