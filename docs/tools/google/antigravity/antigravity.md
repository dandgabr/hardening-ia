# Google Antigravity Security & Hardening Guide

## 1. Overview
- **Vendor:** `google`
- **Tool Name:** `antigravity`
- **Category:** `Agentic Platform (CLI, IDE, MCP, SDK)`

Google Antigravity is an agent-first developer platform featuring IDE workspace orchestration, CLI execution, subagents, and Model Context Protocol (MCP) integrations.

---

## 2. Hardened Security Settings Reference

The following table lists the official configuration keys and their recommended safe defaults applied by the **Hardening IA** policy:

| Setting Key | Hardened Value (Default) | Security Purpose |
| :--- | :--- | :--- |
| `toolPermissions` | `'request-review'` | Ensures the agent prompts for approval on all mutating actions. |
| `enableTerminalSandbox` | `true` | Restricts agent-initiated terminal commands to a secure OS container. |
| `allowNonWorkspaceAccess` | `false` | Blocks the agent from accessing files outside defined project directories. |
| `hooks.enforceGuardrails` | `true` | Enforces deterministic security checks before/after tool calls. |
| `telemetry.enabled` | `false` | Disables usage and prompt transmission to external telemetry. |
| `crashReporting.enabled` | `false` | Prevents memory dumps from sending code fragments to Google. |

---

## 3. Configuration Policy
Declarative policy file: [`configs/tools/google/antigravity/hardening_policy.yaml`](../../../../configs/tools/google/antigravity/hardening_policy.yaml)

### 🚀 Enforcement Commands
```bash
# Apply hardening policy:
python main.py --tool google/antigravity --apply

# Dry run simulation:
python main.py --tool google/antigravity --apply --dry-run
```
