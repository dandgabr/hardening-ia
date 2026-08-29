# Windsurf (Codeium) Security & Hardening Guide

## 1. Overview
- **Vendor:** `codeium`
- **Tool Name:** `windsurf`
- **Category:** `Cascade ADE Desktop, CLI & IDE Extensions`

Windsurf is Codeium's AI-native IDE featuring Cascade ADE, automated workflows, and multi-file code editing.

---

## 2. Hardened Security Settings Reference

The following table lists the official configuration keys and their recommended safe defaults applied by the **Hardening IA** policy:

| Setting Key | Hardened Value (Default) | Security Purpose |
| :--- | :--- | :--- |
| `windsurf.privacyMode` | `true` | Enforces zero retention and prevents cloud training on proprietary code. |
| `codeium.enableTelemetry` | `false` | Disables diagnostic telemetry and prompt metrics transmission. |
| `codeium.enterprise.zeroDataRetention` | `true` | Enforces zero data retention on enterprise AI gateways. |
| `windsurf.cascade.autoExecute` | `false` | Requires interactive user confirmation before Cascade executes commands. |
| `windsurf.cascade.yoloMode` | `false` | Disables unprompted YOLO auto-execution in Cascade ADE. |
| `windsurf.cascade.requireApproval` | `true` | Requires explicit review on multi-file modifications. |
| `mcp.requireConsent` | `true` | Mandates confirmation before invoking Model Context Protocol tools. |
| `telemetry.telemetryLevel` | `'off'` | Disables telemetry reporting in VS Code/Windsurf base. |

---

## 3. Configuration Policy
Declarative policy file: [`configs/tools/codeium/windsurf/hardening_policy.yaml`](file:///configs/tools/codeium/windsurf/hardening_policy.yaml)

### 🚀 Enforcement Commands
```bash
# Apply hardening policy:
python main.py --tool codeium/windsurf --apply

# Dry run simulation:
python main.py --tool codeium/windsurf --apply --dry-run
```
