# GitHub Copilot Security & Hardening Guide

## 1. Overview
- **Vendor:** `github`
- **Tool Name:** `copilot`
- **Category:** `IDE Extension`

GitHub Copilot provides real-time AI code completions and chat in VS Code, JetBrains, and Visual Studio.

---

## 2. Hardened Security Settings Reference

The following table lists the official configuration keys and their recommended safe defaults applied by the **Hardening IA** policy:

| Setting Key | Hardened Value (Default) | Security Purpose |
| :--- | :--- | :--- |
| `github.copilot.enable.plaintext` | `false` | Disables completions in unformatted text files. |
| `github.copilot.enable.markdown` | `false` | Disables completions in markdown documents to prevent prompt injection. |
| `github.copilot.enable.scminput` | `false` | Prevents AI completions in Git commit message fields. |
| `github.copilot.enable..env` | `false` | Prevents code suggestions or context reading in environment secret files. |
| `telemetry.telemetryLevel` | `'off'` | Disables editor and extension diagnostic telemetry. |

---

## 3. Configuration Policy
Declarative policy file: [`configs/tools/github/copilot/hardening_policy.yaml`](file:///B:/Code/hardening-ia/configs/tools/github/copilot/hardening_policy.yaml)

### 🚀 Enforcement Commands
```bash
# Apply hardening policy:
python main.py --tool github/copilot --apply

# Dry run simulation:
python main.py --tool github/copilot --apply --dry-run
```
