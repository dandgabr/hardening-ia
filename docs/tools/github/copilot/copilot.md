# GitHub Copilot Security & Hardening Guide

## 1. Overview
- **Vendor:** `github`
- **Tool Name:** `copilot`
- **Category:** `IDE Extension & Copilot Chat/Edits`

GitHub Copilot provides real-time AI code completions, chat, and agentic edits in VS Code, JetBrains, and Visual Studio.

---

## 2. Hardened Security Settings Reference

The following table lists the official configuration keys and their recommended safe defaults applied by the **Hardening IA** policy:

| Setting Key | Hardened Value (Default) | Security Purpose |
| :--- | :--- | :--- |
| `chat.tools.global.autoApprove` | `false` | Disables automatic tool and command approval in Copilot Chat Agent mode. |
| `chat.tools.eligibleForAutoApproval` | `[]` | Ensures no tools or shell actions are eligible for automatic bypass. |
| `chat.tools.confirm` | `'always'` | Enforces interactive user confirmation before any tool execution. |
| `github.copilot.chat.terminal.autoExecute` | `false` | Prevents Copilot from auto-running commands in the integrated terminal. |
| `github.copilot.chat.autoApplyEdits` | `false` | Requires manual inspection of file diffs before changes are accepted. |
| `chat.agent.allowTerminal` | `false` | Restricts autonomous terminal invocation by agent subroutines. |
| `github.copilot.enable.plaintext` | `false` | Disables completions in unformatted text files. |
| `github.copilot.enable.markdown` | `false` | Disables completions in markdown documents to prevent prompt injection. |
| `github.copilot.enable.scminput` | `false` | Prevents AI completions in Git commit message fields. |
| `github.copilot.enable..env` | `false` | Prevents code suggestions or context reading in environment secret files. |
| `telemetry.telemetryLevel` | `'off'` | Disables editor and extension diagnostic telemetry. |

---

## 3. Configuration Policy
Declarative policy file: [`configs/tools/github/copilot/hardening_policy.yaml`](file:///configs/tools/github/copilot/hardening_policy.yaml)

### 🚀 Enforcement Commands
```bash
# Apply hardening policy:
python main.py --tool github/copilot --apply

# Dry run simulation:
python main.py --tool github/copilot --apply --dry-run
```
