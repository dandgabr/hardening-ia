# Claude Code CLI Security & Hardening Guide

## 1. Overview
- **Vendor:** `anthropic`
- **Tool Name:** `claude-code`
- **Category:** `CLI Agent & Enterprise Sandboxing`

Claude Code is an agentic terminal coding assistant capable of editing repositories, running bash commands, managing development workflows, and executing in OS-level sandboxes.

---

## 2. Hardened Security Settings Reference

The following table lists the official configuration keys and their recommended safe defaults applied by the **Hardening IA** policy:

| Setting Key | Hardened Value (Default) | Security Purpose |
| :--- | :--- | :--- |
| `permissions.defaultMode` | `'manual'` | Prompts for confirmation on all terminal and filesystem actions. |
| `permissions.disableBypassPermissionsMode` | `'disable'` | Disallows '--dangerously-skip-permissions' flag and bypass mode. |
| `permissions.disableAutoMode` | `'disable'` | Blocks autonomous execution without supervision. |
| `permissions.deny` | `[destructive commands, DLP secrets, WebDAV \*, SSRF metadata]` | Explicit deny list rejecting risky operations without prompting. |
| `permissions.ask` | `['Bash(*)', 'PowerShell(*)', 'Edit(*)', 'Write(*)', 'WebFetch(*)']` | Human-in-the-loop confirmation on all mutating operations. |
| `sandbox.enabled` | `true` | Enforces OS process and filesystem sandboxing. |
| `sandbox.autoAllowBashIfSandboxed` | `true (standard) / false (strict)` | Controls whether commands inside the sandbox auto-execute or require human confirmation. |
| `sandbox.allowUnsandboxedCommands` | `false` | Blocks fallback to 'dangerouslyDisableSandbox' when a command fails. |
| `sandbox.failIfUnavailable` | `true` | Halts execution if sandbox dependencies (bubblewrap, socat, seatbelt) are unavailable. |
| `sandbox.network.strictAllowlist` | `false (standard) / true (strict)` | In strict mode, automatically denies any network access outside allowedDomains without prompting. |
| `sandbox.network.deniedDomains` | `['169.254.169.254', 'metadata.google.internal', 'localhost']` | Blocks SSRF and cloud metadata access. |
| `sandbox.filesystem.denyWrite` | `[C:\Windows, /etc, /boot, /root, /sys, /proc]` | Isolates critical OS directories from modification. |
| `sandbox.filesystem.denyRead` | `[~/.ssh, ~/.aws, **/.env*, ~/.credentials.json]` | Blocks sensitive credentials and API keys from file reading. |
| `permissionExplainerEnabled` | `true` | Enables Ctrl+E risk analysis in interactive confirmation prompts. |
| `disableDeepLinkRegistration` | `'disable'` | Blocks registration of 'claude-cli://' URL scheme handlers. |
| `disableSkillShellExecution` | `true` | Disables inline shell execution in custom skills and prompts. |
| `disableRemoteControl` | `true` | Blocks remote web-to-CLI control sessions. |
| `env.DO_NOT_TRACK` | `'1'` | Opt-out from usage and interaction tracking. |
| `env.CLAUDE_CODE_SUBPROCESS_ENV_SCRUB` | `'1'` | Strips sensitive credentials from subprocess environments. |

---

## 3. Configuration Policy
Declarative policy file: [`configs/tools/anthropic/claude-code/hardening_policy.yaml`](file:///configs/tools/anthropic/claude-code/hardening_policy.yaml)

### 🚀 Enforcement Commands
```bash
# Apply hardening policy:
python main.py --tool anthropic/claude-code --apply

# Dry run simulation:
python main.py --tool anthropic/claude-code --apply --dry-run
```
