# Hardening IA 🛡️🤖

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-windows%20%7C%20linux%20%7C%20macos-lightgrey.svg)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

An enterprise-grade, multi-platform framework for automating security hardening, runtime containment, DLP protection, and telemetry lockdown across AI-assisted development tools (CLIs, IDEs, and Autonomous Agents).

---

## 📑 Table of Contents

- [Overview](#-overview)
- [Supported AI Tools](#-supported-ai-tools)
- [Repository Structure](#-repository-structure)
- [Prerequisites & Installation](#-prerequisites--installation)
- [Extra Containment: ai-jail](#-extra-containment-ai-jail)
- [Usage Guide](#-usage-guide)
  - [1. Interactive Terminal UI (TUI with Textual)](#1-interactive-terminal-ui-tui-with-textual)
  - [2. Headless CLI Automation Mode](#2-headless-cli-automation-mode)
- [Logging & Security Auditing](#-logging--security-auditing)
- [Documentation Index](#-documentation-index)

---

## 🌟 Overview

AI developer assistants introduce new threat surfaces: unintended command execution by agents, indirect prompt injection, sensitive secret exfiltration, and unconsented source code ingestion into cloud training sets.

**Hardening IA** provides a unified, declarative pipeline to enforce robust enterprise baselines:
- **Runtime Sandboxing:** Contain autonomous subagents and shell tools.
- **Human-in-the-Loop Controls:** Disallow unrestricted auto-approvals.
- **Dangerous OS Paths Protection:** Detects host OS (Linux, Windows, macOS) and restricts sensitive paths (`/etc`, `C:\Windows`, `/System`, `~/.ssh`, `~/.aws`, `~/.kube`). In Standard Mode, always prompts before access; in Strict Mode, blocks access immediately without asking.
- **Rate Limiting & Timeouts:** Enforces 30 requests/min (burst 10) and 30s/60s command & execution timeouts across supported tools.
- **Strict Restrictive Mode:** One-click toggle in TUI and `--strict` in CLI enforcing explicit denied patterns for critical anti-patterns (`rm -rf /`, `mkfs`, `format`, `dd`, `diskpart`) with zero prompting.
- **Data Loss Prevention (DLP):** Exclude credentials, tokens, and SSH/cloud keys from context pipelines.
- **Zero-Telemetry Lockdown:** Enforce `DO_NOT_TRACK`, disable crash uploads and model training consent.
- **Multi-OS Command Risk Classifier:** 390+ commands categorized across Linux, Windows, and macOS into LOW, MEDIUM, HIGH, and CRITICAL risk tiers.
- **Dynamic Host Discovery:** Automatically detects active OS and installed AI tools before execution.
- **Audit Logging:** Emits structured JSONL audit logs (`logs/audit.jsonl`) for enterprise SIEM/EDR ingestion.

---

## 🤖 Supported AI Tools

| Vendor | Tool | Category | Hardening Policy (YAML) | Tool Security Guide |
|---|---|---|---|---|
| **Google** | Antigravity | Agentic (CLI, IDE, MCP) | [hardening_policy.yaml](configs/tools/google/antigravity/hardening_policy.yaml) | [antigravity.md](docs/tools/google/antigravity/antigravity.md) |
| **Anthropic** | Claude Code | CLI Agent | [hardening_policy.yaml](configs/tools/anthropic/claude-code/hardening_policy.yaml) | [claude-code.md](docs/tools/anthropic/claude-code/claude-code.md) |
| **OpenAI** | Codex | CLI Agent | [hardening_policy.yaml](configs/tools/openai/codex/hardening_policy.yaml) | [codex.md](docs/tools/openai/codex/codex.md) |
| **OpenCode** | OpenCode | CLI Agent | [hardening_policy.yaml](configs/tools/opencode/opencode/hardening_policy.yaml) | [opencode.md](docs/tools/opencode/opencode/opencode.md) |
| **Nous Research** | Hermes Agent | Agentic | [hardening_policy.yaml](configs/tools/nousresearch/hermes-agent/hardening_policy.yaml) | [hermes-agent.md](docs/tools/nousresearch/hermes-agent/hermes-agent.md) |
| **Qoder** | Qoder | Agentic | [hardening_policy.yaml](configs/tools/qoder/qoder/hardening_policy.yaml) | [qoder.md](docs/tools/qoder/qoder/qoder.md) |
| **GitHub** | Copilot | IDE Extension | [hardening_policy.yaml](configs/tools/github/copilot/hardening_policy.yaml) | [copilot.md](docs/tools/github/copilot/copilot.md) |
| **Anysphere** | Cursor | AI-Native IDE | [hardening_policy.yaml](configs/tools/anysphere/cursor/hardening_policy.yaml) | [cursor.md](docs/tools/anysphere/cursor/cursor.md) |
| **Kilo** | Kilo Code | CLI Suite | [hardening_policy.yaml](configs/tools/kilo/kilo-code/hardening_policy.yaml) | [kilo-code.md](docs/tools/kilo/kilo-code/kilo-code.md) |
| **Cline** | Cline | Agentic | [hardening_policy.yaml](configs/tools/cline/cline/hardening_policy.yaml) | [cline.md](docs/tools/cline/cline/cline.md) |
| **ClinePass** | ClinePass | Security Wrapper | [hardening_policy.yaml](configs/tools/clinepass/clinepass/hardening_policy.yaml) | [clinepass.md](docs/tools/clinepass/clinepass/clinepass.md) |
| **CodeBuddy** | CodeBuddy | IDE Assistant | [hardening_policy.yaml](configs/tools/codebuddy/codebuddy/hardening_policy.yaml) | [codebuddy.md](docs/tools/codebuddy/codebuddy/codebuddy.md) |
| **Moonshot** | Kimi | CLI Agent | [hardening_policy.yaml](configs/tools/moonshot/kimi/hardening_policy.yaml) | [kimi.md](docs/tools/moonshot/kimi/kimi.md) |
| **xAI** | Grok | CLI Agent | [hardening_policy.yaml](configs/tools/xai/grok/hardening_policy.yaml) | [grok.md](docs/tools/xai/grok/grok.md) |
| **zAI** | zAI Platform | Agentic (CLI, ADE & Desktop) | [hardening_policy.yaml](configs/tools/zai/zai/hardening_policy.yaml) | [zai.md](docs/tools/zai/zai/zai.md) |

---

## 📂 Repository Structure

```
hardening-ia/
├── docs/                               # Comprehensive technical documentation
│   ├── ARCHITECTURE.md                 # System architecture and execution flow
│   ├── HARDENING_GUIDELINES.md         # Threat models and security pillars
│   ├── CONFIG_SPEC.md                  # Declarative YAML policy specification
│   ├── LINUX_COMMAND_POLICY.md         # Linux command execution risk matrix (390+ cmds)
│   ├── WINDOWS_COMMAND_POLICY.md       # Windows command risk policy (PowerShell/CMD)
│   ├── MACOS_COMMAND_POLICY.md         # macOS command risk policy (Darwin/BSD)
│   └── tools/                          # Dedicated security guides for all 15 tools
├── configs/                            # Declarative YAML policies
│   ├── rules/                          # Deployed agent security rule files
│   └── tools/<vendor>/<tool>/          # Per-tool hardening policy definitions
├── scripts/                            # Platform execution automation
│   ├── os/                             # Native OS scripts (Windows .ps1, Linux/macOS .sh)
│   └── extra-tools/                    # Extra security tool installers (e.g. ai-jail)
├── src/                                # Core application source code
│   ├── core/                           # Engine, models, logger, parser, risk classifier
│   ├── cli/                            # Headless CLI runner with Rich tables
│   └── tui/                            # Interactive Terminal UI with Textual
├── logs/                               # Rolling logs and JSONL audit trail (.gitignored)
├── main.py                             # Unified CLI / TUI entrypoint
├── pyproject.toml                      # Package configuration
├── requirements.txt                    # Python dependencies
├── LICENSE                             # MIT License
├── .gitignore                          # Standardized ignore rules
└── README.md                           # Project documentation
```

---

## 🚀 Prerequisites & Installation

### Prerequisites
- **Python 3.9+**
- **Windows:** PowerShell 5.1+ or PowerShell 7+
- **Linux / macOS:** Bash or Zsh

### Quickstart (1-Step Launchers)
The repository includes native launchers for each platform that automatically detect/create the `.venv` and install dependencies:

```bash
# On Linux / macOS:
./main.sh

# On Windows (PowerShell):
.\main.ps1

# On Windows (CMD):
main.cmd
```

### Manual Virtual Environment Setup
```bash
# Create and activate virtual environment
python3 -m venv .venv

# On Linux/macOS:
source .venv/bin/activate

# On Windows (PowerShell):
.venv\Scripts\Activate.ps1

# Install requirements
pip install -r requirements.txt
```

---

## 🛡️ Extra Tools: Runtime Sandboxes & SAST Analysis

The framework provides automated dependency resolution, installation, and integration for key ecosystem security tooling:

### 1. [ai-jail](https://github.com/akitaonrails/ai-jail) (Runtime Containment)
An open-source sandbox container written in Rust that isolates AI agent processes using `bubblewrap` (Linux / WSL2) or `sandbox-exec` (macOS).

```bash
python main.py --install-extra ai-jail
```

### 2. [OpenGrep](https://github.com/opengrep/opengrep) (AI Code SAST & Vulnerability Remediation)
An enterprise-grade, fully open-source static analysis security scanner (fork of Semgrep CE) integrated with custom rules to identify and fix security flaws in AI-generated code (command injections, hardcoded credentials, insecure deserialization, SQLi, SSRF):

```bash
# Install OpenGrep binary and deploy rules:
python main.py --install-extra opengrep

# Scan the workspace or a target directory for code vulnerabilities:
python main.py --scan-code
python main.py --scan-code ./src
```

### 3. Check Status & Uninstall Extras
```bash
# Query host installation and diagnostic status:
python main.py --status-extra

# Install all components and run post-install diagnostics:
python main.py --install-extra all

# Uninstall and remove extra security components cleanly:
python main.py --remove-extra all
```

---

## 💻 Usage Guide

### 1. Interactive Terminal UI (TUI with Textual)
Launch the modern full-screen terminal interface:
```bash
python main.py
# or explicitly:
python main.py -gui
```

### 2. Headless CLI Automation Mode

- **List all available tools and their live host installation status:**
  ```bash
  python main.py --list
  ```

- **List only tools detected/installed on the current machine:**
  ```bash
  python main.py --list --installed-only
  ```

- **Evaluate Command Risk Level (Low/Medium/High/Critical across Linux, Windows, macOS):**
  ```bash
  python main.py --check-command "ls -la"
  python main.py --check-command "mkdir new_folder"
  python main.py --check-command "sudo systemctl restart nginx"
  python main.py --check-command "rm -rf /"
  ```

- **Apply hardening only to installed tools on the host:**
  ```bash
  python main.py --apply --installed-only
  ```

- **Verify that applied hardening configurations are active on the host:**
  ```bash
  python main.py --verify
  python main.py --verify --installed-only
  python main.py --tool cursor --verify
  ```

- **Run the automated unit and integration test suite:**
  ```bash
  python main.py --test
  ```

- **Scan workspace for security vulnerabilities (OpenGrep SAST & SCA):**
  ```bash
  python main.py --scan-code
  python main.py --scan-code ./src
  ```

- **Provision & apply hardening across ALL 14 supported tools:**
  ```bash
  python main.py --apply
  ```

- **Revert/remove hardening configurations from detected tools:**
  ```bash
  python main.py --remove --installed-only
  python main.py --tool cursor --remove
  ```

- **Auto-remediate any non-compliant tools to 100% compliance:**
  ```bash
  python main.py --verify --fix
  python main.py --verify --installed-only --strict --fix
  ```

- **Enterprise Administrator System-Wide Hardening (Multi-User & Read-Only Locking):**
  Enforces policies across ALL user accounts on the machine and sets file permissions to Read-Only so standard users can read the config but cannot alter or bypass it. Requires elevated privileges (Root/Administrator):
  ```bash
  # Linux & macOS (Run with sudo):
  sudo python main.py --apply --admin --installed-only
  sudo python main.py --apply --admin --strict
  sudo python main.py --verify --admin

  # Windows (Run in elevated PowerShell / Command Prompt as Administrator):
  python main.py --apply --admin --installed-only
  python main.py --apply --admin --strict
  python main.py --verify --admin
  ```

- **Verbose / Debug output:**
  ```bash
  python main.py --apply --verbose
  ```

---

## 📊 Logging & Security Auditing

- **Execution Logs:** Written to `logs/hardening.log` with automatic rotation (10 MB per file, 5 backups).
- **Structured Audit Records:** Every hardening execution produces an immutable record in `logs/audit.jsonl`:
  ```json
  {
    "timestamp": "2026-08-19T16:15:00Z",
    "event": "POLICY_APPLIED",
    "tool": "antigravity",
    "vendor": "google",
    "status": "SUCCESS",
    "details": {
      "dry_run": false,
      "os": "windows",
      "modified_paths": ["C:\\Users\\dev\\.gemini\\antigravity-cli\\settings.json"],
      "changes_count": 4
    }
  }
  ```

---

## 📖 Documentation Index

- [CLI, Commands & Parameters Reference Manual](docs/CLI_REFERENCE.md)
- [System Architecture](docs/ARCHITECTURE.md)
- [Enterprise Hardening Guidelines & Threat Model](docs/HARDENING_GUIDELINES.md)
- [YAML Policy Configuration Specification](docs/CONFIG_SPEC.md)
- [Linux Command Execution Risk Matrix](docs/LINUX_COMMAND_POLICY.md)
- [Windows Command Execution Risk Matrix](docs/WINDOWS_COMMAND_POLICY.md)
- [macOS Command Execution Risk Matrix](docs/MACOS_COMMAND_POLICY.md)
- [OpenGrep SAST & SCA Security Ruleset Specification](docs/OPENGREP_SECURITY_CONFIG.md)
- [Tool Documentation Directory](docs/tools/)
