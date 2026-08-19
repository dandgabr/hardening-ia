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
- **Data Loss Prevention (DLP):** Exclude credentials, tokens, and SSH/cloud keys from context pipelines.
- **Zero-Telemetry Lockdown:** Enforce `DO_NOT_TRACK`, disable crash uploads and model training consent.
- **Audit Logging:** Emits structured JSONL audit logs (`logs/audit.jsonl`) for enterprise SIEM/EDR ingestion.

---

## 🤖 Supported AI Tools

| Vendor | Tool | Category | Policy Reference |
|---|---|---|---|
| **Google** | Antigravity | Agentic (CLI, IDE, MCP) | [`google/antigravity`](file:///B:/Code/hardening-ia/configs/tools/google/antigravity/hardening_policy.yaml) |
| **Anthropic** | Claude Code | CLI Agent | [`anthropic/claude-code`](file:///B:/Code/hardening-ia/configs/tools/anthropic/claude-code/hardening_policy.yaml) |
| **OpenAI** | Codex | CLI Agent | [`openai/codex`](file:///B:/Code/hardening-ia/configs/tools/openai/codex/hardening_policy.yaml) |
| **OpenCode** | OpenCode | CLI Agent | [`opencode/opencode`](file:///B:/Code/hardening-ia/configs/tools/opencode/opencode/hardening_policy.yaml) |
| **Nous Research** | Hermes Agent | Agentic | [`nousresearch/hermes-agent`](file:///B:/Code/hardening-ia/configs/tools/nousresearch/hermes-agent/hardening_policy.yaml) |
| **Qoder** | Qoder | Agentic | [`qoder/qoder`](file:///B:/Code/hardening-ia/configs/tools/qoder/qoder/hardening_policy.yaml) |
| **GitHub** | Copilot | IDE Extension | [`github/copilot`](file:///B:/Code/hardening-ia/configs/tools/github/copilot/hardening_policy.yaml) |
| **Anysphere** | Cursor | AI-Native IDE | [`anysphere/cursor`](file:///B:/Code/hardening-ia/configs/tools/anysphere/cursor/hardening_policy.yaml) |
| **Kilo** | Kilo Code | CLI Suite | [`kilo/kilo-code`](file:///B:/Code/hardening-ia/configs/tools/kilo/kilo-code/hardening_policy.yaml) |
| **Cline** | Cline | Agentic | [`cline/cline`](file:///B:/Code/hardening-ia/configs/tools/cline/cline/hardening_policy.yaml) |
| **ClinePass** | ClinePass | Security Wrapper | [`clinepass/clinepass`](file:///B:/Code/hardening-ia/configs/tools/clinepass/clinepass/hardening_policy.yaml) |
| **CodeBuddy** | CodeBuddy | IDE Assistant | [`codebuddy/codebuddy`](file:///B:/Code/hardening-ia/configs/tools/codebuddy/codebuddy/hardening_policy.yaml) |
| **Moonshot** | Kimi | CLI Agent | [`moonshot/kimi`](file:///B:/Code/hardening-ia/configs/tools/moonshot/kimi/hardening_policy.yaml) |
| **xAI** | Grok | CLI Agent | [`xai/grok`](file:///B:/Code/hardening-ia/configs/tools/xai/grok/hardening_policy.yaml) |

---

## 📂 Repository Structure

```
hardening-ia/
├── docs/                               # Comprehensive technical documentation
│   ├── ARCHITECTURE.md                 # System architecture and execution flow
│   ├── HARDENING_GUIDELINES.md         # Threat models and security pillars
│   ├── CONFIG_SPEC.md                  # Declarative YAML policy specification
│   └── tools/                          # Dedicated guides for all 14 tools
├── configs/                            # Declarative YAML policies
│   └── tools/<vendor>/<tool>/          # Hardening policy definitions
├── scripts/                            # Platform execution automation
│   ├── os/                             # Native OS scripts (Windows .ps1, Linux/macOS .sh)
│   └── extra-tools/                    # Extra security tool installers (e.g. ai-jail)
├── src/                                # Core application source code
│   ├── core/                           # Engine, models, logger, parser
│   ├── cli/                            # Headless CLI runner with Rich tables
│   └── tui/                            # Interactive Terminal UI with Textual
├── logs/                               # Rolling logs and JSONL audit trail (.gitignored)
├── main.py                             # Unified CLI / TUI entrypoint
├── pyproject.toml                      # Package configuration
├── requirements.txt                    # Python dependencies
├── .gitignore                          # Standardized ignore rules
└── README.md                           # Quickstart guide
```

---

## 🚀 Prerequisites & Installation

### Prerequisites
- **Python 3.9+**
- **Windows:** PowerShell 5.1+ or PowerShell 7+
- **Linux / macOS:** Bash or Zsh

### Virtual Environment Setup
```bash
# Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
# or on Windows:
.venv\Scripts\Activate.ps1

# Install requirements
pip install -r requirements.txt
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

- **List all available tools and their host installation status:**
  ```bash
  python main.py --list
  ```

- **List only tools installed on the current host:**
  ```bash
  python main.py --list --installed-only
  ```

- **Evaluate Linux Command Risk Level (Low/Medium/High/Critical):**
  ```bash
  python main.py --check-command "ls -la"
  python main.py --check-command "mkdir new_folder"
  python main.py --check-command "sudo systemctl restart nginx"
  python main.py --check-command "rm -rf /"
  ```

- **Apply hardening only to installed tools:**
  ```bash
  python main.py --apply --installed-only
  ```

- **Apply hardening to a specific tool:**
  ```bash
  python main.py --tool google/antigravity --apply
  python main.py --tool cursor --apply
  ```

- **Simulate execution (Dry Run):**
  ```bash
  python main.py --tool claude-code --apply --dry-run
  ```

- **Install extra containment runtime (`ai-jail`):**
  ```bash
  python main.py --install-extra ai-jail
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

- [System Architecture](docs/ARCHITECTURE.md)
- [Hardening Guidelines & Threat Model](docs/HARDENING_GUIDELINES.md)
- [YAML Policy Configuration Specification](docs/CONFIG_SPEC.md)
