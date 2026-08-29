# Hardening IA 🛡️🤖

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-windows%20%7C%20linux%20%7C%20macos-lightgrey.svg)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

An enterprise-grade, multi-platform framework for automating security hardening, runtime containment, DLP protection, compliance governance reporting, and telemetry lockdown across 21 AI-assisted development tools (CLIs, IDEs, and Autonomous Agents).

---

## 📑 Table of Contents

- [Overview](#-overview)
- [Supported AI Tools (21 Unified Tools)](#-supported-ai-tools-21-unified-tools)
- [Enterprise Compliance & Governance](#-enterprise-compliance--governance)
- [Real-time Security Watchdog](#-real-time-security-watchdog)
- [Runtime Sandboxing & Seccomp-BPF](#-runtime-sandboxing--seccomp-bpf)
- [Usage Guide](#-usage-guide)
  - [1. Headless CLI Automation Mode](#1-headless-cli-automation-mode)
  - [2. Interactive Terminal UI (TUI with Textual)](#2-interactive-terminal-ui-tui-with-textual)
- [Logging & Security Auditing](#-logging--security-auditing)
- [Documentation Index](#-documentation-index)

---

## 🌟 Overview

AI developer assistants introduce critical new threat vectors: unintended command execution by autonomous agents, indirect prompt injection, sensitive secret exfiltration, SSRF exfiltration against cloud metadata services, and unconsented source code ingestion into cloud training sets.

**Hardening IA** provides a unified, declarative pipeline to enforce robust enterprise baselines:
- **Unified Product Architecture:** Hardens CLI, IDE, and ADE / Desktop extensions under a single coherent product interface.
- **Automatic Post-Application Verification:** Immediately audits modified files on disk after applying policies and outputs a live compliance table.
- **Prominent Visual Banners:** High-visibility yellow Dry Run and crimson Strict Mode alert panels.
- **Runtime Sandboxing:** Seccomp-BPF filters denying dangerous syscalls, Bubblewrap namespace isolation, and Cloud Metadata SSRF guardrails.
- **Enterprise Governance Reporting:** Multi-format exporters (**Interactive HTML**, **SARIF 2.1.0**, **JSON**, **Markdown**) mapped directly to **OWASP Top 10 for LLM (2025)**, **NIST AI RMF 1.0**, and **ISO/IEC 42001:2023**.
- **Real-time Security Watchdog Daemon:** Continuous background monitoring for configuration drift, file tampering, and auto-remediation.
- **Multi-OS Command Risk Classifier:** 390+ commands categorized across Linux, Windows, and macOS into LOW, MEDIUM, HIGH, and CRITICAL risk tiers.
- **Data Loss Prevention (DLP):** Excludes credentials, tokens, and private keys from prompt context pipelines.
- **Zero-Telemetry Lockdown:** Enforces `DO_NOT_TRACK`, disables telemetry, analytics, crash uploads, and training sharing.

---

## 🤖 Supported AI Tools (21 Unified Tools)

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
| **Codeium** | Windsurf | Cascade ADE Desktop & CLI | [hardening_policy.yaml](configs/tools/codeium/windsurf/hardening_policy.yaml) | [windsurf.md](docs/tools/codeium/windsurf/windsurf.md) |
| **Continue** | Continue.dev | Headless Agent & IDE | [hardening_policy.yaml](configs/tools/continuedev/continue/hardening_policy.yaml) | [continue.md](docs/tools/continuedev/continue/continue.md) |
| **Aider** | Aider | Git AI Pair Programming CLI | [hardening_policy.yaml](configs/tools/aider/aider/hardening_policy.yaml) | [aider.md](docs/tools/aider/aider/aider.md) |
| **Amazon** | Amazon Q | AWS CLI & IDE Assistant | [hardening_policy.yaml](configs/tools/amazon/amazon-q/hardening_policy.yaml) | [amazon-q.md](docs/tools/amazon/amazon-q/amazon-q.md) |
| **Tabnine** | Tabnine | Privacy AI (CLI & IDE) | [hardening_policy.yaml](configs/tools/tabnine/tabnine/hardening_policy.yaml) | [tabnine.md](docs/tools/tabnine/tabnine/tabnine.md) |
| **Augment** | Augment Code | Workspace Agent & IDE | [hardening_policy.yaml](configs/tools/augment/augment/hardening_policy.yaml) | [augment.md](docs/tools/augment/augment/augment.md) |

---

## 🏛️ Enterprise Compliance & Governance

Export formal compliance audit reports in multiple standard formats:

```bash
# Interactive HTML Dashboard
python main.py --report --format html --output reports/compliance.html

# OASIS SARIF 2.1.0 for GitHub Security Tab / CI Code Scanning
python main.py --report --format sarif --output reports/compliance.sarif

# JSON format for DevSecOps pipelines
python main.py --report --format json --output reports/compliance.json

# Markdown format
python main.py --report --format markdown --output reports/compliance.md
```

### Framework Mappings Matrix:
- **OWASP Top 10 for LLM (2025):** LLM01 (Prompt Injection), LLM02 (Sensitive Information Disclosure), LLM06 (Excessive Agency), LLM07 (System Prompt Leakage), LLM10 (Unbounded Consumption).
- **NIST AI RMF 1.0:** GOVERN-1.1, MAP-1.5, MEASURE-2.3, MANAGE-1.2.
- **ISO/IEC 42001:2023:** Clauses A.6.2 (Data Security), A.8.4 (System Boundary Isolation), A.9.3 (Access Authorization).

---

## 👁️ Real-time Security Watchdog

Run the background watchdog daemon to monitor configuration files for unauthorized drift or tampering:

```bash
# Monitor configuration drift every 5 seconds
python main.py --watch --interval 5

# Monitor and automatically re-apply hardened policies upon detecting drift
python main.py --watch --interval 5 --auto-remediate
```

---

## 🛡️ Runtime Sandboxing & Seccomp-BPF

Inspect host kernel isolation features and runtime sandboxing capabilities:

```bash
python main.py --sandbox-diagnostics
```

Outputs live host diagnostics:
- **Bubblewrap (`bwrap`):** User namespaces, rootfs read-only mounts, and isolated PID namespaces.
- **Seccomp-BPF Syscall Filtering:** Blocks dangerous kernel calls (`ptrace`, `kexec_load`, `reboot`, `swapon`, raw socket creation).
- **SSRF & Cloud Metadata Guard:** Blocks `169.254.169.254`, `metadata.google.internal`, and container metadata endpoints.
- **`ai-jail` Wrapper:** Encapsulates CLI agents in dedicated sandboxed workspaces.

---

## 🚀 Usage Guide

### 1. Headless CLI Automation Mode

```bash
# List all 21 tools and host detection status
python main.py --list

# Apply hardening to all detected tools on the host with automatic verification
python main.py --apply --installed-only

# Apply STRICT zero-trust mode (immediate dangerous path rejection & critical command blocks)
python main.py --apply --installed-only --strict

# Simulate changes without modifying disk files (shows prominent Yellow Dry Run Banner)
python main.py --apply --installed-only --dry-run

# Revert / remove hardening policies across all 21 supported tools
python main.py --remove-all

# Audit and verify compliance on the host
python main.py --verify --installed-only

# Auto-remediate all detected discrepancies to 100% compliance
python main.py --verify --fix

# Scan workspace for AI-generated code vulnerabilities with OpenGrep
python main.py --scan-code ./src

# Test a shell command against the STRIDE risk matrix
python main.py --check-command "rm -rf /etc/shadow" --strict

# Run the complete automated test suite (64 unit & integration tests)
python main.py --test
```

### 2. Interactive Terminal UI (TUI with Textual)

Launch the modern Terminal User Interface:
```bash
python main.py
# or explicitly
python main.py -gui
```

**TUI Features & Hotkeys:**
- `Up` / `Down`: Navigate the 21-tool catalog.
- `V`: Verify selected tool's compliance score against on-disk configuration files.
- `F`: 1-Click Auto-Remediate all installed tools to 100% compliance.
- `D`: Open Data Loss Prevention (DLP) inspector dialog.
- `R`: Open the interactive Command Risk Classifier playground.
- `S`: Toggle Strict Restrictive Mode.
- `Y`: Toggle Dry Run Simulation Mode.
- `H` / `?`: Toggle help dialog.
- `Q`: Quit application.

**Action Buttons Bar:**
- **`Apply`**: Hardens the currently selected tool.
- **`Apply Installed`**: Automatically detects and hardens all tools installed on the host.
- **`Remove Selected`**: Surgically removes hardening overrides from the selected tool, restoring defaults.
- **`Remove Installed`**: Surgically removes hardening overrides from all installed tools on the host.

---

## 📦 Standalone Native Binaries (No Python Required)

Pre-compiled standalone executables are available for direct execution with zero system dependencies:

| OS | Executable Format | Release Package | Quick Start |
| :--- | :--- | :--- | :--- |
| **Linux** | ELF 64-bit | `hardening-ia-linux-x86_64.tar.gz` | `tar -xzf hardening-ia-linux-x86_64.tar.gz && ./hardening-ia` |
| **Windows** | PE32+ Executable | `hardening-ia-windows-x64.zip` | Unzip and run `.\hardening-ia.exe` |
| **macOS** | Mach-O Universal | `hardening-ia-macos-universal.tar.gz` | `tar -xzf hardening-ia-macos-universal.tar.gz && ./hardening-ia` |

For full instructions, SHA-256 checksum verification, and local build instructions, see the [Binary Distribution Guide](docs/BINARY_DISTRIBUTION.md).

---

## 📊 Logging & Security Auditing

Hardening IA maintains comprehensive structured audit trails:
- `logs/hardening.log`: Rolling framework execution logs with full debug traces.
- `logs/audit.jsonl`: Structured JSONL audit events for SIEM/EDR ingestion.

---

## 📄 License

Distributed under the **MIT License**. See [LICENSE](LICENSE) for details.
