# 📖 Complete Commands, Parameters, and Arguments Reference Manual (CLI & TUI)

This document provides the complete technical specification and user manual for all commands, launcher scripts, flags, parameters, execution modes, and behaviors within the **Hardening IA Framework**.

---

## 📑 Table of Contents

1. [Launcher Scripts](#1-launcher-scripts)
2. [General CLI Syntax](#2-general-cli-syntax)
3. [Summary Table of Parameters & Flags](#3-summary-table-of-parameters--flags)
4. [Detailed Parameter & Subcommand Reference](#4-detailed-parameter--subcommand-reference)
   - [4.1 Interface Modes](#41-interface-modes)
   - [4.2 Tool Catalog & Discovery](#42-tool-catalog--discovery)
   - [4.3 Policy Application & Rollback](#43-policy-application--rollback)
   - [4.4 Strict Restrictive Mode](#44-strict-restrictive-mode)
   - [4.5 Compliance Verification & Auto-Remediation](#45-compliance-verification--auto-remediation)
   - [4.6 Enterprise Administrator Mode (System-Wide & Read-Only Locking)](#46-enterprise-administrator-mode-system-wide--read-only-locking)
   - [4.7 Command Risk Matrix Evaluation](#47-command-risk-matrix-evaluation)
   - [4.8 SAST & SCA Code Vulnerability Scanner](#48-sast--sca-code-vulnerability-scanner)
   - [4.9 Security Components & Extras Installation](#49-security-components--extras-installation)
   - [4.10 Automated Test Suite & Diagnostics](#410-automated-test-suite--diagnostics)
5. [Terminal User Interface (TUI) Keybindings](#5-terminal-user-interface-tui-keybindings)
6. [Environment Variables & Logging](#6-environment-variables--logging)
7. [Exit Codes](#7-exit-codes)

---

## 1. Launcher Scripts

The framework includes idempotent launcher scripts for cross-platform execution and automatic virtual environment (`.venv`) lifecycle management:

| Script | Operating System | Description | Example Usage |
| :--- | :--- | :--- | :--- |
| `main.sh` | Linux / macOS | POSIX Bash launcher with automatic `.venv` detection and activation | `./main.sh [arguments]` |
| `main.ps1` | Windows | PowerShell 5.1+ / Core script with environment and execution policy handling | `.\main.ps1 [arguments]` |
| `main.cmd` | Windows | Batch script for standard Command Prompt execution | `main.cmd [arguments]` |
| `main.py` | Cross-Platform | Direct Python entry point | `python main.py [arguments]` |

> [!NOTE]
> All launcher scripts are idempotent: if the `.venv` virtual environment already exists in the project directory, it will not be recreated, preserving pre-installed dependencies.

---

## 2. General CLI Syntax

```bash
python main.py [MODE] [ACTION] [FILTERS] [MODIFIERS] [OPTIONS]
```

### Quick Usage Examples:
```bash
# Launch the interactive Terminal User Interface:
python main.py

# Apply strict hardening to host-installed tools:
python main.py --apply --installed-only --strict

# Audit compliance and automatically remediate discrepancies to 100%:
python main.py --verify --fix

# Enforce system-wide administrative hardening with read-only permission locks:
sudo python main.py --apply --admin --strict
```

---

## 3. Summary Table of Parameters & Flags

| Parameter / Flag | Alias | Data Type | Description |
| :--- | :--- | :--- | :--- |
| `-gui`, `--gui` | — | Flag | Launches the interactive full-screen Terminal User Interface (Textual TUI). |
| `--cli` | — | Flag | Explicitly forces headless / command-line execution mode. |
| `--list` | — | Flag | Lists all 14 supported AI tools, categories, and detection status. |
| `--installed-only` | — | Flag | Restricts any operation strictly to tools detected on the host machine. |
| `--tool <NAME>` | — | String | Filters execution to a specific tool (e.g. `cursor`, `google/antigravity`). |
| `--apply` | — | Flag | Applies declarative security hardening policies to target tools. |
| `--strict` | `--restrictive` | Flag | Enables Strict Mode (explicit critical denials, dangerous paths blocked, auto-write disabled). |
| `--remove` | `--revert` | Flag | Surgically removes hardening overrides and restores configuration backups. |
| `--verify` | — | Flag | Audits host configuration files and generates a compliance verification report. |
| `--fix` | `--remediate` | Flag | Automatically remediates non-compliant baseline settings to 100% compliance. |
| `--admin` | `--system-wide` | Flag | **[CLI Only]** Verifies Admin/Root elevation and enforces Read-Only file locks across all users. |
| `--check-command <CMD>`| — | String | Evaluates a shell command against the multi-OS Command Risk Matrix. |
| `--scan-code [PATH]` | — | Path (Optional)| Runs static code security analysis (SAST/SCA). Default: current directory (`.`). |
| `--install-extra <T>` | — | String | Installs additional isolation components (`ai-jail`, `opengrep`, `all`). |
| `--dry-run` | — | Flag | Simulates operations in memory without modifying any files on disk. |
| `--test` | — | Flag | Runs the complete automated unit and integration test suite (31 tests). |
| `--verbose`, `-v` | — | Flag | Enables verbose debug logging output. |
| `-h`, `--help` | — | Flag | Displays formatted help message with parameter explanations and examples. |

---

## 4. Detailed Parameter & Subcommand Reference

### 4.1 Interface Modes

#### `--gui` / `-gui`
- **Description:** Launches the full-screen terminal graphical user interface powered by Textual. Provides mouse and keyboard navigation, live streaming log viewer, DLP inspector modal, and security guardrail panels.
- **Usage:**
  ```bash
  python main.py
  python main.py --gui
  ```

#### `--cli`
- **Description:** Forces headless CLI mode, ideal for automated scripts, CI/CD pipelines, and cron jobs.
- **Usage:**
  ```bash
  python main.py --cli --list
  ```

---

### 4.2 Tool Catalog & Discovery

#### `--list`
- **Description:** Outputs a Rich table showing all 14 supported AI tools, vendor metadata, category (`ide`, `cli`, `agentic`), and live host detection status.
- **Usage:**
  ```bash
  python main.py --list
  ```

#### `--installed-only`
- **Description:** Filter modifier that restricts subsequent operations (`--list`, `--apply`, `--remove`, `--verify`) exclusively to tools discovered on the local machine.
- **Usage:**
  ```bash
  python main.py --list --installed-only
  python main.py --apply --installed-only
  python main.py --verify --installed-only
  ```

#### `--tool <NAME>`
- **Expected Argument:** Tool name (e.g. `cursor`, `copilot`, `antigravity`, `claude-code`) or `vendor/name` format (`anysphere/cursor`, `anthropic/claude-code`).
- **Description:** Targets execution to a single tool.
- **Usage:**
  ```bash
  python main.py --tool cursor --apply
  python main.py --tool google/antigravity --verify
  python main.py --tool claude-code --remove
  ```

---

### 4.3 Policy Application & Rollback

#### `--apply`
- **Description:** Applies declarative security hardening policies defined in `configs/tools/`. Creates timestamped configuration backups before modifications, preserves user custom settings/providers, and deploys OS-specific security policy rule files.
- **Usage:**
  ```bash
  # Apply hardening to host-installed tools:
  python main.py --apply --installed-only

  # Provision hardening for all 14 supported tools:
  python main.py --apply
  ```

#### `--remove` / `--revert`
- **Description:** Surgically removes all hardening overrides applied by the framework, restoring previous user configuration values without breaking custom extensions or configured AI providers.
- **Usage:**
  ```bash
  python main.py --remove --installed-only
  python main.py --tool cursor --remove
  ```

#### `--dry-run`
- **Description:** Executes policy resolution, diff calculations, and permission validations **without writing any files to disk**.
- **Usage:**
  ```bash
  python main.py --apply --dry-run
  python main.py --remove --dry-run
  ```

---

### 4.4 Strict Restrictive Mode

#### `--strict` / `--restrictive`
- **Description:** Elevates hardening to maximum security isolation:
  1. **Explicit Critical Command Blocking:** Blocks destructive commands (`rm -rf /`, `mkfs`, `format`, `dd if=/dev/zero`, `diskpart`, etc.) immediately without asking.
  2. **OS Dangerous Paths Blocked:** Immediate denial of access to sensitive system paths (`/etc`, `/boot`, `~/.ssh`, `~/.aws`, `C:\Windows`, `/System`, etc.).
  3. **File Edit Auto-Approval Disabled:** Disables autonomous file modifications and auto-accepting diffs (`acceptEdits: False`, `autoApply: False`, `auto_write_files: False`), enforcing Human-in-the-Loop review.
  4. **Active Rate Limits & Timeouts:** Strict threshold of 30 req/min and 30s command execution timeouts.
- **Usage:**
  ```bash
  python main.py --apply --strict
  python main.py --apply --installed-only --strict
  python main.py --verify --strict
  ```

---

### 4.5 Compliance Verification & Auto-Remediation

#### `--verify`
- **Description:** Performs static audits on local configuration files and deployed rule files, calculating a 0% to 100% compliance score per tool.
- **Usage:**
  ```bash
  python main.py --verify
  python main.py --verify --installed-only
  python main.py --verify --strict
  ```

#### `--fix` / `--remediate`
- **Description:** When combined with `--verify`, automatically remediates any missing or non-compliant configuration keys, raising the compliance score to **100%**.
- **Usage:**
  ```bash
  # Audit and auto-remediate in standard mode:
  python main.py --verify --fix

  # Audit and auto-remediate in strict mode:
  python main.py --verify --installed-only --strict --fix
  ```

---

### 4.6 Enterprise Administrator Mode (System-Wide & Read-Only Locking)

#### `--admin` / `--system-wide` *(CLI Exclusive)*
- **Description:** Enterprise feature designed for systems administrators and security teams:
  1. **Elevation Check:** Validates Administrator / Root privileges (`sudo` on Linux/macOS or `Run as Administrator` on Windows).
  2. **Multi-User Profile Scan:** Discovers all local user profile directories (`/home/*`, `/root`, `/etc/skel`, `/Users/*`, `C:\Users\*`).
  3. **Read-Only Permission Locking:**
     - **Linux / macOS:** Sets `chown root:root` (or `root:wheel`), `chmod 644` on configuration files and `chmod 755` on directories.
     - **Windows:** Configures restrictive NTFS ACLs via `icacls`, granting `BUILTIN\Administrators:F`, `NT AUTHORITY\SYSTEM:F` and `BUILTIN\Users:R` (removing write permissions for regular users).
     - **Impact:** Standard users can run their AI tools normally, but **cannot edit, overwrite, tamper with, or disable security policies**.
  4. **Global Telemetry Shutdown:** Deploys `/etc/profile.d/hardening-ia-telemetry.sh` (Linux/macOS) or machine environment variables (Windows).
- **Usage:**
  ```bash
  # Linux & macOS (with sudo):
  sudo python main.py --apply --admin --installed-only
  sudo python main.py --apply --admin --strict
  sudo python main.py --verify --admin

  # Windows (Elevated PowerShell / CMD):
  python main.py --apply --admin --installed-only
  python main.py --apply --admin --strict
  python main.py --verify --admin
  ```

> [!IMPORTANT]
> The `--admin` flag is intentionally omitted from the interactive GUI (TUI) and is strictly accessible via elevated CLI execution.

---

### 4.7 Command Risk Matrix Evaluation

#### `--check-command <CMD>`
- **Expected Argument:** Command string enclosed in quotes (e.g. `"rm -rf /"`, `"git status"`, `"sudo systemctl restart nginx"`).
- **Description:** Evaluates a terminal command against the OS security policy and assigns a risk tier:
  - `LOW`: Read-only and diagnostic commands (auto-executable).
  - `MEDIUM`: State-modifying development commands (requires confirmation).
  - `HIGH`: Administrative, network, and privilege-altering commands (requires explicit operator confirmation).
  - `CRITICAL`: Destructive commands or dangerous path access (blocked immediately in strict mode).
- **Usage:**
  ```bash
  python main.py --check-command "ls -la"
  python main.py --check-command "cat /etc/shadow"
  python main.py --check-command "rm -rf /"
  python main.py --check-command "rm -rf /" --strict
  ```

---

### 4.8 SAST & SCA Code Vulnerability Scanner

#### `--scan-code [PATH]`
- **Expected Argument:** (Optional) Relative or absolute target path. Default: current directory (`.`).
- **Description:** Executes OpenGrep static analysis (SAST) and composition analysis (SCA) configured with rules targeting vulnerabilities prevalent in AI-generated code (Command Injection, SQL Injection, Path Traversal, Hardcoded Secrets, Insecure Deserialization).
- **Usage:**
  ```bash
  # Scan current project workspace:
  python main.py --scan-code

  # Scan a specific directory:
  python main.py --scan-code ./src
  python main.py --scan-code /path/to/project
  ```

---

### 4.9 Security Components & Extras Installation

#### `--install-extra <TOOL>`
- **Supported Arguments:** `ai-jail`, `opengrep`, or `all`.
- **Description:** Executes isolated installation scripts for runtime sandboxes and static analysis engines:
  - `ai-jail`: Process-level namespace/container isolation sandbox.
  - `opengrep`: Fast, local static code analysis engine.
  - `all`: Installs both security components.
- **Usage:**
  ```bash
  python main.py --install-extra opengrep
  python main.py --install-extra ai-jail
  python main.py --install-extra all
  ```

---

### 4.10 Automated Test Suite & Diagnostics

#### `--test`
- **Description:** Discovers and runs the complete `unittest` test suite (31 tests) covering risk classifiers, SAST scanner, hardening engine, compliance verifier, OS detector, and admin manager.
- **Usage:**
  ```bash
  python main.py --test
  ./main.sh --test
  ```

#### `--verbose` / `-v`
- **Description:** Enables `DEBUG` log output, displaying internal JSON diffs, evaluated files, and subprocess details.
- **Usage:**
  ```bash
  python main.py --apply --verbose
  ```

---

## 5. Terminal User Interface (TUI) Keybindings

When launching `python main.py` (or `main.sh` / `main.ps1` without arguments), the interactive interface supports the following keyboard shortcuts:

| Key | Action |
| :---: | :--- |
| `q` | **Quit:** Safely closes the application. |
| `a` | **Apply Hardening:** Applies the policy to the currently selected tool. |
| `s` | **Toggle Strict Mode:** Toggles the *Strict Mode* checkbox. |
| `r` | **Revert Policy:** Removes hardening and restores original configuration for selected tool. |
| `v` | **Verify Config:** Audits the selected tool and prints compliance findings. |
| `f` | **Fix Compliance:** Auto-remediates discrepancies, raising score to 100%. |
| `t` | **Run Tests:** Executes the automated test suite. |
| `d` | **Toggle Dry-Run:** Toggles simulation mode (no disk writes). |
| `c` | **Clear Logs:** Clears the live streaming log panel. |
| `1` - `4` | **Switch Views:** Navigates between *Tools*, *Audit Trail*, *Command Risk*, and *SAST Scanner*. |

---

## 6. Environment Variables & Logging

### Environment Variables Enforced by the Framework:
- `DO_NOT_TRACK=1`: International standard for disabling telemetry and tracking across developer tools.
- `CLAUDE_TELEMETRY_DISABLED=1`: Disables telemetry in Anthropic developer tools.
- `CLAUDE_CODE_ENABLE_TELEMETRY=0`: Disables analytics in Claude Code CLI.
- `ANTHROPIC_TELEMETRY_DISABLED=1`: Global agent analytics shutdown.

### Log Files & Audit Trail:
- `logs/hardening.log`: Technical execution log with automatic rotation (10 MB per file, 5 backups).
- `logs/audit.jsonl`: Immutable JSON Lines audit log recording timestamps, events (`POLICY_APPLIED`, `POLICY_REVERTED`, `ADMIN_SYSTEM_WIDE_ENFORCEMENT`, `VERIFICATION_AUDIT`), tool names, and execution status.

---

## 7. Exit Codes

The CLI returns standard process exit codes for integration into automation and CI/CD pipelines:

| Exit Code | Meaning | Description |
| :---: | :--- | :--- |
| `0` | **Success** | The operation completed successfully without errors. |
| `1` | **Error / Elevation Required** | Execution failure, insufficient privileges for `--admin`, or failing unit tests. |
| `2` | **Invalid Argument** | Invalid CLI parameter or incorrect syntax supplied. |
