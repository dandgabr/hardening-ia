# LINUX Agent Security Policy, Dangerous Paths & Execution Guardrails

## 🛡️ Operating Mode: STANDARD HARDENING MODE (Human-in-the-Loop & Confirmation)

This security baseline governs all AI agent shell operations, tool executions, and filesystem interactions on **LINUX**.

---

## 🚫 1. Dangerous System & Credential Paths (LINUX)

The following paths are designated as sensitive operating system and credential boundaries:

- `/etc`
- `/etc/shadow`
- `/etc/sudoers`
- `/etc/sudoers.d`
- `/etc/passwd`
- `/etc/group`
- `/etc/ssl`
- `/etc/crontab`
- `/etc/cron.*`
- `/boot`
- `/root`
- `/sys`
- `/proc`
- `/dev`
- `/var/log`
- `/var/run`
- `/var/backups`
- `/usr/local/bin`
- `/usr/bin`
- `/sbin`
- `/bin`
- `~/.ssh`
- `~/.gnupg`
- `~/.aws`
- `~/.azure`
- `~/.kube`
- `~/.docker`
- `~/.config/gcloud`
- `~/.bashrc`
- `~/.zshrc`
- `~/.profile`
- `~/.bash_profile`
- `~/.bash_history`
- `~/.zsh_history`
- `~/.git-credentials`
- `~/.netrc`
- `~/.config/gh`
- `~/.npmrc`
- `~/.pypirc`
- `~/.credentials.json`
- `~/.claude.json`

### Path Access Rule:
🟡 **MANDATORY CONFIRMATION:** You MUST explicitly prompt and obtain operator confirmation BEFORE reading, writing, or traversing any of these dangerous paths.

---

## 🌐 2. Network & Cloud Metadata Guardrails (Anti-SSRF)

- **Cloud Instance Metadata Service (IMDS):** Access to `169.254.169.254` and `metadata.google.internal` is strictly BLOCKED.
- **Local Services & Loopback:** WebFetch, network probes, and tools must not target `localhost`, `127.0.0.1`, `0.0.0.0`, or internal subnet addresses.
- **Windows WebDAV / UNC Boundaries:** Access to UNC/WebDAV paths (`\\*`) is forbidden to prevent credential hash exfiltration.

---

## ⏱️ 3. Rate Limits & Execution Timeouts

To prevent runaway agent loops, denial of service, and excessive cloud API billing, you MUST adhere to:

- **Max Requests Rate:** `30 requests per minute`
- **Max Burst Limit:** `10 concurrent executions`
- **Command Execution Timeout:** `30 seconds max per shell command`
- **Session / Step Timeout:** `60 seconds max per agent step`
- **Network Request Timeout:** `15 seconds max`
- **Cost / Budget Guardrail:** `$10.00 USD max threshold per session`

---

## 🛑 4. Critical Destructive Anti-Patterns & Denied Commands

🟠 **CRITICAL MULTI-STEP CONFIRMATION:** Destructive commands are prohibited by default and require strict operator verification.

- **Disk & Partition Destruction:** Formatting (`mkfs`, `format`, `newfs`), zeroing (`dd if=/dev/zero`, `cipher /w`), table manipulation (`fdisk`, `gdisk`, `diskpart`, `diskutil eraseDisk`).
- **Filesystem Purge:** Recursive deletion of root or critical directories (`rm -rf /`, `Remove-Item -Recurse C:\`).
- **Denial of Service:** Fork bombs (`:(){:|:&};:`), recursive full permission escalation (`chmod -R 777 /`).
- **Unverified Remote Pipe:** Piping remote payloads directly into shell (`curl ... | bash`, `wget ... | sh`).
- **Security & Sandbox Bypass:** Disabling sandbox (`dangerouslyDisableSandbox`, `--dangerously-skip-permissions`) or tampering with endpoint protection (`Set-MpPreference -DisableRealtimeMonitoring`).

---

## 📋 5. Compliance & SIEM Audit Logging

Every tool execution, path inspection, and policy evaluation is recorded to `logs/audit.jsonl` with cryptographic timestamps for compliance verification.
