# Linux Agent Security Policy, Dangerous Paths & Execution Guardrails

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

### Path Access Rule:
🟡 **MANDATORY CONFIRMATION:** You MUST explicitly prompt and obtain operator confirmation BEFORE reading, writing, or traversing any of these dangerous paths. In Strict Mode, access is BLOCKED unconditionally without prompting.

---

## ⏱️ 2. Rate Limits & Execution Timeouts

To prevent runaway agent loops, denial of service, and excessive cloud API billing, you MUST adhere to:

- **Max Requests Rate:** `30 requests per minute`
- **Max Burst Limit:** `10 concurrent executions`
- **Command Execution Timeout:** `30 seconds max per shell command`
- **Session / Step Timeout:** `60 seconds max per agent step`
- **Network Request Timeout:** `15 seconds max`
- **Cost / Budget Guardrail:** `$10.00 USD max threshold per session`

---

## 🛑 3. Critical Destructive Anti-Patterns & Denied Commands

🟠 **CRITICAL MULTI-STEP CONFIRMATION:** Destructive commands are prohibited by default and require strict operator verification. (In Strict Mode, these are automatically REJECTED and DENIED without prompting).

- **Disk & Partition Destruction:** Formatting (`mkfs`, `mkfs.ext4`, `mkfs.xfs`, `mkswap`), zeroing (`dd if=/dev/zero`, `dd if=/dev/urandom`), partition destruction (`fdisk`, `gdisk`, `parted`, `wipefs`), logical volume reduction (`lvreduce`).
- **Filesystem Purge:** Recursive deletion of root or critical directories (`rm -rf /`, `rm -rf /*`, `rm -rf /etc`, `rm -rf /boot`, `rm -rf /root`).
- **Denial of Service:** Fork bombs (`:(){ :|:& };:`), recursive full permission escalation (`chmod -R 777 /`, `chown -R nobody /`).
- **Unverified Remote Pipe:** Piping remote payloads directly into shell (`curl ... | bash`, `wget ... | sh`).

---

## 📋 4. Compliance & SIEM Audit Logging

Every tool execution, path inspection, and policy evaluation is recorded to `logs/audit.jsonl` with cryptographic timestamps for compliance verification.
