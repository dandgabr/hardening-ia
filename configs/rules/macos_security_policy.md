# macOS (Darwin / BSD) Agent Security Policy, Dangerous Paths & Execution Guardrails

## 🛡️ Operating Mode: STANDARD HARDENING MODE (Human-in-the-Loop & Confirmation)

This security baseline governs all AI agent shell operations, tool executions, and filesystem interactions on **MACOS**.

---

## 🚫 1. Dangerous System & Credential Paths (MACOS)

The following paths are designated as sensitive operating system and credential boundaries:

- `/System`
- `/System/Library`
- `/Library`
- `/private`
- `/private/etc`
- `/private/var`
- `/private/tmp`
- `/Volumes`
- `/usr/bin`
- `/usr/sbin`
- `/bin`
- `/sbin`
- `~/.ssh`
- `~/.gnupg`
- `~/.aws`
- `~/.azure`
- `~/.kube`
- `~/.docker`
- `~/.config/gcloud`
- `~/Library/Keychains`
- `~/Library/Application Support/com.apple.sharedfilelist`
- `~/.zshrc`
- `~/.bash_profile`
- `~/.bashrc`
- `~/.zsh_history`
- `~/.bash_history`
- `~/.git-credentials`
- `~/.netrc`
- `~/.config/gh`

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

- **Disk & APFS Destruction:** APFS deletion (`diskutil apfs deleteContainer`), partition erasure (`diskutil eraseDisk`, `diskutil partitionDisk`), GPT table destruction (`gpt`), formatting (`newfs_apfs`, `newfs_hfs`), raw zeroing (`dd if=/dev/zero of=/dev/rdisk*`), ASR restores (`asr --restore`).
- **Filesystem Purge:** Recursive root deletion (`rm -rf /`, `rm -rf /System`).
- **Security & SIP Manipulation:** Disabling Gatekeeper/SIP without operator consent (`spctl --master-disable`, `csrutil disable`).

---

## 📋 4. Compliance & SIEM Audit Logging

Every tool execution, path inspection, and policy evaluation is recorded to `logs/audit.jsonl` with cryptographic timestamps for compliance verification.
