# Windows Agent Security Policy, Dangerous Paths & Execution Guardrails

## 🛡️ Operating Mode: STANDARD HARDENING MODE (Human-in-the-Loop & Confirmation)

This security baseline governs all AI agent shell operations, tool executions, and filesystem interactions on **WINDOWS**.

---

## 🚫 1. Dangerous System & Credential Paths (WINDOWS)

The following paths are designated as sensitive operating system and credential boundaries:

- `C:\Windows`
- `C:\Windows\System32`
- `C:\Windows\System32\drivers\etc`
- `C:\Windows\SysWOW64`
- `C:\Program Files`
- `C:\Program Files (x86)`
- `C:\ProgramData`
- `C:\Boot`
- `C:\Recovery`
- `C:\System Volume Information`
- `C:\$Recycle.Bin`
- `%USERPROFILE%\.ssh`
- `%USERPROFILE%\.aws`
- `%USERPROFILE%\.azure`
- `%USERPROFILE%\.kube`
- `%USERPROFILE%\.docker`
- `%USERPROFILE%\AppData\Local\Microsoft\Credentials`
- `%USERPROFILE%\AppData\Roaming\Microsoft\Vault`
- `%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Start Menu`
- `%USERPROFILE%\.git-credentials`
- `%USERPROFILE%\_netrc`
- `%USERPROFILE%\.npmrc`
- `%USERPROFILE%\.pypirc`

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

- **Disk & Partition Destruction:** Formatting (`Format-Volume`, `format C:`), partition wiping (`Clear-Disk`, `Initialize-Disk`, `Remove-Partition`, `Resize-Partition`), diskpart scripts (`diskpart /s`), zeroing (`cipher /w`).
- **Filesystem Purge:** Recursive deletion of system roots (`Remove-Item -Recurse C:\Windows`, `del /f /s /q C:\Windows`, `rd /s /q C:\`).
- **Security Bypass:** Disabling UAC or Tamper Protection (`Set-MpPreference -DisableRealtimeMonitoring $true`).

---

## 📋 4. Compliance & SIEM Audit Logging

Every tool execution, path inspection, and policy evaluation is recorded to `logs/audit.jsonl` with cryptographic timestamps for compliance verification.
