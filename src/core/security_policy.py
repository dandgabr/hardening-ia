"""Security policy constants, dangerous OS paths, rate limits, timeouts, and strict rule generators."""

import re
from enum import Enum
from pathlib import Path
from typing import Dict, List, Tuple, Any

from src.core.os_detector import OSDetector


# ==============================================================================
# 1. OS-SPECIFIC DANGEROUS PATHS
# ==============================================================================
DANGEROUS_PATHS_BY_OS: Dict[str, List[str]] = {
    "linux": [
        # System sensitive directories & files
        "/etc",
        "/etc/shadow",
        "/etc/sudoers",
        "/etc/sudoers.d",
        "/etc/passwd",
        "/etc/group",
        "/etc/ssl",
        "/etc/crontab",
        "/etc/cron.*",
        "/boot",
        "/root",
        "/sys",
        "/proc",
        "/dev",
        "/var/log",
        "/var/run",
        "/var/backups",
        "/usr/local/bin",
        "/usr/bin",
        "/sbin",
        "/bin",
        # User sensitive credentials & shell config
        "~/.ssh",
        "~/.gnupg",
        "~/.aws",
        "~/.azure",
        "~/.kube",
        "~/.docker",
        "~/.config/gcloud",
        "~/.bashrc",
        "~/.zshrc",
        "~/.profile",
        "~/.bash_profile",
        "~/.bash_history",
        "~/.zsh_history",
        "~/.git-credentials",
        "~/.netrc",
        "~/.config/gh",
        "~/.npmrc",
        "~/.pypirc",
        "~/.credentials.json",
        "~/.claude.json"
    ],
    "windows": [
        # System sensitive directories & files
        r"C:\Windows",
        r"C:\Windows\System32",
        r"C:\Windows\System32\drivers\etc",
        r"C:\Windows\SysWOW64",
        r"C:\Program Files",
        r"C:\Program Files (x86)",
        r"C:\ProgramData",
        r"C:\Boot",
        r"C:\Recovery",
        r"C:\System Volume Information",
        r"C:\$Recycle.Bin",
        # User sensitive credentials & startup
        r"%USERPROFILE%\.ssh",
        r"%USERPROFILE%\.aws",
        r"%USERPROFILE%\.azure",
        r"%USERPROFILE%\.kube",
        r"%USERPROFILE%\.docker",
        r"%USERPROFILE%\AppData\Local\Microsoft\Credentials",
        r"%USERPROFILE%\AppData\Roaming\Microsoft\Vault",
        r"%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Start Menu",
        r"%USERPROFILE%\.git-credentials",
        r"%USERPROFILE%\_netrc",
        r"%USERPROFILE%\.npmrc",
        r"%USERPROFILE%\.pypirc",
        r"%USERPROFILE%\.credentials.json",
        r"%USERPROFILE%\.claude.json",
        r"\\*"
    ],
    "macos": [
        # System sensitive directories & files (SIP & Core)
        "/System",
        "/System/Library",
        "/Library",
        "/private",
        "/private/etc",
        "/private/var",
        "/private/tmp",
        "/Volumes",
        "/usr/bin",
        "/usr/sbin",
        "/bin",
        "/sbin",
        # User sensitive credentials & keychains
        "~/.ssh",
        "~/.gnupg",
        "~/.aws",
        "~/.azure",
        "~/.kube",
        "~/.docker",
        "~/.config/gcloud",
        "~/Library/Keychains",
        "~/Library/Application Support/com.apple.sharedfilelist",
        "~/.zshrc",
        "~/.bash_profile",
        "~/.bashrc",
        "~/.zsh_history",
        "~/.bash_history",
        "~/.git-credentials",
        "~/.netrc",
        "~/.config/gh",
        "~/.credentials.json",
        "~/.claude.json"
    ]
}


# ==============================================================================
# 2. CRITICAL DENIED PATTERNS BY OS
# ==============================================================================
CRITICAL_DENIED_PATTERNS_BY_OS: Dict[str, List[str]] = {
    "linux": [
        r"rm\s+-(?:r|f|rf|fr)\s+/(?:\s|$|\*)",
        r"rm\s+-(?:r|f|rf|fr)\s+/etc",
        r"rm\s+-(?:r|f|rf|fr)\s+/boot",
        r"rm\s+-(?:r|f|rf|fr)\s+/root",
        r":\(\)\s*\{\s*:\|:&\s*\}\s*;\s*:",
        r"dd\s+if=/dev/zero",
        r"dd\s+if=/dev/urandom",
        r"mkfs\.[a-z0-9]+\s+/dev/sd[a-z]",
        r"mkfs\s+",
        r">\s*/dev/sd[a-z]",
        r"chmod\s+-(?:R|r)\s+777\s+/",
        r"chown\s+-(?:R|r)\s+nobody\s+/",
        r"mv\s+/\s+/dev/null",
        r"wget.*\|\s*(?:sh|bash)",
        r"curl.*\|\s*(?:sh|bash)",
        r"wipefs\s+",
        r"fdisk\s+",
        r"gdisk\s+",
        r"parted\s+",
        r"lvreduce\s+",
        r"dangerouslyDisableSandbox",
        r"169\.254\.169\.254"
    ],
    "windows": [
        r"format-volume\s+",
        r"format\s+[a-zA-Z]:",
        r"clear-disk\s+",
        r"initialize-disk\s+",
        r"remove-partition\s+",
        r"resize-partition\s+",
        r"diskpart\s+",
        r"cipher\s+/w",
        r"chkdsk\s+/f",
        r"remove-item\s+.*-recurse\s+c:\\windows",
        r"del\s+/f\s+/s\s+/q\s+c:\\windows",
        r"rd\s+/s\s+/q\s+c:\\",
        r"set-mppreference\s+.*-disablerealtimemonitoring",
        r"dangerouslyDisableSandbox",
        r"169\.254\.169\.254"
    ],
    "macos": [
        r"diskutil\s+eraseDisk",
        r"diskutil\s+partitionDisk",
        r"diskutil\s+apfs\s+deleteContainer",
        r"gpt\s+",
        r"newfs_apfs\s+",
        r"newfs_hfs\s+",
        r"dd\s+if=/dev/zero\s+of=/dev/r?disk",
        r"asr\s+--restore",
        r"rm\s+-(?:r|f|rf|fr)\s+/(?:\s|$|\*)",
        r"rm\s+-(?:r|f|rf|fr)\s+/System",
        r"dangerouslyDisableSandbox",
        r"169\.254\.169\.254"
    ]
}


# ==============================================================================
# 3. RATE LIMIT & TIMEOUT CONSTANTS
# ==============================================================================
DEFAULT_RATE_LIMIT: Dict[str, Any] = {
    "max_requests_per_minute": 30,
    "max_tokens_per_minute": 100000,
    "max_daily_budget_usd": 10.0,
    "burst_limit": 10
}

DEFAULT_TIMEOUT: Dict[str, Any] = {
    "execution_timeout_seconds": 60,
    "command_timeout_seconds": 30,
    "network_timeout_seconds": 15,
    "read_timeout_seconds": 30
}


# ==============================================================================
# 4. SECURITY POLICY HELPER CLASS
# ==============================================================================
class SecurityPolicyManager:
    """Manages dangerous OS paths, rate limit parameters, timeouts, and rule generators."""

    @classmethod
    def get_dangerous_paths_for_os(cls, os_type: str) -> List[str]:
        """Returns the list of dangerous and sensitive paths for the specified OS."""
        return DANGEROUS_PATHS_BY_OS.get(os_type.lower(), DANGEROUS_PATHS_BY_OS["linux"])

    @classmethod
    def get_critical_denied_patterns_for_os(cls, os_type: str) -> List[str]:
        """Returns critical destructive command patterns for the specified OS."""
        return CRITICAL_DENIED_PATTERNS_BY_OS.get(os_type.lower(), CRITICAL_DENIED_PATTERNS_BY_OS["linux"])

    @classmethod
    def is_dangerous_path(cls, path_str: str, os_type: str = None) -> bool:
        """Checks whether a given path string targets a dangerous OS location."""
        if os_type is None:
            os_type = OSDetector.get_os_type()

        normalized = path_str.strip().rstrip("/\\").replace("\\", "/")
        dangerous_paths = cls.get_dangerous_paths_for_os(os_type)

        for d_path in dangerous_paths:
            d_norm = d_path.rstrip("/\\").replace("\\", "/")
            if d_norm.startswith("~"):
                d_expanded = str(Path.home()) + d_norm[1:]
                d_expanded = d_expanded.replace("\\", "/")
                if normalized == d_norm or normalized.startswith(d_norm + "/") or \
                   normalized == d_expanded or normalized.startswith(d_expanded + "/"):
                    return True
            elif d_norm.startswith("%USERPROFILE%"):
                d_expanded = str(Path.home()) + d_norm[len("%USERPROFILE%"):]
                d_expanded = d_expanded.replace("\\", "/")
                if normalized.lower() == d_norm.lower() or normalized.lower().startswith(d_norm.lower() + "/") or \
                   normalized.lower() == d_expanded.lower() or normalized.lower().startswith(d_expanded.lower() + "/"):
                    return True
            else:
                if normalized.lower() == d_norm.lower() or normalized.lower().startswith(d_norm.lower() + "/"):
                    return True

        return False

    @classmethod
    def check_path_access(cls, path_str: str, os_type: str = None, strict_mode: bool = False) -> Tuple[bool, str]:
        """
        Evaluates access to a target path based on OS and strict mode.
        Returns: (is_blocked_immediately, message)
        """
        if os_type is None:
            os_type = OSDetector.get_os_type()

        if not cls.is_dangerous_path(path_str, os_type):
            return False, "Path is within allowed workspace boundaries."

        if strict_mode:
            return True, f"[STRICT BLOCKED] Access to sensitive path '{path_str}' is explicitly FORBIDDEN without prompting."
        else:
            return False, f"[HUMAN-IN-THE-LOOP] Access to sensitive path '{path_str}' requires EXPLICIT user confirmation before proceeding."

    @classmethod
    def generate_security_policy_rule(cls, os_type: str, strict_mode: bool = False) -> str:
        """Generates comprehensive markdown rule documentation for injection into agent rule directories."""
        paths = cls.get_dangerous_paths_for_os(os_type)
        paths_md = "\n".join([f"- `{p}`" for p in paths])
        mode_title = "STRICT RESTRICTIVE MODE (Explicit Denials & Zero Prompting)" if strict_mode else "STANDARD HARDENING MODE (Human-in-the-Loop & Confirmation)"
        
        path_rule = (
            "🔴 **STRICT DENIAL:** You are STRICTLY PROHIBITED from reading, modifying, listing, or deleting files in these dangerous paths. "
            "Do NOT ask the operator for permission — immediately reject any action touching these paths."
            if strict_mode else
            "🟡 **MANDATORY CONFIRMATION:** You MUST explicitly prompt and obtain operator confirmation BEFORE reading, writing, or traversing any of these dangerous paths."
        )

        critical_rule = (
            "🔴 **DENIED PATTERNS (AUTOMATIC REJECTION):** All critical destructive commands and anti-patterns are EXPLICITLY DENIED. "
            "Execution is blocked unconditionally without prompting."
            if strict_mode else
            "🟠 **CRITICAL MULTI-STEP CONFIRMATION:** Destructive commands are prohibited by default and require strict operator verification."
        )

        return f"""# {os_type.upper()} Agent Security Policy, Dangerous Paths & Execution Guardrails

## 🛡️ Operating Mode: {mode_title}

This security baseline governs all AI agent shell operations, tool executions, and filesystem interactions on **{os_type.upper()}**.

---

## 🚫 1. Dangerous System & Credential Paths ({os_type.upper()})

The following paths are designated as sensitive operating system and credential boundaries:

{paths_md}

### Path Access Rule:
{path_rule}

---

## 🌐 2. Network & Cloud Metadata Guardrails (Anti-SSRF)

- **Cloud Instance Metadata Service (IMDS):** Access to `169.254.169.254` and `metadata.google.internal` is strictly BLOCKED.
- **Local Services & Loopback:** WebFetch, network probes, and tools must not target `localhost`, `127.0.0.1`, `0.0.0.0`, or internal subnet addresses.
- **Windows WebDAV / UNC Boundaries:** Access to UNC/WebDAV paths (`\\\\*`) is forbidden to prevent credential hash exfiltration.

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

{critical_rule}

- **Disk & Partition Destruction:** Formatting (`mkfs`, `format`, `newfs`), zeroing (`dd if=/dev/zero`, `cipher /w`), table manipulation (`fdisk`, `gdisk`, `diskpart`, `diskutil eraseDisk`).
- **Filesystem Purge:** Recursive deletion of root or critical directories (`rm -rf /`, `Remove-Item -Recurse C:\\`).
- **Denial of Service:** Fork bombs (`:(){{:|:&}};:`), recursive full permission escalation (`chmod -R 777 /`).
- **Unverified Remote Pipe:** Piping remote payloads directly into shell (`curl ... | bash`, `wget ... | sh`).
- **Security & Sandbox Bypass:** Disabling sandbox (`dangerouslyDisableSandbox`, `--dangerously-skip-permissions`) or tampering with endpoint protection (`Set-MpPreference -DisableRealtimeMonitoring`).

---

## 📋 5. Compliance & SIEM Audit Logging

Every tool execution, path inspection, and policy evaluation is recorded to `logs/audit.jsonl` with cryptographic timestamps for compliance verification.
"""
