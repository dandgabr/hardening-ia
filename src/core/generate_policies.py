"""Generates industry-standard, fully hardened declarative YAML policies for all 16 AI tools."""

import yaml
from pathlib import Path
from src.core.security_policy import (
    DANGEROUS_PATHS_BY_OS,
    CRITICAL_DENIED_PATTERNS_BY_OS,
    DEFAULT_RATE_LIMIT,
    DEFAULT_TIMEOUT
)

COMMON_DLP_PATHS = [
    "**/.env*",
    "**/*.pem",
    "**/*.key",
    "**/*.pfx",
    "**/*.p12",
    "**/*_rsa",
    "**/*_ed25519",
    "~/.ssh/**",
    "~/.aws/**",
    "~/.kube/**",
    "~/.gnupg/**",
    "~/.git-credentials",
    "~/.netrc",
    "~/.docker/config.json"
]

COMMON_SCRIPTS = {
    "windows": "scripts/os/windows/apply-hardening.ps1",
    "linux": "scripts/os/linux/apply-hardening.sh",
    "macos": "scripts/os/macos/apply-hardening.sh"
}

POLICIES_DATABASE = [
    {
        "vendor": "google",
        "name": "antigravity",
        "category": "agentic",
        "description": "Google Antigravity - Enterprise agentic developer platform (CLI, IDE, MCP, SDK)",
        "paths": {
            "windows": {
                "config_dir": "%USERPROFILE%\\.gemini\\antigravity-cli",
                "settings_file": "%USERPROFILE%\\.gemini\\antigravity-cli\\settings.json",
                "rules_dir": "%USERPROFILE%\\.gemini\\antigravity-cli\\rules"
            },
            "linux": {
                "config_dir": "~/.gemini/antigravity-cli",
                "settings_file": "~/.gemini/antigravity-cli/settings.json",
                "rules_dir": "~/.gemini/antigravity-cli/rules"
            },
            "macos": {
                "config_dir": "~/.gemini/antigravity-cli",
                "settings_file": "~/.gemini/antigravity-cli/settings.json",
                "rules_dir": "~/.gemini/antigravity-cli/rules"
            }
        },
        "policies": {
            "sandbox": {
                "enforce_sandbox": True,
                "enableTerminalSandbox": True,
                "default_bypass": False,
                "toolPermissions": "request-review"
            },
            "approvals": {
                "require_approval_for_terminal": True,
                "require_approval_for_network": True,
                "require_approval_for_write": True,
                "allowNonWorkspaceAccess": False
            },
            "rate_limit": DEFAULT_RATE_LIMIT,
            "timeout": DEFAULT_TIMEOUT,
            "dangerous_paths": DANGEROUS_PATHS_BY_OS,
            "dlp": {
                "block_sensitive_paths": COMMON_DLP_PATHS,
                "disable_code_training_sharing": True,
                "mask_secrets": True
            },
            "telemetry": {
                "enable_telemetry": False,
                "enable_crash_reporting": False,
                "audit_logging": True
            },
            "strict_rules": {
                "action": "block_without_prompting",
                "denied_patterns": CRITICAL_DENIED_PATTERNS_BY_OS,
                "native_overrides": {
                    "security.dangerousPaths.action": "block",
                    "security.deniedPatterns": [
                        "rm -rf /", "mkfs*", "dd if=/dev/zero*", "dd if=/dev/urandom*",
                        "format*", "diskpart*", "diskutil eraseDisk*"
                    ],
                    "toolPermissions": "deny-critical",
                    "autoApplyEdits": False,
                    "approvals.require_approval_for_write": True,
                    "mcp.allowUnsandboxedServers": False,
                    "subagents.allowAutonomousSpawning": False
                }
            },
            "native_settings_override": {
                "telemetry.enabled": False,
                "crashReporting.enabled": False,
                "toolPermissions": "request-review",
                "enableTerminalSandbox": True,
                "allowNonWorkspaceAccess": False,
                "hooks.enforceGuardrails": True,
                "mcp.requireConsent": True,
                "mcp.allowUnsandboxedServers": False,
                "subagents.requireParentApproval": True,
                "subagents.allowAutonomousSpawning": False,
                "dlp.maskSecrets": True,
                "slashCommands.enforceApproval": True,
                "security.sandbox.default_enforced": True,
                "security.approvals.bypass_allowed": False,
                "timeout.command_timeout_seconds": 30,
                "timeout.execution_timeout_seconds": 60,
                "rate_limit.max_requests_per_minute": 30,
                "security.dangerousPaths.action": "ask"
            }
        }
    },
    {
        "vendor": "anthropic",
        "name": "claude-code",
        "category": "cli",
        "description": "Claude Code CLI - Agentic command line assistant with autonomous tools and enterprise sandboxing",
        "paths": {
            "windows": {
                "config_dir": "%USERPROFILE%\\.claude",
                "settings_file": "%USERPROFILE%\\.claude\\settings.json",
                "rules_dir": "%USERPROFILE%\\.claude\\rules",
                "managed_settings_file": "%ProgramData%\\ClaudeCode\\managed-settings.json"
            },
            "linux": {
                "config_dir": "~/.claude",
                "settings_file": "~/.claude/settings.json",
                "rules_dir": "~/.claude/rules",
                "managed_settings_file": "/etc/claude-code/managed-settings.json"
            },
            "macos": {
                "config_dir": "~/.claude",
                "settings_file": "~/.claude/settings.json",
                "rules_dir": "~/.claude/rules",
                "managed_settings_file": "/Library/Application Support/ClaudeCode/managed-settings.json"
            }
        },
        "policies": {
            "sandbox": {
                "enforce_sandbox": True,
                "allowUnsandboxedCommands": False,
                "failIfUnavailable": True,
                "autoAllowBashIfSandboxed": True,
                "filesystem": {
                    "disabled": False,
                    "denyWrite": [
                        "C:\\Windows", "C:\\Windows\\System32", "C:\\Program Files", "C:\\Program Files (x86)", "C:\\ProgramData",
                        "/etc", "/boot", "/root", "/sys", "/proc", "/dev", "/var/log", "/usr/bin", "/usr/sbin", "/sbin", "/bin",
                        "/System", "/Library", "/private"
                    ],
                    "denyRead": [
                        "**/.env*", "**/*.pem", "**/*.key", "~/.ssh", "~/.aws", "~/.azure", "~/.kube", "~/.gnupg",
                        "~/.git-credentials", "~/.netrc", "~/.docker/config.json", "~/.credentials.json", "~/.claude.json",
                        "%USERPROFILE%\\.ssh", "%USERPROFILE%\\.aws", "%USERPROFILE%\\.azure", "%USERPROFILE%\\.kube",
                        "%USERPROFILE%\\AppData\\Local\\Microsoft\\Credentials", "%USERPROFILE%\\AppData\\Roaming\\Microsoft\\Vault"
                    ]
                },
                "network": {
                    "strictAllowlist": False,
                    "allowedDomains": [
                        "github.com", "*.github.com", "*.githubusercontent.com", "registry.npmjs.org",
                        "*.npmjs.org", "pypi.org", "files.pythonhosted.org"
                    ],
                    "deniedDomains": [
                        "169.254.169.254", "metadata.google.internal", "100.100.100.200", "localhost",
                        "127.0.0.1", "0.0.0.0", "[::1]", "*.local", "*.internal"
                    ]
                },
                "credentials": {
                    "allowPlaintextInject": False,
                    "envVars": [
                        {"name": "ANTHROPIC_API_KEY", "mode": "deny"},
                        {"name": "ANTHROPIC_AUTH_TOKEN", "mode": "deny"},
                        {"name": "AWS_ACCESS_KEY_ID", "mode": "deny"},
                        {"name": "AWS_SECRET_ACCESS_KEY", "mode": "deny"},
                        {"name": "AWS_SESSION_TOKEN", "mode": "deny"},
                        {"name": "AZURE_CLIENT_SECRET", "mode": "deny"},
                        {"name": "GITHUB_TOKEN", "mode": "deny"},
                        {"name": "GH_TOKEN", "mode": "deny"},
                        {"name": "OPENAI_API_KEY", "mode": "deny"},
                        {"name": "GEMINI_API_KEY", "mode": "deny"},
                        {"name": "DATABASE_URL", "mode": "deny"},
                        {"name": "DB_PASSWORD", "mode": "deny"}
                    ]
                }
            },
            "approvals": {
                "permissionMode": "manual",
                "defaultMode": "manual",
                "autoApprove": [],
                "acceptEdits": False,
                "dangerouslySkipPermissions": False,
                "disableBypassPermissionsMode": "disable",
                "disableAutoMode": "disable",
                "permissionExplainerEnabled": True
            },
            "rate_limit": DEFAULT_RATE_LIMIT,
            "timeout": DEFAULT_TIMEOUT,
            "dangerous_paths": DANGEROUS_PATHS_BY_OS,
            "dlp": {
                "block_sensitive_paths": COMMON_DLP_PATHS,
                "disable_code_training_sharing": True,
                "mask_secrets": True
            },
            "telemetry": {
                "enable_telemetry": False,
                "enable_crash_reporting": False,
                "audit_logging": True
            },
            "strict_rules": {
                "action": "block_without_prompting",
                "denied_patterns": CRITICAL_DENIED_PATTERNS_BY_OS,
                "native_overrides": {
                    "permissions": {
                        "defaultMode": "plan",
                        "disableBypassPermissionsMode": "disable",
                        "disableAutoMode": "disable",
                        "allow": [],
                        "deny": [
                            "Bash(rm -rf /*)", "Bash(rm -rf /etc*)", "Bash(rm -rf /boot*)", "Bash(rm -rf /root*)",
                            "Bash(dd if=/dev/zero*)", "Bash(dd if=/dev/urandom*)", "Bash(mkfs*)", "Bash(wipefs*)",
                            "Bash(fdisk*)", "Bash(gdisk*)", "Bash(parted*)", "Bash(lvreduce*)", "Bash(format-volume*)",
                            "Bash(format *:*)", "Bash(clear-disk*)", "Bash(diskpart*)", "Bash(cipher /w*)",
                            "Bash(diskutil eraseDisk*)", "Bash(diskutil partitionDisk*)",
                            "Bash(set-mppreference -disablerealtimemonitoring*)", "Bash(chmod -R 777 /*)",
                            "Bash(chown -R nobody /*)", "Bash(wget *|sh)", "Bash(curl *|sh)", "Bash(wget *|bash)", "Bash(curl *|bash)",
                            "Bash(:(){ :|:& };:)", "Bash(dangerouslyDisableSandbox:true)",
                            "Read(//*)", "Read(\\\\*)",
                            "WebFetch(domain:169.254.169.254)", "WebFetch(domain:metadata.google.internal)",
                            "WebFetch(domain:100.100.100.200)", "WebFetch(domain:localhost)",
                            "WebFetch(domain:127.0.0.1)", "WebFetch(domain:0.0.0.0)", "WebFetch(domain:[::1])",
                            "WebFetch(domain:*.local)", "WebFetch(domain:*.internal)",
                            "Read(~/.ssh/**)", "Read(~/.aws/**)", "Read(~/.azure/**)", "Read(~/.kube/**)",
                            "Read(~/.gnupg/**)", "Read(~/.git-credentials)", "Read(~/.netrc)", "Read(~/.docker/config.json)",
                            "Read(**/.env*)", "Read(**/*.pem)", "Read(**/*.key)", "Read(**/*.pfx)", "Read(**/*.p12)",
                            "Read(**/*_rsa)", "Read(**/*_ed25519)", "Read(~/.credentials.json)", "Read(~/.claude.json)",
                            "Edit(~/.ssh/**)", "Edit(~/.aws/**)", "Edit(~/.kube/**)", "Edit(/etc/**)", "Edit(/boot/**)", "Edit(C:\\Windows\\**)",
                            "Write(~/.ssh/**)", "Write(~/.aws/**)", "Write(~/.kube/**)", "Write(/etc/**)", "Write(/boot/**)", "Write(C:\\Windows\\**)"
                        ],
                        "ask": ["Bash(*)", "PowerShell(*)", "Edit(*)", "Write(*)", "WebFetch(*)"]
                    },
                    "sandbox": {
                        "enabled": True,
                        "autoAllowBashIfSandboxed": False,
                        "allowUnsandboxedCommands": False,
                        "failIfUnavailable": True,
                        "network": {
                            "strictAllowlist": True,
                            "allowedDomains": [
                                "github.com", "*.github.com", "*.githubusercontent.com", "registry.npmjs.org",
                                "*.npmjs.org", "pypi.org", "files.pythonhosted.org"
                            ],
                            "deniedDomains": [
                                "169.254.169.254", "metadata.google.internal", "100.100.100.200", "localhost",
                                "127.0.0.1", "0.0.0.0", "[::1]", "*.local", "*.internal"
                            ]
                        }
                    }
                }
            },
            "native_settings_override": {
                "permissions": {
                    "defaultMode": "manual",
                    "disableBypassPermissionsMode": "disable",
                    "disableAutoMode": "disable",
                    "allow": [
                        "Read(cwd:*)", "Bash(git status:*)", "Bash(git diff:*)", "Bash(git log:*)",
                        "Bash(ls:*)", "Bash(dir:*)", "Bash(pwd:*)", "Bash(find:*)", "Bash(grep:*)", "Bash(rg:*)"
                    ],
                    "deny": [
                        "Bash(rm -rf /*)", "Bash(rm -rf /etc*)", "Bash(rm -rf /boot*)", "Bash(rm -rf /root*)",
                        "Bash(dd if=/dev/zero*)", "Bash(dd if=/dev/urandom*)", "Bash(mkfs*)", "Bash(wipefs*)",
                        "Bash(fdisk*)", "Bash(gdisk*)", "Bash(parted*)", "Bash(lvreduce*)", "Bash(format-volume*)",
                        "Bash(format *:*)", "Bash(clear-disk*)", "Bash(diskpart*)", "Bash(cipher /w*)",
                        "Bash(diskutil eraseDisk*)", "Bash(diskutil partitionDisk*)",
                        "Bash(set-mppreference -disablerealtimemonitoring*)", "Bash(chmod -R 777 /*)",
                        "Bash(chown -R nobody /*)", "Bash(wget *|sh)", "Bash(curl *|sh)", "Bash(wget *|bash)", "Bash(curl *|bash)",
                        "Bash(:(){ :|:& };:)", "Bash(dangerouslyDisableSandbox:true)",
                        "Read(//*)", "Read(\\\\*)",
                        "WebFetch(domain:169.254.169.254)", "WebFetch(domain:metadata.google.internal)",
                        "WebFetch(domain:100.100.100.200)", "WebFetch(domain:localhost)",
                        "WebFetch(domain:127.0.0.1)", "WebFetch(domain:0.0.0.0)", "WebFetch(domain:[::1])",
                        "WebFetch(domain:*.local)", "WebFetch(domain:*.internal)",
                        "Read(~/.ssh/**)", "Read(~/.aws/**)", "Read(~/.azure/**)", "Read(~/.kube/**)",
                        "Read(~/.gnupg/**)", "Read(~/.git-credentials)", "Read(~/.netrc)", "Read(~/.docker/config.json)",
                        "Read(**/.env*)", "Read(**/*.pem)", "Read(**/*.key)", "Read(**/*.pfx)", "Read(**/*.p12)",
                        "Read(**/*_rsa)", "Read(**/*_ed25519)", "Read(~/.credentials.json)", "Read(~/.claude.json)"
                    ],
                    "ask": ["Bash(*)", "PowerShell(*)", "Edit(*)", "Write(*)", "WebFetch(*)"]
                },
                "sandbox": {
                    "enabled": True,
                    "autoAllowBashIfSandboxed": True,
                    "allowUnsandboxedCommands": False,
                    "failIfUnavailable": True,
                    "filesystem": {
                        "disabled": False,
                        "denyWrite": [
                            "C:\\Windows", "C:\\Windows\\System32", "C:\\Program Files", "C:\\Program Files (x86)", "C:\\ProgramData",
                            "/etc", "/boot", "/root", "/sys", "/proc", "/dev", "/var/log", "/usr/bin", "/usr/sbin", "/sbin", "/bin",
                            "/System", "/Library", "/private"
                        ],
                        "denyRead": [
                            "**/.env*", "**/*.pem", "**/*.key", "~/.ssh", "~/.aws", "~/.azure", "~/.kube", "~/.gnupg",
                            "~/.git-credentials", "~/.netrc", "~/.docker/config.json", "~/.credentials.json", "~/.claude.json",
                            "%USERPROFILE%\\.ssh", "%USERPROFILE%\\.aws", "%USERPROFILE%\\.azure", "%USERPROFILE%\\.kube",
                            "%USERPROFILE%\\AppData\\Local\\Microsoft\\Credentials", "%USERPROFILE%\\AppData\\Roaming\\Microsoft\\Vault"
                        ]
                    },
                    "network": {
                        "strictAllowlist": False,
                        "allowedDomains": [
                            "github.com", "*.github.com", "*.githubusercontent.com", "registry.npmjs.org",
                            "*.npmjs.org", "pypi.org", "files.pythonhosted.org"
                        ],
                        "deniedDomains": [
                            "169.254.169.254", "metadata.google.internal", "100.100.100.200", "localhost",
                            "127.0.0.1", "0.0.0.0", "[::1]", "*.local", "*.internal"
                        ]
                    },
                    "credentials": {
                        "allowPlaintextInject": False,
                        "envVars": [
                            {"name": "ANTHROPIC_API_KEY", "mode": "deny"},
                            {"name": "ANTHROPIC_AUTH_TOKEN", "mode": "deny"},
                            {"name": "AWS_ACCESS_KEY_ID", "mode": "deny"},
                            {"name": "AWS_SECRET_ACCESS_KEY", "mode": "deny"},
                            {"name": "AWS_SESSION_TOKEN", "mode": "deny"},
                            {"name": "AZURE_CLIENT_SECRET", "mode": "deny"},
                            {"name": "GITHUB_TOKEN", "mode": "deny"},
                            {"name": "GH_TOKEN", "mode": "deny"},
                            {"name": "OPENAI_API_KEY", "mode": "deny"},
                            {"name": "GEMINI_API_KEY", "mode": "deny"},
                            {"name": "DATABASE_URL", "mode": "deny"},
                            {"name": "DB_PASSWORD", "mode": "deny"}
                        ]
                    }
                },
                "permissionExplainerEnabled": True,
                "feedbackSurveyRate": 0,
                "autoMemoryEnabled": False,
                "disableArtifact": True,
                "disableDeepLinkRegistration": "disable",
                "disableSkillShellExecution": True,
                "disableRemoteControl": True,
                "remoteControlAtStartup": False,
                "disableClaudeAiConnectors": True,
                "strictPluginOnlyCustomization": True,
                "browserExternalPageTools": "disabled",
                "disableBrowserExternalNavigation": True,
                "disableMobileSimulatorTools": True,
                "respectGitignore": True,
                "cleanupPeriodDays": 7,
                "autoUpdatesChannel": "stable",
                "env": {
                    "DO_NOT_TRACK": "1",
                    "CLAUDE_DISABLE_TELEMETRY": "1",
                    "CLAUDE_TELEMETRY_DISABLED": "1",
                    "CLAUDE_CODE_ENABLE_TELEMETRY": "0",
                    "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
                    "CLAUDE_CODE_SUBPROCESS_ENV_SCRUB": "1",
                    "CLAUDE_CODE_DISABLE_FEEDBACK_SURVEY": "1",
                    "DISABLE_TELEMETRY": "1",
                    "DISABLE_AUTOUPDATER": "1"
                },
                "permissionMode": "manual",
                "autoApprove": [],
                "acceptEdits": False,
                "disableTelemetry": True,
                "allowBypassSandbox": False,
                "dangerouslySkipPermissions": False,
                "maxCostThresholdUSD": 10.0,
                "timeoutSeconds": 60,
                "commandTimeoutSeconds": 30,
                "rateLimitPerMinute": 30
            }
        }
    },
    {
        "vendor": "github",
        "name": "copilot",
        "category": "ide",
        "description": "GitHub Copilot - AI pair programmer for VS Code and JetBrains IDEs",
        "paths": {
            "windows": {
                "config_dir": "%APPDATA%\\Code\\User",
                "settings_file": "%APPDATA%\\Code\\User\\settings.json"
            },
            "linux": {
                "config_dir": "~/.config/Code/User",
                "settings_file": "~/.config/Code/User/settings.json"
            },
            "macos": {
                "config_dir": "~/Library/Application Support/Code/User",
                "settings_file": "~/Library/Application Support/Code/User/settings.json"
            }
        },
        "policies": {
            "rate_limit": DEFAULT_RATE_LIMIT,
            "timeout": DEFAULT_TIMEOUT,
            "dangerous_paths": DANGEROUS_PATHS_BY_OS,
            "dlp": {
                "block_sensitive_paths": COMMON_DLP_PATHS,
                "disable_code_training_sharing": True
            },
            "telemetry": {
                "enable_telemetry": False
            },
            "strict_rules": {
                "action": "block_without_prompting",
                "denied_patterns": CRITICAL_DENIED_PATTERNS_BY_OS,
                "native_overrides": {
                    "github.copilot.editor.enableAutoCompletions": True,
                    "github.copilot.chat.localeOverride": "en",
                    "github.copilot.chat.autoApplyEdits": False,
                    "chat.tools.global.autoApprove": False,
                    "chat.agent.allowTerminal": False
                }
            },
            "native_settings_override": {
                "github.copilot.advanced": {
                    "authProvider": "github",
                    "debug.overrideCAPIUrl": "",
                    "requestTimeout": 30,
                    "rateLimitPerMinute": 30
                },
                "github.copilot.enable": {
                    "*": True,
                    "plaintext": False,
                    "markdown": False,
                    "scminput": False,
                    ".env": False
                },
                "github.copilot.editor.enableAutoCompletions": True,
                "github.copilot.chat.localeOverride": "en",
                "github.copilot.chat.terminal.autoExecute": False,
                "github.copilot.chat.autoApplyEdits": False,
                "chat.tools.global.autoApprove": False,
                "chat.tools.eligibleForAutoApproval": [],
                "chat.tools.confirm": "always",
                "chat.agent.allowTerminal": False,
                "chat.editing.confirmEditRequestRemoval": True,
                "chat.commandCenter.enabled": True,
                "telemetry.telemetryLevel": "off"
            }
        }
    },
    {
        "vendor": "anysphere",
        "name": "cursor",
        "category": "ide",
        "description": "Cursor IDE - AI-native code editor built on VS Code foundation",
        "paths": {
            "windows": {
                "config_dir": "%APPDATA%\\Cursor\\User",
                "settings_file": "%APPDATA%\\Cursor\\User\\settings.json"
            },
            "linux": {
                "config_dir": "~/.config/Cursor/User",
                "settings_file": "~/.config/Cursor/User/settings.json"
            },
            "macos": {
                "config_dir": "~/Library/Application Support/Cursor/User",
                "settings_file": "~/Library/Application Support/Cursor/User/settings.json"
            }
        },
        "policies": {
            "sandbox": {
                "enforce_sandbox": True,
                "default_bypass": False
            },
            "approvals": {
                "require_approval_for_terminal": True,
                "require_approval_for_network": True
            },
            "rate_limit": DEFAULT_RATE_LIMIT,
            "timeout": DEFAULT_TIMEOUT,
            "dangerous_paths": DANGEROUS_PATHS_BY_OS,
            "dlp": {
                "block_sensitive_paths": COMMON_DLP_PATHS,
                "disable_code_training_sharing": True
            },
            "telemetry": {
                "enable_telemetry": False
            },
            "strict_rules": {
                "action": "block_without_prompting",
                "denied_patterns": CRITICAL_DENIED_PATTERNS_BY_OS,
                "native_overrides": {
                    "cursor.deniedTerminalPatterns": [
                        "rm -rf /", "mkfs*", "dd if=/dev/zero*", "format*", "diskpart*", "diskutil eraseDisk*"
                    ],
                    "cursor.terminal.strictExecution": True,
                    "cursor.composer.autoApply": False,
                    "cursor.chat.autoApply": False,
                    "cursor.agent.yoloMode": False,
                    "cursor.mcp.requireConsent": True
                }
            },
            "native_settings_override": {
                "cursor.privacyMode": True,
                "cursor.general.privacy": "no-retention",
                "cursor.terminal.autoExecute": False,
                "cursor.terminal.sandbox": True,
                "cursor.terminal.legacyTerminalTool": False,
                "cursor.terminal.timeout": 60,
                "cursor.agent.yoloMode": False,
                "cursor.composer.autoApply": False,
                "cursor.composer.requireUserApproval": True,
                "cursor.chat.autoApply": False,
                "cursor.mcp.requireConsent": True,
                "cursor.agent.autoExecuteTerminal": False,
                "cursor.rateLimit.requestsPerMinute": 30,
                "security.workspace.trust.enabled": True,
                "telemetry.telemetryLevel": "off",
                "cursor.indexer.ignorePatterns": [
                    ".env*",
                    "*.pem",
                    "*.key",
                    "*.pfx",
                    "*.p12",
                    "*_rsa",
                    "*_ed25519",
                    "**/.aws/**",
                    "**/.ssh/**",
                    "**/.kube/**",
                    "**/.gnupg/**",
                    "**/.docker/config.json"
                ]
            }
        }
    },
    {
        "vendor": "cline",
        "name": "cline",
        "category": "agentic",
        "description": "Cline (formerly Claude Dev) - Autonomous AI coding assistant for VS Code",
        "paths": {
            "windows": {
                "config_dir": "%USERPROFILE%\\.cline",
                "settings_file": "%USERPROFILE%\\.cline\\settings.json",
                "rules_dir": "%USERPROFILE%\\.cline\\rules"
            },
            "linux": {
                "config_dir": "~/.cline",
                "settings_file": "~/.cline/settings.json",
                "rules_dir": "~/.cline/rules"
            },
            "macos": {
                "config_dir": "~/.cline",
                "settings_file": "~/.cline/settings.json",
                "rules_dir": "~/.cline/rules"
            }
        },
        "policies": {
            "sandbox": {
                "enforce_sandbox": True,
                "default_bypass": False
            },
            "approvals": {
                "alwaysApproveResubmit": False,
                "autoApproveExecution": False,
                "autoApprove": {
                    "terminal": False,
                    "write": False,
                    "read": True,
                    "browser": False,
                    "mcp": False
                },
                "allowNonWorkspaceAccess": False
            },
            "rate_limit": DEFAULT_RATE_LIMIT,
            "timeout": DEFAULT_TIMEOUT,
            "dangerous_paths": DANGEROUS_PATHS_BY_OS,
            "dlp": {
                "block_sensitive_paths": COMMON_DLP_PATHS,
                "disable_code_training_sharing": True
            },
            "telemetry": {
                "enable_telemetry": False
            },
            "strict_rules": {
                "action": "block_without_prompting",
                "denied_patterns": CRITICAL_DENIED_PATTERNS_BY_OS,
                "native_overrides": {
                    "autoApprove.write": False,
                    "autoApprove.read": False,
                    "autoApproveExecution": False,
                    "deniedCommands": ["rm -rf /", "mkfs*", "dd*", "format*"],
                    "strictPathIsolation": True,
                    "diff.autoApply": False,
                    "mcp.autoApprove": False
                }
            },
            "native_settings_override": {
                "alwaysApproveResubmit": False,
                "autoApproveExecution": False,
                "autoApprove.mode": "never",
                "autoApprove": {
                    "terminal": False,
                    "write": False,
                    "read": True,
                    "browser": False,
                    "mcp": False
                },
                "allowNonWorkspaceAccess": False,
                "telemetryEnabled": False,
                "restrictSecretAccess": True,
                "mcp.requireConsent": True,
                "mcp.autoApprove": False,
                "diff.autoApply": False,
                "executionTimeout": 60,
                "commandTimeout": 30,
                "rateLimitPerMinute": 30
            }
        }
    },
    {
        "vendor": "openai",
        "name": "codex",
        "category": "cli",
        "description": "OpenAI Codex / CLI Assistant - Code generation and agent execution engine",
        "paths": {
            "windows": {
                "config_dir": "%USERPROFILE%\\.codex",
                "settings_file": "%USERPROFILE%\\.codex\\config.json"
            },
            "linux": {
                "config_dir": "~/.codex",
                "settings_file": "~/.codex/config.json"
            },
            "macos": {
                "config_dir": "~/.codex",
                "settings_file": "~/.codex/config.json"
            }
        },
        "policies": {
            "sandbox": {
                "enforce_sandbox": True,
                "default_bypass": False
            },
            "approvals": {
                "require_approval_for_terminal": True,
                "require_approval_for_network": True
            },
            "rate_limit": DEFAULT_RATE_LIMIT,
            "timeout": DEFAULT_TIMEOUT,
            "dangerous_paths": DANGEROUS_PATHS_BY_OS,
            "dlp": {
                "block_sensitive_paths": COMMON_DLP_PATHS,
                "disable_code_training_sharing": True
            },
            "telemetry": {
                "enable_telemetry": False
            },
            "strict_rules": {
                "action": "block_without_prompting",
                "denied_patterns": CRITICAL_DENIED_PATTERNS_BY_OS,
                "native_overrides": {
                    "block_critical_commands": True,
                    "strict_path_isolation": True,
                    "auto_write_files": False,
                    "require_human_confirmation": True
                }
            },
            "native_settings_override": {
                "telemetry": False,
                "code_telemetry": False,
                "auto_execute": False,
                "enforce_sandboxing": True,
                "trusted_workspaces_only": True,
                "allow_network": False,
                "require_human_confirmation": True,
                "prompt_secret_masking": True,
                "mcp_consent_required": True,
                "timeout_seconds": 60,
                "rate_limit_rpm": 30
            }
        }
    },
    {
        "vendor": "opencode",
        "name": "opencode",
        "category": "cli",
        "description": "OpenCode - Open-source AI terminal coding agent",
        "paths": {
            "windows": {
                "config_dir": "%USERPROFILE%\\.opencode",
                "settings_file": "%USERPROFILE%\\.opencode\\config.json"
            },
            "linux": {
                "config_dir": "~/.opencode",
                "settings_file": "~/.opencode/config.json"
            },
            "macos": {
                "config_dir": "~/.opencode",
                "settings_file": "~/.opencode/config.json"
            }
        },
        "policies": {
            "sandbox": {
                "enforce_sandbox": True,
                "default_bypass": False
            },
            "approvals": {
                "require_approval_for_terminal": True,
                "require_approval_for_network": True
            },
            "rate_limit": DEFAULT_RATE_LIMIT,
            "timeout": DEFAULT_TIMEOUT,
            "dangerous_paths": DANGEROUS_PATHS_BY_OS,
            "dlp": {
                "block_sensitive_paths": COMMON_DLP_PATHS,
                "disable_code_training_sharing": True
            },
            "telemetry": {
                "enable_telemetry": False
            },
            "strict_rules": {
                "action": "block_without_prompting",
                "denied_patterns": CRITICAL_DENIED_PATTERNS_BY_OS,
                "native_overrides": {
                    "sandbox.denied_commands": ["rm -rf /", "mkfs*", "dd*", "format*"],
                    "sandbox.strict_mode": True,
                    "agent.auto_apply_edits": False,
                    "agent.confirm_actions": True
                }
            },
            "native_settings_override": {
                "analytics.enabled": False,
                "agent.confirm_actions": True,
                "agent.auto_apply_edits": False,
                "permission_mode": "prompt",
                "auto_approve_tools": [],
                "sandbox.strict_mode": True,
                "network.isolate_agent": True,
                "dlp.mask_credentials": True,
                "mcp_consent_required": True,
                "timeout.command_seconds": 30,
                "timeout.request_seconds": 30,
                "rate_limit.requests_per_minute": 30
            }
        }
    },
    {
        "vendor": "nousresearch",
        "name": "hermes-agent",
        "category": "agentic",
        "description": "Hermes Agent - Advanced reasoning and autonomous execution agent",
        "paths": {
            "windows": {
                "config_dir": "%USERPROFILE%\\.hermes",
                "settings_file": "%USERPROFILE%\\.hermes\\agent_config.json"
            },
            "linux": {
                "config_dir": "~/.hermes",
                "settings_file": "~/.hermes/agent_config.json"
            },
            "macos": {
                "config_dir": "~/.hermes",
                "settings_file": "~/.hermes/agent_config.json"
            }
        },
        "policies": {
            "sandbox": {
                "enforce_sandbox": True,
                "default_bypass": False
            },
            "approvals": {
                "require_approval_for_terminal": True,
                "require_approval_for_network": True
            },
            "rate_limit": DEFAULT_RATE_LIMIT,
            "timeout": DEFAULT_TIMEOUT,
            "dangerous_paths": DANGEROUS_PATHS_BY_OS,
            "dlp": {
                "block_sensitive_paths": COMMON_DLP_PATHS,
                "disable_code_training_sharing": True
            },
            "telemetry": {
                "enable_telemetry": False
            },
            "strict_rules": {
                "action": "block_without_prompting",
                "denied_patterns": CRITICAL_DENIED_PATTERNS_BY_OS,
                "native_overrides": {
                    "safe_mode": True,
                    "blocked_tools": ["system_admin", "raw_exec", "disk_partition", "network_raw"],
                    "auto_write_files": False,
                    "human_in_the_loop": True
                }
            },
            "native_settings_override": {
                "enable_telemetry": False,
                "human_in_the_loop": True,
                "safe_mode": True,
                "max_recursive_steps": 10,
                "sandbox_container": True,
                "blocked_tools": ["system_admin", "raw_exec", "disk_partition", "network_raw"],
                "network_egress_restricted": True,
                "dlp_filter_secrets": True,
                "timeout_seconds": 60,
                "max_requests_per_minute": 30
            }
        }
    },
    {
        "vendor": "qoder",
        "name": "qoder",
        "category": "agentic",
        "description": "Qoder - Enterprise AI development and coding assistant",
        "paths": {
            "windows": {
                "config_dir": "%USERPROFILE%\\.qoder",
                "settings_file": "%USERPROFILE%\\.qoder\\settings.json"
            },
            "linux": {
                "config_dir": "~/.qoder",
                "settings_file": "~/.qoder/settings.json"
            },
            "macos": {
                "config_dir": "~/.qoder",
                "settings_file": "~/.qoder/settings.json"
            }
        },
        "policies": {
            "sandbox": {
                "enforce_sandbox": True,
                "default_bypass": False
            },
            "approvals": {
                "require_approval_for_terminal": True,
                "require_approval_for_network": True
            },
            "rate_limit": DEFAULT_RATE_LIMIT,
            "timeout": DEFAULT_TIMEOUT,
            "dangerous_paths": DANGEROUS_PATHS_BY_OS,
            "dlp": {
                "block_sensitive_paths": COMMON_DLP_PATHS,
                "disable_code_training_sharing": True
            },
            "telemetry": {
                "enable_telemetry": False
            },
            "strict_rules": {
                "action": "block_without_prompting",
                "denied_patterns": CRITICAL_DENIED_PATTERNS_BY_OS,
                "native_overrides": {
                    "security.denyCritical": True,
                    "security.denyDangerousPaths": True,
                    "security.autoApplyEdits": False,
                    "security.executionConsent": "always"
                }
            },
            "native_settings_override": {
                "telemetry.shareData": False,
                "security.executionConsent": "always",
                "security.autoApplyEdits": False,
                "security.sandbox": True,
                "agent.allowNonWorkspaceAccess": False,
                "mcp.requireUserConfirmation": True,
                "dlp.maskEnvSecrets": True,
                "executionTimeout": 60,
                "rateLimitRpm": 30
            }
        }
    },
    {
        "vendor": "kilo",
        "name": "kilo-code",
        "category": "cli",
        "description": "Kilo Code - High-performance AI developer CLI suite",
        "paths": {
            "windows": {
                "config_dir": "%USERPROFILE%\\.kilo",
                "settings_file": "%USERPROFILE%\\.kilo\\config.json"
            },
            "linux": {
                "config_dir": "~/.kilo",
                "settings_file": "~/.kilo/config.json"
            },
            "macos": {
                "config_dir": "~/.kilo",
                "settings_file": "~/.kilo/config.json"
            }
        },
        "policies": {
            "sandbox": {
                "enforce_sandbox": True,
                "default_bypass": False
            },
            "approvals": {
                "require_approval_for_terminal": True,
                "require_approval_for_network": True
            },
            "rate_limit": DEFAULT_RATE_LIMIT,
            "timeout": DEFAULT_TIMEOUT,
            "dangerous_paths": DANGEROUS_PATHS_BY_OS,
            "dlp": {
                "block_sensitive_paths": COMMON_DLP_PATHS,
                "disable_code_training_sharing": True
            },
            "telemetry": {
                "enable_telemetry": False
            },
            "strict_rules": {
                "action": "block_without_prompting",
                "denied_patterns": CRITICAL_DENIED_PATTERNS_BY_OS,
                "native_overrides": {
                    "security.denied_patterns": ["rm -rf /", "mkfs*", "dd*", "format*"],
                    "security.strict_block": True,
                    "execution.auto_accept_edits": False,
                    "execution.require_confirmation": True
                }
            },
            "native_settings_override": {
                "privacy.telemetry": False,
                "execution.require_confirmation": True,
                "execution.auto_accept_edits": False,
                "sandbox.enabled": True,
                "indexing.exclude_hidden_and_secrets": True,
                "mcp.requireConsent": True,
                "dlp.mask_credentials": True,
                "timeout.command": 30,
                "rate_limit.rpm": 30
            }
        }
    },
    {
        "vendor": "clinepass",
        "name": "clinepass",
        "category": "agentic",
        "description": "ClinePass - Managed security wrapper and credential vault for Cline agents",
        "paths": {
            "windows": {
                "config_dir": "%USERPROFILE%\\.clinepass",
                "settings_file": "%USERPROFILE%\\.clinepass\\config.json"
            },
            "linux": {
                "config_dir": "~/.clinepass",
                "settings_file": "~/.clinepass/config.json"
            },
            "macos": {
                "config_dir": "~/.clinepass",
                "settings_file": "~/.clinepass/config.json"
            }
        },
        "policies": {
            "sandbox": {
                "enforce_sandbox": True,
                "default_bypass": False
            },
            "approvals": {
                "require_approval_for_terminal": True,
                "require_approval_for_network": True
            },
            "rate_limit": DEFAULT_RATE_LIMIT,
            "timeout": DEFAULT_TIMEOUT,
            "dangerous_paths": DANGEROUS_PATHS_BY_OS,
            "dlp": {
                "block_sensitive_paths": COMMON_DLP_PATHS,
                "disable_code_training_sharing": True
            },
            "telemetry": {
                "enable_telemetry": False
            },
            "strict_rules": {
                "action": "block_without_prompting",
                "denied_patterns": CRITICAL_DENIED_PATTERNS_BY_OS,
                "native_overrides": {
                    "vault.block_dangerous_paths": True,
                    "proxy.block_unapproved_hosts": True,
                    "proxy.require_consent_for_file_edits": True,
                    "vault.zero_plaintext_cache": True
                }
            },
            "native_settings_override": {
                "vault.enforce_encryption": True,
                "vault.zero_plaintext_cache": True,
                "proxy.block_unapproved_hosts": True,
                "proxy.block_ssrf_metadata": True,
                "proxy.mask_tokens_in_logs": True,
                "proxy.isolate_subprocesses": True,
                "audit.full_logging": True,
                "proxy.timeout_seconds": 30,
                "proxy.rate_limit_rpm": 30
            }
        }
    },
    {
        "vendor": "codebuddy",
        "name": "codebuddy",
        "category": "ide",
        "description": "CodeBuddy - Intelligent AI programming companion",
        "paths": {
            "windows": {
                "config_dir": "%USERPROFILE%\\.codebuddy",
                "settings_file": "%USERPROFILE%\\.codebuddy\\settings.json"
            },
            "linux": {
                "config_dir": "~/.codebuddy",
                "settings_file": "~/.codebuddy/settings.json"
            },
            "macos": {
                "config_dir": "~/.codebuddy",
                "settings_file": "~/.codebuddy/settings.json"
            }
        },
        "policies": {
            "sandbox": {
                "enforce_sandbox": True,
                "default_bypass": False
            },
            "approvals": {
                "require_approval_for_terminal": True,
                "require_approval_for_network": True
            },
            "rate_limit": DEFAULT_RATE_LIMIT,
            "timeout": DEFAULT_TIMEOUT,
            "dangerous_paths": DANGEROUS_PATHS_BY_OS,
            "dlp": {
                "block_sensitive_paths": COMMON_DLP_PATHS,
                "disable_code_training_sharing": True
            },
            "telemetry": {
                "enable_telemetry": False
            },
            "strict_rules": {
                "action": "block_without_prompting",
                "denied_patterns": CRITICAL_DENIED_PATTERNS_BY_OS,
                "native_overrides": {
                    "auto_run_commands": False,
                    "sandbox_isolated": True,
                    "strict_mode": True,
                    "auto_apply_diffs": False
                }
            },
            "native_settings_override": {
                "share_code_snippets": False,
                "telemetry": "off",
                "auto_run_commands": False,
                "auto_apply_diffs": False,
                "sandbox_isolated": True,
                "mcp_require_confirmation": True,
                "dlp_mask_secrets": True,
                "timeout_seconds": 30,
                "rate_limit_rpm": 30
            }
        }
    },
    {
        "vendor": "moonshot",
        "name": "kimi",
        "category": "cli",
        "description": "Kimi - High-context conversational and coding assistant from Moonshot AI",
        "paths": {
            "windows": {
                "config_dir": "%USERPROFILE%\\.kimi",
                "settings_file": "%USERPROFILE%\\.kimi\\config.json"
            },
            "linux": {
                "config_dir": "~/.kimi",
                "settings_file": "~/.kimi/config.json"
            },
            "macos": {
                "config_dir": "~/.kimi",
                "settings_file": "~/.kimi/config.json"
            }
        },
        "policies": {
            "sandbox": {
                "enforce_sandbox": True,
                "default_bypass": False
            },
            "approvals": {
                "require_approval_for_terminal": True,
                "require_approval_for_network": True
            },
            "rate_limit": DEFAULT_RATE_LIMIT,
            "timeout": DEFAULT_TIMEOUT,
            "dangerous_paths": DANGEROUS_PATHS_BY_OS,
            "dlp": {
                "block_sensitive_paths": COMMON_DLP_PATHS,
                "disable_code_training_sharing": True
            },
            "telemetry": {
                "enable_telemetry": False
            },
            "strict_rules": {
                "action": "block_without_prompting",
                "denied_patterns": CRITICAL_DENIED_PATTERNS_BY_OS,
                "native_overrides": {
                    "security.deny_dangerous_paths": True,
                    "security.block_critical": True,
                    "agent.auto_write": False,
                    "security.require_write_confirmation": True
                }
            },
            "native_settings_override": {
                "telemetry.enabled": False,
                "privacy.data_retention": False,
                "agent.auto_write": False,
                "security.require_write_confirmation": True,
                "sandbox.enabled": True,
                "prompt.mask_secrets": True,
                "context.exclude_secret_files": True,
                "network.block_metadata_endpoints": True,
                "timeout.request": 30,
                "rate_limit.max_rpm": 30
            }
        }
    },
    {
        "vendor": "xai",
        "name": "grok",
        "category": "cli",
        "description": "Grok / xAI Developer CLI - Advanced coding and reasoning interface",
        "paths": {
            "windows": {
                "config_dir": "%USERPROFILE%\\.xai",
                "settings_file": "%USERPROFILE%\\.xai\\config.json"
            },
            "linux": {
                "config_dir": "~/.xai",
                "settings_file": "~/.xai/config.json"
            },
            "macos": {
                "config_dir": "~/.xai",
                "settings_file": "~/.xai/config.json"
            }
        },
        "policies": {
            "sandbox": {
                "enforce_sandbox": True,
                "default_bypass": False
            },
            "approvals": {
                "require_approval_for_terminal": True,
                "require_approval_for_network": True
            },
            "rate_limit": DEFAULT_RATE_LIMIT,
            "timeout": DEFAULT_TIMEOUT,
            "dangerous_paths": DANGEROUS_PATHS_BY_OS,
            "dlp": {
                "block_sensitive_paths": COMMON_DLP_PATHS,
                "disable_code_training_sharing": True
            },
            "telemetry": {
                "enable_telemetry": False
            },
            "strict_rules": {
                "action": "block_without_prompting",
                "denied_patterns": CRITICAL_DENIED_PATTERNS_BY_OS,
                "native_overrides": {
                    "sandbox_strict": True,
                    "denied_patterns": ["rm -rf /", "mkfs*", "dd*", "format*"],
                    "auto_edit_files": False,
                    "require_approval_all_tools": True
                }
            },
            "native_settings_override": {
                "telemetry": False,
                "audit_logs": True,
                "sandbox_strict": True,
                "share_prompts": False,
                "auto_edit_files": False,
                "require_approval_all_tools": True,
                "mcp_server_approval": True,
                "block_cloud_metadata": True,
                "timeout_seconds": 60,
                "rate_limit_rpm": 30
            }
        }
    },
    {
        "vendor": "zai",
        "name": "zai-cli",
        "category": "cli",
        "description": "z.ai CLI - Autonomous AI command line coding agent and GLM model interface",
        "paths": {
            "windows": {
                "config_dir": "%APPDATA%\\zai",
                "settings_file": "%APPDATA%\\zai\\config.json",
                "rules_dir": "%APPDATA%\\zai\\rules"
            },
            "linux": {
                "config_dir": "~/.config/zai",
                "settings_file": "~/.config/zai/config.json",
                "rules_dir": "~/.config/zai/rules"
            },
            "macos": {
                "config_dir": "~/Library/Application Support/zai",
                "settings_file": "~/Library/Application Support/zai/config.json",
                "rules_dir": "~/Library/Application Support/zai/rules"
            }
        },
        "policies": {
            "sandbox": {
                "enforce_sandbox": True,
                "default_bypass": False
            },
            "approvals": {
                "require_approval_for_terminal": True,
                "require_approval_for_network": True,
                "require_approval_for_write": True
            },
            "rate_limit": DEFAULT_RATE_LIMIT,
            "timeout": DEFAULT_TIMEOUT,
            "dangerous_paths": DANGEROUS_PATHS_BY_OS,
            "dlp": {
                "block_sensitive_paths": COMMON_DLP_PATHS,
                "disable_code_training_sharing": True,
                "mask_secrets": True
            },
            "telemetry": {
                "enable_telemetry": False,
                "enable_crash_reporting": False,
                "audit_logging": True
            },
            "strict_rules": {
                "action": "block_without_prompting",
                "denied_patterns": CRITICAL_DENIED_PATTERNS_BY_OS,
                "native_overrides": {
                    "agent.auto_execute_commands": False,
                    "agent.auto_apply_edits": False,
                    "sandbox.strict_mode": True,
                    "security.deny_critical_commands": True,
                    "mcp.requireConsent": True
                }
            },
            "native_settings_override": {
                "telemetry": False,
                "analytics.enabled": False,
                "agent.auto_execute_commands": False,
                "agent.require_confirmation": True,
                "agent.auto_apply_edits": False,
                "sandbox.enabled": True,
                "sandbox.strict_mode": True,
                "dlp.mask_secrets": True,
                "mcp.requireConsent": True,
                "timeout.command": 30,
                "timeout.request": 30,
                "rate_limit.max_rpm": 30
            }
        }
    },
    {
        "vendor": "zai",
        "name": "zcode",
        "category": "agentic",
        "description": "z.ai ZCode - Agentic Development Environment (ADE) with integrated workspace, terminal and MCP tools",
        "paths": {
            "windows": {
                "config_dir": "%USERPROFILE%\\.zcode",
                "settings_file": "%USERPROFILE%\\.zcode\\v2\\config.json",
                "rules_dir": "%USERPROFILE%\\.zcode\\rules"
            },
            "linux": {
                "config_dir": "~/.zcode",
                "settings_file": "~/.zcode/v2/config.json",
                "rules_dir": "~/.zcode/rules"
            },
            "macos": {
                "config_dir": "~/.zcode",
                "settings_file": "~/.zcode/v2/config.json",
                "rules_dir": "~/.zcode/rules"
            }
        },
        "policies": {
            "sandbox": {
                "enforce_sandbox": True,
                "default_bypass": False
            },
            "approvals": {
                "require_approval_for_terminal": True,
                "require_approval_for_network": True,
                "require_approval_for_write": True
            },
            "rate_limit": DEFAULT_RATE_LIMIT,
            "timeout": DEFAULT_TIMEOUT,
            "dangerous_paths": DANGEROUS_PATHS_BY_OS,
            "dlp": {
                "block_sensitive_paths": COMMON_DLP_PATHS,
                "disable_code_training_sharing": True,
                "mask_secrets": True
            },
            "telemetry": {
                "enable_telemetry": False,
                "enable_crash_reporting": False,
                "audit_logging": True
            },
            "strict_rules": {
                "action": "block_without_prompting",
                "denied_patterns": CRITICAL_DENIED_PATTERNS_BY_OS,
                "native_overrides": {
                    "terminal.auto_execute": False,
                    "composer.auto_apply": False,
                    "security.dangerous_paths_action": "block",
                    "mcp.allow_unsandboxed": False,
                    "mcp.require_consent": True
                }
            },
            "native_settings_override": {
                "telemetry.enabled": False,
                "privacy.data_retention": False,
                "terminal.auto_execute": False,
                "terminal.sandbox": True,
                "composer.auto_apply": False,
                "composer.require_approval": True,
                "mcp.require_consent": True,
                "mcp.allow_unsandboxed": False,
                "dlp.block_sensitive_paths": True,
                "security.dangerous_paths_action": "ask",
                "timeout_seconds": 60,
                "rate_limit_rpm": 30
            }
        }
    }
]

def generate():
    root = Path(__file__).resolve().parent.parent.parent
    for item in POLICIES_DATABASE:
        doc = {
            "schema_version": "1.0",
            "tool": {
                "name": item["name"],
                "vendor": item["vendor"],
                "category": item["category"],
                "description": item["description"]
            },
            "paths": item["paths"],
            "policies": item["policies"],
            "custom_scripts": COMMON_SCRIPTS
        }
        dest = root / "configs" / "tools" / item["vendor"] / item["name"] / "hardening_policy.yaml"
        dest.parent.mkdir(parents=True, exist_ok=True)
        with open(dest, "w", encoding="utf-8") as f:
            yaml.dump(doc, f, sort_keys=False, allow_unicode=True)
        print(f"[OK] Generated policy: {item["vendor"]}/{item["name"]}")

if __name__ == "__main__":
    generate()
