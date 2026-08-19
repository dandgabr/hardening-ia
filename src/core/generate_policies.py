"""Generates industry-standard, fully hardened declarative YAML policies for all 14 AI tools."""

import yaml
from pathlib import Path

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
                "allowNonWorkspaceAccess": False
            },
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
            "native_settings_override": {
                "telemetry.enabled": False,
                "crashReporting.enabled": False,
                "toolPermissions": "request-review",
                "enableTerminalSandbox": True,
                "allowNonWorkspaceAccess": False,
                "hooks.enforceGuardrails": True,
                "security.sandbox.default_enforced": True,
                "security.approvals.bypass_allowed": False
            }
        }
    },
    {
        "vendor": "anthropic",
        "name": "claude-code",
        "category": "cli",
        "description": "Claude Code CLI - Agentic command line assistant with autonomous tools",
        "paths": {
            "windows": {
                "config_dir": "%USERPROFILE%\\.claude",
                "settings_file": "%USERPROFILE%\\.claude\\config.json",
                "rules_dir": "%USERPROFILE%\\.claude\\rules"
            },
            "linux": {
                "config_dir": "~/.claude",
                "settings_file": "~/.claude/config.json",
                "rules_dir": "~/.claude/rules"
            },
            "macos": {
                "config_dir": "~/.claude",
                "settings_file": "~/.claude/config.json",
                "rules_dir": "~/.claude/rules"
            }
        },
        "policies": {
            "sandbox": {
                "enforce_sandbox": True,
                "allowBypassSandbox": False
            },
            "approvals": {
                "permissionMode": "manual",
                "autoApprove": [],
                "acceptEdits": False,
                "dangerouslySkipPermissions": False
            },
            "dlp": {
                "block_sensitive_paths": COMMON_DLP_PATHS,
                "disable_code_training_sharing": True
            },
            "telemetry": {
                "enable_telemetry": False,
                "CLAUDE_CODE_ENABLE_TELEMETRY": 0,
                "CLAUDE_TELEMETRY_DISABLED": True,
                "audit_logging": True
            },
            "native_settings_override": {
                "permissionMode": "manual",
                "autoApprove": [],
                "acceptEdits": False,
                "disableTelemetry": True,
                "allowBypassSandbox": False,
                "dangerouslySkipPermissions": False,
                "maxCostThresholdUSD": 10.0
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
            "dlp": {
                "block_sensitive_paths": COMMON_DLP_PATHS,
                "disable_code_training_sharing": True
            },
            "telemetry": {
                "enable_telemetry": False
            },
            "native_settings_override": {
                "github.copilot.advanced": {
                    "authProvider": "github",
                    "debug.overrideCAPIUrl": ""
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
            "dlp": {
                "block_sensitive_paths": COMMON_DLP_PATHS,
                "disable_code_training_sharing": True
            },
            "telemetry": {
                "enable_telemetry": False
            },
            "native_settings_override": {
                "cursor.privacyMode": True,
                "cursor.general.privacy": "no-retention",
                "cursor.terminal.autoExecute": False,
                "cursor.terminal.sandbox": True,
                "cursor.terminal.legacyTerminalTool": False,
                "security.workspace.trust.enabled": True,
                "telemetry.telemetryLevel": "off",
                "cursor.indexer.ignorePatterns": [
                    ".env*",
                    "*.pem",
                    "*.key",
                    "**/.aws/**",
                    "**/.ssh/**",
                    "**/.kube/**"
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
            "dlp": {
                "block_sensitive_paths": COMMON_DLP_PATHS,
                "disable_code_training_sharing": True
            },
            "telemetry": {
                "enable_telemetry": False
            },
            "native_settings_override": {
                "alwaysApproveResubmit": False,
                "autoApproveExecution": False,
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
                "mcp.requireConsent": True
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
            "dlp": {
                "block_sensitive_paths": COMMON_DLP_PATHS,
                "disable_code_training_sharing": True
            },
            "telemetry": {
                "enable_telemetry": False
            },
            "native_settings_override": {
                "telemetry": False,
                "auto_execute": False,
                "enforce_sandboxing": True,
                "allow_network": False,
                "require_human_confirmation": True,
                "prompt_secret_masking": True
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
            "dlp": {
                "block_sensitive_paths": COMMON_DLP_PATHS,
                "disable_code_training_sharing": True
            },
            "telemetry": {
                "enable_telemetry": False
            },
            "native_settings_override": {
                "analytics.enabled": False,
                "agent.confirm_actions": True,
                "sandbox.strict_mode": True,
                "network.isolate_agent": True,
                "dlp.mask_credentials": True
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
            "dlp": {
                "block_sensitive_paths": COMMON_DLP_PATHS,
                "disable_code_training_sharing": True
            },
            "telemetry": {
                "enable_telemetry": False
            },
            "native_settings_override": {
                "enable_telemetry": False,
                "human_in_the_loop": True,
                "safe_mode": True,
                "max_recursive_steps": 10,
                "sandbox_container": True,
                "blocked_tools": ["system_admin", "raw_exec"]
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
            "dlp": {
                "block_sensitive_paths": COMMON_DLP_PATHS,
                "disable_code_training_sharing": True
            },
            "telemetry": {
                "enable_telemetry": False
            },
            "native_settings_override": {
                "telemetry.shareData": False,
                "security.executionConsent": "always",
                "security.sandbox": True,
                "dlp.maskEnvSecrets": True
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
            "dlp": {
                "block_sensitive_paths": COMMON_DLP_PATHS,
                "disable_code_training_sharing": True
            },
            "telemetry": {
                "enable_telemetry": False
            },
            "native_settings_override": {
                "privacy.telemetry": False,
                "execution.require_confirmation": True,
                "sandbox.enabled": True,
                "indexing.exclude_hidden_and_secrets": True
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
            "dlp": {
                "block_sensitive_paths": COMMON_DLP_PATHS,
                "disable_code_training_sharing": True
            },
            "telemetry": {
                "enable_telemetry": False
            },
            "native_settings_override": {
                "vault.enforce_encryption": True,
                "proxy.block_unapproved_hosts": True,
                "proxy.mask_tokens_in_logs": True,
                "audit.full_logging": True
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
            "dlp": {
                "block_sensitive_paths": COMMON_DLP_PATHS,
                "disable_code_training_sharing": True
            },
            "telemetry": {
                "enable_telemetry": False
            },
            "native_settings_override": {
                "share_code_snippets": False,
                "telemetry": "off",
                "auto_run_commands": False,
                "sandbox_isolated": True
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
            "dlp": {
                "block_sensitive_paths": COMMON_DLP_PATHS,
                "disable_code_training_sharing": True
            },
            "telemetry": {
                "enable_telemetry": False
            },
            "native_settings_override": {
                "telemetry.enabled": False,
                "privacy.data_retention": False,
                "prompt.mask_secrets": True,
                "context.exclude_secret_files": True
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
            "dlp": {
                "block_sensitive_paths": COMMON_DLP_PATHS,
                "disable_code_training_sharing": True
            },
            "telemetry": {
                "enable_telemetry": False
            },
            "native_settings_override": {
                "telemetry": False,
                "audit_logs": True,
                "sandbox_strict": True,
                "share_prompts": False,
                "require_approval_all_tools": True
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
        print(f"[OK] Generated policy: {item['vendor']}/{item['name']}")

if __name__ == "__main__":
    generate()
