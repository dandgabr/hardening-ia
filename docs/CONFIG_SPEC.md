# Declarative Policy YAML Specification (v1.0)

All security policies stored under `configs/tools/<vendor>/<tool>/hardening_policy.yaml` conform to this declarative schema.

---

## 1. Complete YAML Schema Example

```yaml
schema_version: "1.0"
tool:
  name: "antigravity"
  vendor: "google"
  category: "agentic"  # Options: 'cli' | 'ide' | 'agentic'
  description: "Google Antigravity - Autonomous agentic development suite (CLI, IDE, MCP)"

paths:
  windows:
    config_dir: "%USERPROFILE%\\.gemini\\antigravity-cli"
    settings_file: "%USERPROFILE%\\.gemini\\antigravity-cli\\settings.json"
    rules_dir: "%USERPROFILE%\\.gemini\\antigravity-cli\\rules"
  linux:
    config_dir: "~/.gemini/antigravity-cli"
    settings_file: "~/.gemini/antigravity-cli/settings.json"
    rules_dir: "~/.gemini/antigravity-cli/rules"
  macos:
    config_dir: "~/.gemini/antigravity-cli"
    settings_file: "~/.gemini/antigravity-cli/settings.json"
    rules_dir: "~/.gemini/antigravity-cli/rules"

policies:
  sandbox:
    enforce_sandbox: true
    default_bypass: false

  approvals:
    require_approval_for_terminal: true
    require_approval_for_network: true
    require_approval_for_file_write_outside_workspace: true

  dlp:
    block_sensitive_paths:
      - "**/.env*"
      - "**/*.pem"
      - "**/*.key"
      - "**/*.pfx"
      - "~/.ssh/**"
      - "~/.aws/**"
      - "~/.kube/**"
      - "~/.gnupg/**"
    disable_code_training_sharing: true

  telemetry:
    enable_telemetry: false
    enable_crash_reporting: false
    audit_logging: true

  native_settings_override:
    "telemetry.enabled": false
    "security.sandbox.default_enforced": true
    "security.approvals.bypass_allowed": false
    "security.dlp.strict_mode": true

custom_scripts:
  windows: "scripts/os/windows/apply-hardening.ps1"
  linux: "scripts/os/linux/apply-hardening.sh"
  macos: "scripts/os/macos/apply-hardening.sh"
```

---

## 2. Field Definitions

| Field Path | Type | Mandatory | Description |
|---|---|---|---|
| `schema_version` | String | Yes | Schema version tag (`"1.0"`). |
| `tool.name` | String | Yes | Unique canonical tool identifier. |
| `tool.vendor` | String | Yes | Tool manufacturer or open-source organization. |
| `tool.category` | String | Yes | Category: `cli`, `ide`, or `agentic`. |
| `tool.description` | String | No | Human-readable explanation of the tool. |
| `paths.<os>` | Object | Yes | OS-specific path mapping (`windows`, `linux`, `macos`). |
| `paths.<os>.config_dir` | String | Yes | Configuration root directory. |
| `paths.<os>.settings_file` | String | No | Path to settings JSON configuration file. |
| `paths.<os>.rules_dir` | String | No | Path to custom agent rules directory. |
| `policies.sandbox` | Object | No | Runtime containment and isolation constraints. |
| `policies.approvals` | Object | No | Human-in-the-loop validation parameters. |
| `policies.dlp` | Object | No | Data Loss Prevention pattern list and sharing rules. |
| `policies.telemetry` | Object | No | Diagnostic and telemetry disablement switches. |
| `policies.native_settings_override` | Object | No | Deep-merged configuration map applied directly to settings file. |
| `custom_scripts.<os>` | String | No | Relative path to native shell automation scripts. |
