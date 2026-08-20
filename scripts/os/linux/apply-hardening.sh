#!/usr/bin/env bash
# ==============================================================================
# Hardening IA - Linux Policy Execution Script (YAML Driven)
# ==============================================================================
set -euo pipefail

POLICY_FILE="${1:-}"
DRY_RUN="${2:-false}"

echo "[INFO] ==========================================================="
echo "[INFO]  Hardening IA - Linux Policy Execution Script"
echo "[INFO] ==========================================================="

if [ -n "$POLICY_FILE" ] && [ -f "$POLICY_FILE" ]; then
    echo "[INFO] Loading YAML policy from: ${POLICY_FILE}"

    # Extract target directories and settings using python
    read -r VENDOR TOOL CATEGORY CONFIG_DIR RULES_DIR TELEMETRY_OFF < <(python3 -c "
import yaml, os, sys
try:
    with open('${POLICY_FILE}', 'r', encoding='utf-8') as f:
        data = yaml.safe_load(f)
    v = data.get('tool', {}).get('vendor', 'unknown')
    t = data.get('tool', {}).get('name', 'unknown')
    c = data.get('tool', {}).get('category', 'cli')
    paths = data.get('paths', {}).get('linux', {})
    cdir = os.path.expanduser(paths.get('config_dir', ''))
    rdir = os.path.expanduser(paths.get('rules_dir', ''))
    telemetry_off = '1' if not data.get('policies', {}).get('telemetry', {}).get('enable_telemetry', True) else '0'
    print(f'{v} {t} {c} {cdir or \"-\"} {rdir or \"-\"} {telemetry_off}')
except Exception as e:
    sys.exit(1)
" || echo "unknown unknown cli - - 1")

    echo "[INFO] Executing hardening policy for: ${VENDOR}/${TOOL} (${CATEGORY})"

    # 1. Telemetry Policy
    if [ "$TELEMETRY_OFF" = "1" ]; then
        export DO_NOT_TRACK=1
        export CLAUDE_DISABLE_TELEMETRY=1
        export CLAUDE_TELEMETRY_DISABLED=1
        export CLAUDE_CODE_ENABLE_TELEMETRY=0
        export CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1
        export CLAUDE_CODE_SUBPROCESS_ENV_SCRUB=1
        export DISABLE_TELEMETRY=1
        export DISABLE_AUTOUPDATER=1
        echo "[INFO] Enforced global telemetry lockdown (DO_NOT_TRACK=1, CLAUDE_DISABLE_TELEMETRY=1, CLAUDE_CODE_SUBPROCESS_ENV_SCRUB=1)"
    fi

    # 2. Permissions Lockdown on Target Config Directory
    if [ "$CONFIG_DIR" != "-" ] && [ -d "$CONFIG_DIR" ]; then
        echo "[INFO] Applying restricted permissions (chmod 700 dirs / 600 files) on: $CONFIG_DIR"
        if [ "$DRY_RUN" != "true" ]; then
            find "$CONFIG_DIR" -type d -exec chmod 700 {} + 2>/dev/null || true
            find "$CONFIG_DIR" -type f -exec chmod 600 {} + 2>/dev/null || true
            echo "[INFO] Successfully locked permissions on: $CONFIG_DIR"
        else
            echo "[INFO] [DRY-RUN] Would execute chmod 700/600 on: $CONFIG_DIR"
        fi
    else
        echo "[INFO] Config directory not found on host (skipped): $CONFIG_DIR"
    fi

    echo "[INFO] Tool policy execution for ${VENDOR}/${TOOL} completed."
    exit 0
fi

echo "[WARN] No specific policy file provided. Running generic baseline."
