#!/usr/bin/env bash
# ==============================================================================
# Extra Tool Installer: OpenGrep (Linux) - https://github.com/opengrep/opengrep
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
INSTALLER_PY="${REPO_ROOT}/scripts/extra-tools/install_opengrep.py"

echo "[INFO] ==========================================="
echo "[INFO]  Extra Tool Installer: OpenGrep (Linux)"
echo "[INFO] ==========================================="

if [ -f "$INSTALLER_PY" ]; then
    echo "[INFO] Invoking universal OpenGrep installer..."
    python3 "$INSTALLER_PY"
    exit 0
else
    echo "[ERROR] Installer script not found: $INSTALLER_PY" >&2
    exit 1
fi
