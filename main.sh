#!/usr/bin/env bash
# Hardening IA Launcher for Linux & macOS
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# 1. If currently inside an active virtualenv or Python environment with required dependencies, run directly
if [ -n "${VIRTUAL_ENV}" ] || python3 -c "import textual, rich, yaml, pydantic" 2>/dev/null; then
    exec python3 "${SCRIPT_DIR}/main.py" "$@"
fi

# 2. Check for existing virtual environment folders in the project directory
for venv_path in "${SCRIPT_DIR}/.venv" "${SCRIPT_DIR}/venv" "${SCRIPT_DIR}/env"; do
    if [ -x "${venv_path}/bin/python3" ]; then
        exec "${venv_path}/bin/python3" "${SCRIPT_DIR}/main.py" "$@"
    elif [ -x "${venv_path}/bin/python" ]; then
        exec "${venv_path}/bin/python" "${SCRIPT_DIR}/main.py" "$@"
    fi
done

# 3. Only if no virtual environment exists anywhere, create .venv and install dependencies
VENV_DIR="${SCRIPT_DIR}/.venv"
echo "[*] No existing virtual environment found. Initializing .venv..."
python3 -m venv "${VENV_DIR}"
"${VENV_DIR}/bin/pip" install --upgrade pip --quiet
"${VENV_DIR}/bin/pip" install -r "${SCRIPT_DIR}/requirements.txt"
echo "[+] Virtual environment created and dependencies installed."

exec "${VENV_DIR}/bin/python3" "${SCRIPT_DIR}/main.py" "$@"
