#!/usr/bin/env bash
# ==============================================================================
# Hardening IA - Linux & macOS Launcher with Auto-Python Provisioning
# ==============================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REQ_FILE="${SCRIPT_DIR}/requirements.txt"

get_python_executable() {
    # 1. Check commands in current PATH
    for cmd in python3 python; do
        if command -v "$cmd" >/dev/null 2>&1; then
            if "$cmd" -c "import sys; sys.exit(0 if sys.version_info[0] >= 3 else 1)" 2>/dev/null; then
                command -v "$cmd"
                return 0
            fi
        fi
    done

    # 2. Check well-known user and system locations
    local known_paths=(
        "${HOME}/.pyenv/shims/python3"
        "${HOME}/.local/bin/python3"
        "/opt/homebrew/bin/python3"
        "/usr/local/bin/python3"
        "/usr/bin/python3"
        "/usr/bin/python"
    )

    for p in "${known_paths[@]}"; do
        if [ -x "$p" ]; then
            if "$p" -c "import sys; sys.exit(0 if sys.version_info[0] >= 3 else 1)" 2>/dev/null; then
                echo "$p"
                return 0
            fi
        fi
    done

    return 1
}

install_python_auto() {
    echo "[*] Python 3 was not detected on this system."
    echo "[*] Attempting automatic package provisioning..."

    local os_type
    os_type="$(uname -s)"

    # 1. Check for modern user-space managers (uv, pyenv)
    if command -v uv >/dev/null 2>&1; then
        echo "[*] Found 'uv'. Provisioning managed Python 3.12..."
        if uv python install 3.12 >/dev/null 2>&1; then
            local uv_py
            uv_py="$(uv python find 3.12 2>/dev/null || true)"
            if [ -n "$uv_py" ] && [ -x "$uv_py" ]; then
                echo "[+] Python 3.12 installed successfully via uv ($uv_py)."
                echo "$uv_py"
                return 0
            fi
        fi
    fi

    if command -v pyenv >/dev/null 2>&1; then
        echo "[*] Found 'pyenv'. Provisioning Python 3.12..."
        if pyenv install -s 3.12.0 >/dev/null 2>&1; then
            pyenv global 3.12.0
            local pyenv_py="${HOME}/.pyenv/shims/python3"
            if [ -x "$pyenv_py" ]; then
                echo "[+] Python installed successfully via pyenv."
                echo "$pyenv_py"
                return 0
            fi
        fi
    fi

    # 2. macOS Package Managers (Homebrew / MacPorts)
    if [ "$os_type" = "Darwin" ]; then
        if command -v brew >/dev/null 2>&1; then
            echo "[*] Installing Python 3 via Homebrew..."
            brew install python3
            get_python_executable && return 0
        fi
        if command -v port >/dev/null 2>&1; then
            echo "[*] Installing Python 3 via MacPorts..."
            sudo port install python312
            get_python_executable && return 0
        fi
    fi

    # 3. Linux Package Managers
    if [ "$os_type" = "Linux" ]; then
        local SUDO=""
        if [ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1; then
            SUDO="sudo"
        fi

        if command -v apt-get >/dev/null 2>&1; then
            echo "[*] Installing Python 3 via apt (Debian/Ubuntu)..."
            $SUDO apt-get update -qq && $SUDO apt-get install -y -qq python3 python3-venv python3-pip
            get_python_executable && return 0
        elif command -v dnf >/dev/null 2>&1; then
            echo "[*] Installing Python 3 via dnf (Fedora/RHEL)..."
            $SUDO dnf install -y python3 python3-pip
            get_python_executable && return 0
        elif command -v yum >/dev/null 2>&1; then
            echo "[*] Installing Python 3 via yum (CentOS/RHEL)..."
            $SUDO yum install -y python3 python3-pip
            get_python_executable && return 0
        elif command -v pacman >/dev/null 2>&1; then
            echo "[*] Installing Python 3 via pacman (Arch Linux)..."
            $SUDO pacman -Sy --noconfirm python python-pip
            get_python_executable && return 0
        elif command -v zypper >/dev/null 2>&1; then
            echo "[*] Installing Python 3 via zypper (openSUSE)..."
            $SUDO zypper --non-interactive install python3 python3-pip
            get_python_executable && return 0
        elif command -v apk >/dev/null 2>&1; then
            echo "[*] Installing Python 3 via apk (Alpine Linux)..."
            $SUDO apk add python3 py3-pip
            get_python_executable && return 0
        fi
    fi

    echo "[!] Unable to automatically install Python 3."
    echo "[!] Please install Python 3.10+ using your system package manager or from https://www.python.org/downloads/"
    exit 1
}

# --- Resolve Python 3 Binary ---
PYTHON_BIN="$(get_python_executable || true)"
if [ -z "${PYTHON_BIN}" ]; then
    PYTHON_BIN="$(install_python_auto)"
fi

# --- Step 1: If currently inside active virtualenv or dependencies already installed in Python ---
if [ -n "${VIRTUAL_ENV}" ]; then
    exec "${PYTHON_BIN}" "${SCRIPT_DIR}/main.py" "$@"
fi

if "${PYTHON_BIN}" -c "import textual, rich, yaml, pydantic" 2>/dev/null; then
    exec "${PYTHON_BIN}" "${SCRIPT_DIR}/main.py" "$@"
fi

# --- Step 2: Check for existing virtual environment folders ---
for venv_path in "${SCRIPT_DIR}/.venv" "${SCRIPT_DIR}/venv" "${SCRIPT_DIR}/env"; do
    if [ -x "${venv_path}/bin/python3" ]; then
        exec "${venv_path}/bin/python3" "${SCRIPT_DIR}/main.py" "$@"
    elif [ -x "${venv_path}/bin/python" ]; then
        exec "${venv_path}/bin/python" "${SCRIPT_DIR}/main.py" "$@"
    fi
done

# --- Step 3: Create .venv and install dependencies ---
VENV_DIR="${SCRIPT_DIR}/.venv"
echo "[*] Initializing isolated project virtual environment (.venv)..."

# Ensure venv creation succeeds; on Debian/Ubuntu python3-venv might be missing
if ! "${PYTHON_BIN}" -m venv "${VENV_DIR}" 2>/dev/null; then
    echo "[*] Ensuring 'python3-venv' support is installed..."
    if command -v apt-get >/dev/null 2>&1 && [ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1; then
        sudo apt-get update -qq && sudo apt-get install -y -qq python3-venv python3-pip
        "${PYTHON_BIN}" -m venv "${VENV_DIR}"
    else
        "${PYTHON_BIN}" -m venv "${VENV_DIR}" || {
            echo "[!] Failed to create virtual environment. Running with system python..."
            exec "${PYTHON_BIN}" "${SCRIPT_DIR}/main.py" "$@"
        }
    fi
fi

VENV_PY="${VENV_DIR}/bin/python3"
if [ ! -x "${VENV_PY}" ]; then
    VENV_PY="${VENV_DIR}/bin/python"
fi

echo "[*] Installing required dependencies from requirements.txt..."
"${VENV_PY}" -m pip install --upgrade pip --quiet 2>/dev/null || true
"${VENV_PY}" -m pip install -r "${REQ_FILE}" --quiet

echo "[+] Virtual environment ready and dependencies installed."
exec "${VENV_PY}" "${SCRIPT_DIR}/main.py" "$@"
