#!/usr/bin/env bash
# ==============================================================================
# Hardening IA - Local Standalone Binary Compilation Script (Linux / macOS)
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

cd "${ROOT_DIR}"

echo "[INFO] ==========================================================="
echo "[INFO]  Hardening IA - Standalone Binary Compilation"
echo "[INFO] ==========================================================="

# 1. Activate or initialize virtual environment
if [ -d ".venv" ]; then
    echo "[INFO] Activating virtual environment (.venv)..."
    # shellcheck disable=SC1091
    source .venv/bin/activate
else
    echo "[INFO] Creating virtual environment (.venv)..."
    python3 -m venv .venv
    # shellcheck disable=SC1091
    source .venv/bin/activate
    pip install --upgrade pip
    pip install -r requirements.txt
fi

# 2. Ensure PyInstaller is installed
if ! python -c "import PyInstaller" 2>/dev/null; then
    echo "[INFO] Installing PyInstaller in virtual environment..."
    pip install pyinstaller
fi

# 3. Run automated quality gate test suite
echo "[INFO] Running automated test suite before compilation..."
python main.py --test

# 4. Clean previous build artifacts
echo "[INFO] Cleaning previous build directories..."
rm -rf build dist

# 5. Compile standalone native binary
echo "[INFO] Compiling standalone executable via PyInstaller..."
pyinstaller --clean hardening-ia.spec

# 6. Validate compiled binary
echo "[INFO] Validating compiled standalone binary..."
./dist/hardening-ia --list
./dist/hardening-ia --test

# 7. Package into release archive
OS_NAME="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH_NAME="$(uname -m)"
PACKAGE_NAME="hardening-ia-${OS_NAME}-${ARCH_NAME}"
PACKAGE_DIR="dist/${PACKAGE_NAME}"

echo "[INFO] Creating release archive: ${PACKAGE_NAME}.tar.gz..."
mkdir -p "${PACKAGE_DIR}"
cp dist/hardening-ia "${PACKAGE_DIR}/"
cp README.md "${PACKAGE_DIR}/"
cp LICENSE "${PACKAGE_DIR}/"

tar -czf "dist/${PACKAGE_NAME}.tar.gz" -C dist "${PACKAGE_NAME}"

echo "[INFO] Computing SHA-256 checksum..."
if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "dist/${PACKAGE_NAME}.tar.gz" > "dist/${PACKAGE_NAME}.tar.gz.sha256"
elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "dist/${PACKAGE_NAME}.tar.gz" > "dist/${PACKAGE_NAME}.tar.gz.sha256"
fi

echo "[SUCCESS] Standalone binary and archive successfully generated in dist/"
ls -lh dist/
