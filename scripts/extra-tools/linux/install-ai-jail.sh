#!/usr/bin/env bash
# ==============================================================================
# Extra Tool Installer: ai-jail (Linux)
# ==============================================================================
set -euo pipefail

echo "[INFO] ========================================="
echo "[INFO]  Extra Tool Installer: ai-jail (Linux)"
echo "[INFO] ========================================="

if command -v pip3 &> /dev/null; then
    echo "[INFO] Installing ai-jail via pip3..."
    pip3 install "ai-jail>=0.1.0"
    echo "[INFO] [OK] ai-jail installed successfully on Linux."
elif command -v pip &> /dev/null; then
    echo "[INFO] Installing ai-jail via pip..."
    pip install "ai-jail>=0.1.0"
    echo "[INFO] [OK] ai-jail installed successfully on Linux."
else
    echo "[ERROR] pip not found. Please install python3-pip before running this installer." >&2
    exit 1
fi
