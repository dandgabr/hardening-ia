#!/usr/bin/env bash
# ==============================================================================
# Extra Tool Installer: ai-jail (macOS)
# ==============================================================================
set -euo pipefail

echo "[INFO] ========================================="
echo "[INFO]  Extra Tool Installer: ai-jail (macOS)"
echo "[INFO] ========================================="

if command -v pip3 &> /dev/null; then
    echo "[INFO] Installing ai-jail via pip3..."
    pip3 install "ai-jail>=0.1.0"
    echo "[INFO] [OK] ai-jail installed successfully on macOS."
elif command -v pip &> /dev/null; then
    echo "[INFO] Installing ai-jail via pip..."
    pip install "ai-jail>=0.1.0"
    echo "[INFO] [OK] ai-jail installed successfully on macOS."
else
    echo "[ERROR] pip not found. Please install Python via Homebrew (brew install python)." >&2
    exit 1
fi
