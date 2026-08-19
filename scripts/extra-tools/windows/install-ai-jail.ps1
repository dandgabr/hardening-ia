<#
.SYNOPSIS
    Installs and verifies ai-jail sandbox runtime for AI agents on Windows.
#>

Write-Output "[INFO] ========================================="
Write-Output "[INFO]  Extra Tool Installer: ai-jail (Windows)"
Write-Output "[INFO] ========================================="

if (Get-Command "python" -ErrorAction SilentlyContinue) {
    Write-Output "[INFO] Installing ai-jail via pip..."
    python -m pip install "ai-jail>=0.1.0"
    if ($LASTEXITCODE -eq 0) {
        Write-Output "[INFO] [OK] ai-jail installed and verified successfully."
    } else {
        Write-Error "[ERROR] Failed to install ai-jail."
    }
} else {
    Write-Error "[ERROR] Python was not found in PATH. Please install Python 3.9+."
}
