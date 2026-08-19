<#
.SYNOPSIS
    Installs and verifies ai-jail sandbox runtime for AI agents on Windows (https://github.com/akitaonrails/ai-jail).
#>

Write-Output "[INFO] ========================================="
Write-Output "[INFO]  Extra Tool Installer: ai-jail (Windows)"
Write-Output "[INFO] ========================================="

$repoRoot = (Resolve-Path "$PSScriptRoot\..\..\..").Path
$installerScript = Join-Path $repoRoot "scripts\extra-tools\install_ai_jail.py"

if (Test-Path $installerScript) {
    Write-Output "[INFO] Invoking universal ai-jail installer..."
    python $installerScript
    if ($LASTEXITCODE -eq 0) {
        Write-Output "[INFO] [OK] ai-jail installed and verified successfully."
        exit 0
    } else {
        Write-Error "[ERROR] Failed to install ai-jail."
        exit 1
    }
} else {
    Write-Error "[ERROR] Installer script not found: $installerScript"
    exit 1
}
