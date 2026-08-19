<#
.SYNOPSIS
    Installs and configures OpenGrep vulnerability scanner on Windows (https://github.com/opengrep/opengrep).
#>

Write-Output "[INFO] ==========================================="
Write-Output "[INFO]  Extra Tool Installer: OpenGrep (Windows)"
Write-Output "[INFO] ==========================================="

$repoRoot = (Resolve-Path "$PSScriptRoot\..\..\..").Path
$installerScript = Join-Path $repoRoot "scripts\extra-tools\install_opengrep.py"

if (Test-Path $installerScript) {
    Write-Output "[INFO] Invoking universal OpenGrep installer..."
    python $installerScript
    if ($LASTEXITCODE -eq 0) {
        Write-Output "[INFO] [OK] OpenGrep installed and configured successfully."
        exit 0
    } else {
        Write-Error "[ERROR] Failed to install OpenGrep."
        exit 1
    }
} else {
    Write-Error "[ERROR] Installer script not found: $installerScript"
    exit 1
}
