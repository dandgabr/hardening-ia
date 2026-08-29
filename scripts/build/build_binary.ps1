# ==============================================================================
# Hardening IA - Standalone Binary Compilation Script (Windows PowerShell)
# ==============================================================================
[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$RootDir = Split-Path -Parent (Split-Path -Parent $ScriptDir)

Set-Location $RootDir

Write-Host "[INFO] ===========================================================" -ForegroundColor Cyan
Write-Host "[INFO]  Hardening IA - Standalone Binary Compilation (Windows)" -ForegroundColor Cyan
Write-Host "[INFO] ===========================================================" -ForegroundColor Cyan

# 1. Activate or initialize virtual environment
if (Test-Path ".\.venv\Scripts\Activate.ps1") {
    Write-Host "[INFO] Activating virtual environment (.venv)..." -ForegroundColor Yellow
    & ".\.venv\Scripts\Activate.ps1"
} else {
    Write-Host "[INFO] Creating virtual environment (.venv)..." -ForegroundColor Yellow
    python -m venv .venv
    & ".\.venv\Scripts\Activate.ps1"
    python -m pip install --upgrade pip
    python -m pip install -r requirements.txt
}

# 2. Ensure PyInstaller is installed
try {
    python -c "import PyInstaller"
} catch {
    Write-Host "[INFO] Installing PyInstaller in virtual environment..." -ForegroundColor Yellow
    python -m pip install pyinstaller
}

# 3. Run automated quality gate test suite
Write-Host "[INFO] Running automated test suite before compilation..." -ForegroundColor Yellow
python main.py --test

# 4. Clean previous build artifacts
Write-Host "[INFO] Cleaning previous build directories..." -ForegroundColor Yellow
if (Test-Path ".\build") { Remove-Item -Recurse -Force ".\build" }
if (Test-Path ".\dist") { Remove-Item -Recurse -Force ".\dist" }

# 5. Compile standalone native Windows executable
Write-Host "[INFO] Compiling standalone executable via PyInstaller..." -ForegroundColor Yellow
pyinstaller --clean hardening-ia.spec

# 6. Validate compiled binary
Write-Host "[INFO] Validating compiled standalone binary..." -ForegroundColor Yellow
& ".\dist\hardening-ia.exe" --list
& ".\dist\hardening-ia.exe" --test

# 7. Package into release zip archive
$PackageName = "hardening-ia-windows-x64"
$PackageDir = ".\dist\$PackageName"
Write-Host "[INFO] Creating release archive: $PackageName.zip..." -ForegroundColor Yellow

New-Item -ItemType Directory -Force -Path $PackageDir | Out-Null
Copy-Item ".\dist\hardening-ia.exe" -Destination "$PackageDir\hardening-ia.exe"
Copy-Item ".\README.md" -Destination "$PackageDir\README.md"
Copy-Item ".\LICENSE" -Destination "$PackageDir\LICENSE"

Compress-Archive -Path "$PackageDir\*" -DestinationPath ".\dist\$PackageName.zip" -Force

# 8. Compute SHA-256 Checksum
$Hash = (Get-FileHash ".\dist\$PackageName.zip" -Algorithm SHA256).Hash
Set-Content -Path ".\dist\$PackageName.zip.sha256" -Value "$Hash  $PackageName.zip"

Write-Host "[SUCCESS] Standalone Windows binary and archive generated in dist\" -ForegroundColor Green
Get-ChildItem .\dist\
