$scriptPath = Join-Path $PSScriptRoot "main.py"
$reqFile = Join-Path $PSScriptRoot "requirements.txt"

# 1. If already inside an active virtual environment or dependencies are available
if ($env:VIRTUAL_ENV -or (python -c "import textual, rich, yaml, pydantic" 2>$null)) {
    & python $scriptPath @args
    exit $LASTEXITCODE
}

# 2. Check for existing virtual environments in the project folder
$venvCandidates = @(
    (Join-Path $PSScriptRoot ".venv\Scripts\python.exe"),
    (Join-Path $PSScriptRoot "venv\Scripts\python.exe"),
    (Join-Path $PSScriptRoot "env\Scripts\python.exe")
)

foreach ($candidate in $venvCandidates) {
    if (Test-Path $candidate) {
        & $candidate $scriptPath @args
        exit $LASTEXITCODE
    }
}

# 3. Only create .venv if no existing environment was found
$newVenv = Join-Path $PSScriptRoot ".venv"
$newVenvPython = Join-Path $newVenv "Scripts\python.exe"

Write-Host "[*] No existing virtual environment found. Initializing .venv..." -ForegroundColor Cyan
python -m venv $newVenv
& $newVenvPython -m pip install --upgrade pip --quiet
& $newVenvPython -m pip install -r $reqFile
Write-Host "[+] Virtual environment created and dependencies installed." -ForegroundColor Green

& $newVenvPython $scriptPath @args
