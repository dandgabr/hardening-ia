# ==============================================================================
# Hardening IA - Windows PowerShell Launcher with Auto-Python Provisioning
# ==============================================================================
[CmdletBinding()]
param()

$scriptPath = Join-Path $PSScriptRoot "main.py"
$reqFile = Join-Path $PSScriptRoot "requirements.txt"

function Get-PythonExecutable {
    # 1. Check commands in active PATH
    $commands = @("python", "py", "python3")
    foreach ($cmd in $commands) {
        $cmdInfo = Get-Command $cmd -ErrorAction SilentlyContinue
        if ($null -ne $cmdInfo) {
            try {
                $verTest = & $cmdInfo.Source -c "import sys; print(sys.version_info[0])" 2>$null
                if ($verTest -eq "3") {
                    return $cmdInfo.Source
                }
            } catch {}
        }
    }

    # 2. Check well-known user & system installation locations
    $knownLocations = @(
        "$env:LOCALAPPDATA\Programs\Python\Python313\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python311\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python310\python.exe",
        "$env:USERPROFILE\scoop\shims\python.exe",
        "$env:USERPROFILE\.pyenv\pyenv-win\shims\python.exe",
        "$env:ProgramFiles\Python313\python.exe",
        "$env:ProgramFiles\Python312\python.exe",
        "$env:ProgramFiles\Python311\python.exe",
        "$env:ProgramFiles\Python310\python.exe"
    )

    foreach ($loc in $knownLocations) {
        if (Test-Path -LiteralPath $loc) {
            return $loc
        }
    }

    return $null
}

function Install-PythonUserContext {
    Write-Host "[*] Python 3 was not detected on this system." -ForegroundColor Yellow
    Write-Host "[*] Attempting automatic user-context installation..." -ForegroundColor Cyan

    # 1. Try Windows Package Manager (winget) in user scope
    $winget = Get-Command "winget" -ErrorAction SilentlyContinue
    if ($null -ne $winget) {
        Write-Host "[*] Found winget. Installing Python 3.12 in user context..." -ForegroundColor Cyan
        try {
            & winget install --id Python.Python.3.12 --scope user --exact --accept-package-agreements --accept-source-agreements --silent --disable-interactivity
            if ($LASTEXITCODE -eq 0) {
                Write-Host "[+] Python installed successfully via winget." -ForegroundColor Green
                # Refresh PATH for current session
                $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
                $machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
                $env:PATH = "$userPath;$machinePath"
                return (Get-PythonExecutable)
            }
        } catch {
            Write-Host "[!] Winget installation encountered an error: $_" -ForegroundColor Yellow
        }
    }

    # 2. Try Scoop if available
    $scoop = Get-Command "scoop" -ErrorAction SilentlyContinue
    if ($null -ne $scoop) {
        Write-Host "[*] Found Scoop. Installing Python in user context..." -ForegroundColor Cyan
        try {
            & scoop install python
            if ($LASTEXITCODE -eq 0) {
                Write-Host "[+] Python installed successfully via Scoop." -ForegroundColor Green
                $env:PATH = "$env:USERPROFILE\scoop\shims;$env:PATH"
                return (Get-PythonExecutable)
            }
        } catch {
            Write-Host "[!] Scoop installation encountered an error: $_" -ForegroundColor Yellow
        }
    }

    # 3. Try Chocolatey if available
    $choco = Get-Command "choco" -ErrorAction SilentlyContinue
    if ($null -ne $choco) {
        Write-Host "[*] Found Chocolatey. Installing Python..." -ForegroundColor Cyan
        try {
            & choco install python3 -y --no-progress
            if ($LASTEXITCODE -eq 0) {
                Write-Host "[+] Python installed successfully via Chocolatey." -ForegroundColor Green
                $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
                $machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
                $env:PATH = "$userPath;$machinePath"
                return (Get-PythonExecutable)
            }
        } catch {
            Write-Host "[!] Chocolatey installation encountered an error: $_" -ForegroundColor Yellow
        }
    }

    # If all automatic installation methods failed, notify user
    Write-Host "[!] Unable to automatically install Python 3." -ForegroundColor Red
    Write-Host "[!] Please install Python 3.10+ from: https://www.python.org/downloads/" -ForegroundColor Yellow
    Write-Host "[!] Ensure you check 'Add Python to PATH' during installation." -ForegroundColor Yellow
    exit 1
}

# --- Resolve Python Binary ---
$pythonBinary = Get-PythonExecutable
if ($null -eq $pythonBinary) {
    $pythonBinary = Install-PythonUserContext
}

# --- Step 1: If inside active virtual environment or dependencies already present ---
if ($env:VIRTUAL_ENV) {
    & $pythonBinary $scriptPath @args
    exit $LASTEXITCODE
}

try {
    $depsCheck = & $pythonBinary -c "import textual, rich, yaml, pydantic" 2>$null
    if ($LASTEXITCODE -eq 0) {
        & $pythonBinary $scriptPath @args
        exit $LASTEXITCODE
    }
} catch {}

# --- Step 2: Check for existing virtual environments in the project folder ---
$venvCandidates = @(
    (Join-Path $PSScriptRoot ".venv\Scripts\python.exe"),
    (Join-Path $PSScriptRoot "venv\Scripts\python.exe"),
    (Join-Path $PSScriptRoot "env\Scripts\python.exe")
)

foreach ($candidate in $venvCandidates) {
    if (Test-Path -LiteralPath $candidate) {
        & $candidate $scriptPath @args
        exit $LASTEXITCODE
    }
}

# --- Step 3: Create .venv and install dependencies ---
$newVenv = Join-Path $PSScriptRoot ".venv"
$newVenvPython = Join-Path $newVenv "Scripts\python.exe"

Write-Host "[*] Initializing isolated project virtual environment (.venv)..." -ForegroundColor Cyan
& $pythonBinary -m venv $newVenv

if (-not (Test-Path -LiteralPath $newVenvPython)) {
    Write-Host "[!] Failed to initialize virtual environment with $pythonBinary." -ForegroundColor Red
    Write-Host "[*] Falling back to executing with system python..." -ForegroundColor Yellow
    & $pythonBinary $scriptPath @args
    exit $LASTEXITCODE
}

Write-Host "[*] Installing required dependencies from requirements.txt..." -ForegroundColor Cyan
& $newVenvPython -m pip install --upgrade pip --quiet
& $newVenvPython -m pip install -r $reqFile --quiet
Write-Host "[+] Virtual environment ready and dependencies installed." -ForegroundColor Green

& $newVenvPython $scriptPath @args
exit $LASTEXITCODE
