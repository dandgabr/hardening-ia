@echo off
setlocal
set "SCRIPT_DIR=%~dp0"
set "REQ_FILE=%SCRIPT_DIR%requirements.txt"

:: 1. Check if python is available in PATH or well-known location
set "PYTHON_EXE="
where python >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    set "PYTHON_EXE=python"
) else (
    where py >nul 2>&1
    if %ERRORLEVEL% EQU 0 (
        set "PYTHON_EXE=py"
    ) else (
        where python3 >nul 2>&1
        if %ERRORLEVEL% EQU 0 (
            set "PYTHON_EXE=python3"
        )
    )
)

:: 2. If python is not found, delegate to main.ps1 to auto-install via winget/scoop
if not defined PYTHON_EXE (
    echo [*] Python was not detected in PATH. Delegating to PowerShell auto-provisioner...
    powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%main.ps1" %*
    exit /b %ERRORLEVEL%
)

:: 3. If inside active virtualenv
if defined VIRTUAL_ENV (
    %PYTHON_EXE% "%SCRIPT_DIR%main.py" %*
    exit /b %ERRORLEVEL%
)

:: 4. Check for existing virtual environments in project directory
if exist "%SCRIPT_DIR%.venv\Scripts\python.exe" (
    "%SCRIPT_DIR%.venv\Scripts\python.exe" "%SCRIPT_DIR%main.py" %*
    exit /b %ERRORLEVEL%
)
if exist "%SCRIPT_DIR%venv\Scripts\python.exe" (
    "%SCRIPT_DIR%venv\Scripts\python.exe" "%SCRIPT_DIR%main.py" %*
    exit /b %ERRORLEVEL%
)
if exist "%SCRIPT_DIR%env\Scripts\python.exe" (
    "%SCRIPT_DIR%env\Scripts\python.exe" "%SCRIPT_DIR%main.py" %*
    exit /b %ERRORLEVEL%
)

:: 5. Create .venv and install dependencies
set "NEW_VENV=%SCRIPT_DIR%.venv"
set "NEW_PYTHON=%NEW_VENV%\Scripts\python.exe"

echo [*] No existing virtual environment found. Initializing .venv...
%PYTHON_EXE% -m venv "%NEW_VENV%"
if not exist "%NEW_PYTHON%" (
    echo [!] Failed to create .venv. Falling back to system python...
    %PYTHON_EXE% "%SCRIPT_DIR%main.py" %*
    exit /b %ERRORLEVEL%
)

"%NEW_PYTHON%" -m pip install --upgrade pip --quiet
"%NEW_PYTHON%" -m pip install -r "%REQ_FILE%" --quiet
echo [+] Virtual environment created and dependencies installed.

"%NEW_PYTHON%" "%SCRIPT_DIR%main.py" %*
exit /b %ERRORLEVEL%
