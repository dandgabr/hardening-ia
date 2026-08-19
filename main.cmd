@echo off
setlocal
set "SCRIPT_DIR=%~dp0"
set "REQ_FILE=%SCRIPT_DIR%requirements.txt"

:: 1. If inside active virtualenv
if defined VIRTUAL_ENV (
    python "%SCRIPT_DIR%main.py" %*
    goto :eof
)

:: 2. Check for existing virtual environments in project directory
if exist "%SCRIPT_DIR%.venv\Scripts\python.exe" (
    "%SCRIPT_DIR%.venv\Scripts\python.exe" "%SCRIPT_DIR%main.py" %*
    goto :eof
)
if exist "%SCRIPT_DIR%venv\Scripts\python.exe" (
    "%SCRIPT_DIR%venv\Scripts\python.exe" "%SCRIPT_DIR%main.py" %*
    goto :eof
)
if exist "%SCRIPT_DIR%env\Scripts\python.exe" (
    "%SCRIPT_DIR%env\Scripts\python.exe" "%SCRIPT_DIR%main.py" %*
    goto :eof
)

:: 3. Only create .venv if no existing environment was found
set "NEW_VENV=%SCRIPT_DIR%.venv"
set "NEW_PYTHON=%NEW_VENV%\Scripts\python.exe"

echo [*] No existing virtual environment found. Initializing .venv...
python -m venv "%NEW_VENV%"
"%NEW_PYTHON%" -m pip install --upgrade pip --quiet
"%NEW_PYTHON%" -m pip install -r "%REQ_FILE%"
echo [+] Virtual environment created and dependencies installed.

"%NEW_PYTHON%" "%SCRIPT_DIR%main.py" %*
