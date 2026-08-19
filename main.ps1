<#
.SYNOPSIS
    Hardening IA Launcher for PowerShell
#>

$scriptPath = Join-Path $PSScriptRoot "main.py"
python $scriptPath @args
