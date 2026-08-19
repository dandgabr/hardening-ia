# Windows Terminal Command Execution Risk Matrix & Agent Policy

## 1. Overview

For Windows hosts (PowerShell 5.1/7+, Windows Terminal, CMD, Windows Server), **Hardening IA** enforces a 4-tier Command Risk Matrix:

| Risk Tier | Classification | Description | Execution Policy |
| :--- | :--- | :--- | :--- |
| 🟢 **Low** | Read-Only / Inspection / Query | Non-mutating cmdlets and utilities that inspect filesystem, processes, network, and registry state. | **Auto-executable without operator prompt.** |
| 🟡 **Medium** | Local File & Job Operations | Commands that create, move, copy, archive, or download files, and manage user jobs. | **Requires explicit operator confirmation.** |
| 🟠 **High** | Administrative / UAC / Services / Registry | Commands modifying system services, security execution policies, global registry, firewall rules, and process termination. | **Requires explicit operator confirmation + warning.** |
| 🔴 **Critical** | Irreversible Data Loss / Disk Partitioning | Destructive cmdlets, raw disk formatting, partition deletion, and zeroing. | **Strictly prohibited or multi-step confirmation.** |

---

## 2. Command Catalog by Risk Tier

### 🟢 Low Risk (Auto-Run Permitted)
- **Filesystem Navigation & Inspection:** `Get-ChildItem` (`dir`, `gci`, `ls`), `Get-Location` (`pwd`, `gl`), `Get-Content` (`type`, `cat`, `gc`), `Get-Item`, `Get-ItemProperty`, `Test-Path`, `Measure-Object`, `Select-String` (`findstr`, `sls`), `Select-Object`, `Where-Object`, `Sort-Object`, `Group-Object`, `Format-Table` (`ft`), `Format-List` (`fl`), `Out-String`, `Out-Null`, `Write-Output`, `Write-Host`, `fc`, `comp`.
- **Process & Service Inspection:** `Get-Process` (`ps`, `gps`), `Get-Service` (`gsv`), `Get-EventLog`, `Get-WinEvent`.
- **Network & Diagnostics:** `Get-NetIPAddress`, `Get-NetAdapter`, `Get-NetTCPConnection`, `Test-NetConnection` (`tnc`), `ipconfig`, `ping`, `tracert`, `nslookup`, `pathping`.
- **System & Identity Info:** `systeminfo`, `hostname`, `whoami`, `Get-Date`, `Get-LocalUser`, `Get-LocalGroup`, `Get-ExecutionPolicy`, `Get-Disk`, `Get-Volume`, `Get-Partition`.

---

### 🟡 Medium Risk (Operator Approval Required)
- **Filesystem Creation & Modifications:** `New-Item` (`mkdir`, `md`, `ni`), `Copy-Item` (`copy`, `cp`, `cpi`), `Move-Item` (`move`, `mv`, `mi`), `Rename-Item` (`ren`, `rni`), `Set-Content`, `Add-Content`, `Clear-Content`.
- **Archiving & Compression:** `Compress-Archive`, `Expand-Archive`, `tar`, `zip`.
- **Web Requests & API Sockets:** `Invoke-WebRequest` (`iwr`, `curl`, `wget`), `Invoke-RestMethod` (`irm`).
- **Process Spawning & Job Control:** `Start-Process`, `Start-Job`, `Stop-Job`, `Export-Csv`, `Export-Clixml`, `ConvertTo-Json`.

---

### 🟠 High Risk (Admin Approval + Warning Required)
- **Deletion & Process Termination:** `Remove-Item` (`del`, `rm`, `erase`, `ri`), `Stop-Process` (`kill`, `spps`, `taskkill`).
- **Service & Driver Control:** `Start-Service`, `Stop-Service`, `Restart-Service`, `Set-Service`, `New-Service`, `net start/stop`, `sc.exe`.
- **Permissions & ACLs:** `icacls`, `cacls`, `takeown`, `Set-ExecutionPolicy`.
- **Registry Modification:** `Set-ItemProperty`, `New-ItemProperty`, `Remove-ItemProperty`, `reg.exe`, `regini.exe`.
- **User & Group Administration:** `New-LocalUser`, `Remove-LocalUser`, `Set-LocalUser`, `Add-LocalGroupMember`, `Remove-LocalGroupMember`.
- **Network Configuration & Firewall:** `New-NetFirewallRule`, `Set-NetFirewallRule`, `Remove-NetFirewallRule`, `netsh`.
- **Package Management & System Tools:** `winget`, `choco`, `scoop`, `Install-Package`, `Uninstall-Package`, `wmic`, `bcdedit`, `sfc`, `dism`, `Stop-Computer`, `Restart-Computer`, `shutdown`.

---

### 🔴 Critical Risk (Destructive / Prohibited Anti-Patterns)
- `Format-Volume`, `format` (Disk formatting)
- `Clear-Disk`, `Initialize-Disk` (Partition table zeroing)
- `Remove-Partition`, `Resize-Partition`
- `diskpart` (Interactive/scripted disk partitioning)
- `cipher /w` (Cryptographic unallocated space wipe)
- `chkdsk /f /r`
