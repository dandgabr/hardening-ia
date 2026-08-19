# macOS (Darwin / BSD) Command Execution Risk Matrix & Agent Policy

## 1. Overview

For macOS hosts (macOS Ventura, Sonoma, Sequoia, Apple Silicon & Intel), **Hardening IA** provides a 4-tier Command Risk Matrix:

| Risk Tier | Classification | Description | Execution Policy |
| :--- | :--- | :--- | :--- |
| 🟢 **Low** | Read-Only / Diagnostics / Inspection | System queries, macOS preference readings, diagnostics, and non-mutating BSD utilities. | **Auto-executable without operator prompt.** |
| 🟡 **Medium** | User Operations & Application Control | Local mutations, Homebrew package installation, AppleScript GUI scripts, DMG operations. | **Requires explicit operator confirmation.** |
| 🟠 **High** | Administrative / Daemons / SIP / Network | System launch daemons, kernel extensions, Directory Services, packet filters, and software updates. | **Requires explicit operator confirmation + warning.** |
| 🔴 **Critical** | Irreversible APFS / Partition Formatting | Whole-disk erase, Apple Software Restore (ASR), and raw block operations. | **Strictly prohibited or multi-step confirmation.** |

---

## 2. Command Catalog by Risk Tier

### 🟢 Low Risk (Auto-Run Permitted)
- **macOS System Queries & Metadata:** `sw_vers`, `system_profiler`, `scutil`, `defaults read`, `csrutil status`, `spctl --status`, `codesign -v`, `security find-certificate`, `mdfind` (Spotlight), `mdls`, `pbcopy`, `pbpaste`, `plutil -lint`, `otool`, `tmutil status`, `pmset -g`, `ioreg`.
- **System & Process Diagnostics:** `top`, `vm_stat`, `nettop`, `fs_usage`, `sc_usage`, `ps`, `uname`.
- **Filesystem & BSD Core:** `ls`, `cd`, `pwd`, `cat`, `grep`, `find`, `stat`, `df`, `du`.

---

### 🟡 Medium Risk (Operator Approval Required)
- **App & GUI Control:** `open`, `osascript` (AppleScript / JXA execution).
- **Disk Images & Packages:** `hdiutil` (attach/detach), `pkgutil`, `ditto`.
- **Package Management:** `brew install`, `brew upgrade`.
- **Filesystem Mutations:** `mkdir`, `cp`, `mv`, `touch`, `tar`, `zip`, `unzip`, `rsync`.

---

### 🟠 High Risk (Admin Approval + Warning Required)
- **Daemons & Services:** `launchctl` (load/unload/bootstrap).
- **Network & Firewall:** `networksetup`, `pfctl` (Packet Filter firewall).
- **Directory Services & Users:** `dscl` (Directory Service command line).
- **System Updates & Kernel:** `softwareupdate`, `kextload`, `kextunload`, `kmutil`, `nvram`, `dtrace`.
- **Permissions & Deletion:** `sudo`, `chmod`, `chown`, `chflags`, `kill`, `pkill`, `rm`.

---

### 🔴 Critical Risk (Destructive / Prohibited Anti-Patterns)
- `diskutil eraseDisk`, `diskutil partitionDisk`, `diskutil apfs deleteContainer` (APFS / Disk erasure)
- `gpt` (GUID Partition Table editor)
- `newfs_apfs`, `newfs_hfs` (Filesystem formatting)
- `dd if=/dev/zero of=/dev/rdisk*` (Raw disk zeroing)
- `asr` (Apple Software Restore block-copy overwrite)
