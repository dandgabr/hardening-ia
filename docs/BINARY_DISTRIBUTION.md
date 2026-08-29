# 📦 Standalone Native Binary Distribution & Zero-Python Execution Guide

The **Hardening IA Framework** provides pre-compiled, self-contained standalone executable binaries for **Linux (x86_64)**, **Windows (x64)**, and **macOS (Universal / Apple Silicon & Intel)**.

These binaries bundle the complete application, runtime dependencies, declarative policies (all 21 AI tools), templates, and security engines into a single native binary, allowing you to run the framework on any machine **without requiring Python or pip installed**.

---

## 📑 Table of Contents

1. [Downloading Pre-Compiled Binaries](#1-downloading-pre-compiled-binaries)
2. [Quick-Start by Operating System](#2-quick-start-by-operating-system)
   - [Linux (ELF 64-bit)](#linux-elf-64-bit)
   - [Windows (PE32+ Executable)](#windows-pe32-executable)
   - [macOS (Mach-O Universal)](#macos-mach-o-universal)
3. [Verifying Release Checksums](#3-verifying-release-checksums)
4. [Local Binary Compilation](#4-local-binary-compilation)
5. [Automating Releases with GitHub Actions](#5-automating-releases-with-github-actions)

---

## 1. Downloading Pre-Compiled Binaries

Official releases and checksum files are published on the GitHub repository's **Releases** page:

| Platform | Binary Format | Release Archive Asset | Minimum Requirements |
| :--- | :--- | :--- | :--- |
| **Linux** | ELF 64-bit LSB | `hardening-ia-linux-x86_64.tar.gz` | Ubuntu 20.04+, Debian 11+, RHEL/CentOS 8+, Fedora 36+, Arch Linux |
| **Windows** | PE32+ Executable (`.exe`) | `hardening-ia-windows-x64.zip` | Windows 10, Windows 11, Windows Server 2019+ (64-bit) |
| **macOS** | Mach-O 64-bit Universal | `hardening-ia-macos-universal.tar.gz` | macOS 12 (Monterey) or later (Apple Silicon M1/M2/M3 & Intel) |

---

## 2. Quick-Start by Operating System

### Linux (ELF 64-bit)

1. Download and extract the archive:
   ```bash
   tar -xzf hardening-ia-linux-x86_64.tar.gz
   cd hardening-ia-linux-x86_64
   chmod +x hardening-ia
   ```

2. Run the interactive Terminal User Interface (TUI):
   ```bash
   ./hardening-ia
   ```

3. Or run automated CLI commands directly:
   ```bash
   # List installed tools and check security status
   ./hardening-ia --list

   # Apply hardening to all detected tools
   ./hardening-ia --apply --installed-only

   # Revert / clean hardening from all tools
   ./hardening-ia --remove-all
   ```

---

### Windows (PE32+ Executable)

1. Download and extract `hardening-ia-windows-x64.zip`.
2. Open PowerShell or Command Prompt in the extracted folder.
3. Launch the full-screen TUI interface:
   ```powershell
   .\hardening-ia.exe
   ```
4. Or run headless CLI automation:
   ```powershell
   .\hardening-ia.exe --apply --installed-only --strict
   .\hardening-ia.exe --verify --fix
   ```

---

### macOS (Mach-O Universal)

1. Download and extract the archive:
   ```bash
   tar -xzf hardening-ia-macos-universal.tar.gz
   cd hardening-ia-macos-universal
   chmod +x hardening-ia
   ```

2. If macOS Gatekeeper marks the binary as downloaded from the internet, allow execution:
   ```bash
   xattr -d com.apple.quarantine hardening-ia 2>/dev/null || true
   ```

3. Launch the application:
   ```bash
   ./hardening-ia
   ```

---

## 3. Verifying Release Checksums

Every GitHub Release includes a `SHA256SUMS.txt` file containing cryptographic hashes.

### Linux / macOS:
```bash
sha256sum -c SHA256SUMS.txt --ignore-missing
# or on macOS:
shasum -a 256 -c SHA256SUMS.txt
```

### Windows (PowerShell):
```powershell
Get-FileHash .\hardening-ia-windows-x64.zip -Algorithm SHA256
```

---

## 4. Local Binary Compilation

You can compile standalone binaries locally using the provided build scripts:

### On Linux / macOS:
```bash
./scripts/build/build_binary.sh
```
This script runs the 64-test validation suite, invokes PyInstaller with `hardening-ia.spec`, tests the binary, and produces `dist/hardening-ia-<os>-<arch>.tar.gz`.

### On Windows:
```powershell
.\scripts\build\build_binary.ps1
```
Produces `dist\hardening-ia-windows-x64.zip`.

---

## 5. Automating Releases with GitHub Actions

The repository includes an automated multi-platform CI/CD release workflow (`.github/workflows/release.yml`).

### How to trigger a new release:
1. Ensure your local branch is clean and all tests pass:
   ```bash
   python main.py --test
   ```
2. Create and push a semantic version tag:
   ```bash
   git tag v1.0.0
   git push origin v1.0.0
   ```
3. GitHub Actions will automatically:
   - Run the matrix build across Ubuntu, Windows, and macOS.
   - Execute the test suite on every OS.
   - Package all standalone binaries with licenses and documentation.
   - Generate `SHA256SUMS.txt`.
   - Publish a new release under **GitHub Releases** with release notes.
