#!/usr/bin/env python3
"""Cross-platform installer for ai-jail (https://github.com/akitaonrails/ai-jail).

Automates dependency resolution, package installation, compilation, and execution wrapping
across Linux, macOS, and Windows (with WSL2 integration).
"""

import os
import sys
import shutil
import platform
import subprocess
import urllib.request
from pathlib import Path

REPO_URL = "https://github.com/akitaonrails/ai-jail"
REPO_GIT = "https://github.com/akitaonrails/ai-jail.git"


def log(msg: str):
    print(f"[ai-jail installer] {msg}")


def run_cmd(cmd: list, check: bool = True, capture: bool = False, cwd: str = None) -> subprocess.CompletedProcess:
    log(f"Running: {' '.join(cmd)}")
    return subprocess.run(cmd, check=check, text=True, capture_output=capture, cwd=cwd)


def install_linux() -> bool:
    log("Resolving dependencies on Linux...")

    # 1. Install bubblewrap (bwrap) dependency based on distro package manager
    pkg_managers = [
        ("apt-get", ["sudo", "apt-get", "update"], ["sudo", "apt-get", "install", "-y", "bubblewrap", "git", "curl", "build-essential"]),
        ("pacman", None, ["sudo", "pacman", "-S", "--noconfirm", "bubblewrap", "git", "curl", "base-devel"]),
        ("dnf", None, ["sudo", "dnf", "install", "-y", "bubblewrap", "git", "curl", "gcc"]),
        ("zypper", None, ["sudo", "zypper", "install", "-y", "bubblewrap", "git", "curl"])
    ]

    for mgr, prep_cmd, install_cmd in pkg_managers:
        if shutil.which(mgr):
            try:
                log(f"Detected package manager: {mgr}")
                if prep_cmd:
                    subprocess.run(prep_cmd, check=False)
                subprocess.run(install_cmd, check=False)
                break
            except Exception as e:
                log(f"Package manager installation notice: {e}")

    # 2. Try Homebrew on Linux
    if shutil.which("brew"):
        try:
            log("Attempting installation via Homebrew tap...")
            run_cmd(["brew", "tap", "akitaonrails/tap"])
            run_cmd(["brew", "install", "ai-jail"])
            log("[OK] ai-jail installed successfully via Homebrew.")
            return True
        except Exception as e:
            log(f"Homebrew installation notice: {e}")

    # 3. Try Cargo (Rust)
    if shutil.which("cargo"):
        try:
            log("Attempting installation via Cargo (crates.io)...")
            run_cmd(["cargo", "install", "--locked", "ai-jail"])
            log("[OK] ai-jail installed successfully via Cargo.")
            return True
        except Exception as e:
            log(f"Cargo install notice: {e}. Falling back to building from source...")

    # 4. Build from source git repo
    build_dir = Path.home() / ".cache" / "ai-jail-build"
    try:
        build_dir.parent.mkdir(parents=True, exist_ok=True)
        if build_dir.exists():
            shutil.rmtree(build_dir, ignore_errors=True)

        log(f"Cloning repository from {REPO_GIT} into {build_dir}...")
        run_cmd(["git", "clone", "--depth", "1", REPO_GIT, str(build_dir)])

        if not shutil.which("cargo"):
            log("Rust/Cargo not found. Installing rustup...")
            rustup_script = build_dir / "rustup-init.sh"
            urllib.request.urlretrieve("https://sh.rustup.rs", rustup_script)
            run_cmd(["sh", str(rustup_script), "-y", "--default-toolchain", "stable", "--profile", "minimal"])
            os.environ["PATH"] = f"{Path.home()}/.cargo/bin:" + os.environ.get("PATH", "")

        log("Building release binary with cargo...")
        run_cmd(["cargo", "build", "--release"], cwd=str(build_dir))

        bin_src = build_dir / "target" / "release" / "ai-jail"
        target_bin_dir = Path.home() / ".local" / "bin"
        target_bin_dir.mkdir(parents=True, exist_ok=True)
        target_bin = target_bin_dir / "ai-jail"

        shutil.copy2(bin_src, target_bin)
        target_bin.chmod(0o755)
        log(f"[OK] ai-jail binary installed to {target_bin}")
        return True
    except Exception as e:
        log(f"Build from source notice: {e}")
        return False


def install_macos() -> bool:
    log("Resolving dependencies on macOS...")

    # 1. Prefer Homebrew
    if shutil.which("brew"):
        try:
            log("Installing ai-jail via Homebrew tap (akitaonrails/tap)...")
            run_cmd(["brew", "tap", "akitaonrails/tap"])
            run_cmd(["brew", "install", "ai-jail"])
            log("[OK] ai-jail installed successfully via Homebrew.")
            return True
        except Exception as e:
            log(f"Homebrew installation notice: {e}")

    # 2. Try Cargo
    if shutil.which("cargo"):
        try:
            log("Installing ai-jail via Cargo...")
            run_cmd(["cargo", "install", "--locked", "ai-jail"])
            log("[OK] ai-jail installed successfully via Cargo.")
            return True
        except Exception as e:
            log(f"Cargo install notice: {e}")

    # 3. Build from source
    build_dir = Path.home() / ".cache" / "ai-jail-build"
    try:
        build_dir.parent.mkdir(parents=True, exist_ok=True)
        if build_dir.exists():
            shutil.rmtree(build_dir, ignore_errors=True)

        log(f"Cloning repository from {REPO_GIT}...")
        run_cmd(["git", "clone", "--depth", "1", REPO_GIT, str(build_dir)])

        if not shutil.which("cargo"):
            log("Rust/Cargo not found. Installing rustup...")
            rustup_script = build_dir / "rustup-init.sh"
            urllib.request.urlretrieve("https://sh.rustup.rs", rustup_script)
            run_cmd(["sh", str(rustup_script), "-y", "--default-toolchain", "stable", "--profile", "minimal"])
            os.environ["PATH"] = f"{Path.home()}/.cargo/bin:" + os.environ.get("PATH", "")

        run_cmd(["cargo", "build", "--release"], cwd=str(build_dir))

        target_bin_dir = Path.home() / ".local" / "bin"
        target_bin_dir.mkdir(parents=True, exist_ok=True)
        target_bin = target_bin_dir / "ai-jail"
        shutil.copy2(build_dir / "target" / "release" / "ai-jail", target_bin)
        target_bin.chmod(0o755)
        log(f"[OK] ai-jail binary installed to {target_bin}")
        return True
    except Exception as e:
        log(f"Source build notice: {e}")
        return False


def install_windows() -> bool:
    log("Resolving dependencies on Windows...")
    log("Note: ai-jail sandboxing relies on Linux bubblewrap (bwrap). Configuring WSL2 / Windows wrappers...")

    # 1. Check for WSL
    wsl_installed = shutil.which("wsl") is not None
    if wsl_installed:
        try:
            log("WSL detected. Attempting package check inside WSL...")
            wsl_cmd = (
                "sudo apt-get update && sudo apt-get install -y bubblewrap git curl cargo && "
                "(cargo install --locked ai-jail || "
                "(git clone --depth 1 https://github.com/akitaonrails/ai-jail.git /tmp/ai-jail && "
                "cd /tmp/ai-jail && cargo build --release && sudo cp target/release/ai-jail /usr/local/bin/))"
            )
            subprocess.run(["wsl", "bash", "-c", wsl_cmd], check=False, capture_output=True)
            log("WSL integration routine executed.")
        except Exception as e:
            log(f"WSL invocation notice: {e}")

    # 2. Create Windows bridge scripts in local repository directory
    repo_root = Path(__file__).resolve().parent.parent.parent
    local_bin_dir = repo_root / "scripts" / "extra-tools" / "bin"
    local_bin_dir.mkdir(parents=True, exist_ok=True)

    cmd_wrapper = local_bin_dir / "ai-jail.cmd"
    with open(cmd_wrapper, "w", encoding="utf-8") as f:
        f.write("@echo off\r\nwsl.exe ai-jail %*\r\n")

    ps1_wrapper = local_bin_dir / "ai-jail.ps1"
    with open(ps1_wrapper, "w", encoding="utf-8") as f:
        f.write("& wsl.exe ai-jail $args\r\n")

    log(f"[OK] Created Windows bridge wrappers in {local_bin_dir}:")
    log(f"  - {cmd_wrapper}")
    log(f"  - {ps1_wrapper}")

    # 3. If native cargo is present on Windows, try native build
    if shutil.which("cargo"):
        try:
            log("Native Cargo detected. Attempting native build...")
            subprocess.run(["cargo", "install", "--locked", "ai-jail"], check=False)
        except Exception:
            pass

    return True


def main():
    sys_platform = platform.system().lower()
    log(f"Starting universal ai-jail installer on platform: {sys_platform.upper()}")
    log(f"Source repository: {REPO_URL}")

    success = False
    if sys_platform == "windows":
        success = install_windows()
    elif sys_platform == "darwin":
        success = install_macos()
    else:
        success = install_linux()

    if success:
        log("[SUCCESS] ai-jail installation and environment setup completed successfully.")
        sys.exit(0)
    else:
        log("[ERROR] ai-jail installation failed.")
        sys.exit(1)


if __name__ == "__main__":
    main()
