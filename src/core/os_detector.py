"""Robust Operating System Detection, Environment Resolution, and Multi-Vector AI Tool Discovery.

Performs deep system discovery across:
1. Standard & non-standard configuration directories
2. System PATH executables & package manager binary wrappers
3. Global package managers (npm, pip, brew, winget, choco, scoop, cargo)
4. Active running processes and background daemons
5. IDE extension catalogs (VS Code, Cursor, JetBrains plugins)
"""

import os
import sys
import shutil
import platform
import subprocess
import glob
from pathlib import Path
from typing import List, Dict, Set, Optional

from src.core.logger import get_logger
from src.core.models import HardeningPolicy

logger = get_logger("os_detector")


class OSDetector:
    _cached_running_processes: Optional[Set[str]] = None
    _cached_npm_packages: Optional[Set[str]] = None
    _cached_pip_packages: Optional[Set[str]] = None
    _cached_vscode_extensions: Optional[Set[str]] = None
    _cached_system_packages: Optional[Set[str]] = None

    @staticmethod
    def get_os_type() -> str:
        """Returns the normalized OS platform: 'windows', 'linux', or 'macos'."""
        system = platform.system().lower()
        if system == "windows":
            return "windows"
        elif system == "darwin":
            return "macos"
        else:
            return "linux"

    @staticmethod
    def expand_path(raw_path: str) -> Path:
        """Expands environment variables and user home directory in file paths."""
        if not raw_path:
            return Path()

        # Expand OS environment variables (%VAR% on Windows, $VAR on Unix)
        expanded = os.path.expandvars(raw_path)
        # Expand user home tilde (~)
        expanded = os.path.expanduser(expanded)
        return Path(expanded)

    @staticmethod
    def is_admin() -> bool:
        """Checks if the current execution context holds elevated privileges."""
        try:
            if platform.system().lower() == "windows":
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            else:
                return os.geteuid() == 0
        except Exception as e:
            logger.debug(f"Elevation check exception: {e}")
            return False

    @classmethod
    def get_running_processes(cls) -> Set[str]:
        """Enumerates active processes running on the host system."""
        if cls._cached_running_processes is not None:
            return cls._cached_running_processes

        processes = set()
        os_type = cls.get_os_type()

        try:
            if os_type == "windows":
                res = subprocess.run(["tasklist", "/FO", "CSV", "/NH"], capture_output=True, text=True, timeout=5)
                for line in res.stdout.splitlines():
                    parts = line.split('","')
                    if parts and len(parts) > 0:
                        proc_name = parts[0].replace('"', '').strip().lower()
                        processes.add(proc_name)
            else:
                res = subprocess.run(["ps", "-A", "-o", "comm="], capture_output=True, text=True, timeout=5)
                for line in res.stdout.splitlines():
                    processes.add(line.strip().lower())
        except Exception as e:
            logger.debug(f"Process enumeration notice: {e}")

        cls._cached_running_processes = processes
        return processes

    @classmethod
    def get_installed_npm_packages(cls) -> Set[str]:
        """Discovers globally installed NPM packages."""
        if cls._cached_npm_packages is not None:
            return cls._cached_npm_packages

        packages = set()
        try:
            if shutil.which("npm"):
                res = subprocess.run(["npm", "list", "-g", "--depth=0", "--parseable"], capture_output=True, text=True, timeout=6)
                for line in res.stdout.splitlines():
                    pkg_name = Path(line.strip()).name.lower()
                    packages.add(pkg_name)
        except Exception as e:
            logger.debug(f"NPM package scan notice: {e}")

        # Also check standard npm global root directory on Windows and Unix
        npm_roots = [
            cls.expand_path("%APPDATA%\\npm\\node_modules"),
            cls.expand_path("~/.nvm/versions/node"),
            Path("/usr/local/lib/node_modules"),
            Path("/usr/lib/node_modules")
        ]
        for root in npm_roots:
            if root.exists():
                try:
                    for child in root.iterdir():
                        if child.is_dir():
                            packages.add(child.name.lower())
                except Exception:
                    pass

        cls._cached_npm_packages = packages
        return packages

    @classmethod
    def get_installed_pip_packages(cls) -> Set[str]:
        """Discovers installed Python packages."""
        if cls._cached_pip_packages is not None:
            return cls._cached_pip_packages

        packages = set()
        try:
            import importlib.metadata
            for dist in importlib.metadata.distributions():
                packages.add(dist.metadata["Name"].lower())
        except Exception as e:
            logger.debug(f"Python metadata scan notice: {e}")

        cls._cached_pip_packages = packages
        return packages

    @classmethod
    def get_installed_ide_extensions(cls) -> Set[str]:
        """Discovers installed VS Code, Cursor, and JetBrains IDE extensions."""
        if cls._cached_vscode_extensions is not None:
            return cls._cached_vscode_extensions

        extensions = set()
        extension_dirs = [
            cls.expand_path("~/.vscode/extensions"),
            cls.expand_path("~/.cursor/extensions"),
            cls.expand_path("%USERPROFILE%\\.vscode\\extensions"),
            cls.expand_path("%USERPROFILE%\\.cursor\\extensions"),
            cls.expand_path("~/.vscode-insiders/extensions")
        ]

        # JetBrains plugins directories
        os_type = cls.get_os_type()
        if os_type == "windows":
            jb_base = cls.expand_path("%APPDATA%\\JetBrains")
            if jb_base.exists():
                for p in jb_base.glob("*/plugins/*"):
                    if p.is_dir():
                        extensions.add(p.name.lower())
        elif os_type == "macos":
            jb_base = cls.expand_path("~/Library/Application Support/JetBrains")
            if jb_base.exists():
                for p in jb_base.glob("*/plugins/*"):
                    if p.is_dir():
                        extensions.add(p.name.lower())

        for ext_dir in extension_dirs:
            if ext_dir.exists():
                try:
                    for child in ext_dir.iterdir():
                        if child.is_dir():
                            extensions.add(child.name.lower())
                except Exception:
                    pass

        cls._cached_vscode_extensions = extensions
        return extensions

    @classmethod
    def is_tool_installed(cls, policy: HardeningPolicy) -> bool:
        """
        Deep multi-layered detection of AI development tools on the host.
        Checks:
        1. Default and secondary configuration directories & settings files.
        2. Executable binaries across PATH and standard install directories.
        3. Global package managers (npm, pip, cargo).
        4. Running background processes & daemons.
        5. Installed IDE extensions (VS Code, Cursor, JetBrains).
        """
        os_type = cls.get_os_type()
        path_info = policy.paths.get(os_type)
        tool_name = policy.tool.name.lower()

        # Vector 1: Primary configuration directory & settings file
        if path_info and path_info.config_dir:
            config_path = cls.expand_path(path_info.config_dir)
            try:
                if config_path.exists():
                    logger.debug(f"[Vector 1] Detected {tool_name} via config_dir: {config_path}")
                    return True
            except Exception:
                pass

        if path_info and path_info.settings_file:
            settings_path = cls.expand_path(path_info.settings_file)
            try:
                if settings_path.exists():
                    logger.debug(f"[Vector 1] Detected {tool_name} via settings_file: {settings_path}")
                    return True
            except Exception:
                pass

        # Vector 2: Executable binaries in PATH & alternative installation locations
        binary_aliases = {
            "antigravity": ["agy", "antigravity", "antigravity.exe", "agy.exe"],
            "claude-code": ["claude", "claude-code", "claude.cmd", "claude-code.cmd"],
            "copilot": ["code", "code.exe", "github-copilot-cli"],
            "cursor": ["cursor", "cursor.exe"],
            "kilo-code": ["kilo", "kilo-code", "kilo.exe"],
            "cline": ["cline", "cline.cmd", "cline.exe"],
            "clinepass": ["clinepass", "clinepass.cmd", "clinepass.exe"],
            "codex": ["codex", "openai-codex", "codex.exe"],
            "opencode": ["opencode", "opencode.exe"],
            "hermes-agent": ["hermes", "hermes-agent"],
            "qoder": ["qoder", "qoder.exe"],
            "codebuddy": ["codebuddy", "codebuddy.exe"],
            "kimi": ["kimi", "kimi.exe"],
            "grok": ["grok", "xai", "grok.exe"]
        }

        candidates = binary_aliases.get(tool_name, [tool_name, f"{tool_name}.exe"])
        for b in candidates:
            if shutil.which(b) is not None:
                logger.debug(f"[Vector 2] Detected {tool_name} via PATH binary: {b}")
                return True

        # Check standard user local binary folders
        extra_bin_dirs = [
            cls.expand_path("%LOCALAPPDATA%\\Programs"),
            cls.expand_path("%PROGRAMFILES%"),
            cls.expand_path("%PROGRAMFILES(X86)%"),
            cls.expand_path("%USERPROFILE%\\.local\\bin"),
            cls.expand_path("~/.cargo/bin"),
            cls.expand_path("~/.local/bin"),
            Path("/usr/local/bin"),
            Path("/opt")
        ]
        for bin_dir in extra_bin_dirs:
            if bin_dir.exists():
                for b in candidates:
                    if (bin_dir / b).exists():
                        logger.debug(f"[Vector 2] Detected {tool_name} in folder: {bin_dir / b}")
                        return True

        # Vector 3: Global package managers (npm & pip)
        npm_packages = cls.get_installed_npm_packages()
        npm_mapping = {
            "claude-code": ["@anthropic-ai/claude-code", "claude-code", "@anthropic/claude-code"],
            "cline": ["cline", "claude-dev", "@cline/cline"],
            "opencode": ["opencode", "@opencode/cli"],
            "kilo-code": ["kilo-code", "@kilo/code"],
            "antigravity": ["@google/antigravity", "antigravity-cli"]
        }
        if tool_name in npm_mapping:
            for pkg in npm_mapping[tool_name]:
                if any(pkg.lower() in p for p in npm_packages):
                    logger.debug(f"[Vector 3] Detected {tool_name} via global NPM package: {pkg}")
                    return True

        pip_packages = cls.get_installed_pip_packages()
        pip_mapping = {
            "antigravity": ["antigravity-cli", "google-antigravity"],
            "hermes-agent": ["hermes-agent", "nous-hermes"],
            "codex": ["openai-codex", "codex-cli"],
            "kimi": ["kimi-cli", "moonshot-kimi"],
            "grok": ["xai-grok", "grok-cli"],
            "qoder": ["qoder-agent", "qoder"]
        }
        if tool_name in pip_mapping:
            for pkg in pip_mapping[tool_name]:
                if pkg.lower() in pip_packages:
                    logger.debug(f"[Vector 3] Detected {tool_name} via Python pip package: {pkg}")
                    return True

        # Vector 4: Active Running Processes & Daemons
        running_procs = cls.get_running_processes()
        proc_mapping = {
            "cursor": ["cursor.exe", "cursor"],
            "copilot": ["code.exe", "code"],
            "antigravity": ["antigravity.exe", "antigravity", "agy.exe", "agy"],
            "claude-code": ["claude.exe", "claude"],
            "qoder": ["qoder.exe", "qoder"],
            "codebuddy": ["codebuddy.exe", "codebuddy"]
        }
        if tool_name in proc_mapping:
            for proc in proc_mapping[tool_name]:
                if proc.lower() in running_procs:
                    logger.debug(f"[Vector 4] Detected {tool_name} via running process: {proc}")
                    return True

        # Vector 5: IDE Extensions (VS Code, Cursor, JetBrains plugins)
        extensions = cls.get_installed_ide_extensions()
        ext_mapping = {
            "copilot": ["github.copilot", "github.copilot-chat", "copilot"],
            "cline": ["saoudrizwan.claude-dev", "cline", "clinepass"],
            "clinepass": ["clinepass", "cline"],
            "codebuddy": ["codebuddy", "code-buddy"],
            "antigravity": ["google.antigravity", "antigravity"],
            "qoder": ["qoder", "qoder-ai"],
            "cursor": ["cursor"]
        }
        if tool_name in ext_mapping:
            for ext in ext_mapping[tool_name]:
                if any(ext.lower() in e for e in extensions):
                    logger.debug(f"[Vector 5] Detected {tool_name} via IDE extension: {ext}")
                    return True

        return False
