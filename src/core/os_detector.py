"""Operating system detection, path normalization, and installed AI tools discovery."""

import os
import shutil
import platform
from pathlib import Path
from typing import List, Dict

from src.core.logger import get_logger
from src.core.models import HardeningPolicy

logger = get_logger("os_detector")


class OSDetector:
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
    def is_tool_installed(cls, policy: HardeningPolicy) -> bool:
        """
        Dynamically detects if a target AI development tool is installed on the host.
        Checks both filesystem configuration markers and system PATH executables.
        """
        os_type = cls.get_os_type()
        path_info = policy.paths.get(os_type)

        # 1. Check configuration directory existence
        if path_info and path_info.config_dir:
            config_path = cls.expand_path(path_info.config_dir)
            try:
                if config_path.exists():
                    logger.debug(f"Detected tool {policy.tool.name} via config_dir: {config_path}")
                    return True
            except Exception:
                pass

        # 2. Check settings file existence
        if path_info and path_info.settings_file:
            settings_path = cls.expand_path(path_info.settings_file)
            try:
                if settings_path.exists():
                    logger.debug(f"Detected tool {policy.tool.name} via settings_file: {settings_path}")
                    return True
            except Exception:
                pass

        # 3. Check CLI binary name in PATH
        possible_binaries = [
            policy.tool.name,
            policy.tool.name.replace("-", ""),
            f"{policy.tool.name}.exe" if os_type == "windows" else policy.tool.name
        ]
        
        # Specific tool binary aliases
        binary_aliases = {
            "antigravity": ["agy", "antigravity"],
            "claude-code": ["claude", "claude-code"],
            "copilot": ["code", "github-copilot-cli"],
            "cursor": ["cursor"],
            "kilo-code": ["kilo", "kilo-code"],
            "cline": ["cline"],
            "codex": ["codex"],
            "opencode": ["opencode"],
            "grok": ["grok", "xai"]
        }
        if policy.tool.name in binary_aliases:
            possible_binaries.extend(binary_aliases[policy.tool.name])

        for b in possible_binaries:
            if shutil.which(b) is not None:
                logger.debug(f"Detected tool {policy.tool.name} via executable binary: {b}")
                return True

        return False
