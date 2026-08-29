"""Path resolution utilities supporting standard Python source execution and PyInstaller frozen bundles."""

import sys
from pathlib import Path


def get_app_root() -> Path:
    """Returns the application root directory.
    
    When running as a PyInstaller frozen binary, returns the extracted runtime path (sys._MEIPASS).
    When running from source, returns the project root directory.
    """
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return Path(sys._MEIPASS)
    # Relative to this file: src/core/path_utils.py -> parent.parent.parent is project root
    return Path(__file__).resolve().parent.parent.parent


def get_configs_dir() -> Path:
    """Returns the root path for configuration files and policies."""
    return get_app_root() / "configs"


def get_tools_configs_dir() -> Path:
    """Returns the root path for declarative tool policy YAMLs."""
    return get_configs_dir() / "tools"


def get_rules_configs_dir() -> Path:
    """Returns the root path for base security policy markdown templates."""
    return get_configs_dir() / "rules"


def get_scripts_dir() -> Path:
    """Returns the root path for bundled OS helper scripts and extra tools."""
    return get_app_root() / "scripts"
