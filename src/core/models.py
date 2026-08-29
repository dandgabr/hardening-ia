"""Data models and policy definitions for the Hardening IA framework."""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any


@dataclass
class ToolMeta:
    name: str
    vendor: str
    category: str  # cli | ide | agentic
    description: str = ""
    is_installed: bool = False


@dataclass
class OSPaths:
    config_dir: str = ""
    settings_file: str = ""
    rules_dir: str = ""
    secondary_settings_files: List[str] = field(default_factory=list)
    secondary_rules_dirs: List[str] = field(default_factory=list)


@dataclass
class HardeningPolicy:
    schema_version: str
    tool: ToolMeta
    paths: Dict[str, OSPaths]
    policies: Dict[str, Any]
    custom_scripts: Dict[str, str] = field(default_factory=dict)
    is_installed: bool = False


@dataclass
class SettingDiff:
    key: str
    old_value: Any
    new_value: Any


@dataclass
class ExecutionResult:
    tool_name: str
    vendor: str
    success: bool
    message: str
    modified_paths: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    diffs: List[SettingDiff] = field(default_factory=list)
