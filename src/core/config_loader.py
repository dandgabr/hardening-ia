"""Configuration loader and schema validator for declarative YAML policies."""

from pathlib import Path
from typing import Dict, List, Optional
import yaml

from src.core.models import HardeningPolicy, ToolMeta, OSPaths
from src.core.os_detector import OSDetector
from src.core.logger import get_logger

logger = get_logger("config_loader")


class ConfigLoader:
    def __init__(self, configs_root: Optional[Path] = None):
        if configs_root is None:
            self.configs_root = Path(__file__).resolve().parent.parent.parent / "configs" / "tools"
        else:
            self.configs_root = configs_root

    def discover_policies(self) -> List[HardeningPolicy]:
        """Discovers, parses, and returns all policy YAML files in configs/tools/."""
        policies: List[HardeningPolicy] = []
        if not self.configs_root.exists():
            logger.warning(f"Configs root directory does not exist: {self.configs_root}")
            return policies

        yaml_files = list(self.configs_root.glob("**/*.yaml"))
        logger.debug(f"Found {len(yaml_files)} YAML policy files in {self.configs_root}")

        for yaml_path in yaml_files:
            policy = self.load_policy(yaml_path)
            if policy:
                # Detect if the tool is installed on the host
                installed = OSDetector.is_tool_installed(policy)
                policy.is_installed = installed
                policy.tool.is_installed = installed
                policies.append(policy)

        installed_count = sum(1 for p in policies if p.is_installed)
        logger.info(f"Loaded {len(policies)} policies ({installed_count} tools installed on host).")
        return policies

    def load_policy(self, yaml_path: Path) -> Optional[HardeningPolicy]:
        """Loads and validates a single YAML policy specification."""
        try:
            with open(yaml_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)

            if not data or "tool" not in data:
                logger.warning(f"Skipping invalid policy (missing 'tool' section): {yaml_path}")
                return None

            tool_data = data.get("tool", {})
            tool = ToolMeta(
                name=tool_data.get("name", ""),
                vendor=tool_data.get("vendor", ""),
                category=tool_data.get("category", "cli"),
                description=tool_data.get("description", "")
            )

            paths_data = data.get("paths", {})
            paths: Dict[str, OSPaths] = {}
            for os_key, os_val in paths_data.items():
                if isinstance(os_val, dict):
                    paths[os_key] = OSPaths(
                        config_dir=os_val.get("config_dir", ""),
                        settings_file=os_val.get("settings_file", ""),
                        rules_dir=os_val.get("rules_dir", ""),
                        secondary_settings_files=os_val.get("secondary_settings_files", []),
                        secondary_rules_dirs=os_val.get("secondary_rules_dirs", [])
                    )

            policy = HardeningPolicy(
                schema_version=data.get("schema_version", "1.0"),
                tool=tool,
                paths=paths,
                policies=data.get("policies", {}),
                custom_scripts=data.get("custom_scripts", {})
            )
            return policy
        except Exception as e:
            logger.error(f"Error parsing policy file {yaml_path}: {e}")
            return None

    def get_policy(self, vendor: str, name: str) -> Optional[HardeningPolicy]:
        """Retrieves a specific policy by vendor and tool name, supporting tool aliases."""
        alias_map = {
            "zai-cli": ("zai", "zai"),
            "zcode": ("zai", "zai"),
            "z-ai": ("zai", "zai"),
            "claude": ("anthropic", "claude-code"),
            "kilo": ("kilo", "kilo-code"),
            "hermes": ("nousresearch", "hermes-agent")
        }
        if name.lower() in alias_map:
            vendor, name = alias_map[name.lower()]
        elif vendor.lower() in alias_map:
            vendor, name = alias_map[vendor.lower()]

        target_path = self.configs_root / vendor.lower() / name.lower() / "hardening_policy.yaml"
        if target_path.exists():
            return self.load_policy(target_path)
        for p in self.discover_policies():
            if p.tool.vendor.lower() == vendor.lower() and p.tool.name.lower() == name.lower():
                return p
        return None

