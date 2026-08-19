"""Hardening Engine orchestrating policy enforcement, deep configuration merging, rules deployment, and script execution."""

import json
import shutil
import subprocess
from pathlib import Path
from typing import List, Dict, Any, Optional

from src.core.models import HardeningPolicy, ExecutionResult, SettingDiff
from src.core.os_detector import OSDetector
from src.core.logger import get_logger, log_audit_event

logger = get_logger("engine")


class HardeningEngine:
    def __init__(self, repo_root: Optional[Path] = None):
        self.repo_root = repo_root or Path(__file__).resolve().parent.parent.parent
        self.os_type = OSDetector.get_os_type()

    def apply_policy(self, policy: HardeningPolicy, dry_run: bool = False) -> ExecutionResult:
        """Applies hardening policy controls for a target tool according to its YAML definition."""
        tool_name = policy.tool.name
        vendor = policy.tool.vendor
        modified_paths: List[str] = []
        errors: List[str] = []
        diffs: List[SettingDiff] = []

        logger.info(f"Starting policy application for {vendor}/{tool_name} (dry_run={dry_run})")

        try:
            # 1. Resolve configuration file paths for active OS
            os_paths = policy.paths.get(self.os_type)
            if os_paths:
                if os_paths.settings_file:
                    settings_path = OSDetector.expand_path(os_paths.settings_file)
                    native_overrides = policy.policies.get("native_settings_override", {})

                    if native_overrides:
                        tool_diffs = self._apply_json_settings(settings_path, native_overrides, dry_run)
                        diffs.extend(tool_diffs)
                        modified_paths.append(str(settings_path))
                        logger.info(f"Applied {len(tool_diffs)} configuration overrides to {settings_path}")

                # 2. Deploy Command Execution Policy into agent rules directory if configured
                if os_paths.rules_dir:
                    rules_path = OSDetector.expand_path(os_paths.rules_dir)
                    policy_src = self.repo_root / "configs" / "rules" / "linux_command_risk_policy.md"
                    if policy_src.exists():
                        target_rule_file = rules_path / "linux_command_risk_policy.md"
                        if not dry_run:
                            rules_path.mkdir(parents=True, exist_ok=True)
                            shutil.copy2(policy_src, target_rule_file)
                            logger.info(f"Deployed command risk policy rule to {target_rule_file}")
                        modified_paths.append(str(target_rule_file))

            # 3. Locate YAML policy file path
            yaml_policy_path = self.repo_root / "configs" / "tools" / vendor / tool_name / "hardening_policy.yaml"

            # 4. Execute custom OS hardening script with policy path
            script_rel_path = policy.custom_scripts.get(self.os_type)
            if script_rel_path:
                script_full_path = self.repo_root / script_rel_path
                if script_full_path.exists():
                    self._run_os_script(script_full_path, yaml_policy_path, tool_name, vendor, dry_run)
                else:
                    logger.warning(f"Configured script not found on disk: {script_full_path}")

            message = f"Hardening successfully applied to {vendor}/{tool_name}"
            log_audit_event(
                event_type="POLICY_APPLIED",
                tool_name=tool_name,
                vendor=vendor,
                status="SUCCESS",
                details={
                    "dry_run": dry_run,
                    "os": self.os_type,
                    "modified_paths": modified_paths,
                    "changes_count": len(diffs)
                }
            )

            return ExecutionResult(
                tool_name=tool_name,
                vendor=vendor,
                success=True,
                message=message,
                modified_paths=modified_paths,
                errors=errors,
                diffs=diffs
            )

        except Exception as e:
            error_msg = f"Failed to apply hardening for {vendor}/{tool_name}: {str(e)}"
            logger.error(error_msg, exc_info=True)
            errors.append(str(e))

            log_audit_event(
                event_type="POLICY_APPLIED",
                tool_name=tool_name,
                vendor=vendor,
                status="FAILURE",
                details={"error": str(e), "os": self.os_type}
            )

            return ExecutionResult(
                tool_name=tool_name,
                vendor=vendor,
                success=False,
                message=error_msg,
                modified_paths=modified_paths,
                errors=errors,
                diffs=diffs
            )

    def _deep_merge(self, base: Dict[str, Any], updates: Dict[str, Any], prefix: str = "") -> List[SettingDiff]:
        """Deeply merges updates into base dictionary while tracking individual setting diffs."""
        diffs: List[SettingDiff] = []
        for key, value in updates.items():
            full_key = f"{prefix}.{key}" if prefix else key
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                diffs.extend(self._deep_merge(base[key], value, full_key))
            else:
                old_val = base.get(key)
                if old_val != value:
                    diffs.append(SettingDiff(key=full_key, old_value=old_val, new_value=value))
                base[key] = value
        return diffs

    def _apply_json_settings(self, path: Path, overrides: dict, dry_run: bool) -> List[SettingDiff]:
        """Loads target JSON configuration, merges overrides, and saves state if not dry-run."""
        current_data: Dict[str, Any] = {}
        if path.exists():
            try:
                with open(path, "r", encoding="utf-8") as f:
                    current_data = json.load(f)
            except Exception as e:
                logger.warning(f"Could not parse existing settings at {path}: {e}. Creating new file.")
                current_data = {}

        diffs = self._deep_merge(current_data, overrides)

        if not dry_run and diffs:
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                json.dump(current_data, f, indent=2, ensure_ascii=False)
            logger.debug(f"Wrote updated configuration file to {path}")

        return diffs

    def _run_os_script(self, script_path: Path, policy_path: Path, tool_name: str, vendor: str, dry_run: bool):
        """Executes native OS automation script, passing the tool's YAML policy definition."""
        logger.info(f"Executing OS script: {script_path.name} with policy {policy_path.name}")
        dry_run_flag = "$true" if (self.os_type == "windows" and dry_run) else ("true" if dry_run else "false")

        if self.os_type == "windows":
            cmd = [
                "powershell",
                "-NoProfile",
                "-ExecutionPolicy", "Bypass",
                "-File", str(script_path),
                "-PolicyFile", str(policy_path),
                "-ToolName", tool_name,
                "-Vendor", vendor
            ]
            if dry_run:
                cmd.append("-DryRun")
        else:
            cmd = ["bash", str(script_path), str(policy_path), dry_run_flag]

        process = subprocess.run(cmd, capture_output=True, text=True)

        if process.stdout:
            for line in process.stdout.splitlines():
                logger.info(f"[{script_path.name}] {line}")

        if process.returncode != 0:
            if process.stderr:
                for line in process.stderr.splitlines():
                    logger.error(f"[{script_path.name}] {line}")
            raise RuntimeError(f"Script {script_path.name} failed with exit code {process.returncode}")

    def install_extra_tool(self, tool_id: str) -> bool:
        """Runs security extra tool installation automation script."""
        extra_dir = self.repo_root / "scripts" / "extra-tools" / self.os_type
        logger.info(f"Triggering extra tool installation: {tool_id} on {self.os_type}")

        if self.os_type == "windows":
            script = extra_dir / f"install-{tool_id}.ps1"
            if script.exists():
                cmd = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script)]
                process = subprocess.run(cmd, capture_output=True, text=True)
                for line in process.stdout.splitlines():
                    logger.info(f"[install-{tool_id}] {line}")
                return process.returncode == 0
        else:
            script = extra_dir / f"install-{tool_id}.sh"
            if script.exists():
                cmd = ["bash", str(script)]
                process = subprocess.run(cmd, capture_output=True, text=True)
                for line in process.stdout.splitlines():
                    logger.info(f"[install-{tool_id}] {line}")
                return process.returncode == 0

        logger.warning(f"No installation script found for {tool_id} on {self.os_type}")
        return False
