"""Hardening Verification & Compliance Audit Engine.

Inspects target host configuration files, agent rule directories, OS permissions,
and DLP settings to verify that hardened configurations were applied successfully and are fully functional.
"""

import json
import os
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field

from src.core.models import HardeningPolicy
from src.core.os_detector import OSDetector
from src.core.logger import get_logger, log_audit_event
from src.core.path_utils import get_app_root

logger = get_logger("verifier")


@dataclass
class CheckResult:
    key: str
    expected: Any
    actual: Any
    passed: bool
    description: str


@dataclass
class PolicyVerificationReport:
    tool_name: str
    vendor: str
    is_installed: bool
    settings_file_exists: bool
    rules_dir_exists: bool
    total_checks: int
    passed_checks: int
    failed_checks: int
    compliance_score: float
    checks: List[CheckResult] = field(default_factory=list)
    message: str = ""


class HardeningVerifier:
    """Verifies that hardening policies and security baselines are actively applied and functional."""

    def __init__(self, repo_root: Optional[Path] = None):
        self.repo_root = repo_root or get_app_root()
        self.os_type = OSDetector.get_os_type()

    @staticmethod
    def _deep_update(target: dict, source: dict) -> dict:
        """Recursively updates target dict with source dict, preserving nested dict hierarchies."""
        for k, v in source.items():
            if isinstance(v, dict) and isinstance(target.get(k), dict):
                HardeningVerifier._deep_update(target[k], v)
            else:
                target[k] = v
        return target

    def _flatten_dict(self, d: dict, parent_key: str = "") -> Dict[str, Any]:
        """Flattens a nested dictionary into dotted key paths for granular verification."""
        items: Dict[str, Any] = {}
        for k, v in d.items():
            new_key = f"{parent_key}.{k}" if parent_key else k
            if isinstance(v, dict):
                items.update(self._flatten_dict(v, new_key))
            else:
                items[new_key] = v
        return items

    def verify_policy(self, policy: HardeningPolicy, strict_mode: Optional[bool] = None) -> PolicyVerificationReport:
        """Audits a single tool policy against the host environment."""
        import copy
        tool_name = policy.tool.name
        vendor = policy.tool.vendor
        path_info = policy.paths.get(self.os_type)

        report = PolicyVerificationReport(
            tool_name=tool_name,
            vendor=vendor,
            is_installed=policy.is_installed,
            settings_file_exists=False,
            rules_dir_exists=False,
            total_checks=0,
            passed_checks=0,
            failed_checks=0,
            compliance_score=0.0
        )

        if not path_info or not path_info.settings_file:
            report.message = f"No configuration path defined for OS: {self.os_type}"
            return report

        settings_path = Path(OSDetector.expand_path(path_info.settings_file))
        rules_path = Path(OSDetector.expand_path(path_info.rules_dir)) if path_info.rules_dir else None

        all_settings_files = [settings_path] + [Path(OSDetector.expand_path(s)) for s in getattr(path_info, "secondary_settings_files", []) if s]
        existing_settings_files = [f for f in all_settings_files if f.exists()]

        report.settings_file_exists = len(existing_settings_files) > 0
        if rules_path:
            all_rules_dirs = [rules_path] + [Path(OSDetector.expand_path(r)) for r in getattr(path_info, "secondary_rules_dirs", []) if r]
            report.rules_dir_exists = any(r.exists() for r in all_rules_dirs)

        # Set initial status message
        if not report.settings_file_exists and not policy.is_installed:
            report.message = "Tool is not installed on this host."
        elif not report.settings_file_exists:
            report.message = "Configuration settings file does not exist on disk."

        current_settings: Dict[str, Any] = {}
        for s_file in existing_settings_files:
            try:
                content = s_file.read_text(encoding="utf-8")
                loaded = json.loads(content)
                self._deep_update(current_settings, loaded)
            except Exception as e:
                logger.warning(f"Could not parse settings file {s_file}: {e}")

        # Auto-detect strict mode if not explicitly provided
        is_strict = strict_mode
        if is_strict is None:
            is_strict = bool(
                current_settings.get("security.strict_mode") is True
                or self._get_nested_value(current_settings, "security.strict_mode") is True
                or self._get_nested_value(current_settings, "sandbox.network.strictAllowlist") is True
            )

        # 1. Prepare expected overrides (standard + strict if applicable)
        expected_overrides = copy.deepcopy(dict(policy.policies.get("native_settings_override", {})))
        if is_strict:
            strict_conf = policy.policies.get("strict_rules", {})
            if strict_conf and "native_overrides" in strict_conf:
                self._deep_update(expected_overrides, strict_conf["native_overrides"])
            expected_overrides["security.strict_mode"] = True
            expected_overrides["security.dangerousPaths.action"] = "block"
            expected_overrides["security.approvals.bypass_allowed"] = False
            expected_overrides["security.approvals.auto_apply_edits"] = False
            expected_overrides["security.approvals.require_write_approval"] = True

        flattened_checks = self._flatten_dict(expected_overrides)
        for key, expected_val in flattened_checks.items():
            if key == "$schema":
                continue
            actual_val = self._get_nested_value(current_settings, key)
            if isinstance(expected_val, list) and isinstance(actual_val, list):
                passed = (sorted(str(x) for x in actual_val) == sorted(str(x) for x in expected_val)) or (actual_val == expected_val)
            else:
                passed = (actual_val == expected_val)

            report.checks.append(CheckResult(
                key=key,
                expected=expected_val,
                actual=actual_val if actual_val is not None else "[MISSING]",
                passed=passed,
                description=f"Configuration key '{key}' matches hardened baseline"
            ))

        # 2. Verify Rules Directory and rule file deployment
        if rules_path:
            rule_file_exists = False
            if rules_path.exists():
                for rf in [f"{self.os_type}_security_policy.md", "linux_command_risk_policy.md", "windows_security_policy.md", "macos_security_policy.md"]:
                    if (rules_path / rf).exists():
                        rule_file_exists = True
                        break

            report.checks.append(CheckResult(
                key="security_rules_deployed",
                expected=True,
                actual=rule_file_exists,
                passed=rule_file_exists,
                description=f"Agent security rules file deployed in {rules_path}"
            ))

        # 3. Verify Environment Telemetry Protection
        native_telemetry_disabled = False
        for tk in ("telemetry.enabled", "disableTelemetry", "telemetry", "analytics.enabled", "privacy.telemetry", "telemetryEnabled"):
            if tk in expected_overrides:
                val = self._get_nested_value(current_settings, tk)
                if val == expected_overrides[tk]:
                    native_telemetry_disabled = True
                    break

        env_dnt = os.environ.get("DO_NOT_TRACK") == "1" or os.environ.get("CLAUDE_TELEMETRY_DISABLED") == "1"
        telemetry_protected = env_dnt or native_telemetry_disabled
        report.checks.append(CheckResult(
            key="env_do_not_track",
            expected=True,
            actual=telemetry_protected,
            passed=telemetry_protected,
            description="Environment and settings telemetry lockdown active"
        ))

        # Calculate score
        report.total_checks = len(report.checks)
        report.passed_checks = sum(1 for c in report.checks if c.passed)
        report.failed_checks = report.total_checks - report.passed_checks
        report.compliance_score = (report.passed_checks / report.total_checks * 100.0) if report.total_checks > 0 else 0.0

        mode_desc = " [STRICT MODE]" if is_strict else " [STANDARD MODE]"
        if report.compliance_score == 100.0:
            report.message = f"100% Compliant{mode_desc}: All {report.total_checks} security checks passed."
        elif report.compliance_score >= 80.0:
            report.message = f"Partially Compliant ({report.compliance_score:.1f}%){mode_desc}: {report.failed_checks} check(s) need remediation."
        else:
            report.message = f"Non-Compliant ({report.compliance_score:.1f}%){mode_desc}: {report.failed_checks} check(s) failed."

        log_audit_event(
            event_type="POLICY_VERIFICATION",
            tool_name=tool_name,
            vendor=vendor,
            status="SUCCESS" if report.compliance_score == 100.0 else "WARNING",
            details={
                "compliance_score": report.compliance_score,
                "passed_checks": report.passed_checks,
                "failed_checks": report.failed_checks,
                "total_checks": report.total_checks,
                "strict_mode": is_strict
            }
        )

        return report

    def remediate_policy(self, policy: HardeningPolicy, strict_mode: bool = False) -> Any:
        """Automatically remediates all non-compliant configuration keys, rules, and telemetry settings."""
        from src.core.engine import HardeningEngine
        engine = HardeningEngine(self.repo_root)
        os.environ["DO_NOT_TRACK"] = "1"
        os.environ["CLAUDE_TELEMETRY_DISABLED"] = "1"
        return engine.apply_policy(policy, dry_run=False, strict_mode=strict_mode)

    def _get_nested_value(self, data: Dict[str, Any], path: str) -> Any:
        """Retrieves value by direct key or dotted path notation."""
        if path in data:
            return data[path]

        keys = path.split(".")
        current = data
        for k in keys:
            if isinstance(current, dict) and k in current:
                current = current[k]
            else:
                return None
        return current
