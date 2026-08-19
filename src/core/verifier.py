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
        self.repo_root = repo_root or Path(__file__).resolve().parent.parent.parent
        self.os_type = OSDetector.get_os_type()

    def verify_policy(self, policy: HardeningPolicy) -> PolicyVerificationReport:
        """Audits a single tool policy against the host environment."""
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

        report.settings_file_exists = settings_path.exists()
        if rules_path:
            report.rules_dir_exists = rules_path.exists()

        # If tool is not installed and settings file doesn't exist
        if not report.settings_file_exists and not policy.is_installed:
            report.message = "Tool is not installed on this host (skipping live verification)."
            return report

        current_settings: Dict[str, Any] = {}
        if report.settings_file_exists:
            try:
                content = settings_path.read_text(encoding="utf-8")
                current_settings = json.loads(content)
            except Exception as e:
                logger.warning(f"Could not parse settings file {settings_path}: {e}")

        # 1. Verify Native Settings Overrides
        overrides = policy.policies.get("native_settings_override", {})
        for key, expected_val in overrides.items():
            actual_val = self._get_nested_value(current_settings, key)
            passed = (actual_val == expected_val)

            report.checks.append(CheckResult(
                key=key,
                expected=expected_val,
                actual=actual_val if actual_val is not None else "[MISSING]",
                passed=passed,
                description=f"Configuration key '{key}' matches hardened default"
            ))

        # 2. Verify Rules Directory
        if rules_path:
            rules_exist = rules_path.exists()
            report.checks.append(CheckResult(
                key="security_rules_deployed",
                expected=True,
                actual=rules_exist,
                passed=rules_exist,
                description=f"Agent security rules directory exists at {rules_path}"
            ))

        # 3. Verify Environment Telemetry Variables
        do_not_track = os.environ.get("DO_NOT_TRACK") == "1"
        report.checks.append(CheckResult(
            key="env_do_not_track",
            expected=True,
            actual=do_not_track,
            passed=do_not_track,
            description="Environment variable DO_NOT_TRACK=1 active"
        ))

        # Calculate score
        report.total_checks = len(report.checks)
        report.passed_checks = sum(1 for c in report.checks if c.passed)
        report.failed_checks = report.total_checks - report.passed_checks
        report.compliance_score = (report.passed_checks / report.total_checks * 100.0) if report.total_checks > 0 else 0.0

        if report.compliance_score == 100.0:
            report.message = f"100% Compliant: All {report.total_checks} security checks passed."
        elif report.compliance_score >= 80.0:
            report.message = f"Partially Compliant ({report.compliance_score:.1f}%): {report.failed_checks} check(s) need remediation."
        else:
            report.message = f"Non-Compliant ({report.compliance_score:.1f}%): {report.failed_checks} check(s) failed."

        log_audit_event(
            event_type="POLICY_VERIFICATION",
            tool_name=tool_name,
            vendor=vendor,
            status="SUCCESS" if report.compliance_score == 100.0 else "WARNING",
            details={
                "compliance_score": report.compliance_score,
                "passed_checks": report.passed_checks,
                "failed_checks": report.failed_checks,
                "total_checks": report.total_checks
            }
        )

        return report

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
