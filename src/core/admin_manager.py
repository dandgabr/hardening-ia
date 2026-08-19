"""Enterprise Administrator System-Wide Hardening & Read-Only Policy Enforcer.

Allows system administrators to enforce hardening baselines across all user profiles
on the host system, locking configuration files with Read-Only permissions so standard
users can execute their AI tools but cannot tamper with or bypass security policies.
"""

import os
import sys
import json
import stat
import shutil
import platform
import subprocess
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

from src.core.models import HardeningPolicy, ExecutionResult, SettingDiff
from src.core.os_detector import OSDetector
from src.core.logger import get_logger, log_audit_event
from src.core.security_policy import SecurityPolicyManager

logger = get_logger("admin_manager")


class AdminManager:
    """Manages system-wide policy enforcement, admin elevation verification, and file permission locking."""

    def __init__(self, repo_root: Optional[Path] = None):
        self.repo_root = repo_root or Path(__file__).resolve().parent.parent.parent
        self.os_type = OSDetector.get_os_type()

    def check_admin_privileges(self) -> bool:
        """Verifies if the current process runs with Administrator or Root privileges."""
        return OSDetector.is_admin()

    def get_all_user_profiles(self) -> List[Path]:
        """Discovers all local user profile directories across Windows, Linux, and macOS."""
        user_profiles: List[Path] = []
        os_type = self.os_type

        if os_type == "linux":
            # 1. Parse /etc/passwd for real users
            try:
                if Path("/etc/passwd").exists():
                    with open("/etc/passwd", "r", encoding="utf-8") as f:
                        for line in f:
                            parts = line.strip().split(":")
                            if len(parts) >= 6:
                                uid = int(parts[2]) if parts[2].isdigit() else -1
                                home = Path(parts[5])
                                # Normal user range or root
                                if (uid >= 1000 or uid == 0) and home.exists() and home.is_dir():
                                    if home not in user_profiles:
                                        user_profiles.append(home)
            except Exception as e:
                logger.debug(f"Could not parse /etc/passwd: {e}")

            # 2. Check /home directory
            home_dir = Path("/home")
            if home_dir.exists() and home_dir.is_dir():
                for p in home_dir.iterdir():
                    if p.is_dir() and not p.name.startswith(".") and p not in user_profiles:
                        user_profiles.append(p)

            # 3. Add root home
            root_home = Path("/root")
            if root_home.exists() and root_home not in user_profiles:
                user_profiles.append(root_home)

            # 4. Add /etc/skel (template for future created users)
            skel_dir = Path("/etc/skel")
            if skel_dir.exists() and skel_dir not in user_profiles:
                user_profiles.append(skel_dir)

        elif os_type == "macos":
            users_dir = Path("/Users")
            if users_dir.exists() and users_dir.is_dir():
                for p in users_dir.iterdir():
                    if p.is_dir() and not p.name.startswith(".") and p.name not in ("Shared", "Guest", ".localized"):
                        user_profiles.append(p)
            root_home = Path("/var/root")
            if root_home.exists() and root_home not in user_profiles:
                user_profiles.append(root_home)

        elif os_type == "windows":
            system_drive = os.environ.get("SystemDrive", "C:")
            users_dir = Path(f"{system_drive}\\Users")
            if users_dir.exists() and users_dir.is_dir():
                for p in users_dir.iterdir():
                    if p.is_dir():
                        p_name = p.name.lower()
                        if p_name not in ("public", "default", "default user", "all users") and not p_name.startswith("."):
                            user_profiles.append(p)

        # Fallback to current user if none found
        if not user_profiles:
            user_profiles.append(Path.home())

        return user_profiles

    def resolve_user_tool_path(self, raw_path_template: str, user_home: Path) -> Path:
        """Translates a generic configuration path template into a specific user's filesystem path."""
        if not raw_path_template:
            return Path()

        os_type = self.os_type

        if os_type == "windows":
            path_str = raw_path_template
            # Handle Windows environment variables in path template
            if "%USERPROFILE%" in path_str:
                path_str = path_str.replace("%USERPROFILE%", str(user_home))
            elif "%APPDATA%" in path_str:
                path_str = path_str.replace("%APPDATA%", str(user_home / "AppData" / "Roaming"))
            elif "%LOCALAPPDATA%" in path_str:
                path_str = path_str.replace("%LOCALAPPDATA%", str(user_home / "AppData" / "Local"))
            elif path_str.startswith("~"):
                path_str = str(user_home / path_str.lstrip("~\\/"))
            return Path(path_str)
        else:
            # Linux / macOS
            path_str = raw_path_template
            if path_str.startswith("~"):
                rel_part = path_str.lstrip("~/")
                return user_home / rel_part
            return Path(path_str)

    def apply_admin_read_only_permissions(self, target_path: Path, dry_run: bool = False) -> Tuple[bool, str]:
        """
        Applies system-level Read-Only permissions on target configuration or rules file:
        - Linux/macOS: chown root:root (or root:wheel), chmod 644 (file) / chmod 755 (dir).
        - Windows: NTFS ACLs via icacls (Administrators/SYSTEM: Full Control, Users: Read-Only).
        """
        if not target_path.exists():
            return False, f"Target path {target_path} does not exist"

        if dry_run:
            return True, f"[DRY RUN] Would lock {target_path} as Read-Only for standard users"

        os_type = self.os_type

        try:
            if os_type in ("linux", "macos"):
                # 1. Set directory permissions
                parent_dir = target_path.parent
                if parent_dir.exists():
                    os.chmod(parent_dir, 0o755)
                    try:
                        # chown root:root on Linux, root:wheel on macOS
                        group_id = 0
                        os.chown(parent_dir, 0, group_id)
                    except Exception as e:
                        logger.debug(f"chown parent notice: {e}")

                # 2. Set file permissions to 0644 (Read-only for group/others, writable only by root)
                if target_path.is_file():
                    os.chmod(target_path, 0o644)
                    try:
                        os.chown(target_path, 0, 0)
                    except Exception as e:
                        logger.debug(f"chown file notice: {e}")
                elif target_path.is_dir():
                    os.chmod(target_path, 0o755)
                    try:
                        os.chown(target_path, 0, 0)
                    except Exception as e:
                        logger.debug(f"chown dir notice: {e}")

                return True, f"Locked {target_path} with permissions 0644 (Owner: root)"

            elif os_type == "windows":
                # Use icacls to set restrictive NTFS ACLs
                # Grant Administrators and SYSTEM full control, grant Users read-only, remove inheritance
                cmd = [
                    "icacls",
                    str(target_path),
                    "/inheritance:r",
                    "/grant:r", "BUILTIN\\Administrators:(F)",
                    "/grant:r", "NT AUTHORITY\\SYSTEM:(F)",
                    "/grant:r", "BUILTIN\\Users:(R)",
                    "/T", "/Q"
                ]
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                if res.returncode == 0:
                    return True, f"Locked {target_path} with NTFS Read-Only ACL for standard users"
                else:
                    return False, f"icacls failed on {target_path}: {res.stderr.strip()}"

        except Exception as e:
            logger.error(f"Failed to set admin permissions on {target_path}: {e}")
            return False, str(e)

        return True, "Permissions set successfully"

    def enforce_system_wide_telemetry(self, dry_run: bool = False) -> Tuple[bool, str]:
        """
        Enforces system-wide environment variables disabling telemetry and tracking across all logins:
        - Linux/macOS: /etc/profile.d/hardening-ia.sh
        - Windows: System-wide Machine Environment Variables (DO_NOT_TRACK=1, CLAUDE_TELEMETRY_DISABLED=1)
        """
        if dry_run:
            return True, "[DRY RUN] Would deploy system-wide telemetry shutdown in global profile"

        os_type = self.os_type

        try:
            if os_type in ("linux", "macos"):
                profile_d = Path("/etc/profile.d")
                if profile_d.exists() and profile_d.is_dir():
                    target_script = profile_d / "hardening-ia-telemetry.sh"
                    content = (
                        "# Enterprise System-Wide AI Hardening Telemetry Lockdown\n"
                        "# Enforced by Hardening IA Administrator\n"
                        "export DO_NOT_TRACK=1\n"
                        "export CLAUDE_TELEMETRY_DISABLED=1\n"
                        "export CLAUDE_CODE_ENABLE_TELEMETRY=0\n"
                        "export DO_NOT_TRACK_AGENT=1\n"
                        "export ANTHROPIC_TELEMETRY_DISABLED=1\n"
                    )
                    target_script.write_text(content, encoding="utf-8")
                    os.chmod(target_script, 0o644)
                    os.chown(target_script, 0, 0)
                    return True, f"Deployed global telemetry shutdown script at {target_script}"

            elif os_type == "windows":
                # Set Machine environment variables using powershell
                ps_cmd = (
                    "[Environment]::SetEnvironmentVariable('DO_NOT_TRACK', '1', 'Machine'); "
                    "[Environment]::SetEnvironmentVariable('CLAUDE_TELEMETRY_DISABLED', '1', 'Machine'); "
                    "[Environment]::SetEnvironmentVariable('CLAUDE_CODE_ENABLE_TELEMETRY', '0', 'Machine')"
                )
                subprocess.run(["powershell", "-NoProfile", "-Command", ps_cmd], capture_output=True, text=True, timeout=10)
                return True, "Enforced machine-level DO_NOT_TRACK=1 and CLAUDE_TELEMETRY_DISABLED=1 environment variables"

        except Exception as e:
            logger.error(f"Could not enforce system-wide telemetry: {e}")
            return False, str(e)

        return True, "System-wide telemetry configuration active"

    def apply_admin_system_wide_policy(
        self,
        policy: HardeningPolicy,
        strict_mode: bool = False,
        dry_run: bool = False
    ) -> Dict[str, Any]:
        """
        Enforces a hardening policy across all discovered user accounts and sets
        read-only permissions so users cannot alter the configuration.
        """
        if not self.check_admin_privileges():
            raise PermissionError(
                "Administrator / Root elevation required. Please run this command with 'sudo' (Linux/macOS) or 'Run as Administrator' (Windows)."
            )

        tool_name = policy.tool.name
        vendor = policy.tool.vendor
        os_type = self.os_type
        path_info = policy.paths.get(os_type)

        user_profiles = self.get_all_user_profiles()
        results: List[Dict[str, Any]] = []

        # 1. Enforce global telemetry lockdown
        self.enforce_system_wide_telemetry(dry_run=dry_run)

        # 2. Build configuration payload (with strict mode if requested)
        native_overrides = dict(policy.policies.get("native_settings_override", {}))
        if strict_mode:
            strict_rules = policy.policies.get("strict_rules", {})
            if strict_rules and "native_overrides" in strict_rules:
                native_overrides.update(strict_rules["native_overrides"])
            native_overrides["security.strict_mode"] = True
            native_overrides["security.dangerousPaths.action"] = "block"
            native_overrides["security.approvals.bypass_allowed"] = False
            native_overrides["security.approvals.auto_apply_edits"] = False
            native_overrides["security.approvals.require_write_approval"] = True

        rule_content = SecurityPolicyManager.generate_security_policy_rule(os_type, strict_mode=strict_mode)

        for user_home in user_profiles:
            user_res = {
                "user_home": str(user_home),
                "settings_file": None,
                "rules_file": None,
                "success": True,
                "messages": []
            }

            if path_info:
                # 2.1 Deploy Settings File
                if path_info.settings_file:
                    target_settings = self.resolve_user_tool_path(path_info.settings_file, user_home)
                    user_res["settings_file"] = str(target_settings)

                    if not dry_run:
                        target_settings.parent.mkdir(parents=True, exist_ok=True)
                        current_data = {}
                        if target_settings.exists():
                            try:
                                current_data = json.loads(target_settings.read_text(encoding="utf-8"))
                            except Exception:
                                current_data = {}
                        # Deep merge overrides
                        current_data.update(native_overrides)
                        target_settings.write_text(json.dumps(current_data, indent=2), encoding="utf-8")

                    # Lock settings file as Read-Only
                    lock_ok, lock_msg = self.apply_admin_read_only_permissions(target_settings, dry_run=dry_run)
                    user_res["messages"].append(lock_msg)

                # 2.2 Deploy Rules File
                if path_info.rules_dir:
                    target_rules_dir = self.resolve_user_tool_path(path_info.rules_dir, user_home)
                    target_rule_file = target_rules_dir / f"{os_type}_security_policy.md"
                    user_res["rules_file"] = str(target_rule_file)

                    if not dry_run:
                        target_rules_dir.mkdir(parents=True, exist_ok=True)
                        target_rule_file.write_text(rule_content, encoding="utf-8")

                    # Lock rule file as Read-Only
                    lock_ok, lock_msg = self.apply_admin_read_only_permissions(target_rule_file, dry_run=dry_run)
                    user_res["messages"].append(lock_msg)

            results.append(user_res)

        log_audit_event(
            event_type="ADMIN_SYSTEM_WIDE_ENFORCEMENT",
            tool_name=tool_name,
            vendor=vendor,
            status="SUCCESS",
            details={
                "users_count": len(user_profiles),
                "strict_mode": strict_mode,
                "dry_run": dry_run,
                "os": os_type
            }
        )

        return {
            "tool": f"{vendor}/{tool_name}",
            "users_count": len(user_profiles),
            "strict_mode": strict_mode,
            "dry_run": dry_run,
            "results": results
        }

    def verify_admin_system_wide_policy(
        self,
        policy: HardeningPolicy,
        strict_mode: bool = False
    ) -> Dict[str, Any]:
        """Audits all user accounts to ensure configuration files exist, match policy, and are Read-Only for users."""
        if not self.check_admin_privileges():
            raise PermissionError("Administrator / Root elevation required.")

        tool_name = policy.tool.name
        vendor = policy.tool.vendor
        os_type = self.os_type
        path_info = policy.paths.get(os_type)

        user_profiles = self.get_all_user_profiles()
        user_reports = []

        expected_overrides = dict(policy.policies.get("native_settings_override", {}))
        if strict_mode:
            strict_rules = policy.policies.get("strict_rules", {})
            if strict_rules and "native_overrides" in strict_rules:
                expected_overrides.update(strict_rules["native_overrides"])
            expected_overrides["security.strict_mode"] = True
            expected_overrides["security.dangerousPaths.action"] = "block"
            expected_overrides["security.approvals.auto_apply_edits"] = False

        for user_home in user_profiles:
            user_status = {
                "user_home": str(user_home),
                "compliant": True,
                "read_only_enforced": True,
                "checks": []
            }

            if path_info and path_info.settings_file:
                target_settings = self.resolve_user_tool_path(path_info.settings_file, user_home)
                file_exists = target_settings.exists()
                user_status["checks"].append({
                    "check": "settings_file_exists",
                    "path": str(target_settings),
                    "passed": file_exists
                })

                if file_exists:
                    try:
                        current_data = json.loads(target_settings.read_text(encoding="utf-8"))
                        for k, v in expected_overrides.items():
                            val = current_data.get(k)
                            passed = (val == v)
                            if not passed:
                                user_status["compliant"] = False
                            user_status["checks"].append({
                                "check": f"setting:{k}",
                                "expected": v,
                                "actual": val,
                                "passed": passed
                            })
                    except Exception as e:
                        user_status["compliant"] = False

                    # Check read-only / ownership on Unix
                    if os_type in ("linux", "macos"):
                        st = target_settings.stat()
                        is_root_owned = (st.st_uid == 0)
                        # Check that group and other have no write permissions (not 0o022)
                        not_user_writable = not bool(st.st_mode & 0o022)
                        ro_ok = is_root_owned and not_user_writable
                        if not ro_ok:
                            user_status["read_only_enforced"] = False
                        user_status["checks"].append({
                            "check": "read_only_root_ownership",
                            "passed": ro_ok,
                            "uid": st.st_uid,
                            "mode": oct(st.st_mode)
                        })

            user_reports.append(user_status)

        return {
            "tool": f"{vendor}/{tool_name}",
            "total_users": len(user_profiles),
            "users": user_reports
        }
