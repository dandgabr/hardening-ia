"""Real-time Security Watchdog Daemon for Hardening IA.

Continuously monitors configuration files, rules directories, and host processes
for unauthorized drift, file tampering, or new unhardened tool installations.
Supports automatic baseline remediation and structured audit alerting.
"""

import time
import hashlib
import signal
import sys
from pathlib import Path
from typing import Dict, List, Optional, Callable, Any

from src.core.config_loader import ConfigLoader
from src.core.engine import HardeningEngine
from src.core.verifier import HardeningVerifier, PolicyVerificationReport
from src.core.os_detector import OSDetector
from src.core.logger import get_logger, log_audit_event
from src.core.models import HardeningPolicy

logger = get_logger("watchdog")


class SecurityWatchdog:
    """Continuous security watchdog daemon monitoring configuration drift and compliance."""

    def __init__(
        self,
        config_loader: Optional[ConfigLoader] = None,
        engine: Optional[HardeningEngine] = None,
        verifier: Optional[HardeningVerifier] = None,
        poll_interval: float = 5.0,
        auto_remediate: bool = False,
        strict_mode: bool = False,
        installed_only: bool = True
    ):
        self.loader = config_loader or ConfigLoader()
        self.engine = engine or HardeningEngine()
        self.verifier = verifier or HardeningVerifier()
        self.poll_interval = poll_interval
        self.auto_remediate = auto_remediate
        self.strict_mode = strict_mode
        self.installed_only = installed_only
        self.os_type = OSDetector.get_os_type()
        self.running = False
        self._file_hashes: Dict[str, str] = {}
        self._drift_callbacks: List[Callable[[PolicyVerificationReport, bool], None]] = []

    def register_drift_callback(self, callback: Callable[[PolicyVerificationReport, bool], None]):
        """Registers a callback invoked when configuration drift is detected."""
        self._drift_callbacks.append(callback)

    def compute_file_hash(self, path: Path) -> Optional[str]:
        """Computes SHA-256 hash of a target configuration file."""
        try:
            if path.exists() and path.is_file():
                content = path.read_bytes()
                return hashlib.sha256(content).hexdigest()
        except Exception as e:
            logger.warning(f"Could not compute hash for {path}: {e}")
        return None

    def initialize_fingerprints(self) -> Dict[str, str]:
        """Initializes baseline SHA-256 fingerprints across monitored files."""
        policies = self.loader.load_all_policies()
        if self.installed_only:
            policies = [p for p in policies if p.is_installed]

        self._file_hashes.clear()
        for p in policies:
            paths = p.paths.get(self.os_type)
            if not paths:
                continue
            all_files = [paths.settings_file] + getattr(paths, "secondary_settings_files", [])
            for sf in all_files:
                if sf:
                    expanded = OSDetector.expand_path(sf)
                    h = self.compute_file_hash(expanded)
                    if h:
                        self._file_hashes[str(expanded)] = h
        logger.info(f"Initialized security watchdog monitoring {len(self._file_hashes)} configuration file(s).")
        return self._file_hashes

    def scan_cycle(self) -> List[Dict[str, Any]]:
        """Executes a single monitoring and compliance audit cycle."""
        drifts_detected: List[Dict[str, Any]] = []
        policies = self.loader.load_all_policies()
        if self.installed_only:
            policies = [p for p in policies if p.is_installed]

        for p in policies:
            paths = p.paths.get(self.os_type)
            if not paths:
                continue

            all_files = [paths.settings_file] + getattr(paths, "secondary_settings_files", [])
            has_modified_file = False

            for sf in all_files:
                if not sf:
                    continue
                expanded = OSDetector.expand_path(sf)
                str_path = str(expanded)
                current_hash = self.compute_file_hash(expanded)
                recorded_hash = self._file_hashes.get(str_path)

                if current_hash is not None and current_hash != recorded_hash:
                    has_modified_file = True
                    self._file_hashes[str_path] = current_hash
                elif current_hash is None and recorded_hash is not None:
                    # File was deleted
                    has_modified_file = True
                    self._file_hashes.pop(str_path, None)

            # Audit policy compliance
            report = self.verifier.verify_policy(p, strict_mode=self.strict_mode)
            if report.compliance_score < 100.0 or has_modified_file:
                remediated = False
                if report.compliance_score < 100.0:
                    logger.warning(
                        f"Security drift detected in {p.tool.vendor}/{p.tool.name} "
                        f"(Score: {report.compliance_score:.1f}%, {report.failed_checks} discrepancy(ies))."
                    )

                    log_audit_event(
                        event_type="SECURITY_DRIFT_DETECTED",
                        tool_name=p.tool.name,
                        vendor=p.tool.vendor,
                        status="DRIFT",
                        details={
                            "compliance_score": report.compliance_score,
                            "failed_checks": report.failed_checks,
                            "auto_remediate": self.auto_remediate,
                            "strict_mode": self.strict_mode
                        }
                    )

                    if self.auto_remediate:
                        logger.info(f"Auto-remediating policy for {p.tool.vendor}/{p.tool.name}...")
                        res = self.engine.apply_policy(p, dry_run=False, strict_mode=self.strict_mode)
                        if res.success:
                            remediated = True
                            # Refresh hashes post-remediation
                            for sf in all_files:
                                if sf:
                                    exp = OSDetector.expand_path(sf)
                                    self._file_hashes[str(exp)] = self.compute_file_hash(exp) or ""
                            log_audit_event(
                                event_type="AUTO_REMEDIATION_TRIGGERED",
                                tool_name=p.tool.name,
                                vendor=p.tool.vendor,
                                status="SUCCESS",
                                details={"remediated_paths": res.modified_paths}
                            )

                drift_info = {
                    "tool": f"{p.tool.vendor}/{p.tool.name}",
                    "report": report,
                    "remediated": remediated,
                    "timestamp": time.time()
                }
                drifts_detected.append(drift_info)

                for cb in self._drift_callbacks:
                    try:
                        cb(report, remediated)
                    except Exception as e:
                        logger.error(f"Error in watchdog drift callback: {e}")

        return drifts_detected

    def run_forever(self, max_iterations: Optional[int] = None):
        """Runs the watchdog monitoring loop continuously until interrupted."""
        self.running = True
        self.initialize_fingerprints()
        iteration = 0

        logger.info(f"Security Watchdog active (interval={self.poll_interval}s, auto_remediate={self.auto_remediate}).")

        def _signal_handler(sig, frame):
            logger.info("Watchdog shutdown requested by system signal.")
            self.running = False

        signal.signal(signal.SIGINT, _signal_handler)
        signal.signal(signal.SIGTERM, _signal_handler)

        try:
            while self.running:
                self.scan_cycle()
                iteration += 1
                if max_iterations and iteration >= max_iterations:
                    break
                time.sleep(self.poll_interval)
        finally:
            self.running = False
            logger.info("Security Watchdog daemon stopped.")
