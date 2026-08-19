"""Centralized logging subsystem for Hardening IA.

Supports rotating file logging, structured JSONL audit trails, and rich console output.
"""

import os
import sys
import json
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, Any


DEFAULT_LOG_FORMAT = "%(asctime)s [%(levelname)-7s] [%(name)s]: %(message)s"
DEFAULT_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def setup_logging(
    log_level: int = logging.INFO,
    log_dir: Optional[Path] = None,
    enable_console: bool = True,
    log_filename: str = "hardening.log"
) -> logging.Logger:
    """Configures the root framework logger with rotating file and console sinks."""
    if log_dir is None:
        log_dir = Path(__file__).resolve().parent.parent.parent / "logs"

    root_logger = logging.getLogger("hardening_ia")
    root_logger.setLevel(log_level)

    if root_logger.hasHandlers():
        root_logger.handlers.clear()

    formatter = logging.Formatter(DEFAULT_LOG_FORMAT, datefmt=DEFAULT_DATE_FORMAT)

    # 1. Rotating File Handler (10MB max, 5 backups) with graceful fallback
    file_handler = None
    target_dirs = [log_dir, Path.home() / ".hardening-ia" / "logs"]
    
    for candidate_dir in target_dirs:
        try:
            candidate_dir.mkdir(parents=True, exist_ok=True)
            log_file_path = candidate_dir / log_filename
            file_handler = RotatingFileHandler(
                log_file_path,
                maxBytes=10 * 1024 * 1024,
                backupCount=5,
                encoding="utf-8"
            )
            file_handler.setLevel(log_level)
            file_handler.setFormatter(formatter)
            root_logger.addHandler(file_handler)
            break
        except (PermissionError, OSError) as err:
            if candidate_dir == target_dirs[-1]:
                sys.stderr.write(f"[WARN] Failed to initialize file logger: {err}. Continuing with console only.\n")

    # 2. Console Stream Handler
    if enable_console:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(log_level)
        console_handler.setFormatter(formatter)
        root_logger.addHandler(console_handler)

    return root_logger


def get_logger(name: str) -> logging.Logger:
    """Returns a namespaced child logger under 'hardening_ia'."""
    return logging.getLogger(f"hardening_ia.{name}")


def log_audit_event(
    event_type: str,
    tool_name: str,
    vendor: str,
    status: str,
    details: Dict[str, Any],
    audit_dir: Optional[Path] = None
):
    """Appends an immutable structured audit event to logs/audit.jsonl with fallback."""
    if audit_dir is None:
        audit_dir = Path(__file__).resolve().parent.parent.parent / "logs"

    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": event_type,
        "tool": tool_name,
        "vendor": vendor,
        "status": status,
        "details": details
    }

    target_dirs = [audit_dir, Path.home() / ".hardening-ia" / "logs"]
    payload = json.dumps(record, ensure_ascii=False) + "\n"

    for candidate_dir in target_dirs:
        try:
            candidate_dir.mkdir(parents=True, exist_ok=True)
            audit_file = candidate_dir / "audit.jsonl"
            with open(audit_file, "a", encoding="utf-8") as f:
                f.write(payload)
            return
        except (PermissionError, OSError) as e:
            if candidate_dir == target_dirs[-1]:
                get_logger("audit").error(f"Failed to record audit event: {e}")
