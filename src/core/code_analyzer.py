"""SAST Code Vulnerability Analyzer powered by OpenGrep rules for AI-assisted development."""

import re
import sys
import json
import shutil
import subprocess
from pathlib import Path
from typing import List, Dict, Any, Optional

from src.core.logger import get_logger, log_audit_event
from src.core.os_detector import OSDetector

logger = get_logger("code_analyzer")

# Built-in heuristic AST / regex patterns for instant scanning
BUILTIN_PATTERNS = [
    # OWASP Web / CWE-798
    {
        "id": "OWASP-A04-CWE-798",
        "title": "Hardcoded API Key / Token / Secret",
        "pattern": r"""(?i)(?:api_key|secret_key|private_key|token|password|aws_secret|firebase_token)\s*=\s*['\"][A-Za-z0-9_\-\.]{16,}['\"]""",
        "severity": "HIGH",
        "cwe": "CWE-798",
        "remediation": "Move secrets to environment variables (os.environ.get(...)) or secure secret vaults."
    },
    # OWASP Web / CWE-78
    {
        "id": "OWASP-A03-CWE-78",
        "title": "OS Command Injection via shell=True / os.system",
        "pattern": r"""(?:subprocess\.(?:run|Popen|call|check_output)\([^)]*shell\s*=\s*True|os\.system\([^)]*\)|child_process\.exec\([^)]*\))""",
        "severity": "CRITICAL",
        "cwe": "CWE-78",
        "remediation": "Pass arguments as a list without shell=True, or sanitize with shlex.quote()."
    },
    # OWASP Web / CWE-94 / CWE-95
    {
        "id": "OWASP-A03-CWE-94",
        "title": "Insecure Dynamic Code Execution (eval / exec)",
        "pattern": r"""\b(?:eval|exec)\s*\([^)]+\)""",
        "severity": "HIGH",
        "cwe": "CWE-94",
        "remediation": "Refactor logic using ast.literal_eval() or explicit dispatch tables."
    },
    # OWASP Web / CWE-502
    {
        "id": "OWASP-A08-CWE-502",
        "title": "Insecure Deserialization (pickle / unsafe yaml / Marshal)",
        "pattern": r"""(?:pickle\.loads?|yaml\.load\([^)]*Loader\s*=\s*yaml\.(?:Loader|CLoader)|Marshal\.load|unserialize\()""",
        "severity": "HIGH",
        "cwe": "CWE-502",
        "remediation": "Use yaml.safe_load(), JSON, or signed deserialization tokens."
    },
    # OWASP Web / CWE-89
    {
        "id": "OWASP-A03-CWE-89",
        "title": "SQL Injection via String Formatting",
        "pattern": r"""(?i)(?:execute|cursor\.execute|rawQuery|query)\s*\(\s*f?['\"].*(?:SELECT|INSERT|UPDATE|DELETE|DROP)\s+.*[\+\$]""",
        "severity": "CRITICAL",
        "cwe": "CWE-89",
        "remediation": "Use parameterized query placeholders (?, %s) rather than string concatenation."
    },
    # OWASP Web / CWE-79
    {
        "id": "OWASP-A03-CWE-79",
        "title": "Cross-Site Scripting (XSS) / dangerouslySetInnerHTML",
        "pattern": r"""(?:dangerouslySetInnerHTML|document\.write\([^)]+\)|\.innerHTML\s*=\s*[^;\n]+)""",
        "severity": "HIGH",
        "cwe": "CWE-79",
        "remediation": "Sanitize inputs using DOMPurify or framework auto-escaping templates."
    },
    # OWASP Web / CWE-918
    {
        "id": "OWASP-A10-CWE-918",
        "title": "Server-Side Request Forgery (SSRF)",
        "pattern": r"""(?:requests\.(?:get|post)\(\s*[a-zA-Z0-9_]+|urllib\.request\.urlopen\(\s*[a-zA-Z0-9_]+)""",
        "severity": "WARNING",
        "cwe": "CWE-918",
        "remediation": "Validate target URLs against an explicit domain allowlist and block private IP ranges."
    },
    # OWASP Mobile / Android M5 / CWE-295
    {
        "id": "OWASP-M5-CWE-295",
        "title": "Insecure TLS Certificate Validation / TrustAll",
        "pattern": r"""(?:InsecureSkipVerify:\s*true|checkServerTrusted\(\s*\)\s*\{\s*\}|ServerCertificateValidationCallback\s*=)""",
        "severity": "ERROR",
        "cwe": "CWE-295",
        "remediation": "Enable standard system CA validation and certificate pinning."
    },
    # OWASP Mobile / Android M8 / CWE-276
    {
        "id": "OWASP-M8-CWE-276",
        "title": "World-Readable SharedPreferences / Insecure File Mode",
        "pattern": r"""(?:MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE)""",
        "severity": "HIGH",
        "cwe": "CWE-276",
        "remediation": "Use Context.MODE_PRIVATE and EncryptedSharedPreferences."
    },
    # CWE-787 / Buffer Overflow (C/C++)
    {
        "id": "CWE-787-CWE-119",
        "title": "Unsafe Buffer Operation (strcpy / sprintf / gets)",
        "pattern": r"""\b(?:strcpy|strcat|sprintf|gets)\s*\(""",
        "severity": "HIGH",
        "cwe": "CWE-787",
        "remediation": "Replace with bounds-checked alternatives: strncpy_s, snprintf, fgets."
    },
    # SCA: Insecure HTTP Repository Registry
    {
        "id": "SCA-SUPPLY-CHAIN-001",
        "title": "Insecure Cleartext Package Registry (HTTP)",
        "pattern": r"""(?i)http:\/\/(?:pypi\.org|registry\.npmjs\.org|repo\.maven\.apache\.org)""",
        "severity": "HIGH",
        "cwe": "CWE-319",
        "remediation": "Use HTTPS endpoints exclusively for package managers to prevent supply-chain poisoning."
    }
]


class CodeVulnerabilityScanner:
    """Scans codebases using OpenGrep and native AST patterns to report and remediate security issues."""

    def __init__(self, repo_root: Optional[Path] = None):
        self.repo_root = repo_root or Path(__file__).resolve().parent.parent.parent
        self.rules_dir = self.repo_root / "configs" / "opengrep-rules"

    def scan_path(self, target_path: Path) -> List[Dict[str, Any]]:
        """Scans a file or directory for security vulnerabilities."""
        findings: List[Dict[str, Any]] = []
        target_path = Path(target_path).resolve()

        if not target_path.exists():
            logger.warning(f"Scan target does not exist: {target_path}")
            return findings

        # 1. Try running opengrep binary if available in PATH
        if shutil.which("opengrep"):
            try:
                cmd = ["opengrep", "scan", "--json", str(target_path)]
                if self.rules_dir.exists():
                    cmd.extend(["--config", str(self.rules_dir)])

                res = subprocess.run(cmd, capture_output=True, text=True)
                if res.stdout:
                    try:
                        data = json.loads(res.stdout)
                        for r in data.get("results", []):
                            findings.append({
                                "rule_id": r.get("check_id"),
                                "file": r.get("path"),
                                "line": r.get("start", {}).get("line", 1),
                                "message": r.get("extra", {}).get("message", ""),
                                "severity": r.get("extra", {}).get("severity", "WARNING"),
                                "remediation": r.get("extra", {}).get("fix", "Review security policy.")
                            })
                        if findings:
                            return findings
                    except Exception:
                        pass
            except Exception as e:
                logger.debug(f"Opengrep binary scan skipped: {e}")

        # 2. Native Pattern Scanner Fallback
        files_to_scan = []
        excluded_dirs = (".git", ".venv", "venv", "node_modules", "logs", "configs/opengrep-rules", "configs\\opengrep-rules")
        ignored_files = {"code_analyzer.py", "install_opengrep.py"}
        if target_path.is_file():
            if not any(exc in str(target_path) for exc in excluded_dirs) and target_path.name not in ignored_files:
                files_to_scan.append(target_path)
        else:
            for ext in ("*.py", "*.js", "*.ts", "*.json", "*.yaml", "*.yml", "*.sh", "*.ps1"):
                for p in target_path.rglob(ext):
                    if not any(exc in p.parts for exc in (".git", ".venv", "venv", "node_modules", "logs", "opengrep-rules")) and p.name not in ignored_files:
                        files_to_scan.append(p)

        for file_path in files_to_scan:
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
                lines = content.splitlines()
                for line_idx, line in enumerate(lines, start=1):
                    for rule in BUILTIN_PATTERNS:
                        if re.search(rule["pattern"], line):
                            finding = {
                                "rule_id": rule["id"],
                                "title": rule["title"],
                                "file": str(file_path.relative_to(self.repo_root) if file_path.is_relative_to(self.repo_root) else file_path),
                                "line": line_idx,
                                "code_snippet": line.strip()[:100],
                                "severity": rule["severity"],
                                "cwe": rule["cwe"],
                                "remediation": rule["remediation"]
                            }
                            findings.append(finding)
            except Exception as e:
                logger.debug(f"Could not read {file_path}: {e}")

        log_audit_event(
            event_type="CODE_SCAN",
            tool_name="opengrep",
            vendor="opengrep",
            status="SUCCESS",
            details={
                "target": str(target_path),
                "total_findings": len(findings)
            }
        )

        return findings


def main():
    target = sys.argv[1] if len(sys.argv) > 1 else "."
    scanner = CodeVulnerabilityScanner()
    results = scanner.scan_path(Path(target))
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
