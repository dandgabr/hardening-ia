"""Enterprise Compliance and Governance Reporting Engine for Hardening IA.

Generates structured compliance audits in Interactive HTML, SARIF 2.1.0, JSON, and Markdown formats,
with formal mappings to OWASP Top 10 for LLM, NIST AI RMF 1.0, and ISO/IEC 42001:2023.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional

from src.core.verifier import PolicyVerificationReport
from src.core.models import HardeningPolicy


# Governance Framework Mappings
FRAMEWORK_MAPPINGS: Dict[str, Dict[str, Any]] = {
    "telemetry": {
        "owasp_llm": "LLM02: Sensitive Information Disclosure",
        "nist_ai_rmf": "GOVERN-1.1 / MEASURE-2.3",
        "iso_42001": "A.6.2 Data Security & Privacy Controls",
        "description": "Prevents unauthorized telemetry transmission and cloud metadata exfiltration."
    },
    "sandbox": {
        "owasp_llm": "LLM06: Excessive Agency & Uncontrolled Execution",
        "nist_ai_rmf": "MANAGE-1.2 Risk Treatment",
        "iso_42001": "A.8.4 AI System Boundary Isolation",
        "description": "Enforces execution boundaries, container namespaces, and dangerous syscall blocking."
    },
    "mcp": {
        "owasp_llm": "LLM01: Prompt Injection / Tool Exploitation",
        "nist_ai_rmf": "MAP-1.5 Third-Party Integrations",
        "iso_42001": "A.9.3 Access Control & Protocol Verification",
        "description": "Requires explicit operator consent before invoking external MCP server tools."
    },
    "dlp": {
        "owasp_llm": "LLM02: Sensitive Information Disclosure / LLM07: System Prompt Leakage",
        "nist_ai_rmf": "MEASURE-2.3 Privacy Safeguards",
        "iso_42001": "A.6.2 Sensitive Data Protection",
        "description": "Masks API keys, bearer tokens, private keys, and credential patterns before prompt dispatch."
    },
    "subagents": {
        "owasp_llm": "LLM06: Excessive Agency & Uncontrolled Autonomy",
        "nist_ai_rmf": "GOVERN-1.1 Workload Governance",
        "iso_42001": "A.8.4 Process Orchestration & Guardrails",
        "description": "Restricts autonomous subagent spawning and mandates parent agent approval."
    },
    "approvals": {
        "owasp_llm": "LLM06: Excessive Agency",
        "nist_ai_rmf": "MANAGE-1.2 Human-in-the-Loop Oversight",
        "iso_42001": "A.9.3 Human Authorization",
        "description": "Mandates explicit operator approval for write operations and command execution."
    },
    "rate_limits": {
        "owasp_llm": "LLM10: Unbounded Consumption & Denial of Service",
        "nist_ai_rmf": "MEASURE-2.3 Resource Governance",
        "iso_42001": "A.8.4 Availability Controls",
        "description": "Enforces request rate limits and command execution timeouts."
    }
}


class ComplianceReporter:
    """Enterprise compliance report generator across multiple standardized output formats."""

    def __init__(self, reports: List[PolicyVerificationReport], policies: Optional[List[HardeningPolicy]] = None):
        self.reports = reports
        self.policies = {f"{p.tool.vendor}/{p.tool.name}": p for p in (policies or [])}
        self.generated_at = datetime.now(timezone.utc).isoformat()

    def calculate_overall_compliance(self) -> Dict[str, Any]:
        """Calculates global compliance statistics across all evaluated tools."""
        total_tools = len(self.reports)
        installed_tools = sum(1 for r in self.reports if r.is_installed)
        total_checks = sum(r.total_checks for r in self.reports if r.is_installed)
        passed_checks = sum(r.passed_checks for r in self.reports if r.is_installed)
        failed_checks = sum(r.failed_checks for r in self.reports if r.is_installed)

        global_score = (passed_checks / total_checks * 100.0) if total_checks > 0 else 0.0

        return {
            "total_tools": total_tools,
            "installed_tools": installed_tools,
            "total_checks": total_checks,
            "passed_checks": passed_checks,
            "failed_checks": failed_checks,
            "global_score": round(global_score, 2),
            "generated_at": self.generated_at
        }

    def generate_json(self) -> str:
        """Generates structured JSON compliance report."""
        stats = self.calculate_overall_compliance()
        data = {
            "report_type": "Hardening IA Enterprise Compliance Audit",
            "schema_version": "1.0",
            "timestamp": self.generated_at,
            "statistics": stats,
            "framework_mappings": FRAMEWORK_MAPPINGS,
            "tools": []
        }

        for r in self.reports:
            tool_data = {
                "tool_name": r.tool_name,
                "vendor": r.vendor,
                "is_installed": r.is_installed,
                "compliance_score": r.compliance_score,
                "total_checks": r.total_checks,
                "passed_checks": r.passed_checks,
                "failed_checks": r.failed_checks,
                "message": r.message,
                "checks": [
                    {
                        "key": c.key,
                        "expected": c.expected,
                        "actual": c.actual,
                        "passed": c.passed,
                        "description": c.description,
                        "framework": self._get_framework_mapping_for_key(c.key)
                    }
                    for c in r.checks
                ]
            }
            data["tools"].append(tool_data)

        return json.dumps(data, indent=2, ensure_ascii=False)

    def generate_sarif(self) -> str:
        """Generates SARIF 2.1.0 report for GitHub Security / CI scanning integration."""
        rules = []
        results = []

        rule_map = {}
        for r in self.reports:
            for c in r.checks:
                if not c.passed:
                    rule_id = f"HIA-{c.key.replace(".", "_").upper()}"
                    if rule_id not in rule_map:
                        mapping = self._get_framework_mapping_for_key(c.key)
                        rule_map[rule_id] = {
                            "id": rule_id,
                            "name": c.key,
                            "shortDescription": {"text": f"Non-compliant setting: {c.key}"},
                            "fullDescription": {"text": f"{c.description}. Expected: {c.expected}, Found: {c.actual}"},
                            "help": {
                                "text": f"Remediation: Configure '{c.key}' to '{c.expected}'. Mapped to {mapping.get('owasp_llm')} | {mapping.get('nist_ai_rmf')}"
                            },
                            "defaultConfiguration": {"level": "error"}
                        }

                    results.append({
                        "ruleId": rule_id,
                        "level": "error",
                        "message": {
                            "text": f"Tool '{r.vendor}/{r.tool_name}' failed security check '{c.key}': expected {c.expected}, found {c.actual}."
                        },
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {
                                        "uri": f"configs/tools/{r.vendor}/{r.tool_name}/hardening_policy.yaml"
                                    }
                                }
                            }
                        ]
                    })

        sarif_doc = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Hardening IA Framework",
                            "semanticVersion": "1.0.0",
                            "informationUri": "https://github.com/dandgabr/hardening-ia",
                            "rules": list(rule_map.values())
                        }
                    },
                    "results": results
                }
            ]
        }

        return json.dumps(sarif_doc, indent=2, ensure_ascii=False)

    def generate_markdown(self) -> str:
        """Generates formatted GitHub Markdown compliance report."""
        stats = self.calculate_overall_compliance()
        md = []
        md.append("# Hardening IA Enterprise Compliance Report\n")
        md.append(f"**Generated at (UTC):** `{self.generated_at}`\n")
        md.append("## Executive Summary\n")
        md.append("| Metric | Value |")
        md.append("| :--- | :--- |")
        md.append(f"| **Global Compliance Score** | **{stats['global_score']}%** |")
        md.append(f"| **Tools Evaluated** | {stats['total_tools']} |")
        md.append(f"| **Installed on Host** | {stats['installed_tools']} |")
        md.append(f"| **Passed Checks** | {stats['passed_checks']} |")
        md.append(f"| **Failed Checks** | {stats['failed_checks']} |\n")

        md.append("## Tool Compliance Matrix\n")
        md.append("| Tool | Status | Score | Findings |")
        md.append("| :--- | :--- | :--- | :--- |")

        for r in self.reports:
            inst_badge = "✅ Installed" if r.is_installed else "⚪ Not Found"
            score_badge = f"**{r.compliance_score:.1f}%** ({r.passed_checks}/{r.total_checks})"
            findings = "100% Compliant" if r.compliance_score == 100.0 else f"{r.failed_checks} discrepancy(ies)"
            md.append(f"| `{r.vendor}/{r.tool_name}` | {inst_badge} | {score_badge} | {findings} |")

        md.append("\n## Governance Framework Mappings\n")
        md.append("| Control Domain | OWASP Top 10 for LLM | NIST AI RMF | ISO/IEC 42001 |")
        md.append("| :--- | :--- | :--- | :--- |")
        for domain, map_info in FRAMEWORK_MAPPINGS.items():
            md.append(f"| **{domain.upper()}** | `{map_info['owasp_llm']}` | `{map_info['nist_ai_rmf']}` | `{map_info['iso_42001']}` |")

        return "\n".join(md)

    def generate_html(self) -> str:
        """Generates modern standalone interactive HTML compliance dashboard."""
        stats = self.calculate_overall_compliance()
        score_color = "#10b981" if stats["global_score"] >= 90 else ("#f59e0b" if stats["global_score"] >= 70 else "#ef4444")

        tools_rows = ""
        for r in self.reports:
            status_cls = "badge-success" if r.is_installed else "badge-muted"
            status_text = "Installed" if r.is_installed else "Not Found"
            score_cls = "score-high" if r.compliance_score >= 90 else ("score-mid" if r.compliance_score >= 70 else "score-low")

            discrepancies_html = ""
            if r.failed_checks > 0:
                discrepancies_html = "<ul class='findings-list'>"
                for c in r.checks:
                    if not c.passed:
                        discrepancies_html += f"<li><strong>{c.key}</strong>: expected <code>{c.expected}</code>, found <code>{c.actual}</code></li>"
                discrepancies_html += "</ul>"
            else:
                discrepancies_html = "<span class='all-passed'>All security controls verified</span>"

            tools_rows += f"""
            <tr>
                <td><strong>{r.vendor}/{r.tool_name}</strong></td>
                <td><span class="badge {status_cls}">{status_text}</span></td>
                <td><span class="score-badge {score_cls}">{r.compliance_score:.1f}%</span> ({r.passed_checks}/{r.total_checks})</td>
                <td>{discrepancies_html}</td>
            </tr>
            """

        framework_rows = ""
        for domain, map_info in FRAMEWORK_MAPPINGS.items():
            framework_rows += f"""
            <tr>
                <td><strong>{domain.upper()}</strong></td>
                <td><code>{map_info['owasp_llm']}</code></td>
                <td><code>{map_info['nist_ai_rmf']}</code></td>
                <td><code>{map_info['iso_42001']}</code></td>
                <td>{map_info['description']}</td>
            </tr>
            """

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Hardening IA - Enterprise Security & Governance Audit</title>
    <style>
        :root {{
            --bg-primary: #0f172a;
            --bg-secondary: #1e293b;
            --bg-card: #1e293b;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --border-color: #334155;
            --accent-blue: #3b82f6;
            --accent-green: #10b981;
            --accent-yellow: #f59e0b;
            --accent-red: #ef4444;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background-color: var(--bg-primary);
            color: var(--text-primary);
            margin: 0;
            padding: 30px;
            line-height: 1.5;
        }}
        .container {{
            max-width: 1280px;
            margin: 0 auto;
        }}
        header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding-bottom: 20px;
            border-bottom: 1px solid var(--border-color);
            margin-bottom: 30px;
        }}
        h1 {{ margin: 0; font-size: 1.75rem; color: #fff; display: flex; align-items: center; gap: 10px; }}
        .timestamp {{ color: var(--text-secondary); font-size: 0.875rem; }}
        .kpi-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 20px;
            margin-bottom: 35px;
        }}
        .kpi-card {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            padding: 20px;
            text-align: center;
        }}
        .kpi-value {{
            font-size: 2rem;
            font-weight: 700;
            margin: 5px 0;
        }}
        .kpi-label {{
            color: var(--text-secondary);
            font-size: 0.875rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}
        .section-title {{
            font-size: 1.25rem;
            margin: 30px 0 15px;
            color: #fff;
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: var(--bg-card);
            border-radius: 8px;
            overflow: hidden;
            border: 1px solid var(--border-color);
            margin-bottom: 30px;
        }}
        th, td {{
            padding: 12px 16px;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }}
        th {{
            background: #111827;
            color: var(--text-secondary);
            font-weight: 600;
            font-size: 0.85rem;
            text-transform: uppercase;
        }}
        tr:hover {{
            background: #273549;
        }}
        .badge {{
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 600;
        }}
        .badge-success {{ background: rgba(16, 185, 129, 0.2); color: #34d399; border: 1px solid #10b981; }}
        .badge-muted {{ background: rgba(148, 163, 184, 0.1); color: #94a3b8; border: 1px solid #475569; }}
        .score-badge {{ font-weight: 700; }}
        .score-high {{ color: #34d399; }}
        .score-mid {{ color: #fbbf24; }}
        .score-low {{ color: #f87171; }}
        .findings-list {{ margin: 0; padding-left: 20px; font-size: 0.85rem; color: #fca5a5; }}
        .all-passed {{ color: #34d399; font-size: 0.875rem; }}
        code {{
            background: rgba(0, 0, 0, 0.4);
            padding: 2px 6px;
            border-radius: 4px;
            color: #93c5fd;
            font-size: 0.85rem;
        }}
        footer {{
            text-align: center;
            color: var(--text-secondary);
            font-size: 0.85rem;
            margin-top: 50px;
            border-top: 1px solid var(--border-color);
            padding-top: 20px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div>
                <h1>🛡️ Hardening IA - Enterprise Security & Governance Audit</h1>
                <div class="timestamp">Generated: {self.generated_at} (UTC)</div>
            </div>
            <div>
                <span class="badge badge-success">Enterprise Edition</span>
            </div>
        </header>

        <div class="kpi-grid">
            <div class="kpi-card">
                <div class="kpi-label">Global Compliance Score</div>
                <div class="kpi-value" style="color: {score_color};">{stats['global_score']}%</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-label">Target AI Tools</div>
                <div class="kpi-value" style="color: var(--accent-blue);">{stats['total_tools']}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-label">Installed on Host</div>
                <div class="kpi-value" style="color: #a855f7;">{stats['installed_tools']}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-label">Checks Passed / Failed</div>
                <div class="kpi-value" style="color: #fff;"><span style="color: var(--accent-green);">{stats['passed_checks']}</span> / <span style="color: var(--accent-red);">{stats['failed_checks']}</span></div>
            </div>
        </div>

        <div class="section-title">📊 Tool Compliance Audit Matrix (21 Unified Tools)</div>
        <table>
            <thead>
                <tr>
                    <th>AI Tool / Product</th>
                    <th>Host Status</th>
                    <th>Compliance Score</th>
                    <th>Audit Findings & Active Controls</th>
                </tr>
            </thead>
            <tbody>
                {tools_rows}
            </tbody>
        </table>

        <div class="section-title">🏛️ Governance Framework Compliance Mappings</div>
        <table>
            <thead>
                <tr>
                    <th>Security Control Domain</th>
                    <th>OWASP Top 10 for LLM (2025)</th>
                    <th>NIST AI RMF 1.0</th>
                    <th>ISO/IEC 42001:2023</th>
                    <th>Security Purpose</th>
                </tr>
            </thead>
            <tbody>
                {framework_rows}
            </tbody>
        </table>

        <footer>
            Hardening IA Framework | Autonomous Enterprise Security Suite for AI Development Environments
        </footer>
    </div>
</body>
</html>
"""
        return html_content

    def export_report(self, output_path: Path, report_format: str = "html") -> Path:
        """Exports compliance audit report to disk in specified format."""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        report_format = report_format.lower()

        if report_format == "html":
            content = self.generate_html()
        elif report_format == "sarif":
            content = self.generate_sarif()
        elif report_format == "json":
            content = self.generate_json()
        elif report_format in ("markdown", "md"):
            content = self.generate_markdown()
        else:
            raise ValueError(f"Unsupported report format: {report_format}. Choose html, sarif, json, or markdown.")

        output_path.write_text(content, encoding="utf-8")
        return output_path

    def _get_framework_mapping_for_key(self, key: str) -> Dict[str, Any]:
        """Matches setting key to corresponding governance framework domain."""
        lower_key = key.lower()
        if "telemetry" in lower_key or "analytics" in lower_key or "donottrack" in lower_key:
            return FRAMEWORK_MAPPINGS["telemetry"]
        if "sandbox" in lower_key or "terminal" in lower_key or "dangerouspaths" in lower_key:
            return FRAMEWORK_MAPPINGS["sandbox"]
        if "mcp" in lower_key:
            return FRAMEWORK_MAPPINGS["mcp"]
        if "dlp" in lower_key or "mask" in lower_key or "secrets" in lower_key:
            return FRAMEWORK_MAPPINGS["dlp"]
        if "subagent" in lower_key or "spawn" in lower_key:
            return FRAMEWORK_MAPPINGS["subagents"]
        if "approval" in lower_key or "permission" in lower_key or "consent" in lower_key or "confirm" in lower_key:
            return FRAMEWORK_MAPPINGS["approvals"]
        if "timeout" in lower_key or "rate_limit" in lower_key:
            return FRAMEWORK_MAPPINGS["rate_limits"]

        return {
            "owasp_llm": "LLM06: Excessive Agency",
            "nist_ai_rmf": "MANAGE-1.2 Risk Mitigation",
            "iso_42001": "A.8.4 Boundary Security",
            "description": "Baseline hardening control."
        }
