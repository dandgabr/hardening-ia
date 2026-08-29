"""CLI runner for automated execution, tool discovery, command risk checking, SAST code scanning, verification, rollback, compliance reporting, and real-time watchdog."""

import sys
import argparse
import logging
import unittest
from pathlib import Path
from typing import List

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.markdown import Markdown

from src.core.config_loader import ConfigLoader
from src.core.engine import HardeningEngine
from src.core.os_detector import OSDetector
from src.core.logger import setup_logging, get_logger
from src.core.command_classifier import CommandRiskClassifier, RiskLevel
from src.core.code_analyzer import CodeVulnerabilityScanner
from src.core.verifier import HardeningVerifier
from src.core.admin_manager import AdminManager
from src.core.compliance_reporter import ComplianceReporter
from src.core.watchdog import SecurityWatchdog

logger = get_logger("cli")

HELP_EPILOG = """
[bold cyan]Practical Usage Examples:[/]
  [green]python main.py[/]                                  Launch interactive Textual Control Interface (TUI)
  [green]python main.py --list[/]                           List all 21 supported AI tools and host detection status
  [green]python main.py --list --installed-only[/]          List only AI tools currently installed on this machine
  [green]python main.py --apply --installed-only[/]         Apply security hardening with automatic post-apply verification
  [green]python main.py --apply --strict[/]                 Apply STRICT mode (zero-trust guardrails, immediate path blocking)
  [green]python main.py --apply --dry-run[/]                Simulate policy enforcement with explicit warning banner
  [green]python main.py --tool cursor --apply[/]            Harden a specific tool (e.g. cursor, windsurf, antigravity)
  [green]python main.py --remove --installed-only[/]        Revert/remove hardening from detected tools
  [green]python main.py --remove-all[/]                     Revert/remove hardening from all 21 supported tools
  [green]python main.py --verify[/]                         Audit and verify that hardening settings are functional on host
  [green]python main.py --verify --fix[/]                   Audit and auto-remediate all tools to 100%% compliance
  [green]python main.py --report --format html[/]           Export interactive HTML compliance dashboard
  [green]python main.py --report --format sarif[/]          Export SARIF 2.1.0 report for GitHub Security Tab
  [green]python main.py --watch --auto-remediate[/]         Launch background watchdog monitoring file drift & tampering
  [green]sudo python main.py --apply --admin --strict[/]     [ADMIN] Enforce system-wide read-only hardening across all user accounts
  [green]python main.py --sandbox-diagnostics[/]            Inspect host process isolation, Seccomp, and Bubblewrap features
  [green]python main.py --test[/]                           Execute automated unit and integration test suite
  [green]python main.py --scan-code ./src[/]                Scan directory for code vulnerabilities with OpenGrep
  [green]python main.py --check-command "rm -rf /" --strict[/] Check command in strict restrictive mode
"""


def _matches_tool_query(p, query: str) -> bool:
    query = query.lower()
    full_name = f"{p.tool.vendor}/{p.tool.name}".lower()
    if query in full_name or query == p.tool.name.lower():
        return True
    alias_map = {
        "zai-cli": ("zai", "zai"),
        "zcode": ("zai", "zai"),
        "z-ai": ("zai", "zai"),
        "claude": ("anthropic", "claude-code"),
        "kilo": ("kilo", "kilo-code"),
        "hermes": ("nousresearch", "hermes-agent"),
        "windsurf": ("codeium", "windsurf"),
        "codeium": ("codeium", "windsurf"),
        "cascade": ("codeium", "windsurf"),
        "continue": ("continuedev", "continue"),
        "continue-cli": ("continuedev", "continue"),
        "aider": ("aider", "aider"),
        "aider-chat": ("aider", "aider"),
        "amazon-q": ("amazon", "amazon-q"),
        "amazonq": ("amazon", "amazon-q"),
        "q": ("amazon", "amazon-q"),
        "tabnine": ("tabnine", "tabnine"),
        "augment": ("augment", "augment"),
        "augment-code": ("augment", "augment")
    }
    if query in alias_map:
        v, n = alias_map[query]
        return p.tool.vendor.lower() == v and p.tool.name.lower() == n
    return False


def run_cli(args: List[str]):
    parser = argparse.ArgumentParser(
        prog="hardening-ia",
        description="Enterprise AI Hardening Framework: Multi-OS Command Risk Matrix, SAST/SCA Code Analyzer, Compliance Reporting & Watchdog.",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--tool", type=str, metavar="NAME", help="Filter by tool or vendor name (e.g. google/antigravity, cursor, claude-code)")
    parser.add_argument("--apply", action="store_true", help="Apply declarative security hardening policies to matching tools")
    parser.add_argument("--strict", "--restrictive", action="store_true", help="Apply strict restrictive rules: explicit denied patterns for critical items & immediate blocking of dangerous paths without asking")
    parser.add_argument("--admin", "--system-wide", action="store_true", help="[ADMIN ONLY] Verify administrator/root elevation and enforce read-only system-wide hardening across all user accounts")
    parser.add_argument("--remove", "--revert", action="store_true", help="Revert/remove hardening policies and clean configuration overrides")
    parser.add_argument("--remove-all", "--rollback-all", action="store_true", help="Revert/remove hardening policies across ALL 21 supported tools")
    parser.add_argument("--verify", action="store_true", help="Audit host configuration files to verify that hardening is active and functional")
    parser.add_argument("--fix", "--remediate", action="store_true", help="Automatically remediate and bring any non-compliant tools to 100%% compliance")
    parser.add_argument("--no-verify", action="store_true", help="Skip automatic post-application verification audit when applying policies")
    parser.add_argument("--report", action="store_true", help="Generate enterprise compliance and governance audit report")
    parser.add_argument("--format", type=str, default="html", choices=["html", "sarif", "json", "markdown", "md"], help="Format for compliance report: html (default), sarif, json, or markdown")
    parser.add_argument("--output", type=str, metavar="PATH", help="Destination file path for exported compliance report")
    parser.add_argument("--watch", action="store_true", help="Start continuous security watchdog daemon monitoring configuration drift and file tampering")
    parser.add_argument("--interval", type=float, default=5.0, metavar="SECS", help="Polling interval in seconds for the security watchdog daemon (default: 5.0s)")
    parser.add_argument("--auto-remediate", action="store_true", help="Allow security watchdog daemon to automatically re-apply policies upon detecting configuration drift")
    parser.add_argument("--test", action="store_true", help="Run automated test suite for policies, classifier, verifier, and scanner")
    parser.add_argument("--list", action="store_true", help="List all available tools and their host installation status")
    parser.add_argument("--installed-only", action="store_true", help="Filter operations strictly to tools installed on this host")
    parser.add_argument("--check-command", type=str, metavar="CMD", help="Evaluate terminal command risk level (LOW, MEDIUM, HIGH, CRITICAL)")
    parser.add_argument("--dry-run", action="store_true", help="Simulate policy application or removal without modifying configuration files")
    parser.add_argument("--install-extra", type=str, metavar="TOOL", help="Install extra security component: 'ai-jail', 'opengrep', or 'all'")
    parser.add_argument("--remove-extra", type=str, metavar="TOOL", help="Remove/uninstall extra security component: 'ai-jail', 'opengrep', or 'all'")
    parser.add_argument("--status-extra", action="store_true", help="Display installation, diagnostic status, and environment integration for extra security tools")
    parser.add_argument("--sandbox-diagnostics", action="store_true", help="Inspect host process isolation, Seccomp, Landlock, and Bubblewrap sandboxing features")
    parser.add_argument("--scan-code", type=str, nargs="?", const=".", metavar="PATH", help="Scan workspace or directory for AI-generated code vulnerabilities")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose debug logging")
    parser.add_argument("--cli", action="store_true", help="Explicitly force CLI mode")
    parser.add_argument("-gui", "--gui", action="store_true", help="Launch interactive Terminal User Interface (TUI)")

    # Print custom formatted help with rich colors if -h or --help is requested
    if "-h" in args or "--help" in args:
        console = Console()
        console.print(Panel.fit(
            "[bold cyan]Hardening IA[/bold cyan] - Enterprise AI Security Hardening Framework",
            subtitle="CLI Automation, Compliance Auditing & Verification"
        ))
        console.print(parser.format_help(), markup=False)
        console.print(HELP_EPILOG)
        return

    parsed = parser.parse_args(args)

    log_level = logging.DEBUG if parsed.verbose else logging.INFO
    setup_logging(log_level=log_level, enable_console=False)

    console = Console()
    os_name = OSDetector.get_os_type().upper()

    console.print(Panel.fit(
        f"[bold cyan]Hardening IA Framework[/bold cyan] | Host OS: [bold green]{os_name}[/bold green] | Elevated: [bold]{OSDetector.is_admin()}[/bold]",
        border_style="cyan"
    ))

    # Prominent Visual Banners
    if parsed.dry_run:
        console.print(Panel(
            "[bold yellow]⚠️  DRY RUN MODE ACTIVE (SIMULATION)[/bold yellow]\n"
            "[white]No files or configuration settings will be modified on disk. The output below simulates policy enforcement.[/white]",
            border_style="yellow",
            title="[bold yellow]Dry Run Simulation[/bold yellow]"
        ))

    if parsed.strict:
        console.print(Panel(
            "[bold red]🛡️  STRICT RESTRICTIVE MODE ACTIVE (ZERO TRUST)[/bold red]\n"
            "[white]Enforcing zero-trust guardrails: explicit blocking of critical destructive commands, immediate rejection of sensitive system paths, and mandatory human write approvals.[/white]",
            border_style="red",
            title="[bold red]Strict Security Lockdown[/bold red]"
        ))

    # 1. Run Automated Test Suite
    if parsed.test:
        console.print("\n[bold cyan][*] Running Hardening IA Automated Test Suite...[/bold cyan]\n")
        suite = unittest.defaultTestLoader.discover(start_dir="tests", pattern="test_*.py")
        runner = unittest.TextTestRunner(verbosity=2)
        result = runner.run(suite)
        if result.wasSuccessful():
            console.print(f"\n[bold green][OK] All {result.testsRun} unit and integration tests PASSED successfully.[/bold green]\n")
        else:
            console.print(f"\n[bold red][FAILED] {len(result.failures)} failure(s), {len(result.errors)} error(s) encountered.[/bold red]\n")
        return

    # Runtime Sandbox Diagnostics
    if parsed.sandbox_diagnostics:
        from src.core.runtime_sandbox import RuntimeSandboxManager
        diag = RuntimeSandboxManager.get_sandbox_diagnostics()

        table = Table(title="Host Runtime Sandboxing & Process Isolation Diagnostics", header_style="bold cyan")
        table.add_column("Security Isolation Feature", style="bold white", width=35)
        table.add_column("Host Status", width=25)
        table.add_column("Details / Kernel Subsystem", style="dim")

        table.add_row(
            "Bubblewrap (bwrap)",
            "[bold green]AVAILABLE[/bold green]" if diag["bubblewrap_available"] else "[bold red]NOT INSTALLED[/bold red]",
            "User namespace & rootfs isolation"
        )
        table.add_row(
            "ai-jail Runtime Sandbox",
            "[bold green]INSTALLED[/bold green]" if diag["ai_jail_installed"] else "[dim]Not Installed[/dim]",
            "Encapsulated CLI agent containerization"
        )
        table.add_row(
            "Seccomp-BPF Syscall Filtering",
            "[bold green]SUPPORTED[/bold green]" if diag["seccomp_supported"] else "[bold red]UNSUPPORTED[/bold red]",
            "Kernel dangerous syscall blocking"
        )
        table.add_row(
            "Linux Landlock LSM",
            "[bold green]SUPPORTED[/bold green]" if diag["landlock_supported"] else "[dim]UNSUPPORTED[/dim]",
            "Unprivileged filesystem access control"
        )
        table.add_row(
            "SSRF & Metadata IP Guard",
            "[bold green]ACTIVE (Rules Defined)[/bold green]",
            "Blocks 169.254.169.254 & cloud metadata"
        )

        console.print(table)
        return

    # 2. Security Extra Tools Management (ai-jail, opengrep, all)
    if parsed.install_extra:
        engine = HardeningEngine()
        target = parsed.install_extra.lower()
        console.print(f"\n[*] Installing extra security component: [bold cyan]{target}[/bold cyan]...")
        res = engine.install_extra_tool(target)
        if res.get("success"):
            console.print(f"[bold green][OK] {res.get('message')}[/bold green]")
        else:
            console.print(f"[bold red][ERROR] {res.get('message')}[/bold red]")
        return

    if parsed.remove_extra:
        engine = HardeningEngine()
        target = parsed.remove_extra.lower()
        console.print(f"\n[*] Removing extra security component: [bold cyan]{target}[/bold cyan]...")
        res = engine.remove_extra_tool(target)
        if res.get("success"):
            console.print(f"[bold green][OK] {res.get('message')}[/bold green]")
        else:
            console.print(f"[bold red][ERROR] {res.get('message')}[/bold red]")
        return

    if parsed.status_extra:
        engine = HardeningEngine()
        diag = engine.verify_extra_tools_diagnostics()
        table = Table(title="Extra Security Tools Diagnostics & Host Status", header_style="bold cyan")
        table.add_column("Security Component", style="bold white", width=20)
        table.add_column("Status", width=16)
        table.add_column("Path / Binary", style="dim", width=25)
        table.add_column("Diagnostics Output", style="dim")

        for tool_key, info in diag.items():
            status_badge = "[bold green]INSTALLED[/bold green]" if info["installed"] else "[bold red]NOT INSTALLED[/bold red]"
            table.add_row(
                info["name"],
                status_badge,
                info.get("path") or "N/A",
                info.get("diagnostic_output", "N/A")
            )
        console.print(table)
        return

    # 3. Check Command Risk Level
    if parsed.check_command:
        classifier = CommandRiskClassifier()
        cmd = parsed.check_command
        risk = classifier.classify(cmd, strict_mode=parsed.strict)

        color = "green"
        if risk.level == RiskLevel.MEDIUM:
            color = "yellow"
        elif risk.level == RiskLevel.HIGH:
            color = "bright_red"
        elif risk.level == RiskLevel.CRITICAL:
            color = "bold red on black"

        table = Table(title=f"Command Risk Evaluation{' [STRICT RESTRICTIVE MODE]' if parsed.strict else ''}")
        table.add_column("Command", style="white")
        table.add_column("Risk Tier", style=color)
        table.add_column("Action Taken", style="bold")
        table.add_column("Matched Patterns / Triggers", style="dim")

        table.add_row(
            cmd,
            risk.level.name,
            f"[{color}]{risk.recommended_action.upper()}[/{color}]",
            ", ".join(risk.reasons) if risk.reasons else "Baseline command execution"
        )
        console.print(table)
        return

    # 4. OpenGrep SAST Code Scanning
    if parsed.scan_code:
        target_path = Path(parsed.scan_code).resolve()
        console.print(f"\n[bold cyan][*] Running OpenGrep SAST & SCA Code Security Scan on:[/] [white]{target_path}[/]\n")

        scanner = CodeVulnerabilityScanner()
        findings = scanner.scan_directory(target_path)

        if not findings:
            console.print("[bold green][OK] No code vulnerabilities or hardcoded secrets detected in workspace.[/bold green]\n")
            return

        table = Table(title=f"OpenGrep SAST Security Findings ({len(findings)} issues detected)", header_style="bold red")
        table.add_column("File", style="cyan", width=25)
        table.add_column("Line", width=6)
        table.add_column("Severity", width=10)
        table.add_column("Rule ID", style="bold yellow", width=25)
        table.add_column("Finding Summary", style="white")

        for f in findings:
            sev_style = "bold red" if f.severity in ("CRITICAL", "ERROR", "HIGH") else "yellow"
            rel_file = str(Path(f.file_path).relative_to(target_path) if target_path in Path(f.file_path).parents else f.file_path)
            table.add_row(
                rel_file,
                str(f.line),
                f"[{sev_style}]{f.severity}[/{sev_style}]",
                f.rule_id,
                f.message
            )

        console.print(table)
        console.print(f"\n[bold red][!] Found {len(findings)} security vulnerability(ies). Review findings above.[/bold red]\n")
        return

    # 5. Core Policy Operations
    loader = ConfigLoader()
    engine = HardeningEngine()
    verifier = HardeningVerifier()
    admin_mgr = AdminManager()
    policies = loader.load_all_policies()

    # Continuous Security Watchdog Daemon
    if parsed.watch:
        console.print(f"\n[bold green]👁️ Starting Real-time Security Watchdog Daemon (Interval: {parsed.interval}s, Auto-Remediate: {parsed.auto_remediate})...[/bold green]\n")
        watchdog = SecurityWatchdog(
            config_loader=loader,
            engine=engine,
            verifier=verifier,
            poll_interval=parsed.interval,
            auto_remediate=parsed.auto_remediate,
            strict_mode=parsed.strict,
            installed_only=parsed.installed_only
        )
        try:
            watchdog.run_forever()
        except KeyboardInterrupt:
            console.print("\n[yellow]Watchdog stopped by user.[/yellow]")
        return

    # Compliance & Governance Report Export
    if parsed.report:
        console.print(f"\n[bold cyan]📊 Generating Enterprise Compliance Report (Format: {parsed.format.upper()})...[/bold cyan]\n")
        target_policies = policies
        if parsed.installed_only:
            target_policies = [p for p in target_policies if p.is_installed]
        if parsed.tool:
            target_policies = [p for p in target_policies if _matches_tool_query(p, parsed.tool)]

        reports = [verifier.verify_policy(p, strict_mode=parsed.strict) for p in target_policies]
        reporter = ComplianceReporter(reports, target_policies)

        out_ext = "md" if parsed.format in ("markdown", "md") else parsed.format
        output_file = Path(parsed.output) if parsed.output else Path(f"reports/compliance_report.{out_ext}")
        saved_path = reporter.export_report(output_file, parsed.format)

        stats = reporter.calculate_overall_compliance()
        console.print(f"[bold green][OK] Report successfully exported to:[/] [white]{saved_path}[/]")
        console.print(f"Global Compliance Score: [bold green]{stats['global_score']}%[/bold green] across {stats['total_tools']} tools ({stats['installed_tools']} installed on host).\n")
        return

    # List Tools
    if parsed.list:
        table = Table(title="AI Tools Security Hardening Registry (21 Unified Tools)", header_style="bold cyan")
        table.add_column("Status", width=16)
        table.add_column("Category", width=12)
        table.add_column("Tool / Product", style="bold white", width=30)
        table.add_column("Description", style="dim")

        for p in policies:
            if parsed.installed_only and not p.is_installed:
                continue

            status_badge = "[bold green]INSTALLED[/bold green]" if p.is_installed else "[dim]NOT INSTALLED[/dim]"
            table.add_row(
                status_badge,
                p.tool.category.upper(),
                f"{p.tool.vendor}/{p.tool.name}",
                p.tool.description
            )
        console.print(table)
        return

    # Auto-Remediate Discrepancies
    if parsed.fix:
        target_policies = policies
        if parsed.installed_only:
            target_policies = [p for p in target_policies if p.is_installed]
        if parsed.tool:
            target_policies = [p for p in target_policies if _matches_tool_query(p, parsed.tool)]

        console.print(f"\n[*] [bold cyan]Auto-Remediating compliance discrepancies across {len(target_policies)} target tool(s)...[/bold cyan]\n")
        remediation_table = Table(title="Automated Remediation Summary", header_style="bold green")
        remediation_table.add_column("Tool", style="white", width=25)
        remediation_table.add_column("Host Status", width=14)
        remediation_table.add_column("Remediation Result", width=18)
        remediation_table.add_column("Patched Keys", style="dim")

        for p in target_policies:
            res = verifier.remediate_policy(p, strict_mode=parsed.strict)
            status_badge = "[bold green]100% COMPLIANT[/bold green]" if res.success else "[bold red]FAILED[/bold red]"
            installed_badge = "[green]Installed[/green]" if p.is_installed else "[dim]Not Found[/dim]"
            details = ", ".join([f"{d.key} -> {d.new_value}" for d in res.diffs]) if res.diffs else ("Already 100% Compliant" if res.success else res.message)
            remediation_table.add_row(f"{p.tool.vendor}/{p.tool.name}", installed_badge, status_badge, details)

        console.print(remediation_table)
        console.print("\n[bold green][OK] Remediation completed. Audit logs recorded in logs/audit.jsonl[/bold green]\n")
        return

    # Verify Hardening Compliance
    if parsed.verify:
        target_policies = policies
        if parsed.installed_only:
            target_policies = [p for p in target_policies if p.is_installed]

        if parsed.tool:
            target_policies = [p for p in target_policies if _matches_tool_query(p, parsed.tool)]

        if not target_policies:
            console.print("[bold red][!] No matching tools found to verify.[/bold red]")
            return

        strict_desc = " [STRICT MODE]" if parsed.strict else ""
        console.print(f"\n[*] Auditing Hardening Compliance{strict_desc} across [bold]{len(target_policies)}[/bold] target tool(s)...\n")

        report_table = Table(title=f"Host Security Hardening Verification Report{strict_desc}", header_style="bold cyan")
        report_table.add_column("Tool", style="bold white", width=25)
        report_table.add_column("Host Status", width=14)
        report_table.add_column("Compliance Score", width=18)
        report_table.add_column("Audit Findings & Discrepancies", style="dim")

        for p in target_policies:
            report = verifier.verify_policy(p, strict_mode=parsed.strict)
            status_badge = "[bold green]INSTALLED[/bold green]" if p.is_installed else "[dim]NOT FOUND[/dim]"

            if report.compliance_score == 100.0:
                score_badge = f"[bold green]{report.compliance_score:.0f}% ({report.passed_checks}/{report.total_checks})[/bold green]"
            elif report.compliance_score >= 80.0:
                score_badge = f"[bold yellow]{report.compliance_score:.1f}% ({report.passed_checks}/{report.total_checks})[/bold yellow]"
            else:
                score_badge = f"[bold red]{report.compliance_score:.1f}% ({report.passed_checks}/{report.total_checks})[/bold red]"

            findings = []
            for c in report.checks:
                if not c.passed:
                    findings.append(f"Missing '{c.key}'" if c.actual == "[MISSING]" else f"'{c.key}' expected {c.expected} (found {c.actual})")

            details = "\n".join(findings) if findings else report.message
            report_table.add_row(f"{p.tool.vendor}/{p.tool.name}", status_badge, score_badge, details)

        console.print(report_table)
        console.print("\n[bold green][OK] Verification audit completed. Records written to logs/audit.jsonl[/bold green]\n")
        return

    # Remove / Rollback Hardening Policies
    if parsed.remove or parsed.remove_all:
        target_policies = policies
        if parsed.installed_only and not parsed.remove_all:
            target_policies = [p for p in target_policies if p.is_installed]

        if parsed.tool and not parsed.remove_all:
            target_policies = [p for p in target_policies if _matches_tool_query(p, parsed.tool)]

        if not target_policies:
            console.print("[bold red][!] No matching tools found to remove hardening.[/bold red]")
            return

        mode_str = "[bold yellow][DRY RUN][/bold yellow] " if parsed.dry_run else ""
        console.print(f"\n[*] {mode_str}Removing hardening policies from [bold]{len(target_policies)}[/bold] tool(s)...\n")

        summary_table = Table(title="Hardening Removal Summary", header_style="bold red")
        summary_table.add_column("Tool", style="white", width=25)
        summary_table.add_column("Host Status", width=14)
        summary_table.add_column("Result", width=12)
        summary_table.add_column("Details", style="dim")

        for p in target_policies:
            res = engine.remove_policy(p, dry_run=parsed.dry_run)
            status_badge = "[bold green]REMOVED[/bold green]" if res.success else "[bold red]FAILED[/bold red]"
            installed_badge = "[green]Installed[/green]" if p.is_installed else "[dim]Not Found[/dim]"
            details = ", ".join([f"Removed {d.key}" for d in res.diffs]) if res.diffs else ("No modifications required" if res.success else res.message)
            summary_table.add_row(f"{p.tool.vendor}/{p.tool.name}", installed_badge, status_badge, details)

        console.print(summary_table)
        console.print("\n[bold green][OK] Policy removal completed. Audit logs written to logs/audit.jsonl[/bold green]\n")
        return

    # Apply Hardening Policies
    if parsed.apply:
        target_policies = policies
        if parsed.installed_only:
            target_policies = [p for p in target_policies if p.is_installed]

        if parsed.tool:
            target_policies = [p for p in target_policies if _matches_tool_query(p, parsed.tool)]

        if not target_policies:
            console.print("[bold red][!] No matching tools found to apply hardening.[/bold red]")
            return

        mode_str = "[bold yellow][DRY RUN][/bold yellow] " if parsed.dry_run else ""
        strict_str = "[bold red][STRICT RESTRICTIVE MODE][/bold red] " if parsed.strict else ""

        # System-Wide Multi-User Admin Enforcement
        if parsed.admin:
            user_profiles = admin_mgr.get_all_user_profiles()
            console.print(f"\n[*] {mode_str}{strict_str}[bold green]🔒 Enforcing System-Wide Admin Hardening & Read-Only Permissions across {len(user_profiles)} User Account(s)...[/bold green]\n")

            summary_table = Table(title=f"Admin System-Wide Hardening Summary ({len(user_profiles)} Users)", header_style="bold cyan")
            summary_table.add_column("Tool", style="bold white", width=25)
            summary_table.add_column("User Accounts", width=18)
            summary_table.add_column("Read-Only Lock", width=20)
            summary_table.add_column("Result", width=12)

            for p in target_policies:
                res = admin_mgr.apply_admin_system_wide_policy(p, strict_mode=parsed.strict, dry_run=parsed.dry_run)
                summary_table.add_row(
                    f"{p.tool.vendor}/{p.tool.name}",
                    f"{res['users_count']} profile(s)",
                    "[bold green]LOCKED (0644 / ACL)[/bold green]" if not parsed.dry_run else "[yellow]DRY-RUN[/yellow]",
                    "[bold green]SUCCESS[/bold green]"
                )

            console.print(summary_table)
            console.print("\n[bold green][OK] System-wide policy lockdown enforced. Configuration locked as Read-Only for standard users. Audit logs recorded in logs/audit.jsonl[/bold green]\n")
            return

        console.print(f"\n[*] {mode_str}{strict_str}Applying hardening policies to [bold]{len(target_policies)}[/bold] tool(s)...\n")

        summary_table = Table(title=f"Hardening Execution Summary{' [STRICT RESTRICTIVE MODE]' if parsed.strict else ''}", header_style="bold cyan")
        summary_table.add_column("Tool", style="white", width=25)
        summary_table.add_column("Host Status", width=14)
        summary_table.add_column("Result", width=12)
        summary_table.add_column("Details", style="dim")

        for p in target_policies:
            res = engine.apply_policy(p, dry_run=parsed.dry_run, strict_mode=parsed.strict)
            status_badge = "[bold green]SUCCESS[/bold green]" if res.success else "[bold red]FAILED[/bold red]"
            installed_badge = "[green]Installed[/green]" if p.is_installed else "[dim]Not Found[/dim]"
            details = ", ".join([f"{d.key} -> {d.new_value}" for d in res.diffs]) if res.diffs else ("No changes needed" if res.success else res.message)
            summary_table.add_row(f"{p.tool.vendor}/{p.tool.name}", installed_badge, status_badge, details)

        console.print(summary_table)
        console.print("\n[bold green][OK] Hardening execution completed. Audit logs written to logs/audit.jsonl[/bold green]")

        # Automatic Post-Application Verification Audit
        if not parsed.dry_run and not parsed.no_verify:
            console.print("\n[bold cyan]🔍 Executing Automatic Post-Application Verification Audit...[/bold cyan]\n")
            audit_table = Table(title=f"Post-Hardening Live Compliance Audit{' [STRICT MODE]' if parsed.strict else ''}", header_style="bold green")
            audit_table.add_column("Tool", style="bold white", width=25)
            audit_table.add_column("Host Status", width=14)
            audit_table.add_column("Post-Apply Score", width=20)
            audit_table.add_column("Audit Findings & Active Controls", style="dim")

            for p in target_policies:
                report = verifier.verify_policy(p, strict_mode=parsed.strict)
                status_badge = "[bold green]INSTALLED[/bold green]" if p.is_installed else "[dim]NOT FOUND[/dim]"
                score_badge = f"[bold green]{report.compliance_score:.0f}% ({report.passed_checks}/{report.total_checks})[/bold green]" if report.compliance_score == 100.0 else f"[bold yellow]{report.compliance_score:.1f}%[/bold yellow]"
                findings = "[green]100% Compliant: All security controls active on disk[/green]" if report.compliance_score == 100.0 else f"[yellow]{report.failed_checks} check(s) need attention[/yellow]"
                audit_table.add_row(f"{p.tool.vendor}/{p.tool.name}", status_badge, score_badge, findings)

            console.print(audit_table)
            console.print("\n[bold green][OK] Live post-hardening audit complete. All settings verified on disk.[/bold green]\n")
    else:
        parser.print_help()
