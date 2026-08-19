"""CLI runner for automated execution, tool discovery, command risk checking, SAST code scanning, verification, and Rich reporting."""

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

logger = get_logger("cli")

HELP_EPILOG = """
[bold cyan]Practical Usage Examples:[/]
  [green]python main.py[/]                              Launch interactive Textual Control Interface (TUI)
  [green]python main.py --list[/]                       List all 14 supported AI tools and host detection status
  [green]python main.py --list --installed-only[/]      List only AI tools currently installed on this machine
  [green]python main.py --apply --installed-only[/]     Apply security hardening to detected tools
  [green]python main.py --tool cursor --apply[/]        Harden a specific tool (e.g. cursor, antigravity)
  [green]python main.py --apply --dry-run[/]            Simulate policy enforcement without writing files
  [green]python main.py --verify[/]                     Verify that hardening settings are functional on host
  [green]python main.py --verify --installed-only[/]    Verify compliance only for installed tools
  [green]python main.py --test[/]                       Execute automated unit and integration test suite
  [green]python main.py --scan-code[/]                  Run OpenGrep SAST & SCA scan on current workspace
  [green]python main.py --scan-code ./src[/]            Scan a specific directory for code vulnerabilities
  [green]python main.py --check-command "ls -la"[/]     Evaluate command risk tier (LOW/MEDIUM/HIGH/CRITICAL)
  [green]python main.py --install-extra all[/]          Install runtime sandboxes (ai-jail) and OpenGrep
"""


def run_cli(args: List[str]):
    parser = argparse.ArgumentParser(
        prog="hardening-ia",
        description="Enterprise AI Hardening Framework: Multi-OS Command Risk Matrix, SAST/SCA Code Analyzer & Tool Discovery.",
        epilog=HELP_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--tool", type=str, metavar="NAME", help="Filter by tool or vendor name (e.g. google/antigravity, cursor, claude-code)")
    parser.add_argument("--apply", action="store_true", help="Apply declarative security hardening policies to matching tools")
    parser.add_argument("--verify", action="store_true", help="Audit host configuration files to verify that hardening is active and functional")
    parser.add_argument("--test", action="store_true", help="Run automated test suite for policies, classifier, verifier, and scanner")
    parser.add_argument("--list", action="store_true", help="List all available tools and their host installation status")
    parser.add_argument("--installed-only", action="store_true", help="Filter operations strictly to tools installed on this host")
    parser.add_argument("--check-command", type=str, metavar="CMD", help="Evaluate terminal command risk level (LOW, MEDIUM, HIGH, CRITICAL)")
    parser.add_argument("--dry-run", action="store_true", help="Simulate policy application without modifying configuration files")
    parser.add_argument("--install-extra", type=str, metavar="TOOL", help="Install extra security isolation tool: 'ai-jail', 'opengrep', or 'all'")
    parser.add_argument("--scan-code", type=str, nargs="?", const=".", metavar="PATH", help="Scan workspace or directory for AI-generated code vulnerabilities")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose debug logging")
    parser.add_argument("--cli", action="store_true", help="Explicitly force CLI mode")
    parser.add_argument("-gui", "--gui", action="store_true", help="Launch interactive Terminal User Interface (TUI)")

    # Print custom formatted help if -h or --help is requested
    if "-h" in args or "--help" in args:
        console = Console()
        console.print(Panel.fit(
            "[bold cyan]Hardening IA[/bold cyan] - Enterprise AI Security Hardening Framework",
            subtitle="CLI Automation, Compliance Auditing & Verification"
        ))
        parser.print_help()
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

    # 2. Evaluate command risk if requested
    if parsed.check_command:
        risk, requires_approval, reason = CommandRiskClassifier.classify_command(parsed.check_command)
        color = {
            RiskLevel.LOW: "green",
            RiskLevel.MEDIUM: "yellow",
            RiskLevel.HIGH: "bright_red",
            RiskLevel.CRITICAL: "bold red"
        }.get(risk, "white")

        console.print(Panel(
            f"[bold]Command:[/] `{parsed.check_command}`\n"
            f"[bold]Risk Level:[/] [{color}]{risk.value}[/{color}]\n"
            f"[bold]Requires Approval:[/] {'[bold yellow]YES[/bold yellow]' if requires_approval else '[bold green]NO (Auto-executable)[/bold green]'}\n"
            f"[bold]Policy Rule:[/] {reason}",
            title=f"{os_name} Command Risk Evaluation",
            border_style=color
        ))
        return

    # 3. SAST Code Vulnerability Scan
    if parsed.scan_code:
        scan_target = Path(parsed.scan_code)
        console.print(f"\n[bold cyan][*] Running OpenGrep SAST & SCA Analysis on:[/] {scan_target.resolve()}\n")
        scanner = CodeVulnerabilityScanner()
        findings = scanner.scan_path(scan_target)

        if not findings:
            console.print("[bold green][OK] Zero vulnerabilities or secret leaks detected in target codebase.[/bold green]\n")
            return

        table = Table(title=f"Security Vulnerabilities Detected ({len(findings)})", header_style="bold red")
        table.add_column("Rule / Title", style="bold white", width=25)
        table.add_column("Location", style="cyan", width=30)
        table.add_column("Severity", width=12)
        table.add_column("Remediation / Fix", style="yellow")

        for f in findings:
            sev = f.get("severity", "WARNING").upper()
            sev_style = "bold red" if sev in ("CRITICAL", "HIGH", "ERROR") else "bold yellow"
            loc = f"{f.get('file')}:{f.get('line')}"
            table.add_row(
                f"{f.get('rule_id')}\n[dim]{f.get('title', '')}[/dim]",
                loc,
                f"[{sev_style}]{sev}[/{sev_style}]",
                f.get("remediation", "")
            )

        console.print(table)
        console.print(f"\n[bold yellow][!] {len(findings)} vulnerability finding(s) recorded in logs/audit.jsonl[/bold yellow]\n")
        return

    loader = ConfigLoader()
    engine = HardeningEngine()
    verifier = HardeningVerifier()
    policies = loader.discover_policies()

    # 4. Verify Applied Configurations
    if parsed.verify:
        target_policies = policies
        if parsed.installed_only:
            target_policies = [p for p in target_policies if p.is_installed]

        if parsed.tool:
            query = parsed.tool.lower()
            target_policies = [
                p for p in target_policies
                if query in f"{p.tool.vendor}/{p.tool.name}".lower() or query == p.tool.name.lower()
            ]

        console.print(f"\n[bold cyan][*] Auditing Hardening Compliance across {len(target_policies)} target tool(s)...[/bold cyan]\n")

        table = Table(title="Host Security Hardening Verification Report", header_style="bold magenta")
        table.add_column("Tool", style="bold white", width=25)
        table.add_column("Host Status", width=14)
        table.add_column("Compliance Score", width=18)
        table.add_column("Audit Findings & Discrepancies", style="dim")

        for p in target_policies:
            report = verifier.verify_policy(p)
            installed_badge = "[bold green]INSTALLED[/bold green]" if p.is_installed else "[dim]NOT FOUND[/dim]"

            if report.compliance_score == 100.0:
                score_badge = f"[bold green]100% ({report.passed_checks}/{report.total_checks})[/bold green]"
            elif report.compliance_score > 0:
                score_badge = f"[bold yellow]{report.compliance_score:.1f}% ({report.passed_checks}/{report.total_checks})[/bold yellow]"
            else:
                score_badge = "[dim]N/A[/dim]" if not report.settings_file_exists else "[bold red]0% (0/0)[/bold red]"

            discrepancies = [f"Missing '{c.key}'" for c in report.checks if not c.passed]
            details = ", ".join(discrepancies) if discrepancies else report.message

            table.add_row(f"{p.tool.vendor}/{p.tool.name}", installed_badge, score_badge, details)

        console.print(table)
        console.print("\n[bold green][OK] Verification audit completed. Records written to logs/audit.jsonl[/bold green]\n")
        return

    if parsed.list:
        table = Table(title="AI Tools Catalog & Host Detection", header_style="bold magenta")
        table.add_column("Status", width=15)
        table.add_column("Category", style="cyan", width=10)
        table.add_column("Vendor / Tool", style="bold white", width=28)
        table.add_column("Description", style="dim")

        for p in policies:
            if parsed.installed_only and not p.is_installed:
                continue

            status = "[bold green]INSTALLED[/bold green]" if p.is_installed else "[dim]NOT INSTALLED[/dim]"
            table.add_row(
                status,
                p.tool.category.upper(),
                f"{p.tool.vendor}/{p.tool.name}",
                p.tool.description
            )
        console.print(table)
        return

    if parsed.install_extra:
        tools_to_install = ["ai-jail", "opengrep"] if parsed.install_extra.lower() == "all" else [parsed.install_extra]
        for t in tools_to_install:
            console.print(f"\n[bold yellow][*] Installing extra security component:[/] {t}...")
            success = engine.install_extra_tool(t)
            if success:
                console.print(f"[bold green][OK] Extra tool '{t}' installed successfully.[/bold green]\n")
            else:
                console.print(f"[bold red][!] Installation script for '{t}' failed or not found for {os_name}.[/bold red]\n")
        return

    if parsed.apply:
        target_policies = policies
        if parsed.installed_only:
            target_policies = [p for p in target_policies if p.is_installed]

        if parsed.tool:
            query = parsed.tool.lower()
            target_policies = [
                p for p in target_policies
                if query in f"{p.tool.vendor}/{p.tool.name}".lower() or query == p.tool.name.lower()
            ]

        if not target_policies:
            console.print(f"[bold red][!] No matching tools found to apply hardening.[/bold red]")
            return

        mode_str = "[bold yellow][DRY RUN][/bold yellow] " if parsed.dry_run else ""
        console.print(f"\n[*] {mode_str}Applying hardening policies to [bold]{len(target_policies)}[/bold] tool(s)...\n")

        summary_table = Table(title="Hardening Execution Summary", header_style="bold cyan")
        summary_table.add_column("Tool", style="white", width=25)
        summary_table.add_column("Host Status", width=14)
        summary_table.add_column("Result", width=12)
        summary_table.add_column("Details", style="dim")

        for p in target_policies:
            res = engine.apply_policy(p, dry_run=parsed.dry_run)
            status_badge = "[bold green]SUCCESS[/bold green]" if res.success else "[bold red]FAILED[/bold red]"
            installed_badge = "[green]Installed[/green]" if p.is_installed else "[dim]Not Found[/dim]"
            details = ", ".join([f"{d.key} -> {d.new_value}" for d in res.diffs]) if res.diffs else ("No changes needed" if res.success else res.message)
            summary_table.add_row(f"{p.tool.vendor}/{p.tool.name}", installed_badge, status_badge, details)

        console.print(summary_table)
        console.print("\n[bold green][OK] Hardening execution completed. Audit logs written to logs/audit.jsonl[/bold green]\n")
    else:
        parser.print_help()
