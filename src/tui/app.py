"""Modern Terminal User Interface (TUI) built with Textual for Hardening IA."""

import logging
import shutil
import json
from typing import List, Optional
from pathlib import Path

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical, VerticalScroll
from textual.widgets import Header, Footer, Button, Static, Label, ListView, ListItem, RichLog, Input
from textual.screen import ModalScreen
from textual.reactive import reactive
from textual import events, work

from rich.markup import escape

from src.core.config_loader import ConfigLoader
from src.core.engine import HardeningEngine
from src.core.os_detector import OSDetector
from src.core.models import HardeningPolicy
from src.core.logger import setup_logging
from src.core.code_analyzer import CodeVulnerabilityScanner
from src.core.verifier import HardeningVerifier
from src.core.security_policy import SecurityPolicyManager
from src.core.command_classifier import CommandRiskClassifier, RiskLevel


class TextualLogHandler(logging.Handler):
    """Bridges standard python logging records directly into Textual's RichLog widget."""
    def __init__(self, rich_log: RichLog):
        super().__init__()
        self.rich_log = rich_log

    def emit(self, record: logging.LogRecord):
        try:
            msg = self.format(record)
            self.rich_log.write(msg)
        except Exception:
            pass


class HelpModal(ModalScreen):
    """Interactive Help and Usage Guide Dialog."""

    BINDINGS = [
        ("escape", "dismiss", "Close")
    ]

    def compose(self) -> ComposeResult:
        help_text = """
[bold cyan]╔═══════════════════════════════════════════════════════════════════════════╗[/]
[bold cyan]║                     Hardening IA - User Guide & Controls                  ║[/]
[bold cyan]╚═══════════════════════════════════════════════════════════════════════════╝[/]

[bold yellow]Navigation & Keyboard Shortcuts:[/]
  • [bold white]Up / Down Arrow Keys[/]: Scroll through the catalog of 21 supported AI tools.
  • [bold white]Enter / Click[/]: Select a tool to inspect live configuration, policies, and DLP settings.
  • [bold white]V[/]: [bold magenta]Verify[/] selected tool's configuration compliance on disk.
  • [bold white]D[/]: [bold cyan]DLP Inspector[/] for data loss prevention & dangerous OS paths.
  • [bold white]S[/]: [bold red]Toggle Strict Mode[/] (Zero-trust guardrails, immediate path blocking).
  • [bold white]Y[/]: [bold yellow]Toggle Dry Run Mode[/] (Simulate actions without writing to disk).
  • [bold white]F[/]: [bold green]Fix & Auto-Remediate[/] compliance across all installed tools.
  • [bold white]R[/]: [bold white]Command Risk Tester[/] (Interactive STRIDE risk matrix playground).
  • [bold white]H / ?[/]: Toggle this Help guide.
  • [bold white]Q[/]: Quit application.

[bold yellow]Top Bar Status Indicators:[/]
  • [bold red]🛡️ STRICT: ON[/bold red] / [dim]STRICT: OFF[/dim]: Shows whether zero-trust lockdown is active.
  • [bold yellow]⚠️ DRY-RUN: ON[/bold yellow] / [dim]DRY-RUN: OFF[/dim]: Shows whether simulation mode is active.

[bold yellow]Button Actions Explained:[/]
  • [bold green]Apply[/]: Hardens the currently selected tool.
  • [bold blue]Apply Installed[/]: Automatically detects all installed AI tools on host and hardens them.
  • [bold orange3]Apply All[/]: Provisions configurations and hardened baselines for all 21 tools.
  • [bold red]Remove Selected[/]: Reverts hardening overrides from the selected tool back to defaults.
  • [bold red]Remove Installed[/]: Reverts hardening overrides from all installed tools.

[dim]Press Escape or Click Close to return to the dashboard.[/dim]
"""
        with VerticalScroll(id="help-container"):
            yield Static(help_text, id="help-text")
            yield Button("Close Help (Esc)", id="btn-close-help", variant="primary")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-close-help":
            event.stop()
            self.dismiss()


class DlpModal(ModalScreen):
    """Interactive Data Loss Prevention (DLP) Inspector Dialog."""

    BINDINGS = [
        ("escape", "dismiss", "Close")
    ]

    def __init__(self, policy: HardeningPolicy):
        super().__init__()
        self.policy = policy

    def compose(self) -> ComposeResult:
        dlp_info = self.policy.policies.get("dlp", {})
        patterns = dlp_info.get("block_sensitive_paths", [])
        disable_training = dlp_info.get("disable_code_training_sharing", True)
        mask_secrets = dlp_info.get("mask_secrets", True)
        os_type = OSDetector.get_os_type()
        dangerous_paths = SecurityPolicyManager.get_dangerous_paths_for_os(os_type)

        patterns_formatted = []
        for p in patterns:
            patterns_formatted.append(f"  [cyan]•[/] [bold yellow]{escape(str(p))}[/bold yellow]")
        patterns_str = "\n".join(patterns_formatted) if patterns_formatted else "  [dim]No specific patterns defined[/dim]"

        danger_formatted = []
        for dp in dangerous_paths[:10]:
            danger_formatted.append(f"  [red]•[/] [bold white]{escape(str(dp))}[/bold white]")
        if len(dangerous_paths) > 10:
            danger_formatted.append(f"  [dim]... and {len(dangerous_paths) - 10} more OS paths[/dim]")
        danger_str = "\n".join(danger_formatted)

        dlp_text = f"""
[bold cyan]╔═══════════════════════════════════════════════════════════════════════════╗[/]
[bold cyan]║      🛡️ Data Loss Prevention (DLP) & Dangerous Paths - {self.policy.tool.vendor.upper()}/{self.policy.tool.name.upper()}       ║[/]
[bold cyan]╚═══════════════════════════════════════════════════════════════════════════╝[/]

[bold yellow]DLP Policy Overview:[/]
  • [bold white]Tool Category:[/] {self.policy.tool.category.upper()}
  • [bold white]Prompt Training Ingestion:[/] [bold green]{'BLOCKED (Zero Data Sharing)' if disable_training else 'Allowed'}[/bold green]
  • [bold white]Real-Time Secret Masking:[/] [bold green]{'ACTIVE (Redacted in Agent Context)' if mask_secrets else 'Inactive'}[/bold green]
  • [bold white]Rate Limit:[/] [bold cyan]30 requests/min (Burst 10)[/bold cyan]
  • [bold white]Execution Timeout:[/] [bold cyan]30s Command / 60s Session[/bold cyan]

[bold yellow]Protected File & Path Exclusions (Blocked from AI Prompts & Scans):[/]
{patterns_str}

[bold yellow]OS Dangerous Paths Protected ({os_type.upper()}):[/]
{danger_str}

[dim]Press Escape or Click Close to return to the main dashboard.[/dim]
"""
        with VerticalScroll(id="dlp-container"):
            yield Static(dlp_text, id="dlp-text")
            yield Button("Close DLP Inspector (Esc)", id="btn-close-dlp", variant="success")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-close-dlp":
            event.stop()
            self.dismiss()


class CommandRiskPlaygroundModal(ModalScreen):
    """Interactive Command Risk Classifier Playground Modal."""

    BINDINGS = [
        ("escape", "dismiss", "Close")
    ]

    def __init__(self):
        super().__init__()
        self.classifier = CommandRiskClassifier()

    def compose(self) -> ComposeResult:
        with VerticalScroll(id="risk-container"):
            yield Static(
                "[bold cyan]╔═══════════════════════════════════════════════════════════════════════════╗[/]\n"
                "[bold cyan]║           ⚡ Interactive Command Risk Classifier & STRIDE Matrix           ║[/]\n"
                "[bold cyan]╚═══════════════════════════════════════════════════════════════════════════╝[/]",
                id="risk-header"
            )
            yield Label("[bold white]Type any terminal command to evaluate its risk tier and safety actions:[/bold white]")
            yield Input(placeholder="e.g. rm -rf /etc/shadow, curl http://169.254.169.254, git push", id="input-command-test")
            yield Static("[dim]Evaluation results will appear below...[/dim]", id="risk-result-box")
            with Horizontal():
                yield Button("Close (Esc)", id="btn-close-risk", variant="primary")

    def on_input_changed(self, event: Input.Changed) -> None:
        cmd = event.value.strip()
        result_box = self.query_one("#risk-result-box", Static)
        if not cmd:
            result_box.update("[dim]Type any terminal command above to evaluate...[/dim]")
            return

        std_eval = self.classifier.classify(cmd, strict_mode=False)
        strict_eval = self.classifier.classify(cmd, strict_mode=True)

        std_color = "green" if std_eval.level == RiskLevel.LOW else ("yellow" if std_eval.level == RiskLevel.MEDIUM else "red")
        strict_color = "green" if strict_eval.level == RiskLevel.LOW else ("yellow" if strict_eval.level == RiskLevel.MEDIUM else "bold red")

        reasons = ", ".join(std_eval.reasons) if std_eval.reasons else "Standard safe operation"

        res_text = f"""
[bold white]Evaluated Command:[/] [cyan]{escape(cmd)}[/cyan]
[bold white]Risk Level:[/] [{std_color}]{std_eval.level.name}[/{std_color}]
[bold white]Matched Triggers:[/] [yellow]{escape(reasons)}[/yellow]

[bold yellow]Standard Mode Decision:[/] [{std_color}]{std_eval.recommended_action.upper()}[/{std_color}]
[bold red]Strict Mode Decision:[/] [{strict_color}]{strict_eval.recommended_action.upper()}[/{strict_color}]
"""
        result_box.update(res_text)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-close-risk":
            event.stop()
            self.dismiss()


class ToolItem(ListItem):
    """Custom list item widget for AI tools."""
    def __init__(self, policy: HardeningPolicy):
        super().__init__()
        self.policy = policy

    def compose(self) -> ComposeResult:
        status_badge = "[bold green]INSTALLED[/bold green]" if self.policy.is_installed else "[dim]NOT FOUND[/dim]"
        cat_badge = f"[cyan]{self.policy.tool.category.upper()}[/cyan]"
        yield Label(f"{status_badge} {cat_badge} [b]{self.policy.tool.vendor}/{self.policy.tool.name}[/b]")


class HardeningTUIApp(App):
    """Modern Textual Application for Hardening IA Framework."""

    CSS = """
    Screen {
        background: #0f172a;
        color: #f8fafc;
    }
    Header {
        background: #1e293b;
        color: #38bdf8;
    }
    Footer {
        background: #1e293b;
    }
    #main-container {
        layout: horizontal;
        height: 1fr;
    }
    #sidebar {
        width: 38%;
        height: 100%;
        background: #1e293b;
        border-right: solid #334155;
        padding: 1;
    }
    #tools-list {
        height: 1fr;
        background: #0f172a;
        border: solid #334155;
        margin-bottom: 1;
    }
    #details-panel {
        width: 62%;
        height: 100%;
        padding: 1;
    }
    #policy-details {
        height: 52%;
        background: #0f172a;
        border: solid #334155;
        padding: 1;
        margin-bottom: 1;
    }
    #log-view {
        height: 1fr;
        background: #0f172a;
        border: solid #334155;
    }
    .panel-title {
        color: #38bdf8;
        margin-bottom: 1;
    }
    #action-buttons-bar {
        height: auto;
        margin-bottom: 1;
    }
    Button {
        margin-right: 1;
        min-width: 12;
    }
    #help-container, #dlp-container, #risk-container {
        background: #1e293b;
        border: thick #38bdf8;
        padding: 2;
        width: 80%;
        height: 80%;
        align: center middle;
    }
    #risk-result-box {
        background: #0f172a;
        border: solid #334155;
        padding: 1;
        margin-top: 1;
        margin-bottom: 1;
    }
    """

    BINDINGS = [
        ("h", "toggle_help", "Help"),
        ("v", "verify_config", "Verify"),
        ("d", "view_dlp", "DLP"),
        ("s", "toggle_strict", "Strict [ON/OFF]"),
        ("y", "toggle_dry_run", "Dry Run [ON/OFF]"),
        ("f", "fix_compliance", "Auto-Fix All"),
        ("r", "command_risk", "Risk Tester"),
        ("q", "quit", "Quit")
    ]

    selected_policy: reactive[Optional[HardeningPolicy]] = reactive(None)
    strict_mode: reactive[bool] = reactive(False)
    dry_run: reactive[bool] = reactive(False)

    def __init__(self):
        super().__init__()
        self.config_loader = ConfigLoader()
        self.engine = HardeningEngine()
        self.code_scanner = CodeVulnerabilityScanner()
        self.verifier = HardeningVerifier()
        self.policies: List[HardeningPolicy] = []

    def compose(self) -> ComposeResult:
        os_name = OSDetector.get_os_type().upper()
        yield Header(show_clock=True)
        with Container(id="main-container"):
            with Vertical(id="sidebar"):
                yield Label(f"[b]AI Agents & Tools ({os_name}) - 21 Tools[/b]", classes="panel-title")
                yield ListView(id="tools-list")
            with Vertical(id="details-panel"):
                yield Label("[b]Security Policy & Live Status[/b]", classes="panel-title")
                with VerticalScroll(id="policy-details"):
                    yield Static("Select a tool from the catalog to inspect host status, security policies, and DLP settings.", id="policy-info")
                yield Label("[b]Policy Actions & Enforcement[/b]", classes="panel-title")
                with Horizontal(id="action-buttons-bar"):
                    yield Button("Apply", id="btn-apply-selected", variant="success")
                    yield Button("Apply Installed", id="btn-apply-installed", variant="primary")
                    yield Button("Apply All", id="btn-apply-all-supported", variant="warning")
                    yield Button("Remove Selected", id="btn-remove-selected", variant="error")
                    yield Button("Remove Installed", id="btn-remove-installed", variant="error")
                yield Label("[b]Execution Logs & Audit Trail[/b]", classes="panel-title")
                yield RichLog(id="log-view", highlight=True, markup=True)
        yield Footer()

    def on_mount(self) -> None:
        self.title = "Hardening IA Framework"
        self._update_header_status()

        log_view = self.query_one("#log-view", RichLog)
        textual_handler = TextualLogHandler(log_view)
        textual_handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))

        root_logger = setup_logging(enable_console=False)
        root_logger.addHandler(textual_handler)

        self.policies = self.config_loader.discover_policies()
        tools_list = self.query_one("#tools-list", ListView)
        for p in self.policies:
            tools_list.append(ToolItem(p))

        installed_count = sum(1 for p in self.policies if p.is_installed)
        log_view.write(f"[bold cyan][*] Host OS: {OSDetector.get_os_type().upper()} | Discovered {len(self.policies)} unified tools ({installed_count} installed).[/]")
        log_view.write("[dim]Shortcuts: [V] Verify | [D] DLP | [S] Strict Mode | [Y] Dry Run | [F] Auto-Fix All | [R] Risk Tester | [H] Help[/dim]")

    def _update_header_status(self) -> None:
        os_name = OSDetector.get_os_type().upper()
        strict_status = "🛡️ STRICT: ON" if self.strict_mode else "STRICT: OFF"
        dry_status = "⚠️ DRY-RUN: ON" if self.dry_run else "DRY-RUN: OFF"
        self.sub_title = f"Host: {os_name} | {strict_status} (S) | {dry_status} (Y) | Help (H)"

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        if isinstance(event.item, ToolItem):
            self.selected_policy = event.item.policy
            self._update_details()

    def _update_details(self) -> None:
        if not self.selected_policy:
            return
        p = self.selected_policy
        paths = p.paths.get(OSDetector.get_os_type())
        settings_file = paths.settings_file if paths else "N/A"
        inst_badge = "[bold green]INSTALLED[/bold green]" if p.is_installed else "[dim]NOT INSTALLED[/dim]"

        # Live verification audit of actual on-disk configuration
        report = self.verifier.verify_policy(p, strict_mode=self.strict_mode)
        if report.compliance_score == 100.0:
            score_badge = f"[bold green]{report.compliance_score:.0f}% (FULLY COMPLIANT)[/bold green]"
        elif report.compliance_score >= 80.0:
            score_badge = f"[bold yellow]{report.compliance_score:.1f}% (PARTIALLY COMPLIANT)[/bold yellow]"
        elif report.compliance_score > 0.0:
            score_badge = f"[bold orange3]{report.compliance_score:.1f}% (NEEDS ATTENTION)[/bold orange3]"
        else:
            score_badge = "[bold red]0% (NOT HARDENED / MISSING)[/bold red]"

        strict_badge = "[bold red]ENABLED (Zero-Trust)[/bold red]" if self.strict_mode else "[dim]STANDARD (Interactive)[/dim]"
        dry_badge = "[bold yellow]ACTIVE (Simulation)[/bold yellow]" if self.dry_run else "[dim]DISABLED (Live)[/dim]"

        info_text = f"""
[bold cyan]Tool:[/] [bold white]{p.tool.vendor}/{p.tool.name}[/bold white]  |  [bold cyan]Status:[/] {inst_badge}  |  [bold cyan]Category:[/] [yellow]{p.tool.category.upper()}[/yellow]
[bold cyan]Live Compliance Score:[/] {score_badge} ({report.passed_checks}/{report.total_checks} checks active on disk)
[bold cyan]Primary Settings Path:[/] [white]{settings_file}[/white]
[bold cyan]Strict Mode:[/] {strict_badge}  |  [bold cyan]Dry Run:[/] {dry_badge}

[bold yellow]Active Hardening Overrides (Live On-Disk Status):[/]
"""
        if report.checks:
            for c in report.checks[:12]:
                if c.passed:
                    info_text += f"  [bold green]✔[/bold green] [cyan]{c.key}:[/] [white]{c.expected}[/white] [dim green](Active on disk)[/dim green]\n"
                elif c.actual == "[MISSING]":
                    info_text += f"  [dim yellow]○[/dim yellow] [cyan]{c.key}:[/] [white]{c.expected}[/white] [dim yellow](Not applied / Missing)[/dim yellow]\n"
                else:
                    info_text += f"  [bold red]✘[/bold red] [cyan]{c.key}:[/] [white]{c.expected}[/white] [bold red](Current: {c.actual})[/bold red]\n"
            if len(report.checks) > 12:
                info_text += f"  [dim]... and {len(report.checks) - 12} more live controls[/dim]\n"
        else:
            overrides = dict(p.policies.get("native_settings_override", {}))
            if self.strict_mode:
                overrides.update(p.policies.get("strict_rules", {}).get("native_overrides", {}))
            for k, v in list(overrides.items())[:8]:
                info_text += f"  • [cyan]{k}:[/] [white]{v}[/white]\n"
            if len(overrides) > 8:
                info_text += f"  [dim]... and {len(overrides) - 8} more controls[/dim]\n"

        self.query_one("#policy-info", Static).update(info_text)

    def action_toggle_help(self) -> None:
        self.push_screen(HelpModal())

    def action_toggle_strict(self) -> None:
        self.strict_mode = not self.strict_mode
        self._update_header_status()
        self._update_details()
        log_view = self.query_one("#log-view", RichLog)
        status_msg = "[bold red][!] Strict Mode ENABLED (Zero-Trust Guardrails)[/bold red]" if self.strict_mode else "[cyan][*] Strict Mode DISABLED (Standard)[/cyan]"
        log_view.write(status_msg)

    def action_toggle_dry_run(self) -> None:
        self.dry_run = not self.dry_run
        self._update_header_status()
        self._update_details()
        log_view = self.query_one("#log-view", RichLog)
        status_msg = "[bold yellow][!] Dry Run Mode ENABLED (Simulations only, no files modified)[/bold yellow]" if self.dry_run else "[cyan][*] Dry Run Mode DISABLED (Live file modifications active)[/cyan]"
        log_view.write(status_msg)

    def action_command_risk(self) -> None:
        self.push_screen(CommandRiskPlaygroundModal())

    def action_view_dlp(self) -> None:
        if self.selected_policy:
            self.push_screen(DlpModal(self.selected_policy))
        else:
            self.query_one("#log-view", RichLog).write("[yellow][!] Please select a tool from the catalog first to inspect DLP.[/yellow]")

    def action_verify_config(self) -> None:
        self._run_verification_on_selected()

    def action_fix_compliance(self) -> None:
        self._run_fix_all_installed()

    def _run_verification_on_selected(self) -> None:
        log_view = self.query_one("#log-view", RichLog)
        if not self.selected_policy:
            log_view.write("[bold red][!] Please select a tool from the catalog first.[/]")
            return
        report = self.verifier.verify_policy(self.selected_policy, strict_mode=self.strict_mode)
        score_color = "green" if report.compliance_score == 100.0 else ("yellow" if report.compliance_score >= 80.0 else "red")
        log_view.write(f"\n[*] Compliance Audit for [bold]{self.selected_policy.tool.vendor}/{self.selected_policy.tool.name}[/bold]:")
        log_view.write(f"  Score: [{score_color}]{report.compliance_score:.1f}% ({report.passed_checks}/{report.total_checks})[/{score_color}] - {report.message}")
        self._update_details()

    def _run_fix_all_installed(self) -> None:
        log_view = self.query_one("#log-view", RichLog)
        installed = [p for p in self.policies if p.is_installed]
        log_view.write(f"\n[*] Auto-remediating compliance for {len(installed)} installed tool(s)...")
        for p in installed:
            res = self.verifier.remediate_policy(p, strict_mode=self.strict_mode)
            if res.success:
                log_view.write(f"  [bold green][OK][/bold green] {p.tool.vendor}/{p.tool.name}: 100% compliant")
            else:
                log_view.write(f"  [bold red][FAILED][/bold red] {p.tool.vendor}/{p.tool.name}: {res.message}")
        self._update_details()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn_id = event.button.id
        log_view = self.query_one("#log-view", RichLog)
        dry_run = self.dry_run

        if btn_id == "btn-apply-selected" and self.selected_policy:
            mode_badge = "[yellow][DRY RUN][/yellow] " if dry_run else ""
            log_view.write(f"\n[*] {mode_badge}Applying hardening to [bold]{self.selected_policy.tool.vendor}/{self.selected_policy.tool.name}[/bold]...")
            res = self.engine.apply_policy(self.selected_policy, dry_run=dry_run, strict_mode=self.strict_mode)
            if res.success:
                log_view.write(f"  [bold green][OK] Applied successfully ({len(res.diffs)} settings).[/bold green]")
                if not dry_run:
                    self._run_verification_on_selected()
            else:
                log_view.write(f"  [bold red][ERROR] {res.message}[/bold red]")
            self._update_details()
        elif btn_id == "btn-apply-installed":
            installed = [p for p in self.policies if p.is_installed]
            mode_badge = "[yellow][DRY RUN][/yellow] " if dry_run else ""
            log_view.write(f"\n[*] {mode_badge}Applying hardening to {len(installed)} installed tool(s)...")
            for p in installed:
                res = self.engine.apply_policy(p, dry_run=dry_run, strict_mode=self.strict_mode)
                status = "[bold green]OK[/bold green]" if res.success else "[bold red]FAIL[/bold red]"
                log_view.write(f"  {status} {p.tool.vendor}/{p.tool.name}")
            self._update_details()
        elif btn_id == "btn-apply-all-supported":
            mode_badge = "[yellow][DRY RUN][/yellow] " if dry_run else ""
            log_view.write(f"\n[*] {mode_badge}Applying hardening to ALL {len(self.policies)} supported tools...")
            for p in self.policies:
                res = self.engine.apply_policy(p, dry_run=dry_run, strict_mode=self.strict_mode)
                status = "[bold green]OK[/bold green]" if res.success else "[bold red]FAIL[/bold red]"
                log_view.write(f"  {status} {p.tool.vendor}/{p.tool.name}")
            self._update_details()
        elif btn_id == "btn-remove-selected" and self.selected_policy:
            mode_badge = "[yellow][DRY RUN][/yellow] " if dry_run else ""
            log_view.write(f"\n[*] {mode_badge}Reverting hardening from [bold]{self.selected_policy.tool.vendor}/{self.selected_policy.tool.name}[/bold]...")
            res = self.engine.remove_policy(self.selected_policy, dry_run=dry_run)
            log_view.write(f"  [bold green][OK] Removed.[/bold green]" if res.success else f"  [bold red][ERROR] {res.message}[/bold red]")
            self._update_details()
        elif btn_id == "btn-remove-installed":
            installed = [p for p in self.policies if p.is_installed]
            mode_badge = "[yellow][DRY RUN][/yellow] " if dry_run else ""
            log_view.write(f"\n[*] {mode_badge}Reverting hardening from {len(installed)} installed tool(s)...")
            for p in installed:
                res = self.engine.remove_policy(p, dry_run=dry_run)
                status = "[bold green]REMOVED[/bold green]" if res.success else "[bold red]FAIL[/bold red]"
                log_view.write(f"  {status} {p.tool.vendor}/{p.tool.name}")
            self._update_details()


def run_tui():
    """Entry point for launching the Textual TUI Application."""
    app = HardeningTUIApp()
    app.run()


if __name__ == "__main__":
    run_tui()
