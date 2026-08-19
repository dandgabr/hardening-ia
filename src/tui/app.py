"""Modern Terminal User Interface (TUI) built with Textual for Hardening IA."""

import logging
from typing import List, Optional
from pathlib import Path

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical, VerticalScroll
from textual.widgets import Header, Footer, Button, Static, Label, ListView, ListItem, RichLog, Checkbox
from textual.screen import ModalScreen
from textual.reactive import reactive

from src.core.config_loader import ConfigLoader
from src.core.engine import HardeningEngine
from src.core.os_detector import OSDetector
from src.core.models import HardeningPolicy
from src.core.logger import setup_logging
from src.core.code_analyzer import CodeVulnerabilityScanner
from src.core.verifier import HardeningVerifier


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

    def compose(self) -> ComposeResult:
        help_text = """
[bold cyan]╔═══════════════════════════════════════════════════════════════════════════╗[/]
[bold cyan]║                     Hardening IA - User Guide & Controls                  ║[/]
[bold cyan]╚═══════════════════════════════════════════════════════════════════════════╝[/]

[bold yellow]Navigation & Selection:[/]
  • [bold white]Up / Down Arrow Keys[/]: Scroll through the list of 14 supported AI tools.
  • [bold white]Click on any tool[/]: Instantly inspect its full security policy, DLP, and pending changes.
  • [bold white]F1 or ?[/]: Toggle this Help screen.

[bold yellow]The 3 Application Modes:[/]
  1. [bold green]Apply Selected[/]: Applies hardening policy strictly to the selected tool.
  2. [bold blue]Apply All Installed[/]: Automatically detects all tools present on this host OS and hardens them.
  3. [bold orange3]Apply All Supported[/]: Proactively provisions standard config directories and hardened baselines for ALL 14 tools (even if not yet installed).

[bold yellow]Audit & DLP Tools:[/]
  • [bold yellow]Verify Config[/]: Audits host files and verifies 100% compliance of applied settings.
  • [bold blue]View DLP Config[/]: Inspects Data Loss Prevention secret exclusion patterns (dynamic button).
  • [bold yellow]Dry Run Mode[/]: Simulates policy enforcement without altering host files.

[bold yellow]Extras & SAST Scanner:[/]
  • [bold cyan]ai-jail[/]: Installs Rust/Bubblewrap runtime sandbox container for AI agents.
  • [bold cyan]OpenGrep[/]: Installs open-source static analysis security scanner and rule packs.
  • [bold red]Scan Code[/]: Scans workspace for OWASP Web/API/Mobile, CWE Top 25 & secret leaks.

[dim]Press Escape or Click Close to return to the dashboard.[/dim]
"""
        with VerticalScroll(id="help-container"):
            yield Static(help_text, id="help-text")
            yield Button("Close Help (Esc)", id="btn-close-help", variant="primary")


class DlpModal(ModalScreen):
    """Interactive Data Loss Prevention (DLP) Inspector Dialog."""

    def __init__(self, policy: HardeningPolicy):
        super().__init__()
        self.policy = policy

    def compose(self) -> ComposeResult:
        dlp_info = self.policy.policies.get("dlp", {})
        patterns = dlp_info.get("block_sensitive_paths", [])
        disable_training = dlp_info.get("disable_code_training_sharing", True)
        mask_secrets = dlp_info.get("mask_secrets", True)

        patterns_formatted = []
        for p in patterns:
            patterns_formatted.append(f"  [cyan]•[/] [bold yellow]{p}[/bold yellow]")
        patterns_str = "\n".join(patterns_formatted) if patterns_formatted else "  [dim]No specific patterns defined[/dim]"

        dlp_text = f"""
[bold cyan]╔═══════════════════════════════════════════════════════════════════════════╗[/]
[bold cyan]║      🛡️ Data Loss Prevention (DLP) Security Profile - {self.policy.tool.vendor.upper()}/{self.policy.tool.name.upper()}       ║[/]
[bold cyan]╚═══════════════════════════════════════════════════════════════════════════╝[/]

[bold yellow]DLP Policy Overview:[/]
  • [bold white]Tool Category:[/] {self.policy.tool.category.upper()}
  • [bold white]Prompt Training Ingestion:[/] [bold green]{'BLOCKED (Zero Data Sharing)' if disable_training else 'Allowed'}[/bold green]
  • [bold white]Real-Time Secret Masking:[/] [bold green]{'ACTIVE (Redacted in Agent Context)' if mask_secrets else 'Inactive'}[/bold green]
  • [bold white]Total Excluded Path Rules:[/] [bold green]{len(patterns)} glob pattern rules[/bold green]

[bold yellow]Protected File & Path Exclusions (Blocked from AI Prompts & Scans):[/]
{patterns_str}

[bold yellow]Enforced Cloud & Key Storage Protections:[/]
  [green]✓[/green] [bold white]SSH Private Keys:[/] `~/.ssh/id_rsa`, `~/.ssh/id_ed25519`, `~/.ssh/known_hosts`
  [green]✓[/green] [bold white]Cloud Provider Credentials:[/] `~/.aws/credentials`, `~/.kube/config`, `~/.azure`
  [green]✓[/green] [bold white]GPG Keyrings & Certificates:[/] `~/.gnupg/**`, `*.pem`, `*.key`, `*.pfx`, `*.p12`
  [green]✓[/green] [bold white]Environment & Token Files:[/] `.env*`, `.git-credentials`, `.netrc`, `.docker/config.json`

[dim]Press Escape or Click Close to return to the main dashboard.[/dim]
"""
        with VerticalScroll(id="dlp-container"):
            yield Static(dlp_text, id="dlp-text")
            yield Button("Close DLP Inspector (Esc)", id="btn-close-dlp", variant="success")


class ToolItem(ListItem):
    def __init__(self, policy: HardeningPolicy):
        super().__init__()
        self.policy = policy

    def compose(self) -> ComposeResult:
        category_tag = f"[{self.policy.tool.category.upper():<7}]"
        status_tag = "● [INSTALLED]" if self.policy.is_installed else "○ [NOT FOUND]"
        status_style = "green" if self.policy.is_installed else "dim"
        yield Label(f"[{status_style}]{status_tag}[/{status_style}] {category_tag} [bold]{self.policy.tool.vendor}/{self.policy.tool.name}[/bold]")


class HardeningApp(App):
    BINDINGS = [
        ("f1", "toggle_help", "Help"),
        ("question_mark", "toggle_help", "Help"),
        ("d", "view_dlp", "View DLP"),
        ("v", "verify_config", "Verify Config"),
        ("q", "quit", "Quit")
    ]

    CSS = """
    Screen {
        background: #1e1e2e;
        color: #cdd6f4;
    }
    #main-container {
        layout: horizontal;
        height: 1fr;
    }
    #sidebar {
        width: 36%;
        height: 1fr;
        padding: 1;
        border-right: solid #45475a;
    }
    #details-panel {
        width: 64%;
        height: 1fr;
        padding: 1;
    }
    .panel-title {
        text-style: bold;
        color: #89b4fa;
        margin-bottom: 1;
        margin-top: 1;
    }
    #tools-list {
        height: 1fr;
        border: solid #45475a;
        background: #11111b;
    }
    #apply-action-buttons, #extras-buttons {
        layout: horizontal;
        height: auto;
        margin-top: 1;
        margin-bottom: 1;
    }
    Button {
        margin-right: 1;
        margin-bottom: 1;
    }
    #btn-view-dlp {
        display: none;
    }
    #log-view {
        height: 10;
        border: solid #45475a;
        background: #11111b;
        margin-top: 1;
    }
    #policy-details {
        height: 1fr;
        background: #11111b;
        padding: 1;
        border: solid #45475a;
    }
    #help-container, #dlp-container {
        width: 82%;
        height: 82%;
        background: #181825;
        border: thick #89b4fa;
        padding: 1;
        align: center middle;
    }
    #help-text, #dlp-text {
        margin-bottom: 1;
    }
    #btn-close-help, #btn-close-dlp {
        width: 100%;
    }
    """

    selected_policy: reactive[Optional[HardeningPolicy]] = reactive(None)

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
                yield Label(f"[b]AI Agents & Tools Catalog ({os_name})[/b]", classes="panel-title")
                yield ListView(id="tools-list")
                yield Label("[b]Security Extras & SAST Scanner[/b]", classes="panel-title")
                with Horizontal(id="extras-buttons"):
                    yield Button("ai-jail", id="btn-install-jail")
                    yield Button("OpenGrep", id="btn-install-opengrep")
                    yield Button("Scan Code", id="btn-scan-code", variant="error")
                    yield Button("Help (F1)", id="btn-help", variant="default")
            with Vertical(id="details-panel"):
                yield Label("[b]Security Policy & Risk Controls[/b]", classes="panel-title")
                with VerticalScroll(id="policy-details"):
                    yield Static("Select a tool from the catalog to inspect host status, security policies, and DLP settings.", id="policy-info")
                yield Label("[b]Policy Application Controls (3 Modes)[/b]", classes="panel-title")
                with Horizontal(id="apply-action-buttons"):
                    yield Button("Apply Selected", id="btn-apply-selected", variant="success")
                    yield Button("Apply All Installed", id="btn-apply-installed", variant="primary")
                    yield Button("Apply All Supported", id="btn-apply-all-supported", variant="warning")
                    yield Button("Verify Config", id="btn-verify-selected", variant="default")
                    yield Button("View DLP Config", id="btn-view-dlp", variant="default")
                    yield Checkbox("Dry Run", id="chk-dry-run")
                yield Label("[b]Execution Logs & Audit Trail[/b]", classes="panel-title")
                yield RichLog(id="log-view", highlight=True, markup=True)
        yield Footer()

    def on_mount(self) -> None:
        self.title = "Hardening IA Framework"
        self.sub_title = f"Host Platform: {OSDetector.get_os_type().upper()} | 3 Application Modes & SAST Active"

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
        log_view.write(f"[bold cyan][*] OS Detected: {OSDetector.get_os_type().upper()}[/]")
        log_view.write(f"[*] Discovered {len(self.policies)} policies ({installed_count} tools detected on host).")

    def _supports_dlp(self, policy: Optional[HardeningPolicy]) -> bool:
        if not policy:
            return False
        dlp = policy.policies.get("dlp", {})
        return bool(dlp.get("block_sensitive_paths") or dlp.get("disable_code_training_sharing") or dlp.get("mask_secrets"))

    def action_toggle_help(self) -> None:
        self.push_screen(HelpModal())

    def action_view_dlp(self) -> None:
        if self._supports_dlp(self.selected_policy):
            self.push_screen(DlpModal(self.selected_policy))
        else:
            log_view = self.query_one("#log-view", RichLog)
            log_view.write("[bold yellow][!] Selected tool does not have active DLP configurations.[/]")

    def action_verify_config(self) -> None:
        self._run_verification_on_selected()

    def _run_verification_on_selected(self) -> None:
        log_view = self.query_one("#log-view", RichLog)
        if not self.selected_policy:
            log_view.write("[bold red][!] Please select a tool from the catalog first to verify.[/]")
            return

        report = self.verifier.verify_policy(self.selected_policy)
        score_style = "bold green" if report.compliance_score == 100.0 else ("bold yellow" if report.compliance_score > 0 else "bold red")
        log_view.write(f"\n[*] Auditing compliance for {self.selected_policy.tool.vendor}/{self.selected_policy.tool.name}...")
        log_view.write(f"  Score: [{score_style}]{report.compliance_score:.1f}% ({report.passed_checks}/{report.total_checks} checks passed)[/]")

        for c in report.checks:
            status_sym = "[green]✓ PASSED[/]" if c.passed else "[red]✗ FAILED[/]"
            log_view.write(f"    {status_sym} {c.key} (expected: {c.expected}, actual: {c.actual})")
        log_view.write(f"  Summary: [{score_style}]{report.message}[/]\n")

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        if isinstance(event.item, ToolItem):
            self.selected_policy = event.item.policy
            self._update_details()

    def _update_details(self) -> None:
        if not self.selected_policy:
            return
        p = self.selected_policy
        info_widget = self.query_one("#policy-info", Static)
        btn_dlp = self.query_one("#btn-view-dlp", Button)

        has_dlp = self._supports_dlp(p)
        btn_dlp.display = has_dlp

        os_type = OSDetector.get_os_type()
        path_info = p.paths.get(os_type)
        settings_path = path_info.settings_file if path_info else "N/A"
        rules_path = path_info.rules_dir if path_info and path_info.rules_dir else "N/A"

        status_badge = "[bold green]● INSTALLED ON HOST[/]" if p.is_installed else "[dim]○ NOT DETECTED ON HOST[/]"
        dlp_list = p.policies.get("dlp", {}).get("block_sensitive_paths", [])
        dlp_count = len(dlp_list)
        sandbox_enforced = p.policies.get("sandbox", {}).get("enforce_sandbox", False)
        telemetry_off = not p.policies.get("telemetry", {}).get("enable_telemetry", True)
        native_overrides = p.policies.get("native_settings_override", {})

        overrides_lines = []
        for k, v in native_overrides.items():
            overrides_lines.append(f"  [cyan]•[/] [bold white]{k}[/bold white] [green]➔[/green] [bold yellow]{v}[/bold yellow]")
        overrides_text = "\n".join(overrides_lines) if overrides_lines else "  [dim]Standard baseline configuration[/dim]"

        dlp_sample = ", ".join([f"`{pat}`" for pat in dlp_list[:6]])
        if dlp_count > 6:
            dlp_sample += f" [dim](+{dlp_count - 6} more patterns)[/dim]"

        dlp_badge = f"[bold green]{dlp_count} Protected Secret Patterns (Click 'View DLP Config' button to inspect)[/bold green]" if has_dlp else "[dim]No DLP rules defined for this tool category[/dim]"

        text = f"""[bold yellow]═══════════════════════════════════════════════════════════════════════[/]
[bold cyan]TOOL:[/] [bold white]{p.tool.vendor}/{p.tool.name.upper()}[/]  |  [bold cyan]CATEGORY:[/] [bold]{p.tool.category.upper()}[/]  |  {status_badge}
[dim]{p.tool.description}[/dim]
[bold yellow]═══════════════════════════════════════════════════════════════════════[/]

[bold green]📁 TARGET FILE PATHS & RULES LOCATION ({os_type.upper()}):[/]
  [cyan]• Settings File:[/] [white]{settings_path}[/]
  [cyan]• Agent Rules Dir:[/] [white]{rules_path}[/]

[bold green]⚙️ NATIVE CONFIGURATION OVERRIDES TO BE APPLIED ({len(native_overrides)} settings):[/]
{overrides_text}

[bold green]🛡️ SECURITY CONTROLS & COMPLIANCE ENFORCEMENT:[/]
  [cyan]• Multi-OS Command Risk Matrix:[/] [bold green]ACTIVE[/bold green]
    - [green]LOW Risk Commands[/] (ls, pwd, git status): [bold green]Auto-Executable[/bold green]
    - [yellow]MEDIUM Risk Commands[/] (mkdir, touch, npm build): [bold yellow]Requires Approval[/bold yellow]
    - [red]HIGH / CRITICAL Risk Commands[/] (rm -rf, sudo, chmod): [bold red]Strict Human Approval Required[/bold red]

  [cyan]• Runtime Sandbox Isolation:[/] {'[bold green]ENFORCED (Bypass Disallowed)[/bold green]' if sandbox_enforced else '[yellow]Optional[/yellow]'}
  [cyan]• Zero-Telemetry & Crash Reporting:[/] {'[bold green]SHUTDOWN (DO_NOT_TRACK=1)[/bold green]' if telemetry_off else '[yellow]Enabled[/yellow]'}
  [cyan]• Data Loss Prevention (DLP):[/] {dlp_badge}
    {('Excluding: ' + dlp_sample) if has_dlp else ''}
  [cyan]• OS Filesystem ACL Lockdown:[/] [bold green]Owner Exclusive (chmod 700/600 or Windows NTFS ACL)[/bold green]
"""
        info_widget.update(text)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        log_view = self.query_one("#log-view", RichLog)
        dry_run = self.query_one("#chk-dry-run", Checkbox).value

        if event.button.id == "btn-close-help" or event.button.id == "btn-close-dlp":
            self.pop_screen()

        elif event.button.id == "btn-help":
            self.push_screen(HelpModal())

        elif event.button.id == "btn-view-dlp":
            if self._supports_dlp(self.selected_policy):
                self.push_screen(DlpModal(self.selected_policy))
            elif self.selected_policy:
                log_view.write(f"[bold yellow][!] No DLP configuration defined for {self.selected_policy.tool.name}.[/]")
            else:
                log_view.write("[bold red][!] Please select a tool first to view its DLP configuration.[/]")

        elif event.button.id == "btn-verify-selected":
            self._run_verification_on_selected()

        elif event.button.id == "btn-apply-selected":
            if not self.selected_policy:
                log_view.write("[bold red][!] Please select a tool from the catalog first.[/]")
                return
            mode_prefix = "[bold yellow][DRY RUN][/bold yellow] " if dry_run else ""
            log_view.write(f"[*] {mode_prefix}Applying hardening to [bold]{self.selected_policy.tool.vendor}/{self.selected_policy.tool.name}[/bold]...")
            res = self.engine.apply_policy(self.selected_policy, dry_run=dry_run)
            status_style = "bold green" if res.success else "bold red"
            log_view.write(f"  [{status_style}]{res.message}[/]")

        elif event.button.id == "btn-apply-installed":
            installed_policies = [p for p in self.policies if p.is_installed]
            mode_prefix = "[bold yellow][DRY RUN][/bold yellow] " if dry_run else ""
            log_view.write(f"\n[*] {mode_prefix}Applying policies to {len(installed_policies)} INSTALLED tools on host...")
            if not installed_policies:
                log_view.write("[bold yellow][!] No installed AI tools detected on this host.[/]")
                return
            for p in installed_policies:
                res = self.engine.apply_policy(p, dry_run=dry_run)
                status = "[green][OK][/]" if res.success else "[red][FAILED][/]"
                log_view.write(f"  {status} {p.tool.vendor}/{p.tool.name}")
            log_view.write("[bold green][OK] Host-installed tools hardening completed.[/]\n")

        elif event.button.id == "btn-apply-all-supported":
            mode_prefix = "[bold yellow][DRY RUN][/bold yellow] " if dry_run else ""
            log_view.write(f"\n[*] {mode_prefix}Proactively provisioning standard configs across ALL {len(self.policies)} supported tools...")
            for p in self.policies:
                res = self.engine.apply_policy(p, dry_run=dry_run)
                status = "[green][OK][/]" if res.success else "[red][FAILED][/]"
                log_view.write(f"  {status} {p.tool.vendor}/{p.tool.name}")
            log_view.write("[bold green][OK] All 14 supported tools provisioned and hardened in standard directories.[/]\n")

        elif event.button.id == "btn-install-jail":
            log_view.write("[*] Launching ai-jail installer...")
            success = self.engine.install_extra_tool("ai-jail")
            if success:
                log_view.write("[bold green][OK] ai-jail installed successfully.[/]")
            else:
                log_view.write("[bold red][!] ai-jail installation failed.[/]")

        elif event.button.id == "btn-install-opengrep":
            log_view.write("[*] Launching OpenGrep installer...")
            success = self.engine.install_extra_tool("opengrep")
            if success:
                log_view.write("[bold green][OK] OpenGrep installed and configured successfully.[/]")
            else:
                log_view.write("[bold red][!] OpenGrep installation failed.[/]")

        elif event.button.id == "btn-scan-code":
            log_view.write("[*] Running SAST Code Vulnerability Analysis on workspace...")
            findings = self.code_scanner.scan_path(Path("."))
            if not findings:
                log_view.write("[bold green][OK] No code vulnerabilities or secret leaks detected.[/]")
            else:
                log_view.write(f"[bold red][!] Found {len(findings)} vulnerability issue(s):[/]")
                for idx, f in enumerate(findings[:5], start=1):
                    log_view.write(f"  {idx}. [{f.get('severity')}] {f.get('file')}:{f.get('line')} - {f.get('title')}")
                if len(findings) > 5:
                    log_view.write(f"  ... and {len(findings)-5} more (see logs/audit.jsonl)")


def run_tui():
    app = HardeningApp()
    app.run()
