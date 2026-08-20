"""Modern Terminal User Interface (TUI) built with Textual for Hardening IA."""

import logging
import shutil
from typing import List, Optional
from pathlib import Path

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical, VerticalScroll
from textual.widgets import Header, Footer, Button, Static, Label, ListView, ListItem, RichLog, Checkbox, ProgressBar
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

[bold yellow]Navigation & Selection:[/]
  • [bold white]Up / Down Arrow Keys[/]: Scroll through the list of 14 supported AI tools.
  • [bold white]Click on any tool[/]: Instantly inspect its full security policy, DLP, and pending changes.
  • [bold white]H, F1 or ?[/]: Toggle this Help screen.
  • [bold white]V[/]: Verify selected tool's configuration compliance.
  • [bold white]D[/]: View Data Loss Prevention (DLP) configuration.
  • [bold white]S[/]: Toggle Strict Mode.

[bold yellow]Verification & Compliance Remediation:[/]
  • [bold magenta]Verify Selected (V)[/]: Audits host config files against security baselines and calculates a real-time compliance score (0-100%).
  • [bold green]Fix Compliance[/]: Automatically remediates all detected discrepancies, patching config files directly to achieve 100% baseline compliance.

[bold yellow]The 3 Policy Application Modes:[/]
  1. [bold green]Apply Selected[/]: Applies hardening policy strictly to the selected tool.
  2. [bold blue]Apply All Installed[/]: Automatically detects all tools present on this host OS and hardens them.
  3. [bold orange3]Apply All Supported[/]: Proactively provisions standard config directories and hardened baselines for ALL 14 tools.

[bold yellow]Strict Restrictive Mode:[/]
  • [bold red]Explicit Dangerous Paths Blocking[/]: Blocks access to sensitive system paths immediately without asking.
  • [bold red]Explicit Denied Patterns[/]: Automatic rejection of critical commands (`rm -rf /`, `mkfs`, `dd`, `diskpart`, etc.).
  • [bold green]Standard Mode[/]: Restricts dangerous paths and requires explicit operator confirmation before access.

[bold yellow]Configured Rate Limits & Timeouts:[/]
  • [bold white]Rate Limit:[/] `30 requests per minute` (burst of 10).
  • [bold white]Timeouts:[/] `30s` for terminal commands, `60s` for general session execution.

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


class InstallProgressModal(ModalScreen):
    """Interactive Modal Screen with Real-Time Progress Bar & Streaming Terminal Output."""

    BINDINGS = [
        ("escape", "dismiss_modal", "Close")
    ]

    def __init__(self, tool_id: str, tool_title: str, action: str = "install"):
        super().__init__()
        self.tool_id = tool_id
        self.tool_title = tool_title
        self.action = action  # "install" or "remove"
        self.engine = HardeningEngine()
        self.is_finished = False

    def compose(self) -> ComposeResult:
        action_verb = "Installing" if self.action == "install" else "Removing"
        action_icon = "🛡️" if self.action == "install" else "🗑️"
        with VerticalScroll(id="install-container"):
            yield Static(
                f"[bold cyan]╔═══════════════════════════════════════════════════════════════════════════╗[/]\n"
                f"[bold cyan]║     {action_icon} {action_verb} Security Component: {self.tool_title:<32}║[/]\n"
                f"[bold cyan]╚═══════════════════════════════════════════════════════════════════════════╝[/]",
                id="install-header"
            )
            yield Label(f"[bold cyan]Component:[/] [bold white]{self.tool_id}[/bold white]  |  [bold cyan]Action:[/] [bold yellow]{self.action.upper()}[/bold yellow]  |  [bold cyan]Target OS:[/] [bold]{OSDetector.get_os_type().upper()}[/bold]", id="install-target-info")
            yield ProgressBar(id="install-progress-bar", total=100, show_eta=False)
            yield Label(f"Initializing {self.action} pipeline...", id="install-step-label")
            yield Label("[bold white]Streaming Terminal Output & Step Logs:[/bold white]", id="install-output-title")
            yield RichLog(id="install-terminal-log", highlight=True, markup=True)
            yield Button("Close (Esc)", id="btn-close-install", variant="primary", disabled=True)

    def on_mount(self) -> None:
        self.run_worker_routine()

    @work(thread=True)
    def run_worker_routine(self) -> None:
        log_widget = self.query_one("#install-terminal-log", RichLog)
        progress_bar = self.query_one("#install-progress-bar", ProgressBar)
        step_label = self.query_one("#install-step-label", Label)
        close_btn = self.query_one("#btn-close-install", Button)

        stream = self.engine.stream_remove_extra_tool(self.tool_id) if self.action == "remove" else self.engine.stream_install_extra_tool(self.tool_id)

        final_success = False
        for item in stream:
            event_type = item[0]
            if event_type == "progress":
                percent = item[1]
                desc = item[2]
                self.app.call_from_thread(progress_bar.update, progress=percent)
                self.app.call_from_thread(step_label.update, f"[bold yellow]▶ {desc}[/bold yellow]")
            elif event_type == "log":
                text = item[1]
                self.app.call_from_thread(log_widget.write, escape(text) if "[" not in text else text)
            elif event_type == "done":
                final_success = item[1]
                summary = item[2]
                status_color = "bold green" if final_success else "bold red"
                status_icon = "✓" if final_success else "✗"
                self.app.call_from_thread(
                    step_label.update,
                    f"[{status_color}]{status_icon} {summary}[/{status_color}]"
                )

        self.is_finished = True
        self.app.call_from_thread(setattr, close_btn, "disabled", False)

    def action_dismiss_modal(self) -> None:
        if self.is_finished:
            self.dismiss()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-close-install":
            event.stop()
            self.dismiss()


class ToolItem(ListItem):
    def __init__(self, policy: HardeningPolicy):
        super().__init__()
        self.policy = policy

    def compose(self) -> ComposeResult:
        status_icon = "●" if self.policy.is_installed else "○"
        status_style = "green" if self.policy.is_installed else "dim"
        cat = self.policy.tool.category.upper()[:3]
        yield Label(f"[{status_style}]{status_icon}[/{status_style}] [{cat}] [bold]{self.policy.tool.vendor}/{self.policy.tool.name}[/bold]")


class HardeningApp(App):
    BINDINGS = [
        ("h", "toggle_help", "Help"),
        ("f1", "toggle_help", "Help"),
        ("question_mark", "toggle_help", "Help"),
        ("d", "view_dlp", "View DLP"),
        ("v", "verify_config", "Verify Config"),
        ("s", "toggle_strict", "Strict Mode"),
        ("q", "quit", "Quit")
    ]

    CSS = """
    Screen {
        background: #1e1e2e;
        color: #cdd6f4;
        overflow: hidden;
    }
    #main-container {
        layout: horizontal;
        height: 1fr;
        width: 100%;
    }
    #sidebar {
        width: 34;
        min-width: 32;
        max-width: 36;
        height: 1fr;
        padding: 0 1;
        border-right: solid #45475a;
    }
    #details-panel {
        width: 1fr;
        height: 1fr;
        padding: 0 1;
    }
    .panel-title {
        text-style: bold;
        color: #89b4fa;
        margin-bottom: 0;
        margin-top: 0;
        height: 1;
    }
    #tools-list {
        height: 1fr;
        min-height: 5;
        border: solid #45475a;
        background: #11111b;
        margin-bottom: 0;
    }
    #apply-action-buttons, #remove-action-buttons, #extras-buttons {
        layout: horizontal;
        height: 1;
        margin-top: 0;
        margin-bottom: 0;
    }
    #extras-buttons Button {
        width: 1fr;
        height: 1;
        border: none;
        margin-right: 1;
        margin-bottom: 0;
        padding: 0 1;
    }
    Button {
        min-width: 6;
        height: 1;
        border: none;
        margin-right: 1;
        margin-bottom: 0;
        padding: 0 1;
    }
    Checkbox {
        margin: 0 1 0 0;
        padding: 0;
        height: 1;
        border: none;
    }
    #btn-view-dlp {
        display: none;
    }
    #policy-details {
        height: 12;
        min-height: 8;
        max-height: 14;
        background: #11111b;
        padding: 0 1;
        border: solid #45475a;
        margin-bottom: 0;
    }
    #log-view {
        height: 1fr;
        min-height: 4;
        border: solid #45475a;
        background: #11111b;
        margin-top: 0;
        margin-bottom: 0;
    }
    #help-container, #dlp-container, #install-container {
        width: 85%;
        max-width: 95;
        height: 85%;
        max-height: 28;
        min-width: 40;
        min-height: 14;
        background: #181825;
        border: thick #89b4fa;
        padding: 1;
        align: center middle;
    }
    #help-text, #dlp-text {
        margin-bottom: 1;
    }
    #install-target-info {
        margin-bottom: 1;
    }
    #install-progress-bar {
        width: 100%;
        margin-top: 1;
        margin-bottom: 1;
    }
    #install-step-label {
        color: #f9e2af;
        margin-bottom: 1;
    }
    #install-output-title {
        color: #89b4fa;
        margin-bottom: 1;
    }
    #install-terminal-log {
        height: 1fr;
        min-height: 5;
        max-height: 10;
        border: solid #45475a;
        background: #11111b;
        margin-bottom: 1;
    }
    #btn-close-help, #btn-close-dlp, #btn-close-install {
        width: 100%;
        height: 1;
        border: none;
    }

    /* Responsive Compact Layout for smaller terminals (< 95 cols or < 28 lines) */
    .compact-mode #main-container {
        layout: vertical;
    }
    .compact-mode #sidebar {
        width: 100%;
        max-width: 100%;
        height: auto;
        max-height: 8;
        border-right: none;
        border-bottom: solid #45475a;
        padding: 0 1;
    }
    .compact-mode #tools-list {
        height: 4;
        min-height: 3;
    }
    .compact-mode #details-panel {
        width: 100%;
        height: 1fr;
        padding: 0 1;
    }
    .compact-mode #policy-details {
        height: 8;
        min-height: 4;
        padding: 0 1;
    }
    .compact-mode #log-view {
        height: 1fr;
        min-height: 3;
    }
    .compact-mode Button {
        min-width: 6;
        height: 1;
        border: none;
        padding: 0 1;
        margin-right: 1;
        margin-bottom: 0;
    }
    .compact-mode .panel-title {
        margin-top: 0;
        margin-bottom: 0;
    }

    /* Ultra-Compact Narrow Layout for narrow screens (< 75 cols) */
    .narrow-mode Button {
        min-width: 5;
        padding: 0 0;
    }
    .narrow-mode #help-container, .narrow-mode #dlp-container, .narrow-mode #install-container {
        width: 98%;
        height: 96%;
        padding: 0 1;
    }
    """

    selected_policy: reactive[Optional[HardeningPolicy]] = reactive(None)
    strict_mode: reactive[bool] = reactive(False)

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
                yield Label("[b]Security Extras & Tools[/b]", classes="panel-title")
                with Horizontal(id="extras-buttons"):
                    yield Button("ai-jail", id="btn-install-jail", variant="default")
                    yield Button("OpenGrep", id="btn-install-opengrep", variant="default")
            with Vertical(id="details-panel"):
                yield Label("[b]Security Policy & Risk Controls[/b]", classes="panel-title")
                with VerticalScroll(id="policy-details"):
                    yield Static("Select a tool from the catalog to inspect host status, security policies, and DLP settings.", id="policy-info")
                yield Label("[b]Policy Actions & Enforcement[/b]", classes="panel-title")
                with Horizontal(id="apply-action-buttons"):
                    yield Button("Apply", id="btn-apply-selected", variant="success")
                    yield Button("Apply Installed", id="btn-apply-installed", variant="primary")
                    yield Button("Apply All", id="btn-apply-all-supported", variant="warning")
                    yield Button("Verify", id="btn-verify-selected", variant="default")
                    yield Button("Fix", id="btn-fix-compliance", variant="success")
                    yield Button("DLP", id="btn-view-dlp", variant="default")
                    yield Checkbox("Dry Run", id="chk-dry-run")
                    yield Checkbox("Strict", id="chk-strict-mode")
                with Horizontal(id="remove-action-buttons"):
                    yield Button("Remove", id="btn-remove-selected", variant="error")
                    yield Button("Remove Installed", id="btn-remove-installed", variant="error")
                    yield Button("Remove All", id="btn-remove-all-supported", variant="error")
                yield Label("[b]Execution Logs & Audit Trail[/b]", classes="panel-title")
                yield RichLog(id="log-view", highlight=True, markup=True)
        yield Footer()

    def on_mount(self) -> None:
        self.title = "Hardening IA Framework"
        self.sub_title = f"Host Platform: {OSDetector.get_os_type().upper()} | Apply & Revert Modes Active"

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

        self._update_extras_buttons()

        # Initial responsive class setup
        if self.size.width < 90 or self.size.height < 26:
            self.add_class("compact-mode")
        if self.size.width < 75:
            self.add_class("narrow-mode")

    def on_resize(self, event: events.Resize) -> None:
        """Dynamically adjusts responsive classes, layout stacking, and title bar metrics based on viewport."""
        w = event.size.width
        h = event.size.height

        if w < 90 or h < 26:
            self.add_class("compact-mode")
        else:
            self.remove_class("compact-mode")

        if w < 75:
            self.add_class("narrow-mode")
        else:
            self.remove_class("narrow-mode")

        installed_count = sum(1 for p in self.policies if p.is_installed) if self.policies else 0
        self.sub_title = f"Host: {OSDetector.get_os_type().upper()} | Terminal: {w}x{h} | Installed: {installed_count}/{len(self.policies)} | Strict: {'ON' if self.strict_mode else 'OFF'}"

    def _update_extras_buttons(self) -> None:
        """Dynamically updates extra tool buttons (tool name & green/red color) based on host installation status."""
        try:
            btn_jail = self.query_one("#btn-install-jail", Button)
            btn_opengrep = self.query_one("#btn-install-opengrep", Button)

            jail_installed = self.engine.is_extra_tool_installed("ai-jail")
            opengrep_installed = self.engine.is_extra_tool_installed("opengrep")

            # Green (success) if installed, Red (error) if not installed
            btn_jail.label = "ai-jail"
            btn_jail.variant = "success" if jail_installed else "error"

            btn_opengrep.label = "OpenGrep"
            btn_opengrep.variant = "success" if opengrep_installed else "error"
        except Exception:
            pass

    def _supports_dlp(self, policy: Optional[HardeningPolicy]) -> bool:
        if not policy:
            return False
        dlp = policy.policies.get("dlp", {})
        return bool(dlp.get("block_sensitive_paths") or dlp.get("disable_code_training_sharing") or dlp.get("mask_secrets"))

    def action_toggle_help(self) -> None:
        self.push_screen(HelpModal())

    def action_toggle_strict(self) -> None:
        chk = self.query_one("#chk-strict-mode", Checkbox)
        chk.value = not chk.value
        self.strict_mode = chk.value
        self._update_details()

    def on_checkbox_changed(self, event: Checkbox.Changed) -> None:
        if event.checkbox.id == "chk-strict-mode":
            self.strict_mode = event.value
            self._update_details()

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

        report = self.verifier.verify_policy(self.selected_policy, strict_mode=self.strict_mode)
        score_style = "bold green" if report.compliance_score == 100.0 else ("bold yellow" if report.compliance_score > 0 else "bold red")
        mode_label = "[bold red][STRICT][/bold red] " if self.strict_mode else "[bold green][STANDARD][/bold green] "
        log_view.write(f"\n[*] Auditing {mode_label}compliance for {self.selected_policy.tool.vendor}/{self.selected_policy.tool.name}...")
        log_view.write(f"  Score: [{score_style}]{report.compliance_score:.1f}% ({report.passed_checks}/{report.total_checks} checks passed)[/]")

        for c in report.checks:
            status_sym = "[green]✓ PASSED[/]" if c.passed else "[red]✗ FAILED[/]"
            escaped_key = escape(str(c.key))
            escaped_expected = escape(str(c.expected))
            escaped_actual = escape(str(c.actual))
            log_view.write(f"    {status_sym} {escaped_key} (expected: {escaped_expected}, actual: {escaped_actual})")
        log_view.write(f"  Summary: [{score_style}]{report.message}[/]")

        if report.compliance_score < 100.0:
            log_view.write("[bold yellow][!] Discrepancies detected. Click 'Fix Compliance' to auto-remediate to 100%.[/bold yellow]\n")
        else:
            log_view.write("[bold green][OK] 100% compliance with security baselines achieved.[/bold green]\n")

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
        settings_path = escape(str(path_info.settings_file if path_info and path_info.settings_file else "N/A"))
        rules_path = escape(str(path_info.rules_dir if path_info and path_info.rules_dir else "N/A"))

        status_badge = "[bold green]● INSTALLED ON HOST[/]" if p.is_installed else "[dim]○ NOT DETECTED ON HOST[/]"
        dlp_list = p.policies.get("dlp", {}).get("block_sensitive_paths", [])
        dlp_count = len(dlp_list)
        sandbox_enforced = p.policies.get("sandbox", {}).get("enforce_sandbox", False)
        telemetry_off = not p.policies.get("telemetry", {}).get("enable_telemetry", True)
        native_overrides = dict(p.policies.get("native_settings_override", {}))

        if self.strict_mode:
            strict_overrides = p.policies.get("strict_rules", {}).get("native_overrides", {})
            native_overrides.update(strict_overrides)
            native_overrides["security.strict_mode"] = True
            native_overrides["security.dangerousPaths.action"] = "block"

        overrides_lines = []
        for k, v in native_overrides.items():
            escaped_k = escape(str(k))
            if isinstance(v, list):
                val_str = ", ".join(str(item) for item in v)
                escaped_v = escape(f"[{val_str}]")
            else:
                escaped_v = escape(str(v))
            overrides_lines.append(f"  [cyan]•[/] [bold white]{escaped_k}[/bold white] [green]➔[/green] [bold yellow]{escaped_v}[/bold yellow]")
        overrides_text = "\n".join(overrides_lines) if overrides_lines else "  [dim]Standard baseline configuration[/dim]"

        dlp_sample = ", ".join([f"`{escape(str(pat))}`" for pat in dlp_list[:6]])
        if dlp_count > 6:
            dlp_sample += f" [dim](+{dlp_count - 6} more patterns)[/dim]"

        dlp_badge = f"[bold green]{dlp_count} Protected Secret Patterns (Click 'View DLP Config' button to inspect)[/bold green]" if has_dlp else "[dim]No DLP rules defined for this tool category[/dim]"

        mode_badge = (
            "[bold red]🔴 STRICT RESTRICTIVE MODE ACTIVE (Immediate Denial / Critical Patterns Active / Zero Prompting)[/bold red]"
            if self.strict_mode else
            "[bold green]🟢 STANDARD MODE ACTIVE (Prompt Before Access / Operator Confirmation Required)[/bold green]"
        )

        danger_action = (
            "[bold red]IMMEDIATE EXPLICIT BLOCK (Block immediately without prompting)[/bold red]"
            if self.strict_mode else
            "[bold yellow]ALWAYS PROMPT BEFORE ACCESS (Confirmation Required)[/bold yellow]"
        )

        critical_action = (
            "[bold red]DENIED PATTERNS ACTIVE (Automatic Rejection without Confirmation)[/bold red]"
            if self.strict_mode else
            "[bold yellow]Strict Multi-Step Operator Confirmation[/bold yellow]"
        )

        dangerous_paths = SecurityPolicyManager.get_dangerous_paths_for_os(os_type)
        sample_danger = ", ".join([f"`{escape(str(dp))}`" for dp in dangerous_paths[:6]]) + f" [dim](+{len(dangerous_paths)-6} more)[/dim]"

        escaped_vendor = escape(str(p.tool.vendor))
        escaped_name = escape(str(p.tool.name.upper()))
        escaped_cat = escape(str(p.tool.category.upper()))
        escaped_desc = escape(str(p.tool.description))

        text = f"""[bold yellow]═══════════════════════════════════════════════════════════════════════[/]
[bold cyan]TOOL:[/] [bold white]{escaped_vendor}/{escaped_name}[/]  |  [bold cyan]CATEGORY:[/] [bold]{escaped_cat}[/]  |  {status_badge}
[dim]{escaped_desc}[/dim]
[bold yellow]═══════════════════════════════════════════════════════════════════════[/]

[bold yellow]🛡️ SECURITY MODE STATUS:[/] {mode_badge}

[bold green]📁 TARGET FILE PATHS & RULES LOCATION ({os_type.upper()}):[/]
  [cyan]• Settings File:[/] [white]{settings_path}[/]
  [cyan]• Agent Rules Dir:[/] [white]{rules_path}[/]

[bold green]⚙️ CONFIGURATION OVERRIDES TO BE APPLIED ({len(native_overrides)} settings):[/]
{overrides_text}

[bold green]🛡️ SECURITY CONTROLS & GUARDRAILS ({os_type.upper()}):[/]
  [cyan]• Dangerous Paths Restriction:[/] {danger_action}
    [dim]Monitoring: {sample_danger}[/dim]
  [cyan]• Critical & Destructive Commands:[/] {critical_action}
  [cyan]• Configured Rate Limit:[/] [bold cyan]30 req/min (Burst 10, Max USD $10.00)[/bold cyan]
  [cyan]• Configured Timeouts:[/] [bold cyan]30s Command / 60s Session / 15s Network[/bold cyan]
  [cyan]• Runtime Sandbox Isolation:[/] {'[bold green]ENFORCED (Bypass Disallowed)[/bold green]' if sandbox_enforced else '[yellow]Optional[/yellow]'}
  [cyan]• Zero-Telemetry & Crash Reporting:[/] {'[bold green]SHUTDOWN (DO_NOT_TRACK=1)[/bold green]' if telemetry_off else '[yellow]Enabled[/yellow]'}
  [cyan]• Data Loss Prevention (DLP):[/] {dlp_badge}
"""
        info_widget.update(text)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        log_view = self.query_one("#log-view", RichLog)
        dry_run = self.query_one("#chk-dry-run", Checkbox).value
        strict_mode = self.query_one("#chk-strict-mode", Checkbox).value

        if event.button.id == "btn-help":
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

        elif event.button.id == "btn-fix-compliance":
            if not self.selected_policy:
                log_view.write("[bold red][!] Please select a tool from the catalog first to fix compliance.[/]")
                return
            mode_prefix = "[bold red][STRICT][/bold red] " if strict_mode else ""
            log_view.write(f"\n[*] {mode_prefix}Remediating configuration baseline for [bold]{self.selected_policy.tool.vendor}/{self.selected_policy.tool.name}[/bold]...")
            res = self.verifier.remediate_policy(self.selected_policy, strict_mode=strict_mode)
            if res.success:
                log_view.write(f"  [bold green][OK] {res.message}[/bold green]")
                self._run_verification_on_selected()
            else:
                log_view.write(f"  [bold red][!] {res.message}[/bold red]")

        elif event.button.id == "btn-apply-selected":
            if not self.selected_policy:
                log_view.write("[bold red][!] Please select a tool from the catalog first.[/]")
                return
            mode_prefix = "[bold yellow][DRY RUN][/bold yellow] " if dry_run else ""
            strict_prefix = "[bold red][STRICT][/bold red] " if strict_mode else ""
            log_view.write(f"[*] {mode_prefix}{strict_prefix}Applying hardening to [bold]{self.selected_policy.tool.vendor}/{self.selected_policy.tool.name}[/bold]...")
            res = self.engine.apply_policy(self.selected_policy, dry_run=dry_run, strict_mode=strict_mode)
            status_style = "bold green" if res.success else "bold red"
            log_view.write(f"  [{status_style}]{res.message}[/]")

        elif event.button.id == "btn-apply-installed":
            installed_policies = [p for p in self.policies if p.is_installed]
            mode_prefix = "[bold yellow][DRY RUN][/bold yellow] " if dry_run else ""
            strict_prefix = "[bold red][STRICT][/bold red] " if strict_mode else ""
            log_view.write(f"\n[*] {mode_prefix}{strict_prefix}Applying policies to {len(installed_policies)} INSTALLED tools on host...")
            if not installed_policies:
                log_view.write("[bold yellow][!] No installed AI tools detected on this host.[/]")
                return
            for p in installed_policies:
                res = self.engine.apply_policy(p, dry_run=dry_run, strict_mode=strict_mode)
                status = "[green][OK][/]" if res.success else "[red][FAILED][/]"
                log_view.write(f"  {status} {p.tool.vendor}/{p.tool.name}")
            log_view.write("[bold green][OK] Host-installed tools hardening completed.[/]\n")

        elif event.button.id == "btn-apply-all-supported":
            mode_prefix = "[bold yellow][DRY RUN][/bold yellow] " if dry_run else ""
            strict_prefix = "[bold red][STRICT][/bold red] " if strict_mode else ""
            log_view.write(f"\n[*] {mode_prefix}{strict_prefix}Proactively provisioning standard configs across ALL {len(self.policies)} supported tools...")
            for p in self.policies:
                res = self.engine.apply_policy(p, dry_run=dry_run, strict_mode=strict_mode)
                status = "[green][OK][/]" if res.success else "[red][FAILED][/]"
                log_view.write(f"  {status} {p.tool.vendor}/{p.tool.name}")
            log_view.write("[bold green][OK] All 14 supported tools provisioned and hardened in standard directories.[/]\n")

        elif event.button.id == "btn-remove-selected":
            if not self.selected_policy:
                log_view.write("[bold red][!] Please select a tool from the catalog first to remove.[/]")
                return
            mode_prefix = "[bold yellow][DRY RUN][/bold yellow] " if dry_run else ""
            log_view.write(f"\n[*] {mode_prefix}Removing hardening for [bold]{self.selected_policy.tool.vendor}/{self.selected_policy.tool.name}[/bold]...")
            res = self.engine.remove_policy(self.selected_policy, dry_run=dry_run)
            status_style = "bold green" if res.success else "bold red"
            log_view.write(f"  [{status_style}]{res.message}[/]")

        elif event.button.id == "btn-remove-installed":
            installed_policies = [p for p in self.policies if p.is_installed]
            mode_prefix = "[bold yellow][DRY RUN][/bold yellow] " if dry_run else ""
            log_view.write(f"\n[*] {mode_prefix}Removing hardening across {len(installed_policies)} INSTALLED tools...")
            if not installed_policies:
                log_view.write("[bold yellow][!] No installed AI tools detected on this host.[/]")
                return
            for p in installed_policies:
                res = self.engine.remove_policy(p, dry_run=dry_run)
                status = "[green][OK][/]" if res.success else "[red][FAILED][/]"
                log_view.write(f"  {status} {p.tool.vendor}/{p.tool.name}")
            log_view.write("[bold green][OK] Host-installed tools removal completed.[/]\n")

        elif event.button.id == "btn-remove-all-supported":
            mode_prefix = "[bold yellow][DRY RUN][/bold yellow] " if dry_run else ""
            log_view.write(f"\n[*] {mode_prefix}Removing hardening across ALL {len(self.policies)} supported tools...")
            for p in self.policies:
                res = self.engine.remove_policy(p, dry_run=dry_run)
                status = "[green][OK][/]" if res.success else "[red][FAILED][/]"
                log_view.write(f"  {status} {p.tool.vendor}/{p.tool.name}")
            log_view.write("[bold green][OK] All supported tools hardening removed.[/]\n")

        elif event.button.id == "btn-install-jail":
            jail_installed = self.engine.is_extra_tool_installed("ai-jail")
            action = "remove" if jail_installed else "install"
            title = "ai-jail (Process Sandbox & Isolation)"
            self.push_screen(
                InstallProgressModal("ai-jail", title, action=action),
                callback=lambda _: self._update_extras_buttons()
            )

        elif event.button.id == "btn-install-opengrep":
            opengrep_installed = self.engine.is_extra_tool_installed("opengrep")
            action = "remove" if opengrep_installed else "install"
            title = "OpenGrep (Static Code Vulnerability Scanner)"
            self.push_screen(
                InstallProgressModal("opengrep", title, action=action),
                callback=lambda _: self._update_extras_buttons()
            )


def run_tui():
    app = HardeningApp()
    app.run()

