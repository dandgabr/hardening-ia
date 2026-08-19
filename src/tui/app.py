"""Modern Terminal User Interface (TUI) built with Textual for Hardening IA."""

import logging
from typing import List, Optional
from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical, VerticalScroll
from textual.widgets import Header, Footer, Button, Static, Label, ListView, ListItem, RichLog, Checkbox
from textual.reactive import reactive

from src.core.config_loader import ConfigLoader
from src.core.engine import HardeningEngine
from src.core.os_detector import OSDetector
from src.core.models import HardeningPolicy
from src.core.logger import setup_logging


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


class ToolItem(ListItem):
    def __init__(self, policy: HardeningPolicy):
        super().__init__()
        self.policy = policy

    def compose(self) -> ComposeResult:
        category_tag = f"[{self.policy.tool.category.upper():<7}]"
        status_tag = "● [INSTALLED]" if self.policy.is_installed else "○ [NOT FOUND]"
        status_style = "green" if self.policy.is_installed else "dim"
        yield Label(f"[{status_style}]{status_tag:<14}[/{status_style}] {category_tag} {self.policy.tool.vendor}/{self.policy.tool.name}")


class HardeningApp(App):
    """Textual interactive terminal UI for AI tool hardening and agent management."""

    CSS = """
    Screen {
        background: #1e1e2e;
        color: #cdd6f4;
    }
    Header {
        background: #11111b;
        color: #89b4fa;
        dock: top;
    }
    Footer {
        background: #11111b;
        color: #a6adc8;
        dock: bottom;
    }
    #main-container {
        layout: horizontal;
        height: 1fr;
        padding: 1;
    }
    #sidebar {
        width: 42%;
        background: #181825;
        border: round #313244;
        padding: 1;
    }
    #details-panel {
        width: 58%;
        background: #181825;
        border: round #313244;
        padding: 1;
        margin-left: 1;
    }
    .panel-title {
        text-style: bold;
        color: #89b4fa;
        margin-bottom: 1;
    }
    #tools-list {
        height: 1fr;
        border: solid #45475a;
        background: #11111b;
    }
    #action-buttons {
        layout: horizontal;
        height: auto;
        margin-top: 1;
    }
    Button {
        margin-right: 1;
    }
    #log-view {
        height: 11;
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
    """

    selected_policy: reactive[Optional[HardeningPolicy]] = reactive(None)

    def __init__(self):
        super().__init__()
        self.config_loader = ConfigLoader()
        self.engine = HardeningEngine()
        self.policies: List[HardeningPolicy] = []

    def compose(self) -> ComposeResult:
        os_name = OSDetector.get_os_type().upper()
        yield Header(show_clock=True)
        with Container(id="main-container"):
            with Vertical(id="sidebar"):
                yield Label(f"[b]AI Agents & Tools Catalog ({os_name})[/b]", classes="panel-title")
                yield ListView(id="tools-list")
                with Horizontal(id="action-buttons"):
                    yield Button("Apply Installed", id="btn-apply-installed", variant="primary")
                    yield Button("Apply All", id="btn-apply-all", variant="warning")
                    yield Button("ai-jail", id="btn-install-jail")
            with Vertical(id="details-panel"):
                yield Label("[b]Security Policy & Risk Controls[/b]", classes="panel-title")
                with VerticalScroll(id="policy-details"):
                    yield Static("Select a tool from the catalog to inspect host status and security policies.", id="policy-info")
                with Horizontal():
                    yield Button("Apply to Selected", id="btn-apply-selected", variant="success")
                    yield Checkbox("Dry Run Mode", id="chk-dry-run")
                yield Label("[b]Execution Logs & Audit Trail[/b]", classes="panel-title")
                yield RichLog(id="log-view", highlight=True, markup=True)
        yield Footer()

    def on_mount(self) -> None:
        self.title = "Hardening IA Framework"
        self.sub_title = f"Host Platform: {OSDetector.get_os_type().upper()} | Linux Risk Matrix Active"

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

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        if isinstance(event.item, ToolItem):
            self.selected_policy = event.item.policy
            self._update_details()

    def _update_details(self) -> None:
        if not self.selected_policy:
            return
        p = self.selected_policy
        info_widget = self.query_one("#policy-info", Static)

        os_type = OSDetector.get_os_type()
        path_info = p.paths.get(os_type)
        settings_path = path_info.settings_file if path_info else "N/A"
        rules_path = path_info.rules_dir if path_info and path_info.rules_dir else "N/A"

        status_str = "[bold green]DETECTED ON HOST[/]" if p.is_installed else "[dim]NOT INSTALLED ON HOST[/]"
        dlp_count = len(p.policies.get("dlp", {}).get("block_sensitive_paths", []))
        sandbox_enforced = p.policies.get("sandbox", {}).get("enforce_sandbox", False)
        approvals_enforced = p.policies.get("approvals", {}).get("require_approval_for_terminal", False)
        telemetry_off = not p.policies.get("telemetry", {}).get("enable_telemetry", True)

        text = f"""[bold yellow]Tool:[/] {p.tool.name}
[bold yellow]Vendor:[/] {p.tool.vendor}
[bold yellow]Host Status:[/] {status_str}
[bold yellow]Category:[/] {p.tool.category.upper()}
[bold yellow]Description:[/] {p.tool.description}

[bold cyan]Configuration Path ({os_type}):[/] {settings_path}
[bold cyan]Agent Rules Directory:[/] {rules_path}

[bold green]Security Controls Enforced:[/]
• Linux Command Risk Matrix: Active (Low=Auto, Medium/High/Critical=Approval)
• Runtime Sandbox Enforced: {sandbox_enforced}
• Human Approval Required: {approvals_enforced}
• Sensitive File DLP Blocks: {dlp_count} patterns
• Telemetry & Crash Tracking: {'Disabled' if telemetry_off else 'Enabled'}
"""
        info_widget.update(text)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        log_view = self.query_one("#log-view", RichLog)
        dry_run = self.query_one("#chk-dry-run", Checkbox).value

        if event.button.id == "btn-apply-selected":
            if not self.selected_policy:
                log_view.write("[bold red][!] Please select a tool first.[/]")
                return
            res = self.engine.apply_policy(self.selected_policy, dry_run=dry_run)
            status_style = "bold green" if res.success else "bold red"
            log_view.write(f"[{status_style}]{res.message}[/]")

        elif event.button.id == "btn-apply-installed":
            installed_policies = [p for p in self.policies if p.is_installed]
            log_view.write(f"[*] Applying policies to {len(installed_policies)} INSTALLED tools...")
            if not installed_policies:
                log_view.write("[bold yellow][!] No installed AI tools detected on this host.[/]")
                return
            for p in installed_policies:
                res = self.engine.apply_policy(p, dry_run=dry_run)
                status = "[green][OK][/]" if res.success else "[red][FAILED][/]"
                log_view.write(f"  {status} {p.tool.vendor}/{p.tool.name}")

        elif event.button.id == "btn-apply-all":
            log_view.write(f"[*] Applying policies across ALL {len(self.policies)} tools...")
            for p in self.policies:
                res = self.engine.apply_policy(p, dry_run=dry_run)
                status = "[green][OK][/]" if res.success else "[red][FAILED][/]"
                log_view.write(f"  {status} {p.tool.vendor}/{p.tool.name}")

        elif event.button.id == "btn-install-jail":
            log_view.write("[*] Launching ai-jail installer...")
            success = self.engine.install_extra_tool("ai-jail")
            if success:
                log_view.write("[bold green][OK] ai-jail installed successfully.[/]")
            else:
                log_view.write("[bold red][!] ai-jail installation failed.[/]")


def run_tui():
    app = HardeningApp()
    app.run()
