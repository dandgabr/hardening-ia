#!/usr/bin/env python3
"""Hardening IA - Unified Entrypoint (CLI / TUI)

Usage:
  - Without arguments or with '-gui' / '--gui': Launches interactive Textual TUI
  - With command-line arguments: Runs in headless CLI automation mode
"""

import sys


def main():
    args = sys.argv[1:]

    if len(args) == 0 or "-gui" in args or "--gui" in args:
        try:
            from src.tui.app import run_tui
            run_tui()
        except ImportError as e:
            print(f"[!] Unable to start Textual TUI ({e}).")
            print("[*] Falling back to CLI mode...")
            from src.cli.runner import run_cli
            run_cli(args)
    else:
        from src.cli.runner import run_cli
        run_cli(args)


if __name__ == "__main__":
    main()
