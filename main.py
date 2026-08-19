#!/usr/bin/env python3
"""Hardening IA - Unified Entrypoint (CLI / TUI)

Usage:
  - Without arguments or with '-gui' / '--gui': Launches interactive Textual TUI
  - With command-line arguments: Runs in headless CLI automation mode
"""

import os
import sys
from pathlib import Path


def _ensure_environment():
    """Ensures dependencies are available, auto-activating .venv if detected."""
    try:
        import rich
        import yaml
        import pydantic
        return
    except ImportError:
        pass

    # Check if a project-local .venv exists
    root_dir = Path(__file__).resolve().parent
    venv_pythons = [
        root_dir / ".venv" / "bin" / "python3",
        root_dir / ".venv" / "bin" / "python",
        root_dir / ".venv" / "Scripts" / "python.exe",
        root_dir / "venv" / "bin" / "python3",
        root_dir / "venv" / "bin" / "python",
        root_dir / "venv" / "Scripts" / "python.exe",
    ]

    for venv_python in venv_pythons:
        if venv_python.is_file() and os.path.abspath(sys.executable) != os.path.abspath(str(venv_python)):
            try:
                os.execv(str(venv_python), [str(venv_python)] + sys.argv)
            except Exception:
                pass

    # If re-exec is not possible or dependencies are still missing:
    print("\n" + "=" * 65)
    print(" [!] Hardening IA: Required dependencies are not installed.")
    print("=" * 65)
    print(" To setup the environment and install dependencies:")
    print("   1. Create and activate a virtual environment:")
    print("      python3 -m venv .venv")
    if sys.platform == "win32":
        print("      .venv\\Scripts\\Activate.ps1")
    else:
        print("      source .venv/bin/activate")
    print("   2. Install requirements:")
    print("      pip install -r requirements.txt")
    print("=" * 65 + "\n")
    sys.exit(1)


def main():
    _ensure_environment()
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

