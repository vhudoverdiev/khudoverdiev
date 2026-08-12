#!/usr/bin/env python3
"""Convenience launcher for creating or updating admin credentials."""

import runpy
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent
ADMIN_CREDENTIALS_SCRIPT = PROJECT_ROOT / "deploy" / "admin_credentials.py"


def has_option(args, option):
    return any(arg == option or arg.startswith(f"{option}=") for arg in args)


def main():
    args = sys.argv[1:]

    if "-h" not in args and "--help" not in args:
        if not has_option(args, "--username"):
            args = ["--username", "admin", *args]
        if not has_option(args, "--password") and not has_option(args, "--prompt-password"):
            args = [*args, "--prompt-password"]

    sys.argv = [str(ADMIN_CREDENTIALS_SCRIPT), *args]
    runpy.run_path(str(ADMIN_CREDENTIALS_SCRIPT), run_name="__main__")


if __name__ == "__main__":
    main()
