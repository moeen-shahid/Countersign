"""Command line entry point: python -m countersign <command>. See cli.py."""

from __future__ import annotations

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
