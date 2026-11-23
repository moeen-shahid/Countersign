"""The command line: `python -m countersign <command>` or `countersign <command>`.

Each feature module owns its own commands. A module that wants commands
defines `add_cli(subparsers)`, adds one or more subparsers there, and sets
`func` on each with `parser.set_defaults(func=handler)`. A handler takes the
parsed `argparse.Namespace` and returns an exit code (None means 0).

Exit codes used across commands:
  0  success
  1  a check failed (audit broken, benchmark drift, invariant violated)
  2  usage or configuration error (no database, bad file, not a terminal)
  3  an optional outside service is unavailable (no API key, no network)
"""

from __future__ import annotations

import argparse
import importlib
import sys
from typing import Sequence

from . import __version__

# Modules that provide commands, in the order they appear in --help.
COMMAND_MODULES = (
    "demo",
    "benchmark",
    "dashboard",
    "quickstart",
    "console",
    "mcp",
    "agent",
    "anchor",
    "fuzz",
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="countersign",
        description="A payment firewall for AI agents. The bank is simulated; no real money moves.",
    )
    parser.add_argument("--version", action="version", version=f"countersign {__version__}")
    commands = parser.add_subparsers(dest="command", metavar="<command>")
    for name in COMMAND_MODULES:
        importlib.import_module(f"{__package__}.{name}").add_cli(commands)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    func = getattr(args, "func", None)
    if func is None:
        parser.print_help()
        return 2
    try:
        return int(func(args) or 0)
    except KeyboardInterrupt:
        return 130
    except BrokenPipeError:
        try:
            sys.stdout.close()
        except OSError:
            pass
        return 0


if __name__ == "__main__":
    sys.exit(main())
