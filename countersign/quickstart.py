"""`countersign quickstart`: a working demo directory in one command.

It creates a directory with a database (the demo vendors and a simulated bank
account), an inbox holding one scenario's documents as files, and a receipts
file. It shows the mandate that scenario's user would sign, asks before
signing it, starts the task, and then prints how to connect an agent: the MCP
configuration, the `claude mcp add` command and the command for the scripted
agent. Unless told not to, it then starts the web console.

Nothing here is special: every step is one of the ordinary commands (`init`,
`task start`, `mcp`, `agent`, `dashboard`) or the call behind it.
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import sys
from datetime import datetime, timezone
from typing import Any

from . import mcp
from .agent import one_task_ids, several_tasks
from .console import confirm, default_name, describe_confirmation, is_terminal, show
from .drafting import draft_mandate
from .scenarios import BY_ID
from .simulation import scenario_mandate, scenario_vendors
from .store import Store, StoreError

DEFAULT_DIR = "countersign-demo"
DEFAULT_SCENARIO = "attack-02"
DEFAULT_PORT = 8377
DB_NAME = "countersign.db"

CAVEAT = (
    "If your agent has a shell or file access as this user, it can reach this database "
    "directly. Use an agent without those tools, or run it in a container."
)


def _fail(message: str, code: int = 2) -> int:
    print(f"countersign quickstart: {message}", file=sys.stderr)
    return code


def _write_inbox(inbox: str, documents: dict[str, str]) -> list[str]:
    """Write a scenario's documents as files. Returns the names written.

    A name is used only if it is a plain relative path; the scenarios' own
    names all are.
    """
    written: list[str] = []
    for name, text in documents.items():
        parts = name.split("/")
        if os.path.isabs(name) or any(part in ("", ".", "..") for part in parts):
            continue
        path = os.path.join(inbox, *parts)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        # newline="": the file holds exactly the scenario's text.
        with open(path, "w", encoding="utf-8", errors="replace", newline="") as fp:
            fp.write(text)
        written.append(name)
    return written


def _source_checkout() -> str | None:
    """The directory to put on PYTHONPATH if this package is not installed.

    When Countersign runs straight from a checkout, `python -m countersign`
    only works from that directory, and an MCP client starts its servers from
    wherever it happens to be.
    """
    parent = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    marker = os.path.join(parent, "pyproject.toml")
    return parent if os.path.isfile(marker) else None


def _serve(port: int, db: str) -> int:
    from .dashboard import serve

    print("Starting the web console (Ctrl+C stops it; the database stays).")
    serve(port, db=db)
    return 0


def _command(args: argparse.Namespace) -> int:
    scenario = BY_ID.get(args.scenario)
    if scenario is None:
        return _fail(f"there is no scenario {show(args.scenario, 40)}. "
                     f"Scenarios: {', '.join(sorted(one_task_ids()))}.")
    refused = several_tasks(scenario)
    if refused is not None:
        return _fail(refused)
    if not args.yes and not is_terminal():
        return _fail("signing the demo mandate needs a person at a terminal (or pass --yes).")
    root = os.path.abspath(args.dir)
    db = os.path.join(root, DB_NAME)
    inbox = os.path.join(root, "inbox")
    receipts = os.path.join(root, "receipts.jsonl")
    if os.path.exists(db):
        return _fail(f"there is already a database at {db}. Choose another --dir, "
                     "or delete that directory to start again.")
    try:
        os.makedirs(inbox, exist_ok=True)
        names = _write_inbox(inbox, scenario.documents)
        # The scenario's own vendor file: the demo vendors, plus any supplier it adds.
        store = Store.create(db, vendors=scenario_vendors(scenario), receipts=receipts,
                             inbox=inbox)
    except (OSError, ValueError, StoreError) as exc:
        return _fail(f"could not set up {root}: {exc}")

    print(f"Created {root}")
    print(f"  {DB_NAME:<16} the guard's database: demo vendors, a simulated bank account")
    print(f"  {'inbox/':<16} {len(names)} document(s) of scenario {scenario.id}: "
          f"{show(', '.join(names))}")
    print(f"  {'receipts.jsonl':<16} copies of the audit head. They only prove something "
          "if kept where this machine cannot rewrite them.")
    print()
    print(f"Scenario {scenario.id}: {show(scenario.title)}")
    print(f"  {show(scenario.summary, 400)}")
    print()

    now = datetime.now(timezone.utc)
    mandate = scenario_mandate(scenario, lambda: now)
    # The same confirmation `task start` shows: the mandate, and every reading of
    # the sentence with the words it came from. scenario_mandate drafts it the same way.
    vendors = scenario_vendors(scenario)
    draft = draft_mandate(scenario.instruction, vendors, scenario.payees)
    print("Mandate to sign (what this scenario's user asks for)")
    print("\n".join(describe_confirmation(mandate, draft, vendors, now, hint=False)))
    if not args.yes and not confirm("Sign this mandate? [y/N] "):
        print("Nothing was signed. The database and the inbox are ready; start a task "
              f"yourself with: python -m countersign task start \"...\" --payee NAME --db {db}")
        return 1
    try:
        # The digest says which reading of the sentence was confirmed (task_started).
        store.console().start_task(mandate, confirmed_by=default_name(),
                                   draft_digest=draft.digest())
    except (ValueError, StoreError) as exc:
        return _fail(f"the task was not started: {exc}", 1)
    print(f"Task started: {mandate.id}.")
    print()

    block = mcp.config_block(db, inbox)
    server = block["mcpServers"]["countersign"]
    command = " ".join(shlex.quote(part) for part in [server["command"], *server["args"]])
    checkout = _source_checkout()
    env = f"-e PYTHONPATH={shlex.quote(checkout)} " if checkout else ""
    print("Connect an agent. MCP configuration:")
    print(json.dumps(block, indent=2))
    print()
    print("Or, for Claude Code:")
    print(f"  claude mcp add countersign {env}-- {command}")
    if checkout:
        print(f"Countersign seems to be running from a checkout ({checkout}). An MCP "
              "client starts its servers from its own directory, so unless the package is "
              f'installed the server entry also needs "env": {{"PYTHONPATH": '
              f"{json.dumps(checkout)}}} (the claude command above already passes it).")
    print()
    print("Or run the scripted agent (no model; it replays this scenario's recorded attempts):")
    print(f"  {shlex.quote(sys.executable)} -m countersign agent --db {shlex.quote(db)} "
          f"--inbox {shlex.quote(inbox)} --scenario {scenario.id}")
    print()
    print(CAVEAT)
    print()
    if args.no_serve:
        print("Decide held payments with: python -m countersign holds list --db "
              f"{shlex.quote(db)}")
        print("Approving a payment whose account is in question asks you to type back the "
              "whole account, as the vendor confirmed it to you on a number you already had. "
              "Rejecting one asks what was wrong: the account, or only this payment.")
        return 0
    return _serve(args.port, db)


def add_cli(subparsers: Any) -> None:
    """Register the `quickstart` command (see cli.py for the convention)."""
    parser = subparsers.add_parser(
        "quickstart",
        help="set up a demo directory and connect an agent to it",
        description=(
            "Create a demo directory (database, inbox with one scenario's documents, "
            "receipts file), sign that scenario's mandate after asking, print how to "
            "connect an agent, and start the web console."
        ),
    )
    parser.add_argument("--dir", metavar="DIR", default=DEFAULT_DIR,
                        help=f"where to create it (default ./{DEFAULT_DIR})")
    parser.add_argument("--scenario", metavar="ID", default=DEFAULT_SCENARIO,
                        help=f"whose documents and mandate to use (default {DEFAULT_SCENARIO})")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT,
                        help=f"port for the web console (default {DEFAULT_PORT})")
    parser.add_argument("--no-serve", action="store_true",
                        help="set everything up but do not start the web console")
    parser.add_argument("--yes", action="store_true",
                        help="sign the demo mandate without asking (needed without a terminal)")
    parser.set_defaults(func=_command)
