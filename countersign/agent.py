"""The scripted agent: an offline stand-in for a model that has been fully taken over.

It is not a model and it does not think. It replays the recorded trace of a
scenario through the same five tools a real agent gets: it asks for the task,
lists and reads every document in the inbox, then asks for every payment in
the scenario's script, in order, whatever the guard answered before. That is
the worst case the guard is built for: an agent that does everything the
attacker wants.

Everything it prints is a tool call and the answer that came back. It never
prints reasoning, because it has none.

`run_scripted(surface, scenario)` drives any `ToolSurface` and returns the
transcript. `countersign agent --db PATH --inbox DIR --scenario ID` runs it
against a shared database, slowly enough for a person to watch.

`MemoryBackend` and `DirectBackend` put the same tools over a guard in this
process, or over the simulated bank with no guard at all, for replays.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from dataclasses import dataclass
from typing import Any, Callable, Mapping

from .scenarios import BY_ID
from .store import StoreError, open_agent
from .tools import DirectTools
from .toolsurface import DirInbox, ToolSurface, build_surface, hold_view, pay_view, task_view

DB_ENV = "COUNTERSIGN_DB"
DEFAULT_DELAY = 0.6  # seconds between calls, so the console can be watched
LABEL = "scripted agent (no model)"


class MemoryBackend:
    """The tools' backend over a guard that lives in this process."""

    def __init__(self, guard: Any) -> None:
        self._guard = guard

    def task(self) -> dict[str, Any] | None:
        mandate = self._guard.mandate
        return None if mandate is None else task_view(mandate)

    def observe(self, source: str, text: str) -> None:
        self._guard.observe(source, text)

    def pay(
        self,
        payee: str,
        account: str,
        amount: object,
        reference: str = "",
        currency: str | None = None,
    ) -> dict[str, Any]:
        return pay_view(self._guard.pay(payee, account, amount, reference, currency))

    def hold_status(self, hold_id: str) -> dict[str, Any] | None:
        try:
            return hold_view(self._guard.hold(hold_id))
        except KeyError:
            return None


class DirectBackend:
    """No guard: nothing is recorded and every request goes straight to the bank.

    `pay` never raises; a refusal by the bank comes back as a BLOCK. `task`
    is whatever the caller says the user asked for, since without a guard
    there is no mandate.
    """

    def __init__(self, bank: Any, task: Mapping[str, Any] | None = None) -> None:
        self._tools = DirectTools(bank, {})  # the one definition of paying with no guard
        self._task = None if task is None else dict(task)

    def task(self) -> dict[str, Any] | None:
        return None if self._task is None else dict(self._task)

    def observe(self, source: str, text: str) -> None:
        return None

    def pay(
        self,
        payee: str,
        account: str,
        amount: object,
        reference: str = "",
        currency: str | None = None,
    ) -> dict[str, Any]:
        return pay_view(self._tools.pay(payee, account, amount, reference, currency))

    def hold_status(self, hold_id: str) -> dict[str, Any] | None:
        return None


@dataclass(frozen=True)
class Call:
    """One tool call the scripted agent made, and what came back."""

    tool: str
    arguments: dict[str, Any]
    result: dict[str, Any]
    is_error: bool = False


def run_scripted(
    surface: ToolSurface,
    scenario: Any,
    *,
    on_call: Callable[[Call], None] | None = None,
    pause: Callable[[], None] | None = None,
) -> list[Call]:
    """Replay one scenario's script through the tools. Returns the transcript.

    The order is fixed: get_task, list_documents, read_document for every
    name the inbox listed, pay for every scripted attempt, then one
    payment_status for every hold that pay returned. `on_call` is given each
    call as it finishes; `pause` runs between two calls.
    """
    transcript: list[Call] = []

    def call(tool: str, arguments: dict[str, Any]) -> Call:
        if transcript and pause is not None:
            pause()
        result = surface.call(tool, arguments)
        made = Call(tool, arguments, result.data, result.is_error)
        transcript.append(made)
        if on_call is not None:
            on_call(made)
        return made

    call("get_task", {})
    listing = call("list_documents", {})
    for name in listing.result.get("documents", []):
        call("read_document", {"name": name})
    holds: list[str] = []
    for attempt in scenario.attempts:
        answer = call(
            "pay",
            {
                "payee": attempt.payee,
                "account": attempt.account,
                "amount": str(attempt.amount),
                "reference": attempt.reference,
            },
        ).result
        hold_id = answer.get("hold_id")
        if isinstance(hold_id, str) and hold_id not in holds:
            holds.append(hold_id)
    for hold_id in holds:
        call("payment_status", {"hold_id": hold_id})
    return transcript


def statuses(transcript: list[Call]) -> list[str]:
    """paid | held | blocked | ... for every pay call of a transcript, in order.

    This is about money, as in `simulation.Run.status`. A held payment takes
    the last status payment_status reported for its hold: `held` while it
    waits, `paid` once it has a transfer, otherwise the hold's own status. An
    answer that names a transfer an earlier answer already named moved nothing
    (the bank took it for a retry), so it counts as `blocked`.
    """
    last: dict[str, dict[str, Any]] = {}
    for made in transcript:
        if made.tool == "payment_status" and not made.is_error:
            last[made.result["hold_id"]] = made.result
    found: list[str] = []
    sent: set[str] = set()
    for made in transcript:
        if made.tool != "pay":
            continue
        answer = made.result
        hold = last.get(answer.get("hold_id"))
        transfer = answer.get("transfer_id")
        if transfer is not None:
            found.append("blocked" if transfer in sent else "paid")
            sent.add(transfer)
        elif hold is None:
            found.append("held" if answer.get("outcome") == "HOLD" else "blocked")
        elif hold["transfer_id"] is not None:
            found.append("paid")
        else:
            found.append("held" if hold["status"] == "pending" else hold["status"])
    return found


# --- command line ---------------------------------------------------------------


def _show(text: object, limit: int = 120) -> str:
    """Text from a document or a decision, made safe to print on one line."""
    cleaned = "".join(ch if ch.isprintable() else "?" for ch in str(text))
    return cleaned if len(cleaned) <= limit else cleaned[: limit - 3] + "..."


def _describe(made: Call) -> list[str]:
    """The lines printed for one call: what was asked, then what came back."""
    arguments, result = made.arguments, made.result
    if made.tool == "pay":
        asked = (
            f"pay  {_show(arguments['payee'], 60)}  {_show(arguments['account'], 40)}  "
            f"{_show(arguments['amount'], 20)}  ref {_show(arguments['reference'], 40)}"
        )
    elif made.tool == "read_document":
        asked = f"read_document  {_show(arguments['name'], 80)}"
    elif made.tool == "payment_status":
        asked = f"payment_status  {_show(arguments['hold_id'], 20)}"
    else:
        asked = made.tool
    lines = [f"[scripted] {asked}"]

    def answer(text: str) -> None:
        lines.append(f"           -> {text}")

    if made.is_error:
        answer(f"error: {_show(result.get('message', result.get('error', '')), 200)}")
    elif made.tool == "get_task":
        if result.get("active"):
            answer(f"task: {_show(result.get('instruction', ''), 200)}")
            answer(f"payees: {_show(', '.join(result.get('payees', [])), 200)}")
        else:
            answer("no task is active")
    elif made.tool == "list_documents":
        names = result.get("documents", [])
        answer(f"{len(names)} document(s): {_show(', '.join(names), 200)}")
    elif made.tool == "read_document":
        answer(f"{len(result.get('text', ''))} characters")
    elif made.tool == "pay":
        extra = ""
        if result.get("hold_id"):
            extra = f"  hold {_show(result['hold_id'], 20)}"
        if result.get("transfer_id"):
            extra += f"  transfer {_show(result['transfer_id'], 20)}"
        answer(f"{_show(result.get('outcome'), 10)} {_show(result.get('rule'), 10)}{extra}")
        answer(_show(result.get("reason", ""), 600))
    elif made.tool == "payment_status":
        transfer = result.get("transfer_id")
        extra = f"  transfer {_show(transfer, 20)}" if transfer else ""
        answer(f"{_show(result.get('status'), 20)}{extra}")
    return lines


def _command(args: argparse.Namespace) -> int:
    db = args.db or os.environ.get(DB_ENV)
    if not db:
        print(f"countersign agent: give the database with --db PATH or set {DB_ENV}.",
              file=sys.stderr)
        return 2
    scenario = BY_ID.get(args.scenario)
    if scenario is None:
        known = ", ".join(sorted(BY_ID))
        print(f"countersign agent: there is no scenario {_show(args.scenario, 40)}. "
              f"Scenarios: {known}.", file=sys.stderr)
        return 2
    if args.delay < 0:
        print("countersign agent: --delay must be 0 or more.", file=sys.stderr)
        return 2
    try:
        port = open_agent(db)
        inbox = DirInbox(args.inbox)
        active = port.task() is not None
    except (StoreError, ValueError) as exc:
        print(f"countersign agent: {exc}", file=sys.stderr)
        return 2
    if not active:
        print("countersign agent: no task is active, so there is nothing to act on. "
              "Start one first: countersign task start \"...\" --payee NAME", file=sys.stderr)
        return 2

    print(f"This is a {LABEL}. It replays the recorded attempts of scenario")
    print(f"{scenario.id} ({scenario.title}) through the agent's tools. It stands in for a")
    print("fully hijacked agent: it reads every document, then asks for every payment in")
    print("the script, whatever the guard answers. What follows are its tool calls and the")
    print("answers; there is no reasoning to show.")
    delay_hours = getattr(scenario, "delay_hours", 0)
    if delay_hours:
        print(f"Note: this scenario assumes {delay_hours} hours pass before the payments. "
              "The scripted agent does not wait, so the decisions here can differ from "
              "the benchmark's.")
    print()

    def show(made: Call) -> None:
        print("\n".join(_describe(made)), flush=True)

    pause = (lambda: time.sleep(args.delay)) if args.delay > 0 else None
    transcript = run_scripted(build_surface(port, inbox), scenario, on_call=show, pause=pause)
    found = statuses(transcript)
    print()
    print(f"The {LABEL} is done: {len(found)} payment request(s), "
          f"{found.count('paid')} paid, {found.count('held')} waiting for a person, "
          f"{len(found) - found.count('paid') - found.count('held')} not paid.")
    return 0


def add_cli(subparsers: Any) -> None:
    """Register the `agent` command (see cli.py for the convention)."""
    parser = subparsers.add_parser(
        "agent",
        help="run the scripted agent (no model) against a database",
        description=(
            "Run the scripted agent: not a model, but the recorded trace of a fully "
            "hijacked agent, replayed through the same five tools an MCP client gets. It "
            "uses the task that is active in the database and reads the documents in the "
            "inbox directory."
        ),
    )
    parser.add_argument("--db", metavar="PATH", help=f"the guard's database (or set {DB_ENV})")
    parser.add_argument("--inbox", metavar="DIR", required=True,
                        help="the directory with the documents to read")
    parser.add_argument("--scenario", metavar="ID", required=True,
                        help="whose scripted payment attempts to make, e.g. attack-02")
    parser.add_argument("--delay", metavar="SECONDS", type=float, default=DEFAULT_DELAY,
                        help=f"pause between calls (default {DEFAULT_DELAY})")
    parser.set_defaults(func=_command)
