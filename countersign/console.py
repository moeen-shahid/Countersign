"""The person's side on the command line: `init`, `task` and `holds`.

    countersign init --db PATH [--demo-vendors | --vendors FILE.json] [--mode MODE]
    countersign task start "SENTENCE" --payee NAME [--limit AMT] [--budget AMT] ...
    countersign task show | end
    countersign holds list | show ID | approve ID [--remember-account] | reject ID

These commands start and end tasks and decide held payments. They are for a
person. Deciding a hold needs a terminal and a typed "yes", so a program that
can only pipe text into this command does not get a payment through.

That is a speed bump, not a wall, and it is stated as one: a program running
as the same user can set an environment variable, open a terminal of its own
or write to the database file directly. See the threat model in the README.

The database is the one named by --db, else by COUNTERSIGN_DB, else
./countersign.db. Exit codes: 0 done, 1 not done (declined, refused, already
decided), 2 usage or configuration error (no database, bad file, not a
terminal).
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import secrets
import sys
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any, Iterable, Sequence

from .guard import Hold
from .iban import find_ibans, fmt_iban
from .models import Mandate, money, name_key, parse_amount, typed_accounts
from .policy import GUARD_MODES, rule_title
from .simulation import default_vendors
from .store import Store, StoreError, StoreExists
from .vendors import Vendor, VendorFile

DB_ENV = "COUNTERSIGN_DB"
DEFAULT_DB = "countersign.db"
SCRIPTED_ENV = "COUNTERSIGN_ALLOW_SCRIPTED_APPROVAL"

DEFAULT_LIMIT = Decimal("2000.00")
DEFAULT_BUDGET = Decimal("3000.00")
MAX_HOURS = 24 * 31  # the same limit as the web console
DEFAULT_HOURS = 8.0

CHECKED = "checked with the vendor using contact details I already had"
NOT_CHECKED = "not checked"


class _Stop(Exception):
    """End the command with one line on stderr and an exit code."""

    def __init__(self, message: str, code: int = 2) -> None:
        super().__init__(message)
        self.code = code


# --- small shared pieces (quickstart.py uses them too) -------------------------------


def db_path(args: argparse.Namespace) -> str:
    return getattr(args, "db", None) or os.environ.get(DB_ENV) or DEFAULT_DB


def is_terminal() -> bool:
    """True if a person can be asked: standard input is a terminal."""
    try:
        return sys.stdin is not None and sys.stdin.isatty()
    except (AttributeError, ValueError):
        return False


def ask(prompt: str) -> str:
    try:
        return input(prompt)
    except EOFError:
        return ""


def confirm(prompt: str) -> bool:
    """A yes/no question. Anything but y or yes is a no."""
    return ask(prompt).strip().lower() in ("y", "yes")


def show(text: object, limit: int = 200) -> str:
    """Text that may come from a document or an agent, made safe to print."""
    cleaned = "".join(ch if ch.isprintable() else "?" for ch in str(text))
    return cleaned if len(cleaned) <= limit else cleaned[: limit - 3] + "..."


def default_name() -> str:
    """Who is at the keyboard, for the audit log. Recorded, not verified."""
    try:
        return getpass.getuser() or "console user"
    except (KeyError, OSError):
        return "console user"


def _when(moment: datetime) -> str:
    return f"{moment.astimezone(timezone.utc):%Y-%m-%d %H:%M} UTC"


def _stamp(text: object) -> str:
    """A time from the log (ISO text) the way people read it; shown as it is if unreadable."""
    try:
        return _when(datetime.fromisoformat(str(text)))
    except ValueError:
        return show(text, 40)


def draft_payees(instruction: str, vendor_names: Iterable[str]) -> list[str]:
    """Vendors from the vendor file that a sentence seems to name.

    A vendor is suggested when the sentence contains the first two words of
    its name (the whole name if it has fewer than three words): "Nimbus
    Hosting" suggests "Nimbus Hosting Ltd". This is only a suggestion for a
    person to confirm. The guard never matches names loosely.
    """
    words = name_key(instruction).split()
    found: list[str] = []
    for name in vendor_names:
        key = name_key(name).split()
        lead = key if len(key) < 3 else key[:2]
        size = len(lead)
        if size and any(words[i : i + size] == lead for i in range(len(words) - size + 1)):
            found.append(name)
    return found


def describe_mandate(
    mandate: Mandate, vendors: VendorFile | None = None, now: datetime | None = None
) -> list[str]:
    """The lines a person reads before signing a mandate."""
    unit = mandate.currency
    lines = [
        f"  Instruction   {show(mandate.instruction, 400)}",
        f"  May be paid   {', '.join(show(p) for p in mandate.payees)}",
        f"  Per payment   up to {unit} {money(mandate.max_per_payment)}",
        f"  Task budget   {unit} {money(mandate.max_total)} in total",
    ]
    if mandate.max_payments is None:
        lines.append("  Payments      any number, inside the budget")
    else:
        lines.append(f"  Payments      at most {mandate.max_payments}")
    if mandate.references:
        lines.append(f"  Invoices      only {', '.join(show(r) for r in mandate.references)}")
    else:
        lines.append("  Invoices      any reference")
    expires = _when(mandate.expires_at)
    if now is not None:
        hours = (mandate.expires_at - now).total_seconds() / 3600
        expires += f" (in {round(hours, 1):g} hours)" if hours > 0 else " (already past)"
    lines.append(f"  Expires       {expires}")

    typed = {match.account for match in find_ibans(mandate.instruction)}
    if mandate.accounts:
        lines.append("  Accounts you are trusting for this task:")
        for payee, accounts in mandate.accounts.items():
            on_file = vendors.accounts_for(payee) if vendors is not None else frozenset()
            for account in accounts:
                source = "written in your sentence" if account in typed else "given with --account"
                lines.append(f"    {show(payee)}: {fmt_iban(account)}  ({source})")
                if on_file and account not in on_file:
                    lines.append(
                        "      The vendor file has a different account for this payee and it "
                        "outranks yours: a payment to this account will be held."
                    )
    else:
        lines.append("  Accounts you are trusting for this task: none")
    unbound = sorted(typed - {a for accounts in mandate.accounts.values() for a in accounts})
    if unbound:
        lines.append(
            f"  Your sentence names {len(unbound)} account(s) that are not tied to a payee: "
            + ", ".join(fmt_iban(a) for a in unbound)
        )
        lines.append("    With more than one payee, say whose it is: --account PAYEE=IBAN.")
    return lines


def describe_hold(hold: Hold) -> list[str]:
    """Everything a person needs to decide one hold: both accounts in full and
    every reason."""
    request, decision, evidence = hold.request, hold.decision, hold.decision.evidence
    amount = "?" if request.amount is None else money(request.amount)
    lines = [
        f"Hold {hold.id}  ({hold.status})  task {show(hold.task_id, 80)}",
        f"  Payee       {show(request.payee)}",
        f"  Amount      {request.currency or ''} {amount}".rstrip(),
        f"  Reference   {show(request.reference)}",
        f"  Pay to      {fmt_iban(show(request.account, 60))}",
    ]
    on_file = evidence.on_file if evidence is not None else ()
    if on_file:
        for account in on_file:
            lines.append(f"  On file     {fmt_iban(account)}")
    else:
        lines.append("  On file     no account on file for this payee")
    if evidence is not None and evidence.on_file_for:
        lines.append(f"  Note        this account is on file for {show(evidence.on_file_for)}")
    if hold.created_at:
        lines.append(f"  Asked       {_stamp(hold.created_at)}")
    lines.append("")
    lines.append("  Why it is held:")
    for rule in decision.rules or (decision.rule,):
        lines.append(f"    {rule}  {rule_title(rule)}")
    lines.append(f"  {show(decision.reason, 2000)}")
    if evidence is not None:
        lines.append("")
        if evidence.sightings:
            lines.append("  Where this account was written:")
            for sighting in evidence.sightings:
                if sighting.origin == "user":
                    lines.append(f"    your instruction, line {sighting.line}")
                else:
                    lines.append(
                        f"    untrusted document {show(sighting.source, 60)}, line "
                        f"{sighting.line}  (the sender chose that name)"
                    )
        else:
            lines.append("  This account was not written in your instruction or in any "
                         "document the agent read.")
        if evidence.history:
            paid = ", ".join(money(Decimal(a)) for a in evidence.history)
            lines.append(f"  Earlier payments to this payee: {paid}")
        if evidence.previous_payment:
            before = evidence.previous_payment
            lines.append(
                f"  This reference was paid before: {show(before.get('amount'), 20)} "
                f"(transfer {show(before.get('transfer'), 20)}, {_stamp(before.get('time'))})"
            )
    lines.append("")
    lines.append(f"  Digest      {hold.digest}")
    if hold.status != "pending":
        by = f" by {show(hold.decided_by, 60)}" if hold.decided_by else ""
        when = f" at {_stamp(hold.decided_at)}" if hold.decided_at else ""
        lines.append(f"  Decided     {hold.status}{by}{when}")
        if hold.transfer_id:
            lines.append(f"  Transfer    {hold.transfer_id}")
        if hold.attestation:
            lines.append(f"  Said        {show(hold.attestation)}")
    return lines


def load_vendors(path: str) -> VendorFile:
    """Read a vendor file: a JSON list of {"name", "accounts", "history"}.

    `accounts` are IBANs and `history` past payment amounts as text; both may
    be left out. Raises ValueError with a plain message for anything else.
    """
    try:
        with open(path, encoding="utf-8") as fp:
            raw = json.load(fp)
    except OSError as exc:
        raise ValueError(f"Cannot read {path}: {exc.strerror or exc}.") from None
    except (ValueError, RecursionError):
        raise ValueError(f"{path} is not JSON.") from None
    if not isinstance(raw, list):
        raise ValueError(f"{path} must hold a list of vendors.")
    vendors: list[Vendor] = []
    for index, item in enumerate(raw, start=1):
        name = item.get("name") if isinstance(item, dict) else None
        accounts = item.get("accounts", []) if isinstance(item, dict) else None
        history = item.get("history", []) if isinstance(item, dict) else None
        if not isinstance(name, str) or not name.strip():
            raise ValueError(f"{path}: vendor {index} needs a name.")
        if not isinstance(accounts, list) or not isinstance(history, list):
            raise ValueError(f"{path}: vendor {index}: accounts and history must be lists.")
        if not all(isinstance(account, str) for account in accounts):
            raise ValueError(f"{path}: vendor {index}: every account must be an IBAN as text.")
        amounts = [parse_amount(value) for value in history]
        if any(amount is None or amount <= 0 for amount in amounts):
            raise ValueError(f"{path}: vendor {index}: history must be amounts like \"480.00\".")
        vendors.append(Vendor(name.strip(), set(accounts), amounts))
    try:
        return VendorFile(vendors)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"{path}: {exc}") from None


# --- commands -----------------------------------------------------------------------


def _open(args: argparse.Namespace) -> Store:
    try:
        return Store(db_path(args))
    except StoreError as exc:
        hint = " Create one with: countersign init" if "No database" in str(exc) else ""
        raise _Stop(f"{exc}{hint}") from None


def _amount(text: str | None, flag: str, default: Decimal) -> Decimal:
    if text is None:
        return default
    value = parse_amount(text)
    if value is None or value <= 0:
        raise _Stop(f"{flag} must be a plain amount such as 2000 or 2000.00.")
    return value


def _init(args: argparse.Namespace) -> int:
    path = db_path(args)
    try:
        if args.vendors is not None:
            vendors = load_vendors(args.vendors)
        else:
            vendors = default_vendors() if args.demo_vendors else VendorFile()
        store = Store.create(path, vendors=vendors, mode=args.mode)
    except StoreExists:
        raise _Stop(f"There is already a file at {os.path.abspath(path)}. Nothing was changed.")
    except (ValueError, OSError) as exc:
        raise _Stop(str(exc)) from None
    state = store.state()
    seq, digest = store.head()
    print(f"Created {store.path}")
    print(f"  Guard mode      {state['mode']}")
    print(f"  Vendors on file {len(state['vendors'])}")
    print(f"  Simulated bank  balance {money(Decimal(state['bank']['balance']))} "
          "(no real money moves)")
    print(f"  Audit log       entry {seq}, head {digest}")
    print("Next: countersign task start \"what the agent should do\" --payee NAME")
    return 0


def _accounts(pairs: Sequence[str]) -> dict[str, tuple[str, ...]]:
    found: dict[str, tuple[str, ...]] = {}
    for pair in pairs:
        payee, sep, account = pair.rpartition("=")
        if not sep or not payee.strip() or not account.strip():
            raise _Stop("--account takes PAYEE=IBAN, for example "
                        "--account \"Fernhill Design=NL91 ABNA 0417 1643 00\".")
        found[payee.strip()] = found.get(payee.strip(), ()) + (account.strip(),)
    return found


def _task_start(args: argparse.Namespace) -> int:
    store = _open(args)
    state = store.state()
    vendors = VendorFile.from_state(state["vendors"])
    explicit = bool(args.payee)
    payees = list(args.payee) if explicit else draft_payees(
        args.sentence, [vendor.name for vendor in vendors.all()]
    )
    if not payees:
        raise _Stop("Say who may be paid with --payee NAME. The sentence names no vendor "
                    "from the vendor file.")
    limit = _amount(args.limit, "--limit", DEFAULT_LIMIT)
    budget = _amount(args.budget, "--budget", max(DEFAULT_BUDGET, limit))
    if not (0 < args.hours <= MAX_HOURS):  # also false for NaN and infinity
        raise _Stop(f"--hours must be more than 0 and at most {MAX_HOURS}.")
    accounts: dict[str, tuple[str, ...]] = dict(typed_accounts(args.sentence, payees))
    for payee, values in _accounts(args.account).items():
        accounts[payee] = accounts.get(payee, ()) + values
    now = datetime.now(timezone.utc)
    try:
        mandate = Mandate(
            id=f"task-{now:%Y%m%d-%H%M%S}-{secrets.token_hex(2)}",
            instruction=args.sentence,
            payees=tuple(payees),
            max_per_payment=limit,
            max_total=budget,
            expires_at=now + timedelta(hours=args.hours),
            max_payments=args.payments,
            references=tuple(args.reference),
            accounts=accounts,
        )
    except ValueError as exc:
        raise _Stop(f"This is not a mandate that can be signed: {exc}.") from None

    print("Mandate to sign")
    print("\n".join(describe_mandate(mandate, vendors, now)))
    if not explicit:
        print("  The payees above were suggested from the vendor file. Check them.")
    if state["mandate"] is not None:
        print(f"A task is active now ({show(state['mandate']['id'], 80)}). Signing this one "
              "ends it, and payments still waiting under it expire.")
    if not (args.yes and explicit):
        if not is_terminal():
            why = "--yes needs the payees given with --payee" if args.yes else "or pass --yes"
            raise _Stop(f"Signing a mandate needs a person at a terminal ({why}).")
        if not confirm("Sign this mandate? [y/N] "):
            print("Nothing was signed.")
            return 1
    try:
        store.console().start_task(mandate, confirmed_by=args.signer or default_name())
    except (ValueError, TypeError, StoreError) as exc:
        raise _Stop(f"The task was not started: {exc}", 1) from None
    print(f"Task started: {mandate.id}. The agent can now ask for payments inside it.")
    return 0


def _task_show(args: argparse.Namespace) -> int:
    store = _open(args)
    state = store.state()
    if state["mandate"] is None:
        print("No task is active. Every payment is refused until one is started.")
        return 0
    mandate = Mandate.from_dict(state["mandate"])
    now = datetime.now(timezone.utc)
    print(f"Active task {show(mandate.id, 80)}")
    print("\n".join(describe_mandate(mandate, VendorFile.from_state(state["vendors"]), now)))
    task = state["task"]
    waiting = [h for h in state["holds"]
               if h["status"] == "pending" and h["task_id"] == mandate.id]
    print(f"  Paid so far   {mandate.currency} {money(Decimal(task['spent']))} "
          f"in {task['payments']} payment(s)")
    print(f"  Waiting       {len(waiting)} payment(s) for countersignature")
    return 0


def _task_end(args: argparse.Namespace) -> int:
    store = _open(args)
    mandate = store.mandate()
    if mandate is None:
        print("No task is active.")
        return 0
    try:
        store.console().end_task(by=args.signer or default_name())
    except StoreError as exc:
        raise _Stop(f"The task was not ended: {exc}", 1) from None
    print(f"Task {show(mandate.id, 80)} ended. Nothing can be paid until a new one starts.")
    return 0


def _holds_list(args: argparse.Namespace) -> int:
    holds = _open(args).holds()
    if not holds:
        print("No payment has been held.")
        return 0
    waiting = sum(1 for hold in holds if hold.status == "pending")
    print(f"{len(holds)} held payment(s), {waiting} waiting for a person.")
    for hold in holds:
        request = hold.request
        amount = "?" if request.amount is None else money(request.amount)
        rules = ",".join(hold.decision.rules or (hold.decision.rule,))
        print(f"  {hold.id}  {hold.status:<9} {request.currency or '':<3} {amount:>12}  "
              f"{show(request.payee, 40)}  {fmt_iban(show(request.account, 40))}  [{rules}]")
    if waiting:
        print("Look at one with: countersign holds show ID")
    return 0


def _find(store: Store, hold_id: str) -> Hold:
    try:
        return store.hold(hold_id)
    except KeyError:
        raise _Stop(f"There is no hold {show(hold_id, 40)}. See: countersign holds list") from None


def _holds_show(args: argparse.Namespace) -> int:
    print("\n".join(describe_hold(_find(_open(args), args.id))))
    return 0


def _need_person(what: str) -> None:
    if not is_terminal() and os.environ.get(SCRIPTED_ENV) != "1":
        raise _Stop(
            f"{what} needs a person at a terminal. (For tests and demos only, "
            f"{SCRIPTED_ENV}=1 lets it read the answers from a pipe.)"
        )


def _holds_approve(args: argparse.Namespace) -> int:
    _need_person("Countersigning a payment")
    store = _open(args)
    hold = _find(store, args.id)
    print("\n".join(describe_hold(hold)))
    print()
    if hold.status != "pending":
        raise _Stop(f"Hold {hold.id} is already {hold.status}. There is nothing to decide.", 1)
    mandate = store.mandate()
    if mandate is None or mandate.id != hold.task_id:
        raise _Stop(f"Hold {hold.id} belongs to an earlier task and can no longer be paid.", 1)
    if args.remember_account:
        print("You asked to remember this account: it will be added to the vendor file for "
              "this payee, and later payments to it will not be held for that reason.")
    checked = confirm(
        "Did you check these bank details with the vendor, using contact details you "
        "already had? [y/N] "
    )
    if ask("Type yes to countersign and send this payment: ").strip().lower() != "yes":
        print("Nothing was countersigned. The payment is still waiting.")
        return 1
    try:
        result = store.console().approve(
            hold.id,
            approver=args.signer or default_name(),
            digest=hold.digest,
            attestation=CHECKED if checked else NOT_CHECKED,
            remember_account=args.remember_account,
        )
    except (KeyError, ValueError, StoreError) as exc:
        raise _Stop(f"Nothing was paid: {exc}", 1) from None
    decision = result.decision
    if result.transfer_id is not None:
        request = hold.request
        print(f"Countersigned. Transfer {result.transfer_id}: {request.currency or ''} "
              f"{money(request.amount)} to {show(request.payee)}, {fmt_iban(request.account)}.")
        print(f"Recorded as: {CHECKED if checked else NOT_CHECKED}.")
        return 0
    if decision.outcome.value == "HOLD":
        print("Nothing was paid. Since this hold was shown, another reason applies to it:")
        print(f"  {show(decision.reason, 2000)}")
        print(f"Look at it again: countersign holds show {hold.id}")
        return 1
    print(f"Not paid. {show(decision.reason, 2000)}")
    return 1


def _holds_reject(args: argparse.Namespace) -> int:
    _need_person("Rejecting a payment")
    store = _open(args)
    hold = _find(store, args.id)
    print("\n".join(describe_hold(hold)))
    print()
    if hold.status != "pending":
        raise _Stop(f"Hold {hold.id} is already {hold.status}. There is nothing to decide.", 1)
    if ask("Type yes to reject this payment: ").strip().lower() != "yes":
        print("Nothing was decided. The payment is still waiting.")
        return 1
    try:
        store.console().reject(hold.id, approver=args.signer or default_name())
    except (KeyError, ValueError, StoreError) as exc:
        raise _Stop(f"The hold was not rejected: {exc}", 1) from None
    print(f"Rejected {hold.id}. Nothing was paid, and this payee and account are refused "
          "for the rest of the task.")
    return 0


def _run(handler: Any, name: str) -> Any:
    def run(args: argparse.Namespace) -> int:
        try:
            return handler(args)
        except _Stop as exc:
            print(f"countersign {name}: {exc}", file=sys.stderr)
            return exc.code
        except StoreError as exc:
            print(f"countersign {name}: {exc}", file=sys.stderr)
            return 2

    return run


def _db_option(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--db", metavar="PATH",
        help=f"the guard's database (default: ${DB_ENV}, then ./{DEFAULT_DB})",
    )


def _signer_option(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--as", dest="signer", metavar="NAME",
        help="your name for the audit log (default: your login name; recorded, not verified)",
    )


def add_cli(subparsers: Any) -> None:
    """Register `init`, `task` and `holds` (see cli.py for the convention)."""
    init = subparsers.add_parser(
        "init",
        help="create a database for the guard",
        description="Create a new database: an empty audit log, a vendor file and a "
                    "simulated bank account. Refuses to touch an existing file.",
    )
    _db_option(init)
    source = init.add_mutually_exclusive_group()
    source.add_argument("--demo-vendors", action="store_true",
                        help="start with the three fictional vendors of the demo")
    source.add_argument("--vendors", metavar="FILE.json",
                        help='a JSON list of {"name", "accounts", "history"}')
    init.add_argument("--mode", choices=GUARD_MODES, default="countersign",
                      help="which guard decides (default: countersign; the others are baselines)")
    init.set_defaults(func=_run(_init, "init"))

    task = subparsers.add_parser(
        "task",
        help="start, show or end the task the agent may act on",
        description="A task is a mandate you sign: what the agent may pay, to whom and up "
                    "to how much. Without an active task every payment is refused.",
    )
    actions = task.add_subparsers(dest="task_command", metavar="<action>")
    task.set_defaults(func=lambda args: task.print_help() or 2)

    start = actions.add_parser(
        "start",
        help="sign a mandate and start a task",
        description="Shows the mandate, including every account it would trust, and asks "
                    "before signing. --yes skips the question only when the payees are "
                    "given with --payee.",
    )
    start.add_argument("sentence", metavar="SENTENCE", help="what the agent should do, in words")
    start.add_argument("--payee", action="append", default=[], metavar="NAME",
                       help="who may be paid, spelled exactly (repeatable)")
    start.add_argument("--limit", metavar="AMT",
                       help=f"most for one payment (default {money(DEFAULT_LIMIT)})")
    start.add_argument("--budget", metavar="AMT",
                       help=f"most for the whole task (default {money(DEFAULT_BUDGET)}, "
                            "or the limit if that is larger)")
    start.add_argument("--hours", metavar="N", type=float, default=DEFAULT_HOURS,
                       help=f"how long the mandate lasts (default {DEFAULT_HOURS:g})")
    start.add_argument("--payments", metavar="N", type=int,
                       help="how many payments the task may make (default: no count limit)")
    start.add_argument("--reference", action="append", default=[], metavar="REF",
                       help="an invoice that may be paid; with any given, only those (repeatable)")
    start.add_argument("--account", action="append", default=[], metavar="PAYEE=IBAN",
                       help="an account you vouch for, for one payee (repeatable)")
    start.add_argument("--yes", action="store_true",
                       help="sign without asking (needs --payee)")
    _signer_option(start)
    _db_option(start)
    start.set_defaults(func=_run(_task_start, "task start"))

    shown = actions.add_parser("show", help="show the active task")
    _db_option(shown)
    shown.set_defaults(func=_run(_task_show, "task show"))

    end = actions.add_parser("end", help="end the active task; waiting payments expire")
    _signer_option(end)
    _db_option(end)
    end.set_defaults(func=_run(_task_end, "task end"))

    holds = subparsers.add_parser(
        "holds",
        help="list and decide payments that wait for a person",
        description="Held payments wait here until a person countersigns or rejects them.",
    )
    actions = holds.add_subparsers(dest="holds_command", metavar="<action>")
    holds.set_defaults(func=lambda args: holds.print_help() or 2)

    listing = actions.add_parser("list", help="every held payment and where it stands")
    _db_option(listing)
    listing.set_defaults(func=_run(_holds_list, "holds list"))

    one = actions.add_parser("show", help="one held payment in full")
    one.add_argument("id", metavar="ID", help="the hold id, for example H001")
    _db_option(one)
    one.set_defaults(func=_run(_holds_show, "holds show"))

    scripted = (
        f"Needs a terminal: it refuses to run when standard input is not one. For tests "
        f"and demos only, {SCRIPTED_ENV}=1 lets it read the answers from a pipe."
    )
    approve = actions.add_parser(
        "approve",
        help="countersign one held payment (asks for a typed yes)",
        description="Shows the hold in full, with both accounts and every reason, and "
                    "sends the payment only after you type yes. " + scripted,
    )
    approve.add_argument("id", metavar="ID", help="the hold id, for example H001")
    approve.add_argument("--remember-account", action="store_true",
                         help="also add the account to the vendor file for this payee")
    _signer_option(approve)
    _db_option(approve)
    approve.set_defaults(func=_run(_holds_approve, "holds approve"))

    reject = actions.add_parser(
        "reject",
        help="refuse one held payment (asks for a typed yes)",
        description="Shows the hold in full and refuses it after you type yes. " + scripted,
    )
    reject.add_argument("id", metavar="ID", help="the hold id, for example H001")
    _signer_option(reject)
    _db_option(reject)
    reject.set_defaults(func=_run(_holds_reject, "holds reject"))
