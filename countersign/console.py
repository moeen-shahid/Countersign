"""The person's side on the command line: `init`, `task` and `holds`.

    countersign init --db PATH [--demo-vendors | --vendors FILE.json] [--mode MODE]
    countersign task start "SENTENCE" --payee NAME [--limit AMT] [--budget AMT]
        [--payments-for PAYEE=N] [--amount-for PAYEE=AMT] ...
    countersign task show | end
    countersign holds list | show ID
    countersign holds approve ID [--remember-account] [--usual-amount]
    countersign holds reject ID [--wrong account|payment]

These commands start and end tasks and decide held payments. They are for a
person. Deciding a hold needs a terminal and a typed "yes", so a program that
can only pipe text into this command does not get a payment through.

Starting a task shows everything the drafter read from the sentence, each
reading with the words it came from, and signs exactly that. A person can
expect more payments to one payee, or state its amount, only with a flag
that names the payee (--payments-for, --amount-for).

Approving a hold about the account (P1, P2, P3) needs the whole account typed
back, as the vendor confirmed it through a channel the person already
trusted; it is compared with the hold's account and refused if it differs
(`store.approval_problem`). A hold about the amount (A1, A2) can be marked as
the payee's new usual amount, which is said in plain words first.

Rejecting a hold about the account asks what was wrong: the account (it is
then refused for the rest of the task) or only this payment (the amount or
the invoice). There is no default answer; --wrong gives it ahead of time.

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
import functools
import getpass
import json
import os
import re
import secrets
import sys
import unicodedata
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from decimal import ROUND_DOWN, Decimal
from typing import Any, Iterable, Mapping, Sequence

from .drafting import (  # noqa: F401 (draft_payees is re-exported)
    Draft,
    describe_draft,
    draft_mandate,
    draft_payees,
)
from .guard import NOT_RESHOWN, Hold
from .iban import find_ibans, fmt_iban
from .models import (
    CENT,
    DEFAULT_PAYMENTS,
    NO_ASK,
    Ask,
    Mandate,
    clean_label,
    figures_in,
    fold_lookalikes,
    invoice_core,
    money,
    name_key,
    names_invoice,
    parse_amount,
)
from .policy import (
    AMOUNT_HEADROOM_MAX,
    AMOUNT_HEADROOM_MIN,
    GUARD_MODES,
    expected_payments,
    rule_title,
    usual_ceiling,
)
from .provenance import UNNAMED, hidden_text
from .simulation import default_vendors
from .store import (
    Store,
    StoreError,
    StoreExists,
    approval_problem,
    needs_typed_account,
    offers_remember_account,
    offers_usual_amount,
    with_typed_back,
)
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
# The most payments a person can say one payee is to get in a task.
MAX_SET_PAYMENTS = 100
TYPE_BACK = (
    "This payment's account is in question ({codes}). Before you countersign it, ask the "
    "vendor for their account through a channel you already trusted before this payment: a "
    "phone number or a contact you already had, not one from the invoice, an email or the "
    "agent. Type the whole account they give you. It is compared with the account above in "
    "full, because a look-alike account can share its first and last characters with the "
    "real one."
)


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


def _default_count_reading(draft: Draft | None, payee: str) -> Any:
    """The draft's reading that expects one payment to the payee only because
    the sentence does not say how many (the reading with no words), or None."""
    if draft is None:
        return None
    key = name_key(payee)
    for reading in draft.readings:
        if (reading.field == "payments" and reading.used and not reading.quote
                and reading.payee is not None and name_key(reading.payee) == key):
            return reading
    return None


def _is_default_count(draft: Draft | None, payee: str) -> bool:
    return _default_count_reading(draft, payee) is not None


# The drafter says this when the sentence asks for several payments to one payee
# ("all the open invoices") without saying how many.
_SEVERAL = "asks for more than one payment"


def count_reading(draft: Draft | None, payee: str) -> Any:
    """The draft's reading that took the payee's count from the sentence's own
    words ("all three", "in two instalments"), or None."""
    if draft is None:
        return None
    key = name_key(payee)
    for reading in draft.readings:
        if (reading.field == "payments" and reading.used and reading.quote
                and reading.payee is not None and name_key(reading.payee) == key):
            return reading
    return None


# How the drafter words a reading that leaves some of a payee's invoices out.
_EXCLUDED = "are not to be paid"


def exclusion_reading(draft: Draft | None, payee: str) -> Any:
    """The draft's reading that says some invoices of the payee are not to be
    paid ("don't pay the April one"), or None. It sets `Ask.excludes_some`."""
    if draft is None:
        return None
    key = name_key(payee)
    for reading in draft.readings:
        if (reading.field == "invoices" and reading.used and reading.quote
                and reading.payee is not None and name_key(reading.payee) == key
                and _EXCLUDED in reading.result):
            return reading
    return None


def excluded_text(payee: str) -> str:
    """What `Ask.excludes_some` does (rule S4), in words."""
    return (f"Some invoices are not to be paid: every payment to {show(payee)} waits for you, "
            "unless your sentence names its invoice to pay (S4).")


def default_count_note(draft: Draft | None, payee: str) -> tuple[str, bool] | None:
    """The drafter's line about a payee's default count, and whether it warns
    that the sentence asks for several payments without a number. None when
    the sentence (or nothing at all) gave the count. Both screens show it next
    to the payee's count, where the person can change it."""
    reading = _default_count_reading(draft, payee)
    if reading is None:
        return None
    return reading.result, _SEVERAL in reading.result


def describe_mandate(
    mandate: Mandate,
    vendors: VendorFile | None = None,
    now: datetime | None = None,
    *,
    draft: Draft | None = None,
    set_by_you: Mapping[str, Iterable[str]] | None = None,
) -> list[str]:
    """The lines a person reads before signing a mandate.

    With `draft`, a payment count the sentence did not state is marked as the
    default, and the accounts the sentence names but does not bind are left
    to `describe_draft`. `set_by_you` names, per payee, the fields ("amount",
    "payments") the person set themselves.
    """
    unit = mandate.currency
    mine = {name_key(p): set(fields) for p, fields in (set_by_you or {}).items()}
    lines = [
        f"  Instruction   {show(mandate.instruction, 400)}",
        f"  May be paid   {', '.join(show(p) for p in mandate.payees)}",
        f"  Per payment   up to {unit} {money(mandate.max_per_payment)}",
        f"  Task budget   {unit} {money(mandate.max_total)} in total",
    ]
    if mandate.max_payments is None:
        lines.append("  Payments      no number set for the task (per payee: see below)")
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

    # What the policy expects for each payee (S1, S2, S3): what the sentence states,
    # and one payment per payee where nothing says how many.
    lines.append("  Expected per payee (more than this waits for you; an invoice you did not "
                 "name is refused):")
    for payee in mandate.payees:
        ask = mandate.ask_for(payee)
        count = expected_payments(mandate, payee)
        set_here = mine.get(name_key(payee), set())
        parts = []
        if ask.amount is not None:
            parts.append(f"at most {unit} {money(ask.amount)} in total"
                         + (" (you set this)" if "amount" in set_here else ""))
        read = count_reading(draft, payee)
        if "payments" in set_here:
            how = " (you set this)"
        elif count == DEFAULT_PAYMENTS and (
            _is_default_count(draft, payee)
            or (ask.payments is None and mandate.max_payments is None)
        ):
            how = " (default: the sentence does not say how many)"
        elif read is not None and ask.payments == count and count > 1:
            how = f" (read from \"{show(read.quote, 80)}\")"
        else:
            how = ""
        what = f"{count} payment{'' if count == 1 else 's'}"
        if ask.instalments and count > 1:
            what += ", instalments of one invoice"
        parts.append(what + how)
        if ask.invoices:
            parts.append("only invoice " + ", ".join(show(r) for r in ask.invoices))
        lines.append(f"    {show(payee)}: {'; '.join(parts)}")
        # The drafter's own line about the default, next to the count it is about.
        note = None if "payments" in set_here else default_count_note(draft, payee)
        if note is not None:
            text, several = note
            lines.append(f"      {'Warning: ' if several else ''}{show(text, 800)}")
        if ask.excludes_some:
            lines.append(f"      {excluded_text(payee)}")

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
    if unbound and draft is None:
        lines.append(
            f"  Your sentence names {len(unbound)} account(s) that are not tied to a payee: "
            + ", ".join(fmt_iban(a) for a in unbound)
        )
        lines.append("    A payment to one of them will be held. To trust one for a payee, say "
                     "whose it is: --account PAYEE=IBAN.")
    return lines


def describe_confirmation(
    mandate: Mandate,
    draft: Draft,
    vendors: VendorFile | None = None,
    now: datetime | None = None,
    *,
    set_by_you: Mapping[str, Iterable[str]] | None = None,
    plain: bool = False,
    hint: bool = True,
) -> list[str]:
    """Everything a person confirms when a task starts, as lines of text.

    The mandate (`describe_mandate`), then the drafter's own account of the
    sentence (`drafting.describe_draft`: the payees, the vendors named but
    not included, every reading with the words it came from, the default
    count marked as a default, the accounts in the sentence that are not
    trusted), what the person set themselves, and the digest of the draft.
    With `plain` nothing was read from the sentence and that is said
    instead. `hint` adds how to raise a count or state an amount.
    """
    mine = {p: set(fields) for p, fields in (set_by_you or {}).items() if fields}
    lines = describe_mandate(mandate, vendors, now, draft=None if plain else draft,
                             set_by_you=mine)
    if plain:
        lines.append("  --plain: nothing was read from the sentence. Only the limits above, the "
                     "accounts given with --account and the payments per payee listed above "
                     "apply.")
    else:
        trusted = {a for accounts in mandate.accounts.values() for a in accounts}
        # A default count is shown next to the payee's count above, not twice.
        defaults = {id(r) for p in mandate.payees
                    for r in [_default_count_reading(draft, p)] if r is not None}
        shown = replace(draft, unbound=tuple(a for a in draft.unbound if a not in trusted),
                        readings=tuple(r for r in draft.readings if id(r) not in defaults))
        lines.extend(describe_draft(shown))
    if mine:
        lines.append("  Set by you, not read from the sentence:")
        for payee in mandate.payees:
            fields = mine.get(payee)
            if not fields:
                continue
            ask = mandate.ask_for(payee)
            parts = []
            if "payments" in fields and ask.payments is not None:
                parts.append(f"expect {ask.payments} payment{'' if ask.payments == 1 else 's'}")
            if "amount" in fields and ask.amount is not None:
                parts.append(f"at most {mandate.currency} {money(ask.amount)} in total")
            lines.append(f"    {show(payee)}: {'; '.join(parts)}")
    if not plain:
        lines.append(f"  Draft digest  {draft.digest()}  (this reading of this sentence)")
    if hint:
        lines.append("  To expect more payments to one payee, or to state its amount yourself, "
                     "start again with --payments-for \"PAYEE=N\" or --amount-for "
                     "\"PAYEE=AMOUNT\". Nothing is raised unless you say so.")
    return lines


def adjust_asks(
    asks: Mapping[str, Ask],
    payees: Sequence[str],
    *,
    payments: Mapping[str, object] | None = None,
    amounts: Mapping[str, object] | None = None,
    budget: Decimal | None = None,
) -> tuple[dict[str, Ask], dict[str, set[str]]]:
    """What a person sets on the confirmation screen, on top of the draft.

    `payments` maps a payee to the number of payments to expect, `amounts`
    to the most it is to be paid in the task. Each replaces what was read
    from the sentence (or the default of one payment) for that payee only.
    These are the person's own words, trusted like the sentence. Returns the
    new asks and, per payee, the fields the person set. Raises ValueError
    with a plain sentence for a payee outside the task or a value that is
    not a count from 1 to MAX_SET_PAYMENTS or a plain positive amount.
    """
    by_key = {name_key(p): p.strip() for p in payees if isinstance(p, str) and name_key(p)}
    # Keyed by the payee as the task spells it.
    result = {by_key.get(name_key(p), p): ask for p, ask in asks.items()}
    marks: dict[str, set[str]] = {}

    def slot(name: object) -> str:
        payee = by_key.get(name_key(name)) if isinstance(name, str) else None
        if payee is None:
            raise ValueError(f"{show(name, 60)} is not a payee of this task")
        return payee

    for name, value in (payments or {}).items():
        payee = slot(name)
        if type(value) is not int or not 1 <= value <= MAX_SET_PAYMENTS:
            raise ValueError(f"the number of payments for {show(payee, 60)} must be a whole "
                             f"number from 1 to {MAX_SET_PAYMENTS}")
        ask = result.get(payee, NO_ASK)
        result[payee] = replace(ask, payments=value, set_by=(*ask.set_by, "payments"))
        marks.setdefault(payee, set()).add("payments")
    for name, value in (amounts or {}).items():
        payee = slot(name)
        amount = value if isinstance(value, Decimal) else parse_amount(value)
        if amount is None or not amount.is_finite() or amount <= 0 \
                or amount != amount.quantize(CENT):
            raise ValueError(f"the amount for {show(payee, 60)} must be a plain amount such as "
                             "650 or 650.00")
        if budget is not None and amount > budget:
            raise ValueError(f"the amount for {show(payee, 60)} is more than the task budget "
                             f"({money(budget)}), so it could never be paid")
        ask = result.get(payee, NO_ASK)
        result[payee] = replace(ask, amount=amount, set_by=(*ask.set_by, "amount"))
        marks.setdefault(payee, set()).add("amount")
    return result, marks


# --- a hold, in words --------------------------------------------------------------


def held_rules(decision: Mapping[str, Any]) -> list[tuple[str, str, str]]:
    """(rule, title, what the rule found) for every rule a decision carries.

    The detail is the rule's own line of the rule ladder, so it is the same
    text the evidence card shows: the line and its basis for A1, the amount
    you stated for S1, the count for S2, the account that competes for D3,
    and which limit a waiting payment would break for H2.
    """
    checks = {c.get("rule"): c for c in _items(decision.get("checks")) if isinstance(c, dict)}
    rules = _items(decision.get("rules")) or [decision.get("rule")]
    found = []
    for rule in rules:
        check = checks.get(rule) or {}
        detail = check.get("detail") if check.get("status") in ("hold", "block") else ""
        found.append((str(rule), rule_title(str(rule)), str(detail or "")))
    return found


def _decimal(value: object) -> Decimal | None:
    """A stored amount ("480.00") as a Decimal, or None if it is not one."""
    if value is None or isinstance(value, bool):
        return None
    try:
        amount = Decimal(str(value))
    except (ArithmeticError, ValueError):
        return None
    return amount if amount.is_finite() else None


def _items(value: object) -> list[Any]:
    """A list from a decision read back from the log, or nothing if it is not one."""
    return list(value) if isinstance(value, (list, tuple)) else []


def headroom_basis(ceiling: Decimal, largest: Decimal) -> str:
    """Why the A1 line is where it is, in words."""
    least = (largest + largest * AMOUNT_HEADROOM_MIN).quantize(CENT, rounding=ROUND_DOWN)
    most = (largest + largest * AMOUNT_HEADROOM_MAX).quantize(CENT, rounding=ROUND_DOWN)
    if ceiling == least:
        return f"the least headroom, {int(AMOUNT_HEADROOM_MIN * 100)}% of the largest usual amount"
    if ceiling == most:
        return f"the most headroom, {int(AMOUNT_HEADROOM_MAX * 100)}% of the largest usual amount"
    return "as far as the usual amounts spread: the largest minus the smallest"


def hold_facts(decision: Mapping[str, Any]) -> list[str]:
    """The trusted facts behind a decision that the rules use, one sentence each.

    Read from the decision's evidence (all of it trusted state): usual
    amounts and the A1 line with its basis, the amount the user stated (S1),
    the payments made and expected (S2), the invoices named (S3), when an
    approval added the account (P3), an earlier payment of the invoice (D1)
    and the task's budget. Empty when there is no evidence.
    """
    ev = decision.get("evidence")
    if not isinstance(ev, dict):
        return []
    payee = show(ev.get("payee"), 80)
    facts = []
    history = [a for a in (_decimal(x) for x in _items(ev.get("history"))) if a is not None]
    if history:
        facts.append(f"Usual amounts for {payee} when the task started: "
                     f"{', '.join(money(a) for a in history)}.")
    else:
        facts.append(f"No usual amount for {payee} was on file when the task started.")
    ceiling, largest = _decimal(ev.get("ceiling")), _decimal(ev.get("baseline"))
    if ceiling is not None and largest is not None:
        facts.append(
            f"Line for one invoice (A1): {money(ceiling)}, the largest usual amount "
            f"({money(largest)}) plus a headroom of {money(ceiling - largest)} "
            f"({headroom_basis(ceiling, largest)}). All invoices to {payee} in one task "
            "share one headroom."
        )
    stated = _decimal(ev.get("stated"))
    if stated is not None:
        facts.append(f"You stated {money(stated)} for {payee} in this task (S1).")
    expected = ev.get("expected")
    if isinstance(expected, int) and not isinstance(expected, bool):
        done = ev.get("payments_to_payee")
        done = done if isinstance(done, int) and not isinstance(done, bool) else 0
        paid = _decimal(ev.get("paid_to_payee")) or Decimal("0.00")
        facts.append(
            f"Payments to {payee} in this task before this one: {done} ({money(paid)}). "
            f"The task expects {expected} (S2)."
        )
    named = [show(r, 60) for r in _items(ev.get("named_invoices")) if isinstance(r, str)]
    if named:
        facts.append(f"Invoices your sentence names for {payee}: {', '.join(named)} "
                     "(S3: any other is refused).")
    if ev.get("added"):
        facts.append(f"A person's approval added this account to the vendor file on "
                     f"{_stamp(ev.get('added'))} (P3: it is held until a person countersigns "
                     "a payment to it on a later day).")
    before = ev.get("previous_payment")
    if isinstance(before, dict):
        transfer = before.get("transfer")
        facts.append(
            f"This invoice was paid to {payee} before: {show(before.get('amount'), 20)} on "
            f"{show(str(before.get('time', ''))[:16], 20)} ("
            + (f"transfer {show(transfer, 20)}" if transfer else "not confirmed by the bank")
            + ")."
        )
    spent, budget = _decimal(ev.get("spent")), _decimal(ev.get("budget"))
    if spent is not None and budget is not None:
        facts.append(f"This task when it was decided: {money(spent)} paid of the "
                     f"{money(budget)} budget.")
    return facts


# --- facts for the rules of v0.3 (F2, T1, D4, S4, A3, look-alike references) --------

MAX_QUOTED = 3  # lines quoted from documents per fact
QUOTE_LIMIT = 160
_SENTENCE_END = re.compile(r"(?<=[.!?:;])\s+")
# Words before a number that say "invoice", not who issued it (as rule D4 reads them).
_NUMBER_LABELS = frozenset({"INV", "BILL", "NO", "NR", "NUM", "REF"})


def _quoted(lines: Sequence[str]) -> str:
    """Up to MAX_QUOTED lines of a document, each in quotes, spaces collapsed."""
    shown = "; ".join(f"\"{show(' '.join(line.split()), QUOTE_LIMIT)}\""
                      for line in lines[:MAX_QUOTED])
    more = len(lines) - MAX_QUOTED
    return shown + (f" and {more} more" if more > 0 else "")


@functools.lru_cache(maxsize=64)
def _hidden(text: str) -> str:
    """`provenance.hidden_text`, kept for the documents of the last few views:
    the console asks again for every held payment on every refresh."""
    return hidden_text(text)


def _alphabets(reference: str) -> list[tuple[str, list[str]]]:
    """(alphabet, its letters) for the letters of a reference, in order seen."""
    found: dict[str, list[str]] = {}
    for ch in unicodedata.normalize("NFKC", reference):
        if ch.isalpha():
            name = unicodedata.name(ch, "UNKNOWN").split(" ")[0].capitalize()
            letters = found.setdefault(name, [])
            if ch not in letters:
                letters.append(ch)
    return list(found.items())


def rule_facts(
    decision: Mapping[str, Any],
    *,
    reference: object = "",
    amount: object = None,
    texts: Mapping[str, str] | None = None,
    transfers: Iterable[Any] = (),
) -> list[str]:
    """The facts behind the rules of v0.3 that `hold_facts` does not cover,
    one sentence each, for the hold card and `holds show`:

    * F2: which letters of the reference come from which alphabet, and how
      it reads with the look-alikes made plain;
    * T1: the hidden lines of each document that hold this payment's amount
      or invoice number, quoted (a reader of the document does not see them);
    * D4: the lines of the documents that show another invoice with the
      number you named;
    * S4: that your sentence leaves some of the payee's invoices out, and
      which it names to pay;
    * A3: that the amount is above every usual one but inside the line;
    * D1, D2: the earlier payment's reference when it was written otherwise.

    `texts` maps a document's name, as the guard labels it, to its text: the
    untrusted documents of the hold's own task. `transfers` are the bank's
    transfers (dicts with "id" and "reference"). Without them T1, D4 and the
    earlier reference say nothing more than the decision does.
    """
    rules = {str(r) for r in _items(decision.get("rules")) or [decision.get("rule")]}
    ev = decision.get("evidence")
    ev = ev if isinstance(ev, dict) else {}
    payee = show(ev.get("payee"), 80)
    ref = reference if isinstance(reference, str) else ""
    documents = {str(k): v for k, v in (texts or {}).items() if isinstance(v, str)}
    facts: list[str] = []

    if "F2" in rules and ref:
        groups = _alphabets(ref)
        if len(groups) > 1:
            said = ", ".join(
                f"{' and '.join(letters)} {'is' if len(letters) == 1 else 'are'} {name}"
                for name, letters in groups)
            facts.append(f"The reference \"{show(ref, 60)}\" mixes alphabets: {said}. With "
                         f"the look-alikes made plain it reads "
                         f"\"{show(fold_lookalikes(ref), 60)}\" (F2).")

    if "T1" in rules:
        figure = _decimal(amount)
        for label, text in documents.items():
            hidden = _hidden(text)
            if not hidden:
                continue
            # The sentences of the hidden text that write the figure, not whole paragraphs.
            lines = [part for line in hidden.splitlines() for part in _SENTENCE_END.split(line)
                     if (figure is not None and figure in figures_in(part))
                     or (ref and names_invoice(part, ref))]
            if lines:
                facts.append(f"Hidden in the untrusted document named \"{show(label, 60)}\" "
                             f"(a reader of it does not see this text): {_quoted(lines)} (T1).")

    if "D4" in rules and ref:
        letters, _, number = invoice_core(ref).partition("-")
        if number.isdigit():
            other = re.compile(r"(?<![A-Za-z0-9])([A-Z]{1,6})[-/_]?0*" + number + r"(?![0-9])")
            for label, text in documents.items():
                seen = [line for line in text.splitlines()
                        if any(m.group(1) != letters and m.group(1) not in _NUMBER_LABELS
                               for m in other.finditer(fold_lookalikes(line)))]
                if seen:
                    facts.append(f"The untrusted document named \"{show(label, 60)}\" shows "
                                 f"another invoice with the number {number}: {_quoted(seen)} "
                                 "(D4).")

    if "S4" in rules:
        named = [show(r, 60) for r in _items(ev.get("named_invoices")) if isinstance(r, str)]
        facts.append(
            f"Your sentence says not to pay some invoices of {payee}, and "
            + (f"names {', '.join(named)} to pay" if named else "names none to pay")
            + ". The guard cannot tell which invoice you meant to leave out, so this payment "
            "waits for you (S4)."
        )

    if "A3" in rules:
        largest, ceiling = _decimal(ev.get("baseline")), _decimal(ev.get("ceiling"))
        if largest is not None and ceiling is not None:
            facts.append(
                f"The amount is above the largest usual payment to {payee} ({money(largest)}) "
                f"but inside the line for one invoice ({money(ceiling)}), so it would not wait "
                "for the amount alone. It waits for its account; check the amount against an "
                "invoice you expect as well (A3)."
            )

    before = ev.get("previous_payment")
    if rules & {"D1", "D2"} and isinstance(before, dict) and before.get("transfer") and ref:
        earlier = next((t.get("reference") for t in transfers
                        if isinstance(t, Mapping) and t.get("id") == before.get("transfer")), None)
        if isinstance(earlier, str) and earlier != ref:
            facts.append(
                f"The earlier payment had the reference \"{show(earlier, 60)}\"; this one has "
                f"\"{show(ref, 60)}\". The guard counts them as one invoice: written plainly "
                "(look-alike letters such as O for 0 made plain), they have the same number."
            )
    return facts


ROUNDABOUT = ("not written there as one piece: it was read through HTML tags or invisible "
              "characters")


def sighting_lines(decision: Mapping[str, Any]) -> list[str]:
    """Where the account of a decision was written, one line per text."""
    ev = decision.get("evidence")
    if not isinstance(ev, dict):
        return []
    lines = []
    for sighting in _items(ev.get("sightings")):
        if not isinstance(sighting, dict):
            continue
        if sighting.get("origin") == "user":
            line = f"your instruction, line {sighting.get('line')}"
        else:
            # The name is the sender's words, not a fact: a document can be named
            # "Approved by finance.pdf" (adversary trace D04). Quoted, never bare.
            line = (f"untrusted document named \"{show(sighting.get('source'), 60)}\", line "
                    f"{sighting.get('line')}  (the sender chose that name)")
        if sighting.get("rendered"):
            line += f"; {ROUNDABOUT}"
        lines.append(line)
    return lines


def usual_amount_change(payee: str, amount: Decimal, history: Sequence[Decimal]) -> str:
    """What marking `amount` as the payee's new usual amount changes, in words."""
    after = usual_ceiling(tuple(history) + (amount,))
    unchanged = "The line of this task does not move: it was fixed when the task started."
    if history:
        now = usual_ceiling(tuple(history))
        return (
            f"Marking {money(amount)} as the new usual amount for {show(payee)} moves the line "
            f"for one invoice (A1) from {money(now)} to {money(after)} from the next task on: "
            f"the agent may then pay {show(payee)} up to {money(after)} for one invoice without "
            f"asking you. Without the mark only this payment is approved, and the line stays at "
            f"{money(now)}. Mark it only if {show(payee)} told you that this is their price now, "
            "not for a one-off such as an annual renewal or a late fee. " + unchanged
        )
    return (
        f"{show(payee)} has no usual amount yet. Marking {money(amount)} as its usual amount "
        f"means that from the next task on a payment to {show(payee)} is no longer held for "
        f"having no usual amount (A2), and one invoice may come to {money(after)} without "
        "asking you (A1). Without the mark only this payment is approved, and the next one "
        "waits for you again unless the sentence states an amount. " + unchanged
    )


REJECT_CHOICES = ("account", "payment")
# What a rejection said was wrong, as the hold shows it afterwards.
REJECT_SAID = {"account": "the account (refused for the rest of the task)",
               "payment": "only this payment (the account was not refused)"}


def rejections_said(entries: Iterable[Any]) -> dict[str, str]:
    """Per rejected hold, what the person said was wrong ("account" or
    "payment"), from the audit log (`hold_rejected`). A rejection logged
    before v0.3 says nothing and is left out."""
    said: dict[str, str] = {}
    for entry in entries:
        data = entry.get("data") if isinstance(entry, dict) else None
        if (isinstance(data, dict) and entry.get("event") == "hold_rejected"
                and isinstance(data.get("hold"), str) and data.get("wrong") in REJECT_CHOICES):
            said[data["hold"]] = data["wrong"]
    return said


def reject_choices(hold: Hold, vendors: VendorFile | None) -> list[tuple[str, str, str]]:
    """For a hold about the account (P1, P2, P3), the two answers a person
    gives when rejecting it, as (`wrong`, label, what it does). There is no
    default: the person says which. Empty for any other hold, where
    rejecting refuses only that payment."""
    if not needs_typed_account(hold):
        return []
    request = hold.request
    payee = show(request.payee)
    account = (f"This account is refused for {payee} for the rest of the task: any other "
               "payment to it is refused too.")
    vendor = vendors.get(request.payee) if vendors is not None else None
    if vendor is not None and request.account in vendor.added:
        account += (" An approval added it to the vendor file recently, so it also comes off "
                    "the vendor file.")
    payment = ("The account is right, but the amount or the invoice is not. Only this payment "
               "is refused for the rest of the task. Another payment to this account is "
               "decided on its own.")
    return [("account", "The account is wrong", account),
            ("payment", "Only this payment is wrong", payment)]


def reject_consequence(hold: Hold, vendors: VendorFile | None) -> str:
    """What rejecting this hold does, in words, for the person about to decide.

    A hold about the account (P1, P2, P3) asks what was wrong first
    (`reject_choices`). Any other hold: only this same payment is refused
    (rule R1)."""
    if needs_typed_account(hold):
        return ("Say what was wrong: the account, or only this payment. Nothing is refused "
                "until you choose.")
    return ("Rejecting refuses this same payment for the rest of the task. The account is not "
            "in question, so another payment to it is decided on its own.")


def related_lines(hold: Hold, related: Mapping[str, Any] | None) -> list[str]:
    """What the guard says now about the payments this hold must be decided
    with (`Guard.related`): rival accounts for the same invoice (D3), waiting
    payments it needs room with (H2) and the rules they would make it break,
    and a D3 or H2 reason shown with the hold that no longer applies. When the
    payment would now be refused (other payments used the budget, say), only
    that is said: approving it would pay nothing. These change while the hold
    waits; they are worked out when asked."""
    if not related or hold.status != "pending":
        return []
    def words(items: list[str]) -> str:
        return items[0] if len(items) == 1 else ", ".join(items[:-1]) + " and " + items[-1]

    refused = [str(r) for r in _items(related.get("refused"))]
    if refused:
        named = words([f"{code} ({rule_title(code).lower()})" for code in refused])
        return [f"    Would now be refused: {named}. Approving it would pay nothing; reject "
                "it, or ask the agent again once you have checked."]
    lines = []
    rivals = [show(h, 20) for h in _items(related.get("rivals"))]
    if rivals:
        lines.append(f"    Decide together with {words(rivals)}: another account is waiting "
                     "for the same invoice (D3), and at most one of them can be right.")
    waiting = [show(h, 20) for h in _items(related.get("waiting"))]
    if waiting:
        codes = [str(r) for r in _items(related.get("projected_rules"))]
        broken = words([f"{code} ({rule_title(code).lower()})" for code in codes]) if codes else ""
        one = len(waiting) == 1
        lines.append(f"    Waiting payments it depends on (H2): {words(waiting)}."
                     + (f" If {'it were' if one else 'they were'} paid, this one would break "
                        f"{broken}." if broken else "")
                     + f" Decide {'it' if one else 'them'} first, or together with this one.")
    now = set(_items(related.get("rules")))
    gone = [rule for rule in hold.decision.rules if rule in NOT_RESHOWN and rule not in now]
    if gone:
        lines.append(f"    No longer applies: {', '.join(gone)}. The waiting payment it was about "
                     "has been decided since this hold was made.")
    return lines


def quarantine_of(entries: Iterable[Any], task_id: object) -> dict[str, int] | None:
    """Whether a task was quarantined (`task_quarantined` in the log), and how
    many of its requests the full queue refused (rule H1). None if it was not."""
    found = None
    refused = 0
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("data"), dict):
            continue
        data = entry["data"]
        if data.get("task") != task_id:
            continue
        if entry.get("event") == "task_quarantined":
            waiting = data.get("waiting")
            found = {"waiting": waiting if isinstance(waiting, int) else 0}
        elif entry.get("event") == "payment_decision":
            decision = data.get("decision")
            if isinstance(decision, dict) and decision.get("rule") == "H1":
                refused += 1
    if found is not None:
        found["refused"] = refused
    return found


def quarantine_text(refused: int) -> str:
    """The quarantine banner, in plain words."""
    many = "request was" if refused == 1 else "requests were"
    return (
        "This task is quarantined: it no longer pays anything without a person. Too many "
        f"payments were waiting for a person at once, so {refused} {many} refused. Payments "
        "that already wait can still be decided. A new task starts clean."
    )


def describe_hold(
    hold: Hold,
    related: Mapping[str, Any] | None = None,
    vendors: VendorFile | None = None,
    *,
    texts: Mapping[str, str] | None = None,
    transfers: Iterable[Any] = (),
    wrong: str | None = None,
) -> list[str]:
    """Everything a person needs to decide one hold: both accounts in full,
    every rule with what it found, the trusted facts, and where the account
    was written. With `related` (`Store.related`), the rival and waiting
    payments as they are now; with `vendors`, what rejecting would do. With
    `texts` (the documents of the hold's task) and `transfers` (the bank's),
    the facts of `rule_facts`. `wrong` is what the person said was wrong when
    they rejected it (`rejections_said`)."""
    request, decision, evidence = hold.request, hold.decision, hold.decision.evidence
    shown = decision.to_dict()
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
    for rule, title, detail in held_rules(shown):
        lines.append(f"    {rule}  {title}")
        if detail:
            lines.append(f"        {show(detail, 600)}")
    lines.append(f"  {show(decision.reason, 2000)}")
    if evidence is not None:
        lines.append("")
        where = sighting_lines(shown)
        if where:
            lines.append("  Where this account was written:")
            lines.extend(f"    {line}" for line in where)
        else:
            lines.append("  This account was not written in your instruction or in any "
                         "document the agent read.")
        lines.append("  What the rules looked at (trusted state):")
        lines.extend(f"    {fact}" for fact in hold_facts(shown))
    more = rule_facts(shown, reference=request.reference, amount=request.amount, texts=texts,
                      transfers=transfers)
    if more:
        lines.append("  What else the guard found:")
        lines.extend(f"    {show(fact, 1200)}" for fact in more)
    now = related_lines(hold, related)
    if now:
        lines.append("")
        lines.append("  Now (worked out just now, not when the hold was made):")
        lines.extend(now)
    lines.append("")
    if hold.status == "pending":
        choices = reject_choices(hold, vendors)
        if choices:
            lines.append("  If you reject, say what was wrong:")
            for wrong, label, text in choices:
                lines.append(f"    --wrong {wrong:<8} {label}. {text}")
        elif vendors is not None:
            lines.append(f"  {reject_consequence(hold, vendors)}")
        steps = []
        if needs_typed_account(hold):
            steps.append("type back the whole account the vendor confirmed to you")
        if offers_usual_amount(hold):
            steps.append("say whether this is the payee's new usual amount")
        lines.append(f"  To decide   countersign holds approve {hold.id}"
                     + (f" (you will {' and '.join(steps)})" if steps else "")
                     + f", or countersign holds reject {hold.id}"
                     + (" --wrong account|payment" if choices else ""))
    lines.append(f"  Digest      {hold.digest}")
    if hold.status != "pending":
        by = f" by {show(hold.decided_by, 60)}" if hold.decided_by else ""
        when = f" at {_stamp(hold.decided_at)}" if hold.decided_at else ""
        lines.append(f"  Decided     {hold.status}{by}{when}")
        if hold.status == "rejected" and wrong in REJECT_SAID:
            lines.append(f"  Wrong       {REJECT_SAID[wrong]}")
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


def _per_payee(pairs: Sequence[str], flag: str, example: str) -> dict[str, str]:
    """--payments-for / --amount-for: PAYEE=VALUE, at most once per payee."""
    found: dict[str, str] = {}
    for pair in pairs:
        payee, sep, value = pair.rpartition("=")
        if not sep or not payee.strip() or not value.strip():
            raise _Stop(f"{flag} takes PAYEE=VALUE, for example {flag} \"{example}\".")
        if name_key(payee) in {name_key(p) for p in found}:
            raise _Stop(f"{flag} names {show(payee.strip(), 60)} twice.")
        found[payee.strip()] = value.strip()
    return found


def _task_start(args: argparse.Namespace) -> int:
    store = _open(args)
    state = store.state()
    vendors = VendorFile.from_state(state["vendors"])
    explicit = bool(args.payee)
    # One function reads the sentence, here and in the web console. What it
    # proposes is printed below and nothing is signed before a person agrees.
    draft = draft_mandate(args.sentence, vendors, list(args.payee) if explicit else None)
    payees = list(args.payee) if explicit else list(draft.payees)
    if not payees:
        raise _Stop("Say who may be paid with --payee NAME. The sentence names no vendor "
                    "from the vendor file.")
    limit = _amount(args.limit, "--limit", DEFAULT_LIMIT)
    budget = _amount(args.budget, "--budget", max(DEFAULT_BUDGET, limit))
    if not (0 < args.hours <= MAX_HOURS):  # also false for NaN and infinity
        raise _Stop(f"--hours must be more than 0 and at most {MAX_HOURS}.")
    accounts: dict[str, tuple[str, ...]] = {} if args.plain else dict(draft.accounts)
    for payee, values in _accounts(args.account).items():
        accounts[payee] = accounts.get(payee, ()) + values
    # What the person sets for one payee, by name, on top of what was read.
    counts: dict[str, object] = {}
    for payee, text in _per_payee(args.payments_for, "--payments-for",
                                  "Marlowe Facilities=3").items():
        counts[payee] = int(text) if text.isascii() and text.isdigit() else text
    amounts = _per_payee(args.amount_for, "--amount-for", "Fernhill Design=650.00")
    try:
        asks, set_by_you = adjust_asks(
            # --plain reads nothing. The policy then expects one payment per payee
            # (a further one waits for a person), or what --payments leaves for one.
            {} if args.plain else dict(draft.asks), payees,
            payments=counts, amounts=amounts, budget=budget,
        )
    except ValueError as exc:
        raise _Stop(f"This is not a mandate that can be signed: {exc}.") from None
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
            asks=asks,
        )
    except ValueError as exc:
        raise _Stop(f"This is not a mandate that can be signed: {exc}.") from None

    print("Mandate to sign")
    print("\n".join(describe_confirmation(mandate, draft, vendors, now, set_by_you=set_by_you,
                                          plain=args.plain)))
    if not args.plain and (draft.asks or draft.accounts):
        print("  If a line above is not what you meant, answer no and reword the sentence, "
              "or pass --plain to read nothing from it.")
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
        store.console().start_task(mandate, confirmed_by=args.signer or default_name(),
                                   draft_digest=None if args.plain else draft.digest())
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
    _print_quarantine(store, mandate.id)
    return 0


def _print_quarantine(store: Store, task_id: str) -> None:
    """Say so when the task stopped paying anything without a person."""
    quarantined = quarantine_of(store.audit_entries(), task_id)
    if quarantined is not None:
        print(f"  QUARANTINED   {quarantine_text(quarantined['refused'])}")


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
    store = _open(args)
    holds = store.holds()
    mandate = store.mandate()
    if mandate is not None:
        _print_quarantine(store, mandate.id)
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


def task_texts(state: Mapping[str, Any], task_id: object) -> dict[str, str] | None:
    """The untrusted documents the agent read in this task, by the name the
    guard gives them, from a saved state; None when the task is not the
    active one (its documents are no longer kept)."""
    mandate = state.get("mandate")
    if not isinstance(mandate, dict) or mandate.get("id") != task_id:
        return None
    texts: dict[str, str] = {}
    for seen in state.get("observations") or ():
        if isinstance(seen, dict) and seen.get("origin") != "user" \
                and isinstance(seen.get("text"), str):
            texts.setdefault(clean_label(str(seen.get("name", ""))) or UNNAMED, seen["text"])
    return texts


def _describe(store: Store, hold: Hold) -> list[str]:
    """`describe_hold` with what the guard says about the hold now."""
    state = store.state()
    vendors = VendorFile.from_state(state["vendors"])
    try:
        related = store.related(hold.id)
    except (ValueError, KeyError, TypeError):
        related = None  # a state the guard cannot rebuild: show the hold as it was made
    wrong = None
    if hold.status == "rejected":
        wrong = rejections_said(store.audit_entries()).get(hold.id)
    return describe_hold(hold, related, vendors, texts=task_texts(state, hold.task_id),
                         transfers=(state.get("bank") or {}).get("transfers") or (),
                         wrong=wrong)


def _holds_show(args: argparse.Namespace) -> int:
    store = _open(args)
    print("\n".join(_describe(store, _find(store, args.id))))
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
    print("\n".join(_describe(store, hold)))
    print()
    if hold.status != "pending":
        raise _Stop(f"Hold {hold.id} is already {hold.status}. There is nothing to decide.", 1)
    mandate = store.mandate()
    if mandate is None or mandate.id != hold.task_id:
        raise _Stop(f"Hold {hold.id} belongs to an earlier task and can no longer be paid.", 1)
    request = hold.request
    rules = ", ".join(hold.decision.rules or (hold.decision.rule,))
    if args.usual_amount and not offers_usual_amount(hold):
        raise _Stop(f"--usual-amount is for a hold about the amount (A1, A2). Hold {hold.id} is "
                    f"held for {rules}. Nothing was paid.")
    if args.remember_account:
        if offers_remember_account(hold):
            print("You asked to remember this account: it will be added to the vendor file for "
                  "this payee. Payments to it are still held until you countersign one on a "
                  "later day (P3).")
        else:
            print("You asked to remember this account, but it is already on file for this "
                  "payee. There is nothing to remember.")

    typed: str | None = None
    if needs_typed_account(hold):
        codes = ", ".join(r for r in hold.decision.rules if r in ("P1", "P2", "P3"))
        print(TYPE_BACK.format(codes=codes))
        typed = ask("Account the vendor confirmed: ")
        problem = approval_problem(hold, confirmed_account=typed)
        if problem is not None:
            if typed.strip():  # a wrong account is logged (hold_confirmation_failed)
                store.console().check_account(hold.id, typed, approver=args.signer or default_name())
            raise _Stop(problem, 1)
        print("It is the account of this payment.")
        attestation = with_typed_back("")  # the store checks the match again when approving
    else:
        checked = confirm(
            "Did you check this payment with the vendor, using contact details you already "
            "had? [y/N] "
        )
        attestation = CHECKED if checked else NOT_CHECKED

    usual = False
    if offers_usual_amount(hold) and request.amount is not None:
        history = VendorFile.from_state(store.state()["vendors"]).history_for(request.payee)
        print(usual_amount_change(request.payee, request.amount, history))
        if args.usual_amount:
            print("You asked for this with --usual-amount.")
            usual = True
        else:
            usual = confirm(f"Is {money(request.amount)} the new usual amount for "
                            f"{show(request.payee)}? [y/N] ")
    if ask("Type yes to countersign and send this payment: ").strip().lower() != "yes":
        print("Nothing was countersigned. The payment is still waiting.")
        return 1
    try:
        result = store.console().approve(
            hold.id,
            approver=args.signer or default_name(),
            digest=hold.digest,
            attestation=attestation,
            remember_account=args.remember_account,
            usual_amount=usual,
            confirmed_account=typed,
        )
    except (KeyError, ValueError, StoreError) as exc:
        raise _Stop(f"Nothing was paid: {exc}", 1) from None
    decision = result.decision
    if result.transfer_id is not None:
        print(f"Countersigned. Transfer {result.transfer_id}: {request.currency or ''} "
              f"{money(request.amount)} to {show(request.payee)}, {fmt_iban(request.account)}.")
        said = store.hold(hold.id).attestation or attestation
        print(f"Recorded as: {show(said)}.")
        if usual:
            print(f"{money(request.amount)} is now a usual amount for {show(request.payee)}.")
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
    print("\n".join(_describe(store, hold)))
    print()
    if hold.status != "pending":
        raise _Stop(f"Hold {hold.id} is already {hold.status}. There is nothing to decide.", 1)
    wrong = getattr(args, "wrong", None)
    about_account = needs_typed_account(hold)
    if wrong == "account" and not about_account:
        rules = ", ".join(hold.decision.rules or (hold.decision.rule,))
        raise _Stop(f"--wrong account is for a hold about the account (P1, P2, P3). Hold "
                    f"{hold.id} is held for {rules}, so there is no account to refuse: reject "
                    "it without --wrong. Nothing was decided.", 1)
    if about_account and wrong is None:
        # No default: the person says which. Each does something different.
        print("What was wrong? Type one of:")
        for value, label, _ in reject_choices(hold, None):
            print(f"  {value:<8} {label}")
        wrong = ask("account or payment: ").strip().lower()
        if wrong not in REJECT_CHOICES:
            print("Nothing was decided. The payment is still waiting. (Type account or payment, "
                  "or give --wrong.)")
            return 1
    if ask("Type yes to reject this payment: ").strip().lower() != "yes":
        print("Nothing was decided. The payment is still waiting.")
        return 1
    request = hold.request
    before = VendorFile.from_state(store.state()["vendors"]).accounts_for(request.payee)
    try:
        store.console().reject(hold.id, approver=args.signer or default_name(), wrong=wrong)
    except (KeyError, ValueError, StoreError) as exc:
        raise _Stop(f"The hold was not rejected: {exc}", 1) from None
    after = VendorFile.from_state(store.state()["vendors"]).accounts_for(request.payee)
    if about_account and wrong == "payment":
        print(f"Rejected {hold.id}. Nothing was paid, and this same payment is refused for the "
              "rest of the task. You said the account is right, so another payment to it is "
              "decided on its own.")
    elif about_account:  # P1, P2, P3: the account was the question
        print(f"Rejected {hold.id}. Nothing was paid, and this payee and account are refused "
              "for the rest of the task.")
        if request.account in before and request.account not in after:
            print("The account was also taken off the vendor file: an approval had added it "
                  "recently, and you have now said no to it.")
    else:
        print(f"Rejected {hold.id}. Nothing was paid, and this same payment is refused for the "
              "rest of the task. The account is on file, so another payment to it is decided "
              "on its own.")
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
    start.add_argument("--payments-for", action="append", default=[], metavar="PAYEE=N",
                       help="expect N payments to this payee in the task, instead of what the "
                            "sentence says or the default of one (repeatable, one per payee)")
    start.add_argument("--amount-for", action="append", default=[], metavar="PAYEE=AMT",
                       help="the most this payee is to be paid in the task, instead of what "
                            "the sentence says (repeatable, one per payee)")
    start.add_argument("--plain", action="store_true",
                       help="read nothing from the sentence: no account, amount, count or "
                            "invoice number (the limits, --account and one payment per payee "
                            "apply)")
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
                    "sends the payment only after you type yes. A hold about the account "
                    "(P1, P2, P3) also needs the whole account typed back as the vendor "
                    "confirmed it to you; it is refused if it differs. A hold about the "
                    "amount (A1, A2) asks whether this is the payee's new usual amount. "
                    + scripted,
    )
    approve.add_argument("id", metavar="ID", help="the hold id, for example H001")
    approve.add_argument("--remember-account", action="store_true",
                         help="also add the account to the vendor file for this payee")
    approve.add_argument("--usual-amount", action="store_true",
                         help="also mark the amount as the payee's new usual amount (only for "
                              "a hold about the amount, A1 or A2)")
    _signer_option(approve)
    _db_option(approve)
    approve.set_defaults(func=_run(_holds_approve, "holds approve"))

    reject = actions.add_parser(
        "reject",
        help="refuse one held payment (asks for a typed yes)",
        description="Shows the hold in full and refuses it after you type yes. For a hold "
                    "about the account (P1, P2, P3) it first asks what was wrong, unless "
                    "--wrong says. " + scripted,
    )
    reject.add_argument("id", metavar="ID", help="the hold id, for example H001")
    reject.add_argument(
        "--wrong", choices=REJECT_CHOICES, default=None,
        help="what was wrong, for a hold about the account (P1, P2, P3). account: the account "
             "is not the payee's, so it is refused for the rest of the task. payment: the "
             "account is right but the amount or the invoice is not, so only this payment is "
             "refused. Without it you are asked.")
    _signer_option(reject)
    _db_option(reject)
    reject.set_defaults(func=_run(_holds_reject, "holds reject"))
