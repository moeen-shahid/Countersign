"""The decision engine. Plain code, no model: the same request and the same
state always get the same answer, and nothing an attacker writes in a document
can argue with it.

One table of rules, checked in the order of `RULE_ORDER`. A BLOCK rule ends
the check. The HOLD rules are all checked, and a held payment carries every
one that applies.

The central property is that untrusted text can never produce an ALLOW. It is
true by construction:

* `authorise(req, trusted)` sees only trusted state: the mandate (the user's
  sentence and what a person confirmed from it), the vendor file, what the
  task has paid, the record of paid invoices, the payments waiting for a
  person, rejections and the clock. It answers ALLOW, BLOCK, a HOLD that
  follows from trusted state alone, or None, which means "trusted state does
  not vouch for this destination".
* Only then does `classify(req, trusted, provenance)` look at what the agent
  read. It can only refuse (the account was seen nowhere, or too many
  payments are waiting) or ask a person (the account was seen somewhere).
  The only function that builds an ALLOW is `_allow`, only `authorise` calls
  it, and nothing `classify` calls can reach it (a test walks the code to
  check this).
* When `authorise` allowed or held a payment, `_with_documents` asks the two
  rules that read documents (`DOCUMENT_RULES`): T1, the amount or invoice
  number is written in text a reader does not see, and D4, two invoices have
  the bare number you named. They only ever add a hold, and only when a
  document (or an earlier request) shows something; more documents can only
  show more. Under a full queue they do not count: whether a payment that
  trusted state lets through is refused (H1) never depends on what was read.

Documents can still change an answer in one direction. A payment that waits
for a person because of a document (P1, P2, T1, D4) counts against every
limit as if it were paid (H2) and makes a rival payment of the same invoice
wait (D3). So reading more documents can turn an ALLOW into a HOLD, never the
reverse. That holds over a whole session, not only for one request:

* every rule that looks at payments only gets stricter as more payments are
  counted (paid or waiting), so more waiting payments never make room;
* the queue limit (H1) is the one rule that refuses a payment because others
  wait. A guard that read more documents fills its queue no later than one
  that read less. Once its queue has overflowed (H1 refused something), the
  task is quarantined: nothing more is paid without a person in that task,
  even after a person has decided some of the waiting payments. So the guard
  that refused a payment the other one counts never pays what the other one
  holds back;
* an agent's request is judged with every waiting payment counted, also one
  identical to it. Asked again, it would be one more payment if both were
  paid, so a repeat never goes through while the first one waits: it joins
  the waiting payment instead. And a payment made once in a task is not made
  again in that task (D2), unless a person typed that one invoice is paid in
  parts. So a guard that holds a payment and one that paid it count it alike;
* at approval, the rules about other waiting payments (H2, D3) never re-show
  a hold: which payments wait depends on what was read. The person sees the
  current rivals and waiting payments instead (`Guard.related`).

The mandate also carries what the user's sentence states about each payee
(`Mandate.asks`: an amount, a number of payments, invoice numbers), read by
`drafting.draft_mandate` and confirmed by a person. That is trusted state. A
payment for an invoice other than the ones the user named for that payee is
refused by every guard (S3), like a reference outside the mandate's own list
(M6). A payment above the stated amount or beyond the expected number of
payments (one per payee unless the sentence says more) is held by Countersign
(S1, S2) and refused by the two baselines (M7), which have nobody to ask.
When the sentence says not to pay some of a payee's invoices, every payment
to that payee that is not for an invoice it names waits for a person (S4).

Three guards share the table. "rules" (name allowlist plus caps) and "strict"
(account allowlist plus caps) are our own baselines, there to show what those
designs miss. "countersign" is the product.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, fields, replace
from datetime import datetime, timedelta, timezone
from decimal import ROUND_DOWN, Decimal
from typing import Any, Mapping, Sequence

from .iban import fmt_iban, is_canonical_iban
from .models import (
    CENT,
    DEFAULT_PAYMENTS,
    Check,
    Decision,
    Evidence,
    Mandate,
    Outcome,
    PaymentRequest,
    SightingRef,
    clean_label,
    figures_in,
    fold_lookalikes,
    invoice_core,
    invoice_key,
    is_plain_text,
    mask,
    may_be_same_invoice,
    mixes_alphabets,
    money,
    name_key,
    names_invoice,
    plain,
    ref_core,
    ref_key,
    same_invoice,
)
from .provenance import ProvenanceTracker
from .vendors import VendorFile

GUARD_MODES = ("rules", "strict", "countersign")
# H1. The queue of payments waiting for a person is full when this many of
# them wait because of their account (P1, P2, P3) ...
MAX_PENDING_HOLDS = 5
# ... or when this many wait in all.
MAX_WAITING = 10
# Rules whose question is the destination: is this the payee's account?
DESTINATION_RULES = ("P1", "P2", "P3")
# Rules that read the documents (T1, D4). They are checked after trusted state
# has decided, and they can only add a hold: a document never takes one away.
DOCUMENT_RULES = ("D4", "T1")
# A1, see `usual_ceiling`. One invoice may come to the payee's largest usual
# amount plus a headroom: as much as the usual amounts differ from each other,
# but at least AMOUNT_HEADROOM_MIN and at most AMOUNT_HEADROOM_MAX of the
# largest. A vendor whose amounts never vary gets the small headroom; one whose
# amounts vary a lot gets the large one. The headroom is for the whole task:
# what all invoices to the payee come to above the largest usual amount,
# together. 15% and 35% were measured on every suite (v0.3): 20% and 50% let
# four held-out attacks through that these stop, and two more ordinary tasks
# out of 49 ask a person (a hosting plan up 20%, an invoice with a late fee).
AMOUNT_HEADROOM_MIN = Decimal("0.15")
AMOUNT_HEADROOM_MAX = Decimal("0.35")
# P3: an account a person added through an approval stays on probation until a
# person countersigns a payment to it at least this long after it was added:
# a second look on another occasion, however long the vendor's billing cycle.
PROBATION_GAP = timedelta(days=1)
HISTORY_SHOWN = 10  # earlier payments listed in evidence (the line uses all of them)

_ALL = GUARD_MODES
_STRICT = ("strict",)
_BASELINES = ("rules", "strict")
_OURS = ("countersign",)

# id, title, outcome, guards that run it. The order is the order of evaluation.
_TABLE = (
    ("M0", "No active task", "BLOCK", _ALL),
    ("M1", "Mandate expired", "BLOCK", _ALL),
    ("F1", "Malformed request", "BLOCK", _ALL),
    ("F2", "Reference mixes alphabets", "BLOCK", _OURS),
    ("M2", "Payee not in the mandate", "BLOCK", _ALL),
    ("M3", "Amount invalid or over the per-payment limit", "BLOCK", _ALL),
    ("M4", "Over the task budget", "BLOCK", _ALL),
    ("M5", "Payment count used up", "BLOCK", _ALL),
    ("M6", "Not a reference you typed", "BLOCK", _ALL),
    ("S3", "Not an invoice you named", "BLOCK", _ALL),
    ("B1", "Not the account on file", "BLOCK", _STRICT),
    ("M7", "More than the sentence asks for", "BLOCK", _BASELINES),
    ("O1", "Account seen nowhere", "BLOCK", _OURS),
    ("R1", "Already rejected by a person", "BLOCK", _OURS),
    ("D2", "Already paid in this task", "BLOCK", _OURS),
    ("H1", "Too many payments waiting", "BLOCK", _OURS),
    ("P1", "Not the account on file", "HOLD", _OURS),
    ("P2", "First payment to an unverified account", "HOLD", _OURS),
    ("P3", "Account added recently by an approval", "HOLD", _OURS),
    ("S1", "More than the amount you stated", "HOLD", _OURS),
    ("S2", "More payments than expected", "HOLD", _OURS),
    ("S4", "You said not to pay some of this payee's invoices", "HOLD", _OURS),
    ("A2", "No usual amount for this payee", "HOLD", _OURS),
    ("A1", "Unusual amount for this payee", "HOLD", _OURS),
    ("A3", "Also above the largest usual amount", "HOLD", _OURS),
    ("D1", "Possible duplicate invoice", "HOLD", _OURS),
    ("D4", "Two invoices have the number you named", "HOLD", _OURS),
    ("T1", "Amount or invoice number in hidden text", "HOLD", _OURS),
    ("D3", "Another account is waiting for this invoice", "HOLD", _OURS),
    ("H2", "Needs what a waiting payment needs", "HOLD", _OURS),
)
RULE_ORDER = tuple(row[0] for row in _TABLE)
RULES = {row[0]: row[1] for row in _TABLE}
RULE_OUTCOMES = {row[0]: row[2] for row in _TABLE}
RULE_GUARDS = {row[0]: row[3] for row in _TABLE}
# Codes a decision can carry that are not rules of the table.
OTHER_CODES = {
    "OK": "Allowed",
    "BANK": "Refused or not confirmed by the bank",
    "ERR": "The guard could not evaluate the request",
    "NONE": "No guard",
}


def rule_title(code: str) -> str:
    return RULES.get(code) or OTHER_CODES.get(code, "")


# --- what trusted state says about amounts and counts --------------------------------


def usual_ceiling(history: Sequence[Decimal]) -> Decimal | None:
    """The most one invoice to a payee can come to before a person is asked (A1).

    `history` holds the amounts that count as usual for the payee (see
    `vendors.py`). The line is the largest of them plus a headroom: how far
    the usual amounts reach below the largest (largest minus smallest), kept
    between AMOUNT_HEADROOM_MIN and AMOUNT_HEADROOM_MAX of the largest.
    Rounded down to the cent. None when nothing counts as usual.
    """
    if not history:
        return None
    top, low = max(history), min(history)
    headroom = max(top - low, top * AMOUNT_HEADROOM_MIN)
    headroom = min(headroom, top * AMOUNT_HEADROOM_MAX)
    return (top + headroom).quantize(CENT, rounding=ROUND_DOWN)


def _whole_percent(share: Decimal) -> str:
    return f"{int(share * 100)}%"


def line_words(history: Sequence[Decimal]) -> str:
    """Where the A1 line is and why, in plain words. Empty with no usual amount.

    "The line is 569.25: the largest usual payment (495.00) plus 15%. That is
    the least room the line allows; the usual amounts vary less than that."
    """
    ceiling = usual_ceiling(history)
    if ceiling is None:
        return ""
    largest, smallest = max(history), min(history)
    spread = largest - smallest
    head = f"The line is {money(ceiling)}: the largest usual payment ({money(largest)}) plus"
    if spread <= largest * AMOUNT_HEADROOM_MIN:
        tail = ("; the usual amounts vary less than that." if spread > 0
                else ", because the usual amounts do not vary." if len(history) > 1
                else ", because there is only one usual amount.")
        return (f"{head} {_whole_percent(AMOUNT_HEADROOM_MIN)}. That is the least room the "
                f"line allows{tail}")
    if spread >= largest * AMOUNT_HEADROOM_MAX:
        return (f"{head} {_whole_percent(AMOUNT_HEADROOM_MAX)}. That is the most room the "
                "line allows; the usual amounts vary more than that.")
    return (f"{head} {money(ceiling - largest)}, as much as the usual amounts vary "
            f"({money(smallest)} to {money(largest)}).")


def counts_as_usual(history: Sequence[Decimal], amount: Decimal) -> bool:
    """Does a payment made without a person's mark join the usual amounts?

    Only when it lies inside the range the usual amounts already span. A
    payment above the range is paid (if A1 let it through) but does not raise
    the line, so the agent cannot ratchet the line up task by task; a payment
    below it does not widen the headroom. A person moves the range by marking
    an approved payment as the new usual amount.
    """
    return bool(history) and min(history) <= amount <= max(history)


def stated_amount(mandate: Mandate | None, payee: str | None) -> Decimal | None:
    """The amount the user's sentence states for this payee, if the mandate has one."""
    if mandate is None or payee is None:
        return None
    return mandate.ask_for(payee).amount


def expected_payments(mandate: Mandate, payee: str) -> int:
    """How many payments to one payee the task expects (S2, and the A1 task line).

    The number the sentence states for the payee, or the one a person set
    for it (`Ask.payments`; the drafter leaves it None when the sentence
    does not count). When a person typed a number of payments for the whole
    task, what it leaves for one payee also counts: n - (k - 1) of n for k
    payees, because every other payee needs at least one. The smaller of the
    two wins. With neither, `DEFAULT_PAYMENTS`. So a default never outranks
    a count a person typed: "Pay Nimbus" with `--payments 3` expects three.
    """
    read = mandate.ask_for(payee).payments
    typed = None
    if mandate.max_payments is not None:
        typed = max(mandate.max_payments - (len(mandate.payees) - 1), 1)
    found = [n for n in (read, typed) if n is not None]
    return min(found) if found else DEFAULT_PAYMENTS


def instalments_covered(mandate: Mandate, payee: str | None = None) -> int:
    """How often one invoice a person typed may be paid in a task without D1.

    One, unless a person typed the invoices (`--reference`) and a number of
    payments larger than the number of invoices: for the whole task when it
    has one payee (`--payments`), or for this payee (`--payments-for`, the
    task form). Then they asked for an invoice to be paid in parts: with n
    payments and m invoices, one invoice can be paid n - m + 1 times. When
    both counts are there, the smaller one is n. What the sentence says ("in
    two instalments") does not count here: a reading never lifts D1.
    """
    if not mandate.references:
        return 1
    counts = []
    if mandate.max_payments is not None and len(mandate.payees) == 1:
        counts.append(mandate.max_payments)
    if payee is not None:
        ask = mandate.ask_for(payee)
        if ask.payments is not None and ask.set_by_person("payments"):
            counts.append(ask.payments)
    if not counts:
        return 1
    named = len({ref_core(reference) for reference in mandate.references})
    return max(min(counts) - named + 1, 1)


def identical_payments(mandate: Mandate, payee: str) -> int:
    """How many times exactly the same payment (payee, account, amount and
    invoice) can belong to one task (D2, and when a repeat joins a waiting one).

    As many parts as a person typed for one invoice (`instalments_covered`),
    or as the sentence leaves for one invoice: n payments for m invoices it
    names for the payee leave n - m + 1 for one of them ("invoice KL-0931 in
    two instalments" gives 2), and a count of instalments of one invoice
    that names no number leaves all n ("the Nimbus invoice in two
    instalments", `Ask.instalments`). Otherwise once. This never lifts D1: a
    second part that only the sentence allows still waits for a person.
    """
    ask = mandate.ask_for(payee)
    read = 1
    if ask.invoices and ask.payments is not None:
        read = max(ask.payments - len({ref_core(r) for r in ask.invoices}) + 1, 1)
    elif ask.instalments and ask.payments is not None:
        read = ask.payments
    return max(instalments_covered(mandate, payee), read)


def payment_key(payee_key: str, account: str, amount: Decimal, reference: str
                ) -> tuple[str, str, str, str]:
    """Exactly one payment: the payee, the account, the amount and the reference
    as they are compared (an identical request is this same payment again).
    The reference is compared with look-alikes folded (`invoice_key`), so
    "MPW-118" with a Cyrillic М is the same payment again."""
    return (payee_key, account, plain(amount), invoice_key(reference))


@dataclass(frozen=True)
class Waiting:
    """A payment of this task that waits for a person (trusted: the guard's own record)."""

    payee_key: str
    account: str
    amount: Decimal
    reference: str
    destination: bool = True  # held because of its account (P1, P2, P3)
    hold_id: str = ""  # the hold it waits as, to name it to the person


@dataclass(frozen=True)
class Context:
    """Trusted state: everything `authorise` may look at.

    None of it can be written by the agent or by a document. `history` (and
    `baseline`, the largest of it) is the vendor file's usual amounts as they
    were when the task started, so payments made during the task do not move
    them.
    """

    mode: str
    mandate: Mandate | None
    vendors: VendorFile
    now: datetime
    spent: Decimal = Decimal("0.00")  # executed payments of this task
    payments: int = 0  # how many
    paid_to: Mapping[str, Decimal] = field(default_factory=dict)  # per payee key, this task
    paid_count: Mapping[str, int] = field(default_factory=dict)  # payments per payee key, this task
    # (payee key, invoice core) -> (how many payments, their sum) made for that
    # invoice in this task; the core is `models.ref_core` of the reference
    paid_refs: Mapping[tuple[str, str], tuple[int, Decimal]] = field(default_factory=dict)
    baseline: Mapping[str, Decimal] = field(default_factory=dict)  # payee key -> largest usual
    history: Mapping[str, tuple[Decimal, ...]] = field(default_factory=dict)
    # (payee key, reference key) -> record of the payment already made for it
    ledger: Mapping[tuple[str, str], Mapping[str, Any]] = field(default_factory=dict)
    rejected: frozenset[tuple[str, str]] = frozenset()  # (payee key, account), this task
    # (payee key, account, amount, reference key) of every hold rejected in this task
    rejected_payments: frozenset[tuple[str, str, str, str]] = frozenset()
    pending: int = 0  # payments of this task waiting for a person (other than this one)
    # The payments of this task that wait for a person, other than the one
    # being decided. H1 counts them, H2 and D3 look at what they would pay.
    waiting: tuple[Waiting, ...] = ()
    # A person is deciding a waiting payment (Guard.approve), not the agent
    # asking for a new one: the queue limit (H1) is not about this.
    approving: bool = False
    # The queue overflowed earlier in this task (H1 refused a request). From
    # then on nothing more is paid without a person in this task.
    quarantined: bool = False
    # payment_key -> how many times exactly that payment was made in this task (D2)
    paid_exact: Mapping[tuple[str, str, str, str], int] = field(default_factory=dict)
    # (payee key, account) refused for the rest of the task: a person rejected a
    # payment whose question was that account (P1, P2, P3)
    refused_accounts: frozenset[tuple[str, str]] = frozenset()
    # (payee key, `invoice_key` of the reference) of every request the agent
    # made earlier in this task, whatever was decided (D4). `requested_all`:
    # too many to keep, so D4 counts every number as claimed twice.
    requested: frozenset[tuple[str, str]] = frozenset()
    requested_all: bool = False


class _Ladder:
    """Collects one Check per rule while a request is judged."""

    def __init__(self, mode: str) -> None:
        self.mode = mode
        self._checks: dict[str, Check] = {}

    def set(self, rule: str, status: str, detail: str) -> None:
        self._checks[rule] = Check(rule, status, detail)

    def ok(self, rule: str, detail: str) -> None:
        self.set(rule, "pass", detail)

    def na(self, rule: str, detail: str) -> None:
        self.set(rule, "na", detail)

    def checks(self) -> tuple[Check, ...]:
        """The whole ladder. Rules nobody filled in were not run."""
        done = []
        for rule in RULE_ORDER:
            check = self._checks.get(rule)
            if check is None and self.mode not in RULE_GUARDS[rule]:
                check = Check(rule, "off", "Not part of this guard.")
            elif check is None:
                check = Check(rule, "skipped", "Not reached: an earlier rule refused the payment.")
            done.append(check)
        return tuple(done)


def _when(moment: datetime) -> str:
    return f"{moment.astimezone(timezone.utc):%Y-%m-%d %H:%M} UTC"


def _accounts(accounts: tuple[str, ...]) -> str:
    return " and ".join(fmt_iban(a) for a in accounts)


class _Case:
    """One request being judged against trusted state."""

    def __init__(self, req: PaymentRequest, ctx: Context) -> None:
        self.req = req
        self.ctx = ctx
        self.ladder = _Ladder(ctx.mode)
        mandate = ctx.mandate
        readable = is_plain_text(req.payee)
        # The mandate's own spelling, or None if the payee is not covered.
        self.payee: str | None = (
            mandate.canonical_payee(req.payee) if mandate is not None and readable else None
        )
        self.key = name_key(self.payee) if self.payee is not None else ""
        self.valid_iban = is_canonical_iban(req.account)
        self.on_file: tuple[str, ...] = ()
        self.dictated = False
        self.owner: str | None = None
        self.previous: Mapping[str, Any] | None = None
        self.paid_before = 0  # payments of this invoice to this payee, in any task
        self.sightings: tuple[SightingRef, ...] = ()
        self.added: datetime | None = None  # when an approval put this account on file
        self.expected: int | None = None
        # Invoices the user named for this payee (sentence) or typed (--reference).
        self.named: tuple[str, ...] = ()
        # Filled in by H2 and D3 for the person: hold ids and rule codes.
        self.waiting_holds: tuple[str, ...] = ()
        self.projected_rules: tuple[str, ...] = ()
        self.rivals: tuple[str, ...] = ()
        # What the documents add (T1, D4): (rule, short detail, sentence for the
        # person), and the ladder lines of the ones that do not apply. Only
        # `_document_findings` fills them; `_held` puts them on the ladder.
        self.documents: list[tuple[str, str, str]] = []
        self.document_lines: tuple[Check, ...] = ()
        # Where the documents found it, for the end of the reason: the names
        # are the senders' (like `_sources`), so they go last.
        self.document_tail = ""
        if self.payee is not None:
            self.named = tuple(mandate.ask_for(self.payee).invoices) + tuple(mandate.references)
            self.on_file = tuple(sorted(ctx.vendors.accounts_for(self.payee)))
            self.dictated = self.valid_iban and req.account in mandate.accounts_for(self.payee)
            self.expected = expected_payments(mandate, self.payee)
            if is_plain_text(req.reference) and ref_key(req.reference):
                # The same invoice whoever chose the spelling: "INV-2041", "2041"
                # and "inv2041" are one (`same`). The latest record is shown;
                # records made in the same minute are ordered by their invoice
                # key, so a saved and reloaded guard shows the same one.
                matching = {(str(record.get("time", "")), ref): record
                            for (key, ref), record in ctx.ledger.items()
                            if key == self.key and self.same(ref, req.reference)}
                found = [matching[order] for order in sorted(matching)]
                if found:
                    self.previous = found[-1]
                    self.paid_before = sum(_count(record) for record in found)
            if req.account in self.on_file:
                self.added = ctx.vendors.added_at(self.payee, req.account)
        if self.valid_iban:
            other = ctx.vendors.owner_of(req.account, other_than=self.payee)
            self.owner = other.name if other is not None else None

    @property
    def parts(self) -> int:
        """How often one invoice of this payee may be paid in this task (D1, D2)."""
        return instalments_covered(self.ctx.mandate, self.payee)

    @property
    def vouched(self) -> bool:
        """Trusted state says this account belongs to this payee.

        The vendor file outranks the chat: an account the user dictated only
        counts when the payee has no account on file, and never when the
        vendor file says the account belongs to a different vendor.
        """
        if self.on_file:
            return self.req.account in self.on_file
        return self.dictated and self.owner is None

    def same(self, first: str, second: str) -> bool:
        """Two references may name the same invoice of this payee:
        `may_be_same_invoice` (look-alikes folded), or both are that one
        invoice the user named. `same_invoice` lets a bare number match any
        letters before it ("931" is "KL-931" and "XY-931"), so without the
        second test "KL-931" and "XY-931" would be two invoices although each
        passes S3 as invoice 931. Only ever makes D1, D3, H2 and A1 group more
        payments as one invoice: it can only add holds."""
        if may_be_same_invoice(first, second):
            return True
        return any(may_be_same_invoice(name, first) and may_be_same_invoice(name, second)
                   for name in self.named)

    def in_task(self) -> tuple[int, Decimal]:
        """(payments, their sum) already made for this invoice to this payee in this task."""
        count, total = 0, Decimal("0.00")
        for (key, core), (n, paid) in self.ctx.paid_refs.items():
            if key == self.key and self.same(core, self.req.reference):
                count, total = count + n, total + paid
        return count, total

    def evidence(self) -> Evidence:
        req, ctx = self.req, self.ctx
        baseline = ctx.baseline.get(self.key) if self.key else None
        ceiling = usual_ceiling(ctx.history.get(self.key, ())) if self.key else None
        shown = self.payee
        if shown is None:
            shown = clean_label(req.payee, 60) if isinstance(req.payee, str) else ""
        ask = ctx.mandate.ask_for(self.payee) if self.payee is not None else None
        return Evidence(
            payee=shown,
            account=req.account,
            valid_iban=self.valid_iban,
            on_file=self.on_file,
            on_file_for=self.owner,
            dictated=self.dictated,
            typed_by_user=any(s.origin == "user" for s in self.sightings),
            sightings=self.sightings,
            history=tuple(plain(a) for a in ctx.history.get(self.key, ())[-HISTORY_SHOWN:])
            if self.key else (),
            baseline=None if baseline is None else plain(baseline),
            previous_payment=None if self.previous is None else dict(self.previous),
            spent=plain(ctx.spent),
            budget=plain(ctx.mandate.max_total if ctx.mandate is not None else Decimal(0)),
            paid_to_payee=plain(ctx.paid_to.get(self.key, Decimal(0))),
            ceiling=None if ceiling is None else plain(ceiling),
            added=None if self.added is None else self.added.isoformat(),
            stated=None if ask is None or ask.amount is None else plain(ask.amount),
            expected=self.expected,
            payments_to_payee=ctx.paid_count.get(self.key, 0) if self.key else 0,
            named_invoices=ask.invoices if ask is not None else (),
            waiting_holds=self.waiting_holds,
            projected_rules=self.projected_rules,
            rivals=self.rivals,
        )

    def block(self, rule: str, reason: str) -> Decision:
        self.ladder.set(rule, "block", reason)
        return Decision(
            Outcome.BLOCK, rule, reason, (rule,), self.ladder.checks(), self.evidence()
        )

    def hold(self, rules: list[str], reason: str) -> Decision:
        return Decision(
            Outcome.HOLD, rules[0], reason, tuple(rules), self.ladder.checks(), self.evidence()
        )


def _count(record: Mapping[str, Any]) -> int:
    """How many payments a ledger record stands for (records before v0.3: one)."""
    try:
        return max(int(record.get("count", 1)), 1)
    except (TypeError, ValueError):
        return 1


def _allow(case: _Case, reason: str) -> Decision:
    """The only place an ALLOW is made. Called by `authorise` and nothing else."""
    return Decision(Outcome.ALLOW, "OK", reason, (), case.ladder.checks(), case.evidence())


def _malformed(req: PaymentRequest) -> list[str]:
    problems = []
    if not is_plain_text(req.payee) or not name_key(req.payee):
        problems.append("There is no readable payee name.")
    if not is_canonical_iban(req.account):
        problems.append("The account is not a valid IBAN, and only IBANs are paid.")
    if not is_plain_text(req.reference) or not ref_key(req.reference):
        problems.append("There is no readable payment reference, and every payment needs one.")
    return problems


def _s(count: int) -> str:
    return "" if count == 1 else "s"


def _times(count: int) -> str:
    return "once" if count == 1 else "twice" if count == 2 else f"{count} times"


def _mandate_rules(case: _Case) -> Decision | None:
    """M0 to M6 and S3: is the request inside what the user authorised?"""
    req, ctx, ladder = case.req, case.ctx, case.ladder
    mandate = ctx.mandate
    if mandate is None:
        return case.block("M0", "No task is active, so the agent may not pay anyone.")
    ladder.ok("M0", "A task is active.")

    if ctx.now >= mandate.expires_at:
        return case.block("M1", f"The mandate expired at {_when(mandate.expires_at)}.")
    ladder.ok("M1", f"The mandate is valid until {_when(mandate.expires_at)}.")

    problems = _malformed(req)
    if problems:
        return case.block("F1", "The request is malformed. " + " ".join(problems))
    ladder.ok("F1", "The payee, account and reference are readable.")

    if ctx.mode in RULE_GUARDS["F2"]:
        if mixes_alphabets(req.reference):
            return case.block(
                "F2", "The reference mixes letters of two alphabets (for example a Cyrillic or "
                      "Greek letter that looks like a Latin one), the way a copy of another "
                      f"invoice number is disguised. It reads as {clean_label(fold_lookalikes(req.reference))} "
                      "when the look-alikes are made plain. No genuine invoice needs this, so "
                      "it is refused.",
            )
        ladder.ok("F2", "The letters of the reference come from one alphabet.")

    if case.payee is None:
        asked = clean_label(req.payee) or "(nothing readable)"
        return case.block(
            "M2", f"The payee is not in the mandate. Payee as the agent wrote it: {asked}."
        )
    payee = case.payee
    ladder.ok("M2", f"{payee} is in the mandate.")

    amount = req.amount
    if amount is None or amount <= 0:
        return case.block(
            "M3", "The amount is not a plain positive number with at most two decimals."
        )
    if req.currency is not None and req.currency != mandate.currency:
        return case.block(
            "M3", f"The amount is not in the mandate's currency ({mandate.currency})."
        )
    if amount > mandate.max_per_payment:
        return case.block(
            "M3",
            f"{money(amount)} is over the per-payment limit of {money(mandate.max_per_payment)}.",
        )
    ladder.ok("M3", f"{money(amount)} is within the {money(mandate.max_per_payment)} limit.")

    total = ctx.spent + amount
    if total > mandate.max_total:
        return case.block(
            "M4",
            f"{money(amount)} would take this task to {money(total)}, "
            f"over its budget of {money(mandate.max_total)}.",
        )
    ladder.ok(
        "M4", f"The task would reach {money(total)} of its {money(mandate.max_total)} budget."
    )

    limit = mandate.max_payments
    if limit is None:
        ladder.na("M5", "You did not set a number of payments for the task.")
    elif ctx.payments >= limit:
        return case.block(
            "M5",
            f"You set {limit} payment{_s(limit)} for this task and "
            f"{ctx.payments} {'has' if ctx.payments == 1 else 'have'} already been made.",
        )
    else:
        ladder.ok("M5", f"This would be payment {ctx.payments + 1} of the {limit} you set.")

    if not mandate.references:
        ladder.na("M6", "You did not type the references to pay.")
    elif not any(same_invoice(req.reference, r) for r in mandate.references):
        return case.block(
            "M6", "You typed the references to pay, and this one is not among them "
                  "(compared on the invoice number, without words like INV or leading zeros)."
        )
    else:
        ladder.ok("M6", "You typed this reference.")

    named = mandate.ask_for(payee).invoices
    if not named:
        ladder.na("S3", f"Your sentence names no invoice for {payee}.")
    elif not any(same_invoice(req.reference, r) for r in named):
        listed = ", ".join(named)
        return case.block(
            "S3", f"Not an invoice you named. Your sentence names {listed} for {payee}; "
            f"this payment's reference is not {'that invoice' if len(named) == 1 else 'one of them'}"
            " (compared on the invoice number, without words like INV or leading zeros)."
        )
    else:
        ladder.ok("S3", "You named this invoice.")
    return None


# --- what the sentence states (S1, S2; M7 for the baselines) ---------------------------


def _outside_the_sentence(case: _Case) -> list[tuple[str, str, str]]:
    """Where a payment goes beyond what the task expects for the payee.

    The mandate carries what was read from the user's sentence and confirmed
    by a person (`Mandate.asks`): an amount for the payee, and a number of
    payments (one per payee when nothing says more, `expected_payments`).
    Returns (rule, short detail, sentence for the person) for each one this
    payment would exceed. Everything it looks at is trusted state.
    """
    req, ctx, payee = case.req, case.ctx, case.payee
    ask = ctx.mandate.ask_for(payee)
    found = []
    if ask.amount is not None:
        total = ctx.paid_to.get(case.key, Decimal(0)) + req.amount
        if total > ask.amount:
            found.append((
                "S1",
                f"{money(total)} to {payee} in this task is more than the "
                f"{money(ask.amount)} you stated.",
                f"More than you stated. Your sentence says {money(ask.amount)} for {payee}; "
                f"this payment would bring what this task pays them to {money(total)}.",
            ))
    expected = case.expected
    done = ctx.paid_count.get(case.key, 0)
    if done >= expected:
        if ask.payments is not None and ask.set_by_person("payments") and expected == ask.payments:
            why = f"you set {expected} payment{_s(expected)} for {payee} when you started the task"
        elif ask.payments is not None and expected == ask.payments:
            why = f"the task you confirmed expects {expected} payment{_s(expected)} to {payee}"
        elif ctx.mandate.max_payments is not None:
            why = (f"the {ctx.mandate.max_payments} payments you set for the task leave "
                   f"{expected} for {payee}")
        else:
            why = (f"nothing says how many payments {payee} gets, so {expected} "
                   f"{'is' if expected == 1 else 'are'} expected")
        found.append((
            "S2",
            f"This would be payment {done + 1} to {payee}, and {why}.",
            f"More payments than expected. This task has already paid {payee} {_times(done)} "
            f"({money(ctx.paid_to.get(case.key, Decimal(0)))}), and {why}.",
        ))
    return found


def _sentence_caps(case: _Case) -> Decision | None:
    """M7, for the two baselines: they cannot ask a person, so they refuse what
    Countersign would hold under S1 and S2."""
    outside = _outside_the_sentence(case)
    if outside:
        return case.block("M7", " ".join(sentence for _, _, sentence in outside))
    case.ladder.ok("M7", "Inside the amount and the number of payments the task expects.")
    return None


# --- HOLD rules that look at what was paid --------------------------------------------


def _no_usual_amount(case: _Case) -> tuple[str, str] | None:
    """A2: nothing in trusted state bounds the amount but the generic limit."""
    payee, ladder = case.payee, case.ladder
    if case.ctx.history.get(case.key):
        ladder.na("A2", f"{payee} has usual amounts on file.")
        return None
    stated = stated_amount(case.ctx.mandate, payee)
    if stated is not None:
        ladder.na("A2", f"You stated {money(stated)} for {payee} (S1 holds anything above it).")
        return None
    return (
        f"{payee} has no usual amount, and you stated none.",
        f"No usual amount. Nothing on file shows what {payee} is usually paid, and you did "
        f"not state an amount, so {money(case.req.amount)} comes only from what the agent "
        "read. Check it against the invoice and with the supplier.",
    )


def _percent_more(amount: Decimal, largest: Decimal) -> str:
    """"50%" for 742.50 against 495.00. Whole percent, rounded down, at least 1."""
    percent = int((amount - largest) * 100 / largest)
    return f"{max(percent, 1):,}%"


def _unusual_amount(case: _Case) -> tuple[str, str] | None:
    """A1: is this more than the payee's usual amounts explain?

    Payments of this task for the same invoice are added up, so paying in
    parts does not move the line. The headroom above the largest usual amount
    is for the task, not for each invoice: what every invoice to the payee
    comes to above the largest usual amount, added up, may not pass one
    headroom. An invoice below the largest usual amount makes no room for
    another one, so more payments can only bring the line closer.
    """
    req, ctx, ladder, payee = case.req, case.ctx, case.ladder, case.payee
    history = ctx.history.get(case.key, ())
    ceiling = usual_ceiling(history)
    if ceiling is None:
        ladder.na("A1", f"{payee} has no usual amount to compare with.")
        return None
    ordered = sorted(history)
    largest, smallest = ordered[-1], ordered[0]
    headroom = ceiling - largest
    if len(ordered) == 1:
        basis = f"the one usual amount is {money(largest)}"
    elif largest == smallest:
        basis = f"all {len(ordered)} usual amounts are {money(largest)}"
    else:
        basis = (
            f"the {len(ordered)} usual amounts are between {money(smallest)} and {money(largest)}"
        )
    core = invoice_core(req.reference)
    totals: dict[str, Decimal] = {}
    for (key, other), (_, paid) in ctx.paid_refs.items():
        if key == case.key:
            totals[other] = totals.get(other, Decimal("0.00")) + paid
    _, part_paid = case.in_task()
    this = part_paid + req.amount
    totals = {other: paid for other, paid in totals.items() if not case.same(other, core)}
    totals[core] = this
    excess = sum((max(paid - largest, Decimal("0.00")) for paid in totals.values()),
                 Decimal("0.00"))
    if part_paid:
        what = f"{money(this)} for this invoice ({money(part_paid)} already paid in this task)"
    else:
        what = money(this)
    if this > ceiling:
        lead = "Unusual amount."
        if part_paid:
            lead += f" This payment would bring what this task pays for this invoice to {money(this)}."
        return (
            f"{what} is above {money(ceiling)}: {basis}.",
            f"{lead} {money(this)} is {_percent_more(this, largest)} more than the largest usual "
            f"payment to {payee} ({money(largest)}). {line_words(history)} If it is the new "
            "usual amount, say so when you approve it; otherwise it will not raise the line.",
        )
    if excess > headroom:
        count = len(totals)
        return (
            f"The {count} invoices to {payee} in this task come to {money(excess)} above the "
            f"largest usual amount; one headroom of {money(headroom)} is allowed: {basis}.",
            f"Unusual amount. Each invoice to {payee} may come to at most {money(ceiling)}, but "
            f"the room above the largest usual payment ({money(largest)}) is for the whole task: "
            f"with this payment the {count} invoices of this task would use {money(excess)} "
            f"of it, and there is {money(headroom)}.",
        )
    ladder.ok("A1", f"{what} is not above {money(ceiling)}, the most that the usual amounts of "
                    f"{payee} explain ({basis}), and the task stays within one headroom.")
    return None


def _duplicate(case: _Case) -> tuple[str, str] | None:
    """D1: was this invoice paid to this payee before, in this task or any other?"""
    req, ctx, ladder, payee = case.req, case.ctx, case.ladder, case.payee
    record = case.previous
    if record is None:
        ladder.ok("D1", f"No earlier payment to {payee} has this invoice number.")
        return None
    in_task, _ = case.in_task()
    before_task = case.paid_before - in_task
    parts = case.parts
    if before_task <= 0 and 0 < in_task < parts:
        ladder.ok(
            "D1",
            f"You typed this invoice and more payments than invoices, so it may be paid in "
            f"parts: this would be part {in_task + 1} of at most {parts}.",
        )
        return None
    paid = Decimal(record["amount"])
    when = str(record.get("time", ""))[:10]
    transfer = record.get("transfer")
    proof = f"transfer {transfer}" if transfer else "not confirmed by the bank"
    where = "earlier in this task" if before_task <= 0 else "in an earlier task"
    if before_task > 0 and in_task > 0:
        where = "in this task and in an earlier one"
    same = " This payment is for the same amount." if paid == req.amount else ""
    return (
        f"An invoice with this number was already paid to {payee}.",
        f"Possible duplicate. An invoice with this number was already paid to {payee} "
        f"{where}: {money(paid)} on {when} ({proof}).{same}",
    )


def _payment_findings(case: _Case) -> list[tuple[str, str, str]]:
    """S1, S2, A2, A1 and D1: the HOLD rules that depend on what has been paid.

    Each finding is (rule, short detail, sentence for the person), in table
    order. Every one of them only gets stricter as more payments are counted,
    which is what lets H2 count a waiting payment as if it were made.
    """
    ladder, payee = case.ladder, case.payee
    ask = case.ctx.mandate.ask_for(payee)
    found = []
    outside = {rule: (detail, sentence) for rule, detail, sentence in _outside_the_sentence(case)}
    done = case.ctx.paid_count.get(case.key, 0)
    for rule, fine, unstated in (
        ("S1", f"Within the {money(ask.amount)} you stated for {payee}."
         if ask.amount is not None else "", f"Your sentence states no amount for {payee}."),
        ("S2", f"This would be payment {done + 1} of the {case.expected} expected for {payee}.",
         ""),
    ):
        if rule in outside:
            found.append((rule, *outside[rule]))
        elif fine:
            ladder.ok(rule, fine)
        else:
            ladder.na(rule, unstated)
    for rule, check in (("A2", _no_usual_amount), ("A1", _unusual_amount), ("D1", _duplicate)):
        finding = check(case)
        if finding is not None:
            found.append((rule, *finding))
    return found


def _probation(case: _Case, rules: list[str], sentences: list[str]) -> None:
    """P3: an account a person's approval added to the vendor file is watched.

    It is vouched for, but every payment to it is held until a person has
    countersigned one payment to it at least PROBATION_GAP after it was added
    (`Guard.approve` ends the probation then). There is no time limit: an
    agent that waits a month for the next invoice still meets a person, so
    one mistaken approval is looked at a second time, on another occasion."""
    ladder, payee, added = case.ladder, case.payee, case.added
    if added is None or case.req.account not in case.on_file:
        ladder.na("P3", "The account was not added to the vendor file by an approval.")
        return
    rules.append("P3")
    ladder.set("P3", "hold", f"The account was added to the vendor file on {_when(added)} and "
                             "no later payment to it has been countersigned.")
    sentences.append(
        f"Recently added account. A person added this account to the vendor file for {payee} "
        f"on {_when(added)}, when approving a payment. Until a person countersigns a payment to "
        "it on a later day, payments to it are held, so one mistaken approval does not open "
        "it for good."
    )


def _rivals(case: _Case, rules: list[str], sentences: list[str]) -> None:
    """D3: does a payment of the same invoice to another account wait for a person?"""
    req, ctx, ladder, payee = case.req, case.ctx, case.ladder, case.payee
    found = [w for w in ctx.waiting
             if w.payee_key == case.key and w.account != req.account
             and case.same(w.reference, req.reference)]
    rivals = sorted({w.account for w in found})
    if not rivals:
        ladder.ok("D3", "No payment of this invoice to another account is waiting.")
        return
    case.rivals = tuple(sorted({w.hold_id for w in found if w.hold_id}))
    rules.append("D3")
    ladder.set("D3", "hold", "A payment of this invoice to another account is waiting for a person.")
    sentences.append(
        f"Two accounts for one invoice. A payment of this invoice to {payee} at "
        f"{_accounts(tuple(rivals))} is waiting for a person, and this one would go to "
        f"{fmt_iban(req.account)}. At most one of them can be right: decide them together."
    )


def _projected(ctx: Context) -> Context:
    """Trusted state as it would be if every waiting payment of this task were
    approved and paid: the guard's own record, nothing the agent read."""
    spent, payments = ctx.spent, ctx.payments
    paid_to, paid_count = dict(ctx.paid_to), dict(ctx.paid_count)
    paid_refs, ledger = dict(ctx.paid_refs), dict(ctx.ledger)
    for w in ctx.waiting:
        spent += w.amount
        payments += 1
        paid_to[w.payee_key] = paid_to.get(w.payee_key, Decimal("0.00")) + w.amount
        paid_count[w.payee_key] = paid_count.get(w.payee_key, 0) + 1
        core = invoice_core(w.reference)
        count, total = paid_refs.get((w.payee_key, core), (0, Decimal("0.00")))
        paid_refs[(w.payee_key, core)] = (count + 1, total + w.amount)
        key = invoice_key(w.reference)
        if key:
            record = ledger.get((w.payee_key, key))
            earlier = _count(record) if record is not None else 0
            ledger[(w.payee_key, key)] = {
                "amount": plain(w.amount), "time": "(waiting for a person)", "transfer": None,
                "count": earlier + 1,
            }
    # Built field by field (not with dataclasses.replace, which policy.py
    # keeps for one place only; see the trust-boundary tests).
    state = {f.name: getattr(ctx, f.name) for f in fields(ctx)}
    state.update(spent=spent, payments=payments, paid_to=paid_to, paid_count=paid_count,
                 paid_refs=paid_refs, ledger=ledger, waiting=())
    return Context(**state)


def _reserved(case: _Case, rules: list[str], sentences: list[str]) -> None:
    """H2: would this payment still pass if every waiting payment were approved?

    A payment waiting for a person counts against every limit as if it were
    made: the budget (M4), the number of payments you set (M5), the amount
    and the number of payments the task expects for one payee (S1, S2), the
    usual amount (A1) and the invoices already paid (D1). A request that
    passes only because a waiting payment has not been decided is held, so an
    allowed payment cannot use up what a waiting one needs.

    More waiting payments can only turn an ALLOW into a HOLD, never the other
    way round. A document that makes a payment wait (P1, P2) can therefore
    add holds, but never an ALLOW.

    The reason says what would happen, not what has happened: nothing is
    paid until a person decides. The rules it would break are listed by code
    in `Evidence.projected_rules`, and the waiting payments by hold id in
    `Evidence.waiting_holds`.
    """
    ctx, ladder = case.ctx, case.ladder
    if not ctx.waiting:
        ladder.na("H2", "No other payment of this task is waiting for a person.")
        return
    count = len(ctx.waiting)
    projected = _Case(case.req, _projected(ctx))
    found: list[tuple[str, str]] = []
    refused = _mandate_rules(projected)
    if refused is not None:
        found.append((refused.rule, refused.reason))
    for rule, detail, _ in _payment_findings(projected):
        if rule not in rules and rule not in {code for code, _ in found}:
            found.append((rule, detail))
    if not found:
        ladder.ok("H2", f"It fits even if the {count} waiting payment{_s(count)} "
                        f"{'is' if count == 1 else 'are'} approved.")
        return
    rules.append("H2")
    order = {code: i for i, code in enumerate(RULE_ORDER)}
    found.sort(key=lambda item: order.get(item[0], len(order)))
    codes = tuple(code for code, _ in found)
    ids = tuple(w.hold_id for w in ctx.waiting if w.hold_id)
    case.waiting_holds, case.projected_rules = ids, codes
    total = sum((w.amount for w in ctx.waiting), Decimal("0.00"))
    if count == 1:
        who = f"the waiting payment {ids[0]}" if ids else "the waiting payment"
        which = f"{who} ({money(total)})"
    else:
        named = f" {_listed(ids)}" if len(ids) == count else ""
        which = f"the {count} waiting payments{named} ({money(total)} in all)"
    broken = _listed(tuple(f"{code} ({RULES[code].lower()})" for code in codes))
    detail = " ".join(f"{code}: {text}" for code, text in found)
    ladder.set("H2", "hold", f"It fits only if a waiting payment is refused. If {which} "
                             f"were paid, this one would break "
                             f"{_listed(codes)}. In that case: {detail}")
    them = "it has" if count == 1 else "they have"
    sentences.append(
        f"Needed by a waiting payment. If {which} were paid, this one would break {broken}. "
        f"Nothing is paid until a person decides, and {them} not been decided yet: decide "
        f"{'it' if count == 1 else 'them'} first, or together with this one."
    )


def _listed(items: Sequence[str]) -> str:
    """"A", "A and B", "A, B and C"."""
    items = list(items)
    if len(items) <= 1:
        return "".join(items)
    return ", ".join(items[:-1]) + " and " + items[-1]


def _rejection(case: _Case, first: tuple[str, str, str] | None) -> Decision | None:
    """R1. A person said no earlier in this task.

    When the account was the question (P1, P2, P3) and the person said the
    account was wrong (`Guard.reject`, the default for such a hold), that
    payee and account are refused for the rest of the task, and an account
    added by an approval (P3) leaves the vendor file again. When they said
    only the payment was wrong (the amount, say), or when trusted state
    vouched for the account, only that same payment is refused.
    """
    req, ctx, ladder = case.req, case.ctx, case.ladder
    pair = (case.key, req.account)
    if pair in ctx.refused_accounts:
        return case.block(
            "R1", "A person already rejected a payment to this payee and account in this task, "
                  "and said the account was wrong. No payment to it is made in this task.",
        )
    if first is not None and pair in ctx.rejected:
        return case.block(
            "R1",
            "A person already rejected a payment to this payee and account in this task.",
        )
    same = (case.key, req.account, plain(req.amount), invoice_key(req.reference))
    if same in ctx.rejected_payments:
        return case.block("R1", "A person already rejected this payment in this task.")
    if first is not None:
        ladder.ok("R1", "No payment to this payee and account was refused in this task.")
    else:
        ladder.ok("R1", "This payment was not rejected in this task.")
    return None


def _paid_already(case: _Case) -> Decision | None:
    """D2. Exactly this payment (payee, account, amount, invoice) was already
    made in this task. It is not sent again: a repeated request is far more
    often an agent trying again than a second bill. Only when one invoice is
    paid in parts (`identical_payments`: typed by a person, or "invoice
    KL-0931 in two instalments" in the sentence) may the same payment be made
    again, once per part, and D1 still asks a person unless a person typed it.

    It is a refusal and not a hold for a reason: a guard that holds the first
    request (because of a document) joins the repeat to that hold, while one
    that paid the first would hold the repeat on its own. A person deciding
    "this payment" in both would then pay it twice in one and once in the
    other. Refused, the repeat is never a second payment in either."""
    req, ctx, ladder = case.req, case.ctx, case.ladder
    made = ctx.paid_exact.get(payment_key(case.key, req.account, req.amount, req.reference), 0)
    if made == 0:
        ladder.ok("D2", "This exact payment was not made in this task.")
        return None
    parts = identical_payments(ctx.mandate, case.payee)
    if made < parts:
        ladder.ok("D2", f"This exact payment was made {_times(made)} in this task; this task "
                        f"pays one invoice in up to {parts} parts.")
        return None
    return case.block(
        "D2",
        f"Already paid in this task. Exactly this payment ({money(req.amount)} to the same "
        f"account, reference {clean_label(req.reference, 40)}) was already sent in this task, "
        "so it is not sent again. To pay one invoice in parts, say so when you start the task "
        "(\"invoice KL-0931 in two instalments\", or type the invoice and the number of "
        "payments).",
    )


def _excluded(case: _Case, rules: list[str], sentences: list[str]) -> None:
    """S4: the sentence says not to pay some of this payee's invoices.

    Every payment to the payee then waits for a person, unless its invoice
    is one the sentence names (compared exactly, as S3 does). The guard
    cannot tell which invoice "the April one" is; a person can."""
    req, ladder, payee = case.req, case.ladder, case.payee
    ask = case.ctx.mandate.ask_for(payee)
    if not ask.excludes_some:
        ladder.na("S4", f"Your sentence does not exclude any invoice of {payee}.")
        return
    if any(same_invoice(req.reference, name) for name in ask.invoices):
        ladder.ok("S4", "You named this invoice as one to pay.")
        return
    rules.append("S4")
    ladder.set("S4", "hold", f"Your sentence says not to pay some of {payee}'s invoices, and "
                             "it does not name this one as one to pay.")
    sentences.append(
        f"Some invoices are not to be paid. Your sentence says not to pay some of {payee}'s "
        f"invoices, and it does not name this one ({clean_label(req.reference)}) as one to pay. "
        "Check that it is not one of those."
    )


def _amount_too(case: _Case, rules: list[str], sentences: list[str]) -> None:
    """A3: a hold about the account also asks about the amount, when the
    amount is above the payee's largest usual amount.

    On its own such an amount may be inside the line A1 draws (the largest
    usual amount plus a headroom), so it is not held for it. But a person
    who checks only the account of a held payment would pay it, and a forged
    invoice to a supplier's genuine new account is just that. So whenever a
    payment waits because of its account (P1, P2, P3), an amount above every
    usual one is named too. A3 never holds a payment on its own."""
    req, ladder, payee = case.req, case.ladder, case.payee
    history = case.ctx.history.get(case.key, ())
    if not set(rules) & set(DESTINATION_RULES):
        ladder.na("A3", "Only asked together with a question about the account.")
        return
    if not history:
        ladder.na("A3", f"{payee} has no usual amount to compare with.")
        return
    if "A1" in rules:
        ladder.na("A3", "The amount already has its own question (A1).")
        return
    largest = max(history)
    _, part_paid = case.in_task()
    this = part_paid + req.amount
    if this <= largest:
        ladder.ok("A3", f"{money(this)} is not above the largest usual amount ({money(largest)}).")
        return
    rules.append("A3")
    ladder.set("A3", "hold", f"{money(this)} is above the largest usual payment to {payee} "
                             f"({money(largest)}).")
    sentences.append(
        f"Check the amount too. {money(this)} is {_percent_more(this, largest)} more than the "
        f"largest usual payment to {payee} ({money(largest)}). That alone would not hold it, "
        "but this payment waits anyway: check it against an invoice you expect, as well as "
        "the account."
    )


def _held(case: _Case, first: tuple[str, str, str] | None, tail: str) -> Decision | None:
    """R1, H1 and the HOLD rules, once the destination question is settled.

    `first` is the P1 or P2 finding (rule, short detail, sentences for the
    person) or None when trusted state vouches for the account. `tail` is the
    sentence that names where the account was read; it goes last because it
    carries names an attacker chose. `case.documents` holds what the
    documents add (T1, D4). Returns None when nothing applies. This function
    cannot return an ALLOW.
    """
    ctx, ladder, payee = case.ctx, case.ladder, case.payee

    refused = _rejection(case, first) or _paid_already(case)
    if refused is not None:
        return refused

    # H1: is the queue of payments waiting for a person full? See `_queue`.
    about_account = first is not None or (case.added is not None
                                          and case.req.account in case.on_file)
    full = _queue(case, about_account)
    if full is not None and (about_account or full[0] == "all"):
        return case.block("H1", full[1])
    if full is not None:
        ladder.ok("H1", full[2])

    rules: list[str] = []
    sentences: list[str] = []
    if first is not None:
        rules.append(first[0])
        ladder.set(first[0], "hold", first[1])
        sentences.append(first[2])
    if case.on_file:
        if first is None:
            ladder.ok("P1", f"This is the account on file for {payee}.")
        ladder.na("P2", f"{payee} has an account on file.")
    else:
        ladder.na("P1", f"{payee} has no account on file.")
        if first is None:
            ladder.ok("P2", f"You gave this account for {payee}.")
    _probation(case, rules, sentences)
    _excluded(case, rules, sentences)
    for rule, detail, sentence in _payment_findings(case):
        rules.append(rule)
        ladder.set(rule, "hold", detail)
        sentences.append(sentence)
    _amount_too(case, rules, sentences)
    _rivals(case, rules, sentences)
    _reserved(case, rules, sentences)

    if not rules and full is not None:
        # Nothing is paid without a person while the queue is full. What the
        # documents add does not count here: whether a payment that trusted
        # state lets through is refused must not depend on what was read.
        return case.block("H1", full[1])
    for line in case.document_lines:
        ladder.set(line.rule, line.status, line.detail)
    for rule, detail, sentence in case.documents:
        rules.append(rule)
        ladder.set(rule, "hold", detail)
        sentences.append(sentence)
    if not rules:
        return None
    order = {code: i for i, code in enumerate(RULE_ORDER)}
    ranked = sorted(zip(rules, sentences), key=lambda pair: order[pair[0]])
    rules, sentences = [rule for rule, _ in ranked], [sentence for _, sentence in ranked]
    if tail:
        sentences.append(tail)
    if case.documents and case.document_tail:
        sentences.append(case.document_tail)
    return case.hold(rules, " ".join(sentences))


def _queue(case: _Case, about_account: bool) -> tuple[str, str, str] | None:
    """H1: is the queue of payments waiting for a person full?

    It is full when payments wait because of their account (P1, P2, P3) for
    MAX_PENDING_HOLDS different invoices, or MAX_WAITING payments wait in
    all. Payments whose account is in question count once per payee and
    invoice (`ref_core`): the person answers one question for each, "which
    account is this payee's?". So five accounts offered for one invoice fill
    one place, not five (adversary C03), and one more account for an invoice
    already in the queue still waits with it. When the queue is full, a new
    payment whose question is the account is refused, so is a payment that
    would go through without a person, and at MAX_WAITING so is everything.
    A payment to an account trusted state vouches for that needs a person
    anyway is still queued while fewer than MAX_WAITING wait.

    Once H1 has refused a request, the task is quarantined (`quarantined`):
    the queue counts as full for the rest of the task, also after a person
    has decided some of the waiting payments. So nothing more is paid without
    a person in that task. A new task starts clean.

    Why a payment that needs no person is refused too, and why the queue
    stays full: a guard that has read more documents has more payments
    waiting, so its queue fills first. If it then refused a payment that the
    other guard queues, the other guard's queued payment would count against
    its later payments (H2) and this one's would not. Were it to pay again
    once its queue drained, it could pay something the other guard holds
    back. A full queue that allows nothing, for the rest of the task, cannot.
    Returns ("account" or "all", the reason for a refusal, the ladder line
    for a payment that may still wait) when full, else None. Never applies
    while a person approves.
    """
    ctx, ladder = case.ctx, case.ladder
    if ctx.approving:
        ladder.na("H1", "A person is deciding a payment that is already waiting.")
        return None
    waiting = len(ctx.waiting)
    # Account questions count once per payee and invoice (adversary C03).
    questions = {(w.payee_key, ref_core(w.reference)) for w in ctx.waiting if w.destination}
    accounts = len(questions)
    # One more account for an invoice already in question joins that question.
    joins = about_account and (case.key, ref_core(case.req.reference)) in questions
    if waiting >= MAX_WAITING:
        return "all", (
            f"{waiting} payments of this task are already waiting for a person (the limit is "
            f"{MAX_WAITING}). Until some of them are decided, nothing more is paid or queued "
            "in this task."
        ), ""
    if accounts >= MAX_PENDING_HOLDS and not joins:
        what = ("This payment's account is in question too, so it is refused." if about_account
                else "Until some of them are decided, nothing is paid without a person.")
        return "account", (
            f"Payments for {accounts} invoices of this task are already waiting for a person "
            f"because of their account (the limit is {MAX_PENDING_HOLDS}). {what}"
        ), ("The queue is full for payments about an account. This account is vouched for, "
            "so the payment may only wait for a person, not go through.")
    if ctx.quarantined:
        what = ("This payment's account is in question, so it is refused." if about_account
                else "This payment would have needed no person, so it is refused, not paid.")
        return "account", (
            "This task is quarantined: the queue of payments waiting for a person overflowed "
            "earlier in it, so nothing more is paid without a person until a new task starts. "
            f"{what}"
        ), ("This task is quarantined (the queue overflowed earlier). This account is vouched "
            "for, so the payment may only wait for a person, not go through.")
    ladder.ok("H1", f"Payments for {accounts} of at most {MAX_PENDING_HOLDS} invoices wait for a "
                    f"person because of their account, and {waiting} of at most {MAX_WAITING} "
                    "payments wait in all."
                    + (" This payment's invoice is one of them, so it waits with them."
                       if joins and accounts >= MAX_PENDING_HOLDS else ""))
    return None


def authorise(req: PaymentRequest, trusted: Context) -> Decision | None:
    """Decide from trusted state alone.

    Returns ALLOW, a BLOCK, a HOLD that needs no document to explain it, or
    None when trusted state does not vouch for the destination. It takes no
    provenance tracker on purpose: nothing the agent read can reach it.
    """
    case = _Case(req, trusted)
    decision = _mandate_rules(case)
    if decision is not None:
        return decision
    req, ctx, ladder, payee = case.req, case.ctx, case.ladder, case.payee

    if ctx.mode == "rules":
        refused = _sentence_caps(case)
        if refused is not None:
            return refused
        return _allow(case, "The payee is in the mandate and the amount is inside its limits.")
    if ctx.mode == "strict":
        if req.account not in case.on_file:
            if case.on_file:
                return case.block("B1", f"Account {mask(req.account)} is not on file for {payee}.")
            return case.block("B1", f"{payee} has no account on file.")
        ladder.ok("B1", f"This is the account on file for {payee}.")
        refused = _sentence_caps(case)
        if refused is not None:
            return refused
        return _allow(
            case,
            "The payee is in the mandate, the account is on file and the amount is inside "
            "the limits.",
        )
    if ctx.mode != "countersign":
        raise ValueError(f"unknown guard mode {ctx.mode!r}")

    if case.vouched:
        source = _vouched_source(case)
        held = _held(case, None, "")
        if held is not None:
            return held
        return _allow(case, f"Within the mandate and going to {source}.")

    if case.dictated:
        return _held(case, _dictated(case), "")
    return None


def _vouched_source(case: _Case) -> str:
    """Whose account trusted state says this is, for the ladder and the reason."""
    if case.on_file:
        source = f"the account on file for {case.payee}"
    else:
        source = f"the account you gave for {case.payee}"
    case.ladder.ok("O1", f"This is {source}.")
    return source


def _dictated(case: _Case) -> tuple[str, str, str]:
    """P1 or P2 for an account the user gave that trusted state does not vouch
    for: (rule, short detail, sentence for the person)."""
    req, payee = case.req, case.payee
    case.ladder.ok("O1", f"You gave this account for {payee}.")
    if case.on_file:
        # The user gave this account, but the vendor file has another one.
        return (
            "P1",
            f"You gave this account, but the vendor file has a different one for {payee}.",
            f"Not the account on file. You gave this account for {payee}, but the vendor "
            f"file has a different one: {_accounts(case.on_file)}. This payment would go to "
            f"{fmt_iban(req.account)}. Check with the vendor on a number you already have.",
        )
    # The user gave this account, but the vendor file has it for somebody else.
    return (
        "P2",
        f"You gave this account for {payee}, but it is on file for {case.owner}.",
        f"Account on file for a different vendor. You gave this account for {payee}, "
        f"but the vendor file has it for {case.owner}, and {payee} has no account on "
        f"file. This payment would go to {fmt_iban(req.account)}. Check which of the "
        "two it belongs to before paying.",
    )


# --- what the documents add: T1, D4 ---------------------------------------------------


def _where(labels: Sequence[str]) -> str:
    """"1 document (...): X" or "3 documents (...): X, Y and 1 more". The names
    are the senders' choice, so this goes at the very end of a reason."""
    names = list(dict.fromkeys(labels))
    listed = ", ".join(names[:2])
    if len(names) > 2:
        listed += f" and {len(names) - 2} more"
    return f"{len(names)} document{_s(len(names))} (the sender chose its name): {listed}"


def _hidden_figure(case: _Case, provenance: ProvenanceTracker, ladder: _Ladder
                   ) -> tuple[str, ...] | None:
    """T1: this payment's amount or invoice number is written in text a reader
    does not see (`ProvenanceTracker.hidden_texts`: white or tiny text, text
    styled not to show, comments, alt and title attributes).

    A genuine invoice shows its amount. A figure written where a person
    reading the document cannot see it is written for the agent. Any
    document counts, so more documents can only add this hold."""
    req = case.req
    hidden = provenance.hidden_texts()
    if provenance.unread:
        return (
            "T1",
            "A document of this task was too large to read, so hidden figures cannot be ruled "
            "out.",
            "Hidden figure possible. The agent read a document too large for the guard to keep, "
            "so it cannot tell whether this payment's amount or invoice number is hidden in it. "
            "Check the amount against the invoice as it shows on screen.",
        )
    if not hidden:
        ladder.na("T1", "No document the agent read has text a reader does not see.")
        return None
    amount = [label for label, text in hidden if req.amount in figures_in(text)]
    invoice = [label for label, text in hidden if names_invoice(text, req.reference)]
    if not amount and not invoice:
        ladder.ok("T1", "Neither the amount nor the invoice number is in text a reader does "
                        "not see.")
        return None
    if amount and invoice:
        what = (f"Its amount ({money(req.amount)}) and its invoice number "
                f"({clean_label(req.reference)}) are")
        short = "The amount and the invoice number are"
    elif amount:
        what = f"Its amount ({money(req.amount)}) is"
        short = "The amount is"
    else:
        what = f"Its invoice number ({clean_label(req.reference)}) is"
        short = "The invoice number is"
    return (
        "T1",
        f"{short} written in text a reader does not see.",
        f"Hidden figure. {what} written in a document in text a reader does not see (text "
        "styled not to show, white or tiny text, a comment or an image description). A "
        "genuine invoice shows its figures; hidden ones are written for the agent. Check the "
        "amount against the invoice as it shows on screen.",
        f"The hidden figure was read in {_where(amount + invoice)}.",
    )


# A full reference ending in a number, as invoices print it: capital letters,
# then the number, joined directly or by - / _ ("KL-0952", "DB952").
_FULL_REF = re.compile(r"(?<![A-Za-z0-9])([A-Z]{1,6})[-/_]?([0-9]+)(?![0-9])")
_LABELS = frozenset({"INV", "BILL", "NO", "NR", "NUM", "REF"})
MAX_CLAIMS_SHOWN = 3


def _two_invoices(case: _Case, provenance: ProvenanceTracker, ladder: _Ladder
                  ) -> tuple[str, str, str] | None:
    """D4: you named a bare number ("invoice 952"), this payment's reference
    puts letters you did not type before it ("DB-952"), and a document or an
    earlier request of this task shows that number with other letters
    ("KL-0952"). Two invoices claim the number you named, and S3 lets either
    through, so a person says which one you meant. More documents and more
    requests can only find more claims."""
    req, ctx, payee = case.req, case.ctx, case.payee
    bare = {invoice_core(name) for name in ctx.mandate.ask_for(payee).invoices}
    bare = {core for core in bare if core.isdigit()}
    letters, _, number = invoice_core(req.reference).partition("-")
    if not bare or not (letters.isalpha() and number in bare):
        ladder.na("D4", "You did not name a bare invoice number that this reference adds "
                        "letters to.")
        return None
    claims: dict[str, str] = {}  # other letters -> where they were seen
    for key, other in sorted(ctx.requested):
        mine, _, digits = invoice_core(other).partition("-")
        if key == case.key and digits == number and mine.isalpha() and mine != letters:
            claims.setdefault(f"{mine}-{number}", "an earlier request of this task")
    for label, text in provenance.texts():
        for match in _FULL_REF.finditer(fold_lookalikes(text)):
            mine, digits = match.group(1), match.group(2).lstrip("0") or "0"
            if digits == number and mine not in _LABELS and mine != letters:
                claims.setdefault(f"{mine}-{number}", "a document")
    if ctx.requested_all:
        claims.setdefault("another reference", "the requests of this task (too many to keep)")
    if provenance.unread:
        claims.setdefault("another reference", "a document too large to read")
    if not claims:
        ladder.ok("D4", f"No document or earlier request shows another invoice with the number "
                        f"{number}.")
        return None
    seen = [f"{ref} (in {where})" for ref, where in sorted(claims.items())][:MAX_CLAIMS_SHOWN]
    return (
        "D4",
        f"You named invoice {number}; this reference adds the letters {letters}, and "
        f"{_listed(seen)} also has that number.",
        f"Two invoices have the number you named. You named invoice {number} for {payee}, "
        f"and this payment's reference, {clean_label(req.reference)}, adds letters you did not "
        f"type. {_listed(seen)} also has the number {number}. Check which invoice you meant "
        "before paying.",
    )


def _document_findings(case: _Case, provenance: ProvenanceTracker) -> None:
    """The holds the documents add (D4, T1), into `case.documents`, and the
    ladder lines of the ones that do not apply, into `case.document_lines`.
    Each can only hold a payment: none of them is a reason to pay."""
    notes = _Ladder(case.ctx.mode)
    found = []
    for check in (_two_invoices, _hidden_figure):
        finding = check(case, provenance, notes)
        if finding is not None:
            found.append(finding[:3])
            if len(finding) > 3:
                case.document_tail = finding[3]
    case.documents = found
    case.document_lines = tuple(check for check in notes.checks()
                                if check.rule in DOCUMENT_RULES and check.status in ("na", "pass"))


def _with_documents(
    req: PaymentRequest, trusted: Context, provenance: ProvenanceTracker
) -> tuple[Decision | None, tuple[Check, ...]]:
    """After `authorise` has allowed or held a payment: does a document add a
    hold (T1, D4)? Returns the HOLD with every rule that applies, or None
    when no document adds anything, and the ladder lines of the document
    rules. It cannot return an ALLOW: it only ever adds rules to `_held`."""
    case = _Case(req, trusted)
    if _mandate_rules(case) is not None:  # authorise passed these; cannot happen
        return None, ()
    _document_findings(case, provenance)
    if not case.documents:
        return None, case.document_lines
    if case.vouched:
        first = None
        _vouched_source(case)
    else:
        first = _dictated(case)
    return _held(case, first, ""), ()


def _sources(sightings: tuple[SightingRef, ...]) -> str:
    """Where the account was written. Document names go last, cleaned and labelled."""
    parts = []
    if any(s.origin == "user" for s in sightings):
        parts.append(
            "You typed this account in your instruction, but it was not assigned to this payee."
        )
    untrusted = [s for s in sightings if s.origin != "user"]
    names = list(dict.fromkeys(s.source for s in untrusted))
    if names:
        listed = ", ".join(names[:3])
        if len(names) > 3:
            listed += f" and {len(names) - 3} more"
        if len(names) == 1:
            lead = "The account was read in 1 untrusted document (the sender chose its name)"
        else:
            lead = (
                f"The account was read in {len(names)} untrusted documents "
                "(the senders chose their names)"
            )
        parts.append(f"{lead}: {listed}.")
        if untrusted and all(s.rendered for s in untrusted):
            parts.append(
                "It is not written there as one piece: it was read through HTML tags or "
                "character codes, so it may look different in the source than on screen."
            )
    return " ".join(parts)


def classify(req: PaymentRequest, trusted: Context, provenance: ProvenanceTracker) -> Decision:
    """Decide a request that `authorise` left open, using what the agent read.

    The account is not vouched for by trusted state. If it was written nowhere
    it is refused (O1). If it was written somewhere, a person decides (P1 or
    P2, plus any other HOLD rule). There is no path from here to an ALLOW.
    """
    case = _Case(req, trusted)
    refused = _mandate_rules(case)
    if refused is not None:
        return refused
    if trusted.mode != "countersign" or case.vouched or case.dictated:
        raise ValueError("classify is only for requests that authorise left undecided")
    payee, account = case.payee, req.account
    case.sightings = tuple(provenance.sightings(account))

    if not case.sightings:
        if case.owner is not None:
            reason = (
                f"Account {mask(account)} is on file for {case.owner}, not for {payee}. "
                "It appears in nothing you typed and nothing the agent read in this task."
            )
        else:
            reason = (
                f"Account {mask(account)} is not on file for {payee}, was not given by you for "
                f"{payee}, and appears in nothing you typed and nothing the agent read. "
                "Its origin is unknown."
            )
        return case.block("O1", reason)
    count = len(case.sightings)
    case.ladder.ok("O1", f"The account was written in {count} text{_s(count)} of this task.")
    _document_findings(case, provenance)

    other = f" This account is on file for a different vendor, {case.owner}." if case.owner else ""
    if case.on_file:
        finding = (
            "P1",
            f"The vendor file has a different account for {payee}.",
            f"Not the account on file. The vendor file has {_accounts(case.on_file)} for "
            f"{payee}; this payment would go to {fmt_iban(account)}.{other} "
            "Check with the vendor on a number you already have.",
        )
    else:
        finding = (
            "P2",
            f"{payee} has no account on file and you did not give this one for {payee}.",
            f"First payment to an account that is not on file. {payee} has no account in the "
            f"vendor file and you did not give this one for {payee}. This payment would go to "
            f"{fmt_iban(account)}.{other} "
            "Check it with the supplier using contact details you already have.",
        )
    decision = _held(case, finding, _sources(case.sightings))
    if decision is None:  # cannot happen: a finding always holds or blocks
        raise ValueError("an unvouched destination must be held or refused")
    return decision


def _with_sightings(
    decision: Decision, req: PaymentRequest, provenance: ProvenanceTracker,
    lines: tuple[Check, ...] = (),
) -> Decision:
    """Add where the account was read to the evidence, and the ladder lines of
    the document rules (`lines`, from `_with_documents`). Display only: the
    outcome, the rules and the reason are left exactly as they were decided."""
    checks = decision.checks
    if lines:
        found = {check.rule: check for check in lines}
        checks = tuple(found.get(check.rule, check) for check in checks)
    evidence = decision.evidence
    if evidence is not None and evidence.valid_iban and not evidence.sightings:
        sightings = tuple(provenance.sightings(req.account))
        if sightings:
            typed = any(s.origin == "user" for s in sightings)
            evidence = replace(evidence, sightings=sightings, typed_by_user=typed)
    if checks == decision.checks and evidence is decision.evidence:
        return decision
    return replace(decision, checks=checks, evidence=evidence)


def evaluate(req: PaymentRequest, trusted: Context, provenance: ProvenanceTracker) -> Decision:
    """Decide one payment: trusted state first, then the documents.

    When trusted state leaves the destination open, `classify` decides with
    what the agent read. When it allowed or held the payment, the documents
    may still add a hold (T1, D4) through `_with_documents`; they never turn
    a hold or a refusal into anything else."""
    decision = authorise(req, trusted)
    if decision is None:
        return classify(req, trusted, provenance)
    lines: tuple[Check, ...] = ()
    if trusted.mode == "countersign" and decision.outcome is not Outcome.BLOCK:
        held, lines = _with_documents(req, trusted, provenance)
        if held is not None:
            decision = held
    return _with_sightings(decision, req, provenance, lines)
