"""The decision engine. Plain code, no model: the same request and the same
state always get the same answer, and nothing an attacker writes in a document
can argue with it.

One table of rules, checked in the order of `RULE_ORDER`. A BLOCK rule ends
the check. The HOLD rules are all checked, and a held payment carries every
one that applies.

The central property is that untrusted text can never produce an ALLOW. It is
true by construction:

* `authorise(req, trusted)` sees only trusted state: the mandate, the vendor
  file, what the task has paid, the record of paid invoices, rejections and
  the clock. It answers ALLOW, BLOCK, a HOLD that follows from trusted state
  alone, or None, which means "trusted state does not vouch for this
  destination".
* Only then does `classify(req, trusted, provenance)` look at what the agent
  read. It can only refuse (the account was seen nowhere, or too many
  payments are waiting) or ask a person (the account was seen somewhere).
  The only function that builds an ALLOW is `_allow`, only `authorise` calls
  it, and nothing `classify` calls can reach it (a test walks the code to
  check this).

Three guards share the table. "rules" (name allowlist plus caps) and "strict"
(account allowlist plus caps) are our own baselines, there to show what those
designs miss. "countersign" is the product.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Mapping

from .iban import fmt_iban, is_canonical_iban
from .models import (
    Check,
    Decision,
    Evidence,
    Mandate,
    Outcome,
    PaymentRequest,
    SightingRef,
    clean_label,
    is_plain_text,
    mask,
    money,
    name_key,
    plain,
    ref_key,
)
from .provenance import ProvenanceTracker
from .vendors import VendorFile

GUARD_MODES = ("rules", "strict", "countersign")
MAX_PENDING_HOLDS = 5
UNUSUAL_AMOUNT_FACTOR = Decimal("1.5")
HISTORY_SHOWN = 10  # earlier payments listed in evidence (the baseline uses all of them)

_ALL = GUARD_MODES
_STRICT = ("strict",)
_OURS = ("countersign",)

# id, title, outcome, guards that run it. The order is the order of evaluation.
_TABLE = (
    ("M0", "No active task", "BLOCK", _ALL),
    ("M1", "Mandate expired", "BLOCK", _ALL),
    ("F1", "Malformed request", "BLOCK", _ALL),
    ("M2", "Payee not in the mandate", "BLOCK", _ALL),
    ("M3", "Amount invalid or over the per-payment limit", "BLOCK", _ALL),
    ("M4", "Over the task budget", "BLOCK", _ALL),
    ("M5", "Payment count used up", "BLOCK", _ALL),
    ("M6", "Invoice not named by the user", "BLOCK", _ALL),
    ("B1", "Not the account on file", "BLOCK", _STRICT),
    ("O1", "Account seen nowhere", "BLOCK", _OURS),
    ("R1", "Already rejected by a person", "BLOCK", _OURS),
    ("H1", "Too many payments waiting", "BLOCK", _OURS),
    ("P1", "Not the account on file", "HOLD", _OURS),
    ("P2", "First payment to an unverified account", "HOLD", _OURS),
    ("D1", "Possible duplicate invoice", "HOLD", _OURS),
    ("A1", "Unusual amount for this payee", "HOLD", _OURS),
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


@dataclass(frozen=True)
class Context:
    """Trusted state: everything `authorise` may look at.

    None of it can be written by the agent or by a document. `baseline` and
    `history` are the vendor file's payment history as it was when the task
    started, so payments made during the task do not move them.
    """

    mode: str
    mandate: Mandate | None
    vendors: VendorFile
    now: datetime
    spent: Decimal = Decimal("0.00")  # executed payments of this task
    payments: int = 0  # how many
    paid_to: Mapping[str, Decimal] = field(default_factory=dict)  # per payee key, this task
    baseline: Mapping[str, Decimal] = field(default_factory=dict)  # payee key -> largest on file
    history: Mapping[str, tuple[Decimal, ...]] = field(default_factory=dict)
    # (payee key, reference key) -> record of the payment already made for it
    ledger: Mapping[tuple[str, str], Mapping[str, Any]] = field(default_factory=dict)
    rejected: frozenset[tuple[str, str]] = frozenset()  # (payee key, account), this task
    pending: int = 0  # payments of this task waiting for a person


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
        self.sightings: tuple[SightingRef, ...] = ()
        if self.payee is not None:
            self.on_file = tuple(sorted(ctx.vendors.accounts_for(self.payee)))
            self.dictated = self.valid_iban and req.account in mandate.accounts_for(self.payee)
            if is_plain_text(req.reference):
                self.previous = ctx.ledger.get((self.key, ref_key(req.reference)))
        if self.valid_iban:
            other = ctx.vendors.owner_of(req.account, other_than=self.payee)
            self.owner = other.name if other is not None else None

    @property
    def vouched(self) -> bool:
        """Trusted state says this account belongs to this payee.

        The vendor file outranks the chat: an account the user dictated only
        counts when the payee has no account on file.
        """
        if self.on_file:
            return self.req.account in self.on_file
        return self.dictated

    def evidence(self) -> Evidence:
        req, ctx = self.req, self.ctx
        baseline = ctx.baseline.get(self.key) if self.key else None
        shown = self.payee
        if shown is None:
            shown = clean_label(req.payee, 60) if isinstance(req.payee, str) else ""
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


def _mandate_rules(case: _Case) -> Decision | None:
    """M0 to M6: is the request inside what the user authorised?"""
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
        ladder.na("M5", "The mandate does not limit the number of payments.")
    elif ctx.payments >= limit:
        return case.block(
            "M5",
            f"The mandate allows {limit} payment{_s(limit)} and "
            f"{ctx.payments} {'has' if ctx.payments == 1 else 'have'} already been made "
            "in this task.",
        )
    else:
        ladder.ok("M5", f"This would be payment {ctx.payments + 1} of {limit} allowed.")

    if not mandate.references:
        ladder.na("M6", "The mandate does not name specific invoices.")
    elif ref_key(req.reference) not in {ref_key(r) for r in mandate.references}:
        return case.block(
            "M6", "The mandate names the invoices to pay, and this reference is not one of them."
        )
    else:
        ladder.ok("M6", "The mandate names this invoice.")
    return None


def _s(count: int) -> str:
    return "" if count == 1 else "s"


def _held(case: _Case, first: tuple[str, str, str] | None, tail: str) -> Decision | None:
    """R1, H1 and the HOLD rules, once the destination question is settled.

    `first` is the P1 or P2 finding (rule, short detail, sentences for the
    person) or None when trusted state vouches for the account. `tail` is the
    sentence that names where the account was read; it goes last because it
    carries names an attacker chose. Returns None when nothing applies. This
    function cannot return an ALLOW.
    """
    req, ctx, ladder, payee = case.req, case.ctx, case.ladder, case.payee

    if (case.key, req.account) in ctx.rejected:
        return case.block(
            "R1", "A person already rejected a payment to this payee and account in this task."
        )
    ladder.ok("R1", "No payment to this payee and account was rejected in this task.")

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

    record = case.previous
    if record is not None:
        rules.append("D1")
        ladder.set("D1", "hold", f"An invoice with this reference was already paid to {payee}.")
        paid = money(Decimal(record["amount"]))
        when = str(record.get("time", ""))[:10]
        transfer = record.get("transfer")
        proof = f"transfer {transfer}" if transfer else "not confirmed by the bank"
        sentences.append(
            f"Possible duplicate. An invoice with this reference was already paid to {payee}: "
            f"{paid} on {when} ({proof})."
        )
    else:
        ladder.ok("D1", f"No earlier payment to {payee} has this reference.")

    baseline = ctx.baseline.get(case.key)
    if baseline is None:
        ladder.na("A1", f"{payee} has no payment history, so there is no usual amount.")
    else:
        total = ctx.paid_to.get(case.key, Decimal(0)) + req.amount
        ceiling = baseline * UNUSUAL_AMOUNT_FACTOR
        if total > ceiling:
            rules.append("A1")
            ladder.set(
                "A1", "hold",
                f"{money(total)} to {payee} in this task is more than 1.5 times "
                f"the largest payment on file ({money(baseline)}).",
            )
            sentences.append(
                f"Unusual amount. This payment would bring what this task pays {payee} to "
                f"{money(total)}; the largest payment to them on file is {money(baseline)}."
            )
        else:
            ladder.ok(
                "A1",
                f"{money(total)} to {payee} in this task is within 1.5 times "
                f"the largest payment on file ({money(baseline)}).",
            )

    if not rules:
        ladder.na("H1", "This payment does not need a countersignature.")
        return None
    if ctx.pending >= MAX_PENDING_HOLDS:
        return case.block(
            "H1",
            f"{ctx.pending} payments are already waiting for a person in this task "
            f"(the limit is {MAX_PENDING_HOLDS}). They have to be decided first.",
        )
    ladder.ok(
        "H1", f"{ctx.pending} of at most {MAX_PENDING_HOLDS} payments are waiting for a person."
    )
    if tail:
        sentences.append(tail)
    return case.hold(rules, " ".join(sentences))


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
        return _allow(case, "The payee is in the mandate and the amount is inside its limits.")
    if ctx.mode == "strict":
        if req.account not in case.on_file:
            if case.on_file:
                return case.block("B1", f"Account {mask(req.account)} is not on file for {payee}.")
            return case.block("B1", f"{payee} has no account on file.")
        ladder.ok("B1", f"This is the account on file for {payee}.")
        return _allow(
            case,
            "The payee is in the mandate, the account is on file and the amount is inside "
            "the limits.",
        )
    if ctx.mode != "countersign":
        raise ValueError(f"unknown guard mode {ctx.mode!r}")

    if case.vouched:
        if case.on_file:
            source = f"the account on file for {payee}"
        else:
            source = f"the account you gave for {payee}"
        ladder.ok("O1", f"This is {source}.")
        held = _held(case, None, "")
        if held is not None:
            return held
        return _allow(case, f"Within the mandate and going to {source}.")

    if case.dictated:
        # The user gave this account, but the vendor file has another one.
        ladder.ok("O1", f"You gave this account for {payee}.")
        finding = (
            "P1",
            f"You gave this account, but the vendor file has a different one for {payee}.",
            f"Not the account on file. You gave this account for {payee}, but the vendor file "
            f"has a different one: {_accounts(case.on_file)}. This payment would go to "
            f"{fmt_iban(req.account)}. Check with the vendor on a number you already have.",
        )
        return _held(case, finding, "")
    return None


def _sources(sightings: tuple[SightingRef, ...]) -> str:
    """Where the account was written. Document names go last, cleaned and labelled."""
    parts = []
    if any(s.origin == "user" for s in sightings):
        parts.append(
            "You typed this account in your instruction, but it was not assigned to this payee."
        )
    names = list(dict.fromkeys(s.source for s in sightings if s.origin != "user"))
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
    decision: Decision, req: PaymentRequest, provenance: ProvenanceTracker
) -> Decision:
    """Add where the account was read to the evidence. Display only: the
    outcome, the rules and the reason are left exactly as they were decided."""
    evidence = decision.evidence
    if evidence is None or not evidence.valid_iban or evidence.sightings:
        return decision
    sightings = tuple(provenance.sightings(req.account))
    if not sightings:
        return decision
    typed = any(s.origin == "user" for s in sightings)
    return replace(
        decision, evidence=replace(evidence, sightings=sightings, typed_by_user=typed)
    )


def evaluate(req: PaymentRequest, trusted: Context, provenance: ProvenanceTracker) -> Decision:
    """Decide one payment: trusted state first, documents only if it left the
    destination open."""
    decision = authorise(req, trusted)
    if decision is None:
        return classify(req, trusted, provenance)
    return _with_sightings(decision, req, provenance)
