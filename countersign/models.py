"""Core data types and the text rules shared by every module.

The small functions at the top are the only definitions of "the same payee",
"a readable amount", "the same invoice" and "safe to show a person". Every
module uses them, so the guard, the log and the screens never disagree.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal, InvalidOperation
from enum import Enum
from typing import Any, Iterable

from .iban import canonical_iban, find_ibans

CENT = Decimal("0.01")
MAX_TEXT = 140  # longest payee name or payment reference
_AMOUNT = re.compile(r"[0-9]{1,12}(\.[0-9]{1,2})?")
_NOT_REF = re.compile(r"[^A-Za-z0-9]+")
_LABEL_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 ._-@"
)


def name_key(name: str) -> str:
    """The form in which payee names are compared.

    Case is folded, every character that is not a letter or digit becomes a
    space, and spaces are collapsed. Nothing else: no fuzzy matching and no
    dropping of "Ltd", so a look-alike name is a different name.
    """
    folded = "".join(ch if ch.isalnum() else " " for ch in name.casefold())
    return " ".join(folded.split())


def parse_amount(value: object) -> Decimal | None:
    """A plain decimal such as 480 or 480.00, as a Decimal with two places.

    Anything else is refused: signs, exponents, separators, more than two
    decimals, non-ASCII digits, booleans. Zero parses; the rules refuse it.
    """
    if isinstance(value, bool) or not isinstance(value, (str, int, float, Decimal)):
        return None
    try:
        text = str(value).strip()
        if not _AMOUNT.fullmatch(text):
            return None
        return Decimal(text).quantize(CENT)
    except (ValueError, ArithmeticError):
        return None


def plain(amount: Decimal) -> str:
    """Money as stored and exchanged: 1480.00."""
    return f"{amount:.2f}"


def money(amount: Decimal) -> str:
    """Money as shown to a person: 1,480.00."""
    return f"{amount:,.2f}"


def ref_key(reference: str) -> str:
    """The form in which payment references are compared.

    Upper case, with every run of other characters folded to one hyphen, so
    "INV 2041", "inv-2041." and "INV-2041" are one invoice while "INV-1-12"
    and "INV-11-2" stay two.
    """
    return _NOT_REF.sub("-", reference.upper()).strip("-")


def clean_label(text: str, limit: int = 40) -> str:
    """Text an attacker chose (a document name), made safe to show a person.

    Keeps ASCII letters, digits, spaces and . _ - @, collapses spaces and cuts
    long names short. May return an empty string.
    """
    kept = " ".join("".join(ch for ch in text if ch in _LABEL_CHARS).split())
    return kept if len(kept) <= limit else kept[: max(limit - 3, 0)] + "..."


def _is_control(ch: str) -> bool:
    category = unicodedata.category(ch)
    return category[0] == "C" or category in ("Zl", "Zp")


def is_plain_text(text: object, limit: int = MAX_TEXT) -> bool:
    """True for non-blank text of at most `limit` characters with no control,
    format or line-separator characters in it."""
    return (
        isinstance(text, str)
        and 0 < len(text) <= limit
        and bool(text.strip())
        and not any(_is_control(ch) for ch in text)
    )


def mask(account: str) -> str:
    """Short form of an account for refusals and log lines, e.g. DE89…3000."""
    return account if len(account) <= 8 else f"{account[:4]}…{account[-4:]}"


class Outcome(str, Enum):
    ALLOW = "ALLOW"  # the payment is sent
    HOLD = "HOLD"  # the payment waits for a person to countersign
    BLOCK = "BLOCK"  # the payment is refused


def typed_accounts(instruction: str, payees: Iterable[str]) -> dict[str, tuple[str, ...]]:
    """Accounts to bind to payees when a mandate is drafted from a sentence.

    With exactly one payee, every IBAN written in the instruction is bound to
    that payee. With several payees nothing is bound: free text cannot say
    which payee an account belongs to, so a person has to assign it.
    """
    names = list(payees)
    if len(names) != 1:
        return {}
    found = tuple(dict.fromkeys(match.account for match in find_ibans(instruction)))
    return {names[0]: found} if found else {}


def _limit(value: object, label: str) -> Decimal:
    if not isinstance(value, Decimal):
        raise ValueError(f"{label} must be a Decimal")
    try:
        ok = value.is_finite() and value > 0 and value == value.quantize(CENT)
    except InvalidOperation:
        ok = False
    if not ok:
        raise ValueError(f"{label} must be a positive amount with at most two decimals")
    return value.quantize(CENT)


def _names(value: object, label: str) -> list[str]:
    if isinstance(value, str) or not isinstance(value, (list, tuple)):
        raise ValueError(f"{label} must be a list of names, not {type(value).__name__}")
    for item in value:
        if not is_plain_text(item):
            raise ValueError(f"{label} must be non-blank text of at most {MAX_TEXT} characters")
    return [item.strip() for item in value]


@dataclass(frozen=True)
class Mandate:
    """What the user authorised for one task: their words plus hard limits."""

    id: str
    instruction: str
    payees: tuple[str, ...]
    max_per_payment: Decimal
    max_total: Decimal
    expires_at: datetime  # timezone-aware
    currency: str = "EUR"
    max_payments: int | None = None  # how many payments the task may make; None = no limit
    references: tuple[str, ...] = ()  # invoices the user named; empty = any reference
    # Accounts the user dictated, per payee (canonical IBANs).
    accounts: dict[str, tuple[str, ...]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Check every field and store the normalised form. Raises ValueError."""
        if not isinstance(self.id, str) or not self.id.strip():
            raise ValueError("the mandate needs an id")
        if not isinstance(self.instruction, str):
            raise ValueError("the instruction must be text")

        payees = _names(self.payees, "payees")
        if not payees:
            raise ValueError("the mandate must name at least one payee")
        keys = [name_key(p) for p in payees]
        if not all(keys):
            raise ValueError("a payee name needs at least one letter or digit")
        if len(set(keys)) != len(keys):
            raise ValueError("the mandate names the same payee twice")

        per_payment = _limit(self.max_per_payment, "max_per_payment")
        total = _limit(self.max_total, "max_total")
        if per_payment > total:
            raise ValueError("max_per_payment must not be larger than max_total")

        expires = self.expires_at
        if not isinstance(expires, datetime) or expires.utcoffset() is None:
            raise ValueError("expires_at must be a timezone-aware datetime")

        currency = self.currency
        if not (isinstance(currency, str) and len(currency) == 3 and currency.isascii()
                and currency.isalpha()):
            raise ValueError("currency must be a three-letter code")

        count = self.max_payments
        if count is not None and (type(count) is not int or count < 1):
            raise ValueError("max_payments must be None or a whole number of at least 1")

        references = _names(self.references, "references")
        if not all(ref_key(r) for r in references):
            raise ValueError("a reference needs at least one letter or digit")

        if not isinstance(self.accounts, dict):
            raise ValueError("accounts must map each payee to its accounts")
        by_key = dict(zip(keys, payees))
        accounts: dict[str, tuple[str, ...]] = {}
        for name, values in self.accounts.items():
            payee = by_key.get(name_key(name)) if isinstance(name, str) else None
            if payee is None:
                raise ValueError(f"accounts names {name!r}, which is not a payee of the mandate")
            if isinstance(values, str) or not isinstance(values, (list, tuple, set, frozenset)):
                raise ValueError("the accounts of a payee must be a list")
            canonical = []
            for value in values:
                account = canonical_iban(value)
                if account is None:
                    raise ValueError(f"{value!r} is not a valid IBAN")
                canonical.append(account)
            merged = set(accounts.get(payee, ())) | set(canonical)
            if merged:
                accounts[payee] = tuple(sorted(merged))

        store = object.__setattr__  # the dataclass is frozen
        store(self, "payees", tuple(payees))
        store(self, "max_per_payment", per_payment)
        store(self, "max_total", total)
        store(self, "currency", currency.upper())
        store(self, "references", tuple(references))
        store(self, "accounts", accounts)

    def canonical_payee(self, payee: str) -> str | None:
        """The mandate's own spelling of this payee, or None if it is not covered."""
        if not isinstance(payee, str):
            return None
        key = name_key(payee)
        for name in self.payees:
            if name_key(name) == key:
                return name
        return None

    def covers(self, payee: str) -> bool:
        return self.canonical_payee(payee) is not None

    def accounts_for(self, payee: str) -> frozenset[str]:
        """Accounts the user dictated for this payee."""
        name = self.canonical_payee(payee)
        return frozenset(self.accounts.get(name, ())) if name is not None else frozenset()

    def to_dict(self) -> dict[str, Any]:
        """A JSON-safe copy. `Mandate.from_dict` reads it back."""
        return {
            "id": self.id,
            "instruction": self.instruction,
            "payees": list(self.payees),
            "max_per_payment": plain(self.max_per_payment),
            "max_total": plain(self.max_total),
            "currency": self.currency,
            "expires_at": self.expires_at.isoformat(),
            "max_payments": self.max_payments,
            "references": list(self.references),
            "accounts": {payee: list(values) for payee, values in self.accounts.items()},
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Mandate:
        try:
            return cls(
                id=data["id"],
                instruction=data["instruction"],
                payees=data["payees"],
                max_per_payment=Decimal(str(data["max_per_payment"])),
                max_total=Decimal(str(data["max_total"])),
                expires_at=datetime.fromisoformat(data["expires_at"]),
                currency=data.get("currency", "EUR"),
                max_payments=data.get("max_payments"),
                references=data.get("references") or (),
                accounts={k: tuple(v) for k, v in (data.get("accounts") or {}).items()},
            )
        except (KeyError, TypeError, AttributeError, InvalidOperation) as exc:
            raise ValueError(f"not a mandate: {exc!r}") from None


@dataclass(frozen=True)
class PaymentRequest:
    """A payment the agent is asking for, after the guard has read it.

    `account` is the canonical IBAN when the agent gave a valid one, otherwise
    the text as given. `amount` is None when it could not be read. `currency`
    is None when the agent did not name one.
    """

    payee: str
    account: str
    amount: Decimal | None
    reference: str = ""
    currency: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "payee": self.payee,
            "account": self.account,
            "amount": None if self.amount is None else plain(self.amount),
            "reference": self.reference,
            "currency": self.currency,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PaymentRequest:
        amount = data.get("amount")
        return cls(
            payee=data["payee"],
            account=data["account"],
            amount=None if amount is None else Decimal(amount),
            reference=data.get("reference", ""),
            currency=data.get("currency"),
        )


@dataclass(frozen=True)
class Check:
    """One rung of the rule ladder: what one rule said about one request."""

    rule: str  # "M2"
    # pass | block | hold | na (does not apply here) | off (not part of this
    # guard) | skipped (not reached)
    status: str
    detail: str  # one plain sentence


@dataclass(frozen=True)
class SightingRef:
    """One text in which an account was written, and where in it."""

    origin: str  # "user" | "untrusted"
    source: str  # "your instruction", or the cleaned name of a document
    spans: tuple[tuple[int, int], ...]  # character offsets in that text
    line: int  # 1-based line of the first span


@dataclass(frozen=True)
class Evidence:
    """The facts a decision was made from, for the person who reads it."""

    payee: str
    account: str  # canonical, or the text as given if it is not a valid IBAN
    valid_iban: bool
    on_file: tuple[str, ...]  # accounts on file for this payee
    on_file_for: str | None  # another vendor that has this account on file
    dictated: bool  # the user gave this account for this payee
    typed_by_user: bool  # the account appears in the instruction text
    sightings: tuple[SightingRef, ...]
    history: tuple[str, ...]  # the payee's payment history when the task started
    baseline: str | None  # the largest of those
    previous_payment: dict[str, Any] | None  # an earlier payment of the same invoice
    spent: str  # this task, at decision time
    budget: str
    paid_to_payee: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "payee": self.payee,
            "account": self.account,
            "valid_iban": self.valid_iban,
            "on_file": list(self.on_file),
            "on_file_for": self.on_file_for,
            "dictated": self.dictated,
            "typed_by_user": self.typed_by_user,
            "sightings": [
                {
                    "origin": s.origin,
                    "source": s.source,
                    "spans": [list(span) for span in s.spans],
                    "line": s.line,
                }
                for s in self.sightings
            ],
            "history": list(self.history),
            "baseline": self.baseline,
            "previous_payment": None if self.previous_payment is None
            else dict(self.previous_payment),
            "spent": self.spent,
            "budget": self.budget,
            "paid_to_payee": self.paid_to_payee,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Evidence:
        previous = data.get("previous_payment")
        return cls(
            payee=data["payee"],
            account=data["account"],
            valid_iban=data["valid_iban"],
            on_file=tuple(data["on_file"]),
            on_file_for=data["on_file_for"],
            dictated=data["dictated"],
            typed_by_user=data["typed_by_user"],
            sightings=tuple(
                SightingRef(
                    s["origin"], s["source"], tuple((a, b) for a, b in s["spans"]), s["line"]
                )
                for s in data["sightings"]
            ),
            history=tuple(data["history"]),
            baseline=data["baseline"],
            previous_payment=None if previous is None else dict(previous),
            spent=data["spent"],
            budget=data["budget"],
            paid_to_payee=data["paid_to_payee"],
        )


@dataclass(frozen=True)
class Decision:
    """The guard's answer to one request.

    `rule` is the first rule that applied and `rules` every rule that did, in
    table order. `checks` is the whole rule ladder and `evidence` the facts
    behind it; both are built together with the outcome.
    """

    outcome: Outcome
    rule: str
    reason: str
    rules: tuple[str, ...] = ()
    checks: tuple[Check, ...] = ()
    evidence: Evidence | None = None

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe form: what goes into the audit log and the API."""
        return {
            "outcome": self.outcome.value,
            "rule": self.rule,
            "rules": list(self.rules),
            "reason": self.reason,
            "checks": [
                {"rule": c.rule, "status": c.status, "detail": c.detail} for c in self.checks
            ],
            "evidence": None if self.evidence is None else self.evidence.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Decision:
        evidence = data.get("evidence")
        return cls(
            outcome=Outcome(data["outcome"]),
            rule=data["rule"],
            reason=data["reason"],
            rules=tuple(data.get("rules") or ()),
            checks=tuple(
                Check(c["rule"], c["status"], c["detail"]) for c in data.get("checks") or ()
            ),
            evidence=None if evidence is None else Evidence.from_dict(evidence),
        )
