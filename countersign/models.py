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
# Payments one payee is expected to get in a task when nothing says how many
# (rule S2). A count in the sentence or one a person types can set it.
DEFAULT_PAYMENTS = 1
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


# Words people and invoices put in front of an invoice number. A closed list.
_REF_LABELS = frozenset({"INV", "INVOICE", "BILL", "NO", "NR", "NUM", "NUMBER", "REF",
                         "REFERENCE"})
_REF_PART = re.compile(r"[A-Z]+|[0-9]+")


def ref_core(reference: str) -> str:
    """The invoice number inside a payment reference, for comparing invoices.

    `ref_key`, then cut between letters and digits, drop label words from the
    front ("INV", "Invoice", "No", "Ref": a closed list) and leading zeros
    from numbers. So "2041", "INV-2041", "inv2041", "Invoice no. 02041" and
    "INV 2041" are one invoice, while "INV-2041-FEE", "INV-2041/B" and
    "NH-2041" are other invoices. Two references are the same invoice only
    when their cores are equal: never by one containing the other.
    """
    parts = _REF_PART.findall(ref_key(reference))
    while len(parts) > 1 and parts[0] in _REF_LABELS:
        parts.pop(0)
    return "-".join(part.lstrip("0") or "0" if part.isdigit() else part for part in parts)


def same_invoice(first: str, second: str) -> bool:
    """True when two references name the same invoice.

    Their cores (`ref_core`) are equal, or one core is only a number and the
    other is letters then that same number: people say "invoice 118" for
    "FD-118". Nothing else: "2041" is not "2041-FEE", "INV-2041-B" or
    "NH-20410".
    """
    a, b = ref_core(first), ref_core(second)
    if not a or not b:
        return False
    if a == b:
        return True
    for number, other in ((a, b), (b, a)):
        if number.isdigit():
            letters, _, digits = other.partition("-")
            if letters.isalpha() and digits == number:
                return True
    return False


# Letters of other alphabets that look like Latin ones, as the Latin letter.
# NFKD (in `fold_lookalikes`) already turns fullwidth and styled forms and
# letters with accents into plain ones; this table covers what it leaves.
_LOOKALIKES = str.maketrans({
    # Cyrillic
    "А": "A", "В": "B", "С": "C", "Е": "E", "Н": "H", "І": "I", "Ј": "J", "К": "K", "М": "M",
    "О": "O", "Р": "P", "Ѕ": "S", "Т": "T", "Х": "X", "У": "Y", "Ү": "Y", "Ԁ": "D", "Ԛ": "Q",
    "Ԝ": "W", "Ӏ": "I", "Ѵ": "V", "а": "a", "с": "c", "е": "e", "і": "i", "ј": "j", "о": "o",
    "р": "p", "ѕ": "s", "х": "x", "у": "y", "һ": "h", "ԁ": "d", "ԛ": "q", "ԝ": "w", "ӏ": "l",
    "ѵ": "v",
    # Greek
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N",
    "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X", "Ϲ": "C", "Ϳ": "J", "ο": "o", "ν": "v",
    "ι": "i", "κ": "k", "ρ": "p", "υ": "u", "χ": "x", "ϲ": "c", "ϳ": "j", "α": "a",
    # Latin letters without a dot or with a hook that still read as i, j, l
    "ı": "i", "ȷ": "j", "ǀ": "l",
})
# Letters that look like a digit, read as that digit when they touch a digit.
_DIGIT_LOOKALIKES = {"O": "0", "o": "0", "I": "1", "l": "1", "L": "1", "i": "1"}
_DIGIT_RUN = re.compile("[" + "".join(_DIGIT_LOOKALIKES) + "]+")
# Alphabets whose letters can pass for each other.
_ALPHABETS = ("LATIN", "CYRILLIC", "GREEK")


def fold_lookalikes(text: str) -> str:
    """`text` with look-alike characters made plain, for comparing invoices.

    Fullwidth and styled forms and letters with accents become plain letters
    and digits (Unicode NFKD), Cyrillic and Greek letters that look Latin
    become those Latin letters, digits of any script become 0 to 9, and the
    letters O, I and l become 0 and 1 where they touch a digit. So
    "МРW-118" (Cyrillic М and Р), "INV-2O41" (letter O) and "ＩＮＶ－２０４１"
    all read as their plain form. Case is kept.

    Only the rules that hold or refuse a second payment of one invoice use
    it (D1, D2, D3, H2 and A1's per-invoice total): there it can only group
    more payments as one invoice. S3 and M6 compare exactly, so a look-alike
    of an invoice you named is still refused.
    """
    out = []
    for ch in unicodedata.normalize("NFKD", text):
        if unicodedata.combining(ch):
            continue
        if ch.isdigit() and not ch.isascii():
            try:
                ch = str(unicodedata.decimal(ch))
            except ValueError:
                pass
        out.append(ch)
    plain = "".join(out).translate(_LOOKALIKES)

    def as_digits(run: re.Match[str]) -> str:
        # A run of these letters next to a digit becomes digits, all of it:
        # "1OO" and "OO1" are 100 and 001. One pass, so a long run read from
        # a document cannot make this slow.
        start, end = run.span()
        if (start > 0 and plain[start - 1].isdigit()) or (end < len(plain) and plain[end].isdigit()):
            return "".join(_DIGIT_LOOKALIKES[ch] for ch in run.group())
        return run.group()

    return _DIGIT_RUN.sub(as_digits, plain)


def _fold_invoice(reference: str) -> str:
    """`fold_lookalikes`, then again on the capitals. Invoice numbers are
    compared in capitals, so a small Cyrillic or Greek letter must fold too:
    "мр-78" is "МР-78", which is MP-78. Folding first keeps a small letter
    that looks like another Latin letter than its capital does (Greek ν is v)."""
    return fold_lookalikes(fold_lookalikes(reference).upper())


def invoice_key(reference: str) -> str:
    """`ref_key` of the reference with look-alikes folded (`fold_lookalikes`):
    the form in which the guard records a paid invoice and an exact payment."""
    return ref_key(_fold_invoice(reference))


def invoice_core(reference: str) -> str:
    """`ref_core` of the reference with look-alikes folded."""
    return ref_core(_fold_invoice(reference))


def may_be_same_invoice(first: str, second: str) -> bool:
    """`same_invoice` after folding look-alikes on both sides. For the rules
    that hold or refuse a second payment of one invoice, never for S3 or M6.

    Also true whenever `same_invoice` is, so folding only ever finds more
    payments of one invoice. Without this, a letter the table does not fold
    would make a copy look less alike than without folding: "ПР-73" read
    plainly is the bare number 73, the same as MP-73, but folded it is P-73."""
    return (same_invoice(_fold_invoice(first), _fold_invoice(second))
            or same_invoice(first, second))


def mixes_alphabets(text: str) -> bool:
    """True when the letters of `text` come from more than one alphabet and
    one of them is Latin, Cyrillic or Greek ("МРW-118": Cyrillic М and Р with
    a Latin W). Fullwidth and styled Latin letters count as Latin."""
    alphabets = set()
    for ch in unicodedata.normalize("NFKC", text):
        if ch.isalpha():
            alphabets.add(unicodedata.name(ch, "?").split(" ")[0])
    return len(alphabets) > 1 and bool(alphabets & set(_ALPHABETS))


# --- figures written in a text (rule T1 reads hidden text with these) ----------------

# A number as an invoice prints it: 1860, 1,860.00, 1.860,00, 1 860,00, 480,5.
_FIGURE = re.compile(
    r"(?<![0-9])([0-9]{1,3}(?:[,.'\u00a0\u202f\u2009][0-9]{3})+|[0-9]+)(?:[.,]([0-9]{1,2}))?(?![0-9])"
)
_FIGURE_SPACED = re.compile(
    r"(?<![0-9])([0-9]{1,3}(?: [0-9]{3})+)(?:[.,]([0-9]{1,2}))?(?![0-9])"
)


def figures_in(text: str) -> set[Decimal]:
    """Every amount a reader could take `text` to state, in every reading:
    "1.860" counts as 1,860 and as 1.86. More readings can only find more."""
    found: set[Decimal] = set()
    for pattern in (_FIGURE, _FIGURE_SPACED):
        for match in pattern.finditer(text):
            whole, cents = match.group(1), match.group(2)
            digits = re.sub(r"[^0-9]", "", whole)
            try:
                found.add(Decimal(f"{digits}.{cents}" if cents else digits))
                marks = re.findall(r"[^0-9]", whole)
                if not cents and len(marks) == 1 and marks[0] in ".,":
                    found.add(Decimal(whole.replace(",", ".")))
            except ArithmeticError:
                continue
    return found


# A reference as a document writes it: letters and digits, joined by - / _ . #
_REF_TOKEN = re.compile(r"[A-Za-z0-9]+(?:[-/_.#][A-Za-z0-9]+)*")


def names_invoice(text: str, reference: str) -> bool:
    """True when `text` writes this invoice number: one to three words in a row
    on one line whose invoice number (`ref_core`) is this reference's, with
    look-alikes folded. Only numbers of at least three characters count.
    "Invoice HP-0457" and "HP 0457" write HP-0457; "INV-2041-FEE" and
    "SHOP-457" do not write INV-2041 or HP-0457."""
    core = invoice_core(reference)
    if len(core.replace("-", "")) < 3:
        return False
    for line in _fold_invoice(text).splitlines():
        words = _REF_TOKEN.findall(line)
        for start in range(len(words)):
            for size in (1, 2, 3):
                if start + size <= len(words) \
                        and ref_core(" ".join(words[start:start + size])) == core:
                    return True
    return False


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
    """The first drafting rule for accounts, kept as the yardstick.

    With exactly one payee, every IBAN written in the instruction is bound to
    that payee. With several payees nothing is bound. `drafting.draft_mandate`
    replaced it: it binds an account only when the sentence gives it as the
    place to pay and carries no negation or warning. For one payee it never
    binds an account that this rule would not bind (a test checks that).
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
class Ask:
    """What the task expects for one payee, drafted from the user's sentence
    (`drafting.draft_mandate`) and confirmed by a person.

    A payment to the payee beyond the amount (S1) or beyond the number of
    payments (S2) waits for a person, because a reading of a sentence can be
    wrong and a hold can be approved while a refusal cannot. A payment for an
    invoice other than the ones named is refused (S3), like a reference outside
    the mandate's own list (M6). The baselines, which have nobody to ask,
    refuse what Countersign holds (M7).

    `payments` is None when nothing says how many payments the payee gets.
    The policy then expects what a count a person typed for the task leaves
    for one payee, or else `DEFAULT_PAYMENTS`. The drafter leaves it None
    when the sentence does not count, so a default never outranks a count a
    person typed. (A mandate saved before v0.3 may carry the default written
    out as 1; it is then read as stated, which is stricter.) These fields
    lift only the holds that exist because nothing was stated: a count of
    two or more expects more payments than the default (S2), and an amount
    gives a payee with no usual amount a bound (A2), for payments within it.
    They never lift A1, D1 or a hold about the destination.

    `set_by` names the fields a person set on the confirmation screen
    (`--payments-for`, `--amount-for`, the task form) instead of the
    sentence. Only a count a person set, together with invoices they typed
    (`--reference`), lets one invoice be paid in parts (D1); a reading of
    the sentence never does.

    `instalments` says that `payments` counts the parts of one invoice ("the
    Nimbus invoice in two instalments"), not invoices. Then the same payment
    may be asked for again within that count: it waits for a person (D1)
    instead of being refused as a repeat (D2).

    `excludes_some` says the sentence tells the agent not to pay some of this
    payee's invoices ("don't pay the April one", "all except the disputed
    one"). Then every payment to the payee waits for a person (S4), unless
    its invoice is one the sentence names (`invoices`).
    """

    amount: Decimal | None = None  # the most this payee is to be paid in the task, in total
    payments: int | None = None  # how many payments to this payee are expected
    invoices: tuple[str, ...] = ()  # the invoices the sentence names for this payee
    set_by: tuple[str, ...] = ()  # "amount", "payments": fields a person set, not the sentence
    instalments: bool = False  # `payments` counts the parts of one invoice
    excludes_some: bool = False  # the sentence says not to pay some of the payee's invoices

    def __post_init__(self) -> None:
        store = object.__setattr__
        if self.amount is not None:
            store(self, "amount", _limit(self.amount, "the stated amount"))
        count = self.payments
        if count is not None and (type(count) is not int or count < 1):
            raise ValueError("the number of payments asked for must be a whole number of at "
                             "least 1")
        invoices = _names(self.invoices, "the invoices named")
        if not all(ref_key(r) for r in invoices):
            raise ValueError("a reference needs at least one letter or digit")
        store(self, "invoices", tuple(invoices))
        marks = self.set_by
        if isinstance(marks, str) or not isinstance(marks, (list, tuple, set, frozenset)):
            raise ValueError("set_by must be a list of field names")
        marks = tuple(sorted(set(marks)))
        for mark in marks:
            if mark not in ("amount", "payments", "excludes_some") \
                    or getattr(self, mark) in (None, False):
                raise ValueError("set_by may only name a field that has a value: amount, "
                                 "payments, excludes_some")
        store(self, "set_by", marks)
        for flag in ("instalments", "excludes_some"):
            if type(getattr(self, flag)) is not bool:
                raise ValueError(f"{flag} must be true or false")
        if self.instalments and self.payments is None:
            raise ValueError("instalments needs a number of payments")

    def __bool__(self) -> bool:
        return (self.amount is not None or self.payments is not None or bool(self.invoices)
                or self.excludes_some)

    def set_by_person(self, name: str) -> bool:
        """True when a person set this field ("amount", "payments"), not the sentence."""
        return name in self.set_by

    def to_dict(self) -> dict[str, Any]:
        found: dict[str, Any] = {
            "amount": None if self.amount is None else plain(self.amount),
            "payments": self.payments,
            "invoices": list(self.invoices),
        }
        if self.set_by:  # left out when empty, so older readers see the same shape
            found["set_by"] = list(self.set_by)
        for flag in ("instalments", "excludes_some"):  # the same: left out when false
            if getattr(self, flag):
                found[flag] = True
        return found

    @classmethod
    def from_dict(cls, data: object) -> Ask:
        if not isinstance(data, dict):
            raise ValueError("what the sentence asks for a payee must be an object")
        amount = data.get("amount")
        try:
            return cls(
                amount=None if amount is None else Decimal(str(amount)),
                payments=data.get("payments"),
                invoices=tuple(data.get("invoices") or ()),
                # Missing (saved before v0.3): read as the sentence's, which never
                # lifts D1. Fails closed.
                set_by=tuple(data.get("set_by") or ()),
                # Missing: false. A count is then read as invoices (a repeat is
                # refused, D2), and no exclusion was read: what older versions did.
                instalments=data.get("instalments", False),
                excludes_some=data.get("excludes_some", False),
            )
        except (TypeError, InvalidOperation) as exc:
            raise ValueError(f"not readable: {exc!r}") from None


NO_ASK = Ask()


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
    # What the sentence says about each payee (amount, count, invoices), as the
    # person confirmed it. A payment outside it is held, not refused.
    asks: dict[str, Ask] = field(default_factory=dict)

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

        if not isinstance(self.asks, dict):
            raise ValueError("asks must map each payee to what the sentence says about it")
        asks: dict[str, Ask] = {}
        for name, ask in self.asks.items():
            payee = by_key.get(name_key(name)) if isinstance(name, str) else None
            if payee is None:
                raise ValueError(f"asks names {name!r}, which is not a payee of the mandate")
            if not isinstance(ask, Ask):
                raise ValueError("asks must map each payee to an Ask")
            if payee in asks:
                raise ValueError(f"asks names {payee!r} twice")
            if ask:
                asks[payee] = ask

        store = object.__setattr__  # the dataclass is frozen
        store(self, "asks", asks)
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

    def ask_for(self, payee: str) -> Ask:
        """What the sentence says about this payee; an empty Ask if nothing."""
        name = self.canonical_payee(payee)
        return self.asks.get(name, NO_ASK) if name is not None else NO_ASK

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
            "asks": {payee: ask.to_dict() for payee, ask in self.asks.items()},
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Mandate:
        try:
            asks = data.get("asks") or {}
            if not isinstance(asks, dict):
                raise ValueError("asks must map each payee to what the sentence says about it")
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
                asks={k: Ask.from_dict(v) for k, v in asks.items()},
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
    # True when the account is not written there as one piece: it was only
    # found by reading through inline markup (see `iban.find_ibans`).
    rendered: bool = False


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
    ceiling: str | None = None  # the most one invoice may come to without a question (A1)
    added: str | None = None  # when an approval added this account to the vendor file
    stated: str | None = None  # the amount the user's sentence states for this payee (S1)
    expected: int | None = None  # payments to this payee the task expects (S2)
    payments_to_payee: int = 0  # payments to this payee made in this task, at decision time
    named_invoices: tuple[str, ...] = ()  # invoices the sentence names for this payee (S3)
    # H2: the waiting payments (hold ids) counted as if paid, and the rules this
    # payment would then break (some of M4, M5, S1, S2, A1, D1).
    waiting_holds: tuple[str, ...] = ()
    projected_rules: tuple[str, ...] = ()
    # D3: waiting payments (hold ids) of the same invoice to another account.
    rivals: tuple[str, ...] = ()

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
                    "rendered": s.rendered,
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
            "ceiling": self.ceiling,
            "added": self.added,
            "stated": self.stated,
            "expected": self.expected,
            "payments_to_payee": self.payments_to_payee,
            "named_invoices": list(self.named_invoices),
            "waiting_holds": list(self.waiting_holds),
            "projected_rules": list(self.projected_rules),
            "rivals": list(self.rivals),
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
                    s["origin"], s["source"], tuple((a, b) for a, b in s["spans"]), s["line"],
                    bool(s.get("rendered", False)),
                )
                for s in data["sightings"]
            ),
            history=tuple(data["history"]),
            baseline=data["baseline"],
            previous_payment=None if previous is None else dict(previous),
            spent=data["spent"],
            budget=data["budget"],
            paid_to_payee=data["paid_to_payee"],
            ceiling=data.get("ceiling"),
            added=data.get("added"),
            stated=data.get("stated"),
            expected=data.get("expected"),
            payments_to_payee=int(data.get("payments_to_payee") or 0),
            named_invoices=tuple(data.get("named_invoices") or ()),
            waiting_holds=tuple(data.get("waiting_holds") or ()),
            projected_rules=tuple(data.get("projected_rules") or ()),
            rivals=tuple(data.get("rivals") or ()),
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
