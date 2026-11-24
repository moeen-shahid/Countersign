"""Draft a mandate from the user's sentence. Plain rules over text, no model.

`draft_mandate(sentence, vendors, payees)` is the one function that reads a
sentence into a proposed mandate: the command line (`task start`), the web
console's task form and every scenario of the benchmark use it. It reads:

* the payees: a vendor from the vendor file named in a clause that tells the
  agent to pay ("Pay Nimbus Hosting ...", "Pay Kestrel's retainer"); other
  vendors the sentence names are listed as mentioned and not included
                                                        -> `Draft.payees`
* an account given as the place to pay ("to IBAN ...", or "IBAN: ..." right
  after the instruction)                                -> `Mandate.accounts`
* an amount ("EUR 650", "480 euros")                    -> `Ask.amount`
* a number of payments ("this month's invoice", "the
  two open invoices", "please pay all three")           -> `Ask.payments`
* that the count is of the parts of one invoice ("in
  three instalments", "in two parts")                   -> `Ask.instalments`
* invoice numbers ("invoice KL-0932")                   -> `Ask.invoices`
* that some invoices are not to be paid ("Don't pay the
  April one", "everything except the Kestrel bill")     -> `Ask.excludes_some`

The draft is a proposal. A person confirms it before a task starts, and what
they confirm is the mandate, which is trusted state. Nothing here is given
anything the agent read.

The rules are built so that no reading, right or wrong, can make the mandate
wider than the mandate the sentence gave before there was a drafter (every
account of a one-payee sentence bound, no amount, no count, no invoice):

1. Every reading narrows that mandate. An amount is the most the payee is
   paid in the task; a count is how many payments the payee gets; named
   invoices are the only references allowed. A payment above the amount or
   beyond the count is held (rules S1, S2 in `policy`), so a reading that is
   too narrow costs a hold; a payment for another invoice is refused (S3),
   like a reference a person typed (M6). No reading lifts the unusual-amount
   line (A1), the duplicate check (D1) or a hold about the destination.
2. Each payee is expected to get one payment unless the sentence counts more
   (`DEFAULT_PAYMENTS`). A count of more than one is read only from a number
   that directly counts invoices, payments or instalments of that payee, in a
   sentence with no negation, warning, question or condition. Such a count,
   and a stated amount for a payee with no usual amount (rule A2), are the
   two readings that lift a hold the policy would make with nothing read:
   each only as far as the user's own number. The count must be part of the
   instruction to pay: "Kestrel sent three invoices. Pay the oldest one."
   counts nothing. A count of instalments of one invoice lets the same
   payment be asked for again within that count; each repeat still waits for
   a person (D1), as it would be refused (D2) with nothing read.
3. An account is bound only when the task has one payee (the old rule bound
   every account in such a sentence; this binds a subset of those), and only
   from two closed positive shapes: the account follows "to"/"into" in the
   clause that tells the agent to pay the payee, or it follows the label
   "IBAN" right after that instruction, with at most an amount or an invoice
   number between them. The sentence has no negation, warning, question,
   condition or report of what someone else said, and says nothing after the
   account but what the payment is for ("to IBAN ... for the logo work") or
   "thanks". Everything else is left unbound: a payment to it is held.
4. Reading nothing is always allowed. When a phrase is not one of the shapes
   below, or it is not clear which payee is meant, the field is left empty
   (or at the default) and the reason is recorded for the person
   (`Draft.readings`).
5. An exclusion only adds holds: every payment to that payee then waits for
   a person unless its invoice is one the sentence names (S4). So it is read
   from any sentence, even one with a negation, and when it names no payee
   in a task of several it applies to each of them.

The language is English. A sentence with no English payment verb (pay, send,
transfer, wire, remit, settle, renew, top up) is not read at all: nothing is
bound and nothing is stated except the default count and any exclusion.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field, replace
from decimal import Decimal
from typing import Any, Iterable, Sequence

from .iban import find_ibans, fmt_iban
from .models import DEFAULT_PAYMENTS, Ask, is_plain_text, money, name_key, ref_key
from .vendors import VendorFile

MAX_COUNT = 20  # a larger count in a sentence is not read
# DEFAULT_PAYMENTS (models): payments each payee is expected to get when the
# sentence does not count them. A further payment is held (S2).
MAX_NAMED = 10  # more named invoices than this are not read
MAX_AMOUNT = Decimal("1000000")

# --- word lists ------------------------------------------------------------------
# Every list is closed: a word that is not in a list is never interpreted.

# "topup" is "top up" or "top-up", read as one word (see `_Scan`).
PAY_VERBS = frozenset({"pay", "send", "transfer", "wire", "remit", "settle", "renew", "topup"})
_DIRECT_VERBS = frozenset({"pay", "send", "transfer", "wire", "remit"})
# Words allowed in front of the verb for the direct shape ("Please pay ...").
# Words allowed in front of the verb when the user is instructing ("Please pay",
# "I need you to pay", "Can you pay"). Anything else in front of it ("They asked
# us to pay", "The email says to send") is a report, not an instruction.
_BEFORE_VERB = frozenset({
    "please", "kindly", "just", "now", "today", "to", "go", "ahead", "do", "i", "we", "you",
    "us", "want", "need", "like", "d", "ll", "would", "could", "can", "will", "let", "s",
    "have", "must",
})
_POLITE = frozenset({"can", "could", "would", "will"})
_LEADING_NEXT = frozenset({"for", "to", "in", "by", "on", "total", "each", "per", "exactly",
                           "due", "into"})
_ANAPHOR = frozenset({"the", "this", "that"})
_FILL = frozenset({"the", "a", "an", "exactly", "just", "s", "their", "its", "them", "it"})
_FILL_TO_PAYEE = frozenset({"to", "the", "for"})
_BARE = frozenset({"for", "of", "the", "a", "an", "total", "amount", "sum", "exactly", "is", "in",
                   "at", "to", "value", "due", "each", "per", "invoice", "all", "altogether"})
_AFTER_AMOUNT_ODD = frozenset({"less", "more", "off", "extra", "short", "back", "discount",
                               "over", "above", "cheaper", "refund", "credit", "plus", "net",
                               "excl", "ex", "before", "minus"})
_BEFORE_AMOUNT_ODD = frozenset({"over", "above", "minus", "less", "plus", "exceeds", "beyond",
                                "than", "save", "saving"})
_APPROX = frozenset({"about", "around", "roughly", "approximately", "approx", "circa", "ca",
                     "nearly", "almost", "some", "estimated"})
_EACH = frozenset({"each", "apiece", "per"})
_TOTAL = frozenset({"total", "totalling", "totaling", "altogether", "combined", "overall"})
_CAPS = (
    ("up", "to"), ("at", "most"), ("at", "the", "most"), ("no", "more", "than"),
    ("not", "more", "than"), ("not", "exceeding"), ("not", "to", "exceed"), ("maximum",),
    ("max",), ("under",), ("below",), ("less", "than"), ("capped", "at"), ("limit", "of"),
    ("a", "maximum", "of"), ("maximum", "of"), ("max", "of"),
)

_NEGATION = frozenset({
    "not", "never", "neither", "nor", "without", "except", "excluding", "exclude", "dont",
    "cant", "wont", "doesnt", "isnt", "shouldnt", "mustnt", "cannot", "no", "nothing", "none",
    "nobody", "nowhere",
    # the commonest negations of a few other languages, so that a mixed
    # sentence is refused rather than half read
    "nicht", "kein", "keine", "keinen", "keinem", "keiner", "nie", "niemals", "nichts", "ohne",
    "pas", "jamais", "sans", "nunca", "sin", "non", "mai", "senza", "niet", "nooit", "geen",
    "zonder",
})
_WARNING = frozenset({
    "scam", "scams", "scammer", "fraud", "fraudulent", "fake", "forged", "phishing", "spoof",
    "spoofed", "suspicious", "suspect", "bogus", "fishy", "dodgy", "wrong", "incorrect",
    "invalid", "ignore", "disregard", "avoid", "beware", "careful", "caution", "warning", "warn",
    "stop", "cancel", "cancelled", "canceled", "block", "blocked", "old", "former", "previous",
    "outdated", "instead", "rather", "hacked", "compromised", "unsure", "doubt", "doubtful",
    "maybe", "perhaps", "possibly", "unverified", "unconfirmed", "dispute", "disputed",
    "odd", "strange", "weird", "sketchy", "shady", "questionable", "unexpected", "unusual",
    "apparently", "supposedly", "allegedly",
    "betrug", "falsch", "arnaque", "fraude", "estafa", "truffa", "oplichting",
})
_HEDGE = frozenset({"if", "unless", "otherwise", "until", "once", "whether", "provided",
                    "assuming", "when", "or", "should", "could", "might", "would", "but",
                    "though", "although", "however", "after", "before"})
# Words that make what comes after them a condition ("Pay Kestrel, once they
# confirm"). A later part of the sentence with one of them, that names no
# vendor, puts the payees named before it in doubt.
_CONDITIONS = frozenset({"if", "unless", "until", "till", "once", "when", "whenever", "whether",
                         "provided", "providing", "assuming", "after", "before", "otherwise"})
# Words that take back what was said before them ("Scrap that.", "Actually,
# don't.", "Hold off for now."), or say not to do it.
_NOT_DO = frozenset({
    "not", "never", "dont", "nope", "nah", "scrap", "scratch", "forget", "cancel", "stop", "hold",
    "wait", "undo", "ignore", "disregard", "skip", "leave", "drop", "revoke", "withdraw",
    "retract", "delete", "nevermind",
})
# The only words a sentence (or the end of one) may have when all it does is
# take back what came before: "Actually, don't pay them yet.", "No.", "It's a
# scam.", "Is that right?". A sentence with any other word says something about
# that word ("Ignore the EUR 1,900 reminder", "that was last year's figure",
# "do not pay anything to IBAN ...") and is read for what it says.
_TAKE_BACK_WORDS = frozenset({
    "that", "this", "it", "them", "those", "these", "all", "everything", "above", "actually",
    "no", "mind", "don", "doesn", "didn", "won", "isn", "aren", "wasn", "shouldn", "t", "do",
    "does", "did", "please", "sorry", "oops", "oh", "ah", "hmm", "ok", "okay", "off", "on", "yet",
    "for", "now", "just", "again", "later", "further", "notice", "today", "pay", "paying",
    "send", "sending", "transfer", "i", "we", "you", "me", "us", "my", "our", "changed",
    "change", "second", "thought", "thoughts", "the", "a", "an", "of", "is", "s", "was", "re",
    "ll", "d", "m", "right", "correct", "sure", "and", "so", "then", "one", "any", "anything",
    "time", "moment", "bit", "be", "make", "go", "with",
})
# Words that correct what came before ("Actually, pay Nimbus."). A later part
# of the sentence with one of them that names a vendor puts the other vendors
# named before it in doubt. Not "instead of" or "rather than", which contrast.
_CORRECTION = frozenset({"instead", "actually", "rather", "sorry", "meant", "correction",
                         "oops", "mistake", "mistaken"})
# Words that say where the user got an account from. An account the user copied
# out of a message is no better than the message, so it is not bound.
_SECOND_HAND = frozenset({"email", "emails", "emailed", "mail", "letter", "message", "sms",
                          "says", "said", "according", "told", "asked", "wrote", "writes",
                          "claims", "claimed", "claiming", "forwarded", "mentions",
                          "mentioned"})
_OPEN_ENDED = frozenset({
    "all", "any", "every", "everything", "anything", "whatever", "other", "others", "another",
    "rest", "remaining", "further", "additional", "more", "else", "etc", "several", "some",
    "few", "many", "multiple", "various",
})

# Words after which a vendor's name says something other than whom to pay:
# "Pay Nimbus for the Marlowe job", "from the Marlowe budget", "via Wise",
# "on behalf of Kestrel". "as well as" joins two payees and is not one of them.
_NOT_PAYEE_AFTER = frozenset({"for", "from", "with", "by", "via", "like", "as", "than",
                              "through", "behalf"})

# --- exclusions --------------------------------------------------------------------
# "Don't pay the April one", "pay everything except the Kestrel bill", "not the
# disputed one", "except invoice MPW-120": the sentence says not to pay some
# invoices. Read as `Ask.excludes_some`: every payment to that payee then waits
# for a person unless its invoice is one the sentence names (rule S4). Reading
# an exclusion only ever adds holds, so it is read from any sentence, even one
# with a negation or a condition.
_EXCLUDE_CUES = frozenset({"not", "never", "dont", "no", "except", "excluding", "exclude",
                           "ignore", "disregard", "skip", "hold", "apart"})
# Words that may stand between the cue and what it excludes: "don't pay the
# ...", "hold off on the ...", "except for the ...", "apart from the ...".
_EXCLUDE_SKIP = frozenset({"pay", "paying", "send", "sending", "transfer", "wire", "remit",
                           "settle", "renew", "topup", "to", "for", "off", "on", "out", "yet",
                           "just", "please", "now", "from", "do", "t", "the", "that", "this",
                           "these", "those", "their", "its", "our", "any", "of"})
# What is excluded: an invoice, a bill or "one", with a word that tells it apart
# ("the April one", "the disputed invoice", "the Kestrel bill", "the one from
# April"). "Don't pay the invoice" or "that one" tells nothing apart: it takes
# the instruction back.
_EXCLUDE_NOUNS = frozenset({"invoice", "invoices", "bill", "bills", "one", "ones", "reminder",
                            "reminders"})
_EXCLUDE_AFTER_NOUN = frozenset({"from", "for", "of", "dated", "in", "on", "sent", "issued",
                                 "numbered", "marked", "about", "with", "they", "we", "that",
                                 "which", "where"})
# Words that cannot tell one invoice from another.
_EXCLUDE_PLAIN = _EXCLUDE_SKIP | _EXCLUDE_NOUNS | frozenset({
    "it", "them", "a", "an", "yet", "please", "now", "again", "today", "until", "till", "if",
    "and", "or", "but", "so", "too", "s", "anything", "everything", "nothing", "something",
    "anyone", "everyone", "anybody", "more", "less", "than",
})

# "for another year", "all month": an open-ended word before one of these
# says nothing about how many payments.
_TIME_WORDS = frozenset({"year", "years", "month", "months", "week", "weeks", "day", "days",
                         "quarter", "quarters", "term", "period", "time", "season", "night"})

_INVOICE_ONE = frozenset({"invoice", "bill"})
_INVOICE_MANY = frozenset({"invoices", "bills"})
_PARTS = frozenset({"instalment", "instalments", "installment", "installments", "tranche",
                    "tranches", "parts", "halves"})
_PAYMENTS = frozenset({"payments", "transfers"})
_INTO = frozenset({"in", "into", "over", "across"})
# Open-ended words that ask for more than one payment ("all the open invoices").
_SEVERAL = frozenset({"all", "every", "other", "others", "another", "rest", "remaining",
                      "further", "additional", "more", "else", "etc", "several", "few",
                      "many", "multiple", "various"})
_COUNT_ADJ = frozenset({
    "open", "outstanding", "unpaid", "overdue", "due", "pending", "last", "latest", "new",
    "recent", "attached", "separate", "equal", "monthly", "weekly", "quarterly", "remaining",
    "older", "small", "final", "s",
})
_NUMBERS = {"one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7,
            "eight": 8, "nine": 9, "ten": 10, "eleven": 11, "twelve": 12, "both": 2}

_BIG_NUMBERS = frozenset({"twenty", "thirty", "forty", "fifty", "sixty", "seventy", "eighty",
                          "ninety", "hundred", "thousand", "dozen", "dozens", "couple"})
_COORDINATORS = frozenset({"and", "plus", "then", "also"})
_ABBREVIATIONS = frozenset({"no", "nr", "inv", "ref", "ltd", "inc", "co", "acct", "approx", "ca"})
_COLON_LABELS = frozenset({"iban", "account", "number", "no", "nr", "amount", "total", "details"})

_ACCOUNT_LABEL = frozenset({"iban", "account", "acct", "number", "no", "nr", "bank", "details"})
_ACCOUNT_DET = frozenset({"the", "their", "its", "his", "her", "this", "new", "following",
                          "a", "an", "is"})
_DESTINATION = frozenset({"to", "into"})
# Any of these outside the "to IBAN ..." phrase means the sentence says
# something more about an account ("that account bounced", "our account").
_ACCOUNT_WORDS = frozenset({"iban", "ibans", "account", "accounts", "acct", "bank", "banks",
                            "details"})
_SIGN_OFF = frozenset({"please", "today", "now", "asap", "thanks", "thank", "you"})
_QUOTES = frozenset('"\u201c\u201d\u201e\u00ab\u00bb\u2039\u203a')

# --- patterns --------------------------------------------------------------------

_MASK = "\x00"
_WORD = re.compile(r"[^\W_]+")
_NUM = r"(?:[0-9]{1,3}(?:[.,'   ][0-9]{3})+|[0-9]+)(?:[.,][0-9]{1,2})?"
_NOT_IN_NUMBER = r"(?![^\W_]|[.,][0-9])"
_ALONE = r"(?<![^\W_])(?<![.,/\-])"  # not the tail of a word, a number or a code like INV-480
_AMOUNT = re.compile(
    rf"(?<![^\W_])(?:EUR|euros?)\s?(?P<a>{_NUM}){_NOT_IN_NUMBER}"
    rf"|€\s?(?P<b>{_NUM}){_NOT_IN_NUMBER}"
    rf"|{_ALONE}(?P<c>{_NUM})\s?(?:(?:EUR|euros?)(?![^\W_])|€)",
    re.IGNORECASE,
)
_NUMBER_PARTS = re.compile(r"([0-9]{1,3}(?:[.,][0-9]{3})+|[0-9]+)(?:[.,]([0-9]{1,2}))?")
_REF_LABEL = re.compile(
    r"(?<![^\W_])(invoices?|bills?|inv|reference|ref)(?![^\W_])\.?"
    r"(?:\s+(?:numbers?|no|nr)(?![^\W_])\.?)?\s*[:#]?\s*",
    re.IGNORECASE,
)
_REF_TOKEN = re.compile(r"#?([A-Za-z0-9][A-Za-z0-9/_-]*(?:\.[A-Za-z0-9]+)*)")
_REF_MORE = re.compile(r"\s*(?:,\s*(?:and\s+|&\s*)?|\s+and\s+|\s*&\s*)")
_REF_SELF = re.compile(r"(?<![^\W_])(inv[-_/]?[0-9][A-Za-z0-9/_-]*)", re.IGNORECASE)
_LABEL_BEFORE = re.compile(r"(?:invoices?|bills?|inv|reference|ref|no|nr|numbers?)\.?\s*[:#]?\s*$",
                           re.IGNORECASE)
_BARE_NUMBER = re.compile(
    rf"{_ALONE}(?<!#)[0-9][0-9.,]*[0-9](?![^\W_]|[.,/\-][0-9])|{_ALONE}(?<!#)[0-9]{{3,}}(?![^\W_])"
)
_APOSTROPHE_NOT = re.compile(r"n['’]t(?![^\W_])", re.IGNORECASE)


# --- what a draft is -------------------------------------------------------------


@dataclass(frozen=True)
class Reading:
    """One thing found in the sentence, and what became of it.

    Shown to the person who confirms the mandate. `used` is False when the
    words were seen but not interpreted; `result` then says why and what
    happens instead.
    """

    field: str  # "account" | "amount" | "payments" | "invoices" | "sentence"
    payee: str | None
    quote: str  # the words of the sentence
    result: str
    used: bool

    def to_dict(self) -> dict[str, Any]:
        return {"field": self.field, "payee": self.payee, "quote": self.quote,
                "result": self.result, "used": self.used}


@dataclass(frozen=True)
class Draft:
    """A mandate proposed from a sentence. A person confirms it."""

    instruction: str
    payees: tuple[str, ...]
    suggested: bool  # the payees were suggested from the vendor file, not given
    accounts: dict[str, tuple[str, ...]] = field(default_factory=dict)
    asks: dict[str, Ask] = field(default_factory=dict)
    readings: tuple[Reading, ...] = ()
    # Every account written in the sentence that was not bound to a payee.
    unbound: tuple[str, ...] = ()
    # Vendors on file that the sentence names and that are not payees.
    mentioned: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "payees": list(self.payees),
            "mentioned": list(self.mentioned),
            "suggested": self.suggested,
            "accounts": {payee: list(values) for payee, values in self.accounts.items()},
            "asks": {payee: ask.to_dict() for payee, ask in self.asks.items()},
            "readings": [reading.to_dict() for reading in self.readings],
            "unbound": list(self.unbound),
        }

    def digest(self) -> str:
        """Identifies exactly what a person was shown, so that a form can only
        confirm the draft it displayed."""
        shown = {"instruction": self.instruction, **self.to_dict()}
        text = json.dumps(shown, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
        return hashlib.sha256(text.encode("ascii")).hexdigest()


# --- scanning the sentence -------------------------------------------------------


@dataclass
class _Atom:
    kind: str  # "word" | "iban" | "amount" | "ref"
    text: str  # folded word, canonical IBAN, or the label of a reference ("invoice")
    start: int
    end: int
    value: Decimal | None = None  # amount
    problem: str = ""  # amount: why it is not read
    names: tuple[str, ...] = ()  # ref: the invoice numbers
    sentence: int = 0
    clause: int = 0
    mention: int = -1  # index into the list of mentions, for a word that is part of one
    used: bool = False  # consumed by a cap phrase or a count phrase


@dataclass
class _Mention:
    payee: str | None  # None: a vendor on file that is not a payee of this task
    first: int  # atom index
    last: int


def _parse_number(text: str) -> Decimal | None:
    plain_text = text
    for ch in "'   ":
        plain_text = plain_text.replace(ch, "")
    match = _NUMBER_PARTS.fullmatch(plain_text)
    if match is None:
        return None
    whole = match.group(1).replace(".", "").replace(",", "")
    try:
        value = Decimal(f"{whole}.{match.group(2) or '0'}").quantize(Decimal("0.01"))
    except ArithmeticError:
        return None
    return value if 0 < value <= MAX_AMOUNT else None


def _blank(text: str, start: int, end: int) -> str:
    return text[:start] + _MASK * (end - start) + text[end:]


def _find_amounts(masked: str) -> tuple[list[_Atom], str]:
    """Amounts written with a euro sign or word next to the number."""
    atoms: list[_Atom] = []
    pos = 0
    while True:
        match = _AMOUNT.search(masked, pos)
        if match is None:
            return atoms, masked
        group = "a" if match.group("a") else "b" if match.group("b") else "c"
        start, end = match.span()
        num_start, num_end = match.span(group)
        problem = ""
        if group == "c":
            after = re.match(r"\s?[0-9]", masked[end:])
            if after is not None:
                # "2041 EUR 480": a number on both sides of the currency. If the
                # first is labelled as an invoice number, the second is the amount.
                if _LABEL_BEFORE.search(masked[:num_start]):
                    pos = num_end
                    continue
                problem = "it is not clear which number the currency belongs to"
                end += re.match(rf"\s?{_NUM}", masked[end:]).end()
            elif re.search(r"(?<![\w.,/\-])[0-9]{1,3} $", masked[:num_start]):
                problem = "digits separated by a space could be one number or two"
                start = re.search(r"[0-9]{1,3} $", masked[:num_start]).start()
        else:
            if re.match(r" [0-9]{3}(?![0-9])", masked[num_end:]):
                problem = "digits separated by a space could be one number or two"
                end = num_end + 4
            else:
                loose = re.search(rf"{_ALONE}[0-9][0-9.,]*\s?$", masked[:start])
                if loose is not None and not _LABEL_BEFORE.search(masked[: loose.start()]):
                    problem = "it is not clear which number the currency belongs to"
        if not problem and re.match(r"\s?[-–—]\s?[0-9]", masked[end:]):
            problem = "a range is not one amount"
        if not problem and re.search(r"[-−+]$", masked[:start]):
            problem = "a signed amount is not read"
        value = _parse_number(match.group(group))
        if value is None and not problem:
            problem = "the number is not a plain amount"
        # "1.900" is 1,900 to most of Europe and 1.9 elsewhere. It is read as the
        # larger number, so it must never be allowed to loosen anything.
        unsure = bool(re.fullmatch(r"[0-9]{1,3}\.[0-9]{3}", match.group(group)))
        atoms.append(_Atom("amount", "unsure" if unsure else "", start, end, value=value,
                           problem=problem))
        masked = _blank(masked, start, end)
        pos = end


def _ref_token(masked: str, pos: int) -> re.Match[str] | None:
    match = _REF_TOKEN.match(masked, pos)
    if match is None:
        return None
    token = match.group(1).rstrip("-/_")
    if len(token) < 3 or not any(ch.isdigit() for ch in token) or not token.isascii():
        return None
    return match


def _find_refs(masked: str) -> tuple[list[_Atom], str]:
    """Invoice numbers: a token with a digit right after "invoice", "bill",
    "ref" or "reference", and tokens that begin INV- followed by a digit."""
    atoms: list[_Atom] = []
    pos = 0
    while True:
        label = _REF_LABEL.search(masked, pos)
        if label is None:
            break
        first = _ref_token(masked, label.end())
        if first is None:
            pos = label.end(1)
            continue
        names = [first.group(1).rstrip("-/_")]
        end = first.start(1) + len(names[0])
        while True:
            more = _REF_MORE.match(masked, end)
            token = _ref_token(masked, more.end()) if more is not None else None
            if token is None:
                break
            name = token.group(1).rstrip("-/_")
            names.append(name)
            end = token.start(1) + len(name)
        atoms.append(_Atom("ref", label.group(1).casefold(), label.start(), end,
                           names=tuple(names)))
        masked = _blank(masked, label.start(), end)
        pos = end
    for match in _REF_SELF.finditer(masked):
        name = match.group(1).rstrip("-/_")
        atoms.append(_Atom("ref", "", match.start(), match.start() + len(name), names=(name,)))
    for atom in atoms:
        masked = _blank(masked, atom.start, atom.end)
    return atoms, masked


def draft_payees(instruction: str, vendor_names: Iterable[str]) -> list[str]:
    """Vendors from the vendor file that the sentence tells the agent to pay.

    See `suggest_payees`, which also returns the vendors the sentence names
    without asking for them to be paid.
    """
    return suggest_payees(instruction, vendor_names)[0]


# Words that may stand around a vendor's name in a list that continues an
# instruction ("Pay the Nimbus Hosting and Brightline Office Supplies invoices
# in the inbox", "Pay this month's run: A, B and C"). A closed list: with any
# other word the clause says something else about the vendor.
_LIST_FILL = frozenset({
    "the", "a", "an", "and", "also", "plus", "too", "as", "well", "for", "of", "in", "this",
    "these", "that", "month", "months", "s", "invoice", "invoices", "bill", "bills", "fee",
    "fees", "open", "outstanding", "unpaid", "due", "overdue", "inbox", "last", "latest", "new",
    "both", "each", "their", "its", "one", "ones", "please", "today", "now", "run", "monthly",
    "quarterly", "annual", "retainer", "renewal", "subscription", "one", "two", "three",
})


# --- how a vendor is named in a sentence ------------------------------------------
#
# People rarely write a supplier's full name. They write "Kestrel's retainer",
# "the Nimbus invoice", "Ostara". So a vendor is found by its full name, or
# by a part of its name that no other vendor has: one word ("Marlowe"), or a
# few words in a row ("Kestrel Legal", when another vendor is also called
# Kestrel). Such a part must hold at least one word that can tell businesses
# apart. These words cannot:
#
# * the words below, which many businesses have in their names: a legal form
#   ("Ltd") or a line of business ("Print", "Insurance"). "Pay the print
#   invoice" does not say which printer;
# * a word this module reads for its meaning ("pay", "not", "two", "invoice"),
#   so a name never hides an instruction and an instruction never names a
#   vendor;
# * a word of fewer than three characters, or one with no letter.
#
# A word that two vendors share names neither of them. Matching ignores case
# and punctuation ("kestrel's" is "kestrel s"), like `models.name_key`.
# This only proposes payees and reads the user's own sentence. A person
# confirms the payees; the guard compares names exactly.
#
# The list is data. Add a word when a vendor file has it in names of
# businesses that are not the same business.
GENERIC_NAME_WORDS = frozenset({
    # legal forms
    "ltd", "limited", "llp", "llc", "lp", "plc", "inc", "incorporated", "corp", "corporation",
    "co", "company", "companies", "gmbh", "ag", "kg", "bv", "nv", "sa", "sas", "sarl", "srl",
    "spa", "oy", "ab", "aps", "pty", "pvt", "ug", "se", "cie",
    # lines of business
    "services", "service", "supplies", "supply", "suppliers", "supplier", "office", "offices",
    "legal", "law", "lawyers", "solicitors", "attorneys", "notary", "notaries", "chambers",
    "print", "printing", "printers", "press", "works", "workshop", "insurance", "assurance",
    "brokers", "broker", "brokerage", "design", "designs", "studio", "studios", "hosting",
    "cloud", "software", "systems", "solutions", "technology", "technologies", "tech",
    "digital", "media", "marketing", "agency", "cleaning", "cleaners", "bookkeeping",
    "accounting", "accountants", "payroll", "tax", "audit", "advisory", "advisors", "advisers",
    "consulting", "consultants", "consultancy", "partners", "partnership", "associates",
    "group", "holdings", "holding", "international", "global", "trading", "traders",
    "enterprises", "industries", "logistics", "transport", "couriers", "courier", "express",
    "freight", "shipping", "network", "networks", "telecom", "communications", "energy",
    "power", "utilities", "water", "electric", "electrical", "plumbing", "heating",
    "construction", "builders", "building", "maintenance", "repairs", "facilities",
    "property", "properties", "estates", "lettings", "rentals", "rental", "hire", "leasing",
    "equipment", "furniture", "stationery", "catering", "foods", "food", "security",
    "staffing", "recruitment", "training", "labs", "lab", "data", "web", "management",
    "finance", "financial", "capital", "bank", "health", "medical", "dental", "clinic",
    "pharmacy", "store", "stores", "shop", "shops", "market", "brothers", "bros", "sons",
    "bindery", "translations", "events", "travel",
    # small words in names
    "and", "the", "of", "for", "von", "van", "der", "den", "de", "la", "le", "du", "des",
    "di", "da", "et", "und", "en", "y",
})

# Some suppliers are named with an everyday word: "Friday Ltd", "Wise", "Stripe
# Payments", "First Office". In "Pay Nimbus by Friday" or "Pay Nimbus first"
# the word is not a name. A name made only of such words (and the common
# business words above) is suggested only when it is written as a name: with
# a capital letter and not all in capitals, not as the first word of a
# sentence, and not right after a word such as "by", "on" or "next" ("by
# Friday", "next March"). The list is data: add a word when a vendor's name is
# a word people also use for its meaning.
ORDINARY_WORDS = frozenset("""
monday tuesday wednesday thursday friday saturday sunday weekend week weekly month monthly
year yearly annual daily day days morning afternoon evening night tonight tomorrow yesterday
january february march april may june july august september october november december
spring summer autumn fall winter season christmas easter holiday holidays
first third fourth fifth sixth seventh eighth ninth tenth last final next early late soon
later ago always ever often already still once twice only also even just very quite really
right away back ahead along around about above below under over across behind beyond near
far here there where why how what who which whose up down out inside outside together
full whole half part parts piece usual usually normal normally regular standard simple plain
clear clean quick quickly fast swift rapid prompt direct express smart wise bright sharp
safe secure sure true real fair fine good better best great grand nice kind easy free open
close closed new old young big small little large long short high low top bottom main
central north south east west northern southern eastern western left middle
green blue red black white grey gray gold golden silver brown orange pink purple yellow
royal united general national local global modern classic fresh pure prime premier
happy lucky honest gentle quiet calm wild warm cool cold hot dry wet light dark heavy
paper stripe card cards cash money coin penny pound euro bank check cheque post mail box
note notes line lines link links key keys door gate home house room desk table chair book
books page pages ink pen pencil light lamp sun star stars moon sky cloud clouds rain snow
wind storm fire water stone rock rocks tree trees wood woods leaf rose field fields park
garden river lake sea ocean bay harbor harbour port bridge hill hills mountain summit peak
valley street road way path lane square corner tower castle crown king queen hall court
market shop store farm mill church school college bridge island coast shore beach wave
care help hand hands heart mind life world time times work job jobs team people family
friend friends home house city town village country land earth air space point level
step steps start end edge side line circle cross plus minus zero one
bird birds fox wolf bear lion tiger eagle hawk owl swan crow robin wren dove horse
fish shark whale bee bees ant cat dog rabbit deer
apple orange lemon berry cherry pepper salt sugar honey bread butter milk tea coffee
ledger pocket wallet purse coin vault safe treasury account accounts record records
""".split()) - frozenset({""})
_ORDINARY_BEFORE = frozenset({
    "by", "on", "until", "till", "before", "after", "next", "this", "last", "every", "each",
    "since", "within", "during", "at", "in", "of", "per", "from", "for", "via", "with",
    "than", "as", "like", "through", "end",
})

# Every word this module reads for its meaning.
_READ_WORDS = frozenset().union(
    PAY_VERBS, _BEFORE_VERB, _LEADING_NEXT, _ANAPHOR, _FILL, _FILL_TO_PAYEE, _BARE,
    _AFTER_AMOUNT_ODD, _BEFORE_AMOUNT_ODD, _APPROX, _EACH, _TOTAL, *_CAPS, _NEGATION,
    _WARNING, _HEDGE, _SECOND_HAND, _OPEN_ENDED, _INVOICE_ONE, _INVOICE_MANY, _PARTS,
    _PAYMENTS, _INTO, _COUNT_ADJ, _NUMBERS, _BIG_NUMBERS, _COORDINATORS, _ABBREVIATIONS,
    _COLON_LABELS, _ACCOUNT_LABEL, _ACCOUNT_DET, _DESTINATION, _ACCOUNT_WORDS, _SIGN_OFF,
    _LIST_FILL, _CONDITIONS, _NOT_DO, _TAKE_BACK_WORDS, _CORRECTION, _NOT_PAYEE_AFTER,
    _EXCLUDE_CUES, _EXCLUDE_SKIP, _EXCLUDE_NOUNS, _EXCLUDE_AFTER_NOUN, _EXCLUDE_PLAIN,
)
# What may stand between two words of one name: spaces, "&", "+", or "-", "/"
# and an apostrophe with no space. Never a comma, a full stop or a new line.
_NAME_JOIN = re.compile(r"[^\S\n]*[&+]?[^\S\n]*|[-/'’]")


def _telling(word: str) -> bool:
    """True for a word that can tell one business from another."""
    return (len(word) >= 3 and any(ch.isalpha() for ch in word)
            and word not in GENERIC_NAME_WORDS and word not in _READ_WORDS)


def _has_run(words: Sequence[str], run: Sequence[str]) -> bool:
    size = len(run)
    return any(tuple(words[i : i + size]) == tuple(run) for i in range(len(words) - size + 1))


def name_parts(name: str, names: Iterable[str]) -> list[tuple[str, ...]]:
    """The parts of `name` by which a sentence may name it among `names`: its
    full name, and every run of its words that holds a word that can tell
    businesses apart and that no other name in `names` has."""
    mine = tuple(name_key(name).split())
    others = [tuple(name_key(n).split()) for n in names if name_key(n) != name_key(name)]
    parts = [mine] if mine else []
    for size in range(1, len(mine)):
        for start in range(len(mine) - size + 1):
            run = mine[start : start + size]
            if any(_telling(w) for w in run) and not any(_has_run(o, run) for o in others):
                parts.append(run)
    return parts


# "no" is a label, not a negation, when a number or a code follows it:
# "invoice no. 118", "no 2041", "no: INV-2041", "account no NL91 ...".
_LABEL_NO = re.compile(r"\s*[.:#]?\s*[A-Za-z]{0,4}[-_/]?[0-9]")


def _labels(atom: _Atom, sentence: str) -> bool:
    """True when the word "no" at `atom` is a label. "No." at the end of a
    sentence, "no invoice 118" and "no EUR 480" are negations."""
    return _LABEL_NO.match(sentence, atom.end) is not None


def _cue_clauses(scan: "_Scan", sentence: str) -> set[int]:
    """Clauses with a negation, a warning, a condition or "n't", and every
    clause of a sentence that asks a question (other than "Can you pay ...?")."""
    atoms = scan.atoms
    found: set[int] = set()
    for index, atom in enumerate(atoms):
        if atom.kind != "word" or atom.mention >= 0:
            continue
        if atom.text in _NEGATION or atom.text in _WARNING or atom.text in _HEDGE:
            if atom.text == "no" and _labels(atom, sentence):
                continue  # "invoice no. 118"
            if atom.text in _POLITE and index + 1 < len(atoms) \
                    and atoms[index + 1].kind == "word" and atoms[index + 1].text == "you":
                continue  # "Could you pay ..."
            found.add(atom.clause)
    for match in _APOSTROPHE_NOT.finditer(sentence):
        near = [a for a in atoms if a.start <= match.start() < a.end + 1]
        if near:
            found.add(near[-1].clause)
    for offset, ch in enumerate(sentence):
        if ch != "?":
            continue
        before = [a for a in atoms if a.end <= offset]
        if not before:
            continue
        number = before[-1].sentence
        first = [a for a in atoms if a.sentence == number and a.kind == "word"][:2]
        if len(first) == 2 and first[0].text in _POLITE and first[1].text == "you":
            continue
        found.update(a.clause for a in atoms if a.sentence == number)
    return found


def _negated(scan: "_Scan") -> set[int]:
    """Indexes of the words that "n't" negates ("don" in "don't")."""
    found = set()
    for match in _APOSTROPHE_NOT.finditer(scan.text):
        near = [i for i, a in enumerate(scan.atoms) if a.start <= match.start() < a.end + 1]
        if near:
            found.add(near[-1])
    return found


def _polite(scan: "_Scan", sentence: int) -> bool:
    """The sentence is a request that begins "Can you", "Could you" ..."""
    first = [a for a in scan.atoms if a.sentence == sentence and a.kind == "word"][:2]
    return len(first) == 2 and first[0].text in _POLITE and first[1].text == "you"


@dataclass(frozen=True)
class _Exclusion:
    """Words that say not to pay some invoices: "don't pay the April one"."""

    first: int  # atom index of the cue ("not", "except", "don" of "don't")
    last: int  # atom index of the last word of what is excluded
    vendors: tuple[str | None, ...]  # vendors named in what is excluded
    refs: tuple[str, ...]  # invoice numbers named in what is excluded


def _exclusions(scan: "_Scan") -> list[_Exclusion]:
    """Every place the sentence says not to pay some invoices.

    A cue ("not", "don't", "except", "skip", "hold off on", "ignore"), then,
    in the same clause, what is excluded: an invoice number ("except
    MPW-120"), a vendor's name ("except Kestrel", "the Kestrel bill"), or an
    invoice, a bill or "one" with words that tell it apart ("the April one",
    "the disputed invoice", "the one from April"). "Don't pay the invoice" and
    "not that one" tell nothing apart, so they are not read as exclusions."""
    atoms, text = scan.atoms, scan.text
    negated = _negated(scan)
    found: list[_Exclusion] = []

    def plain(index: int) -> bool:
        atom = atoms[index]
        return atom.kind == "word" and atom.mention < 0 and atom.text in _EXCLUDE_PLAIN

    def noun(index: int) -> bool:
        atom = atoms[index]
        return atom.kind == "word" and atom.mention < 0 and atom.text in _EXCLUDE_NOUNS

    for cue, atom in enumerate(atoms):
        if atom.kind != "word" or atom.mention >= 0:
            continue
        if atom.text not in _EXCLUDE_CUES and cue not in negated:
            continue
        if atom.text == "no" and _labels(atom, text):
            continue  # "invoice no. 118"
        if atom.text == "hold" and not (
            cue + 1 < len(atoms) and atoms[cue + 1].text in ("off", "back")
        ):
            continue  # "hold off on ...", not "pay the deposit to hold the hall"
        clause = atom.clause
        inside = [i for i in range(cue + 1, len(atoms)) if atoms[i].clause == clause]
        while inside and atoms[inside[0]].kind == "word" and atoms[inside[0]].mention < 0 \
                and atoms[inside[0]].text in _EXCLUDE_SKIP:
            inside.pop(0)
        if not inside:
            continue
        head = atoms[inside[0]]
        if head.kind == "ref":
            found.append(_Exclusion(cue, inside[0], (), head.names))  # "except invoice 2042"
            continue
        code = _ref_token(text, head.start) if head.kind == "word" and head.mention < 0 else None
        if code is not None:
            # "except MPW-120", "not 2042": a code with a digit, not an amount.
            name = code.group(1).rstrip("-/_")
            last = max(i for i in inside if atoms[i].start < head.start + len(name))
            found.append(_Exclusion(cue, last, (), (name,)))
            continue
        # Words that tell the invoice apart, then the invoice ("the April one").
        telling = []
        for index in inside:
            if noun(index) or plain(index) or atoms[index].kind not in ("word", "amount") \
                    or len(telling) == 5:
                break
            telling.append(index)
        rest = inside[len(telling):]
        vendors = tuple(dict.fromkeys(scan.mentions[atoms[i].mention].payee
                                      for i in telling if atoms[i].mention >= 0))
        if telling and rest and noun(rest[0]):
            found.append(_Exclusion(cue, rest[0], vendors, ()))  # "the April one"
        elif len(telling) == 1 and rest and atoms[rest[0]].text == "s":
            found.append(_Exclusion(cue, rest[0], vendors, ()))  # "except April's"
        elif vendors and all(atoms[i].mention >= 0 for i in telling) and (
            not rest or atoms[rest[0]].text in _EXCLUDE_VENDOR_THEN
        ):
            found.append(_Exclusion(cue, telling[-1], vendors, ()))  # "except Kestrel"
        elif not telling and len(rest) >= 3 and noun(rest[0]) \
                and atoms[rest[1]].kind == "word" and atoms[rest[1]].text in _EXCLUDE_AFTER_NOUN:
            found.append(_Exclusion(cue, rest[2], (), ()))  # "the one from April"
    return found


# What may follow a vendor's name that an exclusion names ("except Kestrel",
# "hold off on Kestrel until ..."). Anything else ("do not pay Nimbus more
# than ...") says something else about the vendor.
_EXCLUDE_VENDOR_THEN = frozenset({"yet", "too", "either", "until", "till", "for", "now", "today",
                                  "this", "while", "please", "s"})


@dataclass(frozen=True)
class _TakeBack:
    """A later part of the sentence that puts payees named before it in doubt."""

    clause: int  # its first clause
    sentence: int
    # "back": everything before it; "if": what comes before it in its own
    # sentence; "correct": every vendor before it but the ones it names.
    kind: str
    quote: str
    names: tuple[str | None, ...] = ()  # "correct": the vendors it names


def _take_backs(scan: "_Scan", exclusions: Sequence[_Exclusion]) -> list[_TakeBack]:
    """Parts of the sentence that put the payees named before them in doubt:

    * a clause of nothing but words like "actually", "that", "them", "yet"
      and a word that says not to do it: "Actually, don't.", "Scrap that.",
      "Don't pay them, they're scammers.", "Pay Kestrel, but not yet.";
    * the rest of a sentence, or a whole later sentence, of nothing but such
      words, with a negation, a warning or a question: "No.", "It's a scam.",
      "Is that right?";
    * a later clause of the same sentence with a condition: "Pay Kestrel,
      once they confirm.";
    * a later part that names a vendor with a word that corrects: "Actually,
      pay Nimbus."

    Only the last of these names a vendor. A part that has any other word
    ("Ignore the EUR 1,900 reminder", "that was last year's figure", "do not
    pay anything to IBAN ...", "don't pay the April one") says what it is
    about, and is read for that, not as taking the instruction back."""
    atoms, text = scan.atoms, scan.text
    negated = _negated(scan)
    excluded = {i for e in exclusions for i in range(e.first, e.last + 1)}
    fill = _TAKE_BACK_WORDS | _NOT_DO | _NEGATION | _WARNING | _HEDGE | _CORRECTION
    clauses: dict[int, list[int]] = {}
    for index, atom in enumerate(atoms):
        clauses.setdefault(atom.clause, []).append(index)
    order = sorted(clauses)

    def quote(indexes: Sequence[int]) -> str:
        return scan.quote(atoms[indexes[0]].start, atoms[indexes[-1]].end)

    def all_fill(indexes: Sequence[int]) -> bool:
        return all(atoms[i].kind == "word" and atoms[i].mention < 0 and atoms[i].text in fill
                   and i not in excluded for i in indexes)

    def says_not(indexes: Sequence[int]) -> bool:
        return any(i in negated or atoms[i].text in _NOT_DO for i in indexes)

    def doubts(indexes: Sequence[int]) -> bool:
        if says_not(indexes) or any(atoms[i].text in _NEGATION | _WARNING | _HEDGE
                                    for i in indexes):
            return True
        last = indexes[-1]
        gap = text[atoms[last].end : atoms[last + 1].start if last + 1 < len(atoms) else None]
        return "?" in gap and not _polite(scan, atoms[last].sentence)

    found: list[_TakeBack] = []
    for position, clause in enumerate(order[1:], 1):  # nothing comes before the first
        indexes = clauses[clause]
        sentence = atoms[indexes[0]].sentence
        opens = atoms[clauses[order[position - 1]][0]].sentence != sentence
        rest = [i for c in order[position:] for i in clauses[c] if atoms[i].sentence == sentence]
        corrects = [
            i for i in indexes if atoms[i].kind == "word" and atoms[i].mention < 0
            and atoms[i].text in _CORRECTION
            and not (atoms[i].text == "instead" and i + 1 < len(atoms) and atoms[i + 1].text == "of")
            and not (atoms[i].text == "rather" and i + 1 < len(atoms) and atoms[i + 1].text == "than")
        ]
        names = tuple(dict.fromkeys(scan.mentions[atoms[i].mention].payee
                                    for i in rest if atoms[i].mention >= 0
                                    and corrects and i > corrects[0]))
        if corrects and names:
            # "Actually, pay Nimbus": every other vendor named before it is in doubt.
            found.append(_TakeBack(clause, sentence, "correct", quote(rest), names))
            continue
        if any(atoms[i].mention >= 0 for i in indexes):
            continue
        if not opens and any(atoms[i].kind == "word" and atoms[i].text in _CONDITIONS
                             for i in indexes):
            found.append(_TakeBack(clause, sentence, "if", quote(indexes)))
        elif any(atoms[i].sentence == sentence for i in excluded):
            # "Ignore the EUR 1,900 reminder, it is bogus": the sentence is
            # about what it excludes, which is read as an exclusion.
            continue
        elif all_fill(indexes) and says_not(indexes):
            found.append(_TakeBack(clause, sentence, "back", quote(indexes)))
        elif all_fill(rest) and doubts(rest):
            found.append(_TakeBack(clause, sentence, "back", quote(rest)))
    return found


def suggest_payees(
    instruction: str, vendor_names: Iterable[str]
) -> tuple[list[str], list[str]]:
    """(payees to propose, vendors named but not proposed), in sentence order.

    A vendor is named by its full name or by a part of its name that no other
    vendor has (`name_parts`: "Kestrel's", "the Nimbus invoice", "Ostara").
    It is proposed only from one closed positive shape: the name stands in a
    clause that tells the agent to pay ("Pay Nimbus Hosting ..."), or in a
    list that continues such a clause and holds nothing but names and a few
    words like "the", "invoices", "and" ("..., Brightline and Kestrel").

    It is not proposed when any place in the sentence names it in doubt:

    * a negation, a warning, a condition or a question in its clause, in the
      clause with the payment verb, or earlier in its sentence ("Hold off on
      Kestrel", "Pay Nimbus, not Kestrel", "If it matches, pay Kestrel",
      "Pay Kestrel after they fix the invoice");
    * inside quotation marks, or after words that report what someone else
      said ("The email says: pay Kestrel");
    * a later part of the sentence takes it back without naming a vendor
      ("Pay Kestrel. Actually, don't.", "Scrap that.", "Pay Kestrel, once
      they confirm"), or corrects it by naming another ("Actually, pay
      Nimbus"). See `_take_backs`. Saying not to pay some invoices ("Don't
      pay the April one") does not take the payee back: it is read as an
      exclusion (`Ask.excludes_some`).

    In the clause that tells the agent to pay, only the first vendor named
    is the one to pay. A vendor named after "for", "from", "with", "by",
    "via", "like", "as", "than", "through" or "on behalf of" is not ("Pay
    Nimbus for the Marlowe job"). A name made only of everyday words
    (`ORDINARY_WORDS`: "Friday", "Wise", "First") names a vendor only when it
    is written as a name ("by Friday" and "pay Nimbus first" do not).

    Every vendor named and not proposed ("Kestrel asked us to pay them") is
    returned as mentioned, for the person to see and add if they mean it.
    This is only a proposal for a person to confirm. The guard never matches
    names loosely.
    """
    names = [n for n in dict.fromkeys(vendor_names) if isinstance(n, str) and name_key(n)]
    if not names or not isinstance(instruction, str) or not instruction.strip():
        return [], []
    scan = _Scan(instruction, names, [])
    atoms = scan.atoms
    cues = _cue_clauses(scan, instruction)
    takes = _take_backs(scan, _exclusions(scan))

    def verb_clause(at: int) -> int | None:
        """The clause with the payment verb that governs atom `at`: its own
        clause, or else the nearest one before it in the same sentence."""
        sentence = atoms[at].sentence
        for atom in reversed(atoms[: at + 1]):
            if atom.sentence != sentence:
                break
            if atom.kind == "word" and atom.text in PAY_VERBS:
                return atom.clause
        own = atoms[at].clause
        if any(a.kind == "word" and a.text in PAY_VERBS for a in scan.clause_atoms(own)):
            return own  # "Nimbus Hosting, please pay them"
        return None

    def in_doubt(mention: _Mention, verb: int | None) -> bool:
        """A cue in its clause, in its verb's clause or earlier in its
        sentence; inside quotation marks; after "says", "email", "told"; or
        taken back by a later part of the sentence."""
        first = atoms[mention.first]
        clause = first.clause
        if clause in cues or (verb is not None and verb in cues):
            return True
        earlier = [a for a in atoms[: mention.first] if a.sentence == first.sentence]
        if any(a.clause in cues for a in earlier):
            return True
        if any(a.kind == "word" and a.mention < 0 and a.text in _SECOND_HAND for a in earlier):
            return True
        quotes = sum(ch in _QUOTES for ch in instruction[: first.start])
        if quotes % 2 == 1:
            return True
        for take in takes:
            if take.clause <= clause:
                continue
            if take.kind == "back" or (take.kind == "if" and take.sentence == first.sentence) \
                    or (take.kind == "correct" and mention.payee not in take.names):
                return True
        return False

    def written_as_name(mention: _Mention) -> bool:
        """False for a name of everyday words that is not written as a name:
        "first", "by Friday", "ONLY", "Wise" as the first word of a sentence."""
        words = atoms[mention.first : mention.last + 1]
        if any(_telling(a.text) and a.text not in ORDINARY_WORDS for a in words):
            return True
        for atom in words:
            written = instruction[atom.start : atom.end]
            if atom.text in ORDINARY_WORDS and (
                not written[:1].isupper() or (len(written) > 1 and written.isupper())
            ):
                return False
        before = [a for a in atoms[: mention.first] if a.sentence == words[0].sentence]
        return bool(before) and not (before[-1].kind == "word" and before[-1].mention < 0
                                     and before[-1].text in _ORDINARY_BEFORE)

    def governed(mention: _Mention) -> bool:
        """A word like "for" or "from" stands before the name in its clause,
        after the payment verb ("Pay Nimbus for the Marlowe job"); or the name
        is a list item that continues such a name ("via Wise and Stripe")."""
        clause = atoms[mention.first].clause
        here = [i for i in range(mention.first) if atoms[i].clause == clause]
        verbs = [i for i in here if atoms[i].kind == "word" and atoms[i].text in PAY_VERBS]
        if verbs:
            here = [i for i in here if i > verbs[-1]]
        words = [atoms[i].text if atoms[i].kind == "word" and atoms[i].mention < 0 else ""
                 for i in here]
        for k, word in enumerate(words):
            if word in _NOT_PAYEE_AFTER and not (
                word == "as" and (words[k : k + 3] == ["as", "well", "as"]
                                  or words[max(k - 2, 0) : k + 1] == ["as", "well", "as"])
            ):
                return True
        if verbs or not any(a.clause < clause and a.sentence == atoms[mention.first].sentence
                            for a in atoms):
            return False
        before = scan.joined.get(clause)
        if before is None:
            before = max((atoms[m.first].clause for m in scan.mentions
                          if atoms[m.first].clause < clause
                          and atoms[m.first].sentence == atoms[mention.first].sentence),
                         default=None)
        earlier = [m for m in scan.mentions if atoms[m.first].clause == before]
        return bool(earlier) and governed(earlier[-1])

    proposed: list[str] = []
    doubted: set[str] = set()
    named: list[str | None] = []
    for mention in scan.mentions:  # in sentence order
        name = mention.payee
        clause = atoms[mention.first].clause
        here = scan.clause_atoms(clause)
        verb = verb_clause(mention.first)
        positive = False
        if not written_as_name(mention):
            # "Pay Nimbus first": not a name, so it suggests nothing. It may
            # still be one, so a doubt about it counts ("Wise? Not sure.").
            if in_doubt(mention, verb):
                doubted.add(name)
                named.append(name)
            continue
        named.append(name)
        if in_doubt(mention, verb):
            doubted.add(name)
        elif verb is not None and scan.instructs(verb):
            if verb == clause:
                positive = True
            else:
                # A list item: names and filler words, and after the name at most
                # a purpose ("Tidewater Insurance Brokers for the policy").
                last = max(i for i, a in enumerate(here) if a.mention >= 0)
                tail = here[last + 1 :]
                if tail and tail[0].kind == "word" and tail[0].text == "for":
                    tail = []
                positive = all(
                    a.kind in ("amount", "ref") or a.mention >= 0
                    or (a.kind == "word" and (a.text in _LIST_FILL or a.text in _COORDINATORS))
                    for a in here[: last + 1] + tail
                )
            # Only the first vendor of its clause ("Pay Nimbus the Tidewater way"),
            # or one joined to it by "as well as"; and not after "for", "from" ...
            before = [m for m in scan.mentions if atoms[m.first].clause == clause
                      and m.first < mention.first and written_as_name(m)]
            joined = bool(before) and [
                a.text for a in atoms[before[-1].last + 1 : mention.first]
            ] == ["as", "well", "as"]
            positive = positive and (not before or joined) and not governed(mention)
        if positive and name not in proposed:
            proposed.append(name)
    # A vendor named in doubt anywhere is not proposed, even if another place
    # names it plainly ("Pay Kestrel and Nimbus. Don't pay Kestrel yet.").
    proposed = [name for name in proposed if name not in doubted]
    return proposed, [name for name in dict.fromkeys(named) if name not in proposed]


class _Scan:
    """The sentence cut into atoms, clauses and sentences."""

    def __init__(self, text: str, payees: Sequence[str], others: Sequence[str]) -> None:
        self.text = text
        self.payees = tuple(payees)
        ibans = find_ibans(text)
        masked = text
        atoms = [_Atom("iban", m.account, m.start, m.end) for m in ibans]
        for match in ibans:
            masked = _blank(masked, match.start, match.end)
        amounts, masked = _find_amounts(masked)
        refs, masked = _find_refs(masked)
        atoms += amounts + refs
        self.masked = masked  # the text with accounts, amounts and references blanked out
        atoms += [
            _Atom("word", name_key(m.group()) or m.group().casefold(), m.start(), m.end())
            for m in _WORD.finditer(masked)
        ]
        atoms.sort(key=lambda atom: atom.start)
        # "top up" and "top-up" are one payment verb.
        index = 0
        while index + 1 < len(atoms):
            left, right = atoms[index], atoms[index + 1]
            if left.kind == right.kind == "word" and left.text == "top" and right.text == "up" \
                    and text[left.end : right.start] in (" ", "-", "‑"):
                atoms[index : index + 2] = [_Atom("word", "topup", left.start, right.end)]
            index += 1
        self.atoms = atoms
        self.mentions: list[_Mention] = []
        self._find_mentions(payees, others)
        self._cut()

    def _joins(self, index: int) -> bool:
        """True when atoms `index` and `index + 1` may be two words of one name."""
        left, right = self.atoms[index], self.atoms[index + 1]
        return left.kind == right.kind == "word" \
            and _NAME_JOIN.fullmatch(self.text[left.end : right.start]) is not None

    def _find_mentions(self, payees: Sequence[str], others: Sequence[str]) -> None:
        """Every place the sentence names a payee or another vendor: its full
        name, or a part of its name that no other name here has (see
        `name_parts`), together with the words of the name around that part
        ("Kestrel Legal" in "Pay Kestrel Legal's invoice")."""
        atoms = self.atoms
        mine = {name_key(p) for p in payees}
        names = [(p, p) for p in dict.fromkeys(payees)] + [
            (None, o) for o in dict.fromkeys(others) if name_key(o) not in mine
        ]
        everyone = [name for _, name in names]
        found: list[tuple[int, int, int, int, str | None]] = []  # size, first, last, order, payee
        for order, (payee, name) in enumerate(names):
            key = tuple(name_key(name).split())
            parts = name_parts(name, everyone)
            for i, atom in enumerate(atoms):
                if atom.kind != "word":
                    continue
                for p, word in enumerate(key):
                    if atom.text != word:
                        continue
                    if p > 0 and i > 0 and atoms[i - 1].text == key[p - 1] and self._joins(i - 1):
                        continue  # the run starts one word earlier
                    last = i
                    while (
                        last + 1 < len(atoms)
                        and p + last + 1 - i < len(key)
                        and atoms[last + 1].text == key[p + last + 1 - i]
                        and self._joins(last)
                    ):
                        last += 1
                    run = key[p : p + last - i + 1]
                    if any(_has_run(run, part) for part in parts):
                        found.append((last - i + 1, i, last, order, payee))
        # Where two names claim the same words, the longer match wins ("Acme
        # Tools" over "Acme"). A shorter one that overlaps it is dropped.
        taken: set[int] = set()
        for size, first, last, order, payee in sorted(found, key=lambda f: (-f[0], f[1], f[3])):
            if any(i in taken for i in range(first, last + 1)):
                continue
            taken.update(range(first, last + 1))
            self.mentions.append(_Mention(payee, first, last))
        self.mentions.sort(key=lambda mention: mention.first)
        for index, mention in enumerate(self.mentions):
            for atom in atoms[mention.first : mention.last + 1]:
                atom.mention = index

    def _gap(self, index: int) -> int:
        """0: the atoms run on; 1: a clause ends between them; 2: a sentence ends."""
        left, right = self.atoms[index], self.atoms[index + 1]
        if left.mention >= 0 and left.mention == right.mention:
            return 0
        gap = self.text[left.end : right.start]
        level = 0
        if gap in (".", ",") and left.kind == right.kind == "word" \
                and left.text.isdigit() and right.text.isdigit():
            return 0  # "12.50", "1,480" written without a currency: one number
        for offset, ch in enumerate(gap):
            if ch in "!?;":
                return 2
            if ch == "\n":
                level = 1  # a new line continues the instruction, like a comma
            if ch == ".":
                if left.kind == "word" and left.text in _ABBREVIATIONS and offset == 0:
                    continue
                if offset + 1 < len(gap) and not gap[offset + 1].isspace():
                    continue  # "example.com": a full stop ends a sentence before a space
                if offset + 1 == len(gap) and gap == ".":
                    continue
                return 2
            if ch == ":":
                if left.kind == "word" and left.text in _COLON_LABELS:
                    continue
                level = 1
            if ch in ",–—" or (ch == "-" and gap.strip() == "-" and gap != "-"):
                level = 1
        return level

    def _cut(self) -> None:
        atoms = self.atoms
        # clause -> the clause it was joined to by "and", "plus", "then", "also" or "&"
        self.joined: dict[int, int] = {}
        sentence = clause = 0
        for index, atom in enumerate(atoms):
            is_coordinator = (
                atom.kind == "word" and atom.text in _COORDINATORS and atom.mention < 0
            )
            if is_coordinator:
                before = atoms[index - 1].clause if index else clause
                clause += 1
                atom.sentence, atom.clause = sentence, clause
                atom.used = True
                clause += 1
                self.joined[clause] = before
            else:
                atom.sentence, atom.clause = sentence, clause
            if index + 1 < len(atoms):
                level = self._gap(index)
                if level == 2:
                    sentence += 1
                    clause += 1
                    self.joined.pop(clause, None)
                elif level == 1:
                    clause += 1
                nxt = atoms[index + 1]
                same_name = atom.mention >= 0 and atom.mention == nxt.mention
                if "&" in self.text[atom.end : nxt.start] and not same_name and level < 2:
                    clause += 1
                    self.joined[clause] = atom.clause

    # --- questions about the cut sentence ---------------------------------------

    def words(self, clause: int | None = None) -> list[_Atom]:
        return [a for a in self.atoms
                if a.kind == "word" and (clause is None or a.clause == clause)]

    def clause_atoms(self, clause: int) -> list[_Atom]:
        return [a for a in self.atoms if a.clause == clause]

    def payees_in(self, clause: int) -> list[str | None]:
        """Distinct parties mentioned in a clause. None stands for a vendor on
        file that is not a payee of this task."""
        found: list[str | None] = []
        for mention in self.mentions:
            if self.atoms[mention.first].clause == clause and mention.payee not in found:
                found.append(mention.payee)
        return found

    def owner(self, clause: int) -> tuple[str | None, str]:
        """The one payee a clause speaks about, or (None, why not)."""
        named = self.payees_in(clause)
        if len(named) == 1 and named[0] is not None:
            return named[0], ""
        if len(named) > 1:
            return None, "the clause names more than one party"
        if named == [None]:
            return None, "the clause names a vendor that is not a payee of this task"
        if len(self.payees) == 1:
            return self.payees[0], ""
        return None, "the clause names no payee, and the task has more than one"

    def instructs(self, clause: int) -> bool:
        """True when the clause is an instruction from the user: its payment verb
        has nothing in front of it but words like "please" or "I need you to".

        A clause without a payment verb continues the instruction of the
        clause in its sentence that has one ("..., EUR 480, to IBAN ...").
        """
        atoms = self.clause_atoms(clause)
        if not atoms:
            return False
        if not any(a.kind == "word" and a.text in PAY_VERBS for a in atoms):
            number = atoms[0].sentence
            clauses = sorted({a.clause for a in self.atoms if a.sentence == number
                              and a.kind == "word" and a.text in PAY_VERBS})
            if not clauses:
                return False
            atoms = self.clause_atoms(clauses[0])
        for atom in atoms:
            if atom.kind == "word" and atom.text in PAY_VERBS:
                return True
            if atom.kind == "word" and atom.used:
                continue  # the modal of "Could you pay ...?"
            if atom.kind != "word" or atom.text not in _BEFORE_VERB:
                return False
        return False

    def shared(self, clause: int, kind: str) -> bool:
        """True when what this clause says may belong to two payees: it was
        joined by "and" to a clause that names another party and has no item of
        this kind, and it has no payment verb of its own ("Pay Nimbus Hosting
        and Fernhill Design EUR 480")."""
        other = self.joined.get(clause)
        if other is None:
            return False
        here = self.clause_atoms(clause)
        there = self.clause_atoms(other)
        if any(a.kind == "word" and a.text in PAY_VERBS for a in here):
            return False
        if not there or there[0].sentence != here[0].sentence:
            return False
        return bool(set(self.payees_in(other)) - set(self.payees_in(clause))) and not any(
            a.kind == kind for a in there
        )

    def quote(self, start: int, end: int) -> str:
        text = " ".join(self.text[start:end].split())
        return text if len(text) <= 80 else text[:77] + "..."


def _phrase_before(words: list[_Atom], index: int, phrase: tuple[str, ...]) -> bool:
    start = index - len(phrase) + 1
    return start >= 0 and tuple(a.text for a in words[start : index + 1]) == phrase


# --- the drafter -----------------------------------------------------------------


def draft_mandate(
    sentence: str, vendors: VendorFile, payees: Sequence[str] | None = None
) -> Draft:
    """Propose the parts of a mandate that the user's sentence states.

    `payees` are the payees the person named for the task. Left out, they are
    suggested from the vendor file (`draft_payees`) and the draft says so.
    The result never contains anything that is not written in `sentence`.
    The same sentence, vendor file and payees always give the same draft.
    """
    if not isinstance(sentence, str):
        raise TypeError("the sentence must be text")
    known = sorted(vendor.name for vendor in vendors.all())
    suggested = payees is None
    proposed, named_only = suggest_payees(sentence, known)
    names = proposed if suggested else [
        p.strip() for p in payees if is_plain_text(p) and name_key(p)
    ]
    names = list(dict(zip((name_key(n) for n in names), names)).values())
    mine = {name_key(n) for n in names}
    mentioned = tuple(n for n in proposed + named_only if name_key(n) not in mine)
    typed = tuple(dict.fromkeys(match.account for match in find_ibans(sentence)))
    readings: list[Reading] = []
    excluded: dict[str, list[str]] = {}  # payee -> the words that exclude some invoices
    unsure_whose: set[str] = set()  # excluded only because the words name no payee

    def done(accounts: dict[str, tuple[str, ...]], asks: dict[str, Ask]) -> Draft:
        bound = {a for values in accounts.values() for a in values}
        for payee in names:  # nothing read: the default count still applies
            if payee not in asks:
                asks[payee] = Ask()  # no count stated: the policy's default applies
            if payee in excluded:
                asks[payee] = replace(asks[payee], excludes_some=True)
                readings.append(Reading(
                    "invoices", payee, "; ".join(excluded[payee]),
                    f"Some invoices of {payee} are not to be paid. Every payment to {payee} "
                    "will wait for a person, unless its invoice is one your sentence names to "
                    "pay." + (" The sentence does not say whose invoices these are, so this "
                              "applies to each payee." if payee in unsure_whose else ""), True,
                ))
        return Draft(
            instruction=sentence, payees=tuple(names), suggested=suggested,
            accounts=accounts, asks={p: asks[p] for p in names}, readings=tuple(readings),
            unbound=tuple(a for a in typed if a not in bound), mentioned=mentioned,
        )

    if not names:
        return done({}, {})
    scan = _Scan(sentence, names, known)
    atoms = scan.atoms
    words = scan.words()

    # --- exclusions: read from any sentence, because they only add holds --------
    exclusions = _exclusions(scan)
    in_exclusion: set[int] = set()  # atom indexes: an invoice number here is not one to pay
    excluded_refs: dict[str, set[str]] = {}
    for exclusion in exclusions:
        span = range(exclusion.first, exclusion.last + 1)
        in_exclusion.update(span)
        quote = scan.quote(atoms[exclusion.first].start, atoms[exclusion.last].end)
        if exclusion.vendors:
            whose = [v for v in exclusion.vendors if v is not None]  # "except the Kestrel bill"
        else:
            number = atoms[exclusion.first].sentence
            whose = list(dict.fromkeys(
                scan.mentions[a.mention].payee for i, a in enumerate(atoms)
                if a.sentence == number and a.mention >= 0 and i not in span
                and scan.mentions[a.mention].payee is not None
            ))
            if not whose:
                whose = list(names)  # it names no payee: it may be about any of them
                if len(names) > 1:
                    unsure_whose.update(names)
        for payee in whose:
            excluded.setdefault(payee, []).append(quote)
            excluded_refs.setdefault(payee, set()).update(ref_key(r) for r in exclusion.refs)
    takes = _take_backs(scan, exclusions)

    if not any(a.text in PAY_VERBS for a in words):
        readings.append(Reading(
            "sentence", None, scan.quote(0, len(sentence)),
            "No payment verb (pay, send, transfer, wire, remit, settle, renew, top up) was "
            "found, so nothing was read from this sentence. An account written in it is not "
            "trusted; a payment to it will be held. Each payee is expected to get one payment.",
            False,
        ))
        return done({}, {})

    # --- caps, then doubt -------------------------------------------------------
    capped: set[int] = set()  # id() of amount atoms that follow a cap phrase
    position = {id(a): i for i, a in enumerate(atoms)}
    for index, atom in enumerate(words):
        for phrase in _CAPS:
            if not _phrase_before(words, index, phrase):
                continue
            after = atoms[position[id(atom)] + 1 :][:3]
            for offset, nxt in enumerate(after):
                if nxt.kind == "amount" and all(
                    a.kind == "word" and a.text in ("of", "a", "the", "total") for a in after[:offset]
                ):
                    capped.add(id(nxt))
                    for used in words[index - len(phrase) + 1 : index + 1]:
                        used.used = True
                    break

    def is_cue(atom: _Atom, table: frozenset[str]) -> bool:
        if atom.kind != "word" or atom.used or atom.mention >= 0 or atom.text not in table:
            return False
        if atom.text == "no":
            # "invoice no. 118", "account no: ..." is a label, not a negation.
            if _labels(atom, sentence):
                return False
        return True

    doubt_sentences: dict[int, str] = {}
    polite: set[int] = set()
    for atom in words:
        if is_cue(atom, _NEGATION) or is_cue(atom, _WARNING):
            doubt_sentences.setdefault(atom.sentence, sentence[atom.start : atom.end])
    for match in _APOSTROPHE_NOT.finditer(sentence):
        near = [a for a in atoms if a.start <= match.start() < a.end + 1]
        number = near[-1].sentence if near else 0
        doubt_sentences.setdefault(number, sentence[max(match.start() - 6, 0) : match.end()].split()[-1])
    for number in sorted({a.sentence for a in atoms}):
        # "Can you pay ...?" is a request. Its modal is not a condition and its
        # question mark is not a doubt.
        first = [a for a in words if a.sentence == number][:2]
        if len(first) == 2 and first[0].text in _POLITE and first[1].text == "you":
            first[0].used = True
            polite.add(number)
    for offset, ch in enumerate(sentence):
        if ch == "?":
            before = [a for a in atoms if a.end <= offset]
            number = before[-1].sentence if before else 0
            if number not in polite:
                doubt_sentences.setdefault(number, "?")
    hedged: dict[int, str] = {}  # sentence -> the condition word in it
    for atom in words:
        if is_cue(atom, _HEDGE):
            hedged.setdefault(atom.sentence, sentence[atom.start : atom.end])
    hedge = next(iter(hedged.values()), "")
    doubt = next(iter(doubt_sentences.values()), "")
    taken = next((take.quote for take in takes), "")
    plain_sentence = not doubt and not hedge and not taken  # nothing loosens unless this is true
    why_not_plain = (
        f"the sentence has a negation, a warning or a question (\"{doubt}\")" if doubt
        else f"the sentence has a condition or an alternative (\"{hedge}\")" if hedge
        else f"a later part of the sentence takes something back (\"{taken}\")" if taken
        else ""
    )

    second_hand = next(
        (sentence[a.start : a.end] for a in words
         if a.mention < 0 and not a.used and a.text in _SECOND_HAND), ""
    )

    def live(atom: _Atom) -> bool:
        return atom.sentence not in doubt_sentences

    # --- accounts ---------------------------------------------------------------
    # One closed positive shape binds an account: "pay <payee> ... to [IBAN] X"
    # in one clause, with one payee, one account in the whole sentence and
    # nothing that could make it something other than the place to pay. The
    # test is not "is there a warning word": every condition below has to be
    # met, and anything else leaves the account unbound, so a payment to it
    # is held (P2, or P1 when the vendor file has another account).
    ibans = [a for a in atoms if a.kind == "iban"]
    accounts: dict[str, tuple[str, ...]] = {}

    def pays(clause: int, payee: str) -> bool:
        """The clause tells the agent to pay this payee, and names no one else."""
        here = scan.clause_atoms(clause)
        return any(a.kind == "word" and a.text in PAY_VERBS for a in here) \
            and scan.instructs(clause) and scan.payees_in(clause) == [payee]

    def labelled(atom: _Atom, payee: str) -> tuple[str, int]:
        """The second shape that binds: the account after the label "IBAN" (with
        or without a colon), as the last thing the user wrote, right after the
        instruction to pay the payee or inside it:

            Please pay Fernhill Design for the logo work, EUR 650. IBAN: NL91 ...
            Pay Fernhill Design EUR 650, IBAN NL91 ...

        Only an amount or an invoice number may stand between the instruction
        and the label, and nothing but "thanks" or "please" after the account.
        Returns (why not, or "", index of the label)."""
        index = position[id(atom)]
        label = index - 1
        if not (
            label >= 0 and atoms[label].kind == "word" and atoms[label].mention < 0
            and atoms[label].text == "iban"
            and re.fullmatch(r"[^\S\n]*:?[^\S\n]*", sentence[atoms[label].end : atom.start])
        ):
            return ("the sentence does not give it as the place to pay (\"pay <payee> ... to "
                    "IBAN ...\", or \"IBAN: ...\" right after the instruction)"), index
        clauses = [c for c in dict.fromkeys(a.clause for a in atoms[: label + 1]) if pays(c, payee)]
        if not clauses:
            return ("the account does not follow an instruction to pay "
                    f"{payee} by name"), label
        clause = clauses[-1]
        last = max(i for i, a in enumerate(atoms) if a.clause == clause)
        if clause == atoms[label].clause:
            # "Pay Fernhill Design EUR 650 IBAN X": the word before the label is
            # the payee's name, an amount or an invoice number. Not "from IBAN X".
            before = atoms[label - 1]
            if label == 0 or before.clause != clause or not (
                before.kind in ("amount", "ref")
                or (before.mention >= 0 and scan.mentions[before.mention].payee == payee)
            ):
                return "the words before \"IBAN\" say something else about the account", label
        elif atoms[label].sentence > atoms[last].sentence + 1 or any(
            a.kind not in ("amount", "ref") for a in atoms[last + 1 : label]
        ):
            return ("something other than an amount stands between the instruction to pay "
                    f"{payee} and the account"), label
        if any(not (a.kind == "word" and a.text in _SIGN_OFF) for a in atoms[index + 1 :]):
            return "the sentence says more after the account", label
        return "", label

    def binding(atom: _Atom) -> tuple[str | None, str, int]:
        """(payee, why not, index where the phrase starts) for one account."""
        index = position[id(atom)]
        if len(names) != 1:
            return None, ("the task has more than one payee, so an account is trusted only "
                          "when you assign it yourself (--account PAYEE=IBAN, or the account "
                          "field of the form)"), index
        if len(ibans) != 1:
            return None, "the sentence writes more than one account, or one account twice", index
        if not plain_sentence:
            return None, why_not_plain, index
        if second_hand:
            return None, (f"the sentence says where the account was read (\"{second_hand}\"), "
                          "so it is no better than the message it came from"), index
        if any(ch in _QUOTES for ch in sentence):
            return None, "the sentence quotes someone", index
        payee = names[0]
        j = index - 1
        while j >= 0 and atoms[j].clause == atom.clause and atoms[j].kind == "word" \
                and atoms[j].mention < 0 and atoms[j].text in _ACCOUNT_LABEL | _ACCOUNT_DET:
            j -= 1
        if not (j >= 0 and atoms[j].clause == atom.clause and atoms[j].kind == "word"
                and atoms[j].text in _DESTINATION):
            # Not "to IBAN X". The other shape: "IBAN: X" at the end.
            why, j = labelled(atom, payee)
            if why:
                return None, why, j
            if any(a.kind == "word" and a.text in _ACCOUNT_WORDS and a is not atoms[j]
                   for a in atoms):
                return None, "the sentence says something else about an account", j
        else:
            phrase = {id(a) for a in atoms[j : index + 1]}
            if any(a.kind == "word" and a.text in _ACCOUNT_WORDS and id(a) not in phrase
                   for a in atoms):
                return None, "the sentence says something else about an account", j
            here = scan.clause_atoms(atom.clause)
            if not any(a.kind == "word" and a.text in PAY_VERBS for a in here) \
                    or not scan.instructs(atom.clause) \
                    or payee not in scan.payees_in(atom.clause):
                return None, ("the account is not in the clause that tells the agent to pay "
                              f"{payee} by name"), j
            # Only "... to IBAN X." or "... to IBAN X for <what>", then at most
            # "please", "thanks" or "today", to the end of what the user wrote.
            # Anything else may say something about the account, or take it
            # back ("... to IBAN X. Scrap that.").
            after = atoms[index + 1 :]
            purpose = [a for a in after if a.clause == atom.clause]
            if not all(a.kind == "word" and a.text in _SIGN_OFF for a in after) and not (
                purpose and purpose[0].kind == "word" and purpose[0].text == "for"
                and all(a.kind == "word" and a.text in _SIGN_OFF
                        for a in after if a.clause != atom.clause)
            ):
                return None, "the sentence says more after the account", j
        other = vendors.owner_of(atom.text, other_than=payee)
        if other is not None:
            return None, f"this account is on file for a different vendor, {other.name}", j
        return payee, "", j

    for atom in ibans:
        payee, why, start = binding(atom)
        quote = scan.quote(atoms[start].start, atom.end)
        if payee is None:
            readings.append(Reading(
                "account", None, quote, f"Not trusted: {why}. A payment to it will be held.",
                False,
            ))
            continue
        accounts[payee] = (atom.text,)
        on_file = vendors.accounts_for(payee)
        if on_file and atom.text not in on_file:
            result = (f"Given for {payee}, but the vendor file has a different account and "
                      "it outranks yours: a payment to this account will be held.")
        elif on_file:
            result = f"This is the account already on file for {payee}."
        else:
            result = (f"Trusted for {payee} in this task: a payment to it will not be held "
                      "for being unverified.")
        readings.append(Reading("account", payee, quote, result, True))

    # --- counts and invoice numbers ---------------------------------------------
    def instructing(clause: int) -> bool:
        return any(a.kind == "word" and a.text in PAY_VERBS for a in scan.clause_atoms(clause)) \
            and scan.instructs(clause)

    def number_of(atom: _Atom) -> int | None:
        if atom.kind != "word" or atom.mention >= 0:
            return None
        if atom.text in _NUMBERS:
            return _NUMBERS[atom.text]
        if atom.text.isascii() and atom.text.isdigit() and len(atom.text) <= 2:
            return int(atom.text)
        return None

    def in_instruction(atom: _Atom, number: int) -> bool:
        """A count is read only from the instruction to pay: its clause tells
        the agent to pay, or has no payment verb and continues a clause of
        its sentence that does ("Pay Nimbus's invoice and the two Brightline
        invoices"), or a clause of its sentence that tells the agent to pay
        repeats the number on its own ("Kestrel Legal sent a statement with
        three invoices, please pay all three"). "Kestrel sent three invoices.
        Pay the oldest one." counts nothing to pay."""
        if instructing(atom.clause):
            return True
        own_verb = any(a.kind == "word" and a.text in PAY_VERBS
                       for a in scan.clause_atoms(atom.clause))
        same = sorted({a.clause for a in atoms if a.sentence == atom.sentence})
        if not own_verb and any(instructing(c) for c in same if c < atom.clause):
            return True
        for index, other in enumerate(atoms):
            if other is atom or other.sentence != atom.sentence or number_of(other) != number \
                    or not instructing(other.clause):
                continue
            nxt = atoms[index + 1] if index + 1 < len(atoms) else None
            if nxt is None or nxt.clause != other.clause or not (
                nxt.kind == "ref" or nxt.mention >= 0
                or nxt.text in _INVOICE_ONE | _INVOICE_MANY | _PARTS | _PAYMENTS | _COUNT_ADJ
            ):
                return True  # "all three", "both", "the two" standing alone
        return False

    phrases: dict[str, list[tuple[int, str, str]]] = {}  # payee -> (n, kind, quote)
    per_amount: dict[int, int] = {}  # id(amount atom) -> "N instalments of AMOUNT"
    in_parts: set[int] = set()  # id(amount atom) of "AMOUNT in N instalments"
    unattached_open = False
    open_ended: dict[str, str] = {}
    wide: dict[str, _Atom] = {}  # payee -> a word that asks for more than one ("all")
    for index, atom in enumerate(atoms):
        if atom.kind != "word" or not live(atom) or atom.mention >= 0 or index in in_exclusion:
            continue
        number = number_of(atom)
        if number is None or not 1 <= number <= MAX_COUNT:
            continue
        earlier = [a for a in atoms[max(index - 2, 0) : index] if a.clause == atom.clause]
        if any(a.kind == "word" and (a.text in _NUMBERS or a.text in _BIG_NUMBERS
                                     or a.text.isdigit()) for a in earlier) \
                or sentence[max(atom.start - 1, 0) : atom.start] in "-\u2013.,/":
            continue  # "twenty-five", "two to three", "2-3", "1,500"
        partitive = [a.text for a in earlier if a.kind == "word"]
        if partitive[-1:] == ["of"] or partitive[-2:] in (["of", "the"], ["of", "these"],
                                                           ["of", "those"], ["of", "their"]):
            # "the first of the three invoices", "one of the two emails": it picks
            # from a set and does not count payments. The default applies.
            atom.used = True
            continue
        j = index + 1
        if j + 1 < len(atoms) and atoms[j].clause == atoms[j + 1].clause == atom.clause \
                and atoms[j].kind == atoms[j + 1].kind == "word" and atoms[j].text == "of" \
                and atoms[j + 1].text in ("the", "these", "those", "their", "its", "our", "your"):
            j += 2  # "both of the Marlowe invoices", "all three of the invoices"
        while (
            j < len(atoms) and j - index <= 6 and atoms[j].clause == atom.clause
            and atoms[j].kind == "word"
            and (atoms[j].mention >= 0 or atoms[j].text in _COUNT_ADJ)
        ):
            j += 1
        if j >= len(atoms) or atoms[j].clause != atom.clause:
            continue
        noun = atoms[j]
        label = noun.text
        before = atoms[index - 1] if index else None
        if before is not None and before.kind == "word" and before.text == "the" and index > 1:
            before = atoms[index - 2]
        into = before is not None and before.kind == "word" and before.text in _INTO \
            and before.clause == atom.clause
        of_amount = j + 2 < len(atoms) and atoms[j + 1].kind == "word" \
            and atoms[j + 1].text == "of" and atoms[j + 2].kind == "amount" \
            and atoms[j + 2].clause == atom.clause
        if noun.kind == "word" and label in _PARTS:
            if not (into or of_amount):
                # "two instalments was last year's deal": not "in two instalments".
                readings.append(Reading(
                    "payments", None, scan.quote(atom.start, noun.end),
                    "Not read: instalments are read only as \"in N instalments\" or "
                    "\"N instalments of EUR ...\".", False,
                ))
                continue
            kind = "parts"
        elif noun.kind == "word" and label in _PAYMENTS:
            kind = "parts" if into else "payments"
        elif label in _INVOICE_MANY or (number == 1 and label in _INVOICE_ONE):
            kind = "invoices"
        else:
            continue
        quote = scan.quote(atom.start, noun.end)
        if not in_instruction(atom, number):
            readings.append(Reading(
                "payments", None, quote,
                "Not read: the count is not part of the instruction to pay.", False,
            ))
            continue
        payee, why = scan.owner(atom.clause)
        for used in atoms[index : j + 1]:
            if used.kind == "word":
                used.used = True
        if noun.kind == "ref":
            noun.used = True
        if payee is None:
            readings.append(Reading("payments", None, quote, f"Not read: {why}.", False))
            continue
        phrases.setdefault(payee, []).append((number, kind, quote))
        lead = index - 1
        if lead >= 0 and atoms[lead].kind == "word" and atoms[lead].text == "the":
            lead -= 1
        if kind == "parts" and lead >= 1 and atoms[lead].kind == "word" \
                and atoms[lead].text in _INTO and atoms[lead - 1].kind == "amount" \
                and atoms[lead - 1].clause == atom.clause:
            in_parts.add(id(atoms[lead - 1]))  # "EUR 1,500 in two instalments": the total
        if kind == "parts" and j + 2 < len(atoms) and atoms[j + 1].kind == "word" \
                and atoms[j + 1].text == "of" and atoms[j + 2].kind == "amount" \
                and atoms[j + 2].clause == atom.clause:
            per_amount[id(atoms[j + 2])] = number

    for atom in words:
        if live(atom) and not atom.used and atom.mention < 0 and atom.text in _OPEN_ENDED:
            index = position[id(atom)]
            after = [a for a in atoms[index + 1 : index + 3] if a.clause == atom.clause]
            if after and after[0].kind == "word" and after[0].text == "the":
                after = after[1:]
            if atom.text == "all" and after and number_of(after[0]) is not None:
                continue  # "all three", "all 3": a number, read as a count
            if after and after[0].kind == "word" and after[0].text in _TIME_WORDS:
                continue  # "for another year": not more payments
            payee, _ = scan.owner(atom.clause)
            if payee is None:
                unattached_open = True
            else:
                open_ended.setdefault(payee, sentence[atom.start : atom.end])
                if atom.text in _SEVERAL:
                    wide.setdefault(payee, atom)

    nouns: dict[str, list[tuple[bool, _Atom]]] = {}  # payee -> (plural, atom)
    named: dict[str, list[str]] = {}
    for index, atom in enumerate(atoms):
        if not live(atom) or index in in_exclusion:
            continue  # an invoice the sentence says not to pay is not one to pay
        plural: bool | None = None
        if atom.kind == "word" and atom.mention < 0 and not atom.used:
            plural = True if atom.text in _INVOICE_MANY else False if atom.text in _INVOICE_ONE \
                else None
        elif atom.kind == "ref":
            plural = True if atom.text in _INVOICE_MANY else False if atom.text in _INVOICE_ONE \
                else None
        if plural is None and atom.kind != "ref":
            continue
        payee, why = scan.owner(atom.clause)
        if payee is None:
            if atom.kind == "ref":
                readings.append(Reading(
                    "invoices", None, scan.quote(atom.start, atom.end), f"Not read: {why}.", False,
                ))
            continue
        if plural is False and atom.kind == "word" and nouns.get(payee):
            index = position[id(atom)]
            before = atoms[index - 1] if index else None
            if (
                not scan.payees_in(atom.clause)
                and before is not None and before.kind == "word" and before.text in _ANAPHOR
                and atom.sentence > nouns[payee][0][1].sentence
            ):
                continue  # "The invoice is in the inbox": the one already asked for
        if plural is not None and not atom.used:
            nouns.setdefault(payee, []).append((plural, atom))
        if atom.kind == "ref":
            for name in atom.names:
                keys = {ref_key(n) for n in named.setdefault(payee, [])}
                if ref_key(name) and ref_key(name) not in keys:
                    named[payee].append(name)

    # --- amounts ----------------------------------------------------------------
    stated: dict[str, list[tuple[_Atom, str]]] = {}  # payee -> (atom, level)
    # Every readable amount of a payee per sentence, used or not: two amounts in
    # one sentence ("EUR 480 and EUR 12 late fee") are never read as one.
    seen_amounts: dict[tuple[str, int], list[_Atom]] = {}
    for index, atom in enumerate(atoms):
        if atom.kind != "amount":
            continue
        quote = scan.quote(atom.start, atom.end)
        if not live(atom):
            readings.append(Reading(
                "amount", None, quote,
                "Not read: its sentence has a negation, a warning or a question "
                f"(\"{doubt_sentences[atom.sentence]}\").", False,
            ))
            continue
        if atom.sentence in hedged:
            readings.append(Reading(
                "amount", None, quote,
                "Not read: its sentence has a condition or an alternative "
                f"(\"{hedged[atom.sentence]}\").", False,
            ))
            continue
        if atom.problem or atom.value is None:
            readings.append(Reading("amount", None, quote, f"Not read: {atom.problem}.", False))
            continue
        clause = scan.clause_atoms(atom.clause)
        at = next(i for i, a in enumerate(clause) if a is atom)
        prev = clause[at - 1] if at else None
        nxt = clause[at + 1] if at + 1 < len(clause) else None
        prev_word = prev.text if prev is not None and prev.kind == "word" and not prev.used else ""
        next_word = nxt.text if nxt is not None and nxt.kind == "word" else ""
        beyond = atoms[index + 1] if index + 1 < len(atoms) else None
        if not next_word and beyond is not None and beyond.kind == "word" \
                and beyond.sentence == atom.sentence and beyond.text == "plus":
            next_word = "plus"  # "EUR 480 plus VAT": the amount to pay is not 480
        if prev_word in _APPROX or "~" in sentence[max(atom.start - 2, 0) : atom.start]:
            readings.append(Reading(
                "amount", None, quote, "Not read: an approximate amount is not a stated amount.",
                False,
            ))
            continue
        if prev_word in _BEFORE_AMOUNT_ODD or next_word in _AFTER_AMOUNT_ODD:
            readings.append(Reading(
                "amount", None, quote,
                "Not read: the words next to it make it a difference or a comparison, not an "
                "amount to pay.", False,
            ))
            continue
        payee, why = scan.owner(atom.clause)
        if payee is None:
            readings.append(Reading("amount", None, quote, f"Not read: {why}.", False))
            continue
        seen_amounts.setdefault((payee, atom.sentence), []).append(atom)
        others = [a for a in clause if a is not atom and a.kind == "word" and a.mention < 0]
        verbs = [i for i, a in enumerate(clause[:at]) if a.kind == "word" and a.text in PAY_VERBS]
        sentence_has_verb = any(
            a.text in PAY_VERBS for a in words if a.sentence == atom.sentence
        )
        bare = sentence_has_verb and all(
            a.text in _BARE or a.used for a in others
        ) and not any(a.kind in ("iban", "amount") for a in clause if a is not atom)
        level = ""
        if id(atom) in capped:
            level = "cap"
        elif id(atom) in per_amount:
            level = "loose"
        elif verbs:
            level = "loose"
            verb = max(i for i in verbs if clause[i].text in _DIRECT_VERBS) \
                if any(clause[i].text in _DIRECT_VERBS for i in verbs) else -1
            if verb >= 0 and all(a.kind == "word" and a.text in _BEFORE_VERB
                                 for a in clause[:verb]):
                between = clause[verb + 1 : at]
                mention_atoms = [a for a in between if a.mention >= 0]
                rest = [a for a in between if a.mention < 0]
                following = clause[at + 1 :]
                k = 0
                while k < len(following) and following[k].kind == "word" \
                        and following[k].mention < 0 and following[k].text in _FILL_TO_PAYEE:
                    k += 1
                payee_follows = k < len(following) and following[k].mention >= 0 and k >= 1 \
                    and following[0].text == "to"
                fill_ok = all(a.kind == "word" and a.text in _FILL for a in rest)
                if fill_ok and mention_atoms and not payee_follows:
                    level = "exact"  # Pay <payee> EUR 650
                elif fill_ok and not mention_atoms and (
                    payee_follows or not scan.payees_in(atom.clause)
                ):
                    level = "exact"  # Pay EUR 650 to <payee>; Pay EUR 650
        elif bare:
            level = "loose"
        elif sentence_has_verb and at == 0 and (not next_word or next_word in _LEADING_NEXT):
            level = "loose"  # ", EUR 650 for the logo work"
        if level and scan.shared(atom.clause, "amount"):
            readings.append(Reading(
                "amount", None, quote,
                "Not read: it could be meant for more than one of the payees joined by "
                "\"and\".", False,
            ))
            continue
        if not level:
            readings.append(Reading(
                "amount", None, quote,
                "Not read: it does not stand with a payment verb, so it may not be an amount "
                "to pay.", False,
            ))
            continue
        stated.setdefault(payee, []).append((atom, level))

    def more_asked(payee: str, sources: list[_Atom]) -> str:
        """Words joined by "and" to this payee's invoice that were not read
        ("... and the late fee"): the sentence may ask for more than was counted."""
        numbers = {a.sentence for a in sources if live(a)}
        for clause, other in sorted(scan.joined.items()):
            here = scan.clause_atoms(clause)
            if not here or here[0].sentence not in numbers:
                continue
            named = scan.payees_in(clause)
            if any(name != payee for name in named):
                continue
            if not named and scan.payees_in(other) not in ([payee], []) :
                continue
            if any(a.kind == "ref" or (a.kind == "word" and a.text in _INVOICE_ONE | _INVOICE_MANY)
                   for a in here):
                continue
            if all(a.kind == "word" and (a.used or a.mention >= 0) for a in here):
                continue
            return scan.quote(here[0].start, here[-1].end)
        return ""

    # --- one Ask per payee --------------------------------------------------------
    asks: dict[str, Ask] = {}
    for payee in names:
        ended = open_ended.get(payee) or ("an open-ended word" if unattached_open else "")
        found = phrases.get(payee, [])
        mine = nouns.get(payee, [])
        refs = named.get(payee, [])
        clash = [r for r in refs if ref_key(r) in excluded_refs.get(payee, set())]
        if clash:
            # "Pay MPW-118 and MPW-119. Not MPW-119.": the list is not read.
            readings.append(Reading(
                "invoices", payee, ", ".join(refs),
                f"Not read: the sentence also says not to pay {', '.join(clash)}.", False,
            ))
            refs = []
        payments: int | None = None
        instalments = False  # "in two instalments": the parts of one invoice
        source = ""
        parts = [p for p in found if p[1] == "parts"]
        rest = [p for p in found if p[1] != "parts"]
        if len(parts) == 1 and all(p[0] == 1 and p[1] == "invoices" for p in rest) \
                and len(refs) <= 1 and not any(plural for plural, _ in mine):
            payments, instalments, source = parts[0][0], True, parts[0][2]
        elif len(found) == 1 and not parts:
            payments, source = found[0][0], found[0][2]
            if refs and len(refs) != payments:
                readings.append(Reading(
                    "payments", payee, source,
                    f"Not read: the sentence counts {payments} but names {len(refs)} "
                    "invoice number(s).", False,
                ))
                payments, source = None, ""
        elif found:
            readings.append(Reading(
                "payments", payee, "; ".join(p[2] for p in found),
                "Not read: the sentence gives more than one count for this payee.", False,
            ))
        elif refs:
            payments = len(refs)
            source = ", ".join(refs)
        elif len(mine) == 1 and not mine[0][0]:
            payments = 1
            source = scan.quote(mine[0][1].start, mine[0][1].end)

        counted = bool(found)
        also = ""  # "... and the late fee": something more is asked for
        if not ended and not counted and (payments is not None or refs):
            also = ended = more_asked(
                payee, [a for _, a in mine] + [a for a in atoms if a.kind == "ref"])
        if ended and (payments is not None or refs):
            readings.append(Reading(
                "payments", payee, ended,
                "Not read as a count or as a list of invoices: the sentence is open-ended "
                f"about {payee}, or asks for something more.", False,
            ))
            payments, instalments, refs = None, False, []
        if len(refs) > MAX_NAMED:
            refs = []
        if payments is not None and payments >= 2 and not plain_sentence:
            readings.append(Reading(
                "payments", payee, source,
                f"Not read: {why_not_plain}. A count of more than one is read only from a "
                "plain instruction.", False,
            ))
            payments, instalments = None, False

        amount: Decimal | None = None
        mine_amounts = stated.get(payee, [])
        crowded = [a for a, _ in mine_amounts
                   if len(seen_amounts.get((payee, a.sentence), [])) > 1]
        if len(mine_amounts) == 1 and crowded:
            together = seen_amounts[(payee, crowded[0].sentence)]
            readings.append(Reading(
                "amount", payee, "; ".join(scan.quote(a.start, a.end) for a in together),
                f"Not read: its sentence gives more than one amount for {payee}.", False,
            ))
        elif len(mine_amounts) > 1:
            readings.append(Reading(
                "amount", payee, "; ".join(scan.quote(a.start, a.end) for a, _ in mine_amounts),
                f"Not read: the sentence gives more than one amount for {payee}.", False,
            ))
        elif mine_amounts and not crowded:
            atom = mine_amounts[0][0]
            quote = scan.quote(atom.start, atom.end)
            value = atom.value
            index = position[id(atom)]
            around = [a.text for a in atoms[max(index - 3, 0) : index + 4]
                      if a.kind == "word" and a.clause == atom.clause]
            each = index + 1 < len(atoms) and atoms[index + 1].kind == "word" \
                and atoms[index + 1].text in _EACH
            total = any(word in _TOTAL for word in around) or id(atom) in in_parts
            note = ""
            if id(atom) in per_amount and payments == per_amount[id(atom)]:
                amount = value * payments
            elif each and payments is not None:
                amount = value * payments
            elif each or id(atom) in per_amount:
                readings.append(Reading(
                    "amount", payee, quote,
                    "Not read: it is an amount for each payment, and the number of payments "
                    "was not read.", False,
                ))
            elif payments is not None and payments >= 2 and not total:
                # It could be the amount of each payment or of all of them. The
                # larger reading is taken: it is still narrower than none.
                amount = value * payments
                note = (f" It could also mean {money(value)} for all {payments} together; "
                        "the larger reading was taken.")
            else:
                amount = value
            if amount is not None:
                if atom.text == "unsure":
                    note += (f" \"{quote}\" was read as {money(value)}; check the separator.")
                readings.append(Reading(
                    "amount", payee, quote,
                    f"At most {money(amount)} in total for {payee}. A payment that takes the "
                    f"task above it will be held. The unusual-amount check still applies."
                    + note, True,
                ))

        if payments is not None:
            what = (f"{payments} payments (instalments of one invoice)" if instalments
                    else f"{payments} payment{'' if payments == 1 else 's'}")
            readings.append(Reading(
                "payments", payee, source,
                f"{what}. A further payment to {payee} will be held.", True,
            ))
        else:
            # Not stated: the Ask keeps no count, so a count a person types for
            # the task (--payments-for) is not outranked by this default. When
            # the sentence asks for several payments without a number ("all
            # the open invoices", "the invoice and the late fee"), it says so.
            # It does not guess a number.
            plural = [a for is_plural, a in mine if is_plural]
            several = also
            if payee in wide or plural:
                first = wide.get(payee) or plural[0]
                last = next((a for a in plural if a.clause == first.clause
                             and a.start >= first.start), first)
                several = scan.quote(first.start, last.end)  # "all the open ... invoices"
            expected = f"{DEFAULT_PAYMENTS} payment{'' if DEFAULT_PAYMENTS == 1 else 's'}"
            if several:
                why = (f"the sentence asks for more than one payment to {payee} "
                       f"(\"{several}\") but does not say how many: expecting "
                       f"{DEFAULT_PAYMENTS} unless you set a number.")
            elif found:
                why = "the count in the sentence was not read (see below)."
            else:
                why = "the sentence does not say how many."
            readings.append(Reading(
                "payments", payee, "",
                f"{expected}: {why} A further payment to {payee} will be held. To expect "
                f"more, set the number: --payments-for \"{payee}=N\" on the command line, "
                "or the \"Expect ... payment(s)\" box on the confirmation form.", True,
            ))
        if refs:
            readings.append(Reading(
                "invoices", payee, ", ".join(refs),
                "Only these invoices may be paid. A payment with another invoice number will "
                "be refused.", True,
            ))
        asks[payee] = Ask(amount=amount, payments=payments, invoices=tuple(refs),
                          instalments=instalments and (payments or 0) >= 2)

    # Numbers that look like money but carry no currency are pointed out, not read.
    for match in _BARE_NUMBER.finditer(scan.masked):
        text = match.group()
        digits = sum(ch.isdigit() for ch in text)
        if digits < 3 and not re.search(r"[.,][0-9]{2}$", text):
            continue  # "2 invoices", "1 payment"
        near = [a for a in atoms if a.start <= match.start() < a.end]
        if near and (near[0].used or not live(near[0])):
            continue
        readings.append(Reading(
            "amount", None, text,
            "Not read: a number without EUR or a euro sign is not taken as an amount.", False,
        ))
    return done(accounts, asks)


# --- for the person who confirms -------------------------------------------------


def describe_draft(draft: Draft) -> list[str]:
    """What the confirmation screen has to show about a draft, as lines of text.

    The payees and the vendors named but not included, every reading with the
    words it came from and what it will do, every phrase that was seen and not
    used, and the accounts in the sentence that are not trusted.
    """
    lines: list[str] = []
    if draft.mentioned:
        lines.append("  Named in your sentence but NOT a payee (add one only if you mean it): "
                     + ", ".join(draft.mentioned))
    used = [r for r in draft.readings if r.used]
    unused = [r for r in draft.readings if not r.used]
    if used:
        lines.append("  Read from your sentence (check every line):")
        for payee in draft.payees:
            mine = [r for r in used if r.payee == payee]
            if not mine:
                continue
            lines.append(f"    {payee}")
            for reading in mine:
                quote = f"\"{reading.quote}\"" if reading.quote else "(default)"
                lines.append(f"      {reading.field:<9} {quote}: {reading.result}")
    else:
        lines.append("  Read from your sentence: nothing. Only the limits above apply.")
    if unused:
        lines.append("  Seen in your sentence and not used:")
        for reading in unused:
            who = f" ({reading.payee})" if reading.payee else ""
            lines.append(f"      {reading.field:<9} \"{reading.quote}\"{who}: {reading.result}")
    if draft.unbound:
        lines.append(
            "  Accounts in your sentence that are NOT trusted: "
            + ", ".join(fmt_iban(a) for a in draft.unbound)
        )
    return lines
