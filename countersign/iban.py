"""IBAN parsing: the one place that decides what counts as an account number.

Countersign only moves money to IBANs. An account is identified by its
canonical form: upper-case letters and digits, no spaces. Everything here is
exact matching on whole, checksum-valid IBANs:

* `canonical_iban` accepts one account as an agent or a person would type it
  and returns the canonical form, or None if it is not a valid IBAN.
* `find_ibans` finds every valid IBAN written in a piece of text, with the
  position of each, so origin tracking can say exactly where an account was
  seen. It never matches part of a longer run of letters and digits, and it
  never joins text across words that are not an IBAN.

Validation is the ISO 13616 rule: known country code, the fixed length for
that country, and the mod-97 check digits. Letters and digits must be ASCII,
so look-alike Unicode characters are never folded into an account. Groups may
be separated by one space, hyphen or dot, including the non-breaking and thin
spaces that appear when an IBAN is copied out of a web page or a PDF.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Total IBAN length per country (ISO 13616 registry).
IBAN_LENGTHS: dict[str, int] = {
    "AD": 24, "AE": 23, "AL": 28, "AT": 20, "AZ": 28, "BA": 20, "BE": 16, "BG": 22,
    "BH": 22, "BI": 27, "BR": 29, "BY": 28, "CH": 21, "CR": 22, "CY": 28, "CZ": 24,
    "DE": 22, "DJ": 27, "DK": 18, "DO": 28, "EE": 20, "EG": 29, "ES": 24, "FI": 18,
    "FK": 18, "FO": 18, "FR": 27, "GB": 22, "GE": 22, "GI": 23, "GL": 18, "GR": 27,
    "GT": 28, "HR": 21, "HU": 28, "IE": 22, "IL": 23, "IQ": 23, "IS": 26, "IT": 27,
    "JO": 30, "KW": 30, "KZ": 20, "LB": 28, "LC": 32, "LI": 21, "LT": 20, "LU": 20,
    "LV": 21, "LY": 25, "MC": 27, "MD": 24, "ME": 22, "MK": 19, "MN": 20, "MR": 27,
    "MT": 31, "MU": 30, "NI": 28, "NL": 18, "NO": 15, "OM": 23, "PK": 24, "PL": 28,
    "PS": 29, "PT": 25, "QA": 29, "RO": 24, "RS": 22, "RU": 33, "SA": 24, "SC": 31,
    "SD": 18, "SE": 24, "SI": 19, "SK": 24, "SM": 27, "SO": 23, "ST": 25, "SV": 28,
    "TL": 23, "TN": 24, "TR": 26, "UA": 29, "VA": 22, "VG": 24, "XK": 20, "YE": 30,
}

_ALNUM = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
_SEPARATORS = frozenset(" -.\u00a0\u2007\u2009\u202f")
# Two letters and two digits that do not continue a longer run of letters/digits.
_START = re.compile(r"(?<![A-Za-z0-9])[A-Za-z]{2}[0-9]{2}")
_LABEL = re.compile(r"(?:IBAN\s*[:.]?\s+)?", re.IGNORECASE)


@dataclass(frozen=True)
class IbanMatch:
    account: str  # canonical form
    start: int  # offset of the first character in the text
    end: int  # offset just past the last character


def checksum_ok(account: str) -> bool:
    """The ISO 13616 test on a canonical (upper-case, no spaces) string.

    The check digits must be 02 to 98 (00, 01 and 99 are never issued, and
    allowing them would give some accounts a second spelling), and the whole
    number must leave 1 when divided by 97.
    """
    digits = account[2:4]
    if not (digits.isascii() and digits.isdigit() and 2 <= int(digits) <= 98):
        return False
    rearranged = account[4:] + account[:4]
    try:
        return int("".join(str(int(ch, 36)) for ch in rearranged)) % 97 == 1
    except ValueError:
        return False


def is_canonical_iban(account: str) -> bool:
    """True if `account` is already a valid IBAN in canonical form."""
    return (
        isinstance(account, str)
        and account.isascii()
        and account.isalnum()
        and account == account.upper()
        and IBAN_LENGTHS.get(account[:2]) == len(account)
        and account[2:4].isdigit()
        and checksum_ok(account)
    )


def _read_at(text: str, start: int) -> IbanMatch | None:
    """Read one IBAN starting exactly at `start`, or return None."""
    length = IBAN_LENGTHS.get(text[start : start + 2].upper())
    if length is None:
        return None
    chars: list[str] = []
    pos = start
    last = start
    while len(chars) < length and pos < len(text):
        ch = text[pos]
        if ch in _ALNUM:
            chars.append(ch.upper())
            last = pos
            pos += 1
        elif ch in _SEPARATORS and chars and pos + 1 < len(text) and text[pos + 1] in _ALNUM:
            pos += 1  # one separator between groups
        else:
            break
    if len(chars) != length:
        return None
    end = last + 1
    if end < len(text) and text[end] in _ALNUM:
        return None  # runs straight on into more letters or digits
    account = "".join(chars)
    return IbanMatch(account, start, end) if checksum_ok(account) else None


def find_ibans(text: str) -> list[IbanMatch]:
    """Every valid IBAN written in `text`, in order, without overlaps."""
    matches: list[IbanMatch] = []
    pos = 0
    while True:
        candidate = _START.search(text, pos)
        if candidate is None:
            return matches
        match = _read_at(text, candidate.start())
        if match is None:
            pos = candidate.start() + 1
        else:
            matches.append(match)
            pos = match.end


def canonical_iban(raw: object) -> str | None:
    """The canonical form of one account as typed, or None if it is not a valid IBAN.

    Accepts upper or lower case, one separator between groups, and an optional
    leading "IBAN" label. Anything else, including non-ASCII letters or digits
    and trailing text, is refused.
    """
    if not isinstance(raw, str) or len(raw) > 100:
        return None
    text = raw.strip()
    start = _LABEL.match(text).end()
    if not _START.match(text, start):
        return None
    match = _read_at(text, start)
    if match is None or match.end != len(text):
        return None
    return match.account


def fmt_iban(account: str) -> str:
    """Groups of four, the way invoices print it."""
    return " ".join(account[i : i + 4] for i in range(0, len(account), 4))

