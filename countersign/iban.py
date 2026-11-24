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
spaces that appear when an IBAN is copied out of a web page or a PDF. In text
(`find_ibans`), the gap between two groups may also be a run of spaces, tabs
and non-breaking spaces: "DE55  4719" shows on a screen as one account. It
never runs across a line break.

Text the agent read (and only that text) is also read the way a screen shows
it: `find_ibans(text, rendered=True)`. Inside one run of inline text it undoes
what an HTML renderer undoes and nothing else:

* character references (`&nbsp;`, `&#78;`, `&#x41;`) become the character;
* inline tags (`<b>`, `</span>`, `<wbr>`) and characters that show nothing
  (zero-width spaces, soft hyphens) are dropped;
* any Unicode space counts as a separator between groups.

It never joins across a block element or a line break (`<p>`, `<div>`,
`<br>`, `<td>`, any tag it does not know), an HTML comment, an attribute, or
a line break in the text, and it never decodes anything else (reversed text,
base64, quoted-printable). An account found only this way is marked
`rendered`, so a person is told it is not written as one piece. This is safe
by construction for one reason: a sighting in untrusted text is never a
reason to pay. It only turns "seen nowhere" (refused) into "a document asked
for it" (a person decides). The user's own sentence, the agent's `account`
argument and the vendor file are always read strictly.
"""

from __future__ import annotations

import bisect
import html
import re
import unicodedata
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
# find_ibans only: these may repeat between two groups (a gap of spaces, tabs
# and non-breaking spaces inside one line). A hyphen or a dot stays single.
_GAP = frozenset(" \t\u00a0\u2007\u2009\u202f")
# Two letters and two digits that do not continue a longer run of letters/digits.
_START = re.compile(r"(?<![A-Za-z0-9])[A-Za-z]{2}[0-9]{2}")
_LABEL = re.compile(r"(?:IBAN\s*[:.]?\s+)?", re.IGNORECASE)


# rendered=True only. Elements whose content a renderer draws inside the same
# run of text (HTML "phrasing content"). Every other tag ends the run.
_INLINE_TAGS = frozenset({
    "a", "abbr", "b", "bdi", "bdo", "big", "cite", "code", "data", "del", "dfn", "em",
    "font", "i", "ins", "kbd", "mark", "nobr", "q", "s", "samp", "small", "span", "strike",
    "strong", "sub", "sup", "time", "tt", "u", "var", "wbr",
})
_INVISIBLE = "\u00ad\u200b\u200c\u200d\u2060\ufeff"
_MARKUP = re.compile(
    r"(?P<comment><!--.*?(?:-->|\Z))"
    r"|(?P<tag></?(?P<name>[A-Za-z][A-Za-z0-9:-]{0,40})(?:[\s/][^<>]{0,2000})?>)"
    r"|(?P<ref>&(?:#[0-9]{1,7}|#[xX][0-9A-Fa-f]{1,6}|[A-Za-z][A-Za-z0-9]{1,31});)"
    r"|(?P<invisible>[" + _INVISIBLE + r"])",
    re.DOTALL,
)
# Text that reads the same rendered and raw needs no second scan.
_NEEDS_RENDERING = re.compile(r"[<&" + _INVISIBLE + r"]|[^\x00-\x7f]")


@dataclass(frozen=True)
class IbanMatch:
    account: str  # canonical form
    start: int  # offset of the first character in the text
    end: int  # offset just past the last character
    # True when the account is only found by reading through inline markup:
    # it is not written in the text as one piece.
    rendered: bool = False


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


def _is_separator(ch: str, wide: bool) -> bool:
    """One character that may stand between two groups. `wide` adds every
    Unicode space (rendered reading only)."""
    return ch in _SEPARATORS or (wide and unicodedata.category(ch) == "Zs")


def _gap_end(text: str, pos: int, wide: bool) -> int:
    """Where a run of spaces, tabs and non-breaking spaces starting at `pos`
    ends (`pos` itself when there is none). `wide` adds every Unicode space.
    A line break is never part of it."""
    end = pos
    while end < len(text) and (text[end] in _GAP
                               or (wide and unicodedata.category(text[end]) == "Zs")):
        end += 1
    return end


def _read_at(text: str, start: int, wide: bool = False, gaps: bool = False) -> IbanMatch | None:
    """Read one IBAN starting exactly at `start`, or return None. `gaps` lets
    a run of spaces, tabs and non-breaking spaces stand between two groups."""
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
            continue
        if not chars:
            break
        after = _gap_end(text, pos, wide) if gaps else pos
        if after == pos and _is_separator(ch, wide):
            after = pos + 1  # one separator between groups
        if after == pos or after >= len(text) or text[after] not in _ALNUM:
            break
        pos = after
    if len(chars) != length:
        return None
    end = last + 1
    if end < len(text) and text[end] in _ALNUM:
        return None  # runs straight on into more letters or digits
    account = "".join(chars)
    return IbanMatch(account, start, end) if checksum_ok(account) else None


def _scan(text: str, wide: bool = False) -> list[IbanMatch]:
    matches: list[IbanMatch] = []
    pos = 0
    while True:
        candidate = _START.search(text, pos)
        if candidate is None:
            return matches
        match = _read_at(text, candidate.start(), wide, gaps=True)
        if match is None:
            pos = candidate.start() + 1
        else:
            matches.append(match)
            pos = match.end


def _render(text: str) -> tuple[str, list[int], list[int], list[int]]:
    """The text as a screen shows it, one run of inline text at a time.

    Returns the rendered text and, for every piece of it, where it starts in
    the rendered text, where its source starts, and whether it is copied one
    to one (-1) or stands for a source span of that length (a character
    reference, or a break). Breaks are written as a line feed, which no
    account can run across.
    """
    out: list[str] = []
    r_starts: list[int] = []
    s_starts: list[int] = []
    spans: list[int] = []
    r = 0
    pos = 0

    def piece(rendered: str, source: int, span: int) -> None:
        nonlocal r
        out.append(rendered)
        r_starts.append(r)
        s_starts.append(source)
        spans.append(span)
        r += len(rendered)

    for token in _MARKUP.finditer(text):
        if token.start() > pos:
            piece(text[pos:token.start()], pos, -1)
        width = token.end() - token.start()
        if token.group("ref") is not None:
            shown = html.unescape(token.group("ref"))
            for ch in shown:
                piece(ch, token.start(), width)
        elif token.group("tag") is not None:
            if token.group("name").lower() not in _INLINE_TAGS:
                piece("\n", token.start(), width)  # a block, a line break, or unknown
        elif token.group("comment") is not None:
            piece("\n", token.start(), width)
        # an invisible character shows nothing: no piece
        pos = token.end()
    if pos < len(text):
        piece(text[pos:], pos, -1)
    return "".join(out), r_starts, s_starts, spans


def _source(index: int, r_starts: list[int], s_starts: list[int], spans: list[int],
            end: bool) -> int:
    """Where rendered character `index` comes from: its first source offset,
    or (with `end`) the offset just past it."""
    at = bisect.bisect_right(r_starts, index) - 1
    if spans[at] < 0:
        offset = s_starts[at] + (index - r_starts[at])
        return offset + 1 if end else offset
    return s_starts[at] + spans[at] if end else s_starts[at]


def find_ibans(text: str, *, rendered: bool = False) -> list[IbanMatch]:
    """Every valid IBAN written in `text`, in order, without overlaps.

    With `rendered` (text the agent read; see the module text), also every
    account a screen would show inside one run of inline text, marked
    `rendered` where it does not overlap an account written as one piece.
    Offsets are always offsets into `text` as given, markup included.
    """
    strict = _scan(text)
    if not rendered or not _NEEDS_RENDERING.search(text):
        return strict
    shown, r_starts, s_starts, spans = _render(text)
    found = list(strict)
    index = 0
    for match in _scan(shown, wide=True):
        start = _source(match.start, r_starts, s_starts, spans, False)
        end = _source(match.end - 1, r_starts, s_starts, spans, True)
        while index < len(strict) and strict[index].end <= start:
            index += 1
        if index < len(strict) and strict[index].start < end:
            continue  # overlaps an account written as one piece: that one stands
        found.append(IbanMatch(match.account, start, end, True))
    found.sort(key=lambda m: (m.start, m.end))
    return found


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

