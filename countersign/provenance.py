"""Origin tracking: where was an account number written?

The guard sees every piece of text the agent is given. The instruction the
user typed has origin USER. Everything else (emails, invoices, web pages, tool
results) is UNTRUSTED, because an attacker can write it.

An account counts as "seen" in a text only if the text contains that exact
IBAN: a whole, checksum-valid token found by `iban.find_ibans`. There is no
substring matching, so words in a sentence or part of a longer number never
count. The tracker keeps each text and the position of every IBAN in it, so a
decision can point at the exact place.

Untrusted text is also read the way a screen shows it
(`find_ibans(rendered=True)`: `NL91&nbsp;ABNA&nbsp;...` is that account). An
account found only that way is marked, so a person is told it is not written
as one piece. The user's instruction is read strictly, because an account
found there can be trusted for a payee.

Being seen is never a reason to pay. It only separates "an account from
nowhere" (refused) from "an account a document asked for" (a person decides).

The tracker also knows which text of a document a reader does not see
(`hidden_text`): text styled not to show, white or tiny text, comments, and
alt and title attributes. Rule T1 holds a payment whose amount or invoice
number is written there. That too can only make a payment wait.
"""

from __future__ import annotations

import html
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any

from .iban import _MARKUP, IbanMatch, _render, find_ibans
from .models import SightingRef, clean_label

USER_SOURCE = "your instruction"
UNNAMED = "unnamed document"


class Origin(str, Enum):
    USER = "user"
    UNTRUSTED = "untrusted"


# --- text a reader does not see ------------------------------------------------------

# Elements that hold no content of their own (nothing to close).
_VOID = frozenset({"area", "base", "br", "col", "embed", "hr", "img", "input", "keygen", "link",
                   "meta", "param", "source", "track", "wbr"})
# Elements whose content a screen never shows.
_UNSHOWN = frozenset({"script", "style", "template"})
# Attributes whose text a reader does not see on the page.
_UNSHOWN_ATTRIBUTES = frozenset({"alt", "title", "aria-label", "aria-description", "placeholder"})
_ATTRIBUTE = re.compile(
    r"""([A-Za-z_:][-A-Za-z0-9_:.]*)(?:\s*=\s*("[^"]*"|'[^']*'|[^\s"'=<>`]+))?""")
_LENGTH = re.compile(r"(-?[0-9]*\.?[0-9]+)\s*([a-z%]*)")
_NAMED_COLOURS = {"white": (255, 255, 255), "black": (0, 0, 0), "snow": (255, 250, 250),
                  "ivory": (255, 255, 240), "whitesmoke": (245, 245, 245)}
_WHITE = (255, 255, 255)
_INLINE = frozenset({
    "a", "abbr", "b", "bdi", "bdo", "big", "cite", "code", "data", "del", "dfn", "em",
    "font", "i", "ins", "kbd", "mark", "nobr", "q", "s", "samp", "small", "span", "strike",
    "strong", "sub", "sup", "time", "tt", "u", "var", "wbr",
})


def _colour(value: str) -> tuple[int, ...] | str | None:
    """(r, g, b), "transparent", or None when the value is not one we read."""
    value = value.strip().lower()
    if value in _NAMED_COLOURS:
        return _NAMED_COLOURS[value]
    if value == "transparent":
        return "transparent"
    if re.fullmatch(r"#[0-9a-f]{3}", value):
        return tuple(int(c * 2, 16) for c in value[1:])
    if re.fullmatch(r"#[0-9a-f]{6}([0-9a-f]{2})?", value):
        if len(value) == 9 and int(value[7:], 16) == 0:
            return "transparent"
        return tuple(int(value[i:i + 2], 16) for i in (1, 3, 5))
    found = re.fullmatch(r"rgba?\(([^)]*)\)", value)
    if found:
        parts = [p.strip() for p in found.group(1).replace("/", ",").split(",")]
        try:
            if len(parts) == 4 and float(parts[3].rstrip("%")) == 0:
                return "transparent"
            return tuple(min(max(int(float(p.rstrip("%"))), 0), 255) for p in parts[:3])
        except ValueError:
            return None
    return None


def _first_colour(value: str) -> tuple[int, ...] | str | None:
    """The colour in a `background` value such as "#333 url(x.png) no-repeat"."""
    for word in re.findall(r"rgba?\([^)]*\)|#[0-9a-fA-F]+|[A-Za-z]+", value):
        colour = _colour(word)
        if colour is not None:
            return colour
    return None


def _length(value: str) -> tuple[float, str] | None:
    found = _LENGTH.match(value.strip())
    return (float(found.group(1)), found.group(2)) if found else None


def _shows(element: str, attributes: dict[str, str], background: Any) -> tuple[bool, Any]:
    """Does this element show its text, and what background does it draw on?
    `background` is the one it inherits."""
    if element in _UNSHOWN or "hidden" in attributes:
        return False, background
    style: dict[str, str] = {}
    for part in attributes.get("style", "").split(";"):
        name, colon, value = part.partition(":")
        if colon:
            style[name.strip().lower()] = value.replace("!important", "").strip().lower()
    own = style.get("background-color") or style.get("background") or attributes.get("bgcolor")
    if own:
        background = _first_colour(own) or background
    if style.get("display") == "none" or style.get("visibility") in ("hidden", "collapse") \
            or style.get("mso-hide") == "all":
        return False, background
    opacity = _length(style.get("opacity", ""))
    if opacity is not None and opacity[0] <= (10 if opacity[1] == "%" else 0.1):
        return False, background
    size = _length(style.get("font-size", ""))
    if size is not None:
        number, unit = size
        if number <= 0 or (unit in ("px", "pt") and number <= 1) \
                or (unit in ("em", "rem") and number <= 0.1) or (unit == "%" and number <= 10):
            return False, background
    if style.get("overflow") == "hidden":
        for name in ("height", "max-height", "width", "max-width"):
            measure = _length(style.get(name, ""))
            if measure is not None and measure[0] <= 0:
                return False, background
    for name in ("text-indent", "left", "top", "margin-left", "margin-top"):
        measure = _length(style.get(name, ""))
        if measure is not None and measure[0] <= -999:
            return False, background
    colour = style.get("color") or attributes.get("color")
    if colour:
        seen = _colour(colour)
        if seen == "transparent":
            return False, background
        if isinstance(seen, tuple) and isinstance(background, tuple) \
                and max(abs(a - b) for a, b in zip(seen, background)) <= 16:
            return False, background  # text in the colour of what it is drawn on
    return True, background


def hidden_text(text: str) -> str:
    """The text of a document that a reader does not see, as a screen would
    write it out (character references decoded, inline tags dropped), one
    hidden part per line.

    Hidden means: inside an element styled not to show (display:none,
    visibility:hidden, opacity 0, a font size of 0 or 1px, a height of 0
    with overflow hidden, pushed far off the page), text in the colour of
    its background (white on the page, or the background an element sets),
    script, style and template elements, elements with a `hidden` attribute,
    HTML comments, and alt, title and aria-label attributes. It uses the same
    reading of markup as `iban.find_ibans`. Text with no markup has none."""
    if "<" not in text:
        return ""
    out: list[str] = []
    stack: list[tuple[str, bool, Any]] = []  # element, shows, background

    def shown() -> bool:
        return stack[-1][1] if stack else True

    def background() -> Any:
        return stack[-1][2] if stack else _WHITE

    pos = 0
    for token in _MARKUP.finditer(text):
        if token.start() > pos and not shown():
            out.append(html.unescape(text[pos:token.start()]))
        pos = token.end()
        if token.group("comment") is not None:
            body = token.group("comment")
            out.append("\n" + html.unescape(body[4:-3] if body.endswith("-->") else body[4:]) + "\n")
        elif token.group("ref") is not None:
            if not shown():
                out.append(html.unescape(token.group("ref")))
        elif token.group("tag") is not None:
            tag = token.group("tag")
            name = token.group("name").lower()
            attributes = {key.lower(): html.unescape(value.strip("'\"")) if value else ""
                          for key, value in _ATTRIBUTE.findall(tag[len(name) + 1:-1])}
            for key in _UNSHOWN_ATTRIBUTES:
                if attributes.get(key):
                    out.append("\n" + attributes[key] + "\n")
            if name not in _INLINE and not shown():
                out.append("\n")
            if tag.startswith("</"):
                for at in range(len(stack) - 1, -1, -1):
                    if stack[at][0] == name:
                        was = shown()
                        del stack[at:]
                        if not was and shown():
                            out.append("\n")
                        break
            elif name not in _VOID and not tag.endswith("/>"):
                shows, ground = _shows(name, attributes, background())
                stack.append((name, shown() and shows, ground))
    if pos < len(text) and not shown():
        out.append(html.unescape(text[pos:]))
    return "\n".join(line.strip() for line in "".join(out).split("\n") if line.strip())


def seen_ibans(origin: Origin, text: str) -> list[IbanMatch]:
    """The accounts written in one text: strictly in the user's own words,
    also through inline markup in anything the agent read."""
    return find_ibans(text, rendered=origin is Origin.UNTRUSTED)


@dataclass(frozen=True)
class Observation:
    """One text the guard was shown, with the IBANs found in it."""

    origin: Origin
    name: str  # as given; for untrusted text the sender chose it
    text: str
    matches: tuple[IbanMatch, ...]
    hidden: str = ""  # untrusted text only: what a reader does not see (`hidden_text`)

    @property
    def label(self) -> str:
        """The name used when a person is told about this text."""
        if self.origin is Origin.USER:
            return USER_SOURCE
        return clean_label(self.name) or UNNAMED


class ProvenanceTracker:
    def __init__(self) -> None:
        self._seen: list[Observation] = []
        self._index: dict[tuple[Origin, str, str], Observation] = {}
        # Worked out when first asked, then kept: the rendered text of each
        # observation (by its place in `_seen`), for D4.
        self._shown: dict[int, str] = {}
        # Documents the agent read that were too large to keep (`Guard.observe`):
        # what they hide cannot be known, so T1 and D4 assume the worst.
        self.unread = 0

    def find(self, origin: Origin, source: str, text: str) -> Observation | None:
        """The observation already kept for this exact text, if any."""
        name = USER_SOURCE if origin is Origin.USER else source
        return self._index.get((origin, name, text))

    def observe(
        self,
        origin: Origin,
        source: str,
        text: str,
        matches: tuple[IbanMatch, ...] | None = None,
        hidden: str | None = None,
    ) -> Observation:
        """Keep one text, the IBANs in it and, for untrusted text, the part a
        reader does not see. The same text twice is kept once.

        `matches` is `seen_ibans(origin, text)` and `hidden` is
        `hidden_text(text)` when the caller already has them (a saved state).
        """
        name = USER_SOURCE if origin is Origin.USER else source
        key = (origin, name, text)
        known = self._index.get(key)
        if known is not None:
            return known
        found = tuple(seen_ibans(origin, text)) if matches is None else tuple(matches)
        if origin is not Origin.UNTRUSTED:
            hidden = ""
        elif hidden is None:
            hidden = hidden_text(text)
        observation = Observation(origin, name, text, found, hidden)
        self._seen.append(observation)
        self._index[key] = observation
        return observation

    @property
    def untrusted_chars(self) -> int:
        """How much untrusted text is kept, in characters."""
        return sum(len(seen.text) for seen in self._seen if seen.origin is Origin.UNTRUSTED)

    def sightings(self, account: str) -> list[SightingRef]:
        """Every text in which exactly this canonical IBAN was written, in the order seen."""
        found: list[SightingRef] = []
        for seen in self._seen:
            hits = [m for m in seen.matches if m.account == account]
            if hits:
                spans = tuple((m.start, m.end) for m in hits)
                line = seen.text.count("\n", 0, spans[0][0]) + 1
                rendered = all(m.rendered for m in hits)
                found.append(SightingRef(seen.origin.value, seen.label, spans, line, rendered))
        return found

    def hidden_texts(self) -> list[tuple[str, str]]:
        """(label, hidden text) for every untrusted text with a part a reader
        does not see (`hidden_text`), in the order seen."""
        return [(seen.label, seen.hidden) for seen in self._seen
                if seen.origin is Origin.UNTRUSTED and seen.hidden]

    def texts(self) -> list[tuple[str, str]]:
        """(label, text) for every untrusted text, followed by the text the way
        a screen shows it when it has markup, in the order seen."""
        found = []
        for index, seen in enumerate(self._seen):
            if seen.origin is not Origin.UNTRUSTED:
                continue
            if index not in self._shown:
                self._shown[index] = _render(seen.text)[0] if "<" in seen.text or "&" in seen.text \
                    else ""
            found.append((seen.label, seen.text + "\n" + self._shown[index]))
        return found

    def observations(self) -> list[dict[str, Any]]:
        """Every text kept, as JSON-safe dicts (name, origin, text, label)."""
        return [
            {"name": seen.name, "origin": seen.origin.value, "text": seen.text,
             "label": seen.label}
            for seen in self._seen
        ]

    def to_state(self) -> list[dict[str, Any]]:
        # The IBANs found and the hidden text are saved with each text, so
        # rebuilding the tracker (which the database does for every operation)
        # never scans text again.
        return [
            {"name": seen.name, "origin": seen.origin.value, "text": seen.text,
             "matches": [[m.account, m.start, m.end] + ([True] if m.rendered else [])
                         for m in seen.matches],
             **({"hidden": seen.hidden} if seen.origin is Origin.UNTRUSTED else {})}
            for seen in self._seen
        ]

    @classmethod
    def from_state(cls, state: list[dict[str, Any]]) -> ProvenanceTracker:
        tracker = cls()
        for item in state:
            saved = item.get("matches")
            matches = None if saved is None else tuple(
                IbanMatch(m[0], m[1], m[2], bool(m[3]) if len(m) > 3 else False) for m in saved
            )
            # Saved before hidden text was kept: read it again (None), as it is now.
            hidden = item.get("hidden")
            tracker.observe(Origin(item["origin"]), item["name"], item["text"], matches,
                            hidden if isinstance(hidden, str) else None)
        return tracker
