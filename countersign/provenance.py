"""Origin tracking: where was an account number written?

The guard sees every piece of text the agent is given. The instruction the
user typed has origin USER. Everything else (emails, invoices, web pages, tool
results) is UNTRUSTED, because an attacker can write it.

An account counts as "seen" in a text only if the text contains that exact
IBAN: a whole, checksum-valid token found by `iban.find_ibans`. There is no
substring matching, so words in a sentence or part of a longer number never
count. The tracker keeps each text and the position of every IBAN in it, so a
decision can point at the exact place.

Being seen is never a reason to pay. It only separates "an account from
nowhere" (refused) from "an account a document asked for" (a person decides).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from .iban import IbanMatch, find_ibans
from .models import SightingRef, clean_label

USER_SOURCE = "your instruction"
UNNAMED = "unnamed document"


class Origin(str, Enum):
    USER = "user"
    UNTRUSTED = "untrusted"


@dataclass(frozen=True)
class Observation:
    """One text the guard was shown, with the IBANs found in it."""

    origin: Origin
    name: str  # as given; for untrusted text the sender chose it
    text: str
    matches: tuple[IbanMatch, ...]

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
    ) -> Observation:
        """Keep one text and the IBANs in it. The same text twice is kept once.

        `matches` is `find_ibans(text)` when the caller has already computed it.
        """
        name = USER_SOURCE if origin is Origin.USER else source
        key = (origin, name, text)
        known = self._index.get(key)
        if known is not None:
            return known
        found = tuple(find_ibans(text)) if matches is None else tuple(matches)
        observation = Observation(origin, name, text, found)
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
            spans = tuple((m.start, m.end) for m in seen.matches if m.account == account)
            if spans:
                line = seen.text.count("\n", 0, spans[0][0]) + 1
                found.append(SightingRef(seen.origin.value, seen.label, spans, line))
        return found

    def observations(self) -> list[dict[str, Any]]:
        """Every text kept, as JSON-safe dicts (name, origin, text, label)."""
        return [
            {"name": seen.name, "origin": seen.origin.value, "text": seen.text,
             "label": seen.label}
            for seen in self._seen
        ]

    def to_state(self) -> list[dict[str, Any]]:
        # The IBANs found are saved with each text, so rebuilding the tracker
        # (which the database does for every operation) never scans text again.
        return [
            {"name": seen.name, "origin": seen.origin.value, "text": seen.text,
             "matches": [[m.account, m.start, m.end] for m in seen.matches]}
            for seen in self._seen
        ]

    @classmethod
    def from_state(cls, state: list[dict[str, Any]]) -> ProvenanceTracker:
        tracker = cls()
        for item in state:
            saved = item.get("matches")
            matches = None if saved is None else tuple(IbanMatch(a, s, e) for a, s, e in saved)
            tracker.observe(Origin(item["origin"]), item["name"], item["text"], matches)
        return tracker
