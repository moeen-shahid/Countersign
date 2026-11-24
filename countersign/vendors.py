"""The vendor file: suppliers the business already knows and how it has paid them.

Accounts are canonical IBANs and names are looked up by `models.name_key`.
The agent has no way to change this file. The guard adds an account only when
a person approves a hold and explicitly asks for the account to be remembered,
and it records when it did, so the account can be watched for a while.

`history` holds the amounts that count as usual for the payee: the amounts the
file was set up with, plus later payments that were inside the usual range or
that a person marked as usual. Other payments are kept in `other`, so they can
be shown, but they never move the usual amount (see `Guard._execute`).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Iterable

from .iban import canonical_iban
from .models import name_key, plain


@dataclass
class Vendor:
    name: str
    accounts: set[str] = field(default_factory=set)  # verified accounts (canonical IBANs)
    history: list[Decimal] = field(default_factory=list)  # amounts that count as usual
    # Payments made that do not count as usual (above or below the usual range,
    # and not marked as usual by a person).
    other: list[Decimal] = field(default_factory=list)
    # account -> when a person's approval added it (ISO time). Accounts the
    # file was set up with have no entry.
    added: dict[str, str] = field(default_factory=dict)


def _canonical(account: object) -> str:
    canonical = canonical_iban(account)
    if canonical is None:
        raise ValueError(f"{account!r} is not a valid IBAN")
    return canonical


class VendorFile:
    def __init__(self, vendors: Iterable[Vendor] | None = None) -> None:
        self._vendors: dict[str, Vendor] = {}
        for vendor in vendors or ():
            key = name_key(vendor.name)
            if not key:
                raise ValueError("a vendor needs a name")
            if key in self._vendors:
                raise ValueError(f"vendor {vendor.name!r} is listed twice")
            accounts = {_canonical(a) for a in vendor.accounts}
            added = {}
            for account, when in dict(vendor.added).items():
                canonical = _canonical(account)
                if canonical in accounts and isinstance(when, str):
                    added[canonical] = when
            self._vendors[key] = Vendor(
                name=vendor.name,
                accounts=accounts,
                history=list(vendor.history),
                other=list(vendor.other),
                added=added,
            )

    def get(self, name: str) -> Vendor | None:
        return self._vendors.get(name_key(name))

    def all(self) -> list[Vendor]:
        return list(self._vendors.values())

    def accounts_for(self, name: str) -> frozenset[str]:
        """Accounts on file for this payee; empty if there are none."""
        vendor = self.get(name)
        return frozenset(vendor.accounts) if vendor is not None else frozenset()

    def history_for(self, name: str) -> tuple[Decimal, ...]:
        """The amounts that count as usual for this payee."""
        vendor = self.get(name)
        return tuple(vendor.history) if vendor is not None else ()

    def added_at(self, name: str, account: str) -> datetime | None:
        """When a person's approval added this account for this payee, or None
        when the account came with the vendor file (or is not on file)."""
        vendor = self.get(name)
        when = vendor.added.get(account) if vendor is not None else None
        if when is None:
            return None
        try:
            moment = datetime.fromisoformat(when)
        except (TypeError, ValueError):
            moment = None
        if moment is None or moment.utcoffset() is None:
            # Unreadable: treat it as added at the end of time, so the account
            # stays on probation. Fails closed.
            return datetime.max.replace(tzinfo=timezone.utc)
        return moment

    def owner_of(self, account: str, other_than: str | None = None) -> Vendor | None:
        """The vendor that has this account on file, if any.

        `other_than` skips one payee, to answer "is this somebody else's account?".
        """
        skip = name_key(other_than) if other_than is not None else None
        for key, vendor in self._vendors.items():
            if key != skip and account in vendor.accounts:
                return vendor
        return None

    def add_account(self, name: str, account: str, when: str | None = None) -> bool:
        """Record an account as verified for a payee. Returns False if it was there.

        Called only when a person approves a hold and asks to remember it.
        `when` (ISO time) starts the account's probation (rule P3).
        """
        canonical = _canonical(account)
        vendor = self._vendors.setdefault(name_key(name), Vendor(name=name))
        if canonical in vendor.accounts:
            return False
        vendor.accounts.add(canonical)
        if when is not None:
            vendor.added[canonical] = when
        return True

    def end_probation(self, name: str, account: str) -> bool:
        """A person countersigned a later payment to an added account: it is
        no longer on probation. Returns False if it was not."""
        vendor = self.get(name)
        if vendor is None or account not in vendor.added:
            return False
        del vendor.added[account]
        return True

    def record_payment(self, name: str, amount: Decimal, *, usual: bool = True) -> None:
        """Add an executed payment to the payee's record.

        `usual` says whether it counts as a usual amount (`history`) or not
        (`other`). A payee with no record gets one without accounts.
        """
        vendor = self._vendors.setdefault(name_key(name), Vendor(name=name))
        (vendor.history if usual else vendor.other).append(amount)

    def to_state(self) -> list[dict[str, Any]]:
        return [
            {
                "name": vendor.name,
                "accounts": sorted(vendor.accounts),
                "history": [plain(amount) for amount in vendor.history],
                "other": [plain(amount) for amount in vendor.other],
                "added": dict(sorted(vendor.added.items())),
            }
            for vendor in self._vendors.values()
        ]

    @classmethod
    def from_state(cls, state: list[dict[str, Any]]) -> VendorFile:
        return cls(
            Vendor(
                name=item["name"],
                accounts=set(item["accounts"]),
                history=[Decimal(amount) for amount in item["history"]],
                other=[Decimal(amount) for amount in item.get("other") or ()],
                added=dict(item.get("added") or {}),
            )
            for item in state
        )
