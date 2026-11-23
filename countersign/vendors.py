"""The vendor file: suppliers the business already knows and how it has paid them.

Accounts are canonical IBANs and names are looked up by `models.name_key`.
The agent has no way to change this file. The guard adds an account only when
a person approves a hold and explicitly asks for the account to be remembered.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any, Iterable

from .iban import canonical_iban
from .models import name_key, plain


@dataclass
class Vendor:
    name: str
    accounts: set[str] = field(default_factory=set)  # verified accounts (canonical IBANs)
    history: list[Decimal] = field(default_factory=list)  # past payment amounts


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
            self._vendors[key] = Vendor(
                name=vendor.name,
                accounts={_canonical(a) for a in vendor.accounts},
                history=list(vendor.history),
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
        vendor = self.get(name)
        return tuple(vendor.history) if vendor is not None else ()

    def owner_of(self, account: str, other_than: str | None = None) -> Vendor | None:
        """The vendor that has this account on file, if any.

        `other_than` skips one payee, to answer "is this somebody else's account?".
        """
        skip = name_key(other_than) if other_than is not None else None
        for key, vendor in self._vendors.items():
            if key != skip and account in vendor.accounts:
                return vendor
        return None

    def add_account(self, name: str, account: str) -> bool:
        """Record an account as verified for a payee. Returns False if it was there.

        Called only when a person approves a hold and asks to remember it.
        """
        canonical = _canonical(account)
        vendor = self._vendors.setdefault(name_key(name), Vendor(name=name))
        if canonical in vendor.accounts:
            return False
        vendor.accounts.add(canonical)
        return True

    def record_payment(self, name: str, amount: Decimal) -> None:
        """Add an executed payment to the payee's history.

        A payee with no record gets one without accounts, so its next task has
        a usual amount to compare with.
        """
        vendor = self._vendors.setdefault(name_key(name), Vendor(name=name))
        vendor.history.append(amount)

    def to_state(self) -> list[dict[str, Any]]:
        return [
            {
                "name": vendor.name,
                "accounts": sorted(vendor.accounts),
                "history": [plain(amount) for amount in vendor.history],
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
            )
            for item in state
        )
