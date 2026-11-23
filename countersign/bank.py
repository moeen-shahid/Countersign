"""A mock bank. No real money moves anywhere in this project.

It behaves like a careful payment API in the ways the guard relies on: it only
sends positive amounts to well-formed IBANs, it says no with `BankDeclined`,
and a request repeated with the same idempotency key is not sent twice.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from decimal import Decimal
from typing import Any

from .iban import is_canonical_iban
from .models import CENT, plain


class BankDeclined(Exception):
    """The bank definitely did not send the transfer."""


class InsufficientFunds(BankDeclined):
    pass


@dataclass(frozen=True)
class Transfer:
    id: str
    payee: str
    account: str
    amount: Decimal
    reference: str

    def to_dict(self) -> dict[str, str]:
        return {
            "id": self.id,
            "payee": self.payee,
            "account": self.account,
            "amount": plain(self.amount),
            "reference": self.reference,
        }


def _sendable(amount: object) -> bool:
    try:
        return (
            isinstance(amount, Decimal)
            and amount.is_finite()
            and amount > 0
            and amount == amount.quantize(CENT)
        )
    except ArithmeticError:
        return False


class MockBank:
    def __init__(self, balance: Decimal = Decimal("50000.00")) -> None:
        self.balance = balance
        self.transfers: list[Transfer] = []
        self._by_key: dict[str, str] = {}  # idempotency key -> transfer id
        self._lock = threading.RLock()

    def transfer(
        self,
        payee: str,
        account: str,
        amount: Decimal,
        reference: str = "",
        idempotency_key: str | None = None,
    ) -> Transfer:
        """Send one transfer, or raise BankDeclined and move nothing.

        A repeated `idempotency_key` returns the first transfer made with it.
        """
        with self._lock:
            if idempotency_key is not None and idempotency_key in self._by_key:
                first = self._by_key[idempotency_key]
                return next(t for t in self.transfers if t.id == first)
            if not isinstance(payee, str) or not isinstance(reference, str):
                raise BankDeclined("payee and reference must be text")
            if not is_canonical_iban(account):
                raise BankDeclined("the account is not a valid IBAN")
            if not _sendable(amount):
                raise BankDeclined("the amount is not a positive amount in whole cents")
            if amount > self.balance:
                raise InsufficientFunds(f"balance {self.balance} is below {amount}")
            self.balance -= amount
            transfer = Transfer(
                id=f"T{len(self.transfers) + 1:03d}",
                payee=payee,
                account=account,
                amount=amount,
                reference=reference,
            )
            self.transfers.append(transfer)
            if idempotency_key is not None:
                self._by_key[idempotency_key] = transfer.id
            return transfer

    def to_state(self) -> dict[str, Any]:
        with self._lock:
            return {
                "balance": plain(self.balance),
                "transfers": [t.to_dict() for t in self.transfers],
                "keys": dict(sorted(self._by_key.items())),
            }

    @classmethod
    def from_state(cls, state: dict[str, Any]) -> MockBank:
        bank = cls(Decimal(state["balance"]))
        bank.transfers = [
            Transfer(t["id"], t["payee"], t["account"], Decimal(t["amount"]), t["reference"])
            for t in state["transfers"]
        ]
        bank._by_key = dict(state.get("keys") or {})
        return bank
