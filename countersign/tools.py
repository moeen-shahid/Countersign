"""The two tools an agent is given: read a document, and pay.

`DirectTools` wires them straight to the bank (no protection).
`GuardedTools` routes both through the guard, so the guard sees everything
the agent reads and decides everything the agent tries to pay.
"""

from __future__ import annotations

from .bank import BankDeclined, MockBank
from .guard import DECLINED, Guard, PayResult
from .iban import canonical_iban
from .models import Decision, Outcome, parse_amount


class DirectTools:
    def __init__(self, bank: MockBank, documents: dict[str, str]) -> None:
        self._bank = bank
        self._documents = documents

    def read_document(self, name: str) -> str:
        return self._documents[name]

    def pay(
        self,
        payee: str,
        account: str,
        amount: object,
        reference: str = "",
        currency: str | None = None,
    ) -> PayResult:
        """Send the request to the bank as it is. Never raises: a refusal by
        the bank comes back as a BLOCK, like any other refusal."""
        try:
            value = parse_amount(amount)
            if value is None:
                raise BankDeclined("the amount is not readable")
            transfer = self._bank.transfer(
                payee, canonical_iban(account) or account, value, reference
            )
        except Exception:
            return PayResult(Decision(Outcome.BLOCK, "BANK", DECLINED, ("BANK",)))
        reason = "No guard. The request went straight to the bank."
        return PayResult(Decision(Outcome.ALLOW, "NONE", reason), transfer_id=transfer.id)


class GuardedTools:
    def __init__(self, guard: Guard, documents: dict[str, str]) -> None:
        self._guard = guard
        self._documents = documents

    def read_document(self, name: str) -> str:
        text = self._documents[name]
        self._guard.observe(name, text)
        return text

    def pay(
        self,
        payee: str,
        account: str,
        amount: object,
        reference: str = "",
        currency: str | None = None,
    ) -> PayResult:
        return self._guard.pay(payee, account, amount, reference, currency)
