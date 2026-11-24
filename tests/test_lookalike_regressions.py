"""Regressions the fix3 verifier found in how look-alike invoice numbers are compared.

* Small Cyrillic and Greek letters ("мр-78" for MP-78) were folded only in
  part: р became p, м stayed and was dropped, so the copy read as P-78 and
  the same invoice was paid twice without a person. Before v0.3 it was held.
* Folding must only ever find more payments of one invoice than plain
  comparison does (`may_be_same_invoice` is true whenever `same_invoice` is).
* Two invoices written in Arabic-Indic digits shared one idempotency key, so
  the bank handed back the first transfer for the second invoice and the
  guard booked both as paid.
* Folding turned letters next to a digit into digits one pass at a time, so
  a document with a long run of the letter O made every payment slow.
"""

from __future__ import annotations

import time
import unittest
from datetime import timedelta
from decimal import Decimal

from countersign.audit import AuditLog, reconcile
from countersign.bank import MockBank
from countersign.guard import Guard
from countersign.models import (
    Ask, Mandate, Outcome, fold_lookalikes, invoice_core, invoice_key, may_be_same_invoice,
    same_invoice,
)
from countersign.simulation import START, default_vendors

MARLOWE = "Marlowe Print Works"
MARLOWE_ACCOUNT = "ES9121000418450200051332"
NIMBUS = "Nimbus Hosting Ltd"
NIMBUS_ACCOUNT = "DE89370400440532013000"


def _guard(payee: str, asks: dict | None = None, max_payments: int | None = None) -> Guard:
    now = [START]
    guard = Guard(MockBank(), default_vendors(), clock=lambda: now[0],
                  audit=AuditLog(lambda: now[0]))
    guard.start_task(Mandate(
        id="t", instruction="Pay the two open invoices.", payees=(payee,),
        max_per_payment=Decimal("2500"), max_total=Decimal("3000"),
        expires_at=START + timedelta(hours=8), max_payments=max_payments, asks=asks or {}))
    return guard


class SmallLookalikeTests(unittest.TestCase):
    def test_small_cyrillic_and_greek_copies_are_the_same_invoice(self):
        for copy in ("мр-78", "МР-78", "μρ-78", "ΜΡ-78", "Мр-78"):
            with self.subTest(copy=copy):
                self.assertEqual(invoice_key(copy), "MP-78")
                self.assertEqual(invoice_core(copy), "MP-78")
                self.assertTrue(may_be_same_invoice("MP-78", copy))

    def test_a_small_letter_that_looks_like_another_latin_one_keeps_that_reading(self):
        # Greek small nu looks like v; its capital looks like N.
        self.assertEqual(invoice_key("inν-2041"), "INV-2041")

    def test_a_paid_invoice_asked_again_in_small_lookalikes_is_not_paid_twice(self):
        for copy in ("мр-78", "μρ-78"):
            with self.subTest(copy=copy):
                guard = _guard(MARLOWE, {MARLOWE: Ask(payments=2)})
                first = guard.pay(MARLOWE, MARLOWE_ACCOUNT, "340.00", "MP-78")
                again = guard.pay(MARLOWE, MARLOWE_ACCOUNT, "340.00", copy)
                self.assertIs(first.decision.outcome, Outcome.ALLOW)
                self.assertIsNot(again.decision.outcome, Outcome.ALLOW)
                self.assertEqual(len(guard.bank.transfers), 1)

    def test_folding_never_finds_fewer_payments_of_one_invoice(self):
        references = ["MP-73", "МР-73", "мр-73", "ПР-73", "МР-7З", "73", "кт-73", "KT-73",
                      "INV-2041", "INV-2O41", "inν-2041", "2041", "ИНВ-2041", "ᎷᏢ-73",
                      "MP-٧٣", "ＭＰ-７３", "NH-2041", "INV-2041-FEE"]
        for first in references:
            for second in references:
                if same_invoice(first, second):
                    with self.subTest(first=first, second=second):
                        self.assertTrue(may_be_same_invoice(first, second))


class LongRunTests(unittest.TestCase):
    """A document's hidden text is folded for every payment (T1). A long run of
    the letter O ending in a digit used to take one pass per letter."""

    def test_a_long_run_of_letters_next_to_a_digit_folds_quickly(self):
        started = time.monotonic()
        self.assertEqual(fold_lookalikes("O" * 100_000 + "1"), "0" * 100_000 + "1")
        self.assertEqual(fold_lookalikes("1" + "l" * 100_000), "1" * 100_001)
        self.assertLess(time.monotonic() - started, 5)

    def test_runs_touching_a_digit_become_digits_and_others_stay(self):
        self.assertEqual(fold_lookalikes("INV-2O41"), "INV-2041")
        self.assertEqual(fold_lookalikes("OO1-lO-1"), "001-lO-1")
        self.assertEqual(fold_lookalikes("OO1lO-1"), "00110-1")
        self.assertEqual(fold_lookalikes("Oil2"), "0112")
        self.assertEqual(fold_lookalikes("Oil-2"), "Oil-2")
        self.assertEqual(fold_lookalikes("Oil x2"), "Oil x2")
        self.assertEqual(fold_lookalikes("ІNV-2О4l"), "INV-2041")


class IdempotencyKeyTests(unittest.TestCase):
    def test_two_invoices_in_other_digits_are_two_transfers(self):
        guard = _guard(NIMBUS, max_payments=4)
        for reference in ("INV-١٠٠٧", "INV-١٠٠٤"):  # INV-1007, INV-1004
            result = guard.pay(NIMBUS, NIMBUS_ACCOUNT, "495.00", reference)
            self.assertIs(result.decision.outcome, Outcome.ALLOW)
        self.assertEqual(len(guard.bank.transfers), 2)
        self.assertEqual(reconcile(guard.audit.entries, guard.bank.transfers), [])


if __name__ == "__main__":
    unittest.main()
