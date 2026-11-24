"""The invariant fuzzer: it finds nothing new in the real guard, it reaches the
whole rule table, it catches a broken guard for every rule that can be switched
off (A1 included, since INV-13; the rules of fix3 since INV-15), and it has no
known gap of the one-sided property left."""

import dataclasses
import json
import sys
import unittest
from contextlib import ExitStack, redirect_stdout
from datetime import timedelta
from decimal import Decimal
from io import StringIO

from countersign import drafting, fuzz, guard, policy
from countersign.cli import main
from countersign.iban import fmt_iban, is_canonical_iban
from countersign.models import (
    Ask,
    Mandate,
    figures_in,
    fold_lookalikes,
    invoice_key,
    is_plain_text,
    may_be_same_invoice,
    mixes_alphabets,
    names_invoice,
    ref_core,
    ref_key,
    same_invoice,
)
from countersign.provenance import hidden_text
from countersign.scenarios import KESTREL, MULE_1, NIMBUS, TIDEWATER, Task
from countersign.simulation import default_vendors

N, K, T = "Nimbus Hosting Ltd", "Kestrel Legal LLP", "Tidewater Insurance Brokers"
F = fuzz.NEW_PAYEE


class CampaignTests(unittest.TestCase):
    """One campaign on the real guard, shared by the tests that read its report."""

    @classmethod
    def setUpClass(cls):
        cls.report = fuzz.run_fuzz(runs=100, seed=3)

    def test_no_violations_in_the_real_guard(self):
        self.assertEqual(self.report["violations"], [])
        self.assertGreater(self.report["operations"], 3000)
        self.assertEqual([i["id"] for i in self.report["invariants"]],
                         [f"INV-{n}" for n in range(1, 16)])
        self.assertIn("known_gaps", self.report)

    def test_every_rule_of_countersign_decides_requests(self):
        # Weakness 6 of the adversarial review: M0, M6 and H1 never decided a
        # request, and 40% of requests died at F1.
        rules = self.report["rules"]
        ours = [code for code in policy.RULE_ORDER if "countersign" in policy.RULE_GUARDS[code]]
        # A3 only ever comes with a question about the account (P1, P2, P3), which
        # goes first: it is carried, never the first rule (fix3).
        for code in [c for c in ours if c != "A3"] + ["OK"]:
            self.assertGreater(rules.get(code, 0), 0, code)
        self.assertGreater(self.report["carried"].get("A3", 0), 0, "A3")
        malformed = rules.get("F1", 0) / sum(rules.values())
        self.assertLess(malformed, 0.15)
        for code in ("A1", "A2", "D1", "D3", "H2", "P3", "S1", "S2"):  # HOLD rules come together
            self.assertGreaterEqual(self.report["carried"][code], rules.get(code, 0), code)
        self.assertEqual(set(self.report["profiles"]), set(fuzz.PROFILES))
        self.assertIn("OK", self.report["at_approval"])  # approvals that paid

    def test_the_oracle_uses_the_rules_numbers(self):
        self.assertEqual(fuzz.QUEUE_ACCOUNTS, policy.MAX_PENDING_HOLDS)
        self.assertEqual(fuzz.QUEUE_ALL, policy.MAX_WAITING)
        self.assertEqual(fuzz.PROBATION, policy.PROBATION_GAP)
        self.assertEqual(fuzz.DESTINATION, frozenset(policy.DESTINATION_RULES))
        self.assertEqual(fuzz.HEADROOM_LEAST, policy.AMOUNT_HEADROOM_MIN)
        self.assertEqual(fuzz.HEADROOM_MOST, policy.AMOUNT_HEADROOM_MAX)
        self.assertLessEqual(fuzz.PROJECTED, set(policy.RULE_ORDER))
        self.assertEqual(fuzz.TOO_LARGE, guard.MAX_TASK_TEXT)

    def test_the_rules_of_fix3_are_reached(self):
        # F2, S4, T1 and D4 decide requests; A3 is carried by holds about the
        # account; tasks are confirmed both ways; a document too large to keep is
        # read now and then.
        rules, carried = self.report["rules"], self.report["carried"]
        for code in ("F2", "S4", "T1", "D4"):
            self.assertGreater(rules.get(code, 0), 0, code)
        self.assertGreater(carried.get("A3", 0), 0)


class DeterminismTests(unittest.TestCase):
    def test_same_seed_same_result(self):
        a, b = fuzz.run_fuzz(runs=10, seed=5), fuzz.run_fuzz(runs=10, seed=5)
        self.assertEqual((a["operations"], a["rules"]), (b["operations"], b["rules"]))
        self.assertEqual(fuzz._one(42, 30)[1], fuzz._one(42, 30)[1])


class OracleTests(unittest.TestCase):
    """The oracle's own pieces agree with the definitions it was written from."""

    def test_its_reading_of_invoice_numbers_is_the_one_in_models(self):
        references = [
            "INV-2041", "inv 2041", "2041", "Invoice no. 02041", "INV-2041-FEE", "INV-2041/B",
            "NH-2041", "FD-118", "118", "KL-0932", "KL-932", "kl 932", "BL-553", "553", "INV",
            "No 5", "5", "0", "000", "R-1", "X-63", "-", "", "  ", "INV-1-12", "INV-11-2",
            "Ref: TW-31", "TW 31", "tw31", "ß-1", "INV 2041", "F" * 141,
        ]
        for text in references:
            self.assertEqual(fuzz._ref_key(text), ref_key(text), text)
            self.assertEqual(fuzz._ref_core(text), ref_core(text), text)
            readable = is_plain_text(text) and bool(ref_key(text))
            self.assertEqual(fuzz._readable(text), readable, text)
            for other in references:
                self.assertEqual(fuzz._same_invoice(text, other), same_invoice(text, other),
                                 (text, other))

    def test_its_accounts_are_valid_and_on_file_for_nobody(self):
        vendors = default_vendors()
        for account in fuzz.FLOOD + fuzz.FRESH:
            self.assertTrue(is_canonical_iban(account), account)
            self.assertIsNone(vendors.owner_of(account), account)
        self.assertEqual(len(set(fuzz.FLOOD)), len(fuzz.FLOOD))

    def test_its_unusual_amount_line_is_the_one_in_the_rules(self):
        # INV-13 draws the A1 line itself; it must be the line the rules draw.
        session = fuzz.Session(1, 0)
        histories = [
            ["480.00", "480.00", "495.00"], ["96.00"], ["100.00", "10.00"], ["1500.00"] * 3,
            ["120.50", "89.90", "143.20"], ["0.01"], ["333.33", "300.00"], ["999.99", "1.00"],
            ["310.00", "275.00", "340.00"], ["1234.56", "1100.00", "1200.00"],
        ]
        for amounts in histories:
            history = [Decimal(a) for a in amounts]
            session.frozen = {N: tuple(history)}
            largest, headroom, line = session.line(N)
            self.assertEqual(line, policy.usual_ceiling(history), amounts)
            self.assertEqual((largest, headroom), (max(history), line - max(history)))
        session.frozen = {}
        self.assertIsNone(session.line(N))

    def test_its_counts_of_parts_are_the_ones_in_the_rules(self):
        # D1 (parts a person typed) and D2 (the same payment again), worked out
        # by the oracle from the mandate, as the rules work them out.
        base = dict(id="t", instruction="Pay.", max_per_payment=Decimal("2000"),
                    max_total=Decimal("5000"),
                    expires_at=fuzz.START + timedelta(hours=8))
        typed = Ask(payments=3, set_by=("payments",))
        cases = [
            dict(payees=(K,)),
            dict(payees=(K,), references=("KL-12",), max_payments=3),
            dict(payees=(K, N), references=("KL-12",), max_payments=3),
            dict(payees=(K,), references=("KL-12",), asks={K: Ask(payments=2, invoices=("KL-12",))}),
            dict(payees=(K, N), references=("KL-12", "INV-1001"), asks={K: typed}),
            dict(payees=(K,), references=("KL-12",), max_payments=2, asks={K: typed}),
            dict(payees=(K,), asks={K: Ask(payments=3, invoices=("KL-12", "KL-13"))}),
            dict(payees=(K,), references=("KL-12", "kl 12"), max_payments=4),
        ]
        session = fuzz.Session(1, 0)
        for case in cases:
            mandate = Mandate(**base, **case)
            for payee in mandate.payees:
                self.assertEqual(session.parts(mandate, payee),
                                 policy.instalments_covered(mandate, payee), case)
                self.assertEqual(session.identical(mandate, payee),
                                 policy.identical_payments(mandate, payee), case)

    def test_the_drafter_is_held_to_what_the_sentence_says(self):
        # The oracle knows what each generated sentence states; a draft that
        # binds an account the sentence only warns about is caught at once.
        session = fuzz.Session(1, 30)
        words, said = session.sentence([fuzz.NEW_PAYEE], "scam")
        self.assertIn("scam", words)
        self.assertEqual(said.dictated, {})
        draft = drafting.draft_mandate(words, session.guard.vendors, [fuzz.NEW_PAYEE])
        session.check_draft(draft, said)  # the real drafter binds nothing here
        bound = {fuzz.NEW_PAYEE: tuple(said.typed)}
        with self.assertRaises(fuzz._Found) as found:
            session.check_draft(dataclasses.replace(draft, accounts=bound), said)
        self.assertEqual(found.exception.invariant, "INV-1")
        # A sentence that does not count leaves the count empty, and nothing in a
        # draft is marked as set by a person.
        self.assertIsNone(draft.asks[fuzz.NEW_PAYEE].payments)
        for ask in (Ask(payments=1), Ask(amount=Decimal("650"), set_by=("amount",))):
            with self.assertRaises(fuzz._Found) as found:
                session.check_draft(dataclasses.replace(draft, asks={fuzz.NEW_PAYEE: ask}), said)
            self.assertEqual(found.exception.invariant, "INV-8")

    def test_the_sentences_name_the_account_after_the_label_iban(self):
        # "Pay Fernhill EUR 650. IBAN: NL85 ..." and "..., IBAN NL85 ...": the
        # account is given as the place to pay, and the drafter binds it.
        labels, bound = set(), 0
        for seed in range(40):
            session = fuzz.Session(seed, 0)
            words, said = session.sentence([F], "label")
            draft = drafting.draft_mandate(words, session.guard.vendors, [F])
            session.check_draft(draft, said)
            self.assertIn("IBAN", words)
            labels.add(words.split("IBAN")[0][-2:] + "IBAN" + words.split("IBAN")[1][:2])
            account = next(iter(said.dictated[F]))
            if session.guard.vendors.owner_of(account) is None:
                self.assertEqual(draft.accounts.get(F), (account,), words)
                bound += 1
            words, said = session.sentence([F], "label_old")
            draft = drafting.draft_mandate(words, session.guard.vendors, [F])
            session.check_draft(draft, said)
            self.assertEqual((said.dictated, draft.accounts), ({}, {}), words)
        self.assertGreater(bound, 20)
        self.assertGreaterEqual(len(labels), 3)  # ". IBAN: ", ", IBAN ", ...

    def test_the_sentences_use_one_word_and_possessive_names(self):
        short = possessive = 0
        for seed in range(60):
            session = fuzz.Session(seed, 0)
            words, said = session.sentence([K], "invoice")
            draft = drafting.draft_mandate(words, session.guard.vendors, [K])
            session.check_draft(draft, said)
            self.assertEqual(draft.asks[K].invoices, said.invoices[K], words)
            self.assertEqual(draft.asks[K].amount, said.amount[K], words)
            short += words.startswith("Pay Kestrel ") or words.startswith("Pay Kestrel's")
            possessive += "'s invoice" in words
        self.assertGreater(short, 5)
        self.assertGreater(possessive, 5)


class Fix3OracleTests(unittest.TestCase):
    """The oracle's own readings for the rules of fix3 agree with the guard's on
    everything the fuzzer generates, and what the fuzzer believes it wrote (a
    hidden figure, an invoice number shown, an exclusion) is what the guard and
    the drafter read."""

    REFERENCES = ("INV-1001", "INV-1009", "KL-15", "KL-12", "MP-71", "MP-78", "TW-31",
                  "BL-551", "BL-553", "FD-113", "XY-0013", "R-5")

    def lookalikes(self):
        found = []
        for seed in range(12):
            session = fuzz.Session(seed, 0, twin=False)
            for reference in self.REFERENCES:
                found += [session.lookalike(reference) for _ in range(6)]
                found += [session.spelled(reference) for _ in range(4)]
                found += [session.spelled(session.lookalike(reference)) for _ in range(4)]
        return found

    def test_its_reading_of_look_alikes_is_the_one_in_models(self):
        found = self.lookalikes()
        self.assertGreater(len(set(found)), 150)
        self.assertTrue(any(fuzz._mixes(x) for x in found))  # some mix alphabets (F2)
        self.assertTrue(any(not fuzz._mixes(x) and fold_lookalikes(x) != x for x in found))
        for text in found + list(self.REFERENCES):
            self.assertEqual(fuzz._payment_ref(text), invoice_key(text), text)
            self.assertEqual(fuzz._mixes(text), mixes_alphabets(text), text)
            for other in self.REFERENCES:
                self.assertEqual(fuzz._same_folded(text, other),
                                 may_be_same_invoice(text, other), (text, other))

    def test_its_a1_grouping_folds_digits_of_another_script(self):
        # Seed 2 x 1,000 (session 2000326): MP-٧٨ waiting and MP-７１ paid are two
        # invoices. Unfolded, both read "MP", and the oracle added them up.
        session = fuzz.Session(1, 0, twin=False)
        session.frozen = {fuzz.M: (Decimal("310"), Decimal("275"), Decimal("340"))}
        waiting = [fuzz._Waiting("H001", 0, fuzz.M, KESTREL, Decimal("405"),
                                 "MP-\u0667\u0668", "", ("D1",))]
        self.assertIsNone(session.over_line(fuzz.M, "MP-\uff17\uff11", Decimal("275"),
                                            waiting))
        self.assertIsNotNone(session.over_line(fuzz.M, "MP-78", Decimal("275"), waiting))

    def test_what_a_document_hides_is_hidden_to_the_guard(self):
        # Every way the fuzzer hides a figure is one the guard's reader finds,
        # in every way it writes the amount; an invoice number of three or more
        # characters is found too (T1 ignores shorter ones, and so does INV-15).
        for form in fuzz._HIDING:
            for written, value in (("1,860.00", "1860.00"), ("1.860,00", "1860.00"),
                                   ("480", "480"), ("96.00", "96.00")):
                doc = "Invoice KL-12.\n" + form.format(f"EUR {written} for KL-15") + "\nThanks."
                hidden = hidden_text(doc)
                self.assertIn(Decimal(value), figures_in(hidden), (form, written))
                self.assertTrue(names_invoice(hidden, "KL-15"), form)
        hidden = hits = 0
        for seed in range(80):
            session = fuzz.Session(seed, 0, twin=False)
            session.start_task()
            for _ in range(6):
                doc = session.document()
                for _, value, invoice in doc.hidden:
                    hidden += 1
                    shown = hidden_text(doc.text)
                    if value is not None:
                        self.assertIn(value, figures_in(shown), doc.text)
                    core = ref_core(fold_lookalikes(invoice)) if invoice else ""
                    if len(core.replace("-", "")) >= 3:
                        hits += 1
                        self.assertTrue(names_invoice(shown, invoice), doc.text)
        self.assertGreater(hidden, 40)
        self.assertGreater(hits, 20)

    def test_the_invoice_numbers_it_shows_are_ones_the_guard_reads(self):
        # INV-15 counts only the numbers with letters the fuzzer wrote; the
        # guard's reading (D4) finds at least those.
        claims = 0
        for seed in range(80):
            session = fuzz.Session(seed, 0, twin=False)
            session.start_task()
            for _ in range(4):
                doc = session.document()
                read = {(m.group(1), m.group(2).lstrip("0") or "0")
                        for m in policy._FULL_REF.finditer(fold_lookalikes(doc.text))}
                self.assertLessEqual(doc.claims, read, doc.text)
                claims += len(doc.claims)
        self.assertGreater(claims, 100)
        self.assertIsNone(fuzz._claim("INV-1003"))  # a label, not other letters
        self.assertEqual(fuzz._claim("Invoice no. KL-0015"), ("KL", "15"))
        self.assertEqual(fuzz._claim("\u041c\u0420-71"), ("MP", "71"))  # folded

    def test_the_drafter_reads_the_exclusions_and_instalments_it_is_given(self):
        # The sentence shapes of fix3, drafted by the real drafter: every payee
        # the sentence excludes some invoices of is marked, instalments only
        # where the sentence counts them, and no vendor named in passing is
        # proposed as a payee.
        seen = {"excluded": 0, "parts": 0, "others": 0, "every": 0}
        for seed in range(60):
            session = fuzz.Session(seed, 0, twin=False)
            for payees in ([K], [K, N], [N, T, K], [F]):
                for shape in ("except", "parts", "instalments", "other", "two", "bare"):
                    words, said = session.sentence(list(payees), shape)
                    draft = drafting.draft_mandate(words, session.guard.vendors, payees)
                    session.check_draft(draft, said)
                    session.check_proposed(words, said, list(payees))
                    seen["excluded"] += bool(said.excluded)
                    seen["every"] += len(said.excluded) > 1
                    seen["others"] += bool(said.others)
                    for payee in said.parts:
                        seen["parts"] += draft.asks[payee].instalments
        self.assertGreater(seen["excluded"], 150)
        self.assertGreater(seen["every"], 20)  # one exclusion about every payee
        self.assertGreater(seen["others"], 30)
        self.assertGreater(seen["parts"], 150)  # the drafter reads them, so D2 lets them through

    def test_the_drafter_checks_catch_what_they_promise(self):
        session = fuzz.Session(1, 0, twin=False)
        words, said = session.sentence([K], "except")
        draft = drafting.draft_mandate(words, session.guard.vendors, [K])
        self.assertTrue(draft.asks[K].excludes_some, words)
        missed = {K: dataclasses.replace(draft.asks[K], excludes_some=False)}
        with self.assertRaises(fuzz._Found) as found:
            session.check_draft(dataclasses.replace(draft, asks=missed), said)
        self.assertEqual(found.exception.invariant, "INV-8")
        words, said = session.sentence([N], "two")
        draft = drafting.draft_mandate(words, session.guard.vendors, [N])
        read = {N: dataclasses.replace(draft.asks[N], instalments=True)}
        with self.assertRaises(fuzz._Found) as found:
            session.check_draft(dataclasses.replace(draft, asks=read), said)
        self.assertEqual(found.exception.invariant, "INV-8")
        with self.assertRaises(fuzz._Found) as found:
            session.check_proposed("Pay Nimbus EUR 480. Pay Kestrel too.", said, [N])
        self.assertEqual(found.exception.invariant, "INV-1")

    def test_some_tasks_are_confirmed_the_way_the_benchmark_confirms_them(self):
        # simulation.task_mandate with the task's own limits; the oracle keeps the
        # limits it chose, and they are the mandate's.
        seen = 0
        for seed in range(40):
            session = fuzz.Session(seed, 0, twin=False)
            calls = []
            real = fuzz.simulation.task_mandate

            def task_mandate(scenario, task, number, clock, calls=calls, real=real):
                calls.append(task)
                return real(scenario, task, number, clock)

            from unittest import mock
            with mock.patch.object(fuzz.simulation, "task_mandate", task_mandate):
                for _ in range(4):
                    session.start_task()
                    self.assertEqual(session.limits, (session.mandate.max_per_payment,
                                                      session.mandate.max_total))
            seen += sum(1 for task in calls if task.max_per_payment is not None
                        or task.max_total is not None)
        self.assertGreater(seen, 20)


# For each mutant, a campaign seed whose first session the expected invariant
# catches it in (`quick_seeds`), so the test runs one session per mutant. When
# the way sessions are generated changes, the seeds move: the test then still
# runs up to 40 sessions per mutant, and `python3 -m tests.test_fuzz --seeds`
# prints a new table. `fuzz --mutants` runs whole campaigns instead.
QUICK_SEEDS = {
    'every account counts as vouched for': 0,
    'an account seen in a document counts as trusted': 1,
    'an account the user typed outranks the vendor file': 1,
    'a dictated account on file for another vendor counts (F01)': 1,
    'an account added by an approval is trusted at once': 63,
    'an account seen nowhere is held, not refused': 0,
    'the drafter binds every account of a one-payee sentence': 11,
    'ending a task leaves it active': 16,
    'an expired mandate still pays': 14,
    'a request without a readable reference is not refused': 88,
    'any payee name passes the mandate check': 1,
    'the per-payment limit is not checked': 9,
    'the budget and payment count are not checked': 5,
    'the references a person typed are not checked': 2,
    'the invoices the sentence names are not checked': 3,
    'approving a hold pays a cent more than was shown': 0,
    'a rejection is forgotten': 2,
    'a full queue lets through what needs no person (H1 as first specified)': 13,
    'a document that names the invoice lets a payment through (E03)': 0,
    'the stated amount is not checked': 3,
    'the expected number of payments is not checked': 5,
    'a payee with no usual and no stated amount is paid': 3,
    'every payment joins the usual amounts (ratchet)': 0,
    'the queue has no limit': 7,
    'a waiting payment does not count against later ones': 0,
    'a payment of an invoice waiting for another account goes through': 2,
    'an invoice paid before is paid again': 2,
    'the unusual-amount rule is switched off': 4,
    'exactly the same payment twice in a task is not refused': 18,
    'the task is not quarantined after the queue overflowed': 36,
    'a rejected account question refuses one payment, keeps the account': 7,
    'asked again while it waits, a payment is queued a second time': 4,
    'H2 names limits the waiting payments would not break': 0,
    'the drafter writes the default count of one': 1,
    'a count read from the sentence counts as typed by a person': 26,
    'a reference that mixes alphabets is not refused': 21,
    'look-alike characters make another payment (nothing is folded)': 147,
    'look-alike characters make another invoice when invoices are compared': 11,
    'an invoice the sentence says not to pay goes through': 1,
    'the drafter does not read that some invoices are not to be paid': 1,
    'the drafter reads every count as instalments': 8,
    'the drafter proposes every vendor the sentence names': 11,
    'a hold about the account does not ask about an amount above the usual': 1,
    'the line has the headroom of v0.2 (20% to 50%)': 21,
    'account questions count once per payee, not per invoice': 7,
    'rejecting without saying what was wrong means only the payment': 2,
    'instalments read from the sentence let an invoice be paid twice': 26,
    'any count from the sentence lets the same payment be made again': 126,
    'an amount or invoice number in hidden text is not held': 24,
    'a document too large to keep is forgotten': 24,
    'a bare number that two invoices have is not held': 8,
    "a task's own limits are replaced by the scenario's": 12,
}


def quick_seeds(limit: int = 3000) -> dict[str, int]:
    """The first campaign seed (`run_fuzz(seed=...)`) whose first session
    catches each mutant by its expected invariant."""
    found = {}
    for _, label, patch, expected in fuzz.MUTANTS:
        with ExitStack() as stack:
            patch(stack)
            for seed in range(limit):
                _, _, violation = fuzz._one(seed * 1_000_003, 30, twin=expected == "INV-6")
                if violation is not None and violation.invariant == expected:
                    found[label] = seed
                    break
    return found


class MutantTests(unittest.TestCase):
    def test_every_rule_that_can_be_switched_off_is_caught(self):
        self.assertEqual(set(QUICK_SEEDS), {label for _, label, _, _ in fuzz.MUTANTS})
        for rule, label, patch, expected in fuzz.MUTANTS:
            if expected is None:
                continue
            with self.subTest(rule=rule, mutant=label), ExitStack() as stack:
                patch(stack)
                report = fuzz.run_fuzz(runs=40, seed=QUICK_SEEDS[label], stop_on=[expected],
                                       twin=expected == "INV-6")
                caught = {v["invariant"] for v in report["violations"]}
                self.assertIn(expected, caught, f"{label}: caught by {sorted(caught)}")

    def test_the_table_covers_the_rules_and_names_what_is_not_covered(self):
        rules = {rule for rule, _, _, _ in fuzz.MUTANTS}
        for code in ("D1", "R1", "H1", "M6", "O1", "S1", "S2", "S3", "A2", "P3", "D3", "H2",
                     "M0", "M1", "F1", "M2", "M3", "drafter", "A1", "D2",
                     "F2", "S4", "A3", "T1", "D4", "M3/M4"):  # fix3
            self.assertIn(code, rules)
        uncovered = {rule for rule, _, _, expected in fuzz.MUTANTS if expected is None}
        self.assertEqual(uncovered, set(fuzz.NOT_COVERED))
        self.assertEqual(uncovered, set())  # changed (v0.3): A1 is covered by INV-13
        expected = {e for _, _, _, e in fuzz.MUTANTS}
        self.assertEqual(expected, {f"INV-{n}" for n in (1, 2, 5, 6, 8, 9, 10, 11, 12, 13, 14,
                                                         15)})
        self.assertEqual(len({label for _, label, _, _ in fuzz.MUTANTS}), len(fuzz.MUTANTS))

    def test_an_internal_error_in_the_guard_is_a_violation(self):
        from unittest import mock

        from countersign import guard

        def crash(req, trusted, provenance):
            raise RuntimeError("broken rule engine")

        with mock.patch.object(guard, "evaluate", crash):
            report = fuzz.run_fuzz(runs=5, seed=0)
        self.assertEqual({v["invariant"] for v in report["violations"]}, {"INV-4"})

    def test_a_violation_names_the_seed_and_the_steps(self):
        with ExitStack() as stack:
            fuzz.MUTANTS[0][2](stack)
            report = fuzz.run_fuzz(runs=5, seed=0, twin=False)
        first = report["violations"][0]
        self.assertTrue(first["operations"])
        self.assertIsInstance(first["seed"], int)


def _session(sentence, payees, budget="3000.00", twin=False, **fields):
    """A session with the mandate drafted from this sentence, as a person would
    confirm it, and no random extra documents or approvals."""
    session = fuzz.Session(7, 0, twin=twin)
    session.rng.random = lambda: 0.99  # no extra documents; approvals remember nothing
    draft = drafting.draft_mandate(sentence, session.guard.vendors, payees)
    session.start_task(Mandate(
        id=f"trace-{session.task_no + 1}", instruction=sentence, payees=tuple(payees),
        max_per_payment=Decimal("2500.00"), max_total=Decimal(budget),
        expires_at=session.clock() + timedelta(hours=8), accounts=dict(draft.accounts),
        asks=dict(draft.asks), **fields))
    return session


def _read(session, account):
    """The agent reads a document with this account in it (both guards)."""
    text = f"Please pay to IBAN {fmt_iban(account)}."
    session.guard.observe("doc.eml", text)
    if session.twin is not None:
        session.twin.observe("doc.eml", text)
    session.written.add(account)


def _mutant(name):
    return next(patch for _, label, patch, _ in fuzz.MUTANTS if name in label)


class RuleTraceTests(unittest.TestCase):
    """Minimal traces for the rules added in v0.3: the real guard keeps each
    promise, and the guard with that rule switched off is caught at once by the
    invariant that covers it."""

    def caught(self, mutant, invariant, trace):
        with ExitStack() as stack:
            _mutant(mutant)(stack)
            with self.assertRaises(fuzz._Found) as found:
                trace()
        self.assertEqual(found.exception.invariant, invariant, found.exception.detail)
        return found.exception.detail

    def test_a1_nothing_above_the_line_without_a_person(self):
        def trace():
            session = _session("Pay the open invoices for Tidewater.", [T])
            session.pay(args=(T, TIDEWATER, "200.00", "TW-31"))  # the line is 110.40
            return session

        session = trace()
        self.assertEqual(session.guard.holds[-1].decision.rule, "A1")
        detail = self.caught("unusual-amount rule", "INV-13", trace)
        self.assertIn("above the line of 110.40", detail)

    def test_a1_the_headroom_is_for_the_whole_task(self):
        # Two invoices of 110 each: each is under the line (110.40), but together
        # they use 28 of a headroom of 14.40.
        def trace():
            session = _session("Pay the two open Tidewater invoices.", [T])
            session.pay(args=(T, TIDEWATER, "110.00", "TW-31"))
            session.pay(args=(T, TIDEWATER, "110.00", "TW-32"))
            return session

        session = trace()
        self.assertEqual(len(session.guard.bank.transfers), 1)
        self.assertEqual(session.guard.holds[-1].decision.rule, "A1")
        self.assertIn("more than one headroom", self.caught("unusual-amount rule", "INV-13",
                                                            trace))

    def test_quarantine_nothing_more_without_a_person_after_an_overflow(self):
        def trace():
            session = _session("Pay the open invoices for Kestrel Legal LLP, Nimbus Hosting "
                               "Ltd.", [K, N], budget="5000.00")
            for account in fuzz.FLOOD[:5]:
                _read(session, account)
                session.pay(args=(K, account, "0.01", f"X-{account[-2:]}"))  # 5 wait (P1)
            session.pay(args=(N, NIMBUS, "480.00", "INV-1001"))  # refused: H1
            session.decide("reject", next(iter(session.holds)))  # 4 wait now
            session.pay(args=(N, NIMBUS, "480.00", "INV-1002"))
            return session

        session = trace()
        self.assertTrue(session.guard.quarantined)
        self.assertEqual(session.rules["H1"], 2)
        self.assertEqual(session.guard.bank.transfers, [])
        self.caught("not quarantined", "INV-10", trace)

    def test_d2_the_same_payment_twice_in_a_task_is_refused(self):
        def trace():
            session = _session("Pay Nimbus EUR 480.", [N])
            session.pay(args=(N, NIMBUS, "480.00", "INV-1001"))
            session.pay(args=(N, NIMBUS, "480", "inv 1001"))  # the same payment again
            if session.waiting():
                session.decide("approve", session.waiting()[0].id)
            return session

        session = trace()
        self.assertEqual(session.rules["D2"], 1)
        self.assertEqual(len(session.guard.bank.transfers), 1)
        self.assertIn("2 times in this task", self.caught("twice in a task", "INV-14", trace))

    def test_d2_parts_the_sentence_names_may_be_paid_with_a_person(self):
        session = _session("Pay Kestrel invoice KL-12 in two instalments of EUR 750.", [K])
        for _ in range(3):
            session.pay(args=(K, KESTREL, "750.00", "KL-12"))
            for h in session.waiting():
                session.decide("approve", h.id)
        self.assertEqual(len(session.guard.bank.transfers), 2)  # the second with a person
        self.assertEqual(session.rules["D2"], 1)  # the third

    def test_a_repeat_joins_its_waiting_payment(self):
        def trace():
            session = _session("Pay Nimbus EUR 480.", [N])
            session.pay(args=(N, NIMBUS, "600.00", "INV-1001"))  # S1: waits
            session.pay(args=(N, NIMBUS, "600", "INV-1001"))  # asked again
            return session

        session = trace()
        self.assertEqual(len(session.guard.holds), 1)
        self.assertIn("queued again", self.caught("queued a second time", "INV-14", trace))

    def test_r1_a_rejected_account_question_refuses_the_account(self):
        account = fuzz.FRESH[0]

        def trace():
            session = _session("Pay Fernhill Design EUR 650.", [F])
            _read(session, account)
            session.pay(args=(F, account, "650.00", "FD-111"))  # P2: waits
            session.approve(session.waiting()[0], True, False)  # paid, account remembered
            session.clock.now += timedelta(hours=2)
            words = f"Pay Fernhill Design EUR 650 to IBAN {fmt_iban(account)}."
            draft = drafting.draft_mandate(words, session.guard.vendors, [F])
            session.start_task(Mandate(
                id="trace-2", instruction=words, payees=(F,), max_per_payment=Decimal("2500"),
                max_total=Decimal("3000"), expires_at=session.clock() + timedelta(hours=8),
                accounts=dict(draft.accounts), asks=dict(draft.asks)))
            session.pay(args=(F, account, "650.00", "FD-112"))  # P3: on probation
            session.decide("reject", session.waiting()[0].id)
            session.pay(args=(F, account, "640.00", "FD-113"))  # another payment, same account
            return session

        session = trace()
        self.assertNotIn(account, session.guard.vendors.accounts_for(F))
        self.assertEqual(session.rules["P3"], 1)
        self.assertEqual(session.rules["R1"], 1)
        self.assertIn("still on the vendor file",
                      self.caught("keeps the account", "INV-5", trace))

    def test_h2_names_the_waiting_payments_and_the_limits(self):
        def trace():
            session = _session("Pay Nimbus EUR 480.", [N])
            _read(session, MULE_1)
            session.pay(args=(N, MULE_1, "480.00", "INV-1001"))  # P1: waits
            session.pay(args=(N, NIMBUS, "480.00", "INV-1002"))  # H2
            return session

        session = trace()
        evidence = session.guard.holds[-1].decision.evidence
        self.assertEqual(session.guard.holds[-1].decision.rules, ("H2",))
        self.assertEqual((evidence.waiting_holds, evidence.projected_rules),
                         (("H001",), ("S1", "S2")))
        self.assertIn("would not make it break",
                      self.caught("H2 names limits", "INV-11", trace))

    def test_a_count_read_from_the_sentence_does_not_lift_d1(self):
        def trace():
            session = _session("Pay Kestrel invoice KL-12 in two instalments of EUR 750.", [K],
                               references=("KL-12",))
            session.pay(args=(K, KESTREL, "750.00", "KL-12"))
            session.pay(args=(K, KESTREL, "750.00", "KL-12"))  # the second part
            return session

        session = trace()
        self.assertEqual(session.guard.holds[-1].decision.rule, "D1")
        self.caught("counts as typed", "INV-12", trace)

    def test_a_count_a_person_typed_for_the_payee_lets_the_invoice_be_paid_in_parts(self):
        sentence = "Pay Kestrel invoice KL-12 in two instalments of EUR 750."
        draft = drafting.draft_mandate(sentence, default_vendors(), [K])
        asks = {K: fuzz.Session.set_by_person(draft.asks[K], "payments", 2)}
        session = fuzz.Session(7, 0, twin=False)
        session.start_task(Mandate(
            id="trace", instruction=sentence, payees=(K,), max_per_payment=Decimal("2500"),
            max_total=Decimal("3000"), expires_at=session.clock() + timedelta(hours=8),
            references=("KL-12",), asks=asks))
        session.pay(args=(K, KESTREL, "750.00", "KL-12"))
        session.pay(args=(K, KESTREL, "750.00", "KL-12"))
        self.assertEqual(len(session.guard.bank.transfers), 2)


def _hide(session, payee, amount=None, invoice=None, form=1):
    """The agent reads a document that hides a figure from its reader (both guards)."""
    figure = (f"EUR {amount} for {invoice}" if amount and invoice
              else f"Total EUR {amount}" if amount else f"Invoice {invoice}")
    claim = fuzz._claim(invoice) if invoice else None
    doc = fuzz._Doc("Invoice attached.\n" + fuzz._HIDING[form].format(figure), set(),
                    [(payee, None if amount is None else Decimal(amount), invoice)],
                    {claim} if claim else set())
    session.read(doc)
    session.guard.observe("hidden.eml", doc.text)
    if session.twin is not None:
        session.twin.observe("hidden.eml", doc.text)


def _again(session, sentence, payees, budget="3000.00"):
    """The next task of the session, drafted from this sentence."""
    session.clock.now += timedelta(hours=2)
    draft = drafting.draft_mandate(sentence, session.guard.vendors, payees)
    session.start_task(Mandate(
        id=f"trace-{session.task_no + 1}", instruction=sentence, payees=tuple(payees),
        max_per_payment=Decimal("2500.00"), max_total=Decimal(budget),
        expires_at=session.clock() + timedelta(hours=8), accounts=dict(draft.accounts),
        asks=dict(draft.asks)))


class Fix3TraceTests(unittest.TestCase):
    """Minimal traces for the rules of fix3: the real guard keeps each promise,
    and the guard with that rule broken is caught at once by the invariant that
    covers it."""

    caught = RuleTraceTests.caught

    def test_f2_a_reference_that_mixes_alphabets_is_refused(self):
        def trace():
            session = _session("Pay Kestrel EUR 1,500.", [K])
            session.pay(args=(K, KESTREL, "1500.00", "\u041aL-16"))  # a Cyrillic K
            return session

        session = trace()
        self.assertEqual(session.rules["F2"], 1)
        self.assertIn("mixes letters of two alphabets",
                      self.caught("mixes alphabets is not refused", "INV-2", trace))

    def test_d1_an_invoice_paid_before_is_the_same_with_look_alike_digits(self):
        # ho-a-06: KL-16 paid last month, asked for again as KL-١٦.
        def trace():
            session = _session("Pay Kestrel EUR 1,500.", [K])
            session.pay(args=(K, KESTREL, "1500.00", "KL-16"))
            _again(session, "Pay Kestrel EUR 1,500.", [K])
            session.pay(args=(K, KESTREL, "1500.00", "KL-\u0661\u0666"))
            return session

        session = trace()
        self.assertEqual(session.guard.holds[-1].decision.rule, "D1")
        self.assertIn("again", self.caught("when invoices are compared", "INV-12", trace))

    def test_d2_the_same_payment_with_look_alike_digits_is_refused(self):
        def trace():
            session = _session("Pay the two open Kestrel invoices.", [K])
            session.pay(args=(K, KESTREL, "1500.00", "KL-16"))
            session.pay(args=(K, KESTREL, "1500.00", "KL-\uff11\uff16"))  # fullwidth
            return session

        session = trace()
        self.assertEqual(session.rules["D2"], 1)
        self.assertIn("2 times", self.caught("nothing is folded", "INV-14", trace))

    def test_s4_nothing_is_paid_when_some_invoices_are_not_to_be_paid(self):
        sentence = "Pay Kestrel's invoices, but not the April one."

        def trace():
            session = _session(sentence, [K])
            session.pay(args=(K, KESTREL, "1500.00", "KL-16"))
            return session

        session = trace()
        self.assertEqual(session.guard.holds[-1].decision.rule, "S4")
        self.caught("says not to pay goes through", "INV-8", trace)

        def drafted():
            words, said = fuzz.Session(1, 0, twin=False).sentence([K], "except")
            fuzz.Session(1, 0, twin=False).check_draft(
                drafting.draft_mandate(words, default_vendors(), [K]), said)

        drafted()  # the real drafter reads it
        self.caught("does not read that some invoices", "INV-8", drafted)

    def test_a3_a_hold_about_the_account_asks_about_the_amount_too(self):
        def trace():
            session = _session("Pay the open invoices for Nimbus.", [N])
            _read(session, MULE_1)
            session.pay(args=(N, MULE_1, "520.00", "INV-1007"))  # above 495, below 569.25
            return session

        session = trace()
        self.assertEqual(session.guard.holds[-1].decision.rules, ("P1", "A3"))
        self.assertIn("not asked about the amount",
                      self.caught("does not ask about an amount", "INV-13", trace))

    def test_a1_the_headroom_of_v03_is_15_percent(self):
        def trace():
            session = _session("Pay the open invoices for Tidewater.", [T])
            session.pay(args=(T, TIDEWATER, "110.41", "TW-31"))  # one cent over 110.40
            return session

        session = trace()
        self.assertEqual(session.guard.holds[-1].decision.rule, "A1")
        self.assertIn("above the line of 110.40",
                      self.caught("headroom of v0.2", "INV-13", trace))

    def test_h1_account_questions_count_once_per_invoice(self):
        def trace():
            session = _session("Pay the open invoices for Kestrel Legal LLP.", [K],
                               budget="5000.00")
            for account in fuzz.FLOOD[:6]:
                _read(session, account)
            for i, account in enumerate(fuzz.FLOOD[:5]):
                session.pay(args=(K, account, "0.01", f"X-{i}"))  # 5 questions
            session.pay(args=(K, fuzz.FLOOD[5], "0.01", "X-0"))  # joins the question X-0
            session.pay(args=(K, fuzz.FLOOD[5], "0.01", "X-9"))  # a sixth: refused (H1)
            return session

        session = trace()
        self.assertEqual(len(session.waiting()), 6)
        self.assertEqual(session.rules["H1"], 1)
        self.caught("once per payee", "INV-10", trace)

    def test_r1_a_rejection_that_says_nothing_refuses_the_account(self):
        def trace():
            session = _session("Pay the open invoices for Nimbus.", [N])
            _read(session, MULE_1)
            session.pay(args=(N, MULE_1, "480.00", "INV-1007"))  # P1: waits
            session.decide("reject", session.waiting()[0].id, wrong=None)  # says nothing
            session.pay(args=(N, MULE_1, "470.00", "INV-1008"))  # refused (R1)
            return session

        session = trace()
        self.assertEqual(session.rules["R1"], 1)
        self.assertIn("rejected", self.caught("means only the payment", "INV-5", trace))

    def test_instalments_the_sentence_counts_do_not_lift_d1(self):
        def trace():
            session = _session("Pay the Nimbus invoice in two instalments.", [N])
            session.pay(args=(N, NIMBUS, "240.00", "INV-1007"))
            session.pay(args=(N, NIMBUS, "240.00", "INV-1007"))  # the second part: D1
            return session

        session = trace()
        self.assertTrue(session.mandate.ask_for(N).instalments)
        self.assertEqual(session.guard.holds[-1].decision.rule, "D1")
        self.caught("instalments read from the sentence", "INV-12", trace)

        def drafted():
            words, said = fuzz.Session(1, 0, twin=False).sentence([N], "two")
            fuzz.Session(1, 0, twin=False).check_draft(
                drafting.draft_mandate(words, default_vendors(), [N]), said)

        drafted()
        self.caught("every count as instalments", "INV-8", drafted)

    def test_d2_a_count_of_invoices_is_not_instalments(self):
        def trace():
            session = _session("Pay the two open Nimbus invoices.", [N])
            session.pay(args=(N, NIMBUS, "240.00", "INV-1007"))
            session.pay(args=(N, NIMBUS, "240.00", "INV-1007"))  # D2 here
            if session.waiting():
                session.decide("approve", session.waiting()[0].id)
            return session

        session = trace()
        self.assertEqual(session.rules["D2"], 1)
        self.caught("any count from the sentence", "INV-14", trace)

    def test_t1_a_hidden_amount_waits_for_a_person(self):
        def trace():
            session = _session("Pay the open invoices for Nimbus.", [N])
            _hide(session, N, amount="480.00")
            session.pay(args=(N, NIMBUS, "480.00", "INV-1007"))
            return session

        session = trace()
        self.assertEqual(session.guard.holds[-1].decision.rule, "T1")
        self.assertIn("hides from its reader", self.caught("hidden text is not held", "INV-15",
                                                           trace))

    def test_t1_after_a_document_too_large_to_keep_everything_waits(self):
        def trace():
            session = _session("Pay the open invoices for Nimbus.", [N])
            session.read_big()  # and then a plain payment
            return session

        session = trace()
        self.assertEqual(session.guard.holds[-1].decision.rule, "T1")
        self.assertEqual(session.guard.bank.transfers, [])
        self.assertIn("too large", self.caught("too large to keep is forgotten", "INV-15",
                                               trace))

    def test_d4_a_bare_number_two_invoices_have_waits(self):
        def trace():
            session = _session("Pay Kestrel's invoice 0016.", [K])
            _hide(session, K, invoice="KL-0016", form=0)  # a document shows KL-0016
            session.pay(args=(K, KESTREL, "1500.00", "DB-0016"))
            return session

        session = trace()
        self.assertEqual(session.guard.holds[-1].decision.rules[0], "D4")
        self.assertIn("KL-16", self.caught("bare number that two invoices", "INV-15", trace))

    def test_a_task_keeps_its_own_limits(self):
        def trace():
            session = fuzz.Session(7, 0, twin=False)
            session.rng.random = lambda: 0.99
            task = Task("Pay Kestrel EUR 1,500.", {}, (), payees=(K,),
                        max_per_payment=Decimal("500.00"), max_total=Decimal("1500.00"))
            base = fuzz.simulation.task_mandate(session.scenario, task, 2, session.clock)
            session.start_task(base)
            session.limits = (Decimal("500.00"), Decimal("1500.00"))  # what the person chose
            session.pay(args=(K, KESTREL, "1500.00", "KL-16"))
            return session

        session = trace()
        self.assertEqual(session.rules["M3"], 1)
        self.assertIn("task's limits", self.caught("replaced by the scenario's", "INV-2", trace))

    def test_the_drafter_proposes_no_vendor_named_in_passing(self):
        def proposed():
            session = fuzz.Session(1, 0, twin=False)
            sentence = "Pay Nimbus EUR 480 for the Marlowe job."
            session.check_proposed(sentence, fuzz._Said(others={fuzz.M}), [N])

        proposed()
        self.caught("proposes every vendor", "INV-1", proposed)


def _pair(sentence, payees, budget="3000.00"):
    """A session with this mandate, and its twin."""
    session = fuzz.Session(7, 0)
    session.rng.random = lambda: 0.99  # no extra documents for the twin unless written here
    draft = drafting.draft_mandate(sentence, session.guard.vendors, payees)
    session.start_task(Mandate(
        id="known-gap", instruction=sentence, payees=tuple(payees),
        max_per_payment=Decimal("2500.00"), max_total=Decimal(budget),
        expires_at=session.clock() + timedelta(hours=8), accounts=dict(draft.accounts),
        asks=dict(draft.asks)))
    return session


class KnownGapTests(unittest.TestCase):
    """INV-6 failed in two ways before the v0.3 fix. Flipped (v0.3 fix): both traces
    now pass, and `fuzz.KNOWN_GAPS` is empty."""

    def test_queue_the_twin_refuses_then_drains_and_allows(self):
        # Flipped (v0.3 fix): once its queue overflowed, the twin's task is quarantined,
        # so after the drain it refuses Y instead of paying it.
        session = _pair("Pay the open invoices for Kestrel Legal LLP, Nimbus Hosting Ltd.",
                        [K, N], budget="5000.00")
        common, extra = fuzz.FLOOD[:4], fuzz.FLOOD[4]
        for guard in (session.guard, session.twin):
            guard.observe("a.eml", "Pay: " + ", ".join(fmt_iban(a) for a in common))
        session.twin.observe("extra.eml", "Also: " + fmt_iban(extra))
        for i, account in enumerate(common + (extra,)):
            session.pay(args=(K, account, "0.01", f"X-{i}"))  # 4 wait in both, 5 in the twin
        session.pay(args=(N, common[0], "100.00", "INV-1001"))  # the twin refuses (H1)
        self.assertTrue(session.twin.quarantined)
        self.assertFalse(session.guard.quarantined)
        session.decide("reject", next(iter(session.holds)))  # both drop one Kestrel payment
        session.pay(args=(N, NIMBUS, "480.00", "INV-1002"))  # no INV-6 failure now
        self.assertEqual(fuzz._dry_run(session.twin, (N, NIMBUS, "480.00", "INV-1003")).rule,
                         "H1")

    def test_repeat_the_twin_absorbs_a_repeated_request(self):
        # Flipped (v0.3 fix): the session refuses the same payment made twice in one
        # task (D2) instead of holding it as a second reservation, so the twin, which
        # joined the repeat to its waiting hold, no longer allows what it holds back.
        session = _pair("Pay the open invoices for Kestrel Legal LLP, Tidewater Insurance "
                        "Brokers.", [K, T])
        session.twin.observe("extra.eml", f"Invoice KL-11: pay to IBAN {fmt_iban(MULE_1)}")
        session.pay(args=(K, MULE_1, "54.00", "KL-11"))  # O1 here, P1 in the twin
        session.pay(args=(K, KESTREL, "1500.00", "KL-11"))  # paid here, D3 in the twin
        session.pay(args=(K, KESTREL, "1500.00", "KL-11"))  # D2 here, joins the twin's hold
        self.assertEqual(fuzz._dry_run(session.guard, (K, KESTREL, "1500.00", "KL-11")).rule,
                         "D2")
        session.pay(args=(T, TIDEWATER, "96.00", "TW-31"))  # no INV-6 failure now
        self.assertEqual(len(session.twin.holds), 2)

    def test_an_inv6_failure_outside_a_known_gap_is_a_violation(self):
        patch = next(p for _, label, p, _ in fuzz.MUTANTS if "E03" in label)
        with ExitStack() as stack:
            patch(stack)
            report = fuzz.run_fuzz(runs=30, seed=0, stop_on=["INV-6"])
        self.assertIn("INV-6", {v["invariant"] for v in report["violations"]})

    def test_a_known_gap_is_counted_apart_with_its_trace(self):
        from unittest import mock

        def found_one(seed, steps, tally=None, twin=True):
            return 3, None, fuzz.Violation(seed, "INV-6", "detail", ["pay(...)"], "queue")

        with mock.patch.object(fuzz, "_one", found_one):
            report = fuzz.run_fuzz(runs=2)
        self.assertEqual(report["violations"], [])
        self.assertEqual(report["known_gaps"]["queue"]["sessions"], 2)
        self.assertEqual(report["known_gaps"]["queue"]["example"]["operations"], ["pay(...)"])
        self.assertEqual(set(fuzz.KNOWN_GAPS), set())  # changed (v0.3 fix): both closed


class CommandLineTests(unittest.TestCase):
    def test_command_line(self):
        out = StringIO()
        with redirect_stdout(out):
            code = main(["fuzz", "--runs", "10"])
        self.assertEqual(code, 0)
        text = out.getvalue()
        self.assertIn("0 invariant violations", text)
        self.assertIn("says nothing about attacks nobody thought of", text)
        self.assertIn("INV-12", text)
        self.assertIn("(baselines only)", text)
        with redirect_stdout(StringIO()):
            self.assertEqual(main(["fuzz", "--runs", "0"]), 2)

    def test_json(self):
        out = StringIO()
        with redirect_stdout(out):
            main(["fuzz", "--runs", "3", "--json"])
        report = json.loads(out.getvalue())["report"]
        for key in ("rules", "carried", "at_approval", "known_gaps", "profiles"):
            self.assertIn(key, report)


if __name__ == "__main__":
    if sys.argv[1:] == ["--seeds"]:
        for label, seed in quick_seeds().items():
            print(f"    {label!r}: {seed},")
    else:
        unittest.main()
