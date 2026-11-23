"""The person's side on the command line: init, task, holds and quickstart.

Run with: python3 -m unittest tests.test_console -v
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import stat
import sys
import tempfile
import unittest
from decimal import Decimal
from unittest import mock

from countersign import cli, console, dashboard, quickstart
from countersign.anchor import check_receipts, load_receipts
from countersign.console import CHECKED, NOT_CHECKED, describe_mandate, draft_payees, load_vendors
from countersign.iban import fmt_iban
from countersign.scenarios import BY_ID, FERNHILL, MULE_2, NIMBUS, fmt
from countersign.simulation import default_vendors
from countersign.store import Store
from countersign.toolsurface import DirInbox

N = "Nimbus Hosting Ltd"
F = "Fernhill Design"
SENTENCE = "Pay this month's Nimbus Hosting invoice."
ALLOW_SCRIPTED = {"COUNTERSIGN_ALLOW_SCRIPTED_APPROVAL": "1"}


class Run:
    """One command through `cli.main`, with the answers a person would type."""

    def __init__(self, code: int, out: str, err: str, prompts: list[str]) -> None:
        self.code, self.out, self.err, self.prompts = code, out, err, prompts


def run(*argv: str, answers=(), terminal: bool = False, env: dict | None = None) -> Run:
    out, err = io.StringIO(), io.StringIO()
    prompts: list[str] = []
    waiting = list(answers)

    def typed(prompt: str = "") -> str:
        prompts.append(prompt)
        if not waiting:
            raise EOFError
        return waiting.pop(0)

    with mock.patch.dict(os.environ):
        for name in ("COUNTERSIGN_DB", "COUNTERSIGN_ALLOW_SCRIPTED_APPROVAL",
                     "COUNTERSIGN_RECEIPTS"):
            os.environ.pop(name, None)
        os.environ.update(env or {})
        with mock.patch("builtins.input", typed), \
                mock.patch.object(console, "is_terminal", lambda: terminal), \
                mock.patch.object(quickstart, "is_terminal", lambda: terminal), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(list(argv))
    return Run(code, out.getvalue(), err.getvalue(), prompts)


class TempDir(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.dir = os.path.realpath(folder.name)
        self.db = os.path.join(self.dir, "countersign.db")

    def init(self) -> Store:
        if not os.path.exists(self.db):
            self.assertEqual(run("init", "--db", self.db, "--demo-vendors").code, 0)
        return Store(self.db)

    def start(self, *more: str) -> Store:
        store = self.init()
        done = run("task", "start", SENTENCE, "--payee", N, "--yes", "--db", self.db, *more)
        self.assertEqual(done.code, 0, done.err)
        return store

    def held(self, account: str = MULE_2, amount: str = "480.00") -> Store:
        store = self.start()
        port = store.agent()
        port.observe("INV-2041.eml", f"Pay to IBAN {fmt(account)}")
        self.assertEqual(port.pay(N, account, amount, "INV-2041")["hold_id"], "H001")
        return store


# --- init ---------------------------------------------------------------------------


class InitTests(TempDir):
    def test_init_creates_an_owner_only_database_with_the_demo_vendors(self):
        done = run("init", "--db", self.db, "--demo-vendors")
        self.assertEqual((done.code, done.err), (0, ""))
        self.assertIn(f"Created {self.db}", done.out)
        self.assertIn("no real money moves", done.out)
        self.assertEqual(stat.S_IMODE(os.stat(self.db).st_mode), 0o600)
        store = Store(self.db)
        state = store.state()
        self.assertEqual(state["vendors"], default_vendors().to_state())
        self.assertEqual(state["mode"], "countersign")
        self.assertIn(store.head()[1], done.out)

    def test_init_refuses_an_existing_file(self):
        store = self.init()
        head = store.head()
        done = run("init", "--db", self.db)
        self.assertEqual((done.code, done.out), (2, ""))
        self.assertIn("already a file", done.err)
        self.assertEqual(Store(self.db).head(), head)

    def test_init_without_vendors_and_with_another_guard(self):
        self.assertEqual(run("init", "--db", self.db, "--mode", "strict").code, 0)
        state = Store(self.db).state()
        self.assertEqual((state["vendors"], state["mode"]), ([], "strict"))

    def test_init_reads_a_vendor_file(self):
        vendors = os.path.join(self.dir, "vendors.json")
        with open(vendors, "w") as fp:
            json.dump([{"name": F, "accounts": [fmt(FERNHILL)], "history": ["650.00", "700"]},
                       {"name": "Newcomer GmbH"}], fp)
        self.assertEqual(run("init", "--db", self.db, "--vendors", vendors).code, 0)
        self.assertEqual(
            Store(self.db).state()["vendors"],
            [{"name": F, "accounts": [FERNHILL], "history": ["650.00", "700.00"]},
             {"name": "Newcomer GmbH", "accounts": [], "history": []}],
        )

    def test_a_bad_vendor_file_exits_2_and_creates_nothing(self):
        vendors = os.path.join(self.dir, "vendors.json")
        cases = {
            "{not json": "is not JSON",
            '{"name": "x"}': "list of vendors",
            '[{"accounts": []}]': "needs a name",
            '[{"name": "A", "accounts": "DE89"}]': "must be lists",
            '[{"name": "A", "accounts": [1]}]': "IBAN as text",
            '[{"name": "A", "accounts": ["DE00 0000"]}]': "not a valid IBAN",
            '[{"name": "A", "history": ["lots"]}]': "history must be amounts",
            '[{"name": "A"}, {"name": "a"}]': "listed twice",
        }
        for text, phrase in cases.items():
            with self.subTest(text=text):
                with open(vendors, "w") as fp:
                    fp.write(text)
                done = run("init", "--db", self.db, "--vendors", vendors)
                self.assertEqual((done.code, done.out), (2, ""))
                self.assertIn(phrase, done.err)
                self.assertNotIn("Traceback", done.err)
                self.assertFalse(os.path.exists(self.db))
        with self.assertRaises(ValueError):
            load_vendors(os.path.join(self.dir, "missing.json"))

    def test_the_database_path_comes_from_the_flag_the_environment_or_the_directory(self):
        from_env = os.path.join(self.dir, "env.db")
        self.assertEqual(run("init", env={"COUNTERSIGN_DB": from_env}).code, 0)
        self.assertTrue(os.path.isfile(from_env))
        flagged = os.path.join(self.dir, "flag.db")
        self.assertEqual(run("init", "--db", flagged, env={"COUNTERSIGN_DB": from_env}).code, 0)
        self.assertTrue(os.path.isfile(flagged))
        here = os.getcwd()
        os.chdir(self.dir)
        try:
            self.assertEqual(run("init").code, 0)
            self.assertEqual(run("task", "show").code, 0)
        finally:
            os.chdir(here)
        self.assertTrue(os.path.isfile(self.db))

    def test_commands_on_a_missing_database_exit_2_and_create_nothing(self):
        for argv in (["task", "show"], ["task", "end"], ["holds", "list"],
                     ["holds", "show", "H001"], ["task", "start", SENTENCE, "--payee", N, "--yes"]):
            with self.subTest(argv=argv):
                done = run(*argv, "--db", self.db)
                self.assertEqual((done.code, done.out), (2, ""))
                self.assertIn("No database at", done.err)
                self.assertIn("countersign init", done.err)
        self.assertEqual(os.listdir(self.dir), [])


# --- task -----------------------------------------------------------------------------


class TaskTests(TempDir):
    def test_start_with_yes_and_explicit_payees_signs_without_asking(self):
        store = self.init()
        done = run("task", "start", SENTENCE, "--payee", N, "--yes", "--db", self.db,
                   "--as", "sam")
        self.assertEqual((done.code, done.err, done.prompts), (0, "", []))
        mandate = store.mandate()
        self.assertEqual((mandate.instruction, mandate.payees), (SENTENCE, (N,)))
        self.assertEqual((mandate.max_per_payment, mandate.max_total),
                         (Decimal("2000.00"), Decimal("3000.00")))
        self.assertEqual((mandate.max_payments, mandate.references, mandate.accounts),
                         (None, (), {}))
        self.assertIn("Mandate to sign", done.out)
        self.assertIn("Accounts you are trusting for this task: none", done.out)
        self.assertIn(f"Task started: {mandate.id}", done.out)
        started = store.audit_entries()[-1]
        self.assertEqual((started["event"], started["data"]["confirmed_by"]),
                         ("task_started", "sam"))

    def test_every_limit_can_be_set(self):
        store = self.init()
        done = run("task", "start", "Pay Nimbus and Brightline.", "--payee", N,
                   "--payee", "Brightline Office Supplies", "--limit", "500", "--budget", "800.50",
                   "--hours", "2", "--payments", "3", "--reference", "INV-2041",
                   "--reference", "BL-5530", "--yes", "--db", self.db)
        self.assertEqual(done.code, 0, done.err)
        mandate = store.mandate()
        self.assertEqual(mandate.payees, (N, "Brightline Office Supplies"))
        self.assertEqual((mandate.max_per_payment, mandate.max_total),
                         (Decimal("500.00"), Decimal("800.50")))
        self.assertEqual((mandate.max_payments, mandate.references),
                         (3, ("INV-2041", "BL-5530")))
        for phrase in ("up to EUR 500.00", "EUR 800.50 in total", "at most 3",
                       "only INV-2041, BL-5530", "(in 2 hours)"):
            self.assertIn(phrase, done.out)
        # A larger limit lifts the default budget to match, and says so before signing.
        done = run("task", "start", SENTENCE, "--payee", N, "--limit", "5000", "--yes",
                   "--db", self.db)
        self.assertIn("EUR 5,000.00 in total", done.out)
        self.assertEqual(store.mandate().max_total, Decimal("5000.00"))

    def test_an_account_typed_in_the_sentence_is_shown_before_signing(self):
        store = self.init()
        sentence = f"Pay Fernhill Design EUR 650 for invoice FD-118 to IBAN {fmt(FERNHILL)}."
        done = run("task", "start", sentence, "--payee", F, "--db", self.db,
                   answers=["n"], terminal=True)
        self.assertEqual(done.code, 1)
        self.assertIn("Accounts you are trusting for this task:", done.out)
        self.assertIn(f"{F}: {fmt_iban(FERNHILL)}  (written in your sentence)", done.out)
        self.assertIn("Nothing was signed.", done.out)
        self.assertIsNone(store.mandate())

        done = run("task", "start", sentence, "--payee", F, "--db", self.db,
                   answers=["y"], terminal=True)
        self.assertEqual(done.code, 0)
        self.assertEqual(done.prompts, ["Sign this mandate? [y/N] "])
        self.assertEqual(store.mandate().accounts, {F: (FERNHILL,)})
        self.assertEqual(store.agent().pay(F, FERNHILL, "650.00", "FD-118")["outcome"], "ALLOW")

    def test_an_account_given_with_the_flag_is_shown_and_bound(self):
        store = self.init()
        done = run("task", "start", "Pay Fernhill and Nimbus.", "--payee", F, "--payee", N,
                   "--account", f"fernhill design={fmt(FERNHILL)}",
                   "--account", f"{N}={MULE_2}", "--yes", "--db", self.db)
        self.assertEqual(done.code, 0, done.err)
        self.assertIn(f"{F}: {fmt_iban(FERNHILL)}  (given with --account)", done.out)
        self.assertIn(f"{N}: {fmt_iban(MULE_2)}  (given with --account)", done.out)
        # The vendor file outranks the flag, and the person is told before signing.
        self.assertIn("outranks yours: a payment to this account will be held", done.out)
        self.assertEqual(store.mandate().accounts, {F: (FERNHILL,), N: (MULE_2,)})
        self.assertEqual(store.agent().pay(N, MULE_2, "10.00", "X-1")["outcome"], "HOLD")

    def test_accounts_in_a_sentence_with_several_payees_are_bound_to_nobody(self):
        store = self.init()
        done = run("task", "start", f"Pay Fernhill and Nimbus; use {fmt(FERNHILL)}.",
                   "--payee", F, "--payee", N, "--yes", "--db", self.db)
        self.assertEqual(done.code, 0)
        self.assertEqual(store.mandate().accounts, {})
        self.assertIn("names 1 account(s) that are not tied to a payee", done.out)
        self.assertIn(fmt_iban(FERNHILL), done.out)
        self.assertIn("--account PAYEE=IBAN", done.out)

    def test_signing_needs_a_terminal_unless_yes_and_explicit_payees(self):
        store = self.init()
        done = run("task", "start", SENTENCE, "--payee", N, "--db", self.db)
        self.assertEqual(done.code, 2)
        self.assertIn("needs a person at a terminal", done.err)
        self.assertEqual(done.prompts, [])
        # --yes is not enough when the payees were only suggested from the sentence.
        done = run("task", "start", SENTENCE, "--yes", "--db", self.db)
        self.assertEqual(done.code, 2)
        self.assertIn("--yes needs the payees given with --payee", done.err)
        self.assertIsNone(store.mandate())

        done = run("task", "start", SENTENCE, "--yes", "--db", self.db,
                   answers=["yes"], terminal=True)
        self.assertEqual(done.code, 0)
        self.assertEqual(len(done.prompts), 1)
        self.assertIn("suggested from the vendor file", done.out)
        self.assertEqual(store.mandate().payees, (N,))

    def test_suggested_payees(self):
        names = [v.name for v in default_vendors().all()]
        self.assertEqual(draft_payees(SENTENCE, names), [N])
        self.assertEqual(
            draft_payees("Pay the Nimbus Hosting and Brightline Office Supplies invoices.", names),
            [N, "Brightline Office Supplies"],
        )
        self.assertEqual(draft_payees("Pay Nimbus.", names), [])
        self.assertEqual(draft_payees("Pay the hosting bill of nimbus", names), [])
        self.assertEqual(draft_payees("pay ACME now", ["Acme", "Acme Tools"]), ["Acme"])
        self.assertEqual(draft_payees("", names), [])
        store = self.init()
        done = run("task", "start", "Pay Fernhill Design.", "--db", self.db, terminal=True)
        self.assertEqual(done.code, 2)
        self.assertIn("--payee NAME", done.err)
        self.assertIsNone(store.mandate())

    def test_a_mandate_that_cannot_be_signed_exits_2(self):
        store = self.init()
        cases = (
            (["--payee", N, "--limit", "0"], "--limit must be"),
            (["--payee", N, "--limit", "1e3"], "--limit must be"),
            (["--payee", N, "--budget", "-5"], "--budget must be"),
            (["--payee", N, "--limit", "500", "--budget", "100"], "not be larger"),
            (["--payee", N, "--hours", "0"], "--hours must be"),
            (["--payee", N, "--payments", "0"], "max_payments"),
            (["--payee", N, "--payee", "nimbus hosting ltd"], "same payee twice"),
            (["--payee", N, "--account", "no-equals-sign"], "PAYEE=IBAN"),
            (["--payee", N, "--account", f"{N}=DE00 1234"], "not a valid IBAN"),
            (["--payee", N, "--account", f"{F}={FERNHILL}"], "not a payee"),
        )
        for more, phrase in cases:
            with self.subTest(more=more):
                done = run("task", "start", SENTENCE, *more, "--yes", "--db", self.db)
                self.assertEqual(done.code, 2)
                self.assertIn(phrase, done.err)
                self.assertNotIn("Traceback", done.err)
        self.assertEqual(store.head()[0], 0)

    def test_starting_over_an_active_task_says_what_happens(self):
        store = self.held()
        first = store.mandate().id
        done = run("task", "start", SENTENCE, "--payee", N, "--yes", "--db", self.db)
        self.assertEqual(done.code, 0)
        self.assertIn(f"A task is active now ({first})", done.out)
        self.assertIn("payments still waiting under it expire", done.out)
        self.assertEqual(store.hold("H001").status, "expired")

    def test_show_and_end(self):
        store = self.init()
        self.assertIn("No task is active", run("task", "show", "--db", self.db).out)
        self.assertIn("No task is active", run("task", "end", "--db", self.db).out)
        self.held()
        store.agent().pay(N, NIMBUS, "480.00", "INV-2040")
        shown = run("task", "show", "--db", self.db)
        self.assertEqual(shown.code, 0)
        for phrase in (store.mandate().id, SENTENCE, "Paid so far   EUR 480.00 in 1 payment(s)",
                       "Waiting       1 payment(s)"):
            self.assertIn(phrase, shown.out)
        ended = run("task", "end", "--db", self.db, "--as", "sam")
        self.assertEqual(ended.code, 0)
        self.assertIn("ended", ended.out)
        self.assertIsNone(store.mandate())
        self.assertEqual(store.audit_entries()[-1]["data"]["by"], "sam")
        self.assertEqual(store.agent().pay(N, NIMBUS, "1.00", "X")["rule"], "M0")

    def test_the_mandate_summary_marks_a_past_expiry(self):
        store = self.start()
        mandate = store.mandate()
        lines = describe_mandate(mandate, None, mandate.expires_at)
        self.assertTrue(any("already past" in line for line in lines))


# --- holds ----------------------------------------------------------------------------


class HoldTests(TempDir):
    def test_list_and_show_give_both_accounts_in_full_and_every_reason(self):
        store = self.init()
        self.assertIn("No payment has been held", run("holds", "list", "--db", self.db).out)
        store = self.held(amount="1480.00")  # the wrong account and an unusual amount
        hold = store.hold("H001")
        self.assertEqual(hold.decision.rules, ("P1", "A1"))

        listed = run("holds", "list", "--db", self.db)
        self.assertEqual(listed.code, 0)
        self.assertIn("1 held payment(s), 1 waiting for a person", listed.out)
        self.assertIn(fmt_iban(MULE_2), listed.out)
        self.assertIn("[P1,A1]", listed.out)

        shown = run("holds", "show", "H001", "--db", self.db)
        self.assertEqual((shown.code, shown.prompts), (0, []))
        for phrase in (
            "Hold H001  (pending)",
            f"Payee       {N}",
            "Amount      EUR 1,480.00",
            "Reference   INV-2041",
            f"Pay to      {fmt_iban(MULE_2)}",
            f"On file     {fmt_iban(NIMBUS)}",
            "P1  Not the account on file",
            "A1  Unusual amount for this payee",
            hold.decision.reason,
            "untrusted document INV-2041.eml, line 1  (the sender chose that name)",
            "Earlier payments to this payee: 480.00, 480.00, 495.00",
            f"Digest      {hold.digest}",
        ):
            self.assertIn(phrase, shown.out)

        missing = run("holds", "show", "H404", "--db", self.db)
        self.assertEqual(missing.code, 2)
        self.assertIn("There is no hold H404", missing.err)

    def test_deciding_refuses_to_run_without_a_terminal(self):
        store = self.held()
        head = store.head()
        for action in ("approve", "reject"):
            with self.subTest(action=action):
                done = run("holds", action, "H001", "--db", self.db, answers=["y", "yes"])
                self.assertEqual((done.code, done.out, done.prompts), (2, "", []))
                self.assertIn("needs a person at a terminal", done.err)
                self.assertIn("COUNTERSIGN_ALLOW_SCRIPTED_APPROVAL=1", done.err)
                # Any other value of the variable is not the switch.
                done = run("holds", action, "H001", "--db", self.db, answers=["y", "yes"],
                           env={"COUNTERSIGN_ALLOW_SCRIPTED_APPROVAL": "true"})
                self.assertEqual(done.code, 2)
        self.assertEqual(store.head(), head)
        self.assertEqual(store.hold("H001").status, "pending")

    def test_approve_shows_the_hold_and_pays_after_a_typed_yes(self):
        store = self.held()
        hold = store.hold("H001")
        done = run("holds", "approve", "H001", "--db", self.db, "--as", "sam",
                   answers=["y", "yes"], env=ALLOW_SCRIPTED)
        self.assertEqual((done.code, done.err), (0, ""))
        self.assertEqual(len(done.prompts), 2)
        self.assertIn("contact details you already had", done.prompts[0])
        self.assertEqual(done.prompts[1], "Type yes to countersign and send this payment: ")
        # The whole hold was on screen before the question.
        for phrase in (f"Pay to      {fmt_iban(MULE_2)}", f"On file     {fmt_iban(NIMBUS)}",
                       hold.decision.reason, "P1  Not the account on file"):
            self.assertIn(phrase, done.out)
        self.assertIn(f"Countersigned. Transfer T001: EUR 480.00 to {N}, {fmt_iban(MULE_2)}.",
                      done.out)
        self.assertEqual(store.hold("H001").status, "approved")
        self.assertEqual(len(store.state()["bank"]["transfers"]), 1)
        approved = [e for e in store.audit_entries() if e["event"] == "hold_approved"][0]["data"]
        self.assertEqual(
            (approved["approver"], approved["attestation"], approved["digest"],
             approved["remember_account"]),
            ("sam", CHECKED, hold.digest, False),
        )
        # Not remembered: the next payment to that account is held again.
        self.assertEqual(store.agent().pay(N, MULE_2, "10.00", "INV-2050")["outcome"], "HOLD")

    def test_approve_at_a_terminal_needs_no_variable(self):
        store = self.held()
        done = run("holds", "approve", "H001", "--db", self.db, answers=["n", "yes"],
                   terminal=True)
        self.assertEqual(done.code, 0)
        approved = [e for e in store.audit_entries() if e["event"] == "hold_approved"][0]["data"]
        self.assertEqual(approved["attestation"], NOT_CHECKED)
        self.assertIn(f"Recorded as: {NOT_CHECKED}.", done.out)

    def test_anything_but_the_word_yes_decides_nothing(self):
        store = self.held()
        head = store.head()
        for action, answers in (("approve", ["y", "y"]), ("approve", ["y", "Yes please"]),
                                ("approve", ["y", ""]), ("approve", []), ("reject", ["y"]),
                                ("reject", ["no"]), ("reject", [])):
            with self.subTest(action=action, answers=answers):
                done = run("holds", action, "H001", "--db", self.db, answers=answers,
                           env=ALLOW_SCRIPTED)
                self.assertEqual(done.code, 1)
                self.assertIn("still waiting", done.out)
        self.assertEqual(store.head(), head)
        self.assertEqual(store.state()["bank"]["transfers"], [])

    def test_remember_account_is_a_separate_explicit_choice(self):
        store = self.held()
        done = run("holds", "approve", "H001", "--remember-account", "--db", self.db,
                   answers=["y", "YES"], env=ALLOW_SCRIPTED)
        self.assertEqual(done.code, 0)
        self.assertIn("You asked to remember this account", done.out)
        self.assertIn(MULE_2, store.state()["vendors"][0]["accounts"])
        self.assertIn("vendor_account_added", [e["event"] for e in store.audit_entries()])

    def test_reject_refuses_the_payee_and_account_for_the_task(self):
        store = self.held()
        done = run("holds", "reject", "H001", "--db", self.db, "--as", "sam",
                   answers=["yes"], env=ALLOW_SCRIPTED)
        self.assertEqual((done.code, done.err), (0, ""))
        self.assertEqual(done.prompts, ["Type yes to reject this payment: "])
        self.assertIn(f"Pay to      {fmt_iban(MULE_2)}", done.out)
        self.assertIn("Rejected H001. Nothing was paid", done.out)
        self.assertEqual(store.hold("H001").status, "rejected")
        self.assertEqual(store.hold("H001").decided_by, "sam")
        self.assertEqual(store.agent().pay(N, MULE_2, "480.00", "INV-2041")["rule"], "R1")
        shown = run("holds", "show", "H001", "--db", self.db).out
        self.assertIn("Decided     rejected by sam at ", shown)

    def test_a_hold_that_cannot_be_decided_any_more(self):
        store = self.held()
        run("holds", "reject", "H001", "--db", self.db, answers=["yes"], env=ALLOW_SCRIPTED)
        head = store.head()
        for action in ("approve", "reject"):
            done = run("holds", action, "H001", "--db", self.db, answers=["y", "yes"],
                       env=ALLOW_SCRIPTED)
            self.assertEqual((done.code, done.prompts), (1, []))
            self.assertIn("already rejected", done.err)
        for action in ("approve", "reject"):
            done = run("holds", action, "H404", "--db", self.db, answers=["y", "yes"],
                       env=ALLOW_SCRIPTED)
            self.assertEqual((done.code, done.prompts), (2, []))
        self.assertEqual(store.head(), head)

    def test_a_hold_of_an_earlier_task_is_not_offered_for_approval(self):
        store = self.held()
        store.console().end_task(by="sam")
        done = run("holds", "approve", "H001", "--db", self.db, answers=["y", "yes"],
                   env=ALLOW_SCRIPTED)
        self.assertEqual((done.code, done.prompts), (1, []))
        self.assertIn("already expired", done.err)
        self.assertEqual(store.state()["bank"]["transfers"], [])

    def test_a_new_reason_since_the_hold_was_shown_stops_the_payment(self):
        store = self.held()
        # While the person reads the hold, the agent gets a large payment through.
        store.agent().pay(N, NIMBUS, "495.00", "INV-2040")
        done = run("holds", "approve", "H001", "--db", self.db, answers=["y", "yes"],
                   env=ALLOW_SCRIPTED)
        self.assertEqual(done.code, 1)
        self.assertIn("Nothing was paid. Since this hold was shown, another reason applies",
                      done.out)
        self.assertIn("countersign holds show H001", done.out)
        self.assertEqual(store.hold("H001").status, "pending")
        self.assertEqual(store.hold("H001").decision.rules, ("P1", "A1"))
        self.assertEqual(len(store.state()["bank"]["transfers"]), 1)

    def test_a_refusal_at_approval_is_reported(self):
        store = self.init()
        run("task", "start", SENTENCE, "--payee", N, "--limit", "480", "--budget", "500",
            "--yes", "--db", self.db)
        port = store.agent()
        port.observe("INV-2041.eml", f"IBAN {fmt(MULE_2)}")
        port.pay(N, MULE_2, "480.00", "INV-2041")
        port.pay(N, NIMBUS, "480.00", "INV-2040")  # uses up the budget
        done = run("holds", "approve", "H001", "--db", self.db, answers=["y", "yes"],
                   env=ALLOW_SCRIPTED)
        self.assertEqual(done.code, 1)
        self.assertIn("Not paid.", done.out)
        self.assertEqual(len(store.state()["bank"]["transfers"]), 1)

    def test_text_from_an_agent_cannot_draw_on_the_terminal(self):
        self.assertEqual(console.show("a\x1b[2Jb\nc"), "a?[2Jb?c")
        self.assertEqual(console.show("x" * 300, 10), "xxxxxxx...")

    def test_help_says_how_scripted_approval_is_allowed(self):
        for action in ("approve", "reject"):
            out = io.StringIO()
            with contextlib.redirect_stdout(out), self.assertRaises(SystemExit):
                cli.main(["holds", action, "--help"])
            text = " ".join(out.getvalue().split())
            self.assertIn("COUNTERSIGN_ALLOW_SCRIPTED_APPROVAL=1", text)
            self.assertIn("tests and demos only", text)
        self.assertEqual(run("holds").code, 2)
        self.assertEqual(run("task").code, 2)


# --- quickstart -------------------------------------------------------------------------


class QuickstartTests(TempDir):
    def setUp(self):
        super().setUp()
        self.demo = os.path.join(self.dir, "demo")
        self.demo_db = os.path.join(self.demo, "countersign.db")
        self.inbox = os.path.join(self.demo, "inbox")

    def test_it_sets_up_a_directory_and_a_signed_task(self):
        done = run("quickstart", "--dir", self.demo, "--no-serve", "--yes")
        self.assertEqual((done.code, done.err, done.prompts), (0, "", []))
        scenario = BY_ID["attack-02"]
        self.assertEqual(sorted(os.listdir(self.demo))[:3],
                         ["countersign.db", "inbox", "receipts.jsonl"])
        self.assertEqual(stat.S_IMODE(os.stat(self.demo_db).st_mode), 0o600)
        inbox = DirInbox(self.inbox)
        self.assertEqual(inbox.names(), list(scenario.documents))
        for name, text in scenario.documents.items():
            self.assertEqual(inbox.read(name), text)

        store = Store(self.demo_db)
        state = store.state()
        self.assertEqual(state["vendors"], default_vendors().to_state())
        mandate = store.mandate()
        self.assertEqual((mandate.id, mandate.instruction, mandate.payees),
                         ("mandate-attack-02", scenario.instruction, scenario.payees))
        self.assertEqual((mandate.max_per_payment, mandate.max_total),
                         (scenario.max_per_payment, scenario.max_total))
        self.assertEqual(store.meta()["inbox"], self.inbox)
        receipts = load_receipts(os.path.join(self.demo, "receipts.jsonl"))
        self.assertEqual([r.seq for r in receipts], [0, 1])
        self.assertTrue(all(f.ok for f in check_receipts(store.audit_entries(), receipts)))

    def test_it_prints_how_to_connect_an_agent_and_the_caveat(self):
        done = run("quickstart", "--dir", self.demo, "--no-serve", "--yes")
        out = done.out
        self.assertIn("Mandate to sign", out)
        self.assertIn("Pay this month's Nimbus Hosting invoice.", out)
        block = {"mcpServers": {"countersign": {
            "command": sys.executable,
            "args": ["-m", "countersign", "mcp", "--db", self.demo_db, "--inbox", self.inbox],
        }}}
        self.assertIn(json.dumps(block, indent=2), out)
        self.assertRegex(
            out,
            r"claude mcp add countersign (-e PYTHONPATH=\S+ )?-- \S+ -m countersign mcp "
            r"--db \S+countersign\.db --inbox \S+inbox\n",
        )
        self.assertIn(f"-m countersign agent --db {self.demo_db} --inbox {self.inbox} "
                      "--scenario attack-02", out)
        self.assertIn("scripted agent (no model", out)
        self.assertIn(
            "If your agent has a shell or file access as this user, it can reach this database "
            "directly. Use an agent without those tools, or run it in a container.",
            out,
        )
        self.assertNotIn("tamper-proof", out)

    def test_it_refuses_a_directory_that_already_has_a_database(self):
        self.assertEqual(run("quickstart", "--dir", self.demo, "--no-serve", "--yes").code, 0)
        head = Store(self.demo_db).head()
        done = run("quickstart", "--dir", self.demo, "--no-serve", "--yes")
        self.assertEqual((done.code, done.out), (2, ""))
        self.assertIn("already a database", done.err)
        self.assertEqual(Store(self.demo_db).head(), head)

    def test_signing_needs_a_terminal_or_yes(self):
        done = run("quickstart", "--dir", self.demo, "--no-serve")
        self.assertEqual((done.code, done.out), (2, ""))
        self.assertIn("needs a person at a terminal", done.err)
        self.assertFalse(os.path.exists(self.demo))

        done = run("quickstart", "--dir", self.demo, "--no-serve", answers=["n"], terminal=True)
        self.assertEqual(done.code, 1)
        self.assertEqual(done.prompts, ["Sign this mandate? [y/N] "])
        self.assertIn("Nothing was signed", done.out)
        self.assertIsNone(Store(self.demo_db).mandate())

        other = os.path.join(self.dir, "other")
        done = run("quickstart", "--dir", other, "--no-serve", answers=["y"], terminal=True)
        self.assertEqual(done.code, 0)
        self.assertEqual(done.prompts, ["Sign this mandate? [y/N] "])
        self.assertIsNotNone(Store(os.path.join(other, "countersign.db")).mandate())

    def test_another_scenario_and_an_unknown_one(self):
        done = run("quickstart", "--dir", self.demo, "--scenario", "attack-03", "--no-serve",
                   "--yes")
        self.assertEqual(done.code, 0)
        self.assertEqual(DirInbox(self.inbox).names(), sorted(BY_ID["attack-03"].documents))
        self.assertIn("--scenario attack-03", done.out)
        done = run("quickstart", "--dir", os.path.join(self.dir, "x"), "--scenario", "nope",
                   "--no-serve", "--yes")
        self.assertEqual(done.code, 2)
        self.assertIn("no scenario nope", done.err)
        self.assertFalse(os.path.exists(os.path.join(self.dir, "x")))

    def test_the_scripted_agent_then_runs_against_it(self):
        self.assertEqual(run("quickstart", "--dir", self.demo, "--no-serve", "--yes").code, 0)
        done = run("agent", "--db", self.demo_db, "--inbox", self.inbox, "--scenario",
                   "attack-02", "--delay", "0")
        self.assertEqual(done.code, 0)
        self.assertIn("HOLD P1  hold H001", done.out)
        self.assertEqual(Store(self.demo_db).state()["bank"]["transfers"], [])

    def test_the_web_console_is_started_on_the_new_database(self):
        calls = []

        def serve(port=8377, db=None):
            calls.append((port, db))

        with mock.patch.object(dashboard, "serve", serve):
            done = run("quickstart", "--dir", self.demo, "--yes", "--port", "8399")
        self.assertEqual(done.code, 0)
        self.assertEqual(calls, [(8399, self.demo_db)])


if __name__ == "__main__":
    unittest.main()
