"""The shared database: one state and one audit log for several processes.

Run with: python3 -m unittest tests.test_store -v
"""

from __future__ import annotations

import json
import os
import sqlite3
import stat
import subprocess
import sys
import tempfile
import textwrap
import threading
import unittest
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from unittest import mock

from countersign import cli, store as store_module
from countersign.anchor import check_receipts, load_receipts
from countersign.audit import AuditLog, reconcile
from countersign.guard import Guard, PayResult
from countersign.models import Mandate, Outcome
from countersign.scenarios import BY_ID, MULE_2, NIMBUS, SCENARIOS, fmt
from countersign.simulation import (
    FakeClock,
    default_vendors,
    log_id,
    run_scenario,
    scenario_mandate,
)
from countersign.policy import GUARD_MODES
from countersign.store import (
    AgentPort,
    Console,
    DbAuditLog,
    Store,
    StoreError,
    StoreExists,
    StoreMissing,
    StoreVersionError,
    audit_head,
    open_agent,
)
from countersign.toolsurface import pay_view

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
N = "Nimbus Hosting Ltd"


def public(cls) -> list[str]:
    return sorted(name for name in vars(cls) if not name.startswith("_"))


class TempDir(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.dir = folder.name

    def path(self, name: str = "countersign.db") -> str:
        return os.path.join(self.dir, name)

    def make(self, name: str = "countersign.db", **options) -> Store:
        options.setdefault("vendors", default_vendors())
        return Store.create(self.path(name), **options)

    def mandate(self, **over) -> Mandate:
        fields = dict(
            id="task-1",
            instruction="Pay this month's Nimbus Hosting invoice.",
            payees=(N,),
            max_per_payment=Decimal("2000"),
            max_total=Decimal("3000"),
            expires_at=datetime.now(timezone.utc) + timedelta(hours=8),
        )
        fields.update(over)
        return Mandate(**fields)

    def held(self, store: Store) -> str:
        """Start a task and get one payment held (the swapped account of attack-02)."""
        store.console().start_task(self.mandate(), confirmed_by="tester")
        port = store.agent()
        port.observe("INV-2041.eml", f"Pay to IBAN {fmt(MULE_2)}")
        answer = port.pay(N, MULE_2, "480.00", "INV-2041")
        self.assertEqual((answer["outcome"], answer["rule"]), ("HOLD", "P1"))
        return answer["hold_id"]


# --- the same decisions as the in-memory guard -----------------------------------


def answer_hold(store: Store, attempt, hold_id: str, approver: str) -> None:
    """The person of the simulation (`simulation._answer_hold`), acting
    through the store's console instead of on the guard in memory."""
    hold = store.hold(hold_id)
    if hold.status != "pending":
        return
    approve = approver == "careless" or (approver == "careful" and attempt.legit)
    if approve:
        for _ in range(3):
            hold = store.hold(hold_id)
            answer = store.console().approve(
                hold.id, approver=f"{approver} approver", digest=hold.digest
            )
            if answer.transfer_id is not None or answer.decision.outcome is not Outcome.HOLD:
                break
    elif getattr(attempt, "reject", False):
        store.console().reject(hold.id, approver="scenario user")


class ReplayTests(TempDir):
    def test_every_scenario_decides_and_hashes_exactly_like_the_simulation(self):
        """Every scenario under every guard with nobody approving, and under
        Countersign also with a careful and a careless approver, so that every
        console method is compared too."""
        compared = expected_count = 0
        for scenario in SCENARIOS:
            runs = [(mode, "none") for mode in GUARD_MODES]
            if any(r.hold_id for r in run_scenario(scenario, "countersign").results):
                # Something is held, so who answers makes a difference.
                runs += [("countersign", "careful"), ("countersign", "careless")]
            expected_count += len(runs) * len(scenario.attempts)
            for mode, approver in runs:
                with self.subTest(scenario=scenario.id, mode=mode, approver=approver):
                    expected = run_scenario(scenario, mode, approver)
                    clock = FakeClock()
                    store = self.make(
                        f"{scenario.id}-{mode}-{approver}.db", mode=mode, clock=clock,
                        log_id=log_id(scenario, mode),
                    )
                    store.console().start_task(
                        scenario_mandate(scenario, clock), confirmed_by="scenario user"
                    )
                    clock.advance(scenario.delay_hours)
                    port = store.agent()
                    for name, text in scenario.documents.items():
                        port.observe(name, text)
                    answers = []
                    for a in scenario.attempts:
                        answer = port.pay(a.payee, a.account, a.amount, a.reference)
                        answers.append(answer)
                        if answer["hold_id"] is not None:
                            answer_hold(store, a, answer["hold_id"], approver)
                    # Decisions, hold ids and transfer ids.
                    self.assertEqual(answers, [pay_view(r) for r in expected.results])
                    # The log, entry for entry, and so the head hash.
                    self.assertEqual(store.audit_entries(), expected.guard.audit.entries)
                    self.assertEqual(store.head(), expected.guard.audit.head())
                    self.assertEqual(store.state(), expected.guard.to_state())
                    self.assertEqual(store.verify(), (True, None))
                    # Log and bank agree exactly as far as they do in memory.
                    self.assertEqual(
                        store.reconcile(),
                        reconcile(expected.guard.audit.entries, expected.bank.transfers),
                    )
                    if mode == "countersign":
                        self.assertEqual(store.reconcile(), [])
                    compared += len(answers)
        self.assertEqual(compared, expected_count)
        self.assertGreater(compared, 3 * sum(len(s.attempts) for s in SCENARIOS))

    def test_approval_through_the_console_matches_the_guard(self):
        scenario = BY_ID["attack-02"]
        expected = run_scenario(scenario, "countersign")
        clock = FakeClock()
        store = self.make(clock=clock, log_id=log_id(scenario, "countersign"))
        store.console().start_task(scenario_mandate(scenario, clock), confirmed_by="scenario user")
        for name, text in scenario.documents.items():
            store.agent().observe(name, text)
        answer = store.agent().pay(N, MULE_2, Decimal("480.00"), "INV-2041")
        hold = store.hold(answer["hold_id"])

        ours = store.console().approve(
            hold.id, approver="sam", digest=hold.digest, attestation="not checked"
        )
        theirs = expected.guard.approve(
            hold.id, "sam", digest=hold.digest, attestation="not checked"
        )
        self.assertIsInstance(ours, PayResult)
        self.assertEqual(ours.transfer_id, "T001")
        self.assertEqual(ours.decision.to_dict(), theirs.decision.to_dict())
        self.assertEqual(store.head(), expected.guard.audit.head())
        self.assertEqual(store.agent().hold_status(hold.id),
                         {"hold_id": "H001", "status": "approved", "transfer_id": "T001"})


# --- creating and opening ---------------------------------------------------------


class FileTests(TempDir):
    def test_the_file_is_created_owner_only_and_in_wal_mode(self):
        old = os.umask(0)  # even with a permissive umask
        try:
            store = self.make()
        finally:
            os.umask(old)
        self.assertEqual(stat.S_IMODE(os.stat(store.path).st_mode), 0o600)
        self.held(store)
        for name in os.listdir(self.dir):
            with self.subTest(file=name):
                self.assertEqual(stat.S_IMODE(os.stat(self.path(name)).st_mode), 0o600)
        conn = sqlite3.connect(store.path)
        try:
            self.assertEqual(conn.execute("PRAGMA journal_mode").fetchone()[0], "wal")
            tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master")}
        finally:
            conn.close()
        self.assertLessEqual({"meta", "state", "audit"}, tables)

    def test_create_refuses_an_existing_file_and_leaves_it_alone(self):
        store = self.make()
        head = store.head()
        with self.assertRaises(StoreExists):
            Store.create(store.path)
        self.assertEqual(Store(store.path).head(), head)
        other = self.path("notes.txt")
        with open(other, "w") as fp:
            fp.write("mine")
        with self.assertRaises(StoreExists):
            Store.create(other)
        with open(other) as fp:
            self.assertEqual(fp.read(), "mine")

    def test_a_bad_argument_creates_no_file(self):
        for options in ({"mode": "lenient"}, {"balance": 5}, {"balance": Decimal("-1")},
                        {"balance": Decimal("NaN")}):
            with self.subTest(options=options):
                with self.assertRaises(ValueError):
                    Store.create(self.path("bad.db"), **options)
                self.assertEqual(os.listdir(self.dir), [])

    def test_opening_never_creates_a_database(self):
        missing = self.path("nothing-here.db")
        for attempt in (lambda: Store(missing), lambda: open_agent(missing),
                        lambda: audit_head(missing)):
            with self.assertRaises(StoreMissing) as caught:
                attempt()
            self.assertIn("No database at", str(caught.exception))
        self.assertEqual(os.listdir(self.dir), [])

    def test_a_database_deleted_under_an_open_store_is_not_recreated(self):
        store = self.make()
        for name in os.listdir(self.dir):
            os.remove(self.path(name))
        with self.assertRaises(StoreMissing):
            store.agent().pay(N, NIMBUS, "1.00", "X-1")
        with self.assertRaises(StoreMissing):
            store.head()
        self.assertEqual(os.listdir(self.dir), [])

    def test_a_wrong_schema_version_is_refused_with_a_clear_message(self):
        store = self.make()
        conn = sqlite3.connect(store.path)
        conn.execute("UPDATE meta SET value = '99' WHERE key = 'schema_version'")
        conn.commit()
        conn.close()
        with self.assertRaises(StoreVersionError) as caught:
            Store(store.path)
        self.assertIn("layout version 99", str(caught.exception))
        self.assertIn("reads version 1", str(caught.exception))

    def test_a_file_that_is_not_a_countersign_database_is_refused(self):
        text = self.path("notes.db")
        with open(text, "w") as fp:
            fp.write("this is not a database, it is a long enough note to be read as one\n" * 20)
        other = self.path("other.db")
        conn = sqlite3.connect(other)
        conn.execute("CREATE TABLE things (x)")
        conn.commit()
        conn.close()
        for path in (text, other):
            with self.subTest(path=os.path.basename(path)):
                with self.assertRaises(StoreError) as caught:
                    Store(path)
                self.assertNotIsInstance(caught.exception, StoreMissing)

    def test_a_new_store_holds_what_it_was_given(self):
        store = self.make(balance=Decimal("1234.50"), mode="strict", log_id="feedfacefeedface")
        state = store.state()
        self.assertEqual(state["mode"], "strict")
        self.assertEqual(state["bank"]["balance"], "1234.50")
        self.assertEqual([v["name"] for v in state["vendors"]],
                         [v.name for v in default_vendors().all()])
        self.assertIsNone(store.mandate())
        self.assertEqual(store.holds(), [])
        entries = store.audit_entries()
        self.assertEqual([e["event"] for e in entries], ["log_opened"])
        self.assertEqual(entries[0]["data"], {"log_id": "feedfacefeedface", "version": 1})
        self.assertEqual(store.meta()["log_id"], "feedfacefeedface")
        self.assertEqual(store.meta()["schema_version"], "1")
        self.assertEqual(self.make("two.db").state()["bank"]["balance"], "50000.00")
        self.assertEqual(Store.create(self.path("empty.db")).state()["vendors"], [])

    def test_two_stores_do_not_share_a_log_id(self):
        self.assertNotEqual(self.make("a.db").head(), self.make("b.db").head())


# --- the capability boundary ------------------------------------------------------


class BoundaryTests(TempDir):
    def test_the_agent_port_has_exactly_four_methods(self):
        self.assertEqual(public(AgentPort), ["hold_status", "observe", "pay", "task"])
        port = self.make().agent()
        for word in ("approve", "reject", "start_task", "end_task", "console"):
            self.assertFalse(hasattr(port, word), word)
        with self.assertRaises(AttributeError):
            port.extra = 1  # no room to hang anything else on it

    def test_the_console_has_exactly_the_person_s_four_methods(self):
        self.assertEqual(public(Console), ["approve", "end_task", "reject", "start_task"])

    def test_open_agent_returns_only_the_port(self):
        store = self.make()
        port = open_agent(store.path)
        self.assertIs(type(port), AgentPort)
        self.assertEqual(audit_head(store.path), store.head())

    def test_what_the_agent_is_told(self):
        store = self.make()
        port = store.agent()
        self.assertIsNone(port.task())
        self.assertIsNone(port.hold_status("H001"))
        mandate = self.mandate(max_payments=2, references=("INV-2041",))
        store.console().start_task(mandate, confirmed_by="tester")
        self.assertEqual(
            port.task(),
            {"instruction": mandate.instruction, "payees": [N], "currency": "EUR",
             "expires_at": mandate.expires_at.isoformat()},
        )
        port.observe("INV-2041.eml", f"IBAN {fmt(MULE_2)}")
        answer = port.pay(N, fmt(MULE_2), "480", "INV-2041")
        self.assertEqual(
            sorted(answer), ["hold_id", "outcome", "reason", "rule", "rules", "transfer_id"]
        )
        self.assertEqual(answer["rules"], ["P1"])
        self.assertEqual(answer["reason"], store.hold("H001").decision.reason)
        self.assertEqual(port.hold_status("H001"),
                         {"hold_id": "H001", "status": "pending", "transfer_id": None})
        self.assertIsNone(port.hold_status("H999"))
        # Nothing about limits, budgets, balances or the rule ladder leaves the port.
        told = json.dumps([port.task(), answer, port.hold_status("H001")])
        for secret in ("3000", "2000", "50000", "max_", "checks", "evidence", "digest"):
            self.assertNotIn(secret, told)

    def test_pay_never_raises_on_odd_arguments_and_logs_them(self):
        store = self.make()
        store.console().start_task(self.mandate(), confirmed_by="tester")
        port = store.agent()
        before = store.head()[0]
        odd = [(None, None, None, None), ("", "", "", ""), (N, NIMBUS, float("nan"), "R"),
               (N, "x" * 5000, "1e9", "R"), (["a"], {"b": 1}, object(), 7),
               ("\ud800", "\udfff", "-1", "\x00")]
        for arguments in odd:
            with self.subTest(arguments=repr(arguments)[:40]):
                self.assertEqual(port.pay(*arguments)["outcome"], "BLOCK")
        self.assertEqual(store.head()[0], before + len(odd))
        self.assertEqual(store.verify(), (True, None))


# --- all or nothing ---------------------------------------------------------------


class RollbackTests(TempDir):
    def test_a_failure_in_the_middle_changes_nothing(self):
        store = self.make()
        store.console().start_task(self.mandate(), confirmed_by="tester")
        head, state = store.head(), store.state()

        class Crash(Exception):
            pass

        # The payment is decided, logged and sent to the bank; then the
        # snapshot cannot be written.
        with mock.patch.object(Guard, "to_state", side_effect=Crash("in the middle")):
            with self.assertRaises(Crash):
                store.agent().pay(N, NIMBUS, "480.00", "INV-2041")
        self.assertEqual(store.head(), head)
        self.assertEqual(store.state(), state)
        self.assertEqual(store.state()["bank"]["transfers"], [])

        answer = store.agent().pay(N, NIMBUS, "480.00", "INV-2041")
        self.assertEqual((answer["outcome"], answer["transfer_id"]), ("ALLOW", "T001"))
        self.assertEqual(store.verify(), (True, None))
        self.assertEqual(store.reconcile(), [])

    def test_a_failed_console_call_changes_nothing(self):
        store = self.make()
        hold_id = self.held(store)
        head, state = store.head(), store.state()
        with self.assertRaises(KeyError):
            store.console().approve("H999", approver="sam")
        with self.assertRaises(ValueError):
            store.console().approve(hold_id, approver="sam", digest="0" * 64)
        with self.assertRaises(TypeError):
            store.console().start_task({"not": "a mandate"}, confirmed_by="sam")
        with self.assertRaises(TypeError):
            store.agent().observe("name", b"bytes")
        self.assertEqual(store.head(), head)
        self.assertEqual(store.state(), state)

    def test_a_log_that_cannot_be_written_stops_the_whole_operation(self):
        store = self.make()
        store.console().start_task(self.mandate(), confirmed_by="tester")
        head, state = store.head(), store.state()
        real = DbAuditLog.append
        calls = []

        def failing(log, event, data):
            calls.append(event)
            if event == "payment_executed":
                log.failed = sqlite3.OperationalError("disk I/O error")
                raise log.failed
            return real(log, event, data)

        # The guard itself swallows a log failure after the bank answered.
        # The store must not commit a payment whose entry is missing.
        with mock.patch.object(DbAuditLog, "append", failing):
            with self.assertRaises(StoreError) as caught:
                store.agent().pay(N, NIMBUS, "480.00", "INV-2041")
        self.assertIn("nothing was changed", str(caught.exception))
        self.assertEqual(calls, ["payment_decision", "payment_submitted", "payment_executed"])
        self.assertEqual(store.head(), head)
        self.assertEqual(store.state(), state)
        self.assertEqual(store.reconcile(), [])

    def test_a_process_killed_in_the_middle_leaves_the_head_unchanged(self):
        store = self.make()
        store.console().start_task(self.mandate(), confirmed_by="tester")
        head, state = store.head(), store.state()
        script = textwrap.dedent(
            """
            import os, sys
            from countersign.guard import Guard
            from countersign.store import Store

            def die(self):
                os._exit(7)  # no clean-up at all, like a power cut

            Guard.to_state = die
            Store(sys.argv[1]).agent().pay("Nimbus Hosting Ltd", sys.argv[2], "480.00", "INV-1")
            """
        )
        done = subprocess.run(
            [sys.executable, "-c", script, store.path, NIMBUS],
            env={**os.environ, "PYTHONPATH": REPO}, capture_output=True, timeout=60,
        )
        self.assertEqual(done.returncode, 7, done.stderr)
        self.assertEqual(store.head(), head)
        self.assertEqual(store.state(), state)
        self.assertEqual(store.agent().pay(N, NIMBUS, "480.00", "INV-1")["transfer_id"], "T001")
        self.assertEqual(store.verify(), (True, None))

    def test_data_that_is_not_json_is_refused_like_the_in_memory_log(self):
        store = self.make(clock=FakeClock())
        conn = sqlite3.connect(store.path, isolation_level=None)
        self.addCleanup(conn.close)
        log = DbAuditLog(conn, FakeClock())
        with self.assertRaises((TypeError, ValueError)):
            log.append("note", {"when": datetime.now()})
        with self.assertRaises(TypeError):
            log.append("note", {1: "x"})
        self.assertIsNone(log.failed)
        self.assertEqual(log.added, [])
        memory = AuditLog(FakeClock(), log_id=store.meta()["log_id"])
        conn.execute("BEGIN IMMEDIATE")
        self.assertEqual(log.append("note", {"n": 1}), memory.append("note", {"n": 1}))
        self.assertEqual(log.added, memory.entries[1:])
        conn.execute("ROLLBACK")
        self.assertEqual(store.head()[0], 0)


class ReviewFixTests(TempDir):
    def test_snapshot_checks_only_new_entries_but_still_sees_old_edits(self):
        store = self.make(clock=FakeClock())
        store.console().start_task(self.mandate(), confirmed_by="test")
        self.assertTrue(store.snapshot()["intact"])
        head = store.head()
        self.assertEqual(store.snapshot(after_seq=head[0])["entries"], [])
        store.agent().pay(N, NIMBUS, "480.00", "INV-1")
        fresh = store.snapshot(after_seq=head[0])
        self.assertTrue(fresh["intact"])
        self.assertEqual(fresh["entries"][0]["seq"], head[0] + 1)
        # An intruder edits entry 1. It is found by the next full check.
        conn = sqlite3.connect(store.path, isolation_level=None)
        self.addCleanup(conn.close)
        conn.execute("UPDATE audit SET data = '{\"edited\":true}' WHERE seq = 1")
        store._checked = (store._checked[0], store._checked[1], -1e9)  # full check is due
        self.assertEqual((store.snapshot()["intact"], store.snapshot()["broken_at"]), (False, 1))

    def test_a_missed_receipt_is_written_by_the_next_commit(self):
        store = self.make(clock=FakeClock())
        blocked = os.path.join(self.dir, "no-such-dir", "receipts.jsonl")
        store.receipts = blocked
        store.console().start_task(self.mandate(), confirmed_by="test")
        self.assertEqual(len(store.receipt_failures), 1)
        store.receipts = os.path.join(self.dir, "receipts.jsonl")
        store.agent().observe("note.eml", "no account here")  # not an authority change
        with open(store.receipts, encoding="utf-8") as fp:
            self.assertEqual(len(fp.readlines()), 1)
        store.agent().observe("note2.eml", "still none")
        with open(store.receipts, encoding="utf-8") as fp:
            self.assertEqual(len(fp.readlines()), 1)


# --- holds across tasks -----------------------------------------------------------


class TaskTests(TempDir):
    def test_a_hold_from_an_earlier_task_cannot_be_approved(self):
        store = self.make()
        hold_id = self.held(store)
        store.console().start_task(self.mandate(id="task-2"), confirmed_by="tester")
        self.assertEqual(store.hold(hold_id).status, "expired")
        with self.assertRaises(ValueError):
            store.console().approve(hold_id, approver="sam")
        self.assertEqual(store.state()["bank"]["transfers"], [])
        self.assertEqual(store.agent().hold_status(hold_id)["status"], "expired")

    def test_ending_a_task_stops_payments(self):
        store = self.make()
        hold_id = self.held(store)
        store.console().end_task(by="sam")
        self.assertIsNone(store.agent().task())
        self.assertEqual(store.agent().pay(N, NIMBUS, "1.00", "X-1")["rule"], "M0")
        with self.assertRaises(ValueError):
            store.console().approve(hold_id, approver="sam")
        with self.assertRaises(KeyError):
            store.hold("H404")

    def test_reject_and_remember_account(self):
        store = self.make()
        first = self.held(store)
        store.console().reject(first, approver="sam")
        self.assertEqual(store.agent().pay(N, MULE_2, "480.00", "INV-2041")["rule"], "R1")

        other = self.make("other.db")
        hold_id = self.held(other)
        result = other.console().approve(hold_id, approver="sam", remember_account=True,
                                         attestation="checked")
        self.assertEqual(result.transfer_id, "T001")
        self.assertIn(MULE_2, other.state()["vendors"][0]["accounts"])
        approved = [e for e in other.audit_entries() if e["event"] == "hold_approved"][0]
        self.assertEqual(approved["data"]["attestation"], "checked")
        self.assertEqual(approved["data"]["approver"], "sam")


# --- reading ----------------------------------------------------------------------


class ReadingTests(TempDir):
    def test_snapshot_has_everything_the_live_console_shows(self):
        clock = FakeClock()
        inbox = self.path("inbox")
        store = self.make(clock=clock, inbox=inbox)
        scenario = BY_ID["attack-05"]
        store.console().start_task(scenario_mandate(scenario, clock), confirmed_by="tester")
        for name, text in scenario.documents.items():
            store.agent().observe(name, text)
        for a in scenario.attempts:
            store.agent().pay(a.payee, a.account, str(a.amount), a.reference)

        shot = store.snapshot()
        self.assertLessEqual(
            {"head", "mode", "state", "entries", "intact", "broken_at"}, set(shot)
        )
        self.assertEqual(shot["head"], store.head())
        self.assertEqual(shot["mode"], "countersign")
        self.assertEqual((shot["intact"], shot["broken_at"]), (True, None))
        self.assertEqual(shot["entries"], store.audit_entries())
        self.assertEqual(shot["now"], clock().isoformat())
        self.assertEqual(shot["path"], store.path)
        self.assertEqual(shot["meta"]["inbox"], inbox)
        json.dumps(shot, allow_nan=False)  # plain JSON data throughout

        state = shot["state"]
        self.assertEqual(state["mandate"]["id"], "mandate-attack-05")
        self.assertEqual((state["task"]["spent"], state["task"]["payments"]), ("240.00", 1))
        self.assertEqual([o["name"] for o in state["observations"] if o["origin"] == "untrusted"],
                         list(scenario.documents))
        self.assertEqual([t["id"] for t in state["bank"]["transfers"]], ["T001"])
        self.assertEqual(state["bank"]["balance"], "49760.00")
        self.assertEqual([h["id"] for h in state["holds"]], ["H001"])
        decisions = [e for e in shot["entries"] if e["event"] == "payment_decision"]
        self.assertEqual([d["data"]["decision"]["outcome"] for d in decisions],
                         ["ALLOW", "HOLD"])
        self.assertEqual(decisions[1]["data"]["hold"], "H001")
        self.assertTrue(decisions[1]["data"]["decision"]["checks"])
        self.assertTrue(decisions[1]["data"]["decision"]["evidence"]["sightings"])

    def test_snapshot_and_entries_after_a_position(self):
        store = self.make()
        self.held(store)
        seq = store.head()[0]
        self.assertEqual(store.audit_entries(seq), [])
        self.assertEqual([e["seq"] for e in store.audit_entries(0)], list(range(1, seq + 1)))
        self.assertEqual(store.snapshot(seq)["entries"], [])
        self.assertEqual(store.snapshot(seq - 1)["entries"], store.audit_entries()[-1:])
        self.assertTrue(store.snapshot(seq)["intact"])

    def test_tampering_in_the_file_is_reported(self):
        store = self.make()
        self.held(store)
        conn = sqlite3.connect(store.path)
        conn.execute("UPDATE audit SET data = replace(data, '480.00', '4.80') WHERE seq = 3")
        conn.commit()
        conn.close()
        self.assertEqual(store.verify(), (False, 3))
        shot = store.snapshot()
        self.assertEqual((shot["intact"], shot["broken_at"]), (False, 3))

        conn = sqlite3.connect(store.path)
        conn.execute("UPDATE audit SET data = 'not json' WHERE seq = 2")
        conn.commit()
        conn.close()
        self.assertEqual(store.verify(), (False, 2))
        self.assertEqual(store.audit_entries()[2]["data"], "not json")

    def test_reconcile_reports_a_transfer_missing_from_the_log(self):
        store = self.make()
        store.console().start_task(self.mandate(), confirmed_by="tester")
        store.agent().pay(N, NIMBUS, "480.00", "INV-2041")
        self.assertEqual(store.reconcile(), [])
        conn = sqlite3.connect(store.path)
        conn.execute("DELETE FROM audit WHERE event = 'payment_executed'")
        conn.commit()
        conn.close()
        problems = store.reconcile()
        self.assertEqual(len(problems), 1)
        self.assertIn("T001", problems[0])

    def test_the_audit_commands_read_a_real_database(self):
        store = self.make()
        self.held(store)
        out = self.path("log.jsonl")
        with mock.patch("sys.stdout"), mock.patch("sys.stderr"):
            self.assertEqual(cli.main(["audit", "verify", "--db", store.path]), 0)
            self.assertEqual(cli.main(["audit", "export", "--db", store.path, "-o", out]), 0)
            self.assertEqual(cli.main(["audit", "verify", "--file", out]), 0)
        with open(out) as fp:
            self.assertEqual([json.loads(line) for line in fp], store.audit_entries())


# --- receipts ---------------------------------------------------------------------


class ReceiptTests(TempDir):
    def seqs(self, path: str) -> list[int]:
        return [receipt.seq for receipt in load_receipts(path)]

    def test_a_receipt_follows_every_commit_that_moves_money_or_changes_authority(self):
        receipts = self.path("receipts.jsonl")
        store = Store(self.make().path, receipts=receipts)
        self.assertFalse(os.path.exists(receipts))

        store.console().start_task(self.mandate(), confirmed_by="tester")
        self.assertEqual(self.seqs(receipts), [store.head()[0]])  # authority changed

        port = store.agent()
        port.observe("INV-2041.eml", f"IBAN {fmt(MULE_2)}")
        port.pay(N, MULE_2, "480.00", "INV-2041")  # held: nothing moved
        port.pay("Nobody", NIMBUS, "1.00", "X")  # blocked
        self.assertEqual(len(self.seqs(receipts)), 1)

        port.pay(N, NIMBUS, "100.00", "INV-2042")  # paid
        self.assertEqual(self.seqs(receipts)[-1], store.head()[0])
        self.assertEqual(len(self.seqs(receipts)), 2)

        self.assertEqual(store.console().approve("H001", approver="sam").transfer_id, "T002")
        self.assertEqual(self.seqs(receipts)[-1], store.head()[0])
        port.pay(N, MULE_2, "10.00", "INV-2043")
        store.console().reject("H002", approver="sam")
        store.console().end_task(by="sam")
        self.assertEqual(len(self.seqs(receipts)), 5)
        self.assertEqual(self.seqs(receipts)[-1], store.head()[0])

        findings = check_receipts(store.audit_entries(), load_receipts(receipts))
        self.assertTrue(all(finding.ok for finding in findings))
        self.assertEqual(stat.S_IMODE(os.stat(receipts).st_mode), 0o600)
        self.assertEqual(store.receipt_failures, [])

    def test_the_receipts_file_can_come_from_the_environment_or_the_database(self):
        from_env = self.path("env.jsonl")
        with mock.patch.dict(os.environ, {"COUNTERSIGN_RECEIPTS": from_env}):
            store = self.make("a.db")
            self.assertEqual(store.receipts, from_env)
            self.assertEqual(self.seqs(from_env), [0])
            argument = self.path("argument.jsonl")
            self.assertEqual(Store(store.path, receipts=argument).receipts, argument)
        with mock.patch.dict(os.environ):
            os.environ.pop("COUNTERSIGN_RECEIPTS", None)
            self.assertIsNone(Store(store.path).receipts)

            recorded = self.path("recorded.jsonl")
            made = self.make("b.db", receipts=recorded)
            self.assertEqual(self.seqs(recorded), [0])
            # Another process that knows only the database still writes receipts.
            again = Store(made.path)
            self.assertEqual(again.receipts, recorded)
            again.console().start_task(self.mandate(), confirmed_by="tester")
            self.assertEqual(self.seqs(recorded), [0, 1])

    def test_a_receipt_that_cannot_be_written_does_not_undo_the_commit(self):
        store = Store(self.make().path, receipts=os.path.join(self.dir, "no", "such", "dir.jsonl"))
        store.console().start_task(self.mandate(), confirmed_by="tester")
        self.assertIsNotNone(store.mandate())
        self.assertEqual([seq for seq, _ in store.receipt_failures], [1])


# --- several processes, one file ----------------------------------------------------

WORKER = textwrap.dedent(
    """
    import json, sys
    from countersign.store import Store

    store = Store(sys.argv[1])
    print("ready", flush=True)
    sys.stdin.readline()  # every worker is released at the same moment
    try:
        if sys.argv[2] == "approve":
            result = store.console().approve(sys.argv[3], approver=sys.argv[4])
            out = {"outcome": result.decision.outcome.value, "transfer": result.transfer_id}
        else:
            answer = store.agent().pay(*sys.argv[3:7])
            out = {"outcome": answer["outcome"], "rule": answer["rule"],
                   "transfer": answer["transfer_id"]}
    except Exception as exc:
        out = {"error": type(exc).__name__, "message": str(exc)}
    print(json.dumps(out), flush=True)
    """
)


def release_together(commands: list[list[str]]) -> list[dict]:
    """Start one Python process per command, wait until all have opened the
    database, let them go at once, and return what each printed."""
    env = {**os.environ, "PYTHONPATH": REPO}
    workers = [
        subprocess.Popen(
            [sys.executable, "-c", WORKER, *command], env=env, text=True,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        for command in commands
    ]
    try:
        for worker in workers:
            ready = worker.stdout.readline().strip()
            if ready != "ready":
                raise AssertionError(f"a worker did not start: {worker.stderr.read()}")
        for worker in workers:
            worker.stdin.write("go\n")
            worker.stdin.flush()
        results = []
        for worker in workers:
            out, err = worker.communicate(timeout=120)
            if worker.returncode != 0:
                raise AssertionError(f"a worker failed: {err}")
            results.append(json.loads(out))
        return results
    finally:
        for worker in workers:
            if worker.poll() is None:
                worker.kill()
            for stream in (worker.stdin, worker.stdout, worker.stderr):
                stream.close()


class ConcurrencyTests(TempDir):
    def test_eight_processes_approving_one_hold_send_one_transfer(self):
        store = self.make()
        hold_id = self.held(store)
        results = release_together(
            [[store.path, "approve", hold_id, f"approver-{i}"] for i in range(8)]
        )
        paid = [r for r in results if r.get("transfer")]
        refused = [r for r in results if "error" in r]
        self.assertEqual(len(paid), 1, results)
        self.assertEqual(len(refused), 7, results)
        self.assertEqual({r["error"] for r in refused}, {"ValueError"})
        self.assertTrue(all("already approved" in r["message"] for r in refused))

        state = store.state()
        self.assertEqual(len(state["bank"]["transfers"]), 1)
        self.assertEqual(state["bank"]["balance"], "49520.00")
        self.assertEqual(state["task"]["spent"], "480.00")
        events = [e["event"] for e in store.audit_entries()]
        self.assertEqual(events.count("hold_approved"), 1)
        self.assertEqual(events.count("payment_executed"), 1)
        self.assertEqual(store.hold(hold_id).status, "approved")
        self.assertEqual(store.verify(), (True, None))
        self.assertEqual(store.reconcile(), [])

    def test_six_processes_paying_into_a_budget_for_one_send_one_transfer(self):
        store = self.make()
        mandate = self.mandate(max_per_payment=Decimal("480"), max_total=Decimal("500"))
        store.console().start_task(mandate, confirmed_by="tester")
        results = release_together(
            [[store.path, "pay", N, NIMBUS, "480.00", f"INV-{i}"] for i in range(6)]
        )
        self.assertEqual(sorted(r["outcome"] for r in results), ["ALLOW"] + ["BLOCK"] * 5)
        self.assertEqual({r["rule"] for r in results if r["outcome"] == "BLOCK"}, {"M4"})
        self.assertEqual([r["transfer"] for r in results if r["transfer"]], ["T001"])

        state = store.state()
        self.assertEqual(len(state["bank"]["transfers"]), 1)
        self.assertEqual(state["task"]["spent"], "480.00")
        entries = store.audit_entries()
        self.assertEqual([e["seq"] for e in entries], list(range(len(entries))))
        self.assertEqual([e["event"] for e in entries].count("payment_decision"), 6)
        self.assertEqual(store.verify(), (True, None))
        self.assertEqual(store.reconcile(), [])

    def test_threads_sharing_one_store_keep_one_chain(self):
        store = self.make()
        mandate = self.mandate(max_per_payment=Decimal("100"), max_total=Decimal("250"))
        store.console().start_task(mandate, confirmed_by="tester")
        answers: list[dict] = []
        gate = threading.Barrier(12)

        def work(index: int) -> None:
            port = open_agent(store.path) if index % 2 else store.agent()
            gate.wait()
            port.observe(f"note-{index}.txt", f"note {index}")
            answers.append(port.pay(N, NIMBUS, "100.00", f"INV-{index}"))

        threads = [threading.Thread(target=work, args=(i,)) for i in range(12)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(60)
        self.assertEqual(len(answers), 12)
        self.assertEqual(sum(1 for a in answers if a["outcome"] == "ALLOW"), 2)
        self.assertEqual(len({a["transfer_id"] for a in answers if a["transfer_id"]}), 2)
        self.assertEqual(store.state()["task"]["spent"], "200.00")
        self.assertEqual(store.head()[0], 1 + 12 + 12 + 2 * 2)
        self.assertEqual(store.verify(), (True, None))
        self.assertEqual(store.reconcile(), [])


class ModuleTests(unittest.TestCase):
    def test_every_module_states_its_future_import(self):
        with open(store_module.__file__) as fp:
            self.assertIn("from __future__ import annotations", fp.read())


if __name__ == "__main__":
    unittest.main()
