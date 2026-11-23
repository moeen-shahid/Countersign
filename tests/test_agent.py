"""The scripted agent: a recorded trace replayed through the agent's tools.

Run with: python3 -m unittest tests.test_agent -v
"""

from __future__ import annotations

import contextlib
import io
import os
import tempfile
import unittest
from datetime import datetime, timezone
from unittest import mock

from countersign import agent, cli
from countersign.agent import Call, DirectBackend, MemoryBackend, run_scripted, statuses
from countersign.audit import AuditLog
from countersign.bank import MockBank
from countersign.guard import Guard
from countersign.scenarios import BY_ID, SCENARIOS
from countersign.simulation import (
    MODES,
    FakeClock,
    default_vendors,
    log_id,
    run_scenario,
    scenario_mandate,
)
from countersign.store import Store
from countersign.toolsurface import DictInbox, build_surface

ATTACK = BY_ID["attack-02"]


def replay(scenario, mode: str):
    """The scripted agent over the same set-up `simulation.run_scenario` uses."""
    clock = FakeClock()
    bank = MockBank()
    guard = None
    if mode == "none":
        backend = DirectBackend(bank)
    else:
        audit = AuditLog(clock, log_id=log_id(scenario, mode))
        guard = Guard(bank, default_vendors(), mode=mode, clock=clock, audit=audit)
        guard.start_task(scenario_mandate(scenario, clock), confirmed_by="scenario user")
        backend = MemoryBackend(guard)
    clock.advance(scenario.delay_hours)
    surface = build_surface(backend, DictInbox(scenario.documents))
    attempts = iter(scenario.attempts)

    def person(call: Call) -> None:
        """The person of the scenario. Some scenarios script a refusal of a
        hold; the agent has no tool for that, so it happens here, at the
        guard, between two of the agent's calls."""
        if call.tool != "pay":
            return
        attempt, hold_id = next(attempts), call.result.get("hold_id")
        if guard is not None and hold_id and getattr(attempt, "reject", False):
            if guard.hold(hold_id).status == "pending":
                guard.reject(hold_id, "scenario user")

    return run_scripted(surface, scenario, on_call=person), bank, guard


class ReplayTests(unittest.TestCase):
    def test_every_scenario_under_every_guard_ends_like_the_simulation(self):
        compared = 0
        for scenario in SCENARIOS:
            for mode in MODES:
                with self.subTest(scenario=scenario.id, mode=mode):
                    expected = run_scenario(scenario, mode)
                    transcript, bank, guard = replay(scenario, mode)
                    self.assertEqual(statuses(transcript), expected.statuses())
                    self.assertEqual(bank.to_state(), expected.bank.to_state())
                    pays = [c.result for c in transcript if c.tool == "pay"]
                    self.assertEqual(
                        [(p["outcome"], p["rule"], p["transfer_id"], p["hold_id"]) for p in pays],
                        [(r.decision.outcome.value, r.decision.rule, r.transfer_id, r.hold_id)
                         for r in expected.results],
                    )
                    if guard is not None:
                        # Going through the tools leaves the very same audit log.
                        self.assertEqual(guard.audit.head(), expected.guard.audit.head())
                    compared += len(pays)
        self.assertEqual(compared, len(MODES) * sum(len(s.attempts) for s in SCENARIOS))

    def test_the_order_of_calls_is_fixed(self):
        scenario = BY_ID["attack-05"]
        transcript, _, _ = replay(scenario, "countersign")
        self.assertEqual(
            [call.tool for call in transcript],
            ["get_task", "list_documents", "read_document", "pay", "pay", "payment_status"],
        )
        self.assertTrue(all(isinstance(call, Call) for call in transcript))
        self.assertEqual(transcript[2].arguments, {"name": "INV-2041.eml"})
        first = scenario.attempts[0]
        self.assertEqual(
            transcript[3].arguments,
            {"payee": first.payee, "account": first.account, "amount": "240.00",
             "reference": first.reference},
        )
        self.assertEqual(transcript[5].arguments, {"hold_id": "H001"})
        self.assertFalse(any(call.is_error for call in transcript))

    def test_it_reads_what_the_inbox_lists_not_what_the_scenario_says(self):
        clock = FakeClock()
        guard = Guard(MockBank(), default_vendors(), clock=clock)
        guard.start_task(scenario_mandate(ATTACK, clock), confirmed_by="tester")
        surface = build_surface(MemoryBackend(guard), DictInbox({"a.txt": "one", "b.txt": "two"}))
        transcript = run_scripted(surface, ATTACK)
        self.assertEqual([c.arguments["name"] for c in transcript if c.tool == "read_document"],
                         ["a.txt", "b.txt"])
        # The swapped account was in neither document, so the guard never saw it.
        self.assertEqual(statuses(transcript), ["blocked"])
        self.assertEqual([c.result["rule"] for c in transcript if c.tool == "pay"], ["O1"])

    def test_it_keeps_asking_whatever_the_guard_answers(self):
        scenario = BY_ID["attack-12"]
        transcript, _, _ = replay(scenario, "countersign")
        self.assertEqual(sum(1 for c in transcript if c.tool == "pay"), len(scenario.attempts))

    def test_callbacks_see_every_call_and_pauses_fall_between_calls(self):
        seen, pauses = [], []
        clock = FakeClock()
        guard = Guard(MockBank(), default_vendors(), clock=clock)
        guard.start_task(scenario_mandate(ATTACK, clock), confirmed_by="tester")
        surface = build_surface(MemoryBackend(guard), DictInbox(ATTACK.documents))
        transcript = run_scripted(
            surface, ATTACK, on_call=seen.append, pause=lambda: pauses.append(len(seen))
        )
        self.assertEqual(seen, transcript)
        self.assertEqual(pauses, [1, 2, 3, 4])  # never before the first call

    def test_statuses_follow_what_a_person_decided(self):
        paid = Call("pay", {}, {"outcome": "HOLD", "hold_id": "H001", "transfer_id": None})
        blocked = Call("pay", {}, {"outcome": "BLOCK", "hold_id": None, "transfer_id": None})
        sent = Call("pay", {}, {"outcome": "ALLOW", "hold_id": None, "transfer_id": "T001"})

        def status(value, transfer=None):
            return Call("payment_status", {"hold_id": "H001"},
                        {"hold_id": "H001", "status": value, "transfer_id": transfer})

        self.assertEqual(statuses([paid, blocked, sent]), ["held", "blocked", "paid"])
        self.assertEqual(statuses([paid, status("pending")]), ["held"])
        self.assertEqual(statuses([paid, status("pending"), status("approved", "T002")]),
                         ["paid"])
        self.assertEqual(statuses([paid, status("rejected")]), ["rejected"])
        self.assertEqual(statuses([paid, status("expired")]), ["expired"])
        # The same transfer named twice: the bank sent it once.
        self.assertEqual(statuses([sent, sent, blocked]), ["paid", "blocked", "blocked"])


def run_cli(*argv: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with mock.patch.dict(os.environ):
        os.environ.pop("COUNTERSIGN_DB", None)
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(list(argv))
    return code, out.getvalue(), err.getvalue()


class CommandTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.db = os.path.join(folder.name, "countersign.db")
        self.inbox = os.path.join(folder.name, "inbox")
        os.makedirs(self.inbox)
        for name, text in ATTACK.documents.items():
            with open(os.path.join(self.inbox, name), "w", encoding="utf-8", newline="") as fp:
                fp.write(text)
        self.store = Store.create(self.db, vendors=default_vendors())

    def start(self):
        now = datetime.now(timezone.utc)
        self.store.console().start_task(scenario_mandate(ATTACK, lambda: now),
                                        confirmed_by="tester")

    def agent(self, *more: str) -> tuple[int, str, str]:
        return run_cli("agent", "--db", self.db, "--inbox", self.inbox, "--delay", "0", *more)

    def test_it_runs_against_the_active_task_and_prints_every_call(self):
        self.start()
        code, out, err = self.agent("--scenario", "attack-02")
        self.assertEqual((code, err), (0, ""))
        self.assertIn("scripted agent (no model)", out.splitlines()[0])
        lines = out.split("\n\n")[1].splitlines()  # between the header and the summary
        self.assertTrue(all(line.startswith(("[scripted] ", "           -> ")) for line in lines))
        asked = [line[len("[scripted] "):].split()[0] for line in lines if line[0] == "["]
        self.assertEqual(asked, ["get_task", "list_documents", "read_document", "pay",
                                 "payment_status"])
        self.assertIn("-> HOLD P1  hold H001", out)
        self.assertIn(self.store.hold("H001").decision.reason, out)
        self.assertIn("1 payment request(s), 0 paid, 1 waiting for a person, 0 not paid", out)
        self.assertEqual(self.store.state()["bank"]["transfers"], [])
        self.assertEqual(self.store.hold("H001").status, "pending")

    def test_it_never_claims_to_think(self):
        self.start()
        _, out, _ = self.agent("--scenario", "attack-02")
        lowered = out.lower()
        for word in ("i think", "i will", "i should", "let me", "thinking", "decided to",
                     "because the", "claude", "gpt", "llm"):
            self.assertNotIn(word, lowered)
        self.assertIn("there is no reasoning to show", lowered)
        self.assertGreaterEqual(lowered.count("scripted"), 7)

    def test_without_an_active_task_it_stops(self):
        code, out, err = self.agent("--scenario", "attack-02")
        self.assertEqual((code, out), (2, ""))
        self.assertIn("no task is active", err)
        self.assertEqual(self.store.head()[0], 0)

    def test_usage_errors_exit_2_and_change_nothing(self):
        self.start()
        head = self.store.head()
        missing = self.db + ".missing"
        for argv, phrase in (
            (["agent", "--db", self.db, "--inbox", self.inbox, "--scenario", "attack-99"],
             "no scenario"),
            (["agent", "--db", missing, "--inbox", self.inbox, "--scenario", "attack-02"],
             "No database at"),
            (["agent", "--db", self.db, "--inbox", self.inbox + "-none", "--scenario",
              "attack-02"], "No inbox directory"),
            (["agent", "--inbox", self.inbox, "--scenario", "attack-02"], "COUNTERSIGN_DB"),
            (["agent", "--db", self.db, "--inbox", self.inbox, "--scenario", "attack-02",
              "--delay", "-1"], "--delay"),
        ):
            with self.subTest(phrase=phrase):
                code, out, err = run_cli(*argv)
                self.assertEqual((code, out), (2, ""))
                self.assertIn(phrase, err)
                self.assertEqual(err.count("\n"), 1)
        self.assertFalse(os.path.exists(missing))
        self.assertEqual(self.store.head(), head)

    def test_the_default_delay_lets_a_person_watch(self):
        self.start()
        naps = []
        with mock.patch.object(agent.time, "sleep", naps.append):
            code, _, _ = run_cli("agent", "--db", self.db, "--inbox", self.inbox,
                                 "--scenario", "attack-02")
        self.assertEqual(code, 0)
        self.assertEqual(naps, [0.6] * 4)

    def test_a_scenario_that_needs_time_to_pass_says_so(self):
        self.start()
        _, out, _ = self.agent("--scenario", "attack-10")
        self.assertIn("assumes 24 hours pass", out)
        self.assertIn("does not wait", out)

    def test_text_from_documents_cannot_draw_on_the_terminal(self):
        with open(os.path.join(self.inbox, "evil\x1b[2J.eml"), "w") as fp:
            fp.write("x")
        self.start()
        _, out, _ = self.agent("--scenario", "attack-02")
        self.assertNotIn("\x1b", out)
        self.assertIn("evil?[2J.eml", out)


if __name__ == "__main__":
    unittest.main()
