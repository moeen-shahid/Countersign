"""The audit log: what the chain catches alone, and what needs a head kept elsewhere.

Run with: python3 -m unittest tests.test_audit -v
"""

from __future__ import annotations

import copy
import io
import json
import threading
import unittest
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal

from countersign import audit
from countersign.audit import (
    ENTRY_KEYS,
    GENESIS,
    AuditLog,
    entry_hash,
    export_jsonl,
    load_jsonl,
    make_entry,
    reconcile,
    verify_entries,
)
START = datetime(2026, 11, 23, 9, 0, tzinfo=timezone.utc)


class Clock:
    """Moves one second per reading, so every entry has its own timestamp."""

    def __init__(self) -> None:
        self.now = START

    def __call__(self) -> datetime:
        self.now += timedelta(seconds=1)
        return self.now


def make_log(count: int = 5, **kwargs) -> AuditLog:
    log = AuditLog(Clock(), **kwargs)
    for i in range(count):
        log.append("event", {"i": i})
    return log


def rechain(entries: list) -> list:
    """What an intruder with full access can do: recompute every hash."""
    prev = GENESIS
    out = []
    for seq, entry in enumerate(entries):
        fresh = make_entry(seq, entry["ts"], entry["event"], entry["data"], prev)
        out.append(fresh)
        prev = fresh["hash"]
    return out


class AppendTests(unittest.TestCase):
    def test_entry_zero_opens_the_log(self):
        log = AuditLog(Clock())
        self.assertEqual(len(log.entries), 1)
        first = log.entries[0]
        self.assertEqual(first["event"], "log_opened")
        self.assertEqual(first["seq"], 0)
        self.assertEqual(first["prev"], GENESIS)
        self.assertEqual(first["data"]["version"], 1)
        self.assertRegex(first["data"]["log_id"], r"\A[0-9a-f]{16}\Z")
        self.assertEqual(log.log_id, first["data"]["log_id"])
        self.assertEqual(log.verify(), (True, None))

    def test_old_call_shape_still_works(self):
        log = AuditLog(Clock())  # positional clock
        entry = log.append("event", {"i": 1})
        self.assertIs(entry, log.entries[-1])
        self.assertIsInstance(log.entries, list)
        self.assertEqual(tuple(entry), ENTRY_KEYS)
        self.assertEqual(entry["seq"], 1)
        self.assertEqual(entry["prev"], log.entries[0]["hash"])
        self.assertEqual(entry["ts"], (START + timedelta(seconds=2)).isoformat())
        self.assertEqual(log.verify(), (True, None))

    def test_default_clock_and_random_log_ids(self):
        first, second = AuditLog(), AuditLog()
        self.assertNotEqual(first.log_id, second.log_id)
        self.assertNotEqual(first.head(), second.head())
        self.assertEqual(first.verify(), (True, None))

    def test_fixed_log_id_makes_replays_identical(self):
        one, two = make_log(log_id="replay"), make_log(log_id="replay")
        self.assertEqual(one.entries, two.entries)
        self.assertEqual(one.head(), two.head())
        self.assertNotEqual(one.head(), make_log(log_id="other").head())

    def test_head_is_the_newest_entry(self):
        log = make_log(3)
        self.assertEqual(log.head(), (3, log.entries[3]["hash"]))
        entry = log.append("event", {})
        self.assertEqual(log.head(), (4, entry["hash"]))

    def test_hash_is_sha256_of_the_canonical_body(self):
        import hashlib

        entry = make_log(1).entries[1]
        body = {key: entry[key] for key in ("seq", "ts", "event", "data", "prev")}
        text = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        self.assertEqual(entry["hash"], hashlib.sha256(text.encode("ascii")).hexdigest())

    def test_data_that_is_not_json_safe_is_refused(self):
        log = AuditLog(Clock())
        bad = [
            {"amount": Decimal("1.50")},
            {"when": START},
            {"tags": {"a", "b"}},
            {"raw": b"bytes"},
            {"x": float("nan")},
            {"x": float("inf")},
            {1: "whole-number key"},
            {"nested": {None: "none key"}},
            {"list": [{2: "deep"}]},
            {"obj": object()},
        ]
        for data in bad:
            with self.subTest(data=repr(data)):
                with self.assertRaises((TypeError, ValueError)):
                    log.append("event", data)
        loop: dict = {}
        loop["self"] = loop
        with self.assertRaises((TypeError, ValueError)):
            log.append("event", loop)
        for data in ("text", ["list"], None, 5):
            with self.subTest(data=data):
                with self.assertRaises(TypeError):
                    log.append("event", data)
        for event in ("", None, 5):
            with self.subTest(event=event):
                with self.assertRaises(TypeError):
                    log.append(event, {})
        # Nothing was added by any of the refused calls.
        self.assertEqual(len(log.entries), 1)
        self.assertEqual(log.verify(), (True, None))

    def test_plain_data_is_stored_exactly_as_hashed(self):
        log = AuditLog(Clock())
        data = {
            "amount": "1.50",
            "count": 3,
            "ok": True,
            "none": None,
            "payees": ("A", "B"),  # a tuple comes back as a list
            "nested": {"k": ["v", 1]},
            "text": "café € \U0001f600 line\nbreak",
            "surrogate": "lone \ud83d here",  # must not break hashing or export
        }
        entry = log.append("event", data)
        self.assertEqual(entry["data"]["payees"], ["A", "B"])
        self.assertEqual(entry["data"]["surrogate"], "lone \ud83d here")
        self.assertEqual(entry["hash"], entry_hash(entry))
        self.assertEqual(log.verify(), (True, None))
        data["nested"]["k"].append("changed later")  # the caller's object is not the stored one
        self.assertEqual(entry["data"]["nested"], {"k": ["v", 1]})
        self.assertEqual(log.verify(), (True, None))

    def test_sink_gets_every_entry_after_it_is_appended(self):
        seen = []
        holder = {}

        def sink(entry):
            log = holder.get("log")
            seen.append((entry["seq"], log is not None and log.entries[-1] is entry))

        holder["log"] = log = AuditLog(Clock(), sink=sink)
        log.append("event", {"i": 0})
        self.assertEqual(seen, [(0, False), (1, True)])  # entry 1 was in the list already
        self.assertEqual(log.sink_failures, [])

    def test_a_failing_sink_does_not_lose_the_entry(self):
        def sink(entry):
            if entry["seq"] == 1:
                raise OSError("disk full")

        log = AuditLog(Clock(), sink=sink)
        entry = log.append("event", {"i": 0})
        log.append("event", {"i": 1})
        self.assertEqual(entry["seq"], 1)
        self.assertEqual(len(log.entries), 3)
        self.assertEqual(log.verify(), (True, None))
        self.assertEqual(log.sink_failures, [(1, "OSError: disk full")])

    def test_append_is_safe_from_many_threads(self):
        log = AuditLog(Clock())

        def work(n: int) -> None:
            for i in range(50):
                log.append("event", {"thread": n, "i": i})

        threads = [threading.Thread(target=work, args=(n,)) for n in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len(log.entries), 401)
        self.assertEqual(log.verify(), (True, None))


class ChainTests(unittest.TestCase):
    """Changes inside the chain, made without recomputing later hashes."""

    def check(self, entries, position):
        try:
            result = verify_entries(entries)
        except Exception as exc:  # the point of these tests
            self.fail(f"verify_entries raised {exc!r}")
        self.assertEqual(result, (False, position))

    def test_edit(self):
        for position in range(6):
            with self.subTest(position=position):
                log = make_log()
                log.entries[position]["data"]["i"] = 99
                self.assertEqual(log.verify(), (False, position))
        for field, value in (("ts", "2030-01-01T00:00:00+00:00"), ("event", "other")):
            with self.subTest(field=field):
                log = make_log()
                log.entries[3][field] = value
                self.assertEqual(log.verify(), (False, 3))

    def test_edit_with_only_that_entry_rehashed(self):
        log = make_log()
        log.entries[2]["data"]["i"] = 99
        log.entries[2]["hash"] = entry_hash(log.entries[2])
        self.assertEqual(log.verify(), (False, 3))  # the next entry no longer links to it

    def test_delete(self):
        for position in range(5):
            with self.subTest(position=position):
                log = make_log()
                del log.entries[position]
                self.assertEqual(log.verify(), (False, position))

    def test_reorder(self):
        log = make_log()
        log.entries[2], log.entries[4] = log.entries[4], log.entries[2]
        self.assertEqual(log.verify(), (False, 2))
        log = make_log()
        log.entries.reverse()
        self.assertEqual(log.verify(), (False, 0))

    def test_inserted_and_duplicated_entries(self):
        log = make_log()
        log.entries.insert(3, copy.deepcopy(log.entries[2]))
        self.assertEqual(log.verify(), (False, 3))
        log = make_log()
        forged = make_entry(3, START.isoformat(), "event", {"i": "forged"}, log.entries[2]["hash"])
        log.entries.insert(3, forged)
        self.assertEqual(log.verify(), (False, 4))  # the forged entry links; the next does not

    def test_extra_key(self):
        log = make_log()
        log.entries[3]["note"] = "not covered by the hash"
        self.check(log.entries, 3)

    def test_missing_key(self):
        for key in ENTRY_KEYS:
            with self.subTest(key=key):
                log = make_log()
                del log.entries[2][key]
                self.check(log.entries, 2)

    def test_unserialisable_data(self):
        for value in ({1, 2}, Decimal("1.50"), b"bytes", float("nan"), object()):
            with self.subTest(value=repr(value)):
                log = make_log()
                log.entries[4]["data"]["i"] = value
                self.check(log.entries, 4)
        log = make_log()
        log.entries[1]["data"] = {1: "a", "1": "b"}
        self.check(log.entries, 1)
        log = make_log()
        loop: dict = {}
        loop["self"] = loop
        log.entries[2]["data"] = loop
        self.check(log.entries, 2)

    def test_wrong_types(self):
        cases = [
            ("seq", "3"),
            ("seq", 3.0),
            ("seq", True),
            ("seq", None),
            ("ts", 5),
            ("event", None),
            ("event", ["event"]),
            ("data", "text"),
            ("data", ["i", 2]),
            ("data", None),
            ("prev", None),
            ("prev", 0),
            ("hash", None),
            ("hash", ["a"]),
        ]
        for key, value in cases:
            with self.subTest(key=key, value=value):
                log = make_log()
                log.entries[3][key] = value
                self.check(log.entries, 3)

    def test_entries_that_are_not_dicts(self):
        for junk in (None, "text", 7, ["seq", 2], ("a",), b"x"):
            with self.subTest(junk=junk):
                log = make_log()
                log.entries[2] = junk
                self.check(log.entries, 2)

    def test_first_entry_must_open_a_log(self):
        log = make_log()
        self.check(rechain(log.entries[1:]), 0)  # opening entry removed, all hashes redone
        entries = make_log().entries
        entries[0]["data"]["version"] = 2
        self.check(rechain(entries), 0)  # a format this code does not know
        entries = make_log().entries
        del entries[0]["data"]["log_id"]
        self.check(rechain(entries), 0)
        self.check([], 0)  # an emptied log is not an intact log

    def test_verify_does_not_change_the_entries(self):
        log = make_log()
        before = copy.deepcopy(log.entries)
        log.verify()
        self.assertEqual(log.entries, before)

    def test_tuple_of_entries_is_accepted(self):
        self.assertEqual(verify_entries(tuple(make_log().entries)), (True, None))


class AnchorTests(unittest.TestCase):
    """What the chain alone cannot see, and what a head kept elsewhere adds."""

    def test_full_rewrite_passes_alone_and_fails_against_the_old_head(self):
        log = make_log()
        head = log.head()
        entries = copy.deepcopy(log.entries)
        entries[2]["data"]["i"] = 99
        rewritten = rechain(entries)
        self.assertEqual(len(rewritten), len(log.entries))
        self.assertEqual(verify_entries(rewritten), (True, None))  # the stated limit
        self.assertEqual(verify_entries(rewritten, expected_head=head), (False, head[0]))
        self.assertEqual(verify_entries(log.entries, expected_head=head), (True, None))

    def test_replaced_log_fails_against_the_old_head(self):
        log, other = make_log(), make_log()
        self.assertEqual(other.verify(), (True, None))
        self.assertEqual(other.verify(expected_head=log.head()), (False, 5))

    def test_truncation_passes_alone_and_fails_against_the_old_head(self):
        log = make_log()
        head = log.head()
        cut = log.entries[:3]
        self.assertEqual(verify_entries(cut), (True, None))  # the stated limit
        self.assertEqual(verify_entries(cut, expected_head=head), (False, 3))
        self.assertEqual(verify_entries(cut, expected_length=6), (False, 3))
        self.assertEqual(verify_entries(log.entries[:1], expected_head=head), (False, 1))

    def test_an_older_head_still_checks_after_the_log_grows(self):
        log = make_log(2)
        old = log.head()
        log.append("event", {"i": "later"})
        self.assertEqual(log.verify(expected_head=old), (True, None))
        self.assertEqual(log.verify(expected_head=log.head()), (True, None))
        self.assertEqual(log.verify(expected_head=(old[0], "0" * 64)), (False, old[0]))

    def test_expected_length(self):
        log = make_log()
        self.assertEqual(log.verify(expected_length=6), (True, None))
        self.assertEqual(log.verify(expected_length=5), (False, 5))  # one entry too many
        self.assertEqual(log.verify(expected_length=9), (False, 6))  # entries missing

    def test_a_chain_break_is_reported_before_the_head(self):
        log = make_log()
        head = log.head()
        log.entries[1]["data"]["i"] = 99
        self.assertEqual(log.verify(expected_head=head), (False, 1))

    def test_malformed_expectations_are_a_caller_error(self):
        log = make_log()
        for head in ((1,), ("1", "h"), (1, None), (-1, "h"), (True, "h")):
            with self.subTest(head=head):
                with self.assertRaises(ValueError):
                    log.verify(expected_head=head)
        for length in (-1, "6", 6.0):
            with self.subTest(length=length):
                with self.assertRaises(ValueError):
                    log.verify(expected_length=length)


class JsonlTests(unittest.TestCase):
    def export(self, entries) -> str:
        fp = io.StringIO()
        export_jsonl(entries, fp)
        return fp.getvalue()

    def test_export_load_verify_round_trip(self):
        log = make_log()
        log.append("event", {"text": "café €\nnew line", "surrogate": "\ud83d", "n": [1, 2]})
        text = self.export(log.entries)
        self.assertTrue(text.isascii())
        self.assertEqual(text.count("\n"), len(log.entries))
        loaded = load_jsonl(io.StringIO(text))
        self.assertEqual(loaded, log.entries)
        self.assertEqual(verify_entries(loaded, expected_head=log.head()), (True, None))
        self.assertEqual(self.export(loaded), text)

    def test_export_returns_the_count(self):
        log = make_log(2)
        self.assertEqual(export_jsonl(log.entries, io.StringIO()), 3)

    def test_blank_lines_are_skipped(self):
        log = make_log(2)
        text = "\n" + self.export(log.entries).replace("\n", "\n\n") + "  \n"
        self.assertEqual(load_jsonl(io.StringIO(text)), log.entries)

    def test_an_edit_in_the_file_is_found_at_its_line(self):
        log = make_log()
        lines = self.export(log.entries).splitlines()
        lines[3] = lines[3].replace('"i":2', '"i":7')
        self.assertEqual(verify_entries(load_jsonl(lines)), (False, 3))

    def test_a_line_that_is_not_json_is_found_at_its_line(self):
        log = make_log()
        for junk in ("{not json", "[1, 2", '"text"', "null", "NaN", '{"seq": 2}'):
            with self.subTest(junk=junk):
                lines = self.export(log.entries).splitlines()
                lines[2] = junk
                loaded = load_jsonl(lines)
                self.assertEqual(len(loaded), 6)
                self.assertEqual(verify_entries(loaded), (False, 2))

    def test_a_removed_line_is_found(self):
        lines = self.export(make_log().entries).splitlines()
        del lines[4]
        self.assertEqual(verify_entries(load_jsonl(lines)), (False, 4))

    def test_number_spelling_changes_are_found(self):
        log = make_log()
        lines = self.export(log.entries).splitlines()
        lines[1] = lines[1].replace('"i":0', '"i":0.0')
        self.assertNotEqual(lines[1], self.export(log.entries).splitlines()[1])
        self.assertEqual(verify_entries(load_jsonl(lines)), (False, 1))


@dataclass(frozen=True)
class Transfer:
    """The fields of a bank transfer that reconcile() reads."""

    id: str
    payee: str
    account: str
    amount: Decimal
    reference: str


def executed(log: AuditLog, transfer: Transfer, **changes) -> None:
    request = {
        "payee": transfer.payee,
        "account": transfer.account,
        "amount": str(transfer.amount),
        "reference": transfer.reference,
    }
    request.update(changes)
    log.append("payment_executed", {"task": "m1", "transfer": transfer.id, "request": request})


T1 = Transfer("T001", "Nimbus Hosting Ltd", "DE89370400440532013000", Decimal("480.00"), "INV-2041")
T2 = Transfer("T002", "Fernhill Design", "GB29NWBK60161331926819", Decimal("650.00"), "FD-118")


class ReconcileTests(unittest.TestCase):
    def test_matching_log_and_bank_agree(self):
        log = AuditLog(Clock())
        log.append("payment_decision", {"task": "m1", "outcome": "ALLOW"})
        executed(log, T1)
        executed(log, T2)
        self.assertEqual(reconcile(log.entries, [T1, T2]), [])
        self.assertEqual(reconcile(AuditLog(Clock()).entries, []), [])

    def test_amount_spelling_does_not_matter(self):
        log = AuditLog(Clock())
        executed(log, T1, amount="480")
        self.assertEqual(reconcile(log.entries, [T1]), [])

    def test_transfer_with_no_log_entry(self):
        log = AuditLog(Clock())
        executed(log, T1)
        problems = reconcile(log.entries, [T1, T2])
        self.assertEqual(len(problems), 1)
        self.assertIn("T002", problems[0])
        self.assertIn("is in the bank but not in the log", problems[0])

    def test_truncated_log_is_caught_by_the_bank_record(self):
        log = AuditLog(Clock())
        executed(log, T1)
        executed(log, T2)
        cut = log.entries[:2]
        self.assertEqual(verify_entries(cut), (True, None))  # the chain alone cannot tell
        problems = reconcile(cut, [T1, T2])
        self.assertEqual(len(problems), 1)
        self.assertIn("T002", problems[0])

    def test_log_entry_with_no_transfer(self):
        log = AuditLog(Clock())
        executed(log, T1)
        executed(log, T2)
        problems = reconcile(log.entries, [T1])
        self.assertEqual(len(problems), 1)
        self.assertIn("Log entry 2 records transfer T002", problems[0])
        self.assertIn("the bank does not have", problems[0])

    def test_each_field_is_compared(self):
        changes = {
            "payee": "Someone Else",
            "account": "MT84MALT011000012345MTLCAST001S",
            "amount": "4800.00",
            "reference": "INV-9999",
        }
        for field, value in changes.items():
            with self.subTest(field=field):
                log = AuditLog(Clock())
                executed(log, T1, **{field: value})
                problems = reconcile(log.entries, [T1])
                self.assertEqual(len(problems), 1)
                self.assertIn(f"says {field} {value}", problems[0])
                self.assertIn("T001", problems[0])

    def test_two_entries_for_one_transfer(self):
        log = AuditLog(Clock())
        executed(log, T1)
        executed(log, T1)
        problems = reconcile(log.entries, [T1])
        self.assertEqual(len(problems), 1)
        self.assertIn("2 times", problems[0])
        self.assertIn("entries 1, 2", problems[0])

    def test_bank_listing_a_transfer_twice(self):
        log = AuditLog(Clock())
        executed(log, T1)
        problems = reconcile(log.entries, [T1, T1])
        self.assertEqual(problems, ["The bank lists transfer T001 more than once."])

    def test_transfers_may_be_dicts(self):
        log = AuditLog(Clock())
        executed(log, T1)
        as_dict = {
            "id": "T001",
            "payee": T1.payee,
            "account": T1.account,
            "amount": "480.00",
            "reference": T1.reference,
        }
        self.assertEqual(reconcile(log.entries, [as_dict]), [])
        as_dict["amount"] = "481.00"
        self.assertEqual(len(reconcile(log.entries, [as_dict])), 1)

    def test_other_entry_shapes_are_read(self):
        log = AuditLog(Clock())
        log.append(
            "payment_executed",
            {
                "transfer": {
                    "id": "T001",
                    "payee": T1.payee,
                    "account": T1.account,
                    "amount": "480.00",
                    "reference": T1.reference,
                }
            },
        )
        self.assertEqual(reconcile(log.entries, [T1]), [])

    def test_only_executed_payments_count(self):
        log = AuditLog(Clock())
        for event in ("payment_submitted", "payment_declined", "payment_unknown", "hold_approved"):
            log.append(event, {"task": "m1", "transfer": "T001"})
        problems = reconcile(log.entries, [T1])
        self.assertEqual(len(problems), 1)
        self.assertIn("is in the bank but not in the log", problems[0])

    def test_malformed_entries_do_not_raise(self):
        log = AuditLog(Clock())
        executed(log, T1)
        entries = list(log.entries) + [
            None,
            "text",
            {"event": "payment_executed"},
            {"event": "payment_executed", "data": "text"},
            {"event": "payment_executed", "data": {"transfer": 7}},
            {"event": "payment_executed", "data": {"transfer": "T009", "request": "text"}},
        ]
        problems = reconcile(entries, [T1, {"payee": "no id"}, object()])
        self.assertEqual(len([p for p in problems if "without a transfer id" in p]), 3)
        self.assertEqual(len([p for p in problems if "T009" in p]), 1)
        self.assertEqual(len([p for p in problems if "without an id" in p]), 2)
        self.assertEqual(len(problems), 6)

    def test_agrees_with_the_real_guard_and_bank(self):
        """Whatever the guard writes for a payment, a clean run must reconcile."""
        from countersign.scenarios import SCENARIOS
        from countersign.simulation import run_scenario

        runs = (run_scenario(s, "countersign") for s in SCENARIOS if s.kind == "benign")
        run = next(r for r in runs if r.bank.transfers)
        entries = run.guard.audit.entries
        self.assertEqual(run.guard.audit.verify(), (True, None))
        self.assertEqual(reconcile(entries, run.bank.transfers), [])
        without_payments = [e for e in entries if e["event"] != "payment_executed"]
        problems = reconcile(without_payments, run.bank.transfers)
        self.assertEqual(len(problems), len(run.bank.transfers))


class ModuleTests(unittest.TestCase):
    def test_no_fallback_conversion_and_no_package_imports(self):
        import ast
        import inspect

        tree = ast.parse(inspect.getsource(audit))
        calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)]
        keywords = [keyword.arg for call in calls for keyword in call.keywords]
        self.assertNotIn("default", keywords)  # no default=str
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                self.assertEqual(node.level, 0, "audit.py stands alone")


if __name__ == "__main__":
    unittest.main()
