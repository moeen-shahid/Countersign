"""Receipts and the `audit` command.

Run with: python3 -m unittest tests.test_anchor -v
"""

from __future__ import annotations

import contextlib
import copy
import io
import json
import os
import stat
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from countersign import cli
from countersign.anchor import (
    Finding,
    Receipt,
    append_receipt,
    check_receipts,
    file_sink,
    load_receipts,
)
from countersign.audit import GENESIS, AuditLog, export_jsonl, load_jsonl, make_entry

START = datetime(2026, 11, 23, 9, 0, tzinfo=timezone.utc)


class Clock:
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
    """Recompute every hash, as someone with full access to the log could."""
    prev = GENESIS
    out = []
    for seq, entry in enumerate(entries):
        fresh = make_entry(seq, entry["ts"], entry["event"], entry["data"], prev)
        out.append(fresh)
        prev = fresh["hash"]
    return out


def rewritten(log: AuditLog) -> list:
    entries = copy.deepcopy(log.entries)
    entries[2]["data"]["i"] = 99
    return rechain(entries)


def run(*argv: str) -> tuple[int, str, str]:
    """Call the command line in-process. Returns (exit code, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = cli.main(list(argv))
        except SystemExit as exc:  # argparse reports its own usage errors this way
            code = exc.code
    return code, out.getvalue(), err.getvalue()


class TempDir(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = tmp.name

    def path(self, name: str) -> str:
        return os.path.join(self.dir, name)

    def write_log(self, entries, name: str = "log.jsonl") -> str:
        path = self.path(name)
        with open(path, "w", encoding="ascii", newline="\n") as fp:
            export_jsonl(entries, fp)
        return path

    def write_receipts(self, entries, name: str = "receipts.jsonl") -> str:
        path = self.path(name)
        for entry in entries:
            append_receipt(path, Receipt.of(entry))
        return path


class ReceiptTests(TempDir):
    def test_receipt_of_an_entry(self):
        log = make_log(1)
        receipt = Receipt.of(log.entries[1])
        self.assertEqual(receipt, Receipt(1, log.entries[1]["hash"], log.entries[1]["ts"]))
        self.assertEqual((receipt.seq, receipt.hash), log.head())
        self.assertEqual(Receipt.from_dict(receipt.to_dict()), receipt)

    def test_append_and_load_round_trip(self):
        log = make_log(3)
        path = self.path("receipts.jsonl")
        for entry in log.entries:
            append_receipt(path, Receipt.of(entry))
        self.assertEqual(load_receipts(path), [Receipt.of(e) for e in log.entries])
        with open(path, "rb") as fp:
            raw = fp.read()
        self.assertTrue(raw.isascii())
        self.assertEqual(raw.count(b"\n"), 4)
        self.assertTrue(raw.endswith(b"\n"))
        first = json.loads(raw.splitlines()[0])
        self.assertEqual(sorted(first), ["hash", "seq", "ts"])

    def test_file_is_private_and_only_appended_to(self):
        path = self.path("receipts.jsonl")
        log = make_log(1)
        append_receipt(path, Receipt.of(log.entries[0]))
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode) & 0o077, 0)
        with open(path, "rb") as fp:
            before = fp.read()
        append_receipt(path, Receipt.of(log.entries[1]))
        with open(path, "rb") as fp:
            after = fp.read()
        self.assertTrue(after.startswith(before))
        self.assertGreater(len(after), len(before))

    def test_file_sink_writes_a_receipt_for_every_entry(self):
        path = self.path("receipts.jsonl")
        log = make_log(3, sink=file_sink(path))
        receipts = load_receipts(path)
        self.assertEqual([r.seq for r in receipts], [0, 1, 2, 3])
        self.assertEqual(log.sink_failures, [])
        self.assertTrue(all(f.ok for f in check_receipts(log.entries, receipts)))

    def test_a_sink_that_cannot_write_is_recorded_not_raised(self):
        log = make_log(1, sink=file_sink(self.path("no-such-dir/receipts.jsonl")))
        self.assertEqual(log.verify(), (True, None))
        self.assertEqual([seq for seq, _ in log.sink_failures], [0, 1])

    def test_blank_lines_are_skipped(self):
        path = self.write_receipts(make_log(1).entries)
        with open(path, "a", encoding="ascii") as fp:
            fp.write("\n   \n")
        self.assertEqual(len(load_receipts(path)), 2)

    def test_lines_that_are_not_receipts_name_the_line(self):
        good = json.dumps(Receipt(0, "a" * 64, START.isoformat()).to_dict())
        bad_lines = [
            "{not json",
            "[]",
            '"text"',
            '{"seq": 1, "hash": "a"}',
            '{"seq": 1, "hash": "a", "ts": "t", "extra": 1}',
            '{"seq": "1", "hash": "a", "ts": "t"}',
            '{"seq": -1, "hash": "a", "ts": "t"}',
            '{"seq": true, "hash": "a", "ts": "t"}',
            '{"seq": 1, "hash": 5, "ts": "t"}',
            '{"seq": 1, "hash": "a", "ts": null}',
        ]
        for bad in bad_lines:
            with self.subTest(bad=bad):
                path = self.path("bad.jsonl")
                with open(path, "w", encoding="ascii") as fp:
                    fp.write(good + "\n" + bad + "\n")
                with self.assertRaises(ValueError) as caught:
                    load_receipts(path)
                self.assertIn("line 2", str(caught.exception))

    def test_missing_file_is_an_os_error(self):
        with self.assertRaises(OSError):
            load_receipts(self.path("nothing-here.jsonl"))


class CheckReceiptsTests(unittest.TestCase):
    def statuses(self, entries, receipts) -> list[str]:
        return [finding.status for finding in check_receipts(entries, receipts)]

    def test_intact_log_matches_every_receipt(self):
        log = make_log()
        receipts = [Receipt.of(e) for e in log.entries]
        findings = check_receipts(log.entries, receipts)
        self.assertEqual([f.status for f in findings], ["ok"] * 6)
        self.assertEqual([f.receipt for f in findings], receipts)
        self.assertIsInstance(findings[0], Finding)
        self.assertEqual(findings[0].found, log.entries[0]["hash"])

    def test_log_that_grew_still_matches_old_receipts(self):
        log = make_log(2)
        receipts = [Receipt.of(e) for e in log.entries]
        log.append("event", {"i": "later"})
        self.assertEqual(self.statuses(log.entries, receipts), ["ok"] * 3)

    def test_truncated_log(self):
        log = make_log()
        receipts = [Receipt.of(e) for e in log.entries]
        self.assertEqual(
            self.statuses(log.entries[:4], receipts), ["ok"] * 4 + ["missing_entry"] * 2
        )
        self.assertEqual(self.statuses([], receipts), ["missing_entry"] * 6)

    def test_rewritten_log(self):
        log = make_log()
        receipts = [Receipt.of(e) for e in log.entries]
        findings = check_receipts(rewritten(log), receipts)
        self.assertEqual([f.status for f in findings], ["ok"] * 2 + ["hash_mismatch"] * 4)
        self.assertNotEqual(findings[2].found, receipts[2].hash)

    def test_one_newest_receipt_is_enough(self):
        log = make_log()
        newest = [Receipt.of(log.entries[-1])]
        self.assertEqual(self.statuses(log.entries, newest), ["ok"])
        self.assertEqual(self.statuses(log.entries[:5], newest), ["missing_entry"])
        self.assertEqual(self.statuses(rewritten(log), newest), ["hash_mismatch"])

    def test_malformed_entries_do_not_raise(self):
        log = make_log(3)
        receipts = [Receipt.of(e) for e in log.entries]
        entries = [None, "text", {"seq": 2}, {"hash": 5}]
        findings = check_receipts(entries, receipts)
        self.assertEqual([f.status for f in findings], ["hash_mismatch"] * 4)
        self.assertEqual([f.found for f in findings], [None] * 4)

    def test_no_receipts_no_findings(self):
        self.assertEqual(check_receipts(make_log().entries, []), [])


class VerifyFileTests(TempDir):
    def test_intact_log(self):
        code, out, err = run("audit", "verify", "--file", self.write_log(make_log().entries))
        self.assertEqual(code, 0, out + err)
        self.assertIn("Entries: 6", out)
        self.assertIn("Chain: intact.", out)
        self.assertIn("Result: OK", out)
        # Without a head or receipts the limit of the check is spelled out.
        self.assertIn("no head or receipts were given", out)

    def test_edited_log(self):
        log = make_log()
        log.entries[3]["data"]["i"] = 99
        code, out, _ = run("audit", "verify", "--file", self.write_log(log.entries))
        self.assertEqual(code, 1)
        self.assertIn("Chain: BROKEN at entry 3.", out)
        self.assertIn("Result: FAILED", out)
        self.assertNotIn("Result: OK", out)

    def test_deleted_and_reordered_lines(self):
        log = make_log()
        entries = list(log.entries)
        del entries[2]
        code, out, _ = run("audit", "verify", "--file", self.write_log(entries))
        self.assertEqual((code, "BROKEN at entry 2." in out), (1, True))
        entries = list(log.entries)
        entries[1], entries[4] = entries[4], entries[1]
        code, out, _ = run("audit", "verify", "--file", self.write_log(entries))
        self.assertEqual((code, "BROKEN at entry 1." in out), (1, True))

    def test_junk_in_the_file_is_reported_not_raised(self):
        path = self.write_log(make_log().entries)
        with open(path, "rb") as fp:
            lines = fp.read().splitlines()
        for junk in (b"{not json", b"\xff\xfe\x00 not utf-8", b"[1, 2, 3]", b'{"seq": 2}'):
            with self.subTest(junk=junk):
                broken = list(lines)
                broken[2] = junk
                with open(path, "wb") as fp:
                    fp.write(b"\n".join(broken) + b"\n")
                code, out, err = run("audit", "verify", "--file", path)
                self.assertEqual(code, 1, out + err)
                self.assertIn("Chain: BROKEN at entry 2.", out)

    def test_undecodable_byte_inside_an_entry_is_reported(self):
        log = make_log()
        log.append("event", {"note": "plain"})
        path = self.write_log(log.entries)
        with open(path, "rb") as fp:
            raw = fp.read()
        with open(path, "wb") as fp:
            fp.write(raw.replace(b"plain", b"pl\xffin"))
        code, out, err = run("audit", "verify", "--file", path)
        self.assertEqual(code, 1, out + err)
        self.assertIn("Chain: BROKEN at entry 6.", out)

    def test_empty_file_fails(self):
        path = self.path("empty.jsonl")
        open(path, "w").close()
        code, out, _ = run("audit", "verify", "--file", path)
        self.assertEqual(code, 1)
        self.assertIn("Chain: BROKEN at entry 0.", out)

    def test_truncated_log_passes_alone_and_fails_against_receipts_or_head(self):
        log = make_log()
        receipts = self.write_receipts(log.entries)
        seq, digest = log.head()
        cut = self.write_log(log.entries[:4])

        code, out, _ = run("audit", "verify", "--file", cut)
        self.assertEqual(code, 0)  # the stated limit of the chain alone
        self.assertIn("no head or receipts were given", out)

        code, out, _ = run("audit", "verify", "--file", cut, "--receipts", receipts)
        self.assertEqual(code, 1)
        self.assertIn("Chain: intact.", out)
        self.assertIn("Receipts: 2 of 6 DO NOT MATCH.", out)
        self.assertIn("entry 4,", out)
        self.assertIn("entry 5,", out)
        self.assertIn("the log has no such entry", out)
        self.assertIn("Result: FAILED", out)

        code, out, _ = run("audit", "verify", "--file", cut, "--head", digest, "--seq", str(seq))
        self.assertEqual(code, 1)
        self.assertIn("Head: MISSING.", out)

    def test_rewritten_log_passes_alone_and_fails_against_receipts_or_head(self):
        log = make_log()
        receipts = self.write_receipts(log.entries)
        seq, digest = log.head()
        forged = self.write_log(rewritten(log))

        code, out, _ = run("audit", "verify", "--file", forged)
        self.assertEqual(code, 0)  # the stated limit of the chain alone

        code, out, _ = run("audit", "verify", "--file", forged, "--receipts", receipts)
        self.assertEqual(code, 1)
        self.assertIn("Receipts: 4 of 6 DO NOT MATCH.", out)
        self.assertIn("a different entry at that position", out)

        code, out, _ = run("audit", "verify", "--file", forged, "--head", digest, "--seq", str(seq))
        self.assertEqual(code, 1)
        self.assertIn("Head: DOES NOT MATCH.", out)

    def test_intact_log_with_receipts_and_head(self):
        log = make_log()
        path = self.write_log(log.entries)
        receipts = self.write_receipts(log.entries[:4])  # receipts may lag behind the log
        seq, digest = log.head()
        code, out, err = run(
            "audit", "verify", "--file", path, "--receipts", receipts,
            "--head", digest.upper(), "--seq", str(seq),
        )
        self.assertEqual(code, 0, out + err)
        self.assertIn("Receipts: 4 checked, all match (newest is entry 3).", out)
        self.assertIn(f"Head: entry {seq} matches.", out)
        self.assertNotIn("no head or receipts were given", out)
        self.assertIn("Result: OK", out)

    def test_an_older_head_checks_a_log_that_grew(self):
        log = make_log(2)
        seq, digest = log.head()
        log.append("event", {"i": "later"})
        path = self.write_log(log.entries)
        code, _, _ = run("audit", "verify", "--file", path, "--head", digest, "--seq", str(seq))
        self.assertEqual(code, 0)
        code, _, _ = run("audit", "verify", "--file", path, "--head", digest, "--seq", "3")
        self.assertEqual(code, 1)

    def test_empty_receipts_file_is_not_a_pass(self):
        path = self.write_log(make_log().entries)
        receipts = self.path("receipts.jsonl")
        open(receipts, "w").close()
        code, out, _ = run("audit", "verify", "--file", path, "--receipts", receipts)
        self.assertEqual(code, 1)
        self.assertIn("nothing to check against", out)

    def test_usage_errors_exit_2(self):
        path = self.write_log(make_log().entries)
        receipts = self.path("bad-receipts.jsonl")
        with open(receipts, "w", encoding="ascii") as fp:
            fp.write("not a receipt\n")
        cases = [
            ("audit",),
            ("audit", "verify"),
            ("audit", "verify", "--file", path, "--db", self.path("x.db")),
            ("audit", "verify", "--file", path, "--head", "ab" * 32),
            ("audit", "verify", "--file", path, "--seq", "3"),
            ("audit", "verify", "--file", path, "--head", "ab" * 32, "--seq", "-1"),
            ("audit", "verify", "--file", path, "--head", "ab" * 32, "--seq", "three"),
            ("audit", "verify", "--file", self.path("nothing-here.jsonl")),
            ("audit", "verify", "--file", self.dir),
            ("audit", "verify", "--file", path, "--receipts", self.path("nothing-here.jsonl")),
            ("audit", "verify", "--file", path, "--receipts", receipts),
            ("audit", "export"),
            ("audit", "head"),
            ("audit", "head", "--file", self.path("nothing-here.jsonl")),
            ("audit", "frobnicate"),
        ]
        for argv in cases:
            with self.subTest(argv=argv[1:]):
                code, out, err = run(*argv)
                self.assertEqual(code, 2, out + err)
                self.assertNotIn("Result: OK", out)
                self.assertNotIn("Traceback", err)

    def test_head_of_a_file(self):
        log = make_log()
        code, out, _ = run("audit", "head", "--file", self.write_log(log.entries))
        seq, digest = log.head()
        self.assertEqual((code, out), (0, f"{seq} {digest}\n"))
        code, out, _ = run("audit", "head", "--file", self.write_log(["junk"], "junk.jsonl"))
        self.assertEqual((code, out), (1, ""))


class DatabaseTests(TempDir):
    """The --db forms, against a real database with one task and one payment."""

    def make_db(self) -> str:
        from decimal import Decimal

        from countersign.models import Mandate
        from countersign.scenarios import NIMBUS
        from countersign.simulation import default_vendors
        from countersign.store import Store

        path = self.path("countersign.db")
        store = Store.create(path, vendors=default_vendors())
        store.console().start_task(
            Mandate(
                id="task-1", instruction="Pay the Nimbus invoice.",
                payees=("Nimbus Hosting Ltd",), max_per_payment=Decimal("2000"),
                max_total=Decimal("3000"),
                expires_at=datetime.now(timezone.utc) + timedelta(hours=8),
            ),
            confirmed_by="test",
        )
        store.agent().pay("Nimbus Hosting Ltd", NIMBUS, "480.00", "INV-1")
        return path

    def sql(self, db: str, statement: str) -> None:
        import sqlite3

        conn = sqlite3.connect(db, isolation_level=None)
        try:
            conn.execute(statement)
        finally:
            conn.close()

    def test_a_file_that_is_not_a_database_exits_2_without_a_traceback(self):
        junk = self.path("junk.db")
        with open(junk, "w") as fp:
            fp.write("not a database")
        for argv in (("audit", "verify", "--db", junk), ("audit", "head", "--db", junk),
                     ("audit", "export", "--db", junk)):
            with self.subTest(argv=argv[1]):
                code, out, err = run(*argv)
                self.assertEqual(code, 2)
                self.assertIn("not a Countersign database", err)
                self.assertNotIn("Traceback", err)

    def test_missing_database_exits_2_and_is_not_created(self):
        missing = self.path("nothing-here.db")
        code, _, err = run("audit", "verify", "--db", missing)
        self.assertEqual(code, 2)
        self.assertIn("No database at", err)
        self.assertFalse(os.path.exists(missing))

    def test_verify_head_and_export_from_the_database(self):
        db = self.make_db()
        code, out, err = run("audit", "verify", "--db", db)
        self.assertEqual(code, 0, out + err)
        self.assertIn("Chain: intact.", out)
        self.assertIn("Bank: every transfer in the bank is in the log", out)

        code, out, _ = run("audit", "head", "--db", db)
        seq, digest = out.split()
        self.assertEqual(code, 0)
        code, out, _ = run("audit", "verify", "--db", db, "--head", digest, "--seq", seq)
        self.assertEqual(code, 0)

        exported = self.path("exported.jsonl")
        code, out, err = run("audit", "export", "--db", db, "-o", exported)
        self.assertEqual((code, out), (0, ""))
        self.assertIn(f"Wrote {int(seq) + 1} entries", err)
        code, out, _ = run("audit", "verify", "--file", exported, "--head", digest, "--seq", seq)
        self.assertEqual(code, 0)

    def test_tampered_database_fails(self):
        db = self.make_db()
        self.sql(db, "UPDATE audit SET data = '{\"edited\":true}' WHERE seq = 2")
        code, out, _ = run("audit", "verify", "--db", db)
        self.assertEqual(code, 1)
        self.assertIn("Chain: BROKEN at entry 2.", out)
        self.assertIn("Result: FAILED", out)

    def test_a_log_cut_short_after_a_payment_is_caught_by_the_bank(self):
        db = self.make_db()
        self.sql(db, "DELETE FROM audit WHERE seq >= (SELECT MIN(seq) FROM audit "
                     "WHERE event = 'payment_submitted')")
        code, out, _ = run("audit", "verify", "--db", db)
        self.assertEqual(code, 1)
        self.assertIn("Chain: intact.", out)  # what is left is consistent with itself
        self.assertIn("is in the bank but not in the log", out)
        self.assertIn("Result: FAILED", out)

    def test_export_to_a_place_that_cannot_be_written(self):
        code, _, err = run(
            "audit", "export", "--db", self.make_db(), "-o", self.path("no-such-dir/out.jsonl")
        )
        self.assertEqual(code, 2)
        self.assertIn("Cannot write", err)


class HelpTests(unittest.TestCase):
    def test_the_command_is_listed(self):
        code, out, _ = run("--help")
        self.assertEqual(code, 0)
        self.assertIn("audit", out)
        code, out, _ = run("audit", "verify", "--help")
        self.assertEqual(code, 0)
        for option in ("--db", "--file", "--receipts", "--head", "--seq"):
            self.assertIn(option, out)


if __name__ == "__main__":
    unittest.main()
