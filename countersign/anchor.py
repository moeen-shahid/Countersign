"""Receipts: copies of the audit log's head that leave the guard's process.

The chain in `audit.py` shows that nobody edited the middle of the log
without redoing every later hash. It cannot show that the end was cut off, or
that the whole log was replaced by another self-consistent one. For that,
something outside the log has to remember what the head was.

A receipt is that memory: the position, hash and time of one entry, written
as one line to an append-only file. Checking a log against a receipts file
catches truncation and rewriting, but only as far as the receipts file itself
is out of the attacker's reach: put it on another machine, a write-once
share, or a printer. A receipts file that sits next to the log, writable by
the same user, proves nothing against that user.

There is no HMAC and no signature here, on purpose. A key on the same host as
the log proves nothing against that host, and we do not pretend otherwise.

Commands: `countersign audit verify | export | head`.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass
from typing import Any, Callable, Sequence

from .audit import canonical, export_jsonl, load_jsonl, verify_entries

OK = "ok"
MISSING_ENTRY = "missing_entry"
HASH_MISMATCH = "hash_mismatch"


@dataclass(frozen=True)
class Receipt:
    """One remembered head: entry `seq` had hash `hash`; `ts` is that entry's time."""

    seq: int
    hash: str
    ts: str

    @classmethod
    def of(cls, entry: dict[str, Any]) -> "Receipt":
        return cls(seq=entry["seq"], hash=entry["hash"], ts=entry["ts"])

    def to_dict(self) -> dict[str, Any]:
        return {"seq": self.seq, "hash": self.hash, "ts": self.ts}

    @classmethod
    def from_dict(cls, raw: Any) -> "Receipt":
        if not isinstance(raw, dict) or raw.keys() != {"seq", "hash", "ts"}:
            raise ValueError("a receipt has exactly the keys seq, hash and ts")
        seq, digest, ts = raw["seq"], raw["hash"], raw["ts"]
        if type(seq) is not int or seq < 0:
            raise ValueError("a receipt's seq is a whole number, 0 or more")
        if not isinstance(digest, str) or not isinstance(ts, str):
            raise ValueError("a receipt's hash and ts are text")
        return cls(seq=seq, hash=digest, ts=ts)


@dataclass(frozen=True)
class Finding:
    """The result of checking one receipt against a log."""

    receipt: Receipt
    status: str  # "ok" | "missing_entry" | "hash_mismatch"
    found: str | None = None  # the hash the log has at that position, if any

    @property
    def ok(self) -> bool:
        return self.status == OK


def append_receipt(path: str | os.PathLike, receipt: Receipt) -> None:
    """Add one receipt as one JSON line. Appended in a single write, then synced."""
    line = (canonical(receipt.to_dict()) + "\n").encode("ascii")
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        os.write(fd, line)
        os.fsync(fd)
    finally:
        os.close(fd)


def load_receipts(path: str | os.PathLike) -> list[Receipt]:
    """Read a receipts file. Raises ValueError naming the line if one is not a receipt."""
    receipts: list[Receipt] = []
    with open(path, encoding="utf-8", errors="replace") as fp:
        for number, line in enumerate(fp, start=1):
            if not line.strip():
                continue
            try:
                receipts.append(Receipt.from_dict(json.loads(line)))
            except (ValueError, RecursionError) as exc:
                where = f"{os.fspath(path)}: line {number}"
                raise ValueError(f"{where} is not a receipt ({exc})") from None
    return receipts


def file_sink(path: str | os.PathLike) -> Callable[[dict[str, Any]], None]:
    """A sink for `AuditLog(sink=...)` that writes a receipt for every new entry."""

    def sink(entry: dict[str, Any]) -> None:
        append_receipt(path, Receipt.of(entry))

    return sink


def check_receipts(entries: Sequence[Any], receipts: Sequence[Receipt]) -> list[Finding]:
    """One finding per receipt, in the order given.

    `missing_entry`: the log has no entry at that position (it was cut short).
    `hash_mismatch`: the log has a different entry there (it was rewritten).
    This does not check the chain itself; use `audit.verify_entries` as well.
    """
    findings: list[Finding] = []
    for receipt in receipts:
        if receipt.seq >= len(entries):
            findings.append(Finding(receipt, MISSING_ENTRY))
            continue
        entry = entries[receipt.seq]
        found = entry.get("hash") if isinstance(entry, dict) else None
        if not isinstance(found, str):
            found = None
        findings.append(Finding(receipt, OK if found == receipt.hash else HASH_MISMATCH, found))
    return findings


# --- command line ---------------------------------------------------------------


class _Usage(Exception):
    """A problem with how the command was called or with a file it was given."""


def _store(path: str) -> Any:
    from .store import Store, StoreError  # imported here: the --file forms need no database

    if not os.path.isfile(path):
        raise _Usage(f"No database at {path}.")
    try:
        return Store(path)
    except StoreError as exc:
        raise _Usage(str(exc)) from None


def _entries_from_db(path: str) -> list[Any]:
    return _store(path).audit_entries()


def _entries_from_file(path: str) -> list[Any]:
    try:
        # Undecodable bytes become lone surrogates, which then fail the hash
        # check at their position instead of stopping the whole command.
        with open(path, encoding="utf-8", errors="surrogateescape") as fp:
            return load_jsonl(fp)
    except OSError as exc:
        raise _Usage(f"Cannot read {path}: {exc.strerror or exc}.") from None


def _entries(args: argparse.Namespace) -> list[Any]:
    if getattr(args, "file", None) is not None:
        return _entries_from_file(args.file)
    return _entries_from_db(args.db)


def _head_of(entries: Sequence[Any]) -> tuple[int, str] | None:
    last = entries[-1] if entries else None
    if not isinstance(last, dict):
        return None
    seq, digest = last.get("seq"), last.get("hash")
    return (seq, digest) if type(seq) is int and isinstance(digest, str) else None


def _cmd_verify(args: argparse.Namespace) -> int:
    if (args.head is None) != (args.seq is None):
        raise _Usage("--head and --seq go together: the hash and the position it was taken at.")
    if args.seq is not None and args.seq < 0:
        raise _Usage("--seq must be 0 or more.")
    entries = _entries(args)
    receipts: list[Receipt] | None = None
    if args.receipts is not None:
        try:
            receipts = load_receipts(args.receipts)
        except OSError as exc:
            raise _Usage(f"Cannot read {args.receipts}: {exc.strerror or exc}.") from None
        except ValueError as exc:
            raise _Usage(str(exc)) from None

    failed = False
    print(f"Entries: {len(entries)}")
    intact, bad = verify_entries(entries)
    if intact:
        print("Chain: intact.")
    else:
        failed = True
        print(f"Chain: BROKEN at entry {bad}.")

    if args.head is not None:
        expected = args.head.strip().lower()
        entry = entries[args.seq] if args.seq < len(entries) else None
        if entry is None:
            failed = True
            print(f"Head: MISSING. The log has no entry {args.seq}; it ends before that.")
        elif not isinstance(entry, dict) or entry.get("hash") != expected:
            failed = True
            print(f"Head: DOES NOT MATCH. Entry {args.seq} is not the one that was recorded.")
        else:
            print(f"Head: entry {args.seq} matches.")

    if receipts is not None:
        findings = check_receipts(entries, receipts)
        wrong = [f for f in findings if not f.ok]
        if not findings:
            failed = True
            print("Receipts: the file is empty, so there is nothing to check against.")
        elif not wrong:
            newest = max(f.receipt.seq for f in findings)
            print(f"Receipts: {len(findings)} checked, all match (newest is entry {newest}).")
        else:
            failed = True
            print(f"Receipts: {len(wrong)} of {len(findings)} DO NOT MATCH.")
            for finding in wrong:
                if finding.status == MISSING_ENTRY:
                    what = "the log has no such entry; it ends before that"
                else:
                    what = "the log has a different entry at that position"
                print(f"  entry {finding.receipt.seq}, receipt of {finding.receipt.ts}: {what}")

    if getattr(args, "db", None):
        # The simulated bank lives in the same file, so the log can also be
        # compared with the money that actually moved. This catches a log cut
        # short after a payment even without a head or receipts.
        problems = _store(args.db).reconcile()
        if problems:
            failed = True
            print(f"Bank: {len(problems)} DISAGREEMENT(S) between the log and the bank.")
            for problem in problems:
                print(f"  {problem}")
        else:
            print("Bank: every transfer in the bank is in the log, and the reverse.")

    if args.head is None and receipts is None and not failed:
        print(
            "Note: no head or receipts were given. This shows the log is consistent with "
            "itself. It does not show that the end was not cut off or that the whole log "
            "was not replaced; for that, check against a head or receipts kept elsewhere."
        )
    print("Result: FAILED" if failed else "Result: OK")
    return 1 if failed else 0


def _cmd_export(args: argparse.Namespace) -> int:
    entries = _entries_from_db(args.db)
    if args.output is None:
        export_jsonl(entries, sys.stdout)
        return 0
    try:
        with open(args.output, "w", encoding="ascii", newline="\n") as fp:
            count = export_jsonl(entries, fp)
    except OSError as exc:
        raise _Usage(f"Cannot write {args.output}: {exc.strerror or exc}.") from None
    print(f"Wrote {count} entries to {args.output}.", file=sys.stderr)
    return 0


def _cmd_head(args: argparse.Namespace) -> int:
    head = _head_of(_entries(args))
    if head is None:
        print("The log has no readable last entry.", file=sys.stderr)
        return 1
    print(f"{head[0]} {head[1]}")
    return 0


def _run(handler: Callable[[argparse.Namespace], int]) -> Callable[[argparse.Namespace], int]:
    def run(args: argparse.Namespace) -> int:
        try:
            return handler(args)
        except _Usage as exc:
            print(f"countersign audit: {exc}", file=sys.stderr)
            return 2

    return run


def add_cli(subparsers: Any) -> None:
    """Register the `audit` command (see cli.py for the convention)."""
    audit = subparsers.add_parser(
        "audit",
        help="verify or export the audit log",
        description="Check the tamper-evident audit log, export it, or print its head.",
    )
    actions = audit.add_subparsers(dest="audit_command", metavar="<action>")
    audit.set_defaults(func=lambda args: audit.print_help() or 2)

    verify = actions.add_parser(
        "verify",
        help="check the chain, and a head or receipts if given",
        description="Exit code 0 if every check passes, 1 if any fails, 2 on a usage error.",
    )
    source = verify.add_mutually_exclusive_group(required=True)
    source.add_argument("--db", metavar="PATH", help="the guard's database")
    source.add_argument("--file", metavar="LOG.jsonl", help="a log written by `audit export`")
    verify.add_argument("--receipts", metavar="FILE", help="receipts kept outside the guard's host")
    verify.add_argument("--head", metavar="HASH", help="a head hash recorded earlier (with --seq)")
    verify.add_argument("--seq", metavar="N", type=int, help="the entry that hash belongs to")
    verify.set_defaults(func=_run(_cmd_verify))

    export = actions.add_parser("export", help="write the log as JSON lines")
    export.add_argument("--db", metavar="PATH", required=True, help="the guard's database")
    export.add_argument("-o", "--output", metavar="FILE", help="write here instead of the terminal")
    export.set_defaults(func=_run(_cmd_export))

    head = actions.add_parser(
        "head",
        help="print the position and hash of the newest entry",
        description="Prints `SEQ HASH`. Keep it somewhere else; `audit verify` can check it later.",
    )
    source = head.add_mutually_exclusive_group(required=True)
    source.add_argument("--db", metavar="PATH", help="the guard's database")
    source.add_argument("--file", metavar="LOG.jsonl", help="a log written by `audit export`")
    head.set_defaults(func=_run(_cmd_head))
