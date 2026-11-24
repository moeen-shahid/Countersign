"""One database file shared by every process that works with the guard.

The MCP server (the agent's side), the web console and the command line (the
person's side) are separate processes. They share one SQLite file, so there is
one state and one audit log however many of them run.

The design is a unit of work around the ordinary in-memory `Guard`. Every
operation opens its own connection and then:

    BEGIN IMMEDIATE            take the write lock; other writers wait here
    load the state snapshot    one JSON document, `Guard.to_state()`
    Guard.from_state(...)      with an audit log that writes to this connection
    call one Guard method
    write the new snapshot
    COMMIT

Anything that goes wrong before COMMIT rolls the whole operation back: the
snapshot, the audit entries and the simulated bank (which lives inside the
snapshot) change together or not at all. Two processes can therefore never
both pass a check that only one of them should pass.

`Store.agent()` and `Store.console()` are the capability boundary. An
`AgentPort` can read the task, record a document, ask for a payment and look
up a hold. Starting a task and deciding a hold are on `Console` only, and
agent-facing modules never hold one.

`Console.approve` also checks what a person must do before a hold is passed
to the guard (`approve_hold`), in the same transaction: a hold about the
account (P1, P2, P3) needs the whole account typed back as the vendor
confirmed it, and only a hold about the amount (A1, A2) can be marked as the
payee's new usual amount. The guard compares the typed account
(`Guard.approve(confirmed_account=...)`) and logs a mismatch
(`hold_confirmation_failed`); that entry is kept although the approval is
refused. The command line and the web console both go through it, so the
check does not depend on a page.

Limits, stated plainly:

* The boundary is between modules, not between operating-system users. A
  program that can open this file as the same user can change it. The file
  is created readable and writable by its owner only (mode 0600).
* The bank is simulated and stored in the same snapshot, so one commit covers
  the decision and the transfer. A real bank is a separate system: the
  `payment_submitted` entry would have to be committed before the bank is
  called. The guard already writes its entries in that order.
* The whole snapshot is rewritten on every operation, which is fine for a
  desk-sized workload and not meant for more.
"""

from __future__ import annotations

import json
import os
import pathlib
import secrets
import sqlite3
import sys
import time
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Callable, Iterable, TypeVar

from . import __version__
from .anchor import Receipt, append_receipt
from .audit import (
    GENESIS,
    LOG_VERSION,
    Entry,
    Head,
    canonical,
    continue_chain,
    make_entry,
    reconcile,
)
from .audit import verify_entries
from .bank import MockBank
from .guard import (  # noqa: F401 - ApprovalRefused is part of this module's interface
    ApprovalRefused,
    ConfirmationFailed,
    Guard,
    Hold,
    PayResult,
    confirmation_problem,
)
from .models import Mandate
from .policy import DESTINATION_RULES, GUARD_MODES
from .toolsurface import hold_view, pay_view, task_view
from .vendors import Vendor, VendorFile

SCHEMA_VERSION = 1
BUSY_SECONDS = 30.0  # how long one operation waits for another process to finish
FULL_CHECK_SECONDS = 30.0
RECEIPTS_ENV = "COUNTERSIGN_RECEIPTS"

# Entries after which the new head is worth remembering outside the database:
# money moved (or may have), or what may be paid changed.
RECEIPT_EVENTS = frozenset(
    {
        "task_started",
        "task_ended",
        "task_quarantined",
        "hold_approved",
        "hold_rejected",
        "payment_executed",
        "payment_unknown",
        "vendor_account_added",
        "vendor_account_removed",
    }
)

_SCHEMA = (
    "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
    "CREATE TABLE state (id INTEGER PRIMARY KEY CHECK (id = 1), json TEXT NOT NULL)",
    "CREATE TABLE audit (seq INTEGER PRIMARY KEY, ts TEXT NOT NULL, event TEXT NOT NULL, "
    "data TEXT NOT NULL, prev TEXT NOT NULL, hash TEXT NOT NULL)",
)
_ENTRY_COLUMNS = "seq, ts, event, data, prev, hash"

T = TypeVar("T")


class StoreError(Exception):
    """The database could not be used. The message is one plain sentence."""


class StoreExists(StoreError):
    """`Store.create` was asked to create a file that is already there."""


class StoreMissing(StoreError):
    """There is no database at the path. Opening never creates one."""


class StoreVersionError(StoreError):
    """The database was written with a different layout than this code reads."""


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _connect(path: str) -> sqlite3.Connection:
    """Open an existing database file. `mode=rw` means SQLite never creates one."""
    uri = pathlib.Path(path).absolute().as_uri() + "?mode=rw"
    try:
        # isolation_level=None: no implicit transactions; every BEGIN here is explicit.
        return sqlite3.connect(uri, uri=True, timeout=BUSY_SECONDS, isolation_level=None)
    except sqlite3.OperationalError:
        raise StoreMissing(f"No database at {path}.") from None


def _end(conn: sqlite3.Connection) -> None:
    """Give up whatever the connection has open, then close it."""
    try:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
    except sqlite3.Error:
        pass  # closing drops an open transaction as well
    finally:
        conn.close()


def _entry_of(row: tuple[Any, ...]) -> Any:
    seq, ts, event, data, prev, digest = row
    try:
        data = json.loads(data)
    except (TypeError, ValueError, RecursionError):
        pass  # kept as it is; verification then reports the log broken at this entry
    return {"seq": seq, "ts": ts, "event": event, "data": data, "prev": prev, "hash": digest}


def _entries(conn: sqlite3.Connection, after_seq: int = -1) -> list[Any]:
    rows = conn.execute(
        f"SELECT {_ENTRY_COLUMNS} FROM audit WHERE seq > ? ORDER BY seq", (after_seq,)
    )
    return [_entry_of(row) for row in rows]


def _head(conn: sqlite3.Connection) -> Head | None:
    row = conn.execute("SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
    return None if row is None else (row[0], row[1])


def _meta(conn: sqlite3.Connection) -> dict[str, str]:
    return {key: value for key, value in conn.execute("SELECT key, value FROM meta")}


def _state(conn: sqlite3.Connection) -> dict[str, Any]:
    row = conn.execute("SELECT json FROM state WHERE id = 1").fetchone()
    if row is None:
        raise StoreError("The database has no guard state in it.")
    try:
        state = json.loads(row[0])
    except (TypeError, ValueError, RecursionError):
        state = None
    if not isinstance(state, dict):
        raise StoreError("The guard state in the database cannot be read.")
    return state


class DbAuditLog:
    """The audit log of one unit of work, written to that unit's connection.

    It has the interface the guard uses (`append`, `head`, `entries`,
    `verify`) and builds entries with `audit.make_entry`, so a log kept here
    hashes exactly like one kept in memory. Nothing is durable until the
    surrounding transaction commits.
    """

    def __init__(
        self, conn: sqlite3.Connection, clock: Callable[[], datetime] | None = None
    ) -> None:
        self._conn = conn
        self._clock = clock or _utc_now
        self._last: Head | None = None  # read once; this connection holds the write lock
        self._known = False
        self.added: list[Entry] = []  # entries appended through this object
        # Set when the database refused an entry. The guard may swallow that
        # error to answer the agent; the unit of work must not commit after it.
        self.failed: Exception | None = None

    def append(self, event: str, data: dict[str, Any]) -> Entry:
        """Add one entry and return it. Raises on data that is not JSON-safe."""
        if not self._known:
            self._last, self._known = _head(self._conn), True
        seq, prev = (0, GENESIS) if self._last is None else (self._last[0] + 1, self._last[1])
        entry = make_entry(seq, self._clock().isoformat(), event, data, prev)
        try:
            self._conn.execute(
                f"INSERT INTO audit ({_ENTRY_COLUMNS}) VALUES (?, ?, ?, ?, ?, ?)",
                (seq, entry["ts"], event, canonical(entry["data"]), prev, entry["hash"]),
            )
        except sqlite3.Error as exc:
            self.failed = exc
            raise
        self._last = (seq, entry["hash"])
        self.added.append(entry)
        return entry


class AgentPort:
    """Everything an agent-facing module can do with the store. Four methods.

    The answers are plain dicts holding only what an agent is told: no
    limits, no balance, no rule ladder, no evidence.
    """

    __slots__ = ("_store",)

    def __init__(self, store: Store) -> None:
        self._store = store

    def task(self) -> dict[str, Any] | None:
        """None, or the instruction, the exact payee names, the currency and the expiry."""
        mandate = self._store.mandate()
        return None if mandate is None else task_view(mandate)

    def observe(self, source: str, text: str) -> None:
        """Record a document the agent has read. Raises if it could not be recorded."""
        self._store._write(lambda guard: guard.observe(source, text))

    def pay(
        self,
        payee: str,
        account: str,
        amount: object,
        reference: str = "",
        currency: str | None = None,
    ) -> dict[str, Any]:
        """Ask for a payment. The guard's answer: outcome, rule, rules, reason,
        transfer_id, hold_id. Raises `StoreError` only when the database could
        not record the request; nothing is paid in that case."""
        result = self._store._write(
            lambda guard: guard.pay(payee, account, amount, reference, currency)
        )
        return pay_view(result)

    def hold_status(self, hold_id: str) -> dict[str, Any] | None:
        """The status and transfer id of one hold, or None if there is no such hold."""
        for hold in self._store.holds():
            if hold.id == hold_id:
                return hold_view(hold)
        return None


# --- what the person's side asks before a hold is approved ---------------------------
#
# Every way a person approves a hold (the command line, the web console's live
# view and its lab) goes through `approve_hold`, so these checks hold for the
# API as well as for the page. The benchmark's approver models call
# `Guard.approve` directly: they are models of a person, not a person.

# Holds whose question is the account (P1, P2, P3). To countersign one, the
# person types back the whole account the vendor confirmed through a channel
# they already trusted, and it must be the account in the hold. The whole
# account: a look-alike can share the first twelve and the last four
# characters with the real one (adversary trace D01).
ACCOUNT_RULES = frozenset(DESTINATION_RULES)
# Holds about the amount, where the person may say "this is the new usual amount".
AMOUNT_RULES = frozenset({"A1", "A2"})
# Holds where the account is not on file for the payee, so it can be remembered.
NEW_ACCOUNT_RULES = frozenset({"P1", "P2"})
TYPED_BACK = "typed back the account the vendor confirmed, and it matched this payment's account"


def with_typed_back(attestation: str) -> str:
    """The attestation a person's screen records after the account was typed
    back and matched (`approve_hold` checks the match; this only words it)."""
    note = str(attestation or "").strip()
    return f"{note}; {TYPED_BACK}" if note else TYPED_BACK


def needs_typed_account(hold: Hold) -> bool:
    """True when approving this hold needs the account typed back (P1, P2, P3)."""
    return bool(ACCOUNT_RULES & set(hold.decision.rules))


def offers_usual_amount(hold: Hold) -> bool:
    """True when the hold is about the amount (A1, A2), so it can be marked usual."""
    return bool(AMOUNT_RULES & set(hold.decision.rules))


def offers_remember_account(hold: Hold) -> bool:
    """True when the account is not on file for the payee (P1, P2)."""
    return bool(NEW_ACCOUNT_RULES & set(hold.decision.rules))


def approval_problem(
    hold: Hold, *, confirmed_account: object = None, usual_amount: bool = False
) -> str | None:
    """Why the person's side will not pass this approval to the guard, or None.

    * A hold about the account needs the account typed back. The typed text
      is read as one IBAN (spaces and case do not matter) and compared with
      the hold's account as a whole (`guard.confirmation_problem`, the one
      comparison). Nothing is pre-filled and no part of it is enough.
    * An account typed for any other hold must match too.
    * Only a hold about the amount can be marked as the new usual amount.

    This only answers; it logs nothing. `approve_hold` leaves the comparison
    to `Guard.approve`, which logs a mismatch.
    """
    problem = _before_the_guard(hold, confirmed_account, usual_amount)
    if problem is not None:
        return problem
    if confirmed_account is not None and str(confirmed_account).strip():
        return confirmation_problem(hold, confirmed_account)
    return None


def _before_the_guard(hold: Hold, confirmed_account: object, usual_amount: bool) -> str | None:
    """What the person's side refuses without asking the guard: text that is not
    text, no account typed for a hold about the account, a usual-amount mark on
    a hold that is not about the amount."""
    if confirmed_account is not None and not isinstance(confirmed_account, str):
        return "The confirmed account must be text."
    typed = confirmed_account.strip() if isinstance(confirmed_account, str) else ""
    rules = set(hold.decision.rules)
    if rules & ACCOUNT_RULES and not typed:
        codes = ", ".join(rule for rule in hold.decision.rules if rule in ACCOUNT_RULES)
        return (
            f"Hold {hold.id} is held because of its account ({codes}). To countersign it, "
            "type the whole account the vendor confirmed to you through a channel you already "
            "trusted, such as a phone number you already had. Nothing was paid."
        )
    if usual_amount and not rules & AMOUNT_RULES:
        return (
            f"Hold {hold.id} is not held because of its amount (A1, A2), so there is no "
            "amount to mark as usual. Nothing was paid."
        )
    return None


def approve_hold(
    guard: Guard,
    hold_id: str,
    *,
    approver: str,
    digest: str | None = None,
    attestation: str = "",
    remember_account: bool = False,
    usual_amount: bool = False,
    confirmed_account: str | None = None,
) -> PayResult:
    """Countersign one hold for a person: the person's-side checks, then
    `Guard.approve`, which compares the typed account.

    Raises `ApprovalRefused` (a ValueError) before the guard is asked when
    the person's side refuses, `ConfirmationFailed` (an ApprovalRefused) when
    the typed account is not the hold's (the guard has logged that), and
    whatever else `Guard.approve` raises. A stale digest is left to the
    guard, so that it is reported as such. The attestation is passed on as it
    is: the screens word it (`with_typed_back`), so that an approval made here
    logs exactly what the same approval made on the guard in memory logs.
    """
    hold = guard.hold(hold_id)  # KeyError for an unknown hold
    typed = None
    if hold.status == "pending" and (digest is None or digest == hold.digest):
        problem = _before_the_guard(hold, confirmed_account, usual_amount)
        if problem is not None:
            raise ApprovalRefused(problem)
        typed = confirmed_account if confirmed_account and confirmed_account.strip() else None
    return guard.approve(
        hold_id,
        approver,
        remember_account=remember_account,
        digest=digest,
        attestation=attestation,
        usual_amount=usual_amount,
        confirmed_account=typed,
    )


class Console:
    """The person's side: starting and ending tasks, deciding holds.

    Every method is one unit of work. What the guard raises (an unknown hold
    is KeyError; a hold already decided, from an earlier task or changed since
    it was displayed is ValueError) is raised here after the roll back, and
    so is `ApprovalRefused` (a ValueError) from the checks of `approve_hold`.
    """

    __slots__ = ("_store",)

    def __init__(self, store: Store) -> None:
        self._store = store

    def start_task(
        self, mandate: Mandate, *, confirmed_by: str, draft_digest: str | None = None
    ) -> None:
        """Start a task. `draft_digest` is the digest of the draft the person
        confirmed (`Draft.digest()`), logged with the task."""
        self._store._write(lambda guard: guard.start_task(
            mandate, confirmed_by=confirmed_by, draft_digest=draft_digest))

    def check_account(
        self, hold_id: str, confirmed_account: object, *, approver: str
    ) -> str | None:
        """Compare the account a person typed back with a waiting hold, before
        asking them to approve it: None when it matches, else the reason. A
        mismatch is logged (`hold_confirmation_failed`) and that is kept."""
        return self._store._write(
            lambda guard: guard.check_confirmation(hold_id, confirmed_account, approver))

    def end_task(self, *, by: str) -> None:
        self._store._write(lambda guard: guard.end_task(by=by))

    def approve(
        self,
        hold_id: str,
        *,
        approver: str,
        digest: str | None = None,
        attestation: str = "",
        remember_account: bool = False,
        usual_amount: bool = False,
        confirmed_account: str | None = None,
    ) -> PayResult:
        """Countersign one hold. See `approve_hold` and `Guard.approve` for what
        the result can be.

        `confirmed_account` is the account the person typed back; a hold about
        the account (P1, P2, P3) is refused without it, or when it is not the
        hold's account (`ConfirmationFailed`; the attempt stays in the log).
        `usual_amount` marks the amount as a usual amount for the payee (rules
        A1, A2), only on a hold about the amount; without it, an amount outside
        the usual range does not move the line."""
        return self._store._write(
            lambda guard: approve_hold(
                guard,
                hold_id,
                approver=approver,
                digest=digest,
                attestation=attestation,
                remember_account=remember_account,
                usual_amount=usual_amount,
                confirmed_account=confirmed_account,
            )
        )

    def reject(self, hold_id: str, *, approver: str, wrong: str | None = None) -> None:
        """Refuse a held payment. `wrong` is what the person says was wrong,
        "account" or "payment" (`Guard.reject`); None keeps the guard's default:
        for a hold about the account, the account."""
        self._store._write(lambda guard: guard.reject(hold_id, approver, wrong=wrong))


class Store:
    """An existing Countersign database. Use `Store.create` to make a new one."""

    def __init__(
        self,
        path: str | os.PathLike,
        *,
        clock: Callable[[], datetime] | None = None,
        receipts: str | os.PathLike | None = None,
    ) -> None:
        """Open the database at `path`. Never creates one.

        Raises `StoreMissing` if there is no file, `StoreVersionError` if it
        was written with another layout, `StoreError` if it is not a
        Countersign database. `receipts` names a file that gets a copy of the
        audit head after every commit that moved money or changed authority;
        without it the `COUNTERSIGN_RECEIPTS` variable is used, then the path
        recorded when the database was created, if any.
        """
        self.path = os.path.abspath(os.fspath(path))
        self._clock = clock or _utc_now
        if not os.path.isfile(self.path):
            raise StoreMissing(f"No database at {self.path}.")
        meta = self.meta()
        found = meta.get("schema_version")
        if found != str(SCHEMA_VERSION):
            raise StoreVersionError(
                f"The database at {self.path} has layout version {found or 'unknown'}; "
                f"this version of Countersign reads version {SCHEMA_VERSION}."
            )
        chosen = receipts if receipts is not None else os.environ.get(RECEIPTS_ENV)
        chosen = chosen or meta.get("receipts")
        self.receipts: str | None = os.path.abspath(os.fspath(chosen)) if chosen else None
        # (seq, error) for every receipt that could not be written. The commit
        # it belongs to stands; the next commit writes a receipt for its own
        # head as soon as receipts can be written again.
        self.receipt_failures: list[tuple[int, str]] = []
        self._receipt_owed = False
        # (seq, hash, when) of the last time the whole chain was checked, so a
        # console polling every second only checks what was added since.
        self._checked: tuple[int, str, float] | None = None

    @classmethod
    def create(
        cls,
        path: str | os.PathLike,
        *,
        vendors: VendorFile | Iterable[Vendor] = (),
        balance: Decimal = Decimal("50000.00"),
        mode: str = "countersign",
        clock: Callable[[], datetime] | None = None,
        log_id: str | None = None,
        receipts: str | os.PathLike | None = None,
        inbox: str | os.PathLike | None = None,
    ) -> Store:
        """Create a new database and return it opened. Refuses an existing file.

        `balance` is the simulated bank's opening balance. `log_id` fixes the
        id in entry 0 of the audit log (random by default; a fixed one makes a
        replay reproducible). `receipts` and `inbox` are paths recorded in the
        database so that every process finds the same receipts file and the
        console can show the inbox the agent was given.
        """
        path = os.path.abspath(os.fspath(path))
        clock = clock or _utc_now
        if mode not in GUARD_MODES:
            raise ValueError(f"mode must be one of {GUARD_MODES}")
        if isinstance(balance, bool) or not isinstance(balance, Decimal):
            raise ValueError("balance must be a Decimal")
        if not balance.is_finite() or balance < 0:
            raise ValueError("balance must be a finite amount, 0 or more")
        if log_id is not None and not isinstance(log_id, str):
            raise ValueError("log_id must be text")
        vendor_file = vendors if isinstance(vendors, VendorFile) else VendorFile(vendors)
        # Checked and built before any file exists, so a bad argument leaves nothing behind.
        state = Guard(MockBank(balance), vendor_file, mode=mode, clock=clock).to_state()
        opened = make_entry(
            0,
            clock().isoformat(),
            "log_opened",
            {"log_id": secrets.token_hex(8) if log_id is None else log_id, "version": LOG_VERSION},
            GENESIS,
        )
        meta = {
            "schema_version": str(SCHEMA_VERSION),
            "created_at": opened["ts"],
            "created_by": f"countersign {__version__}",
            "log_id": opened["data"]["log_id"],
        }
        if receipts is not None:
            meta["receipts"] = os.path.abspath(os.fspath(receipts))
        if inbox is not None:
            meta["inbox"] = os.path.abspath(os.fspath(inbox))

        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            raise StoreExists(f"There is already a file at {path}.") from None
        try:
            if hasattr(os, "fchmod"):
                os.fchmod(fd, 0o600)  # exactly 0600, whatever the umask is
        finally:
            os.close(fd)
        try:
            conn = _connect(path)
            try:
                # WAL: readers do not block the writer. SQLite gives the -wal
                # and -shm files the same permissions as the database file.
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute("BEGIN IMMEDIATE")
                for statement in _SCHEMA:
                    conn.execute(statement)
                conn.executemany("INSERT INTO meta (key, value) VALUES (?, ?)", meta.items())
                conn.execute("INSERT INTO state (id, json) VALUES (1, ?)", (canonical(state),))
                conn.execute(
                    f"INSERT INTO audit ({_ENTRY_COLUMNS}) VALUES (?, ?, ?, ?, ?, ?)",
                    (0, opened["ts"], opened["event"], canonical(opened["data"]),
                     opened["prev"], opened["hash"]),
                )
                conn.execute("COMMIT")
            finally:
                _end(conn)
        except BaseException:
            for leftover in (path, path + "-wal", path + "-shm"):
                try:
                    os.remove(leftover)
                except OSError:
                    pass
            raise
        store = cls(path, clock=clock, receipts=receipts)
        store._anchor([opened], always=True)
        return store

    # --- the two sides ----------------------------------------------------------

    def agent(self) -> AgentPort:
        """The agent's side: task, observe, pay, hold_status."""
        return AgentPort(self)

    def console(self) -> Console:
        """The person's side. Never handed to an agent-facing module."""
        return Console(self)

    # --- reading ----------------------------------------------------------------

    def head(self) -> Head:
        """(seq, hash) of the newest audit entry."""
        head = self._read(_head)
        if head is None:
            raise StoreError(f"The audit log in {self.path} is empty.")
        return head

    def audit_entries(self, after_seq: int = -1) -> list[Any]:
        """The audit entries with a position after `after_seq`, oldest first."""
        return self._read(lambda conn: _entries(conn, after_seq))

    def verify(self) -> tuple[bool, int | None]:
        """Check the hash chain: (True, None), or (False, first broken position).

        This shows the log is consistent with itself. Whether its end was cut
        off or the whole log replaced can only be checked against a head or
        receipts kept elsewhere (see anchor.py).
        """
        return verify_entries(self.audit_entries())

    def reconcile(self) -> list[str]:
        """Compare the log with the simulated bank's transfers. Empty means they agree."""
        entries, state = self._read(lambda conn: (_entries(conn), _state(conn)))
        return reconcile(entries, state["bank"]["transfers"])

    def state(self) -> dict[str, Any]:
        """The guard's state as plain JSON data (`Guard.to_state()`)."""
        return self._read(_state)

    def meta(self) -> dict[str, str]:
        """What was recorded at creation: schema_version, created_at, created_by,
        log_id, and receipts and inbox when they were given."""
        try:
            return self._read(_meta)
        except sqlite3.DatabaseError:
            raise StoreError(f"{self.path} is not a Countersign database.") from None

    def mandate(self) -> Mandate | None:
        """The mandate of the active task, or None."""
        mandate = self.state()["mandate"]
        return None if mandate is None else Mandate.from_dict(mandate)

    def holds(self) -> list[Hold]:
        """Every hold, oldest first, whatever became of it."""
        return [Hold.from_dict(item) for item in self.state()["holds"]]

    def hold(self, hold_id: str) -> Hold:
        """One hold. Raises KeyError if there is none with that id."""
        for hold in self.holds():
            if hold.id == hold_id:
                return hold
        raise KeyError(hold_id)

    def related(self, hold_id: str) -> dict[str, Any]:
        """What a person deciding this hold should see next to it now: rival
        payments of the same invoice (D3) and the waiting payments it needs
        room with (H2), computed from the current state (`Guard.related`).
        Raises KeyError if there is no such hold. Changes nothing."""
        return Guard.from_state(self.state(), clock=self._clock).related(hold_id)

    def snapshot(self, after_seq: int = -1) -> dict[str, Any]:
        """Everything a live console shows, read at one moment.

        `head` is (seq, hash); `mode` the guard mode; `state` the guard state
        (mandate, task totals, observations, holds, vendors, bank); `entries`
        the audit entries after `after_seq` (all of them by default); `intact`
        and `broken_at` the result of checking the whole chain. `now` is the
        store's clock, `path` the database file and `meta` what `meta()`
        returns.
        """

        def read(conn: sqlite3.Connection) -> tuple[Any, ...]:
            intact, broken_at = self._check_chain(conn)
            return _head(conn), _entries(conn, after_seq), intact, broken_at, _state(conn), _meta(
                conn
            )

        head, entries, intact, broken_at, state, meta = self._read(read)
        return {
            "head": head,
            "mode": state.get("mode"),
            "state": state,
            "entries": entries,
            "intact": intact,
            "broken_at": broken_at,
            "now": self._clock().isoformat(),
            "path": self.path,
            "meta": meta,
        }

    def _check_chain(self, conn: sqlite3.Connection) -> tuple[bool, int | None]:
        """Check the chain, re-reading only what was added since the last check.

        The whole chain is read again at least every FULL_CHECK_SECONDS, or
        whenever the entry that ended the last check has changed, so an edit
        to an old entry is still reported, at most that much later.
        """
        now = time.monotonic()
        checked = self._checked
        if checked is not None and now - checked[2] < FULL_CHECK_SECONDS:
            row = conn.execute("SELECT hash FROM audit WHERE seq = ?", (checked[0],)).fetchone()
            if row is not None and row[0] == checked[1]:
                tail = _entries(conn, checked[0])
                ok, _ = continue_chain(tail, (checked[0], checked[1]))
                if ok:
                    if tail:
                        self._checked = (tail[-1]["seq"], tail[-1]["hash"], checked[2])
                    return True, None
        entries = _entries(conn)
        intact, broken_at = verify_entries(entries)
        self._checked = (entries[-1]["seq"], entries[-1]["hash"], now) if intact else None
        return intact, broken_at

    # --- the unit of work -------------------------------------------------------

    def _read(self, work: Callable[[sqlite3.Connection], T]) -> T:
        """Run `work` inside one read transaction, so it sees one moment."""
        conn = _connect(self.path)
        try:
            conn.execute("BEGIN")
            return work(conn)
        except sqlite3.OperationalError as exc:
            raise StoreError(f"The database at {self.path} could not be read ({exc}).") from None
        finally:
            _end(conn)

    def _write(self, work: Callable[[Guard], T]) -> T:
        """Run one guard method as one transaction. Commits, or changes nothing."""
        conn = _connect(self.path)
        try:
            try:
                conn.execute("BEGIN IMMEDIATE")
                log = DbAuditLog(conn, self._clock)
                guard = Guard.from_state(_state(conn), clock=self._clock, audit=log)
            except sqlite3.Error as exc:
                raise StoreError(
                    f"The database at {self.path} could not be opened for writing ({exc})."
                ) from None
            kept: ConfirmationFailed | None = None
            try:
                result = work(guard)
            except ConfirmationFailed as refused:
                # The approval is refused, but the guard logged why; keep that
                # entry (nothing else changed) and raise after the commit.
                kept, result = refused, None
            if log.failed is not None:
                # The guard answered, but an entry is missing. Keep nothing.
                raise StoreError(
                    "The audit log could not be written, so nothing was changed."
                ) from log.failed
            try:
                conn.execute("UPDATE state SET json = ? WHERE id = 1",
                             (canonical(guard.to_state()),))
                conn.execute("COMMIT")
            except sqlite3.Error as exc:
                raise StoreError(
                    f"The database at {self.path} could not be written ({exc}); "
                    "nothing was changed."
                ) from None
        finally:
            _end(conn)  # rolls back unless the commit went through
        self._anchor(log.added)
        if kept is not None:
            raise kept
        return result

    def _anchor(self, added: list[Entry], always: bool = False) -> None:
        """After a commit: write a receipt for the new head if it matters."""
        if self.receipts is None or not added:
            return
        matters = any(entry["event"] in RECEIPT_EVENTS for entry in added)
        if not (always or matters or self._receipt_owed):
            return
        newest = added[-1]
        try:
            append_receipt(self.receipts, Receipt.of(newest))
        except Exception as exc:  # the commit stands; remember that the receipt is missing
            self.receipt_failures.append((newest["seq"], f"{type(exc).__name__}: {exc}"))
            self._receipt_owed = True
            # stderr is the terminal for the CLI and the console, and the log for
            # the MCP server (whose stdout carries only the protocol).
            print(
                f"countersign: WARNING: no receipt could be written to {self.receipts} "
                f"for audit entry {newest['seq']} ({exc}). The change itself was saved; "
                "the next change will try again.",
                file=sys.stderr,
            )
        else:
            # A receipt for this head also covers every entry before it.
            self._receipt_owed = False


# --- for agent-facing modules ----------------------------------------------------
#
# The MCP server and the scripted agent import these two functions and nothing
# else from this module, so they never hold a `Store`.


def open_agent(
    path: str | os.PathLike,
    *,
    clock: Callable[[], datetime] | None = None,
    receipts: str | os.PathLike | None = None,
) -> AgentPort:
    """The agent's side of the database at `path`. Raises `StoreError` like `Store`."""
    return Store(path, clock=clock, receipts=receipts).agent()


def audit_head(path: str | os.PathLike) -> Head:
    """(seq, hash) of the newest audit entry in the database at `path`."""
    return Store(path).head()
