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
from .guard import Guard, Hold, PayResult
from .models import Mandate
from .policy import GUARD_MODES
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
        "hold_approved",
        "hold_rejected",
        "payment_executed",
        "payment_unknown",
        "vendor_account_added",
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


class Console:
    """The person's side: starting and ending tasks, deciding holds.

    Every method is one unit of work. What the guard raises (an unknown hold
    is KeyError; a hold already decided, from an earlier task or changed since
    it was displayed is ValueError) is raised here after the roll back.
    """

    __slots__ = ("_store",)

    def __init__(self, store: Store) -> None:
        self._store = store

    def start_task(self, mandate: Mandate, *, confirmed_by: str) -> None:
        self._store._write(lambda guard: guard.start_task(mandate, confirmed_by=confirmed_by))

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
    ) -> PayResult:
        """Countersign one hold. See `Guard.approve` for what the result can be."""
        return self._store._write(
            lambda guard: guard.approve(
                hold_id,
                approver,
                remember_account=remember_account,
                digest=digest,
                attestation=attestation,
            )
        )

    def reject(self, hold_id: str, *, approver: str) -> None:
        self._store._write(lambda guard: guard.reject(hold_id, approver))


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
            result = work(guard)
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
