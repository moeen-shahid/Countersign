"""A tamper-evident audit log.

Every entry stores the hash of the entry before it, so changing, removing or
reordering an old entry breaks the chain from that point on.

The exact claim, and its limit:

* Edits and deletions inside the chain are detected by the chain alone, as
  long as whoever made them did not also recompute every later hash.
* Cutting entries off the end, or rewriting the whole log so that it is
  self-consistent again, is not detectable from the log alone. It is detected
  only by comparing the log with a head (`head()`), or with receipts
  (`anchor.py`), kept somewhere the guard's host cannot rewrite.

The log is tamper-evident, not tamper-proof: it detects, it does not prevent.

Entry 0 is always `log_opened` and carries a random log id, so two logs never
share a head by accident. An entry has exactly the keys in `ENTRY_KEYS`.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import threading
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Any, Callable, Iterable, Sequence, TextIO

GENESIS = "0" * 64
LOG_VERSION = 1
ENTRY_KEYS = ("seq", "ts", "event", "data", "prev", "hash")
_HASHED_KEYS = ENTRY_KEYS[:-1]
_KEY_SET = frozenset(ENTRY_KEYS)

Entry = dict[str, Any]  # seq: int, ts: str, event: str, data: dict, prev: str, hash: str
Head = tuple[int, str]  # (seq, hash) of the newest entry


def canonical(value: Any) -> str:
    """The one JSON form that is hashed, stored and exported. Always ASCII.

    Raises TypeError or ValueError for anything that is not plain JSON data.
    """
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
        )
    except RecursionError:
        raise ValueError("audit data is nested too deeply") from None


def _require_text_keys(value: Any) -> None:
    """json.dumps would quietly turn 1 into "1"; two keys could then collide."""
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError(f"audit data keys must be text, not {type(key).__name__}")
            _require_text_keys(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _require_text_keys(item)


def entry_hash(entry: Entry) -> str:
    """sha256 over everything in the entry except the hash itself."""
    body = {key: entry[key] for key in _HASHED_KEYS}
    return hashlib.sha256(canonical(body).encode("ascii")).hexdigest()


def make_entry(seq: int, ts: str, event: str, data: dict[str, Any], prev: str) -> Entry:
    """Build one chained entry. Shared by every log backend so they all hash alike.

    Raises TypeError or ValueError if `data` is not JSON-safe. There is no
    fallback conversion: callers pass plain dicts of text, whole numbers,
    booleans, None, lists and dicts (money as text). The stored data is the
    JSON round trip of what was passed, so it is exactly what was hashed.
    """
    if not isinstance(event, str) or not event:
        raise TypeError("audit event must be a non-empty string")
    if not isinstance(data, dict):
        raise TypeError("audit data must be a dict")
    try:
        _require_text_keys(data)
    except RecursionError:
        raise ValueError("audit data is nested too deeply") from None
    entry: Entry = {
        "seq": seq,
        "ts": ts,
        "event": event,
        "data": json.loads(canonical(data)),
        "prev": prev,
    }
    entry["hash"] = entry_hash(entry)
    return entry


class AuditLog:
    """An in-memory hash-chained log. `entries` is a plain list of dicts."""

    def __init__(
        self,
        clock: Callable[[], datetime] | None = None,
        log_id: str | None = None,
        sink: Callable[[Entry], None] | None = None,
    ) -> None:
        """`log_id` defaults to 16 random hex characters; pass a fixed one for
        reproducible replays. `sink` is called with each new entry after it is
        appended, so the head can be sent somewhere else (see anchor.py).
        """
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._sink = sink
        self._lock = threading.RLock()
        self.entries: list[Entry] = []
        # (seq, error) for every entry the sink failed to take. See append().
        self.sink_failures: list[tuple[int, str]] = []
        self.append(
            "log_opened",
            {"log_id": secrets.token_hex(8) if log_id is None else log_id, "version": LOG_VERSION},
        )

    @property
    def log_id(self) -> str | None:
        try:
            return self.entries[0]["data"]["log_id"]
        except (IndexError, KeyError, TypeError):
            return None

    def append(self, event: str, data: dict[str, Any]) -> Entry:
        """Add one entry and return it. Raises on data that is not JSON-safe;
        in that case nothing is added.

        A sink that fails does not undo the entry and does not raise (the
        caller may be in the middle of a payment). The failure is kept in
        `sink_failures` so it can be shown and the receipt written again.
        """
        with self._lock:
            entry = make_entry(
                seq=len(self.entries),
                ts=self._clock().isoformat(),
                event=event,
                data=data,
                prev=self.entries[-1]["hash"] if self.entries else GENESIS,
            )
            self.entries.append(entry)
            if self._sink is not None:
                try:
                    self._sink(entry)
                except Exception as exc:  # the entry itself is safely recorded
                    self.sink_failures.append((entry["seq"], f"{type(exc).__name__}: {exc}"))
            return entry

    def head(self) -> Head:
        """(seq, hash) of the newest entry: the value to keep outside this host."""
        with self._lock:
            last = self.entries[-1]
            return last["seq"], last["hash"]

    def verify(
        self, *, expected_head: Head | None = None, expected_length: int | None = None
    ) -> tuple[bool, int | None]:
        """Return (True, None) if the chain is intact, else (False, first bad position)."""
        with self._lock:
            return verify_entries(
                self.entries, expected_head=expected_head, expected_length=expected_length
            )


def _check_entry(entry: Any, index: int, prev: str) -> bool:
    if not isinstance(entry, dict) or entry.keys() != _KEY_SET:
        return False
    seq, event, data = entry["seq"], entry["event"], entry["data"]
    if type(seq) is not int or seq != index:
        return False
    if not isinstance(entry["ts"], str) or not isinstance(event, str) or not isinstance(data, dict):
        return False
    if not isinstance(entry["prev"], str) or entry["prev"] != prev:
        return False
    if not isinstance(entry["hash"], str) or entry["hash"] != entry_hash(entry):
        return False
    if index == 0:
        # Entry 0 must open a log of a format this code knows how to check.
        return (
            event == "log_opened"
            and isinstance(data.get("log_id"), str)
            and type(data.get("version")) is int
            and data["version"] == LOG_VERSION
        )
    return True


def verify_entries(
    entries: Sequence[Any],
    *,
    expected_head: Head | None = None,
    expected_length: int | None = None,
) -> tuple[bool, int | None]:
    """Check a list of entries. Returns (True, None) or (False, first bad position).

    Never raises on malformed entries: a missing or extra key, a wrong type or
    data that cannot be serialised all count as broken at that position. An
    empty list is broken at 0, because entry 0 is always `log_opened`.

    `expected_head=(seq, hash)` is a head that was kept elsewhere. The check
    then also fails when the log is shorter than `seq + 1` (reported at the
    first missing position) or when the hash at `seq` differs (reported at
    `seq`; the change itself is at or before it). This is what catches
    truncation and a complete self-consistent rewrite. `expected_length`
    fails on any other length.
    """
    if expected_head is not None:
        head_seq, head_hash = expected_head
        if type(head_seq) is not int or head_seq < 0 or not isinstance(head_hash, str):
            raise ValueError("expected_head must be (seq, hash)")
    if expected_length is not None and (type(expected_length) is not int or expected_length < 0):
        raise ValueError("expected_length must be a whole number")

    if not entries:
        return False, 0
    prev = GENESIS
    for index, entry in enumerate(entries):
        try:
            ok = _check_entry(entry, index, prev)
        except Exception:  # unserialisable data, unhashable values and the like
            ok = False
        if not ok:
            return False, index
        prev = entry["hash"]

    if expected_head is not None:
        if head_seq >= len(entries):
            return False, len(entries)
        if entries[head_seq]["hash"] != head_hash:
            return False, head_seq
    if expected_length is not None and len(entries) != expected_length:
        return False, min(len(entries), expected_length)
    return True, None


def continue_chain(entries: Sequence[Any], head: Head) -> tuple[bool, int | None]:
    """Check entries that follow an already checked `head` (seq, hash).

    Returns (True, None) or (False, first bad position). Used to keep checking
    a growing log without re-reading the part that was checked before.
    """
    seq, prev = head
    for offset, entry in enumerate(entries):
        index = seq + 1 + offset
        try:
            ok = _check_entry(entry, index, prev)
        except Exception:
            ok = False
        if not ok:
            return False, index
        prev = entry["hash"]
    return True, None


def export_jsonl(entries: Iterable[Entry], fp: TextIO) -> int:
    """Write one canonical JSON object per line (ASCII only). Returns the count."""
    count = 0
    for entry in entries:
        fp.write(canonical(entry) + "\n")
        count += 1
    return count


def load_jsonl(fp: Iterable[str]) -> list[Any]:
    """Read what `export_jsonl` wrote. Blank lines are skipped.

    Never raises on content: a line that is not JSON is kept as the raw text,
    so `verify_entries` reports the log as broken at exactly that position.
    """
    entries: list[Any] = []
    for line in fp:
        text = line.strip()
        if not text:
            continue
        try:
            entries.append(json.loads(text))
        except (ValueError, RecursionError):
            entries.append(text)
    return entries


# --- reconciling the log with the bank ------------------------------------------

_PAYMENT_FIELDS = ("payee", "account", "amount", "reference")


def _field(record: Any, name: str) -> Any:
    return record.get(name) if isinstance(record, dict) else getattr(record, name, None)


def _same(name: str, logged: Any, banked: Any) -> bool:
    if name == "amount":
        try:
            return Decimal(str(logged)) == Decimal(str(banked))
        except InvalidOperation:
            return False
    return logged == banked


def _logged_payment(data: dict[str, Any]) -> tuple[Any, dict[str, Any]]:
    """The transfer id and payment fields of one `payment_executed` entry.

    The entry names the bank transfer as `"transfer": "T001"` and carries the
    payment as it was sent to the bank under `"request"`. A `"transfer"` that
    is itself a dict with an `"id"`, or fields placed directly in the data,
    are read the same way.
    """
    transfer = data.get("transfer")
    if isinstance(transfer, dict):
        return transfer.get("id"), transfer
    transfer_id = transfer if transfer is not None else data.get("transfer_id")
    request = data.get("request")
    return transfer_id, request if isinstance(request, dict) else data


def reconcile(entries: Sequence[Any], transfers: Iterable[Any]) -> list[str]:
    """Compare the log with the bank's list of transfers.

    Every bank transfer must have exactly one `payment_executed` entry with the
    same id, payee, account, amount and reference, and every such entry must
    have its transfer. Returns one plain sentence per mismatch; an empty list
    means the two agree. A transfer may be an object (`bank.Transfer`) or a
    dict with the same fields.

    This needs no hashes, so it also catches a log that was cut short after
    money moved, as long as the bank's own record is intact.
    """
    problems: list[str] = []
    logged: dict[str, list[tuple[int, dict[str, Any]]]] = {}
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict) or entry.get("event") != "payment_executed":
            continue
        data = entry.get("data")
        transfer_id, fields = _logged_payment(data) if isinstance(data, dict) else (None, {})
        if not isinstance(transfer_id, str) or not transfer_id:
            problems.append(f"Log entry {index} records a payment without a transfer id.")
            continue
        logged.setdefault(transfer_id, []).append((index, fields))

    seen: set[str] = set()
    for transfer in transfers:
        transfer_id = _field(transfer, "id")
        if not isinstance(transfer_id, str) or not transfer_id:
            problems.append("The bank lists a transfer without an id.")
            continue
        if transfer_id in seen:
            problems.append(f"The bank lists transfer {transfer_id} more than once.")
            continue
        seen.add(transfer_id)
        matches = logged.get(transfer_id, [])
        if not matches:
            problems.append(
                f"Transfer {transfer_id} ({_field(transfer, 'amount')} to "
                f"{_field(transfer, 'payee')}) is in the bank but not in the log."
            )
            continue
        if len(matches) > 1:
            where = ", ".join(str(index) for index, _ in matches)
            problems.append(
                f"Transfer {transfer_id} is in the log {len(matches)} times "
                f"(entries {where}); it should be there once."
            )
        for index, fields in matches:
            for name in _PAYMENT_FIELDS:
                in_log, in_bank = fields.get(name), _field(transfer, name)
                if not _same(name, in_log, in_bank):
                    problems.append(
                        f"Transfer {transfer_id}: log entry {index} says {name} {in_log!s}, "
                        f"the bank says {in_bank!s}."
                    )

    for transfer_id, matches in logged.items():
        if transfer_id not in seen:
            for index, _ in matches:
                problems.append(
                    f"Log entry {index} records transfer {transfer_id}, "
                    "which the bank does not have."
                )
    return problems
