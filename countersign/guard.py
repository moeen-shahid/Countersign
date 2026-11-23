"""The guard sits between the agent and the bank.

The agent never talks to the bank. It asks the guard to pay, and the guard
decides with the policy engine. Starting a task, approving and rejecting are
separate methods for a person; they are not given to the agent as tools.

One lock is held for the whole of every public method, so two requests can
never both pass a check that only one of them should pass.

A payment is written to the audit log and counted against the task before the
bank is called. If the bank then says no, the count is taken back. If the bank
does not answer, the payment stays counted and is marked for a person to
reconcile, because it may have been sent.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Callable

from .audit import AuditLog, canonical
from .bank import BankDeclined, MockBank
from .iban import canonical_iban, find_ibans
from .models import (
    Decision,
    Mandate,
    Outcome,
    PaymentRequest,
    clean_label,
    is_plain_text,
    name_key,
    parse_amount,
    plain,
    ref_key,
)
from .policy import GUARD_MODES, Context, evaluate
from .provenance import UNNAMED, USER_SOURCE, Origin, ProvenanceTracker
from .vendors import VendorFile

STATE_VERSION = 1
HOLD_STATUSES = ("pending", "approved", "rejected", "blocked", "expired", "unknown")
# Untrusted text kept per task. Past this, a document is logged but its
# accounts are not recorded as seen, so a payment to them is refused (O1).
MAX_TASK_TEXT = 8 * 1024 * 1024
_KEEP = 500  # longest raw string kept in the log or as a document name
_FIELD = 200  # longest malformed field kept in a request (well-formed ones are shorter)

DECLINED = "The bank declined the transfer."
UNCONFIRMED = (
    "The bank did not confirm the transfer. It is recorded as possibly sent and needs a "
    "person to reconcile it."
)
FAILED = "The guard could not evaluate this request, so it was refused."
COUNTERSIGNED = "Within the mandate and countersigned by a person."


@dataclass
class Hold:
    """A payment waiting for a person, and what became of it."""

    id: str
    task_id: str  # the mandate it was requested under
    request: PaymentRequest
    decision: Decision  # what the person is shown
    digest: str  # identifies exactly what the person is asked to approve
    status: str = "pending"  # one of HOLD_STATUSES
    transfer_id: str | None = None  # set once an approved hold is paid
    decided_by: str | None = None
    attestation: str | None = None  # what the approver says they checked; recorded, not verified
    created_at: str = ""
    decided_at: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "task_id": self.task_id,
            "request": self.request.to_dict(),
            "decision": self.decision.to_dict(),
            "digest": self.digest,
            "status": self.status,
            "transfer_id": self.transfer_id,
            "decided_by": self.decided_by,
            "attestation": self.attestation,
            "created_at": self.created_at,
            "decided_at": self.decided_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Hold:
        return cls(
            id=data["id"],
            task_id=data["task_id"],
            request=PaymentRequest.from_dict(data["request"]),
            decision=Decision.from_dict(data["decision"]),
            digest=data["digest"],
            status=data["status"],
            transfer_id=data.get("transfer_id"),
            decided_by=data.get("decided_by"),
            attestation=data.get("attestation"),
            created_at=data.get("created_at", ""),
            decided_at=data.get("decided_at"),
        )


@dataclass(frozen=True)
class PayResult:
    decision: Decision
    transfer_id: str | None = None
    hold_id: str | None = None
    request: PaymentRequest | None = None  # the request as the guard read it


def hold_digest(
    hold_id: str, task_id: str, request: PaymentRequest, rules: tuple[str, ...], reason: str
) -> str:
    """sha256 over the payment, and the hold rules and reason a person is shown for it."""
    shown = {"hold": hold_id, "task": task_id, "request": request.to_dict(),
             "rules": list(rules), "reason": reason}
    return hashlib.sha256(canonical(shown).encode("ascii")).hexdigest()


def _sha256(text: str) -> str:
    # surrogatepass: text from a JSON tool result may hold half a surrogate pair.
    return hashlib.sha256(text.encode("utf-8", errors="surrogatepass")).hexdigest()


def _raw(value: object) -> Any:
    """One argument exactly as the agent passed it, in a form the log can hold."""
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value[:_KEEP]
    if isinstance(value, (int, float, Decimal)):
        try:
            return str(value)[:_KEEP]
        except ValueError:  # a number too long to print
            pass
    return f"<{type(value).__name__}>"


def _label(text: object) -> str:
    """A name a person wrote (approver, confirmer), kept short."""
    return str(text)[:_FIELD] if isinstance(text, str) else "human"


class Guard:
    def __init__(
        self,
        bank: MockBank,
        vendors: VendorFile,
        *,
        mode: str = "countersign",
        clock: Callable[[], datetime] | None = None,
        audit: AuditLog | None = None,
    ) -> None:
        if mode not in GUARD_MODES:
            raise ValueError(f"mode must be one of {GUARD_MODES}")
        self.bank = bank
        self.vendors = vendors
        self.mode = mode
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self.audit = audit if audit is not None else AuditLog(self._clock)
        self._lock = threading.RLock()
        self.mandate: Mandate | None = None
        self.provenance = ProvenanceTracker()
        self.holds: list[Hold] = []
        self._hold_counter = 0
        # Paid invoices, kept across tasks: (payee key, reference key) -> record.
        self.ledger: dict[tuple[str, str], dict[str, Any]] = {}
        # (event, error) for log entries that could not be written after the
        # bank had already answered. See _after_bank().
        self.log_failures: list[tuple[str, str]] = []
        self._reset_task()

    def _reset_task(self) -> None:
        self.spent = Decimal("0.00")
        self.payments = 0
        self.paid_to: dict[str, Decimal] = {}
        self.rejected: set[tuple[str, str]] = set()
        # The vendor file's payment history as it was when the task started.
        self.history: dict[str, tuple[Decimal, ...]] = {}
        self._baseline_cache: tuple[Any, dict[str, Decimal]] | None = None

    # --- called by the human side -------------------------------------------

    def start_task(self, mandate: Mandate, *, confirmed_by: str = "human") -> None:
        """Begin a task. The mandate is the only thing the agent is allowed to act on."""
        with self._lock:
            if not isinstance(mandate, Mandate):
                raise TypeError("start_task needs a Mandate")
            if self._clock() >= mandate.expires_at:
                raise ValueError("the mandate has already expired")
            instruction = mandate.instruction
            digest = _sha256(instruction)
            matches = tuple(find_ibans(instruction))
            typed = list(dict.fromkeys(m.account for m in matches))
            if self.mandate is not None:
                self._close_task(_label(confirmed_by), "a new task started")
            self.audit.append(
                "task_started",
                {
                    "task": mandate.id,
                    "mandate": mandate.to_dict(),
                    "confirmed_by": _label(confirmed_by),
                    "instruction_sha256": digest,
                    "accounts_typed": typed,
                },
            )
            self.mandate = mandate
            self._reset_task()
            self.history = {
                name_key(v.name): tuple(v.history) for v in self.vendors.all() if v.history
            }
            self.provenance = ProvenanceTracker()
            self.provenance.observe(Origin.USER, USER_SOURCE, instruction, matches)

    def end_task(self, *, by: str = "human") -> None:
        """End the task. Nothing can be paid until a new one starts."""
        with self._lock:
            if self.mandate is not None:
                self._close_task(_label(by), "the task was ended")

    def approve(
        self,
        hold_id: str,
        approver: str = "human",
        *,
        remember_account: bool = False,
        digest: str | None = None,
        attestation: str = "",
    ) -> PayResult:
        """Countersign one held payment. It covers exactly the payment shown.

        Every rule is checked again against the current state. `digest`, when
        given, must be the digest of the hold as it was displayed.
        `attestation` is the approver's own note of what they checked: it is
        logged for accountability and is not verified. `remember_account`
        also adds the account to the vendor file for this payee; without it
        the next payment to the same account is held again.
        """
        with self._lock:
            hold = self._pending(hold_id)
            task = self._task_id()
            if task is None or hold.task_id != task:
                raise ValueError(f"hold {hold.id} belongs to an earlier task")
            if digest is not None and digest != hold.digest:
                raise ValueError(f"hold {hold.id} changed since it was displayed")
            who, note = _label(approver), str(attestation)[:_KEEP]
            req = hold.request

            fresh = evaluate(req, self._context(leave_out=hold), self.provenance)
            if fresh.outcome is Outcome.BLOCK:
                # Nothing that blocks can clear later in the same task (the
                # amount paid only grows), so the hold is closed.
                self.audit.append(
                    "hold_blocked",
                    {"task": task, "hold": hold.id, "approver": who, "status": "blocked",
                     "decision": fresh.to_dict()},
                )
                self._decide(hold, "blocked", who)
                return PayResult(fresh, hold_id=hold.id, request=req)

            added = [rule for rule in fresh.rules if rule not in hold.decision.rules]
            changed = fresh.reason != hold.decision.reason
            if fresh.outcome is Outcome.HOLD and (added or changed):
                # The person was shown a reason that no longer holds (a new rule,
                # or new facts such as another payment of the same invoice).
                # Show the current one; pay nothing.
                new_digest = hold_digest(hold.id, hold.task_id, req, fresh.rules, fresh.reason)
                self.audit.append(
                    "hold_updated",
                    {"task": task, "hold": hold.id, "approver": who, "added": added,
                     "digest": new_digest, "decision": fresh.to_dict()},
                )
                hold.decision, hold.digest = fresh, new_digest
                return PayResult(fresh, hold_id=hold.id, request=req)

            self.audit.append(
                "hold_approved",
                {"task": task, "hold": hold.id, "approver": who, "digest": hold.digest,
                 "attestation": note, "remember_account": bool(remember_account)},
            )
            countersigned = replace(fresh, outcome=Outcome.ALLOW, rule="OK", reason=COUNTERSIGNED)
            result = self._execute(req, countersigned, hold)
            if result.transfer_id is None:
                if hold.status == "unknown":  # not confirmed by the bank
                    hold.decided_by, hold.attestation = who, note
                return result  # declined by the bank: the hold is still waiting
            hold.transfer_id = result.transfer_id
            hold.attestation = note
            self._decide(hold, "approved", who)
            if remember_account and req.account not in self.vendors.accounts_for(req.payee):
                self.audit.append(
                    "vendor_account_added",
                    {"task": task, "hold": hold.id, "approver": who, "payee": req.payee,
                     "account": req.account},
                )
                self.vendors.add_account(req.payee, req.account)
            return result

    def reject(self, hold_id: str, approver: str = "human") -> None:
        """Refuse a held payment. The same payee and account is then blocked for the task."""
        with self._lock:
            hold = self._pending(hold_id)
            who = _label(approver)
            self.audit.append(
                "hold_rejected", {"task": hold.task_id, "hold": hold.id, "approver": who}
            )
            self._decide(hold, "rejected", who)
            if hold.task_id == self._task_id():
                self.rejected.add((name_key(hold.request.payee), hold.request.account))

    def hold(self, hold_id: str) -> Hold:
        with self._lock:
            for hold in self.holds:
                if hold.id == hold_id:
                    return hold
            raise KeyError(hold_id)

    # --- called on behalf of the agent --------------------------------------

    def observe(self, source: str, text: str) -> None:
        """Record content the agent has read. All of it is untrusted.

        The order matters: hash, then the log entry, then origin tracking. If
        anything failed in between, the account would be logged but not
        "seen", which refuses a payment; never seen but not logged.
        """
        with self._lock:
            if not isinstance(source, str) or not isinstance(text, str):
                raise TypeError("observe needs a document name and its text")
            name = source[:_KEEP]
            digest = _sha256(text)
            entry = {"task": self._task_id(), "source": clean_label(name) or UNNAMED,
                     "name": name, "sha256": digest}
            if self.provenance.find(Origin.UNTRUSTED, name, text) is not None:
                # Read again: already logged in full and already tracked.
                self.audit.append("content_observed", {**entry, "repeat": True})
                return
            if self.provenance.untrusted_chars + len(text) > MAX_TASK_TEXT:
                # Too much text in one task. Logged, but its accounts count as
                # seen nowhere, so a payment to them is refused: fails closed.
                self.audit.append("content_observed", {**entry, "recorded": False})
                return
            matches = tuple(find_ibans(text))
            entry["accounts"] = list(dict.fromkeys(m.account for m in matches))
            self.audit.append("content_observed", entry)
            self.provenance.observe(Origin.UNTRUSTED, name, text, matches)

    def pay(
        self,
        payee: str,
        account: str,
        amount: object,
        reference: str = "",
        currency: str | None = None,
    ) -> PayResult:
        """The only way the agent can move money. Never raises: whatever the
        arguments are, the answer is a logged ALLOW, HOLD or BLOCK."""
        with self._lock:
            try:
                return self._pay(payee, account, amount, reference, currency)
            except Exception as exc:
                return self._refuse_after_error(exc, payee, account, amount, reference, currency)

    # --- persistence --------------------------------------------------------

    def to_state(self) -> dict[str, Any]:
        """Everything needed to rebuild this guard, as plain JSON data.

        The audit log is not part of it; pass the log to `from_state`.
        """
        with self._lock:
            return {
                "version": STATE_VERSION,
                "mode": self.mode,
                "bank": self.bank.to_state(),
                "vendors": self.vendors.to_state(),
                "mandate": None if self.mandate is None else self.mandate.to_dict(),
                "task": {
                    "spent": plain(self.spent),
                    "payments": self.payments,
                    "paid_to": {k: plain(v) for k, v in sorted(self.paid_to.items())},
                    "rejected": [list(pair) for pair in sorted(self.rejected)],
                    "history": {
                        k: [plain(a) for a in v] for k, v in sorted(self.history.items())
                    },
                },
                "observations": self.provenance.to_state(),
                "ledger": [
                    {"payee_key": key[0], "ref_key": key[1], **record}
                    for key, record in sorted(self.ledger.items())
                ],
                "holds": [hold.to_dict() for hold in self.holds],
                "hold_counter": self._hold_counter,
            }

    @classmethod
    def from_state(
        cls,
        state: dict[str, Any],
        *,
        clock: Callable[[], datetime] | None = None,
        audit: AuditLog | None = None,
    ) -> Guard:
        """Rebuild a guard from `to_state()`. It decides exactly as the original would."""
        if state.get("version") != STATE_VERSION:
            raise ValueError("this state was written by a different version of the guard")
        guard = cls(
            MockBank.from_state(state["bank"]),
            VendorFile.from_state(state["vendors"]),
            mode=state["mode"],
            clock=clock,
            audit=audit,
        )
        if state["mandate"] is not None:
            guard.mandate = Mandate.from_dict(state["mandate"])
        task = state["task"]
        guard.spent = Decimal(task["spent"])
        guard.payments = int(task["payments"])
        guard.paid_to = {k: Decimal(v) for k, v in task["paid_to"].items()}
        guard.rejected = {(key, account) for key, account in task["rejected"]}
        guard.history = {
            k: tuple(Decimal(a) for a in v) for k, v in task["history"].items()
        }
        guard.provenance = ProvenanceTracker.from_state(state["observations"])
        for item in state["ledger"]:
            record = {k: v for k, v in item.items() if k not in ("payee_key", "ref_key")}
            guard.ledger[(item["payee_key"], item["ref_key"])] = record
        guard.holds = [Hold.from_dict(item) for item in state["holds"]]
        guard._hold_counter = int(state["hold_counter"])
        return guard

    # --- internals ----------------------------------------------------------

    def _task_id(self) -> str | None:
        return self.mandate.id if self.mandate is not None else None

    def _now(self) -> str:
        return self._clock().isoformat()

    def _waiting(self) -> list[Hold]:
        """Holds of the current task that still wait for a person."""
        task = self._task_id()
        return [h for h in self.holds if h.status == "pending" and h.task_id == task]

    def _baseline(self) -> dict[str, Decimal]:
        """The largest earlier payment per payee. History is frozen for the task."""
        source = self.history
        if self._baseline_cache is None or self._baseline_cache[0] is not source:
            self._baseline_cache = (
                source, {key: max(amounts) for key, amounts in source.items() if amounts}
            )
        return self._baseline_cache[1]

    def _context(self, leave_out: Hold | None = None) -> Context:
        return Context(
            mode=self.mode,
            mandate=self.mandate,
            vendors=self.vendors,
            now=self._clock(),
            spent=self.spent,
            payments=self.payments,
            paid_to=dict(self.paid_to),
            baseline=self._baseline(),
            history=dict(self.history),
            ledger=self.ledger,
            rejected=frozenset(self.rejected),
            pending=sum(1 for hold in self._waiting() if hold is not leave_out),
        )

    def _pending(self, hold_id: str) -> Hold:
        hold = self.hold(hold_id)
        if hold.status != "pending":
            raise ValueError(f"hold {hold_id} is already {hold.status}")
        return hold

    def _decide(self, hold: Hold, status: str, by: str | None) -> None:
        hold.status = status
        hold.decided_by = by
        hold.decided_at = self._now()

    def _close_task(self, by: str, why: str) -> None:
        """Expire what is still waiting and end the current task."""
        task = self._task_id()
        for hold in self._waiting():
            self.audit.append("hold_expired", {"task": task, "hold": hold.id, "why": why})
            self._decide(hold, "expired", None)
        self.audit.append(
            "task_ended",
            {"task": task, "by": by, "why": why, "spent": plain(self.spent),
             "payments": self.payments},
        )
        self.mandate = None

    def _read(
        self, payee: object, account: object, amount: object, reference: object, currency: object
    ) -> PaymentRequest:
        """Turn the agent's arguments into one request, canonical where they are valid."""
        mandate = self.mandate
        name = payee[:_FIELD] if isinstance(payee, str) else ""
        if mandate is not None and is_plain_text(name):
            # From here on the payee is spelled the way the mandate spells it.
            name = mandate.canonical_payee(name) or name
        iban = canonical_iban(account)
        if iban is None:
            iban = account[:_FIELD] if isinstance(account, str) else ""
        if currency is None:
            unit = mandate.currency if mandate is not None else None
        elif isinstance(currency, str):
            unit = currency.strip().upper()[:8]
        else:
            unit = "?"
        ref = reference.strip()[:_FIELD] if isinstance(reference, str) else ""
        return PaymentRequest(name, iban, parse_amount(amount), ref, unit)

    def _same_waiting(self, req: PaymentRequest) -> Hold | None:
        """A hold of this task that already waits for exactly this payment."""
        if req.amount is None:
            return None
        key, ref = name_key(req.payee), ref_key(req.reference)
        for hold in self._waiting():
            other = hold.request
            if (
                other.account == req.account
                and other.amount == req.amount
                and name_key(other.payee) == key
                and ref_key(other.reference) == ref
            ):
                return hold
        return None

    def _pay(
        self, payee: object, account: object, amount: object, reference: object, currency: object
    ) -> PayResult:
        task = self._task_id()
        raw = {
            "payee": _raw(payee),
            "account": _raw(account),
            "amount": _raw(amount),
            "reference": _raw(reference),
            "currency": _raw(currency),
        }
        req = self._read(payee, account, amount, reference, currency)
        waiting = self._same_waiting(req)
        decision = evaluate(req, self._context(leave_out=waiting), self.provenance)
        entry = {"task": task, "raw": raw, "request": req.to_dict(), "hold": None,
                 "digest": None, "repeat": False}

        if decision.outcome is Outcome.HOLD and waiting is not None:
            # Asked again for a payment that already waits: same hold, no new one.
            entry.update(hold=waiting.id, digest=waiting.digest, repeat=True,
                         decision=waiting.decision.to_dict())
            self.audit.append("payment_decision", entry)
            return PayResult(waiting.decision, hold_id=waiting.id, request=waiting.request)

        if decision.outcome is Outcome.HOLD:
            hold_id = f"H{self._hold_counter + 1:03d}"
            hold = Hold(
                id=hold_id,
                task_id=task,
                request=req,
                decision=decision,
                digest=hold_digest(hold_id, task, req, decision.rules, decision.reason),
                created_at=self._now(),
            )
            entry.update(hold=hold.id, digest=hold.digest, decision=decision.to_dict())
            self.audit.append("payment_decision", entry)
            self._hold_counter += 1
            self.holds.append(hold)
            return PayResult(decision, hold_id=hold.id, request=req)

        entry["decision"] = decision.to_dict()
        self.audit.append("payment_decision", entry)
        if decision.outcome is Outcome.ALLOW:
            return self._execute(req, decision)
        return PayResult(decision, request=req)

    def _refuse_after_error(self, exc: Exception, *args: object) -> PayResult:
        """Something unexpected went wrong while deciding. Refuse, and say so in the log."""
        decision = Decision(Outcome.BLOCK, "ERR", FAILED, ("ERR",))
        try:
            raw = dict(zip(("payee", "account", "amount", "reference", "currency"),
                           (_raw(value) for value in args)))
        except Exception:
            raw = {}
        try:
            self.audit.append(
                "payment_decision",
                {"task": self._task_id(), "raw": raw, "request": None, "hold": None,
                 "digest": None, "repeat": False, "decision": decision.to_dict(),
                 "error": type(exc).__name__},
            )
        except Exception:
            pass  # the log itself is failing; refusing is still the safe answer
        return PayResult(decision)

    def _idempotency_key(self, req: PaymentRequest, hold: Hold | None) -> str:
        parts = [
            self._task_id(),
            name_key(req.payee),
            req.account,
            plain(req.amount),
            ref_key(req.reference),
            hold.id if hold is not None else "",
        ]
        return hashlib.sha256(canonical(parts).encode("ascii")).hexdigest()

    def _execute(
        self, req: PaymentRequest, decision: Decision, hold: Hold | None = None
    ) -> PayResult:
        """Send one payment that has been allowed or countersigned."""
        task = self._task_id()
        hold_id = hold.id if hold is not None else None
        payee_key = name_key(req.payee)
        invoice = (payee_key, ref_key(req.reference))
        key = self._idempotency_key(req, hold)
        data = {"task": task, "request": req.to_dict(), "hold": hold_id}

        # Write ahead: log it and count it before any money can move.
        self.audit.append("payment_submitted", {**data, "idempotency_key": key})
        before = (self.spent, self.payments, self.paid_to.get(payee_key), self.ledger.get(invoice))
        record = {"transfer": None, "amount": plain(req.amount), "time": self._now(),
                  "task": task, "hold": hold_id}
        self.spent += req.amount
        self.payments += 1
        self.paid_to[payee_key] = self.paid_to.get(payee_key, Decimal("0.00")) + req.amount
        self.ledger[invoice] = record

        try:
            transfer = self.bank.transfer(
                req.payee, req.account, req.amount, req.reference, idempotency_key=key
            )
        except BankDeclined as exc:
            # A definite no: nothing moved, so take the count back.
            self.spent, self.payments = before[0], before[1]
            if before[2] is None:
                del self.paid_to[payee_key]
            else:
                self.paid_to[payee_key] = before[2]
            if before[3] is None:
                del self.ledger[invoice]
            else:
                self.ledger[invoice] = before[3]
            declined = replace(decision, outcome=Outcome.BLOCK, rule="BANK", reason=DECLINED,
                               rules=("BANK",))
            # The bank's own words (they may name the balance) stay in the log.
            self._after_bank("payment_declined", {**data, "bank_message": str(exc)[:_KEEP]})
            return PayResult(declined, hold_id=hold_id, request=req)
        except Exception as exc:
            # No answer: the money may have moved. Keep it counted.
            if hold is not None:
                self._decide(hold, "unknown", hold.decided_by)
            unknown = replace(decision, outcome=Outcome.BLOCK, rule="BANK", reason=UNCONFIRMED,
                              rules=("BANK",))
            self._after_bank("payment_unknown", {**data, "error": type(exc).__name__})
            return PayResult(unknown, hold_id=hold_id, request=req)

        record["transfer"] = transfer.id
        self.vendors.record_payment(req.payee, req.amount)
        self._after_bank("payment_executed", {**data, "transfer": transfer.id})
        return PayResult(decision, transfer_id=transfer.id, hold_id=hold_id, request=req)

    def _after_bank(self, event: str, data: dict[str, Any]) -> None:
        """Log what the bank answered. The answer stands even if the log fails.

        By now the state already says what happened, and `payment_submitted`
        is in the log. Turning a sent payment into an error here would be a
        lie, so a failure is kept in `log_failures` instead; comparing the log
        with the bank (`audit.reconcile`) shows the missing entry.
        """
        try:
            self.audit.append(event, data)
        except Exception as exc:
            self.log_failures.append((event, f"{type(exc).__name__}: {exc}"[:_KEEP]))
