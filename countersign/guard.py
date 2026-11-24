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
    invoice_core,
    invoice_key,
    is_plain_text,
    may_be_same_invoice,
    name_key,
    parse_amount,
    plain,
    ref_key,
)
from .policy import (
    DESTINATION_RULES,
    GUARD_MODES,
    PROBATION_GAP,
    Context,
    Waiting,
    counts_as_usual,
    evaluate,
    identical_payments,
    payment_key,
)
from .provenance import UNNAMED, USER_SOURCE, Origin, ProvenanceTracker, seen_ibans
from .vendors import VendorFile

STATE_VERSION = 1
HOLD_STATUSES = ("pending", "approved", "rejected", "blocked", "expired", "unknown")
# Untrusted text kept per task. Past this, a document is logged but its
# accounts are not recorded as seen, so a payment to them is refused (O1).
MAX_TASK_TEXT = 8 * 1024 * 1024
_KEEP = 500  # longest raw string kept in the log or as a document name
_FIELD = 200  # longest malformed field kept in a request (well-formed ones are shorter)
# References of the agent's requests kept per task for D4. Past this, D4 counts
# every number you named as claimed by two invoices: fails closed.
MAX_REQUESTED = 2000
# What a person can say was wrong when they reject a hold (`Guard.reject`).
REJECT_REASONS = ("account", "payment")

DECLINED = "The bank declined the transfer."
UNCONFIRMED = (
    "The bank did not confirm the transfer. It is recorded as possibly sent and needs a "
    "person to reconcile it."
)
FAILED = "The guard could not evaluate this request, so it was refused."
COUNTERSIGNED = "Within the mandate and countersigned by a person."
# H2 and D3 are about other waiting payments. Which of those exist depends on
# what the agent read (a document can make a payment wait), so a change in
# them never re-shows a hold at approval: the person decides this payment, and
# `Guard.related` shows the current rivals and waiting payments next to it.
# T1 and D4 read the documents themselves, so the same holds for them: a
# document read after the hold was shown does not put the approval off, and
# `Guard.related` lists them among the rules that hold the payment now.
NOT_RESHOWN = frozenset({"H2", "D3", "T1", "D4"})


class ApprovalRefused(ValueError):
    """An approval was refused before anything was paid. The message is one
    plain sentence for the person."""


class ConfirmationFailed(ApprovalRefused):
    """The account a person typed back is not the account of the hold. Nothing
    was paid, and the attempt is in the audit log (`hold_confirmation_failed`)."""


def confirmation_problem(hold: Hold, confirmed_account: object) -> str | None:
    """Why the account a person typed back does not confirm this hold, or None.

    The typed text is read as one IBAN (spaces, case and an "IBAN" label do
    not matter) and compared with the hold's account as a whole: no part of
    it is enough, since a look-alike can share the first twelve and the last
    four characters with the real one.
    """
    if not isinstance(confirmed_account, str):
        return "The confirmed account must be text. Nothing was paid."
    typed = confirmed_account.strip()
    if not typed:
        return "No account was typed. Nothing was paid."
    account = canonical_iban(typed)
    if account is None:
        return "The account you typed is not a valid IBAN. Nothing was paid."
    if account != hold.request.account:
        return (
            "The account you typed is not the account this payment would go to, so "
            "nothing was paid. If you typed what the vendor confirmed, this payment is "
            "not going to their account: reject it."
        )
    return None


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


def _shown_facts(decision: Decision) -> tuple[Any, ...]:
    """What a countersignature is about, besides the payment and its rules: the
    accounts on file, whose account it is, whether the user gave it, when an
    approval added it, and the earlier payment of the same invoice that makes
    it a possible duplicate (D1). Running totals, the list of documents and
    an earlier payment that D1 does not count against it (an instalment you
    typed) are left out on purpose: the agent can move those at will."""
    evidence = decision.evidence
    if evidence is None:
        return ()
    previous = evidence.previous_payment if "D1" in decision.rules else None
    return (evidence.on_file, evidence.on_file_for, evidence.dictated, evidence.added, previous)


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
        self.paid_count: dict[str, int] = {}  # payments per payee key, this task
        # (payee key, invoice core) -> (payments, their sum) in this task: one
        # invoice, perhaps in parts. The core is `models.ref_core` of the reference.
        self.paid_refs: dict[tuple[str, str], tuple[int, Decimal]] = {}
        self.rejected: set[tuple[str, str]] = set()
        # (payee key, account) refused for the rest of the task: a person rejected
        # a payment whose question was the account (P1, P2, P3).
        self.refused_accounts: set[tuple[str, str]] = set()
        # policy.payment_key -> how often exactly that payment was made in this task (D2).
        self.paid_exact: dict[tuple[str, str, str, str], int] = {}
        # H1 refused a request in this task: nothing more is paid without a person
        # until a new task starts (see policy._queue).
        self.quarantined = False
        # (payee key, invoice_key) of every request the agent made in this task (D4).
        self.requested: set[tuple[str, str]] = set()
        self.requested_all = False  # more than MAX_REQUESTED: D4 assumes the worst
        # The vendor file's payment history as it was when the task started.
        self.history: dict[str, tuple[Decimal, ...]] = {}
        self._baseline_cache: tuple[Any, dict[str, Decimal]] | None = None

    # --- called by the human side -------------------------------------------

    def start_task(
        self, mandate: Mandate, *, confirmed_by: str = "human", draft_digest: str | None = None
    ) -> None:
        """Begin a task. The mandate is the only thing the agent is allowed to act on.

        `draft_digest` is `Draft.digest()` of the reading of the sentence the
        person confirmed, when there was one. The log records it, and per
        payee which fields of the mandate a person set instead of the sentence
        (`Ask.set_by`), so it shows what came from where.
        """
        with self._lock:
            if not isinstance(mandate, Mandate):
                raise TypeError("start_task needs a Mandate")
            if draft_digest is not None and not (
                isinstance(draft_digest, str) and 0 < len(draft_digest) <= 128
                and draft_digest.isascii() and draft_digest.isalnum()
            ):
                raise ValueError("draft_digest must be the draft's digest (letters and digits)")
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
                    "draft_digest": draft_digest,
                    "set_by_person": {payee: list(ask.set_by)
                                      for payee, ask in mandate.asks.items() if ask.set_by},
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
        usual_amount: bool = False,
        confirmed_account: str | None = None,
    ) -> PayResult:
        """Countersign one held payment. It covers exactly the payment shown.

        Every rule is checked again against the current state. `digest`, when
        given, must be the digest of the hold as it was displayed.
        `attestation` is the approver's own note of what they checked: it is
        logged for accountability and is not verified. `remember_account`
        also adds the account to the vendor file for this payee; without it
        the next payment to the same account is held again. A remembered
        account is held (rule P3) until a later payment to it is approved
        at least `policy.PROBATION_GAP` after it was added.
        `usual_amount` says this amount is now a usual amount for the payee;
        without it an amount above the usual range does not move the line
        that rule A1 draws.
        `confirmed_account` is the account the person typed back, as the
        vendor confirmed it through a channel they already trusted. When it
        is given it must be the hold's account (`confirmation_problem`);
        otherwise nothing is paid, `hold_confirmation_failed` is logged and
        `ConfirmationFailed` is raised. The person's side (`store.approve_hold`)
        requires it for a hold about the account (P1, P2, P3).

        At approval, a change in H2 or D3 alone does not show the hold again:
        see `NOT_RESHOWN` and `related`.
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
            if confirmed_account is not None:
                problem = self._confirm(hold, confirmed_account, who)
                if problem is not None:
                    raise ConfirmationFailed(problem)

            fresh = evaluate(req, self._context(leave_out=hold, approving=True),
                             self.provenance)
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

            added = [rule for rule in fresh.rules
                     if rule not in hold.decision.rules and rule not in NOT_RESHOWN]
            changed = _shown_facts(fresh) != _shown_facts(hold.decision)
            if fresh.outcome is Outcome.HOLD and (added or changed):
                # The person was shown a reason that no longer holds (a new rule,
                # or new facts such as another payment of the same invoice).
                # Show the current one; pay nothing. A running total that moved
                # or one more document that names the account is not such a
                # fact: the agent can cause either at will, and an approval
                # that waited for them to stand still could be put off for ever.
                new_digest = hold_digest(hold.id, hold.task_id, req, fresh.rules, fresh.reason)
                self.audit.append(
                    "hold_updated",
                    {"task": task, "hold": hold.id, "approver": who, "added": added,
                     "digest": new_digest, "decision": fresh.to_dict()},
                )
                hold.decision, hold.digest = fresh, new_digest
                return PayResult(fresh, hold_id=hold.id, request=req)

            approved = {"task": task, "hold": hold.id, "approver": who, "digest": hold.digest,
                        "attestation": note, "remember_account": bool(remember_account),
                        "usual_amount": bool(usual_amount)}
            if fresh.reason != hold.decision.reason:
                # Same rules and same facts, but a total or a list of documents
                # moved while the hold waited. The log keeps the current wording.
                approved["reason_at_approval"] = fresh.reason
            self.audit.append("hold_approved", approved)
            countersigned = replace(fresh, outcome=Outcome.ALLOW, rule="OK", reason=COUNTERSIGNED)
            result = self._execute(req, countersigned, hold, usual=bool(usual_amount))
            if result.transfer_id is None:
                if hold.status == "unknown":  # not confirmed by the bank
                    hold.decided_by, hold.attestation = who, note
                return result  # declined by the bank: the hold is still waiting
            hold.transfer_id = result.transfer_id
            hold.attestation = note
            self._decide(hold, "approved", who)
            added = self.vendors.added_at(req.payee, req.account)
            if ("P3" in fresh.rules and added is not None
                    and self._clock() - added >= PROBATION_GAP
                    and self.vendors.end_probation(req.payee, req.account)):
                # A person looked at the added account again, later, and paid it.
                self.audit.append(
                    "vendor_account_confirmed",
                    {"task": task, "hold": hold.id, "approver": who, "payee": req.payee,
                     "account": req.account},
                )
            if remember_account and req.account not in self.vendors.accounts_for(req.payee):
                self.audit.append(
                    "vendor_account_added",
                    {"task": task, "hold": hold.id, "approver": who, "payee": req.payee,
                     "account": req.account},
                )
                self.vendors.add_account(req.payee, req.account, when=self._now())
            return result

    def check_confirmation(
        self, hold_id: str, confirmed_account: object, approver: str = "human"
    ) -> str | None:
        """Compare the account a person typed back with a waiting hold, before
        they are asked to approve it. Returns None when it matches; otherwise
        the reason, after logging `hold_confirmation_failed`. Pays nothing."""
        with self._lock:
            hold = self._pending(hold_id)
            return self._confirm(hold, confirmed_account, _label(approver))

    def _confirm(self, hold: Hold, confirmed_account: object, who: str) -> str | None:
        problem = confirmation_problem(hold, confirmed_account)
        if problem is not None:
            typed = canonical_iban(confirmed_account) if isinstance(confirmed_account, str) \
                else None
            # Logged although nothing changes: a wrong account typed back is worth
            # knowing about (it may be the look-alike of a real one).
            self.audit.append(
                "hold_confirmation_failed",
                {"task": hold.task_id, "hold": hold.id, "approver": who,
                 "typed_account": typed, "reason": problem},
            )
        return problem

    def reject(self, hold_id: str, approver: str = "human", *, wrong: str | None = None) -> None:
        """Refuse a held payment.

        `wrong` is what the person says was wrong: "account" or "payment".
        For a hold whose question was the account (P1, P2, P3) the default is
        "account": that payee and account are refused for the rest of the
        task (rule R1), and an account an approval added to the vendor file
        that is still on probation (P3) is taken off the file again. With
        "payment" (the account is the payee's, but the amount or the invoice
        is wrong) only this same payment is refused. When trusted state
        vouches for the account, only this same payment is refused whatever
        `wrong` says."""
        if wrong is not None and wrong not in REJECT_REASONS:
            raise ValueError(f"wrong must be one of {REJECT_REASONS}")
        with self._lock:
            hold = self._pending(hold_id)
            who = _label(approver)
            req = hold.request
            about_account = bool(set(hold.decision.rules) & set(DESTINATION_RULES))
            said = wrong or ("account" if about_account else "payment")
            account_refused = about_account and said == "account"
            self.audit.append(
                "hold_rejected", {"task": hold.task_id, "hold": hold.id, "approver": who,
                                  "wrong": said, "account_refused": account_refused}
            )
            self._decide(hold, "rejected", who)
            if hold.task_id == self._task_id():
                pair = (name_key(req.payee), req.account)
                if account_refused or not about_account:
                    self.rejected.add(pair)
                if account_refused:
                    self.refused_accounts.add(pair)
            vendor = self.vendors.get(req.payee)
            if account_refused and vendor is not None and req.account in vendor.added:
                self.audit.append(
                    "vendor_account_removed",
                    {"task": hold.task_id, "hold": hold.id, "approver": who, "payee": req.payee,
                     "account": req.account,
                     "why": "A person rejected a payment to this account while it was still on "
                            "probation after an approval added it."},
                )
                vendor.accounts.discard(req.account)
                del vendor.added[req.account]

    def related(self, hold_id: str) -> dict[str, Any]:
        """What a person deciding this hold should see next to it, now.

        Computed from trusted state when asked, not taken from what the hold
        showed when it was made, because waiting payments come and go while it
        waits. `rivals`: the waiting payments (hold ids) of the same invoice to
        another account (D3): at most one of them can be right, so decide them
        together. `waiting`: the waiting payments (hold ids) that, if paid,
        would make this one break a limit (H2), and `projected_rules` which
        limits (some of M4, M5, S1, S2, A1, D1). `rules`: every rule that
        holds this payment now. `refused`: the rule that would refuse it now
        (for example M4, when other payments have used the budget since), so
        approving it would pay nothing; empty when it would not be refused.
        All empty when the hold no longer waits.
        """
        with self._lock:
            hold = self.hold(hold_id)
            found: dict[str, Any] = {"hold": hold.id, "status": hold.status, "rules": [],
                                     "rivals": [], "waiting": [], "projected_rules": [],
                                     "refused": []}
            if hold.status != "pending" or hold.task_id != self._task_id():
                return found
            now = evaluate(hold.request, self._context(leave_out=hold, approving=True),
                           self.provenance)
            evidence = now.evidence
            if now.outcome is Outcome.BLOCK:
                found["refused"] = [now.rule]
                return found
            found["rules"] = list(now.rules)
            if evidence is not None:
                found["rivals"] = list(evidence.rivals)
                if "H2" in now.rules:
                    found["waiting"] = list(evidence.waiting_holds)
                    found["projected_rules"] = list(evidence.projected_rules)
            return found

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
                # seen nowhere, so a payment to them is refused, and what it may
                # hide is unknown, so every payment waits (T1): fails closed.
                self.audit.append("content_observed", {**entry, "recorded": False})
                self.provenance.unread += 1
                return
            matches = tuple(seen_ibans(Origin.UNTRUSTED, text))
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
                    "paid_count": dict(sorted(self.paid_count.items())),
                    "paid_refs": [
                        [key[0], key[1], count, plain(total)]
                        for key, (count, total) in sorted(self.paid_refs.items())
                    ],
                    "rejected": [list(pair) for pair in sorted(self.rejected)],
                    "refused_accounts": [list(pair) for pair in sorted(self.refused_accounts)],
                    "paid_exact": [
                        [*key, count] for key, count in sorted(self.paid_exact.items())
                    ],
                    "quarantined": self.quarantined,
                    "requested": [list(item) for item in sorted(self.requested)],
                    "unread_documents": self.provenance.unread,
                    "requested_all": self.requested_all,
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
        # A state written before these counters existed (v0.2) fails closed:
        # every payee is taken to have had as many payments as the whole task
        # (so S2 asks), and what each payee was paid counts as one invoice of
        # unknown number (so A1 sees all of it above the usual amount at once).
        counts = task.get("paid_count")
        if counts is None:
            counts = {k: guard.payments for k in guard.paid_to}
        guard.paid_count = {k: int(v) for k, v in counts.items()}
        refs = task.get("paid_refs")
        if refs is None:
            refs = [[k, "", guard.paid_count.get(k, 1), plain(v)]
                    for k, v in guard.paid_to.items()]
        guard.paid_refs = {
            (payee, core): (int(count), Decimal(total)) for payee, core, count, total in refs
        }
        guard.rejected = {(key, account) for key, account in task["rejected"]}
        # Written before v0.3: these three are rebuilt so that the guard is no
        # less strict than it was. Accounts of rejected holds about an account
        # stay refused; payments of this task are found in the bank's record;
        # an old state has no quarantine to keep.
        refused = task.get("refused_accounts")
        if refused is None:
            refused = [[name_key(h["request"]["payee"]), h["request"]["account"]]
                       for h in state["holds"]
                       if h.get("status") == "rejected" and guard.mandate is not None
                       and h.get("task_id") == guard.mandate.id
                       and set((h.get("decision") or {}).get("rules") or ())
                       & set(DESTINATION_RULES)]
        guard.refused_accounts = {(key, account) for key, account in refused}
        guard.paid_exact = {
            (payee, account, amount, ref): int(count)
            for payee, account, amount, ref, count in task.get("paid_exact") or ()
        }
        guard.quarantined = bool(task.get("quarantined", False))
        guard.requested = {(key, ref) for key, ref in task.get("requested") or ()}
        guard.requested_all = bool(task.get("requested_all", False))
        guard.history = {
            k: tuple(Decimal(a) for a in v) for k, v in task["history"].items()
        }
        guard.provenance = ProvenanceTracker.from_state(state["observations"])
        guard.provenance.unread = int(task.get("unread_documents") or 0)
        for item in state["ledger"]:
            record = {k: v for k, v in item.items() if k not in ("payee_key", "ref_key")}
            guard.ledger[(item["payee_key"], item["ref_key"])] = record
        guard.holds = [Hold.from_dict(item) for item in state["holds"]]
        guard._hold_counter = int(state["hold_counter"])
        if task.get("paid_exact") is None and guard.mandate is not None:
            # Before v0.3: every invoice this task paid, as the ledger and the
            # bank record it, counts as made once (D2 then refuses it again).
            sent = {t.id: t for t in guard.bank.transfers}
            for (payee, ref), record in guard.ledger.items():
                transfer = sent.get(record.get("transfer"))
                if record.get("task") == guard.mandate.id and transfer is not None:
                    key = payment_key(payee, transfer.account, transfer.amount, ref)
                    guard.paid_exact[key] = max(guard.paid_exact.get(key, 0), 1)
        if task.get("requested") is None and guard.mandate is not None:
            # Written before the guard kept the agent's requests (D4): what this
            # task paid and held are requests it made, so they count.
            task_id = guard.mandate.id
            guard.requested |= {(payee, ref) for (payee, ref), record in guard.ledger.items()
                                if record.get("task") == task_id}
            guard.requested |= {(name_key(h.request.payee), invoice_key(h.request.reference))
                                for h in guard.holds if h.task_id == task_id
                                and isinstance(h.request.reference, str)}
        # Exact payments recorded before references were compared with
        # look-alikes folded are filed under the folded form too.
        for (payee, account, amount, ref), count in list(guard.paid_exact.items()):
            folded = (payee, account, amount, invoice_key(ref))
            if folded != (payee, account, amount, ref):
                guard.paid_exact[folded] = max(guard.paid_exact.get(folded, 0), count)
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

    def _context(self, leave_out: Hold | None = None, *, approving: bool = False) -> Context:
        """Trusted state for one decision.

        `leave_out` is the hold a person is deciding (`approving`): it is not
        counted against itself. An agent's request is judged with every
        waiting payment counted, also one identical to it: asked again, it
        would be one more payment if both were paid (D1, S2, H2), so a repeat
        never goes through while the first one waits. Without `approving`,
        `leave_out` therefore leaves nothing out.
        """
        if not approving:
            leave_out = None
        return Context(
            mode=self.mode,
            mandate=self.mandate,
            vendors=self.vendors,
            now=self._clock(),
            spent=self.spent,
            payments=self.payments,
            paid_to=dict(self.paid_to),
            paid_count=dict(self.paid_count),
            paid_refs=dict(self.paid_refs),
            baseline=self._baseline(),
            history=dict(self.history),
            ledger=self.ledger,
            rejected=frozenset(self.rejected),
            rejected_payments=frozenset(
                (name_key(h.request.payee), h.request.account, plain(h.request.amount),
                 invoice_key(h.request.reference))
                for h in self.holds
                if h.status == "rejected" and h.task_id == self._task_id()
                and h.request.amount is not None
            ),
            pending=sum(1 for hold in self._waiting() if hold is not leave_out),
            waiting=tuple(
                Waiting(name_key(h.request.payee), h.request.account, h.request.amount,
                        h.request.reference,
                        destination=bool(set(h.decision.rules) & set(DESTINATION_RULES)),
                        hold_id=h.id)
                for h in self._waiting()
                if h is not leave_out and h.request.amount is not None
            ),
            approving=approving,
            quarantined=self.quarantined,
            paid_exact=dict(self.paid_exact),
            refused_accounts=frozenset(self.refused_accounts),
            requested=frozenset(self.requested),
            requested_all=self.requested_all,
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
        """A hold of this task that already waits for exactly this payment
        (the newest one, when one invoice may be paid in parts)."""
        found = self._identical_waiting(req)
        return found[-1] if found else None

    def _identical_waiting(self, req: PaymentRequest) -> list[Hold]:
        if req.amount is None:
            return []
        key = payment_key(name_key(req.payee), req.account, req.amount, req.reference)
        return [hold for hold in self._waiting()
                if hold.request.amount is not None
                and payment_key(name_key(hold.request.payee), hold.request.account,
                                hold.request.amount, hold.request.reference) == key]

    def _joins(self, req: PaymentRequest) -> Hold | None:
        """The waiting hold an identical request joins, or None when it is a payment
        of its own.

        Usually an identical request is the agent asking again, and it joins the
        payment that waits. Only when one invoice is paid in parts
        (`policy.identical_payments`) can it be the next part: then it is a
        payment of its own until there are as many of them, made or waiting, as
        parts. Counting each one this way keeps a guard that holds a payment
        and one that paid it alike: neither can drop an ask the other counts."""
        found = self._identical_waiting(req)
        if not found:
            return None
        allowed = 1
        if self.mandate is not None and self.mandate.covers(req.payee):
            allowed = identical_payments(self.mandate, req.payee)
        made = self.paid_exact.get(
            payment_key(name_key(req.payee), req.account, req.amount, req.reference), 0)
        return found[-1] if made + len(found) >= allowed else None

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
        decision = evaluate(req, self._context(), self.provenance)
        self._remember_request(req)
        entry = {"task": task, "raw": raw, "request": req.to_dict(), "hold": None,
                 "digest": None, "repeat": False}

        waiting = self._joins(req) if decision.outcome is not Outcome.BLOCK else None
        if waiting is not None:
            # Asked again for a payment that already waits: same hold, no new one,
            # and nothing is paid while it waits (the waiting one counts against
            # this request, so it could not pass on its own anyway).
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
        if decision.rule == "H1" and not self.quarantined:
            self._quarantine(decision)
        if decision.outcome is Outcome.ALLOW:
            return self._execute(req, decision)
        return PayResult(decision, request=req)

    def _remember_request(self, req: PaymentRequest) -> None:
        """Keep the reference of one request of this task, for D4 (two invoices
        with the number you named). Past MAX_REQUESTED, D4 assumes the worst."""
        if self.mandate is None or not is_plain_text(req.reference) or not ref_key(req.reference):
            return
        payee = self.mandate.canonical_payee(req.payee)
        if payee is None:
            return
        item = (name_key(payee), invoice_key(req.reference))
        if item in self.requested:
            return
        if len(self.requested) >= MAX_REQUESTED:
            self.requested_all = True
            return
        self.requested.add(item)

    def _quarantine(self, decision: Decision) -> None:
        """H1 refused a request: from now on nothing more is paid without a person
        in this task (see `policy._queue`). Logged once, so a screen can say so."""
        waiting = self._waiting()
        self.audit.append(
            "task_quarantined",
            {"task": self._task_id(), "waiting": len(waiting),
             "about_account": sum(1 for h in waiting
                                  if set(h.decision.rules) & set(DESTINATION_RULES)),
             "reason": decision.reason,
             "what_it_means": "The queue of payments waiting for a person overflowed. Until a "
                              "new task starts, nothing more is paid without a person."},
        )
        self.quarantined = True

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
        payee_key, reference = name_key(req.payee), ref_key(req.reference)
        parts = [
            self._task_id(),
            payee_key,
            req.account,
            plain(req.amount),
            reference,
            hold.id if hold is not None else "",
        ]
        if self.mode == "countersign":
            # Which payment of this invoice it is in this task. An invoice can
            # be paid in parts, and the second part is a payment of its own,
            # not a retry of the first. Our baselines keep the plain key.
            parts.append(sum(count for (key, core), (count, _) in self.paid_refs.items()
                             if key == payee_key and may_be_same_invoice(core, req.reference)))
        folded = invoice_key(req.reference)
        if folded != reference:
            # `ref_key` drops digits of other scripts, so INV-١٠٠٧ and INV-١٠٠٤
            # both read INV, and the bank would hand back the first transfer for
            # the second invoice. With the folded form too, two invoices never
            # share a key. Left out when it adds nothing, so other keys stay as
            # they were.
            parts.append(folded)
        return hashlib.sha256(canonical(parts).encode("ascii")).hexdigest()

    def _execute(
        self, req: PaymentRequest, decision: Decision, hold: Hold | None = None,
        *, usual: bool = False,
    ) -> PayResult:
        """Send one payment that has been allowed or countersigned.

        `usual` is the approver's mark that this amount is a usual amount for
        the payee. Without it the payment joins the payee's usual amounts only
        when it lies inside their range, so neither the agent's own payments
        nor one approved exception move the line that rule A1 draws.
        """
        task = self._task_id()
        hold_id = hold.id if hold is not None else None
        payee_key = name_key(req.payee)
        # Recorded with look-alikes folded, so a copy of this invoice with a
        # Cyrillic letter or a letter O for a zero is found as the same one.
        invoice = (payee_key, invoice_key(req.reference))
        part = (payee_key, invoice_core(req.reference))
        exact = payment_key(payee_key, req.account, req.amount, req.reference)
        key = self._idempotency_key(req, hold)
        data = {"task": task, "request": req.to_dict(), "hold": hold_id}

        # Write ahead: log it and count it before any money can move.
        self.audit.append("payment_submitted", {**data, "idempotency_key": key})
        before = (self.spent, self.payments, self.paid_to.get(payee_key), self.ledger.get(invoice),
                  self.paid_count.get(payee_key), self.paid_refs.get(part),
                  self.paid_exact.get(exact))
        # "count": how often this invoice has been paid, in any task.
        record = {"transfer": None, "amount": plain(req.amount), "time": self._now(),
                  "task": task, "hold": hold_id,
                  "count": int((before[3] or {}).get("count", 1 if before[3] else 0)) + 1}
        self.spent += req.amount
        self.payments += 1
        self.paid_to[payee_key] = self.paid_to.get(payee_key, Decimal("0.00")) + req.amount
        self.paid_count[payee_key] = self.paid_count.get(payee_key, 0) + 1
        parts, part_total = before[5] or (0, Decimal("0.00"))
        self.paid_refs[part] = (parts + 1, part_total + req.amount)
        self.paid_exact[exact] = (before[6] or 0) + 1
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
            for counter, slot, earlier in ((self.paid_count, payee_key, before[4]),
                                           (self.paid_refs, part, before[5]),
                                           (self.paid_exact, exact, before[6])):
                if earlier is None:
                    del counter[slot]
                else:
                    counter[slot] = earlier
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
        self.vendors.record_payment(req.payee, req.amount, usual=self._usual(req, usual))
        self._after_bank("payment_executed", {**data, "transfer": transfer.id})
        return PayResult(decision, transfer_id=transfer.id, hold_id=hold_id, request=req)

    def _usual(self, req: PaymentRequest, marked: bool) -> bool:
        """Does an executed payment join the payee's usual amounts?

        Only when a person marked it as usual when approving it, or when it
        lies inside the range the usual amounts already span. A payee with no
        usual amount gets one only from a person's mark.
        """
        if marked:
            return True
        return counts_as_usual(self.vendors.history_for(req.payee), req.amount)

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
