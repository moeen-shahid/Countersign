"""The local web console: one small HTTP server on the standard library.

There are two layers, kept apart so that each can be tested alone.

`App` is the console itself and knows nothing about sockets. Its one entry
point, `handle(method, path, query, body)`, answers every `/api` call with a
status and plain JSON data. It holds the current lab (one scenario replayed
under every guard), the playground tally and, when the server was started
with a database, the live console on top of `store.Store`.

The HTTP layer (`make_server`, `serve`) is the only part that touches the
network. It binds to 127.0.0.1 and refuses, in this order: a Host that is not
this machine, an Origin that is not this server, a path that is not on the
static whitelist or under /api, an /api call without the console key, a POST
that is not JSON, and a body over 256 KiB (refused unread). Every answer
carries the same security headers, and nothing an exception says ever reaches
the browser: an unexpected error is a plain 500 with the traceback on stderr.

What the console key is and is not: it stops other web pages and other people
on the network path from calling this server. It does not stop a program that
runs as the same operating-system user, which can read the database file and
this process directly.

Text offsets in the API (document segments, accounts and the spans in
evidence) are counted in UTF-16 code units, the unit a browser indexes
strings in, so the page can slice the text it was sent. They are the same
numbers as Python's unless the text has characters outside the basic plane.
The audit log keeps the guard's own offsets and is never rewritten here.
"""

from __future__ import annotations

import argparse
import bisect
import copy
import functools
import hmac
import io
import json
import os
import re
import secrets
import sys
import threading
import traceback
import webbrowser
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from typing import Any, Callable, Iterable, Mapping
from urllib.parse import parse_qs, quote, unquote, urlsplit

from . import __version__, scenarios
from .audit import entry_hash, export_jsonl, verify_entries
from .console import (
    MAX_SET_PAYMENTS,
    REJECT_CHOICES,
    adjust_asks,
    count_reading,
    default_count_note,
    exclusion_reading,
    held_rules,
    hold_facts,
    quarantine_of,
    quarantine_text,
    reject_choices,
    reject_consequence,
    rule_facts,
    usual_amount_change,
)
from .drafting import describe_draft, draft_mandate
from .guard import DECLINED, NOT_RESHOWN, UNCONFIRMED, Guard, Hold
from .iban import canonical_iban, find_ibans
from .models import (
    Ask,
    Decision,
    Mandate,
    Outcome,
    clean_label,
    parse_amount,
    plain,
)
from .policy import RULE_GUARDS, RULE_ORDER, RULE_OUTCOMES, RULES, rule_title, usual_ceiling
from .provenance import UNNAMED, USER_SOURCE
from .simulation import APPROVERS, MODE_LABELS, MODES, Run, default_vendors, run_scenario
from .vendors import VendorFile

DEFAULT_PORT = 8377
MAX_BODY = 256 * 1024  # bytes; a longer POST is refused without being read
SOCKET_TIMEOUT = 15.0  # seconds a connection may stay silent
TOKEN_HEADER = "X-Countersign-Token"
TOKEN_ENV = "COUNTERSIGN_TOKEN"
APPROVER = "console"  # how the audit log names a decision made on this page
MAX_FUZZ_RUNS = 2000
MAX_TASK_HOURS = 24 * 31
TAMPER_STAGES = ("edit", "rehash", "rechain", "truncate")
EDITED = "(edited after the fact)"

CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
    "img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)
SECURITY_HEADERS = (
    ("Content-Security-Policy", CSP),
    ("X-Frame-Options", "DENY"),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "no-referrer"),
    ("Cache-Control", "no-store"),
)
# The only files this server gives out. Anything else outside /api is a 404.
STATIC_FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/app.css": ("app.css", "text/css; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
}

MODE_NOTES = {"rules": "our baseline", "strict": "our baseline"}

# One plain sentence per real limit of the product. Shown under "Limits".
LIMITS = (
    "The attacks in the lab are scripted traces replayed against the guard. No live model is "
    "attacked here.",
    "Both baselines (Allowlist + caps and Account allowlist + caps) are our own. We wrote them "
    "to show what those designs miss; they are not anybody else's product.",
    "We wrote both the attacks and the defence. The playground is there so that you can write "
    "an attack we did not think of.",
    "Only IBAN accounts are paid. Any other kind of account number is refused.",
    "A valid IBAN only shows that the number is well formed. It says nothing about who owns "
    "the account.",
    "An extra or inflated payment to a vendor's genuine account that stays inside every limit "
    "of the mandate cannot be told from a genuine one, and is paid.",
    "A person who approves a hold without checking loses that payment. Holds only work if "
    "someone reads them.",
    "To approve a payment whose account is in question, the person types back the whole "
    "account the vendor confirmed. That stops a look-alike account and a hurried click. It "
    "does not stop a person who copies the account from the hold or the invoice instead of "
    "asking the vendor on a number they already had.",
    "Marking an approved amount as a payee's new usual amount raises the line for later "
    "tasks. A wrong mark lets the agent pay up to the new line without asking.",
    "An account typed in the instruction is trusted for a payee only in a task with exactly "
    "one payee, when the sentence gives it as the place to pay that payee (\"to IBAN ...\" in "
    "the clause that tells the agent to pay), carries no negation, warning, question or "
    "condition, and the vendor file has no account for that payee. The words that count as "
    "a warning are a fixed list; a warning in other words, in that same clause, is not "
    "recognised. A user who was fooled into typing the wrong account is trusted. Whoever "
    "can type the instruction is the user.",
    "The amount, the number of payments (one per payee unless the sentence counts more) and "
    "the invoice numbers are read from the instruction by fixed rules, in English, and a "
    "reading can be wrong: the person who confirms the task is shown every line. A payment "
    "above the amount or beyond the count is held; one for an invoice that was not named is "
    "refused. A count of two or more, or an amount stated for a payee with no usual amount, "
    "lets through payments that would otherwise wait, up to the user's own number. No "
    "reading lifts the unusual-amount or duplicate holds.",
    "When the sentence does not name the invoice, one payment inside every limit can go to "
    "the genuine account for an invoice that does not exist, and the genuine invoice is then "
    "held as one payment too many.",
    "Origin tracking sees only what the agent reads through the guard. An account the agent "
    "learned any other way counts as seen nowhere, and the payment is refused.",
    "A payee with no usual amount on file is held unless the user states an amount. A "
    "stated amount that is wrong is paid up to that amount.",
    "The audit log is tamper-evident, not tamper-proof. Cutting off its end, or rewriting all "
    "of it, is caught only against a head or receipt kept somewhere this machine cannot "
    "rewrite.",
    "The key in the console link keeps other web pages out. It does not stop a program that "
    "runs as the same operating-system user, which can read the database and this server.",
    "Anything that happens outside the guard is not seen, for example an email that asks a "
    "vendor to send money back.",
    "The human view of a document recognises one hiding trick, white 1px text, to show what a "
    "reader would miss. The guard itself never looks for hidden text.",
    "The bank is a mock. No real money moves, and a real bank can fail in ways this one does "
    "not.",
)

_LOCAL_HOST = re.compile(r"\A(?:127\.0\.0\.1|localhost)(?::[0-9]{1,5})?\Z", re.IGNORECASE)
_TOKEN = re.compile(r"\A[A-Za-z0-9._~-]{16,200}\Z")
_AMOUNT_IN_TEXT = re.compile(
    r"(?<![\w.,])(?:[0-9]{1,3}(?:,[0-9]{3})+|[0-9]+)\.[0-9]{2}(?![\w]|[.,][0-9])"
)


class ApiError(Exception):
    """A refusal the page should show: an HTTP status and one plain sentence."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


@dataclass(frozen=True)
class Download:
    """A payload that is a file to save, not JSON."""

    content_type: str
    filename: str
    data: bytes


def _sentence(text: object) -> str:
    """An exception message as one sentence for the page."""
    words = str(text).strip() or "The request could not be carried out"
    words = words[0].upper() + words[1:]
    return words if words[-1] in ".!?" else words + "."


# --- view builders: core objects -> the shapes of the HTTP contract ---------------


@functools.lru_cache(maxsize=64)
def _wide(text: str) -> tuple[int, ...]:
    """Positions of characters a browser counts twice (outside the BMP). Cached,
    because the same documents are converted again for every view."""
    return tuple(index for index, ch in enumerate(text) if ord(ch) > 0xFFFF)


def _utf16(text: str) -> Callable[[int], int]:
    """Turn offsets into `text` as Python counts them into offsets as a browser does."""
    wide = _wide(text)
    if not wide:
        return lambda offset: offset
    return lambda offset: offset + bisect.bisect_left(wide, offset)


def _segments(text: str) -> list[tuple[int, int, bool]]:
    """(start, end, hidden) pieces that cover `text` in order."""
    return [tuple(piece) for piece in scenarios.split_hidden(text)]


def document_view(
    name: str, text: str, vendors: VendorFile, attackers: Iterable[str] | None
) -> dict[str, Any]:
    """One document as the page shows it: the raw text, which parts a reader
    would not see, and every account written in it.

    `attackers` is the scenario's ground truth; None means nobody knows.
    """
    at = _utf16(text)
    accounts = []
    for match in find_ibans(text, rendered=True):  # as the guard reads a document
        owner = vendors.owner_of(match.account)
        accounts.append(
            {
                "account": match.account,
                "start": at(match.start),
                "end": at(match.end),
                "on_file_for": owner.name if owner is not None else None,
                "attacker": None if attackers is None else match.account in attackers,
                "rendered": match.rendered,
            }
        )
    return {
        "name": name,
        # The name the guard uses for this document when it quotes it as evidence.
        "label": clean_label(name) or UNNAMED,
        "text": text,
        "segments": [[at(start), at(end), bool(hidden)] for start, end, hidden in _segments(text)],
        "accounts": accounts,
    }


def _attackers(scenario: Any) -> frozenset[str] | None:
    """Accounts the scenario says the attacker controls; None if nobody said.

    A scenario of ours always says. One written in the playground says only
    if its author listed accounts.
    """
    own = frozenset(scenario.attacker_accounts)
    return None if scenario.id == "custom" and not own else own


def _tasks(scenario: Any) -> tuple[Any, ...]:
    """Every task of a scenario, in order. One for a scenario of one task."""
    return tuple(scenario.tasks())


def _has_hidden_text(scenario: Any) -> bool:
    return any(
        hidden for task in _tasks(scenario) for text in task.documents.values()
        for _, _, hidden in _segments(text)
    )


def scenario_summary(scenario: Any) -> dict[str, Any]:
    return {
        "id": scenario.id,
        "title": scenario.title,
        "kind": scenario.kind,
        "family": scenario.family,
        "summary": scenario.summary,
        "known_gap": bool(scenario.known_miss),
        "suite": getattr(scenario, "suite", "standard"),
        "tasks": len(_tasks(scenario)),
    }


def scenario_view(scenario: Any, vendors: VendorFile) -> dict[str, Any]:
    """A scenario as the Stage shows it. `instruction` and `documents` are the
    first task's; `tasks` lists every task with its own sentence, payees,
    limits and documents (a scenario of several tasks runs them one after
    another on one guard)."""
    attackers = _attackers(scenario)
    view = scenario_summary(scenario)
    tasks = []
    for number, task in enumerate(_tasks(scenario), 1):
        own_limit = getattr(task, "max_per_payment", None)
        own_total = getattr(task, "max_total", None)
        tasks.append({
            "number": number,
            "instruction": task.instruction,
            "payees": list(task.payees or scenario.payees),
            # The limits the person chose for this task: its own, or the scenario's.
            "max_per_payment": plain(own_limit if own_limit is not None
                                     else scenario.max_per_payment),
            "max_total": plain(own_total if own_total is not None else scenario.max_total),
            "gap_hours": int(task.gap_hours),
            "attempts": len(task.attempts),
            "documents": [document_view(name, text, vendors, attackers)
                          for name, text in task.documents.items()],
        })
    view["instruction"] = tasks[0]["instruction"]
    view["documents"] = tasks[0]["documents"]
    view["tasks"] = tasks
    view["miss_reason"] = getattr(scenario, "miss_reason", "")
    return view


def _checks(decision: Mapping[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            "rule": check.get("rule"),
            "title": rule_title(str(check.get("rule"))),
            "status": check.get("status"),
            "detail": check.get("detail"),
        }
        for check in decision.get("checks") or ()
        if isinstance(check, dict)
    ]


def _evidence(decision: Mapping[str, Any], texts: Mapping[str, str]) -> dict[str, Any] | None:
    """The decision's evidence, with spans counted the way the page counts.

    `texts` maps the name the guard uses for a text to the text itself.
    """
    evidence = decision.get("evidence")
    if not isinstance(evidence, dict):
        return None
    evidence = copy.deepcopy(evidence)
    for sighting in evidence.get("sightings") or ():
        text = texts.get(sighting.get("source"))
        if text is not None:
            at = _utf16(text)
            sighting["spans"] = [[at(start), at(end)] for start, end in sighting["spans"]]
    return evidence


def rejections(entries: Iterable[Any]) -> dict[str, dict[str, Any]]:
    """Per rejected hold, what the rejection did beyond refusing the payment:
    `account_refused` (the person said the account was wrong, so it is
    refused for the rest of the task), `vendor_removed` (it came off the
    vendor file) and `wrong`, what the person said was wrong ("account",
    "payment", or None for a rejection logged before v0.3). Read from the
    audit log (`hold_rejected`, `vendor_account_removed`)."""
    found: dict[str, dict[str, Any]] = {}
    for entry in entries:
        data = _data(entry)
        hold = data.get("hold")
        if not isinstance(hold, str):
            continue
        if _event(entry) == "hold_rejected":
            found.setdefault(hold, {"account_refused": False, "vendor_removed": False,
                                    "wrong": None})
            found[hold]["account_refused"] = data.get("account_refused") is True
            found[hold]["wrong"] = data.get("wrong") if data.get("wrong") in REJECT_CHOICES \
                else None
        elif _event(entry) == "vendor_account_removed":
            found.setdefault(hold, {"account_refused": True, "vendor_removed": False,
                                    "wrong": None})
            found[hold]["vendor_removed"] = True
    return found


def _hold_info(
    hold: Mapping[str, Any] | None, rejected: Mapping[str, Mapping[str, Any]] | None = None
) -> dict[str, Any] | None:
    if hold is None:
        return None
    done = (rejected or {}).get(hold["id"]) or {}
    return {
        "id": hold["id"],
        "digest": hold["digest"],
        "status": hold["status"],
        "decided_by": hold.get("decided_by"),
        "attestation": hold.get("attestation"),
        "account_refused": bool(done.get("account_refused")),
        "vendor_removed": bool(done.get("vendor_removed")),
        "wrong": done.get("wrong"),
    }


def approval_view(
    hold: Hold, vendors: VendorFile, related: Mapping[str, Any] | None = None
) -> dict[str, Any]:
    """What a person is asked for before approving a hold that waits.

    `typed_account`: the hold is about the account (P1, P2, P3), so the whole
    account has to be typed back as the vendor confirmed it; the page never
    fills it in. `remember_account`: the account is not on file (P1, P2).
    `usual_amount`: the hold is about the amount (A1, A2): the A1 line for
    one invoice now and after the mark, from the vendor file as it is now,
    and what the mark changes in words.

    `related` is what the guard says about this hold now (`Guard.related`,
    `Store.related`), not when it was made: `rivals`, waiting holds of the
    same invoice to another account (D3); `waiting`, the waiting holds that,
    if paid, would make this one break a limit (H2), and `projected_rules`
    which limits; `cleared`, a D3 or H2 shown with the hold that no longer
    applies; `refused`, the rule that would refuse it now (approving it would
    pay nothing), and then nothing is "cleared". `on_reject` says what
    rejecting does. `reject_choices` lists, for a hold about the account,
    the two answers the person must choose between when rejecting it
    ({wrong, label, text}; none is chosen for them); empty for any other
    hold, which is rejected as it is.
    """
    from .store import needs_typed_account, offers_remember_account, offers_usual_amount

    request = hold.request
    usual = None
    if offers_usual_amount(hold) and request.amount is not None:
        history = vendors.history_for(request.payee)
        now = usual_ceiling(history)
        usual = {
            "amount": plain(request.amount),
            "now": None if now is None else plain(now),
            "after": plain(usual_ceiling(history + (request.amount,))),
            "text": usual_amount_change(request.payee, request.amount, history),
        }
    related = related or {}
    rules_now = set(related.get("rules") or ())
    refused = [{"rule": str(r), "title": rule_title(str(r))}
               for r in related.get("refused") or ()]
    return {
        "typed_account": needs_typed_account(hold),
        "remember_account": offers_remember_account(hold),
        "usual_amount": usual,
        "rivals": [str(h) for h in related.get("rivals") or ()],
        "waiting": [str(h) for h in related.get("waiting") or ()],
        "projected_rules": [{"rule": str(r), "title": rule_title(str(r))}
                            for r in related.get("projected_rules") or ()],
        "cleared": [r for r in hold.decision.rules if r in NOT_RESHOWN and r not in rules_now]
        if related and not refused else [],
        "refused": refused,
        "on_reject": reject_consequence(hold, vendors),
        "reject_choices": [{"wrong": wrong, "label": label, "text": text}
                           for wrong, label, text in reject_choices(hold, vendors)],
    }


def attempt_view(
    index: int,
    *,
    payee: str,
    account: str,
    account_raw: str,
    amount: str,
    reference: str,
    decision: Mapping[str, Any],
    texts: Mapping[str, str],
    hold: Mapping[str, Any] | None,
    transfer_id: str | None,
    status: str,
    legit: bool | None = None,
    to_attacker: bool | None = None,
    note: str = "",
    approval: dict[str, Any] | None = None,
    rejected: Mapping[str, Mapping[str, Any]] | None = None,
    task: int = 1,
    repeat: bool = False,
    transfers: Iterable[Any] = (),
) -> dict[str, Any]:
    """One payment the agent asked for, with the guard's answer and what became of it.

    `held` lists every rule the decision carries with what it found (the
    rule's line of the ladder), `facts` the trusted facts the rules used
    (`console.hold_facts`), `found` what else the guard found for the rules
    of v0.3 (`console.rule_facts`: hidden figures, a look-alike reference,
    another invoice with the number you named, invoices your sentence left
    out, an amount above every usual one) from this task's documents
    (`texts`) and the bank's `transfers`, and `approval` what a person is
    asked for to approve a hold that waits (`approval_view`); None otherwise. `task` is
    the task it was asked in (from 1); `repeat` is true when it asked again
    for a payment that was waiting and joined that hold. `rejected`
    (`rejections`) says what a rejection of its hold did.
    """
    rule = str(decision.get("rule") or "")
    return {
        "task": task,
        "repeat": repeat,
        "held": [{"rule": code, "title": title, "detail": detail}
                 for code, title, detail in held_rules(decision)]
        if decision.get("outcome") in ("HOLD", "BLOCK") else [],
        "facts": hold_facts(decision),
        "found": rule_facts(decision, reference=reference, amount=amount,
                            texts={k: v for k, v in texts.items() if k != USER_SOURCE},
                            transfers=transfers),
        "approval": approval,
        "index": index,
        "payee": payee,
        "account": account,
        "account_raw": account_raw,
        "amount": amount,
        "reference": reference,
        "legit": legit,
        "to_attacker": to_attacker,
        "note": note,
        "outcome": decision.get("outcome"),
        "rule": rule,
        "rules": list(decision.get("rules") or ()),
        "rule_title": rule_title(rule),
        "reason": decision.get("reason"),
        "checks": _checks(decision),
        "evidence": _evidence(decision, texts),
        "hold": _hold_info(hold, rejected),
        "transfer_id": transfer_id,
        "status": status,
    }


def _shown_decision(
    asked: Mapping[str, Any], hold: Mapping[str, Any] | None, refusal: Mapping[str, Any] | None
) -> Mapping[str, Any]:
    """Which decision the page shows for an attempt.

    Normally the one made when the agent asked, unchanged by anything that
    happened later. Two cases replace it, because the earlier answer is then
    no longer what stands: an approval that the guard refused (the refusal is
    shown), and a hold whose reasons grew when a person tried to approve it
    (the hold's current decision is shown; its digest covers exactly that).
    """
    if hold is None:
        return asked
    if hold["status"] in ("blocked", "unknown") and refusal is not None:
        return refusal
    if hold["status"] == "pending" and hold["decision"].get("rules") != asked.get("rules"):
        return hold["decision"]
    return asked


def audit_view(
    entries: list[Any], intact: bool, broken_at: int | None, head: tuple[int, str] | None = None
) -> dict[str, Any]:
    if head is None and entries and isinstance(entries[-1], dict):
        head = (entries[-1].get("seq"), entries[-1].get("hash"))
    seq, digest = head if head is not None else (-1, "0" * 64)
    return {
        "intact": bool(intact),
        "broken_at": broken_at,
        "head": {"seq": seq, "hash": digest},
        "entries": entries,
    }


def _amount_text(value: object) -> str:
    parsed = parse_amount(value)
    return plain(parsed) if parsed is not None else str(value)


def _lab_texts(scenario: Any, task: Any = None) -> dict[str, str]:
    """The texts of one task of a replay under the names the guard uses for
    them in evidence. Each task has its own: what the agent read is tracked
    per task."""
    task = task if task is not None else _tasks(scenario)[0]
    texts = {USER_SOURCE: task.instruction}
    for name, text in task.documents.items():
        texts.setdefault(clean_label(name) or UNNAMED, text)
    return texts


REPEATED = (
    "The bank had already sent exactly this payment in this task ({transfer}), so it sent "
    "nothing new for this request."
)
JOINED = (
    "The agent asked again for exactly this payment while hold {hold} was waiting. It joined "
    "that hold: one decision covers both requests, and the payment is made at most once."
)


def quarantine_view(entries: Iterable[Any], task_id: object) -> dict[str, Any] | None:
    """The quarantine banner of one task, or None if the task was not quarantined:
    the queue of payments waiting for a person overflowed, so the task stopped
    paying anything without a person, and how many requests that refused."""
    found = quarantine_of(entries, task_id)
    if found is None:
        return None
    return {"task": task_id, "waiting": found["waiting"], "refused": found["refused"],
            "text": quarantine_text(found["refused"])}


def run_state(run: Run, refusals: Mapping[str, Decision] | None = None) -> dict[str, Any]:
    """One scenario replayed under one guard, as the contract's RunState.

    Every task of the scenario, in order: each attempt says which task it
    belongs to (`task`, from 1), and `mandates` holds each task's mandate
    (`mandate` is the first one). `refusals` holds, per hold id, the guard's
    answer to an approval that it refused. The totals are the replay's own
    (`Run.unauthorised_paid`, `Run.to_attacker_paid`), the same numbers the
    benchmark reports. `quarantines` lists the tasks whose queue overflowed.
    """
    scenario, guard = run.scenario, run.guard
    attackers = _attackers(scenario)
    tasks = _tasks(scenario)
    texts = [_lab_texts(scenario, task) for task in tasks]
    refusals = refusals or {}
    entries = guard.audit.entries if guard is not None else []
    rejected = rejections(entries)
    attempts = []
    sent: dict[str, str | None] = {}  # transfer id -> the hold it was paid through
    seen_holds: set[str] = set()
    related: dict[str, dict[str, Any]] = {}
    paid = [transfer.to_dict() for transfer in run.bank.transfers]

    for index, (attempt, result) in enumerate(zip(run.attempts, run.results)):
        number = run.task_of[index] if index < len(run.task_of) else 1
        request = result.request
        account = canonical_iban(attempt.account) or str(attempt.account)
        hold = None
        if result.hold_id is not None and guard is not None:
            hold = guard.hold(result.hold_id).to_dict()
        transfer_id = result.transfer_id
        if transfer_id is None and hold is not None:
            transfer_id = hold["transfer_id"]
        refusal = refusals.get(result.hold_id) if result.hold_id is not None else None
        decision = _shown_decision(
            result.decision.to_dict(), hold, None if refusal is None else refusal.to_dict()
        )
        approval = None
        if hold is not None and hold["status"] == "pending":
            if result.hold_id not in related:
                related[result.hold_id] = guard.related(result.hold_id)
            approval = approval_view(guard.hold(result.hold_id), guard.vendors,
                                     related[result.hold_id])
        note = attempt.note
        repeat = result.hold_id is not None and result.hold_id in seen_holds
        if repeat:
            note = (note + " " if note else "") + JOINED.format(hold=result.hold_id)
        if result.hold_id is not None:
            seen_holds.add(result.hold_id)
        if transfer_id is not None:
            if transfer_id in sent and sent[transfer_id] != result.hold_id:
                # The same request twice: the bank answers the second with the
                # first transfer. Say so, or the lane would show money that never moved.
                note = (note + " " if note else "") + REPEATED.format(transfer=transfer_id)
            sent.setdefault(transfer_id, result.hold_id)
        amount = request.amount if request is not None and request.amount is not None else None
        view = attempt_view(
            index,
            payee=request.payee if request is not None else str(attempt.payee),
            account=account,
            account_raw=str(attempt.account),
            amount=plain(amount) if amount is not None else _amount_text(attempt.amount),
            reference=str(attempt.reference),
            decision=decision,
            texts=texts[number - 1] if 0 < number <= len(texts) else texts[0],
            hold=hold,
            transfer_id=transfer_id,
            status=run.status(index),
            legit=bool(attempt.legit),
            to_attacker=None if attackers is None else account in attackers,
            note=note,
            approval=approval,
            rejected=rejected,
            task=number,
            repeat=repeat,
            transfers=paid,
        )
        attempts.append(view)

    wanted = {transfer.id: bool(attempt.legit) for attempt, transfer in run.payments()}
    audit = None
    if guard is not None:
        # A copy: the answer must not change when the log does.
        copied = copy.deepcopy(guard.audit.entries)
        intact, broken_at = verify_entries(copied)
        audit = audit_view(copied, intact, broken_at)
    mandates = list(run.mandates) if guard is not None else []
    quarantines = []
    for number, mandate in enumerate(mandates, 1):
        found = quarantine_view(entries, mandate.id)
        if found is not None:
            quarantines.append({**found, "number": number})
    return {
        "mode": run.mode,
        "mode_label": MODE_LABELS[run.mode],
        "mandate": None if guard is None else run.mandate.to_dict(),
        "mandates": [mandate.to_dict() for mandate in mandates],
        "quarantines": quarantines,
        "attempts": attempts,
        "unauthorised": plain(run.unauthorised_paid()),
        "to_attacker": plain(run.to_attacker_paid()),
        "transfers": [
            {**transfer.to_dict(), "unauthorised": not wanted.get(transfer.id, True)}
            for transfer in run.bank.transfers
        ],
        "balance": plain(run.bank.balance),
        "audit": audit,
    }


def agent_tools() -> list[str]:
    """The names of the tools an agent is given, read from the tool layer."""
    from .toolsurface import TOOL_NAMES

    return sorted(TOOL_NAMES)


def build_meta(live: bool) -> dict[str, Any]:
    return {
        "version": __version__,
        "currency": "EUR",
        "live": live,
        "modes": [
            {"id": mode, "label": MODE_LABELS[mode], "ours": mode in MODE_NOTES,
             **({"note": MODE_NOTES[mode]} if mode in MODE_NOTES else {})}
            for mode in MODES
        ],
        "rules": [
            {"id": rule, "title": RULES[rule], "outcome": RULE_OUTCOMES[rule],
             "guards": list(RULE_GUARDS[rule])}
            for rule in RULE_ORDER
        ],
        # Every suite, in order: the Stage and the scoreboard show all of them.
        "scenarios": [
            {**scenario_summary(scenario), "hidden_text": _has_hidden_text(scenario)}
            for scenario in scenarios.ALL_SCENARIOS
        ],
        "suites": [{"id": suite, "note": scenarios.SUITE_NOTES.get(suite, "")}
                   for suite in scenarios.SUITES],
        "approvers": list(APPROVERS),
        "vendors": default_vendors().to_state(),
        "attacker_accounts": sorted(scenarios.ATTACKER_ACCOUNTS),
        "agent_tools": agent_tools(),
        "limits": list(LIMITS),
    }


# --- the live console: Store.snapshot() -> LiveState -------------------------------


def _parse_time(text: object) -> datetime | None:
    try:
        moment = datetime.fromisoformat(str(text))
    except ValueError:
        return None
    return moment if moment.utcoffset() is not None else None


def _data(entry: Any) -> dict[str, Any]:
    data = entry.get("data") if isinstance(entry, dict) else None
    return data if isinstance(data, dict) else {}


def _event(entry: Any) -> str:
    return str(entry.get("event")) if isinstance(entry, dict) else ""


def _live_task(snapshot: Mapping[str, Any], started: Any) -> dict[str, Any] | None:
    """The task the console shows: the active one, or the last one that ran."""
    state = snapshot["state"]
    mandate = state.get("mandate")
    active = mandate is not None
    spent, payments = "0.00", 0
    if active:
        spent, payments = state["task"]["spent"], state["task"]["payments"]
    elif started is not None:
        mandate = _data(started).get("mandate")
        for entry in snapshot["entries"]:
            if _event(entry) == "task_ended" and _data(entry).get("task") == mandate.get("id"):
                spent = _data(entry).get("spent", spent)
                payments = _data(entry).get("payments", payments)
    if not isinstance(mandate, dict):
        return None
    now = _parse_time(snapshot.get("now")) or datetime.now(timezone.utc)
    expires = _parse_time(mandate.get("expires_at"))
    return {
        "mandate": mandate,
        "active": active,
        "expired": bool(active and expires is not None and now >= expires),
        "spent": spent,
        "payments": payments,
        # The queue overflowed in this task, so it pays nothing more without a person.
        "quarantine": quarantine_view(snapshot["entries"], mandate.get("id")),
    }


def _shown_related(hold: Hold) -> dict[str, Any]:
    """What the hold showed when it was made, for when the guard cannot be asked."""
    evidence = hold.decision.evidence
    return {
        "rules": list(hold.decision.rules),
        "rivals": list(getattr(evidence, "rivals", ()) or ()),
        "waiting": list(getattr(evidence, "waiting_holds", ()) or ())
        if "H2" in hold.decision.rules else [],
        "projected_rules": list(getattr(evidence, "projected_rules", ()) or ())
        if "H2" in hold.decision.rules else [],
    }


def live_related(snapshot: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    """`Store.related` for every waiting hold, at the moment of the snapshot:
    one guard is rebuilt from the snapshot's state and asked about each."""
    state = snapshot["state"]
    pending = [hold["id"] for hold in state.get("holds") or () if hold.get("status") == "pending"]
    if not pending:
        return {}
    now = _parse_time(snapshot.get("now")) or datetime.now(timezone.utc)
    try:
        guard = Guard.from_state(copy.deepcopy(state), clock=lambda: now)
        return {hold_id: guard.related(hold_id) for hold_id in pending}
    except (ValueError, KeyError, TypeError):
        # A state this guard cannot rebuild: show what each hold showed when made.
        return {}


def _live_attempts(
    snapshot: Mapping[str, Any], since: int, texts: Mapping[str, str]
) -> list[dict[str, Any]]:
    """Every payment the agent asked for since the task began, oldest first.

    Read from the `payment_decision` entries of the audit log. What became of
    a hold, and its transfer, come from the guard's state; the rivals and
    waiting payments of a hold that waits from the guard, now (`live_related`).
    """
    entries = [entry for entry in snapshot["entries"] if isinstance(entry, dict)]
    holds = {hold["id"]: hold for hold in snapshot["state"].get("holds") or ()}
    vendors = VendorFile.from_state(snapshot["state"]["vendors"])
    related = live_related(snapshot)
    rejected = rejections(entries)
    refused: dict[str, dict[str, Any]] = {}
    for entry in entries:
        data = _data(entry)
        if _event(entry) == "hold_blocked" and data.get("status") == "blocked":
            if isinstance(data.get("decision"), dict):
                refused[data.get("hold")] = data["decision"]

    attempts = []
    for position, entry in enumerate(entries):
        if _event(entry) != "payment_decision" or entry.get("seq", -1) <= since:
            continue
        data = _data(entry)
        raw = data.get("raw") if isinstance(data.get("raw"), dict) else {}
        request = data.get("request") if isinstance(data.get("request"), dict) else {}
        decision = data.get("decision") if isinstance(data.get("decision"), dict) else {}
        hold = holds.get(data.get("hold")) if data.get("hold") is not None else None
        repeat = data.get("repeat") is True and hold is not None

        # What the bank answered follows the decision directly in the log.
        transfer_id, bank = None, None
        for later in entries[position + 1:]:
            if _event(later) == "payment_decision":
                break
            if _event(later) in ("payment_executed", "payment_declined", "payment_unknown"):
                if _data(later).get("hold") is None:
                    bank = _event(later)
                    transfer_id = _data(later).get("transfer")
                break
        approval = None
        if hold is not None:
            transfer_id = hold.get("transfer_id")
            status = {"pending": "held", "approved": "paid"}.get(hold["status"], hold["status"])
            if hold["status"] == "pending":
                shown = Hold.from_dict(hold)
                approval = approval_view(shown, vendors,
                                         related.get(hold["id"]) or _shown_related(shown))
            refusal = refused.get(hold["id"])
            if hold["status"] == "unknown":
                refusal = {**hold["decision"], "outcome": "BLOCK", "rule": "BANK",
                           "rules": ["BANK"], "reason": UNCONFIRMED}
            decision = _shown_decision(decision, hold, refusal)
        elif bank == "payment_declined":
            decision = {**decision, "outcome": "BLOCK", "rule": "BANK", "rules": ["BANK"],
                        "reason": DECLINED}
            status = "blocked"
        elif bank == "payment_unknown":
            decision = {**decision, "outcome": "BLOCK", "rule": "BANK", "rules": ["BANK"],
                        "reason": UNCONFIRMED}
            status = "unknown"
        else:
            status = "paid" if transfer_id is not None else "blocked"

        def field(name: str) -> str:
            value = request.get(name)
            if value is None:
                value = raw.get(name)
            return "" if value is None else str(value)

        attempts.append(
            attempt_view(
                len(attempts),
                payee=field("payee"),
                account=field("account"),
                account_raw="" if raw.get("account") is None else str(raw.get("account")),
                amount=field("amount"),
                reference=field("reference"),
                decision=decision,
                texts=texts,
                hold=hold,
                transfer_id=transfer_id,
                status=status,
                note=JOINED.format(hold=clean_label(hold["id"])) if repeat else "",
                approval=approval,
                rejected=rejected,
                repeat=repeat,
                transfers=snapshot["state"]["bank"]["transfers"],
            )
        )
    return attempts


def mcp_config(db: str, inbox: str | None) -> dict[str, Any]:
    """What an agent host needs to start the MCP server on this database."""
    from .mcp import config_block

    return config_block(db, inbox)


def live_state(snapshot: Mapping[str, Any], *, db: str, inbox: str | None) -> dict[str, Any]:
    """Everything the live console shows, built from one `Store.snapshot()`."""
    state = snapshot["state"]
    entries = snapshot["entries"]
    started = None
    for entry in entries:
        if _event(entry) == "task_started":
            started = entry
    task = _live_task(snapshot, started)
    vendors = VendorFile.from_state(state["vendors"])
    untrusted = [seen for seen in state.get("observations") or () if seen["origin"] != "user"]
    texts = {USER_SOURCE: task["mandate"].get("instruction", "")} if task is not None else {}
    for seen in untrusted:
        texts.setdefault(clean_label(seen["name"]) or UNNAMED, seen["text"])
    since = started["seq"] if started is not None else -1
    meta = snapshot.get("meta") or {}
    return {
        "changed": True,
        "head": audit_view(entries, True, None, snapshot.get("head"))["head"],
        "guard_mode": snapshot.get("mode"),
        "task": task,
        "documents": [
            document_view(seen["name"], seen["text"], vendors, None) for seen in untrusted
        ],
        "attempts": _live_attempts(snapshot, since, texts),
        # Nobody knows here which payments the user wanted, so nothing is flagged.
        "transfers": [
            {**transfer, "unauthorised": None} for transfer in state["bank"]["transfers"]
        ],
        "balance": state["bank"]["balance"],
        "vendors": state["vendors"],
        "audit": audit_view(
            entries, snapshot["intact"], snapshot["broken_at"], snapshot.get("head")
        ),
        "mcp_config": mcp_config(db, inbox or meta.get("inbox")),
    }


def draft(
    instruction: str, vendors: VendorFile, payees: list[str] | None = None
) -> dict[str, Any]:
    """What can be read out of a sentence before a task is confirmed.

    A proposal for the person filling in the form: it changes nothing and
    decides nothing. `draft_mandate` reads the sentence, the same function
    the command line uses. "readings" lists every phrase it used or refused,
    in words for the person; "digest" identifies exactly this proposal, and
    a task started with it is refused if the proposal has changed since.
    """
    proposal = draft_mandate(instruction, vendors, payees)
    found = find_ibans(instruction)
    amounts = []
    for match in _AMOUNT_IN_TEXT.finditer(instruction):
        if any(iban.start < match.end() and match.start() < iban.end for iban in found):
            continue  # digits of an account number, not an amount
        amount = parse_amount(match.group().replace(",", ""))
        if amount is not None:
            amounts.append(plain(amount))
    return {
        "payees": list(proposal.payees),
        "suggested": proposal.suggested,
        # Vendors on file the sentence names that are not payees ("Hold off on Kestrel").
        "mentioned": list(proposal.mentioned),
        "accounts": list(dict.fromkeys(iban.account for iban in found)),
        "amounts": list(dict.fromkeys(amounts)),
        "bound": {payee: list(values) for payee, values in proposal.accounts.items()},
        "asks": {payee: ask.to_dict() for payee, ask in proposal.asks.items()},
        "readings": [reading.to_dict() for reading in proposal.readings],
        "unbound": list(proposal.unbound),
        # The same confirmation the command line prints, line by line.
        "lines": describe_draft(proposal),
        "digest": proposal.digest(),
        "max_set_payments": MAX_SET_PAYMENTS,
        # Per payee whose count is only the default: the drafter's line about it,
        # for the form to show next to that payee's count box, and whether it
        # warns that the sentence asks for several payments without a number.
        "count_notes": {
            payee: {"text": _for_the_form(note[0]), "several": note[1]}
            for payee in proposal.asks
            for note in [default_count_note(proposal, payee)] if note is not None
        },
        # Per payee whose count the sentence gives ("all three", "in two
        # instalments"): the words, the count, and whether the payments are
        # instalments of one invoice. Shown next to the count box.
        "count_from": {
            payee: {"quote": reading.quote, "payments": proposal.asks[payee].payments,
                    "instalments": proposal.asks[payee].instalments}
            for payee in proposal.asks
            for reading in [count_reading(proposal, payee)]
            if reading is not None and (proposal.asks[payee].payments or 0) > 1
        },
        # Per payee some of whose invoices the sentence leaves out ("don't pay
        # the April one"): the words and what that does (rule S4). The form
        # shows it as a banner on the payee instead of a plain reading line.
        "excludes": {
            payee: {"quote": reading.quote, "text": reading.result}
            for payee in proposal.asks if proposal.asks[payee].excludes_some
            for reading in [exclusion_reading(proposal, payee)] if reading is not None
        },
    }


# The drafter's default-count line names both screens' controls. On the form, the
# box is right next to the line, so it says only that.
_SET_THE_NUMBER = " To expect more, set the number:"


def _for_the_form(text: str) -> str:
    head, found, _ = text.partition(_SET_THE_NUMBER)
    return head + " To expect more, type the number in the box." if found else text


# --- the console --------------------------------------------------------------------


@dataclass
class Lab:
    """One scenario replayed under every guard, and what was done to it since."""

    scenario: Any
    runs: dict[str, Run]
    # Per hold id: the guard's answer to an approval that it refused.
    refusals: dict[str, Decision]
    saved_log: list[Any] | None = None  # the audit log as it was before the intruder demo
    edited: int | None = None  # position of the entry the demo edited


def _text(body: Mapping[str, Any], key: str, limit: int = 4000, default: str | None = None) -> str:
    value = body.get(key, default)
    if not isinstance(value, str) or len(value) > limit:
        raise ApiError(400, f"\"{key}\" must be text of at most {limit} characters.")
    return value


def _flag(body: Mapping[str, Any], key: str) -> bool:
    value = body.get(key, False)
    if not isinstance(value, bool):
        raise ApiError(400, f"\"{key}\" must be true or false.")
    return value


def _wrong(body: Mapping[str, Any]) -> str | None:
    """What the person says was wrong when they reject a hold: "account",
    "payment", or nothing (the guard's default: the account, for a hold about
    the account). The page always asks for a hold about the account."""
    value = body.get("wrong")
    if value is not None and value not in REJECT_CHOICES:
        raise ApiError(400, "\"wrong\" must be \"account\" or \"payment\".")
    return value


def _check_wrong(hold: Hold, wrong: str | None) -> None:
    """"The account is wrong" only means something for a hold about the
    account (P1, P2, P3); for any other hold it is refused, so the audit log
    never says an account was wrong when it was not the question."""
    from .store import needs_typed_account

    if wrong == "account" and not needs_typed_account(hold):
        rules = ", ".join(hold.decision.rules or (hold.decision.rule,))
        raise ApiError(409, f"Hold {clean_label(hold.id)} is held for {rules}, not for its "
                            "account, so there is no account to refuse. Reject it without "
                            "saying what was wrong.")


def _typed_account(body: Mapping[str, Any]) -> str | None:
    """The account a person typed back to approve a hold, or None."""
    value = body.get("confirmed_account")
    if value is None:
        return None
    if not isinstance(value, str) or len(value) > 200:
        raise ApiError(400, "\"confirmed_account\" must be text of at most 200 characters.")
    return value


def _limit(body: Mapping[str, Any], key: str) -> Decimal:
    value = body.get(key)
    amount = parse_amount(value) if isinstance(value, (str, int)) else None
    if amount is None:
        raise ApiError(400, f"\"{key}\" must be a plain amount such as 2000.00.")
    return amount


class App:
    """The console, without the network. One lock keeps requests consistent."""

    def __init__(self, db: str | os.PathLike | None = None,
                 inbox: str | os.PathLike | None = None) -> None:
        self._lock = threading.RLock()
        self._lab: Lab | None = None
        self._tally = {"runs": 0, "attempts": 0, "with_money": 0, "unauthorised": Decimal("0.00")}
        self.db = os.path.abspath(os.fspath(db)) if db is not None else None
        self.inbox = os.path.abspath(os.fspath(inbox)) if inbox is not None else None
        self._store: Any = None
        self._routes = (
            ("GET", ("meta",), self._get_meta),
            ("POST", ("compare",), self._compare),
            ("GET", ("lab",), self._get_lab),
            ("POST", ("reset",), self._reset),
            ("POST", ("holds", None, "approve"), self._approve),
            ("POST", ("holds", None, "reject"), self._reject),
            ("POST", ("audit", "tamper"), self._tamper),
            ("POST", ("audit", "restore"), self._restore),
            ("GET", ("audit", "export"), self._export),
            ("GET", ("scenarios", None), self._get_scenario),
            ("POST", ("playground", "run"), self._playground),
            ("GET", ("benchmark",), self._benchmark),
            ("GET", ("fuzz",), self._fuzz),
            ("GET", ("live", "state"), self._live_state),
            ("POST", ("live", "tasks"), self._live_start),
            ("POST", ("live", "tasks", "end"), self._live_end),
            ("POST", ("live", "draft"), self._live_draft),
            ("POST", ("live", "holds", None, "approve"), self._live_approve),
            ("POST", ("live", "holds", None, "reject"), self._live_reject),
        )

    @property
    def live(self) -> bool:
        return self.db is not None

    def handle(
        self,
        method: str,
        path: str,
        query: Mapping[str, str] | None = None,
        body: Any = None,
    ) -> tuple[int, Any]:
        """Answer one /api call: (status, JSON data), or (200, Download).

        Refusals come back as (status, {"error": sentence}). Anything else
        that goes wrong is a bug and is raised; the HTTP layer turns it into
        a plain 500.
        """
        try:
            return 200, self._dispatch(method, path, dict(query or {}), body)
        except ApiError as exc:
            return exc.status, {"error": exc.message}

    def _dispatch(self, method: str, path: str, query: dict[str, str], body: Any) -> Any:
        parts = [unquote(part) for part in path.split("/") if part]
        if not parts or parts[0] != "api":
            raise ApiError(404, "There is nothing at this address.")
        if body is None:
            body = {}
        if not isinstance(body, dict):
            raise ApiError(400, "The request body must be a JSON object.")
        other_method = False
        for verb, pattern, handler in self._routes:
            if len(pattern) != len(parts) - 1:
                continue
            if any(want is not None and want != got for want, got in zip(pattern, parts[1:])):
                continue
            if verb != method:
                other_method = True
                continue
            if pattern[0] == "live":
                self.store()  # no database, no live console: say so before anything else
            args = [got for want, got in zip(pattern, parts[1:]) if want is None]
            return handler(*args, query=query, body=body)
        if other_method:
            raise ApiError(405, f"This address does not take {method} requests.")
        raise ApiError(404, "There is nothing at this address.")

    # --- lab ------------------------------------------------------------------------

    def _get_meta(self, *, query: dict[str, str], body: dict[str, Any]) -> dict[str, Any]:
        return build_meta(self.live)

    def _lab_state(self) -> dict[str, Any]:
        lab = self._lab
        if lab is None:
            return {"scenario": None, "runs": {}}
        vendors = lab.runs["countersign"].guard.vendors
        return {
            "scenario": scenario_view(lab.scenario, vendors),
            "runs": {
                mode: run_state(run, lab.refusals if mode == "countersign" else None)
                for mode, run in lab.runs.items()
            },
        }

    def _replay(self, scenario: Any) -> dict[str, Any]:
        runs = {mode: run_scenario(scenario, mode) for mode in MODES}
        self._lab = Lab(scenario, runs, {})
        return self._lab_state()

    def _compare(self, *, query: dict[str, str], body: dict[str, Any]) -> dict[str, Any]:
        scenario = scenarios.BY_ID.get(body.get("scenario")) if isinstance(
            body.get("scenario"), str) else None
        if scenario is None:
            raise ApiError(404, "There is no scenario with that id.")
        with self._lock:
            return self._replay(scenario)

    def _get_lab(self, *, query: dict[str, str], body: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            return self._lab_state()

    def _reset(self, *, query: dict[str, str], body: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            self._lab = None
            return self._lab_state()

    def _countersign_run(self) -> tuple[Lab, Run]:
        lab = self._lab
        if lab is None:
            raise ApiError(409, "Nothing has been replayed yet. Play a scenario first.")
        return lab, lab.runs["countersign"]

    def _untampered(self, lab: Lab) -> None:
        if lab.saved_log is not None:
            raise ApiError(
                409, "The audit log of this run was edited in the Audit view. Restore it first."
            )

    def _approve(self, hold_id: str, *, query: dict[str, str], body: dict[str, Any]) -> Any:
        from .store import approve_hold, with_typed_back

        digest = _text(body, "digest", 200)
        attestation = _text(body, "attestation", 200, "")
        remember = _flag(body, "remember_account")
        usual = _flag(body, "usual_amount")
        typed = _typed_account(body)
        if typed is not None and typed.strip():
            attestation = with_typed_back(attestation)  # checked by approve_hold below
        with self._lock:
            lab, run = self._countersign_run()
            self._untampered(lab)
            try:
                # The same checks as the live console and the command line: a hold
                # about the account needs the account typed back (store.approve_hold).
                result = approve_hold(
                    run.guard, hold_id, approver=APPROVER, remember_account=remember,
                    digest=digest, attestation=attestation, usual_amount=usual,
                    confirmed_account=typed,
                )
            except KeyError:
                raise ApiError(404, f"There is no hold {clean_label(hold_id)}.") from None
            except ValueError as exc:
                raise ApiError(409, _sentence(exc)) from None
            self._after_approval(result, run.guard.hold(hold_id).status, lab.refusals)
            return self._lab_state()

    @staticmethod
    def _after_approval(result: Any, status: str, refusals: dict[str, Decision] | None) -> None:
        """Deal with an approval that did not pay.

        A hold the guard closed keeps the refusal, so the page can show why.
        A refusal that leaves the hold waiting (over budget for now, or the
        bank said no) changes nothing the page shows, so it is answered as a
        conflict with the guard's reason.
        """
        if result.transfer_id is not None:
            return
        if status == "pending" and result.decision.outcome is Outcome.BLOCK:
            raise ApiError(409, "Not paid. " + _sentence(result.decision.reason))
        if status in ("blocked", "unknown") and refusals is not None and result.hold_id:
            refusals[result.hold_id] = result.decision

    def _reject(self, hold_id: str, *, query: dict[str, str], body: dict[str, Any]) -> Any:
        with self._lock:
            lab, run = self._countersign_run()
            self._untampered(lab)
            wrong = _wrong(body)
            try:
                _check_wrong(run.guard.hold(hold_id), wrong)
                run.guard.reject(hold_id, APPROVER, wrong=wrong)
            except KeyError:
                raise ApiError(404, f"There is no hold {clean_label(hold_id)}.") from None
            except ValueError as exc:
                raise ApiError(409, _sentence(exc)) from None
            return self._lab_state()

    def _tamper(self, *, query: dict[str, str], body: dict[str, Any]) -> dict[str, Any]:
        """Demo only: change the Countersign run's log the way an intruder would."""
        stage = body.get("stage")
        if stage not in TAMPER_STAGES:
            raise ApiError(400, "The stage must be edit, rehash, rechain or truncate.")
        with self._lock:
            lab, run = self._countersign_run()
            entries = run.guard.audit.entries
            saved = copy.deepcopy(entries)
            if stage == "truncate":
                if len(entries) < 3:
                    raise ApiError(409, "The log is too short to drop two entries.")
                del entries[-2:]
            elif stage == "edit":
                target = self._edit_target(entries)
                decision = target["data"]["decision"]
                if decision.get("outcome") == "ALLOW":
                    decision.update(outcome="BLOCK", rule="ERR", rules=["ERR"], reason=EDITED)
                else:
                    decision.update(outcome="ALLOW", rule="OK", rules=[], reason=EDITED)
                lab.edited = entries.index(target)
            else:
                at = lab.edited
                if at is None or at >= len(entries):
                    raise ApiError(409, "Edit a decision first.")
                entries[at]["hash"] = entry_hash(entries[at])
                if stage == "rechain":
                    for index in range(at + 1, len(entries)):
                        entries[index]["prev"] = entries[index - 1]["hash"]
                        entries[index]["hash"] = entry_hash(entries[index])
            if lab.saved_log is None:
                lab.saved_log = saved
            return self._lab_state()

    @staticmethod
    def _edit_target(entries: list[Any]) -> dict[str, Any]:
        """The decision the intruder rewrites: a refusal if there is one, and
        one with entries after it, so that the later stages have work to do."""
        decisions = [
            entry for entry in entries
            if entry.get("event") == "payment_decision"
            and isinstance(entry.get("data", {}).get("decision"), dict)
        ]
        if not decisions:
            raise ApiError(409, "There is no payment decision in this log to edit.")
        last = entries[-1]
        for wanted in (
            lambda e: e is not last and e["data"]["decision"].get("outcome") != "ALLOW",
            lambda e: e is not last,
        ):
            for entry in decisions:
                if wanted(entry):
                    return entry
        return decisions[0]

    def _restore(self, *, query: dict[str, str], body: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            lab, run = self._countersign_run()
            if lab.saved_log is not None:
                run.guard.audit.entries[:] = lab.saved_log
                lab.saved_log, lab.edited = None, None
            return self._lab_state()

    def _export(self, *, query: dict[str, str], body: dict[str, Any]) -> Download:
        with self._lock:
            _, run = self._countersign_run()
            out = io.StringIO()
            export_jsonl(run.guard.audit.entries, out)
        return Download(
            "application/x-ndjson", "countersign-audit.jsonl", out.getvalue().encode("ascii")
        )

    # --- playground, benchmark, invariant check ------------------------------------------

    def _get_scenario(self, scenario_id: str, *, query: dict[str, str], body: dict[str, Any]) -> Any:
        scenario = scenarios.BY_ID.get(scenario_id)
        if scenario is None:
            raise ApiError(404, "There is no scenario with that id.")
        return scenarios.scenario_to_doc(scenario)

    def _playground(self, *, query: dict[str, str], body: dict[str, Any]) -> dict[str, Any]:
        try:
            scenario = scenarios.scenario_from_doc(body)
            if scenario.id != "custom":
                scenario = replace(scenario, id="custom")
            with self._lock:
                state = self._replay(scenario)
        except ValueError as exc:
            raise ApiError(400, _sentence(exc)) from None
        with self._lock:
            ours = state["runs"]["countersign"]
            lost = Decimal(ours["unauthorised"])
            tally = self._tally
            tally["runs"] += 1
            tally["attempts"] += len(ours["attempts"])
            tally["with_money"] += 1 if lost > 0 else 0
            tally["unauthorised"] += lost
            state["tally"] = {
                "runs": tally["runs"],
                "attempts": tally["attempts"],
                "runs_with_unauthorised_money": tally["with_money"],
                "unauthorised": plain(tally["unauthorised"]),
            }
        return state

    def _benchmark(self, *, query: dict[str, str], body: dict[str, Any]) -> Any:
        approver = query.get("approver", "none")
        if approver not in APPROVERS:
            raise ApiError(400, "The approver must be none, careful, procedural or careless.")
        late = query.get("late", "0")
        if late not in ("0", "1"):
            raise ApiError(400, "\"late\" must be 0 (answer at once) or 1 (answer late).")
        from .benchmark import run_benchmark

        # Every suite, so the board is the README's benchmark, scenario for scenario.
        return run_benchmark(approver=approver, late=late == "1",
                             scenarios=scenarios.ALL_SCENARIOS)

    def _fuzz(self, *, query: dict[str, str], body: dict[str, Any]) -> Any:
        text = query.get("runs", "300")
        if not (text.isascii() and text.isdigit() and 1 <= int(text) <= MAX_FUZZ_RUNS):
            raise ApiError(400, f"\"runs\" must be a whole number from 1 to {MAX_FUZZ_RUNS}.")
        from .fuzz import run_fuzz

        return run_fuzz(runs=int(text), seed=0)

    # --- live console ---------------------------------------------------------------------

    def store(self) -> Any:
        """The shared database. 404 without --db, 503 if it cannot be used."""
        if self.db is None:
            raise ApiError(404, "This console was started without a database (--db).")
        if self._store is None:
            from .store import Store, StoreError

            try:
                self._store = Store(self.db)
            except StoreError as exc:
                raise ApiError(503, _sentence(exc)) from None
        return self._store

    def _with_store(self, work: Callable[[Any], Any]) -> Any:
        store = self.store()
        from .store import StoreError

        try:
            return work(store)
        except StoreError as exc:
            raise ApiError(503, _sentence(exc)) from None

    def _live_now(self) -> dict[str, Any]:
        snapshot = self._with_store(lambda store: store.snapshot())
        return live_state(snapshot, db=self.db, inbox=self.inbox)

    def _live_state(self, *, query: dict[str, str], body: dict[str, Any]) -> dict[str, Any]:
        after = query.get("after")
        if after is None or after == "":
            return self._live_now()
        if not re.fullmatch(r"-?[0-9]{1,12}", after):
            raise ApiError(400, "\"after\" must be the position of an audit entry.")
        # Reading the newest entry is one indexed row; building the whole view is
        # not. The page asks without "after" once a task's expiry time has passed,
        # since running out of time writes nothing to the log.
        seq, digest = self._with_store(lambda store: store.head())
        if seq == int(after):
            return {"changed": False, "head": {"seq": seq, "hash": digest}}
        return self._live_now()

    def _live_draft(self, *, query: dict[str, str], body: dict[str, Any]) -> dict[str, Any]:
        instruction = _text(body, "instruction")
        payees = body.get("payees")
        if payees is not None and not (
            isinstance(payees, list) and all(isinstance(p, str) for p in payees)
        ):
            raise ApiError(400, "\"payees\" must be a list of text.")
        vendors = VendorFile.from_state(self._with_store(lambda store: store.state())["vendors"])
        return draft(instruction, vendors, payees)

    def _live_start(self, *, query: dict[str, str], body: dict[str, Any]) -> dict[str, Any]:
        hours = body.get("hours", 8)
        if isinstance(hours, bool) or not isinstance(hours, (int, float)) or not (
            0 < hours <= MAX_TASK_HOURS
        ):
            raise ApiError(400, f"\"hours\" must be more than 0 and at most {MAX_TASK_HOURS}.")
        payees, references = body.get("payees"), body.get("references") or []
        accounts = body.get("accounts") or {}
        if not isinstance(payees, list) or not isinstance(references, list):
            raise ApiError(400, "\"payees\" and \"references\" must be lists of text.")
        if not isinstance(accounts, dict):
            raise ApiError(400, "\"accounts\" must map a payee to its accounts.")
        instruction = _text(body, "instruction")
        asks: dict[str, Ask] = {}
        digest = body.get("draft_digest")
        if digest is not None:
            # The form confirms a draft. It is drafted again here, from the same
            # sentence and payees, and must be the one the person was shown.
            if not all(isinstance(p, str) for p in payees):
                raise ApiError(400, "\"payees\" and \"references\" must be lists of text.")
            vendors = VendorFile.from_state(
                self._with_store(lambda store: store.state())["vendors"]
            )
            proposal = draft_mandate(instruction, vendors, payees)
            if digest != proposal.digest():
                raise ApiError(409, "The sentence, the payees or the vendor file changed after "
                                    "the draft was shown. Check the draft again.")
            accounts = {payee: list(values) for payee, values in proposal.accounts.items()}
            asks = dict(proposal.asks)
        # What the person set for one payee on the confirmation screen, on top of
        # the draft: {"Payee": {"payments": 3, "amount": "650.00"}}. Only a value
        # the person typed is sent; it replaces what was read for that payee only.
        adjust = body.get("adjust") or {}
        if not isinstance(adjust, dict) or not all(
            isinstance(name, str) and isinstance(change, dict)
            and set(change) <= {"payments", "amount"} for name, change in adjust.items()
        ):
            raise ApiError(400, "\"adjust\" must map a payee to {\"payments\", \"amount\"}.")
        counts = {name: change["payments"] for name, change in adjust.items()
                  if change.get("payments") is not None}
        amounts = {name: change["amount"] for name, change in adjust.items()
                   if change.get("amount") is not None}
        if not all(isinstance(value, str) for value in amounts.values()):
            raise ApiError(400, "An amount must be text such as \"650.00\".")
        if counts or amounts:
            if not all(isinstance(p, str) for p in payees):
                raise ApiError(400, "\"payees\" and \"references\" must be lists of text.")
            try:
                asks, _ = adjust_asks(asks, payees, payments=counts, amounts=amounts,
                                      budget=_limit(body, "max_total"))
            except ValueError as exc:
                raise ApiError(400, _sentence(exc)) from None
        typed = {match.account for match in find_ibans(instruction)}
        for values in accounts.values():
            for value in values if isinstance(values, list) else [values]:
                if canonical_iban(value) not in typed:
                    # Only an account the person can see in their own sentence may be
                    # trusted, so a stale form cannot slip another one in.
                    raise ApiError(400, "Every account given for a payee must be written in "
                                        "the instruction.")
        try:
            mandate = Mandate(
                id="T-" + secrets.token_hex(4),
                instruction=instruction,
                payees=tuple(payees),
                max_per_payment=_limit(body, "max_per_payment"),
                max_total=_limit(body, "max_total"),
                expires_at=datetime.now(timezone.utc) + timedelta(hours=hours),
                max_payments=body.get("max_payments"),
                references=tuple(references),
                accounts=accounts,
                asks=asks,
            )
            # The digest of the draft the person confirmed goes into the log.
            self._with_store(
                lambda s: s.console().start_task(mandate, confirmed_by=APPROVER,
                                                 draft_digest=digest)
            )
        except (ValueError, TypeError) as exc:
            raise ApiError(400, _sentence(exc)) from None
        return self._live_now()

    def _live_end(self, *, query: dict[str, str], body: dict[str, Any]) -> dict[str, Any]:
        self._with_store(lambda store: store.console().end_task(by=APPROVER))
        return self._live_now()

    def _live_approve(self, hold_id: str, *, query: dict[str, str], body: dict[str, Any]) -> Any:
        digest = _text(body, "digest", 200)
        attestation = _text(body, "attestation", 200, "")
        remember = _flag(body, "remember_account")
        usual = _flag(body, "usual_amount")
        typed = _typed_account(body)
        if typed is not None and typed.strip():
            from .store import with_typed_back

            attestation = with_typed_back(attestation)  # checked by the store below

        def approve(store: Any) -> Any:
            # Store.console().approve checks the typed-back account in the same
            # transaction as the approval: the page is not the control.
            return store.console().approve(
                hold_id, approver=APPROVER, digest=digest, attestation=attestation,
                remember_account=remember, usual_amount=usual, confirmed_account=typed,
            )

        try:
            result = self._with_store(approve)
        except KeyError:
            raise ApiError(404, f"There is no hold {clean_label(hold_id)}.") from None
        except ValueError as exc:
            raise ApiError(409, _sentence(exc)) from None
        status = self._with_store(lambda store: store.hold(hold_id)).status
        self._after_approval(result, status, None)
        return self._live_now()

    def _live_reject(self, hold_id: str, *, query: dict[str, str], body: dict[str, Any]) -> Any:
        wrong = _wrong(body)

        def reject(store: Any) -> None:
            _check_wrong(store.hold(hold_id), wrong)
            store.console().reject(hold_id, approver=APPROVER, wrong=wrong)

        try:
            self._with_store(reject)
        except KeyError:
            raise ApiError(404, f"There is no hold {clean_label(hold_id)}.") from None
        except ValueError as exc:
            raise ApiError(409, _sentence(exc)) from None
        return self._live_now()


# --- the HTTP layer ------------------------------------------------------------------


def _no_constants(name: str) -> Any:
    raise ValueError(f"{name} is not JSON")


def make_handler(app: App, token: str) -> type[BaseHTTPRequestHandler]:
    """The request handler for one console and one key."""
    static = resources.files(__package__).joinpath("static")
    files = {
        path: (static.joinpath(name).read_bytes(), content_type)
        for path, (name, content_type) in STATIC_FILES.items()
    }
    secret = token.encode("ascii")

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "Countersign"
        sys_version = ""
        timeout = SOCKET_TIMEOUT  # a connection that stays silent this long is dropped

        def log_message(self, *args: Any) -> None:  # keep the terminal quiet
            pass

        def version_string(self) -> str:
            return self.server_version

        def _reply(
            self,
            status: int,
            payload: Any,
            content_type: str = "application/json",
            *,
            close: bool = False,
            filename: str | None = None,
        ) -> None:
            if isinstance(payload, bytes):
                data = payload
            else:
                data = json.dumps(payload, ensure_ascii=True, allow_nan=False).encode("ascii")
            if close:
                self.close_connection = True
            if self.request_version == "HTTP/0.9":
                # A request line too broken to name a version. Answer it like
                # any other, so that the headers below are always sent.
                self.request_version = "HTTP/1.0"
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            for name, value in SECURITY_HEADERS:
                self.send_header(name, value)
            if filename is not None:
                self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
            if close:
                self.send_header("Connection", "close")
            try:
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(data)
            except (BrokenPipeError, ConnectionResetError):
                # The browser closed the connection (a tab closed, a page left)
                # before the answer was sent. Nobody is waiting for it.
                self.close_connection = True

        def _refuse(self, status: int, message: str) -> None:
            """Answer without reading whatever the client is still sending."""
            self._reply(status, {"error": message}, close=True)

        def send_error(self, code: int, message: str | None = None,
                       explain: str | None = None) -> None:
            # The base class answers malformed requests itself, as an HTML
            # page. Give those the same plain JSON and headers as the rest.
            try:
                self._refuse(code, "The request could not be read.")
            except OSError:
                pass

        def _local(self) -> str | None:
            """Why this request did not come from this console's own page, or None."""
            hosts = self.headers.get_all("Host") or []
            if len(hosts) != 1 or not _LOCAL_HOST.match(hosts[0].strip()):
                return "This console only answers on 127.0.0.1."
            origin = self.headers.get("Origin")
            if origin is not None and origin != "http://" + hosts[0].strip():
                return "Requests from another origin are refused."
            return None

        def _body(self) -> Any:
            """The JSON body of a POST. Answers and returns None if it is refused."""
            kind = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
            if kind != "application/json":
                self._refuse(415, "Send JSON with Content-Type: application/json.")
                return None
            declared = self.headers.get("Content-Length")
            if declared is None:
                self._refuse(411, "A request body needs a Content-Length.")
                return None
            if not (declared.isascii() and declared.isdigit()):
                self._refuse(400, "The Content-Length is not a whole number.")
                return None
            if int(declared) > MAX_BODY:
                self._refuse(413, "The request body is larger than 256 KiB.")
                return None
            raw = self.rfile.read(int(declared))
            try:
                body = json.loads(raw or b"{}", parse_constant=_no_constants)
            except (ValueError, RecursionError):
                body = None
            if not isinstance(body, dict):
                self._reply(400, {"error": "The request body must be a JSON object."})
                return None
            return body

        def _serve(self) -> None:
            if not hasattr(self.headers, "get_all"):  # an HTTP/0.9 line has no headers
                return self._refuse(400, "The request could not be read.")
            method = self.command
            url = urlsplit(self.path)
            not_local = self._local()
            if not_local is not None:
                return self._refuse(403, not_local)
            if not url.path.startswith("/api/"):
                if method in ("GET", "HEAD") and url.path in files:
                    data, content_type = files[url.path]
                    return self._reply(200, data, content_type)
                return self._refuse(404, "There is nothing at this address.")
            given = (self.headers.get(TOKEN_HEADER) or "").encode("latin-1", "replace")
            if not hmac.compare_digest(given, secret):
                return self._refuse(401, "token required")
            if method not in ("GET", "POST"):
                return self._refuse(405, f"This address does not take {method} requests.")
            body = None
            if method == "POST":
                body = self._body()
                if body is None:
                    return None
            query = {key: values[-1] for key, values in parse_qs(url.query).items()}
            try:
                status, payload = app.handle(method, url.path, query, body)
                if isinstance(payload, Download):
                    return self._reply(
                        status, payload.data, payload.content_type, filename=payload.filename
                    )
                # Serialised here, so a payload that cannot be is a 500 like any other bug.
                data = json.dumps(payload, ensure_ascii=True, allow_nan=False).encode("ascii")
            except Exception:
                traceback.print_exc(file=sys.stderr)
                return self._reply(500, {"error": "internal error"})
            return self._reply(status, data)

        do_GET = do_POST = do_HEAD = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = _serve

    return Handler


def choose_token(token: str | None = None) -> str:
    """The console key: the one given, else COUNTERSIGN_TOKEN, else a new random one.

    There is no command-line option for it: a process's arguments can be read by
    every local user, its environment only by the same user.
    """
    token = token or os.environ.get(TOKEN_ENV) or secrets.token_urlsafe(24)
    if not _TOKEN.match(token):
        raise ValueError(
            "the console key must be 16 to 200 characters from A-Z, a-z, 0-9 and . _ ~ -"
        )
    return token


def make_server(
    port: int = DEFAULT_PORT,
    *,
    db: str | os.PathLike | None = None,
    inbox: str | os.PathLike | None = None,
    token: str | None = None,
) -> tuple[ThreadingHTTPServer, str]:
    """Bind the console to 127.0.0.1 and return (server, link to open).

    The link carries the key after the #, a part of the address a browser
    never sends to a server. Port 0 picks a free port. Raises ValueError for
    a bad key and OSError if the port is taken.
    """
    key = choose_token(token)
    server = ThreadingHTTPServer(("127.0.0.1", port), make_handler(App(db, inbox), key))
    server.daemon_threads = True
    return server, f"http://127.0.0.1:{server.server_address[1]}/#token={quote(key, safe='')}"


def serve(
    port: int = DEFAULT_PORT,
    *,
    db: str | os.PathLike | None = None,
    inbox: str | os.PathLike | None = None,
    token: str | None = None,
    open_browser: bool = False,
) -> None:
    """Run the console until Ctrl+C. With `db`, the live console is part of it."""
    server, link = make_server(port, db=db, inbox=inbox, token=token)
    print(f"Countersign console: {link}", flush=True)
    print("The link carries the key for this console. Ctrl+C stops the server.", flush=True)
    if open_browser:
        try:
            webbrowser.open(link)
        except Exception:  # no browser here; the link is on the terminal
            pass
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


def _command(args: argparse.Namespace) -> int:
    if args.db is not None:
        try:
            App(args.db).store()
        except ApiError as exc:
            print(f"countersign dashboard: {exc.message}", file=sys.stderr)
            return 2
    try:
        serve(args.port, db=args.db, inbox=args.inbox, open_browser=args.open)
    except ValueError as exc:
        print(f"countersign dashboard: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"countersign dashboard: cannot listen on port {args.port} ({exc})",
              file=sys.stderr)
        return 2
    return 0


def add_cli(subparsers: Any) -> None:
    parser = subparsers.add_parser(
        "dashboard",
        help="start the local web console",
        description="Start the web console on 127.0.0.1 and print the link to open. "
        "With --db it also shows the live session of that database.",
    )
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, metavar="N")
    parser.add_argument("--db", metavar="PATH", help="a Countersign database: adds the live console")
    parser.add_argument("--inbox", metavar="DIR",
                        help="the agent's document folder, shown in the MCP configuration")
    parser.add_argument(
        "--open", action="store_true",
        help="open the link in a browser (the browser is given the link, key included, on its "
        "command line, which other local users may be able to see)")
    parser.set_defaults(func=_command)
