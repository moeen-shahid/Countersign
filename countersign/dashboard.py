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
from .guard import DECLINED, UNCONFIRMED
from .iban import canonical_iban, find_ibans
from .models import Decision, Mandate, Outcome, clean_label, parse_amount, plain
from .policy import RULE_GUARDS, RULE_ORDER, RULE_OUTCOMES, RULES, rule_title
from .provenance import UNNAMED, USER_SOURCE
from .simulation import MODE_LABELS, MODES, Run, default_vendors, run_scenario
from .vendors import VendorFile

DEFAULT_PORT = 8377
MAX_BODY = 256 * 1024  # bytes; a longer POST is refused without being read
SOCKET_TIMEOUT = 15.0  # seconds a connection may stay silent
TOKEN_HEADER = "X-Countersign-Token"
TOKEN_ENV = "COUNTERSIGN_TOKEN"
APPROVER = "console"  # how the audit log names a decision made on this page
MAX_FUZZ_RUNS = 2000
MAX_TASK_HOURS = 24 * 31
APPROVERS = ("none", "careful", "careless")
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
    "An account typed in the instruction is trusted for the payee when the task has exactly "
    "one payee and the vendor file has no account for that payee. Whoever can type the "
    "instruction is the user.",
    "Origin tracking sees only what the agent reads through the guard. An account the agent "
    "learned any other way counts as seen nowhere, and the payment is refused.",
    "A payee with no payment history on file has no usual amount, so the unusual-amount rule "
    "does not apply to it.",
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
    for match in find_ibans(text):
        owner = vendors.owner_of(match.account)
        accounts.append(
            {
                "account": match.account,
                "start": at(match.start),
                "end": at(match.end),
                "on_file_for": owner.name if owner is not None else None,
                "attacker": None if attackers is None else match.account in attackers,
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


def _has_hidden_text(scenario: Any) -> bool:
    return any(
        hidden for text in scenario.documents.values() for _, _, hidden in _segments(text)
    )


def scenario_summary(scenario: Any) -> dict[str, Any]:
    return {
        "id": scenario.id,
        "title": scenario.title,
        "kind": scenario.kind,
        "family": scenario.family,
        "summary": scenario.summary,
        "known_gap": bool(scenario.known_miss),
    }


def scenario_view(scenario: Any, vendors: VendorFile) -> dict[str, Any]:
    attackers = _attackers(scenario)
    view = scenario_summary(scenario)
    view["instruction"] = scenario.instruction
    view["documents"] = [
        document_view(name, text, vendors, attackers)
        for name, text in scenario.documents.items()
    ]
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


def _hold_info(hold: Mapping[str, Any] | None) -> dict[str, Any] | None:
    if hold is None:
        return None
    return {
        "id": hold["id"],
        "digest": hold["digest"],
        "status": hold["status"],
        "decided_by": hold.get("decided_by"),
        "attestation": hold.get("attestation"),
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
) -> dict[str, Any]:
    """One payment the agent asked for, with the guard's answer and what became of it."""
    rule = str(decision.get("rule") or "")
    return {
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
        "hold": _hold_info(hold),
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


def _lab_texts(scenario: Any) -> dict[str, str]:
    """The texts of a replay under the names the guard uses for them in evidence."""
    texts = {USER_SOURCE: scenario.instruction}
    for name, text in scenario.documents.items():
        texts.setdefault(clean_label(name) or UNNAMED, text)
    return texts


REPEATED = (
    "The bank had already sent exactly this payment in this task ({transfer}), so it sent "
    "nothing new for this request."
)


def run_state(run: Run, refusals: Mapping[str, Decision] | None = None) -> dict[str, Any]:
    """One scenario replayed under one guard, as the contract's RunState.

    `refusals` holds, per hold id, the guard's answer to an approval that it
    refused. The totals are the replay's own (`Run.unauthorised_paid`,
    `Run.to_attacker_paid`), the same numbers the benchmark reports.
    """
    scenario, guard = run.scenario, run.guard
    attackers = _attackers(scenario)
    texts = _lab_texts(scenario)
    refusals = refusals or {}
    attempts = []
    sent: dict[str, str | None] = {}  # transfer id -> the hold it was paid through

    for index, (attempt, result) in enumerate(zip(scenario.attempts, run.results)):
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
        note = attempt.note
        if transfer_id is not None:
            if transfer_id in sent and sent[transfer_id] != result.hold_id:
                # The same request twice: the bank answers the second with the
                # first transfer. Say so, or the lane would show money that never moved.
                note = (note + " " if note else "") + REPEATED.format(transfer=transfer_id)
            sent.setdefault(transfer_id, result.hold_id)
        amount = request.amount if request is not None and request.amount is not None else None
        attempts.append(
            attempt_view(
                index,
                payee=request.payee if request is not None else str(attempt.payee),
                account=account,
                account_raw=str(attempt.account),
                amount=plain(amount) if amount is not None else _amount_text(attempt.amount),
                reference=str(attempt.reference),
                decision=decision,
                texts=texts,
                hold=hold,
                transfer_id=transfer_id,
                status=run.status(index),
                legit=bool(attempt.legit),
                to_attacker=None if attackers is None else account in attackers,
                note=note,
            )
        )

    wanted = {transfer.id: bool(attempt.legit) for attempt, transfer in run.payments()}
    audit = None
    if guard is not None:
        # A copy: the answer must not change when the log does.
        entries = copy.deepcopy(guard.audit.entries)
        intact, broken_at = verify_entries(entries)
        audit = audit_view(entries, intact, broken_at)
    return {
        "mode": run.mode,
        "mode_label": MODE_LABELS[run.mode],
        "mandate": None if guard is None else run.mandate.to_dict(),
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
        "scenarios": [
            {**scenario_summary(scenario), "hidden_text": _has_hidden_text(scenario)}
            for scenario in scenarios.SCENARIOS
        ],
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
    }


def _live_attempts(
    snapshot: Mapping[str, Any], since: int, texts: Mapping[str, str]
) -> list[dict[str, Any]]:
    """Every payment the agent asked for since the task began, oldest first.

    Read from the `payment_decision` entries of the audit log. What became of
    a hold, and its transfer, come from the guard's state.
    """
    entries = [entry for entry in snapshot["entries"] if isinstance(entry, dict)]
    holds = {hold["id"]: hold for hold in snapshot["state"].get("holds") or ()}
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
        if hold is not None:
            transfer_id = hold.get("transfer_id")
            status = {"pending": "held", "approved": "paid"}.get(hold["status"], hold["status"])
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


def draft(instruction: str, vendor_names: Iterable[str]) -> dict[str, Any]:
    """What can be read out of a sentence before a task is confirmed.

    A convenience for the person filling in the form: it changes nothing and
    decides nothing. The person still ticks the payees.
    """
    names = list(vendor_names)
    from .console import draft_payees  # the same suggestion the command line makes

    payees = draft_payees(instruction, names)
    found = find_ibans(instruction)
    amounts = []
    for match in _AMOUNT_IN_TEXT.finditer(instruction):
        if any(iban.start < match.end() and match.start() < iban.end for iban in found):
            continue  # digits of an account number, not an amount
        amount = parse_amount(match.group().replace(",", ""))
        if amount is not None:
            amounts.append(plain(amount))
    return {
        "payees": payees,
        "accounts": list(dict.fromkeys(iban.account for iban in found)),
        "amounts": list(dict.fromkeys(amounts)),
    }


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
        digest = _text(body, "digest", 200)
        attestation = _text(body, "attestation", 200, "")
        remember = _flag(body, "remember_account")
        with self._lock:
            lab, run = self._countersign_run()
            self._untampered(lab)
            try:
                result = run.guard.approve(
                    hold_id, APPROVER, remember_account=remember, digest=digest,
                    attestation=attestation,
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
            try:
                run.guard.reject(hold_id, APPROVER)
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
            raise ApiError(400, "The approver must be none, careful or careless.")
        from .benchmark import run_benchmark

        return run_benchmark(approver=approver)

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
        vendors = self._with_store(lambda store: store.state())["vendors"]
        return draft(instruction, [vendor["name"] for vendor in vendors])

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
            )
            self._with_store(
                lambda s: s.console().start_task(mandate, confirmed_by=APPROVER)
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

        def approve(store: Any) -> Any:
            return store.console().approve(
                hold_id, approver=APPROVER, digest=digest, attestation=attestation,
                remember_account=remember,
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
        try:
            self._with_store(lambda store: store.console().reject(hold_id, approver=APPROVER))
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
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(data)

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
