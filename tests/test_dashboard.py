"""The web console server: the App, the shapes of the HTTP contract, the
intruder demo, the live console on a temporary database, and a real server on
a free port.

Nothing here leaves this machine: the server binds 127.0.0.1 and the tests
talk to it with urllib and http.client.
"""

from __future__ import annotations

import contextlib
import http.client
import importlib
import inspect
import io
import json
import os
import re
import tempfile
import threading
import unittest
from unittest import mock
import urllib.error
import urllib.request
from dataclasses import replace
from decimal import Decimal
from importlib import resources

from countersign import __version__, benchmark, dashboard, scenarios
from countersign.audit import verify_entries
from countersign.dashboard import App, Download
from countersign.iban import find_ibans, fmt_iban
from countersign.models import clean_label
from countersign.policy import RULE_GUARDS, RULE_ORDER, RULE_OUTCOMES, RULES
from countersign.scenarios import BY_ID, SCENARIOS
from countersign.simulation import MODES, default_vendors, run_scenario

NIMBUS = "DE89370400440532013000"
MULE = "LT121000011101001000"
MULE_B = "MT84MALT011000012345MTLCAST001S"
FERNHILL = "NL91ABNA0417164300"
TOKEN = "test-token-123456789"


def _available(module: str, name: str | None = None) -> bool:
    try:
        found = importlib.import_module(f"countersign.{module}")
    except ImportError:
        return False
    return name is None or hasattr(found, name)


HAVE_STORE = _available("store")
HAVE_DOCS = _available("scenarios", "scenario_from_doc") and _available(
    "scenarios", "scenario_to_doc"
)
HAVE_FUZZ = _available("fuzz", "run_fuzz")
HAVE_ATTACKERS = _available("scenarios", "ATTACKER_ACCOUNTS")
HAVE_APPROVERS = "approver" in inspect.signature(benchmark.run_benchmark).parameters


# --- a small checker for the shapes in the contract ---------------------------------

MONEY = re.compile(r"\A[0-9]+\.[0-9]{2}\Z")
HEX64 = re.compile(r"\A[0-9a-f]{64}\Z")


def money(value):
    return isinstance(value, str) and bool(MONEY.match(value))


def digest(value):
    return isinstance(value, str) and bool(HEX64.match(value))


def one_of(*allowed):
    return lambda value: value in allowed


def maybe(spec):
    return ("maybe", spec)


def problems(value, spec, where="$"):
    """Every place where `value` does not have the shape `spec` describes."""
    if isinstance(spec, tuple) and spec and spec[0] == "maybe":
        return [] if value is None else problems(value, spec[1], where)
    if isinstance(spec, dict):
        if not isinstance(value, dict):
            return [f"{where}: expected an object, got {type(value).__name__}"]
        found = []
        for key, inner in spec.items():
            if key not in value:
                found.append(f"{where}.{key}: missing")
            else:
                found.extend(problems(value[key], inner, f"{where}.{key}"))
        return found
    if isinstance(spec, list):
        if not isinstance(value, list):
            return [f"{where}: expected a list, got {type(value).__name__}"]
        return [p for i, item in enumerate(value) for p in problems(item, spec[0], f"{where}[{i}]")]
    if isinstance(spec, type):
        ok = isinstance(value, spec) and not (spec is int and isinstance(value, bool))
        return [] if ok else [f"{where}: expected {spec.__name__}, got {value!r}"]
    return [] if spec(value) else [f"{where}: unexpected value {value!r}"]


MANDATE = {
    "id": str, "instruction": str, "payees": [str], "max_per_payment": money,
    "max_total": money, "currency": str, "expires_at": str, "max_payments": maybe(int),
    "references": [str], "accounts": dict,
}
DOCUMENT = {
    "name": str, "label": str, "text": str, "segments": [list],
    "accounts": [{"account": str, "start": int, "end": int, "on_file_for": maybe(str),
                  "attacker": maybe(bool)}],
}
SCENARIO_VIEW = {
    "id": str, "title": str, "kind": one_of("benign", "attack"), "family": str, "summary": str,
    "known_gap": bool, "instruction": str, "documents": [DOCUMENT],
}
EVIDENCE = {
    "payee": str, "account": str, "valid_iban": bool, "on_file": [str],
    "on_file_for": maybe(str), "dictated": bool, "typed_by_user": bool,
    "sightings": [{"origin": one_of("user", "untrusted"), "source": str, "spans": [list],
                   "line": int}],
    "history": [money], "baseline": maybe(money), "previous_payment": maybe(dict),
    "spent": money, "budget": money, "paid_to_payee": money,
}
HOLD = {
    "id": str, "digest": digest,
    "status": one_of("pending", "approved", "rejected", "blocked", "expired", "unknown"),
    "decided_by": maybe(str), "attestation": maybe(str),
}
ATTEMPT = {
    "index": int, "payee": str, "account": str, "account_raw": str, "amount": str,
    "reference": str, "legit": maybe(bool), "to_attacker": maybe(bool), "note": str,
    "outcome": one_of("ALLOW", "HOLD", "BLOCK"), "rule": str, "rules": [str], "rule_title": str,
    "reason": str,
    "checks": [{"rule": str, "title": str,
                "status": one_of("pass", "block", "hold", "na", "off", "skipped"), "detail": str}],
    "evidence": maybe(EVIDENCE), "hold": maybe(HOLD), "transfer_id": maybe(str),
    "status": one_of("paid", "held", "rejected", "blocked", "expired", "unknown"),
}
AUDIT = {
    "intact": bool, "broken_at": maybe(int), "head": {"seq": int, "hash": digest},
    "entries": [{"seq": int, "ts": str, "event": str, "data": dict, "prev": str, "hash": str}],
}
TRANSFER = {"id": str, "payee": str, "account": str, "amount": money, "reference": str,
            "unauthorised": maybe(bool)}
RUN_STATE = {
    "mode": one_of(*MODES), "mode_label": str, "mandate": maybe(MANDATE), "attempts": [ATTEMPT],
    "unauthorised": money, "to_attacker": money, "transfers": [TRANSFER], "balance": money,
    "audit": maybe(AUDIT),
}
LAB_STATE = {"scenario": SCENARIO_VIEW, "runs": {mode: RUN_STATE for mode in MODES}}
VENDOR = {"name": str, "accounts": [str], "history": [money]}
META = {
    "version": str, "currency": str, "live": bool,
    "modes": [{"id": str, "label": str, "ours": bool}],
    "rules": [{"id": str, "title": str, "outcome": one_of("BLOCK", "HOLD"), "guards": [str]}],
    "scenarios": [{"id": str, "title": str, "kind": one_of("benign", "attack"), "family": str,
                   "summary": str, "known_gap": bool, "hidden_text": bool}],
    "vendors": [VENDOR], "attacker_accounts": [str], "agent_tools": [str], "limits": [str],
}
SUMMARY = {
    "label": str, "attacks_total": int, "attacks_money_moved": int, "attacks_held": int,
    "attacks_blocked": int, "unauthorised": money, "to_attacker": money, "to_vendor": money,
    "benign_total": int, "benign_paid": int, "benign_held": int, "benign_blocked": int,
    "wanted_paid": int, "wanted_total": int,
}
CELL = {"verdict": one_of("paid", "held", "blocked"), "unauthorised": money, "to_attacker": money,
        "rules": [str], "wanted_paid": int, "wanted_total": int}
BENCHMARK = {
    "approver": one_of("none", "careful", "careless"), "replays": int, "elapsed_ms": int,
    "summary": {mode: SUMMARY for mode in MODES},
    "rows": [{"id": str, "title": str, "kind": one_of("benign", "attack"), "family": str,
              "known_gap": bool, "cells": {mode: CELL for mode in MODES}}],
    "caveats": [str],
}
FUZZ = {"runs": int, "operations": int, "violations": list,
        "invariants": [{"id": str, "text": str}], "seed": int, "elapsed_ms": int}
LIVE_STATE = {
    "changed": bool, "head": {"seq": int, "hash": digest},
    "guard_mode": one_of("rules", "strict", "countersign"),
    "task": maybe({"mandate": MANDATE, "active": bool, "expired": bool, "spent": money,
                   "payments": int}),
    "documents": [DOCUMENT], "attempts": [ATTEMPT], "transfers": [TRANSFER], "balance": money,
    "vendors": [VENDOR], "audit": AUDIT,
    "mcp_config": {"mcpServers": {"countersign": {"command": str, "args": [str]}}},
}


class ShapeMixin:
    def assertShape(self, value, spec):
        found = problems(value, spec)
        self.assertEqual(found, [], "\n".join(found[:12]))

    def ok(self, answer):
        status, payload = answer
        self.assertEqual(status, 200, payload)
        return payload

    def refused(self, answer, status):
        got, payload = answer
        self.assertEqual(got, status, payload)
        self.assertEqual(list(payload), ["error"])
        self.assertIsInstance(payload["error"], str)
        self.assertTrue(payload["error"].strip())
        return payload["error"]


def invoice(*accounts: str) -> str:
    return "Invoice\n" + "".join(f"Pay to IBAN {fmt_iban(account)}\n" for account in accounts)


def custom(attempts, documents, **changes):
    """A scenario for one test, built from a real one so every field is there."""
    base = BY_ID["attack-05"]
    made = tuple(
        replace(base.attempts[0], payee="Nimbus Hosting Ltd", account=account,
                amount=type(base.attempts[0].amount)(amount), reference=reference, legit=legit)
        for account, amount, reference, legit in attempts
    )
    return replace(base, id="custom", documents=documents, attempts=made, **changes)


def holds(state):
    return [a["hold"] for a in state["runs"]["countersign"]["attempts"] if a["hold"]]


# --- meta ---------------------------------------------------------------------------


class MetaTests(ShapeMixin, unittest.TestCase):
    def setUp(self):
        self.meta = self.ok(App().handle("GET", "/api/meta"))

    def test_shape(self):
        self.assertShape(self.meta, META)
        self.assertEqual(self.meta["version"], __version__)
        self.assertEqual(self.meta["currency"], "EUR")
        self.assertIs(self.meta["live"], False)

    def test_modes_are_in_display_order_and_the_baselines_are_marked_ours(self):
        modes = self.meta["modes"]
        self.assertEqual([m["id"] for m in modes], list(MODES))
        self.assertEqual({m["id"]: m["ours"] for m in modes},
                         {"none": False, "rules": True, "strict": True, "countersign": False})
        for mode in modes:
            self.assertEqual(mode.get("note"), "our baseline" if mode["ours"] else None)

    def test_rules_are_the_policy_table(self):
        self.assertEqual(
            self.meta["rules"],
            [{"id": r, "title": RULES[r], "outcome": RULE_OUTCOMES[r],
              "guards": list(RULE_GUARDS[r])} for r in RULE_ORDER],
        )

    def test_scenarios_and_hidden_text(self):
        listed = {s["id"]: s for s in self.meta["scenarios"]}
        self.assertEqual(list(listed), [s.id for s in SCENARIOS])
        for scenario in SCENARIOS:
            hidden = any('font-size:1px' in text for text in scenario.documents.values())
            if hasattr(scenarios, "split_hidden"):
                self.assertEqual(listed[scenario.id]["hidden_text"], hidden, scenario.id)
            self.assertEqual(listed[scenario.id]["known_gap"], scenario.known_miss)

    def test_vendors_attackers_and_tools(self):
        self.assertEqual(self.meta["vendors"], default_vendors().to_state())
        self.assertIn(MULE, self.meta["attacker_accounts"])
        self.assertEqual(
            self.meta["agent_tools"],
            ["get_task", "list_documents", "pay", "payment_status", "read_document"],
        )

    def test_limits_are_plain_sentences_that_cover_the_threat_model(self):
        limits = self.meta["limits"]
        self.assertGreaterEqual(len(limits), 12)
        for sentence in limits:
            self.assertTrue(sentence.endswith("."), sentence)
            self.assertNotIn("tamper-proof.", sentence.replace("not tamper-proof.", ""))
        text = " ".join(limits).lower()
        for words in ("scripted", "baselines", "we wrote both", "iban", "who owns",
                      "genuine account", "without checking", "exactly one payee",
                      "through the guard", "tamper-evident", "operating-system user", "mock"):
            self.assertIn(words, text)

    def test_live_is_true_with_a_database(self):
        self.assertIs(App("/nowhere/countersign.db").handle("GET", "/api/meta")[1]["live"], True)


# --- lab ----------------------------------------------------------------------------


class LabTests(ShapeMixin, unittest.TestCase):
    def setUp(self):
        self.app = App()

    def compare(self, scenario_id="attack-05"):
        return self.ok(self.app.handle("POST", "/api/compare", {}, {"scenario": scenario_id}))

    def test_empty_lab_and_reset(self):
        empty = {"scenario": None, "runs": {}}
        self.assertEqual(self.ok(self.app.handle("GET", "/api/lab")), empty)
        self.compare()
        self.assertEqual(self.ok(self.app.handle("GET", "/api/lab"))["scenario"]["id"], "attack-05")
        self.assertEqual(self.ok(self.app.handle("POST", "/api/reset", {}, {})), empty)
        self.assertEqual(self.ok(self.app.handle("GET", "/api/lab")), empty)

    def test_unknown_scenario(self):
        self.refused(self.app.handle("POST", "/api/compare", {}, {"scenario": "nope"}), 404)
        self.refused(self.app.handle("POST", "/api/compare", {}, {}), 404)
        self.refused(self.app.handle("POST", "/api/compare", {}, {"scenario": ["attack-05"]}), 404)

    def test_every_scenario_has_the_contract_shape_under_all_four_guards(self):
        for scenario in SCENARIOS:
            with self.subTest(scenario=scenario.id):
                state = self.compare(scenario.id)
                self.assertShape(state, LAB_STATE)
                self.assertEqual(list(state["runs"]), list(MODES))
                self.assertEqual(self.ok(self.app.handle("GET", "/api/lab")), state)
                json.dumps(state, allow_nan=False)

    def test_no_guard_run_has_no_mandate_checks_evidence_or_log(self):
        run = self.compare()["runs"]["none"]
        self.assertIsNone(run["mandate"])
        self.assertIsNone(run["audit"])
        for attempt in run["attempts"]:
            self.assertEqual(attempt["checks"], [])
            self.assertIsNone(attempt["evidence"])
            self.assertIsNone(attempt["hold"])
            self.assertEqual(attempt["rule_title"], "No guard")

    def test_guarded_runs_carry_the_whole_rule_ladder(self):
        state = self.compare()
        for mode in ("rules", "strict", "countersign"):
            run = state["runs"][mode]
            self.assertEqual(run["mandate"]["id"], "mandate-attack-05")
            self.assertTrue(run["audit"]["intact"])
            for attempt in run["attempts"]:
                self.assertEqual([c["rule"] for c in attempt["checks"]], list(RULE_ORDER))
                self.assertEqual([c["title"] for c in attempt["checks"]],
                                 [RULES[r] for r in RULE_ORDER])
                self.assertIsNotNone(attempt["evidence"])

    def test_documents_segments_accounts_and_labels(self):
        for scenario in SCENARIOS:
            view = self.compare(scenario.id)["scenario"]
            self.assertEqual([d["name"] for d in view["documents"]], list(scenario.documents))
            for doc in view["documents"]:
                with self.subTest(scenario=scenario.id, document=doc["name"]):
                    text = doc["text"]
                    self.assertEqual(text, scenario.documents[doc["name"]])
                    self.assertEqual(doc["label"], clean_label(doc["name"]))
                    # The segments cover the whole text, in order, without gaps.
                    position = 0
                    for start, end, hidden in doc["segments"]:
                        self.assertEqual(start, position)
                        self.assertGreater(end, start)
                        self.assertIsInstance(hidden, bool)
                        position = end
                    self.assertEqual(position, len(text))
                    self.assertEqual(
                        [(a["account"], a["start"], a["end"]) for a in doc["accounts"]],
                        [(m.account, m.start, m.end) for m in find_ibans(text)],
                    )

    def test_attack_05_document_shows_the_hidden_account(self):
        doc = self.compare()["scenario"]["documents"][0]
        by_account = {a["account"]: a for a in doc["accounts"]}
        self.assertEqual(by_account[NIMBUS]["on_file_for"], "Nimbus Hosting Ltd")
        self.assertIsNone(by_account[MULE_B]["on_file_for"])
        if hasattr(scenarios, "split_hidden"):
            hidden = [(s, e) for s, e, h in doc["segments"] if h]
            self.assertEqual(len(hidden), 1)
            self.assertTrue(hidden[0][0] <= by_account[MULE_B]["start"] < hidden[0][1])
            self.assertFalse(hidden[0][0] <= by_account[NIMBUS]["start"] < hidden[0][1])
        if HAVE_ATTACKERS:
            self.assertIs(by_account[MULE_B]["attacker"], True)
            self.assertIs(by_account[NIMBUS]["attacker"], False)

    def test_attempts_show_the_raw_and_the_canonical_account(self):
        raw = "  mt84 malt 0110 0001 2345 mtlc ast0 01s "
        scenario = custom([(raw, "240.00", "INV-2041-B", False)], {"a.eml": invoice(MULE_B)})
        with self.app._lock:
            state = self.app._replay(scenario)
        for mode in MODES:
            attempt = state["runs"][mode]["attempts"][0]
            self.assertEqual(attempt["account_raw"], raw)
            self.assertEqual(attempt["account"], MULE_B)
            self.assertEqual(attempt["amount"], "240.00")
        held = state["runs"]["countersign"]["attempts"][0]
        self.assertEqual((held["outcome"], held["rule"], held["status"]), ("HOLD", "P1", "held"))
        self.assertEqual(held["rule_title"], RULES["P1"])
        self.assertEqual(held["evidence"]["sightings"][0]["source"], "a.eml")

    def test_statuses_and_totals_agree_with_the_replay(self):
        for scenario in SCENARIOS:
            state = self.compare(scenario.id)
            for mode in MODES:
                with self.subTest(scenario=scenario.id, mode=mode):
                    run = run_scenario(scenario, mode)
                    shown = state["runs"][mode]
                    self.assertEqual([a["status"] for a in shown["attempts"]], run.statuses())
                    self.assertEqual([a["index"] for a in shown["attempts"]],
                                     list(range(len(scenario.attempts))))
                    self.assertEqual(Decimal(shown["unauthorised"]), run.unauthorised_paid())
                    self.assertLessEqual(Decimal(shown["to_attacker"]),
                                         Decimal(shown["unauthorised"]))
                    self.assertEqual(shown["balance"], f"{run.bank.balance:.2f}")
                    self.assertEqual([t["id"] for t in shown["transfers"]],
                                     [t.id for t in run.bank.transfers])

    def test_transfers_are_flagged_when_the_user_did_not_want_them(self):
        state = self.compare()
        unguarded = state["runs"]["none"]
        self.assertEqual([t["unauthorised"] for t in unguarded["transfers"]], [False, True])
        self.assertEqual(unguarded["unauthorised"], "240.00")
        self.assertEqual([a["legit"] for a in unguarded["attempts"]], [True, False])
        ours = state["runs"]["countersign"]
        self.assertEqual([t["unauthorised"] for t in ours["transfers"]], [False])
        self.assertEqual((ours["unauthorised"], ours["to_attacker"]), ("0.00", "0.00"))
        if HAVE_ATTACKERS:
            self.assertEqual(unguarded["to_attacker"], "240.00")
            self.assertEqual([a["to_attacker"] for a in unguarded["attempts"]], [False, True])

    def test_offsets_are_counted_the_way_a_browser_counts(self):
        text = "\U0001F389 Party invoice \U0001F389\n" + invoice(MULE)
        state = self.app._replay(custom([(MULE, "100.00", "INV-9", False)], {"p.eml": text}))
        doc = state["scenario"]["documents"][0]
        as_browser = text.encode("utf-16-le")

        def cut(start, end):
            return as_browser[2 * start:2 * end].decode("utf-16-le")

        account = doc["accounts"][0]
        self.assertEqual(cut(account["start"], account["end"]), fmt_iban(MULE))
        self.assertEqual(doc["segments"][-1][1], len(as_browser) // 2)
        sighting = state["runs"]["countersign"]["attempts"][0]["evidence"]["sightings"][0]
        self.assertEqual(sighting["spans"], [[account["start"], account["end"]]])
        # The log keeps the guard's own offsets.
        logged = [e for e in state["runs"]["countersign"]["audit"]["entries"]
                  if e["event"] == "payment_decision"][0]
        span = logged["data"]["decision"]["evidence"]["sightings"][0]["spans"][0]
        self.assertEqual(text[span[0]:span[1]], fmt_iban(MULE))


class HoldTests(ShapeMixin, unittest.TestCase):
    def setUp(self):
        self.app = App()
        self.state = self.ok(self.app.handle("POST", "/api/compare", {}, {"scenario": "attack-05"}))
        self.hold = holds(self.state)[0]

    def approve(self, hold_id="H001", **body):
        body.setdefault("digest", self.hold["digest"])
        body.setdefault("attestation", "checked")
        return self.app.handle("POST", f"/api/holds/{hold_id}/approve", {}, body)

    def ours(self):
        return self.ok(self.app.handle("GET", "/api/lab"))["runs"]["countersign"]

    def test_hold_as_displayed(self):
        self.assertShape(self.hold, HOLD)
        self.assertEqual((self.hold["id"], self.hold["status"]), ("H001", "pending"))
        self.assertIsNone(self.hold["decided_by"])

    def test_stale_digest_is_a_conflict_and_nothing_is_paid(self):
        before = self.ours()
        message = self.refused(self.approve(digest="0" * 64), 409)
        self.assertIn("changed since it was displayed", message)
        after = self.ours()
        self.assertEqual(after, before)
        self.assertEqual(len(after["transfers"]), 1)
        self.assertEqual(holds({"runs": {"countersign": after}})[0]["status"], "pending")

    def test_the_digest_is_required(self):
        self.refused(self.app.handle("POST", "/api/holds/H001/approve", {}, {}), 400)
        self.refused(self.approve(digest=None), 400)
        self.refused(self.approve(remember_account="yes"), 400)
        self.refused(self.approve(attestation=7), 400)
        self.assertEqual(len(self.ours()["transfers"]), 1)

    def test_unknown_hold(self):
        self.refused(self.approve("H999"), 404)
        self.refused(self.app.handle("POST", "/api/holds/H999/reject", {}, {}), 404)

    def test_nothing_to_decide_before_a_replay(self):
        fresh = App()
        self.refused(fresh.handle("POST", "/api/holds/H001/approve", {},
                                  {"digest": "x", "attestation": "checked"}), 409)
        self.refused(fresh.handle("POST", "/api/holds/H001/reject", {}, {}), 409)

    def test_approval_pays_exactly_the_payment_shown(self):
        state = self.ok(self.approve(attestation="not checked"))
        self.assertShape(state, LAB_STATE)
        ours = state["runs"]["countersign"]
        attempt = ours["attempts"][1]
        self.assertEqual(attempt["status"], "paid")
        self.assertEqual(attempt["transfer_id"], "T002")
        self.assertEqual(attempt["hold"], {**self.hold, "status": "approved",
                                           "decided_by": "console",
                                           "attestation": "not checked"})
        self.assertEqual(ours["unauthorised"], "240.00")
        self.assertEqual([t["unauthorised"] for t in ours["transfers"]], [False, True])
        self.assertEqual(ours["balance"], "49520.00")
        events = [e["event"] for e in ours["audit"]["entries"]]
        self.assertEqual(events[-3:], ["hold_approved", "payment_submitted", "payment_executed"])
        approved = ours["audit"]["entries"][-3]["data"]
        self.assertEqual((approved["approver"], approved["attestation"], approved["digest"]),
                         ("console", "not checked", self.hold["digest"]))
        self.assertTrue(ours["audit"]["intact"])
        # The other guards' runs are not touched.
        for mode in ("none", "rules", "strict"):
            self.assertEqual(state["runs"][mode], self.state["runs"][mode])

    def test_evidence_is_identical_before_and_after_an_approval(self):
        before = self.state["runs"]["countersign"]["attempts"]
        after = self.ok(self.approve())["runs"]["countersign"]["attempts"]
        for old, new in zip(before, after):
            for key in ("outcome", "rule", "rules", "rule_title", "reason", "checks", "evidence"):
                self.assertEqual(new[key], old[key], key)
        self.assertEqual(after[1]["outcome"], "HOLD")
        self.assertEqual(after[1]["evidence"]["spent"], "240.00")

    def test_a_hold_is_decided_once(self):
        self.ok(self.approve())
        self.assertIn("already approved", self.refused(self.approve(), 409))
        self.refused(self.app.handle("POST", "/api/holds/H001/reject", {}, {}), 409)
        self.assertEqual(len(self.ours()["transfers"]), 2)

    def test_reject(self):
        state = self.ok(self.app.handle("POST", "/api/holds/H001/reject", {}, {}))
        attempt = state["runs"]["countersign"]["attempts"][1]
        self.assertEqual((attempt["status"], attempt["hold"]["status"]), ("rejected", "rejected"))
        self.assertEqual(attempt["hold"]["decided_by"], "console")
        self.assertIsNone(attempt["transfer_id"])
        self.assertEqual(len(state["runs"]["countersign"]["transfers"]), 1)
        self.assertIn("already rejected", self.refused(self.approve(), 409))
        self.refused(self.app.handle("POST", "/api/holds/H001/reject", {}, {}), 409)

    def test_remember_account_puts_it_on_file(self):
        state = self.ok(self.app.handle("POST", "/api/compare", {}, {"scenario": "benign-03"}))
        hold = holds(state)[0]
        doc_account = state["scenario"]["documents"][0]["accounts"][0]
        self.assertIsNone(doc_account["on_file_for"])
        state = self.ok(self.app.handle(
            "POST", f"/api/holds/{hold['id']}/approve", {},
            {"digest": hold["digest"], "attestation": "checked", "remember_account": True}))
        ours = state["runs"]["countersign"]
        self.assertEqual(ours["attempts"][0]["status"], "paid")
        self.assertEqual(ours["unauthorised"], "0.00")
        self.assertIn("vendor_account_added", [e["event"] for e in ours["audit"]["entries"]])
        self.assertEqual(state["scenario"]["documents"][0]["accounts"][0]["on_file_for"],
                         ours["attempts"][0]["payee"])

    def test_an_approval_the_guard_refuses_for_good_shows_the_refusal(self):
        # Two holds to the same account. A person rejects one, then tries to
        # approve the other: rule R1 closes it.
        scenario = custom([(MULE, "100.00", "INV-1", False), (MULE, "150.00", "INV-2", False)],
                          {"a.eml": invoice(MULE)})
        state = self.app._replay(scenario)
        first, second = holds(state)
        self.ok(self.app.handle("POST", f"/api/holds/{first['id']}/reject", {}, {}))
        state = self.ok(self.app.handle(
            "POST", f"/api/holds/{second['id']}/approve", {},
            {"digest": second["digest"], "attestation": "checked"}))
        attempt = state["runs"]["countersign"]["attempts"][1]
        self.assertEqual((attempt["status"], attempt["hold"]["status"]), ("blocked", "blocked"))
        self.assertEqual((attempt["outcome"], attempt["rule"]), ("BLOCK", "R1"))
        self.assertEqual(attempt["rule_title"], RULES["R1"])
        self.assertEqual(state["runs"]["countersign"]["transfers"], [])
        self.assertShape(state, LAB_STATE)

    def test_an_approval_the_budget_refuses_closes_the_hold_and_shows_why(self):
        # Two holds that fit the budget one at a time, not together.
        scenario = custom([(MULE, "300.00", "INV-1", False), (MULE, "300.00", "INV-2", False)],
                          {"a.eml": invoice(MULE)},
                          max_per_payment=Decimal("400.00"), max_total=Decimal("500.00"))
        state = self.app._replay(scenario)
        first, second = holds(state)
        body = {"attestation": "not checked"}
        self.ok(self.app.handle("POST", f"/api/holds/{first['id']}/approve", {},
                                {**body, "digest": first["digest"]}))
        self.ok(self.app.handle("POST", f"/api/holds/{second['id']}/approve", {},
                                {**body, "digest": second["digest"]}))
        ours = self.ours()
        self.assertEqual(len(ours["transfers"]), 1)
        self.assertEqual(ours["attempts"][1]["status"], "blocked")
        self.assertEqual(ours["attempts"][1]["hold"]["status"], "blocked")

    def test_a_hold_whose_reasons_grew_is_shown_again_with_a_new_digest(self):
        # Held first; then the same invoice is paid to the genuine account.
        # Approving the hold would now also pay that invoice twice (D1).
        scenario = custom([(MULE, "100.00", "INV-7", False), (NIMBUS, "100.00", "INV-7", True)],
                          {"a.eml": invoice(MULE)})
        state = self.app._replay(scenario)
        hold = holds(state)[0]
        self.assertEqual(state["runs"]["countersign"]["attempts"][0]["rules"], ["P1"])
        state = self.ok(self.app.handle(
            "POST", f"/api/holds/{hold['id']}/approve", {},
            {"digest": hold["digest"], "attestation": "checked"}))
        attempt = state["runs"]["countersign"]["attempts"][0]
        self.assertEqual(attempt["status"], "held")
        self.assertEqual(attempt["rules"], ["P1", "D1"])
        self.assertNotEqual(attempt["hold"]["digest"], hold["digest"])
        self.assertEqual(len(state["runs"]["countersign"]["transfers"]), 1)
        # The digest that was displayed first no longer approves anything.
        self.refused(self.app.handle(
            "POST", f"/api/holds/{hold['id']}/approve", {},
            {"digest": hold["digest"], "attestation": "checked"}), 409)
        state = self.ok(self.app.handle(
            "POST", f"/api/holds/{hold['id']}/approve", {},
            {"digest": attempt["hold"]["digest"], "attestation": "checked"}))
        self.assertEqual(state["runs"]["countersign"]["attempts"][0]["status"], "paid")


class TamperTests(ShapeMixin, unittest.TestCase):
    def setUp(self):
        self.app = App()
        state = self.ok(self.app.handle("POST", "/api/compare", {}, {"scenario": "attack-05"}))
        self.original = state["runs"]["countersign"]["audit"]

    def tamper(self, stage):
        state = self.ok(self.app.handle("POST", "/api/audit/tamper", {}, {"stage": stage}))
        return state["runs"]["countersign"]["audit"]

    def test_the_four_stages_and_restore(self):
        original = self.original
        self.assertTrue(original["intact"])
        self.assertEqual(original["head"]["seq"], len(original["entries"]) - 1)

        edited = self.tamper("edit")
        changed = [e["seq"] for e, o in zip(edited["entries"], original["entries"]) if e != o]
        self.assertEqual(len(changed), 1)
        at = changed[0]
        self.assertEqual(edited["entries"][at]["event"], "payment_decision")
        self.assertIn("edited", edited["entries"][at]["data"]["decision"]["reason"])
        self.assertLess(at, len(original["entries"]) - 1)
        # 1. Only the content changed: the chain breaks at the edited entry.
        self.assertEqual((edited["intact"], edited["broken_at"]), (False, at))
        self.assertEqual(edited["head"], original["head"])

        # 2. Its hash recomputed: the next entry no longer points at it.
        rehashed = self.tamper("rehash")
        self.assertEqual((rehashed["intact"], rehashed["broken_at"]), (False, at + 1))
        self.assertEqual(rehashed["head"], original["head"])

        # 3. Every later hash recomputed: the chain verifies; only the head differs.
        rechained = self.tamper("rechain")
        self.assertEqual((rechained["intact"], rechained["broken_at"]), (True, None))
        self.assertEqual(rechained["head"]["seq"], original["head"]["seq"])
        self.assertNotEqual(rechained["head"]["hash"], original["head"]["hash"])
        self.assertEqual(len(rechained["entries"]), len(original["entries"]))

        # 4. The end cut off: the chain verifies and is simply shorter.
        cut = self.tamper("truncate")
        self.assertEqual((cut["intact"], cut["broken_at"]), (True, None))
        self.assertEqual(len(cut["entries"]), len(original["entries"]) - 2)
        self.assertEqual(cut["head"]["seq"], original["head"]["seq"] - 2)
        # Only a head kept elsewhere catches stages 3 and 4.
        saved = (original["head"]["seq"], original["head"]["hash"])
        self.assertEqual(verify_entries(rechained["entries"], expected_head=saved)[0], False)
        self.assertEqual(verify_entries(cut["entries"], expected_head=saved)[0], False)

        state = self.ok(self.app.handle("POST", "/api/audit/restore", {}, {}))
        restored = state["runs"]["countersign"]["audit"]
        self.assertEqual(restored, original)
        self.assertShape(state, LAB_STATE)

    def test_truncation_alone_verifies(self):
        cut = self.tamper("truncate")
        self.assertEqual((cut["intact"], len(cut["entries"])),
                         (True, len(self.original["entries"]) - 2))
        self.assertEqual(cut["entries"], self.original["entries"][:-2])

    def test_stages_need_an_edit_first(self):
        self.refused(self.app.handle("POST", "/api/audit/tamper", {}, {"stage": "rehash"}), 409)
        self.refused(self.app.handle("POST", "/api/audit/tamper", {}, {"stage": "rechain"}), 409)
        self.assertEqual(self.ok(self.app.handle("GET", "/api/lab"))["runs"]["countersign"]["audit"],
                         self.original)

    def test_bad_stage_and_empty_lab(self):
        self.refused(self.app.handle("POST", "/api/audit/tamper", {}, {"stage": "burn"}), 400)
        self.refused(self.app.handle("POST", "/api/audit/tamper", {}, {}), 400)
        fresh = App()
        self.refused(fresh.handle("POST", "/api/audit/tamper", {}, {"stage": "edit"}), 409)
        self.refused(fresh.handle("POST", "/api/audit/restore", {}, {}), 409)
        self.refused(fresh.handle("GET", "/api/audit/export"), 409)

    def test_only_the_countersign_run_is_touched(self):
        before = self.ok(self.app.handle("GET", "/api/lab"))["runs"]
        after = self.ok(self.app.handle("POST", "/api/audit/tamper", {}, {"stage": "edit"}))["runs"]
        for mode in ("rules", "strict"):
            self.assertEqual(after[mode], before[mode])
        self.assertEqual(after["countersign"]["attempts"], before["countersign"]["attempts"])

    def test_holds_cannot_be_decided_on_an_edited_log(self):
        hold = holds(self.ok(self.app.handle("GET", "/api/lab")))[0]
        body = {"digest": hold["digest"], "attestation": "checked"}
        self.tamper("edit")
        self.refused(self.app.handle("POST", "/api/holds/H001/approve", {}, body), 409)
        self.refused(self.app.handle("POST", "/api/holds/H001/reject", {}, {}), 409)
        self.ok(self.app.handle("POST", "/api/audit/restore", {}, {}))
        state = self.ok(self.app.handle("POST", "/api/holds/H001/approve", {}, body))
        self.assertTrue(state["runs"]["countersign"]["audit"]["intact"])

    def test_restore_without_tampering_changes_nothing(self):
        state = self.ok(self.app.handle("POST", "/api/audit/restore", {}, {}))
        self.assertEqual(state["runs"]["countersign"]["audit"], self.original)

    def test_export_is_the_log_as_json_lines(self):
        status, download = self.app.handle("GET", "/api/audit/export")
        self.assertEqual(status, 200)
        self.assertIsInstance(download, Download)
        self.assertEqual(download.content_type, "application/x-ndjson")
        self.assertTrue(download.filename.endswith(".jsonl"))
        lines = download.data.decode("ascii").splitlines()
        entries = [json.loads(line) for line in lines]
        self.assertEqual(entries, self.original["entries"])
        self.assertEqual(verify_entries(entries), (True, None))


# --- playground, benchmark, invariant check -------------------------------------------


@unittest.skipUnless(HAVE_DOCS, "scenarios.scenario_from_doc is not in this build yet")
class PlaygroundTests(ShapeMixin, unittest.TestCase):
    def setUp(self):
        self.app = App()

    def doc(self, **changes):
        doc = {
            "title": "My attack", "instruction": "Pay this month's Nimbus Hosting invoice.",
            "payees": ["Nimbus Hosting Ltd"], "max_per_payment": "2000.00",
            "max_total": "3000.00", "max_payments": None, "references": [], "delay_hours": 0,
            "documents": [{"name": "INV-2041.eml", "text": invoice(NIMBUS, MULE)}],
            "attempts": [
                {"payee": "Nimbus Hosting Ltd", "account": NIMBUS, "amount": "480.00",
                 "reference": "INV-2041", "legit": True},
                {"payee": "Nimbus Hosting Ltd", "account": fmt_iban(MULE), "amount": "480.00",
                 "reference": "INV-2041-B", "legit": False},
            ],
            "attacker_accounts": [MULE],
        }
        doc.update(changes)
        return doc

    def run_doc(self, **changes):
        return self.app.handle("POST", "/api/playground/run", {}, self.doc(**changes))

    def test_a_hand_written_attack(self):
        state = self.ok(self.run_doc())
        self.assertShape({k: state[k] for k in ("scenario", "runs")}, LAB_STATE)
        self.assertEqual(state["scenario"]["id"], "custom")
        self.assertEqual(state["scenario"]["title"], "My attack")
        self.assertEqual(state["runs"]["none"]["unauthorised"], "480.00")
        self.assertEqual(state["runs"]["none"]["to_attacker"], "480.00")
        ours = state["runs"]["countersign"]
        self.assertEqual([a["status"] for a in ours["attempts"]], ["paid", "held"])
        self.assertEqual(ours["attempts"][1]["account_raw"], fmt_iban(MULE))
        self.assertEqual(ours["unauthorised"], "0.00")
        self.assertEqual(state["tally"], {"runs": 1, "attempts": 2,
                                          "runs_with_unauthorised_money": 0,
                                          "unauthorised": "0.00"})
        # It is now the current lab, and its hold can be decided like any other.
        lab = self.ok(self.app.handle("GET", "/api/lab"))
        self.assertEqual(lab, {k: state[k] for k in ("scenario", "runs")})
        hold = holds(lab)[0]
        paid = self.ok(self.app.handle("POST", f"/api/holds/{hold['id']}/approve", {},
                                       {"digest": hold["digest"], "attestation": "not checked"}))
        self.assertEqual(paid["runs"]["countersign"]["unauthorised"], "480.00")

    def test_the_tally_counts_runs_of_this_process(self):
        self.ok(self.run_doc())
        # An inflated payment to the genuine account, inside every limit: the known gap.
        gap = self.doc(attempts=[{"payee": "Nimbus Hosting Ltd", "account": NIMBUS,
                                  "amount": "495.00", "reference": "INV-2041", "legit": False}])
        state = self.ok(self.app.handle("POST", "/api/playground/run", {}, gap))
        self.assertEqual(state["runs"]["countersign"]["unauthorised"], "495.00")
        self.assertEqual(state["tally"], {"runs": 2, "attempts": 3,
                                          "runs_with_unauthorised_money": 1,
                                          "unauthorised": "495.00"})
        self.assertEqual(self.ok(App().handle("POST", "/api/playground/run", {},
                                              self.doc()))["tally"]["runs"], 1)

    def test_bad_scenarios_are_refused_with_a_reason(self):
        for changes in (
            {"payees": []},
            {"max_per_payment": "lots"},
            {"max_per_payment": "5000.00"},  # larger than the budget
            {"attempts": []},
            {"attempts": "pay me"},
            {"documents": [{"name": f"d{i}.eml", "text": "x"} for i in range(5)]},
            {"attempts": [self.doc()["attempts"][0]] * 9},
        ):
            with self.subTest(changes=changes):
                self.refused(self.run_doc(**changes), 400)
        self.refused(self.app.handle("POST", "/api/playground/run", {}, {}), 400)
        self.assertEqual(self.ok(self.app.handle("GET", "/api/lab")),
                         {"scenario": None, "runs": {}})

    def test_start_from_a_scenario_replays_the_same_way(self):
        for scenario in SCENARIOS:
            with self.subTest(scenario=scenario.id):
                doc = self.ok(self.app.handle("GET", f"/api/scenarios/{scenario.id}"))
                for key in ("title", "instruction", "payees", "max_per_payment", "max_total",
                            "documents", "attempts"):
                    self.assertIn(key, doc)
                json.dumps(doc, allow_nan=False)
                custom_run = self.ok(self.app.handle("POST", "/api/playground/run", {}, doc))
                listed = self.ok(self.app.handle("POST", "/api/compare", {},
                                                 {"scenario": scenario.id}))
                for mode in MODES:
                    self.assertEqual(
                        [(a["outcome"], a["rules"], a["status"])
                         for a in custom_run["runs"][mode]["attempts"]],
                        [(a["outcome"], a["rules"], a["status"])
                         for a in listed["runs"][mode]["attempts"]], mode)
                    self.assertEqual(custom_run["runs"][mode]["unauthorised"],
                                     listed["runs"][mode]["unauthorised"])

    def test_unknown_scenario_doc(self):
        self.refused(self.app.handle("GET", "/api/scenarios/nope"), 404)


class BenchmarkTests(ShapeMixin, unittest.TestCase):
    def test_bad_approver(self):
        self.refused(App().handle("GET", "/api/benchmark", {"approver": "bribed"}), 400)

    @unittest.skipUnless(HAVE_APPROVERS, "the benchmark has no approver models yet")
    def test_shape_for_every_approver(self):
        app = App()
        for approver in ("none", "careful", "careless"):
            with self.subTest(approver=approver):
                report = self.ok(app.handle("GET", "/api/benchmark", {"approver": approver}))
                self.assertShape(report, BENCHMARK)
                self.assertEqual(report["approver"], approver)
                self.assertEqual([row["id"] for row in report["rows"]], [s.id for s in SCENARIOS])
                self.assertEqual(list(report["summary"]), list(MODES))
                json.dumps(report, allow_nan=False)
        self.assertEqual(self.ok(app.handle("GET", "/api/benchmark"))["approver"], "none")

    @unittest.skipUnless(HAVE_APPROVERS, "the benchmark has no approver models yet")
    def test_the_stage_shows_the_numbers_the_benchmark_reports(self):
        app = App()
        report = self.ok(app.handle("GET", "/api/benchmark", {"approver": "none"}))
        for row in report["rows"]:
            state = self.ok(app.handle("POST", "/api/compare", {}, {"scenario": row["id"]}))
            self.assertEqual(state["scenario"]["known_gap"], row["known_gap"])
            for mode in MODES:
                with self.subTest(scenario=row["id"], mode=mode):
                    self.assertEqual(state["runs"][mode]["unauthorised"],
                                     row["cells"][mode]["unauthorised"])
                    self.assertEqual(state["runs"][mode]["to_attacker"],
                                     row["cells"][mode]["to_attacker"])


@unittest.skipUnless(HAVE_FUZZ, "fuzz.run_fuzz is not in this build yet")
class FuzzTests(ShapeMixin, unittest.TestCase):
    def test_a_short_run(self):
        result = self.ok(App().handle("GET", "/api/fuzz", {"runs": "5"}))
        self.assertShape(result, FUZZ)
        self.assertEqual((result["runs"], result["seed"], result["violations"]), (5, 0, []))
        self.assertGreater(result["operations"], 0)
        self.assertTrue(result["invariants"])

    def test_bad_run_counts(self):
        for runs in ("0", "-3", "many", "1e3", "99999", ""):
            with self.subTest(runs=runs):
                self.refused(App().handle("GET", "/api/fuzz", {"runs": runs}), 400)


class RoutingTests(ShapeMixin, unittest.TestCase):
    def test_unknown_paths_and_wrong_methods(self):
        app = App()
        for method, path in (("GET", "/api/nope"), ("GET", "/api"), ("GET", "/"),
                             ("GET", "/api/holds/H001"), ("POST", "/api/holds/H001/pay"),
                             ("GET", "/apix/meta"), ("GET", "/api/meta/extra")):
            with self.subTest(path=path):
                self.refused(app.handle(method, path, {}, {}), 404)
        for method, path in (("POST", "/api/meta"), ("GET", "/api/compare"),
                             ("GET", "/api/holds/H001/approve"), ("POST", "/api/benchmark"),
                             ("DELETE", "/api/lab")):
            with self.subTest(path=path):
                self.refused(app.handle(method, path, {}, {}), 405)

    def test_the_body_must_be_an_object(self):
        app = App()
        self.refused(app.handle("POST", "/api/compare", {}, ["attack-05"]), 400)
        self.refused(app.handle("POST", "/api/compare", {}, "attack-05"), 400)

    def test_live_endpoints_need_a_database(self):
        app = App()
        self.refused(app.handle("GET", "/api/live/state"), 404)
        self.refused(app.handle("POST", "/api/live/tasks", {}, {}), 404)
        self.refused(app.handle("POST", "/api/live/draft", {}, {"instruction": "x"}), 404)
        self.refused(app.handle("POST", "/api/live/holds/H001/reject", {}, {}), 404)

    def test_a_missing_database_is_reported_not_raised(self):
        with tempfile.TemporaryDirectory() as folder:
            app = App(os.path.join(folder, "missing.db"))
            self.refused(app.handle("GET", "/api/live/state"), 503)


# --- the live console ---------------------------------------------------------------


@unittest.skipUnless(HAVE_STORE, "countersign.store is not in this build yet")
class LiveTests(ShapeMixin, unittest.TestCase):
    TASK = {
        "instruction": "Pay this month's Nimbus Hosting invoice.",
        "payees": ["Nimbus Hosting Ltd"], "max_per_payment": "2000.00", "max_total": "3000.00",
        "hours": 8, "max_payments": None, "references": [], "accounts": {},
    }

    def setUp(self):
        from countersign.store import Store

        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.db = os.path.join(folder.name, "countersign.db")
        self.inbox = os.path.join(folder.name, "inbox")
        self.store = Store.create(self.db, vendors=default_vendors())
        self.agent = self.store.agent()
        self.app = App(self.db, self.inbox)

    def state(self, **query):
        return self.ok(self.app.handle("GET", "/api/live/state", query))

    def start(self, **changes):
        return self.app.handle("POST", "/api/live/tasks", {}, {**self.TASK, **changes})

    def play_attack(self):
        """What a hijacked agent does: read the invoice, pay it, pay the mule too."""
        self.ok(self.start())
        scenario = BY_ID["attack-05"]
        for name, text in scenario.documents.items():
            self.agent.observe(name, text)
        for attempt in scenario.attempts:
            self.agent.pay(attempt.payee, fmt_iban(attempt.account), str(attempt.amount),
                           attempt.reference)
        return self.state()

    def test_a_new_database(self):
        state = self.state()
        self.assertShape(state, LIVE_STATE)
        self.assertIs(state["changed"], True)
        self.assertIsNone(state["task"])
        self.assertEqual((state["documents"], state["attempts"], state["transfers"]), ([], [], []))
        self.assertEqual(state["balance"], "50000.00")
        self.assertEqual(state["vendors"], default_vendors().to_state())
        self.assertEqual(state["head"]["seq"], 0)
        self.assertEqual(state["audit"]["entries"][0]["event"], "log_opened")
        self.assertIs(self.ok(self.app.handle("GET", "/api/meta"))["live"], True)

    def test_mcp_config_has_absolute_paths(self):
        server = self.state()["mcp_config"]["mcpServers"]["countersign"]
        args = server["args"]
        self.assertEqual(args[:3], ["-m", "countersign", "mcp"])
        self.assertEqual(args[args.index("--db") + 1], self.db)
        self.assertEqual(args[args.index("--inbox") + 1], self.inbox)
        self.assertTrue(os.path.isabs(self.db) and os.path.isabs(self.inbox))

    def test_nothing_changed_is_a_short_answer(self):
        head = self.state()["head"]
        self.assertEqual(self.state(after=str(head["seq"])), {"changed": False, "head": head})
        self.agent.observe("note.txt", "hello")
        fresh = self.state(after=str(head["seq"]))
        self.assertIs(fresh["changed"], True)
        self.assertEqual(fresh["head"]["seq"], head["seq"] + 1)
        self.assertShape(fresh, LIVE_STATE)
        self.refused(self.app.handle("GET", "/api/live/state", {"after": "soon"}), 400)

    def test_a_dictated_account_must_be_in_the_sentence(self):
        # A stale form must not be able to trust an account the person cannot see.
        message = self.refused(self.start(accounts={"Nimbus Hosting Ltd": [fmt_iban(NIMBUS)]}),
                               400)
        self.assertIn("written in the instruction", message)

    def test_starting_a_task(self):
        sentence = f"Pay this month's Nimbus Hosting invoice to {fmt_iban(NIMBUS)}."
        state = self.ok(self.start(instruction=sentence,
                                   accounts={"Nimbus Hosting Ltd": [fmt_iban(NIMBUS)]},
                                   max_payments=2, references=["INV-2041"]))
        self.assertShape(state, LIVE_STATE)
        task = state["task"]
        self.assertEqual((task["active"], task["expired"], task["spent"], task["payments"]),
                         (True, False, "0.00", 0))
        mandate = task["mandate"]
        self.assertRegex(mandate["id"], r"\AT-[0-9a-f]{8}\Z")
        self.assertEqual(mandate["instruction"], sentence)
        self.assertEqual(mandate["accounts"], {"Nimbus Hosting Ltd": [NIMBUS]})
        self.assertEqual((mandate["max_payments"], mandate["references"]), (2, ["INV-2041"]))
        started = state["audit"]["entries"][-1]
        self.assertEqual((started["event"], started["data"]["confirmed_by"]),
                         ("task_started", "console"))
        self.assertEqual(self.store.mandate().id, mandate["id"])

    def test_a_bad_task_is_refused_and_nothing_starts(self):
        for changes in (
            {"payees": []},
            {"payees": "Nimbus Hosting Ltd"},
            {"max_per_payment": "lots"},
            {"max_per_payment": 12.5},
            {"max_per_payment": "5000.00"},
            {"hours": 0},
            {"hours": True},
            {"hours": "8"},
            {"instruction": None},
            {"max_payments": 0},
            {"accounts": {"Somebody Else": [NIMBUS]}},
            {"accounts": {"Nimbus Hosting Ltd": ["not an iban"]}},
            {"accounts": [NIMBUS]},
            {"references": "INV-1"},
        ):
            with self.subTest(changes=changes):
                self.refused(self.start(**changes), 400)
        self.assertIsNone(self.state()["task"])
        self.assertEqual(self.state()["head"]["seq"], 0)

    def test_what_the_agent_did_is_shown(self):
        state = self.play_attack()
        self.assertShape(state, LIVE_STATE)
        self.assertEqual([d["name"] for d in state["documents"]], ["INV-2041.eml"])
        self.assertTrue(all(a["attacker"] is None for a in state["documents"][0]["accounts"]))
        first, second = state["attempts"]
        self.assertEqual((first["index"], first["status"], first["outcome"], first["transfer_id"]),
                         (0, "paid", "ALLOW", "T001"))
        self.assertEqual((second["index"], second["status"], second["outcome"], second["rule"]),
                         (1, "held", "HOLD", "P1"))
        self.assertEqual(second["account"], MULE_B)
        self.assertEqual(second["account_raw"], fmt_iban(MULE_B))
        self.assertEqual(second["hold"]["status"], "pending")
        for attempt in state["attempts"]:
            self.assertIsNone(attempt["legit"])
            self.assertIsNone(attempt["to_attacker"])
            self.assertEqual([c["rule"] for c in attempt["checks"]], list(RULE_ORDER))
        self.assertEqual(second["evidence"]["sightings"][0]["source"],
                         state["documents"][0]["label"])
        self.assertEqual((state["task"]["spent"], state["task"]["payments"]), ("240.00", 1))
        self.assertEqual(state["balance"], "49760.00")
        self.assertEqual([t["id"] for t in state["transfers"]], ["T001"])
        self.assertIsNone(state["transfers"][0]["unauthorised"])
        self.assertTrue(state["audit"]["intact"])
        self.assertEqual(state["audit"]["head"], state["head"])

    def test_a_repeated_request_joins_its_hold(self):
        self.play_attack()
        self.agent.pay("Nimbus Hosting Ltd", MULE_B, "240.00", "INV-2041-B")
        attempts = self.state()["attempts"]
        self.assertEqual(len(attempts), 3)
        self.assertEqual(attempts[2]["hold"], attempts[1]["hold"])
        self.assertEqual(attempts[2]["status"], "held")

    def test_a_malformed_request_is_shown_as_the_agent_sent_it(self):
        self.ok(self.start())
        self.agent.pay("Nimbus Hosting Ltd", "send it to my cousin", "lots", "INV-1")
        attempt = self.state()["attempts"][0]
        self.assertEqual((attempt["status"], attempt["outcome"], attempt["rule"]),
                         ("blocked", "BLOCK", "F1"))
        self.assertEqual(attempt["account_raw"], "send it to my cousin")
        self.assertEqual(attempt["amount"], "lots")
        self.assertShape(attempt, ATTEMPT)

    def test_stale_digest_is_a_conflict_and_nothing_is_paid(self):
        before = self.play_attack()
        self.refused(self.app.handle("POST", "/api/live/holds/H001/approve", {},
                                     {"digest": "f" * 64, "attestation": "checked"}), 409)
        self.refused(self.app.handle("POST", "/api/live/holds/H001/approve", {}, {}), 400)
        self.refused(self.app.handle("POST", "/api/live/holds/H404/approve", {},
                                     {"digest": "f" * 64, "attestation": "checked"}), 404)
        after = self.state()
        self.assertEqual(after["transfers"], before["transfers"])
        self.assertEqual(after["head"], before["head"])

    def test_approving_from_the_console_pays_and_keeps_the_evidence(self):
        before = self.play_attack()
        hold = before["attempts"][1]["hold"]
        state = self.ok(self.app.handle(
            "POST", "/api/live/holds/H001/approve", {},
            {"digest": hold["digest"], "attestation": "checked", "remember_account": False}))
        self.assertShape(state, LIVE_STATE)
        attempt = state["attempts"][1]
        self.assertEqual((attempt["status"], attempt["transfer_id"]), ("paid", "T002"))
        self.assertEqual(attempt["hold"], {**hold, "status": "approved", "decided_by": "console",
                                           "attestation": "checked"})
        for key in ("outcome", "rule", "rules", "reason", "checks", "evidence"):
            self.assertEqual(attempt[key], before["attempts"][1][key], key)
        self.assertEqual((state["task"]["spent"], state["task"]["payments"]), ("480.00", 2))
        self.assertEqual(state["balance"], "49520.00")
        # The agent sees the same thing through its own port.
        self.assertEqual(self.agent.hold_status("H001")["status"], "approved")
        self.refused(self.app.handle(
            "POST", "/api/live/holds/H001/approve", {},
            {"digest": hold["digest"], "attestation": "checked"}), 409)

    def test_rejecting_from_the_console(self):
        self.play_attack()
        state = self.ok(self.app.handle("POST", "/api/live/holds/H001/reject", {}, {}))
        attempt = state["attempts"][1]
        self.assertEqual((attempt["status"], attempt["hold"]["status"]), ("rejected", "rejected"))
        self.assertEqual(attempt["hold"]["decided_by"], "console")
        self.assertEqual(len(state["transfers"]), 1)
        self.refused(self.app.handle("POST", "/api/live/holds/H001/reject", {}, {}), 409)
        self.refused(self.app.handle("POST", "/api/live/holds/H404/reject", {}, {}), 404)
        # The same payee and account is now refused outright.
        self.agent.pay("Nimbus Hosting Ltd", MULE_B, "10.00", "INV-X")
        self.assertEqual(self.state()["attempts"][-1]["rule"], "R1")

    def test_an_approval_the_guard_refuses_shows_the_refusal(self):
        self.ok(self.start())
        self.agent.observe("a.eml", invoice(MULE))
        self.agent.pay("Nimbus Hosting Ltd", MULE, "100.00", "INV-1")
        self.agent.pay("Nimbus Hosting Ltd", MULE, "150.00", "INV-2")
        first, second = [a["hold"] for a in self.state()["attempts"]]
        self.ok(self.app.handle("POST", f"/api/live/holds/{first['id']}/reject", {}, {}))
        state = self.ok(self.app.handle(
            "POST", f"/api/live/holds/{second['id']}/approve", {},
            {"digest": second["digest"], "attestation": "checked"}))
        attempt = state["attempts"][1]
        self.assertEqual((attempt["status"], attempt["outcome"], attempt["rule"]),
                         ("blocked", "BLOCK", "R1"))
        self.assertEqual(state["transfers"], [])

    def test_ending_the_task_keeps_the_session_on_screen(self):
        self.play_attack()
        state = self.ok(self.app.handle("POST", "/api/live/tasks/end", {}, {}))
        self.assertShape(state, LIVE_STATE)
        task = state["task"]
        self.assertEqual((task["active"], task["expired"], task["spent"], task["payments"]),
                         (False, False, "240.00", 1))
        self.assertEqual(len(state["attempts"]), 2)
        self.assertEqual(state["attempts"][1]["status"], "expired")
        self.assertEqual(len(state["documents"]), 1)
        # A payment asked for after the end is refused, and shown.
        self.agent.pay("Nimbus Hosting Ltd", NIMBUS, "1.00", "INV-LATE")
        self.assertEqual(self.state()["attempts"][-1]["rule"], "M0")
        # Ending twice is harmless.
        self.ok(self.app.handle("POST", "/api/live/tasks/end", {}, {}))

    def test_a_new_task_starts_a_new_session(self):
        self.play_attack()
        state = self.ok(self.start(instruction="Pay Kestrel Legal.", payees=["Kestrel Legal LLP"]))
        self.assertEqual((state["attempts"], state["documents"]), ([], []))
        self.assertEqual(state["task"]["mandate"]["payees"], ["Kestrel Legal LLP"])
        self.assertEqual(len(state["transfers"]), 1)  # the bank remembers

    def test_draft_reads_a_sentence_and_changes_nothing(self):
        head = self.state()["head"]
        sentence = (f"Pay Nimbus Hosting 1,480.00 and send 12.50 to {fmt_iban(FERNHILL)} "
                    "for invoice 2041.")
        found = self.ok(self.app.handle("POST", "/api/live/draft", {}, {"instruction": sentence}))
        self.assertEqual(found, {"payees": ["Nimbus Hosting Ltd"], "accounts": [FERNHILL],
                                 "amounts": ["1480.00", "12.50"]})
        self.assertEqual(
            self.ok(self.app.handle("POST", "/api/live/draft", {}, {"instruction": ""})),
            {"payees": [], "accounts": [], "amounts": []})
        self.refused(self.app.handle("POST", "/api/live/draft", {}, {}), 400)
        self.refused(self.app.handle("POST", "/api/live/draft", {}, {"instruction": 5}), 400)
        self.assertEqual(self.state()["head"], head)


# --- a real server -----------------------------------------------------------------------


class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, cls.link = dashboard.make_server(0, token=TOKEN)
        cls.port = cls.server.server_address[1]
        cls.base = f"http://127.0.0.1:{cls.port}"
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(5)

    def call(self, path, *, method="GET", token=TOKEN, body=None, headers=None, raw=None):
        """One request with urllib. Returns (status, headers, body bytes)."""
        send = dict(headers or {})
        if token is not None:
            send["X-Countersign-Token"] = token
        data = raw
        if body is not None:
            data = json.dumps(body).encode()
            send.setdefault("Content-Type", "application/json")
        request = urllib.request.Request(self.base + path, data=data, method=method, headers=send)
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                return response.status, response.headers, response.read()
        except urllib.error.HTTPError as error:
            with error:
                return error.code, error.headers, error.read()

    def low_level(self, method, path, headers, body=b""):
        """One request with exact headers, for what urllib will not send."""
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            connection.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
            for name, value in headers.items():
                connection.putheader(name, value)
            connection.endheaders(body or None)
            response = connection.getresponse()
            return response.status, response.headers, response.read()
        finally:
            connection.close()

    def assertSecure(self, headers):
        self.assertEqual(headers["Content-Security-Policy"], dashboard.CSP)
        self.assertEqual(headers["X-Frame-Options"], "DENY")
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(headers["Referrer-Policy"], "no-referrer")
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertNotIn("Access-Control-Allow-Origin", headers)

    def assertError(self, answer, status, message=None):
        got, headers, body = answer
        self.assertEqual(got, status, body)
        self.assertSecure(headers)
        self.assertEqual(headers["Content-Type"], "application/json")
        payload = json.loads(body)
        self.assertEqual(list(payload), ["error"])
        if message is not None:
            self.assertEqual(payload["error"], message)

    def test_the_link_carries_the_key_after_the_hash(self):
        self.assertEqual(self.link, f"{self.base}/#token={TOKEN}")
        self.assertEqual(self.server.server_address[0], "127.0.0.1")

    def test_static_files_and_their_content_types(self):
        static = resources.files("countersign").joinpath("static")
        for path, name, content_type in (
            ("/", "index.html", "text/html; charset=utf-8"),
            ("/app.css", "app.css", "text/css; charset=utf-8"),
            ("/app.js", "app.js", "text/javascript; charset=utf-8"),
        ):
            with self.subTest(path=path):
                status, headers, body = self.call(path, token=None)
                self.assertEqual(status, 200)
                self.assertEqual(headers["Content-Type"], content_type)
                self.assertEqual(body, static.joinpath(name).read_bytes())
                self.assertSecure(headers)

    def test_only_the_whitelist_is_served(self):
        for path in ("/index.html", "/static/app.js", "/app.js.map", "/favicon.ico", "/nope",
                     "/../cli.py", "/app.js/", "/%61pp.js", "/api", "/apix/meta"):
            with self.subTest(path=path):
                self.assertError(self.low_level("GET", path, {"Host": f"127.0.0.1:{self.port}"}),
                                 404)
        self.assertError(self.call("/api/nope"), 404)
        self.assertError(self.call("/", method="POST", body={}), 404)

    def test_api_needs_the_key(self):
        self.assertError(self.call("/api/meta", token=None), 401, "token required")
        self.assertError(self.call("/api/meta", token="wrong-token-123"), 401, "token required")
        self.assertError(self.call("/api/meta", token=TOKEN + "x"), 401, "token required")
        self.assertError(self.call("/api/meta", token=""), 401, "token required")
        self.assertError(self.call("/api/meta?token=" + TOKEN, token=None), 401)
        self.assertError(self.call("/api/reset", method="POST", token=None, body={}), 401)
        self.assertError(self.call("/api/nope", token=None), 401)

    def test_with_the_key(self):
        status, headers, body = self.call("/api/meta")
        self.assertEqual(status, 200)
        self.assertEqual(headers["Content-Type"], "application/json")
        self.assertSecure(headers)
        self.assertEqual(json.loads(body)["version"], __version__)

    def test_the_key_is_never_sent_back(self):
        answers = [
            self.call("/", token=None), self.call("/app.js", token=None),
            self.call("/api/meta"), self.call("/api/meta", token=None),
            self.call("/api/lab"), self.call("/api/nope"),
            self.call("/api/compare", method="POST", body={"scenario": "attack-05"}),
        ]
        for status, headers, body in answers:
            self.assertNotIn(TOKEN.encode(), body)
            self.assertNotIn(TOKEN, str(headers))

    def test_another_origin_is_refused(self):
        self.assertError(self.call("/api/meta", headers={"Origin": "http://evil.example"}), 403)
        self.assertError(self.call("/", token=None, headers={"Origin": "http://evil.example"}), 403)
        self.assertError(self.call("/api/meta", headers={"Origin": "null"}), 403)
        self.assertError(self.call("/api/meta", headers={"Origin": f"http://127.0.0.1:{self.port + 1}"}),
                         403)
        self.assertError(self.call("/api/meta", headers={"Origin": f"https://127.0.0.1:{self.port}"}),
                         403)
        self.assertError(self.call("/api/reset", method="POST", body={},
                                   headers={"Origin": "http://evil.example"}), 403)
        status, _, _ = self.call("/api/meta", headers={"Origin": self.base})
        self.assertEqual(status, 200)

    def test_another_host_name_is_refused(self):
        token = {"X-Countersign-Token": TOKEN}
        for host in ("evil.example", f"evil.example:{self.port}", "127.0.0.1.evil.example",
                     "[::1]", ""):
            with self.subTest(host=host):
                self.assertError(self.low_level("GET", "/api/meta", {"Host": host, **token}), 403)
        self.assertError(self.low_level("GET", "/api/meta", token), 403)  # no Host at all
        status, _, _ = self.low_level("GET", "/api/meta",
                                      {"Host": f"localhost:{self.port}", **token})
        self.assertEqual(status, 200)

    def test_post_must_be_json(self):
        self.assertError(self.call("/api/reset", method="POST", raw=b"{}",
                                   headers={"Content-Type": "text/plain"}), 415)
        self.assertError(self.call("/api/reset", method="POST", raw=b"a=1", headers={
            "Content-Type": "application/x-www-form-urlencoded"}), 415)
        self.assertError(self.call("/api/reset", method="POST", raw=b"{nope",
                                   headers={"Content-Type": "application/json"}), 400)
        self.assertError(self.call("/api/reset", method="POST", raw=b"[1]",
                                   headers={"Content-Type": "application/json"}), 400)
        self.assertError(self.call("/api/reset", method="POST", raw=b'{"a": NaN}',
                                   headers={"Content-Type": "application/json"}), 400)
        self.assertError(self.call("/api/reset", method="POST", raw=b"[" * 50000,
                                   headers={"Content-Type": "application/json"}), 400)
        status, _, body = self.call("/api/reset", method="POST", raw=b"{}", headers={
            "Content-Type": "application/json; charset=utf-8"})
        self.assertEqual((status, json.loads(body)), (200, {"scenario": None, "runs": {}}))

    def post_headers(self, **extra):
        return {"Host": f"127.0.0.1:{self.port}", "X-Countersign-Token": TOKEN,
                "Content-Type": "application/json", **extra}

    def test_an_oversized_body_is_refused_unread(self):
        # Only the headers are sent. A server that tried to read the body
        # first would wait for it and this request would time out.
        status, headers, body = self.low_level(
            "POST", "/api/reset", self.post_headers(**{"Content-Length": str(256 * 1024 + 1)}))
        self.assertError((status, headers, body), 413)
        self.assertEqual(headers["Connection"], "close")
        # Exactly at the limit it is read.
        padding = b" " * (256 * 1024 - 2)
        status, _, _ = self.low_level(
            "POST", "/api/reset", self.post_headers(**{"Content-Length": str(256 * 1024)}),
            b"{" + padding + b"}")
        self.assertEqual(status, 200)

    def test_a_bad_content_length_is_refused(self):
        for value in ("-1", "ten", "1.5", "+5", ""):
            with self.subTest(value=value):
                answer = self.low_level("POST", "/api/reset",
                                        self.post_headers(**{"Content-Length": value}))
                self.assertError(answer, 400)
                self.assertEqual(answer[1]["Connection"], "close")
        self.assertError(self.low_level("POST", "/api/reset", self.post_headers()), 411)

    def test_other_methods(self):
        self.assertError(self.call("/api/lab", method="PUT", body={}), 405)
        self.assertError(self.call("/api/lab", method="DELETE"), 405)
        self.assertError(self.call("/api/meta", method="POST", body={}), 405)
        self.assertError(self.call("/api/lab", method="BREW"), 501)
        status, headers, body = self.call("/", method="HEAD", token=None)
        self.assertEqual((status, body), (200, b""))
        self.assertSecure(headers)

    def test_a_malformed_request_line_gets_the_same_plain_answer(self):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            connection.sock = None
            connection.connect()
            connection.sock.sendall(b"NONSENSE\r\n\r\n")
            received = b""
            while True:  # the server closes the connection after its answer
                chunk = connection.sock.recv(65536)
                if not chunk:
                    break
                received += chunk
            response = received.decode("latin-1")
        finally:
            connection.close()
        self.assertTrue(response.startswith("HTTP/1.1 400 "), response[:40])
        self.assertIn("Content-Security-Policy: ", response)
        self.assertIn("Connection: close", response)
        self.assertTrue(response.endswith('{"error": "The request could not be read."}'))
        self.assertNotIn("<html", response.lower())
        self.assertNotIn("Python", response)
        # A header line that is far too long is refused the same way.
        answer = self.low_level("GET", "/", {"Host": f"127.0.0.1:{self.port}",
                                             "X-Long": "a" * 70000})
        self.assertError(answer, 431)

    def test_a_whole_session_over_http(self):
        status, _, body = self.call("/api/compare", method="POST", body={"scenario": "attack-05"})
        self.assertEqual(status, 200)
        state = json.loads(body)
        self.assertEqual(problems(state, LAB_STATE), [])
        hold = holds(state)[0]
        self.assertError(self.call("/api/holds/H001/approve", method="POST",
                                   body={"digest": "0" * 64, "attestation": "checked"}), 409)
        status, _, body = self.call("/api/holds/H001/approve", method="POST",
                                    body={"digest": hold["digest"], "attestation": "checked",
                                          "remember_account": False})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["runs"]["countersign"]["attempts"][1]["status"], "paid")
        status, headers, body = self.call("/api/audit/export")
        self.assertEqual(status, 200)
        self.assertEqual(headers["Content-Type"], "application/x-ndjson")
        self.assertIn("attachment", headers["Content-Disposition"])
        self.assertSecure(headers)
        entries = [json.loads(line) for line in body.decode("ascii").splitlines()]
        self.assertEqual(verify_entries(entries), (True, None))
        status, _, body = self.call("/api/lab")
        self.assertEqual(json.loads(body)["runs"]["countersign"]["audit"]["entries"], entries)
        self.assertEqual(self.call("/api/reset", method="POST", body={})[0], 200)

    def test_query_strings(self):
        status, _, body = self.call("/api/benchmark?approver=nobody")
        self.assertEqual(status, 400)
        status, _, body = self.call("/?utm=1", token=None)
        self.assertEqual(status, 200)


class ServerErrorTests(unittest.TestCase):
    def test_an_unexpected_error_is_a_plain_500_with_the_traceback_on_stderr_only(self):
        class Broken(App):
            def handle(self, method, path, query=None, body=None):
                raise RuntimeError("secret detail 4711")

        handler = dashboard.make_handler(Broken(), TOKEN)
        server = dashboard.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        errors = io.StringIO()
        try:
            request = urllib.request.Request(
                f"http://127.0.0.1:{server.server_address[1]}/api/meta",
                headers={"X-Countersign-Token": TOKEN})
            with contextlib.redirect_stderr(errors):
                with self.assertRaises(urllib.error.HTTPError) as caught:
                    urllib.request.urlopen(request, timeout=10)
                with caught.exception as error:
                    body = error.read()
                    headers = error.headers
        finally:
            server.shutdown()
            server.server_close()
            thread.join(5)
        self.assertEqual(caught.exception.code, 500)
        self.assertEqual(json.loads(body), {"error": "internal error"})
        self.assertEqual(headers["Content-Security-Policy"], dashboard.CSP)
        self.assertNotIn(b"4711", body)
        self.assertIn("secret detail 4711", errors.getvalue())
        self.assertIn("Traceback", errors.getvalue())

    def test_token_rules(self):
        self.assertEqual(dashboard.choose_token("abcdefgh-ijklmnop"), "abcdefgh-ijklmnop")
        for bad in ("short", "abcdefgh", "has space in it here", "line\nbreak-token-long",
                    "café-token-long-enough"):
            with self.subTest(token=bad):
                with self.assertRaises(ValueError):
                    dashboard.choose_token(bad)
        saved = os.environ.pop(dashboard.TOKEN_ENV, None)
        try:
            first, second = dashboard.choose_token(), dashboard.choose_token()
            self.assertNotEqual(first, second)
            self.assertGreaterEqual(len(first), 32)
            os.environ[dashboard.TOKEN_ENV] = "from-the-environment"
            self.assertEqual(dashboard.choose_token(), "from-the-environment")
            self.assertEqual(dashboard.choose_token("given-by-the-caller"), "given-by-the-caller")
        finally:
            os.environ.pop(dashboard.TOKEN_ENV, None)
            if saved is not None:
                os.environ[dashboard.TOKEN_ENV] = saved


class CommandTests(unittest.TestCase):
    def parse(self, *argv):
        from countersign.cli import build_parser

        return build_parser().parse_args(["dashboard", *argv])

    def test_options(self):
        args = self.parse()
        self.assertEqual((args.port, args.db, args.inbox, args.open), (8377, None, None, False))
        args = self.parse("--port", "8600", "--db", "x.db", "--inbox", "in", "--open")
        self.assertEqual((args.port, args.db, args.inbox, args.open), (8600, "x.db", "in", True))

    def test_the_key_cannot_be_given_on_the_command_line(self):
        # Every local user can read a process's arguments; only the same user its environment.
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            self.parse("--token", "t" * 20)

    def test_a_missing_database_or_a_bad_key_is_a_usage_error(self):
        errors = io.StringIO()
        with tempfile.TemporaryDirectory() as folder, contextlib.redirect_stderr(errors):
            args = self.parse("--port", "0", "--db", os.path.join(folder, "none.db"))
            self.assertEqual(args.func(args), 2)
            args = self.parse("--port", "0")
            with mock.patch.dict(os.environ, {dashboard.TOKEN_ENV: "short"}):
                self.assertEqual(args.func(args), 2)
        self.assertIn("countersign dashboard:", errors.getvalue())

    def test_serve_prints_the_link_and_opens_it_when_asked(self):
        opened, printed = [], io.StringIO()
        real_open, real_forever = dashboard.webbrowser.open, dashboard.ThreadingHTTPServer.serve_forever

        def stop_at_once(server, *args, **kwargs):
            raise KeyboardInterrupt

        dashboard.webbrowser.open = opened.append
        dashboard.ThreadingHTTPServer.serve_forever = stop_at_once
        try:
            with contextlib.redirect_stdout(printed):
                dashboard.serve(0, token=TOKEN, open_browser=True)
                dashboard.serve(0, token=TOKEN)
        finally:
            dashboard.webbrowser.open = real_open
            dashboard.ThreadingHTTPServer.serve_forever = real_forever
        links = re.findall(r"http://127\.0\.0\.1:[0-9]+/#token=" + re.escape(TOKEN),
                           printed.getvalue())
        self.assertEqual(len(links), 2)
        self.assertEqual(opened, links[:1])


# --- the page itself ----------------------------------------------------------------------


class StaticFileTests(unittest.TestCase):
    def setUp(self):
        static = resources.files("countersign").joinpath("static")
        self.files = {name: static.joinpath(name).read_text(encoding="utf-8")
                      for name in ("index.html", "app.css", "app.js")}

    def test_nothing_is_loaded_from_outside(self):
        for name, text in self.files.items():
            with self.subTest(file=name):
                self.assertIsNone(re.search(r"https?:", text, re.IGNORECASE))
                self.assertIsNone(re.search(r"""(?:src|href|url)\s*[=(]\s*["']?//""", text))
                self.assertNotIn("@import", text)

    def test_no_html_is_ever_built_from_text(self):
        for name, text in self.files.items():
            with self.subTest(file=name):
                for banned in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write",
                               "eval(", "new Function", "srcdoc"):
                    self.assertNotIn(banned, text)

    def test_the_page_obeys_its_own_content_security_policy(self):
        html = self.files["index.html"]
        self.assertIsNone(re.search(r"<script(?![^>]*\bsrc=)", html))
        self.assertIsNone(re.search(r"<style\b", html))
        self.assertIsNone(re.search(r"\sstyle\s*=", html))
        self.assertIsNone(re.search(r"\son[a-z]+\s*=", html))
        self.assertEqual(re.findall(r"""(?:src|href)="([^"#][^"]*)\"""", html),
                         ["app.css", "app.js"])
        js = self.files["app.js"]
        self.assertNotIn('setAttribute("style"', js)
        self.assertNotIn(".cssText", js)

    def test_static_files_are_packaged(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(dashboard.__file__)))
        with open(os.path.join(root, "pyproject.toml"), encoding="utf-8") as fp:
            self.assertIn('countersign = ["static/*"]', fp.read())


if __name__ == "__main__":
    unittest.main()
