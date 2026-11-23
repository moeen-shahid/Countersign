"""A six-scene walkthrough in the terminal: python -m countersign demo.

Everything printed comes from running the code. Nothing is typed in.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from decimal import Decimal
from typing import Any

from .benchmark import run_benchmark
from .iban import fmt_iban
from .models import money
from .policy import rule_title
from .scenarios import BY_ID, SCENARIOS, split_hidden
from .simulation import MODE_LABELS, MODES, OUR_BASELINES, run_scenario

HERO = "attack-05"  # hidden text, beats the name allowlist, Countersign pays half and holds half


class Out:
    def __init__(self, color: bool, pause: float) -> None:
        self.color = color
        self.pause_s = pause

    def paint(self, code: str, text: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.color else text

    def red(self, t: str) -> str:
        return self.paint("31;1", t)

    def green(self, t: str) -> str:
        return self.paint("32;1", t)

    def amber(self, t: str) -> str:
        return self.paint("33;1", t)

    def dim(self, t: str) -> str:
        return self.paint("2", t)

    def bold(self, t: str) -> str:
        return self.paint("1", t)

    def scene(self, n: int, title: str) -> None:
        self.pause()
        print()
        print(self.bold(f"SCENE {n}. {title}"))
        print(self.dim("-" * 72))

    def pause(self) -> None:
        if self.pause_s:
            time.sleep(self.pause_s)


def _outcome(out: Out, status: str, rule: str) -> str:
    if status == "paid":
        return out.green("PAID")
    if status == "held":
        return out.amber(f"HELD {rule}")
    return out.red(f"BLOCKED {rule}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="countersign demo")
    parser.add_argument("--fast", action="store_true", help="no pauses")
    parser.add_argument("--no-color", action="store_true")
    args = parser.parse_args(argv)
    run(color=sys.stdout.isatty() and not args.no_color and "NO_COLOR" not in os.environ,
        pause=0 if args.fast or not sys.stdout.isatty() else 0.6)
    return 0


def run(color: bool = False, pause: float = 0) -> None:
    out = Out(color, pause)
    hero = BY_ID[HERO]
    name, text = next(iter(hero.documents.items()))

    out.scene(1, "One sentence from the user. One invoice.")
    print(f'  The user tells their agent: "{hero.instruction}"')
    print(f"  The invoice, {name}, as a person sees it in a mail client:\n")
    hidden_parts = []
    for start, end, hidden in split_hidden(text):
        if hidden:
            hidden_parts.append(text[start:end])
        else:
            for line in text[start:end].rstrip().splitlines():
                print("    " + line)
    print()
    print("  What the agent reads as well (white text, 1 pixel high):")
    for part in hidden_parts:
        print("    " + out.red(part))

    out.scene(2, "The same hijacked agent, four guards")
    print(out.dim("  The agent is scripted: it attempts every payment the attacker wants.\n"))
    runs = {mode: run_scenario(hero, mode) for mode in MODES}
    for index, attempt in enumerate(hero.attempts):
        truth = "the user wanted this" if attempt.legit else "the user did NOT want this"
        print(f"  Payment {index + 1}: EUR {money(attempt.amount)} to "
              f"{fmt_iban(attempt.account)}  ({truth})")
        for mode in MODES:
            run = runs[mode]
            status = run.status(index)
            rule = run.results[index].decision.rule
            label = MODE_LABELS[mode] + (" (ours)" if mode in OUR_BASELINES else "")
            print(f"    {label:<32} {_outcome(out, status, rule)}")
        print()
    for mode in MODES:
        lost = runs[mode].unauthorised_paid()
        text_lost = f"EUR {money(lost)}"
        print(f"  {MODE_LABELS[mode]:<26} unauthorised money moved: "
              f"{out.red(text_lost) if lost else out.green(text_lost)}")

    out.scene(3, "Why Countersign held it")
    cs = runs["countersign"]
    held = next(r for r in cs.results if r.hold_id)
    decision, ev = held.decision, held.decision.evidence
    print("  The rules, in order (plain code, not a model):")
    line = []
    for check in decision.checks:
        mark = {"pass": out.green(check.rule), "hold": out.amber(check.rule + "!"),
                "block": out.red(check.rule + "!")}.get(check.status, out.dim(check.rule))
        line.append(mark)
    print("    " + " ".join(line))
    print(f"\n  Where did {fmt_iban(ev.account)} come from?")
    print(f"    the user's sentence:      {'yes' if ev.typed_by_user else 'no'}")
    print(f"    the vendor file:          no (it has {', '.join(fmt_iban(a) for a in ev.on_file)})")
    for s in ev.sightings:
        print(f"    a document the agent read: {s.source}, line {s.line} (untrusted)")
    print(f"\n  {decision.rule} ({rule_title(decision.rule)}): {out.amber(decision.reason)}")

    out.scene(4, "A person decides. The agent has no approve tool.")
    print(f"  Hold {held.hold_id} is rejected in the console. Nothing is sent.")
    cs.guard.reject(held.hold_id, approver="demo")
    supplier = run_scenario(BY_ID["benign-03"], "countersign")
    hold_id = supplier.results[0].hold_id
    print(f'\n  Next task: "{supplier.scenario.instruction}"')
    print(f"  A genuine new supplier is held once too ({supplier.results[0].decision.rule}): "
          "the guard cannot tell it from a fake.")
    supplier.guard.approve(hold_id, approver="demo", attestation="checked")
    print(f"  The person phones the supplier, then countersigns {hold_id}: "
          f"{out.green(supplier.status(0).upper())}.")

    out.scene(5, "Every decision is in a hash-chained log")
    log = cs.guard.audit
    ok, _ = log.verify()
    print(f"  {len(log.entries)} entries, head {log.head()[1][:12]}..., chain intact: {ok}")
    target = next(e for e in log.entries if e["event"] == "payment_decision"
                  and e["data"]["decision"]["outcome"] == "HOLD")
    target["data"]["decision"]["outcome"] = "ALLOW"
    ok, at = log.verify()
    print(f"  An intruder rewrites entry {target['seq']} to say ALLOW: "
          + out.red(f"TAMPERING DETECTED at entry {at}"))
    print(out.dim("  Tamper-evident, not tamper-proof: rewriting every later hash too is only "
                  "caught\n  against a head kept somewhere else (python -m countersign audit)."))

    out.scene(6, f"The scoreboard: {len(SCENARIOS)} scenarios, every guard")
    report = run_benchmark()
    widest = max(float(report["summary"][m]["unauthorised"]) for m in MODES) or 1.0
    for mode in MODES:
        s = report["summary"][mode]
        bar = "#" * max(0, round(28 * float(s["unauthorised"]) / widest))
        label = MODE_LABELS[mode] + (" (ours)" if mode in OUR_BASELINES else "")
        print(f"  {label:<32} {s['attacks_money_moved']:>2} of {s['attacks_total']} attacks "
              f"moved money  EUR {money(Decimal(s['unauthorised'])):>10}  {out.red(bar)}")
        print(out.dim(f"  {'':<32} ordinary tasks paid / held / blocked: {s['benign_paid']} / "
                      f"{s['benign_held']} / {s['benign_blocked']} of {s['benign_total']}"))
    gaps = [r for r in report["rows"] if r["known_gap"]]
    print(f"\n  Known gaps, kept on the board ({len(gaps)}):")
    for row in gaps:
        cell = row["cells"]["countersign"]
        print(f"    {row['id']:<12} {row['title']}: EUR {money(Decimal(cell['unauthorised']))}")
    careless = run_benchmark("careless")["summary"]["countersign"]
    print(f"\n  If a careless person approved every hold: {careless['attacks_money_moved']} of "
          f"{careless['attacks_total']} attacks would move money. Holds only work if someone "
          "checks.")
    print(out.dim("\n  Scripted attacks. Both baselines are ours. We wrote both the attacks and "
                  "the defence."))
    print(out.dim("  Run it yourself: python -m countersign benchmark"))


def add_cli(commands: Any) -> None:
    parser = commands.add_parser("demo", help="six-scene walkthrough in the terminal")
    parser.add_argument("--fast", action="store_true", help="no pauses")
    parser.add_argument("--no-color", action="store_true")
    parser.set_defaults(func=lambda a: main((["--fast"] if a.fast else [])
                                            + (["--no-color"] if a.no_color else [])))


if __name__ == "__main__":
    sys.exit(main())
