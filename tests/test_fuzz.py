"""The invariant fuzzer: it finds nothing in the real guard, and it does catch broken ones."""

import unittest
from contextlib import ExitStack

from countersign import fuzz
from countersign.cli import main


class FuzzTests(unittest.TestCase):
    def test_no_violations_in_the_real_guard(self):
        report = fuzz.run_fuzz(runs=120, seed=3)
        self.assertEqual(report["violations"], [])
        self.assertGreater(report["operations"], 1000)
        self.assertEqual([i["id"] for i in report["invariants"]],
                         [f"INV-{n}" for n in range(1, 8)])

    def test_same_seed_same_result(self):
        a, b = fuzz.run_fuzz(runs=20, seed=5), fuzz.run_fuzz(runs=20, seed=5)
        self.assertEqual(a["operations"], b["operations"])
        self.assertEqual(fuzz._one(42, 30)[1], fuzz._one(42, 30)[1])

    def test_broken_guards_are_caught(self):
        expected = {
            "every account counts as vouched for": "INV-1",
            "an account seen in a document counts as trusted": "INV-1",
            "an account the user typed outranks the vendor file": "INV-1",
            "approving a hold pays a cent more than was shown": "INV-5",
            "the budget and payment count are not checked": "INV-2",
            "any payee name passes the mandate check": "INV-2",
        }
        self.assertEqual(set(expected) | {"the unusual-amount rule (A1) is switched off"},
                         {label for label, _ in fuzz.MUTANTS})
        for label, patch in fuzz.MUTANTS:
            if label not in expected:
                continue
            with self.subTest(mutant=label), ExitStack() as stack:
                patch(stack)
                report = fuzz.run_fuzz(runs=80, seed=0)
                self.assertIn(expected[label], {v["invariant"] for v in report["violations"]})

    def test_an_internal_error_in_the_guard_is_a_violation(self):
        from unittest import mock

        from countersign import guard

        def crash(req, trusted, provenance):
            raise RuntimeError("broken rule engine")

        with mock.patch.object(guard, "evaluate", crash):
            report = fuzz.run_fuzz(runs=10, seed=0)
        self.assertEqual({v["invariant"] for v in report["violations"]}, {"INV-4"})

    def test_reports_which_rules_decided(self):
        rules = fuzz.run_fuzz(runs=40, seed=1)["rules"]
        for rule in ("OK", "P1", "O1", "M2", "A1"):
            self.assertGreater(rules.get(rule, 0), 0, rule)

    def test_a_violation_names_the_seed_and_the_steps(self):
        with ExitStack() as stack:
            fuzz.MUTANTS[0][1](stack)
            report = fuzz.run_fuzz(runs=50, seed=0)
        first = report["violations"][0]
        self.assertTrue(first["operations"])
        self.assertIsInstance(first["seed"], int)

    def test_command_line(self):
        from contextlib import redirect_stdout
        from io import StringIO
        out = StringIO()
        with redirect_stdout(out):
            code = main(["fuzz", "--runs", "10"])
        self.assertEqual(code, 0)
        self.assertIn("0 invariant violations", out.getvalue())
        self.assertIn("says nothing about attacks nobody thought of", out.getvalue())
        with redirect_stdout(StringIO()):
            self.assertEqual(main(["fuzz", "--runs", "0"]), 2)


if __name__ == "__main__":
    unittest.main()
