"""nix/mutants-baseline.py's own tests, on reports and baselines written for each
(packages.mutants-gate runs them first).

Usage: python3 -I nix/mutants-baseline-tests.py [SCRIPT]. SCRIPT, nix/mutants-baseline.py by
default, is the script under test: a changed copy shows which test holds which rule.
"""

import json
import pathlib
import subprocess
import sys
import tempfile
import tomllib
import unittest

SCRIPT = pathlib.Path(sys.argv.pop(1) if len(sys.argv) > 1 else pathlib.Path(__file__).with_name("mutants-baseline.py"))

FILE = "crates/x/lib.rs"
SOURCE = "pub fn same(a: u32, b: u32) -> bool {\n    a == b\n}\n\npub fn small(a: u32) -> bool {\n    a == 1 || a == 2\n}\n"
# Two lines more above every function: no key may change.
SHIFTED = "// A comment\n// and another.\n" + SOURCE

SAME_TRUE = "same: FnValue →true"
SAME_EQ = "same: BinaryOperator ==→!="
SMALL_EQ = "small: BinaryOperator ==→!="


def mutant(function, genre, line, col, end, replacement, shift=0):
    """A mutant as cargo-mutants' outcomes.json and `--list --json` give it."""
    line += shift
    span = {"start": {"line": line, "column": col}, "end": {"line": line, "column": end}}
    if genre == "FnValue":
        what = f"replace {function} -> bool with {replacement}"
    else:
        what = f"replace == with {replacement} in {function}"
    return {
        "name": f"{FILE}:{line}:{col}: {what}",
        "package": "x",
        "file": FILE,
        "function": {"function_name": function, "return_type": "-> bool", "span": span},
        "span": span,
        "replacement": replacement,
        "genre": genre,
    }


def mutants(shift=0):
    return {
        "same=true": mutant("same", "FnValue", 2, 5, 11, "true", shift),
        "same==": mutant("same", "BinaryOperator", 2, 7, 9, "!=", shift),
        "small==1": mutant("small", "BinaryOperator", 6, 7, 9, "!=", shift),
        "small==2": mutant("small", "BinaryOperator", 6, 17, 19, "!=", shift),
    }


TXT = {"CaughtMutant": "caught.txt", "MissedMutant": "missed.txt", "Timeout": "timeout.txt", "Unviable": "unviable.txt"}


class Case(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.dir.name)
        self.source(SOURCE)
        self.reports = 0

    def tearDown(self):
        self.dir.cleanup()

    def source(self, text):
        p = self.root / FILE
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)

    def report(self, outcomes, shift=0, listed=None):
        """A report of one scope: `outcomes` maps a mutant of `mutants()` to its summary;
        `listed`, the scope's every mutant (all-mutants.json), is all of `mutants()` by default."""
        self.reports += 1
        ms = mutants(shift)
        scope = self.root / f"report-{self.reports}" / "x"
        scope.mkdir(parents=True)
        rows = [{"scenario": "Baseline", "summary": "Success"}]
        rows += [{"scenario": {"Mutant": ms[m]}, "summary": s} for m, s in outcomes.items()]
        (scope / "outcomes.json").write_text(json.dumps({"outcomes": rows}))
        for summary, txt in TXT.items():
            (scope / txt).write_text("".join(ms[m]["name"] + "\n" for m, s in outcomes.items() if s == summary))
        (scope / "all-mutants.json").write_text(json.dumps([ms[m] for m in (listed or ms)]))
        return scope.parent

    def baseline(self, entries, max=None, enforce=True):
        text = f"enforce = {str(enforce).lower()}\nmax = {len(entries) if max is None else max}  # only goes down\n"
        if entries:
            text += f'\n["{FILE}"]\n' + "".join(f'"{key}" = "why"\n' for key in entries)
        (self.root / "nix").mkdir(exist_ok=True)
        (self.root / "nix/mutants-baseline.toml").write_text(text)

    def read_baseline(self):
        return tomllib.loads((self.root / "nix/mutants-baseline.toml").read_text())

    def gate(self, mode, *reports, extra=()):
        return subprocess.run(
            [sys.executable, "-I", str(SCRIPT), "--mode", mode, "--source", str(self.root), *extra, *map(str, reports)],
            capture_output=True,
            text=True,
        )


class Gate(Case):
    def test_an_unlisted_survivor_fails(self):
        self.baseline([SAME_TRUE])
        r = self.report({"same=true": "MissedMutant", "same==": "MissedMutant"})
        for mode in ["diff", "touched", "sweep"]:
            with self.subTest(mode=mode):
                got = self.gate(mode, r)
                self.assertEqual(got.returncode, 1, got.stdout + got.stderr)
                self.assertIn(f'{FILE}: "{SAME_EQ}"', got.stdout)
                self.assertNotIn(f'{FILE}: "{SAME_TRUE}"', got.stdout)

    def test_a_listed_survivor_passes(self):
        self.baseline([SAME_TRUE, SAME_EQ])
        r = self.report({"same=true": "MissedMutant", "same==": "MissedMutant", "small==1": "CaughtMutant"})
        got = self.gate("sweep", r)
        self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
        self.assertIn("2 missed (2 listed)", got.stdout)

    def test_a_stale_entry_fails_in_sweep_mode(self):
        # Caught now, or no longer a mutant at all: neither survives.
        for stale, outcomes, fails in [
            (SAME_EQ, {"same==": "CaughtMutant"}, {"diff": 0, "touched": 1, "sweep": 1}),
            ("gone: FnValue →true", {}, {"diff": 0, "touched": 0, "sweep": 1}),
        ]:
            self.baseline([SAME_TRUE, stale])
            r = self.report({"same=true": "MissedMutant", **outcomes})
            for mode, code in fails.items():
                with self.subTest(stale=stale, mode=mode):
                    got = self.gate(mode, r)
                    self.assertEqual(got.returncode, code, got.stdout + got.stderr)
                    if code:
                        self.assertIn(f'{FILE}: "{stale}"', got.stdout)

    def test_the_key_survives_a_line_shift(self):
        self.baseline([SAME_EQ, SMALL_EQ + " #2"])
        self.source(SHIFTED)
        r = self.report({"same==": "MissedMutant", "small==2": "MissedMutant"}, shift=2)
        got = self.gate("sweep", r)
        self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
        self.assertIn("2 missed (2 listed)", got.stdout)

    def test_duplicates_get_k(self):
        self.baseline([])
        r = self.report({"small==1": "MissedMutant", "small==2": "MissedMutant"})
        got = self.gate("diff", r)
        self.assertIn(f'"{SMALL_EQ}"', got.stdout)
        self.assertIn(f'"{SMALL_EQ} #2"', got.stdout)
        # k counts the function's every mutant, not the run's: a diff that reaches only the
        # second one still names it #2.
        r = self.report({"small==2": "MissedMutant"})
        got = self.gate("diff", r)
        self.assertIn(f'"{SMALL_EQ} #2"', got.stdout)
        self.assertNotIn(f'"{SMALL_EQ}"', got.stdout)

    def test_reports_are_one_run(self):
        # The token pass caught what the first pass missed: no survivor.
        self.baseline([])
        first = self.report({"same==": "MissedMutant", "small==1": "CaughtMutant"})
        tokens = self.report({"same==": "CaughtMutant"})
        got = self.gate("diff", first, tokens)
        self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
        self.assertIn("2 caught, 0 missed", got.stdout)

    def test_timeouts_and_unviable_are_listed_not_gated(self):
        self.baseline([])
        r = self.report({"same==": "Timeout", "small==1": "Unviable"})
        got = self.gate("sweep", r)
        self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
        self.assertIn(f'{FILE}: "{SAME_EQ}"', got.stdout)
        self.assertIn("1 timeout", got.stdout)

    def test_more_entries_than_max_fails(self):
        self.baseline([SAME_TRUE, SAME_EQ], max=1)
        r = self.report({"same=true": "MissedMutant", "same==": "MissedMutant"})
        got = self.gate("diff", r)
        self.assertEqual(got.returncode, 1, got.stdout + got.stderr)
        self.assertIn("2 entries, over max = 1", got.stdout)

    def test_report_mode_prints_what_would_fail_and_passes(self):
        self.baseline([], enforce=False)
        r = self.report({"same==": "MissedMutant"})
        got = self.gate("sweep", r)
        self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
        self.assertIn(f'{FILE}: "{SAME_EQ}"', got.stdout)
        self.assertIn("report mode", got.stdout)


class Write(Case):
    def test_write_removes_stale_entries_and_lowers_max(self):
        self.baseline([SAME_TRUE, SAME_EQ], max=5)
        r = self.report({"same=true": "MissedMutant", "same==": "CaughtMutant"})
        got = self.gate("sweep", r, extra=["--write"])
        self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
        self.assertEqual(self.read_baseline(), {"enforce": True, "max": 1, FILE: {SAME_TRUE: "why"}})

    def test_write_never_raises_max(self):
        # Over max, and a survivor not listed: --write adds neither the entry nor to max.
        self.baseline([SAME_TRUE, SAME_EQ], max=1)
        r = self.report({"same=true": "MissedMutant", "same==": "MissedMutant", "small==1": "MissedMutant"})
        got = self.gate("sweep", r, extra=["--write"])
        self.assertEqual(got.returncode, 1, got.stdout + got.stderr)
        self.assertEqual(self.read_baseline(), {"enforce": True, "max": 1, FILE: {SAME_TRUE: "why", SAME_EQ: "why"}})

    def test_seed_lists_every_survivor_in_report_mode_only(self):
        r = self.report({"same=true": "MissedMutant", "small==1": "MissedMutant", "small==2": "MissedMutant"})
        self.baseline([], enforce=True)
        self.assertEqual(self.gate("sweep", r, extra=["--seed"]).returncode, 2)
        self.baseline([], enforce=False)
        got = self.gate("sweep", r, extra=["--seed"])
        self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
        seeded = self.read_baseline()
        self.assertEqual(seeded["max"], 3)
        self.assertEqual(sorted(seeded[FILE]), [SAME_TRUE, SMALL_EQ, SMALL_EQ + " #2"])
        self.assertEqual(seeded[FILE][SAME_TRUE]["reviewed"], False)
        self.assertTrue(seeded[FILE][SAME_TRUE]["why"].startswith("seeded "))
        # Enforced, the seeded baseline passes the run it came from.
        text = (self.root / "nix/mutants-baseline.toml").read_text()
        (self.root / "nix/mutants-baseline.toml").write_text(text.replace("enforce = false", "enforce = true"))
        got = self.gate("sweep", r)
        self.assertEqual(got.returncode, 0, got.stdout + got.stderr)


if __name__ == "__main__":
    unittest.main()
