"""Fixture tests of nix/golden-rows.py: on two trees, a base commit and the change after it, in a
git repository made here, each rule fails when it is broken and passes when it is kept; and the
record `--stub` writes, once its whys are written, passes this check and nix/ledger.py's.

Usage: python3 -I golden-rows-test.py. Exits 1 on a failure. Needs git.
"""

import hashlib
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
SCRIPT, LEDGER = HERE / "golden-rows.py", HERE / "ledger.py"
GOLDEN = "spec-coverage/objects/t.toml"
BEFORE = """token = "t"

[summary]
"direct" = 1
"exit" = 2

[rows]
"a" = "exit 17"
"b" = "direct rfc7093m4"
"c" = "exit 13"
"""
# a moved, c removed, d added; b stays.
AFTER = """token = "t"

[summary]
"direct" = 2
"exit" = 1

[rows]
"a" = "direct rfc7093m4"
"b" = "direct rfc7093m4"
"d" = "exit 15"
"""
ROWS = {
    "rows.a": '{ was = "exit 17", why = "now identified" }',
    "rows.c": '{ was = "exit 13", why = "the grid dropped it" }',
    "rows.d": '{ why = "a new object" }',
}


def sha(text):
    return "sha256:" + hashlib.sha256(text.encode()).hexdigest()


class GoldenRows(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.dir.name)
        self.env = dict(os.environ, HOME=self.dir.name, GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL="/dev/null")
        self.env.pop("GITHUB_STEP_SUMMARY", None)
        self.git("init", "-q")
        self.write("gen/a.rs", "fn a() {}\n")
        self.write(GOLDEN, BEFORE)
        self.write("profiles/LEDGER.toml", self.ledger())
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "base")
        self.base = self.git("rev-parse", "HEAD").strip()
        self.write("gen/a.rs", "fn a() { moved() }\n")
        self.write(GOLDEN, AFTER)

    def tearDown(self):
        self.dir.cleanup()

    def git(self, *args):
        p = subprocess.run(
            ["git", "-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false", *args],
            cwd=self.root,
            env=self.env,
            capture_output=True,
            text=True,
            check=True,
        )
        return p.stdout

    def write(self, rel, text):
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    @staticmethod
    def ledger(*records):
        first = (
            f'[[golden."{GOLDEN}".regenerated]]\nby = "seed"\nhash = "{sha(BEFORE)}"\ncode-hash = "sha256:first"\n'
            'why = "the first record"\nrows = {}\n\n'
        )
        return '[regen]\nrsa-max-bits = 4096\nsources = []\n\n[golden."' + GOLDEN + '"]\ngenerator = ["gen/*.rs"]\n\n' + first + "".join(records)

    @staticmethod
    def record(rows, text=AFTER, by="f00d123"):
        lines = [f"{k!r} = {v}".replace("'", '"') for k, v in rows.items()]
        return (
            f'[[golden."{GOLDEN}".regenerated]]\nby = "{by}"\nhash = "{sha(text)}"\ncode-hash = "sha256:second"\n'
            f'[golden."{GOLDEN}".regenerated.rows]\n' + "\n".join(lines) + "\n\n"
        )

    def run_script(self, script, *args, summary=None):
        env = dict(self.env)
        if summary:
            env["GITHUB_STEP_SUMMARY"] = str(summary)
        p = subprocess.run([sys.executable, "-I", str(script), *args, str(self.root)], env=env, capture_output=True, text=True)
        return p.returncode, p.stdout + p.stderr

    def check(self, rows, summary=None):
        self.write("profiles/LEDGER.toml", self.ledger(self.record(rows)))
        return self.run_script(SCRIPT, "--base", self.base, summary=summary)

    def test_a_record_of_exactly_the_moved_rows_passes_and_says_them(self):
        summary = self.root / "summary.md"
        code, out = self.check(ROWS, summary=summary)
        self.assertEqual(code, 0, out)
        self.assertIn(f"golden-rows: {GOLDEN}: 3 rows moved since {self.base}, as its record lists", out)
        table = summary.read_text()
        self.assertIn('| `rows.a` | "exit 17" | "direct rfc7093m4" | now identified |', table)
        self.assertIn('| `rows.c` | "exit 13" | (none) | the grid dropped it |', table)
        self.assertIn('| `rows.d` | (none) | "exit 15" | a new object |', table)
        # The summary counts the rows, so it is none: nothing of it is asked for.
        self.assertNotIn("summary", table)

    def test_a_moved_row_not_listed_fails(self):
        for left_out in ROWS:
            code, out = self.check({k: v for k, v in ROWS.items() if k != left_out})
            self.assertEqual(code, 1, out)
            self.assertIn(f"row {left_out!r} moved since {self.base}", out)

    def test_a_listed_row_that_did_not_move_fails(self):
        # The sandbox check cannot tell: `b` is not listed with its value now.
        code, out = self.check(ROWS | {"rows.b": '{ was = "exit 17", why = "said to move" }'})
        self.assertEqual(code, 1, out)
        self.assertIn(f"row 'rows.b' is listed, but did not move since {self.base}", out)

    def test_a_row_that_was_other_than_it_says_fails(self):
        for row, said in (
            ("rows.a", '{ was = "exit 13", why = "now identified" }'),
            ("rows.d", '{ was = "exit 17", why = "a new object" }'),
            ("rows.c", '{ why = "the grid dropped it" }'),
        ):
            code, out = self.check(ROWS | {row: said})
            self.assertEqual(code, 1, (row, out))
            self.assertIn(f"row {row!r} says it was", out)

    def test_a_change_without_a_record_fails(self):
        self.write("profiles/LEDGER.toml", self.ledger())
        code, out = self.run_script(SCRIPT, "--base", self.base)
        self.assertEqual(code, 1, out)
        self.assertIn("a change without a record", out)

    def test_an_unchanged_golden_file_asks_nothing(self):
        self.write(GOLDEN, BEFORE)
        code, out = self.run_script(SCRIPT, "--base", self.base)
        self.assertEqual(code, 0, out)
        self.assertEqual(out, "")

    def test_a_first_record_starts_the_watch_and_only_the_first(self):
        # A file the ledger did not watch at the base: its first record lists no row.
        new, text = "spec-coverage/objects/u.toml", '[rows]\n"x" = "exit 17"\n'
        self.write(new, text)
        first = f'[golden."{new}"]\ngenerator = ["gen/*.rs"]\n\n[[golden."{new}".regenerated]]\nby = "f00d123"\n'
        first += f'hash = "{sha(text)}"\ncode-hash = "sha256:x"\nwhy = "the first record"\nrows = {{}}\n\n'
        self.write("profiles/LEDGER.toml", self.ledger(self.record(ROWS)) + first)
        code, out = self.run_script(SCRIPT, "--base", self.base)
        self.assertEqual(code, 0, out)
        self.assertIn(f"golden-rows: {new}: the ledger's first record, which starts watching it", out)
        # A file it watched: starting its record again does not excuse the rows that moved.
        restart = self.ledger().replace(sha(BEFORE), sha(AFTER))
        self.write("profiles/LEDGER.toml", restart)
        code, out = self.run_script(SCRIPT, "--base", self.base)
        self.assertEqual(code, 1, out)
        self.assertIn("row 'rows.a' moved since", out)

    def filled(self, stub):
        """`stub` with its whys and who written, as a person would."""
        return stub.replace('"TODO: the commit or package"', '"f00d123"').replace('why = "TODO"', 'why = "reviewed"')

    def test_the_stub_filled_in_passes_both_checks(self):
        code, out = self.run_script(SCRIPT, "--stub", "--base", self.base)
        self.assertEqual(code, 0, out)
        self.assertIn('why = "TODO"', out)
        self.assertIn('"rows.a" = { was = "exit 17", why = "TODO" }', out)
        self.assertIn('# now: "direct rfc7093m4"', out)
        stub = re.sub(r"(?m)^# spec-coverage.*\n", "", out)
        # Unfilled, the ledger refuses it.
        self.write("profiles/LEDGER.toml", self.ledger() + stub)
        self.assertNotEqual(self.run_script(LEDGER)[0], 0)
        self.write("profiles/LEDGER.toml", self.ledger() + self.filled(stub))
        self.assertEqual(self.run_script(SCRIPT, "--base", self.base), (0, f"golden-rows: {GOLDEN}: 3 rows moved since {self.base}, as its record lists\n"))
        code, out = self.run_script(LEDGER)
        self.assertEqual(code, 0, out)

    def test_the_stub_of_a_regeneration_waiting_as_new(self):
        # The writers leave a regeneration beside the file (`<file>.new`) until it is accepted.
        self.write(GOLDEN, BEFORE)
        self.write(GOLDEN + ".new", AFTER)
        code, out = self.run_script(SCRIPT, "--stub")
        self.assertEqual(code, 0, out)
        self.assertIn(f"# {GOLDEN}: 3 rows moved since {GOLDEN}", out)
        self.assertIn(f'hash = "{sha(AFTER)}"', out)


if __name__ == "__main__":
    sys.exit(not unittest.main(exit=False).result.wasSuccessful())
