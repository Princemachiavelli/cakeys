"""Fixture tests of nix/golden-rows.py. Each test makes a git repository with a base commit and
one or more changes after it: commits, a merge, or the working tree. Each rule of the script fails
when the records break it and passes when the records keep it. The record that `--stub` writes,
once a person writes its whys, passes this check and nix/ledger.py's.

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
# The file after the first of two changes from BEFORE to AFTER: the first change moves a and
# removes c, and the second change adds d.
MIDDLE = """token = "t"

[rows]
"a" = "direct rfc7093m4"
"b" = "direct rfc7093m4"
"""
FIRST = {k: ROWS[k] for k in ("rows.a", "rows.c")}
SECOND = {"rows.d": ROWS["rows.d"]}


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
        # The regeneration verb's size, which checks.ledger holds to [regen] (review 2026-11-24 E-8).
        self.write("verb.rs", "pub const REGENERATE_RSA_MAX_BITS: u32 = 4096;\n")
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
        return '[regen]\nrsa-max-bits = 4096\nverb = "verb.rs"\nsources = []\n\n[golden."' + GOLDEN + '"]\ngenerator = ["gen/*.rs"]\n\n' + first + "".join(records)

    @staticmethod
    def record(rows, text=AFTER, by="f00d123", path=GOLDEN):
        lines = [f"{k!r} = {v}".replace("'", '"') for k, v in rows.items()]
        return (
            f'[[golden."{path}".regenerated]]\nby = "{by}"\nhash = "{sha(text)}"\ncode-hash = "sha256:second"\n'
            f'[golden."{path}".regenerated.rows]\n' + "\n".join(lines) + "\n\n"
        )

    @staticmethod
    def watch(path, text):
        """The entry of `path`, which the base's ledger does not have, with the first record that
        names `text` and lists no row."""
        return (
            f'[golden."{path}"]\ngenerator = ["gen/*.rs"]\n\n[[golden."{path}".regenerated]]\nby = "f00d123"\n'
            f'hash = "{sha(text)}"\ncode-hash = "sha256:x"\nwhy = "the first record"\nrows = {{}}\n\n'
        )

    def commit(self, message):
        """Commit every change in the working tree, and return the commit's hash."""
        self.git("add", "-A")
        self.git("commit", "-q", "-m", message)
        return self.git("rev-parse", "HEAD").strip()

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
            self.assertIn(f"row {left_out!r} moved (", out)
            self.assertIn("and is not listed", out)

    def test_a_listed_row_that_did_not_move_fails(self):
        # The sandbox check cannot tell: `b` is not listed with its value now.
        code, out = self.check(ROWS | {"rows.b": '{ was = "exit 17", why = "said to move" }'})
        self.assertEqual(code, 1, out)
        self.assertIn("row 'rows.b' is listed, but it did not move", out)

    def test_a_row_that_was_other_than_it_says_fails(self):
        for row, said in (
            ("rows.a", '{ was = "exit 13", why = "now identified" }'),
            ("rows.d", '{ was = "exit 17", why = "a new object" }'),
            ("rows.c", '{ why = "the grid dropped it" }'),
        ):
            code, out = self.check(ROWS | {row: said})
            self.assertEqual(code, 1, (row, out))
            self.assertIn(f"row {row!r} records its old value as", out)

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
        self.assertIn("row 'rows.a' moved (", out)

    def test_the_first_record_of_a_newly_watched_file_lists_no_row(self):
        new, text = "spec-coverage/objects/u.toml", '[rows]\n"x" = "exit 17"\n'
        self.write(new, text)
        first = self.watch(new, text).replace("rows = {}", 'rows = { "rows.x" = { why = "a row from before the ledger" } }')
        self.write("profiles/LEDGER.toml", self.ledger(self.record(ROWS)) + first)
        code, out = self.run_script(SCRIPT, "--base", self.base)
        self.assertEqual(code, 1, out)
        self.assertIn(f"{new}: [[regenerated]] f00d123: row 'rows.x' is listed, but the first record", out)

    def test_each_of_two_records_in_one_range_lists_its_own_change(self):
        # Two commits after the base change the file, and each commit adds the record of its change.
        first, second = self.record(FIRST, text=MIDDLE, by="first"), self.record(SECOND, by="second")
        self.write(GOLDEN, MIDDLE)
        self.write("profiles/LEDGER.toml", self.ledger(first))
        self.commit("the first change")
        self.write(GOLDEN, AFTER)
        self.write("profiles/LEDGER.toml", self.ledger(first, second))
        made = self.commit("the second change")
        code, out = self.run_script(SCRIPT, "--base", self.base)
        self.assertEqual(code, 0, out)
        self.assertIn(f"golden-rows: {GOLDEN}: 3 rows moved since {self.base}, as its 2 new records list", out)
        # The second record lists every row that moved since the base, as the only record of the
        # range would. Rows a and c moved in the first commit, not in the second.
        self.write("profiles/LEDGER.toml", self.ledger(first, self.record(ROWS, by="second")))
        code, out = self.run_script(SCRIPT, "--base", self.base)
        self.assertEqual(code, 1, out)
        for row in FIRST:
            self.assertIn(f"[[regenerated]] second, the version made in commit {made[:12]}: row {row!r} is listed, but it did not move", out)
        # A record whose hash no commit made fails, even when another record names the file now.
        self.write("profiles/LEDGER.toml", self.ledger(first, self.record(SECOND, text=BEFORE + "#\n", by="stray"), second))
        code, out = self.run_script(SCRIPT, "--base", self.base)
        self.assertEqual(code, 1, out)
        stray = sha(BEFORE + "#\n")
        self.assertIn(f'[[regenerated]] stray: the file never had this record\'s hash ("{stray}") in a commit since {self.base}', out)

    def test_a_merge_record_lists_the_rows_that_the_merge_moved_from_its_first_parent(self):
        main = self.git("rev-parse", "--abbrev-ref", "HEAD").strip()
        side_text = BEFORE + '"d" = "exit 15"\n'
        first, side = self.record(FIRST, text=MIDDLE, by="first"), self.record(SECOND, text=side_text, by="side")
        # A side branch adds d, while the main branch moves a and removes c.
        self.git("switch", "-q", "-c", "side")
        self.write(GOLDEN, side_text)
        self.write("profiles/LEDGER.toml", self.ledger(side))
        self.commit("the side change")
        self.git("switch", "-q", main)
        self.write(GOLDEN, MIDDLE)
        self.write("profiles/LEDGER.toml", self.ledger(first))
        self.commit("the main change")
        # The merge makes a version that neither parent has. Compared with its first parent, the
        # main branch, the merge adds d.
        self.git("merge", "-q", "-s", "ours", "--no-commit", "side")
        self.write(GOLDEN, AFTER)
        self.write("profiles/LEDGER.toml", self.ledger(first, side, self.record(SECOND, by="merge")))
        merge = self.commit("the merge")
        code, out = self.run_script(SCRIPT, "--base", self.base)
        self.assertEqual(code, 0, out)
        self.assertIn(f"golden-rows: {GOLDEN}: 3 rows moved since {self.base}, as its 3 new records list", out)
        # A merge record that lists no row leaves out the row that the merge brought from the side.
        self.write("profiles/LEDGER.toml", self.ledger(first, side, self.record({}, by="merge")))
        code, out = self.run_script(SCRIPT, "--base", self.base)
        self.assertEqual(code, 1, out)
        self.assertIn(f"[[regenerated]] merge, the version made in commit {merge[:12]}: row 'rows.d' moved ((none) -> \"exit 15\") and is not listed", out)

    def test_a_newly_watched_file_is_checked_from_its_first_record(self):
        new = "spec-coverage/objects/u.toml"
        before, watched, after = '[rows]\n"x" = "exit 17"\n', '[rows]\n"x" = "exit 13"\n', '[rows]\n"x" = "exit 13"\n"y" = "exit 15"\n'
        self.write(GOLDEN, BEFORE)
        self.write(new, before)
        base = self.commit("the base, whose ledger does not watch u.toml")
        # The file changes twice before the ledger watches it. No record names the version that the
        # first of these changes makes, and none needs to, because the ledger did not watch the file.
        self.write(new, '[rows]\n"x" = "exit 15"\n')
        self.commit("a change before the ledger watches u.toml")
        self.write(new, watched)
        self.commit("a second change before the ledger watches u.toml")
        self.write("profiles/LEDGER.toml", self.ledger() + self.watch(new, watched))
        self.commit("the ledger starts to watch u.toml")
        self.write(new, after)
        self.write("profiles/LEDGER.toml", self.ledger() + self.watch(new, watched) + self.record({"rows.y": '{ why = "new" }'}, text=after, path=new))
        self.commit("a change after the ledger watches u.toml")
        code, out = self.run_script(SCRIPT, "--base", base)
        self.assertEqual(code, 0, out)
        self.assertIn(f"golden-rows: {new}: the ledger's first record, which starts watching it", out)
        self.assertIn(f"golden-rows: {new}: 1 row moved since the version that the ledger's first record names, as its record lists", out)
        # The later record lists the change from before the ledger watched the file as well.
        both = {"rows.x": '{ was = "exit 17", why = "old" }', "rows.y": '{ why = "new" }'}
        self.write("profiles/LEDGER.toml", self.ledger() + self.watch(new, watched) + self.record(both, text=after, path=new))
        code, out = self.run_script(SCRIPT, "--base", base)
        self.assertEqual(code, 1, out)
        self.assertIn("row 'rows.x' is listed, but it did not move", out)

    def test_a_change_without_a_record_between_two_commits_fails(self):
        once, twice = (BEFORE.replace('"a" = "exit 17"', f'"a" = "{v}"') for v in ("direct rfc7093m4", "exit 15"))
        self.write(GOLDEN, once)
        unrecorded = self.commit("a change without a record")
        self.write(GOLDEN, twice)
        # The record of the second change gives row a's value before the second change, so the
        # first change of row a has no record.
        self.write("profiles/LEDGER.toml", self.ledger(self.record({"rows.a": '{ was = "direct rfc7093m4", why = "w" }'}, text=twice)))
        self.commit("a change with a record")
        missing = f"{GOLDEN}: commit {unrecorded[:12]} changed the file to a version that no record names (hash = \"{sha(once)}\")"
        code, out = self.run_script(SCRIPT, "--base", self.base)
        self.assertEqual(code, 1, out)
        self.assertIn(missing, out)
        # A record of the whole range, which gives row a's value at the base, does not cover the
        # version that the first commit made either.
        self.write("profiles/LEDGER.toml", self.ledger(self.record({"rows.a": '{ was = "exit 17", why = "w" }'}, text=twice)))
        code, out = self.run_script(SCRIPT, "--base", self.base)
        self.assertEqual(code, 1, out)
        self.assertIn(missing, out)

    def test_a_change_without_a_record_after_the_ledger_starts_to_watch_a_file_fails(self):
        new = "spec-coverage/objects/u.toml"
        before, between, after = ('[rows]\n"x" = "exit %s"\n' % v for v in (17, 13, 15))
        self.write(GOLDEN, BEFORE)
        self.write(new, before)
        base = self.commit("the base, whose ledger does not watch u.toml")
        self.write("profiles/LEDGER.toml", self.ledger() + self.watch(new, before))
        self.commit("the ledger starts to watch u.toml")
        self.write(new, between)
        unrecorded = self.commit("a change without a record")
        self.write(new, after)
        self.write("profiles/LEDGER.toml", self.ledger() + self.watch(new, before) + self.record({"rows.x": '{ was = "exit 13", why = "w" }'}, text=after, path=new))
        self.commit("a change with a record")
        code, out = self.run_script(SCRIPT, "--base", base)
        self.assertEqual(code, 1, out)
        self.assertIn(f"{new}: commit {unrecorded[:12]} changed the file to a version that no record names", out)

    def test_a_return_to_a_version_that_an_older_record_names_fails_without_a_new_record(self):
        # At this base, the file is MIDDLE. The change returns it to BEFORE, which the base's
        # first record names, so the change makes no version without a record. The rows a and c
        # still moved since the base, and no record that the change added lists them.
        self.write(GOLDEN, MIDDLE)
        self.write("profiles/LEDGER.toml", self.ledger(self.record(FIRST, text=MIDDLE)))
        base = self.commit("the base, at MIDDLE")
        self.write(GOLDEN, BEFORE)
        code, out = self.run_script(SCRIPT, "--base", base)
        self.assertEqual(code, 1, out)
        self.assertIn(f"{GOLDEN}: row 'rows.a' moved since {base} (\"direct rfc7093m4\" -> \"exit 17\"), and no record that this change added lists it", out)

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

    def test_the_stub_compares_with_the_parent_of_the_change_that_made_the_file(self):
        # The first change has its record. The second change is committed without one, so the
        # stub lists only the row that the second change moved.
        first = self.record(FIRST, text=MIDDLE, by="first")
        self.write(GOLDEN, MIDDLE)
        self.write("profiles/LEDGER.toml", self.ledger(first))
        parent = self.commit("the first change, with its record")
        self.write(GOLDEN, AFTER)
        self.commit("the second change, without a record")
        code, out = self.run_script(SCRIPT, "--stub", "--base", self.base)
        self.assertEqual(code, 0, out)
        self.assertIn(f"# {GOLDEN}: 1 row moved since {parent[:12]}", out)
        self.assertNotIn("rows.a", out)
        stub = re.sub(r"(?m)^# spec-coverage.*\n", "", out)
        self.write("profiles/LEDGER.toml", self.ledger(first) + self.filled(stub))
        code, out = self.run_script(SCRIPT, "--base", self.base)
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
