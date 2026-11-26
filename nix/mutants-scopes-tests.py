"""nix/mutants-scopes.py's own tests, each on a small workspace written for it
(checks.mutants-scopes runs them first).

Usage: python3 -I nix/mutants-scopes-tests.py [SCRIPT]. SCRIPT, nix/mutants-scopes.py by
default, is the script under test. Running the tests against a changed copy of the script shows
which test fails when a rule is removed.
"""

import pathlib
import subprocess
import sys
import tempfile
import textwrap
import unittest

SCRIPT = pathlib.Path(sys.argv.pop(1) if len(sys.argv) > 1 else pathlib.Path(__file__).with_name("mutants-scopes.py"))

# Two crates: `a` with two files, and `b` with one file whose functions include a method of
# `Draft` and a function that only the tests define.
SOURCES = {
    "crates/a/src/lib.rs": "pub mod plan;\npub fn keep() {}\n",
    "crates/a/src/plan.rs": "pub fn decide(x: u32) -> bool {\n    x == 1\n}\n",
    "crates/b/src/lib.rs": textwrap.dedent(
        """\
        struct Draft;
        impl Draft {
            fn finish(self) {}
        }
        impl std::fmt::Display for Report {
            fn fmt(&self) {}
        }
        pub fn check_slot() {}
        #[cfg(test)]
        mod tests {
            fn only_in_tests() {}
        }
        """
    ),
}

# The scopes that take every file above exactly once.
SCOPES = textwrap.dedent(
    """\
    [[unit]]
    package = "crate-a"
    files = ["crates/a/src/**/*.rs"]

    [[tokens]]
    package = "crate-b"
    files = ["crates/b/src/lib.rs"]
    re = "check_slot|Draft::|finish"
    """
)


class Case(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.dir.name)
        self.members = {"crates/a": "crate-a", "crates/b": "crate-b"}
        for path, text in SOURCES.items():
            self.write(path, text)
        self.scopes(SCOPES)

    def tearDown(self):
        self.dir.cleanup()

    def write(self, path, text):
        p = self.root / path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)

    def scopes(self, text, left_out=None):
        if left_out:
            text += "\n[left-out]\n" + "".join(f'"{k}" = "{v}"\n' for k, v in left_out.items())
        self.write("nix/mutants-scopes.toml", text)

    def check(self):
        members = "".join(f'"{m}", ' for m in self.members)
        self.write("Cargo.toml", f"[workspace]\nmembers = [{members}]\n")
        for member, name in self.members.items():
            self.write(f"{member}/Cargo.toml", f'[package]\nname = "{name}"\n')
        return subprocess.run([sys.executable, "-I", str(SCRIPT), str(self.root)], capture_output=True, text=True)

    def assertFails(self, *lines):
        got = self.check()
        self.assertEqual(got.returncode, 1, got.stdout + got.stderr)
        for line in lines:
            self.assertIn(line, got.stdout)
        return got.stdout


class Scopes(Case):
    def test_the_complete_workspace_passes(self):
        got = self.check()
        self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
        self.assertIn("each of the 3 source files", got.stdout)

    def test_a_crate_in_no_scope_fails(self):
        # A new workspace crate, as cakeys-names was when P4 added it.
        self.members["crates/names"] = "crate-names"
        self.write("crates/names/src/lib.rs", "pub fn curve() {}\n")
        self.assertFails("crates/names/src/lib.rs: in no scope of a tier and not left out")
        # Left out with a reason, it passes.
        self.scopes(SCOPES, {"crates/names/src/**/*.rs": "tables"})
        self.assertEqual(self.check().returncode, 0)

    def test_a_new_file_in_no_scope_fails(self):
        self.write("crates/b/src/extra.rs", "pub fn more() {}\n")
        self.assertFails("crates/b/src/extra.rs: in no scope of a tier and not left out")

    def test_a_renamed_file_fails(self):
        # The scope names the old path, and the new path is in no scope.
        self.scopes(SCOPES.replace('"crates/a/src/**/*.rs"', '"crates/a/src/lib.rs", "crates/a/src/plan.rs"'))
        self.assertEqual(self.check().returncode, 0)
        (self.root / "crates/a/src/plan.rs").rename(self.root / "crates/a/src/planner.rs")
        self.assertFails(
            "crates/a/src/plan.rs matches no source file",
            "crates/a/src/planner.rs: in no scope of a tier and not left out",
        )

    def test_a_renamed_left_out_file_fails(self):
        self.scopes(SCOPES.replace('"crates/a/src/**/*.rs"', '"crates/a/src/lib.rs"'), {"crates/a/src/plan.rs": "why"})
        self.assertEqual(self.check().returncode, 0)
        (self.root / "crates/a/src/plan.rs").rename(self.root / "crates/a/src/planner.rs")
        self.assertFails('[left-out] "crates/a/src/plan.rs" matches no source file')

    def test_a_renamed_function_fails(self):
        self.write("crates/b/src/lib.rs", SOURCES["crates/b/src/lib.rs"].replace("fn check_slot", "fn verify_slot"))
        out = self.assertFails("re part 'check_slot' matches no function")
        # The other parts still match: `Draft::` by the impl block, `finish` by its method.
        self.assertNotIn("'Draft::'", out)
        self.assertNotIn("'finish'", out)

    def test_a_function_only_the_tests_define_matches_nothing(self):
        self.scopes(SCOPES.replace('re = "check_slot|Draft::|finish"', 're = "check_slot|only_in_tests"'))
        self.assertFails("re part 'only_in_tests' matches no function")

    def test_a_function_after_a_nested_test_module_matches(self):
        # A `#[cfg(test)]` module inside another module removes only that module. The functions
        # after it are still code that cargo-mutants mutates (camigrate's lib.rs has this shape).
        nested = "mod inner {\n    #[cfg(test)]\n    mod t {\n        fn nested_test() {}\n    }\n}\n"
        self.write("crates/b/src/lib.rs", nested + SOURCES["crates/b/src/lib.rs"])
        got = self.check()
        self.assertEqual(got.returncode, 0, got.stdout + got.stderr)

    def test_a_function_only_a_nested_test_module_defines_matches_nothing(self):
        nested = "mod inner {\n    #[cfg(test)]\n    mod t {\n        fn nested_test() {}\n    }\n}\n"
        self.write("crates/b/src/lib.rs", nested + SOURCES["crates/b/src/lib.rs"])
        self.scopes(SCOPES.replace('re = "check_slot|Draft::|finish"', 're = "check_slot|nested_test"'))
        self.assertFails("re part 'nested_test' matches no function")

    def test_a_file_taken_twice_fails(self):
        self.scopes(SCOPES + '\n[[tokens]]\npackage = "crate-a"\nname = "again"\nfiles = ["crates/a/src/plan.rs"]\n')
        self.assertFails("crates/a/src/plan.rs: taken more than once, by [[unit]] crate-a, [[tokens]] again")
        self.scopes(SCOPES, {"crates/a/src/plan.rs": "why"})
        self.assertFails("crates/a/src/plan.rs: taken more than once, by [[unit]] crate-a, [left-out]")

    def test_a_scope_outside_its_package_fails(self):
        self.scopes(SCOPES + '\n[[unit]]\npackage = "crate-gone"\nfiles = ["crates/gone/src/lib.rs"]\n')
        self.assertFails("'crate-gone' is not a workspace crate")
        self.scopes(SCOPES.replace('files = ["crates/b/src/lib.rs"]', 'files = ["crates/b/src/lib.rs", "crates/a/src/plan.rs"]'))
        self.assertFails("crates/a/src/plan.rs is not a file of crate-b")

    def test_a_left_out_entry_needs_a_reason(self):
        self.write("crates/b/src/extra.rs", "pub fn more() {}\n")
        self.scopes(SCOPES, {"crates/b/src/extra.rs": " "})
        self.assertFails('[left-out] "crates/b/src/extra.rs": needs a reason')

    def test_an_unknown_table_is_bad_input(self):
        self.scopes(SCOPES + '\n[[tokenz]]\npackage = "crate-a"\nfiles = []\n')
        got = self.check()
        self.assertEqual(got.returncode, 2, got.stdout + got.stderr)


if __name__ == "__main__":
    unittest.main()
