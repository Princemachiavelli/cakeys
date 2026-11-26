"""nix/claims.py's own tests, on small trees written for each (checks.claims runs them first).

Usage: python3 -I nix/claims-test.py [SCRIPT]. SCRIPT, nix/claims.py by default, is the script
under test: a changed copy shows which test holds which rule.
"""

import pathlib
import subprocess
import sys
import tempfile
import textwrap
import tomllib
import unittest

HERE = pathlib.Path(__file__).resolve().parent
SCRIPT = pathlib.Path(sys.argv.pop(1) if len(sys.argv) > 1 else HERE / "claims.py")
# The repository's register, which may only go down from its seed: the count of unregistered
# claims at 3a17302, with DESIGN.md §8.1's bullets registered.
REGISTER = HERE.parent / "docs/claims.toml"
SEEDED_MAX = 101

FILES = {
    "Cargo.toml": '[workspace]\nmembers = ["crates/a"]\n',
    "crates/a/Cargo.toml": '[package]\nname = "a"\n',
    "crates/a/src/lib.rs": "#[test]\nfn holds_the_claim() {}\n\nfn helper() {}\n",
    "docs/DESIGN.md": """
        # Design

        Every lock is checked.
        A PIN is never printed, and a secret is
        never logged in the clear.
        Every verb takes the global options.

        ```text
        never a lock
        ```

        ### 8.1 Enforced (with tests)

        - **Held** (`holds_the_claim`).
        """,
    "docs/CAKEYS.md": "# cakeys\n",
    "docs/CAMIGRATE.md": "# camigrate\n",
    "docs/CAPROBE.md": "# caprobe\n",
}
CLAIMS = [
    "docs/DESIGN.md:4: Every lock is checked.",
    "docs/DESIGN.md:5: A PIN is never printed, and a secret is",
    "docs/DESIGN.md:6: never logged in the clear.",
]
HOLDS = {"doc": "docs/DESIGN.md", "kind": "enforced", "tests": ["holds_the_claim"]}


def write(root, files):
    for rel, text in files.items():
        p = pathlib.Path(root) / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(text))


def toml(value):
    if isinstance(value, bool):
        return str(value).lower()
    if isinstance(value, list):
        return "[" + ", ".join(map(toml, value)) + "]"
    return repr(value) if isinstance(value, int) else '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


class Case(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.dir.name)
        write(self.root, FILES)

    def tearDown(self):
        self.dir.cleanup()

    def run_with(self, most, *entries):
        text = f"max-unregistered = {toml(most)}\n" + "".join(
            "\n[[claim]]\n" + "".join(f"{k} = {toml(v)}\n" for k, v in e.items()) for e in entries
        )
        write(self.root, {"docs/claims.toml": text})
        got = subprocess.run([sys.executable, "-I", str(SCRIPT), str(self.root), "--list"], capture_output=True, text=True)
        return got.returncode, got.stdout, got.stderr


class Count(Case):
    def test_the_claims_are_the_universal_lines_about_a_subject(self):
        rc, out, err = self.run_with(3)
        self.assertEqual(rc, 0, err)
        self.assertEqual(out.splitlines()[:-1], CLAIMS)

    def test_an_unregistered_claim_over_the_max_fails(self):
        rc, _, err = self.run_with(2)
        self.assertEqual(rc, 1)
        self.assertIn("3 unregistered claims, more than max-unregistered (2)", err)

    def test_fewer_than_the_max_fails_until_it_is_lowered(self):
        rc, _, err = self.run_with(4)
        self.assertEqual(rc, 1)
        self.assertIn("lower max-unregistered in docs/claims.toml from 4 to 3", err)

    def test_a_registered_claim_does_not_count(self):
        rc, out, err = self.run_with(2, HOLDS | {"says": "Every lock is checked"})
        self.assertEqual(rc, 0, err)
        self.assertEqual(out.splitlines()[:-1], CLAIMS[1:])

    def test_a_phrase_across_a_line_break_registers_both_lines(self):
        entry = {"doc": "docs/DESIGN.md", "kind": "descriptive", "why": "a test", "says": "a secret is never logged"}
        rc, out, err = self.run_with(1, entry)
        self.assertEqual(rc, 0, err)
        self.assertEqual(out.splitlines()[:-1], CLAIMS[:1])

    def test_a_claim_the_words_miss_may_be_registered(self):
        rc, _, err = self.run_with(3, HOLDS | {"says": "Every verb takes the global options."})
        self.assertEqual(rc, 0, err)

    def test_the_max_must_be_a_count(self):
        for most in ["3", -1, True]:
            with self.subTest(most=most):
                rc, _, err = self.run_with(most)
                self.assertEqual(rc, 1)
                self.assertIn("not a count", err)


class Entries(Case):
    def fails(self, entry, why):
        rc, _, err = self.run_with(3, entry)
        self.assertEqual(rc, 1, err)
        self.assertIn(why, err)

    def test_an_entry_naming_a_missing_fn_fails(self):
        self.fails(HOLDS | {"says": "Every lock is checked", "tests": ["holds_the_claim", "gone_test"]}, "`gone_test` is no fn")

    def test_a_phrase_found_twice_or_not_at_all_fails(self):
        self.fails(HOLDS | {"says": "Every"}, "found 2 times in docs/DESIGN.md")
        self.fails(HOLDS | {"says": "Every lock is refused"}, "found 0 times in docs/DESIGN.md")

    def test_each_kind_needs_its_field_and_no_other(self):
        says = {"doc": "docs/DESIGN.md", "says": "Every lock is checked"}
        self.fails(says | {"kind": "enforced"}, 'kind "enforced" needs tests')
        self.fails(says | {"kind": "enforced", "tests": []}, 'kind "enforced" needs tests')
        self.fails(says | {"kind": "descriptive"}, 'kind "descriptive" needs why')
        self.fails(says | {"kind": "descriptive", "why": "x", "tests": ["holds_the_claim"]}, 'kind "descriptive" takes no tests')
        self.fails(says | {"kind": "obvious"}, "kind is 'obvious'")

    def test_tests_is_a_list_of_names(self):
        self.fails(HOLDS | {"says": "Every lock is checked", "tests": "holds_the_claim"}, "tests is a list of fn names")

    def test_a_document_that_is_not_there_fails(self):
        self.fails(HOLDS | {"doc": "docs/GONE.md", "says": "x"}, "docs/GONE.md does not exist")
        (self.root / "docs/CAPROBE.md").unlink()
        self.fails(HOLDS | {"says": "Every lock is checked"}, "docs/CAPROBE.md does not exist: claims.py's DOCUMENTS names it")

    def test_one_line_registered_twice_fails(self):
        rc, _, err = self.run_with(2, HOLDS | {"says": "Every lock"}, HOLDS | {"says": "is checked"})
        self.assertEqual(rc, 1)
        self.assertIn("docs/DESIGN.md:4 is registered already", err)


class Enforced(Case):
    """DESIGN.md §8.1 is held to its heading: each bullet names a test that holds it."""

    def section(self, text):
        design = (self.root / "docs/DESIGN.md").read_text().split("### 8.1")[0]
        write(self.root, {"docs/DESIGN.md": design + text})
        return self.run_with(3)

    def test_each_bullet_names_a_test(self):
        rc, _, err = self.section(
            """### 8.1 Enforced (with tests)

            - **Held** (`holds_the_claim()`).
            - **Named only a helper** (`helper`).
            - **Named nothing.**
            - **Held on its second line**, as
              `holds_the_claim` says.

            ### 8.2 Not enforced

            - **A gap** names nothing.
            """.replace("\n            ", "\n")
        )
        self.assertEqual(rc, 1)
        unheld = [line.split(": a bullet")[0] for line in err.splitlines() if "names no test" in line]
        self.assertEqual(unheld, ["claims: docs/DESIGN.md:16", "claims: docs/DESIGN.md:17"], err)

    def test_a_bullet_may_name_a_check_of_the_flake(self):
        write(self.root, {"checks.nix": "{ }:\n{\n  module = import ./t.nix;\n  inherit (x) clippy doc;\n}\n"})
        for name in ["module", "doc"]:
            with self.subTest(name=name):
                rc, _, err = self.section(f"### 8.1 Enforced (with tests)\n\n- **Held** (`checks.{name}`).\n")
                self.assertEqual(rc, 0, err)
        rc, _, err = self.section("### 8.1 Enforced (with tests)\n\n- **Held** (`checks.gone`).\n")
        self.assertEqual(rc, 1)
        self.assertIn("names no test in backticks", err)

    def test_every_bullet_held_passes(self):
        rc, _, err = self.section("### 8.1 Enforced (with tests)\n\n- **Held** (`holds_the_claim`).\n")
        self.assertEqual(rc, 0, err)

    def test_the_section_must_be_there(self):
        for text in ["### 8.1 Enforced\n\n- **Held** (`holds_the_claim`).\n", "### 8.1 Enforced (with tests)\n\nNo bullets.\n"]:
            with self.subTest(text=text):
                rc, _, err = self.section(text)
                self.assertEqual(rc, 1)
                self.assertIn("has no bullets under '### 8.1 Enforced (with tests)': claims.py's ENFORCED names it", err)


class Register(unittest.TestCase):
    def test_the_register_stays_at_or_below_its_seed(self):
        most = tomllib.loads(REGISTER.read_text())["max-unregistered"]
        self.assertLessEqual(most, SEEDED_MAX, "register the new claim, or soften it")


if __name__ == "__main__":
    unittest.main()
