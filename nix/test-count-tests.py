"""nix/test-count.py's own tests, on small workspaces written for each (checks.test-count runs
them first).

Usage: python3 -I nix/test-count-tests.py [SCRIPT]. SCRIPT, nix/test-count.py by default, is the
script under test: a changed copy shows which test holds which rule.
"""

import importlib.util
import pathlib
import subprocess
import sys
import tempfile
import textwrap
import unittest

SCRIPT = pathlib.Path(sys.argv.pop(1) if len(sys.argv) > 1 else pathlib.Path(__file__).with_name("test-count.py"))
# Read-only in the Nix sandbox, and no file to leave in a checkout.
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("test_count", SCRIPT)
tc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tc)

WORKSPACE = '[workspace]\nmembers = ["pkgs/a", "pkgs/b"]\ndefault-members = ["pkgs/a"]\n'
A = '[package]\nname = "a"\n\n[features]\ndefault = ["hw"]\nhw = ["deep"]\ndeep = []\n\n[[test]]\nname = "gated"\nrequired-features = ["deep"]\n'
B = '[package]\nname = "b-lib"\n\n[lib]\ntest = false\n\n[[test]]\nname = "custom"\nharness = false\n'

# One package of each shape: tests in comments and strings that are none, every way a module
# is reached, a binary, a test directory and a target behind a feature.
FILES = {
    "Cargo.toml": WORKSPACE,
    "pkgs/a/Cargo.toml": A,
    "pkgs/a/src/lib.rs": """
        //! #[test] fn in_a_doc_comment() {}
        /* #[test] fn in_a_block_comment() { /* nested */ } */
        mod plain;
        mod dir;
        #[cfg(test)]
        mod tests {
            const S: &str = "#[test] fn in_a_string() {}";
            const R: &str = r#"#[test] fn in_a_raw_string() {}"#;
            const C: char = '{';
            fn helper<'a>(x: &'a str) -> &'a str { x }
            #[test]
            fn top() {}
            #[test]
            #[should_panic(expected = "x")]
            fn second_attribute() { panic!("x") }
            #[tokio::test]
            async fn on_a_runtime() {}
            #[test]
            #[ignore]
            fn ignored() {}
            #[kani::proof]
            fn a_proof_is_no_test() {}
            mod inner {
                #[test]
                fn nested() {}
            }
            proptest::proptest! {
                #![proptest_config(Config::with_cases(8))]
                #[test]
                fn a_property(x in 0u8..) { let _ = x; }
            }
        }
        """,
    "pkgs/a/src/plain.rs": """
        mod child;
        #[test]
        fn in_plain() {}
        """,
    "pkgs/a/src/plain/child.rs": "#[test]\nfn in_child() {}\n",
    "pkgs/a/src/dir/mod.rs": """
        #[path = "../elsewhere.rs"]
        mod moved;
        """,
    "pkgs/a/src/elsewhere.rs": "mod beside;\n#[test]\nfn through_path() {}\n",
    "pkgs/a/src/beside.rs": "#[test]\nfn beside_the_path() {}\n",
    "pkgs/a/src/main.rs": "fn main() {}\n#[test]\nfn in_the_bin() {}\n",
    "pkgs/a/tests/flat.rs": "mod common;\n#[test]\nfn flat() {}\n",
    "pkgs/a/tests/common/mod.rs": "pub fn helper() {}\n#[test]\nfn shared() {}\n",
    "pkgs/a/tests/suite/main.rs": "#[test]\nfn in_a_directory() {}\n",
    "pkgs/a/tests/gated.rs": "#[test]\nfn gated() {}\n",
    "pkgs/b/Cargo.toml": B,
    "pkgs/b/src/lib.rs": "#[test]\nfn not_tested() {}\n",
    "pkgs/b/tests/custom.rs": "fn main() {}\n",
    "pkgs/b/tests/it.rs": "#[test]\nfn one() {}\n#[test]\nfn two() {}\n",
}

COUNTS = {
    "a": 10,
    "a::bin/a": 1,
    "a::flat": 2,
    "a::suite": 1,
    "a::gated": 1,
    "b-lib::it": 2,
}


def write(root, files):
    for rel, text in files.items():
        p = pathlib.Path(root) / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(text))


def run(*args):
    return subprocess.run([sys.executable, "-I", str(SCRIPT), *map(str, args)], capture_output=True, text=True)


class Case(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.dir.name)
        write(self.root, FILES)

    def tearDown(self):
        self.dir.cleanup()

    def manifest(self, counts):
        write(self.root, {"nix/test-count.toml": "# header\n" + "".join(f'"{b}" = {n}\n' for b, n in counts.items())})


class Counting(Case):
    def test_every_test_and_only_tests_count(self):
        got = {b: len(x.tests) for b, x in tc.count(tc.Tree(self.root)).items() if x.tests}
        self.assertEqual(got, COUNTS)

    def test_names_are_the_module_paths_libtest_gives(self):
        names = sorted(n for n, _, _ in tc.count(tc.Tree(self.root))["a"].tests)
        self.assertEqual(
            names,
            [
                "dir::moved::beside::beside_the_path",
                "dir::moved::through_path",
                "plain::child::in_child",
                "plain::in_plain",
                "tests::a_property",
                "tests::ignored",
                "tests::inner::nested",
                "tests::on_a_runtime",
                "tests::second_attribute",
                "tests::top",
            ],
        )

    def test_an_ignored_test_counts_but_is_not_expected_to_run(self):
        a = tc.count(tc.Tree(self.root))["a"]
        self.assertEqual(a.names["tests::ignored"], 1)
        self.assertEqual(a.run["tests::ignored"], 0)

    def test_a_test_it_cannot_count_is_an_error(self):
        for text in [
            "#[rstest]\nfn cases() {}\n",
            "macro_rules! many { ($n:ident) => { #[test] fn $n() {} } }\nmany!(x);\n",
            "mod missing;\n",
            "#[test]\nfn x() {}\n/* never closed\n",
        ]:
            with self.subTest(text=text):
                write(self.root, {"pkgs/b/tests/it.rs": text})
                self.manifest({})
                got = run(self.root)
                self.assertEqual(got.returncode, 2, got.stdout + got.stderr)


class Manifest(Case):
    def test_at_or_above_the_manifest_passes(self):
        self.manifest({**COUNTS, "a": COUNTS["a"] - 1})
        got = run(self.root)
        self.assertEqual(got.returncode, 0, got.stderr)

    def test_a_lost_test_fails_naming_its_binary(self):
        self.manifest(COUNTS)
        write(self.root, {"pkgs/b/tests/it.rs": "#[test]\nfn one() {}\n"})
        got = run(self.root)
        self.assertEqual(got.returncode, 1)
        self.assertIn("b-lib::it: 1 tests, ", got.stderr)

    def test_a_lost_binary_fails(self):
        self.manifest(COUNTS)
        (self.root / "pkgs/a/tests/suite/main.rs").unlink()
        got = run(self.root)
        self.assertEqual(got.returncode, 1)
        self.assertIn("a::suite: 0 tests", got.stderr)

    def test_a_test_moved_to_another_binary_lowers_the_one_it_left(self):
        self.manifest(COUNTS)
        write(self.root, {"pkgs/b/tests/it.rs": "#[test]\nfn one() {}\n#[test]\nfn two() {}\n#[test]\nfn flat() {}\n"})
        write(self.root, {"pkgs/a/tests/flat.rs": "mod common;\n"})
        got = run(self.root)
        self.assertEqual(got.returncode, 1)
        self.assertIn("a::flat: 1 tests", got.stderr)

    def test_the_tests_gone_are_named_from_the_base(self):
        self.manifest(COUNTS)
        with tempfile.TemporaryDirectory() as before:
            write(before, FILES)
            # One test deleted, one moved to another module of the same binary.
            write(self.root, {"pkgs/a/src/plain/child.rs": "\n", "pkgs/a/src/plain.rs": "mod child;\n"})
            write(self.root, {"pkgs/a/src/beside.rs": "#[test]\nfn beside_the_path() {}\n#[test]\nfn in_plain() {}\n"})
            got = run(self.root, "--base", before)
        self.assertEqual(got.returncode, 1)
        self.assertIn("gone since", got.stderr)
        self.assertIn("plain::child::in_child", got.stderr)
        self.assertNotIn(": plain::in_plain", got.stderr)
        self.assertIn("1 moved or renamed", got.stderr)

    def test_write_records_the_source_and_keeps_the_header(self):
        self.manifest({"a": 1})
        self.assertEqual(run(self.root, "--write").returncode, 0)
        text = (self.root / "nix/test-count.toml").read_text()
        self.assertTrue(text.startswith("# header\n"))
        self.assertEqual(tc.read_manifest(self.root / "nix/test-count.toml")[1], COUNTS)
        self.assertEqual(run(self.root).returncode, 0)


def junit(suites):
    cases = "".join(
        f'<testsuite name="{s}">' + "".join(f'<testcase name="{n}" classname="{s}"/>' for n in names) + "</testsuite>"
        for s, names in suites.items()
    )
    return f'<?xml version="1.0"?><testsuites name="nextest-run">{cases}</testsuites>'


class Report(Case):
    def ran(self, suites, *args, skips=""):
        write(self.root, {"junit.xml": junit(suites), "skips.log": skips})
        return run(self.root, "--junit", self.root / "junit.xml", "--skips", self.root / "skips.log", *args)

    def everything(self):
        binaries = tc.count(tc.Tree(self.root))
        return {b: sorted(x.run.elements()) for b, x in binaries.items() if x.tests}

    def test_a_run_of_every_test_passes(self):
        got = self.ran(self.everything(), "--", "--workspace")
        self.assertEqual(got.returncode, 0, got.stdout + got.stderr)

    def test_a_test_the_run_lacks_fails_naming_it(self):
        suites = self.everything()
        suites["a::flat"].remove("common::shared")
        got = self.ran(suites, "--", "--workspace")
        self.assertEqual(got.returncode, 1)
        self.assertIn("not run: common::shared", got.stderr)

    def test_a_test_the_source_lacks_fails(self):
        suites = self.everything()
        suites["b-lib::it"].append("three")
        got = self.ran(suites, "--", "--workspace")
        self.assertEqual(got.returncode, 1)
        self.assertIn("not in the source: three", got.stderr)

    def test_a_binary_the_run_built_must_have_run(self):
        suites = self.everything()
        del suites["b-lib::it"]
        got = self.ran(suites, "--", "--workspace")
        self.assertEqual(got.returncode, 1)
        self.assertIn("b-lib::it: built by this run, and it ran none", got.stderr)

    def test_a_binary_its_features_leave_out_need_not_run(self):
        suites = {b: n for b, n in self.everything().items() if b.startswith("a")}
        del suites["a::gated"]
        # The default members alone, without the feature: not built.
        got = self.ran(suites, "--", "--no-default-features")
        self.assertEqual(got.returncode, 0, got.stderr)
        self.assertIn("not built here (needs deep)", got.stdout)
        # The default feature implies it, as does naming it.
        self.assertEqual(self.ran(suites, "--").returncode, 1)
        self.assertEqual(self.ran(suites, "--", "--features", "a/deep", "--no-default-features").returncode, 1)
        self.assertEqual(self.ran(suites, "--", "--features", "deep", "--no-default-features").returncode, 1)

    def test_a_package_the_run_leaves_out_need_not_run(self):
        suites = {b: n for b, n in self.everything().items() if b.startswith("a")}
        for selection in [[], ["--workspace", "--exclude", "b-lib"], ["-p", "a"]]:
            with self.subTest(selection=selection):
                got = self.ran(suites, "--", *selection)
                self.assertEqual(got.returncode, 0, got.stderr)
        self.assertEqual(self.ran(suites, "--", "--workspace").returncode, 1)

    def test_skips_are_counted_per_binary(self):
        skips = "a::flat\tflat\tCAKEYS_X_REQUIRE\twhy\na::flat\tflat\tCAKEYS_X_REQUIRE\tagain\nb-lib::it\tone\tR\twhy\n"
        got = self.ran(self.everything(), "--", "--workspace", skips=skips)
        self.assertEqual(got.returncode, 0, got.stderr)
        row = next(ln for ln in got.stdout.splitlines() if ln.startswith("a::flat "))
        self.assertEqual(row.split()[1:], ["2", "1"])
        self.assertIn("2 of them skipped", got.stdout)

    def test_a_skip_in_a_binary_the_run_lacks_fails(self):
        suites = {b: n for b, n in self.everything().items() if b != "a::suite"}
        got = self.ran(suites, "--", "-p", "b-lib", skips="a::suite\tin_a_directory\tR\twhy\n")
        self.assertEqual(got.returncode, 1)
        self.assertIn("a::suite: the skip log names it", got.stderr)

    def test_a_partial_run_compares_nothing(self):
        got = self.ran({"a::flat": ["flat"]}, "--partial", "--", "--workspace")
        self.assertEqual(got.returncode, 0, got.stderr)


if __name__ == "__main__":
    unittest.main()
