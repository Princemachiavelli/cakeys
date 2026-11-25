"""nix/oracle-count.py's own tests, on small trees written for each (checks.oracle-count runs
them first).

Usage: python3 -I nix/oracle-count-tests.py [SCRIPT]. SCRIPT, nix/oracle-count.py by default, is
the script under test (with nix/test-count.py beside it, whose lexer it reads): a changed copy
shows which test holds which rule.
"""

import pathlib
import subprocess
import sys
import tempfile
import textwrap
import unittest

SCRIPT = pathlib.Path(sys.argv.pop(1) if len(sys.argv) > 1 else pathlib.Path(__file__).with_name("oracle-count.py"))
# Read-only in the Nix sandbox, and no file to leave in a checkout.
sys.dont_write_bytecode = True

# Each kind of site once or more, and what is none: the message, a comment, a string, a file's
# text, a field of the parsed output compared whole, a name bound in another function.
SITES = """
    fn refusal() {
        let o = run();
        assert_eq!(code(&o), 13, "{}", stderr(&o));
        assert!(stderr(&o).contains("refused"));
        let err = stderr(&o);
        assert!(err.contains("why") && !err.contains("other"), "{err}");
        let warned = stderr(&o).lines().any(|l| l.contains("warning"));
        assert!(warned);
        assert!(code(&o) == 17 && stderr(&o).contains("x"));
        let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
        assert!(v["reasons"][0].as_str().unwrap().contains("why"));
        assert_eq!(v["rule"].as_str(), Some("locator-free"));
        let text = std::fs::read_to_string("keys.lock").unwrap();
        assert!(text.contains("objects"), "{}", stderr(&o));
        assert!(o.status.success());
        assert_eq!(e.code(&["x"]), 0);
        // assert!(stderr(&o).contains("in a comment"));
        let s = "assert!(stderr(&o).contains(\\"in a string\\"))";
        for r in rows(&o) {
            assert!(r.error.unwrap().contains("e"));
        }
        if let Some(said) = said_by(&o) {
            assert!(said.contains("y"));
        }
    }

    fn another() {
        let err = String::new();
        assert!(err.contains("x"));
        let line = |o: &Output| {
            let c = code(o);
            assert_ne!(c, 0);
        };
    }
"""
# refusal: the stderr contains, `err` (one site), `warned`, the exit and prose one, the parsed
# reason, the row's error. Exits: 13, the exit and prose one, success, `e.code`, `c`.
PROSE, EXITS = 6, 5


def write(root, files):
    for rel, text in files.items():
        p = pathlib.Path(root) / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(text))


def run(*args):
    return subprocess.run([sys.executable, "-I", str(SCRIPT), *map(str, args)], capture_output=True, text=True)


def prose(n, name="p"):
    """A test with `n` prose sites."""
    return f"fn {name}() {{\n" + "".join(f'    assert!(stderr(&o).contains("{i}"));\n' for i in range(n)) + "}\n"


class Case(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.dir.name)

    def tearDown(self):
        self.dir.cleanup()

    def manifest(self, most):
        write(self.root, {"nix/oracle-count.toml": "# header\n" + "".join(f'"{f}" = {n}\n' for f, n in most.items())})

    def read_manifest(self):
        return (self.root / "nix/oracle-count.toml").read_text()


class Counting(Case):
    def test_sites_are_counted_by_their_subject(self):
        write(self.root, {"crates/a/tests/t.rs": SITES})
        self.manifest({"crates/a/tests/t.rs": PROSE})
        got = run(self.root)
        self.assertEqual(got.returncode, 0, got.stderr)
        row = next(ln for ln in got.stdout.splitlines() if ln.startswith("crates/a/tests/t.rs"))
        self.assertEqual(row.split()[1:], [str(PROSE), str(PROSE), str(EXITS)])

    def test_only_integration_tests_count(self):
        write(self.root, {"crates/a/src/lib.rs": prose(2), "crates/a/tests/common/mod.rs": prose(1)})
        self.manifest({"crates/a/tests/common/mod.rs": 1})
        got = run(self.root)
        self.assertEqual(got.returncode, 0, got.stderr)
        self.assertIn("1 prose sites", got.stdout)

    def test_a_source_it_cannot_read_is_exit_2(self):
        write(self.root, {"crates/a/tests/t.rs": 'fn t() { let s = "no end; }\n'})
        self.manifest({})
        self.assertEqual(run(self.root).returncode, 2)


class Ratchet(Case):
    def test_one_more_prose_site_fails(self):
        write(self.root, {"crates/a/tests/t.rs": prose(2)})
        self.manifest({"crates/a/tests/t.rs": 2})
        self.assertEqual(run(self.root).returncode, 0)
        write(self.root, {"crates/a/tests/t.rs": prose(3)})
        got = run(self.root)
        self.assertEqual(got.returncode, 1)
        self.assertIn("crates/a/tests/t.rs: 3 prose assertion sites", got.stderr)

    def test_a_file_the_manifest_does_not_name_has_none(self):
        write(self.root, {"crates/a/tests/t.rs": prose(1)})
        self.manifest({})
        self.assertEqual(run(self.root).returncode, 1)

    def test_exit_sites_are_not_limited(self):
        exits = "fn e() {\n" + "    assert_eq!(code(&o), 13);\n" * 5 + "}\n"
        write(self.root, {"crates/a/tests/t.rs": prose(1) + exits})
        self.manifest({"crates/a/tests/t.rs": 1})
        got = run(self.root)
        self.assertEqual(got.returncode, 0, got.stderr)
        self.assertIn("5 exit sites", got.stdout)

    def test_fewer_passes_and_says_to_lower(self):
        write(self.root, {"crates/a/tests/t.rs": prose(1)})
        self.manifest({"crates/a/tests/t.rs": 3})
        got = run(self.root)
        self.assertEqual(got.returncode, 0, got.stderr)
        self.assertIn("2 fewer than the manifest allows", got.stdout)


class Write(Case):
    def test_write_only_lowers(self):
        write(
            self.root,
            {
                "crates/a/tests/lower.rs": prose(1),
                "crates/a/tests/more.rs": prose(3),
                "crates/a/tests/unlisted.rs": prose(2),
                "crates/a/tests/none.rs": "fn n() {}\n",
            },
        )
        self.manifest({"crates/a/tests/lower.rs": 3, "crates/a/tests/more.rs": 1, "crates/a/tests/none.rs": 2})
        got = run(self.root, "--write")
        self.assertEqual(got.returncode, 0, got.stderr)
        self.assertEqual(
            self.read_manifest(), '# header\n\n"crates/a/tests/lower.rs" = 1\n"crates/a/tests/more.rs" = 1\n'
        )
        # What it could not lower still fails.
        self.assertEqual(run(self.root).returncode, 1)

    def test_write_seeds_a_manifest_that_is_not_there(self):
        write(self.root, {"crates/a/tests/t.rs": prose(2), "crates/b/tests/u.rs": "fn n() {}\n"})
        self.assertEqual(run(self.root, "--write").returncode, 0)
        self.assertEqual(self.read_manifest(), '"crates/a/tests/t.rs" = 2\n')
        self.assertEqual(run(self.root).returncode, 0)


if __name__ == "__main__":
    unittest.main()
