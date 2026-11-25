"""Fixture tests of nix/ledger.py (checks.ledger): each rule, on a small tree made here, fails
the check when it is broken and passes when it is kept.

Usage: python3 -I ledger-test.py. Exits 1 on a failure.
"""

import hashlib
import json
import pathlib
import re
import subprocess
import sys
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).resolve().parent / "ledger.py"
MODULE = "profiles/modules/m/1.toml"
SOFT = "profiles/modules/s/1.toml"
CERT = "fixtures/cert.pem"
PROBED, EDITED, CAPTURED = "as probed\n", "as probed, then edited\n", "as captured\n"
# A Rust source with the comments, doc comments and literals the check must tell apart: comment
# markers inside a string, a quote inside a character, a raw string, and a comment after both.
RUST = """use a::b;
use c::d;

/// Signs.
fn a(x: &str) -> bool {
    // what it does
    let q = '"'; // a quote, in a character
    x == "a // b /* c */" && f(q, r#"q " q"#) // and after
}
"""
CARGO_LOCK = """version = 4

[[package]]
name = "cryptoki"
version = "0.12.0"
source = "git+https://example.org/rust-cryptoki?rev=aaaa#aaaa"

[[package]]
name = "other"
version = "1.0.0"
"""
FLAKE_LOCK = {
    "nodes": {
        "nixpkgs": {"locked": {"narHash": "sha256-A", "rev": "aaaa", "type": "tarball"}},
        "other": {"locked": {"narHash": "sha256-B", "rev": "bbbb", "type": "github"}},
        "root": {"inputs": {"nixpkgs": "nixpkgs", "other": "other"}},
    },
    "root": "root",
    "version": 7,
}
LOCKS = '["@src", "Cargo.lock#cryptoki", "flake.lock#nixpkgs"]'


def sha(text):
    return "sha256:" + hashlib.sha256(text.encode()).hexdigest()


class Ledger(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.dir.name)
        self.write(MODULE, PROBED)
        self.write(SOFT, "re-probed by every build\n")
        self.write(CERT, CAPTURED)
        self.write("code/a.rs", "fn a() {}\n")
        self.write("code/b.rs", "fn b() {}\n")
        self.write("scripts/regen.sh", "caprobe probe --write-probes --rsa-max-bits 4096 --out x\n")
        self.write("Cargo.lock", CARGO_LOCK)
        self.write("flake.lock", json.dumps(FLAKE_LOCK, indent=2))
        # The code's hash as the check prints it for pasting, read from a run that lacks it.
        code, out = self.run_with(code_hash="sha256:none")
        self.assertEqual(code, 1, out)
        self.code = self.printed_code_hash(out)

    def tearDown(self):
        self.dir.cleanup()

    def write(self, rel, text):
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    @staticmethod
    def printed_code_hash(out):
        return re.search(r'code-hash = "(sha256:[0-9a-f]{64})"', out).group(1)

    def run_with(self, *, module=None, code_hash=None, code='["@src"]', groups="", edits="", ack="", extra="", soft="", regen=""):
        """The check over the tree, with the ledger's entries as given; by default every hash is
        the tree's."""
        module, probed, captured = module or sha(PROBED), sha(PROBED), sha(CAPTURED)
        ledger = f"""
[regen]
rsa-max-bits = 4096
sources = ["scripts/regen.sh"]

[groups]
src = ["code/*.rs"]
{groups}

[[artifact]]
path = "{SOFT}"
from = "a software token"
regen = "scripts/regen.sh"
verified-by = "every build"
{soft}
[[artifact]]
path = "{MODULE}"
from = "a device"
regen = "{regen or 'probe it on the device'}"
code = {code}
hash = "{module}"
{extra}
[artifact.probed]
by = "abc1234"
date = "2026-11-19"
hash = "{probed}"
code-hash = "{code_hash or self.code}"
{edits}
{ack}

[[artifact]]
path = "{CERT}"
from = "a device's certificate"
regen = "capture it"
code = []
hash = "{captured}"

[artifact.probed]
by = "def5678"
date = "2026-11-13"
hash = "{captured}"
"""
        self.write("profiles/LEDGER.toml", ledger)
        p = subprocess.run([sys.executable, "-I", str(SCRIPT), str(self.root)], capture_output=True, text=True)
        return p.returncode, p.stdout + p.stderr

    def ack(self, code_hash, reprobe="probe it again"):
        return f'[artifact.acknowledged]\ncode-hash = "{code_hash}"\nby = "a reviewer"\nwhy = "the code moved"\nreprobe = "{reprobe}"\n'

    def test_a_kept_ledger_passes_and_says_what_each_file_is(self):
        code, out = self.run_with()
        self.assertEqual(code, 0, out)
        self.assertIn(f"build-verified  {SOFT}: every build", out)
        self.assertIn(f"fresh  {MODULE}: probed abc1234 (2026-11-19)", out)
        self.assertIn(f"captured  {CERT}: probed def5678 (2026-11-13)", out)

    def test_changed_code_fails_until_acknowledged(self):
        self.write("code/a.rs", "fn a() { changed() }\n")
        code, out = self.run_with()
        self.assertEqual(code, 1, out)
        self.assertIn("the code on its path changed since the run (abc1234, 2026-11-19)", out)
        now = self.printed_code_hash(out)
        self.assertNotEqual(now, self.code)
        code, out = self.run_with(ack=self.ack(now))
        self.assertEqual(code, 0, out)
        self.assertIn(f"STALE  {MODULE}: probed abc1234 (2026-11-19); the code on its path changed since", out)

    def test_a_file_added_renamed_or_removed_on_the_path_is_a_change(self):
        self.write("code/c.rs", "fn c() {}\n")
        self.assertEqual(self.run_with()[0], 1)
        (self.root / "code/c.rs").unlink()
        (self.root / "code/b.rs").rename(self.root / "code/d.rs")
        self.assertEqual(self.run_with()[0], 1)
        (self.root / "code/d.rs").unlink()
        self.assertEqual(self.run_with()[0], 1)

    def test_an_acknowledgement_covers_only_the_code_it_names(self):
        self.write("code/a.rs", "fn a() { changed() }\n")
        acknowledged = self.printed_code_hash(self.run_with()[1])
        self.write("code/b.rs", "fn b() { changed() }\n")
        code, out = self.run_with(ack=self.ack(acknowledged))
        self.assertEqual(code, 1, out)
        self.assertIn("changed since it was acknowledged (a reviewer)", out)

    def test_an_acknowledgement_beside_the_runs_code_fails(self):
        code, out = self.run_with(ack=self.ack(self.code))
        self.assertEqual(code, 1, out)
        self.assertIn("the code on its path is the run's: drop it", out)

    def test_an_acknowledgement_says_what_needs_a_run(self):
        self.write("code/a.rs", "fn a() { changed() }\n")
        now = self.printed_code_hash(self.run_with()[1])
        code, out = self.run_with(ack=self.ack(now, reprobe=""))
        self.assertEqual(code, 1, out)
        self.assertIn("[artifact.acknowledged] has no `reprobe`", out)

    def test_a_changed_file_fails_until_its_hand_edit_is_recorded(self):
        self.write(MODULE, EDITED)
        code, out = self.run_with()
        self.assertEqual(code, 1, out)
        self.assertIn(f'the file is not the one recorded (now hash = "{sha(EDITED)}")', out)
        # The new hash alone passes the edit off as the run's output.
        code, out = self.run_with(module=sha(EDITED))
        self.assertEqual(code, 1, out)
        self.assertIn("not what the run (abc1234) wrote, and no [[artifact.hand-edits]] row says so", out)
        edit = '[[artifact.hand-edits]]\nby = "f00d123"\nwhat = "a row by hand"\n'
        code, out = self.run_with(module=sha(EDITED), edits=edit)
        self.assertEqual(code, 0, out)
        self.assertIn(f"fresh  {MODULE}: probed abc1234 (2026-11-19), hand-edited since by f00d123", out)

    def test_hand_edits_beside_the_runs_output_fail(self):
        edit = '[[artifact.hand-edits]]\nby = "f00d123"\nwhat = "a row by hand"\n'
        code, out = self.run_with(edits=edit)
        self.assertEqual(code, 1, out)
        self.assertIn("[[artifact.hand-edits]] rows, but the file is what the run wrote: drop them", out)

    def test_a_captured_file_is_held_to_its_hash(self):
        self.write(CERT, "another certificate\n")
        code, out = self.run_with()
        self.assertEqual(code, 1, out)
        self.assertIn(f"{CERT}: the file is not the one recorded", out)

    def test_every_module_profile_has_an_entry(self):
        self.write("profiles/modules/n/2.toml", "unlisted\n")
        code, out = self.run_with()
        self.assertEqual(code, 1, out)
        self.assertIn("profiles/modules/n/2.toml has no [[artifact]]", out)

    def test_a_glob_or_group_that_names_nothing_fails(self):
        for globs in ('["@src", "elsewhere/*.rs"]', '["@nothing"]'):
            code, out = self.run_with(code=globs)
            self.assertEqual(code, 1, out)
            self.assertIn("names no file", out)

    def test_a_key_the_check_does_not_read_fails(self):
        code, out = self.run_with(extra='acknowledgement = "yes"\n')
        self.assertEqual(code, 1, out)
        self.assertIn("`acknowledgement` is no key of artifact", out)

    def test_a_build_verified_file_records_no_run(self):
        code, out = self.run_with(soft="code = []\n")
        self.assertEqual(code, 1, out)
        self.assertIn("so it records no run: drop ['code']", out)

    def test_every_regeneration_probes_the_same_rsa_sizes(self):
        # Review 2026-11-24 E-8: the cloud scripts passed no size and probed to caprobe's default.
        for script in ("caprobe probe --write-probes --rsa-max-bits 16384\n", "caprobe probe --write-probes\n"):
            self.write("scripts/regen.sh", script)
            code, out = self.run_with()
            self.assertEqual(code, 1, out)
            self.assertIn("scripts/regen.sh", out)
        self.write("scripts/regen.sh", 'km(&["probe", "--write-probes", "--rsa-max-bits", "4096"])\n')
        self.assertEqual(self.run_with()[0], 0)
        code, out = self.run_with(regen="caprobe probe --write-probes --rsa-max-bits 2048")
        self.assertEqual(code, 1, out)
        self.assertIn(f"{MODULE}: its regen probes RSA up to 2048, not 4096", out)

    def test_a_regen_command_names_files_that_exist(self):
        code, out = self.run_with(regen="scripts/gone.sh probe")
        self.assertEqual(code, 1, out)
        self.assertIn(f"{MODULE}: its regen names scripts/gone.sh, which does not exist", out)

    def code_changed(self, rel, before, after, code='["@src"]', groups=""):
        """Whether the check reads `rel` going from `before` to `after` as a change of the code on
        the path: the run is recorded with `before`, then the check runs on `after`."""
        self.write(rel, before)
        self.code = self.printed_code_hash(self.run_with(code=code, groups=groups, code_hash="sha256:none")[1])
        self.write(rel, after)
        status, out = self.run_with(code=code, groups=groups)
        if status == 0:
            self.assertIn(f"fresh  {MODULE}", out)
            return False
        self.assertIn("the code on its path changed since the run", out)
        return True

    # A Rust source counts as its tokens: the p0-gate merge renewed every acknowledgement for
    # rustfmt and doc comments alone, which teaches acknowledging without reading.
    def test_a_comment_or_rustfmt_edit_of_rust_is_no_change(self):
        for after in (
            RUST.replace("// what it does", "// what it does, said better"),
            RUST.replace("/// Signs.", "/// Signs.\n/** And more. */\n//! Inside."),
            RUST.replace("// a quote, in a character", "// a quote in a character, not a string"),
            RUST.replace("fn a", "/* a /* nested */ comment, ended */ fn a"),
            RUST.replace("    x == ", "x==").replace(" && f(", "\n        && f(\n            "),
        ):
            self.assertFalse(self.code_changed("code/a.rs", RUST, after), after)

    def test_an_edit_inside_a_rust_literal_is_a_change(self):
        for old, new in (
            ("/* c */", "/* d */"),
            ("a // b", "a //  b"),
            ('q " q', 'q "  q'),
            ("'\"'", "'#'"),
        ):
            self.assertTrue(self.code_changed("code/a.rs", RUST, RUST.replace(old, new)), new)

    def test_a_code_edit_of_rust_is_a_change(self):
        for old, new in (
            ("x ==", "x !="),
            # The same characters, other tokens: spacing that rustc reads is kept.
            ("&& f(", "& &f("),
            ("&str", "&'static str"),
            ("fn a", "pub fn a"),
            # rustc does not care, but the check does not parse Rust: a reorder is a change.
            ("use a::b;\nuse c::d;", "use c::d;\nuse a::b;"),
        ):
            self.assertTrue(self.code_changed("code/a.rs", RUST, RUST.replace(old, new)), new)

    def test_any_other_file_counts_byte_for_byte(self):
        self.assertTrue(self.code_changed("code/x.sh", "run # why\n", "run # why not\n", code='["@src", "code/*.sh"]'))

    # Review 2026-11-24, p0-follow: a cryptoki or nixpkgs bump changes what a run would measure,
    # but watching whole lockfiles would make every bump a re-acknowledgement of everything.
    def test_a_watched_lock_entry_is_code_and_the_rest_of_the_lock_is_not(self):
        bumped = json.loads(json.dumps(FLAKE_LOCK))
        bumped["nodes"]["nixpkgs"]["locked"]["rev"] = "cccc"
        other = json.loads(json.dumps(FLAKE_LOCK))
        other["nodes"]["other"]["locked"]["rev"] = "dddd"
        flake = json.dumps(FLAKE_LOCK, indent=2)
        for rel, before, after, change in (
            ("Cargo.lock", CARGO_LOCK, CARGO_LOCK.replace("0.12.0", "0.12.1"), True),
            ("Cargo.lock", CARGO_LOCK, CARGO_LOCK.replace("rev=aaaa#aaaa", "rev=bbbb#bbbb"), True),
            ("Cargo.lock", CARGO_LOCK, CARGO_LOCK.replace('"1.0.0"', '"1.0.1"'), False),
            ("flake.lock", flake, json.dumps(bumped, indent=2), True),
            ("flake.lock", flake, json.dumps(other, indent=2), False),
            # The entry, not the bytes: the same lock written another way.
            ("flake.lock", flake, json.dumps(FLAKE_LOCK, sort_keys=True), False),
        ):
            self.assertEqual(self.code_changed(rel, before, after, code=LOCKS), change, (rel, after))

    def test_a_lock_entry_that_names_nothing_fails(self):
        for code, missing in (
            ('["@src", "Cargo.lock#cryptokey"]', "Cargo.lock#cryptokey"),
            ('["@src", "flake.lock#nixpkg"]', "flake.lock#nixpkg"),
            ('["@src", "gone/Cargo.lock#cryptoki"]', "gone/Cargo.lock#cryptoki"),
        ):
            status, out = self.run_with(code=code)
            self.assertEqual(status, 1, out)
            self.assertIn(f"code entry {missing} names nothing", out)

    def test_a_lock_entry_in_a_group_counts(self):
        bumped = json.loads(json.dumps(FLAKE_LOCK))
        bumped["nodes"]["nixpkgs"]["locked"]["rev"] = "cccc"
        flake, groups = json.dumps(FLAKE_LOCK), 'locks = ["flake.lock#nixpkgs"]'
        self.assertTrue(self.code_changed("flake.lock", flake, json.dumps(bumped), '["@src", "@locks"]', groups))


if __name__ == "__main__":
    sys.exit(not unittest.main(exit=False).result.wasSuccessful())
