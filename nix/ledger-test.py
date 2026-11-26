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
# A build re-probes SOFT, so it is golden: a profile with a list and a table of rows.
SOFT_TEXT = """profile = "s/1"
advertise = ["CKM_A", "CKM_B"]

[capabilities]
"generate.CKK_AES.8" = { answer = "no", by = "module" }
"generate.CKK_AES.16" = { answer = "yes", by = "host" }
"""
# SOFT regenerated: one row moved, one added, one list member gone.
SOFT_AGAIN = """profile = "s/1"
advertise = ["CKM_A"]

[capabilities]
"generate.CKK_AES.8" = { answer = "yes", by = "host" }
"generate.CKK_AES.16" = { answer = "yes", by = "host" }
"generate.CKK_AES.32" = { answer = "yes", by = "host" }
"""
# What each moved row was, with why it is right now.
MOVED = (
    '"capabilities.generate.CKK_AES.8" = { was = { answer = "no", by = "module" }, why = "the module takes 8 bytes" }, '
    '"capabilities.generate.CKK_AES.32" = { why = "a new size" }, '
    '"advertise.CKM_B" = { was = true, why = "the module stopped listing it" }'
)
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
        self.write(SOFT, SOFT_TEXT)
        self.write(CERT, CAPTURED)
        self.write("code/a.rs", "fn a() {}\n")
        self.write("code/b.rs", "fn b() {}\n")
        self.write("scripts/regen.sh", '# with --write-probes, as the verb runs\ncaprobe regenerate "$name" --out x\n')
        self.write("code/verb.rs", "pub const REGENERATE_RSA_MAX_BITS: u32 = 4096;\n")
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

    def run_with(
        self,
        *,
        module=None,
        code_hash=None,
        code='["@src"]',
        groups="",
        edits="",
        ack="",
        extra="",
        soft="",
        regen="",
        golden=None,
        verb="code/verb.rs",
    ):
        """The check over the tree, with the ledger's entries as given; by default every hash is
        the tree's, and the golden SOFT has its first record only."""
        module, probed, captured = module or sha(PROBED), sha(PROBED), sha(CAPTURED)
        ledger = f"""
[regen]
rsa-max-bits = 4096
verb = "{verb}"
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

{self.golden() if golden is None else golden}
"""
        self.write("profiles/LEDGER.toml", ledger)
        p = subprocess.run([sys.executable, "-I", str(SCRIPT), str(self.root)], capture_output=True, text=True)
        return p.returncode, p.stdout + p.stderr

    def ack(self, code_hash, reprobe="probe it again"):
        return f'[artifact.acknowledged]\ncode-hash = "{code_hash}"\nby = "a reviewer"\nwhy = "the code moved"\nreprobe = "{reprobe}"\n'

    def golden(self, *records, path=SOFT):
        """`path`'s [golden] entry: SOFT_TEXT's first record, then `records`."""
        first = self.record(SOFT_TEXT, code_hash="sha256:first", rows="", why="the ledger's first record", by="seed")
        return f'[golden."{path}"]\ngenerator = ["@src"]\n\n' + first + "".join(records)

    @staticmethod
    def record(text, *, kind="regenerated", code_hash="sha256:second", rows=MOVED, why=None, by="f00d123", path=SOFT):
        """A record of `path` as `text`."""
        r = f'[[golden."{path}".{kind}]]\nby = "{by}"\nhash = "{sha(text)}"\n'
        if kind == "regenerated":
            r += f'code-hash = "{code_hash}"\n'
        if why is not None:
            r += f'why = "{why}"\n'
        return r + f"rows = {{ {rows} }}\n\n"

    def test_a_kept_ledger_passes_and_says_what_each_file_is(self):
        code, out = self.run_with()
        self.assertEqual(code, 0, out)
        self.assertIn(f"build-verified  {SOFT}: every build", out)
        self.assertIn(f"fresh  {MODULE}: probed abc1234 (2026-11-19)", out)
        self.assertIn(f"captured  {CERT}: probed def5678 (2026-11-13)", out)
        self.assertIn(f"golden  {SOFT}: regenerated by seed", out)

    # Review 2026-11-24 C-8: a golden file regenerated in the commit that changed its generator
    # moved the expectation with the code, and nothing asked which verdicts moved, or why.
    def test_a_golden_change_without_a_record_fails(self):
        self.write(SOFT, SOFT_AGAIN)
        code, out = self.run_with()
        self.assertEqual(code, 1, out)
        self.assertIn(f'no record names the file as it is (hash = "{sha(SOFT_AGAIN)}"): a change without a record', out)
        # A record of another file accepts nothing.
        code, out = self.run_with(golden=self.golden(self.record(SOFT_AGAIN + "\n")))
        self.assertEqual(code, 1, out)
        self.assertIn("a change without a record", out)
        code, out = self.run_with(golden=self.golden(self.record(SOFT_AGAIN)))
        self.assertEqual(code, 0, out)
        self.assertIn(f"golden  {SOFT}: regenerated by f00d123", out)

    def test_every_golden_file_has_an_entry(self):
        self.write("spec-coverage/objects/t.toml", '[rows]\n"a" = "exit 17"\n')
        code, out = self.run_with()
        self.assertEqual(code, 1, out)
        self.assertIn("spec-coverage/objects/t.toml is a golden file without a [golden] entry", out)
        code, out = self.run_with(golden=self.golden())
        self.assertEqual(code, 1, out)
        code, out = self.run_with(golden="")
        self.assertEqual(code, 1, out)
        self.assertIn(f"{SOFT} is a golden file without a [golden] entry", out)

    def test_a_why_not_written_fails(self):
        self.write(SOFT, SOFT_AGAIN)
        for rows, why in (
            (MOVED.replace('"the module takes 8 bytes"', '"TODO"'), None),
            (MOVED.replace('"a new size"', '"  "'), None),
            (MOVED.replace('why = "a new size"', ""), None),
            (MOVED, "TODO: say why"),
            ("", None),
            ("", "TODO"),
        ):
            code, out = self.run_with(golden=self.golden(self.record(SOFT_AGAIN, rows=rows, why=why)))
            self.assertEqual(code, 1, (rows, why, out))
            self.assertRegex(out, r"`why` is not written|says why it changed the file")
        # A change that moved no row says why it was made.
        self.write(SOFT, "# a header\n" + SOFT_TEXT)
        golden = self.golden(self.record("# a header\n" + SOFT_TEXT, rows="", why="the generator's header"))
        self.assertEqual(self.run_with(golden=golden)[0], 0)

    def test_a_record_naming_an_unchanged_row_fails(self):
        self.write(SOFT, SOFT_AGAIN)
        unchanged = MOVED + ', "capabilities.generate.CKK_AES.16" = { was = { answer = "yes", by = "host" }, why = "it is" }'
        code, out = self.run_with(golden=self.golden(self.record(SOFT_AGAIN, rows=unchanged)))
        self.assertEqual(code, 1, out)
        self.assertIn("row 'capabilities.generate.CKK_AES.16': unchanged", out)
        # A list member that stayed is unchanged too.
        unchanged = MOVED + ', "advertise.CKM_A" = { was = true, why = "listed" }'
        code, out = self.run_with(golden=self.golden(self.record(SOFT_AGAIN, rows=unchanged)))
        self.assertEqual(code, 1, out)
        self.assertIn("row 'advertise.CKM_A': unchanged (True)", out)

    def test_a_record_naming_a_row_that_neither_was_nor_is_fails(self):
        self.write(SOFT, SOFT_AGAIN)
        rows = MOVED + ', "capabilities.generate.CKK_AES.64" = { why = "gone" }'
        code, out = self.run_with(golden=self.golden(self.record(SOFT_AGAIN, rows=rows)))
        self.assertEqual(code, 1, out)
        self.assertIn("row 'capabilities.generate.CKK_AES.64': the file has no such row", out)

    def test_a_regeneration_by_the_generator_before_is_a_hand_edit(self):
        self.write(SOFT, SOFT_AGAIN)
        code, out = self.run_with(golden=self.golden(self.record(SOFT_AGAIN, code_hash="sha256:first")))
        self.assertEqual(code, 1, out)
        self.assertIn("the generator is the previous regeneration's (seed): record it as a hand edit", out)
        code, out = self.run_with(golden=self.golden(self.record(SOFT_AGAIN, kind="hand-edits")))
        self.assertEqual(code, 0, out)
        self.assertIn(f"golden  {SOFT}: hand-edits by f00d123", out)
        both = self.golden(self.record(SOFT_AGAIN), self.record(SOFT_AGAIN, kind="hand-edits"))
        code, out = self.run_with(golden=both)
        self.assertEqual(code, 1, out)
        self.assertIn("a regeneration and a hand edit both name the file as it is", out)

    def test_a_generator_that_moved_while_its_output_did_not_needs_nothing(self):
        golden = self.golden().replace('"sha256:first"', f'"{self.code}"')
        self.assertEqual(self.run_with(golden=golden)[0], 0)
        self.write("code/a.rs", "fn a() { changed() }\n")
        code, out = self.run_with(golden=golden, code_hash="sha256:none")
        self.assertIn(f"golden  {SOFT}: regenerated by seed; the generator moved since", out)
        self.assertNotIn(f'[golden."{SOFT}"]', out)

    def test_a_golden_key_the_check_does_not_read_fails(self):
        golden = self.golden(self.record(SOFT_TEXT, rows=MOVED.replace("why =", "reason =", 1)))
        code, out = self.run_with(golden=golden)
        self.assertEqual(code, 1, out)
        self.assertIn("`reason` is no key of row", out)
        code, out = self.run_with(golden=self.golden().replace("generator =", "generators ="))
        self.assertEqual(code, 1, out)
        self.assertIn("`generators` is no key of golden", out)

    def test_a_summary_is_no_row(self):
        # A matrix's summary counts its rows: a moved row moves it, and only the row is listed.
        before = '[summary]\n"exit" = 1\n\n[rows]\n"a" = "exit 17"\n'
        after = '[summary]\n"direct" = 1\n\n[rows]\n"a" = "direct rfc7093m4"\n'
        path = "spec-coverage/objects/t.toml"
        self.write(path, after)
        first = self.record(before, code_hash="sha256:first", rows="", why="first", by="seed", path=path)
        moved = self.record(after, rows='"rows.a" = { was = "exit 17", why = "now identified" }', path=path)
        golden = self.golden() + f'[golden."{path}"]\ngenerator = ["@src"]\n\n' + first + moved
        code, out = self.run_with(golden=golden)
        self.assertEqual(code, 0, out)

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

    def test_every_regeneration_is_the_one_verb(self):
        # Review 2026-11-24 E-8: four hand-copied probe lines, two of which probed to caprobe's
        # default size. Each source calls `caprobe regenerate` and passes none of its flags.
        for script in (
            "caprobe probe --write-probes --rsa-max-bits 4096 --out x\n",
            'caprobe regenerate "$name" --rsa-max-bits 4096 --out x\n',
            'km(&["regenerate", name, "--write-probes"])\n',
            '# caprobe regenerate "$name"\ncaprobe probe --out x\n',
        ):
            self.write("scripts/regen.sh", script)
            code, out = self.run_with()
            self.assertEqual(code, 1, out)
            self.assertIn("scripts/regen.sh", out)
        self.write("scripts/regen.sh", 'km(&["regenerate", name, "--token", token, "--out", out])\n')
        self.assertEqual(self.run_with()[0], 0)
        code, out = self.run_with(regen="caprobe probe --token t --write-probes --rsa-max-bits 4096 --out f")
        self.assertEqual(code, 1, out)
        self.assertIn(f"{MODULE}: its regen passes --rsa-max-bits, which `caprobe regenerate` holds", out)
        self.assertIn(f"{MODULE}: its regen passes --write-probes, which", out)
        self.assertEqual(self.run_with(regen="caprobe regenerate m/1 --token t --out f")[0], 0)

    def test_the_verb_states_the_ledgers_size(self):
        for text in ("pub const REGENERATE_RSA_MAX_BITS: u32 = 16384;\n", "pub const OTHER: u32 = 4096;\n"):
            self.write("code/verb.rs", text)
            code, out = self.run_with(code_hash="sha256:none")
            self.assertIn("[regen] verb code/verb.rs: `caprobe regenerate` probes RSA up to", out)
        code, out = self.run_with(verb="code/gone.rs")
        self.assertEqual(code, 1, out)
        self.assertIn("[regen] verb code/gone.rs: no such file", out)

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
