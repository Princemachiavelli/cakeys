"""nix/doc-references.py's own tests, on small trees written for each (checks.doc-references runs
them first).

Usage: python3 -I nix/doc-references-test.py [SCRIPT]. SCRIPT, nix/doc-references.py by default,
is the script under test: a changed copy shows which test holds which rule.
"""

import importlib.util
import pathlib
import sys
import tempfile
import textwrap
import unittest

SCRIPT = pathlib.Path(sys.argv.pop(1) if len(sys.argv) > 1 else pathlib.Path(__file__).with_name("doc-references.py"))
# Read-only in the Nix sandbox, and no file to leave in a checkout.
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("doc_references", SCRIPT)
dr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dr)

# KNOWN_STALE when it was made (3a17302): empty. The design's five stale names were four
# parameters of the function their comment documents (`object_curve`, `by_oid`, `mac_by`,
# `private_key_type`) and ykcs11's `pvtkey_objects`; none was stale. The set may only shrink.
SEEDED_STALE = frozenset()

FILES = {
    "Cargo.toml": '[workspace]\nmembers = ["crates/a"]\n\n[workspace.dependencies]\nserde = "1"\n',
    "crates/a/Cargo.toml": '[package]\nname = "cakeys-a"\n\n[dependencies]\nder = "0.7"\n',
    "crates/a/src/lib.rs": """
        //! The crate's items.
        mod sub_mod;
        use der::Encode;

        pub struct Type {
            pub some_field: u8,
        }

        pub enum Kind {
            FirstOne,
            #[allow(dead_code)]
            SecondOne(u8),
        }

        macro_rules! made_here {
            () => {};
        }

        impl Type {
            /// What it is.
            pub fn here(&self, a_param: u8) -> Vec<u8> {
                let local_only = a_param;
                let _ = "string_only_name";
                // comment_only_name
                made_here!();
                self.to_der().unwrap_or_default()
            }
        }

        #[test]
        fn a_test_of_four_words() {}
        """,
    "crates/a/src/sub_mod.rs": "pub fn in_sub() {}\n",
    "nix/env.sh": "shell_fn() {\n  :\n}\n",
    "docs/A.md": "# A\n",
}


def write(root, files):
    for rel, text in files.items():
        p = pathlib.Path(root) / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(text))


class Case(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.dir.name)
        write(self.root, FILES)

    def tearDown(self):
        self.dir.cleanup()

    def misses(self, comment="", doc="", **lists):
        """The misses with `comment` lines appended to lib.rs and `doc` to docs/A.md, under the
        lists given (each empty by default)."""
        lib = self.root / "crates/a/src/lib.rs"
        lib.write_text(lib.read_text() + textwrap.dedent(comment))
        (self.root / "docs/A.md").write_text("# A\n\n" + textwrap.dedent(doc))
        given = {"foreign_names": {}, "gone_names": {}, "known_stale": {}, "foreign_paths": {}} | lists
        return dr.check(self.root, **given)


class Comments(Case):
    def test_a_doc_comment_citing_a_gone_method_fails(self):
        got = self.misses("/// Calls `Type::gone`.\npub fn x() {}\n")
        self.assertEqual(len(got), 1, got)
        self.assertIn("lib.rs:", got[0])
        self.assertIn("`Type::gone`: `gone`", got[0])

    def test_inner_and_line_comments_are_read_too(self):
        got = self.misses("//! `gone_name` here,\n// and `gone_again()` there.\n")
        self.assertEqual(len(got), 2, got)
        self.assertIn("`gone_name`", got[0])
        self.assertIn("`gone_again`", got[1])

    def test_a_gone_type_fails_though_its_method_exists(self):
        got = self.misses("/// `Gone::here`.\n")
        self.assertEqual(len(got), 1, got)
        self.assertIn("`Gone::here`: `Gone`", got[0])

    def test_what_the_code_defines_resolves(self):
        cited = [
            "Type::here()",
            "a_param",
            "some_field",
            "Kind::FirstOne",
            "Kind::SecondOne",
            "made_here!",
            "sub_mod::in_sub",
            "cakeys_a::Type",
            "crate::Type",
            "Self::here",
            "shell_fn",
            "a_test_of_four_words",
        ]
        self.assertEqual(self.misses("".join(f"/// `{c}`\n" for c in cited)), [])

    def test_what_the_code_uses_from_other_crates_resolves(self):
        cited = ["to_der", "Encode::to_der", "unwrap_or_default", "der::Never::seen", "std::fs::read_to_end", "serde::not_checked"]
        self.assertEqual(self.misses("".join(f"/// `{c}`\n" for c in cited)), [])

    def test_a_local_a_string_or_a_comment_is_no_item(self):
        got = self.misses("/// `local_only`, `string_only_name`, `comment_only_name`\n")
        self.assertEqual(len(got), 3, got)

    def test_a_name_without_an_underscore_and_trailing_comments_are_not_read(self):
        self.assertEqual(self.misses("/// `gone`\npub fn y() {} // `gone_name`\n"), [])

    def test_a_path_from_a_crate_no_manifest_names_is_checked(self):
        got = self.misses("/// `nodep::thing_here`\n")
        self.assertEqual(len(got), 2, got)


class Docs(Case):
    def test_a_path_of_any_length_is_checked(self):
        got = self.misses(doc="`Type::here` and `Type::gone`.\n")
        self.assertEqual(len(got), 1, got)
        self.assertIn("docs/A.md:3: `Type::gone`: `gone`", got[0])

    def test_a_test_name_of_four_words_is_a_fn(self):
        got = self.misses(doc="`a_test_of_four_words`, `no_test_of_four_words`, `some_field`.\n")
        self.assertEqual(got, ["docs/A.md:3: `no_test_of_four_words` is no fn in crates/ or fuzz/"])


class Lists(Case):
    def test_a_listed_foreign_name_passes_and_an_unneeded_entry_fails(self):
        got = self.misses("/// `tpm2_ptool`\n", foreign_names={"tpm2_ptool": "a tool", "never_cited": "x", "to_der": "the code names it"})
        self.assertEqual(len(got), 2, got)
        self.assertIn("FOREIGN_NAMES lists never_cited", got[0])
        self.assertIn("FOREIGN_NAMES lists to_der", got[1])

    def test_a_name_cited_as_gone_passes_only_in_its_file(self):
        gone = {("docs/A.md", "gone_name"): "a history names it"}
        got = self.misses("/// `Type::gone_name`\n", doc="`Type::gone_name`\n", gone_names=gone)
        self.assertEqual(len(got), 1, got)
        self.assertIn("lib.rs:", got[0])

    def test_a_known_stale_name_passes_until_it_resolves_or_goes(self):
        stale = {"gone_name": "what it became"}
        self.assertEqual(self.misses("/// `gone_name`\n", known_stale=stale), [])
        got = self.misses("pub fn gone_name() {}\n", known_stale=stale)
        self.assertEqual(got, ["doc-references.py: KNOWN_STALE lists gone_name, which resolves now: remove it"])
        write(self.root, FILES)
        got = self.misses(known_stale=stale)
        self.assertEqual(got, ["doc-references.py: KNOWN_STALE lists gone_name, which nothing cites now: remove it"])

    def test_the_stale_set_only_shrinks(self):
        self.assertLessEqual(set(dr.KNOWN_STALE), SEEDED_STALE, "fix the citation instead")


if __name__ == "__main__":
    unittest.main()
