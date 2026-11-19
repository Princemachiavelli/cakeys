//! The embedded trust anchors (`roots/`) are built in only as reviewed: each file is pinned here
//! by its SHA-256, so a file that changed under the code (a bad checkout, a substituted copy)
//! fails the build before `include_str!` embeds it (docs/DEVELOPMENT.md, "Built-in material").
//! Updating one is a deliberate diff of both, with the file compared to its source first
//! (roots/README.md).

use sha2::{Digest, Sha256};

/// Each embedded file and its SHA-256 (`sha256sum`), as AMD's key distribution server serves it
/// (fetched 2026-11-18).
const PINNED: &[(&str, &str)] = &[
    ("roots/amd-ftpm-rsa-root.pem", "94449e47c7f4ec0eac792fed9023d4d7fef1959ae5c9527f763ae55ccc544624"),
    ("roots/amd-ftpm-ecc-root.pem", "a2ee58ac77d24929133fe2fc945ac0c6512e4a4582d1a81aa6c7b55900acd76a"),
];

fn main() {
    for (path, pinned) in PINNED {
        println!("cargo::rerun-if-changed={path}");
        let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("reading {path}: {e}"));
        let got = base16ct::lower::encode_string(&Sha256::digest(&bytes));
        assert!(
            got == *pinned,
            "{path} has SHA-256 {got}, and build.rs pins {pinned}: compare the file with its source \
             (roots/README.md) before changing either"
        );
    }
}
