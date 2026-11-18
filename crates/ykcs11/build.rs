//! The embedded trust anchors (`roots/`) are built in only as reviewed: each file is pinned here
//! by its SHA-256, so a file that changed under the code (a bad checkout, a substituted copy)
//! fails the build before `include_str!` embeds it (docs/DEVELOPMENT.md, "Built-in material").
//! Updating one is a deliberate diff of both, with the file compared to its source first
//! (roots/README.md).

use sha2::{Digest, Sha256};

/// Each embedded file and its SHA-256 (`sha256sum`), as Yubico published it (2025-02-03).
const PINNED: &[(&str, &str)] = &[
    ("roots/yubico-piv-ca-1.pem", "6234f33d5f652109d265b391f2898b8ba92f62df406b684db18363f50d7c9129"),
    ("roots/yubico-ca-1.pem", "9271d914d48d05487666703586aea27d9a69ad0c8ddf8c2fc4c8734a04285887"),
    ("roots/yubico-intermediate.pem", "ec0172fe38838e3de174aae4e058bb44920be47cebd8d658a0fba1634b82aee1"),
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
