// The root-pinning check both providers' build.rs `include!` (review 2026-11-23 B-24): each
// keeps its own `PINNED` list and calls `pin_roots` from `main`.

use sha2::{Digest, Sha256};

/// Fail the build when a pinned file's SHA-256 is not the one pinned beside it.
fn pin_roots(pinned: &[(&str, &str)]) {
    for (path, pinned) in pinned {
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
