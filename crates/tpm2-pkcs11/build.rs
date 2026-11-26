//! The embedded trust anchors (`roots/`) are built in only in their reviewed form. This script
//! pins each file by its SHA-256, so a file that changed without a matching code change (a bad
//! checkout, or a substituted copy) fails the build before `include_str!` embeds it
//! (docs/DEVELOPMENT.md, "Built-in material"). To update a file, change both the file and its
//! hash in one deliberate diff, after comparing the file with its source (roots/README.md).

include!("../pin-roots.rs");

/// Each embedded file and its SHA-256 (as `sha256sum` prints it), as AMD's key distribution
/// server serves the file (fetched 2026-11-18).
const PINNED: &[(&str, &str)] = &[
    ("roots/amd-ftpm-rsa-root.pem", "94449e47c7f4ec0eac792fed9023d4d7fef1959ae5c9527f763ae55ccc544624"),
    ("roots/amd-ftpm-ecc-root.pem", "a2ee58ac77d24929133fe2fc945ac0c6512e4a4582d1a81aa6c7b55900acd76a"),
];

fn main() {
    pin_roots(PINNED);
}
