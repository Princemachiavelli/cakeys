//! The embedded trust anchors (`roots/`) are built in only in their reviewed form. Each file is
//! pinned here by its SHA-256, so a file that changed without a change to the code (because of a
//! bad checkout or a substituted copy) fails the build before `include_str!` embeds it
//! (docs/DEVELOPMENT.md, "Built-in material"). An update of a file is a deliberate change to both
//! the file and its hash here, after the file is compared with its source (roots/README.md).

include!("../pin-roots.rs");

/// Each embedded file and its SHA-256 (`sha256sum`), as Yubico published the file (2025-02-03).
const PINNED: &[(&str, &str)] = &[
    ("roots/yubico-piv-ca-1.pem", "6234f33d5f652109d265b391f2898b8ba92f62df406b684db18363f50d7c9129"),
    ("roots/yubico-ca-1.pem", "9271d914d48d05487666703586aea27d9a69ad0c8ddf8c2fc4c8734a04285887"),
    ("roots/yubico-intermediate.pem", "ec0172fe38838e3de174aae4e058bb44920be47cebd8d658a0fba1634b82aee1"),
];

fn main() {
    pin_roots(PINNED);
}
