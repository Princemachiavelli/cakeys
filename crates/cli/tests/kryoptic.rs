//! The reference-token suite (`tests/reference/`) against a kryoptic token (PKCS#11 3.2).
//!
//! Needs `KRYOPTIC_CONF` (ending with the token's `[[slots]]` table) and `CAKEYS_KRYOPTIC_MODULE`
//! (path to `libkryoptic_pkcs11.so`) with an initialised token labelled `kmtest`, user PIN `1234`
//! (the Nix build's preCheck sets this up). Tests are skipped when `CAKEYS_KRYOPTIC_MODULE` is
//! unset, unless `CAKEYS_KRYOPTIC_REQUIRE=1`.

mod common;
mod reference;
// Here and in tests/softhsm.rs, not in tests/fault.rs (its header says why).
#[path = "reference/matrix.rs"]
mod matrix;

const REF: &common::Reference = &common::KRYOPTIC;
