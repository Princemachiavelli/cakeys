//! The reference-token suite (`tests/reference/`) against a kryoptic token (PKCS#11 3.2).
//!
//! The tests need `KRYOPTIC_CONF` (which ends with the token's `[[slots]]` table) and
//! `CAKEYS_KRYOPTIC_MODULE` (the path to `libkryoptic_pkcs11.so`), with an initialized token
//! labeled `kmtest` and the user PIN `1234` (the Nix build's preCheck sets this up). The tests are
//! skipped when `CAKEYS_KRYOPTIC_MODULE` is unset, unless `CAKEYS_KRYOPTIC_REQUIRE=1` is set.

mod common;
mod reference;
// The object matrix is included here and in tests/softhsm.rs, but not in tests/fault.rs. The
// header of reference/matrix.rs says why.
#[path = "reference/matrix.rs"]
mod matrix;

const REF: &common::Reference = &common::KRYOPTIC;
