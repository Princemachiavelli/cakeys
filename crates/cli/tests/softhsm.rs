//! The reference-token suite (`tests/reference/`) against a `SoftHSM` token.
//!
//! The tests need `SOFTHSM2_CONF` and `CAKEYS_TEST_MODULE` (the path to libsofthsm2.so), with an
//! initialized token labeled `kmtest` and the user PIN `1234` (the Nix build's preCheck sets this
//! up). The tests are skipped when `CAKEYS_TEST_MODULE` is unset, unless `CAKEYS_TEST_REQUIRE=1`
//! is set.

mod common;
mod reference;
// The object matrix is included here and in tests/kryoptic.rs, but not in tests/fault.rs. The
// header of reference/matrix.rs says why.
#[path = "reference/matrix.rs"]
mod matrix;

const REF: &common::Reference = &common::SOFTHSM;
