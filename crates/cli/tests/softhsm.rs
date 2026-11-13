//! The reference-token suite (`tests/reference/`) against a `SoftHSM` token.
//!
//! Needs `SOFTHSM2_CONF` and `CAKEYS_TEST_MODULE` (path to libsofthsm2.so) with an initialised token
//! labelled `kmtest`, user PIN `1234` (the Nix build's preCheck sets this up). Tests are skipped
//! when `CAKEYS_TEST_MODULE` is unset, unless `CAKEYS_TEST_REQUIRE=1`.

mod common;
mod reference;
