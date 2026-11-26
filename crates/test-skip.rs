//! The one way a test skips (review 2026-11-24 C-11). Every test that cannot run here calls
//! [`skip`] and returns: the skip is said on stderr and appended to `$CAKEYS_SKIP_LOG`, where the
//! runners count it per binary (nix/test-count.py), and it is a failure instead when the run
//! requires it ([`required`]). Included by each crate whose tests can skip: the three tools'
//! harness (crates/cli/tests/common/), crates/cli/tests/cloud.rs, crates/pkcs11/tests/ and core's
//! unit tests; cakeys' harness tests hold every other skip to it.
#![allow(dead_code, reason = "each test binary uses a subset")]

use std::io::Write as _;

/// Set by the runs that set up every software token (nix/token-env.sh's `test_env`: the Nix
/// builds' check phase and reports, scripts/local-tests.sh): every skip fails but those of the
/// suites [`HARDWARE`] names. It is set once for the whole run, apart from the per-test routing
/// (nix/test-tokens.sh), so a suite that the routing loses fails instead of skipping.
pub(crate) const REQUIRE_ALL: &str = "CAKEYS_REQUIRE_ALL";

/// The require variables of the suites that need hardware or a cloud account, which no automated
/// run has: what may still skip under [`REQUIRE_ALL`].
pub(crate) const HARDWARE: [&str; 4] =
    ["CAKEYS_YUBIKEY_REQUIRE", "CAKEYS_FTPM_REQUIRE", "CAKEYS_FTPM_ATTEST_REQUIRE", "CAKEYS_CLOUD_REQUIRE"];

/// The software TPM's require variables: hardware too, under [`REQUIRE_ALL`], where the binary is
/// built without the TPM (the tools' `tpm2` feature off: darwin, `withTpm2 = false`).
pub(crate) const TPM: [&str; 2] = ["CAKEYS_TPM_REQUIRE", "CAKEYS_TPM_VENDOR_REQUIRE"];

/// The binary under test as cargo-nextest names it: `<package>::<test>` for an integration test,
/// the package for a library's own tests.
const BINARY: &str = match option_env!("CARGO_TARGET_TMPDIR") {
    Some(_) => concat!(env!("CARGO_PKG_NAME"), "::", env!("CARGO_CRATE_NAME")),
    None => env!("CARGO_PKG_NAME"),
};

/// Why a skip under `require` must fail, in an environment where `set` says which variables are
/// set; `None` when it may skip. `tpm` says whether the binary is built with the TPM.
pub(crate) fn required(require: &str, tpm: bool, set: &dyn Fn(&str) -> bool) -> Option<String> {
    if set(require) {
        return Some(format!("{require} is set"));
    }
    let hardware = HARDWARE.contains(&require) || (!tpm && TPM.contains(&require));
    (set(REQUIRE_ALL) && !hardware).then(|| format!("{REQUIRE_ALL} is set, and {require} is no hardware suite's"))
}

/// Whether this binary is built with the TPM: the tools' `tpm2` feature, which no other crate has.
#[allow(unexpected_cfgs, reason = "only the three tools have the feature; elsewhere it is off")]
pub(crate) const TPM_BUILT: bool = cfg!(feature = "tpm2");

/// [`required`] in this process's environment and build.
pub(crate) fn required_here(require: &str) -> Option<String> {
    required(require, TPM_BUILT, &|v| std::env::var_os(v).is_some())
}

/// Test `test` cannot run here, for `why`: say so, log it, and let the caller return, unless the
/// run requires it ([`required`]). `require` is the variable that makes this skip a failure.
///
/// # Panics
///
/// When the skip is required, or `$CAKEYS_SKIP_LOG` cannot be written.
pub(crate) fn skip(test: &str, require: &str, why: &str) {
    // libtest names each test's thread after the test: the name nextest reports it by.
    let thread = std::thread::current();
    let name = thread.name().filter(|n| *n != "main").unwrap_or(test);
    if let Some(because) = required_here(require) {
        panic!("{name}: {why}, and it may not skip: {because}");
    }
    eprintln!("skipping {name}: {why}");
    if let Some(log) = std::env::var_os("CAKEYS_SKIP_LOG") {
        let line = format!("{BINARY}\t{name}\t{require}\t{}\n", why.replace(['\t', '\n'], " "));
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log)
            .and_then(|mut f| f.write_all(line.as_bytes()))
            .unwrap_or_else(|e| panic!("$CAKEYS_SKIP_LOG {}: {e}", log.display()));
    }
}
