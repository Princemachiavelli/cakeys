//! Tests of caprobe against the host's real TPM through tpm2-pkcs11 (nix/ftpm-test-env.sh).
//! These tests run only when they are opted in.
//!
//! The tests need `CAKEYS_FTPM_MODULE` (`libtpm2_pkcs11.so`), `CAKEYS_FTPM_PROFILE` (the
//! committed pair profile of this TPM, for example `tpm2-pkcs11/1.10+amd-ftpm`), and the
//! `TPM2_PKCS11_*` environment of the harness, whose new store holds the token `kmtest` (user
//! PIN 1234). They are skipped when `CAKEYS_FTPM_MODULE` is unset, so they never run in the Nix
//! build. Run them before the ftpm suite of `cakeys`, on the harness's new store, and only
//! through the harness. `scripts/coverage-full.sh` starts and stops the harness around both
//! suites, with the patched cryptoki that the diff needs:
//!
//! ```console
//! $ CAKEYS_FTPM_PROFILE=tpm2-pkcs11/1.10+amd-ftpm nix run .#coverage-full
//! ```
//!
//! A plain `cargo test` builds the unpatched cryptoki. With both variables set, that build
//! fails and names the patch, instead of passing with nothing compared (review ftpm.rs F1).
//!
//! Nothing here touches the TPM outside that store: no persistent handle, no NV index, no
//! attestation key, and no wrong PIN (the dictionary-attack lockout applies to the whole TPM).

#[path = "../../cli/tests/common/mod.rs"]
mod common;

use common::*;

/// Runs on the harness's new store, because tpm2-pkcs11 leaves objects behind that it cannot
/// destroy, and those objects change what a later probe can do. The committed pair profile is
/// what the probe observes on this TPM, and regenerating it changes no byte (the `[migration]`
/// and `[manual]` sections are kept). The test needs the patched cryptoki (as the Nix build has
/// it): when the test is opted in, an unpatched build fails.
#[test]
fn a_fresh_probe_is_the_committed_profile() {
    let Some([module, profile]) = opted_in("a_fresh_probe_is_the_committed_profile", FTPM_OPT_IN) else { return };
    cryptoki_hmac_types_fixed(true);
    let w = Workdir::new("ftpm-probe");
    w.write_config(&ftpm_tokens(&module, &w.dir));
    let path = format!("modules/{profile}.toml");
    assert_profile_conforms(|args| w.km(args), "ftpm", &profile, &path, &w.dir.join("profile.toml"));
}
