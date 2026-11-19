//! caprobe against the host's real TPM through tpm2-pkcs11 (nix/ftpm-test-env.sh), opt-in.
//!
//! Needs `CAKEYS_FTPM_MODULE` (`libtpm2_pkcs11.so`), `CAKEYS_FTPM_PROFILE` (the committed pair
//! profile of this TPM, e.g. `tpm2-pkcs11/1.10+amd-ftpm`) and the `TPM2_PKCS11_*` environment
//! of the harness, whose fresh store holds token `kmtest` (user PIN 1234). Skipped when
//! `CAKEYS_FTPM_MODULE` is unset — never in the Nix build. Run it before `cakeys`' ftpm suite,
//! on the harness's fresh store, and only through the harness, which `scripts/coverage-full.sh`
//! brings up and down around both suites with the patched cryptoki the diff needs:
//!
//! ```console
//! $ CAKEYS_FTPM_PROFILE=tpm2-pkcs11/1.10+amd-ftpm nix run .#coverage-full
//! ```
//!
//! A plain `cargo test` builds the unpatched cryptoki: with both variables set, that fails,
//! naming the patch, instead of passing with nothing compared (review ftpm.rs F1).
//!
//! Nothing here touches the TPM beyond that store: no persistent handle, no NV, no attestation
//! key, and no wrong PIN (the dictionary-attack lockout is the whole TPM's).

#[path = "../../cli/tests/common/mod.rs"]
mod common;

use common::*;

/// On the harness's fresh store: tpm2-pkcs11 leaves objects behind it cannot destroy, and they
/// change what a later probe can do. The committed pair profile is what the probe observes on
/// this TPM, and regenerating it changes no byte (`[migration]` and `[manual]` kept). Needs the
/// patched cryptoki (the Nix build's): opted in, an unpatched build fails.
#[test]
fn a_fresh_probe_is_the_committed_profile() {
    let Some([module, profile]) = opted_in("a_fresh_probe_is_the_committed_profile", FTPM_OPT_IN) else { return };
    cryptoki_hmac_types_fixed(true);
    let w = Workdir::new("ftpm-probe");
    w.write_config(&ftpm_tokens(&module, &w.dir));
    let path = format!("modules/{profile}.toml");
    assert_profile_conforms(|args| w.km(args), "ftpm", &profile, &path, &w.dir.join("profile.toml"));
}
