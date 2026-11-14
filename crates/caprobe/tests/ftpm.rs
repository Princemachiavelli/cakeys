//! caprobe against the host's real TPM through tpm2-pkcs11 (nix/ftpm-test-env.sh), opt-in.
//!
//! Needs `CAKEYS_FTPM_MODULE` (`libtpm2_pkcs11.so`), `CAKEYS_FTPM_PROFILE` (the committed pair
//! profile of this TPM, e.g. `tpm2-pkcs11/1.10+amd-ftpm`) and the `TPM2_PKCS11_*` environment
//! of the harness, whose fresh store holds token `kmtest` (user PIN 1234). Skipped when
//! `CAKEYS_FTPM_MODULE` is unset — never in the Nix build. Run it before `cakeys`' ftpm suite,
//! on the harness's fresh store, and only through the harness:
//!
//! ```console
//! $ nix shell --inputs-from . nixpkgs#{tpm2-pkcs11,tpm2-tools,tpm2-abrmd,dbus}
//! $ bash nix/ftpm-test-env.sh up /tmp/ftpm && . /tmp/ftpm/env
//! $ CAKEYS_FTPM_MODULE=.../libtpm2_pkcs11.so CAKEYS_FTPM_PROFILE=tpm2-pkcs11/1.10+amd-ftpm \
//!     cargo test -p caprobe --test ftpm
//! $ bash nix/ftpm-test-env.sh down /tmp/ftpm
//! ```
//!
//! Nothing here touches the TPM beyond that store: no persistent handle, no NV, no attestation
//! key, and no wrong PIN (the dictionary-attack lockout is the whole TPM's).

#[path = "../../cli/tests/common/mod.rs"]
mod common;

use common::*;

/// On the harness's fresh store: tpm2-pkcs11 leaves objects behind it cannot destroy, and they
/// change what a later probe can do. The committed pair profile is what the probe observes on
/// this TPM, and regenerating it changes no byte ([migration] and [manual] kept). Needs the
/// patched cryptoki (the Nix build's); a cargo build skips the diff.
#[test]
fn a_fresh_probe_is_the_committed_profile() {
    let (Ok(module), Ok(profile)) = (std::env::var("CAKEYS_FTPM_MODULE"), std::env::var("CAKEYS_FTPM_PROFILE")) else {
        eprintln!(
            "skipping a_fresh_probe_is_the_committed_profile: CAKEYS_FTPM_MODULE and CAKEYS_FTPM_PROFILE not both set"
        );
        return;
    };
    if !cryptoki_hmac_types_fixed(false) {
        return;
    }
    let w = Workdir::new("ftpm-probe");
    w.write_config(&ftpm_tokens(&module, &w.dir));
    let path = format!("modules/{profile}.toml");
    assert_profile_conforms(|args| w.km(args), "ftpm", &profile, &path, &w.dir.join("profile.toml"));
}
