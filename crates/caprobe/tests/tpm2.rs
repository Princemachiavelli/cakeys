//! caprobe against tpm2-pkcs11 on a software TPM (nix/tpm2-test-env.sh): needs
//! `CAKEYS_TPM_MODULE` and the harness's environment, as `cakeys`' tpm2 suite does (its header
//! describes it). Skipped when `CAKEYS_TPM_MODULE` is unset, unless `CAKEYS_TPM_REQUIRE=1`.

#[path = "../../cli/tests/common/mod.rs"]
mod common;

use common::*;

fn env(test: &str) -> Option<Workdir> {
    let module = suite_var("CAKEYS_TPM_MODULE", "CAKEYS_TPM_REQUIRE", test)?;
    let w = Workdir::new(&format!("tpm2-{test}"));
    w.write_config(&tpm2_tokens(&module, &w.dir));
    Some(w)
}

/// `caps` names the tpm2-pkcs11 provider, and the mechanisms show what the provider's refusals
/// rest on: EC generation is there, AES generation is not (`cakeys`' tpm2 suite tests the
/// refusals themselves).
#[test]
fn caps_names_the_provider_and_what_the_module_offers() {
    let Some(w) = env("caps") else { return };
    let caps: serde_json::Value = serde_json::from_str(&stdout(&w.km(&["caps", "--token", "tpm"]))).unwrap();
    assert_eq!(caps["provider"], "tpm2-pkcs11");
    let mechs = caps["mechanisms"].to_string();
    assert!(mechs.contains("CKM_EC_KEY_PAIR_GEN") && !mechs.contains("CKM_AES_KEY_GEN"), "{mechs}");
}

/// The committed pair profile tpm2-pkcs11/1.10+swtpm is probe output (docs/PROVIDERS.md
/// phase 3): what this module does on this TPM, measured together. A fresh probe conforms and
/// regenerating it changes no byte.
#[test]
fn the_committed_profile_is_what_the_probe_observes() {
    let Some(w) = env("profile_conformance") else { return };
    if !cryptoki_hmac_types_fixed(std::env::var("CAKEYS_TPM_REQUIRE").is_ok()) {
        return;
    }
    let (name, path) = ("tpm2-pkcs11/1.10+swtpm", "modules/tpm2-pkcs11/1.10+swtpm.toml");
    assert_profile_conforms(|args| w.km(args), "tpm", name, path, &w.dir.join("profile.toml"));
}
