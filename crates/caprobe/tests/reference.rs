//! caprobe against the software tokens the Nix check phase sets up (nix/package.nix): `SoftHSM`
//! and kryoptic, whose committed module profiles must be what a fresh probe observes, and
//! `SoftHSM` behind p11-kit forwarding, whose layer profile must be what the forwarder hides.
//! Each test skips when its suite's variables are unset (the `*_REQUIRE` variables make that a
//! failure), as `cakeys`' suites do; their headers describe the environment.

#[path = "../../cli/tests/common/mod.rs"]
mod common;

use common::*;

/// The committed module profile is probe output (docs/CAPROBE.md): a fresh probe of
/// the reference token conforms to it, regenerating it changes no byte, and the write probes
/// are refused on a token keys.toml does not mark scratch.
fn committed_profile_is_what_the_probe_observes(r: &Reference, test: &str) {
    let Some(module) = suite_var(r.module_var, r.require_var, test) else { return };
    // Through an unpatched cryptoki the advertisement is short; the probe refuses to judge.
    if !cryptoki_hmac_types_fixed(std::env::var(r.require_var).is_ok()) {
        return;
    }
    let w = Workdir::new(test);
    w.write_config(&reference_tokens(&module, &w.dir));
    let (name, path) = r.profile;
    assert_profile_conforms(|args| w.km(args), "ref", name, path, &w.dir.join("profile.toml"));
    let anon = w.km(&["probe", "--token", "ref-anon", "--write"]);
    assert_eq!(code(&anon), 17);
    assert!(stderr(&anon).contains("not marked scratch"));
}

#[test]
fn softhsm_committed_profile_is_what_the_probe_observes() {
    committed_profile_is_what_the_probe_observes(&SOFTHSM, "softhsm-profile");
}

#[test]
fn kryoptic_committed_profile_is_what_the_probe_observes() {
    committed_profile_is_what_the_probe_observes(&KRYOPTIC, "kryoptic-profile");
}

/// The p11-kit suite's tokens, when its variables are set.
fn p11kit(test: &str) -> Option<Workdir> {
    let client = suite_var("CAKEYS_P11KIT_CLIENT", "CAKEYS_P11KIT_REQUIRE", test)?;
    let direct = std::env::var("CAKEYS_TEST_MODULE").expect("CAKEYS_TEST_MODULE (SoftHSM) for the direct path");
    let w = Workdir::new(&format!("p11kit-{test}"));
    w.write_config(&p11kit_tokens(&client, &direct, &w.dir));
    Some(w)
}

fn caps(w: &Workdir, token: &str) -> serde_json::Value {
    serde_json::from_str(&stdout(&w.km(&["caps", "--token", token]))).unwrap()
}

const FORWARDING_DROPS: [&str; 4] =
    ["CKM_AES_KEY_WRAP", "CKM_AES_KEY_WRAP_PAD", "CKM_EC_EDWARDS_KEY_PAIR_GEN", "CKM_EDDSA"];

/// Through p11-kit, `caps` shows the forwarder's provider and a filtered mechanism list.
#[test]
fn p11kit_forwards_a_filtered_view() {
    let Some(w) = p11kit("view") else { return };
    let fwd = caps(&w, "fwd");
    assert_eq!(fwd["provider"], "p11-kit", "detected from the proxy's C_GetInfo");
    let has = |c: &serde_json::Value, m: &str| c["mechanisms"].as_array().unwrap().iter().any(|x| x == m);
    let direct = caps(&w, "direct");
    assert_eq!(direct["provider"], "softhsm");
    for m in ["CKM_EC_KEY_PAIR_GEN", "CKM_RSA_PKCS_KEY_PAIR_GEN", "CKM_AES_CMAC", "CKM_AES_ECB", "CKM_SHA256_HMAC"] {
        assert!(has(&fwd, m) && has(&direct, m), "{m} is forwarded");
    }
    // The RPC drops what it cannot marshal (if a p11-kit update forwards one, revisit the docs).
    for m in FORWARDING_DROPS {
        assert!(has(&direct, m) && !has(&fwd, m), "{m}: SoftHSM has it, p11-kit hides it");
    }
    // Naming the provider behind the proxy applies its behaviour.
    assert_eq!(caps(&w, "fwd-softhsm")["provider"], "softhsm");
    // The server exports only the token in its URI; the same SoftHSM's other token is invisible.
    assert_eq!(w.code(&["caps", "--token", "fwd-other"]), 16);
}

/// The p11-kit layer profile against the forwarder itself (docs/CAPROBE.md): probed
/// through p11-kit, `SoftHSM` advertises exactly what its committed profile advertises minus
/// what profiles/layers/p11-kit.toml subtracts — the client filters `C_GetMechanismList` — and
/// the probe sees p11-kit's identity, not the module's.
#[test]
fn the_forwarder_subtracts_exactly_its_layer() {
    let Some(w) = p11kit("probe_forwarded") else { return };
    if !cryptoki_hmac_types_fixed(std::env::var("CAKEYS_P11KIT_REQUIRE").is_ok()) {
        return;
    }
    let read = |path: &str| -> toml::Value {
        toml::from_str(&std::fs::read_to_string(committed_profile(path)).unwrap()).unwrap()
    };
    let names = |v: &toml::Value| -> std::collections::BTreeSet<String> {
        v.as_array().unwrap().iter().map(|m| m.as_str().unwrap().to_owned()).collect()
    };
    let module = names(&read("modules/softhsm/2.7.toml")["advertise"]);
    let layer = names(&read("layers/p11-kit.toml")["subtract"]["mechanisms"]);
    assert!(layer.is_subset(&module), "the layer subtracts what SoftHSM never advertises");
    let out = w.km(&["probe", "--token", "fwd"]);
    assert_eq!(code(&out), 0);
    let probed: toml::Value = toml::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    let forwarded = names(&probed["advertise"]);
    let expected: std::collections::BTreeSet<String> = module.difference(&layer).cloned().collect();
    assert_eq!(forwarded, expected, "p11-kit forwards a different list than its layer profile says");
    assert_eq!(probed["match"]["manufacturer"].as_str(), Some("PKCS#11 Kit"));
}
