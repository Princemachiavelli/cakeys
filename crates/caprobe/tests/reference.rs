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
    // Against the other reference's profile, the drift is printed row by row and refused (15).
    let other = if r.provider == "softhsm" { KRYOPTIC.profile.0 } else { SOFTHSM.profile.0 };
    let drift = w.km(&["probe", "--token", "ref", "--diff", other]);
    assert_eq!(code(&drift), 15, "{}", stderr(&drift));
    assert!(stderr(&drift).contains(&format!("rows differ from profile {other}")), "{}", stderr(&drift));
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
    // `--name` names the generated profile; the default is `<provider>/<version>`, the version
    // p11-kit reports of itself (1.1), not its release.
    let out = w.km(&["probe", "--token", "fwd", "--name", "mine/1.0"]);
    assert_eq!(code(&out), 0);
    let renamed: toml::Value = toml::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert_eq!((renamed["profile"].as_str(), probed["profile"].as_str()), (Some("mine/1.0"), Some("p11-kit/1.1")));
}

/// The write probes' scratch guard (docs/CAPROBE.md), on the reference token named
/// `provider = "ykcs11"`: a provider that creates only as Security Officer probes one slot,
/// named by `scratchId`, with the admin credential; without either it is refused (17), as is a
/// `scratchId` on a provider that creates as the user, and a token with no PIN. A slot holding
/// anything but ykcs11's own placeholder is never overwritten (17); an empty one, or one with the
/// placeholder, is probed.
fn the_scratch_guard_names_one_slot(r: &Reference, test: &str) {
    let Some(module) = suite_var(r.module_var, r.require_var, test) else { return };
    let w = Workdir::new(test);
    std::fs::write(w.dir.join("so-pin"), "5678\n").unwrap();
    let (pin, so) = (w.dir.join("pin"), w.dir.join("so-pin"));
    let token = |name: &str, extra: &str| {
        format!("[tokens.{name}]\nmodule = \"{module}\"\ntokenLabel = \"kmtest\"\n{extra}\n\n")
    };
    let yk = |id: &str| {
        format!(
            "provider = \"ykcs11\"\npinFile = \"{}\"\nsoCredentialFile = \"{}\"\nprobe = {{ scratchId = \"{id}\" }}",
            pin.display(),
            so.display()
        )
    };
    w.write_config(
        &[
            token("no-slot", &format!("provider = \"ykcs11\"\npinFile = \"{}\"", pin.display())),
            token(
                "no-admin",
                &format!("provider = \"ykcs11\"\npinFile = \"{}\"\nprobe = {{ scratchId = \"05\" }}", pin.display()),
            ),
            token("user-slot", &format!("pinFile = \"{}\"\nprobe = {{ scratchId = \"05\" }}", pin.display())),
            token("no-pin", "probe = { scratch = true }"),
            token("empty", &yk("05")),
            token("taken", &yk("06")),
            token("placeholder", &yk("18")),
        ]
        .concat(),
    );
    let refused = |name: &str, why: &str| {
        let o = w.km(&["probe", "--token", name, "--write"]);
        assert_eq!(code(&o), 17, "{name}: {}", stderr(&o));
        assert!(stderr(&o).contains(why), "{name}: expected {why:?} in {}", stderr(&o));
    };
    refused("no-slot", "name the one slot the write probes may overwrite");
    refused("no-admin", "set tokens.no-admin.soCredentialFile");
    refused("user-slot", "scratchId names a slot for providers that create only as Security Officer");
    refused("no-pin", "has no PIN configured");

    // A real certificate in slot 06, ykcs11's own placeholder in slot 95 (CKA_ID 18).
    let s = open_session(&module, "kmtest", "1234");
    let fixture = |name: &str| {
        let pem = std::fs::read_to_string(format!("{}/../ykcs11/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR")));
        x509_cert::der::pem::decode_vec(pem.unwrap().as_bytes()).unwrap().1
    };
    for (der, id) in [(fixture("slot.pem"), 0x06), (fixture("placeholder95.pem"), 0x18)] {
        let cert = <x509_cert::Certificate as x509_cert::der::Decode>::from_der(&der).unwrap();
        let subject = x509_cert::der::Encode::to_der(cert.tbs_certificate().subject()).unwrap();
        s.create_object(&[
            cryptoki::object::Attribute::Class(cryptoki::object::ObjectClass::CERTIFICATE),
            cryptoki::object::Attribute::CertificateType(cryptoki::object::CertificateType::X_509),
            cryptoki::object::Attribute::Token(true),
            cryptoki::object::Attribute::Id(vec![id]),
            cryptoki::object::Attribute::Subject(subject),
            cryptoki::object::Attribute::Value(der),
        ])
        .unwrap();
    }
    drop(s);
    refused("taken", "scratchId 06 holds objects that are not ykcs11's own placeholder");
    for name in ["empty", "placeholder"] {
        let o = w.km(&["probe", "--token", name, "--write"]);
        assert_eq!(code(&o), 0, "{name}: {}", stderr(&o));
        assert!(stderr(&o).contains("in a scratch slot: no secret-key, wrap or delete probes"), "{}", stderr(&o));
    }
}

#[test]
fn softhsm_the_scratch_guard_names_one_slot() {
    the_scratch_guard_names_one_slot(&SOFTHSM, "softhsm-scratch-slot");
}

#[test]
fn kryoptic_the_scratch_guard_names_one_slot() {
    the_scratch_guard_names_one_slot(&KRYOPTIC, "kryoptic-scratch-slot");
}
