//! caprobe against the software tokens the Nix check phase sets up (nix/package-common.nix): `SoftHSM`
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
    if !hmac_types_fixed(r.require_var) {
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
    let anon = w.km(&["probe", "--token", "ref-anon", "--write-probes", "--rsa-max-bits", "4096"]);
    assert_eq!(code(&anon), 17, "{}", stderr(&anon));
    assert!(stderr(&anon).contains("not marked scratch"), "{}", stderr(&anon));
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
    let other = w.km(&["caps", "--token", "fwd-other"]);
    assert_eq!(code(&other), 16, "{}", stderr(&other));
}

/// The p11-kit layer profile against the forwarder itself (docs/CAPROBE.md): probed
/// through p11-kit, `SoftHSM` advertises exactly what its committed profile advertises minus
/// what profiles/layers/p11-kit.toml subtracts — the client filters `C_GetMechanismList` — and
/// the probe sees p11-kit's identity, not the module's.
#[test]
fn the_forwarder_subtracts_exactly_its_layer() {
    let Some(w) = p11kit("probe_forwarded") else { return };
    if !hmac_types_fixed("CAKEYS_P11KIT_REQUIRE") {
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
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let probed: toml::Value = toml::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    let forwarded = names(&probed["advertise"]);
    let expected: std::collections::BTreeSet<String> = module.difference(&layer).cloned().collect();
    assert_eq!(forwarded, expected, "p11-kit forwards a different list than its layer profile says");
    assert_eq!(probed["match"]["manufacturer"].as_str(), Some("PKCS#11 Kit"));
    // `--name` names the generated profile; the default is `<provider>/<version>`, the version
    // p11-kit reports of itself (1.1), not its release.
    let out = w.km(&["probe", "--token", "fwd", "--name", "mine/1.0"]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let renamed: toml::Value = toml::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert_eq!((renamed["profile"].as_str(), probed["profile"].as_str()), (Some("mine/1.0"), Some("p11-kit/1.1")));
}

/// `--module TOKEN=PATH` replaces a token's module for the run: the reference token's, by a
/// path that loads nothing, is unavailable (16) naming that path; an override not of that form
/// is invalid (17), as in every tool (`module_overrides`).
#[test]
fn a_module_override_replaces_the_tokens_module() {
    let test = "module-override";
    let Some(module) = suite_var(SOFTHSM.module_var, SOFTHSM.require_var, test) else { return };
    let w = Workdir::new(test);
    w.write_config(&reference_tokens(&module, &w.dir));
    let gone = format!("ref={}", w.dir.join("libgone.so").display());
    let o = w.km(&["--module", &gone, "probe", "--token", "ref"]);
    assert!(code(&o) == 16 && stderr(&o).contains("libgone.so"), "{}", stderr(&o));
    let o = w.km(&["--module", "ref", "probe", "--token", "ref"]);
    assert!(code(&o) == 17 && stderr(&o).contains("expects TOKEN=PATH"), "{}", stderr(&o));
}

/// The write probes' scratch guard (docs/CAPROBE.md), on the reference token named
/// `provider = "ykcs11"`: a provider that creates only as Security Officer probes one slot,
/// named by `scratchId`, with the admin credential; without either it is refused (17), as is a
/// `scratchId` on a provider that creates as the user, and a token with no PIN. A slot is probed
/// only empty or holding the probe's own certificate over the key beside it, which every slot run
/// leaves there: never one with a real certificate, a key with none, or ykcs11's placeholder,
/// which every key ykcs11 generates has, a real one too (review 2026-11-23 D-1: that placeholder
/// used to pass); nor a marked slot whose key is another (review 2026-11-24 E-6: a key put into a
/// probed slot kept the mark, which named a certificate, not the key).
fn the_scratch_guard_names_one_slot(r: &Reference, test: &str) {
    use cryptoki::object::Attribute as A;
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
            token("key-only", &yk("16")),
            token("old-mark", &yk("17")),
            token("placeholder", &yk("18")),
        ]
        .concat(),
    );
    let refused = |name: &str, why: &str| {
        let o = w.km(&["probe", "--token", name, "--write-probes", "--rsa-max-bits", "4096"]);
        assert_eq!(code(&o), 17, "{name}: {}", stderr(&o));
        assert!(stderr(&o).contains(why), "{name}: expected {why:?} in {}", stderr(&o));
    };
    refused("no-slot", "name the one slot the write probes may overwrite");
    refused("no-admin", "set tokens.no-admin.soCredentialFile");
    refused("user-slot", "scratchId names a slot for providers that create only as Security Officer");
    refused("no-pin", "has no PIN configured");

    // A real certificate in slot 06, ykcs11's placeholder in slot 95 (CKA_ID 18), in slot 93
    // (CKA_ID 16) a key with no certificate, and in slot 94 (CKA_ID 17) the fixed certificate the
    // probe once marked with, which vouches for no key there.
    let fixture = |name: &str| {
        let pem = std::fs::read_to_string(format!("{}/../ykcs11/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR")));
        x509_cert::der::pem::decode_vec(pem.unwrap().as_bytes()).unwrap().1
    };
    let slot = fixture("slot.pem");
    let probes = include_bytes!("../fixtures/import/certificate.der").to_vec();
    let s = open_session(&module, "kmtest", "1234");
    let key = [A::Token(true), A::ValueLen(32.into()), A::Id(vec![0x16])];
    s.generate_key(&cryptoki::mechanism::Mechanism::AesKeyGen, &key).unwrap();
    for (der, id) in [(slot.clone(), 0x06), (probes.clone(), 0x17), (fixture("placeholder95.pem"), 0x18)] {
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
    for (name, id) in [("taken", "06"), ("key-only", "16"), ("old-mark", "17"), ("placeholder", "18")] {
        refused(name, &format!("scratchId {id} holds objects caprobe did not leave there"));
    }
    // Never overwritten: the slot holds its one certificate, as it was (review reference.rs F1:
    // the exit alone passed a probe that cleared the slot and then refused).
    let s = open_session(&module, "kmtest", "1234");
    let held: Vec<Vec<u8>> = s
        .find_objects(&[cryptoki::object::Attribute::Id(vec![0x06])])
        .unwrap()
        .into_iter()
        .map(|h| match &s.get_attributes(h, &[cryptoki::object::AttributeType::Value]).unwrap()[..] {
            [cryptoki::object::Attribute::Value(v)] => v.clone(),
            other => panic!("slot 06: {other:?}"),
        })
        .collect();
    assert_eq!(held, [slot], "slot 06 was changed by a refused probe");
    drop(s);
    a_mark_vouches_for_its_key(&w, &module);
}

/// [`the_scratch_guard_names_one_slot`]'s slot 05, empty: two write probes on it, then another
/// key put there.
fn a_mark_vouches_for_its_key(w: &Workdir, module: &str) {
    use cryptoki::object::Attribute as A;
    // Two write probes on one slot: these modules destroy what the probe makes, so the second
    // meets only what the first left there, its key and its mark, and the guard accepts it
    // (review reference.rs F3; `assert_profile_conforms` holds tpm2-pkcs11 to one).
    for _ in 0..2 {
        let o = w.km(&["probe", "--token", "empty", "--write-probes", "--rsa-max-bits", "4096"]);
        assert_eq!(code(&o), 0, "{}", stderr(&o));
        assert!(
            stderr(&o).contains("in a scratch slot: no secret-key, wrap, export or delete probes"),
            "{}",
            stderr(&o)
        );
    }
    // Each run leaves its slot marked as the probe's: a certificate over the slot's own key, or,
    // where the SO generates none (SoftHSM, kryoptic), over the probe's own P-256 test key.
    let session = open_session(module, "kmtest", "1234");
    let in_slot = |s: &TestSession, class| {
        s.find_objects(&[A::Class(class), A::Id(vec![0x05])])
            .unwrap()
            .into_iter()
            .map(|h| match &s.get_attributes(h, &[cryptoki::object::AttributeType::Value]).unwrap()[..] {
                [A::Value(v)] => v.clone(),
                other => panic!("slot 05: {other:?}"),
            })
            .collect::<Vec<_>>()
    };
    let public = |s: &TestSession| {
        let keys = s.find_objects(&[A::Class(cryptoki::object::ObjectClass::PUBLIC_KEY), A::Id(vec![0x05])]).unwrap();
        keys.first().map(|h| match &s.get_attributes(*h, &[cryptoki::object::AttributeType::EcPoint]).unwrap()[..] {
            [A::EcPoint(p)] => cakeys_core::id::Curve::P256.spki_from_point(p).unwrap(),
            other => panic!("slot 05: {other:?}"),
        })
    };
    let certs = in_slot(&session, cryptoki::object::ObjectClass::CERTIFICATE);
    let own = include_bytes!("../fixtures/import/certificate.der");
    let spki = public(&session).unwrap_or_else(|| cakeys_core::id::cert_spki(own).unwrap());
    assert!(
        certs.iter().any(|c| cakeys_core::id::cert_spki(c).is_ok_and(|k| k == spki)),
        "slot 05 was left without a mark over its key: {} certificates",
        certs.len()
    );
    // Another key put into the marked slot, without a certificate (as `ykman piv keys generate`
    // does): the mark vouches for another key, and the guard refuses the slot, unchanged.
    for class in [cryptoki::object::ObjectClass::PUBLIC_KEY, cryptoki::object::ObjectClass::PRIVATE_KEY] {
        for h in session.find_objects(&[A::Class(class), A::Id(vec![0x05])]).unwrap() {
            session.destroy_object(h).unwrap();
        }
    }
    let p256 = vec![0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
    session
        .generate_key_pair(
            &cryptoki::mechanism::Mechanism::EccKeyPairGen,
            &[A::Token(true), A::Id(vec![0x05]), A::EcParams(p256), A::Verify(true)],
            &[A::Token(true), A::Id(vec![0x05]), A::Private(true), A::Sensitive(true), A::Sign(true)],
        )
        .unwrap();
    let foreign = public(&session).unwrap();
    drop(session);
    let o = w.km(&["probe", "--token", "empty", "--write-probes", "--rsa-max-bits", "4096"]);
    assert_eq!(code(&o), 17, "{}", stderr(&o));
    assert!(stderr(&o).contains("scratchId 05 holds objects caprobe did not leave there"), "{}", stderr(&o));
    let session = open_session(module, "kmtest", "1234");
    assert_eq!(
        (public(&session), in_slot(&session, cryptoki::object::ObjectClass::CERTIFICATE)),
        (Some(foreign), certs),
        "a refused probe changed slot 05"
    );
}

#[test]
fn softhsm_the_scratch_guard_names_one_slot() {
    the_scratch_guard_names_one_slot(&SOFTHSM, "softhsm-scratch-slot");
}

#[test]
fn kryoptic_the_scratch_guard_names_one_slot() {
    the_scratch_guard_names_one_slot(&KRYOPTIC, "kryoptic-scratch-slot");
}
