//! The static gate (docs/CAPROBE.md): `validate` checks each spec's needs against its
//! token's capability profiles, resolved from keys.toml and the lock — no token, no module,
//! no environment needed, so these run everywhere.

mod common;

use common::*;
use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_cakeys");
const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

fn validate(config: &str) -> Output {
    Command::new(BIN).arg("--config").arg(format!("{FIXTURES}/{config}")).arg("validate").output().unwrap()
}

/// docs/CAPROBE.md's two static-gate cases, each naming the profile that decided it: a `kw`
/// commitment through p11-kit is refused (15); kryoptic asked to generate secp256k1 is a note
/// for `cakeys create`, since the key might be adopted. A token nothing is known about is
/// skipped with a note.
#[test]
fn a_profile_no_refuses_and_names_its_profile() {
    let out = validate("gate.toml");
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(code(&out), 15, "{err}");
    assert!(
        err.contains("note: validate: 'k1' (spec 'k1-kry') on token 'kry': `cakeys create` cannot make it")
            && err.contains("no — kryoptic/1.5"),
        "{err}"
    );
    assert!(err.contains("1 target needs what the capability profiles say"), "{err}");
    assert!(err.contains("'aes' (spec 'aes-kw')") && err.contains("CKM_AES_KEY_WRAP: no — p11-kit/0.26"), "{err}");
    assert!(err.contains("token 'unknown': no provider named"), "{err}");
    // What the profiles allow passes silently: P-256 on kryoptic.
    assert!(!err.contains("'p256' (spec 'p256-kry') on token 'kry'"), "{err}");
}

/// The lock's recorded module and token are the profile source when keys.toml names no
/// provider: the token's observation resolves softhsm/2.7, whose rows allow every spec
/// (generation it does not record is a note, never a refusal, and asked only of an object the
/// lock does not pin). The fixture's three `SoftHSM`
/// realisations name three observations, so which is current is not known: a note naming
/// `realise`, and the token is skipped. With one observation it resolves.
#[test]
fn the_lock_resolves_a_token_keys_toml_does_not_name() {
    let out = validate("keys.toml");
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(code(&out), 0, "{err}");
    assert!(err.contains("token 'softhsm' were recorded with 3 different observations"), "{err}");
    assert!(err.contains("`realise` them") && !err.contains("softhsm/2.7"), "{err}");

    let w = Workdir::new("validate-one-observation");
    // One object the lock does not pin yet, so `create` would make it there.
    let fresh = "\n[objects.fresh]\nclass = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_GENERIC_SECRET\"\nvalueLen = 32\n\n\
                 [specs.fresh]\nobject = \"fresh\"\nattributes = { CKA_SIGN = true }\n\
                 tokens.softhsm = { locator = { CKA_LABEL = \"fresh\" } }\n";
    w.write_config(&(std::fs::read_to_string(format!("{FIXTURES}/keys.toml")).unwrap() + fresh));
    let mut lock: toml::Value =
        toml::from_str(&std::fs::read_to_string(format!("{FIXTURES}/keys.lock")).unwrap()).unwrap();
    for spec in ["shared-sign", "shared-nosign"] {
        lock["realisations"][spec]["softhsm"].as_table_mut().unwrap().remove("observation");
    }
    std::fs::write(w.dir.join("keys.lock"), toml::to_string(&lock).unwrap()).unwrap();
    let out = w.km(&["validate"]);
    let err = stderr(&out);
    assert_eq!(code(&out), 0, "{err}");
    let fresh =
        "'fresh' (spec 'fresh') on token 'softhsm': generation not decided: unknown — module profile softhsm/2.7";
    assert!(err.contains(fresh), "{err}");
    // The lock pins every other object: `create` would make none of them, so no generation is asked.
    assert_eq!(err.lines().filter(|l| l.contains("generation")).count(), 1, "{err}");
}

/// What the gate refuses or leaves open, from keys.toml alone: an attestation the provider
/// cannot make is refused (15); a hash-bound HMAC key the token cannot generate is a note
/// naming `cakeys create`, since keys.toml does not say it is created rather than adopted; a
/// provider with no module profile (`generic`) leaves the generation undecided, a note; so does a family whose profiles need the module's version to choose (`tpm2-pkcs11`,
/// whose module nobody has seen yet): one stands in without its hardware rows, never an
/// error; a layer the stack already holds (the binding layer) is not added twice.
/// A build whose cryptoki maps the SHA-2 HMAC key types wrongly refuses the HMAC key by its
/// type before any profile is asked.
#[test]
fn the_gate_refuses_what_it_can_decide_and_says_what_it_cannot() {
    let w = Workdir::new("validate-gate-cases");
    let token = |name: &str, extra: &str| format!("[tokens.{name}]\ntokenLabel = \"{name}\"\n{extra}\n\n");
    let spec = |name: &str, object: &str, token: &str, extra: &str| {
        format!(
            "[specs.{name}]\nobject = \"{object}\"\nattributes = {{ CKA_SIGN = true }}\n\
             tokens.{token} = {{ locator = {{ CKA_LABEL = \"{name}\" }}{extra} }}\n\n"
        )
    };
    let ec = |name: &str| {
        format!("[objects.{name}]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n")
    };
    let text = [
        token("soft", "provider = \"softhsm\"\nprofiles = [\"cryptoki/0.12\"]"),
        token("gen", "provider = \"generic\""),
        token("tpm", "provider = \"tpm2-pkcs11\""),
        token("yk", "provider = \"ykcs11\""),
        "[objects.aes]\nclass = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_AES\"\nvalueLen = 32\n\n".to_owned(),
        "[objects.mac]\nclass = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_SHA384_HMAC\"\nvalueLen = 48\n\n".to_owned(),
        ec("soft"),
        ec("gen"),
        ec("tpm"),
        spec("mac-soft", "mac", "soft", ""),
        spec("p-soft", "soft", "soft", ", attestation = true"),
        spec("p-gen", "gen", "gen", ""),
        spec("p-tpm", "tpm", "tpm", ""),
        spec("aes-yk", "aes", "yk", ", attestation = true"),
    ]
    .concat();
    w.write_config(&text);
    let out = w.km(&["validate"]);
    let err = stderr(&out);
    assert_eq!(code(&out), 15, "{err}");
    let hmac = if cakeys_pkcs11::binding::patched() {
        "note: validate: 'mac' (spec 'mac-soft') on token 'soft': `cakeys create` cannot make it: token 'soft' \
         cannot do what mode 'commitment' needs (CKM_SHA384_KEY_GEN: no — softhsm/2.7: not advertised)"
    } else {
        "CKK_SHA384_HMAC: this build's cryptoki maps it to CKK_SHA256_HMAC"
    };
    for line in [
        hmac,
        "opts into attestation, but provider 'softhsm' attests nothing on this module",
        "opts into attestation, but provider 'ykcs11' attests only [\"CKO_PRIVATE_KEY\", \"CKO_PUBLIC_KEY\"]",
        "validate: 'gen' (spec 'p-gen') on token 'gen': the profiles do not decide",
        "validate: 'tpm' (spec 'p-tpm') on token 'tpm': generation not decided",
    ] {
        assert!(err.contains(line), "expected {line:?} in\n{err}");
    }
}
