//! The static gate (docs/CAPROBE.md): `validate` checks each spec's needs against its
//! token's capability profiles, resolved from keys.toml and the lock — no token, no module,
//! no environment needed, so these run everywhere.

mod common;

use common::*;
use std::path::Path;
use std::process::Output;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

fn validate(config: &str) -> Output {
    Run::new(BIN, Path::new(&format!("{FIXTURES}/{config}"))).output(&["validate"])
}

/// docs/CAPROBE.md's two static-gate cases, each refused (15) naming the profile that decided
/// it: kryoptic asked to generate secp256k1 (`origin = "create"`), and a `kw` commitment through
/// p11-kit. A token nothing is known about is skipped with a note.
#[test]
fn a_profile_no_refuses_and_names_its_profile() {
    let out = validate("gate.toml");
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(code(&out), 15, "{err}");
    // Who refused and which profile decided, not the sentence around them (review validate.rs F2).
    let line = |start: &str| err.lines().find(|l| l.contains(start)).unwrap_or_else(|| panic!("{start}: {err}"));
    assert!(line("'k1' (spec 'k1-kry') on token 'kry': token 'kry' cannot").contains("kryoptic/1.5"), "{err}");
    assert!(err.contains("2 targets need what the capability profiles say"), "{err}");
    let kw = line("'aes' (spec 'aes-kw')");
    assert!(kw.contains("CKM_AES_KEY_WRAP") && kw.contains("p11-kit/0.26"), "{err}");
    assert!(err.contains("token 'unknown': no provider named"), "{err}");
    // What the profiles allow passes silently: P-256 on kryoptic.
    assert!(!err.contains("'p256' (spec 'p256-kry') on token 'kry'"), "{err}");
}

/// The lock's recorded module and token are the profile source when keys.toml names no
/// provider: the token's observation resolves softhsm/2.7, whose rows allow every spec
/// (generation it does not record is a note, never a refusal, and asked only of a pair whose
/// origin is `create` and whose object the lock does not pin). The fixture's three `SoftHSM`
/// realisations name three observations, so which is current is not known: a note naming
/// `lock`, and the token is skipped. With one observation it resolves.
#[test]
fn the_lock_resolves_a_token_keys_toml_does_not_name() {
    let out = validate("keys.toml");
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(code(&out), 0, "{err}");
    assert!(err.contains("token 'softhsm' were recorded with 3 different observations"), "{err}");
    assert!(err.contains("`lock` them") && !err.contains("softhsm/2.7"), "{err}");

    let w = Workdir::new("validate-one-observation");
    // One object the lock does not pin yet, so `create` would make it there, of a length beyond
    // those the profile's probe generated: its generation is not decided.
    let fresh = "\n[objects.fresh]\nclass = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_GENERIC_SECRET\"\nvalueLen = 4096\n\n\
                 [specs.fresh]\nobject = \"fresh\"\nattributes = { CKA_SIGN = true }\n\
                 tokens.softhsm = { locator = { CKA_LABEL = \"fresh\" }, origin = \"create\" }\n";
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

/// A secret key to create is decided by the lengths the module profile recorded, in bytes: AES at
/// 32, Triple DES at the 24 its type fixes and a generic secret between the lengths tried generate
/// with no note; a generic secret longer than any tried is left open, a note, never a guess.
#[test]
fn a_secret_key_to_create_is_decided_by_its_recorded_lengths() {
    let w = Workdir::new("validate-secret-lengths");
    let object = |name: &str, key_type: &str, len: Option<u32>| {
        let len = len.map_or(String::new(), |n| format!("valueLen = {n}\n"));
        format!("[objects.{name}]\nclass = \"CKO_SECRET_KEY\"\nkeyType = \"{key_type}\"\n{len}\n")
    };
    let spec = |name: &str, usage: &str| {
        format!(
            "[specs.{name}]\nobject = \"{name}\"\nattributes = {{ {usage} = true }}\n\
             tokens.soft = {{ locator = {{ CKA_LABEL = \"{name}\" }}, origin = \"create\" }}\n\n"
        )
    };
    let text = [
        "[tokens.soft]\ntokenLabel = \"soft\"\nprovider = \"softhsm\"\n\n".to_owned(),
        object("aes", "CKK_AES", Some(32)),
        object("des3", "CKK_DES3", None),
        object("mac", "CKK_GENERIC_SECRET", Some(48)),
        object("huge", "CKK_GENERIC_SECRET", Some(4096)),
        object("short", "CKK_GENERIC_SECRET", Some(8)),
        spec("aes", "CKA_SIGN"),
        spec("des3", "CKA_ENCRYPT"),
        spec("mac", "CKA_SIGN"),
        spec("huge", "CKA_SIGN"),
        spec("short", "CKA_SIGN"),
    ]
    .concat();
    w.write_config(&text);
    let out = w.km(&["validate"]);
    let err = stderr(&out);
    assert_eq!(code(&out), 0, "{err}");
    let noted = |object: &str, what: &str| {
        err.lines().any(|l| l.contains(&format!("'{object}' (spec")) && l.contains(what) && l.contains("not decided"))
    };
    for object in ["aes", "des3", "mac", "short"] {
        assert!(!noted(object, "generation"), "{object}: {err}");
    }
    assert!(noted("huge", "generation"), "{err}");
    assert!(err.contains("probed 1, 16, 32, 64, 128, 256, 512, 1024 bytes only"), "{err}");
    // SoftHSM computes the HMAC commitment at 32 and 64 bytes and refuses 16: 48 lies between two
    // that worked, 8 below one refused, which is unknown, never a yes (review 2026-11-23 A-1).
    assert!(!noted("mac", "commitments"), "{err}");
    assert!(noted("short", "commitments"), "{err}");
    assert!(err.contains("probed hmac-sha256 at 16, 32, 64 bytes only"), "{err}");
}

/// What the gate refuses or leaves open, from keys.toml alone: a hash-bound HMAC key to
/// create (PKCS#11 has no mechanism for it) and an attestation the provider cannot make are
/// refused (15); a provider with no module profile (`generic`) leaves the generation undecided,
/// a note; so does a family whose profiles need the module's version to choose (`tpm2-pkcs11`,
/// whose module nobody has seen yet): one stands in without its hardware rows, never an
/// error; a layer the stack already holds (the binding layer) is not added twice. An adopted
/// key is never asked about generation. A build whose cryptoki maps the SHA-2 HMAC key types
/// wrongly refuses the HMAC key by its type before any profile is asked.
#[test]
fn the_gate_refuses_what_it_can_decide_and_says_what_it_cannot() {
    let w = Workdir::new("validate-gate-cases");
    let token = |name: &str, extra: &str| format!("[tokens.{name}]\ntokenLabel = \"{name}\"\n{extra}\n\n");
    let spec = |name: &str, object: &str, token: &str, extra: &str| {
        let origin = if extra.contains("origin") { "" } else { ", origin = \"create\"" };
        format!(
            "[specs.{name}]\nobject = \"{object}\"\nattributes = {{ CKA_SIGN = true }}\n\
             tokens.{token} = {{ locator = {{ CKA_LABEL = \"{name}\" }}{origin}{extra} }}\n\n"
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
        ec("yk"),
        ec("yk-in"),
        spec("mac-soft", "mac", "soft", ""),
        spec("p-soft", "soft", "soft", ", attestation = true"),
        spec("p-gen", "gen", "gen", ""),
        spec("p-tpm", "tpm", "tpm", ""),
        spec("aes-yk", "aes", "yk", ", origin = \"adopt\", attestation = true"),
        // A key ykcs11 would make under a label, created or imported: it places keys in PIV slots
        // by CKA_ID alone (review 2026-11-23 B-3: only `create` itself, token open, said so).
        spec("p-yk", "yk", "yk", ""),
        spec("in-yk", "yk-in", "yk", ", origin = \"import\""),
    ]
    .concat();
    w.write_config(&text);
    let out = w.km(&["validate"]);
    let err = stderr(&out);
    assert_eq!(code(&out), 15, "{err}");
    let hmac = if cakeys_pkcs11::binding::patched() {
        "'mac' (spec 'mac-soft') on token 'soft': token 'soft' cannot do what mode 'commitment' needs \
         (CKM_SHA384_KEY_GEN: no — softhsm/2.7: not advertised)"
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
    for pair in ["'yk' (spec 'p-yk') on token 'yk': provider 'ykcs11'", "'yk-in' (spec 'in-yk') on token 'yk'"] {
        let refused = err.lines().find(|l| l.contains(pair)).unwrap_or_else(|| panic!("{pair}: {err}"));
        assert!(refused.contains("ykcs11 ignores CKA_LABEL when generating"), "{refused}");
    }
}

/// A token whose provider is known only when it opens (no `provider`, nothing in the lock: a
/// ykcs11 module, say) still has its provider's rules asked: `validate` and `create --dry-run`
/// defer each by name — where a key may go, the module's own generation, the templates, what the
/// token can do — and never pass them in silence (review 2026-11-24 B-1). The run that opens the
/// token decides them; a pair it would refuse (ykcs11: a key under a label, 17) differs from the
/// dry run only by a rule the dry run named. `create --dry-run` opens the token too (review
/// 2026-11-24 C-4): one that does not open is unavailable (16), as for the run, its rows printed.
#[test]
fn a_provider_known_only_at_open_defers_its_rules_by_name() {
    let w = Workdir::new("validate-unresolved-provider");
    w.write_config(
        "[tokens.yk]\nmodule = \"/nonexistent/libykcs11.so\"\ntokenLabel = \"YubiKey PIV\"\n\n\
         [objects.k]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n\
         [specs.s]\nobject = \"k\"\nattributes = { CKA_SIGN = true }\n\
         tokens.yk = { locator = { CKA_LABEL = \"under-a-label\" }, origin = \"create\" }\n",
    );
    let deferred = "(deferred: placement, own-generation, templates, capability)";
    let out = w.km(&["validate"]);
    let err = stderr(&out);
    assert_eq!(code(&out), 0, "{err}");
    let line = err.lines().find(|l| l.contains("'k' (spec 's') on token 'yk'")).unwrap_or_else(|| panic!("{err}"));
    assert!(line.ends_with(deferred), "{line}");

    let out = w.km(&["create", "--dry-run"]);
    assert_eq!(code(&out), 16, "{}", stderr(&out));
    assert_eq!(code(&w.km(&["create"])), 16, "the run, the same");
    let rows: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let rules: Vec<&str> =
        rows[0]["deferred"].as_array().unwrap().iter().map(|d| d["rule"].as_str().unwrap()).collect();
    assert_eq!(rules, ["placement", "own-generation", "templates", "capability"], "{rows}");
}
