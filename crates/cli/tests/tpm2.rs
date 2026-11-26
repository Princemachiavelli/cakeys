//! End-to-end tests against tpm2-pkcs11 on a software TPM (nix/tpm2-test-env.sh).
//!
//! The tests need `CAKEYS_TPM_MODULE` (`libtpm2_pkcs11.so`), the `TPM2_PKCS11_*` environment from
//! the harness, a token `kmtest` with user PIN `1234`, and `tpm2_ptool` on PATH. The tests are
//! skipped when `CAKEYS_TPM_MODULE` is unset, unless `CAKEYS_TPM_REQUIRE=1`.

mod common;
mod object_matrix;

use common::*;
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, ObjectClass};
use cryptoki::session::Session;
use hmac::{Hmac, KeyInit, Mac};
use std::process::Command;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

/// Returns the suite for test `name` ([`tpm2_tokens`]), or `None` (the test is skipped). A
/// tpm2-pkcs11 session sees only the objects that existed when it was opened, so call
/// [`Suite::session`] after the run that made the objects.
fn env(name: &str) -> Option<Suite> {
    let module = suite_var("CAKEYS_TPM_MODULE", "CAKEYS_TPM_REQUIRE", name)?;
    Some(Suite::new(&format!("tpm2-{name}"), module, tpm2_tokens).checking(no_attestation_off_swtpm))
}

/// Checks every keys.toml that a test writes. An attestation provisions a persistent Attestation
/// Key, so a keys.toml that asks for an attestation may be written only against the suite's swtpm
/// (review tpm2.rs F1; docs/DEVELOPMENT.md, "Hardware rules").
fn no_attestation_off_swtpm(text: &str) {
    assert!(
        !text.contains("attestation = true") || on_swtpm(),
        "an attestation makes a persistent TPM object: only against the suite's swtpm"
    );
}

impl Suite {
    /// Returns the attestation that a realisation pins (§3.7: the attestation is stored per
    /// realisation, and never in the object's ids).
    fn locked_attestation(&self, spec: &str, token: &str) -> toml::Value {
        self.lock()["realisations"][spec][token]["attestation"].clone()
    }
}

fn labelled(s: &Session, label: &str) -> usize {
    s.find_objects(&[Attribute::Label(label.as_bytes().to_vec())]).unwrap().len()
}

/// Works like `unwrap_octets`, but also accepts tpm2-pkcs11's P-521 encoding `04 85 <133 bytes>`
/// (see cakeys-tpm2-pkcs11). The oracle stays independent of cakeys because it builds the SPKI
/// itself.
fn unwrap_tpm2(v: &[u8]) -> Vec<u8> {
    match v {
        [0x04, n, rest @ ..] if *n >= 0x80 && rest.len() == *n as usize => rest.to_vec(),
        _ => unwrap_octets(v),
    }
}

#[test]
fn tpm2_provider_refuses_what_the_module_cannot_do() {
    let Some(e) = env("refusals") else { return };
    ptool(&["addkey", "--algorithm=aes256", "--key-label=refusal-aes"]);
    e.config(
        r#"
[objects.aes-gen]
class = "CKO_SECRET_KEY"
keyType = "CKK_AES"
valueLen = 32

[specs.aes-gen]
object = "aes-gen"
attributes = { CKA_ENCRYPT = true }
tokens.tpm = { locator = { CKA_LABEL = "refusal-aes-gen" }, origin = "create" }

[objects.hmac-gen]
class = "CKO_SECRET_KEY"
keyType = "CKK_SHA256_HMAC"
valueLen = 32

[specs.hmac-gen]
object = "hmac-gen"
attributes = { CKA_SIGN = true }
tokens.tpm = { locator = { CKA_LABEL = "refusal-hmac-gen" }, origin = "create" }

[objects.ed]
class = "CKO_PRIVATE_KEY"
keyType = "CKK_EC_EDWARDS"
curve = "edwards25519"

[specs.ed]
object = "ed"
attributes = { CKA_SIGN = true }
tokens.tpm = { locator = { CKA_LABEL = "refusal-ed" }, origin = "create" }

[objects.aes]
class = "CKO_SECRET_KEY"
keyType = "CKK_AES"
valueLen = 32

[specs.aes-mac]
object = "aes"
attributes = { CKA_SIGN = true }
tokens.tpm = { locator = { CKA_LABEL = "refusal-aes" }, origin = "adopt" }

[objects.des3]
class = "CKO_SECRET_KEY"
keyType = "CKK_DES3"

[specs.des3]
object = "des3"
attributes = { CKA_ENCRYPT = true }
tokens.tpm = { locator = { CKA_LABEL = "refusal-des3" }, origin = "create" }
"#,
    );
    // A TPM has no Triple DES (TPM2 symmetric keys are AES), so neither the check value nor the
    // generation is possible. cakeys refuses the spec, based on the mechanisms that the module
    // lists, before anything is created.
    let o = e.km(&["create", "--spec", "des3", "--token", "tpm", "--no-update-lock"]);
    assert_eq!(code(&o), 15, "{}", stderr(&o));
    assert!(stderr(&o).contains("CKM_DES3_ECB"), "{}", stderr(&o));
    assert_eq!(labelled(&e.session(), "refusal-des3"), 0);
    // Secret-key generation is refused before it starts, with the provider's advice, and it
    // creates nothing.
    for (spec, label) in [("aes-gen", "refusal-aes-gen"), ("hmac-gen", "refusal-hmac-gen")] {
        let o = e.km(&["create", "--spec", spec, "--token", "tpm", "--no-update-lock"]);
        assert_eq!(code(&o), 15, "{spec}");
        assert!(stderr(&o).contains("tpm2_ptool addkey"), "{spec}");
        assert_eq!(labelled(&e.session(), label), 0, "{spec}");
    }
    assert_eq!(e.code(&["create", "--spec", "ed", "--token", "tpm", "--no-update-lock"]), 15);
    // The module has no CKM_AES_CMAC, so a sign-only AES spec has no commitment on this token.
    assert_eq!(e.code(&["lock", "--spec", "aes-mac", "--token", "tpm", "--dry-run"]), 15);
}

#[test]
#[expect(clippy::format_push_string, reason = "the fixture TOML bodies are appended as += format!(...)")]
fn tpm2_generated_keys_match_der_oracle() {
    let Some(e) = env("generated") else { return };
    let kinds = [
        ("tpm-p256", "keyType = \"CKK_EC\"\ncurve = \"secp256r1\""),
        ("tpm-p384", "keyType = \"CKK_EC\"\ncurve = \"secp384r1\""),
        ("tpm-p521", "keyType = \"CKK_EC\"\ncurve = \"secp521r1\""),
        ("tpm-rsa2048", "keyType = \"CKK_RSA\"\nmodulusBits = 2048"),
        ("tpm-rsa3072", "keyType = \"CKK_RSA\"\nmodulusBits = 3072"),
    ];
    let mut body = String::new();
    for (k, ty) in kinds {
        // tpm2-pkcs11 1.10.1 cannot sign with its P-521 keys: C_SignInit parses the malformed
        // CKA_EC_POINT that the module itself wrote, and fails with CKR_HOST_MEMORY. The patches in
        // upstream/tpm2-pkcs11 fix both problems.
        let binding = if k == "tpm-p521" { ", binding = \"token-asserted\"" } else { "" };
        body += &format!(
            "[objects.{k}]\nclass = \"CKO_PRIVATE_KEY\"\n{ty}\n\n\
             [specs.{k}-gen]\nobject = \"{k}\"\nattributes = {{ CKA_SIGN = true }}\n\
             tokens.tpm = {{ locator = {{ CKA_LABEL = \"{k}\" }}, origin = \"create\"{binding} }}\n\n\
             [specs.{k}-pub]\nobject = \"{k}\"\n\
             tokens.tpm-anon = {{ locator = {{ CKA_LABEL = \"{k}\" }}, origin = \"adopt\", publicOnly = true }}\n\n"
        );
    }
    e.config(&body);
    for (k, _) in kinds {
        let spec = format!("{k}-gen");
        let first = e.km(&["create", "--spec", &spec, "--token", "tpm", "--no-update-lock"]);
        assert_eq!(code(&first), 18, "{k}");
        assert_eq!(
            got_hash(&e.km(&["lock", "--spec", &spec, "--token", "tpm", "--dry-run"])),
            got_hash(&first),
            "{k}: no duplicate"
        );
        assert_eq!(e.code(&["lock", "--spec", &spec, "--token", "tpm"]), 22, "{k}");
        // Open a new session now, because tpm2-pkcs11 sessions do not see objects that were
        // created after the session was opened.
        assert_eq!(e.locked_id(k, "rfc7093m4"), sri(&oracle_spki_with(&e.session(), k, unwrap_tpm2)), "{k}");
        let binding = if k == "tpm-p521" { "token-asserted" } else { "pop-sign" };
        assert_eq!(e.lock()["realisations"][&spec]["tpm"]["binding"].as_str(), Some(binding), "{k}");
        let pubs = format!("{k}-pub");
        assert_eq!(e.code(&["lock", "--spec", &pubs, "--token", "tpm-anon"]), 22, "{k}");
    }
}

#[test]
fn tpm2_identity_failure_after_create_leaves_nothing() {
    let Some(e) = env("orphan") else { return };
    // The key is generated, and then the fault shim truncates its point when cakeys reads it.
    // cakeys gets no identity, so it removes what it made. The shim causes the failure with any
    // version of tpm2-pkcs11 (review tpm2.rs F4: the trigger was tpm2-pkcs11's own malformed
    // P-521 point).
    e.write_config(
        &(tpm2_tokens(&fault_shim(), &e.dir)
            + "[objects.p]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n\
               [specs.p]\nobject = \"p\"\nattributes = { CKA_SIGN = true }\n\
               tokens.tpm = { locator = { CKA_LABEL = \"orphan-p256\" }, origin = \"create\" }\n"),
    );
    let plan = e.dir.join("plan.toml");
    let rule = "fn = \"C_GetAttributeValue\"\nof_label = \"orphan-p256\"\nattribute = \"CKA_EC_POINT\"\ntruncate = 10";
    std::fs::write(&plan, format!("[[rule]]\n{rule}\n")).unwrap();
    let o = e.km_env(
        &["create", "--spec", "p", "--token", "tpm", "--no-update-lock"],
        &[("P11_FAULT_MODULE", std::path::Path::new(&e.module)), ("P11_FAULT_PLAN", &plan)],
    );
    assert_eq!(code(&o), 13, "{}", stderr(&o));
    assert!(stderr(&o).contains("is not a P256 point"), "{}", stderr(&o));
    assert!(stderr(&o).contains("removed 2 object(s) just created"), "{}", stderr(&o));
    assert_eq!(labelled(&e.session(), "orphan-p256"), 0, "what the failed create made is still there");
}

/// tpm2-pkcs11's `C_DestroyObject` leaves private keys behind (the swtpm profile measured this:
/// `delete.CKO_PRIVATE_KEY = no`). `delete` refuses before it calls `C_DestroyObject`
/// (`delete-refused`, 15) and names the profile row, and the key and the lock stay. It once
/// reported the key as deleted (review 2026-11-24 B-13). A dry run gives the same result.
#[test]
fn tpm2_delete_is_refused_where_the_module_keeps_keys() {
    let Some(e) = env("delete-refused") else { return };
    e.config(
        "[objects.p]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n\
         [specs.p]\nobject = \"p\"\nattributes = { CKA_SIGN = true }\n\
         tokens.tpm = { locator = { CKA_LABEL = \"kept-p256\" }, origin = \"create\" }\n",
    );
    assert_eq!(e.code(&["create", "--spec", "p", "--token", "tpm"]), 22);
    let before = std::fs::read(e.dir.join("keys.lock")).unwrap();
    for dry in [true, false] {
        let args = if dry {
            vec!["delete", "--spec", "p", "--token", "tpm", "--dry-run"]
        } else {
            vec!["delete", "--spec", "p", "--token", "tpm"]
        };
        let o = e.km(&args);
        assert_eq!(code(&o), 15, "{}", stderr(&o));
        assert!(stderr(&o).contains("delete.CKO_PRIVATE_KEY"), "{}", stderr(&o));
    }
    assert_eq!(std::fs::read(e.dir.join("keys.lock")).unwrap(), before, "the lock is kept");
    assert!(labelled(&e.session(), "kept-p256") > 0, "the key is there");
}

/// `pop-ecdh` on tpm2-pkcs11. The module derives, but cannot compute a MAC with a sealed derived
/// secret (its `C_SignInit` requires a `CKA_ALLOWED_MECHANISMS` that the derived object lacks), so
/// the committed profile says `derive.sealed = false`, and the proof compares an extractable
/// derived secret instead. Before the probe recorded that, every ECDH proof on this token failed.
#[test]
fn tpm2_proves_possession_by_deriving() {
    let Some(e) = env("ecdh") else { return };
    e.config(
        "[objects.p]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n\
         [specs.p]\nobject = \"p\"\nattributes = { CKA_DERIVE = true }\n\
         tokens.tpm = { locator = { CKA_LABEL = \"ecdh-p256\" }, origin = \"create\", binding = \"pop-ecdh\" }\n",
    );
    let o = e.km(&["create", "--spec", "p", "--token", "tpm"]);
    assert_eq!(code(&o), 22, "{}", stderr(&o));
    assert_eq!(e.lock()["realisations"]["p"]["tpm"]["binding"].as_str(), Some("pop-ecdh"));
    let o = e.km(&["check", "--spec", "p", "--token", "tpm"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
}

/// The rfc7093m4 IDs of the import fixtures (test-only keys), computed with openssl.
const IMPORT_P256: &str = "sha256-0ymh9vfz8P3lnbdlAXskvxwoDAfUJNEIbsv0KEupcSg=";
const IMPORT_RSA2048: &str = "sha256-kRE6YzH4EXmqqAKhbLhb0z6/57mcGvHKrm4F4omLIn4=";
const HMAC_VALUE: &[u8; 32] = b"key-management hmac test vector!";
const HMAC384_VALUE: &[u8; 48] = b"key-management hmac-sha384 test vector, 48 bytes";

#[test]
fn tpm2_imported_keys_match_openssl_and_host_hmac() {
    let Some(e) = env("imported") else { return };
    if !hmac_types_fixed("CAKEYS_TPM_REQUIRE") {
        return;
    }
    ptool(&["import", "--algorithm=ecc", &format!("--privkey={FIXTURES}/tpm-import-p256.pem"), "--key-label=imp-p256"]);
    ptool(&[
        "import",
        "--algorithm=rsa",
        &format!("--privkey={FIXTURES}/tpm-import-rsa2048.pem"),
        "--key-label=imp-rsa",
    ]);
    let hmac_file = e.dir.join("hmac.bin");
    std::fs::write(&hmac_file, HMAC_VALUE).unwrap();
    ptool(&[
        "import",
        "--algorithm=hmac:sha256",
        &format!("--privkey={}", hmac_file.display()),
        "--key-label=imp-hmac",
    ]);
    let hmac384_file = e.dir.join("hmac384.bin");
    std::fs::write(&hmac384_file, HMAC384_VALUE).unwrap();
    ptool(&[
        "import",
        "--algorithm=hmac:sha384",
        &format!("--privkey={}", hmac384_file.display()),
        "--key-label=imp-hmac384",
    ]);
    e.config(
        r#"
[objects.p256]
class = "CKO_PRIVATE_KEY"
keyType = "CKK_EC"
curve = "secp256r1"

[specs.p256]
object = "p256"
attributes = { CKA_SIGN = true }
tokens.tpm = { locator = { CKA_LABEL = "imp-p256" }, origin = "adopt" }

[objects.rsa]
class = "CKO_PRIVATE_KEY"
keyType = "CKK_RSA"
modulusBits = 2048

[specs.rsa]
object = "rsa"
tokens.tpm-anon = { locator = { CKA_LABEL = "imp-rsa" }, origin = "adopt", publicOnly = true }

[objects.hmac]
class = "CKO_SECRET_KEY"
keyType = "CKK_SHA256_HMAC"
valueLen = 32

# tpm2_ptool marks imported keys CKA_EXTRACTABLE = true; commitment (CKA_SIGN) is preferred.
[specs.hmac]
object = "hmac"
attributes = { CKA_SIGN = true, CKA_EXTRACTABLE = true }
tokens.tpm = { locator = { CKA_LABEL = "imp-hmac" }, origin = "adopt" }

[objects.hmac384]
class = "CKO_SECRET_KEY"
keyType = "CKK_SHA384_HMAC"
valueLen = 48

[specs.hmac384]
object = "hmac384"
attributes = { CKA_SIGN = true }
tokens.tpm = { locator = { CKA_LABEL = "imp-hmac384" }, origin = "adopt" }
"#,
    );
    for (spec, token) in [("p256", "tpm"), ("rsa", "tpm-anon"), ("hmac", "tpm"), ("hmac384", "tpm")] {
        assert_eq!(e.code(&["lock", "--spec", spec, "--token", token]), 22, "{spec}");
    }
    assert_eq!(e.locked_id("p256", "rfc7093m4"), IMPORT_P256);
    assert_eq!(e.locked_id("rsa", "rfc7093m4"), IMPORT_RSA2048);
    let mut mac = <Hmac<sha2::Sha256> as KeyInit>::new_from_slice(HMAC_VALUE).unwrap();
    mac.update(b"key-management/v1/commitment/CKK_SHA256_HMAC/256");
    assert_eq!(e.locked_id("hmac", "commitment"), sri(&mac.finalize().into_bytes()));
    // An HMAC-SHA384 key's commitment uses HMAC-SHA384, because the TPM binds the key to its hash.
    let mut mac = <Hmac<sha2::Sha384> as KeyInit>::new_from_slice(HMAC384_VALUE).unwrap();
    mac.update(b"key-management/v1/commitment/CKK_SHA384_HMAC/384");
    assert_eq!(e.locked_id("hmac384", "commitment"), sri(&mac.finalize().into_bytes()));
}

#[test]
fn tpm2_aes_key_is_identified_by_its_kcv() {
    let Some(e) = env("aes") else { return };
    // tpm2-pkcs11 cannot import AES keys, so the oracle here is a consistency check: the test
    // encrypts the same block through a separate session. The independent AES oracle runs on
    // SoftHSM.
    ptool(&["addkey", "--algorithm=aes256", "--key-label=kcv-aes"]);
    e.config(
        "[objects.aes]\nclass = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_AES\"\nvalueLen = 32\n\n\
         [specs.aes]\nobject = \"aes\"\nattributes = { CKA_ENCRYPT = true, CKA_SENSITIVE = true }\n\
         tokens.tpm = { locator = { CKA_LABEL = \"kcv-aes\" }, origin = \"adopt\" }\n",
    );
    let r = ["lock", "--spec", "aes", "--token", "tpm", "--dry-run"];
    let first = e.km(&r);
    assert_eq!(code(&first), 18);
    assert_eq!(got_hash(&e.km(&r)), got_hash(&first));
    assert_eq!(e.code(&recording(&r)), 22);
    assert_eq!(e.code(&["check", "aes.id.kcv-ecb"]), 0);

    let s = e.session();
    let h =
        s.find_objects(&[Attribute::Class(ObjectClass::SECRET_KEY), Attribute::Label(b"kcv-aes".to_vec())]).unwrap()[0];
    let block = &<sha2::Sha256 as sha2::Digest>::digest(b"key-management/v1/kcv-ecb/CKK_AES/256")[..16];
    let kcv = s.encrypt(&Mechanism::AesEcb, h, block).unwrap();
    assert_eq!(e.locked_id("aes", "kcv-ecb"), sri(&kcv));
}

/// tpm2-pkcs11 holds a data object only as a private object (it seals `CKA_VALUE`, and
/// `CKA_PRIVATE = false` gives `CKR_ATTRIBUTE_VALUE_INVALID` \[src\]). So a data object on it can be
/// identified only through a spec that declares `CKA_PRIVATE = true`. The ID is `valuehash`, the
/// SHA-256 of the value, which cakeys reads after the login.
#[test]
fn tpm2_private_data_object_is_identified_by_its_value() {
    let Some(e) = env("private-data") else { return };
    let value = b"9d02c7e5a1f4b8367e0c2a95d1b4f863 a sealed application secret".to_vec();
    e.session()
        .create_object(&[
            Attribute::Class(ObjectClass::DATA),
            Attribute::Token(true),
            Attribute::Private(true),
            Attribute::Label(b"tpm-data".to_vec()),
            Attribute::Value(value.clone()),
        ])
        .unwrap();
    e.config(
        "[objects.blob]\nclass = \"CKO_DATA\"\n\n\
         [specs.blob]\nobject = \"blob\"\nattributes = { CKA_PRIVATE = true }\n\
         tokens.tpm = { locator = { CKA_LABEL = \"tpm-data\" }, origin = \"adopt\" }\n\n\
         [specs.blob-undeclared]\nobject = \"blob\"\n\
         tokens.tpm = { locator = { CKA_LABEL = \"tpm-data\" }, origin = \"adopt\" }\n",
    );
    // When the spec does not declare `CKA_PRIVATE = true`, the hash would let anyone test guesses
    // of the value offline, which nobody agreed to, so cakeys refuses the spec (15).
    let o = e.km(&["lock", "--spec", "blob-undeclared", "--token", "tpm"]);
    assert_eq!(code(&o), 15, "{}", stderr(&o));
    assert!(stderr(&o).contains("declare CKA_PRIVATE = true"), "{}", stderr(&o));
    let o = e.km(&["lock", "--spec", "blob", "--token", "tpm"]);
    assert_eq!(code(&o), 22, "{}", stderr(&o));
    assert_eq!(e.locked_id("blob", "valuehash"), sri(&value));
    assert_eq!(e.code(&["check", "blob", "--spec", "blob"]), 0);
}

/// The `tpm-certify` commitment (§3.7 of docs/DESIGN.md): a native `TPM2_Certify` over the
/// object's Name, which the host verifies against a provisioned AK and compares with the material
/// that `rfc7093m4` names. The test provisions persistent objects (the AK, and a key at another AK
/// handle), so it runs only on the suite's swtpm (review tpm2.rs F1).
#[test]
fn tpm2_keys_attest_their_tpm_residence() {
    let Some(e) = env("attest") else { return };
    if !swtpm_or_skip("attest", "it makes persistent TPM objects, on the suite's swtpm only") {
        return;
    }
    // A generated EC key (in the style of the 9a slot) is attested on the TPM after the AK is
    // provisioned.
    e.config(
        "[objects.p256]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n\
         [specs.p256]\nobject = \"p256\"\nattributes = { CKA_SIGN = true }\n\
         tokens.tpm = { locator = { CKA_LABEL = \"attest-p256\" }, origin = \"create\", attestation = true }\n",
    );
    let r = ["lock", "--spec", "p256", "--token", "tpm", "--dry-run"];
    let first = e.km(&["create", "--spec", "p256", "--token", "tpm", "--no-update-lock"]);
    assert_eq!(code(&first), 18, "first use: got the ID, the lock is written by review");
    let got: serde_json::Value =
        serde_json::from_str(&stdout(&e.km(&["resolve", "--spec", "p256", "--token", "tpm"]))).unwrap();
    let ids = got["ids"].as_object().unwrap();
    assert_eq!(ids.len(), 1, "only the portable rfc7093m4 is an object ID: {ids:?}");
    assert!(got["attestation"]["id"].as_str().unwrap().starts_with("sha256-"));
    assert_eq!(e.code(&recording(&r)), 22);
    // In the lock, the attestation is stored on the realisation (per device), and the portable ID
    // is stored on the object. The realisation pins the AK (`root`) next to its attestation ID.
    assert!(e.lock()["objects"]["p256"]["ids"].get("tpm-certify").is_none());
    let real = &e.lock()["realisations"]["p256"]["tpm"];
    assert_eq!(real["schemes"].as_array().unwrap().len(), 1);
    let att = e.locked_attestation("p256", "tpm");
    assert_eq!(att["kind"].as_str(), Some("tpm-certify"));
    assert!(att["root"].as_str().unwrap().starts_with("sha256-"));
    assert_ne!(att["id"].as_str(), Some(e.locked_id("p256", "rfc7093m4").as_str()));
    // A verification runs a new certify, with a new nonce and the same stable Name.
    assert_eq!(e.code(&["check", "--spec", "p256", "--token", "tpm"]), 0);
    assert_eq!(e.code(&["check", "p256.id.tpm-certify", "--token", "tpm"]), 0);
    // The AK is persistent at the default handle, so a second run reuses it, and the root does not
    // change.
    let again = e.km(&["resolve", "--spec", "p256", "--token", "tpm"]);
    let got: serde_json::Value = serde_json::from_str(&stdout(&again)).unwrap();
    assert_eq!(got["attestation"]["root"].as_str(), att["root"].as_str());

    // After the attestation is locked, a run that cannot attest is a scheme downgrade (14). Here,
    // no AK is at the configured handle. Reads never provision an AK, so the second verification
    // fails in the same way.
    let base = std::fs::read_to_string(e.dir.join("keys.toml")).unwrap();
    let alt = |handle: &str| {
        base.replacen(
            "tokenLabel = \"kmtest\"\n",
            &format!("tokenLabel = \"kmtest\"\noptions = {{ akHandle = \"{handle}\" }}\n"),
            1,
        )
    };
    std::fs::write(e.dir.join("keys.toml"), alt("0x81000017")).unwrap();
    for _ in 0..2 {
        let o = e.km(&["check", "--spec", "p256", "--token", "tpm"]);
        assert_eq!(code(&o), 14, "{}", stderr(&o));
        assert!(stderr(&o).contains("no Attestation Key at 0x81000017"));
    }
    // A `check` of the attestation ID is a read, like a verification (DESIGN §3.7). It fails in
    // the same way and leaves the TPM's persistent handles as they were, so the AK is still
    // missing.
    let before = persistent_handles();
    for _ in 0..2 {
        let o = e.km(&["check", "p256.id.tpm-certify", "--token", "tpm"]);
        assert_eq!(code(&o), 14, "{}", stderr(&o));
        assert!(stderr(&o).contains("no Attestation Key at 0x81000017"));
    }
    assert_eq!(persistent_handles(), before);
    assert!(!before.contains("0x81000017"), "{before}");
    // A key at the AK handle that is not a restricted signing key is never trusted as the AK (13),
    // because an unrestricted key could sign a forged attestation.
    let ctx = e.dir.join("storage.ctx");
    let ctx = ctx.to_str().unwrap();
    tpm2_tool("createprimary", &["-C", "o", "-G", "ecc", "-c", ctx]);
    tpm2_tool("evictcontrol", &["-C", "o", "-c", ctx, "0x81000018"]);
    std::fs::write(e.dir.join("keys.toml"), alt("0x81000018")).unwrap();
    let o = e.km(&r);
    assert_eq!(code(&o), 13, "{}", stderr(&o));
    assert!(stderr(&o).contains("is not a cakeys Attestation Key"));
    std::fs::write(e.dir.join("keys.toml"), &base).unwrap();

    // HMAC keys are attested too (TPM2_Certify covers any loaded object), together with the
    // `commitment` ID.
    if hmac_types_fixed("CAKEYS_TPM_REQUIRE") {
        let hmac_file = e.dir.join("hmac.bin");
        std::fs::write(&hmac_file, HMAC_VALUE).unwrap();
        ptool(&[
            "import",
            "--algorithm=hmac:sha256",
            &format!("--privkey={}", hmac_file.display()),
            "--key-label=attest-hmac",
        ]);
        e.config(
            "[objects.hmac]\nclass = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_SHA256_HMAC\"\nvalueLen = 32\n\n\
             [specs.hmac]\nobject = \"hmac\"\nattributes = { CKA_SIGN = true, CKA_EXTRACTABLE = true }\n\
             tokens.tpm = { locator = { CKA_LABEL = \"attest-hmac\" }, origin = \"adopt\", attestation = true }\n",
        );
        assert_eq!(e.code(&["lock", "--spec", "hmac", "--token", "tpm"]), 22);
        assert!(e.lock()["objects"]["hmac"]["ids"].get("commitment").is_some());
        assert!(e.locked_attestation("hmac", "tpm")["id"].as_str().is_some());
        // A certified secret key that the TPM holds gets a fresh proof (`assurance = proof`), and
        // not only a commitment, which is a fingerprint that can be replayed.
        let got: serde_json::Value =
            serde_json::from_str(&stdout(&e.km(&["resolve", "--spec", "hmac", "--token", "tpm"]))).unwrap();
        assert_eq!(got["assurance"].as_str(), Some("proof"), "{got}");
    }
}

/// EK→AK activation (review D5). With `ekCertificate`, every attestation proves that the AK is in
/// the TPM that the certificate names: the host makes a credential for the EK, bound to the AK's
/// Name, which only that TPM can activate. The lock then pins the CA that the certificate verifies
/// to, here a test CA that `ekRoots` names, instead of the AK. cakeys refuses a CA that nothing
/// names (13), a certificate for a key other than the TPM's EK (13), and a change of anchor in
/// either direction (14): a lock made on first use, until its attestation is removed, and a locked
/// activation that is later lost. The RSA EK and the P-256 EK both activate.
#[test]
fn tpm2_attestation_activates_a_credential_to_the_certified_ek() {
    let Some(e) = env("activate") else { return };
    if !swtpm_or_skip("activate", "it makes persistent TPM objects, on the suite's swtpm only") {
        return;
    }
    let path = |name: &str| e.dir.join(name).to_str().unwrap().to_owned();
    test_ek_certificates(&e.dir);

    ptool(&["addkey", "--algorithm=ecc256", "--key-label=activate-a"]);
    let pin = format!("pinFile = \"{}\"", e.dir.join("pin").display());
    let config = |options: &str| {
        e.write_config(&format!(
            "[tokens.tpm]\nmodule = \"{}\"\ntokenLabel = \"kmtest\"\n{pin}\n{options}\n\n\
             [objects.a]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n\
             [specs.a]\nobject = \"a\"\nattributes = {{ CKA_SIGN = true }}\n\
             tokens.tpm = {{ locator = {{ CKA_LABEL = \"activate-a\" }}, origin = \"adopt\", attestation = true, binding = \"token-asserted\" }}\n",
            e.module,
        ));
    };
    let ek = |cert: &str, roots: &str| {
        config(&format!("options = {{ ekCertificate = \"{}\", ekRoots = \"{}\" }}", path(cert), path(roots)));
    };
    let refused = |o: &std::process::Output, want: i32, why: &str| {
        assert_eq!(code(o), want, "{why}: {}", stderr(o));
        assert!(stderr(o).contains(why), "expected {why:?} in {}", stderr(o));
    };
    let lock = ["lock", "--spec", "a", "--token", "tpm"];
    let verify = ["check", "--spec", "a", "--token", "tpm"];

    // On first use, as before the EK certificate, the AK's own key is the anchor.
    config("");
    assert_eq!(e.code(&lock), 22);
    let first_use = e.locked_attestation("a", "tpm")["root"].clone();
    ek("ek-ecc.pem", "other-ca.pem");
    refused(&e.km(&lock), 13, "signed by no pinned root");
    // Anchoring that attestation at the manufacturer changes its anchor, which even `lock`
    // refuses (14). When the locked attestation is removed, by a reviewed edit of keys.lock, `lock`
    // records the new one (docs/DESIGN.md §3.7).
    ek("ek-ecc.pem", "ca.pem");
    refused(&e.km(&lock), 14, "attestation anchor");
    let mut edited = e.lock();
    edited["realisations"]["a"]["tpm"].as_table_mut().unwrap().remove("attestation").unwrap();
    e.write_lock(&edited);
    assert_eq!(e.code(&lock), 22);
    // The lock pins the test CA's key, which is the anchor that the EK certificate verified to.
    let ca_spki =
        Command::new("openssl").args(["pkey", "-in", &path("ca.key"), "-pubout", "-outform", "DER"]).output().unwrap();
    let att = e.locked_attestation("a", "tpm");
    assert_eq!(att["root"].as_str(), Some(cakeys_core::id::sri(&ca_spki.stdout).as_str()), "{att}");
    assert_ne!(att["root"], first_use);
    let handles = persistent_handles();
    assert_eq!(e.code(&verify), 0);
    assert_eq!(e.code(&["check", "a.id.tpm-certify", "--token", "tpm"]), 0);
    // The RSA EK, which the same CA certified, also activates, with the same anchor.
    ek("ek-rsa.pem", "ca.pem");
    assert_eq!(e.code(&verify), 0);
    // A certificate that the CA issued for a key that is not this TPM's EK is refused (13).
    ek("ek-stranger.pem", "ca.pem");
    refused(&e.km(&verify), 13, "the EK certificate names another key than this TPM's endorsement key");
    // Without an EK certificate (the swtpm keeps none in NV), the anchor is the AK on first use,
    // which differs from the locked anchor (14).
    config("");
    refused(&e.km(&verify), 14, "anchor");
    // Activation leaves no persistent object behind, because the EK is created again and flushed
    // every time.
    assert_eq!(persistent_handles(), handles);
}

/// Checks the session salted to the EK (the transport of review D5) on the wire. swtpm's log
/// (level 20, nix/tpm2-test-env.sh) holds every command and response. With the EK certificate,
/// neither the seal auth derived from the PIN (an HMAC session never sends it) nor the unsealed
/// wrapping key (64 ASCII hex characters, encrypted in the response) crosses the transport.
/// Without the certificate, cakeys uses password sessions as before, and both values cross; this
/// control run shows that the capture can see them. The lockout counter stays 0, so no
/// authorization of the salted session failed.
#[test]
fn tpm2_the_salted_session_keeps_the_token_secrets_off_the_wire() {
    let Some(e) = env("salted") else { return };
    if !swtpm_or_skip("salted", "it reads the suite's swtpm log, and makes the AK") {
        return;
    }
    test_ek_certificates(&e.dir);
    ptool(&["addkey", "--algorithm=ecc256", "--key-label=salted-a"]);
    let store = std::path::PathBuf::from(tpm2_store());
    let log = store.parent().unwrap().join("swtpm.log");
    let salt: Vec<u8> = rusqlite::Connection::open(store.join("tpm2_pkcs11.sqlite3"))
        .unwrap()
        .query_row("SELECT userauthsalt FROM sealobjects", [], |r| r.get(0))
        .unwrap();
    // tpm2-pkcs11's seal auth is the hex text of the first 16 bytes of SHA-256(PIN ‖ salt).
    let seal_auth = {
        use sha2::Digest as _;
        let digest = sha2::Sha256::digest([b"1234".as_slice(), &salt].concat());
        cakeys_core::hex::encode(&digest[..16]).into_bytes()
    };
    let path = |name: &str| e.dir.join(name).to_str().unwrap().to_owned();
    let config = |options: &str| {
        e.write_config(&format!(
            "[tokens.tpm]\nmodule = \"{}\"\ntokenLabel = \"kmtest\"\npinFile = \"{}\"\n{options}\n\n\
             [objects.a]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n\
             [specs.a]\nobject = \"a\"\nattributes = {{ CKA_SIGN = true }}\n\
             tokens.tpm = {{ locator = {{ CKA_LABEL = \"salted-a\" }}, origin = \"adopt\", attestation = true, binding = \"token-asserted\" }}\n",
            e.module,
            e.dir.join("pin").display(),
        ));
    };
    // Returns the bytes that crossed the transport during `run`, taken from every hex dump line
    // that swtpm logged.
    let wire = |run: &dyn Fn()| {
        let before = std::fs::metadata(&log).unwrap().len();
        run();
        let text = std::fs::read(&log).unwrap();
        let text = String::from_utf8_lossy(&text[usize::try_from(before).unwrap()..]).into_owned();
        let mut bytes = Vec::new();
        for line in text.lines() {
            let pairs: Vec<&str> = line.split_whitespace().collect();
            if !pairs.is_empty() && pairs.iter().all(|p| p.len() == 2 && p.bytes().all(|b| b.is_ascii_hexdigit())) {
                bytes.extend(pairs.iter().map(|p| u8::from_str_radix(p, 16).unwrap()));
            }
        }
        assert!(!bytes.is_empty(), "swtpm logged no traffic: is its log level 20?");
        bytes
    };
    let resolve = || {
        let o = e.km(&["resolve", "--spec", "a", "--token", "tpm"]);
        assert_eq!(code(&o), 0, "{}", stderr(&o));
    };
    let has = |bytes: &[u8], needle: &[u8]| bytes.windows(needle.len()).any(|w| w == needle);
    // Looks for a sequence of 64 ASCII hex digits, which is the form in which tpm2-pkcs11 seals
    // the wrapping key.
    let has_key_text = |bytes: &[u8]| bytes.windows(64).any(|w| w.iter().all(u8::is_ascii_hexdigit));

    config(&format!("options = {{ ekCertificate = \"{}\", ekRoots = \"{}\" }}", path("ek-ecc.pem"), path("ca.pem")));
    assert_eq!(e.code(&["lock", "--spec", "a", "--token", "tpm"]), 22);
    let salted = wire(&resolve);
    assert!(!has(&salted, &seal_auth), "the seal auth crossed the transport in the clear");
    assert!(!has_key_text(&salted), "the wrapping key crossed the transport in the clear");
    assert!(salted_session_started(&salted), "no TPM2_StartAuthSession salted to a loaded key");

    config("");
    let plain = wire(&resolve);
    assert!(has(&plain, &seal_auth), "the control: a password session sends the seal auth");
    assert!(has_key_text(&plain), "the control: an unencrypted unseal returns the wrapping key's text");

    let props = Command::new("tpm2_getcap").arg("properties-variable").output().unwrap();
    assert!(stdout(&props).contains("TPM2_PT_LOCKOUT_COUNTER: 0x0"), "{}", stdout(&props));
}

/// Returns whether `wire` holds a `TPM2_StartAuthSession` command salted to a loaded key: its
/// `tpmKey` is a transient object (0x80......, the EK) instead of `TPM_RH_NULL`, and its
/// `encryptedSalt` is not empty. An unsalted HMAC session would also keep the auth values off the
/// wire, but anyone who sees the nonces on the transport can compute its session key.
fn salted_session_started(wire: &[u8]) -> bool {
    let be16 = |b: &[u8]| usize::from(u16::from_be_bytes([b[0], b[1]]));
    (0..wire.len().saturating_sub(22)).any(|i| {
        let w = &wire[i..];
        // TPM_ST_NO_SESSIONS, a size, TPM_CC_StartAuthSession, and a `tpmKey` that starts with
        // 0x80 (a transient object).
        if w[..2] != [0x80, 0x01] || w[6..10] != [0x00, 0x00, 0x01, 0x76] || w[10] != 0x80 {
            return false;
        }
        // tpmKey (4), bind (4), nonceCaller (TPM2B), then encryptedSalt (TPM2B).
        let nonce = be16(&w[18..]);
        w.get(20 + nonce..22 + nonce).is_some_and(|s| be16(s) > 0)
    })
}

/// Writes into `dir`, for [`tpm2_attestation_activates_a_credential_to_the_certified_ek`], two
/// test CAs (`ca.pem`, and `other-ca.pem`, which nothing trusts), and certificates from `ca` for
/// the swtpm's default P-256 and RSA EKs (`ek-ecc.pem`, `ek-rsa.pem`) and for a key that is not
/// an EK of this TPM (`ek-stranger.pem`).
fn test_ek_certificates(dir: &std::path::Path) {
    let path = |name: &str| dir.join(name).to_str().unwrap().to_owned();
    let openssl = |args: &[&str]| {
        let out = Command::new("openssl").args(args).output().unwrap();
        assert!(out.status.success(), "openssl {args:?}: {}", stderr(&out));
    };
    std::fs::write(
        dir.join("ca.cnf"),
        "[req]\ndistinguished_name = dn\nx509_extensions = ca\nprompt = no\n[dn]\nCN = cakeys test\n\
         [ca]\nbasicConstraints = critical, CA:TRUE\nkeyUsage = critical, keyCertSign\n\
         subjectKeyIdentifier = hash\n\
         [ek]\nbasicConstraints = CA:FALSE\nkeyUsage = critical, keyEncipherment\n",
    )
    .unwrap();
    // The CA that `ekRoots` names, and a CA that nothing names.
    for ca in ["ca", "other-ca"] {
        openssl(&[
            "req",
            "-x509",
            "-config",
            &path("ca.cnf"),
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-nodes",
            "-keyout",
            &path(&format!("{ca}.key")),
            "-out",
            &path(&format!("{ca}.pem")),
            "-subj",
            &format!("/CN=cakeys test {ca}"),
            "-days",
            "2",
        ]);
    }
    // Issues an EK certificate from `ca` for the public key in `public` (PEM).
    let issue = |public: &str, out: &str| {
        openssl(&[
            "x509",
            "-new",
            "-subj",
            "/CN=cakeys test EK",
            "-force_pubkey",
            &path(public),
            "-CA",
            &path("ca.pem"),
            "-CAkey",
            &path("ca.key"),
            "-days",
            "2",
            "-extfile",
            &path("ca.cnf"),
            "-extensions",
            "ek",
            "-out",
            &path(out),
        ]);
    };
    for alg in ["ecc", "rsa"] {
        tpm2_tool(
            "createek",
            &["-G", alg, "-c", &path(&format!("ek-{alg}.ctx")), "-u", &path(&format!("ek-{alg}.pub.pem")), "-f", "pem"],
        );
        issue(&format!("ek-{alg}.pub.pem"), &format!("ek-{alg}.pem"));
    }
    openssl(&["genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", &path("stranger.key")]);
    openssl(&["pkey", "-in", &path("stranger.key"), "-pubout", "-out", &path("stranger.pub.pem")]);
    issue("stranger.pub.pem", "ek-stranger.pem");
}

/// The same material attested on two TPM tokens (§3.7). Each attestation belongs to one device:
/// the imported HMAC's Name differs for each import (because of a fresh seedValue), and the
/// qualified Name differs for each hierarchy. So each realisation pins its own attestation, and
/// the object links them through its one portable `commitment`. If the attestations were recorded
/// on the object, the second one would be a mismatch.
#[test]
fn tpm2_each_token_pins_its_own_attestation() {
    let Some(e) = env("attest-two") else { return };
    if !hmac_types_fixed("CAKEYS_TPM_REQUIRE") {
        return;
    }
    let store = tpm2_store();
    ptool_in(&store, &["addtoken", "--pid=1", "--label=kmtest2", "--sopin=5678", "--userpin=1234"]);
    let hmac_file = e.dir.join("hmac.bin");
    std::fs::write(&hmac_file, HMAC_VALUE).unwrap();
    for label in ["kmtest", "kmtest2"] {
        ptool_in(
            &store,
            &[
                "import",
                "--algorithm=hmac:sha256",
                &format!("--privkey={}", hmac_file.display()),
                "--key-label=two-hmac",
                &format!("--label={label}"),
                "--userpin=1234",
            ],
        );
    }
    let pin = e.dir.join("pin").display().to_string();
    e.config(&format!(
        "[tokens.tpm2]\nmodule = \"{}\"\ntokenLabel = \"kmtest2\"\npinFile = \"{pin}\"\n\n\
         [objects.hmac]\nclass = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_SHA256_HMAC\"\nvalueLen = 32\n\n\
         [specs.hmac]\nobject = \"hmac\"\nattributes = {{ CKA_SIGN = true, CKA_EXTRACTABLE = true }}\n\
         tokens.tpm = {{ locator = {{ CKA_LABEL = \"two-hmac\" }}, origin = \"adopt\", attestation = true }}\n\
         tokens.tpm2 = {{ locator = {{ CKA_LABEL = \"two-hmac\" }}, origin = \"adopt\", attestation = true }}\n",
        e.module
    ));
    assert_eq!(e.code(&["lock", "--spec", "hmac", "--token", "tpm"]), 22);
    assert_eq!(e.code(&["lock", "--spec", "hmac", "--token", "tpm2"]), 22);
    let lock = e.lock();
    let ids = lock["objects"]["hmac"]["ids"].as_table().unwrap();
    assert_eq!(ids.keys().collect::<Vec<_>>(), ["commitment"], "{ids:?}");
    let (one, two) = (e.locked_attestation("hmac", "tpm"), e.locked_attestation("hmac", "tpm2"));
    assert_ne!(one["id"].as_str(), two["id"].as_str(), "two imports, two TPM objects, two attestations");
    assert_eq!(one["root"].as_str(), two["root"].as_str(), "one TPM, one AK");
    for t in ["tpm", "tpm2"] {
        assert_eq!(e.code(&["check", "--spec", "hmac", "--token", t]), 0);
    }
}

/// The user's portability requirement (§3.7): an attestation is provenance for one device. A copy
/// of the same material on a token that attests nothing (here `SoftHSM`) verifies through the
/// portable commitment alone, and the TPM realisation's attestation stays on that realisation.
#[test]
fn tpm2_attested_material_travels_to_a_second_hsm() {
    let Some(e) = env("attest-travel") else { return };
    if !hmac_types_fixed("CAKEYS_TPM_REQUIRE") {
        return;
    }
    // The test needs SoftHSM next to the TPM, and SoftHSM is required when the TPM is required
    // (the harness's preCheck sets both).
    let Some(soft) = suite_var("CAKEYS_TEST_MODULE", "CAKEYS_TPM_REQUIRE", "attest-travel") else { return };
    let pin = e.dir.join("pin").display().to_string();
    // The same HMAC material is on the TPM (imported and attested) and on SoftHSM (planted, and
    // not attestable, because SoftHSM attests nothing).
    let hmac_file = e.dir.join("hmac.bin");
    std::fs::write(&hmac_file, HMAC_VALUE).unwrap();
    ptool(&[
        "import",
        "--algorithm=hmac:sha256",
        &format!("--privkey={}", hmac_file.display()),
        "--key-label=travel-hmac",
    ]);
    e.config(&format!(
        "[tokens.soft]\nmodule = \"{soft}\"\ntokenLabel = \"kmtest\"\npinFile = \"{pin}\"\n\n\
         [objects.hmac]\nclass = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_SHA256_HMAC\"\nvalueLen = 32\n\n\
         [specs.hmac-tpm]\nobject = \"hmac\"\nattributes = {{ CKA_SIGN = true, CKA_EXTRACTABLE = true }}\n\
         tokens.tpm = {{ locator = {{ CKA_LABEL = \"travel-hmac\" }}, origin = \"adopt\", attestation = true }}\n\n\
         [specs.hmac-soft]\nobject = \"hmac\"\nattributes = {{ CKA_SIGN = true }}\n\
         tokens.soft = {{ locator = {{ CKA_LABEL = \"travel-hmac\" }}, origin = \"adopt\" }}\n\n\
         [specs.hmac-attest-soft]\nobject = \"hmac\"\nattributes = {{ CKA_SIGN = true }}\n\
         tokens.soft = {{ locator = {{ CKA_LABEL = \"travel-hmac\" }}, origin = \"adopt\", attestation = true }}\n",
    ));
    let soft_session = open_session(&soft, "kmtest", "1234");
    soft_session
        .create_object(&[
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(cryptoki::object::KeyType::SHA256_HMAC),
            Attribute::Token(true),
            Attribute::Label(b"travel-hmac".to_vec()),
            Attribute::Value(HMAC_VALUE.to_vec()),
            Attribute::Sign(true),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
        ])
        .unwrap();
    // The portable identity is locked first, from the token without attestation. The TPM
    // realisation then joins the same object through the shared commitment scheme, and pins its
    // attestation.
    assert_eq!(e.code(&["lock", "--spec", "hmac-soft", "--token", "soft"]), 22);
    assert_eq!(e.code(&["lock", "--spec", "hmac-tpm", "--token", "tpm"]), 22);
    let lock = e.lock();
    let ids = lock["objects"]["hmac"]["ids"].as_table().unwrap();
    assert_eq!(ids.keys().collect::<Vec<_>>(), ["commitment"], "the portable ID only: {ids:?}");
    let mut mac = <Hmac<sha2::Sha256> as KeyInit>::new_from_slice(HMAC_VALUE).unwrap();
    mac.update(b"key-management/v1/commitment/CKK_SHA256_HMAC/256");
    assert_eq!(e.locked_id("hmac", "commitment"), sri(&mac.finalize().into_bytes()));
    assert!(e.locked_attestation("hmac-tpm", "tpm")["id"].as_str().unwrap().starts_with("sha256-"));
    // The copy on the second HSM verifies through the commitment, and the TPM realisation verifies
    // through both the commitment and the attestation.
    assert_eq!(e.code(&["check", "--spec", "hmac-soft", "--token", "soft"]), 0);
    assert_eq!(e.code(&["check", "--spec", "hmac-tpm", "--token", "tpm"]), 0);
    // A request for attestation on a module that attests nothing is refused before any work (15).
    let o = e.km(&["lock", "--spec", "hmac-attest-soft", "--token", "soft", "--dry-run"]);
    assert_eq!(code(&o), 15);
    assert!(stderr(&o).contains("attests nothing"), "{}", stderr(&o));
}

/// `pop-unwrap` (a transport key's proof, docs/CAMIGRATE.md D3). tpm2-pkcs11 never unwraps (its
/// profile says `unwraps = false`, and `C_UnwrapKey` returns `CKR_FUNCTION_NOT_SUPPORTED` on the
/// real TPM, tests/ftpm.rs), so an unwrap-only key is refused as unsupported (15) before it is
/// generated.
#[test]
fn unwrap_only_keys_are_refused_before_generation() {
    let Some(e) = env("unwrap") else { return };
    e.config(
        "[objects.u]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_RSA\"\nmodulusBits = 2048\n\n\
         [specs.u]\nobject = \"u\"\nattributes = { CKA_UNWRAP = true, CKA_EXTRACTABLE = false }\n\
         tokens.tpm = { locator = { CKA_LABEL = \"refusal-unwrap\" }, origin = \"create\", binding = \"pop-unwrap\" }\n",
    );
    let o = e.km(&["lock", "--spec", "u", "--token", "tpm", "--dry-run"]);
    assert_eq!(code(&o), 15, "{}", stderr(&o));
    assert!(stderr(&o).contains("never unwraps") && !stderr(&o).contains("created"), "{}", stderr(&o));
}

/// Returns the value of attribute `ty` in the attrs of a tpm2-pkcs11 store row (YAML with explicit
/// tags, with one `? !!int "<type>"` / `: !!<tag> "<value>"` pair per attribute).
fn row_value(attrs: &str, ty: u64) -> String {
    let key = format!("? !!int \"{ty}\"\n");
    let at = attrs.find(&key).unwrap_or_else(|| panic!("no attribute {ty} in\n{attrs}")) + key.len();
    let value = &attrs[at..];
    let start = value.find('"').unwrap() + 1;
    value[start..start + value[start..].find('"').unwrap()].to_owned()
}

/// Rewrites the attrs of the private-key row whose `CKA_LABEL` is `label` in the test's store.
/// Another process (the module) reads the rewritten attrs.
fn edit_private_row(label: &str, edit: impl FnOnce(&str) -> String) {
    edit_private_row_in(&std::env::var("TPM2_PKCS11_STORE").unwrap(), label, edit);
}

/// Does what [`edit_private_row`] does, in the store in directory `store`.
fn edit_private_row_in(store: &str, label: &str, edit: impl FnOnce(&str) -> String) {
    let db = rusqlite::Connection::open(std::path::Path::new(store).join("tpm2_pkcs11.sqlite3")).unwrap();
    let hex = label.bytes().fold(String::new(), |hex, b| hex + &format!("{b:02x}"));
    let rows: Vec<(i64, String)> = db
        .prepare("SELECT id, CAST(attrs AS TEXT) FROM tobjects")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    let (id, attrs) = rows
        .into_iter()
        .find(|(_, a)| a.contains("\"2399141891\"") && a.contains(&format!("? !!int \"3\"\n  : !!str \"{hex}\"")))
        .unwrap_or_else(|| panic!("no private-key row labelled {label}"));
    db.execute("UPDATE tobjects SET attrs = ?1 WHERE id = ?2", rusqlite::params![edit(&attrs), id]).unwrap();
}

/// The native attestation compares the module's view of a key with what the TPM certifies. A
/// store row that claims `CKA_EXTRACTABLE` where the TPM certified a key that never leaves it, or
/// a store row that carries another key's TPM blobs under its own public key, is a conflict (13).
/// A token whose primary is transient (`tpm2_ptool init --transient-parent`) has no persistent
/// parent to load the key under, so its attestation is unavailable (16).
#[test]
fn tpm2_attestation_refuses_a_store_that_disagrees() {
    let Some(e) = env("attest-store") else { return };
    for label in ["store-a", "store-b"] {
        ptool(&["addkey", "--algorithm=ecc256", &format!("--key-label={label}")]);
    }
    // The proof of possession would detect the swap first, so the spec uses `token-asserted`, and
    // the test checks only the attestation.
    e.config(
        "[objects.a]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n\
         [specs.a]\nobject = \"a\"\nattributes = { CKA_SIGN = true }\n\
         tokens.tpm = { locator = { CKA_LABEL = \"store-a\" }, origin = \"adopt\", attestation = true, binding = \"token-asserted\" }\n",
    );
    let r = ["lock", "--spec", "a", "--token", "tpm", "--dry-run"];
    let o = e.km(&r);
    assert_eq!(code(&o), 18, "{}", stderr(&o));
    let refused = |why: &str| {
        let o = e.km(&r);
        assert_eq!(code(&o), 13, "{}", stderr(&o));
        assert!(stderr(&o).contains(why), "expected {why:?} in {}", stderr(&o));
    };

    // CKA_EXTRACTABLE (0x162) is true in the store, and the key in the TPM is fixedTPM.
    let mut original = String::new();
    edit_private_row("store-a", |attrs| {
        original = attrs.to_owned();
        attrs.replace("? !!int \"354\"\n  : !!bool \"false\"", "? !!int \"354\"\n  : !!bool \"true\"")
    });
    refused("the module does not report what the TPM holds");
    edit_private_row("store-a", |_| original.clone());
    assert_eq!(code(&e.km(&r)), 18);

    // store-b's blobs and auth (CKA_TPM2_OBJAUTH_ENC, _PUB_BLOB, _PRIV_BLOB) under store-a's
    // attributes: the module shows store-a's point, and the TPM loads and certifies store-b.
    let tpm_attrs = [0x8F00_0001_u64, 0x8F00_0002, 0x8F00_0003];
    let mut b_values = Vec::new();
    edit_private_row("store-b", |attrs| {
        b_values = tpm_attrs.iter().map(|t| row_value(attrs, *t)).collect();
        attrs.to_owned()
    });
    edit_private_row("store-a", |attrs| {
        tpm_attrs.iter().zip(&b_values).fold(attrs.to_owned(), |a, (t, b)| a.replace(&row_value(&a, *t), b))
    });
    refused("the TPM attests the public key");

    // An HMAC key's blobs under the EC key's attributes, so the TPM certifies a symmetric object.
    let hmac_file = e.dir.join("hmac.bin");
    std::fs::write(&hmac_file, HMAC_VALUE).unwrap();
    ptool(&[
        "import",
        "--algorithm=hmac:sha256",
        &format!("--privkey={}", hmac_file.display()),
        "--key-label=store-mac",
    ]);
    let mut mac_values = Vec::new();
    edit_private_row("store-mac", |attrs| {
        mac_values = tpm_attrs.iter().map(|t| row_value(attrs, *t)).collect();
        attrs.to_owned()
    });
    edit_private_row("store-a", |attrs| {
        tpm_attrs.iter().zip(&mac_values).fold(attrs.to_owned(), |a, (t, b)| a.replace(&row_value(&a, *t), b))
    });
    refused("the TPM object is a symmetric object, but the PKCS#11 object is an asymmetric key");

    // A second, transient primary, with a token of its own.
    let store = tpm2_store();
    for args in [
        &["init", "--transient-parent=tpm2-tools-default"][..],
        &["addtoken", "--pid=2", "--label=kmtrans", "--sopin=5678", "--userpin=1234"],
        &["addkey", "--algorithm=ecc256", "--label=kmtrans", "--userpin=1234", "--key-label=trans"],
    ] {
        ptool_in(&store, args);
    }
    e.write_config(&format!(
        "[tokens.trans]\nmodule = \"{}\"\ntokenLabel = \"kmtrans\"\npinFile = \"{}\"\n\n\
         [objects.t]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n\
         [specs.t]\nobject = \"t\"\nattributes = {{ CKA_SIGN = true }}\n\
         tokens.trans = {{ locator = {{ CKA_LABEL = \"trans\" }}, origin = \"adopt\", attestation = true }}\n",
        e.module,
        e.dir.join("pin").display()
    ));
    let o = e.km(&["lock", "--spec", "t", "--token", "trans", "--dry-run"]);
    assert!(stderr(&o).contains("the token's primary is transient"), "{}", stderr(&o));
    assert_eq!(code(&o), 16, "{}", stderr(&o));
}

/// A secret key's `tpm-certify` is bound to its material (review 2026-11-23 B-1). The TPM computes
/// the key's HMAC commitment again with the same object that it certified, and the result must
/// equal the commitment that the module computed. A copy of the store (`tpm2Store`) whose row for
/// the key carries another HMAC key's TPM blobs makes cakeys certify that other key while the
/// module computes the commitment with the real key. cakeys refuses this (13); before the fix, it
/// pinned the other key's attestation. An AES key has no HMAC commitment for the TPM to compute
/// again, so it is refused (15).
#[test]
fn tpm2_a_secret_keys_attestation_is_bound_to_its_material() {
    let Some(e) = env("attest-bound") else { return };
    if !hmac_types_fixed("CAKEYS_TPM_REQUIRE")
        || !swtpm_or_skip("attest-bound", "it makes persistent TPM objects, on the suite's swtpm only")
    {
        return;
    }
    for (label, value) in [("bound-a", &HMAC_VALUE[..]), ("bound-b", &b"another key-management hmac key!"[..])] {
        let file = e.dir.join(format!("{label}.bin"));
        std::fs::write(&file, value).unwrap();
        ptool(&[
            "import",
            "--algorithm=hmac:sha256",
            &format!("--privkey={}", file.display()),
            &format!("--key-label={label}"),
        ]);
    }
    ptool(&["addkey", "--algorithm=aes256", "--key-label=bound-aes"]);
    // In the copy, bound-a's row carries bound-b's TPM blobs and auth (CKA_TPM2_OBJAUTH_ENC,
    // _PUB_BLOB, _PRIV_BLOB). The module reads the original store.
    let copy = e.dir.join("copied-store");
    std::fs::create_dir_all(&copy).unwrap();
    let store = std::env::var("TPM2_PKCS11_STORE").unwrap();
    std::fs::copy(std::path::Path::new(&store).join("tpm2_pkcs11.sqlite3"), copy.join("tpm2_pkcs11.sqlite3")).unwrap();
    let copy = copy.to_str().unwrap();
    let tpm_attrs = [0x8F00_0001_u64, 0x8F00_0002, 0x8F00_0003];
    let mut b_values = Vec::new();
    edit_private_row_in(copy, "bound-b", |attrs| {
        b_values = tpm_attrs.iter().map(|t| row_value(attrs, *t)).collect();
        attrs.to_owned()
    });
    edit_private_row_in(copy, "bound-a", |attrs| {
        tpm_attrs.iter().zip(&b_values).fold(attrs.to_owned(), |a, (t, b)| a.replace(&row_value(&a, *t), b))
    });
    let config = |options: &str| {
        e.write_config(&format!(
            "[tokens.tpm]\nmodule = \"{}\"\ntokenLabel = \"kmtest\"\npinFile = \"{}\"\n{options}\n\n\
             [objects.mac]\nclass = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_SHA256_HMAC\"\nvalueLen = 32\n\n\
             [specs.mac]\nobject = \"mac\"\nattributes = {{ CKA_SIGN = true, CKA_EXTRACTABLE = true }}\n\
             tokens.tpm = {{ locator = {{ CKA_LABEL = \"bound-a\" }}, origin = \"adopt\", attestation = true }}\n\n\
             [objects.aes]\nclass = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_AES\"\nvalueLen = 32\n\n\
             [specs.aes]\nobject = \"aes\"\nattributes = {{ CKA_ENCRYPT = true }}\n\
             tokens.tpm = {{ locator = {{ CKA_LABEL = \"bound-aes\" }}, origin = \"adopt\", attestation = true }}\n",
            e.module,
            e.dir.join("pin").display()
        ));
    };
    let lock = |spec: &str| e.km(&["lock", "--spec", spec, "--token", "tpm", "--dry-run"]);
    // With the module's own store, the certified object computes the key's commitment again.
    config("");
    let o = lock("mac");
    assert_eq!(code(&o), 18, "{}", stderr(&o));
    // With the copy, cakeys certifies bound-b, while the module computes the commitment with
    // bound-a.
    config(&format!("options = {{ tpm2Store = \"{copy}\" }}"));
    let o = lock("mac");
    assert_eq!(code(&o), 13, "{}", stderr(&o));
    assert!(stderr(&o).contains("its HMAC commitment is not the one the key computes"), "{}", stderr(&o));
    // An AES key has no HMAC commitment to bind its certify to.
    config("");
    let o = lock("aes");
    assert_eq!(code(&o), 15, "{}", stderr(&o));
    assert!(stderr(&o).contains("binds a secret key to the TPM object it certifies"), "{}", stderr(&o));
}

/// Every key type that tpm2-pkcs11 generates is attested with its own public area: P-384, P-521
/// and RSA are attested as P-256 is (`tpm2_keys_attest_their_tpm_residence`), and the attested key
/// is compared with the object's material.
#[test]
fn tpm2_attests_each_key_type() {
    let Some(e) = env("attest-types") else { return };
    let key = |name: &str, ty: &str, binding: &str| {
        format!(
            "[objects.{name}]\nclass = \"CKO_PRIVATE_KEY\"\n{ty}\n\n[specs.{name}]\nobject = \"{name}\"\n\
             attributes = {{ CKA_SIGN = true }}\n\
             tokens.tpm = {{ locator = {{ CKA_LABEL = \"types-{name}\" }}, origin = \"create\", attestation = true{binding} }}\n\n"
        )
    };
    e.config(
        &[
            key("p384", "keyType = \"CKK_EC\"\ncurve = \"secp384r1\"", ""),
            // tpm2-pkcs11 cannot sign with a P-521 key (upstream/tpm2-pkcs11/PR.md), so this key
            // has no signing proof.
            key("p521", "keyType = \"CKK_EC\"\ncurve = \"secp521r1\"", ", binding = \"token-asserted\""),
            key("rsa", "keyType = \"CKK_RSA\"\nmodulusBits = 2048", ""),
        ]
        .concat(),
    );
    for spec in ["p384", "p521", "rsa"] {
        let o = e.km(&["create", "--spec", spec, "--token", "tpm"]);
        assert_eq!(code(&o), 22, "{spec}: {}", stderr(&o));
        assert_eq!(e.locked_attestation(spec, "tpm")["kind"].as_str(), Some("tpm-certify"), "{spec}");
        assert_eq!(e.code(&["check", "--spec", spec, "--token", "tpm"]), 0, "{spec}");
    }
}

/// Returns the suite on the module with tpm2-pkcs11's vendor mechanisms
/// (`CAKEYS_TPM_VENDOR_MODULE`: the nixpkgs module with the patches of upstream/tpm2-pkcs11/,
/// nix/tpm2-pkcs11-vendor.nix). It runs next to the module of `env`, which has no vendor
/// mechanisms.
fn vendor_env(name: &str) -> Option<Suite> {
    let module = suite_var("CAKEYS_TPM_VENDOR_MODULE", "CAKEYS_TPM_VENDOR_REQUIRE", name)?;
    Some(Suite::new(&format!("tpm2-{name}"), module, tpm2_tokens).checking(no_attestation_off_swtpm))
}

/// Returns the nixpkgs module (`CAKEYS_TPM_MODULE`), which the vendor suites run next to their own
/// module. It has no vendor mechanisms, and it uses the same TPM and store.
fn store_module(name: &str) -> String {
    suite_var("CAKEYS_TPM_MODULE", "CAKEYS_TPM_REQUIRE", name)
        .unwrap_or_else(|| panic!("{name}: the vendor module is set, CAKEYS_TPM_MODULE is not"))
}

/// Returns a `[tokens.<name>]` table for `module` and the suite's token `kmtest`, logged in, with
/// the `extra` lines.
fn token_of(e: &Suite, name: &str, module: &str, extra: &str) -> String {
    format!(
        "[tokens.{name}]\nmodule = \"{module}\"\ntokenLabel = \"kmtest\"\npinFile = \"{}\"\nprobe = {{ scratch = true }}\n{extra}\n\n",
        e.dir.join("pin").display()
    )
}

/// Returns the spec of one attested P-256 key `label`, which is created on token `tpm` and adopted
/// on the tokens in `others`.
fn p256_spec(label: &str, others: &[&str]) -> String {
    let head = format!(
        "[objects.p256]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n\
         [specs.p256]\nobject = \"p256\"\nattributes = {{ CKA_SIGN = true }}\n\
         tokens.tpm = {{ locator = {{ CKA_LABEL = \"{label}\" }}, origin = \"create\", attestation = true }}\n"
    );
    let adopted = others.iter().map(|t| {
        format!("tokens.{t} = {{ locator = {{ CKA_LABEL = \"{label}\" }}, origin = \"adopt\", attestation = true }}\n")
    });
    head + &adopted.collect::<String>()
}

/// A module with `CKM_TPM2_CERTIFY` certifies the key itself, and the attestation equals the one
/// that the store path makes of the same key: the same ID and the same root (the persistent
/// Attestation Key is still the signer). The vendor token is configured with a store that does not
/// exist, so reading a store would fail. The `store` token uses the nixpkgs module, without the
/// mechanism, on the same TPM and store.
#[test]
fn tpm2_vendor_module_attests_as_the_store_path_does() {
    let Some(e) = vendor_env("vendor-same") else { return };
    let store_module = store_module("vendor-same");
    e.write_config(
        &(token_of(&e, "tpm", &e.module, "options = { tpm2Store = \"/nonexistent\" }")
            + &token_of(&e, "store", &store_module, "")
            + &p256_spec("vendor-p256", &["store"])),
    );
    let first = e.km(&["create", "--spec", "p256", "--token", "tpm", "--no-update-lock"]);
    assert_eq!(code(&first), 18, "{}", stderr(&first));
    let resolve = |token: &str| -> serde_json::Value {
        let o = e.km(&["resolve", "--spec", "p256", "--token", token]);
        assert_eq!(code(&o), 0, "{token}: {}", stderr(&o));
        // The persistent AK is read from the TPM, so cakeys prints no caveat about the signer,
        // unlike for akLabel (review 2026-11-23 B-2).
        assert!(!stderr(&o).contains("only the module vouches for"), "{token}: {}", stderr(&o));
        serde_json::from_str(&stdout(&o)).unwrap()
    };
    let (vendor, store) = (resolve("tpm"), resolve("store"));
    assert!(vendor["attestation"]["id"].as_str().unwrap().starts_with("sha256-"));
    assert_eq!(vendor["attestation"]["id"], store["attestation"]["id"], "one key, one attestation ID");
    assert_eq!(vendor["attestation"]["root"], store["attestation"]["root"], "the same persistent AK signed");
    // Each realisation, locked through its own path, verifies, because both paths pinned the same
    // ID and root.
    for token in ["tpm", "store"] {
        assert_eq!(e.code(&recording(&["lock", "--spec", "p256", "--token", token, "--dry-run"])), 22, "{token}");
    }
    assert_eq!(e.locked_attestation("p256", "tpm"), e.locked_attestation("p256", "store"));
    for token in ["tpm", "store"] {
        assert_eq!(e.code(&["check", "--spec", "p256", "--token", token]), 0, "{token}");
    }
}

/// An Attestation Key that is an object of the token (`akLabel`, `CKM_TPM2_AK_PAIR_GEN`). `lock`
/// makes it, and a read never does, and the attestation needs no TCTI, no TPM handle and no store
/// (the token is configured with a TCTI and a store that do not exist). It is a different key from
/// the persistent AK, so it gives a different root. A key that is not an Attestation Key is never
/// trusted as one, and cakeys reports a module that lacks the mechanisms.
#[test]
fn tpm2_vendor_token_attestation_key_needs_no_tpm_handle_or_store() {
    let Some(e) = vendor_env("vendor-ak") else { return };
    let none = "tcti = \"device:/nonexistent\", tpm2Store = \"/nonexistent\"";
    let config = |options: &str| {
        e.write_config(
            &(token_of(&e, "tpm", &e.module, &format!("options = {{ {options} }}"))
                + &p256_spec("vendor-ak-p256", &[])),
        );
    };
    config(&format!("akLabel = \"cakeys-ak\", {none}"));
    let before = on_swtpm().then(persistent_handles);
    let first = e.km(&["create", "--spec", "p256", "--token", "tpm", "--no-update-lock"]);
    assert_eq!(code(&first), 18, "{}", stderr(&first));
    assert_eq!(e.code(&recording(&["lock", "--spec", "p256", "--token", "tpm", "--dry-run"])), 22);
    let att = e.locked_attestation("p256", "tpm");
    assert_eq!(att["kind"].as_str(), Some("tpm-certify"));
    for _ in 0..2 {
        // Each run reports what this signer cannot establish: only the module vouches for it
        // (review 2026-11-23 B-2: no run reported this).
        let o = e.km(&["check", "--spec", "p256", "--token", "tpm"]);
        assert_eq!(code(&o), 0, "{}", stderr(&o));
        assert!(stderr(&o).contains("its tpm-certify signer (akLabel) is a key only the module vouches for"));
        assert_eq!(e.code(&["check", "p256.id.tpm-certify", "--token", "tpm"]), 0);
    }
    // No persistent AK was made, so the TPM's handles are as they were.
    assert_eq!(before.map(|b| b == persistent_handles()), on_swtpm().then_some(true));
    // The Attestation Key is on the token, and the next run reuses it, so the root does not
    // change.
    assert!(labelled(&e.session(), "cakeys-ak") >= 1);
    let again = e.km(&["resolve", "--spec", "p256", "--token", "tpm"]);
    let got: serde_json::Value = serde_json::from_str(&stdout(&again)).unwrap();
    assert_eq!(got["attestation"]["root"].as_str(), att["root"].as_str());

    // Reads never make an Attestation Key, so another label is a downgrade (14), and the message
    // names the label.
    config(&format!("akLabel = \"other-ak\", {none}"));
    for _ in 0..2 {
        let o = e.km(&["check", "--spec", "p256", "--token", "tpm"]);
        assert_eq!(code(&o), 14, "{}", stderr(&o));
        assert!(stderr(&o).contains("no Attestation Key labelled \"other-ak\""), "{}", stderr(&o));
    }
    // An ordinary key is not an Attestation Key, because it could sign a forged statement (13).
    config(&format!("akLabel = \"vendor-ak-p256\", {none}"));
    let o = e.km(&["check", "--spec", "p256", "--token", "tpm"]);
    assert_eq!(code(&o), 13, "{}", stderr(&o));
    assert!(stderr(&o).contains("is not a cakeys Attestation Key"), "{}", stderr(&o));
    // Both an `akLabel` and an `akHandle` give two answers to one question, so the configuration
    // is invalid (17).
    config("akLabel = \"cakeys-ak\", akHandle = \"0x81000017\"");
    assert_eq!(e.code(&["check", "--spec", "p256", "--token", "tpm"]), 17);

    // The nixpkgs module has no such mechanism. When the configuration asks for it, cakeys reports
    // the missing mechanism and does not use another way, because an attestation that cannot be
    // computed is a downgrade of the locked one (14).
    let store_module = store_module("vendor-ak");
    e.write_config(
        &(token_of(&e, "tpm", &store_module, "options = { akLabel = \"cakeys-ak\" }")
            + &p256_spec("vendor-ak-p256", &[])),
    );
    let o = e.km(&["check", "--spec", "p256", "--token", "tpm"]);
    assert_eq!(code(&o), 14, "{}", stderr(&o));
    assert!(stderr(&o).contains("CKM_TPM2_AK_PAIR_GEN"), "{}", stderr(&o));
}

/// Where the attestation finds the store and the TPM: a TCTI named in the token's options, and,
/// when `TPM2_PKCS11_STORE` is unset, the module's own search path (`~/.tpm2_pkcs11`). When the
/// store named in the options holds another token, the token is not found (11).
#[test]
fn tpm2_attestation_finds_its_store_and_tpm_as_configured() {
    let Some(e) = env("attest-find") else { return };
    ptool(&["addkey", "--algorithm=ecc256", "--key-label=find-a"]);
    let store = tpm2_store();
    let tcti = std::env::var("TPM2_PKCS11_TCTI").unwrap();
    let config = |options: &str| {
        e.write_config(&format!(
            "[tokens.tpm]\nmodule = \"{}\"\ntokenLabel = \"kmtest\"\npinFile = \"{}\"\n{options}\n\n\
             [objects.a]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n\
             [specs.a]\nobject = \"a\"\nattributes = {{ CKA_SIGN = true }}\n\
             tokens.tpm = {{ locator = {{ CKA_LABEL = \"find-a\" }}, origin = \"adopt\", attestation = true }}\n",
            e.module,
            e.dir.join("pin").display()
        ));
    };
    let r = ["lock", "--spec", "a", "--token", "tpm", "--dry-run"];
    config(&format!("options = {{ tcti = \"{tcti}\" }}"));
    assert_eq!(e.code(&r), 18, "the TCTI from the options");

    // Without TPM2_PKCS11_STORE, the attestation uses the store under $HOME, where the module also
    // looks.
    config("");
    let home = e.dir.join("home");
    std::fs::create_dir_all(&home).unwrap();
    std::os::unix::fs::symlink(&store, home.join(".tpm2_pkcs11")).unwrap();
    let o = e.run().env_remove("TPM2_PKCS11_STORE").env("HOME", &home).output(&r);
    assert_eq!(code(&o), 18, "the store under $HOME: {}", stderr(&o));

    // The options name a store of another token.
    let other = e.dir.join("other-store");
    std::fs::create_dir_all(&other).unwrap();
    let other_store = other.to_str().unwrap();
    ptool_in(other_store, &["init"]);
    ptool_in(other_store, &["addtoken", "--pid=1", "--label=other", "--sopin=5678", "--userpin=1234"]);
    config(&format!("options = {{ tpm2Store = \"{}\" }}", other.display()));
    let o = e.km(&r);
    assert_eq!(code(&o), 11, "{}", stderr(&o));
    assert!(stderr(&o).contains("token 'kmtest' in the tpm2-pkcs11 store"), "{}", stderr(&o));
}

/// The object matrix (`tests/object_matrix/`) on tpm2-pkcs11, against the software TPM only. The
/// matrix makes hundreds of objects, and tpm2-pkcs11 cannot destroy some of them, so the matrix
/// must not run on a TPM that the platform depends on (docs/DEVELOPMENT.md, "Hardware rules"). The
/// store belongs to the test and is new, so the table is the same in every run.
#[test]
fn tpm2_object_matrix_is_the_committed_one() {
    let Some(e) = env("object-matrix") else { return };
    if !swtpm_or_skip("object-matrix", "the object matrix runs on the suite's swtpm only") {
        return;
    }
    object_matrix::check(&object_matrix::Target {
        name: "tpm2-pkcs11+swtpm",
        token: "tpm",
        tokens: &|dir| tpm2_tokens(&e.module, dir),
        session: &|| e.session(),
        batch: 8,
        dir: &e.dir,
        // tpm2-abrmd serialises access to the TPM, so more workers would not make the run faster.
        workers: 4,
    });
}

/// Returns whether this suite's TPM is the software TPM that `nix/tpm2-test-env.sh` started (its
/// private bus is named for it). The same suite can be pointed at a real TPM
/// (`nix/ftpm-test-env.sh`), so a test that changes TPM state beyond the token's own objects runs
/// only on the software TPM (docs/DEVELOPMENT.md, "Hardware rules").
///
/// The script sets `CAKEYS_TPM_SWTPM`, and the TPM must confirm it: its vendor strings must be
/// swtpm's, "SW  " and " TPM" \[run\]. When the marker is set on another TPM, the run is
/// misconfigured, and the function panics. It also panics when a suite that requires the TPM
/// (`CAKEYS_TPM_REQUIRE`) runs on any other TPM, because the steps that change the TPM are part of
/// what the suite requires, and they are never skipped silently (review tpm2.rs F3). The check was
/// once a substring of the D-Bus address, and a renamed bus skipped those steps while every test
/// passed.
fn on_swtpm() -> bool {
    let said = std::env::var_os("CAKEYS_TPM_SWTPM").is_some();
    let software = said && tpm_is_software();
    assert!(!said || software, "CAKEYS_TPM_SWTPM is set, but the TPM's vendor strings are not swtpm's");
    assert!(
        software || std::env::var_os("CAKEYS_TPM_REQUIRE").is_none(),
        "CAKEYS_TPM_REQUIRE is set, but this is not the suite's swtpm (nix/tpm2-test-env.sh sets CAKEYS_TPM_SWTPM)"
    );
    software
}

/// Returns [`on_swtpm`]. When it is false, the function skips the steps of test `test` that only
/// the suite's swtpm may take, and gives `why` as the reason. The skip goes through [`skip`], which
/// panics instead when `CAKEYS_TPM_REQUIRE` requires the suite.
fn swtpm_or_skip(test: &str, why: &str) -> bool {
    let software = on_swtpm();
    if !software {
        skip(test, "CAKEYS_TPM_REQUIRE", why);
    }
    software
}

/// Returns whether the TPM's fixed properties carry swtpm's vendor strings
/// (`TPM2_PT_VENDOR_STRING_1` and `_2`, "SW  " and " TPM").
fn tpm_is_software() -> bool {
    let out = Command::new("tpm2_getcap").arg("properties-fixed").output().unwrap();
    assert!(out.status.success(), "tpm2_getcap properties-fixed: {}", stderr(&out));
    let text = stdout(&out);
    let raw = |name: &str| {
        let mut lines = text.lines().skip_while(|l| l.trim_end() != format!("{name}:"));
        lines.nth(1).map(|l| l.trim().to_owned())
    };
    raw("TPM2_PT_VENDOR_STRING_1").as_deref() == Some("raw: 0x53572020")
        && raw("TPM2_PT_VENDOR_STRING_2").as_deref() == Some("raw: 0x2054504D")
}

/// Returns what `tpm2_getcap handles-persistent` lists, which is the TPM's persistent handles.
fn persistent_handles() -> String {
    let out = Command::new("tpm2_getcap").arg("handles-persistent").output().unwrap();
    assert!(out.status.success(), "tpm2_getcap handles-persistent: {}", stderr(&out));
    stdout(&out)
}

/// Runs `tpm2_<tool> <args>` against the suite's software TPM.
fn tpm2_tool(tool: &str, args: &[&str]) {
    assert!(on_swtpm(), "tpm2_{tool} changes the TPM: only against the suite's swtpm");
    let out = Command::new(format!("tpm2_{tool}")).args(args).output().unwrap();
    assert!(out.status.success(), "tpm2_{tool} {args:?}: {}", stderr(&out));
}

/// When the attestation does not find what it needs, cakeys reports the missing item, and nothing
/// is attested. The cases are a store directory that does not exist (16; `~` is kept as written
/// when `$HOME` is unset), a module (the fault shim in front of tpm2-pkcs11) that withholds the
/// `CKA_ID` by which the store row is found (15), a key at the AK handle that is not a cakeys
/// Attestation Key (13, because it could sign forged attestations), and an owner hierarchy with an
/// auth value, in which no Attestation Key can be made (16).
#[test]
fn tpm2_attestation_says_what_it_lacks() {
    let Some(e) = env("attest-lacks") else { return };
    ptool(&["addkey", "--algorithm=ecc256", "--key-label=lacks-a"]);
    let config = |token: &str| {
        e.write_config(&format!(
            "[tokens.tpm]\nmodule = \"{}\"\ntokenLabel = \"kmtest\"\n{token}\n\n\
             [objects.a]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n\
             [specs.a]\nobject = \"a\"\nattributes = {{ CKA_SIGN = true }}\n\
             tokens.tpm = {{ locator = {{ CKA_LABEL = \"lacks-a\" }}, origin = \"adopt\", attestation = true, binding = \"token-asserted\" }}\n",
            e.module,
        ));
    };
    let pin = format!("pinFile = \"{}\"", e.dir.join("pin").display());
    let r = ["lock", "--spec", "a", "--token", "tpm", "--dry-run"];
    let refused = |o: &std::process::Output, want: i32, why: &str| {
        assert_eq!(code(o), want, "{why}: {}", stderr(o));
        assert!(stderr(o).contains(why), "expected {why:?} in {}", stderr(o));
    };

    config(&format!("{pin}\noptions = {{ tpm2Store = \"~/no-store\" }}"));
    let o = e.run().env_remove("HOME").output(&r);
    refused(&o, 16, "opening tpm2-pkcs11 store ~/no-store");

    config(&pin);
    // Behind a module that withholds the object's CKA_ID, cakeys cannot find the store row (15).
    // Behind a module that withholds the object's label, cakeys finds the row by the CKA_ID alone.
    e.write_config(&std::fs::read_to_string(e.dir.join("keys.toml")).unwrap().replace(&e.module, &fault_shim()));
    let plan = e.dir.join("plan.toml");
    let withheld = |attribute: &str| {
        let rule =
            format!("fn = \"C_GetAttributeValue\"\nof_label = \"lacks-a\"\nattribute = \"{attribute}\"\ndrop = true");
        std::fs::write(&plan, format!("[[rule]]\n{rule}\n")).unwrap();
        e.km_env(&r, &[("P11_FAULT_MODULE", std::path::Path::new(&e.module)), ("P11_FAULT_PLAN", &plan)])
    };
    refused(&withheld("CKA_ID"), 15, "the key object exposes no CKA_ID to find its store row by");
    let o = withheld("CKA_LABEL");
    assert_eq!(code(&o), 18, "{}", stderr(&o));

    if !swtpm_or_skip("attest-lacks", "the Attestation Key cases change the TPM, and this is not the suite's swtpm") {
        return;
    }
    // An RSA storage key is at the handle where cakeys looks for the Attestation Key.
    let primary = e.dir.join("primary.ctx");
    let primary = primary.to_str().unwrap();
    tpm2_tool("createprimary", &["-C", "o", "-G", "rsa2048", "-c", primary]);
    tpm2_tool("evictcontrol", &["-C", "o", "-c", primary, "0x81000017"]);
    config(&format!("{pin}\noptions = {{ akHandle = \"0x81000017\" }}"));
    refused(&e.km(&r), 13, "the object at akHandle 0x81000017 is not a cakeys Attestation Key");

    // A free handle, and an owner hierarchy for which cakeys has no auth value.
    tpm2_tool("changeauth", &["-c", "owner", "an owner password"]);
    config(&format!("{pin}\noptions = {{ akHandle = \"0x81000018\" }}"));
    refused(&e.km(&r), 16, "creating the Attestation Key in the owner hierarchy (is owner auth empty?)");
}

/// False results of the module's own attestation (`CKM_TPM2_CERTIFY`) (`tests/liars/tpm2.toml`,
/// review 2026-11-24 B-12). The vendor module runs behind p11-fault on the suite's swtpm. Each
/// injected fault produces a statement that passes every check of it except one (another
/// signature, another run's nonce, another public area, another certified object), and cakeys
/// refuses each one (13). A secret key and an `ekCertificate` are refused (15) before any certify.
/// Every cell runs in the same way as `tests/liars.rs` runs the table of cakeys
/// ([`liars::run_cells`]).
#[test]
fn tpm2_vendor_attestation_liars() {
    let name = "vendor-liars";
    let Some(module) = suite_var("CAKEYS_TPM_VENDOR_MODULE", "CAKEYS_TPM_VENDOR_REQUIRE", name) else { return };
    if !swtpm_or_skip(
        name,
        "an attestation provisions the persistent Attestation Key, and this is not the suite's swtpm",
    ) {
        return;
    }
    let table = liars::Table::tpm2();
    let (f, mut wrong) = vendor_liars(module, &table);
    let cells = table.cells();
    wrong.extend(liars::run_cells(&table, &cells, &f));
    assert!(
        wrong.is_empty(),
        "{} wrong in the {} cells and their runs:\n{}",
        wrong.len(),
        cells.len(),
        wrong.join("\n")
    );
}

/// Builds the fixture of `tests/liars/tpm2.toml` on the vendor `module`. `tpm2_ptool` makes each
/// object next to its decoy `<name>-other`. The tokens `tpm`, `tpm-b` and `tpm-ek` all name the
/// one token behind the shim, and each is configured with a store that does not exist (so the
/// module certifies); `tpm-ek` also has an `ekCertificate`. The objects `ec-sign` and `ec-adopt`
/// are also placed on `tpm-b` by the specs `ec-sign-b` and `ec-adopt-b`, because an address names
/// one token, so a run with two specs has two pairs. Both pairs of `ec-sign` are locked, which
/// provisions the Attestation Key. The function also returns each invariant of the runner that a
/// setup run broke.
fn vendor_liars(module: String, table: &liars::Table) -> (liars::Fixture, Vec<String>) {
    use std::fmt::Write as _;
    let w = Workdir::new("tpm2-vendor-liars");
    let token = |name: &str, options: &str| {
        format!(
            "[tokens.{name}]\nmodule = \"{}\"\ntokenLabel = \"kmtest\"\npinFile = \"{}\"\n\
             options = {{ tpm2Store = \"/nonexistent\"{options} }}\n\n",
            fault_shim(),
            w.dir.join("pin").display()
        )
    };
    let ek = concat!(env!("CARGO_MANIFEST_DIR"), "/../tpm2-pkcs11/tests/fixtures/amd-ftpm-ek-ecc.pem");
    let mut config = token("tpm", "") + &token("tpm-b", "") + &token("tpm-ek", &format!(", ekCertificate = \"{ek}\""));
    for (name, o) in &table.objects {
        let (kind, attributes, algorithm, binding) = match o.class.as_str() {
            "private" => (
                "class = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"",
                "CKA_SIGN = true",
                "ecc256",
                ", binding = \"token-asserted\"",
            ),
            "secret" => (
                "class = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_AES\"\nvalueLen = 32",
                "CKA_ENCRYPT = true, CKA_SENSITIVE = true",
                "aes256",
                "",
            ),
            class => panic!("the fixture has no {class} object"),
        };
        let _ = writeln!(config, "[objects.{name}]\n{kind}\n");
        let specs = if ["ec-sign", "ec-adopt"].contains(&name.as_str()) {
            vec![(name.clone(), "tpm"), (format!("{name}-b"), "tpm-b")]
        } else {
            vec![(name.clone(), o.token.as_str())]
        };
        for (spec, t) in specs {
            let _ = writeln!(
                config,
                "[specs.{spec}]\nobject = \"{name}\"\nattributes = {{ {attributes} }}\n\
                 tokens.{t} = {{ locator = {{ CKA_LABEL = \"{name}\" }}, origin = \"adopt\", attestation = true{binding} }}\n"
            );
        }
        for label in [name.clone(), format!("{name}-other")] {
            ptool(&["addkey", &format!("--algorithm={algorithm}"), &format!("--key-label={label}")]);
        }
    }
    no_attestation_off_swtpm(&config);
    w.write_config(&config);
    let f = liars::Fixture { w, real: module, planted: Vec::new() };
    let mut wrong = Vec::new();
    for spec in ["ec-sign", "ec-sign-b"] {
        let (out, problems) = f.held(&["lock", "--spec", spec], None, None);
        assert_eq!(code(&out), 22, "planting {spec}: {}", stderr(&out));
        wrong.extend(problems);
    }
    let planted = std::fs::read(f.lock()).unwrap();
    (liars::Fixture { planted, ..f }, wrong)
}
