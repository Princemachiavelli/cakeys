//! End-to-end tests against tpm2-pkcs11 on a software TPM (nix/tpm2-test-env.sh).
//!
//! Needs `CAKEYS_TPM_MODULE` (`libtpm2_pkcs11.so`), the `TPM2_PKCS11_*` environment from the harness,
//! a token `kmtest` with user PIN `1234`, and `tpm2_ptool` on PATH. Skipped when
//! `CAKEYS_TPM_MODULE` is unset, unless `CAKEYS_TPM_REQUIRE=1`.

mod common;
mod object_matrix;

use common::*;
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, ObjectClass};
use cryptoki::session::Session;
use hmac::{Hmac, KeyInit, Mac};
use std::process::Command;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

/// The suite for test `name` ([`tpm2_tokens`]), or `None` (skipped). A tpm2-pkcs11 session sees
/// only the objects that existed when it opened: take [`Suite::session`] after the run that made
/// them.
fn env(name: &str) -> Option<Suite> {
    let module = suite_var("CAKEYS_TPM_MODULE", "CAKEYS_TPM_REQUIRE", name)?;
    Some(Suite::new(&format!("tpm2-{name}"), module, tpm2_tokens).checking(no_attestation_off_swtpm))
}

/// Every keys.toml a test writes: an attestation provisions a persistent Attestation Key, so one
/// asking for it is written only against the suite's swtpm (review tpm2.rs F1;
/// docs/DEVELOPMENT.md, "Hardware rules").
fn no_attestation_off_swtpm(text: &str) {
    assert!(
        !text.contains("attestation = true") || on_swtpm(),
        "an attestation makes a persistent TPM object: only against the suite's swtpm"
    );
}

impl Suite {
    /// The attestation a realisation pins (§3.7: per realisation, never in the object's ids).
    fn locked_attestation(&self, spec: &str, token: &str) -> toml::Value {
        self.lock()["realisations"][spec][token]["attestation"].clone()
    }
}

fn labelled(s: &Session, label: &str) -> usize {
    s.find_objects(&[Attribute::Label(label.as_bytes().to_vec())]).unwrap().len()
}

/// Like `unwrap_octets`, but also accepting tpm2-pkcs11's P-521 encoding `04 85 <133 bytes>`
/// (see cakeys-tpm2-pkcs11). The oracle's independence is in building the SPKI.
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
    // No Triple DES in a TPM (TPM2 symmetric keys are AES): neither the check value nor the
    // generation, refused from what the module lists before anything is created.
    let o = e.km(&["create", "--spec", "des3", "--token", "tpm", "--no-update-lock"]);
    assert_eq!(code(&o), 15, "{}", stderr(&o));
    assert!(stderr(&o).contains("CKM_DES3_ECB"), "{}", stderr(&o));
    assert_eq!(labelled(&e.session(), "refusal-des3"), 0);
    // Secret-key generation is refused up front, with the provider's advice, and creates nothing.
    for (spec, label) in [("aes-gen", "refusal-aes-gen"), ("hmac-gen", "refusal-hmac-gen")] {
        let o = e.km(&["create", "--spec", spec, "--token", "tpm", "--no-update-lock"]);
        assert_eq!(code(&o), 15, "{spec}");
        assert!(stderr(&o).contains("tpm2_ptool addkey"), "{spec}");
        assert_eq!(labelled(&e.session(), label), 0, "{spec}");
    }
    assert_eq!(e.code(&["create", "--spec", "ed", "--token", "tpm", "--no-update-lock"]), 15);
    // No CKM_AES_CMAC: a sign-only AES spec has no commitment here.
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
        // tpm2-pkcs11 1.10.1 cannot sign with its P-521 keys: C_SignInit parses its own malformed
        // CKA_EC_POINT and fails (CKR_HOST_MEMORY; upstream/tpm2-pkcs11 fixes both).
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
        assert_eq!(e.code(&["lock", "--spec", &spec, "--token", "tpm"]), 0, "{k}");
        // A session opened now: tpm2-pkcs11 sessions don't see objects created after they opened.
        assert_eq!(e.locked_id(k, "rfc7093m4"), sri(&oracle_spki_with(&e.session(), k, unwrap_tpm2)), "{k}");
        let binding = if k == "tpm-p521" { "token-asserted" } else { "pop-sign" };
        assert_eq!(e.lock()["realisations"][&spec]["tpm"]["binding"].as_str(), Some(binding), "{k}");
        let pubs = format!("{k}-pub");
        assert_eq!(e.code(&["lock", "--spec", &pubs, "--token", "tpm-anon"]), 0, "{k}");
    }
}

#[test]
fn tpm2_identity_failure_after_create_leaves_nothing() {
    let Some(e) = env("orphan") else { return };
    // The key is generated, then its point, read through the fault shim, is cut short: no
    // identity, so what was made is removed. The shim does it whatever tpm2-pkcs11's version
    // (review tpm2.rs F4: the trigger was tpm2-pkcs11's own malformed P-521 point).
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

/// `pop-ecdh` on tpm2-pkcs11: it derives, but cannot MAC with a sealed derived secret (its
/// `C_SignInit` wants a `CKA_ALLOWED_MECHANISMS` the derived object lacks), so the committed
/// profile says `derive.sealed = false` and the proof compares an extractable derived secret
/// instead. Before the probe recorded that, every ECDH proof here failed.
#[test]
fn tpm2_proves_possession_by_deriving() {
    let Some(e) = env("ecdh") else { return };
    e.config(
        "[objects.p]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n\
         [specs.p]\nobject = \"p\"\nattributes = { CKA_DERIVE = true }\n\
         tokens.tpm = { locator = { CKA_LABEL = \"ecdh-p256\" }, origin = \"create\", binding = \"pop-ecdh\" }\n",
    );
    let o = e.km(&["create", "--spec", "p", "--token", "tpm"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert_eq!(e.lock()["realisations"]["p"]["tpm"]["binding"].as_str(), Some("pop-ecdh"));
    let o = e.km(&["check", "--spec", "p", "--token", "tpm"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
}

/// openssl-computed rfc7093m4 IDs of the import fixtures (test-only keys).
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
        assert_eq!(e.code(&["lock", "--spec", spec, "--token", token]), 0, "{spec}");
    }
    assert_eq!(e.locked_id("p256", "rfc7093m4"), IMPORT_P256);
    assert_eq!(e.locked_id("rsa", "rfc7093m4"), IMPORT_RSA2048);
    let mut mac = <Hmac<sha2::Sha256> as KeyInit>::new_from_slice(HMAC_VALUE).unwrap();
    mac.update(b"key-management/v1/commitment/CKK_SHA256_HMAC/256");
    assert_eq!(e.locked_id("hmac", "commitment"), sri(&mac.finalize().into_bytes()));
    // An HMAC-SHA384 key is committed with HMAC-SHA384 (the TPM binds the key to its hash).
    let mut mac = <Hmac<sha2::Sha384> as KeyInit>::new_from_slice(HMAC384_VALUE).unwrap();
    mac.update(b"key-management/v1/commitment/CKK_SHA384_HMAC/384");
    assert_eq!(e.locked_id("hmac384", "commitment"), sri(&mac.finalize().into_bytes()));
}

#[test]
fn tpm2_aes_key_is_identified_by_its_kcv() {
    let Some(e) = env("aes") else { return };
    // tpm2-pkcs11 cannot import AES keys, so the oracle here is a consistency check: the same
    // block encrypted through a separate session. The independent AES oracle runs on SoftHSM.
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
    assert_eq!(e.code(&recording(&r)), 0);
    assert_eq!(e.code(&["check", "aes.id.kcv-ecb"]), 0);

    let s = e.session();
    let h =
        s.find_objects(&[Attribute::Class(ObjectClass::SECRET_KEY), Attribute::Label(b"kcv-aes".to_vec())]).unwrap()[0];
    let block = &<sha2::Sha256 as sha2::Digest>::digest(b"key-management/v1/kcv-ecb/CKK_AES/256")[..16];
    let kcv = s.encrypt(&Mechanism::AesEcb, h, block).unwrap();
    assert_eq!(e.locked_id("aes", "kcv-ecb"), sri(&kcv));
}

/// tpm2-pkcs11 holds a data object only private (it seals `CKA_VALUE`; `CKA_PRIVATE = false` is
/// `CKR_ATTRIBUTE_VALUE_INVALID` \[src\]), so a spec declaring `CKA_PRIVATE = true` is how any data
/// object on it is identified: `valuehash`, read under the login, the value's own SHA-256.
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
    // Undeclared, its hash would be an offline guessing oracle nobody agreed to: refused.
    let o = e.km(&["lock", "--spec", "blob-undeclared", "--token", "tpm"]);
    assert_eq!(code(&o), 15, "{}", stderr(&o));
    assert!(stderr(&o).contains("declare CKA_PRIVATE = true"), "{}", stderr(&o));
    let o = e.km(&["lock", "--spec", "blob", "--token", "tpm"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert_eq!(e.locked_id("blob", "valuehash"), sri(&value));
    assert_eq!(e.code(&["check", "blob", "--spec", "blob"]), 0);
}

/// The `tpm-certify` commitment (§3.7 of docs/DESIGN.md): a native `TPM2_Certify` over the
/// object's Name, host-verified against a provisioned AK, and cross-checked against the
/// material `rfc7093m4` names. It provisions persistent objects (the AK, a key at another AK
/// handle): on the suite's swtpm only (review tpm2.rs F1).
#[test]
fn tpm2_keys_attest_their_tpm_residence() {
    let Some(e) = env("attest") else { return };
    if !on_swtpm() {
        eprintln!("skipping attest: it makes persistent TPM objects, on the suite's swtpm only");
        return;
    }
    // A generated EC key (9a slot style): attested on the TPM, once the AK is provisioned.
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
    assert_eq!(e.code(&recording(&r)), 0);
    // The lock: the attestation lives on the realisation (per device), the portable ID on the
    // object; the realisation pins the AK beside its attestation ID.
    assert!(e.lock()["objects"]["p256"]["ids"].get("tpm-certify").is_none());
    let real = &e.lock()["realisations"]["p256"]["tpm"];
    assert_eq!(real["schemes"].as_array().unwrap().len(), 1);
    let att = e.locked_attestation("p256", "tpm");
    assert_eq!(att["kind"].as_str(), Some("tpm-certify"));
    assert!(att["root"].as_str().unwrap().starts_with("sha256-"));
    assert_ne!(att["id"].as_str(), Some(e.locked_id("p256", "rfc7093m4").as_str()));
    // Verify is a fresh certify run: a new nonce, the same stable Name.
    assert_eq!(e.code(&["check", "--spec", "p256", "--token", "tpm"]), 0);
    assert_eq!(e.code(&["check", "p256.id.tpm-certify", "--token", "tpm"]), 0);
    // The AK is persistent at the default handle: a second run reuses it, so the root is stable.
    let again = e.km(&["resolve", "--spec", "p256", "--token", "tpm"]);
    let got: serde_json::Value = serde_json::from_str(&stdout(&again)).unwrap();
    assert_eq!(got["attestation"]["root"].as_str(), att["root"].as_str());

    // Once locked, a run that cannot attest is a scheme downgrade (14) — here no AK at the
    // configured handle. Reads never provision one, so the second verify fails the same way.
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
    // `check` is a read like verify (DESIGN §3.7): it fails the same way and leaves the TPM's
    // persistent handles as they were, the missing AK included.
    let before = persistent_handles();
    for _ in 0..2 {
        let o = e.km(&["check", "p256.id.tpm-certify", "--token", "tpm"]);
        assert_eq!(code(&o), 14, "{}", stderr(&o));
        assert!(stderr(&o).contains("no Attestation Key at 0x81000017"));
    }
    assert_eq!(persistent_handles(), before);
    assert!(!before.contains("0x81000017"), "{before}");
    // A key at the AK handle that is not a restricted signing key is never trusted as the AK:
    // an unrestricted one could sign a forged attestation.
    let ctx = e.dir.join("storage.ctx");
    let ctx = ctx.to_str().unwrap();
    tpm2_tool("createprimary", &["-C", "o", "-G", "ecc", "-c", ctx]);
    tpm2_tool("evictcontrol", &["-C", "o", "-c", ctx, "0x81000018"]);
    std::fs::write(e.dir.join("keys.toml"), alt("0x81000018")).unwrap();
    let o = e.km(&r);
    assert_eq!(code(&o), 13, "{}", stderr(&o));
    assert!(stderr(&o).contains("is not a cakeys Attestation Key"));
    std::fs::write(e.dir.join("keys.toml"), &base).unwrap();

    // HMAC keys attest too (TPM2_Certify covers any loaded object), pairing with `commitment`.
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
        assert_eq!(e.code(&["lock", "--spec", "hmac", "--token", "tpm"]), 0);
        assert!(e.lock()["objects"]["hmac"]["ids"].get("commitment").is_some());
        assert!(e.locked_attestation("hmac", "tpm")["id"].as_str().is_some());
        // A TPM-held secret key, certified: a fresh proof, not the replayable fingerprint a
        // commitment alone is.
        let got: serde_json::Value =
            serde_json::from_str(&stdout(&e.km(&["resolve", "--spec", "hmac", "--token", "tpm"]))).unwrap();
        assert_eq!(got["assurance"].as_str(), Some("proof"), "{got}");
    }
}

/// EK→AK activation (review D5): with `ekCertificate`, every attestation proves the AK resides in
/// the TPM the certificate names (a credential made on the host to the EK, bound to the AK's
/// Name, which only that TPM activates), and the lock pins the CA the certificate verifies to,
/// here a test CA named by `ekRoots`, rather than the AK. Refused: a CA nothing names (13), a
/// certificate over another key than the TPM's EK (13), and a change of anchor either way (14):
/// a lock made on first use until its attestation is dropped, and a locked activation that is
/// then lost. The RSA and the P-256 EK both activate.
#[test]
fn tpm2_attestation_activates_a_credential_to_the_certified_ek() {
    let Some(e) = env("activate") else { return };
    if !on_swtpm() {
        eprintln!("skipping activate: it makes persistent TPM objects, on the suite's swtpm only");
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

    // First use, as before the EK certificate: the AK's own key is the anchor.
    config("");
    assert_eq!(e.code(&lock), 0);
    let first_use = e.locked_attestation("a", "tpm")["root"].clone();
    ek("ek-ecc.pem", "other-ca.pem");
    refused(&e.km(&lock), 13, "signed by no pinned root");
    // Anchoring that attestation at the manufacturer changes its anchor, which even `lock`
    // refuses (14). Dropping the locked attestation, a reviewed edit of keys.lock, lets `lock`
    // record the new one (docs/DESIGN.md §3.7).
    ek("ek-ecc.pem", "ca.pem");
    refused(&e.km(&lock), 14, "attestation anchor");
    let mut edited = e.lock();
    edited["realisations"]["a"]["tpm"].as_table_mut().unwrap().remove("attestation").unwrap();
    e.write_lock(&edited);
    assert_eq!(e.code(&lock), 0);
    // The lock pins the test CA's key, the anchor the EK certificate verified to.
    let ca_spki =
        Command::new("openssl").args(["pkey", "-in", &path("ca.key"), "-pubout", "-outform", "DER"]).output().unwrap();
    let att = e.locked_attestation("a", "tpm");
    assert_eq!(att["root"].as_str(), Some(cakeys_core::id::sri(&ca_spki.stdout).as_str()), "{att}");
    assert_ne!(att["root"], first_use);
    let handles = persistent_handles();
    assert_eq!(e.code(&verify), 0);
    assert_eq!(e.code(&["check", "a.id.tpm-certify", "--token", "tpm"]), 0);
    // The RSA EK, certified by the same CA, activates as well: the same anchor.
    ek("ek-rsa.pem", "ca.pem");
    assert_eq!(e.code(&verify), 0);
    // A certificate the CA issued for a key that is not this TPM's EK.
    ek("ek-stranger.pem", "ca.pem");
    refused(&e.km(&verify), 13, "the EK certificate names another key than this TPM's endorsement key");
    // No EK certificate (the swtpm keeps none in NV): the AK on first use, another anchor than
    // the locked one.
    config("");
    refused(&e.km(&verify), 14, "anchor");
    // Activation leaves nothing persistent behind: the EK is recreated and flushed every time.
    assert_eq!(persistent_handles(), handles);
}

/// The session salted to the EK (review D5's transport), on the wire: swtpm's log (level 20,
/// nix/tpm2-test-env.sh) holds every command and response. With the EK certificate, neither the
/// PIN-derived seal auth (an HMAC session never sends it) nor the unsealed wrapping key (64
/// ASCII hex characters, encrypted in the response) crosses; without it, password sessions as
/// before, both do — the control that shows the capture sees them. The lockout counter stays 0:
/// no authorization of the salted session failed.
#[test]
fn tpm2_the_salted_session_keeps_the_token_secrets_off_the_wire() {
    let Some(e) = env("salted") else { return };
    if !on_swtpm() {
        eprintln!("skipping salted: it reads the suite's swtpm log, and makes the AK");
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
    // tpm2-pkcs11's seal auth: the hex text of SHA-256(PIN ‖ salt)'s first 16 bytes.
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
    // The bytes that crossed the transport during `run`: every hex dump line swtpm logged.
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
    // A run of 64 ASCII hex digits: the unsealed wrapping key, as tpm2-pkcs11 seals it.
    let has_key_text = |bytes: &[u8]| bytes.windows(64).any(|w| w.iter().all(u8::is_ascii_hexdigit));

    config(&format!("options = {{ ekCertificate = \"{}\", ekRoots = \"{}\" }}", path("ek-ecc.pem"), path("ca.pem")));
    assert_eq!(e.code(&["lock", "--spec", "a", "--token", "tpm"]), 0);
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

/// Whether `wire` holds a `TPM2_StartAuthSession` command salted to a loaded key: its `tpmKey`
/// a transient object (0x80......, the EK) rather than `TPM_RH_NULL`, and a non-empty
/// `encryptedSalt`. An unsalted HMAC session would keep the auth values off the wire too, but
/// its session key is computable from the nonces anyone on the transport sees.
fn salted_session_started(wire: &[u8]) -> bool {
    let be16 = |b: &[u8]| usize::from(u16::from_be_bytes([b[0], b[1]]));
    (0..wire.len().saturating_sub(22)).any(|i| {
        let w = &wire[i..];
        // TPM_ST_NO_SESSIONS, a size, TPM_CC_StartAuthSession.
        if w[..2] != [0x80, 0x01] || w[6..10] != [0x00, 0x00, 0x01, 0x76] || w[10] != 0x80 {
            return false;
        }
        // tpmKey (4), bind (4), nonceCaller (TPM2B), then encryptedSalt (TPM2B).
        let nonce = be16(&w[18..]);
        w.get(20 + nonce..22 + nonce).is_some_and(|s| be16(s) > 0)
    })
}

/// In `dir`, for [`tpm2_attestation_activates_a_credential_to_the_certified_ek`]: two test CAs
/// (`ca.pem`, and `other-ca.pem` that nothing trusts), and certificates from `ca` for the
/// swtpm's default P-256 and RSA EKs (`ek-ecc.pem`, `ek-rsa.pem`) and for a key that is no EK of
/// this TPM (`ek-stranger.pem`).
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
    // The CA `ekRoots` names, and one nothing names.
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
    // An EK certificate from `ca` for the public key in `public` (PEM).
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

/// The same material attested on two TPM tokens (§3.7): each attestation is per device — the
/// imported HMAC's Name differs per import (a fresh seedValue), and the qualified Name per
/// hierarchy — so each realisation pins its own, and the object links them through its one
/// portable `commitment`. Recording them on the object would make the second a mismatch.
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
    assert_eq!(e.code(&["lock", "--spec", "hmac", "--token", "tpm"]), 0);
    assert_eq!(e.code(&["lock", "--spec", "hmac", "--token", "tpm2"]), 0);
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

/// The user's portability requirement (§3.7): attestation is provenance for one device. A copy
/// of the same material on a token that attests nothing (here `SoftHSM`) verifies through the
/// portable commitment alone; the TPM realisation's attestation stays on that realisation.
#[test]
fn tpm2_attested_material_travels_to_a_second_hsm() {
    let Some(e) = env("attest-travel") else { return };
    if !hmac_types_fixed("CAKEYS_TPM_REQUIRE") {
        return;
    }
    // SoftHSM beside the TPM: required with it (the harness's preCheck sets both).
    let Some(soft) = suite_var("CAKEYS_TEST_MODULE", "CAKEYS_TPM_REQUIRE", "attest-travel") else { return };
    let pin = e.dir.join("pin").display().to_string();
    // The same HMAC material on the TPM (imported, attested) and on SoftHSM (planted, not
    // attestable: SoftHSM attests nothing).
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
    // The portable identity first, from the token without attestation; the TPM realisation
    // then joins the same object through the shared commitment scheme, pinning its attestation.
    assert_eq!(e.code(&["lock", "--spec", "hmac-soft", "--token", "soft"]), 0);
    assert_eq!(e.code(&["lock", "--spec", "hmac-tpm", "--token", "tpm"]), 0);
    let lock = e.lock();
    let ids = lock["objects"]["hmac"]["ids"].as_table().unwrap();
    assert_eq!(ids.keys().collect::<Vec<_>>(), ["commitment"], "the portable ID only: {ids:?}");
    let mut mac = <Hmac<sha2::Sha256> as KeyInit>::new_from_slice(HMAC_VALUE).unwrap();
    mac.update(b"key-management/v1/commitment/CKK_SHA256_HMAC/256");
    assert_eq!(e.locked_id("hmac", "commitment"), sri(&mac.finalize().into_bytes()));
    assert!(e.locked_attestation("hmac-tpm", "tpm")["id"].as_str().unwrap().starts_with("sha256-"));
    // The copy on the second HSM verifies through the commitment; the TPM through both.
    assert_eq!(e.code(&["check", "--spec", "hmac-soft", "--token", "soft"]), 0);
    assert_eq!(e.code(&["check", "--spec", "hmac-tpm", "--token", "tpm"]), 0);
    // Opting into attestation on a module that attests nothing is refused up front (15).
    let o = e.km(&["lock", "--spec", "hmac-attest-soft", "--token", "soft", "--dry-run"]);
    assert_eq!(code(&o), 15);
    assert!(stderr(&o).contains("attests nothing"), "{}", stderr(&o));
}

/// `pop-unwrap` (a transport key's proof, docs/CAMIGRATE.md D3): tpm2-pkcs11 never unwraps (its
/// profile's `unwraps = false`; `C_UnwrapKey` is `CKR_FUNCTION_NOT_SUPPORTED` on the real TPM,
/// tests/ftpm.rs), so an unwrap-only key is refused as unsupported (15) before it is generated.
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

/// The value of attribute `ty` in a tpm2-pkcs11 store row's attrs (YAML with explicit tags,
/// one `? !!int "<type>"` / `: !!<tag> "<value>"` pair per attribute).
fn row_value(attrs: &str, ty: u64) -> String {
    let key = format!("? !!int \"{ty}\"\n");
    let at = attrs.find(&key).unwrap_or_else(|| panic!("no attribute {ty} in\n{attrs}")) + key.len();
    let value = &attrs[at..];
    let start = value.find('"').unwrap() + 1;
    value[start..start + value[start..].find('"').unwrap()].to_owned()
}

/// Rewrite the attrs of the private-key row whose `CKA_LABEL` is `label` in the test's store,
/// as another process (the module) will read them.
fn edit_private_row(label: &str, edit: impl FnOnce(&str) -> String) {
    edit_private_row_in(&std::env::var("TPM2_PKCS11_STORE").unwrap(), label, edit);
}

/// [`edit_private_row`] in the store in directory `store`.
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

/// The native attestation holds the module's view to what the TPM certifies: a store row
/// claiming `CKA_EXTRACTABLE` where the TPM certified a key that never leaves it, or carrying
/// another key's TPM blobs under its own public key, is a conflict (13); a token whose primary
/// is transient (`tpm2_ptool init --transient-parent`) has no persistent parent to load under.
#[test]
fn tpm2_attestation_refuses_a_store_that_disagrees() {
    let Some(e) = env("attest-store") else { return };
    for label in ["store-a", "store-b"] {
        ptool(&["addkey", "--algorithm=ecc256", &format!("--key-label={label}")]);
    }
    // The proof of possession would see the swap first: this is about the attestation alone.
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

    // CKA_EXTRACTABLE (0x162) true in the store, a fixedTPM key in the TPM.
    let mut original = String::new();
    edit_private_row("store-a", |attrs| {
        original = attrs.to_owned();
        attrs.replace("? !!int \"354\"\n  : !!bool \"false\"", "? !!int \"354\"\n  : !!bool \"true\"")
    });
    refused("the module does not report what the TPM holds");
    edit_private_row("store-a", |_| original.clone());
    assert_eq!(code(&e.km(&r)), 18);

    // store-b's blobs and auth (CKA_TPM2_OBJAUTH_ENC, _PUB_BLOB, _PRIV_BLOB) under store-a's
    // attributes: the module shows store-a's point, the TPM loads and certifies store-b.
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

    // An HMAC key's blobs under the EC key's attributes: the TPM certifies a symmetric object.
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

    // A second primary, transient, with a token of its own.
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

/// A secret key's `tpm-certify` is bound to its material (review 2026-11-23 B-1): the TPM
/// computes the key's HMAC commitment again with the very object it certified, and it must be
/// the commitment the module computed. A copy of the store (`tpm2Store`) whose row for the key
/// carries another HMAC key's TPM blobs makes cakeys certify that other key while the module
/// commits with the real one: refused (13), where that other key's attestation was pinned
/// before. An AES key has no HMAC commitment for the TPM to compute again: refused (15).
#[test]
fn tpm2_a_secret_keys_attestation_is_bound_to_its_material() {
    let Some(e) = env("attest-bound") else { return };
    if !hmac_types_fixed("CAKEYS_TPM_REQUIRE") || !on_swtpm() {
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
    // The copy: bound-a's row carries bound-b's TPM blobs and auth (CKA_TPM2_OBJAUTH_ENC,
    // _PUB_BLOB, _PRIV_BLOB); the module reads the original.
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
    // The module's own store: the certified object computes the key's commitment again.
    config("");
    let o = lock("mac");
    assert_eq!(code(&o), 18, "{}", stderr(&o));
    // The copy: cakeys certifies bound-b, while the module commits with bound-a.
    config(&format!("options = {{ tpm2Store = \"{copy}\" }}"));
    let o = lock("mac");
    assert_eq!(code(&o), 13, "{}", stderr(&o));
    assert!(stderr(&o).contains("its HMAC commitment is not the one the key computes"), "{}", stderr(&o));
    // An AES key: no HMAC commitment to bind its certify to.
    config("");
    let o = lock("aes");
    assert_eq!(code(&o), 15, "{}", stderr(&o));
    assert!(stderr(&o).contains("binds a secret key to the TPM object it certifies"), "{}", stderr(&o));
}

/// Every key type tpm2-pkcs11 generates is attested with its own public area: P-384, P-521 and
/// RSA as P-256 is (`tpm2_keys_attest_their_tpm_residence`), the attested key compared with
/// the object's material.
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
            // tpm2-pkcs11 cannot sign with a P-521 key (upstream/tpm2-pkcs11/PR.md): no signing proof.
            key("p521", "keyType = \"CKK_EC\"\ncurve = \"secp521r1\"", ", binding = \"token-asserted\""),
            key("rsa", "keyType = \"CKK_RSA\"\nmodulusBits = 2048", ""),
        ]
        .concat(),
    );
    for spec in ["p384", "p521", "rsa"] {
        let o = e.km(&["create", "--spec", spec, "--token", "tpm"]);
        assert_eq!(code(&o), 0, "{spec}: {}", stderr(&o));
        assert_eq!(e.locked_attestation(spec, "tpm")["kind"].as_str(), Some("tpm-certify"), "{spec}");
        assert_eq!(e.code(&["check", "--spec", spec, "--token", "tpm"]), 0, "{spec}");
    }
}

/// The module with tpm2-pkcs11's vendor mechanisms (`CAKEYS_TPM_VENDOR_MODULE`: nixpkgs' with the
/// patches of upstream/tpm2-pkcs11/, nix/tpm2-pkcs11-vendor.nix), beside `env`'s, which has none.
fn vendor_env(name: &str) -> Option<Suite> {
    let module = suite_var("CAKEYS_TPM_VENDOR_MODULE", "CAKEYS_TPM_VENDOR_REQUIRE", name)?;
    Some(Suite::new(&format!("tpm2-{name}"), module, tpm2_tokens).checking(no_attestation_off_swtpm))
}

/// nixpkgs' module (`CAKEYS_TPM_MODULE`), which the vendor suites run beside their own: without
/// the vendor mechanisms, on the same TPM and store.
fn store_module(name: &str) -> String {
    suite_var("CAKEYS_TPM_MODULE", "CAKEYS_TPM_REQUIRE", name)
        .unwrap_or_else(|| panic!("{name}: the vendor module is set, CAKEYS_TPM_MODULE is not"))
}

/// `[tokens.<name>]` on `module` and the suite's token `kmtest`, logged in, with `extra` lines.
fn token_of(e: &Suite, name: &str, module: &str, extra: &str) -> String {
    format!(
        "[tokens.{name}]\nmodule = \"{module}\"\ntokenLabel = \"kmtest\"\npinFile = \"{}\"\nprobe = {{ scratch = true }}\n{extra}\n\n",
        e.dir.join("pin").display()
    )
}

/// One P-256 key `label`, created on token `tpm` (and adopted on `others`), attested.
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

/// A module with `CKM_TPM2_CERTIFY` certifies the key itself, and the attestation is the one the
/// store path makes of the same key: the same ID, the same root (the persistent Attestation Key
/// stays the signer). The vendor token is told no store exists, so reading one would fail; the
/// `store` token is nixpkgs' module, without the mechanism, on the same TPM and store.
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
        // The persistent AK is read from the TPM: no caveat, unlike akLabel's (review 2026-11-23 B-2).
        assert!(!stderr(&o).contains("only the module vouches for"), "{token}: {}", stderr(&o));
        serde_json::from_str(&stdout(&o)).unwrap()
    };
    let (vendor, store) = (resolve("tpm"), resolve("store"));
    assert!(vendor["attestation"]["id"].as_str().unwrap().starts_with("sha256-"));
    assert_eq!(vendor["attestation"]["id"], store["attestation"]["id"], "one key, one attestation ID");
    assert_eq!(vendor["attestation"]["root"], store["attestation"]["root"], "the same persistent AK signed");
    // Each realisation, locked through its own path, verifies: the same ID and root were pinned.
    for token in ["tpm", "store"] {
        assert_eq!(e.code(&recording(&["lock", "--spec", "p256", "--token", token, "--dry-run"])), 0, "{token}");
    }
    assert_eq!(e.locked_attestation("p256", "tpm"), e.locked_attestation("p256", "store"));
    for token in ["tpm", "store"] {
        assert_eq!(e.code(&["check", "--spec", "p256", "--token", token]), 0, "{token}");
    }
}

/// An Attestation Key that is an object of the token (`akLabel`, `CKM_TPM2_AK_PAIR_GEN`): made by
/// `lock`, never by a read, and the attestation needs no TCTI, no TPM handle and no store (the token
/// is told none exists). Another key than the persistent one, so another root; a key that is no
/// Attestation Key is never trusted as one, and a module without the mechanisms is said so.
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
    assert_eq!(e.code(&recording(&["lock", "--spec", "p256", "--token", "tpm", "--dry-run"])), 0);
    let att = e.locked_attestation("p256", "tpm");
    assert_eq!(att["kind"].as_str(), Some("tpm-certify"));
    for _ in 0..2 {
        // Each run says what this signer cannot establish: only the module vouches for it
        // (review 2026-11-23 B-2: nothing said so).
        let o = e.km(&["check", "--spec", "p256", "--token", "tpm"]);
        assert_eq!(code(&o), 0, "{}", stderr(&o));
        assert!(stderr(&o).contains("its tpm-certify signer (akLabel) is a key only the module vouches for"));
        assert_eq!(e.code(&["check", "p256.id.tpm-certify", "--token", "tpm"]), 0);
    }
    // No persistent AK was made: the TPM's handles are as they were.
    assert_eq!(before.map(|b| b == persistent_handles()), on_swtpm().then_some(true));
    // The Attestation Key is on the token, and the next run reuses it (a stable root).
    assert!(labelled(&e.session(), "cakeys-ak") >= 1);
    let again = e.km(&["resolve", "--spec", "p256", "--token", "tpm"]);
    let got: serde_json::Value = serde_json::from_str(&stdout(&again)).unwrap();
    assert_eq!(got["attestation"]["root"].as_str(), att["root"].as_str());

    // Reads never make one: another label is a downgrade (14), naming it.
    config(&format!("akLabel = \"other-ak\", {none}"));
    for _ in 0..2 {
        let o = e.km(&["check", "--spec", "p256", "--token", "tpm"]);
        assert_eq!(code(&o), 14, "{}", stderr(&o));
        assert!(stderr(&o).contains("no Attestation Key labelled \"other-ak\""), "{}", stderr(&o));
    }
    // An ordinary key is no Attestation Key: it could sign a forged statement (13).
    config(&format!("akLabel = \"vendor-ak-p256\", {none}"));
    let o = e.km(&["check", "--spec", "p256", "--token", "tpm"]);
    assert_eq!(code(&o), 13, "{}", stderr(&o));
    assert!(stderr(&o).contains("is not a cakeys Attestation Key"), "{}", stderr(&o));
    // Both Attestation Keys at once are two answers to one question (17).
    config("akLabel = \"cakeys-ak\", akHandle = \"0x81000017\"");
    assert_eq!(e.code(&["check", "--spec", "p256", "--token", "tpm"]), 17);

    // nixpkgs' module has no such mechanism: asked for, it is said so, not read around — an
    // attestation that cannot be computed is a downgrade of the locked one (14).
    let store_module = store_module("vendor-ak");
    e.write_config(
        &(token_of(&e, "tpm", &store_module, "options = { akLabel = \"cakeys-ak\" }")
            + &p256_spec("vendor-ak-p256", &[])),
    );
    let o = e.km(&["check", "--spec", "p256", "--token", "tpm"]);
    assert_eq!(code(&o), 14, "{}", stderr(&o));
    assert!(stderr(&o).contains("CKM_TPM2_AK_PAIR_GEN"), "{}", stderr(&o));
}

/// Where the attestation finds the store and the TPM: a TCTI named in the token's options, and
/// — with `TPM2_PKCS11_STORE` unset — the module's own search path (`~/.tpm2_pkcs11`). A store
/// named in the options that holds another token is not found (11).
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

    // No TPM2_PKCS11_STORE: the store under $HOME, where the module looks too.
    config("");
    let home = e.dir.join("home");
    std::fs::create_dir_all(&home).unwrap();
    std::os::unix::fs::symlink(&store, home.join(".tpm2_pkcs11")).unwrap();
    let o = e.run().env_remove("TPM2_PKCS11_STORE").env("HOME", &home).output(&r);
    assert_eq!(code(&o), 18, "the store under $HOME: {}", stderr(&o));

    // A store of another token, named in the options.
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

/// The object matrix (`tests/object_matrix/`) on tpm2-pkcs11, against the software TPM only:
/// hundreds of objects, some of which tpm2-pkcs11 cannot destroy, have no place on a TPM the
/// platform depends on (docs/DEVELOPMENT.md, "Hardware rules"). The store is the test's own and
/// fresh, so the table is the same every run.
#[test]
fn tpm2_object_matrix_is_the_committed_one() {
    let Some(e) = env("object-matrix") else { return };
    if !on_swtpm() {
        eprintln!("skipping: the object matrix runs on the suite's swtpm only");
        return;
    }
    object_matrix::check(&object_matrix::Target {
        name: "tpm2-pkcs11+swtpm",
        token: "tpm",
        tokens: &|dir| tpm2_tokens(&e.module, dir),
        session: &|| e.session(),
        batch: 8,
        dir: &e.dir,
        // tpm2-abrmd serialises the TPM: more gains nothing.
        workers: 4,
    });
}

/// Whether this suite's TPM is the software one `nix/tpm2-test-env.sh` started (its private bus
/// is named for it). The same suite shape can be pointed at a real TPM (`nix/ftpm-test-env.sh`):
/// a test that changes TPM state beyond the token's own objects runs only here
/// (docs/DEVELOPMENT.md, "Hardware rules").
///
/// The script says so (`CAKEYS_TPM_SWTPM`), and the TPM agrees: its vendor strings are swtpm's,
/// "SW  " " TPM" \[run\]. A marker on another TPM is a misconfigured run and fails; so does a
/// suite that requires the TPM (`CAKEYS_TPM_REQUIRE`) on any other: the steps that change the
/// TPM are part of what it requires, never skipped quietly (review tpm2.rs F3). It was a D-Bus
/// address substring, and a renamed bus skipped them with every test passing.
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

/// Whether the TPM's fixed properties carry swtpm's vendor strings (`TPM2_PT_VENDOR_STRING_1`
/// and `_2`, "SW  " and " TPM").
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

/// What `tpm2_getcap handles-persistent` lists: the TPM's persistent handles.
fn persistent_handles() -> String {
    let out = Command::new("tpm2_getcap").arg("handles-persistent").output().unwrap();
    assert!(out.status.success(), "tpm2_getcap handles-persistent: {}", stderr(&out));
    stdout(&out)
}

/// `tpm2_<tool> <args>` against the suite's software TPM.
fn tpm2_tool(tool: &str, args: &[&str]) {
    assert!(on_swtpm(), "tpm2_{tool} changes the TPM: only against the suite's swtpm");
    let out = Command::new(format!("tpm2_{tool}")).args(args).output().unwrap();
    assert!(out.status.success(), "tpm2_{tool} {args:?}: {}", stderr(&out));
}

/// What the attestation needs and does not find is said, and nothing is attested: a store
/// directory that does not exist (`~` left as written with no `$HOME`), a module (the fault shim
/// in front of tpm2-pkcs11) that withholds the `CKA_ID` the store row is found by, a key at the AK handle
/// that is no cakeys Attestation Key (13: it could sign forged attestations), and an owner
/// hierarchy with an auth value, in which no Attestation Key can be made.
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
    // Behind a module that withholds the object's CKA_ID there is no store row to find it by
    // (15); one that withholds its label is found by the CKA_ID alone.
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

    if !on_swtpm() {
        eprintln!("skipping the Attestation Key cases: they change the TPM, and this is not the suite's swtpm");
        return;
    }
    // An RSA storage key where the Attestation Key is looked for.
    let primary = e.dir.join("primary.ctx");
    let primary = primary.to_str().unwrap();
    tpm2_tool("createprimary", &["-C", "o", "-G", "rsa2048", "-c", primary]);
    tpm2_tool("evictcontrol", &["-C", "o", "-c", primary, "0x81000017"]);
    config(&format!("{pin}\noptions = {{ akHandle = \"0x81000017\" }}"));
    refused(&e.km(&r), 13, "the object at akHandle 0x81000017 is not a cakeys Attestation Key");

    // A free handle, and an owner hierarchy cakeys has no auth value for.
    tpm2_tool("changeauth", &["-c", "owner", "an owner password"]);
    config(&format!("{pin}\noptions = {{ akHandle = \"0x81000018\" }}"));
    refused(&e.km(&r), 16, "creating the Attestation Key in the owner hierarchy (is owner auth empty?)");
}
