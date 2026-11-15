//! End-to-end tests against tpm2-pkcs11 on a software TPM (nix/tpm2-test-env.sh).
//!
//! Needs `CAKEYS_TPM_MODULE` (`libtpm2_pkcs11.so`), the `TPM2_PKCS11_*` environment from the harness,
//! a token `kmtest` with user PIN `1234`, and `tpm2_ptool` on PATH. Skipped when
//! `CAKEYS_TPM_MODULE` is unset, unless `CAKEYS_TPM_REQUIRE=1`.

mod common;

use common::*;
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, ObjectClass};
use cryptoki::session::Session;
use hmac::{Hmac, KeyInit, Mac};
use std::process::Command;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

struct Env {
    w: Workdir,
    module: String,
}

impl std::ops::Deref for Env {
    type Target = Workdir;
    fn deref(&self) -> &Workdir {
        &self.w
    }
}

fn env(name: &str) -> Option<Env> {
    let Ok(module) = std::env::var("CAKEYS_TPM_MODULE") else {
        assert!(std::env::var("CAKEYS_TPM_REQUIRE").is_err(), "CAKEYS_TPM_MODULE is required");
        eprintln!("skipping {name}: CAKEYS_TPM_MODULE not set");
        return None;
    };
    Some(Env { w: Workdir::new(&format!("tpm2-{name}")), module })
}

impl Env {
    /// keys.toml: the suite's tokens ([`tpm2_tokens`]) and `body`.
    fn config(&self, body: &str) {
        self.write_config(&(tpm2_tokens(&self.module, &self.dir) + body));
    }

    /// The attestation a realisation pins (§3.7: per realisation, never in the object's ids).
    fn locked_attestation(&self, spec: &str, token: &str) -> toml::Value {
        self.lock()["realisations"][spec][token]["attestation"].clone()
    }

    /// `tpm2_ptool <args> --label kmtest --userpin 1234 --path $TPM2_PKCS11_STORE`.
    #[expect(clippy::unused_self, reason = "the fixture helpers sit in an impl so the call sites read uniformly")]
    fn ptool(&self, args: &[&str]) {
        let store = std::env::var("TPM2_PKCS11_STORE").unwrap();
        let out = Command::new("tpm2_ptool")
            .args(args)
            .args(["--label=kmtest", "--userpin=1234", &format!("--path={store}")])
            .output()
            .unwrap();
        assert!(out.status.success(), "tpm2_ptool {args:?}: {}", stderr(&out));
    }

    /// A fresh session: tpm2-pkcs11 loads the object list when a session opens, so objects
    /// created by another process afterwards are invisible to it.
    fn session(&self) -> TestSession {
        open_session(&self.module, "kmtest", "1234")
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
    e.ptool(&["addkey", "--algorithm=aes256", "--key-label=refusal-aes"]);
    e.config(
        r#"
[objects.aes-gen]
class = "CKO_SECRET_KEY"
keyType = "CKK_AES"
valueLen = 32

[specs.aes-gen]
object = "aes-gen"
attributes = { CKA_ENCRYPT = true }
tokens.tpm = { locator = { CKA_LABEL = "refusal-aes-gen" }, autoCreate = true }

[objects.hmac-gen]
class = "CKO_SECRET_KEY"
keyType = "CKK_SHA256_HMAC"
valueLen = 32

[specs.hmac-gen]
object = "hmac-gen"
attributes = { CKA_SIGN = true }
tokens.tpm = { locator = { CKA_LABEL = "refusal-hmac-gen" }, autoCreate = true }

[objects.ed]
class = "CKO_PRIVATE_KEY"
keyType = "CKK_EC_EDWARDS"
curve = "edwards25519"

[specs.ed]
object = "ed"
attributes = { CKA_SIGN = true }
tokens.tpm = { locator = { CKA_LABEL = "refusal-ed" }, autoCreate = true }

[objects.aes]
class = "CKO_SECRET_KEY"
keyType = "CKK_AES"
valueLen = 32

[specs.aes-mac]
object = "aes"
attributes = { CKA_SIGN = true }
tokens.tpm = { locator = { CKA_LABEL = "refusal-aes" } }

[objects.des3]
class = "CKO_SECRET_KEY"
keyType = "CKK_DES3"

[specs.des3]
object = "des3"
attributes = { CKA_ENCRYPT = true }
tokens.tpm = { locator = { CKA_LABEL = "refusal-des3" }, autoCreate = true }
"#,
    );
    // No Triple DES in a TPM (TPM2 symmetric keys are AES): neither the check value nor the
    // generation, refused from what the module lists before anything is created.
    let o = e.km(&["realise", "des3", "--token", "tpm", "--no-update-lock"]);
    assert_eq!(code(&o), 15, "{}", stderr(&o));
    assert!(stderr(&o).contains("CKM_DES3_ECB"), "{}", stderr(&o));
    assert_eq!(labelled(&e.session(), "refusal-des3"), 0);
    // Secret-key generation is refused up front, with the provider's advice, and creates nothing.
    for (spec, label) in [("aes-gen", "refusal-aes-gen"), ("hmac-gen", "refusal-hmac-gen")] {
        let o = e.km(&["realise", spec, "--token", "tpm", "--no-update-lock"]);
        assert_eq!(code(&o), 15, "{spec}");
        assert!(stderr(&o).contains("tpm2_ptool addkey"), "{spec}");
        assert_eq!(labelled(&e.session(), label), 0, "{spec}");
    }
    assert_eq!(e.code(&["realise", "ed", "--token", "tpm", "--no-update-lock"]), 15);
    // No CKM_AES_CMAC: a sign-only AES spec has no commitment here.
    assert_eq!(e.code(&["realise", "aes-mac", "--token", "tpm", "--no-update-lock"]), 15);
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
             tokens.tpm = {{ locator = {{ CKA_LABEL = \"{k}\" }}, autoCreate = true{binding} }}\n\n\
             [specs.{k}-pub]\nobject = \"{k}\"\n\
             tokens.tpm-anon = {{ locator = {{ CKA_LABEL = \"{k}\" }}, publicOnly = true }}\n\n"
        );
    }
    e.config(&body);
    for (k, _) in kinds {
        let spec = format!("{k}-gen");
        let first = e.km(&["realise", &spec, "--token", "tpm", "--no-update-lock"]);
        assert_eq!(code(&first), 10, "{k}");
        assert_eq!(
            got_hash(&e.km(&["realise", &spec, "--token", "tpm", "--no-update-lock"])),
            got_hash(&first),
            "{k}: no duplicate"
        );
        assert_eq!(e.code(&["realise", &spec, "--token", "tpm", "--update-lock"]), 0, "{k}");
        // A session opened now: tpm2-pkcs11 sessions don't see objects created after they opened.
        assert_eq!(e.locked_id(k, "rfc7093m4"), sri(&oracle_spki_with(&e.session(), k, unwrap_tpm2)), "{k}");
        let binding = if k == "tpm-p521" { "token-asserted" } else { "pop-sign" };
        assert_eq!(e.lock()["realisations"][&spec]["tpm"]["binding"].as_str(), Some(binding), "{k}");
        let pubs = format!("{k}-pub");
        assert_eq!(e.code(&["realise", &pubs, "--token", "tpm-anon", "--update-lock"]), 0, "{k}");
    }
}

#[test]
fn tpm2_identity_failure_after_create_leaves_nothing() {
    let Some(e) = env("orphan") else { return };
    // Without the provider, tpm2-pkcs11's P-521 point is rejected after the key was generated.
    e.config(
        "[objects.p]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp521r1\"\n\n\
         [specs.p]\nobject = \"p\"\nattributes = { CKA_SIGN = true }\ntokens.tpm-generic = { locator = { CKA_LABEL = \"orphan-p521\" }, autoCreate = true }\n",
    );
    let o = e.km(&["realise", "p", "--token", "tpm-generic", "--no-update-lock"]);
    assert_eq!(code(&o), 13);
    assert!(stderr(&o).contains("removed 2 object(s) just created"));
    assert_eq!(labelled(&e.session(), "orphan-p521"), 0);
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
         tokens.tpm = { locator = { CKA_LABEL = \"ecdh-p256\" }, autoCreate = true, binding = \"pop-ecdh\" }\n",
    );
    let o = e.km(&["realise", "p", "--token", "tpm", "--update-lock"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert_eq!(e.lock()["realisations"]["p"]["tpm"]["binding"].as_str(), Some("pop-ecdh"));
    let o = e.km(&["verify", "p", "--token", "tpm"]);
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
    if !cryptoki_hmac_types_fixed(std::env::var("CAKEYS_TPM_REQUIRE").is_ok()) {
        return;
    }
    e.ptool(&[
        "import",
        "--algorithm=ecc",
        &format!("--privkey={FIXTURES}/tpm-import-p256.pem"),
        "--key-label=imp-p256",
    ]);
    e.ptool(&[
        "import",
        "--algorithm=rsa",
        &format!("--privkey={FIXTURES}/tpm-import-rsa2048.pem"),
        "--key-label=imp-rsa",
    ]);
    let hmac_file = e.dir.join("hmac.bin");
    std::fs::write(&hmac_file, HMAC_VALUE).unwrap();
    e.ptool(&[
        "import",
        "--algorithm=hmac:sha256",
        &format!("--privkey={}", hmac_file.display()),
        "--key-label=imp-hmac",
    ]);
    let hmac384_file = e.dir.join("hmac384.bin");
    std::fs::write(&hmac384_file, HMAC384_VALUE).unwrap();
    e.ptool(&[
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
tokens.tpm = { locator = { CKA_LABEL = "imp-p256" } }

[objects.rsa]
class = "CKO_PRIVATE_KEY"
keyType = "CKK_RSA"
modulusBits = 2048

[specs.rsa]
object = "rsa"
tokens.tpm-anon = { locator = { CKA_LABEL = "imp-rsa" }, publicOnly = true }

[objects.hmac]
class = "CKO_SECRET_KEY"
keyType = "CKK_SHA256_HMAC"
valueLen = 32

# tpm2_ptool marks imported keys CKA_EXTRACTABLE = true; commitment (CKA_SIGN) is preferred.
[specs.hmac]
object = "hmac"
attributes = { CKA_SIGN = true, CKA_EXTRACTABLE = true }
tokens.tpm = { locator = { CKA_LABEL = "imp-hmac" } }

[objects.hmac384]
class = "CKO_SECRET_KEY"
keyType = "CKK_SHA384_HMAC"
valueLen = 48

[specs.hmac384]
object = "hmac384"
attributes = { CKA_SIGN = true }
tokens.tpm = { locator = { CKA_LABEL = "imp-hmac384" } }
"#,
    );
    for (spec, token) in [("p256", "tpm"), ("rsa", "tpm-anon"), ("hmac", "tpm"), ("hmac384", "tpm")] {
        assert_eq!(e.code(&["realise", spec, "--token", token, "--update-lock"]), 0, "{spec}");
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
    e.ptool(&["addkey", "--algorithm=aes256", "--key-label=kcv-aes"]);
    e.config(
        "[objects.aes]\nclass = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_AES\"\nvalueLen = 32\n\n\
         [specs.aes]\nobject = \"aes\"\nattributes = { CKA_ENCRYPT = true, CKA_SENSITIVE = true }\n\
         tokens.tpm = { locator = { CKA_LABEL = \"kcv-aes\" } }\n",
    );
    let r = ["realise", "aes", "--token", "tpm", "--no-update-lock"];
    let first = e.km(&r);
    assert_eq!(code(&first), 10);
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
         tokens.tpm = { locator = { CKA_LABEL = \"tpm-data\" } }\n\n\
         [specs.blob-undeclared]\nobject = \"blob\"\n\
         tokens.tpm = { locator = { CKA_LABEL = \"tpm-data\" } }\n",
    );
    // Undeclared, its hash would be an offline guessing oracle nobody agreed to: refused.
    let o = e.km(&["realise", "blob-undeclared", "--token", "tpm", "--update-lock"]);
    assert_eq!(code(&o), 15, "{}", stderr(&o));
    assert!(stderr(&o).contains("declare CKA_PRIVATE = true"), "{}", stderr(&o));
    let o = e.km(&["realise", "blob", "--token", "tpm", "--update-lock"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert_eq!(e.locked_id("blob", "valuehash"), sri(&value));
    assert_eq!(e.code(&["check", "blob", "--spec", "blob"]), 0);
}

/// The `tpm-certify` commitment (§3.7 of docs/DESIGN.md): a native `TPM2_Certify` over the
/// object's Name, host-verified against a provisioned AK, and cross-checked against the
/// material `rfc7093m4` names.
#[test]
fn tpm2_keys_attest_their_tpm_residence() {
    let Some(e) = env("attest") else { return };
    // A generated EC key (9a slot style): attested on the TPM, once the AK is provisioned.
    e.config(
        "[objects.p256]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n\
         [specs.p256]\nobject = \"p256\"\nattributes = { CKA_SIGN = true }\n\
         tokens.tpm = { locator = { CKA_LABEL = \"attest-p256\" }, autoCreate = true, attestation = true }\n",
    );
    let r = ["realise", "p256", "--token", "tpm", "--no-update-lock"];
    let first = e.km(&r);
    assert_eq!(code(&first), 10, "first use: got the ID, the lock is written by review");
    let got: serde_json::Value = serde_json::from_str(&stdout(&e.km(&["resolve", "p256", "--token", "tpm"]))).unwrap();
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
    assert_eq!(e.code(&["verify", "p256", "--token", "tpm"]), 0);
    assert_eq!(e.code(&["check", "p256.id.tpm-certify", "--token", "tpm"]), 0);
    // The AK is persistent at the default handle: a second run reuses it, so the root is stable.
    let again = e.km(&["resolve", "p256", "--token", "tpm"]);
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
        let o = e.km(&["verify", "p256", "--token", "tpm"]);
        assert_eq!(code(&o), 14, "{}", stderr(&o));
        assert!(stderr(&o).contains("no Attestation Key at 0x81000017"));
    }
    // A key at the AK handle that is not a restricted signing key is never trusted as the AK:
    // an unrestricted one could sign a forged attestation.
    let ctx = e.dir.join("storage.ctx");
    for args in [
        vec!["tpm2_createprimary", "-C", "o", "-G", "ecc", "-c", ctx.to_str().unwrap()],
        vec!["tpm2_evictcontrol", "-C", "o", "-c", ctx.to_str().unwrap(), "0x81000018"],
    ] {
        let out = Command::new(args[0]).args(&args[1..]).output().unwrap();
        assert!(out.status.success(), "{args:?}: {}", stderr(&out));
    }
    std::fs::write(e.dir.join("keys.toml"), alt("0x81000018")).unwrap();
    let o = e.km(&r);
    assert_eq!(code(&o), 13, "{}", stderr(&o));
    assert!(stderr(&o).contains("is not a cakeys Attestation Key"));
    std::fs::write(e.dir.join("keys.toml"), &base).unwrap();

    // HMAC keys attest too (TPM2_Certify covers any loaded object), pairing with `commitment`.
    if cryptoki_hmac_types_fixed(false) {
        let hmac_file = e.dir.join("hmac.bin");
        std::fs::write(&hmac_file, HMAC_VALUE).unwrap();
        e.ptool(&[
            "import",
            "--algorithm=hmac:sha256",
            &format!("--privkey={}", hmac_file.display()),
            "--key-label=attest-hmac",
        ]);
        e.config(
            "[objects.hmac]\nclass = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_SHA256_HMAC\"\nvalueLen = 32\n\n\
             [specs.hmac]\nobject = \"hmac\"\nattributes = { CKA_SIGN = true, CKA_EXTRACTABLE = true }\n\
             tokens.tpm = { locator = { CKA_LABEL = \"attest-hmac\" }, attestation = true }\n",
        );
        assert_eq!(e.code(&["realise", "hmac", "--token", "tpm", "--update-lock"]), 0);
        assert!(e.lock()["objects"]["hmac"]["ids"].get("commitment").is_some());
        assert!(e.locked_attestation("hmac", "tpm")["id"].as_str().is_some());
        // A TPM-held secret key, certified: a fresh proof, not the replayable fingerprint a
        // commitment alone is.
        let got: serde_json::Value =
            serde_json::from_str(&stdout(&e.km(&["resolve", "hmac", "--token", "tpm"]))).unwrap();
        assert_eq!(got["assurance"].as_str(), Some("proof"), "{got}");
    }
}

/// The same material attested on two TPM tokens (§3.7): each attestation is per device — the
/// imported HMAC's Name differs per import (a fresh seedValue), and the qualified Name per
/// hierarchy — so each realisation pins its own, and the object links them through its one
/// portable `commitment`. Recording them on the object would make the second a mismatch.
#[test]
fn tpm2_each_token_pins_its_own_attestation() {
    let Some(e) = env("attest-two") else { return };
    if !cryptoki_hmac_types_fixed(std::env::var("CAKEYS_TPM_REQUIRE").is_ok()) {
        return;
    }
    let store = std::env::var("TPM2_PKCS11_STORE").unwrap();
    let ptool = |args: &[&str]| {
        let out = Command::new("tpm2_ptool").args(args).arg(format!("--path={store}")).output().unwrap();
        assert!(out.status.success(), "tpm2_ptool {args:?}: {}", stderr(&out));
    };
    ptool(&["addtoken", "--pid=1", "--label=kmtest2", "--sopin=5678", "--userpin=1234"]);
    let hmac_file = e.dir.join("hmac.bin");
    std::fs::write(&hmac_file, HMAC_VALUE).unwrap();
    for label in ["kmtest", "kmtest2"] {
        ptool(&[
            "import",
            "--algorithm=hmac:sha256",
            &format!("--privkey={}", hmac_file.display()),
            "--key-label=two-hmac",
            &format!("--label={label}"),
            "--userpin=1234",
        ]);
    }
    let pin = e.dir.join("pin").display().to_string();
    e.config(&format!(
        "[tokens.tpm2]\nmodule = \"{}\"\ntokenLabel = \"kmtest2\"\npinFile = \"{pin}\"\n\n\
         [objects.hmac]\nclass = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_SHA256_HMAC\"\nvalueLen = 32\n\n\
         [specs.hmac]\nobject = \"hmac\"\nattributes = {{ CKA_SIGN = true, CKA_EXTRACTABLE = true }}\n\
         tokens.tpm = {{ locator = {{ CKA_LABEL = \"two-hmac\" }}, attestation = true }}\n\
         tokens.tpm2 = {{ locator = {{ CKA_LABEL = \"two-hmac\" }}, attestation = true }}\n",
        e.module
    ));
    assert_eq!(e.code(&["realise", "hmac", "--token", "tpm", "--update-lock"]), 0);
    assert_eq!(e.code(&["realise", "hmac", "--token", "tpm2", "--update-lock"]), 0);
    let lock = e.lock();
    let ids = lock["objects"]["hmac"]["ids"].as_table().unwrap();
    assert_eq!(ids.keys().collect::<Vec<_>>(), ["commitment"], "{ids:?}");
    let (one, two) = (e.locked_attestation("hmac", "tpm"), e.locked_attestation("hmac", "tpm2"));
    assert_ne!(one["id"].as_str(), two["id"].as_str(), "two imports, two TPM objects, two attestations");
    assert_eq!(one["root"].as_str(), two["root"].as_str(), "one TPM, one AK");
    for t in ["tpm", "tpm2"] {
        assert_eq!(e.code(&["verify", "hmac", "--token", t]), 0);
    }
}

/// The user's portability requirement (§3.7): attestation is provenance for one device. A copy
/// of the same material on a token that attests nothing (here `SoftHSM`) verifies through the
/// portable commitment alone; the TPM realisation's attestation stays on that realisation.
#[test]
fn tpm2_attested_material_travels_to_a_second_hsm() {
    let Some(e) = env("attest-travel") else { return };
    if !cryptoki_hmac_types_fixed(std::env::var("CAKEYS_TPM_REQUIRE").is_ok()) {
        return;
    }
    let soft = std::env::var("CAKEYS_TEST_MODULE").expect("the SoftHSM module (harness preCheck)");
    let pin = e.dir.join("pin").display().to_string();
    // The same HMAC material on the TPM (imported, attested) and on SoftHSM (planted, not
    // attestable: SoftHSM attests nothing).
    let hmac_file = e.dir.join("hmac.bin");
    std::fs::write(&hmac_file, HMAC_VALUE).unwrap();
    e.ptool(&[
        "import",
        "--algorithm=hmac:sha256",
        &format!("--privkey={}", hmac_file.display()),
        "--key-label=travel-hmac",
    ]);
    e.config(&format!(
        "[tokens.soft]\nmodule = \"{soft}\"\ntokenLabel = \"kmtest\"\npinFile = \"{pin}\"\n\n\
         [objects.hmac]\nclass = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_SHA256_HMAC\"\nvalueLen = 32\n\n\
         [specs.hmac-tpm]\nobject = \"hmac\"\nattributes = {{ CKA_SIGN = true, CKA_EXTRACTABLE = true }}\n\
         tokens.tpm = {{ locator = {{ CKA_LABEL = \"travel-hmac\" }}, attestation = true }}\n\n\
         [specs.hmac-soft]\nobject = \"hmac\"\nattributes = {{ CKA_SIGN = true }}\n\
         tokens.soft = {{ locator = {{ CKA_LABEL = \"travel-hmac\" }} }}\n\n\
         [specs.hmac-attest-soft]\nobject = \"hmac\"\nattributes = {{ CKA_SIGN = true }}\n\
         tokens.soft = {{ locator = {{ CKA_LABEL = \"travel-hmac\" }}, attestation = true }}\n",
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
    assert_eq!(e.code(&["realise", "hmac-soft", "--token", "soft", "--update-lock"]), 0);
    assert_eq!(e.code(&["realise", "hmac-tpm", "--token", "tpm", "--update-lock"]), 0);
    let lock = e.lock();
    let ids = lock["objects"]["hmac"]["ids"].as_table().unwrap();
    assert_eq!(ids.keys().collect::<Vec<_>>(), ["commitment"], "the portable ID only: {ids:?}");
    let mut mac = <Hmac<sha2::Sha256> as KeyInit>::new_from_slice(HMAC_VALUE).unwrap();
    mac.update(b"key-management/v1/commitment/CKK_SHA256_HMAC/256");
    assert_eq!(e.locked_id("hmac", "commitment"), sri(&mac.finalize().into_bytes()));
    assert!(e.locked_attestation("hmac-tpm", "tpm")["id"].as_str().unwrap().starts_with("sha256-"));
    // The copy on the second HSM verifies through the commitment; the TPM through both.
    assert_eq!(e.code(&["verify", "hmac-soft", "--token", "soft"]), 0);
    assert_eq!(e.code(&["verify", "hmac-tpm", "--token", "tpm"]), 0);
    // Opting into attestation on a module that attests nothing is refused up front (15).
    let o = e.km(&["realise", "hmac-attest-soft", "--token", "soft", "--no-update-lock"]);
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
         tokens.tpm = { locator = { CKA_LABEL = \"refusal-unwrap\" }, autoCreate = true, binding = \"pop-unwrap\" }\n",
    );
    let o = e.km(&["realise", "u", "--token", "tpm", "--no-update-lock"]);
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
    let store = std::env::var("TPM2_PKCS11_STORE").unwrap();
    let db = rusqlite::Connection::open(std::path::Path::new(&store).join("tpm2_pkcs11.sqlite3")).unwrap();
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
        e.ptool(&["addkey", "--algorithm=ecc256", &format!("--key-label={label}")]);
    }
    // The proof of possession would see the swap first: this is about the attestation alone.
    e.config(
        "[objects.a]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n\
         [specs.a]\nobject = \"a\"\nattributes = { CKA_SIGN = true }\n\
         tokens.tpm = { locator = { CKA_LABEL = \"store-a\" }, attestation = true, binding = \"token-asserted\" }\n",
    );
    let r = ["realise", "a", "--token", "tpm", "--no-update-lock"];
    let o = e.km(&r);
    assert_eq!(code(&o), 10, "{}", stderr(&o));
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
    refused("the store does not match what the TPM holds");
    edit_private_row("store-a", |_| original.clone());
    assert_eq!(code(&e.km(&r)), 10);

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
    e.ptool(&[
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
    refused("the store object is a symmetric object, but the PKCS#11 object is an asymmetric key");

    // A second primary, transient, with a token of its own.
    let store = std::env::var("TPM2_PKCS11_STORE").unwrap();
    let path = format!("--path={store}");
    for args in [
        vec!["init", "--transient-parent=tpm2-tools-default", &path],
        vec!["addtoken", "--pid=2", "--label=kmtrans", "--sopin=5678", "--userpin=1234", &path],
        vec!["addkey", "--algorithm=ecc256", "--label=kmtrans", "--userpin=1234", "--key-label=trans", &path],
    ] {
        let out = Command::new("tpm2_ptool").args(&args).output().unwrap();
        assert!(out.status.success(), "tpm2_ptool {args:?}: {}", stderr(&out));
    }
    e.write_config(&format!(
        "[tokens.trans]\nmodule = \"{}\"\ntokenLabel = \"kmtrans\"\npinFile = \"{}\"\n\n\
         [objects.t]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n\
         [specs.t]\nobject = \"t\"\nattributes = {{ CKA_SIGN = true }}\n\
         tokens.trans = {{ locator = {{ CKA_LABEL = \"trans\" }}, attestation = true }}\n",
        e.module,
        e.dir.join("pin").display()
    ));
    let o = e.km(&["realise", "t", "--token", "trans", "--no-update-lock"]);
    assert!(stderr(&o).contains("the token's primary is transient"), "{}", stderr(&o));
    assert_eq!(code(&o), 16, "{}", stderr(&o));
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
             tokens.tpm = {{ locator = {{ CKA_LABEL = \"types-{name}\" }}, autoCreate = true, attestation = true{binding} }}\n\n"
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
        let o = e.km(&["realise", spec, "--token", "tpm", "--update-lock"]);
        assert_eq!(code(&o), 0, "{spec}: {}", stderr(&o));
        assert_eq!(e.locked_attestation(spec, "tpm")["kind"].as_str(), Some("tpm-certify"), "{spec}");
        assert_eq!(e.code(&["verify", spec, "--token", "tpm"]), 0, "{spec}");
    }
}

/// Where the attestation finds the store and the TPM: a TCTI named in the token's options, and
/// — with `TPM2_PKCS11_STORE` unset — the module's own search path (`~/.tpm2_pkcs11`). A store
/// named in the options that holds another token is not found (11).
#[test]
fn tpm2_attestation_finds_its_store_and_tpm_as_configured() {
    let Some(e) = env("attest-find") else { return };
    e.ptool(&["addkey", "--algorithm=ecc256", "--key-label=find-a"]);
    let store = std::env::var("TPM2_PKCS11_STORE").unwrap();
    let tcti = std::env::var("TPM2_PKCS11_TCTI").unwrap();
    let config = |options: &str| {
        e.write_config(&format!(
            "[tokens.tpm]\nmodule = \"{}\"\ntokenLabel = \"kmtest\"\npinFile = \"{}\"\n{options}\n\n\
             [objects.a]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n\
             [specs.a]\nobject = \"a\"\nattributes = {{ CKA_SIGN = true }}\n\
             tokens.tpm = {{ locator = {{ CKA_LABEL = \"find-a\" }}, attestation = true }}\n",
            e.module,
            e.dir.join("pin").display()
        ));
    };
    let r = ["realise", "a", "--token", "tpm", "--no-update-lock"];
    config(&format!("options = {{ tcti = \"{tcti}\" }}"));
    assert_eq!(e.code(&r), 10, "the TCTI from the options");

    // No TPM2_PKCS11_STORE: the store under $HOME, where the module looks too.
    config("");
    let home = e.dir.join("home");
    std::fs::create_dir_all(&home).unwrap();
    std::os::unix::fs::symlink(&store, home.join(".tpm2_pkcs11")).unwrap();
    let o = Command::new(BIN)
        .env_remove("TPM2_PKCS11_STORE")
        .env_remove("NIX_BUILD_TOP")
        .env("HOME", &home)
        .arg("--config")
        .arg(e.dir.join("keys.toml"))
        .args(r)
        .output()
        .unwrap();
    assert_eq!(code(&o), 10, "the store under $HOME: {}", stderr(&o));

    // A store of another token, named in the options.
    let other = e.dir.join("other-store");
    let path = format!("--path={}", other.display());
    std::fs::create_dir_all(&other).unwrap();
    for args in
        [vec!["init", &path], vec!["addtoken", "--pid=1", "--label=other", "--sopin=5678", "--userpin=1234", &path]]
    {
        let out = Command::new("tpm2_ptool").args(&args).output().unwrap();
        assert!(out.status.success(), "tpm2_ptool {args:?}: {}", stderr(&out));
    }
    config(&format!("options = {{ tpm2Store = \"{}\" }}", other.display()));
    let o = e.km(&r);
    assert_eq!(code(&o), 11, "{}", stderr(&o));
    assert!(stderr(&o).contains("token 'kmtest' in the tpm2-pkcs11 store"), "{}", stderr(&o));
}

/// Whether this suite's TPM is the software one `nix/tpm2-test-env.sh` started (its private bus
/// is named for it). The same suite shape can be pointed at a real TPM (`nix/ftpm-test-env.sh`):
/// a test that changes TPM state beyond the token's own objects runs only here
/// (docs/DEVELOPMENT.md, "Hardware rules").
fn on_swtpm() -> bool {
    std::env::var("DBUS_SESSION_BUS_ADDRESS").is_ok_and(|a| a.contains("unix:abstract=cakeys-tpm-"))
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
    e.ptool(&["addkey", "--algorithm=ecc256", "--key-label=lacks-a"]);
    let config = |token: &str| {
        e.write_config(&format!(
            "[tokens.tpm]\nmodule = \"{}\"\ntokenLabel = \"kmtest\"\n{token}\n\n\
             [objects.a]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n\
             [specs.a]\nobject = \"a\"\nattributes = {{ CKA_SIGN = true }}\n\
             tokens.tpm = {{ locator = {{ CKA_LABEL = \"lacks-a\" }}, attestation = true, binding = \"token-asserted\" }}\n",
            e.module,
        ));
    };
    let pin = format!("pinFile = \"{}\"", e.dir.join("pin").display());
    let r = ["realise", "a", "--token", "tpm", "--no-update-lock"];
    let refused = |o: &std::process::Output, want: i32, why: &str| {
        assert_eq!(code(o), want, "{why}: {}", stderr(o));
        assert!(stderr(o).contains(why), "expected {why:?} in {}", stderr(o));
    };

    config(&format!("{pin}\noptions = {{ tpm2Store = \"~/no-store\" }}"));
    let o = Command::new(BIN)
        .env_remove("HOME")
        .env_remove("NIX_BUILD_TOP")
        .arg("--config")
        .arg(e.dir.join("keys.toml"))
        .args(r)
        .output()
        .unwrap();
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
    assert_eq!(code(&o), 10, "{}", stderr(&o));

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
