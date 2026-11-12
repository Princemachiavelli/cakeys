//! End-to-end tests against tpm2-pkcs11 on a software TPM (nix/tpm2-test-env.sh).
//!
//! Needs `KM_TPM_MODULE` (libtpm2_pkcs11.so), the `TPM2_PKCS11_*` environment from the harness,
//! a token `kmtest` with user PIN `1234`, and `tpm2_ptool` on PATH. Skipped when
//! `KM_TPM_MODULE` is unset, unless `KM_TPM_REQUIRE=1`.

mod common;

use common::*;
use cryptoki::context::{CInitializeArgs, Pkcs11};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, ObjectClass};
use cryptoki::session::{Session, UserType};
use cryptoki::types::AuthPin;
use hmac::{Hmac, KeyInit, Mac};
use std::path::PathBuf;
use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_key-mgmnt");
const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

struct Env {
    dir: PathBuf,
    module: String,
}

fn env(name: &str) -> Option<Env> {
    let Ok(module) = std::env::var("KM_TPM_MODULE") else {
        assert!(std::env::var("KM_TPM_REQUIRE").is_err(), "KM_TPM_MODULE is required");
        eprintln!("skipping {name}: KM_TPM_MODULE not set");
        return None;
    };
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("tpm2-{name}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("pin"), "1234\n").unwrap();
    Some(Env { dir, module })
}

impl Env {
    /// keys.toml with `tpm` (logged in), `tpm-anon` (no PIN) and `tpm-generic` (logged in, but
    /// without the tpm2-pkcs11 provider's fix-ups).
    fn config(&self, body: &str) {
        let pin = self.dir.join("pin");
        let token = |name: &str, extra: &str| {
            format!("[tokens.{name}]\nmodule = \"{}\"\ntokenLabel = \"kmtest\"\n{extra}\n", self.module)
        };
        let head = token("tpm", &format!("pinFile = \"{}\"", pin.display()))
            + &token("tpm-anon", "")
            + &token("tpm-generic", &format!("pinFile = \"{}\"\nprovider = \"generic\"", pin.display()));
        std::fs::write(self.dir.join("keys.toml"), head + body).unwrap();
    }

    fn km(&self, args: &[&str]) -> Output {
        let out = Command::new(BIN).arg("--config").arg(self.dir.join("keys.toml")).args(args).output().unwrap();
        eprintln!(
            "$ key-mgmnt {}\n  exit={:?}\n  stdout={}\n  stderr={}",
            args.join(" "),
            out.status.code(),
            String::from_utf8_lossy(&out.stdout).trim(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
        out
    }

    fn locked_id(&self, object: &str, scheme: &str) -> String {
        let lock: toml::Value = toml::from_str(&std::fs::read_to_string(self.dir.join("keys.lock")).unwrap()).unwrap();
        lock["objects"][object]["ids"][scheme].as_str().unwrap().to_owned()
    }

    /// `tpm2_ptool <args> --label kmtest --userpin 1234 --path $TPM2_PKCS11_STORE`.
    fn ptool(&self, args: &[&str]) {
        let store = std::env::var("TPM2_PKCS11_STORE").unwrap();
        let out = Command::new("tpm2_ptool")
            .args(args)
            .args(["--label=kmtest", "--userpin=1234", &format!("--path={store}")])
            .output()
            .unwrap();
        assert!(out.status.success(), "tpm2_ptool {args:?}: {}", String::from_utf8_lossy(&out.stderr));
    }

    /// A fresh session: tpm2-pkcs11 loads the object list when a session opens, so objects
    /// created by another process afterwards are invisible to it.
    fn session(&self) -> Session {
        let ctx = Pkcs11::new(&self.module).unwrap();
        ctx.initialize(CInitializeArgs::OsThreads).unwrap();
        let slot = ctx
            .get_slots_with_token()
            .unwrap()
            .into_iter()
            .find(|s| ctx.get_token_info(*s).unwrap().label() == "kmtest")
            .unwrap();
        let s = ctx.open_rw_session(slot).unwrap();
        s.login(UserType::User, Some(&AuthPin::new("1234".into()))).unwrap();
        s
    }
}

fn labelled(s: &Session, label: &str) -> usize {
    s.find_objects(&[Attribute::Label(label.as_bytes().to_vec())]).unwrap().len()
}

/// Like `unwrap_octets`, but also accepting tpm2-pkcs11's P-521 encoding `04 85 <133 bytes>`
/// (see key-mgmnt-tpm2-pkcs11). The oracle's independence is in building the SPKI.
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
tokens.tpm = { locator = { CKA_LABEL = "refusal-ed" }, autoCreate = true }

[objects.aes]
class = "CKO_SECRET_KEY"
keyType = "CKK_AES"
valueLen = 32

[specs.aes-mac]
object = "aes"
attributes = { CKA_SIGN = true }
tokens.tpm = { locator = { CKA_LABEL = "refusal-aes" } }
"#,
    );
    let caps: serde_json::Value = serde_json::from_str(&stdout(&e.km(&["caps", "--token", "tpm"]))).unwrap();
    assert_eq!(caps["provider"], "tpm2-pkcs11");
    let mechs = caps["mechanisms"].to_string();
    assert!(mechs.contains("CKM_EC_KEY_PAIR_GEN") && !mechs.contains("CKM_AES_KEY_GEN"), "{mechs}");

    // Secret-key generation is refused up front, with the provider's advice, and creates nothing.
    for (spec, label) in [("aes-gen", "refusal-aes-gen"), ("hmac-gen", "refusal-hmac-gen")] {
        let o = e.km(&["realise", spec, "--token", "tpm"]);
        assert_eq!(code(&o), 15, "{spec}");
        assert!(String::from_utf8_lossy(&o.stderr).contains("tpm2_ptool addkey"), "{spec}");
        assert_eq!(labelled(&e.session(), label), 0, "{spec}");
    }
    assert_eq!(code(&e.km(&["realise", "ed", "--token", "tpm"])), 15);
    // No CKM_AES_CMAC: a sign-only AES spec has no commitment here.
    assert_eq!(code(&e.km(&["realise", "aes-mac", "--token", "tpm"])), 15);
}

#[test]
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
        body += &format!(
            "[objects.{k}]\nclass = \"CKO_PRIVATE_KEY\"\n{ty}\n\n\
             [specs.{k}-gen]\nobject = \"{k}\"\nattributes = {{ CKA_SIGN = true }}\n\
             tokens.tpm = {{ locator = {{ CKA_LABEL = \"{k}\" }}, autoCreate = true }}\n\n\
             [specs.{k}-pub]\nobject = \"{k}\"\n\
             tokens.tpm-anon = {{ locator = {{ CKA_LABEL = \"{k}\" }}, publicOnly = true }}\n\n"
        );
    }
    e.config(&body);
    for (k, _) in kinds {
        let gen = format!("{k}-gen");
        let first = e.km(&["realise", &gen, "--token", "tpm"]);
        assert_eq!(code(&first), 10, "{k}");
        assert_eq!(got_hash(&e.km(&["realise", &gen, "--token", "tpm"])), got_hash(&first), "{k}: no duplicate");
        assert_eq!(code(&e.km(&["realise", &gen, "--token", "tpm", "--update-lock"])), 0, "{k}");
        // A session opened now: tpm2-pkcs11 sessions don't see objects created after they opened.
        assert_eq!(e.locked_id(k, "pubkeyhash"), sri(&oracle_spki_with(&e.session(), k, unwrap_tpm2)), "{k}");
        let pubs = format!("{k}-pub");
        assert_eq!(code(&e.km(&["realise", &pubs, "--token", "tpm-anon", "--update-lock"])), 0, "{k}");
    }
}

#[test]
fn tpm2_identity_failure_after_create_leaves_nothing() {
    let Some(e) = env("orphan") else { return };
    // Without the provider, tpm2-pkcs11's P-521 point is rejected after the key was generated.
    e.config(
        "[objects.p]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp521r1\"\n\n\
         [specs.p]\nobject = \"p\"\ntokens.tpm-generic = { locator = { CKA_LABEL = \"orphan-p521\" }, autoCreate = true }\n",
    );
    let o = e.km(&["realise", "p", "--token", "tpm-generic"]);
    assert_eq!(code(&o), 13);
    assert!(String::from_utf8_lossy(&o.stderr).contains("removed 2 object(s) just created"));
    assert_eq!(labelled(&e.session(), "orphan-p521"), 0);
}

/// openssl-computed pubkeyhashes of the import fixtures (test-only keys).
const IMPORT_P256: &str = "sha256-0ymh9vfz8P3lnbdlAXskvxwoDAfUJNEIbsv0KEupcSg=";
const IMPORT_RSA2048: &str = "sha256-kRE6YzH4EXmqqAKhbLhb0z6/57mcGvHKrm4F4omLIn4=";
const HMAC_VALUE: &[u8; 32] = b"key-management hmac test vector!";

#[test]
fn tpm2_imported_keys_match_openssl_and_host_hmac() {
    let Some(e) = env("imported") else { return };
    e.ptool(&["import", "--algorithm=ecc", &format!("--privkey={FIXTURES}/tpm-import-p256.pem"), "--key-label=imp-p256"]);
    e.ptool(&["import", "--algorithm=rsa", &format!("--privkey={FIXTURES}/tpm-import-rsa2048.pem"), "--key-label=imp-rsa"]);
    let hmac_file = e.dir.join("hmac.bin");
    std::fs::write(&hmac_file, HMAC_VALUE).unwrap();
    e.ptool(&["import", "--algorithm=hmac:sha256", &format!("--privkey={}", hmac_file.display()), "--key-label=imp-hmac"]);
    e.config(
        r#"
[objects.p256]
class = "CKO_PRIVATE_KEY"
keyType = "CKK_EC"
curve = "secp256r1"

[specs.p256]
object = "p256"
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
"#,
    );
    for (spec, token) in [("p256", "tpm"), ("rsa", "tpm-anon"), ("hmac", "tpm")] {
        assert_eq!(code(&e.km(&["realise", spec, "--token", token, "--update-lock"])), 0, "{spec}");
    }
    assert_eq!(e.locked_id("p256", "pubkeyhash"), IMPORT_P256);
    assert_eq!(e.locked_id("rsa", "pubkeyhash"), IMPORT_RSA2048);
    let mut mac = <Hmac<sha2::Sha256> as KeyInit>::new_from_slice(HMAC_VALUE).unwrap();
    mac.update(b"key-management/v1/commitment/CKK_SHA256_HMAC/256");
    assert_eq!(e.locked_id("hmac", "commitment"), sri(&mac.finalize().into_bytes()));
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
    let r = ["realise", "aes", "--token", "tpm"];
    let first = e.km(&r);
    assert_eq!(code(&first), 10);
    assert_eq!(got_hash(&e.km(&r)), got_hash(&first));
    assert_eq!(code(&e.km(&[&r[..], &["--update-lock"]].concat())), 0);
    assert_eq!(code(&e.km(&["check", "aes.id.kcv-ecb"])), 0);

    let s = e.session();
    let h = s.find_objects(&[Attribute::Class(ObjectClass::SECRET_KEY), Attribute::Label(b"kcv-aes".to_vec())]).unwrap()[0];
    let block = &<sha2::Sha256 as sha2::Digest>::digest(b"key-management/v1/kcv-ecb/CKK_AES/256")[..16];
    let kcv = s.encrypt(&Mechanism::AesEcb, h, block).unwrap();
    assert_eq!(e.locked_id("aes", "kcv-ecb"), sri(&kcv));
}
