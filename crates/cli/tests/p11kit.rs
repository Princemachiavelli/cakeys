//! End-to-end tests through p11-kit forwarding: `p11-kit server` in front of a `SoftHSM` token
//! (`kmp11`), reached with `p11-kit-client.so`, compared with the same token opened directly.
//!
//! Needs `CAKEYS_P11KIT_CLIENT` (p11-kit-client.so), `P11_KIT_SERVER_ADDRESS`, `CAKEYS_TEST_MODULE`
//! (libsofthsm2.so, for the direct path) and `SOFTHSM2_CONF`; the server must export only
//! `pkcs11:token=kmp11` (user PIN 1234) while the same `SoftHSM` also holds `kmtest`. Skipped when
//! `CAKEYS_P11KIT_CLIENT` is unset, unless `CAKEYS_P11KIT_REQUIRE=1`.

mod common;

use common::*;
use cryptoki::object::{Attribute, KeyType, ObjectClass};
use hmac::{Hmac, KeyInit, Mac};
use std::path::PathBuf;
use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_cakeys");

struct Env {
    dir: PathBuf,
    client: String,
    direct: String,
}

fn env(name: &str) -> Option<Env> {
    let Ok(client) = std::env::var("CAKEYS_P11KIT_CLIENT") else {
        assert!(std::env::var("CAKEYS_P11KIT_REQUIRE").is_err(), "CAKEYS_P11KIT_CLIENT is required");
        eprintln!("skipping {name}: CAKEYS_P11KIT_CLIENT not set");
        return None;
    };
    let direct = std::env::var("CAKEYS_TEST_MODULE").expect("CAKEYS_TEST_MODULE (SoftHSM) for the direct path");
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("p11kit-{name}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("pin"), "1234\n").unwrap();
    Some(Env { dir, client, direct })
}

impl Env {
    /// Tokens: `fwd` (through p11-kit), `fwd-anon` (no PIN), `fwd-softhsm` (provider named),
    /// `fwd-other` (a token the server does not export) and `direct` (`SoftHSM` itself).
    fn config(&self, body: &str) {
        let pin = format!("pinFile = \"{}\"", self.dir.join("pin").display());
        let token = |name: &str, module: &str, label: &str, extra: &str| {
            format!("[tokens.{name}]\nmodule = \"{module}\"\ntokenLabel = \"{label}\"\n{extra}\n\n")
        };
        let head = token("fwd", &self.client, "kmp11", &pin)
            + &token("fwd-anon", &self.client, "kmp11", "")
            + &token("fwd-softhsm", &self.client, "kmp11", &format!("{pin}\nprovider = \"softhsm\""))
            + &token("fwd-other", &self.client, "kmtest", &pin)
            + &token("direct", &self.direct, "kmp11", &pin);
        std::fs::write(self.dir.join("keys.toml"), head + body).unwrap();
    }

    fn km(&self, args: &[&str]) -> Output {
        let out = Command::new(BIN)
            .env_remove("NIX_BUILD_TOP")
            .arg("--config")
            .arg(self.dir.join("keys.toml"))
            .args(args)
            .output()
            .unwrap();
        eprintln!(
            "$ cakeys {}\n  exit={:?}\n  stdout={}\n  stderr={}",
            args.join(" "),
            out.status.code(),
            String::from_utf8_lossy(&out.stdout).trim(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
        out
    }

    fn ids(&self, o: &Output) -> serde_json::Value {
        serde_json::from_str::<serde_json::Value>(&stdout(o)).unwrap()["ids"].clone()
    }

    fn locked_id(&self, object: &str, scheme: &str) -> String {
        let lock: toml::Value = toml::from_str(&std::fs::read_to_string(self.dir.join("keys.lock")).unwrap()).unwrap();
        lock["objects"][object]["ids"][scheme].as_str().unwrap().to_owned()
    }

    fn session(&self, module: &str) -> TestSession {
        open_session(module, "kmp11", "1234")
    }
}

fn caps(e: &Env, token: &str) -> serde_json::Value {
    serde_json::from_str(&stdout(&e.km(&["caps", "--token", token]))).unwrap()
}

const FORWARDING_DROPS: [&str; 4] =
    ["CKM_AES_KEY_WRAP", "CKM_AES_KEY_WRAP_PAD", "CKM_EC_EDWARDS_KEY_PAIR_GEN", "CKM_EDDSA"];

#[test]
fn p11kit_forwards_a_filtered_view() {
    let Some(e) = env("view") else { return };
    e.config("");
    let fwd = caps(&e, "fwd");
    assert_eq!(fwd["provider"], "p11-kit", "detected from the proxy's C_GetInfo");
    let has = |c: &serde_json::Value, m: &str| c["mechanisms"].as_array().unwrap().iter().any(|x| x == m);
    let direct = caps(&e, "direct");
    assert_eq!(direct["provider"], "softhsm");
    for m in ["CKM_EC_KEY_PAIR_GEN", "CKM_RSA_PKCS_KEY_PAIR_GEN", "CKM_AES_CMAC", "CKM_AES_ECB", "CKM_SHA256_HMAC"] {
        assert!(has(&fwd, m) && has(&direct, m), "{m} is forwarded");
    }
    // The RPC drops what it cannot marshal (if a p11-kit update forwards one, revisit the docs).
    for m in FORWARDING_DROPS {
        assert!(has(&direct, m) && !has(&fwd, m), "{m}: SoftHSM has it, p11-kit hides it");
    }
    // Naming the provider behind the proxy applies its behaviour.
    assert_eq!(caps(&e, "fwd-softhsm")["provider"], "softhsm");
    // The server exports only the token in its URI; the same SoftHSM's other token is invisible.
    assert_eq!(code(&e.km(&["caps", "--token", "fwd-other"])), 16);
}

/// A test-only AES-256 value planted on the token, known to the host.
const AES_VALUE: [u8; 32] = *b"p11-kit forwarding aes vector!!!";
const HMAC_VALUE: [u8; 32] = *b"p11-kit forwarding hmac vector!!";

#[test]
fn p11kit_and_direct_paths_agree() {
    let Some(e) = env("agree") else { return };
    let s = e.session(&e.direct);
    s.create_object(&[
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(KeyType::AES),
        Attribute::Token(true),
        Attribute::Label(b"fwd-aes".to_vec()),
        Attribute::Value(AES_VALUE.to_vec()),
        Attribute::Sign(true),
        Attribute::Encrypt(true),
        Attribute::Wrap(true),
        Attribute::Sensitive(true),
        Attribute::Extractable(false),
    ])
    .unwrap();
    s.create_object(&[
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(KeyType::GENERIC_SECRET),
        Attribute::Token(true),
        Attribute::Label(b"fwd-hmac".to_vec()),
        Attribute::Value(HMAC_VALUE.to_vec()),
        Attribute::Sign(true),
        Attribute::Sensitive(true),
        Attribute::Extractable(false),
    ])
    .unwrap();
    drop(s);

    let kinds = [
        ("fwd-p256", "keyType = \"CKK_EC\"\ncurve = \"secp256r1\""),
        ("fwd-p521", "keyType = \"CKK_EC\"\ncurve = \"secp521r1\""),
        ("fwd-rsa3072", "keyType = \"CKK_RSA\"\nmodulusBits = 3072"),
    ];
    let mut body = String::new();
    for (k, ty) in kinds {
        body += &format!(
            "[objects.{k}]\nclass = \"CKO_PRIVATE_KEY\"\n{ty}\n\n\
             [specs.{k}]\nobject = \"{k}\"\nattributes = {{ CKA_SIGN = true }}\n\
             tokens.fwd = {{ locator = {{ CKA_LABEL = \"{k}\" }}, autoCreate = true }}\n\
             tokens.direct = {{ locator = {{ CKA_LABEL = \"{k}\" }} }}\n\n\
             [specs.{k}-pub]\nobject = \"{k}\"\n\
             tokens.fwd-anon = {{ locator = {{ CKA_LABEL = \"{k}\" }}, publicOnly = true }}\n\n"
        );
    }
    body += r#"
[objects.aes]
class = "CKO_SECRET_KEY"
keyType = "CKK_AES"
valueLen = 32

[specs.aes]
object = "aes"
attributes = { CKA_SIGN = true, CKA_ENCRYPT = true, CKA_WRAP = true, CKA_EXTRACTABLE = false }
tokens.fwd = { locator = { CKA_LABEL = "fwd-aes" } }
tokens.direct = { locator = { CKA_LABEL = "fwd-aes" } }

[objects.hmac]
class = "CKO_SECRET_KEY"
keyType = "CKK_GENERIC_SECRET"
valueLen = 32

[specs.hmac]
object = "hmac"
attributes = { CKA_SIGN = true, CKA_EXTRACTABLE = false }
tokens.fwd = { locator = { CKA_LABEL = "fwd-hmac" } }
"#;
    e.config(&body);

    // Generated through the forwarded token, then the same object opened directly: one identity.
    for (k, _) in kinds {
        assert_eq!(code(&e.km(&["realise", k, "--token", "fwd", "--update-lock"])), 0, "{k}");
        assert_eq!(code(&e.km(&["realise", k, "--token", "direct", "--update-lock"])), 0, "{k}: direct agrees");
        let pubs = format!("{k}-pub");
        assert_eq!(code(&e.km(&["realise", &pubs, "--token", "fwd-anon", "--update-lock"])), 0, "{k}");
        assert_eq!(e.locked_id(k, "rfc7093m4"), sri(&oracle_spki(&e.session(&e.direct), k)), "{k}");
    }

    // AES: p11-kit forwards CMAC and ECB but not key wrap, so the forwarded path computes two of
    // the three commitments; they still link to the direct path, which computes all three.
    let o = e.km(&["realise", "aes", "--token", "fwd", "--update-lock"]);
    assert_eq!(code(&o), 0);
    assert_eq!(e.ids(&o).as_object().unwrap().keys().collect::<Vec<_>>(), ["cmac", "kcv-ecb"]);
    assert_eq!(code(&e.km(&["realise", "aes", "--token", "direct", "--update-lock"])), 0);
    for scheme in ["cmac", "kcv-ecb", "kw"] {
        assert_eq!(e.locked_id("aes", scheme), aes_commitment(&AES_VALUE[..], scheme), "{scheme}");
    }

    assert_eq!(code(&e.km(&["realise", "hmac", "--token", "fwd", "--update-lock"])), 0);
    let mut mac = <Hmac<sha2::Sha256> as KeyInit>::new_from_slice(&HMAC_VALUE).unwrap();
    mac.update(b"key-management/v1/commitment/CKK_GENERIC_SECRET/256");
    assert_eq!(e.locked_id("hmac", "commitment"), sri(&mac.finalize().into_bytes()));
}

#[test]
fn p11kit_refuses_what_it_cannot_forward_before_creating() {
    let Some(e) = env("refusals") else { return };
    e.config(
        r#"
[objects.ed]
class = "CKO_PRIVATE_KEY"
keyType = "CKK_EC_EDWARDS"
curve = "edwards25519"

[specs.ed]
object = "ed"
attributes = { CKA_SIGN = true }
tokens.fwd = { locator = { CKA_LABEL = "fwd-refused-ed" }, autoCreate = true }

[objects.aes-x]
class = "CKO_SECRET_KEY"
keyType = "CKK_AES"
valueLen = 32

[specs.aes-x]
object = "aes-x"
attributes = { CKA_SIGN = false, CKA_ENCRYPT = false, CKA_WRAP = false, CKA_EXTRACTABLE = true }
tokens.fwd = { locator = { CKA_LABEL = "fwd-refused-aes-x" }, autoCreate = true }

[objects.aes-kek]
class = "CKO_SECRET_KEY"
keyType = "CKK_AES"
valueLen = 32

[specs.aes-kek]
object = "aes-kek"
attributes = { CKA_WRAP = true, CKA_EXTRACTABLE = false }
tokens.fwd = { locator = { CKA_LABEL = "fwd-refused-kek" }, autoCreate = true }
"#,
    );
    for (spec, label) in [("ed", "fwd-refused-ed"), ("aes-x", "fwd-refused-aes-x"), ("aes-kek", "fwd-refused-kek")] {
        let o = e.km(&["realise", spec, "--token", "fwd", "--no-update-lock"]);
        assert_eq!(code(&o), 15, "{spec}");
        assert!(String::from_utf8_lossy(&o.stderr).contains("forwarded by p11-kit"), "{spec}: hint");
        let left = e.session(&e.direct).find_objects(&[Attribute::Label(label.as_bytes().to_vec())]).unwrap();
        assert!(left.is_empty(), "{spec}: nothing created");
    }
}

#[test]
fn p11kit_login_is_per_client() {
    let Some(e) = env("login") else { return };
    e.config(
        "[objects.k]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n\
         [specs.k]\nobject = \"k\"\nattributes = { CKA_SIGN = true }\ntokens.fwd = { locator = { CKA_LABEL = \"fwd-login\" }, autoCreate = true }\n\
         tokens.fwd-anon = { locator = { CKA_LABEL = \"fwd-login\" } }\n\n\
         [specs.k-pub]\nobject = \"k\"\ntokens.fwd-anon = { locator = { CKA_LABEL = \"fwd-login\" }, publicOnly = true }\n",
    );
    assert_eq!(code(&e.km(&["realise", "k", "--token", "fwd", "--update-lock"])), 0);
    // Another client of the same server holds a logged-in session meanwhile...
    let held = e.session(&e.client);
    // ...yet a client without the PIN still cannot see the private key; the public half works.
    assert_eq!(code(&e.km(&["realise", "k", "--token", "fwd-anon", "--no-update-lock"])), 11);
    assert_eq!(code(&e.km(&["realise", "k-pub", "--token", "fwd-anon", "--update-lock"])), 0);
    drop(held);
}
