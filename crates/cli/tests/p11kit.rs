//! End-to-end tests through p11-kit forwarding: `p11-kit server` in front of a `SoftHSM` token
//! (`kmp11`), reached with `p11-kit-client.so`, compared with the same token opened directly.
//!
//! Needs `CAKEYS_P11KIT_CLIENT` (p11-kit-client.so), `P11_KIT_SERVER_ADDRESS`, `CAKEYS_TEST_MODULE`
//! (libsofthsm2.so, for the direct path) and `SOFTHSM2_CONF`; the server must export only
//! `pkcs11:token=kmp11` (user PIN 1234) while the same `SoftHSM` also holds `kmtest`. Skipped when
//! `CAKEYS_P11KIT_CLIENT` or `CAKEYS_TEST_MODULE` is unset, unless `CAKEYS_P11KIT_REQUIRE=1`.

mod common;

use common::*;
use cryptoki::object::{Attribute, KeyType, ObjectClass};
use hmac::{Hmac, KeyInit, Mac};
use std::process::Output;

/// The suite for test `name` ([`p11kit_tokens`]; its module is the client) and the `SoftHSM`
/// module of the direct path, or `None` (skipped). Both through the gate (review p11kit.rs F2:
/// the direct one was an `expect`).
fn env(name: &str) -> Option<(Suite, String)> {
    let client = suite_var("CAKEYS_P11KIT_CLIENT", "CAKEYS_P11KIT_REQUIRE", name)?;
    let direct = suite_var("CAKEYS_TEST_MODULE", "CAKEYS_P11KIT_REQUIRE", name)?;
    let suite = Suite::new(&format!("p11kit-{name}"), client, |client, dir| p11kit_tokens(client, &direct, dir));
    Some((suite, direct))
}

/// A logged-in session on the exported token `kmp11`, through `module` (the client or direct).
fn session(module: &str) -> TestSession {
    open_session(module, "kmp11", "1234")
}

/// The IDs a `lock` run printed.
fn ids(o: &Output) -> serde_json::Value {
    serde_json::from_str::<serde_json::Value>(&stdout(o)).unwrap()["ids"].clone()
}

/// A test-only AES-256 value planted on the token, known to the host.
const AES_VALUE: [u8; 32] = *b"p11-kit forwarding aes vector!!!";
const HMAC_VALUE: [u8; 32] = *b"p11-kit forwarding hmac vector!!";

#[test]
#[expect(clippy::format_push_string, reason = "the fixture TOML bodies are appended as += format!(...)")]
fn p11kit_and_direct_paths_agree() {
    let Some((e, direct)) = env("agree") else { return };
    let s = session(&direct);
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
             tokens.fwd = {{ locator = {{ CKA_LABEL = \"{k}\" }}, origin = \"create\" }}\n\
             tokens.direct = {{ locator = {{ CKA_LABEL = \"{k}\" }}, origin = \"adopt\" }}\n\n\
             [specs.{k}-pub]\nobject = \"{k}\"\n\
             tokens.fwd-anon = {{ locator = {{ CKA_LABEL = \"{k}\" }}, origin = \"adopt\", publicOnly = true }}\n\n"
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
tokens.fwd = { locator = { CKA_LABEL = "fwd-aes" }, origin = "adopt" }
tokens.direct = { locator = { CKA_LABEL = "fwd-aes" }, origin = "adopt" }

[objects.hmac]
class = "CKO_SECRET_KEY"
keyType = "CKK_GENERIC_SECRET"
valueLen = 32

[specs.hmac]
object = "hmac"
attributes = { CKA_SIGN = true, CKA_EXTRACTABLE = false }
tokens.fwd = { locator = { CKA_LABEL = "fwd-hmac" }, origin = "adopt" }
"#;
    e.config(&body);

    // Generated through the forwarded token, then the same object opened directly: one identity.
    for (k, _) in kinds {
        assert_eq!(e.code(&["create", "--spec", k, "--token", "fwd", "--update-lock"]), 0, "{k}");
        assert_eq!(e.code(&["lock", "--spec", k, "--token", "direct", "--update-lock"]), 0, "{k}: direct agrees");
        let pubs = format!("{k}-pub");
        assert_eq!(e.code(&["lock", "--spec", &pubs, "--token", "fwd-anon", "--update-lock"]), 0, "{k}");
        assert_eq!(e.locked_id(k, "rfc7093m4"), sri(&oracle_spki(&session(&direct), k)), "{k}");
    }

    // AES: p11-kit forwards CMAC and ECB but not key wrap, so the forwarded path computes two of
    // the three commitments; they still link to the direct path, which computes all three.
    let o = e.km(&["lock", "--spec", "aes", "--token", "fwd", "--update-lock"]);
    assert_eq!(code(&o), 0);
    assert_eq!(ids(&o).as_object().unwrap().keys().collect::<Vec<_>>(), ["cmac", "kcv-ecb"]);
    assert_eq!(e.code(&["lock", "--spec", "aes", "--token", "direct", "--update-lock"]), 0);
    for scheme in ["cmac", "kcv-ecb", "kw"] {
        assert_eq!(e.locked_id("aes", scheme), aes_commitment(&AES_VALUE[..], scheme), "{scheme}");
    }

    assert_eq!(e.code(&["lock", "--spec", "hmac", "--token", "fwd", "--update-lock"]), 0);
    let mut mac = <Hmac<sha2::Sha256> as KeyInit>::new_from_slice(&HMAC_VALUE).unwrap();
    mac.update(b"key-management/v1/commitment/CKK_GENERIC_SECRET/256");
    assert_eq!(e.locked_id("hmac", "commitment"), sri(&mac.finalize().into_bytes()));
}

#[test]
fn p11kit_refuses_what_it_cannot_forward_before_creating() {
    let Some((e, direct)) = env("refusals") else { return };
    e.config(
        r#"
[objects.ed]
class = "CKO_PRIVATE_KEY"
keyType = "CKK_EC_EDWARDS"
curve = "edwards25519"

[specs.ed]
object = "ed"
attributes = { CKA_SIGN = true }
tokens.fwd = { locator = { CKA_LABEL = "fwd-refused-ed" }, origin = "create" }

[objects.aes-x]
class = "CKO_SECRET_KEY"
keyType = "CKK_AES"
valueLen = 32

[specs.aes-x]
object = "aes-x"
attributes = { CKA_SIGN = false, CKA_ENCRYPT = false, CKA_WRAP = false, CKA_EXTRACTABLE = true }
tokens.fwd = { locator = { CKA_LABEL = "fwd-refused-aes-x" }, origin = "create" }

[objects.aes-kek]
class = "CKO_SECRET_KEY"
keyType = "CKK_AES"
valueLen = 32

[specs.aes-kek]
object = "aes-kek"
attributes = { CKA_WRAP = true, CKA_EXTRACTABLE = false }
tokens.fwd = { locator = { CKA_LABEL = "fwd-refused-kek" }, origin = "create" }
"#,
    );
    for (spec, label) in [("ed", "fwd-refused-ed"), ("aes-x", "fwd-refused-aes-x"), ("aes-kek", "fwd-refused-kek")] {
        let o = e.km(&["create", "--spec", spec, "--token", "fwd", "--no-update-lock"]);
        assert_eq!(code(&o), 15, "{spec}");
        assert!(stderr(&o).contains("forwarded by p11-kit"), "{spec}: hint");
        let left = session(&direct).find_objects(&[Attribute::Label(label.as_bytes().to_vec())]).unwrap();
        assert!(left.is_empty(), "{spec}: nothing created");
    }
}

#[test]
fn p11kit_login_is_per_client() {
    let Some((e, _)) = env("login") else { return };
    e.config(
        "[objects.k]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n\
         [specs.k]\nobject = \"k\"\nattributes = { CKA_SIGN = true }\ntokens.fwd = { locator = { CKA_LABEL = \"fwd-login\" }, origin = \"create\" }\n\
         tokens.fwd-anon = { locator = { CKA_LABEL = \"fwd-login\" }, origin = \"adopt\" }\n\n\
         [specs.k-pub]\nobject = \"k\"\ntokens.fwd-anon = { locator = { CKA_LABEL = \"fwd-login\" }, origin = \"adopt\", publicOnly = true }\n",
    );
    assert_eq!(e.code(&["create", "--spec", "k", "--token", "fwd", "--update-lock"]), 0);
    // Another client of the same server holds a logged-in session meanwhile...
    let held = session(&e.module);
    // ...yet a client without the PIN still cannot see the private key; the public half works.
    assert_eq!(e.code(&["lock", "--spec", "k", "--token", "fwd-anon", "--no-update-lock"]), 11);
    assert_eq!(e.code(&["lock", "--spec", "k-pub", "--token", "fwd-anon", "--update-lock"]), 0);
    drop(held);
}
