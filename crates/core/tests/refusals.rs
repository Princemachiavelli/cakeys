//! What loading keys.toml and a lock, planning a target and reading a key refuse, each with the
//! message that says why (the coverage report's gaps in `config`, `plan`, `pop` and `plaintext`):
//! none needs a token.

use cakeys_core::KmError;
use cakeys_core::config::{Config, parse_config_with, parse_lock};
use cakeys_core::id::Scheme;
use cakeys_core::plaintext::{PrivateParts, private_from_pkcs8, spki_of_pkcs8};
use cakeys_core::plan::{Assurance, Target, plan_mode};
use cakeys_core::types::KeyType;
use ed25519_dalek::pkcs8::{EncodePrivateKey as _, EncodePublicKey as _};
use std::path::Path;

/// keys.toml with one token `t`, one object `o` of `object`, and one spec `s` on `t` with
/// `spec` lines and `on_token` entries beside the locator.
fn keys(object: &str, spec: &str, on_token: &str) -> String {
    format!(
        "[tokens.t]\ntokenLabel = \"t\"\n\n[objects.o]\n{object}\n\n[specs.s]\nobject = \"o\"\n{spec}\n\
         tokens.t = {{ locator = {{ CKA_LABEL = \"o\" }}{on_token} }}\n"
    )
}

fn load(text: &str) -> cakeys_core::Result<Config> {
    parse_config_with(text, Path::new("keys.toml"), &|_| None)
}

/// Why `text` is refused: at load, or when its one target is planned.
fn refusal(text: &str) -> String {
    match load(text) {
        Err(e) => e.to_string(),
        Ok(cfg) => match Target::new(&cfg, "s", "t").and_then(|t| plan_mode(&t)) {
            Err(e) => e.to_string(),
            Ok(mode) => panic!("accepted as {mode}:\n{text}"),
        },
    }
}

const EC: &str = "class = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"";
const AES: &str = "class = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_AES\"\nvalueLen = 32";
const CERT: &str = "class = \"CKO_CERTIFICATE\"\ncertificateType = \"CKC_X_509\"";
const SIGN: &str = "attributes = { CKA_SIGN = true }";

#[test]
fn specs_that_cannot_hold_are_refused_with_why() {
    let cases: &[(&str, &str, &str, &str)] = &[
        (AES, SIGN, ", binding = \"pop-sign\"", "applies to private keys only"),
        (EC, SIGN, ", publicOnly = true, binding = \"pop-sign\"", "publicOnly cannot prove possession"),
        (
            "class = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC_EDWARDS\"\ncurve = \"edwards25519\"",
            "attributes = { CKA_DERIVE = true }",
            ", binding = \"pop-ecdh\"",
            "Weierstrass EC keys",
        ),
        (
            EC,
            "attributes = { CKA_SIGN = true, CKA_DERIVE = [\"CKM_ECDSA\"] }",
            "",
            "only CKA_ALLOWED_MECHANISMS takes a mechanism list",
        ),
        (EC, "attributes = { CKA_SIGN = true, CKA_BOGUS = true }", "", "CKA_BOGUS"),
        (AES, "attributes = { CKA_SIGN = true }\npublicAttributes = { CKA_VERIFY = true }", "", "private keys only"),
        ("class = \"CKO_CERTIFICATE\"\ncertificateType = \"CKC_WTLS\"", "", "", "CKC_X_509"),
        (&format!("{EC}\ncertificateType = \"CKC_X_509\""), SIGN, "", "certificates only"),
        (&format!("{CERT}\nkeyType = \"CKK_RSA\""), "", "", "keyType"),
        ("class = \"CKO_DATA\"", "", ", attestation = true", "key objects only"),
        ("class = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp112r1\"", SIGN, "", "secp112r1"),
        ("class = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_RSA\"", SIGN, "", "CKK_RSA"),
    ];
    for (object, spec, on_token, why) in cases {
        let said = refusal(&keys(object, spec, on_token));
        assert!(said.contains(why), "expected {why:?} in {said:?}");
    }
}

#[test]
fn names_that_select_nothing_are_refused() {
    let cfg = load(&keys(EC, SIGN, "")).unwrap();
    let e = Target::new(&cfg, "s", "elsewhere").err().unwrap();
    assert!(matches!(&e, KmError::NotFound(m) if m.contains("has no token 'elsewhere'")), "{e}");
    assert!(Target::new(&cfg, "nope", "t").is_err());
    let said = load(&keys(EC, SIGN, "").replace("object = \"o\"", "object = \"gone\"")).unwrap_err().to_string();
    assert!(said.contains("gone"), "{said}");
    // An object's one (spec, token) pair, or why there is not exactly one.
    assert_eq!(cfg.pick_spec("o", None, None).unwrap(), ("s".to_owned(), "t".to_owned()));
    assert!(matches!(cfg.pick_spec("o", None, Some("elsewhere")), Err(KmError::NotFound(_))));
    let two = keys(EC, SIGN, "") + "\n[specs.s2]\nobject = \"o\"\ntokens.t = { locator = { CKA_LABEL = \"o2\" } }\n";
    assert!(matches!(load(&two).unwrap().pick_spec("o", None, None), Err(KmError::Ambiguous(_))));
}

#[test]
fn token_and_creation_rules_are_checked_at_load() {
    let refused = |text: String, why: &str| {
        let said = load(&text).unwrap_err().to_string();
        assert!(said.contains(why), "expected {why:?} in {said:?}");
    };
    let with_token =
        |line: &str| keys(EC, SIGN, "").replace("tokenLabel = \"t\"", &format!("tokenLabel = \"t\"\n{line}"));
    refused(with_token("scratchId = \"zz\""), "is not a hex CKA_ID");
    refused(with_token("scratchId = \"\""), "is not a hex CKA_ID");
    // A transport key: an RSA private key of at least 2048 bits that unwraps and never leaves.
    let rsa = |bits: u32| format!("class = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_RSA\"\nmodulusBits = {bits}");
    let unwraps = "attributes = { CKA_UNWRAP = true, CKA_EXTRACTABLE = false }";
    let transport = |object: &str, spec: &str| {
        keys(object, spec, "").replace("tokenLabel = \"t\"", "tokenLabel = \"t\"\ntransportWith = \"s\"")
    };
    load(&transport(&rsa(2048), unwraps)).unwrap();
    refused(transport(EC, SIGN), "a transport key is an RSA private key");
    refused(transport(&rsa(1024), unwraps), "at least 2048 bits");
    refused(
        transport(&rsa(2048), "attributes = { CKA_UNWRAP = true }"),
        "CKA_UNWRAP = true and CKA_EXTRACTABLE = false",
    );
    refused(
        transport(&rsa(2048), unwraps).replace("transportWith = \"s\"", "transportWith = \"nope\""),
        "names no spec",
    );
    // createOn names a token the object has a spec on.
    let born = keys(EC, SIGN, "").replace("curve = \"secp256r1\"", "curve = \"secp256r1\"\ncreateOn = \"u\"")
        + "\n[tokens.u]\ntokenLabel = \"u\"\n";
    refused(born, "no spec realises it on 'u'");
}

#[test]
fn schemes_and_assurance_names_follow_the_class() {
    let schemes = |object: &str, spec: &str| {
        let cfg = load(&keys(object, spec, "")).unwrap();
        Target::new(&cfg, "s", "t").unwrap().schemes()
    };
    assert_eq!(schemes(CERT, ""), [Scheme::Certhash, Scheme::Rfc7093m4]);
    let secret = "class = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_GENERIC_SECRET\"\nvalueLen = 32";
    assert_eq!(schemes(secret, SIGN), [Scheme::Commitment]);
    let names = [Assurance::Proof, Assurance::Fingerprint, Assurance::Public].map(Assurance::name);
    assert_eq!(names, ["proof", "fingerprint", "public"]);
    // An object's type reads back as keys.toml writes it.
    let cfg = load(&keys(EC, SIGN, "")).unwrap();
    let shown = cfg.objects["o"].to_string();
    assert_eq!(shown, "{ class = \"CKO_PRIVATE_KEY\", keyType = \"CKK_EC\", curve = \"secp256r1\" }");
    let located = load(&keys(EC, SIGN, "").replace("CKA_LABEL = \"o\"", "CKA_LABEL = \"o\", CKA_ID = \"0a\"")).unwrap();
    assert!(located.specs["s"].tokens["t"].locator.to_string().contains("CKA_ID = \"0a\""));
}

#[test]
fn locks_that_contradict_themselves_are_invalid() {
    let sri = cakeys_core::id::sri(b"x");
    let refused = |text: String, why: &str| {
        let e = parse_lock(&text, Path::new("keys.lock")).unwrap_err();
        assert!(e.exit_code() == 17 && e.to_string().contains(why), "expected {why:?} in {e}");
    };
    let object = "version = 1\n[objects.k]\ntype = { class = \"CKO_PRIVATE_KEY\", keyType = \"CKK_EC\", curve = \"secp256r1\" }\n";
    refused(format!("{object}publicKey = \"AAAA\"\n[objects.k.ids]\ncerthash = \"{sri}\"\n"), "publicKey");
    refused(format!("{object}publicKey = \"!\"\n[objects.k.ids]\nrfc7093m4 = \"{sri}\"\n"), "publicKey is not base64");
    refused(format!("{object}publicKey = \"AAAA\"\n[objects.k.ids]\nrfc7093m4 = \"{sri}\"\n"), "publicKey hashes to");
    refused("version = 2\n".into(), "lock version 2 is not supported");
    refused(
        format!(
            "version = 1\n[observations.\"{sri}\"]\nmechanisms = []\nmodule = {{ path = \"/m.so\", hash = \"md5-x\", description = \"\", manufacturer = \"\", version = \"\", cryptoki = \"\" }}\n"
        ),
        "module hash",
    );
    refused("version = 1\n[observations.short]\nmechanisms = []\n".into(), "is not a sha256 SRI digest");
    // A directory is no lock file: an I/O error, not an empty lock.
    let e = cakeys_core::config::load_lock(Path::new(env!("CARGO_MANIFEST_DIR"))).unwrap_err();
    assert_eq!(e.exit_code(), 1, "{e}");
}

/// Every curve cakeys names parses from its own PKCS#8 into its private scalar and its public
/// key; a key of another type than asked for, or of no type cakeys reads, is refused.
#[test]
fn every_curve_parses_from_pkcs8() {
    macro_rules! ec {
        ($key:ty, $curve:literal, $bytes:expr) => {{
            let key = <$key>::from_slice(&$bytes).unwrap();
            let der = key.to_pkcs8_der().unwrap();
            let PrivateParts::Ec(v) = private_from_pkcs8(der.as_bytes(), KeyType::Ec, Some($curve)).unwrap() else {
                unreachable!("an EC curve yields an EC scalar")
            };
            assert_eq!(v.as_slice(), &$bytes[..], $curve);
            let spki = key.public_key().to_public_key_der().unwrap();
            assert_eq!(spki_of_pkcs8(der.as_bytes()).unwrap(), spki.as_bytes(), $curve);
        }};
    }
    ec!(p384::SecretKey, "secp384r1", [7u8; 48]);
    ec!(p521::SecretKey, "secp521r1", [1u8; 66]);
    ec!(k256::SecretKey, "secp256k1", [7u8; 32]);
    ec!(bp256::r1::SecretKey, "brainpoolP256r1", [7u8; 32]);
    ec!(bp384::r1::SecretKey, "brainpoolP384r1", [7u8; 48]);
    let ed = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
    let der = ed.to_pkcs8_der().unwrap();
    assert_eq!(spki_of_pkcs8(der.as_bytes()).unwrap(), ed.verifying_key().to_public_key_der().unwrap().as_bytes());
    // Asked for as another type, or a type with no parser: refused, the bytes never echoed.
    assert!(matches!(private_from_pkcs8(der.as_bytes(), KeyType::Ec, Some("secp384r1")), Err(KmError::Conflict(_))));
    let e = private_from_pkcs8(der.as_bytes(), KeyType::Aes, Some("secp256r1")).err().unwrap();
    assert!(matches!(&e, KmError::Unsupported(m) if m.contains("on secp256r1")), "{e}");
    assert!(matches!(spki_of_pkcs8(b"no key at all"), Err(KmError::Unsupported(_))));
}

/// A proof of possession needs a verifier for the key's type: Ed448 has none, and bytes that
/// are no public key name themselves by their digest.
#[test]
fn proofs_need_a_verifier_for_the_key() {
    let ed448 = ed448::pkcs8::PublicKeyBytes([3u8; 57]).to_public_key_der().unwrap();
    let e = cakeys_core::pop::verify(ed448.as_bytes(), b"m", b"s").unwrap_err();
    assert!(matches!(&e, KmError::Unsupported(m) if m.contains("no Ed448 signature verifier")), "{e}");
    let e = cakeys_core::pop::verify(b"junk", b"m", b"s").unwrap_err();
    assert!(matches!(&e, KmError::Unsupported(m) if m.contains("not an ECDSA, Ed25519 or RSA key")), "{e}");
}
