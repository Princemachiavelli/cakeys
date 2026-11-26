//! The inputs that the load of keys.toml and of a lock, the plan of a target, and the read of a
//! key refuse, each with the message that gives the reason. These tests fill the gaps of the
//! coverage report in `config`, `plan`, `pop` and `plaintext`, and none of them needs a token.

use cakeys_core::KmError;
use cakeys_core::config::{Binding, Config, Mode, ObjectKind, parse_config_with, parse_lock};
use cakeys_core::id::{Curve, Scheme};
use cakeys_core::plaintext::{PrivateParts, private_from_pkcs8, spki_of_pkcs8};
use cakeys_core::plan::{Assurance, Target, binding, expected_binding, plan_mode};
use cakeys_core::types::KeyType;
use ed25519_dalek::pkcs8::{EncodePrivateKey as _, EncodePublicKey as _};
use std::path::Path;

/// The RSA signature that the PKCS#11 baseline makes: PKCS#1 v1.5 over SHA-256.
const V15: cakeys_core::pop::RsaSignature = cakeys_core::pop::RsaSignature::Pkcs1v15(cakeys_core::pop::HashAlg::Sha256);

/// Returns a keys.toml with one token `t`, one object `o` with the lines `object`, and one spec
/// `s` on `t` with the lines `spec` and the entries `on_token` next to the locator. The pair gets
/// `origin = "adopt"` unless `on_token` names an origin.
fn keys(object: &str, spec: &str, on_token: &str) -> String {
    let origin = if on_token.contains("origin") { "" } else { ", origin = \"adopt\"" };
    format!(
        "[tokens.t]\ntokenLabel = \"t\"\n\n[objects.o]\n{object}\n\n[specs.s]\nobject = \"o\"\n{spec}\n\
         tokens.t = {{ locator = {{ CKA_LABEL = \"o\" }}{on_token}{origin} }}\n"
    )
}

fn load(text: &str) -> cakeys_core::Result<Config> {
    parse_config_with(text, Path::new("keys.toml"), &|_| None)
}

/// Returns how `text` is refused, as its exit code and the reason, at load or when its one target
/// is planned. The exit code is part of the contract of cakeys, and the message distinguishes the
/// rules that share an exit code, so a table pins both (review `refusals.rs` F1).
fn refusal(text: &str) -> (u8, String) {
    let e = match load(text) {
        Err(e) => e,
        Ok(cfg) => match Target::new(&cfg, "s", "t").and_then(|t| plan_mode(&t)) {
            Err(e) => e,
            Ok(mode) => panic!("accepted as {mode}:\n{text}"),
        },
    };
    (e.exit_code(), e.to_string())
}

/// Asserts that `text` is refused with `code`, and that the message contains `why`.
fn refused_with(text: &str, code: u8, why: &str) {
    let (got, said) = refusal(text);
    assert!(got == code && said.contains(why), "expected {code} and {why:?}, got {got}: {said}");
}

const EC: &str = "class = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"";
const AES: &str = "class = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_AES\"\nvalueLen = 32";
const CERT: &str = "class = \"CKO_CERTIFICATE\"\ncertificateType = \"CKC_X_509\"";
const SIGN: &str = "attributes = { CKA_SIGN = true }";

#[test]
fn specs_that_cannot_hold_are_refused_with_why() {
    // An invalid spec exits with 17, and a type that cakeys does not manage exits with 15
    // (`every_object_is_typed_at_load`).
    let cases: &[(&str, &str, &str, u8, &str)] = &[
        (AES, SIGN, ", binding = \"pop-sign\"", 17, "applies to private keys only"),
        (EC, SIGN, ", publicOnly = true, binding = \"pop-sign\"", 17, "publicOnly cannot prove possession"),
        (
            "class = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC_EDWARDS\"\ncurve = \"edwards25519\"",
            "attributes = { CKA_DERIVE = true }",
            ", binding = \"pop-ecdh\"",
            17,
            "Weierstrass EC keys",
        ),
        (
            EC,
            "attributes = { CKA_SIGN = true, CKA_DERIVE = [\"CKM_ECDSA\"] }",
            "",
            17,
            "only CKA_ALLOWED_MECHANISMS takes a mechanism list",
        ),
        (EC, "attributes = { CKA_SIGN = true, CKA_BOGUS = true }", "", 17, "unsupported policy attribute CKA_BOGUS"),
        (
            "class = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"",
            SIGN,
            "",
            15,
            "CKO_SECRET_KEY/CKK_EC",
        ),
        (
            AES,
            "attributes = { CKA_SIGN = true }\npublicAttributes = { CKA_VERIFY = true }",
            "",
            17,
            "private keys only",
        ),
        (
            "class = \"CKO_CERTIFICATE\"\ncertificateType = \"CKC_WTLS\"",
            "",
            "",
            15,
            "manages CKC_X_509 certificates only",
        ),
        (&format!("{EC}\ncertificateType = \"CKC_X_509\""), SIGN, "", 17, "certificates only"),
        (&format!("{CERT}\nkeyType = \"CKK_RSA\""), "", "", 17, "keyType"),
        ("class = \"CKO_DATA\"", "", ", attestation = true", 17, "key objects only"),
        ("class = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp112r1\"", SIGN, "", 15, "secp112r1"),
        ("class = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_RSA\"", SIGN, "", 15, "CKK_RSA"),
    ];
    for (object, spec, on_token, code, why) in cases {
        refused_with(&keys(object, spec, on_token), *code, why);
    }
}

/// Every object's type is parsed at load (`ObjectCfg::kind`), whether a spec uses the object or
/// not. A field that has no meaning for its class or key type is invalid (17). What PKCS#11 has
/// but cakeys does not manage (a combination of class and key type, or a certificate type) is
/// unsupported (15).
#[test]
fn every_object_is_typed_at_load() {
    let unused = |object: &str| format!("{}\n[objects.unused]\n{object}\n", keys(EC, SIGN, ""));
    for (object, code, why) in [
        ("class = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_AES\"\nmodulusBits = 2048", 17, "modulusBits applies to CKK_RSA"),
        ("class = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_RSA\"\ncurve = \"secp256r1\"", 17, "curve applies to"),
        ("class = \"CKO_PUBLIC_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"P-256\"\nvalueLen = 32", 17, "valueLen applies"),
        ("class = \"CKO_DATA\"\nkeyType = \"CKK_AES\"", 17, "keyType applies to keys only"),
        ("class = \"CKO_CERTIFICATE\"", 17, "certificates need certificateType"),
        ("class = \"CKO_CERTIFICATE\"\ncertificateType = \"CKC_X509\"", 17, "is no PKCS#11 certificate type"),
        ("class = \"CKO_CERTIFICATE\"\ncertificateType = \"CKC_X_509_ATTR_CERT\"", 15, "CKC_X_509 certificates only"),
        ("class = \"CKO_CERTIFICATE\"\ncertificateType = \"CKC_WTLS\"", 15, "CKC_X_509 certificates only"),
        ("class = \"CKO_CERTIFICATE\"\ncertificateType = \"CKC_VENDOR_DEFINED\"", 15, "CKC_X_509 certificates only"),
        ("class = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_AES\"", 15, "CKO_PRIVATE_KEY/CKK_AES"),
        ("class = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"brainpoolP512r1\"", 15, "no RustCrypto crate"),
    ] {
        let e = load(&unused(object)).unwrap_err();
        assert_eq!(e.exit_code(), code, "{e}");
        assert!(e.to_string().contains("object 'unused'") && e.to_string().contains(why), "{why}: {e}");
    }
    let des3 = load(&unused("class = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_DES3\"")).unwrap();
    let kind = des3.objects["unused"].kind().unwrap();
    assert_eq!(kind, ObjectKind::Secret { key_type: KeyType::Des3, value_len: Some(24) });
}

/// A configuration that loads is usable (review D1). Every rule that needs only keys.toml is
/// checked at load, so that no verb, including `validate`, meets a spec that loaded but is then
/// refused at every use. An empty `CKA_ID` is the ID of a real object and loads. Hex is stored in
/// lower case, so `0A` and `0a` name one object.
#[test]
fn what_loads_is_usable() {
    let at_load = |text: &str, why: &str| {
        let e = load(text).err().unwrap_or_else(|| panic!("loaded:\n{text}"));
        assert!(
            matches!(&e, KmError::Validation(m) if m.starts_with("keys.toml: ") && m.contains(why)),
            "expected {why:?} at load: {e}"
        );
    };
    let located = |locator: &str| keys(EC, SIGN, "").replace("{ CKA_LABEL = \"o\" }", locator);
    at_load(&keys(EC, SIGN, "").replace("[tokens.t]", "[tokens.u]"), "unknown token 't'");
    at_load(&located("{}"), "locator needs CKA_LABEL and/or CKA_ID");
    at_load(&located("{ CKA_ID = \"zz\" }"), "CKA_ID 'zz' is not hex");
    at_load(&located("{ CKA_ID = \"0\" }"), "CKA_ID '0' is not hex");
    for len in [0, 20, 64] {
        let aes = AES.replace("valueLen = 32", &format!("valueLen = {len}"));
        at_load(&keys(&aes, SIGN, ""), "an AES key is 16, 24 or 32 bytes");
    }
    let generic = "class = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_GENERIC_SECRET\"\nvalueLen = 0";
    at_load(&keys(generic, SIGN, ""), "valueLen 0");
    // The plan of the spec itself: a binding that its class cannot have, and a secret key
    // without an identity that can be verified again.
    at_load(&keys(AES, SIGN, ", binding = \"pop-sign\""), "applies to private keys only");
    at_load(&keys(AES, "attributes = { CKA_SIGN = false }", ""), "no re-verifiable identity");

    let id = |cfg: &Config| cfg.specs["s"].tokens["t"].locator.id.clone();
    assert_eq!(id(&load(&located("{ CKA_LABEL = \"o\", CKA_ID = \"\" }")).unwrap()), Some(String::new()));
    assert_eq!(id(&load(&located("{ CKA_ID = \"0A\" }")).unwrap()), Some("0a".into()));
}

#[test]
fn names_that_select_nothing_are_refused() {
    let cfg = load(&keys(EC, SIGN, "")).unwrap();
    let e = Target::new(&cfg, "s", "elsewhere").err().unwrap();
    assert!(matches!(&e, KmError::NotFound(m) if m.contains("has no token 'elsewhere'")), "{e}");
    let e = Target::new(&cfg, "nope", "t").err().unwrap();
    assert!(matches!(&e, KmError::NotFound(m) if m.contains("'nope'")), "{e}");
    // A spec whose object keys.toml does not define is refused at load (17). A spec that is
    // realised on a token that `[tokens]` does not define is also refused at load
    // (`what_loads_is_usable`), and the plan still refuses it, for a config that was built in
    // another way.
    let e = load(&keys(EC, SIGN, "").replace("object = \"o\"", "object = \"gone\"")).unwrap_err();
    assert!(e.exit_code() == 17 && e.to_string().contains("'gone'"), "{e}");
    // The address returns an object's one (spec, token) pair, or the reason why there is not
    // exactly one pair. Every part of the address must name something that keys.toml has, or
    // the run is invalid (17).
    assert_eq!(cfg.address(Some("o"), None, None).unwrap(), ("s".to_owned(), "t".to_owned()));
    assert_eq!(cfg.address(None, Some("s"), None).unwrap(), ("s".to_owned(), "t".to_owned()));
    for (object, spec, token, why) in [
        (None, None, None, "name an object, or a spec with --spec"),
        (Some("nope"), None, None, "unknown object 'nope'"),
        (None, Some("nope"), None, "unknown spec 'nope'"),
        (Some("o"), None, Some("elsewhere"), "unknown token 'elsewhere'"),
    ] {
        let e = cfg.address(object, spec, token).unwrap_err();
        assert!(matches!(&e, KmError::Validation(m) if m.contains(why)), "{why}: {e}");
    }
    let two = keys(EC, SIGN, "")
        + "\n[specs.s2]\nobject = \"o\"\nattributes = { CKA_SIGN = true }\ntokens.t = { locator = { CKA_LABEL = \"o2\" }, origin = \"adopt\" }\n";
    assert!(matches!(load(&two).unwrap().address(Some("o"), None, None), Err(KmError::Ambiguous(_))));
}

#[test]
fn token_and_creation_rules_are_checked_at_load() {
    // Each config is invalid (17) at load, and the message distinguishes the cases.
    let refused = |text: String, why: &str| {
        let e = load(&text).unwrap_err();
        assert!(e.exit_code() == 17 && e.to_string().contains(why), "expected 17 and {why:?}: {e}");
    };
    let with_token =
        |line: &str| keys(EC, SIGN, "").replace("tokenLabel = \"t\"", &format!("tokenLabel = \"t\"\n{line}"));
    // A provider names a family, and `moduleProfile` names one profile of that same family.
    refused(
        with_token("provider = \"aws-cloudhsm/5.18+hsm2m-non-fips\""),
        "name its family in provider and the profile in moduleProfile",
    );
    refused(
        with_token("provider = \"softhsm\"\nmoduleProfile = \"aws-cloudhsm/5.18+hsm2m-non-fips\""),
        "is not of provider 'softhsm''s family",
    );
    load(&with_token("moduleProfile = \"aws-cloudhsm/5.18+hsm2m-non-fips\"")).unwrap();
    refused(with_token("probe = { scratchId = \"zz\" }"), "is not a hex CKA_ID");
    refused(with_token("probe = { scratchId = \"\" }"), "is not a hex CKA_ID");
    // The probe's scratch slot must not be a slot in which keys.toml keeps a key on that token,
    // in either case of the hex (review 2026-11-23 D-1: with an ID that differed by one digit,
    // the probe overwrote a real key).
    let at_id = |scratch: &str| {
        with_token(&format!("probe = {{ scratchId = \"{scratch}\" }}"))
            .replace("locator = { CKA_LABEL = \"o\" }", "locator = { CKA_ID = \"0a\" }")
    };
    refused(at_id("0A"), "probe.scratchId 0a is the CKA_ID of spec 's''s locator there");
    load(&at_id("0b")).unwrap();
    // A transport key is an RSA private key of at least 2048 bits that may unwrap and never
    // leaves the token.
    let rsa = |bits: u32| format!("class = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_RSA\"\nmodulusBits = {bits}");
    let unwraps = "attributes = { CKA_UNWRAP = true, CKA_EXTRACTABLE = false }";
    let transport = |object: &str, spec: &str| {
        keys(object, spec, ", binding = \"pop-unwrap\"")
            .replace("tokenLabel = \"t\"", "tokenLabel = \"t\"\nmigrate = { transportWith = \"s\" }")
    };
    load(&transport(&rsa(2048), unwraps)).unwrap();
    refused(transport(EC, SIGN), "a transport key is an RSA private key");
    refused(transport(&rsa(1024), unwraps), "at least 2048 bits");
    refused(
        transport(&rsa(2048), "attributes = { CKA_UNWRAP = true }"),
        "CKA_UNWRAP = true and CKA_EXTRACTABLE = false",
    );
    refused(
        transport(&rsa(2048), unwraps)
            .replace("migrate = { transportWith = \"s\" }", "migrate = { transportWith = \"nope\" }"),
        "names no spec",
    );
    // A token's transport key is on that token, so another token cannot name it.
    refused(
        transport(&rsa(2048), unwraps) + "\n[tokens.u]\ntokenLabel = \"u\"\nmigrate = { transportWith = \"s\" }\n",
        "token 'u': migrate.transportWith = \"s\", but that spec does not realise it on 'u'",
    );
    // A key states how it gets onto its token, and it is created at most once.
    refused(keys(EC, SIGN, ", origin = \"made\""), "unknown variant `made`");
    let twice = keys(EC, SIGN, ", origin = \"create\"")
        + "\n[tokens.u]\ntokenLabel = \"u\"\n\n[specs.s2]\nobject = \"o\"\n\
           tokens.u = { locator = { CKA_LABEL = \"o\" }, origin = \"create\" }\n";
    refused(twice, "has origin = \"create\" on several pairs");
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
    // A key pair is identified by its public key, and a data object by its value. An AES key is
    // identified by the commitments that its declared usage allows, strongest first, and by all
    // of them when it declares no usage (because a wrap out of the token computes each of them).
    assert_eq!(schemes(EC, SIGN), [Scheme::Rfc7093m4]);
    assert_eq!(
        schemes("class = \"CKO_PUBLIC_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"", ""),
        [Scheme::Rfc7093m4]
    );
    assert_eq!(schemes("class = \"CKO_DATA\"", ""), [Scheme::Valuehash]);
    assert_eq!(schemes(AES, "attributes = { CKA_WRAP = true, CKA_SIGN = true }"), [Scheme::Cmac, Scheme::Kw]);
    assert_eq!(schemes(AES, "attributes = { CKA_DECRYPT = true }"), [Scheme::KcvEcbDec]);
    assert_eq!(
        schemes(AES, "attributes = { CKA_EXTRACTABLE = true }"),
        [Scheme::Cmac, Scheme::KcvEcb, Scheme::KcvEcbDec, Scheme::Kw]
    );
    let names = [Assurance::Proof, Assurance::Fingerprint, Assurance::Public].map(Assurance::name);
    assert_eq!(names, ["proof", "fingerprint", "public"]);
    // An object's type prints in the form that keys.toml uses.
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
    refused(
        format!("{object}publicKey = \"AAAA\"\n[objects.k.ids]\ncerthash = \"{sri}\"\n"),
        "publicKey without an rfc7093m4 ID",
    );
    refused(format!("{object}publicKey = \"!\"\n[objects.k.ids]\nrfc7093m4 = \"{sri}\"\n"), "publicKey is not base64");
    refused(format!("{object}publicKey = \"AAAA\"\n[objects.k.ids]\nrfc7093m4 = \"{sri}\"\n"), "publicKey hashes to");
    refused("version = 2\n".into(), "lock version 2 is not supported");
    refused(
        format!(
            "version = 1\n[observations.\"{sri}\"]\nmechanisms = []\nmodule = {{ path = \"/m.so\", hash = \"md5-x\", description = \"\", manufacturer = \"\", version = \"\", cryptoki = \"\" }}\n"
        ),
        "module hash",
    );
    // The load checks the module hash of every observation, not only of the first one with a
    // hash. Before, a valid hash that sorted first allowed an invalid hash after it to load.
    let (first, second) = {
        let (a, b) = (cakeys_core::id::sri(b"a"), cakeys_core::id::sri(b"b"));
        if a < b { (a, b) } else { (b, a) }
    };
    let observation = |key: &str, hash: &str| {
        format!(
            "[observations.\"{key}\"]\nmechanisms = []\nmodule = {{ path = \"/m.so\", hash = \"{hash}\", description = \"\", manufacturer = \"\", version = \"\", cryptoki = \"\" }}\n"
        )
    };
    refused(
        format!("version = 1\n{}{}", observation(&first, &sri), observation(&second, "md5-x")),
        "module hash \"md5-x\"",
    );
    refused("version = 1\n[observations.short]\nmechanisms = []\n".into(), "is not a sha256 SRI digest");
    // A directory is not a lock file, so the load fails with an I/O error and does not return an
    // empty lock.
    let e = cakeys_core::config::load_lock(Path::new(env!("CARGO_MANIFEST_DIR"))).unwrap_err();
    assert_eq!(e.exit_code(), 1, "{e}");
}

/// A key on every curve that cakeys names parses from its own PKCS#8 into its private scalar and
/// its public key. A key of a different type than the requested type, or of a type that cakeys
/// does not read, is refused.
#[test]
fn every_curve_parses_from_pkcs8() {
    macro_rules! ec {
        ($key:ty, $curve:literal, $bytes:expr) => {{
            let key = <$key>::from_slice(&$bytes).unwrap();
            let der = key.to_pkcs8_der().unwrap();
            let PrivateParts::Ec(v) =
                private_from_pkcs8(der.as_bytes(), KeyType::Ec, Curve::from_cfg(KeyType::Ec, $curve)).unwrap()
            else {
                unreachable!("an EC curve yields an EC scalar")
            };
            assert_eq!(v.as_slice(), &$bytes[..], $curve);
            let spki = key.public_key().to_public_key_der().unwrap();
            assert_eq!(spki_of_pkcs8(der.as_bytes()).unwrap(), spki.as_bytes(), $curve);
            assert_eq!(cakeys_core::id::spki_canonical(spki.as_bytes()).unwrap(), spki.as_bytes(), $curve);
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
    // A key requested as a different type, or as a type without a parser, is refused, and the
    // error never repeats the bytes.
    assert!(matches!(private_from_pkcs8(der.as_bytes(), KeyType::Ec, Some(Curve::P384)), Err(KmError::Conflict(_))));
    let e = private_from_pkcs8(der.as_bytes(), KeyType::Aes, Some(Curve::P256)).err().unwrap();
    assert!(matches!(&e, KmError::Unsupported(m) if m.contains("on secp256r1")), "{e}");
    assert!(matches!(spki_of_pkcs8(b"no key at all"), Err(KmError::Unsupported(_))));
    // An Edwards curve has no ECDSA hash, because its proof uses EdDSA.
    assert!(cakeys_core::pop::HashAlg::for_curve(cakeys_core::id::Curve::Ed25519).is_none());
}

/// A proof of possession needs a verifier for the key's type. Ed448 has no verifier, and the
/// error for bytes that are not a public key names the bytes by their digest.
#[test]
fn proofs_need_a_verifier_for_the_key() {
    let ed448 = ed448::pkcs8::PublicKeyBytes([3u8; 57]).to_public_key_der().unwrap();
    let e = cakeys_core::pop::verify(ed448.as_bytes(), b"m", b"s", V15).unwrap_err();
    assert!(matches!(&e, KmError::Unsupported(m) if m.contains("no Ed448 signature verifier")), "{e}");
    let e = cakeys_core::pop::verify(b"junk", b"m", b"s", V15).unwrap_err();
    assert!(matches!(&e, KmError::Unsupported(m) if m.contains("not a SubjectPublicKeyInfo")), "{e}");
}

const RSA: &str = "class = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_RSA\"\nmodulusBits = 2048";
const ED448: &str = "class = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC_EDWARDS\"\ncurve = \"edwards448\"";

fn planned(object: &str, spec: &str, on_token: &str) -> (Mode, Option<Binding>, Option<Binding>) {
    let text = keys(object, spec, on_token);
    let cfg = load(&text).unwrap_or_else(|e| panic!("{e}:\n{text}"));
    let t = Target::new(&cfg, "s", "t").unwrap();
    let mode = plan_mode(&t).unwrap_or_else(|e| panic!("{e}:\n{text}"));
    (mode, binding(&t), expected_binding(&t))
}

/// A private key proves possession in the way that its type and its declared usage allow
/// (docs/DESIGN.md §3.6). Each binding is accepted on the key that it fits, with the usage bit
/// that it needs, and it is refused everywhere else with the reason for that binding.
#[test]
fn a_binding_fits_its_key_and_usage_or_is_refused() {
    use Binding::{PopDecrypt, PopEcdh, PopSign, PopSignPin, PopUnwrap, TokenAsserted};
    let flag = |name: &str| format!("attributes = {{ {name} = true }}");
    let per_use = |name: &str| format!("attributes = {{ {name} = true, CKA_ALWAYS_AUTHENTICATE = true }}");
    let with = |b: &str| format!(", binding = \"{b}\"");
    let accepted: &[(&str, String, String, Binding, Binding)] = &[
        (EC, flag("CKA_SIGN"), String::new(), PopSign, PopSign),
        (EC, flag("CKA_SIGN"), with("pop-sign"), PopSign, PopSign),
        // The token decides whether to demand the PIN for each use, so the binding is planned
        // as pop-sign and expected as pop-sign-pin.
        (EC, per_use("CKA_SIGN"), String::new(), PopSign, PopSignPin),
        (EC, flag("CKA_DERIVE"), with("pop-ecdh"), PopEcdh, PopEcdh),
        (RSA, flag("CKA_DECRYPT"), with("pop-decrypt"), PopDecrypt, PopDecrypt),
        (RSA, flag("CKA_UNWRAP"), with("pop-unwrap"), PopUnwrap, PopUnwrap),
        (RSA, flag("CKA_SIGN"), String::new(), PopSign, PopSign),
        // The key has no usage with which to prove possession, and the spec states that. A PIN
        // for each use does not change that.
        (EC, flag("CKA_DERIVE"), with("token-asserted"), TokenAsserted, TokenAsserted),
        (EC, per_use("CKA_DERIVE"), with("token-asserted"), TokenAsserted, TokenAsserted),
        (ED448, flag("CKA_SIGN"), with("token-asserted"), TokenAsserted, TokenAsserted),
        (EC, String::new(), ", publicOnly = true".into(), TokenAsserted, TokenAsserted),
    ];
    for (object, spec, on_token, plan, expect) in accepted {
        let got = planned(object, spec, on_token);
        assert_eq!(got, (Mode::Direct, Some(*plan), Some(*expect)), "{object}\n{spec}\n{on_token}");
    }
    let refused: &[(&str, String, String, &str)] = &[
        (EC, flag("CKA_SIGN"), with("pop-sign-pin"), "is recorded, not configured"),
        (ED448, flag("CKA_SIGN"), String::new(), "no Ed448 verifier"),
        (EC, flag("CKA_DERIVE"), String::new(), "needs CKA_SIGN = true"),
        (EC, "attributes = { CKA_SIGN = false }".into(), with("pop-sign"), "needs CKA_SIGN = true"),
        (EC, per_use("CKA_DERIVE"), with("pop-ecdh"), "binding = \"pop-ecdh\" has no point for that login"),
        (RSA, per_use("CKA_DECRYPT"), with("pop-decrypt"), "binding = \"pop-decrypt\" has no point for that login"),
        (RSA, per_use("CKA_UNWRAP"), with("pop-unwrap"), "binding = \"pop-unwrap\" has no point for that login"),
        (RSA, flag("CKA_DERIVE"), with("pop-ecdh"), "it applies to EC private keys only"),
        (EC, flag("CKA_SIGN"), with("pop-ecdh"), "needs CKA_DERIVE = true"),
        (EC, "attributes = { CKA_DERIVE = false }".into(), with("pop-ecdh"), "needs CKA_DERIVE = true"),
        (EC, flag("CKA_DECRYPT"), with("pop-decrypt"), "by decrypting: it applies to RSA private keys only"),
        (RSA, flag("CKA_SIGN"), with("pop-decrypt"), "needs CKA_DECRYPT = true"),
        (RSA, "attributes = { CKA_DECRYPT = false }".into(), with("pop-decrypt"), "needs CKA_DECRYPT = true"),
        (EC, flag("CKA_UNWRAP"), with("pop-unwrap"), "by unwrapping: it applies to RSA private keys only"),
        (RSA, flag("CKA_SIGN"), with("pop-unwrap"), "needs CKA_UNWRAP = true"),
        (RSA, "attributes = { CKA_UNWRAP = false }".into(), with("pop-unwrap"), "needs CKA_UNWRAP = true"),
    ];
    // Each spec is invalid (17), and the message distinguishes the cases.
    for (object, spec, on_token, why) in refused {
        refused_with(&keys(object, spec, on_token), 17, why);
    }
    // Other classes have no binding to plan or to expect.
    assert_eq!(planned(AES, SIGN, ""), (Mode::Commitment, None, None));
    assert_eq!(planned(CERT, "", ""), (Mode::Direct, None, None));
}

/// The identity mode follows what the spec declares (docs/DESIGN.md §3.4). Asymmetric keys and
/// public objects are hashed directly. A secret key is identified by a commitment that its usage
/// allows, otherwise by a wrap when it is extractable, and otherwise not at all. A spec that asks
/// a class for something that the class cannot do is refused.
#[test]
fn the_identity_mode_follows_the_declared_usage() {
    const HMAC: &str = "class = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_GENERIC_SECRET\"\nvalueLen = 32";
    const PUBLIC: &str = "class = \"CKO_PUBLIC_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"";
    let mode = |object: &str, spec: &str, on_token: &str| planned(object, spec, on_token).0;
    for usage in ["CKA_SIGN", "CKA_ENCRYPT", "CKA_DECRYPT", "CKA_WRAP"] {
        assert_eq!(mode(AES, &format!("attributes = {{ {usage} = true }}"), ""), Mode::Commitment, "{usage}");
    }
    assert_eq!(mode(AES, "attributes = { CKA_EXTRACTABLE = true }", ""), Mode::WrapRebind);
    assert_eq!(mode(AES, "attributes = { CKA_SIGN = false, CKA_EXTRACTABLE = true }", ""), Mode::WrapRebind);
    assert_eq!(mode(HMAC, SIGN, ""), Mode::Commitment);
    // An HMAC key computes a commitment only by signing. Encryption gives it no commitment.
    assert_eq!(mode(HMAC, "attributes = { CKA_ENCRYPT = true, CKA_EXTRACTABLE = true }", ""), Mode::WrapRebind);
    assert_eq!(mode(PUBLIC, "", ""), Mode::Direct);
    assert_eq!(mode("class = \"CKO_DATA\"", "", ""), Mode::Direct);
    assert_eq!(mode(CERT, "", ""), Mode::Direct);
    assert_eq!(mode(EC, SIGN, ", attestation = true"), Mode::Direct);
    assert_eq!(mode(AES, SIGN, ", attestation = true"), Mode::Commitment);
    // An adopted trusted key is only read. A generated trusted key would need the token to set
    // `CKA_TRUSTED`.
    assert_eq!(mode(AES, "attributes = { CKA_WRAP = true, CKA_TRUSTED = true }", ""), Mode::Commitment);
    assert_eq!(mode(AES, "attributes = { CKA_WRAP = true, CKA_TRUSTED = false }", ""), Mode::Commitment);
    assert_eq!(
        mode(EC, "attributes = { CKA_SIGN = true }\npublicAttributes = { CKA_VERIFY = true }", ""),
        Mode::Direct
    );
    let cases: &[(&str, &str, &str, &str)] = &[
        (AES, "", "", "has no re-verifiable identity"),
        (AES, "attributes = { CKA_SIGN = false }", "", "has no re-verifiable identity"),
        (HMAC, "attributes = { CKA_ENCRYPT = true }", "", "has no re-verifiable identity"),
        ("class = \"CKO_CERTIFICATE\"", "", "", "certificates need certificateType"),
        (AES, SIGN, ", publicOnly = true", "publicOnly applies to private keys only"),
        (EC, SIGN, ", publicOnly = true", "publicOnly cannot verify private-key policy attributes"),
        (CERT, "", ", attestation = true", "attestation = true applies to key objects only"),
        (EC, "attributes = { CKA_SIGN = true, CKA_WRAP = true }", "", "CKA_WRAP does not apply to"),
        (
            EC,
            "attributes = { CKA_SIGN = true }\npublicAttributes = { CKA_SIGN = true }",
            "",
            "CKA_SIGN does not apply to",
        ),
        (
            CERT,
            "attributes = { CKA_ALLOWED_MECHANISMS = [\"CKM_ECDSA\"] }",
            "",
            "CKA_ALLOWED_MECHANISMS does not apply to",
        ),
    ];
    // Each spec is invalid (17), and the message distinguishes the cases.
    for (object, spec, on_token, why) in cases {
        refused_with(&keys(object, spec, on_token), 17, why);
    }
}

/// An object that `cakeys create` never makes, on any token, cannot have `origin = "create"` (17
/// at load). These are the classes that cakeys adopts, a `publicOnly` adoption, and a key that
/// the token's security officer must mark `CKA_TRUSTED`. Each one is a valid spec to adopt.
#[test]
fn what_create_never_makes_cannot_say_origin_create() {
    const PUBLIC: &str = "class = \"CKO_PUBLIC_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"";
    let create = ", origin = \"create\"";
    let trusted = "attributes = { CKA_WRAP = true, CKA_TRUSTED = true }";
    for (object, spec, on_token, why) in [
        (CERT, "", create, "CKO_CERTIFICATE objects are adopted or imported, never created"),
        (PUBLIC, "", create, "CKO_PUBLIC_KEY objects are adopted or imported, never created"),
        ("class = \"CKO_DATA\"", "", create, "CKO_DATA objects are adopted or imported, never created"),
        (EC, "", ", publicOnly = true, origin = \"create\"", "publicOnly adopts the public half, never origin"),
        (AES, trusted, create, "CKA_TRUSTED = true cannot be generated"),
    ] {
        let e = load(&keys(object, spec, on_token)).unwrap_err();
        assert!(e.exit_code() == 17 && e.to_string().contains(why), "expected 17 and {why:?}: {e}");
        load(&keys(object, spec, &on_token.replace("\"create\"", "\"adopt\""))).unwrap();
    }
    for (object, spec) in [(EC, SIGN), (AES, SIGN), (AES, "attributes = { CKA_WRAP = true, CKA_TRUSTED = false }")] {
        load(&keys(object, spec, create)).unwrap_or_else(|e| panic!("{e}: {object}\n{spec}"));
    }
}

/// Returns a lock's `[objects.<name>]` table: its type (by class and key type), its IDs, and
/// extra lines.
fn lock_object(name: &str, ty: &str, ids: &[(&str, &str)], extra: &str) -> String {
    let ids = ids.iter().map(|(s, v)| format!("{s} = \"{v}\"\n")).collect::<Vec<_>>().concat();
    format!("[objects.{name}]\n{extra}{ty}[objects.{name}.ids]\n{ids}\n")
}

const KEY_TYPE: &str = "type = { class = \"CKO_PRIVATE_KEY\", keyType = \"CKK_EC\", curve = \"secp256r1\" }\n";
const PUBLIC_TYPE: &str = "type = { class = \"CKO_PUBLIC_KEY\", keyType = \"CKK_EC\", curve = \"secp256r1\" }\n";
const CERT_TYPE: &str = "type = { class = \"CKO_CERTIFICATE\", certificateType = \"CKC_X_509\" }\n";
const AES_TYPE: &str = "type = { class = \"CKO_SECRET_KEY\", keyType = \"CKK_AES\", valueLen = 32 }\n";

/// The load checks the invariants of the lock's objects (docs/DESIGN.md §4): one object for each
/// material within a class, pairs that share a public key and list each other, and IDs with a
/// type and with a label where they need one. A lock that satisfies them loads, and its pairs are
/// computed from the shared public key.
#[test]
fn lock_objects_keep_their_invariants() {
    use base64::Engine as _;
    let (a, b, c) = (cakeys_core::id::sri(b"a"), cakeys_core::id::sri(b"b"), cakeys_core::id::sri(b"c"));
    let lock = |objects: &[String]| format!("version = 1\n{}", objects.concat());
    let loaded = |objects: &[String]| {
        let text = lock(objects);
        parse_lock(&text, Path::new("keys.lock")).unwrap_or_else(|e| panic!("{e}:\n{text}"))
    };
    let refused = |objects: &[String], why: &str| {
        let e = parse_lock(&lock(objects), Path::new("keys.lock")).unwrap_err();
        assert!(e.exit_code() == 17 && e.to_string().contains(why), "expected {why:?} in {e}");
    };
    let key = |name: &str, id: &str, extra: &str| lock_object(name, KEY_TYPE, &[("rfc7093m4", id)], extra);
    let cert = |name: &str, hash: &str, id: &str, extra: &str| {
        lock_object(name, CERT_TYPE, &[("certhash", hash), ("rfc7093m4", id)], extra)
    };

    // One material has one object in each class: a key, its public key object and two
    // certificates of the key share the public key. An object that records nothing yet is still
    // an object.
    let family = [
        key("k", &a, "pairs = [\"c1\", \"elsewhere\"]\n"),
        lock_object("p", PUBLIC_TYPE, &[("rfc7093m4", &a)], ""),
        cert("c1", &b, &a, "pairs = [\"k\"]\n"),
        cert("c2", &c, &a, ""),
        "[objects.empty]\n".to_owned(),
        lock_object("s", AES_TYPE, &[("cmac", &b)], "commitmentLabel = \"a label\"\n"),
    ];
    let l = loaded(&family);
    let names = |set: &[&str]| set.iter().map(|s| (*s).to_owned()).collect::<std::collections::BTreeSet<_>>();
    let pairs = l.computed_pairs();
    assert_eq!(pairs.keys().map(String::as_str).collect::<Vec<_>>(), ["c1", "c2", "k", "p"]);
    assert_eq!(pairs["k"], names(&["c1", "c2", "p"]));
    assert_eq!(pairs["c2"], names(&["c1", "k", "p"]));
    // The objects that share the key and are not listed yet. An object without a public key
    // shares no key.
    assert_eq!(l.unlisted_pairs("k"), names(&["c2", "p"]));
    assert_eq!(l.unlisted_pairs("c1"), names(&["c2", "p"]));
    assert_eq!(l.unlisted_pairs("p"), names(&["c1", "c2", "k"]));
    assert!(l.unlisted_pairs("s").is_empty() && l.unlisted_pairs("absent").is_empty());

    refused(&[key("k", &a, ""), key("k2", &a, "")], "'k' and 'k2' are the same CKO_PRIVATE_KEY material");
    refused(&[cert("c1", &b, &a, ""), cert("c2", &b, &c, "")], "'c1' and 'c2' are the same CKO_CERTIFICATE material");
    refused(&[key("k", &a, "pairs = [\"k\"]\n")], "lists itself as a pair");
    refused(&[key("k", &a, "pairs = [\"c\"]\n"), cert("c", &b, &a, "")], "do not list each other");
    refused(&[key("k", &a, "pairs = [\"c\"]\n"), cert("c", &b, &c, "pairs = [\"k\"]\n")], "do not share an rfc7093m4");
    refused(
        &[key("k", &a, "pairs = [\"c\"]\n"), lock_object("c", CERT_TYPE, &[("certhash", &b)], "pairs = [\"k\"]\n")],
        "do not share an rfc7093m4",
    );
    refused(&[lock_object("k", "", &[("rfc7093m4", &a)], "")], "has IDs but no type");
    refused(&[lock_object("s", AES_TYPE, &[("cmac", &b)], "")], "has commitment IDs but no commitmentLabel");
    for label in ["", "tab\\there"] {
        let extra = format!("commitmentLabel = \"{label}\"\n");
        refused(&[lock_object("s", AES_TYPE, &[("cmac", &b)], &extra)], "must be non-empty printable ASCII");
    }

    // A recorded public key must be the key that its identity hashes.
    let spki = base64::engine::general_purpose::STANDARD.encode(b"a");
    let l = loaded(&[key("k", &a, &format!("publicKey = \"{spki}\"\n"))]);
    assert_eq!(l.objects["k"].public_key.as_deref(), Some(spki.as_str()));
    refused(&[key("k", &b, &format!("publicKey = \"{spki}\"\n"))], "publicKey hashes to");
}

/// What is shown and selected matches what is there. A curve alias loads as its canonical name,
/// a spec is selected among the object's own specs and narrowed by name, and the lock's small
/// views (a mode, the immutables, and differing observations) print what they hold.
#[test]
fn views_and_picks_say_what_is_there() {
    use cakeys_core::config::{Immutables, TokenObservation};
    let alias = load(&keys(EC, SIGN, "").replace("secp256r1", "P-256")).unwrap();
    assert_eq!(alias.objects["o"].curve.as_deref(), Some("secp256r1"));

    let more = keys(EC, SIGN, "")
        + "\n[specs.s2]\nobject = \"o\"\nattributes = { CKA_SIGN = true }\ntokens.t = { locator = { CKA_LABEL = \"o2\" }, origin = \"adopt\" }\n\
           \n[objects.other]\nclass = \"CKO_DATA\"\n\n[specs.s3]\nobject = \"other\"\ntokens.t = { locator = { CKA_LABEL = \"d\" }, origin = \"adopt\" }\n";
    let cfg = load(&more).unwrap();
    let pair = |spec: &str| (spec.to_owned(), "t".to_owned());
    assert_eq!(cfg.address(Some("other"), None, None).unwrap(), pair("s3"));
    assert_eq!(cfg.address(Some("o"), Some("s2"), None).unwrap(), pair("s2"));
    assert_eq!(cfg.address(Some("o"), Some("s"), Some("t")).unwrap(), pair("s"));
    assert_eq!(cfg.address(None, Some("s2"), Some("t")).unwrap(), pair("s2"));
    let e = cfg.address(Some("o"), Some("s3"), None).unwrap_err();
    assert!(matches!(&e, KmError::Validation(m) if m.contains("spec 's3' realises 'other', not 'o'")), "{e}");
    assert_eq!(cfg.select(Some("o"), None, Some("t")).unwrap(), [("s", "t"), ("s2", "t")]);

    assert_eq!(
        [Mode::Direct, Mode::Commitment, Mode::WrapRebind].map(|m| m.to_string()),
        ["direct", "commitment", "wrap-rebind"]
    );
    let none = Immutables::default();
    assert!(none.is_empty());
    assert_eq!(none.to_string(), "{  }");
    let made = Immutables {
        local: Some(true),
        never_extractable: Some(false),
        key_gen_mechanism: Some("CKM_EC_KEY_PAIR_GEN".into()),
        ..Immutables::default()
    };
    assert!(!made.is_empty());
    assert_eq!(
        made.to_string(),
        "{ CKA_LOCAL = true, CKA_NEVER_EXTRACTABLE = false, CKA_KEY_GEN_MECHANISM = \"CKM_EC_KEY_PAIR_GEN\" }"
    );
    let said = TokenObservation::several("t", &[vec!["a".into(), "b".into()], vec!["c".into()]]);
    assert!(
        said.contains("token 't'") && said.contains("2 different observations") && said.contains("(a, b; c)"),
        "{said}"
    );
}

/// The small tables on which the rest of the code is built: the hash with which an HMAC key type
/// computes a commitment and with which an EC curve signs, which curves are Edwards curves and
/// how they may be named to a token, and which classes have a mechanism list.
#[test]
fn types_name_their_hash_and_curve() {
    use cakeys_core::id::{Curve, HmacHash};
    use cakeys_core::pop::HashAlg;
    use cakeys_core::types::ObjectClass;
    let hmac = [
        (KeyType::GenericSecret, Some(HmacHash::Sha256), false),
        (KeyType::Sha1Hmac, Some(HmacHash::Sha1), true),
        (KeyType::Sha224Hmac, Some(HmacHash::Sha224), true),
        (KeyType::Sha256Hmac, Some(HmacHash::Sha256), true),
        (KeyType::Sha384Hmac, Some(HmacHash::Sha384), true),
        (KeyType::Sha512Hmac, Some(HmacHash::Sha512), true),
        (KeyType::Aes, None, false),
        (KeyType::Ec, None, false),
    ];
    for (kt, hash, bound) in hmac {
        assert_eq!((HmacHash::for_key_type(kt), kt.is_hash_bound_hmac()), (hash, bound), "{kt:?}");
    }
    let curves = [
        (Curve::P256, Some(HashAlg::Sha256), false, None),
        (Curve::P384, Some(HashAlg::Sha384), false, None),
        (Curve::P521, Some(HashAlg::Sha512), false, None),
        (Curve::Ed25519, None, true, Some(&b"\x13\x0cedwards25519"[..])),
        (Curve::Ed448, None, true, Some(&b"\x13\x0aedwards448"[..])),
    ];
    for (curve, hash, edwards, by_name) in curves {
        let got = (HashAlg::for_curve(curve), curve.edwards(), curve.params_by_name());
        assert_eq!(got, (hash, edwards, by_name), "{curve:?}");
    }
    assert!(cakeys_core::attrs::has_allowed_mechanisms(ObjectClass::PrivateKey));
    assert!(cakeys_core::attrs::has_allowed_mechanisms(ObjectClass::SecretKey));
    assert!(!cakeys_core::attrs::has_allowed_mechanisms(ObjectClass::Certificate));
}

/// A certificate is linked to its key by its subject public key, and an Ed25519 proof of
/// possession verifies only for the key and the message for which it was made.
#[test]
fn a_certificate_names_its_key_and_an_ed25519_proof_its_signer() {
    use ed25519_dalek::Signer as _;
    // The fixture certificate of the fixture key, whose identity the token test suites pin.
    let cert = include_bytes!("../../cli/tests/fixtures/tpm-import-p256-cert.der");
    let spki = cakeys_core::id::cert_spki(cert).unwrap();
    assert_eq!(cakeys_core::id::sri(&spki), "sha256-0ymh9vfz8P3lnbdlAXskvxwoDAfUJNEIbsv0KEupcSg=");
    assert!(matches!(cakeys_core::id::cert_spki(b"no certificate"), Err(KmError::Conflict(_))));

    let key = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
    let other = ed25519_dalek::SigningKey::from_bytes(&[8u8; 32]);
    let spki = key.verifying_key().to_public_key_der().unwrap();
    let signature = key.sign(b"message").to_bytes();
    cakeys_core::pop::verify(spki.as_bytes(), b"message", &signature, V15).unwrap();
    assert_eq!(cakeys_core::sig::ed25519(spki.as_bytes(), b"message", &signature), Some(Ok(())));
    for (msg, sig) in [(&b"another"[..], signature), (b"message", other.sign(b"message").to_bytes())] {
        let e = cakeys_core::pop::verify(spki.as_bytes(), msg, &sig, V15).unwrap_err();
        assert!(matches!(&e, KmError::Conflict(m) if m.contains("did not sign for the public key")), "{e}");
    }
}

/// A secret's length has an upper bound so that its commitment label cannot overflow. The
/// largest length that fits loads, and a length one larger is refused (17). Over the full `u64`
/// range, `commitment_labels_are_injective` (tests/properties.rs) failed with an overflow panic,
/// so its range is now the range that keys.toml accepts.
#[test]
fn the_value_length_bound_is_inclusive() {
    let secret = |len: u64| format!("class = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_GENERIC_SECRET\"\nvalueLen = {len}");
    let most = u64::from(u32::MAX);
    assert_eq!(load(&keys(&secret(most), SIGN, "")).unwrap().objects["o"].value_len, Some(most));
    let e = load(&keys(&secret(most + 1), SIGN, "")).unwrap_err();
    assert_eq!(e.exit_code(), 17, "{e}");
    assert!(e.to_string().contains("is out of range"), "{e}");
}
