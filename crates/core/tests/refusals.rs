//! What loading keys.toml and a lock, planning a target and reading a key refuse, each with the
//! message that says why (the coverage report's gaps in `config`, `plan`, `pop` and `plaintext`):
//! none needs a token.

use cakeys_core::KmError;
use cakeys_core::config::{Binding, Config, Mode, ObjectKind, parse_config_with, parse_lock};
use cakeys_core::id::Scheme;
use cakeys_core::plaintext::{PrivateParts, private_from_pkcs8, spki_of_pkcs8};
use cakeys_core::plan::{Assurance, Target, binding, expected_binding, plan_mode};
use cakeys_core::types::KeyType;
use ed25519_dalek::pkcs8::{EncodePrivateKey as _, EncodePublicKey as _};
use std::path::Path;

/// keys.toml with one token `t`, one object `o` of `object`, and one spec `s` on `t` with
/// `spec` lines and `on_token` entries beside the locator; `origin = "adopt"` unless they name
/// one.
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
        (EC, "attributes = { CKA_SIGN = true, CKA_BOGUS = true }", "", "unsupported policy attribute CKA_BOGUS"),
        ("class = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"", SIGN, "", "CKO_SECRET_KEY/CKK_EC"),
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

/// Every object's type is parsed at load (`ObjectCfg::kind`), whether a spec uses it or not:
/// a field that names nothing on its class or key type is invalid (17), a pairing cakeys does
/// not manage unsupported (15).
#[test]
fn every_object_is_typed_at_load() {
    let unused = |object: &str| format!("{}\n[objects.unused]\n{object}\n", keys(EC, SIGN, ""));
    for (object, code, why) in [
        ("class = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_AES\"\nmodulusBits = 2048", 17, "modulusBits applies to CKK_RSA"),
        ("class = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_RSA\"\ncurve = \"secp256r1\"", 17, "curve applies to"),
        ("class = \"CKO_PUBLIC_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"P-256\"\nvalueLen = 32", 17, "valueLen applies"),
        ("class = \"CKO_DATA\"\nkeyType = \"CKK_AES\"", 17, "keyType applies to keys only"),
        ("class = \"CKO_CERTIFICATE\"", 17, "certificates need certificateType"),
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

#[test]
fn names_that_select_nothing_are_refused() {
    let cfg = load(&keys(EC, SIGN, "")).unwrap();
    let e = Target::new(&cfg, "s", "elsewhere").err().unwrap();
    assert!(matches!(&e, KmError::NotFound(m) if m.contains("has no token 'elsewhere'")), "{e}");
    assert!(Target::new(&cfg, "nope", "t").is_err());
    // A spec realised on a token `[tokens]` does not define loads, and is refused when used.
    let undefined = load(&keys(EC, SIGN, "").replace("[tokens.t]", "[tokens.u]")).unwrap();
    let e = Target::new(&undefined, "s", "t").err().unwrap();
    assert!(matches!(&e, KmError::Validation(m) if m.contains("unknown token 't'")), "{e}");
    let said = load(&keys(EC, SIGN, "").replace("object = \"o\"", "object = \"gone\"")).unwrap_err().to_string();
    assert!(said.contains("gone"), "{said}");
    // An object's one (spec, token) pair, or why there is not exactly one.
    // Every part of the address names something keys.toml has, or the run is invalid (17).
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
        + "\n[specs.s2]\nobject = \"o\"\ntokens.t = { locator = { CKA_LABEL = \"o2\" }, origin = \"adopt\" }\n";
    assert!(matches!(load(&two).unwrap().address(Some("o"), None, None), Err(KmError::Ambiguous(_))));
}

#[test]
fn token_and_creation_rules_are_checked_at_load() {
    let refused = |text: String, why: &str| {
        let said = load(&text).unwrap_err().to_string();
        assert!(said.contains(why), "expected {why:?} in {said:?}");
    };
    let with_token =
        |line: &str| keys(EC, SIGN, "").replace("tokenLabel = \"t\"", &format!("tokenLabel = \"t\"\n{line}"));
    // A provider is a family; one profile of it is moduleProfile, of the same family.
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
    // A transport key: an RSA private key of at least 2048 bits that unwraps and never leaves.
    let rsa = |bits: u32| format!("class = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_RSA\"\nmodulusBits = {bits}");
    let unwraps = "attributes = { CKA_UNWRAP = true, CKA_EXTRACTABLE = false }";
    let transport = |object: &str, spec: &str| {
        keys(object, spec, "").replace("tokenLabel = \"t\"", "tokenLabel = \"t\"\nmigrate = { transportWith = \"s\" }")
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
    // A token's transport key is on that token: another token cannot name it.
    refused(
        transport(&rsa(2048), unwraps) + "\n[tokens.u]\ntokenLabel = \"u\"\nmigrate = { transportWith = \"s\" }\n",
        "token 'u': migrate.transportWith = \"s\", but that spec does not realise it on 'u'",
    );
    // A key states how it comes to be on its token, and is created once at most.
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
    // A key pair by its public key, a data object by its value; an AES key by the commitments
    // its declared usage allows, strongest first, and by all of them when it declares none
    // (wrapping it out computes each).
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
    // Asked for as another type, or a type with no parser: refused, the bytes never echoed.
    assert!(matches!(private_from_pkcs8(der.as_bytes(), KeyType::Ec, Some("secp384r1")), Err(KmError::Conflict(_))));
    let e = private_from_pkcs8(der.as_bytes(), KeyType::Aes, Some("secp256r1")).err().unwrap();
    assert!(matches!(&e, KmError::Unsupported(m) if m.contains("on secp256r1")), "{e}");
    assert!(matches!(spki_of_pkcs8(b"no key at all"), Err(KmError::Unsupported(_))));
    // An Edwards curve has no ECDSA hash: its proof is EdDSA.
    assert!(cakeys_core::pop::EcdsaHash::for_curve(cakeys_core::id::Curve::Ed25519).is_none());
}

/// A proof of possession needs a verifier for the key's type: Ed448 has none, and bytes that
/// are no public key name themselves by their digest.
#[test]
fn proofs_need_a_verifier_for_the_key() {
    let ed448 = ed448::pkcs8::PublicKeyBytes([3u8; 57]).to_public_key_der().unwrap();
    let e = cakeys_core::pop::verify(ed448.as_bytes(), b"m", b"s").unwrap_err();
    assert!(matches!(&e, KmError::Unsupported(m) if m.contains("no Ed448 signature verifier")), "{e}");
    let e = cakeys_core::pop::verify(b"junk", b"m", b"s").unwrap_err();
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

/// A private key proves possession the way its type and declared usage allow (docs/DESIGN.md
/// §3.6): each binding is accepted on the key it fits, with the usage bit it needs, and refused
/// anywhere else with the reason for that binding.
#[test]
fn a_binding_fits_its_key_and_usage_or_is_refused() {
    use Binding::{PopDecrypt, PopEcdh, PopSign, PopSignPin, PopUnwrap, TokenAsserted};
    let flag = |name: &str| format!("attributes = {{ {name} = true }}");
    let per_use = |name: &str| format!("attributes = {{ {name} = true, CKA_ALWAYS_AUTHENTICATE = true }}");
    let with = |b: &str| format!(", binding = \"{b}\"");
    let accepted: &[(&str, String, String, Binding, Binding)] = &[
        (EC, flag("CKA_SIGN"), String::new(), PopSign, PopSign),
        (EC, flag("CKA_SIGN"), with("pop-sign"), PopSign, PopSign),
        // The per-use PIN is the token's to demand: planned as pop-sign, expected as pop-sign-pin.
        (EC, per_use("CKA_SIGN"), String::new(), PopSign, PopSignPin),
        (EC, flag("CKA_DERIVE"), with("pop-ecdh"), PopEcdh, PopEcdh),
        (RSA, flag("CKA_DECRYPT"), with("pop-decrypt"), PopDecrypt, PopDecrypt),
        (RSA, flag("CKA_UNWRAP"), with("pop-unwrap"), PopUnwrap, PopUnwrap),
        (RSA, flag("CKA_SIGN"), String::new(), PopSign, PopSign),
        // No usage to prove with, and said so; a per-use PIN changes nothing about that.
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
    for (object, spec, on_token, why) in refused {
        let said = refusal(&keys(object, spec, on_token));
        assert!(said.contains(why), "expected {why:?} in {said:?}");
    }
    // Other classes have no binding to plan or expect.
    assert_eq!(planned(AES, SIGN, ""), (Mode::Commitment, None, None));
    assert_eq!(planned(CERT, "", ""), (Mode::Direct, None, None));
}

/// The identity mode follows what the spec declares (docs/DESIGN.md §3.4): asymmetric keys and
/// public objects are hashed directly, a secret key by a commitment its usage allows, else by
/// wrapping when it is extractable, else not at all; and what a class cannot be asked is refused.
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
    // An HMAC key commits by signing alone: encrypting names no commitment for it.
    assert_eq!(mode(HMAC, "attributes = { CKA_ENCRYPT = true, CKA_EXTRACTABLE = true }", ""), Mode::WrapRebind);
    assert_eq!(mode(PUBLIC, "", ""), Mode::Direct);
    assert_eq!(mode("class = \"CKO_DATA\"", "", ""), Mode::Direct);
    assert_eq!(mode(CERT, "", ""), Mode::Direct);
    assert_eq!(mode(EC, SIGN, ", attestation = true"), Mode::Direct);
    assert_eq!(mode(AES, SIGN, ", attestation = true"), Mode::Commitment);
    // Adopted, a trusted key is only read; generated, the token would have to set it.
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
    for (object, spec, on_token, why) in cases {
        let said = refusal(&keys(object, spec, on_token));
        assert!(said.contains(why), "expected {why:?} in {said:?}");
    }
}

/// What `cakeys create` never makes, whatever the token, cannot say `origin = "create"` (17 at
/// load): the classes cakeys adopts, a `publicOnly` adoption, and a key the token's security
/// officer must mark `CKA_TRUSTED`. Each is a valid spec to adopt.
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
        let said = load(&keys(object, spec, on_token)).unwrap_err().to_string();
        assert!(said.contains(why), "expected {why:?} in {said:?}");
        load(&keys(object, spec, &on_token.replace("\"create\"", "\"adopt\""))).unwrap();
    }
    for (object, spec) in [(EC, SIGN), (AES, SIGN), (AES, "attributes = { CKA_WRAP = true, CKA_TRUSTED = false }")] {
        load(&keys(object, spec, create)).unwrap_or_else(|e| panic!("{e}: {object}\n{spec}"));
    }
}

/// A lock's `[objects.<name>]` table: its type (by class and key type), IDs, and extra lines.
fn lock_object(name: &str, ty: &str, ids: &[(&str, &str)], extra: &str) -> String {
    let ids = ids.iter().map(|(s, v)| format!("{s} = \"{v}\"\n")).collect::<Vec<_>>().concat();
    format!("[objects.{name}]\n{extra}{ty}[objects.{name}.ids]\n{ids}\n")
}

const KEY_TYPE: &str = "type = { class = \"CKO_PRIVATE_KEY\", keyType = \"CKK_EC\", curve = \"secp256r1\" }\n";
const PUBLIC_TYPE: &str = "type = { class = \"CKO_PUBLIC_KEY\", keyType = \"CKK_EC\", curve = \"secp256r1\" }\n";
const CERT_TYPE: &str = "type = { class = \"CKO_CERTIFICATE\", certificateType = \"CKC_X_509\" }\n";
const AES_TYPE: &str = "type = { class = \"CKO_SECRET_KEY\", keyType = \"CKK_AES\", valueLen = 32 }\n";

/// The lock's objects are held to their invariants on load (docs/DESIGN.md §4): one object per
/// material within a class, pairs that share a public key and list each other, IDs with a type
/// and a label where they need one. A lock that keeps them loads, and its pairs are computed
/// from the shared public key.
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

    // One material, one object per class: a key, its public key object and two certificates
    // of it share the public key; an object that records nothing yet is still an object.
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
    // What shares the key and is not listed yet; an object with no public key shares none.
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

    // A recorded public key is the one its identity hashes.
    let spki = base64::engine::general_purpose::STANDARD.encode(b"a");
    let l = loaded(&[key("k", &a, &format!("publicKey = \"{spki}\"\n"))]);
    assert_eq!(l.objects["k"].public_key.as_deref(), Some(spki.as_str()));
    refused(&[key("k", &b, &format!("publicKey = \"{spki}\"\n"))], "publicKey hashes to");
}

/// What is shown and picked is what is there: a curve alias loads as its canonical name, a
/// spec is picked among the object's own and narrowed by name, and the lock's small views
/// (a mode, the immutables, differing observations) print what they hold.
#[test]
fn views_and_picks_say_what_is_there() {
    use cakeys_core::config::{Immutables, TokenObservation};
    let alias = load(&keys(EC, SIGN, "").replace("secp256r1", "P-256")).unwrap();
    assert_eq!(alias.objects["o"].curve.as_deref(), Some("secp256r1"));

    let more = keys(EC, SIGN, "")
        + "\n[specs.s2]\nobject = \"o\"\ntokens.t = { locator = { CKA_LABEL = \"o2\" }, origin = \"adopt\" }\n\
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

/// The small tables the rest is built on: the hash an HMAC key type commits with and an EC
/// curve signs with, which curves are Edwards and how they may be named to a token, and which
/// classes carry a mechanism list.
#[test]
fn types_name_their_hash_and_curve() {
    use cakeys_core::id::{Curve, HmacHash};
    use cakeys_core::pop::EcdsaHash;
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
        (Curve::P256, Some(EcdsaHash::Sha256), false, None),
        (Curve::P384, Some(EcdsaHash::Sha384), false, None),
        (Curve::P521, Some(EcdsaHash::Sha512), false, None),
        (Curve::Ed25519, None, true, Some(&b"\x13\x0cedwards25519"[..])),
        (Curve::Ed448, None, true, Some(&b"\x13\x0aedwards448"[..])),
    ];
    for (curve, hash, edwards, by_name) in curves {
        let got = (EcdsaHash::for_curve(curve), curve.edwards(), curve.params_by_name());
        assert_eq!(got, (hash, edwards, by_name), "{curve:?}");
    }
    assert!(cakeys_core::attrs::has_allowed_mechanisms(ObjectClass::PrivateKey));
    assert!(cakeys_core::attrs::has_allowed_mechanisms(ObjectClass::SecretKey));
    assert!(!cakeys_core::attrs::has_allowed_mechanisms(ObjectClass::Certificate));
}

/// A certificate is linked to its key by its subject public key, and an Ed25519 proof of
/// possession verifies only for the key and the message it was made for.
#[test]
fn a_certificate_names_its_key_and_an_ed25519_proof_its_signer() {
    use ed25519_dalek::Signer as _;
    // The fixture certificate of the fixture key, whose identity the token suites pin.
    let cert = include_bytes!("../../cli/tests/fixtures/tpm-import-p256-cert.der");
    let spki = cakeys_core::id::cert_spki(cert).unwrap();
    assert_eq!(cakeys_core::id::sri(&spki), "sha256-0ymh9vfz8P3lnbdlAXskvxwoDAfUJNEIbsv0KEupcSg=");
    assert!(matches!(cakeys_core::id::cert_spki(b"no certificate"), Err(KmError::Conflict(_))));

    let key = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
    let other = ed25519_dalek::SigningKey::from_bytes(&[8u8; 32]);
    let spki = key.verifying_key().to_public_key_der().unwrap();
    let signature = key.sign(b"message").to_bytes();
    cakeys_core::pop::verify(spki.as_bytes(), b"message", &signature).unwrap();
    assert_eq!(cakeys_core::sig::ed25519(spki.as_bytes(), b"message", &signature), Some(Ok(())));
    for (msg, sig) in [(&b"another"[..], signature), (b"message", other.sign(b"message").to_bytes())] {
        let e = cakeys_core::pop::verify(spki.as_bytes(), msg, &sig).unwrap_err();
        assert!(matches!(&e, KmError::Conflict(m) if m.contains("did not sign for the public key")), "{e}");
    }
}

/// A secret's length is bounded so its commitment label cannot overflow: the largest length
/// that fits loads, one more is refused.
#[test]
fn the_value_length_bound_is_inclusive() {
    let secret = |len: u64| format!("class = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_GENERIC_SECRET\"\nvalueLen = {len}");
    let most = u64::from(u32::MAX);
    assert_eq!(load(&keys(&secret(most), SIGN, "")).unwrap().objects["o"].value_len, Some(most));
    let said = load(&keys(&secret(most + 1), SIGN, "")).unwrap_err().to_string();
    assert!(said.contains("is out of range"), "{said}");
}
