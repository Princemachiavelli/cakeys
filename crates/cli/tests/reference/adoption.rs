//! Adoption: certificates standing in for a key's public half, and `publicOnly` keys.

use super::*;

/// Hashes of tests/fixtures/adopt-cert.der computed independently with openssl:
///   sha256(cert DER) and sha256(`openssl x509 -pubkey | openssl pkey -pubin -outform DER`).
const ADOPT_CERTHASH: &str = "sha256-lXNE6ciIfLkwGf6kf84qfibQ08d5fkPuGNKQ5KnyTMM=";
const ADOPT_PUBKEYHASH: &str = "sha256-8DQBv2fMc+z0Q5uxky0+5t9TS6MAHO07fNMqG9thHtM=";

/// A certificate's declared attributes are held to the token as a key's are: a certificate the
/// spec says is public but the token holds private is refused (13), and one that agrees passes.
/// Certificates were checked for their type alone, so any declaration passed, `CKA_TRUSTED`
/// included.
#[test]
fn a_certificates_declared_attributes_are_checked() {
    let Some(e) = env("cert_policy") else { return };
    let s = e.session();
    for (label, private) in [("pub-cert", false), ("priv-cert", true)] {
        let mut t = cert_object(ADOPT_CERT, label.as_bytes(), None);
        t.push(Attribute::Private(private));
        s.create_object(&t).unwrap();
    }
    let spec = |name: &str, label: &str| {
        format!(
            "[specs.{name}]\nobject = \"{name}\"\nattributes = {{ CKA_PRIVATE = false }}\n\
             tokens.ref = {{ locator = {{ CKA_LABEL = \"{label}\" }}, origin = \"adopt\" }}\n\n\
             [objects.{name}]\nclass = \"CKO_CERTIFICATE\"\ncertificateType = \"CKC_X_509\"\n\n"
        )
    };
    e.config(&(spec("agrees", "pub-cert") + &spec("differs", "priv-cert")));
    assert_eq!(e.code(&["lock", "--spec", "agrees", "--token", "ref", "--update-lock"]), 0);
    let o = e.km(&["lock", "--spec", "differs", "--token", "ref", "--update-lock"]);
    assert_eq!(code(&o), 13, "{}", stderr(&o));
    assert!(stderr(&o).contains("CKA_PRIVATE is true"), "{}", stderr(&o));
    assert_eq!(e.code(&["check", "--spec", "agrees", "--token", "ref"]), 0);
}

/// An imported EC private key exposes no public point; when its importer wrote only the
/// certificate beside it, that certificate stands in for the public half (docs/DESIGN.md §3.2),
/// and only a certificate of the key's own type and curve does: under `token-asserted` no proof
/// would catch another key's (13).
#[test]
fn a_certificate_stands_in_for_an_imported_keys_public_half() {
    let Some(e) = env("cert_stand_in") else { return };
    let fixtures = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");
    let (params, scalar, _) = ec_fixture(&pem_der(&format!("{fixtures}/tpm-import-p256.pem")));
    let own: &[u8] = include_bytes!("../fixtures/tpm-import-p256-cert.der");
    let s = e.session();
    for (label, cert) in [("own-cert", own), ("other-cert", ADOPT_CERT)] {
        s.create_object(&[
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::KeyType(cryptoki::object::KeyType::EC),
            Attribute::Token(true),
            Attribute::Private(true),
            Attribute::Label(label.as_bytes().to_vec()),
            Attribute::Sign(true),
            Attribute::EcParams(params.clone()),
            Attribute::Value(scalar.clone()),
        ])
        .unwrap();
        s.create_object(&cert_object(cert, label.as_bytes(), None)).unwrap();
    }
    let spec = |name: &str, label: &str, binding: &str| {
        format!(
            "[specs.{name}]\nobject = \"k\"\nattributes = {{ CKA_SIGN = true }}\n\
             tokens.ref = {{ locator = {{ CKA_LABEL = \"{label}\" }}, origin = \"adopt\", binding = \"{binding}\" }}\n\n"
        )
    };
    e.config(&format!(
        "[objects.k]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n{}{}{}",
        spec("own", "own-cert", "pop-sign"),
        spec("other", "other-cert", "token-asserted"),
        spec("other-proven", "other-cert", "pop-sign"),
    ));
    assert_eq!(e.code(&["lock", "--spec", "own", "--token", "ref", "--update-lock"]), 0);
    let cert = <x509_cert::Certificate as x509_cert::der::Decode>::from_der(own).unwrap();
    let spki = x509_cert::der::Encode::to_der(cert.tbs_certificate().subject_public_key_info()).unwrap();
    assert_eq!(e.locked_id("k", "rfc7093m4"), sri(&spki), "the certificate's key is the identity");
    for other in ["other", "other-proven"] {
        let o = e.km(&["lock", "--spec", other, "--token", "ref", "--no-update-lock"]);
        assert_eq!(code(&o), 13, "{other}: {}", stderr(&o));
        assert!(stderr(&o).contains("is RSA") && stderr(&o).contains("private key is secp256r1"), "{}", stderr(&o));
    }
}

#[test]
fn adopt_certificate_and_public_only_key() {
    use rsa::traits::PublicKeyParts;
    let Some(e) = env("adopt") else { return };
    // Plant what a PIV slot exposes without login: a certificate and its public key.
    let cert = <x509_cert::Certificate as x509_cert::der::Decode>::from_der(ADOPT_CERT).unwrap();
    let spki = x509_cert::der::Encode::to_der(cert.tbs_certificate().subject_public_key_info()).unwrap();
    let rsa = <rsa::PublicKey as rsa::pkcs8::DecodePublicKey>::from_public_key_der(&spki).unwrap();
    let s = e.session();
    s.create_object(&cert_object(ADOPT_CERT, b"adopt-cert", Some(0x42))).unwrap();
    s.create_object(&[
        Attribute::Class(ObjectClass::PUBLIC_KEY),
        Attribute::KeyType(cryptoki::object::KeyType::RSA),
        Attribute::Token(true),
        Attribute::Label(b"adopt-key".to_vec()),
        Attribute::Id(vec![0x42]),
        Attribute::Modulus(rsa.n().as_ref().to_be_bytes_trimmed_vartime().to_vec()),
        Attribute::PublicExponent(rsa.e().to_be_bytes_trimmed_vartime().to_vec()),
    ])
    .unwrap();
    e.config(
        r#"
[objects.adopted]
class = "CKO_PRIVATE_KEY"
keyType = "CKK_RSA"
modulusBits = 2048

[specs.adopted-pub]
object = "adopted"
tokens.ref-anon = { locator = { CKA_LABEL = "adopt-key" }, origin = "adopt", publicOnly = true }

[specs.adopted-priv]
object = "adopted"
attributes = { CKA_SIGN = true }
tokens.ref = { locator = { CKA_LABEL = "adopt-key" }, origin = "adopt" }

[objects.adopted-cert]
class = "CKO_CERTIFICATE"
certificateType = "CKC_X_509"

[specs.adopted-cert]
object = "adopted-cert"
tokens.ref-anon = { locator = { CKA_LABEL = "adopt-cert" }, origin = "adopt" }

[specs.adopted-cert-by-id]
object = "adopted-cert"
tokens.ref-anon = { locator = { CKA_ID = "42" }, origin = "adopt" }
"#,
    );
    let pub_only = ["lock", "--spec", "adopted-pub", "--token", "ref-anon", "--update-lock"];
    assert_eq!(e.code(&pub_only), 0);
    assert_eq!(e.code(&["lock", "--spec", "adopted-cert", "--token", "ref-anon", "--update-lock"]), 0);
    assert_eq!(e.locked_id("adopted", "rfc7093m4"), ADOPT_PUBKEYHASH);
    assert_eq!(e.locked_id("adopted-cert", "certhash"), ADOPT_CERTHASH);
    assert_eq!(e.locked_id("adopted-cert", "rfc7093m4"), ADOPT_PUBKEYHASH, "cert links to its key");
    // The relation is explicit in the lock, and checked when it is loaded.
    let lock = e.lock();
    assert_eq!(lock["objects"]["adopted-cert"]["pairs"].as_array().unwrap(), &vec![toml::Value::from("adopted")]);
    assert_eq!(lock["objects"]["adopted"]["pairs"].as_array().unwrap(), &vec![toml::Value::from("adopted-cert")]);
    let lock = e.lock();
    assert_eq!(lock["realisations"]["adopted-pub"]["ref-anon"]["publicOnly"].as_bool(), Some(true));
    assert!(lock["realisations"]["adopted-cert"]["ref-anon"].get("publicOnly").is_none());
    let verify = e.km(&["verify", "--spec", "adopted-pub", "--token", "ref-anon"]);
    assert!(stdout(&verify).contains("object=adopt-key;type=private"), "consumers get the private key URI");
    // There is no private half: without publicOnly the same locator is simply absent.
    assert_eq!(e.code(&["verify", "--spec", "adopted-priv", "--token", "ref"]), 11);
    // Adopted public-only keys are never deleted (only the public half would go).
    assert_eq!(e.code(&["delete", "--spec", "adopted-pub", "--token", "ref-anon", "--no-update-lock"]), 15);
    // CKA_ID alone also matches the public key object, but certificates are looked up by class.
    let by_id = ["lock", "--spec", "adopted-cert-by-id", "--token", "ref-anon", "--no-update-lock"];
    assert_eq!(e.code(&by_id), 14, "same certificate, but not recorded under this spec yet");
    assert_eq!(e.code(&recording(&by_id)), 0);

    // Locks split per object and join again: a pair partner in another fragment is allowed.
    let full = e.lock();
    let write = |lock: &toml::Value| std::fs::write(e.dir.join("keys.lock"), toml::to_string(lock).unwrap()).unwrap();
    let fragment = |objects: &[&str], specs: &[&str]| {
        let mut f = full.clone();
        f["objects"].as_table_mut().unwrap().retain(|k, _| objects.contains(&k));
        f["realisations"].as_table_mut().unwrap().retain(|k, _| specs.contains(&k));
        f
    };
    let key = fragment(&["adopted"], &["adopted-pub"]);
    let cert = fragment(&["adopted-cert"], &["adopted-cert", "adopted-cert-by-id"]);
    write(&key);
    assert_eq!(e.code(&["verify", "--spec", "adopted-pub", "--token", "ref-anon"]), 0);
    write(&cert);
    assert_eq!(e.code(&["verify", "--spec", "adopted-cert", "--token", "ref-anon"]), 0);
    let mut joined = key.clone();
    for part in ["objects", "realisations"] {
        joined[part].as_table_mut().unwrap().extend(cert[part].as_table().unwrap().clone());
    }
    assert_eq!(joined, full);
    // Partners that share the key but are not listed: a note, and --update-lock records them.
    let mut unlisted = full.clone();
    for o in ["adopted", "adopted-cert"] {
        unlisted["objects"][o].as_table_mut().unwrap().remove("pairs");
    }
    write(&unlisted);
    let o = e.km(&["verify", "--spec", "adopted-pub", "--token", "ref-anon"]);
    assert_eq!(code(&o), 0);
    assert!(stderr(&o).contains("not listed as its pairs"));
    assert_eq!(e.code(&["lock", "--spec", "adopted-pub", "--token", "ref-anon", "--update-lock"]), 0);
    assert_eq!(e.lock(), full);
    // A listed partner that is present must list back.
    let mut one_sided = full.clone();
    one_sided["objects"]["adopted"].as_table_mut().unwrap().remove("pairs");
    write(&one_sided);
    assert_eq!(e.code(&["verify", "--spec", "adopted-pub", "--token", "ref-anon"]), 17);
}

#[test]
fn rsa_private_and_public_only_paths_agree() {
    let Some(e) = env("rsa_paths") else { return };
    e.config(
        r#"
[objects.r]
class = "CKO_PRIVATE_KEY"
keyType = "CKK_RSA"
modulusBits = 2048

[specs.r-gen]
object = "r"
attributes = { CKA_SIGN = true, CKA_SENSITIVE = true, CKA_EXTRACTABLE = false }
tokens.ref = { locator = { CKA_LABEL = "rsa-paths" }, origin = "create" }

[specs.r-pub]
object = "r"
tokens.ref-anon = { locator = { CKA_LABEL = "rsa-paths" }, origin = "adopt", publicOnly = true }
"#,
    );
    assert_eq!(e.code(&["create", "--spec", "r-gen", "--token", "ref", "--no-update-lock"]), 18);
    assert_eq!(e.code(&["lock", "--spec", "r-gen", "--token", "ref", "--update-lock"]), 0);
    // Same material through the public key object, without login: same locked identity.
    assert_eq!(e.code(&["lock", "--spec", "r-pub", "--token", "ref-anon", "--update-lock"]), 0);
    assert_eq!(e.code(&["check", "r", "--spec", "r-pub"]), 0);
}

#[test]
#[expect(clippy::format_push_string, reason = "the fixture TOML bodies are appended as += format!(...)")]
fn adopt_ec_and_edwards_certificates() {
    let Some(e) = env("adopt_ec") else { return };
    let s = e.session();
    let fixtures: [(&str, &[u8], &[u8], &str, &str, &str); 2] = [
        (
            "p384",
            include_bytes!("../fixtures/adopt-cert-p384.der"),
            P384,
            "CKK_EC\"\ncurve = \"secp384r1",
            P384_CERTHASH,
            P384_PUBKEYHASH,
        ),
        (
            "ed25519",
            include_bytes!("../fixtures/adopt-cert-ed25519.der"),
            ED25519,
            "CKK_EC_EDWARDS\"\ncurve = \"edwards25519",
            ED25519_CERTHASH,
            ED25519_PUBKEYHASH,
        ),
    ];
    let mut body = String::new();
    for (i, (k, der, params, ty, _, _)) in fixtures.iter().enumerate() {
        let id = 0x50 + u8::try_from(i).unwrap();
        s.create_object(&cert_object(der, format!("{k}-cert").as_bytes(), Some(id))).unwrap();
        // What a PIV slot exposes without login: the certificate and its public key.
        let cert = <x509_cert::Certificate as x509_cert::der::Decode>::from_der(der).unwrap();
        let point = cert.tbs_certificate().subject_public_key_info().subject_public_key.raw_bytes().to_vec();
        let key_type = if *k == "p384" { cryptoki::object::KeyType::EC } else { cryptoki::object::KeyType::EC_EDWARDS };
        s.create_object(&[
            Attribute::Class(ObjectClass::PUBLIC_KEY),
            Attribute::KeyType(key_type),
            Attribute::Token(true),
            Attribute::Label(format!("{k}-key").into_bytes()),
            Attribute::Id(vec![id]),
            Attribute::EcParams(params.to_vec()),
            Attribute::EcPoint(tlv(0x04, &point)),
        ])
        .unwrap();
        body += &format!(
            "[objects.{k}]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"{ty}\"\n\n\
             [specs.{k}]\nobject = \"{k}\"\n\
             tokens.ref-anon = {{ locator = {{ CKA_LABEL = \"{k}-key\" }}, origin = \"adopt\", publicOnly = true }}\n\n\
             [objects.{k}-cert]\nclass = \"CKO_CERTIFICATE\"\ncertificateType = \"CKC_X_509\"\n\n\
             [specs.{k}-cert]\nobject = \"{k}-cert\"\n\
             tokens.ref-anon = {{ locator = {{ CKA_LABEL = \"{k}-cert\" }}, origin = \"adopt\" }}\n\n"
        );
    }
    e.config(&body);
    for (k, _, _, _, certhash, rfc7093m4) in fixtures {
        assert_eq!(e.code(&["lock", "--spec", k, "--token", "ref-anon", "--update-lock"]), 0, "{k}");
        let cert = format!("{k}-cert");
        assert_eq!(e.code(&["lock", "--spec", &cert, "--token", "ref-anon", "--update-lock"]), 0, "{k}");
        assert_eq!(e.locked_id(k, "rfc7093m4"), rfc7093m4, "{k}");
        assert_eq!(e.locked_id(&cert, "certhash"), certhash, "{k}");
        assert_eq!(e.locked_id(&cert, "rfc7093m4"), rfc7093m4, "{k}: cert links to its key");
    }
}
