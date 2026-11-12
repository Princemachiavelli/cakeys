//! End-to-end tests of the CLI against a SoftHSM token.
//!
//! Needs `SOFTHSM2_CONF` and `CAKEYS_TEST_MODULE` (path to libsofthsm2.so) with an initialised token
//! labelled `kmtest`, user PIN `1234` (the Nix build's preCheck sets this up). Tests are skipped
//! when `CAKEYS_TEST_MODULE` is unset, unless `CAKEYS_TEST_REQUIRE=1`.

#![allow(clippy::type_complexity)] // table-driven cases

use cryptoki::context::{CInitializeArgs, Pkcs11};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, ObjectClass};
use cryptoki::session::{Session, UserType};
use cryptoki::types::AuthPin;
use hmac::{Hmac, KeyInit, Mac};
use std::path::PathBuf;
use std::process::{Command, Output};

mod common;
use common::*;

const BIN: &str = env!("CARGO_BIN_EXE_cakeys");

struct Env {
    dir: PathBuf,
    module: String,
}

fn env(name: &str) -> Option<Env> {
    let Ok(module) = std::env::var("CAKEYS_TEST_MODULE") else {
        assert!(std::env::var("CAKEYS_TEST_REQUIRE").is_err(), "CAKEYS_TEST_MODULE is required");
        eprintln!("skipping {name}: CAKEYS_TEST_MODULE not set");
        return None;
    };
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("pin"), "1234\n").unwrap();
    Some(Env { dir, module })
}

impl Env {
    /// Write keys.toml: the token header plus the given objects/specs.
    fn config(&self, body: &str) {
        // `softhsm-anon` is the same token without a PIN: it sees only public objects, like
        // a PIV token used without login.
        let head = format!(
            "[tokens.softhsm]\nmodule = \"{m}\"\ntokenLabel = \"kmtest\"\npinFile = \"{}\"\n\n\
             [tokens.softhsm-anon]\nmodule = \"{m}\"\ntokenLabel = \"kmtest\"\n\n",
            self.dir.join("pin").display(),
            m = self.module,
        );
        std::fs::write(self.dir.join("keys.toml"), head + body).unwrap();
    }

    fn km(&self, args: &[&str]) -> Output {
        self.km_env(args, &[])
    }

    fn km_env(&self, args: &[&str], envs: &[(&str, &std::path::Path)]) -> Output {
        let out = Command::new(BIN)
            .envs(envs.iter().copied())
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

    fn lock(&self) -> toml::Value {
        toml::from_str(&std::fs::read_to_string(self.dir.join("keys.lock")).unwrap()).unwrap()
    }

    fn locked_id(&self, object: &str, scheme: &str) -> String {
        self.lock()["objects"][object]["ids"][scheme].as_str().unwrap().to_owned()
    }

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

const EC: &str = r#"
[objects.signing]
class = "CKO_PRIVATE_KEY"
keyType = "CKK_EC"
curve = "secp256r1"

[specs.signing-soft]
object = "signing"
attributes = { CKA_SIGN = true, CKA_SENSITIVE = true, CKA_EXTRACTABLE = false }
tokens.softhsm = { locator = { CKA_LABEL = "ec-lifecycle" }, autoCreate = true }
"#;

#[test]
fn ec_lifecycle() {
    let Some(e) = env("ec_lifecycle") else { return };
    e.config(EC);
    let r = ["realise", "signing-soft", "--token", "softhsm"];

    // First use: creates, then fails like a FOD with a fake hash.
    let first = e.km(&r);
    assert_eq!(code(&first), 10);
    let got = got_hash(&first);
    // Re-running finds the same object: same hash, no duplicate (else exit 12, ambiguous).
    let again = e.km(&r);
    assert_eq!(code(&again), 10);
    assert_eq!(got_hash(&again), got);
    assert_eq!(code(&e.km(&["resolve", "signing-soft", "--token", "softhsm"])), 0);

    // Record it; now realise is a no-op success.
    assert_eq!(code(&e.km(&[&r[..], &["--update-lock"]].concat())), 0);
    assert_eq!(e.locked_id("signing", "pubkeyhash"), got);
    assert_eq!(code(&e.km(&r)), 0);

    let verify = e.km(&["verify", "signing-soft", "--token", "softhsm"]);
    assert_eq!(code(&verify), 0);
    assert!(stdout(&verify).starts_with("pkcs11:token=kmtest;object=ec-lifecycle;type=private"));
    let check = e.km(&["check", "signing.id.pubkeyhash"]);
    assert_eq!(code(&check), 0);
    assert_eq!(stdout(&check), stdout(&verify));
    assert_eq!(code(&e.km(&["check", "signing.id.commitment"])), 15);

    // DELETE + If-Match.
    let del = ["delete", "signing-soft", "--token", "softhsm", "--update-lock"];
    let wrong = e.km(&[&del[..], &["--if-match", "sha256-AAAA"]].concat());
    assert_eq!(code(&wrong), 14);
    assert_eq!(code(&e.km(&["verify", "signing-soft", "--token", "softhsm"])), 0);
    assert_eq!(code(&e.km(&del)), 0);
    assert_eq!(code(&e.km(&del)), 0, "delete of an absent object succeeds");
    assert_eq!(code(&e.km(&["verify", "signing-soft", "--token", "softhsm"])), 11);
    assert!(e.lock().get("realisations").and_then(|r| r.get("signing-soft")).is_none());

    // Deleting something that never existed succeeds even with no expected identity anywhere.
    std::fs::remove_file(e.dir.join("keys.lock")).unwrap();
    assert_eq!(code(&e.km(&["delete", "signing-soft", "--token", "softhsm"])), 0);
    // ...but a present object with no expected identity is never deleted blindly.
    assert_eq!(code(&e.km(&r)), 10);
    assert_eq!(code(&e.km(&["delete", "signing-soft", "--token", "softhsm"])), 14);
    assert_eq!(code(&e.km(&["verify", "signing-soft", "--token", "softhsm"])), 10);
    assert_eq!(code(&e.km(&[&r[..], &["--update-lock"]].concat())), 0);
    assert_eq!(code(&e.km(&del)), 0);
    // Restore the original locked identity for the final check.
    std::fs::write(
        e.dir.join("keys.lock"),
        format!("version = 1\n[objects.signing.ids]\npubkeyhash = \"{got}\"\n"),
    )
    .unwrap();

    // A re-created key is new material: it must not satisfy the locked identity.
    assert_eq!(code(&e.km(&r)), 10);
    assert_eq!(code(&e.km(&del)), 14, "locked id no longer matches the object under the locator");
}

#[test]
fn secret_commitments_match_host_hmac() {
    let Some(e) = env("secret_commitments") else { return };
    // Non-sensitive so the test can read CKA_VALUE and compute the oracle on the host.
    e.config(
        r#"
[objects.mac]
class = "CKO_SECRET_KEY"
keyType = "CKK_GENERIC_SECRET"
valueLen = 32

[specs.mac-sign]
object = "mac"
attributes = { CKA_SIGN = true, CKA_SENSITIVE = false, CKA_EXTRACTABLE = true }
tokens.softhsm = { locator = { CKA_LABEL = "oracle-commitment" }, autoCreate = true }

[objects.mac2]
class = "CKO_SECRET_KEY"
keyType = "CKK_GENERIC_SECRET"
valueLen = 32

[specs.mac2-nosign]
object = "mac2"
attributes = { CKA_SIGN = false, CKA_SENSITIVE = false, CKA_EXTRACTABLE = true }
tokens.softhsm = { locator = { CKA_LABEL = "oracle-wrap-rebind" }, autoCreate = true }
"#,
    );
    for (spec, object, label, key_type, mode) in [
        ("mac-sign", "mac", "oracle-commitment", "CKK_GENERIC_SECRET", "commitment"),
        ("mac2-nosign", "mac2", "oracle-wrap-rebind", "CKK_GENERIC_SECRET", "wrap-rebind"),
    ] {
        assert_eq!(code(&e.km(&["realise", spec, "--token", "softhsm", "--update-lock"])), 0);
        assert_eq!(e.lock()["realisations"][spec]["softhsm"]["mode"].as_str(), Some(mode));
        let s = e.session();
        let h = s.find_objects(&[Attribute::Label(label.as_bytes().to_vec())]).unwrap()[0];
        let value = match &s.get_attributes(h, &[AttributeType::Value]).unwrap()[0] {
            Attribute::Value(v) => v.clone(),
            a => panic!("{a:?}"),
        };
        let mut mac = Hmac::<sha2::Sha256>::new_from_slice(&value).unwrap();
        mac.update(format!("key-management/v1/commitment/{key_type}/256").as_bytes());
        assert_eq!(e.locked_id(object, "commitment"), sri(&mac.finalize().into_bytes()), "{mode}");
    }
}

#[test]
fn two_specs_same_material() {
    let Some(e) = env("two_specs") else { return };
    // One object, two specs with different policy: sign-capable (commitment) and sign-less
    // (wrap-rebind). Same material must give the same material CA-ID.
    e.config(
        r#"
[objects.shared]
class = "CKO_SECRET_KEY"
keyType = "CKK_GENERIC_SECRET"
valueLen = 32

[specs.shared-sign]
object = "shared"
attributes = { CKA_SIGN = true, CKA_SENSITIVE = true, CKA_EXTRACTABLE = true }
tokens.softhsm = { locator = { CKA_LABEL = "shared-a" }, autoCreate = true }

[specs.shared-nosign]
object = "shared"
attributes = { CKA_SIGN = false, CKA_SENSITIVE = true, CKA_EXTRACTABLE = true }
tokens.softhsm = { locator = { CKA_LABEL = "shared-b" } }
"#,
    );
    assert_eq!(code(&e.km(&["realise", "shared-sign", "--token", "softhsm", "--update-lock"])), 0);
    // No autoCreate on the second spec: absent is NotFound, not a silent create.
    assert_eq!(code(&e.km(&["realise", "shared-nosign", "--token", "softhsm"])), 11);
    let s = e.session();
    let a = s.find_objects(&[Attribute::Label(b"shared-a".to_vec())]).unwrap()[0];
    s.copy_object(a, &[Attribute::Label(b"shared-b".to_vec()), Attribute::Sign(false)])
        .unwrap();
    // The replica verifies against the identity locked through the first spec.
    assert_eq!(code(&e.km(&["realise", "shared-nosign", "--token", "softhsm", "--update-lock"])), 0);
    let lock = e.lock();
    assert_eq!(lock["realisations"]["shared-sign"]["softhsm"]["mode"].as_str(), Some("commitment"));
    assert_eq!(lock["realisations"]["shared-nosign"]["softhsm"]["mode"].as_str(), Some("wrap-rebind"));
    assert_ne!(
        lock["realisations"]["shared-sign"]["softhsm"]["specDigest"],
        lock["realisations"]["shared-nosign"]["softhsm"]["specDigest"]
    );
    assert_eq!(code(&e.km(&["check", "shared", "--spec", "shared-nosign"])), 0);
}

#[test]
fn weak_modes_need_per_token_opt_in() {
    let Some(e) = env("opt_in") else { return };
    let spec = |allow: &str| {
        format!(
            r#"
[objects.locked]
class = "CKO_SECRET_KEY"
keyType = "CKK_AES"
valueLen = 32

[specs.locked-down]
object = "locked"
attributes = {{ CKA_SIGN = false, CKA_SENSITIVE = true, CKA_EXTRACTABLE = false, CKA_DERIVE = true }}
tokens.softhsm = {{ locator = {{ CKA_LABEL = "locked" }}, autoCreate = true, identity.allow = [{allow}] }}
"#
        )
    };
    e.config(&spec(""));
    assert_eq!(code(&e.km(&["validate"])), 17);
    assert_eq!(code(&e.km(&["realise", "locked-down", "--token", "softhsm"])), 17);
    e.config(&spec("\"host-at-import\""));
    let v = e.km(&["validate"]);
    assert_eq!(code(&v), 0);
    assert!(stdout(&v).contains("host-at-import (opted in)"));
    // Opted in but not implemented: refused before anything is created.
    assert_eq!(code(&e.km(&["realise", "locked-down", "--token", "softhsm"])), 15);
    assert!(e.session().find_objects(&[Attribute::Label(b"locked".to_vec())]).unwrap().is_empty());
}

#[test]
fn conflicts_and_ambiguity() {
    let Some(e) = env("conflicts") else { return };
    e.config(
        r#"
[objects.k]
class = "CKO_PRIVATE_KEY"
keyType = "CKK_EC"
curve = "secp256r1"

[specs.k-sign]
object = "k"
attributes = { CKA_SIGN = true }
tokens.softhsm = { locator = { CKA_LABEL = "conflict" }, autoCreate = true }

[specs.k-nosign]
object = "k"
attributes = { CKA_SIGN = false }
tokens.softhsm = { locator = { CKA_LABEL = "conflict" }, autoCreate = true }

[specs.k-dup]
object = "k"
tokens.softhsm = { locator = { CKA_LABEL = "dup" } }

[objects.g]
class = "CKO_SECRET_KEY"
keyType = "CKK_GENERIC_SECRET"
valueLen = 32

[specs.g-on-aes]
object = "g"
attributes = { CKA_SIGN = true }
tokens.softhsm = { locator = { CKA_LABEL = "typed" } }
"#,
    );
    assert_eq!(code(&e.km(&["realise", "k-sign", "--token", "softhsm", "--update-lock"])), 0);
    // Same locator, different policy: the live object doesn't satisfy the spec.
    assert_eq!(code(&e.km(&["realise", "k-nosign", "--token", "softhsm"])), 13);

    let s = e.session();
    let ec_params = vec![0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
    for _ in 0..2 {
        let label = Attribute::Label(b"dup".to_vec());
        s.generate_key_pair(
            &Mechanism::EccKeyPairGen,
            &[Attribute::Token(true), label.clone(), Attribute::EcParams(ec_params.clone())],
            &[Attribute::Token(true), label, Attribute::Sign(true)],
        )
        .unwrap();
    }
    assert_eq!(code(&e.km(&["resolve", "k-dup", "--token", "softhsm"])), 12);

    // Same class, different key type under the locator: the object type must match.
    s.generate_key(
        &Mechanism::AesKeyGen,
        &[
            Attribute::Token(true),
            Attribute::Label(b"typed".to_vec()),
            Attribute::ValueLen(32.into()),
            Attribute::Sign(true),
            Attribute::Class(ObjectClass::SECRET_KEY),
        ],
    )
    .unwrap();
    assert_eq!(code(&e.km(&["resolve", "g-on-aes", "--token", "softhsm"])), 13);
}

#[test]
fn downgrade_is_an_error() {
    let Some(e) = env("downgrade") else { return };
    e.config(
        r#"
[objects.d]
class = "CKO_SECRET_KEY"
keyType = "CKK_AES"
valueLen = 32

[specs.d-wrap]
object = "d"
attributes = { CKA_EXTRACTABLE = true }
tokens.softhsm = { locator = { CKA_LABEL = "downgrade" }, autoCreate = true }
"#,
    );
    assert_eq!(code(&e.km(&["realise", "d-wrap", "--token", "softhsm", "--update-lock"])), 0);
    // Pretend the lock was recorded with a stronger mode than is now achievable.
    let path = e.dir.join("keys.lock");
    let text = std::fs::read_to_string(&path).unwrap().replace("\"wrap-rebind\"", "\"commitment\"");
    std::fs::write(&path, text).unwrap();
    assert_eq!(code(&e.km(&["verify", "d-wrap", "--token", "softhsm"])), 14);
}

/// Hashes of tests/fixtures/adopt-cert.der computed independently with openssl:
///   sha256(cert DER) and sha256(`openssl x509 -pubkey | openssl pkey -pubin -outform DER`).
const ADOPT_CERTHASH: &str = "sha256-lXNE6ciIfLkwGf6kf84qfibQ08d5fkPuGNKQ5KnyTMM=";
const ADOPT_PUBKEYHASH: &str = "sha256-8DQBv2fMc+z0Q5uxky0+5t9TS6MAHO07fNMqG9thHtM=";

const ADOPT_CERT: &[u8] = include_bytes!("fixtures/adopt-cert.der");

/// Token object template for a fixture certificate (SoftHSM requires CKA_SUBJECT).
fn cert_object(der: &[u8], label: &[u8], id: Option<u8>) -> Vec<Attribute> {
    let der = der.to_vec();
    let cert = <x509_cert::Certificate as x509_cert::der::Decode>::from_der(&der).unwrap();
    let subject = x509_cert::der::Encode::to_der(cert.tbs_certificate().subject()).unwrap();
    let mut t = vec![
        Attribute::Class(ObjectClass::CERTIFICATE),
        Attribute::CertificateType(cryptoki::object::CertificateType::X_509),
        Attribute::Token(true),
        Attribute::Label(label.to_vec()),
        Attribute::Subject(subject),
        Attribute::Value(der),
    ];
    t.extend(id.map(|i| Attribute::Id(vec![i])));
    t
}

#[test]
fn adopt_certificate_and_public_only_key() {
    let Some(e) = env("adopt") else { return };
    // Plant what a PIV slot exposes without login: a certificate and its public key.
    let cert = <x509_cert::Certificate as x509_cert::der::Decode>::from_der(ADOPT_CERT).unwrap();
    let spki = x509_cert::der::Encode::to_der(cert.tbs_certificate().subject_public_key_info()).unwrap();
    let rsa = <rsa::PublicKey as rsa::pkcs8::DecodePublicKey>::from_public_key_der(&spki).unwrap();
    use rsa::traits::PublicKeyParts;
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
tokens.softhsm-anon = { locator = { CKA_LABEL = "adopt-key" }, publicOnly = true }

[specs.adopted-priv]
object = "adopted"
tokens.softhsm = { locator = { CKA_LABEL = "adopt-key" } }

[objects.adopted-cert]
class = "CKO_CERTIFICATE"
certificateType = "CKC_X_509"

[specs.adopted-cert]
object = "adopted-cert"
tokens.softhsm-anon = { locator = { CKA_LABEL = "adopt-cert" } }

[specs.adopted-cert-by-id]
object = "adopted-cert"
tokens.softhsm-anon = { locator = { CKA_ID = "42" } }
"#,
    );
    let pub_only = ["realise", "adopted-pub", "--token", "softhsm-anon", "--update-lock"];
    assert_eq!(code(&e.km(&pub_only)), 0);
    assert_eq!(code(&e.km(&["realise", "adopted-cert", "--token", "softhsm-anon", "--update-lock"])), 0);
    assert_eq!(e.locked_id("adopted", "pubkeyhash"), ADOPT_PUBKEYHASH);
    assert_eq!(e.locked_id("adopted-cert", "certhash"), ADOPT_CERTHASH);
    assert_eq!(e.locked_id("adopted-cert", "pubkeyhash"), ADOPT_PUBKEYHASH, "cert links to its key");
    let lock = e.lock();
    assert_eq!(lock["realisations"]["adopted-pub"]["softhsm-anon"]["publicOnly"].as_bool(), Some(true));
    assert!(lock["realisations"]["adopted-cert"]["softhsm-anon"].get("publicOnly").is_none());
    let verify = e.km(&["verify", "adopted-pub", "--token", "softhsm-anon"]);
    assert!(stdout(&verify).contains("object=adopt-key;type=private"), "consumers get the private key URI");
    // There is no private half: without publicOnly the same locator is simply absent.
    assert_eq!(code(&e.km(&["verify", "adopted-priv", "--token", "softhsm"])), 11);
    // Adopted public-only keys are never deleted (only the public half would go).
    assert_eq!(code(&e.km(&["delete", "adopted-pub", "--token", "softhsm-anon"])), 15);
    // CKA_ID alone also matches the public key object, but certificates are looked up by class.
    assert_eq!(code(&e.km(&["verify", "adopted-cert-by-id", "--token", "softhsm-anon"])), 0);
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
tokens.softhsm = { locator = { CKA_LABEL = "rsa-paths" }, autoCreate = true }

[specs.r-pub]
object = "r"
tokens.softhsm-anon = { locator = { CKA_LABEL = "rsa-paths" }, publicOnly = true }
"#,
    );
    assert_eq!(code(&e.km(&["realise", "r-gen", "--token", "softhsm"])), 10);
    assert_eq!(code(&e.km(&["realise", "r-gen", "--token", "softhsm", "--update-lock"])), 0);
    // Same material through the public key object, without login: same locked identity.
    assert_eq!(code(&e.km(&["realise", "r-pub", "--token", "softhsm-anon", "--update-lock"])), 0);
    assert_eq!(code(&e.km(&["check", "r", "--spec", "r-pub"])), 0);
}

#[test]
fn never_create_over_an_occupied_locator() {
    let Some(e) = env("occupied") else { return };
    let s = e.session();
    s.create_object(&cert_object(ADOPT_CERT, b"occupied", None)).unwrap();
    e.config(
        r#"
[objects.k]
class = "CKO_PRIVATE_KEY"
keyType = "CKK_EC"
curve = "secp256r1"

[specs.k]
object = "k"
tokens.softhsm = { locator = { CKA_LABEL = "occupied" }, autoCreate = true }
"#,
    );
    // Like a PIV slot holding a certificate: generating there would replace its key.
    assert_eq!(code(&e.km(&["realise", "k", "--token", "softhsm"])), 13);
    let keys = s
        .find_objects(&[Attribute::Class(ObjectClass::PRIVATE_KEY), Attribute::Label(b"occupied".to_vec())])
        .unwrap();
    assert!(keys.is_empty());
}

#[test]
fn adoption_rules_are_validated() {
    let Some(e) = env("adoption_rules") else { return };
    for (body, why) in [
        ("keyType = \"CKK_RSA\"\nmodulusBits = 2048\nclass = \"CKO_PRIVATE_KEY\"", "{ CKA_LABEL = \"x\" }, publicOnly = true, autoCreate = true"),
        ("keyType = \"CKK_RSA\"\nmodulusBits = 2048\nclass = \"CKO_PRIVATE_KEY\"", "{ CKA_LABEL = \"x\" }, publicOnly = true }\nattributes = { CKA_SIGN = true"),
        ("certificateType = \"CKC_X_509\"\nclass = \"CKO_CERTIFICATE\"", "{ CKA_LABEL = \"x\" }, autoCreate = true"),
        ("keyType = \"CKK_AES\"\nvalueLen = 32\nclass = \"CKO_SECRET_KEY\"", "{ CKA_LABEL = \"x\" }, publicOnly = true"),
    ] {
        e.config(&format!(
            "[objects.o]\n{body}\n\n[specs.s]\nobject = \"o\"\ntokens.softhsm = {{ locator = {why} }}\n"
        ));
        assert_eq!(code(&e.km(&["validate"])), 17, "{body} / {why}");
    }
}

#[test]
fn module_and_token_provenance_warn_but_do_not_fail() {
    let Some(e) = env("provenance") else { return };
    e.config(EC.replace("ec-lifecycle", "provenance").as_str());
    let r = ["realise", "signing-soft", "--token", "softhsm", "--update-lock"];
    let verify = ["verify", "signing-soft", "--token", "softhsm"];
    assert_eq!(code(&e.km(&["realise", "signing-soft", "--token", "softhsm"])), 10);
    assert_eq!(code(&e.km(&r)), 0);

    let real = &e.lock()["realisations"]["signing-soft"]["softhsm"];
    assert_eq!(real["module"]["path"].as_str(), Some(e.module.as_str()));
    assert_eq!(real["module"]["manufacturer"].as_str(), Some("SoftHSM"));
    assert!(!real["module"]["version"].as_str().unwrap().is_empty());
    assert_eq!(real["token"]["model"].as_str(), Some("SoftHSM v2"));
    assert!(!real["uri"].as_str().unwrap().contains("module-path"), "URI is a pure locator");
    let stderr = |o: &Output| String::from_utf8_lossy(&o.stderr).into_owned();
    assert!(!stderr(&e.km(&verify)).contains("warning"));

    let path = e.dir.join("keys.lock");
    let original = std::fs::read_to_string(&path).unwrap();
    let version = real["module"]["version"].as_str().unwrap().to_owned();

    // A different module version: still verifies (identity is the CA-ID), with a warning.
    std::fs::write(&path, original.replace(&format!("version = \"{version}\""), "version = \"0.0\"")).unwrap();
    let o = e.km(&verify);
    assert_eq!(code(&o), 0);
    assert!(stderr(&o).contains("warning:") && stderr(&o).contains("with module"), "{}", stderr(&o));

    // Same build identity, different file: a note only.
    std::fs::write(&path, original.replace(&e.module, "/nix/store/old-softhsm/lib/libsofthsm2.so")).unwrap();
    let o = e.km(&verify);
    assert_eq!(code(&o), 0);
    assert!(stderr(&o).contains("note:") && !stderr(&o).contains("warning:"), "{}", stderr(&o));

    // A different token: warning.
    std::fs::write(&path, original.replace("model = \"SoftHSM v2\"", "model = \"Other\"")).unwrap();
    assert!(stderr(&e.km(&verify)).contains("realised on token Other"));

    // Re-binding with --update-lock records the current module and token.
    assert_eq!(code(&e.km(&r)), 0);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
    assert!(!stderr(&e.km(&verify)).contains("warning"));
}

/// A known AES-256 value, planted several times with different usage bits: the host knows the
/// material, the token holds it sensitive and (mostly) non-extractable.
const AES_VALUE: [u8; 32] = *b"key-management aes test vector!!";

fn aes_oracle(scheme: &str) -> String {
    aes_commitment(&AES_VALUE, scheme)
}

#[test]
fn aes_commitments_match_host_oracles() {
    let Some(e) = env("aes_commitments") else { return };
    // (spec, label, SIGN, ENCRYPT, WRAP, EXTRACTABLE, mode, schemes computed)
    // aes-all goes first: it links the schemes the single-purpose specs then each check.
    let cases: [(&str, &str, bool, bool, bool, bool, &str, &[&str]); 5] = [
        ("aes-all", "aes-all", true, true, true, false, "commitment", &["cmac", "kcv-ecb", "kw"]),
        ("aes-kek", "aes-kek", false, false, true, false, "commitment", &["kw"]),
        ("aes-mac", "aes-mac", true, false, false, false, "commitment", &["cmac"]),
        ("aes-enc", "aes-enc", false, true, false, false, "commitment", &["kcv-ecb"]),
        // No usable usage bit, but extractable: a session copy gets every AES commitment.
        ("aes-x", "aes-x", false, false, false, true, "wrap-rebind", &["cmac", "kcv-ecb", "kcv-ecb-dec", "kw"]),
    ];
    let s = e.session();
    let mut body = String::from(
        "[objects.aes]\nclass = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_AES\"\nvalueLen = 32\n\n\
         [objects.kek-gen]\nclass = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_AES\"\nvalueLen = 32\n\n\
         [specs.kek-gen]\nobject = \"kek-gen\"\n\
         attributes = { CKA_WRAP = true, CKA_UNWRAP = true, CKA_SIGN = false, CKA_ENCRYPT = false, CKA_SENSITIVE = true, CKA_EXTRACTABLE = false }\n\
         tokens.softhsm = { locator = { CKA_LABEL = \"kek-gen\" }, autoCreate = true }\n",
    );
    for (spec, label, sign, enc, wrap, x, _, _) in cases {
        s.create_object(&[
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(cryptoki::object::KeyType::AES),
            Attribute::Token(true),
            Attribute::Label(label.as_bytes().to_vec()),
            Attribute::Value(AES_VALUE.to_vec()),
            Attribute::Sign(sign),
            Attribute::Encrypt(enc),
            Attribute::Decrypt(true),
            Attribute::Wrap(wrap),
            Attribute::Sensitive(true),
            Attribute::Extractable(x),
        ])
        .unwrap();
        body += &format!(
            "\n[specs.{spec}]\nobject = \"aes\"\n\
             attributes = {{ CKA_SIGN = {sign}, CKA_ENCRYPT = {enc}, CKA_WRAP = {wrap}, CKA_SENSITIVE = true, CKA_EXTRACTABLE = {x} }}\n\
             tokens.softhsm = {{ locator = {{ CKA_LABEL = \"{label}\" }} }}\n"
        );
    }
    e.config(&body);

    // Each spec computes what its usage bits allow; later specs must agree with earlier ones.
    for (spec, _, _, _, _, _, mode, schemes) in cases {
        let o = e.km(&["realise", spec, "--token", "softhsm", "--update-lock"]);
        assert_eq!(code(&o), 0, "{spec}");
        let r: serde_json::Value = serde_json::from_str(&stdout(&o)).unwrap();
        let got: Vec<&str> = r["ids"].as_object().unwrap().keys().map(String::as_str).collect();
        assert_eq!(got, schemes, "{spec}");
        assert_eq!(r["mode"].as_str(), Some(mode), "{spec}");
    }
    // cmac/kcv-ecb/kw are unchanged by kcv-ecb-dec joining (it only adds an ID).
    for scheme in ["cmac", "kcv-ecb", "kcv-ecb-dec", "kw"] {
        assert_eq!(e.locked_id("aes", scheme), aes_oracle(scheme), "{scheme}");
    }
    // The lock never holds the token output itself, only its hash.
    let lock_text = std::fs::read_to_string(e.dir.join("keys.lock")).unwrap();
    assert!(!lock_text.contains(&{
        use base64::Engine;
        let mut m = <cmac::Cmac<aes::Aes256> as KeyInit>::new_from_slice(&AES_VALUE).unwrap();
        m.update(b"key-management/v1/cmac/CKK_AES/256");
        base64::engine::general_purpose::STANDARD.encode(m.finalize().into_bytes())
    }));

    assert_eq!(code(&e.km(&["check", "aes.id.kw", "--spec", "aes-kek"])), 0);
    // aes-kek may only wrap: no CMAC is computed for it.
    assert_eq!(code(&e.km(&["check", "aes.id.cmac", "--spec", "aes-kek"])), 15);
    assert_eq!(code(&e.km(&["check", "aes.id.commitment", "--spec", "aes-kek"])), 15);

    // A scheme the spec can never compute is refused before anything is created.
    assert_eq!(code(&e.km(&["check", "kek-gen.id.cmac"])), 15);
    assert!(s.find_objects(&[Attribute::Label(b"kek-gen".to_vec())]).unwrap().is_empty());

    // A generated, non-extractable KEK: stable identity across runs, deletable by it.
    let r = ["realise", "kek-gen", "--token", "softhsm"];
    let first = e.km(&r);
    assert_eq!(code(&first), 10);
    assert_eq!(got_hash(&e.km(&r)), got_hash(&first));
    assert_eq!(code(&e.km(&[&r[..], &["--update-lock"]].concat())), 0);
    assert_eq!(e.locked_id("kek-gen", "kw"), got_hash(&first));
    assert_eq!(code(&e.km(&["delete", "kek-gen", "--token", "softhsm", "--update-lock"])), 0);
    assert_eq!(code(&e.km(&["verify", "kek-gen", "--token", "softhsm"])), 11);
}

#[test]
fn disjoint_schemes_never_link_material() {
    let Some(e) = env("disjoint") else { return };
    // Two *different* AES keys: one may only sign (cmac), the other only wrap (kw).
    let s = e.session();
    for (label, value, sign, wrap) in [("only-mac", [1u8; 32], true, false), ("only-kek", [2u8; 32], false, true)] {
        s.create_object(&[
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(cryptoki::object::KeyType::AES),
            Attribute::Token(true),
            Attribute::Label(label.as_bytes().to_vec()),
            Attribute::Value(value.to_vec()),
            Attribute::Sign(sign),
            Attribute::Wrap(wrap),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
        ])
        .unwrap();
    }
    e.config(
        r#"
[objects.k]
class = "CKO_SECRET_KEY"
keyType = "CKK_AES"
valueLen = 32

[specs.k-mac]
object = "k"
attributes = { CKA_SIGN = true, CKA_EXTRACTABLE = false }
tokens.softhsm = { locator = { CKA_LABEL = "only-mac" } }

[specs.k-kek]
object = "k"
attributes = { CKA_WRAP = true, CKA_EXTRACTABLE = false }
tokens.softhsm = { locator = { CKA_LABEL = "only-kek" } }
"#,
    );
    assert_eq!(code(&e.km(&["realise", "k-mac", "--token", "softhsm", "--update-lock"])), 0);
    // No shared scheme: the lock must not start claiming the KEK is the same material.
    assert_eq!(code(&e.km(&["realise", "k-kek", "--token", "softhsm", "--update-lock"])), 14);
    assert!(e.lock()["objects"]["k"]["ids"].get("kw").is_none());
    assert!(e.lock()["realisations"].get("k-kek").is_none());
}

#[test]
fn curves_and_rsa_sizes_match_an_independent_der_oracle() {
    let Some(e) = env("curves") else { return };
    let kinds = [
        ("p256", "keyType = \"CKK_EC\"\ncurve = \"secp256r1\""),
        ("p384", "keyType = \"CKK_EC\"\ncurve = \"secp384r1\""),
        ("p521", "keyType = \"CKK_EC\"\ncurve = \"P-521\""),
        ("ed25519", "keyType = \"CKK_EC_EDWARDS\"\ncurve = \"edwards25519\""),
        ("ed448", "keyType = \"CKK_EC_EDWARDS\"\ncurve = \"Ed448\""),
        ("secp256k1", "keyType = \"CKK_EC\"\ncurve = \"secp256k1\""),
        ("bp256", "keyType = \"CKK_EC\"\ncurve = \"brainpoolP256r1\""),
        ("bp384", "keyType = \"CKK_EC\"\ncurve = \"brainpoolP384r1\""),
        ("rsa3072", "keyType = \"CKK_RSA\"\nmodulusBits = 3072"),
        ("rsa4096", "keyType = \"CKK_RSA\"\nmodulusBits = 4096"),
    ];
    let mut body = String::new();
    for (k, ty) in kinds {
        body += &format!(
            "[objects.{k}]\nclass = \"CKO_PRIVATE_KEY\"\n{ty}\n\n\
             [specs.{k}-gen]\nobject = \"{k}\"\n\
             attributes = {{ CKA_SIGN = true, CKA_SENSITIVE = true, CKA_EXTRACTABLE = false }}\n\
             tokens.softhsm = {{ locator = {{ CKA_LABEL = \"{k}\" }}, autoCreate = true }}\n\n\
             [specs.{k}-pub]\nobject = \"{k}\"\n\
             tokens.softhsm-anon = {{ locator = {{ CKA_LABEL = \"{k}\" }}, publicOnly = true }}\n\n"
        );
    }
    e.config(&body);
    assert_eq!(code(&e.km(&["validate"])), 0);
    let s = e.session();
    for (k, _) in kinds {
        let gen = format!("{k}-gen");
        assert_eq!(code(&e.km(&["realise", &gen, "--token", "softhsm"])), 10, "{k}");
        assert_eq!(code(&e.km(&["realise", &gen, "--token", "softhsm", "--update-lock"])), 0, "{k}");
        assert_eq!(e.locked_id(k, "pubkeyhash"), sri(&oracle_spki(&s, k)), "{k}");
        // Same identity through the public key object, without login.
        let pubs = format!("{k}-pub");
        assert_eq!(code(&e.km(&["realise", &pubs, "--token", "softhsm-anon", "--update-lock"])), 0, "{k}");
    }
    // The curve is part of the object type: a P-384 key does not satisfy a P-256 spec.
    let text = std::fs::read_to_string(e.dir.join("keys.toml")).unwrap();
    std::fs::write(
        e.dir.join("keys.toml"),
        text.replace("[objects.p384]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp384r1\"",
                     "[objects.p384]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\""),
    )
    .unwrap();
    assert_eq!(code(&e.km(&["resolve", "p384-gen", "--token", "softhsm"])), 13);
}

/// openssl-computed hashes of the EC and Edwards fixture certificates (see ADOPT_CERTHASH).
const P384_CERTHASH: &str = "sha256-N9KvOrT63A5pe2lyZhomsSGisv5jxm7uGH0BBaDvT8w=";
const P384_PUBKEYHASH: &str = "sha256-vOGGK+vjgXw92IhWaKP7ud6cGe6qS9UCctpXq6zZmZo=";
const ED25519_CERTHASH: &str = "sha256-vLKP3eF+jeIMpcIz0K9c8oiCVsbvDve+uBUYho+aOmU=";
const ED25519_PUBKEYHASH: &str = "sha256-LmLQD9g76Y3XJI3Wu72BFxjm/HLImLgqJazAeCNi4lY=";

#[test]
fn adopt_ec_and_edwards_certificates() {
    let Some(e) = env("adopt_ec") else { return };
    let s = e.session();
    let fixtures: [(&str, &[u8], &[u8], &str, &str, &str); 2] = [
        ("p384", include_bytes!("fixtures/adopt-cert-p384.der"), P384, "CKK_EC\"\ncurve = \"secp384r1", P384_CERTHASH, P384_PUBKEYHASH),
        ("ed25519", include_bytes!("fixtures/adopt-cert-ed25519.der"), ED25519, "CKK_EC_EDWARDS\"\ncurve = \"edwards25519", ED25519_CERTHASH, ED25519_PUBKEYHASH),
    ];
    let mut body = String::new();
    for (i, (k, der, params, ty, _, _)) in fixtures.iter().enumerate() {
        let id = 0x50 + i as u8;
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
             tokens.softhsm-anon = {{ locator = {{ CKA_LABEL = \"{k}-key\" }}, publicOnly = true }}\n\n\
             [objects.{k}-cert]\nclass = \"CKO_CERTIFICATE\"\ncertificateType = \"CKC_X_509\"\n\n\
             [specs.{k}-cert]\nobject = \"{k}-cert\"\n\
             tokens.softhsm-anon = {{ locator = {{ CKA_LABEL = \"{k}-cert\" }} }}\n\n"
        );
    }
    e.config(&body);
    for (k, _, _, _, certhash, pubkeyhash) in fixtures {
        assert_eq!(code(&e.km(&["realise", k, "--token", "softhsm-anon", "--update-lock"])), 0, "{k}");
        let cert = format!("{k}-cert");
        assert_eq!(code(&e.km(&["realise", &cert, "--token", "softhsm-anon", "--update-lock"])), 0, "{k}");
        assert_eq!(e.locked_id(k, "pubkeyhash"), pubkeyhash, "{k}");
        assert_eq!(e.locked_id(&cert, "certhash"), certhash, "{k}");
        assert_eq!(e.locked_id(&cert, "pubkeyhash"), pubkeyhash, "{k}: cert links to its key");
    }
}

#[test]
fn scheme_the_token_lacks_is_refused_before_create() {
    let Some(e) = env("token_lacks") else { return };
    // The same token through a SoftHSM config that hides CKM_AES_CMAC.
    let conf = std::fs::read_to_string(std::env::var("SOFTHSM2_CONF").unwrap()).unwrap();
    let no_cmac = e.dir.join("softhsm2-no-cmac.conf");
    std::fs::write(&no_cmac, conf + "\nslots.mechanisms = -CKM_AES_CMAC\n").unwrap();
    let env = [("SOFTHSM2_CONF", no_cmac.as_path())];
    e.config(
        r#"
[objects.k]
class = "CKO_SECRET_KEY"
keyType = "CKK_AES"
valueLen = 32

[specs.k]
object = "k"
attributes = { CKA_SIGN = true, CKA_WRAP = true, CKA_SENSITIVE = true, CKA_EXTRACTABLE = false }
tokens.softhsm = { locator = { CKA_LABEL = "no-cmac" }, autoCreate = true }
"#,
    );
    let caps = stdout(&e.km_env(&["caps", "--token", "softhsm"], &env));
    assert!(caps.contains("CKM_AES_KEY_WRAP\"") && !caps.contains("CKM_AES_CMAC\""), "config did not hide CMAC: {caps}");
    // The spec allows cmac, but this token cannot compute it: refused, nothing created.
    assert_eq!(code(&e.km_env(&["check", "k.id.cmac"], &env)), 15);
    assert!(e.session().find_objects(&[Attribute::Label(b"no-cmac".to_vec())]).unwrap().is_empty());
    // kw is still available: first use creates the key (TOFU: no locked hash yet).
    assert_eq!(code(&e.km_env(&["check", "k.id.kw"], &env)), 10);
    let o = e.km_env(&["realise", "k", "--token", "softhsm", "--update-lock"], &env);
    assert_eq!(code(&o), 0);
    let ids: serde_json::Value = serde_json::from_str(&stdout(&o)).unwrap();
    assert_eq!(ids["ids"].as_object().unwrap().keys().collect::<Vec<_>>(), ["kw"]);
    // With CMAC back, the same key also yields cmac, linked through the locked kw.
    assert_eq!(code(&e.km(&["realise", "k", "--token", "softhsm", "--update-lock"])), 0);
    assert!(e.lock()["objects"]["k"]["ids"].get("cmac").is_some());
}

#[test]
fn provider_is_detected_or_named() {
    let Some(e) = env("provider") else { return };
    e.config(EC);
    let caps = |o: &Output| serde_json::from_str::<serde_json::Value>(&stdout(o)).unwrap()["provider"].clone();
    assert_eq!(caps(&e.km(&["caps", "--token", "softhsm"])), "softhsm", "auto-detected from C_GetInfo");
    let path = e.dir.join("keys.toml");
    let text = std::fs::read_to_string(&path).unwrap();
    let named = |p: &str| text.replacen("tokenLabel = \"kmtest\"", &format!("tokenLabel = \"kmtest\"\nprovider = \"{p}\""), 1);
    std::fs::write(&path, named("generic")).unwrap();
    assert_eq!(caps(&e.km(&["caps", "--token", "softhsm"])), "generic", "explicit choice wins");
    std::fs::write(&path, named("nope")).unwrap();
    assert_eq!(code(&e.km(&["validate"])), 17);
    assert_eq!(code(&e.km(&["caps", "--token", "softhsm"])), 17);
}


/// Plant a secret key with a known value (the host oracle knows it).
fn plant_secret(s: &Session, label: &str, kt: cryptoki::object::KeyType, value: &[u8], attrs: &[Attribute]) {
    let mut t = vec![
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(kt),
        Attribute::Token(true),
        Attribute::Label(label.as_bytes().to_vec()),
        Attribute::Value(value.to_vec()),
        Attribute::Sensitive(true),
        Attribute::Extractable(false),
    ];
    t.extend_from_slice(attrs);
    s.create_object(&t).unwrap();
}

#[test]
fn hmac_key_types_commit_with_their_own_hash() {
    use cryptoki::object::KeyType as K;
    let Some(e) = env("hmac_types") else { return };
    if !cryptoki_hmac_types_fixed(std::env::var("CAKEYS_TEST_REQUIRE").is_ok()) {
        return;
    }
    // SoftHSM wants HMAC keys at least as long as the hash output.
    let material = *b"hmac key types test vector, long enough for every hash in the set";
    let types = [
        ("CKK_SHA_1_HMAC", K::SHA_1_HMAC, 20),
        ("CKK_SHA224_HMAC", K::SHA224_HMAC, 28),
        ("CKK_SHA256_HMAC", K::SHA256_HMAC, 32),
        ("CKK_SHA384_HMAC", K::SHA384_HMAC, 48),
        ("CKK_SHA512_HMAC", K::SHA512_HMAC, 64),
    ];
    let s = e.session();
    let mut body = String::new();
    for (name, kt, len) in types {
        let label = format!("hmac-{name}");
        plant_secret(&s, &label, kt, &material[..len], &[Attribute::Sign(true)]);
        body += &format!(
            "[objects.{name}]\nclass = \"CKO_SECRET_KEY\"\nkeyType = \"{name}\"\nvalueLen = {len}\n\n\
             [specs.{name}]\nobject = \"{name}\"\nattributes = {{ CKA_SIGN = true, CKA_EXTRACTABLE = false }}\n\
             tokens.softhsm = {{ locator = {{ CKA_LABEL = \"{label}\" }} }}\n\n"
        );
    }
    body += "[objects.gen384]\nclass = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_SHA384_HMAC\"\nvalueLen = 48\n\n\
             [specs.gen384]\nobject = \"gen384\"\nattributes = { CKA_SIGN = true, CKA_EXTRACTABLE = false }\n\
             tokens.softhsm = { locator = { CKA_LABEL = \"hmac-gen384\" }, autoCreate = true }\n";
    e.config(&body);
    for (name, _, len) in types {
        assert_eq!(code(&e.km(&["realise", name, "--token", "softhsm", "--update-lock"])), 0, "{name}");
        let label = format!("key-management/v1/commitment/{name}/{}", len * 8);
        let value = &material[..len];
        let mac = |out: Vec<u8>| sri(&out);
        let want = match name {
            "CKK_SHA_1_HMAC" => mac({ let mut m = <Hmac<sha1::Sha1> as KeyInit>::new_from_slice(value).unwrap(); m.update(label.as_bytes()); m.finalize().into_bytes().to_vec() }),
            "CKK_SHA224_HMAC" => mac({ let mut m = <Hmac<sha2::Sha224> as KeyInit>::new_from_slice(value).unwrap(); m.update(label.as_bytes()); m.finalize().into_bytes().to_vec() }),
            "CKK_SHA256_HMAC" => mac({ let mut m = <Hmac<sha2::Sha256> as KeyInit>::new_from_slice(value).unwrap(); m.update(label.as_bytes()); m.finalize().into_bytes().to_vec() }),
            "CKK_SHA384_HMAC" => mac({ let mut m = <Hmac<sha2::Sha384> as KeyInit>::new_from_slice(value).unwrap(); m.update(label.as_bytes()); m.finalize().into_bytes().to_vec() }),
            _ => mac({ let mut m = <Hmac<sha2::Sha512> as KeyInit>::new_from_slice(value).unwrap(); m.update(label.as_bytes()); m.finalize().into_bytes().to_vec() }),
        };
        assert_eq!(e.locked_id(name, "commitment"), want, "{name}");
    }
    // There is no key generation for hash-bound HMAC types: refused up front, nothing created.
    let o = e.km(&["realise", "gen384", "--token", "softhsm"]);
    assert_eq!(code(&o), 15);
    assert!(String::from_utf8_lossy(&o.stderr).contains("no key generation for CKK_SHA384_HMAC"));
    assert!(s.find_objects(&[Attribute::Label(b"hmac-gen384".to_vec())]).unwrap().is_empty());
}

#[test]
fn aes_128_192_and_decrypt_only_match_host_oracles() {
    let Some(e) = env("aes_sizes") else { return };
    let s = e.session();
    let all = [Attribute::Sign(true), Attribute::Encrypt(true), Attribute::Decrypt(true), Attribute::Wrap(true)];
    let k128 = *b"aes-128 vector!!";
    let k192 = *b"aes-192 test vector 24B!";
    let k256 = *b"aes-256 decrypt-only vector 32B!";
    plant_secret(&s, "aes-128", cryptoki::object::KeyType::AES, &k128, &all);
    plant_secret(&s, "aes-192", cryptoki::object::KeyType::AES, &k192, &all);
    plant_secret(&s, "aes-dec", cryptoki::object::KeyType::AES, &k256, &[Attribute::Decrypt(true), Attribute::Encrypt(false), Attribute::Sign(false), Attribute::Wrap(false)]);
    let spec = |name: &str, len: usize, attrs: &str, label: &str| {
        format!(
            "[objects.{name}]\nclass = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_AES\"\nvalueLen = {len}\n\n\
             [specs.{name}]\nobject = \"{name}\"\nattributes = {{ {attrs}, CKA_EXTRACTABLE = false }}\n\
             tokens.softhsm = {{ locator = {{ CKA_LABEL = \"{label}\" }} }}\n\n"
        )
    };
    let every = "CKA_SIGN = true, CKA_ENCRYPT = true, CKA_DECRYPT = true, CKA_WRAP = true";
    e.config(&(spec("a128", 16, every, "aes-128") + &spec("a192", 24, every, "aes-192") + &spec("adec", 32, "CKA_DECRYPT = true", "aes-dec")));
    for (name, key, schemes) in [
        ("a128", &k128[..], &["cmac", "kcv-ecb", "kcv-ecb-dec", "kw"][..]),
        ("a192", &k192[..], &["cmac", "kcv-ecb", "kcv-ecb-dec", "kw"][..]),
        ("adec", &k256[..], &["kcv-ecb-dec"][..]),
    ] {
        let o = e.km(&["realise", name, "--token", "softhsm", "--update-lock"]);
        assert_eq!(code(&o), 0, "{name}");
        let r: serde_json::Value = serde_json::from_str(&stdout(&o)).unwrap();
        assert_eq!(r["ids"].as_object().unwrap().keys().collect::<Vec<_>>(), schemes, "{name}");
        for scheme in schemes {
            assert_eq!(e.locked_id(name, scheme), aes_commitment(key, scheme), "{name} {scheme}");
        }
    }
    // The decrypt-only key is now identifiable (before kcv-ecb-dec it needed an opt-in mode).
    assert_eq!(code(&e.km(&["check", "adec"])), 0);
}

#[test]
fn a_new_scheme_missing_from_the_lock_is_a_note_unless_requested() {
    let Some(e) = env("upgrade") else { return };
    let key = *b"upgrade rule aes test vector 32B";
    plant_secret(&e.session(), "upgrade-aes", cryptoki::object::KeyType::AES, &key, &[Attribute::Sign(true), Attribute::Encrypt(true)]);
    e.config(
        "[objects.u]\nclass = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_AES\"\nvalueLen = 32\n\n\
         [specs.u]\nobject = \"u\"\nattributes = { CKA_SIGN = true, CKA_ENCRYPT = true }\n\
         tokens.softhsm = { locator = { CKA_LABEL = \"upgrade-aes\" } }\n",
    );
    // First use: nothing to compare, fails like a FOD.
    assert_eq!(code(&e.km(&["verify", "u", "--token", "softhsm"])), 10);
    // A lock written by a version that only knew cmac.
    std::fs::write(
        e.dir.join("keys.lock"),
        format!("version = 1\n[objects.u.ids]\ncmac = \"{}\"\n", aes_commitment(&key, "cmac")),
    )
    .unwrap();
    let v = e.km(&["verify", "u", "--token", "softhsm"]);
    assert_eq!(code(&v), 0);
    assert!(String::from_utf8_lossy(&v.stderr).contains("kcv-ecb identity the lock does not record"));
    assert_eq!(code(&e.km(&["check", "u"])), 0);
    assert_eq!(code(&e.km(&["check", "u.id.cmac"])), 0);
    // Asking for the scheme explicitly requires it to be locked.
    assert_eq!(code(&e.km(&["check", "u.id.kcv-ecb"])), 10);
    assert_eq!(code(&e.km(&["realise", "u", "--token", "softhsm", "--update-lock"])), 0);
    assert_eq!(code(&e.km(&["check", "u.id.kcv-ecb"])), 0);
    // A wrong locked value still fails, whatever else matches.
    let text = std::fs::read_to_string(e.dir.join("keys.lock")).unwrap();
    let wrong = text.replace(&aes_commitment(&key, "kcv-ecb"), "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
    std::fs::write(e.dir.join("keys.lock"), wrong).unwrap();
    assert_eq!(code(&e.km(&["verify", "u", "--token", "softhsm"])), 10);
}

#[test]
fn standalone_public_key_objects() {
    let Some(e) = env("public_keys") else { return };
    let der: &[u8] = include_bytes!("fixtures/adopt-cert-p384.der");
    let cert = <x509_cert::Certificate as x509_cert::der::Decode>::from_der(der).unwrap();
    let point = cert.tbs_certificate().subject_public_key_info().subject_public_key.raw_bytes().to_vec();
    e.session()
        .create_object(&[
            Attribute::Class(ObjectClass::PUBLIC_KEY),
            Attribute::KeyType(cryptoki::object::KeyType::EC),
            Attribute::Token(true),
            Attribute::Label(b"standalone-pub".to_vec()),
            Attribute::Verify(true),
            Attribute::EcParams(P384.to_vec()),
            Attribute::EcPoint(tlv(0x04, &point)),
        ])
        .unwrap();
    e.config(
        "[objects.anchor]\nclass = \"CKO_PUBLIC_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp384r1\"\n\n\
         [specs.anchor]\nobject = \"anchor\"\nattributes = { CKA_VERIFY = true }\n\
         tokens.softhsm-anon = { locator = { CKA_LABEL = \"standalone-pub\" } }\n\
         tokens.softhsm = { locator = { CKA_LABEL = \"standalone-pub\" } }\n",
    );
    let o = e.km(&["realise", "anchor", "--token", "softhsm-anon", "--update-lock"]);
    assert_eq!(code(&o), 0);
    assert_eq!(e.locked_id("anchor", "pubkeyhash"), P384_PUBKEYHASH, "matches openssl over the certificate's key");
    assert!(stdout(&e.km(&["verify", "anchor", "--token", "softhsm-anon"])).ends_with("object=standalone-pub;type=public"));
    assert_eq!(code(&e.km(&["check", "anchor.id.pubkeyhash", "--token", "softhsm-anon"])), 0);
    // Deletable by identity; then absent.
    assert_eq!(code(&e.km(&["delete", "anchor", "--token", "softhsm", "--update-lock"])), 0);
    assert_eq!(code(&e.km(&["verify", "anchor", "--token", "softhsm-anon"])), 11);
    // Public keys are adopted, not created.
    let text = std::fs::read_to_string(e.dir.join("keys.toml")).unwrap();
    std::fs::write(e.dir.join("keys.toml"), text.replace("\"standalone-pub\" } }\ntokens.softhsm =", "\"standalone-pub\" }, autoCreate = true }\ntokens.softhsm =")).unwrap();
    assert_eq!(code(&e.km(&["validate"])), 17);
}

#[test]
fn data_objects_are_identified_by_their_public_value() {
    let Some(e) = env("data") else { return };
    let value = b"key-management data object payload\n".to_vec();
    let s = e.session();
    let data = |label: &str, private: bool| {
        vec![
            Attribute::Class(ObjectClass::DATA),
            Attribute::Token(true),
            Attribute::Private(private),
            Attribute::Label(label.as_bytes().to_vec()),
            Attribute::Application(b"key-management test".to_vec()),
            Attribute::Value(value.clone()),
        ]
    };
    s.create_object(&data("data-public", false)).unwrap();
    s.create_object(&data("data-private", true)).unwrap();
    e.config(
        "[objects.blob]\nclass = \"CKO_DATA\"\n\n\
         [specs.blob]\nobject = \"blob\"\nattributes = { CKA_PRIVATE = false }\n\
         tokens.softhsm-anon = { locator = { CKA_LABEL = \"data-public\" } }\n\n\
         [objects.secret-blob]\nclass = \"CKO_DATA\"\n\n\
         [specs.secret-blob]\nobject = \"secret-blob\"\n\
         tokens.softhsm = { locator = { CKA_LABEL = \"data-private\" } }\n",
    );
    assert_eq!(code(&e.km(&["realise", "blob", "--token", "softhsm-anon", "--update-lock"])), 0);
    // valuehash is SHA-256 of the content: the same SRI hash as a flat Nix fixed-output hash.
    assert_eq!(e.locked_id("blob", "valuehash"), sri(&value));
    assert!(stdout(&e.km(&["verify", "blob", "--token", "softhsm-anon"])).ends_with("object=data-public;type=data"));
    assert_eq!(code(&e.km(&["check", "blob.id.valuehash"])), 0);
    // A private value's hash would be an offline guessing oracle: refused, nothing recorded.
    let o = e.km(&["realise", "secret-blob", "--token", "softhsm", "--update-lock"]);
    assert_eq!(code(&o), 15);
    assert!(String::from_utf8_lossy(&o.stderr).contains("CKA_PRIVATE"));
    let lock = std::fs::read_to_string(e.dir.join("keys.lock")).unwrap();
    assert!(!lock.contains("secret-blob"), "{lock}");
    // Data objects are adopted, not created.
    let text = std::fs::read_to_string(e.dir.join("keys.toml")).unwrap();
    std::fs::write(e.dir.join("keys.toml"), text.replace("\"data-public\" } }", "\"data-public\" }, autoCreate = true }")).unwrap();
    assert_eq!(code(&e.km(&["validate"])), 17);
}

#[test]
fn brainpool_p512_is_refused_clearly() {
    let Some(e) = env("bp512") else { return };
    e.config(
        "[objects.k]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"brainpoolP512r1\"\n\n\
         [specs.k]\nobject = \"k\"\ntokens.softhsm = { locator = { CKA_LABEL = \"bp512\" }, autoCreate = true }\n",
    );
    let o = e.km(&["validate"]);
    assert_eq!(code(&o), 15);
    assert!(String::from_utf8_lossy(&o.stderr).contains("no RustCrypto crate"));
}

/// KNOWN GAP (docs/REVIEW-2026-11-11.md, H1), documents current behaviour: SoftHSM EC private
/// keys expose no public key, so their identity is read from the public key object under the same
/// locator, which nothing binds to the private key. Replace the private key, keep the public
/// object: `verify` still passes. When H1 is fixed this must fail (flip the assertion).
#[test]
fn known_gap_ec_private_identity_comes_from_an_unbound_public_object() {
    let Some(e) = env("gap_h1") else { return };
    e.config(EC.replace("ec-lifecycle", "gap-a").as_str());
    assert_eq!(code(&e.km(&["realise", "signing-soft", "--token", "softhsm", "--update-lock"])), 0);
    let s = e.session();
    let ec_params = vec![0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
    let (_, other_private) = s
        .generate_key_pair(
            &Mechanism::EccKeyPairGen,
            &[Attribute::Token(true), Attribute::Label(b"gap-b".to_vec()), Attribute::EcParams(ec_params)],
            &[Attribute::Token(true), Attribute::Label(b"gap-b".to_vec()), Attribute::Sign(true), Attribute::Sensitive(true), Attribute::Extractable(false)],
        )
        .unwrap();
    let original = s
        .find_objects(&[Attribute::Class(ObjectClass::PRIVATE_KEY), Attribute::Label(b"gap-a".to_vec())])
        .unwrap()[0];
    s.destroy_object(original).unwrap();
    s.update_attributes(other_private, &[Attribute::Label(b"gap-a".to_vec())]).unwrap();
    // Different private key under the locator, same public object: not detected today.
    assert_eq!(code(&e.km(&["verify", "signing-soft", "--token", "softhsm"])), 0, "H1 fixed? flip this assertion");
}
