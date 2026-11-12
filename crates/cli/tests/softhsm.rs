//! End-to-end tests of the CLI against a SoftHSM token.
//!
//! Needs `SOFTHSM2_CONF` and `CAKEYS_TEST_MODULE` (path to libsofthsm2.so) with an initialised token
//! labelled `kmtest`, user PIN `1234` (the Nix build's preCheck sets this up). Tests are skipped
//! when `CAKEYS_TEST_MODULE` is unset, unless `CAKEYS_TEST_REQUIRE=1`.

#![allow(clippy::type_complexity)] // table-driven cases

use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::object::{Attribute, AttributeType, ObjectClass};
use cryptoki::session::Session;
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

    /// Replace the lock with a hand-written one, keeping the realisations already recorded (the
    /// part under test is `objects`).
    fn write_lock_keeping_realisations(&self, text: &str) {
        let mut lock: toml::Table = toml::from_str(text).unwrap();
        lock.insert("realisations".into(), self.lock()["realisations"].clone());
        std::fs::write(self.dir.join("keys.lock"), toml::to_string(&lock).unwrap()).unwrap();
    }

    fn session(&self) -> TestSession {
        open_session(&self.module, "kmtest", "1234")
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
    assert_eq!(e.locked_id("signing", "rfc7093m4"), got);
    assert_eq!(code(&e.km(&r)), 0);

    let verify = e.km(&["verify", "signing-soft", "--token", "softhsm"]);
    assert_eq!(code(&verify), 0);
    let uri = stdout(&verify);
    assert!(uri.starts_with("pkcs11:token=kmtest;serial=") && uri.contains(";object=ec-lifecycle;type=private"), "{uri}");
    let check = e.km(&["check", "signing.id.rfc7093m4"]);
    assert_eq!(code(&check), 0);
    // `pubkeyhash` is an input alias of rfc7093m4.
    assert_eq!(stdout(&e.km(&["check", "signing.id.pubkeyhash"])), stdout(&check));
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
        format!(
            "version = 1\n[objects.signing.type]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\
             [objects.signing.ids]\nrfc7093m4 = \"{got}\"\n"
        ),
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
tokens.softhsm = { locator = { CKA_LABEL = "conflict" }, autoCreate = true, binding = "token-asserted" }

[specs.k-dup]
object = "k"
attributes = { CKA_SIGN = true }
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
attributes = { CKA_SIGN = true }
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
    assert_eq!(e.locked_id("adopted", "rfc7093m4"), ADOPT_PUBKEYHASH);
    assert_eq!(e.locked_id("adopted-cert", "certhash"), ADOPT_CERTHASH);
    assert_eq!(e.locked_id("adopted-cert", "rfc7093m4"), ADOPT_PUBKEYHASH, "cert links to its key");
    // The relation is explicit in the lock, and checked when it is loaded.
    let lock = e.lock();
    assert_eq!(lock["objects"]["adopted-cert"]["pairs"].as_array().unwrap(), &vec![toml::Value::from("adopted")]);
    assert_eq!(lock["objects"]["adopted"]["pairs"].as_array().unwrap(), &vec![toml::Value::from("adopted-cert")]);
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
    let by_id = ["realise", "adopted-cert-by-id", "--token", "softhsm-anon"];
    assert_eq!(code(&e.km(&by_id)), 14, "same certificate, but not recorded under this spec yet");
    assert_eq!(code(&e.km(&[&by_id[..], &["--update-lock"]].concat())), 0);

    // Locks split per object and join again: a pair partner in another fragment is allowed.
    let full = e.lock();
    let write = |lock: &toml::Value| std::fs::write(e.dir.join("keys.lock"), toml::to_string(lock).unwrap()).unwrap();
    let fragment = |objects: &[&str], specs: &[&str]| {
        let mut f = full.clone();
        f["objects"].as_table_mut().unwrap().retain(|k, _| objects.iter().any(|o| *o == k));
        f["realisations"].as_table_mut().unwrap().retain(|k, _| specs.iter().any(|s| *s == k));
        f
    };
    let key = fragment(&["adopted"], &["adopted-pub"]);
    let cert = fragment(&["adopted-cert"], &["adopted-cert", "adopted-cert-by-id"]);
    write(&key);
    assert_eq!(code(&e.km(&["verify", "adopted-pub", "--token", "softhsm-anon"])), 0);
    write(&cert);
    assert_eq!(code(&e.km(&["verify", "adopted-cert", "--token", "softhsm-anon"])), 0);
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
    let o = e.km(&["verify", "adopted-pub", "--token", "softhsm-anon"]);
    assert_eq!(code(&o), 0);
    assert!(String::from_utf8_lossy(&o.stderr).contains("not listed as its pairs"));
    assert_eq!(code(&e.km(&["realise", "adopted-pub", "--token", "softhsm-anon", "--update-lock"])), 0);
    assert_eq!(e.lock(), full);
    // A listed partner that is present must list back.
    let mut one_sided = full.clone();
    one_sided["objects"]["adopted"].as_table_mut().unwrap().remove("pairs");
    write(&one_sided);
    assert_eq!(code(&e.km(&["verify", "adopted-pub", "--token", "softhsm-anon"])), 17);
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
attributes = { CKA_SIGN = true }
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
    assert_eq!(real["provenance"]["module"]["path"].as_str(), Some(e.module.as_str()));
    assert_eq!(real["provenance"]["module"]["manufacturer"].as_str(), Some("SoftHSM"));
    assert!(!real["provenance"]["module"]["version"].as_str().unwrap().is_empty());
    assert_eq!(real["provenance"]["token"]["model"].as_str(), Some("SoftHSM v2"));
    assert!(!real["observed"]["uri"].as_str().unwrap().contains("module-path"), "URI is a pure locator");
    let stderr = |o: &Output| String::from_utf8_lossy(&o.stderr).into_owned();
    assert!(!stderr(&e.km(&verify)).contains("warning"));

    let path = e.dir.join("keys.lock");
    let original = std::fs::read_to_string(&path).unwrap();
    let version = real["provenance"]["module"]["version"].as_str().unwrap().to_owned();

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

/// The field classes are real: removing `observed` and `provenance` changes no verdict, while the
/// compared fields and the version are required.
#[test]
fn observed_and_provenance_never_change_a_verdict() {
    let Some(e) = env("classes") else { return };
    e.config(EC.replace("ec-lifecycle", "classes").as_str());
    let verify = ["verify", "signing-soft", "--token", "softhsm"];
    assert_eq!(code(&e.km(&["realise", "signing-soft", "--token", "softhsm", "--update-lock"])), 0);
    let full = e.lock();
    let strip = |mut lock: toml::Value| {
        let real = lock["realisations"]["signing-soft"]["softhsm"].as_table_mut().unwrap();
        assert!(real.remove("observed").is_some() && real.remove("provenance").is_some());
        lock
    };
    let write = |lock: &toml::Value| std::fs::write(e.dir.join("keys.lock"), toml::to_string(lock).unwrap()).unwrap();
    write(&strip(full.clone()));
    assert_eq!(code(&e.km(&verify)), 0);
    // A wrong ID is still a mismatch, a missing record still a precondition failure.
    let mut wrong = strip(full.clone());
    wrong["objects"]["signing"]["ids"]["rfc7093m4"] = sri(b"other").into();
    write(&wrong);
    assert_eq!(code(&e.km(&verify)), 10);
    let mut unrecorded = full.clone();
    unrecorded["realisations"].as_table_mut().unwrap().clear();
    write(&unrecorded);
    assert_eq!(code(&e.km(&verify)), 14);
    // Required: the version, and every compared field.
    let mut versionless = full.clone();
    versionless.as_table_mut().unwrap().remove("version");
    write(&versionless);
    assert_eq!(code(&e.km(&verify)), 17);
    let mut objectless = full.clone();
    objectless["realisations"]["signing-soft"]["softhsm"].as_table_mut().unwrap().remove("object");
    write(&objectless);
    assert_eq!(code(&e.km(&verify)), 17);
}

/// A consumer that picks the private key by CKA_ID (OpenSSH) must get this one: with a login,
/// another private key under the same CKA_ID is ambiguous. The lock records the session kind.
#[test]
fn a_second_private_key_under_the_same_id_is_ambiguous() {
    let Some(e) = env("dup_id") else { return };
    let s = e.session();
    let ec_params = vec![0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
    let gen = |label: &[u8]| {
        let common = [Attribute::Token(true), Attribute::Label(label.to_vec()), Attribute::Id(vec![0x77])];
        s.generate_key_pair(
            &Mechanism::EccKeyPairGen,
            &[&common[..], &[Attribute::EcParams(ec_params.clone())]].concat(),
            &[&common[..], &[Attribute::Sign(true)]].concat(),
        )
        .unwrap()
    };
    gen(b"dup-id-a");
    e.config(
        "[objects.k]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n\
         [specs.k]\nobject = \"k\"\nattributes = { CKA_SIGN = true }\n\
         tokens.softhsm = { locator = { CKA_LABEL = \"dup-id-a\" } }\n\n\
         [specs.k-pub]\nobject = \"k\"\ntokens.softhsm-anon = { locator = { CKA_LABEL = \"dup-id-a\" }, publicOnly = true }\n",
    );
    assert_eq!(code(&e.km(&["realise", "k", "--token", "softhsm", "--update-lock"])), 0);
    assert_eq!(code(&e.km(&["realise", "k-pub", "--token", "softhsm-anon", "--update-lock"])), 0);
    let lock = e.lock();
    assert_eq!(lock["realisations"]["k"]["softhsm"]["observed"]["session"].as_str(), Some("user"));
    assert_eq!(lock["realisations"]["k-pub"]["softhsm-anon"]["observed"]["session"].as_str(), Some("public"));
    let uri = lock["realisations"]["k"]["softhsm"]["observed"]["uri"].as_str().unwrap();
    assert!(uri.contains(";serial="), "{uri}");
    gen(b"dup-id-b");
    let o = e.km(&["verify", "k", "--token", "softhsm"]);
    assert_eq!(code(&o), 12);
    assert!(String::from_utf8_lossy(&o.stderr).contains("share CKA_ID %77"), "{}", String::from_utf8_lossy(&o.stderr));
    // A public session cannot see the other private key: it passes, as the lock says it would.
    assert_eq!(code(&e.km(&["verify", "k-pub", "--token", "softhsm-anon"])), 0);
}

/// A malformed or self-contradictory lock is invalid (exit 17), not a hash mismatch; the same
/// material is never recorded under two names; computing fewer schemes than recorded is refused.
#[test]
fn lock_invariants_are_checked() {
    let Some(e) = env("invariants") else { return };
    let body = EC.replace("ec-lifecycle", "invariants")
        + "\n[objects.twin]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n\
           [specs.twin]\nobject = \"twin\"\nattributes = { CKA_SIGN = true }\n\
           tokens.softhsm = { locator = { CKA_LABEL = \"invariants\" } }\n";
    e.config(&body);
    let verify = ["verify", "signing-soft", "--token", "softhsm"];
    assert_eq!(code(&e.km(&["realise", "signing-soft", "--token", "softhsm", "--update-lock"])), 0);
    let good = e.lock();
    assert_eq!(good["realisations"]["signing-soft"]["softhsm"]["schemes"].as_array().unwrap().len(), 1);
    // The same key under a second object name is refused when recording.
    assert_eq!(code(&e.km(&["realise", "twin", "--token", "softhsm", "--update-lock"])), 14);
    assert!(e.lock().get("objects").unwrap().get("twin").is_none());

    let write = |lock: &toml::Value| std::fs::write(e.dir.join("keys.lock"), toml::to_string(lock).unwrap()).unwrap();
    let edit = |f: &dyn Fn(&mut toml::Value)| {
        let mut lock = good.clone();
        f(&mut lock);
        write(&lock);
        code(&e.km(&verify))
    };
    assert_eq!(edit(&|l| l["objects"]["signing"]["ids"]["rfc7093m4"] = "sha256-AAAA".into()), 17);
    assert_eq!(edit(&|l| l["realisations"]["signing-soft"]["softhsm"]["specDigest"] = "abc".into()), 17);
    let set = |l: &mut toml::Value, k: &str, v: toml::Value| {
        l["objects"]["signing"].as_table_mut().unwrap().insert(k.into(), v);
    };
    assert_eq!(edit(&|l| set(l, "commitmentLabel", "".into())), 17);
    assert_eq!(edit(&|l| set(l, "pairs", toml::Value::Array(vec!["signing".into()]))), 17);
    assert_eq!(edit(&|l| set(l, "pairs", toml::Value::Array(vec!["in-another-fragment".into()]))), 0);
    assert_eq!(
        edit(&|l| {
            l["realisations"]["signing-soft"]["softhsm"].as_table_mut().unwrap().remove("binding");
        }),
        17,
        "a private key realisation must record its binding"
    );
    assert_eq!(
        edit(&|l| {
            let s = l["objects"]["signing"].clone();
            l["objects"].as_table_mut().unwrap().insert("twin".into(), s);
        }),
        17,
        "same material twice"
    );
    assert_eq!(edit(&|l| l["realisations"]["signing-soft"]["softhsm"]["schemes"] = toml::Value::Array(vec!["certhash".into()])), 17);
    // A scheme the realisation established but no longer computes: a downgrade.
    let valuehash = sri(b"recorded by an imaginary earlier version");
    assert_eq!(
        edit(&|l| {
            l["objects"]["signing"]["ids"].as_table_mut().unwrap().insert("valuehash".into(), valuehash.clone().into());
            l["realisations"]["signing-soft"]["softhsm"]["schemes"] =
                toml::Value::Array(vec!["rfc7093m4".into(), "valuehash".into()]);
        }),
        14
    );
    write(&good);
    assert_eq!(code(&e.km(&verify)), 0);
}

/// The lock records every boolean attribute the object shows (declared or not) and its creation
/// facts: a later change on the token is reviewed, and a replaced object is refused outright.
#[test]
fn policy_drift_and_replaced_objects_are_refused() {
    let Some(e) = env("policy") else { return };
    e.config(
        "[objects.k]\nclass = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_AES\"\nvalueLen = 32\n\n\
         [specs.k]\nobject = \"k\"\nattributes = { CKA_SIGN = true, CKA_SENSITIVE = false, CKA_EXTRACTABLE = true }\n\
         tokens.softhsm = { locator = { CKA_LABEL = \"policy\" }, autoCreate = true }\n",
    );
    let r = ["realise", "k", "--token", "softhsm", "--update-lock"];
    let verify = ["verify", "k", "--token", "softhsm"];
    let stderr = |o: &Output| String::from_utf8_lossy(&o.stderr).into_owned();
    assert_eq!(code(&e.km(&r)), 0);
    let real = &e.lock()["realisations"]["k"]["softhsm"];
    assert_eq!(real["policy"]["CKA_SIGN"].as_bool(), Some(true));
    assert!(real["policy"].get("CKA_ENCRYPT").is_some(), "undeclared attributes are recorded too");
    assert_eq!(real["immutables"]["CKA_LOCAL"].as_bool(), Some(true));
    assert_eq!(real["immutables"]["CKA_KEY_GEN_MECHANISM"].as_str(), Some("CKM_AES_KEY_GEN"));

    // An undeclared attribute changed on the token: a change to review, then re-record.
    let s = e.session();
    let find = || s.find_objects(&[Attribute::Class(ObjectClass::SECRET_KEY), Attribute::Label(b"policy".to_vec())]).unwrap()[0];
    let h = find();
    let encrypt = real["policy"]["CKA_ENCRYPT"].as_bool().unwrap();
    s.update_attributes(h, &[Attribute::Encrypt(!encrypt)]).unwrap();
    let o = e.km(&verify);
    assert_eq!(code(&o), 14);
    assert!(stderr(&o).contains(&format!("CKA_ENCRYPT {encrypt} -> {}", !encrypt)), "{}", stderr(&o));
    assert_eq!(code(&e.km(&r)), 0);
    assert_eq!(code(&e.km(&verify)), 0);

    // The same material re-imported: the IDs match, but it is no longer CKA_LOCAL.
    let value = match s.get_attributes(h, &[AttributeType::Value]).unwrap().remove(0) {
        Attribute::Value(v) => v,
        a => panic!("{a:?}"),
    };
    s.destroy_object(h).unwrap();
    s.create_object(&[
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(cryptoki::object::KeyType::AES),
        Attribute::Token(true),
        Attribute::Label(b"policy".to_vec()),
        Attribute::Value(value),
        Attribute::Sign(true),
        Attribute::Encrypt(!encrypt),
        Attribute::Sensitive(false),
        Attribute::Extractable(true),
    ])
    .unwrap();
    let o = e.km(&verify);
    assert_eq!(code(&o), 14);
    assert!(stderr(&o).contains("was replaced") && stderr(&o).contains("CKA_LOCAL"), "{}", stderr(&o));
    assert_eq!(code(&e.km(&r)), 14, "also when updating");
}

/// P2-10: `CKA_ALLOWED_MECHANISMS` and `publicAttributes` are set when generating, checked on
/// the object (and on the public half), and a mechanism list the spec no longer names is a
/// conflict like any other attribute mismatch.
#[test]
fn allowed_mechanisms_and_public_attributes() {
    let Some(e) = env("attrs") else { return };
    // The token is shared between runs: remove anything left under the test's locators.
    let s = e.session();
    for c in [ObjectClass::PRIVATE_KEY, ObjectClass::PUBLIC_KEY] {
        for h in s.find_objects(&[Attribute::Class(c), Attribute::Label(b"attrs".to_vec())]).unwrap() {
            s.destroy_object(h).unwrap();
        }
    }
    let spec = |mechs: &str, public: &str| {
        format!(
            "[objects.k]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n\
             [specs.k]\nobject = \"k\"\n\
             attributes = {{ CKA_SIGN = true, CKA_SENSITIVE = true, CKA_EXTRACTABLE = false, CKA_ALLOWED_MECHANISMS = [{mechs}] }}\n\
             publicAttributes = {{ {public} }}\n\
             tokens.softhsm = {{ locator = {{ CKA_LABEL = \"attrs\" }}, autoCreate = true }}\n"
        )
    };
    // A mechanism the token does not offer: refused before anything is created.
    e.config(&spec("\"CKM_BOGUS\"", "CKA_VERIFY = false"));
    assert_eq!(code(&e.km(&["realise", "k", "--token", "softhsm"])), 15);
    assert!(
        s.find_objects(&[Attribute::Label(b"attrs".to_vec())]).unwrap().is_empty(),
        "nothing was created"
    );

    // Created with the restriction; the public half honors publicAttributes (the default
    // CKA_VERIFY = true is left out where they override it).
    e.config(&spec("\"CKM_ECDSA\", \"CKM_ECDSA_SHA256\"", "CKA_VERIFY = false"));
    assert_eq!(code(&e.km(&["realise", "k", "--token", "softhsm", "--update-lock"])), 0);
    let digest = e.lock()["realisations"]["k"]["softhsm"]["specDigest"].as_str().unwrap().to_owned();
    let policy = &e.lock()["realisations"]["k"]["softhsm"]["policy"]["CKA_ALLOWED_MECHANISMS"];
    assert_eq!(policy.as_array().map(|a| a.len()), Some(2), "{policy}");
    assert_eq!(policy[0].as_str(), Some("CKM_ECDSA"), "{policy}");
    let public = s
        .find_objects(&[Attribute::Class(ObjectClass::PUBLIC_KEY), Attribute::Label(b"attrs".to_vec())])
        .unwrap()[0];
    let Attribute::Verify(verify) = &s.get_attributes(public, &[AttributeType::Verify]).unwrap()[0] else {
        panic!("no CKA_VERIFY on the public half")
    };
    assert!(!*verify, "publicAttributes = {{ CKA_VERIFY = false }}");
    assert_eq!(code(&e.km(&["verify", "k", "--token", "softhsm"])), 0);

    // The same set in another order is the same spec: same digest, no change to review.
    e.config(&spec("\"CKM_ECDSA_SHA256\", \"CKM_ECDSA\"", "CKA_VERIFY = false"));
    assert_eq!(code(&e.km(&["verify", "k", "--token", "softhsm"])), 0);
    assert_eq!(e.lock()["realisations"]["k"]["softhsm"]["specDigest"].as_str(), Some(digest.as_str()));

    // A different set does not satisfy the object: a conflict naming the attribute.
    e.config(&spec("\"CKM_ECDSA_SHA256\"", "CKA_VERIFY = false"));
    let o = e.km(&["verify", "k", "--token", "softhsm"]);
    assert_eq!(code(&o), 13);
    assert!(String::from_utf8_lossy(&o.stderr).contains("CKA_ALLOWED_MECHANISMS"));
    e.config(&spec("\"CKM_ECDSA\", \"CKM_ECDSA_SHA256\"", "CKA_VERIFY = false"));

    // A changed public half is a conflict; without it publicAttributes cannot be checked (11).
    s.update_attributes(public, &[Attribute::Verify(true)]).unwrap();
    assert_eq!(code(&e.km(&["verify", "k", "--token", "softhsm"])), 13);
    s.update_attributes(public, &[Attribute::Verify(false)]).unwrap();
    s.destroy_object(public).unwrap();
    assert_eq!(code(&e.km(&["verify", "k", "--token", "softhsm"])), 11);
}

/// P2-10: `CKA_ALLOWED_MECHANISMS` joins the observed policy vector. It is read-only once set
/// (PKCS#11 3.2 §4), so it cannot drift on the token; a lock recorded before cakeys observed it
/// still verifies, with a note, and `realise --update-lock` records it.
#[test]
fn an_undeclared_mechanism_list_is_observed_policy() {
    let Some(e) = env("attrs-drift") else { return };
    let s = e.session();
    // The token is shared between runs: remove anything left under the test's locators.
    for c in [ObjectClass::PRIVATE_KEY, ObjectClass::PUBLIC_KEY] {
        for h in s.find_objects(&[Attribute::Class(c), Attribute::Label(b"attrs-drift".to_vec())]).unwrap() {
            s.destroy_object(h).unwrap();
        }
    }
    let ec_params = vec![0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
    let common = [
        Attribute::Token(true),
        Attribute::Label(b"attrs-drift".to_vec()),
        Attribute::AllowedMechanisms(vec![MechanismType::ECDSA, MechanismType::ECDSA_SHA256]),
    ];
    s.generate_key_pair(
        &Mechanism::EccKeyPairGen,
        &[&common[..], &[Attribute::EcParams(ec_params.clone())]].concat(),
        &[&common[..], &[Attribute::Sign(true), Attribute::Sensitive(true), Attribute::Extractable(false)]].concat(),
    )
    .unwrap();
    e.config(
        "[objects.k]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n\
         [specs.k]\nobject = \"k\"\nattributes = { CKA_SIGN = true, CKA_SENSITIVE = true, CKA_EXTRACTABLE = false }\n\
         tokens.softhsm = { locator = { CKA_LABEL = \"attrs-drift\" } }\n",
    );
    assert_eq!(code(&e.km(&["realise", "k", "--token", "softhsm", "--update-lock"])), 0);
    let policy = &e.lock()["realisations"]["k"]["softhsm"]["policy"];
    assert_eq!(policy.get("CKA_ALLOWED_MECHANISMS").map(|m| m.as_array().unwrap().len()), Some(2), "{policy}");

    // A lock that does not record the list (e.g. written by an older cakeys) still verifies.
    let path = e.dir.join("keys.lock");
    let text = std::fs::read_to_string(&path)
        .unwrap()
        .replace("CKA_ALLOWED_MECHANISMS = [\n    \"CKM_ECDSA\",\n    \"CKM_ECDSA_SHA256\",\n]\n", "");
    std::fs::write(&path, text).unwrap();
    let o = e.km(&["verify", "k", "--token", "softhsm"]);
    assert_eq!(code(&o), 0);
    assert!(String::from_utf8_lossy(&o.stderr).contains("CKA_ALLOWED_MECHANISMS"), "{}", String::from_utf8_lossy(&o.stderr));
    assert_eq!(code(&e.km(&["realise", "k", "--token", "softhsm", "--update-lock"])), 0);
    assert_eq!(code(&e.km(&["verify", "k", "--token", "softhsm"])), 0);
}

/// P2-10: declared attribute names must fit the class (PKCS#11 3.2 §4), the extra booleans are
/// settable, and the new refusals apply: `CKA_ALWAYS_AUTHENTICATE = true` cannot prove possession,
/// and `CKA_TRUSTED = true` cannot be generated.
#[test]
fn attributes_are_validated_per_class() {
    let Some(e) = env("attr-class") else { return };
    for (object, attrs) in [
        (
            "certificateType = \"CKC_X_509\"\nclass = \"CKO_CERTIFICATE\"",
            "attributes = { CKA_SIGN = true }",
        ),
        (
            "class = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"",
            "attributes = { CKA_TRUSTED = true }",
        ),
        (
            "class = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"",
            "publicAttributes = { CKA_ALWAYS_AUTHENTICATE = true }",
        ),
        (
            "class = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_AES\"\nvalueLen = 32",
            "attributes = { CKA_ALWAYS_AUTHENTICATE = true }",
        ),
        (
            "class = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"",
            "attributes = { CKA_SIGN = [\"CKM_ECDSA\"] }",
        ),
    ] {
        e.config(&format!(
            "[objects.o]\n{object}\n\n[specs.s]\nobject = \"o\"\n{attrs}\n\
             tokens.softhsm = {{ locator = {{ CKA_LABEL = \"x\" }} }}\n"
        ));
        let o = e.km(&["validate"]);
        assert_eq!(code(&o), 17, "{attrs}: {}", String::from_utf8_lossy(&o.stderr));
    }

    // Proving possession with CKA_ALWAYS_AUTHENTICATE would spend a PIN entry per run.
    e.config(
        "[objects.o]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n\
         [specs.s]\nobject = \"o\"\nattributes = { CKA_SIGN = true, CKA_ALWAYS_AUTHENTICATE = true }\n\
         tokens.softhsm = { locator = { CKA_LABEL = \"x\" } }\n",
    );
    assert_eq!(code(&e.km(&["validate"])), 17);

    // CKA_TRUSTED is set by the token's security officer, never by generation.
    e.config(
        "[objects.o]\nclass = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_AES\"\nvalueLen = 32\n\n\
         [specs.s]\nobject = \"o\"\nattributes = { CKA_TRUSTED = true }\n\
         tokens.softhsm = { locator = { CKA_LABEL = \"trusted\" }, autoCreate = true }\n",
    );
    assert_eq!(code(&e.km(&["validate"])), 17);

    // The extra booleans are settable: the key is created with them, the policy records them, and
    // binding = "token-asserted" replaces the impossible proof of possession.
    let s = e.session();
    // The token is shared between runs: remove anything left under the test's locator.
    for h in s.find_objects(&[Attribute::Label(b"always-auth".to_vec())]).unwrap() {
        s.destroy_object(h).unwrap();
    }
    e.config(
        "[objects.o]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n\
         [specs.s]\nobject = \"o\"\n\
         attributes = { CKA_SIGN = true, CKA_ALWAYS_AUTHENTICATE = true, CKA_DESTROYABLE = true }\n\
         tokens.softhsm = { locator = { CKA_LABEL = \"always-auth\" }, autoCreate = true, binding = \"token-asserted\" }\n",
    );
    assert_eq!(code(&e.km(&["realise", "s", "--token", "softhsm", "--update-lock"])), 0);
    let policy = &e.lock()["realisations"]["s"]["softhsm"]["policy"];
    assert_eq!(policy["CKA_ALWAYS_AUTHENTICATE"].as_bool(), Some(true), "{policy}");
    let private = s
        .find_objects(&[Attribute::Class(ObjectClass::PRIVATE_KEY), Attribute::Label(b"always-auth".to_vec())])
        .unwrap()[0];
    let Attribute::AlwaysAuthenticate(aa) = &s.get_attributes(private, &[AttributeType::AlwaysAuthenticate]).unwrap()[0]
    else {
        panic!("no CKA_ALWAYS_AUTHENTICATE on the private half")
    };
    assert!(*aa, "the template set CKA_ALWAYS_AUTHENTICATE");
    assert_eq!(code(&e.km(&["verify", "s", "--token", "softhsm"])), 0);
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
        // No Ed448 verifier on the host: possession cannot be proven, so it is an explicit opt-in.
        let binding = if k == "ed448" { ", binding = \"token-asserted\"" } else { "" };
        body += &format!(
            "[objects.{k}]\nclass = \"CKO_PRIVATE_KEY\"\n{ty}\n\n\
             [specs.{k}-gen]\nobject = \"{k}\"\n\
             attributes = {{ CKA_SIGN = true, CKA_SENSITIVE = true, CKA_EXTRACTABLE = false }}\n\
             tokens.softhsm = {{ locator = {{ CKA_LABEL = \"{k}\" }}, autoCreate = true{binding} }}\n\n\
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
        assert_eq!(e.locked_id(k, "rfc7093m4"), sri(&oracle_spki(&s, k)), "{k}");
        let binding = if k == "ed448" { "token-asserted" } else { "pop-sign" };
        assert_eq!(e.lock()["realisations"][&gen]["softhsm"]["binding"].as_str(), Some(binding), "{k}");
        // A fresh challenge each run: repeat to catch encoding quirks (high-S, short r or s).
        for _ in 0..8 {
            assert_eq!(code(&e.km(&["verify", &gen, "--token", "softhsm"])), 0, "{k}");
        }
        // Same identity through the public key object, without login.
        let pubs = format!("{k}-pub");
        assert_eq!(code(&e.km(&["realise", &pubs, "--token", "softhsm-anon", "--update-lock"])), 0, "{k}");
        assert_eq!(e.lock()["realisations"][&pubs]["softhsm-anon"]["binding"].as_str(), Some("token-asserted"), "{k}");
    }
    // Without the opt-in, an Ed448 key is refused up front.
    e.config(&body.replace(", binding = \"token-asserted\"", ""));
    assert_eq!(code(&e.km(&["validate"])), 17);
    e.config(&body);
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
    for (k, _, _, _, certhash, rfc7093m4) in fixtures {
        assert_eq!(code(&e.km(&["realise", k, "--token", "softhsm-anon", "--update-lock"])), 0, "{k}");
        let cert = format!("{k}-cert");
        assert_eq!(code(&e.km(&["realise", &cert, "--token", "softhsm-anon", "--update-lock"])), 0, "{k}");
        assert_eq!(e.locked_id(k, "rfc7093m4"), rfc7093m4, "{k}");
        assert_eq!(e.locked_id(&cert, "certhash"), certhash, "{k}");
        assert_eq!(e.locked_id(&cert, "rfc7093m4"), rfc7093m4, "{k}: cert links to its key");
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
    assert_eq!(code(&e.km(&["realise", "u", "--token", "softhsm", "--update-lock"])), 0);
    // A lock written by a version that only knew cmac.
    e.write_lock_keeping_realisations(&format!(
        "version = 1\n[objects.u]\ncommitmentLabel = \"key-management/v1\"\n\
         [objects.u.type]\nclass = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_AES\"\nvalueLen = 32\n[objects.u.ids]\ncmac = \"{}\"\n",
        aes_commitment(&key, "cmac")
    ));
    let mut old = e.lock();
    old["realisations"]["u"]["softhsm"]["schemes"] = toml::Value::Array(vec!["cmac".into()]);
    std::fs::write(e.dir.join("keys.lock"), toml::to_string(&old).unwrap()).unwrap();
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
    assert_eq!(e.locked_id("anchor", "rfc7093m4"), P384_PUBKEYHASH, "matches openssl over the certificate's key");
    assert!(stdout(&e.km(&["verify", "anchor", "--token", "softhsm-anon"])).ends_with("object=standalone-pub;type=public"));
    assert_eq!(code(&e.km(&["check", "anchor.id.rfc7093m4", "--token", "softhsm-anon"])), 0);
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
         [specs.k]\nobject = \"k\"\nattributes = { CKA_SIGN = true }\ntokens.softhsm = { locator = { CKA_LABEL = \"bp512\" }, autoCreate = true }\n",
    );
    let o = e.km(&["validate"]);
    assert_eq!(code(&o), 15);
    assert!(String::from_utf8_lossy(&o.stderr).contains("no RustCrypto crate"));
}

/// H1 (docs/REVIEW-2026-11-11.md): SoftHSM EC private keys expose no public key, so their
/// identity is read from the public key object under the same locator. Replace the private key,
/// keep the public object: the proof of possession fails, a conflict.
#[test]
fn h1_a_private_key_beside_an_unbound_public_object_is_a_conflict() {
    let Some(e) = env("gap_h1") else { return };
    e.config(EC.replace("ec-lifecycle", "gap-a").as_str());
    assert_eq!(code(&e.km(&["realise", "signing-soft", "--token", "softhsm", "--update-lock"])), 0);
    assert_eq!(e.lock()["realisations"]["signing-soft"]["softhsm"]["binding"].as_str(), Some("pop-sign"));
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
    // Different private key under the locator, same public object.
    let verify = e.km(&["verify", "signing-soft", "--token", "softhsm"]);
    assert_eq!(code(&verify), 13);
    assert!(String::from_utf8_lossy(&verify.stderr).contains("proof of possession failed"));
    // So is deleting: If-Match must not pass on the public object alone.
    assert_eq!(code(&e.km(&["delete", "signing-soft", "--token", "softhsm"])), 13);
}

/// A recorded proof of possession cannot silently become a token assertion.
#[test]
fn binding_downgrade_is_refused() {
    let Some(e) = env("binding") else { return };
    let body = EC.replace("ec-lifecycle", "binding");
    e.config(&body);
    assert_eq!(code(&e.km(&["realise", "signing-soft", "--token", "softhsm", "--update-lock"])), 0);
    let opted_out = body.replace("autoCreate = true", "autoCreate = true, binding = \"token-asserted\"");
    assert_ne!(opted_out, body);
    e.config(&opted_out);
    assert_eq!(code(&e.km(&["verify", "signing-soft", "--token", "softhsm"])), 14);
    assert_eq!(code(&e.km(&["realise", "signing-soft", "--token", "softhsm", "--update-lock"])), 14);
    // Without CKA_SIGN and without the opt-in, the spec is invalid.
    e.config(&body.replace("CKA_SIGN = true", "CKA_SIGN = false"));
    assert_eq!(code(&e.km(&["validate"])), 17);
}

/// P0-1: keys that cannot sign still prove possession. `pop-ecdh` derives the shared secret into
/// a non-extractable session key and MACs the challenge on both sides; `pop-decrypt` has the token
/// RSA-OAEP-decrypt the challenge. A different private key under the locator fails either proof.
#[test]
fn derive_and_decrypt_only_keys_prove_possession() {
    let Some(e) = env("pop-ecdh") else { return };
    // The token is shared between runs: remove anything left under the test's locators. A session
    // opened now sees the leftovers (they predate it); it is dropped before the realise runs.
    let cleanup = e.session();
    for label in ["pop-ecdh", "pop-oaep", "pop-ecdh-b"] {
        for h in cleanup.find_objects(&[Attribute::Label(label.as_bytes().to_vec())]).unwrap() {
            cleanup.destroy_object(h).unwrap();
        }
    }
    drop(cleanup);
    // Shapes: each proof needs its capability declared, and applies to its key type only.
    let ec = "[objects.k]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n\
              [specs.k]\nobject = \"k\"\nattributes = { CKA_DERIVE = true, CKA_SENSITIVE = true, CKA_EXTRACTABLE = false }\n";
    let rsa = "[objects.r]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_RSA\"\nmodulusBits = 2048\n\n\
               [specs.r]\nobject = \"r\"\nattributes = { CKA_DECRYPT = true, CKA_SENSITIVE = true, CKA_EXTRACTABLE = false }\n";
    for (body, token) in [
        (&ec[..], "binding = \"pop-decrypt\""),                      // RSA proof on an EC key
        (ec.replace("CKA_DERIVE = true, ", "").as_str(), "binding = \"pop-ecdh\""), // ... without CKA_DERIVE
        (&rsa[..], "binding = \"pop-ecdh\""),                       // EC proof on an RSA key
        (rsa.replace("CKA_DECRYPT = true, ", "").as_str(), "binding = \"pop-decrypt\""), // ... without CKA_DECRYPT
    ] {
        e.config(&format!(
            "{body}tokens.softhsm = {{ locator = {{ CKA_LABEL = \"x\" }}, {token} }}\n"
        ));
        let o = e.km(&["validate"]);
        assert_eq!(code(&o), 17, "{token}: {}", String::from_utf8_lossy(&o.stderr));
    }
    // The default proof (pop-sign) still needs CKA_SIGN.
    e.config(&format!("{ec}tokens.softhsm = {{ locator = {{ CKA_LABEL = \"x\" }} }}\n"));
    assert_eq!(code(&e.km(&["validate"])), 17);

    // Derive-only EC key, proven by deriving: created, recorded as pop-ecdh, verifies.
    e.config(&format!(
        "{ec}tokens.softhsm = {{ locator = {{ CKA_LABEL = \"pop-ecdh\" }}, autoCreate = true, binding = \"pop-ecdh\" }}\n"
    ));
    assert_eq!(code(&e.km(&["realise", "k", "--token", "softhsm", "--update-lock"])), 0);
    let real = &e.lock()["realisations"]["k"]["softhsm"];
    assert_eq!(real["binding"].as_str(), Some("pop-ecdh"));
    assert_eq!(code(&e.km(&["verify", "k", "--token", "softhsm"])), 0);
    assert!(e.lock()["objects"]["k"]["ids"].get("rfc7093m4").is_some(), "the object id was recorded");

    // Decrypt-only RSA key, proven by decrypting (OAEP-SHA256).
    e.config(&format!(
        "{rsa}tokens.softhsm = {{ locator = {{ CKA_LABEL = \"pop-oaep\" }}, autoCreate = true, binding = \"pop-decrypt\" }}\n"
    ));
    assert_eq!(code(&e.km(&["realise", "r", "--token", "softhsm", "--update-lock"])), 0);
    assert_eq!(e.lock()["realisations"]["r"]["softhsm"]["binding"].as_str(), Some("pop-decrypt"));
    assert_eq!(code(&e.km(&["verify", "r", "--token", "softhsm"])), 0);

    // Back to the EC spec for the conflict phase.
    e.config(&format!(
        "{ec}tokens.softhsm = {{ locator = {{ CKA_LABEL = \"pop-ecdh\" }}, binding = \"pop-ecdh\" }}\n"
    ));

    // A different private key under the EC locator fails the derivation proof, like H1. A fresh
    // session: one opened before the realise processes does not see objects they created
    // (common/mod.rs), but everything is visible to a session opened after them.
    let s = e.session();
    let ec_params = vec![0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
    let (_, other_private) = s
        .generate_key_pair(
            &Mechanism::EccKeyPairGen,
            &[Attribute::Token(true), Attribute::Label(b"pop-ecdh-b".to_vec()), Attribute::EcParams(ec_params)],
            &[
                Attribute::Token(true),
                Attribute::Label(b"pop-ecdh-b".to_vec()),
                Attribute::Derive(true),
                Attribute::Sensitive(true),
                Attribute::Extractable(false),
            ],
        )
        .unwrap();
    let original = s
        .find_objects(&[Attribute::Class(ObjectClass::PRIVATE_KEY), Attribute::Label(b"pop-ecdh".to_vec())])
        .unwrap()[0];
    s.destroy_object(original).unwrap();
    s.update_attributes(other_private, &[Attribute::Label(b"pop-ecdh".to_vec())]).unwrap();
    let o = e.km(&["verify", "k", "--token", "softhsm"]);
    assert_eq!(code(&o), 13);
    assert!(String::from_utf8_lossy(&o.stderr).contains("proof of possession failed"), "{}", String::from_utf8_lossy(&o.stderr));
    assert_eq!(code(&e.km(&["realise", "k", "--token", "softhsm"])), 13);
}


#[test]
fn commitment_label_comes_from_the_lock() {
    let Some(e) = env("label") else { return };
    let value = *b"commitment label test vector 32B";
    plant_secret(&e.session(), "label-mac", cryptoki::object::KeyType::GENERIC_SECRET, &value, &[Attribute::Sign(true)]);
    e.config(
        "[objects.m]\nclass = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_GENERIC_SECRET\"\nvalueLen = 32\n\n\
         [specs.m]\nobject = \"m\"\nattributes = { CKA_SIGN = true }\n\
         tokens.softhsm = { locator = { CKA_LABEL = \"label-mac\" } }\n",
    );
    let hmac = |label: &str| {
        let mut m = <Hmac<sha2::Sha256> as KeyInit>::new_from_slice(&value).unwrap();
        m.update(format!("{label}/commitment/CKK_GENERIC_SECRET/256").as_bytes());
        sri(&m.finalize().into_bytes())
    };
    let path = e.dir.join("keys.lock");
    let lock = |text: String| e.write_lock_keeping_realisations(&text.replace("{M_TYPE}", M_TYPE));
    let verify = ["verify", "m", "--token", "softhsm"];

    // A new object gets the default label, and the lock records it.
    assert_eq!(code(&e.km(&["realise", "m", "--token", "softhsm", "--update-lock"])), 0);
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.starts_with("version = 1"), "{text}");
    assert!(text.contains("commitmentLabel = \"key-management/v1\""), "{text}");
    assert_eq!(e.locked_id("m", "commitment"), hmac("key-management/v1"));

    // Another label in the lock is the one used (not the code default)...
    let custom = "example.org/keys/v1";
    lock(format!("version = 1\n[objects.m]\ncommitmentLabel = \"{custom}\"\n{{M_TYPE}}[objects.m.ids]\ncommitment = \"{}\"\n", hmac(custom)));
    assert_eq!(code(&e.km(&verify)), 0);
    // ...so a hash made with any other label does not match it.
    lock(format!("version = 1\n[objects.m]\ncommitmentLabel = \"{custom}\"\n{{M_TYPE}}[objects.m.ids]\ncommitment = \"{}\"\n", hmac("key-management/v1")));
    assert_eq!(code(&e.km(&verify)), 10);

    // Commitment IDs require the label; other lock versions are refused.
    lock(format!("version = 1\n{{M_TYPE}}[objects.m.ids]\ncommitment = \"{}\"\n", hmac("key-management/v1")));
    assert_eq!(code(&e.km(&verify)), 17);
    lock("version = 2\n".into());
    assert_eq!(code(&e.km(&verify)), 17);
}


const M_TYPE: &str = "[objects.m.type]\nclass = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_GENERIC_SECRET\"\nvalueLen = 32\n";

#[test]
fn the_lock_pins_type_spec_provenance_and_schemes() {
    let Some(e) = env("pins") else { return };
    e.config(EC.replace("ec-lifecycle", "pins").as_str());
    let toml = e.dir.join("keys.toml");
    let path = e.dir.join("keys.lock");
    let config = std::fs::read_to_string(&toml).unwrap();
    let r = ["realise", "signing-soft", "--token", "softhsm", "--update-lock"];
    let verify = ["verify", "signing-soft", "--token", "softhsm"];
    let stderr = |o: &Output| String::from_utf8_lossy(&o.stderr).into_owned();
    assert_eq!(code(&e.km(&r)), 0);
    let locked = std::fs::read_to_string(&path).unwrap();
    let lock: toml::Value = toml::from_str(&locked).unwrap();
    assert_eq!(lock["objects"]["signing"]["type"]["curve"].as_str(), Some("secp256r1"));
    let real = &lock["realisations"]["signing-soft"]["softhsm"];
    assert_eq!(real["provenance"]["provider"].as_str(), Some("softhsm"));
    assert!(real["provenance"]["cakeysVersion"].as_str().is_some_and(|v| !v.is_empty()));

    // 1. A curve alias is the same object type: keys.toml and the lock canonicalize it, so
    //    nothing changed and nothing needs re-recording.
    std::fs::write(&toml, config.replace("curve = \"secp256r1\"", "curve = \"P-256\"")).unwrap();
    assert_eq!(code(&e.km(&verify)), 0);
    assert_eq!(code(&e.km(&r)), 0);
    std::fs::write(&toml, &config).unwrap();

    // 2. A changed spec (still satisfied by the token) needs the lock re-recorded.
    std::fs::write(&toml, config.replace("CKA_EXTRACTABLE = false }", "CKA_EXTRACTABLE = false, CKA_PRIVATE = true }")).unwrap();
    let o = e.km(&verify);
    assert_eq!(code(&o), 14);
    assert!(stderr(&o).contains("spec 'signing-soft' changed in keys.toml"), "{}", stderr(&o));
    assert_eq!(code(&e.km(&r)), 0);
    assert_eq!(code(&e.km(&verify)), 0);
    std::fs::write(&toml, &config).unwrap();
    assert_eq!(code(&e.km(&r)), 0);
    let locked = std::fs::read_to_string(&path).unwrap();

    // 3. Provenance: another provider warns, another cakeys version is a note.
    std::fs::write(&path, locked.replace("provider = \"softhsm\"", "provider = \"other\"")).unwrap();
    let o = e.km(&verify);
    assert_eq!(code(&o), 0);
    assert!(stderr(&o).contains("warning:") && stderr(&o).contains("provider other"), "{}", stderr(&o));
    let version = real["provenance"]["cakeysVersion"].as_str().unwrap();
    std::fs::write(&path, locked.replace(&format!("cakeysVersion = \"{version}\""), "cakeysVersion = \"0.0.0\"")).unwrap();
    let o = e.km(&verify);
    assert_eq!(code(&o), 0);
    assert!(stderr(&o).contains("note:") && stderr(&o).contains("cakeys 0.0.0") && !stderr(&o).contains("warning:"), "{}", stderr(&o));

    // 4. A scheme this cakeys does not know is reported by name, not silently skipped.
    std::fs::write(&path, locked.replace("[objects.signing.ids]\n", "[objects.signing.ids]\nfuturehash = \"sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=\"\n")).unwrap();
    let o = e.km(&verify);
    assert_eq!(code(&o), 0);
    assert!(stderr(&o).contains("futurehash") && stderr(&o).contains("does not know"), "{}", stderr(&o));

    // The alias is input-only: a lock recording `pubkeyhash` is refused with a rename hint.
    std::fs::write(&path, locked.replace("rfc7093m4 = ", "pubkeyhash = ")).unwrap();
    let o = e.km(&verify);
    assert_eq!(code(&o), 17);
    assert!(stderr(&o).contains("the lock uses 'rfc7093m4'"), "{}", stderr(&o));

    // IDs without a type are an incomplete lock.
    let lock_without_type = locked
        .lines()
        .filter(|l| !["[objects.signing.type]", "class = \"CKO_PRIVATE_KEY\"", "keyType = \"CKK_EC\"", "curve = \"secp256r1\""].contains(l))
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(&path, lock_without_type).unwrap();
    assert_eq!(code(&e.km(&verify)), 17);
}

/// H1b (report "Cakeys lock file design review"): SoftHSM lets a user set CKA_PUBLIC_KEY_INFO on a
/// private key without checking it. cakeys reads the key material first and only cross-checks the
/// asserted SPKI, so a different RSA private key carrying the old SPKI is a conflict.
#[test]
fn h1b_a_forged_public_key_info_is_a_conflict() {
    let Some(e) = env("gap_h1b") else { return };
    e.config(
        "[objects.r]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_RSA\"\nmodulusBits = 2048\n\n\
         [specs.r]\nobject = \"r\"\nattributes = { CKA_SIGN = true }\n\
         tokens.softhsm = { locator = { CKA_LABEL = \"h1b\" }, autoCreate = true }\n",
    );
    assert_eq!(code(&e.km(&["realise", "r", "--token", "softhsm", "--update-lock"])), 0);
    let s = e.session();
    let spki_a = oracle_spki(&s, "h1b");
    let (_, other) = s
        .generate_key_pair(
            &Mechanism::RsaPkcsKeyPairGen,
            &[Attribute::Token(true), Attribute::Label(b"h1b-other".to_vec()), Attribute::ModulusBits(2048.into()), Attribute::PublicExponent(vec![1, 0, 1])],
            &[Attribute::Token(true), Attribute::Label(b"h1b-other".to_vec()), Attribute::Sign(true)],
        )
        .unwrap();
    let original = s.find_objects(&[Attribute::Class(ObjectClass::PRIVATE_KEY), Attribute::Label(b"h1b".to_vec())]).unwrap()[0];
    s.destroy_object(original).unwrap();
    s.update_attributes(other, &[Attribute::Label(b"h1b".to_vec()), Attribute::PublicKeyInfo(spki_a)]).unwrap();
    drop(s);
    let o = e.km(&["verify", "r", "--token", "softhsm"]);
    assert_eq!(code(&o), 13);
    assert!(String::from_utf8_lossy(&o.stderr).contains("disagrees with the key material"));
}

/// S3: a (spec, token) pair the lock has never recorded does not verify on object IDs alone.
#[test]
fn s3_an_unrecorded_token_is_a_precondition_failure() {
    let Some(e) = env("gap_s3") else { return };
    let pin = e.dir.join("pin");
    e.config(&format!(
        "[tokens.softhsm-b]\nmodule = \"{}\"\ntokenLabel = \"kmtest\"\npinFile = \"{}\"\n\n{}\
         tokens.softhsm-b = {{ locator = {{ CKA_LABEL = \"s3\" }} }}\n",
        e.module,
        pin.display(),
        EC.replace("ec-lifecycle", "s3")
    ));
    assert_eq!(code(&e.km(&["realise", "signing-soft", "--token", "softhsm", "--update-lock"])), 0);
    let verify = ["verify", "signing-soft", "--token", "softhsm-b"];
    assert_eq!(code(&e.km(&verify)), 14);
    assert_eq!(code(&e.km(&["realise", "signing-soft", "--token", "softhsm-b", "--update-lock"])), 0);
    assert_eq!(code(&e.km(&verify)), 0);
}

/// S4: turning publicOnly on is a change to keys.toml, also for a spec without attributes.
#[test]
fn s4_a_public_only_flip_is_a_spec_change() {
    let Some(e) = env("gap_s4") else { return };
    let body = "[objects.k]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n\
                [specs.k]\nobject = \"k\"\ntokens.softhsm = { locator = { CKA_LABEL = \"s4\" }, autoCreate = true, binding = \"token-asserted\" }\n";
    e.config(body);
    assert_eq!(code(&e.km(&["realise", "k", "--token", "softhsm", "--update-lock"])), 0);
    e.config(&body.replace("autoCreate = true", "publicOnly = true"));
    let verify = e.km(&["verify", "k", "--token", "softhsm"]);
    assert_eq!(code(&verify), 14);
    assert!(String::from_utf8_lossy(&verify.stderr).contains("publicOnly false -> true"));
}

/// S8: pointing a spec at another object, or another locator, is reported as a keys.toml change
/// (exit 14), not as an unexplained hash mismatch.
#[test]
fn s8_a_retargeted_spec_is_a_spec_change() {
    let Some(e) = env("gap_s8") else { return };
    let body = "[objects.a]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n\
                [objects.b]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n\
                [specs.sa]\nobject = \"a\"\nattributes = { CKA_SIGN = true }\ntokens.softhsm = { locator = { CKA_LABEL = \"s8-a\" }, autoCreate = true }\n\n\
                [specs.sb]\nobject = \"b\"\nattributes = { CKA_SIGN = true }\ntokens.softhsm = { locator = { CKA_LABEL = \"s8-b\" }, autoCreate = true }\n";
    e.config(body);
    assert_eq!(code(&e.km(&["realise", "sa", "--token", "softhsm", "--update-lock"])), 0);
    assert_eq!(code(&e.km(&["realise", "sb", "--token", "softhsm", "--update-lock"])), 0);
    let lock = e.lock();
    assert_eq!(lock["realisations"]["sa"]["softhsm"]["object"].as_str(), Some("a"));
    assert_eq!(lock["realisations"]["sa"]["softhsm"]["locator"]["CKA_LABEL"].as_str(), Some("s8-a"));
    e.config(&body.replace("[specs.sa]\nobject = \"a\"", "[specs.sa]\nobject = \"b\""));
    let verify = e.km(&["verify", "sa", "--token", "softhsm"]);
    assert_eq!(code(&verify), 14);
    assert!(String::from_utf8_lossy(&verify.stderr).contains("object 'a' -> 'b'"));
    // The same object under another locator: also a change to review.
    e.config(&body.replace("CKA_LABEL = \"s8-a\"", "CKA_LABEL = \"s8-b\""));
    assert_eq!(code(&e.km(&["verify", "sa", "--token", "softhsm"])), 14);
}
