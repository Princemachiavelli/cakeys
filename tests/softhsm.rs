//! End-to-end tests of the CLI against a SoftHSM token.
//!
//! Needs `SOFTHSM2_CONF` and `KM_TEST_MODULE` (path to libsofthsm2.so) with an initialised token
//! labelled `kmtest`, user PIN `1234` (the Nix build's preCheck sets this up). Tests are skipped
//! when `KM_TEST_MODULE` is unset, unless `KM_TEST_REQUIRE=1`.

use cryptoki::context::{CInitializeArgs, Pkcs11};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, ObjectClass};
use cryptoki::session::{Session, UserType};
use cryptoki::types::AuthPin;
use hmac::{Hmac, Mac};
use std::path::PathBuf;
use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_key-mgmnt");

struct Env {
    dir: PathBuf,
    module: String,
}

fn env(name: &str) -> Option<Env> {
    let Ok(module) = std::env::var("KM_TEST_MODULE") else {
        assert!(std::env::var("KM_TEST_REQUIRE").is_err(), "KM_TEST_MODULE is required");
        eprintln!("skipping {name}: KM_TEST_MODULE not set");
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
        let out = Command::new(BIN)
            .arg("--config")
            .arg(self.dir.join("keys.toml"))
            .args(args)
            .output()
            .unwrap();
        eprintln!(
            "$ key-mgmnt {}\n  exit={:?}\n  stdout={}\n  stderr={}",
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

fn code(o: &Output) -> i32 {
    o.status.code().unwrap()
}

fn got_hash(o: &Output) -> String {
    let err = String::from_utf8_lossy(&o.stderr);
    let line = err.lines().find(|l| l.trim_start().starts_with("got:")).expect("no got: line");
    line.split_whitespace().last().unwrap().to_owned()
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).trim().to_owned()
}

fn sri(bytes: &[u8]) -> String {
    use base64::Engine;
    use sha2::Digest;
    format!("sha256-{}", base64::engine::general_purpose::STANDARD.encode(sha2::Sha256::digest(bytes)))
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

[objects.kek]
class = "CKO_SECRET_KEY"
keyType = "CKK_AES"
valueLen = 32

[specs.kek-wrap]
object = "kek"
attributes = { CKA_SIGN = false, CKA_WRAP = true, CKA_SENSITIVE = false, CKA_EXTRACTABLE = true }
tokens.softhsm = { locator = { CKA_LABEL = "oracle-wrap-rebind" }, autoCreate = true }
"#,
    );
    for (spec, object, label, key_type, mode) in [
        ("mac-sign", "mac", "oracle-commitment", "CKK_GENERIC_SECRET", "commitment"),
        ("kek-wrap", "kek", "oracle-wrap-rebind", "CKK_AES", "wrap-rebind"),
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

/// Token object template for the fixture certificate (SoftHSM requires CKA_SUBJECT).
fn cert_object(label: &[u8], id: Option<u8>) -> Vec<Attribute> {
    let der = include_bytes!("fixtures/adopt-cert.der").to_vec();
    let cert = <x509_cert::Certificate as x509_cert::der::Decode>::from_der(&der).unwrap();
    let subject = x509_cert::der::Encode::to_der(&cert.tbs_certificate.subject).unwrap();
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
    let der = include_bytes!("fixtures/adopt-cert.der").to_vec();
    let cert = <x509_cert::Certificate as x509_cert::der::Decode>::from_der(&der).unwrap();
    let spki = x509_cert::der::Encode::to_der(&cert.tbs_certificate.subject_public_key_info).unwrap();
    let rsa = <rsa::RsaPublicKey as rsa::pkcs8::DecodePublicKey>::from_public_key_der(&spki).unwrap();
    use rsa::traits::PublicKeyParts;
    let s = e.session();
    s.create_object(&cert_object(b"adopt-cert", Some(0x42))).unwrap();
    s.create_object(&[
        Attribute::Class(ObjectClass::PUBLIC_KEY),
        Attribute::KeyType(cryptoki::object::KeyType::RSA),
        Attribute::Token(true),
        Attribute::Label(b"adopt-key".to_vec()),
        Attribute::Id(vec![0x42]),
        Attribute::Modulus(rsa.n().to_bytes_be()),
        Attribute::PublicExponent(rsa.e().to_bytes_be()),
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
    s.create_object(&cert_object(b"occupied", None)).unwrap();
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
