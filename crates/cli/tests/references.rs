//! Cross-reference tests: the same material on every reference token has the same identity, and
//! the same scenario gets the same verdict. The references are `SoftHSM`, kryoptic (twice: raw
//! and DER Edwards points), `SoftHSM` behind p11-kit forwarding, and tpm2-pkcs11 for the
//! material `tpm2_ptool` can import.
//!
//! A reference takes part when its suite's variables are set (`CAKEYS_TEST_MODULE`,
//! `CAKEYS_KRYOPTIC_MODULE`, `CAKEYS_P11KIT_CLIENT`, `CAKEYS_TPM_MODULE`, with the environment
//! those suites' headers describe); a set `*_REQUIRE` makes a missing one a failure. Skipped
//! with fewer than two references.

mod common;

use common::*;
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass};
use cryptoki::session::Session;
use std::collections::BTreeMap;
use std::fmt::Write;
use std::path::PathBuf;
use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_cakeys");
const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");
const ADOPT_CERT: &[u8] = include_bytes!("fixtures/adopt-cert.der");
const AES_VALUE: &[u8; 32] = b"cakeys cross-reference aes key!!";
const SECRET_VALUE: &[u8; 32] = b"cakeys cross-reference secret!!!";
const HMAC_VALUE: &[u8; 32] = b"cakeys cross-reference hmac key!";
const DATA_VALUE: &[u8] = b"cakeys cross-reference data object";

/// How a reference gets the material.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Plant {
    /// `C_CreateObject` through the module.
    Create,
    /// `tpm2_ptool import` (tpm2-pkcs11 creates no keys from values).
    Ptool,
    /// The token of the reference before it, through another configuration.
    Shared,
}

struct Ref {
    /// The token's name in keys.toml.
    name: &'static str,
    module: String,
    token_label: &'static str,
    /// Environment of every cakeys run against it.
    env: &'static [(&'static str, &'static str)],
    plant: Plant,
    /// `CKM_EDDSA` is usable: not through p11-kit, whose RPC drops it.
    eddsa: bool,
}

struct Env {
    dir: PathBuf,
    refs: Vec<Ref>,
}

fn module(var: &str, require: &str) -> Option<String> {
    let m = std::env::var(var).ok();
    assert!(m.is_some() || std::env::var(require).is_err(), "{var} is required");
    m
}

fn env(name: &str) -> Option<Env> {
    let mut refs = Vec::new();
    let r = |name, module, token_label, env, plant, eddsa| Ref { name, module, token_label, env, plant, eddsa };
    if let Some(m) = module("CAKEYS_TEST_MODULE", "CAKEYS_TEST_REQUIRE") {
        refs.push(r("softhsm", m, "kmtest", &[], Plant::Create, true));
    }
    if let Some(m) = module("CAKEYS_KRYOPTIC_MODULE", "CAKEYS_KRYOPTIC_REQUIRE") {
        refs.push(r("kryoptic", m.clone(), "kmtest", &[], Plant::Create, true));
        let der: &[(&str, &str)] = &[("KRYOPTIC_EC_POINT_ENCODING", "DER")];
        refs.push(r("kryoptic-der", m, "kmtest", der, Plant::Shared, true));
    }
    if let Some(m) = module("CAKEYS_P11KIT_CLIENT", "CAKEYS_P11KIT_REQUIRE") {
        refs.push(r("p11kit", m, "kmp11", &[], Plant::Create, false));
    }
    if let Some(m) = module("CAKEYS_TPM_MODULE", "CAKEYS_TPM_REQUIRE") {
        refs.push(r("tpm2", m, "kmtest", &[], Plant::Ptool, false));
    }
    if refs.len() < 2 {
        eprintln!("skipping {name}: fewer than two reference tokens set");
        return None;
    }
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("xref-{name}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("pin"), "1234\n").unwrap();
    Some(Env { dir, refs })
}

impl Env {
    /// keys.toml: one token per reference, then `body`.
    fn config(&self, body: &str) {
        let pin = self.dir.join("pin");
        let mut text = String::new();
        for r in &self.refs {
            let (name, module, label) = (r.name, &r.module, r.token_label);
            writeln!(text, "[tokens.{name}]\nmodule = \"{module}\"\ntokenLabel = \"{label}\"").unwrap();
            writeln!(text, "pinFile = \"{}\"\n", pin.display()).unwrap();
        }
        std::fs::write(self.dir.join("keys.toml"), text + body).unwrap();
    }

    fn km(&self, r: &Ref, args: &[&str]) -> Output {
        let out = Command::new(BIN)
            .env_remove("NIX_BUILD_TOP")
            .env_remove("IN_NIX_SHELL")
            .envs(r.env.iter().copied())
            .arg("--config")
            .arg(self.dir.join("keys.toml"))
            .args(args)
            .output()
            .unwrap();
        eprintln!(
            "$ cakeys {} ({})\n  exit={:?}\n  stdout={}\n  stderr={}",
            args.join(" "),
            r.name,
            out.status.code(),
            String::from_utf8_lossy(&out.stdout).trim(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
        out
    }

    fn refs(&self, keep: impl Fn(&Ref) -> bool) -> Vec<&Ref> {
        self.refs.iter().filter(|r| keep(r)).collect()
    }

    /// A spec over `object` on `refs`, located by `label`; `extra` is appended to each token entry.
    fn spec(name: &str, object: &str, attributes: &str, refs: &[&Ref], label: &str, extra: &str) -> String {
        let mut s = format!("[specs.{name}]\nobject = \"{object}\"\n{attributes}");
        for r in refs {
            writeln!(s, "tokens.{} = {{ locator = {{ CKA_LABEL = \"{label}\" }}{extra} }}", r.name).unwrap();
        }
        s + "\n"
    }

    /// Realise `spec` on every reference into one lock: the first records the identity and each
    /// other must match it (a different one would be 10). Every scheme two references both
    /// compute reports the same ID, and each then verifies.
    fn assert_one_identity(&self, spec: &str, refs: &[&Ref]) {
        let mut seen: BTreeMap<String, (serde_json::Value, &str)> = BTreeMap::new();
        for r in refs {
            let o = self.km(r, &["realise", spec, "--token", r.name]);
            assert_eq!(code(&o), 0, "{spec} on {}: {}", r.name, String::from_utf8_lossy(&o.stderr));
            let resolved: serde_json::Value = serde_json::from_str(&stdout(&o)).unwrap();
            for (scheme, id) in resolved["ids"].as_object().unwrap() {
                match seen.get(scheme) {
                    Some((want, by)) => assert_eq!(id, want, "{spec}: {scheme} on {} differs from {by}", r.name),
                    None => {
                        seen.insert(scheme.clone(), (id.clone(), r.name));
                    }
                }
            }
        }
        assert!(!seen.is_empty(), "{spec}: no identity");
        for r in refs {
            assert_eq!(code(&self.km(r, &["verify", spec, "--token", r.name])), 0, "{spec} on {}", r.name);
        }
    }

    /// `tpm2_ptool <args>` on the tpm2 reference's token.
    #[allow(clippy::unused_self)] // beside the other planting helpers
    fn ptool(&self, args: &[&str]) {
        let store = std::env::var("TPM2_PKCS11_STORE").unwrap();
        let out = Command::new("tpm2_ptool")
            .args(args)
            .args(["--label=kmtest", "--userpin=1234", &format!("--path={store}")])
            .output()
            .unwrap();
        assert!(out.status.success(), "tpm2_ptool {args:?}: {}", String::from_utf8_lossy(&out.stderr));
    }

    /// Plant through `C_CreateObject` on every `Create` reference.
    fn create(&self, objects: &[Vec<Attribute>]) {
        for r in self.refs(|r| r.plant == Plant::Create) {
            let s = open_session(&r.module, r.token_label, "1234");
            for o in objects {
                s.create_object(o).unwrap_or_else(|e| panic!("{} on {}: {e}", label_of(o), r.name));
            }
        }
    }

    /// The P-256 fixture key pair under `label`: created, or imported on tpm2.
    fn plant_p256(&self, label: &str) {
        let (params, scalar, point) = ec_fixture(&pem_der(&format!("{FIXTURES}/tpm-import-p256.pem")));
        self.create(&ec_pair(KeyType::EC, &params, &scalar, &point, label));
        if self.refs.iter().any(|r| r.plant == Plant::Ptool) {
            let pem = format!("--privkey={FIXTURES}/tpm-import-p256.pem");
            self.ptool(&["import", "--algorithm=ecc", &pem, &format!("--key-label={label}")]);
        }
    }
}

fn label_of(template: &[Attribute]) -> String {
    template
        .iter()
        .find_map(|a| match a {
            Attribute::Label(l) => Some(String::from_utf8_lossy(l).into_owned()),
            _ => None,
        })
        .unwrap_or_default()
}

/// One DER element: (tag, contents, rest). Independent of the crates cakeys uses.
fn der(input: &[u8]) -> (u8, &[u8], &[u8]) {
    let (tag, first) = (input[0], input[1]);
    let (len, off) = if first < 0x80 {
        (usize::from(first), 2)
    } else {
        let n = usize::from(first & 0x7f);
        (input[2..2 + n].iter().fold(0, |acc, b| (acc << 8) | usize::from(*b)), 2 + n)
    };
    (tag, &input[off..off + len], &input[off + len..])
}

/// The DER inside a PEM file.
fn pem_der(path: &str) -> Vec<u8> {
    use base64::Engine;
    let text = std::fs::read_to_string(path).unwrap();
    let b64: String = text.lines().filter(|l| !l.starts_with("-----")).collect();
    base64::engine::general_purpose::STANDARD.decode(b64).unwrap()
}

/// A PKCS#8 EC key: (curve OID as DER, private scalar, uncompressed public point).
fn ec_fixture(pkcs8: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let (_, info, _) = der(pkcs8);
    let (_, _, rest) = der(info); // version
    let (_, alg, rest) = der(rest);
    let (_, _, curve) = der(alg); // id-ecPublicKey
    let curve_len = curve.len() - der(curve).2.len();
    let (_, inner, _) = der(rest); // OCTET STRING { ECPrivateKey }
    let (_, ec, _) = der(inner);
    let (_, _, rest) = der(ec); // version
    let (_, scalar, mut rest) = der(rest);
    loop {
        let (tag, body, next) = der(rest);
        if tag == 0xa1 {
            let (_, bits, _) = der(body);
            return (curve[..curve_len].to_vec(), scalar.to_vec(), bits[1..].to_vec());
        }
        rest = next;
    }
}

/// A PKCS#8 RSA key: modulus, public and private exponents, primes, CRT exponents, coefficient.
fn rsa_fixture(pkcs8: &[u8]) -> Vec<Vec<u8>> {
    let (_, info, _) = der(pkcs8);
    let (_, _, rest) = der(info); // version
    let (_, _, rest) = der(rest); // algorithm
    let (_, inner, _) = der(rest);
    let (_, key, _) = der(inner);
    let (_, _, mut rest) = der(key); // version
    let mut ints = Vec::new();
    while !rest.is_empty() {
        let (_, int, next) = der(rest);
        ints.push(int.iter().copied().skip_while(|b| *b == 0).collect());
        rest = next;
    }
    ints
}

/// A private and a public key object over the same EC or Edwards material. The point is given
/// DER-wrapped (the PKCS#11 2.40 form every module accepts).
fn ec_pair(kt: KeyType, params: &[u8], scalar: &[u8], point: &[u8], label: &str) -> [Vec<Attribute>; 2] {
    let common = |class| {
        vec![
            Attribute::Class(class),
            Attribute::KeyType(kt),
            Attribute::Token(true),
            Attribute::Label(label.as_bytes().to_vec()),
            Attribute::EcParams(params.to_vec()),
        ]
    };
    let mut private = common(ObjectClass::PRIVATE_KEY);
    private.extend([Attribute::Value(scalar.to_vec()), Attribute::Sign(true), Attribute::Sensitive(true)]);
    let mut public = common(ObjectClass::PUBLIC_KEY);
    public.extend([Attribute::EcPoint(tlv(0x04, point)), Attribute::Verify(true)]);
    [private, public]
}

/// Generate a key pair on `s` with readable material, read it out, and destroy it: material for
/// the curves without a fixture.
fn export_ec(s: &Session, kt: KeyType, params: &[u8], label: &str) -> (Vec<u8>, Vec<u8>) {
    let mech = if kt == KeyType::EC { Mechanism::EccKeyPairGen } else { Mechanism::EccEdwardsKeyPairGen };
    let l = Attribute::Label(label.as_bytes().to_vec());
    let (public, private) = s
        .generate_key_pair(
            &mech,
            &[Attribute::Token(false), l.clone(), Attribute::EcParams(params.to_vec())],
            &[Attribute::Token(false), l, Attribute::Sensitive(false), Attribute::Extractable(true)],
        )
        .unwrap();
    let value = match &s.get_attributes(private, &[AttributeType::Value]).unwrap()[0] {
        Attribute::Value(v) => v.clone(),
        a => panic!("{a:?}"),
    };
    let point = match &s.get_attributes(public, &[AttributeType::EcPoint]).unwrap()[0] {
        Attribute::EcPoint(p) => p.clone(),
        a => panic!("{a:?}"),
    };
    s.destroy_object(private).unwrap();
    s.destroy_object(public).unwrap();
    // Raw (PKCS#11 3.2) or DER-wrapped: keep the bare point.
    let raw = match params {
        ED25519 => Some(32),
        ED448 => Some(57),
        _ => None,
    };
    (value, if raw == Some(point.len()) { point } else { unwrap_octets(&point) })
}

fn secret(kt: KeyType, value: &[u8], label: &str, usage: &[Attribute]) -> Vec<Attribute> {
    let mut t = vec![
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(kt),
        Attribute::Token(true),
        Attribute::Label(label.as_bytes().to_vec()),
        Attribute::Value(value.to_vec()),
        Attribute::Sensitive(true),
        Attribute::Extractable(false),
    ];
    t.extend_from_slice(usage);
    t
}

const P384_PARAMS: &[u8] = &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22];
const P521_PARAMS: &[u8] = &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23];

/// Every key type the references share: the P-256 and RSA fixtures (also on tpm2), and P-384,
/// P-521, Ed25519 and Ed448 keys exported from one reference into the others. Each private key
/// proves possession where the reference can sign with it, and the public key object is
/// identified on every reference (`publicOnly`).
#[test]
fn asymmetric_material_has_one_identity_on_every_reference() {
    let Some(e) = env("asymmetric") else { return };
    let tpm = e.refs.iter().any(|r| r.plant == Plant::Ptool);
    e.plant_p256("xref-p256");
    let rsa = rsa_fixture(&pem_der(&format!("{FIXTURES}/tpm-import-rsa2048.pem")));
    let (n, pe) = (rsa[0].clone(), rsa[1].clone());
    let private = vec![
        Attribute::Class(ObjectClass::PRIVATE_KEY),
        Attribute::KeyType(KeyType::RSA),
        Attribute::Token(true),
        Attribute::Label(b"xref-rsa".to_vec()),
        Attribute::Sign(true),
        Attribute::Sensitive(true),
        Attribute::Modulus(n.clone()),
        Attribute::PublicExponent(pe.clone()),
        Attribute::PrivateExponent(rsa[2].clone()),
        Attribute::Prime1(rsa[3].clone()),
        Attribute::Prime2(rsa[4].clone()),
        Attribute::Exponent1(rsa[5].clone()),
        Attribute::Exponent2(rsa[6].clone()),
        Attribute::Coefficient(rsa[7].clone()),
    ];
    let public = vec![
        Attribute::Class(ObjectClass::PUBLIC_KEY),
        Attribute::KeyType(KeyType::RSA),
        Attribute::Token(true),
        Attribute::Label(b"xref-rsa".to_vec()),
        Attribute::Verify(true),
        Attribute::Modulus(n),
        Attribute::PublicExponent(pe),
    ];
    e.create(&[private, public]);
    if tpm {
        let pem = format!("--privkey={FIXTURES}/tpm-import-rsa2048.pem");
        e.ptool(&["import", "--algorithm=rsa", &pem, "--key-label=xref-rsa"]);
    }
    // Material without a fixture comes from the first reference that creates objects.
    let source = e.refs.iter().find(|r| r.plant == Plant::Create).unwrap();
    let s = open_session(&source.module, source.token_label, "1234");
    let exported = [
        ("p384", KeyType::EC, P384_PARAMS, "secp384r1"),
        ("p521", KeyType::EC, P521_PARAMS, "secp521r1"),
        ("ed25519", KeyType::EC_EDWARDS, ED25519, "edwards25519"),
        ("ed448", KeyType::EC_EDWARDS, ED448, "edwards448"),
    ];
    // Export everything before planting: a module is initialised once per process at a time.
    let material: Vec<_> =
        exported.iter().map(|(k, kt, params, _)| export_ec(&s, *kt, params, &format!("xref-src-{k}"))).collect();
    drop(s);
    for ((k, kt, params, _), (scalar, point)) in exported.iter().zip(&material) {
        e.create(&ec_pair(*kt, params, scalar, point, &format!("xref-{k}")));
    }

    let all = e.refs(|_| true);
    let created = e.refs(|r| r.plant != Plant::Ptool);
    let mut body = String::new();
    // (spec, the references it is realised on, by name)
    let mut cases: Vec<(String, Vec<&str>)> = Vec::new();
    let mut add = |k: &str, object: &str, signers: &[&Ref], publics: &[&Ref], binding: &str| {
        let attrs = "attributes = { CKA_SIGN = true }\n";
        body += object;
        body += &Env::spec(k, k, attrs, signers, &format!("xref-{k}"), binding);
        body += &Env::spec(&format!("{k}-pub"), k, "", publics, &format!("xref-{k}"), ", publicOnly = true");
        cases.push((k.to_owned(), signers.iter().map(|r| r.name).collect()));
        cases.push((format!("{k}-pub"), publics.iter().map(|r| r.name).collect()));
    };
    let ec = |k: &str, kt: &str, curve: &str| {
        format!("[objects.{k}]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"{kt}\"\ncurve = \"{curve}\"\n\n")
    };
    // tpm2-pkcs11 signs with its imported P-256 key; its RSA key is identified through the
    // public object, as in tests/tpm2.rs.
    add("p256", &ec("p256", "CKK_EC", "secp256r1"), &all, &all, "");
    let rsa_object = "[objects.rsa]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_RSA\"\nmodulusBits = 2048\n\n";
    add("rsa", rsa_object, &created, &all, "");
    let eddsa = e.refs(|r| r.plant != Plant::Ptool && r.eddsa);
    for (k, kt, _, curve) in exported {
        let kt = if kt == KeyType::EC { "CKK_EC" } else { "CKK_EC_EDWARDS" };
        match k {
            // No Ed448 verifier on the host: possession is the token's word everywhere.
            "ed448" => add(k, &ec(k, kt, curve), &created, &created, ", binding = \"token-asserted\""),
            "ed25519" => add(k, &ec(k, kt, curve), &eddsa, &created, ""),
            _ => add(k, &ec(k, kt, curve), &created, &created, ""),
        }
    }
    e.config(&body);
    for (spec, names) in &cases {
        let refs = e.refs(|r| names.contains(&r.name));
        e.assert_one_identity(spec, &refs);
    }
}

/// Secret keys with known values commit alike: AES (`cmac`, `kcv-ecb`, `kcv-ecb-dec`, `kw`
/// where the reference offers each), a generic secret and an HMAC-SHA256 key (also on tpm2) —
/// the same `commitment` everywhere.
#[test]
fn secret_material_commits_alike_on_every_reference() {
    let Some(e) = env("secret") else { return };
    let aes_usage = [Attribute::Sign(true), Attribute::Encrypt(true), Attribute::Decrypt(true), Attribute::Wrap(true)];
    e.create(&[
        secret(KeyType::AES, AES_VALUE, "xref-aes", &aes_usage),
        secret(KeyType::GENERIC_SECRET, SECRET_VALUE, "xref-secret", &[Attribute::Sign(true)]),
        secret(KeyType::SHA256_HMAC, HMAC_VALUE, "xref-hmac", &[Attribute::Sign(true)]),
    ]);
    if e.refs.iter().any(|r| r.plant == Plant::Ptool) {
        let file = e.dir.join("hmac.bin");
        std::fs::write(&file, HMAC_VALUE).unwrap();
        let key = format!("--privkey={}", file.display());
        e.ptool(&["import", "--algorithm=hmac:sha256", &key, "--key-label=xref-hmac"]);
    }
    let created = e.refs(|r| r.plant != Plant::Ptool);
    let all = e.refs(|_| true);
    let object =
        |k: &str, kt: &str| format!("[objects.{k}]\nclass = \"CKO_SECRET_KEY\"\nkeyType = \"{kt}\"\nvalueLen = 32\n\n");
    let body = object("aes", "CKK_AES")
        + &Env::spec(
            "aes",
            "aes",
            "attributes = { CKA_SIGN = true, CKA_ENCRYPT = true, CKA_DECRYPT = true, CKA_WRAP = true }\n",
            &created,
            "xref-aes",
            "",
        )
        + &object("secret", "CKK_GENERIC_SECRET")
        + &Env::spec("secret", "secret", "attributes = { CKA_SIGN = true }\n", &created, "xref-secret", "")
        + &object("hmac", "CKK_SHA256_HMAC")
        + &Env::spec("hmac", "hmac", "attributes = { CKA_SIGN = true }\n", &all, "xref-hmac", "");
    e.config(&body);
    e.assert_one_identity("aes", &created);
    e.assert_one_identity("secret", &created);
    e.assert_one_identity("hmac", &all);
}

/// A certificate (`certhash` and its subject key's `rfc7093m4`) and a public data object
/// (`valuehash`) hash alike.
#[test]
fn certificates_and_data_objects_hash_alike_on_every_reference() {
    let Some(e) = env("adopted") else { return };
    let cert = <x509_cert::Certificate as x509_cert::der::Decode>::from_der(ADOPT_CERT).unwrap();
    let subject = x509_cert::der::Encode::to_der(cert.tbs_certificate().subject()).unwrap();
    e.create(&[
        vec![
            Attribute::Class(ObjectClass::CERTIFICATE),
            Attribute::CertificateType(cryptoki::object::CertificateType::X_509),
            Attribute::Token(true),
            Attribute::Label(b"xref-cert".to_vec()),
            Attribute::Subject(subject),
            Attribute::Value(ADOPT_CERT.to_vec()),
        ],
        vec![
            Attribute::Class(ObjectClass::DATA),
            Attribute::Token(true),
            Attribute::Private(false),
            Attribute::Label(b"xref-data".to_vec()),
            Attribute::Value(DATA_VALUE.to_vec()),
        ],
    ]);
    let created = e.refs(|r| r.plant != Plant::Ptool);
    let body = "[objects.cert]\nclass = \"CKO_CERTIFICATE\"\ncertificateType = \"CKC_X_509\"\n\n".to_owned()
        + &Env::spec("cert", "cert", "", &created, "xref-cert", "")
        + "[objects.data]\nclass = \"CKO_DATA\"\n\n"
        + &Env::spec("data", "data", "", &created, "xref-data", "");
    e.config(&body);
    e.assert_one_identity("cert", &created);
    e.assert_one_identity("data", &created);
}

/// The same scenario, the same verdict on every reference: nothing under the locator (11), two
/// objects under it (12), material of another type (13), and a private key swapped under a
/// recorded locator (13, through the proof of possession or the `CKA_PUBLIC_KEY_INFO`
/// cross-check, `tests/reference/`).
#[test]
fn the_same_scenario_gets_the_same_verdict_on_every_reference() {
    let Some(e) = env("verdicts") else { return };
    e.plant_p256("xref-v-p256");
    e.plant_p256("xref-v-dup");
    e.plant_p256("xref-v-dup");
    e.plant_p256("xref-v-swap");
    let all = e.refs(|_| true);
    let created = e.refs(|r| r.plant != Plant::Ptool);
    let p256 = "[objects.p256]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n";
    let sign = "attributes = { CKA_SIGN = true }\n";
    let body = p256.to_owned()
        + "[objects.p384]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp384r1\"\n\n"
        + "[objects.swap]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n"
        + &Env::spec("absent", "p256", sign, &all, "xref-v-absent", "")
        + &Env::spec("dup", "p256", sign, &all, "xref-v-dup", "")
        + &Env::spec("wrong-type", "p384", sign, &all, "xref-v-p256", "")
        + &Env::spec("swap", "swap", sign, &created, "xref-v-swap", "");
    e.config(&body);
    let verdicts = |spec: &str, refs: &[&Ref]| -> BTreeMap<&str, i32> {
        refs.iter().map(|r| (r.name, code(&e.km(r, &["resolve", spec, "--token", r.name])))).collect()
    };
    let expect = |spec: &str, refs: &[&Ref], want: i32| {
        let got = verdicts(spec, refs);
        assert!(got.values().all(|c| *c == want), "{spec}: want {want} everywhere, got {got:?}");
    };
    expect("absent", &all, 11);
    expect("dup", &all, 12);
    expect("wrong-type", &all, 13);

    // Record the swap key everywhere, then replace each private key with another P-256 key.
    for r in &created {
        assert_eq!(code(&e.km(r, &["realise", "swap", "--token", r.name])), 0, "{}", r.name);
    }
    for r in e.refs(|r| r.plant == Plant::Create) {
        let s = open_session(&r.module, r.token_label, "1234");
        let label = Attribute::Label(b"xref-v-swap".to_vec());
        let original = s.find_objects(&[Attribute::Class(ObjectClass::PRIVATE_KEY), label.clone()]).unwrap()[0];
        s.destroy_object(original).unwrap();
        s.generate_key_pair(
            &Mechanism::EccKeyPairGen,
            &[Attribute::Token(false), Attribute::EcParams(EC_P256_PARAMS.to_vec())],
            &[Attribute::Token(true), label, Attribute::Sign(true), Attribute::Sensitive(true)],
        )
        .unwrap();
    }
    let swapped: BTreeMap<&str, (i32, bool)> = created
        .iter()
        .map(|r| {
            let o = e.km(r, &["verify", "swap", "--token", r.name]);
            let err = String::from_utf8_lossy(&o.stderr);
            let why = err.contains("proof of possession failed") || err.contains("disagrees with the key material");
            (r.name, (code(&o), why))
        })
        .collect();
    assert!(swapped.values().all(|v| *v == (13, true)), "swap: want 13 everywhere, got {swapped:?}");
}

const EC_P256_PARAMS: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];

/// `export --dry-run` (MIGRATE.md phase 1): the plan follows each side's capabilities. Between
/// the software references, the composed sealed method with the strongest OAEP hash both
/// implement; to tpm2-pkcs11 and through p11-kit (whose RPC drops AES key wrap) only through the
/// host, behind the flag; to a file behind the flag; a key made non-extractable never. Nothing
/// moves without --dry-run yet.
#[test]
fn export_plans_follow_each_sides_capabilities() {
    let Some(e) = env("export-plan") else { return };
    let named = |n: &str| e.refs.iter().find(|r| r.name == n);
    let (Some(soft), Some(kry)) = (named("softhsm"), named("kryoptic")) else {
        eprintln!("skipping export-plan: needs the softhsm and kryoptic references");
        return;
    };
    let p256 = |o: &str| {
        format!("[objects.{o}]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n")
    };
    let attrs = |x: bool| format!("attributes = {{ CKA_SIGN = true, CKA_EXTRACTABLE = {x} }}\n");
    let body = p256("movable")
        + &p256("fixed")
        + &p256("movable-k")
        + &Env::spec("movable", "movable", &attrs(true), &[soft], "xref-mv", ", autoCreate = true")
        + &Env::spec("fixed", "fixed", &attrs(false), &[soft], "xref-fx", ", autoCreate = true")
        + &Env::spec("movable-k", "movable-k", &attrs(true), &[kry], "xref-mvk", ", autoCreate = true");
    e.config(&body);
    for (spec, r) in [("movable", soft), ("fixed", soft), ("movable-k", kry)] {
        assert_eq!(code(&e.km(r, &["realise", spec, "--token", r.name])), 0, "{spec}");
    }
    let plan = |r: &Ref, args: &[&str]| -> (i32, serde_json::Value) {
        let mut a = vec!["export"];
        a.extend_from_slice(args);
        a.extend(["--token", r.name, "--dry-run", "--json"]);
        let o = e.km(r, &a);
        (code(&o), serde_json::from_str(&stdout(&o)).unwrap_or_default())
    };
    let first = |v: &serde_json::Value| {
        let p = &v["plans"][0];
        (p["method"].as_str().map(str::to_owned), p["exposure"].as_str().map(str::to_owned), p["ready"].as_bool())
    };
    let some = |s: &str| Some(s.to_owned());

    let (c, v) = plan(soft, &["movable", "--target", "kryoptic"]);
    assert_eq!(c, 0, "{v}");
    assert_eq!(first(&v), (some("rsa-oaep-sha1+aes-kwp"), some("sealed"), Some(true)), "{v}");
    assert_eq!(v["capabilities"]["to"], "token");
    if named("kryoptic-der").is_some() {
        let (c, v) = plan(kry, &["movable-k", "--target", "kryoptic-der"]);
        assert_eq!((c, first(&v).0), (0, some("rsa-oaep-sha256+aes-kwp")), "{v}");
    }
    let (c, v) = plan(soft, &["fixed", "--target", "kryoptic"]);
    assert_eq!((c, first(&v).0), (15, None), "{v}");
    assert!(v["plans"][0]["reasons"][0].as_str().unwrap().contains("not extractable"), "{v}");
    if named("tpm2").is_some() {
        let (c, v) = plan(soft, &["movable", "--target", "tpm2"]);
        assert_eq!((c, first(&v)), (15, (some("tpm2-ptool"), some("host"), Some(false))), "{v}");
        assert!(v["plans"][0]["reasons"][0].as_str().unwrap().contains("--allow-host-plaintext"), "{v}");
        let (c, v) = plan(soft, &["movable", "--target", "tpm2", "--allow-host-plaintext"]);
        assert_eq!((c, first(&v).2), (0, Some(true)), "{v}");
        assert!(v["plans"][0]["notes"][0].as_str().unwrap().contains("residence"), "{v}");
    }
    if named("p11kit").is_some() {
        let (c, v) = plan(soft, &["movable", "--target", "p11kit"]);
        assert_eq!((c, first(&v)), (15, (some("host-pkcs8"), some("host"), Some(false))), "{v}");
    }
    let (c, v) = plan(soft, &["movable", "--to-file", "pkcs12", "--allow-host-plaintext"]);
    assert_eq!((c, first(&v)), (0, (some("pkcs12"), some("file"), Some(true))), "{v}");
    // Every object on the source: one plan each, 15 since one cannot move.
    let (c, v) = plan(soft, &["--target", "kryoptic"]);
    assert_eq!((c, v["plans"].as_array().map(Vec::len)), (15, Some(2)), "{v}");
    let o = e.km(soft, &["export", "movable", "--token", "softhsm", "--target", "kryoptic"]);
    assert_eq!(code(&o), 15);
    assert!(String::from_utf8_lossy(&o.stderr).contains("only --dry-run"));
}

/// `cakeys transport` (MIGRATE.md D3) writes the transport key's public half with its locked
/// identity; an export planned from that file alone wraps to it, and an edited file is refused.
#[test]
fn transport_files_carry_the_locked_identity() {
    let Some(e) = env("transport") else { return };
    let named = |n: &str| e.refs.iter().find(|r| r.name == n);
    let (Some(soft), Some(kry)) = (named("softhsm"), named("kryoptic")) else {
        eprintln!("skipping transport: needs the softhsm and kryoptic references");
        return;
    };
    let body = "[objects.kek]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_RSA\"\nmodulusBits = 3072\n\n\
                [objects.ec]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n\
                [objects.mv]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n"
        .to_owned()
        + &Env::spec(
            "kek",
            "kek",
            "attributes = { CKA_UNWRAP = true, CKA_DECRYPT = true, CKA_EXTRACTABLE = false }\n",
            &[kry],
            "xref-kek",
            ", autoCreate = true, binding = \"pop-decrypt\"",
        )
        + &Env::spec("ec-k", "ec", "attributes = { CKA_SIGN = true }\n", &[kry], "xref-tec", ", autoCreate = true")
        + &Env::spec(
            "movable",
            "mv",
            "attributes = { CKA_SIGN = true, CKA_EXTRACTABLE = true }\n",
            &[soft],
            "xref-tmv",
            ", autoCreate = true",
        );
    e.config(&body);
    assert_eq!(code(&e.km(kry, &["realise", "kek", "--token", "kryoptic"])), 0);
    let file = e.dir.join("kryoptic.transport.toml");
    let path = file.to_str().unwrap();
    let o = e.km(kry, &["transport", "kek", "--token", "kryoptic", "--out", path]);
    assert_eq!(code(&o), 0, "{}", String::from_utf8_lossy(&o.stderr));
    assert!(String::from_utf8_lossy(&o.stderr).contains("also decrypts"));
    let t: toml::Table = toml::from_str(&std::fs::read_to_string(&file).unwrap()).unwrap();
    let lock: toml::Table = toml::from_str(&std::fs::read_to_string(e.dir.join("keys.lock")).unwrap()).unwrap();
    assert_eq!(t["format"].as_str(), Some("cakeys-transport"));
    assert_eq!(t["provider"].as_str(), Some("kryoptic"));
    assert_eq!(t["rfc7093m4"], lock["objects"]["kek"]["ids"]["rfc7093m4"], "the locked identity");
    // Only an RSA private key can be a transport key.
    assert_eq!(code(&e.km(kry, &["realise", "ec-k", "--token", "kryoptic"])), 0);
    assert_eq!(code(&e.km(kry, &["transport", "ec-k", "--token", "kryoptic"])), 17);
    // A source plans from the file alone.
    assert_eq!(code(&e.km(soft, &["realise", "movable", "--token", "softhsm"])), 0);
    let o = e.km(soft, &["export", "mv", "--token", "softhsm", "--transport", path, "--dry-run", "--json"]);
    assert_eq!(code(&o), 0, "{}", String::from_utf8_lossy(&o.stderr));
    let v: serde_json::Value = serde_json::from_str(&stdout(&o)).unwrap();
    assert_eq!(v["capabilities"]["to"], "transport file");
    assert_eq!(v["plans"][0]["method"], "rsa-oaep-sha1+aes-kwp");
    // A file edited to name another identity is refused.
    let text = std::fs::read_to_string(&file).unwrap();
    let edited = text.replace(t["rfc7093m4"].as_str().unwrap(), "sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=");
    std::fs::write(&file, edited).unwrap();
    let o = e.km(soft, &["export", "mv", "--token", "softhsm", "--transport", path, "--dry-run"]);
    assert_eq!(code(&o), 17, "{}", String::from_utf8_lossy(&o.stderr));
}
