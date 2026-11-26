//! Cross-reference tests: the same material on every reference token has the same identity, and
//! the same scenario gets the same verdict. The references are `SoftHSM`, kryoptic (twice: with
//! raw and with DER Edwards points), `SoftHSM` behind p11-kit forwarding, and tpm2-pkcs11 for the
//! material that `tpm2_ptool` can import.
//!
//! A reference takes part when its suite's variables are set (`CAKEYS_TEST_MODULE`,
//! `CAKEYS_KRYOPTIC_MODULE`, `CAKEYS_P11KIT_CLIENT`, `CAKEYS_TPM_MODULE`, with the environment
//! that the headers of those suites describe). When a `*_REQUIRE` variable is set, a missing
//! reference is a failure. The tests are skipped when fewer than two references take part.

mod common;

use common::xref::{Env, Plant, Ref, env};
use common::*;
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass};
use cryptoki::session::Session;
use std::collections::BTreeMap;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");
const ADOPT_CERT: &[u8] = include_bytes!("fixtures/adopt-cert.der");
const AES_VALUE: &[u8; 32] = b"cakeys cross-reference aes key!!";
const SECRET_VALUE: &[u8; 32] = b"cakeys cross-reference secret!!!";
const HMAC_VALUE: &[u8; 32] = b"cakeys cross-reference hmac key!";
const DATA_VALUE: &[u8] = b"cakeys cross-reference data object";

impl Env {
    /// Locks `spec` on every reference into one lock. The first reference records the identity,
    /// and each other reference must match it (a different identity would exit 10). Every scheme
    /// that two references both compute reports the same ID, and each reference then verifies.
    /// The identity must also be the one that the host computes: each `(scheme, ID)` of `oracle`
    /// that the references computed must have that ID, and the references must have computed at
    /// least one of them (review references.rs F2: when the test only compared the references
    /// with each other, an encoder bug that they all shared passed).
    fn assert_one_identity(&self, spec: &str, refs: &[&Ref], oracle: &[(&str, String)]) {
        let mut seen: BTreeMap<String, (serde_json::Value, &str)> = BTreeMap::new();
        for r in refs {
            let o = self.km(r, &["lock", "--spec", spec, "--token", r.name]);
            assert_eq!(code(&o), 22, "{spec} on {}: {}", r.name, String::from_utf8_lossy(&o.stderr));
            let resolved = lock_result(&o);
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
        let known: Vec<&str> = oracle
            .iter()
            .filter_map(|(scheme, want)| {
                let (got, by) = seen.get(*scheme)?;
                assert_eq!(got.as_str(), Some(want.as_str()), "{spec}: {scheme} on {by} is not the host's");
                Some(*scheme)
            })
            .collect();
        assert!(!known.is_empty(), "{spec}: none of {oracle:?} computed, only {:?}", seen.keys().collect::<Vec<_>>());
        for r in refs {
            assert_eq!(code(&self.km(r, &["check", "--spec", spec, "--token", r.name])), 0, "{spec} on {}", r.name);
        }
    }

    /// Returns the `rfc7093m4` that the host computes for the public key object under `label`.
    /// The object is read from the first reference that creates objects ([`oracle_spki`]).
    fn spki_id(&self, label: &str) -> (&'static str, String) {
        let source = self.refs.iter().find(|r| r.plant == Plant::Create).unwrap();
        let s = open_session(&source.module, source.token_label, "1234");
        ("rfc7093m4", sri(&oracle_spki(&s, label)))
    }

    /// Plants `objects` through `C_CreateObject` on every reference that plants with `Create`.
    fn create(&self, objects: &[Vec<Attribute>]) {
        for r in self.refs(|r| r.plant == Plant::Create) {
            let s = open_session(&r.module, r.token_label, "1234");
            for o in objects {
                s.create_object(o).unwrap_or_else(|e| panic!("{} on {}: {e}", label_of(o), r.name));
            }
        }
    }

    /// Plants the P-256 fixture key pair under `label`. The pair is created through
    /// `C_CreateObject`, or imported on tpm2.
    fn plant_p256(&self, label: &str) {
        let (params, scalar, point) = ec_fixture(&pem_der(&format!("{FIXTURES}/tpm-import-p256.pem")));
        self.create(&ec_pair(KeyType::EC, &params, &scalar, &point, label));
        if self.refs.iter().any(|r| r.plant == Plant::Ptool) {
            let pem = format!("--privkey={FIXTURES}/tpm-import-p256.pem");
            ptool(&["import", "--algorithm=ecc", &pem, &format!("--key-label={label}")]);
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

/// Returns a private and a public key object over the same EC or Edwards material. The point is
/// DER-wrapped, because every module accepts that PKCS#11 2.40 form.
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

/// Generates a key pair on `s` with readable material, reads the material out, and destroys the
/// key pair. This gives material for the curves that have no fixture.
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
    // The module returns the point raw (PKCS#11 3.2) or DER-wrapped. Keep the bare point.
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

/// This test covers every key type that the references share: the P-256 and RSA fixtures (also on
/// tpm2), and P-384, P-521, Ed25519 and Ed448 keys exported from one reference into the others.
/// Each private key proves possession where the reference can sign with it, and the public key
/// object is identified on every reference (`publicOnly`).
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
        ptool(&["import", "--algorithm=rsa", &pem, "--key-label=xref-rsa"]);
    }
    // Material without a fixture comes from the first reference that creates objects.
    let source = e.refs.iter().find(|r| r.plant == Plant::Create).unwrap();
    let s = open_session(&source.module, source.token_label, "1234");
    let exported = [
        ("p384", KeyType::EC, P384, "secp384r1"),
        ("p521", KeyType::EC, P521, "secp521r1"),
        ("ed25519", KeyType::EC_EDWARDS, ED25519, "edwards25519"),
        ("ed448", KeyType::EC_EDWARDS, ED448, "edwards448"),
    ];
    // Export all material before planting, because a process can initialise a module only once
    // at a time.
    let material: Vec<_> =
        exported.iter().map(|(k, kt, params, _)| export_ec(&s, *kt, params, &format!("xref-src-{k}"))).collect();
    drop(s);
    for ((k, kt, params, _), (scalar, point)) in exported.iter().zip(&material) {
        e.create(&ec_pair(*kt, params, scalar, point, &format!("xref-{k}")));
    }

    let all = e.refs(|_| true);
    let created = e.refs(|r| r.plant != Plant::Ptool);
    let mut body = String::new();
    // Each case is (spec, the names of the references on which the spec is realised).
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
            // The host has no Ed448 verifier, so no reference proves possession of the Ed448
            // key, and the binding is `token-asserted` everywhere.
            "ed448" => add(k, &ec(k, kt, curve), &created, &created, ", binding = \"token-asserted\""),
            "ed25519" => add(k, &ec(k, kt, curve), &eddsa, &created, ""),
            _ => add(k, &ec(k, kt, curve), &created, &created, ""),
        }
    }
    e.config(&body);
    for (spec, names) in &cases {
        let refs = e.refs(|r| names.contains(&r.name));
        let key = spec.trim_end_matches("-pub");
        e.assert_one_identity(spec, &refs, &[e.spki_id(&format!("xref-{key}"))]);
    }
}

/// Returns the `commitment` that the host computes for a 256-bit secret of `key_type`: the
/// HMAC-SHA256, under the secret, of the commitment label for `key_type`.
fn commitment(key: &[u8], key_type: &str) -> (&'static str, String) {
    use hmac::Mac as _;
    let mut mac = <hmac::Hmac<sha2::Sha256> as hmac::KeyInit>::new_from_slice(key).unwrap();
    mac.update(format!("key-management/v1/commitment/{key_type}/256").as_bytes());
    ("commitment", sri(&mac.finalize().into_bytes()))
}

/// Secret keys with known values give the same commitments on every reference: AES (`cmac`,
/// `kcv-ecb`, `kcv-ecb-dec`, and `kw` where the reference offers each), a generic secret, and an
/// HMAC-SHA256 key (also on tpm2), which have the same `commitment` everywhere.
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
        ptool(&["import", "--algorithm=hmac:sha256", &key, "--key-label=xref-hmac"]);
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
    let aes = ["cmac", "kcv-ecb", "kcv-ecb-dec", "kw"].map(|scheme| (scheme, aes_commitment(AES_VALUE, scheme)));
    e.assert_one_identity("aes", &created, &aes);
    e.assert_one_identity("secret", &created, &[commitment(SECRET_VALUE, "CKK_GENERIC_SECRET")]);
    e.assert_one_identity("hmac", &all, &[commitment(HMAC_VALUE, "CKK_SHA256_HMAC")]);
}

/// A certificate (`certhash` and its subject key's `rfc7093m4`) and a public data object
/// (`valuehash`) give the same hashes on every reference.
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
    e.assert_one_identity("cert", &created, &[("certhash", sri(ADOPT_CERT))]);
    e.assert_one_identity("data", &created, &[("valuehash", sri(DATA_VALUE))]);
}

/// The same scenario gives the same verdict on every reference: nothing under the locator (11),
/// two objects under it (12), material of another type (13), and a private key swapped under a
/// recorded locator (13, through the proof of possession or through the `CKA_PUBLIC_KEY_INFO`
/// cross-check, as in `tests/reference/`).
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
        refs.iter().map(|r| (r.name, code(&e.km(r, &["resolve", "--spec", spec, "--token", r.name])))).collect()
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
        assert_eq!(code(&e.km(r, &["lock", "--spec", "swap", "--token", r.name])), 22, "{}", r.name);
    }
    for r in e.refs(|r| r.plant == Plant::Create) {
        let s = open_session(&r.module, r.token_label, "1234");
        let (p256, usage) = ([Attribute::EcParams(P256.to_vec())], [Attribute::Sign(true), Attribute::Sensitive(true)]);
        swap_private_key(&s, "xref-v-swap", &Mechanism::EccKeyPairGen, &p256, &usage, &[]);
    }
    let swapped: BTreeMap<&str, (i32, bool)> = created
        .iter()
        .map(|r| {
            let o = e.km(r, &["check", "--spec", "swap", "--token", r.name]);
            let err = String::from_utf8_lossy(&o.stderr);
            let why = err.contains("proof of possession failed") || err.contains("disagrees with the key material");
            (r.name, (code(&o), why))
        })
        .collect();
    assert!(swapped.values().all(|v| *v == (13, true)), "swap: want 13 everywhere, got {swapped:?}");
}

/// `origin` (keys.toml): an object on several tokens is created on the pair whose origin is
/// `create`. `create` makes the object only there, prints that the `import` pair gets the material
/// from camigrate, and refuses that pair by name (17) before it touches the pair.
#[test]
fn create_happens_where_origin_says_create() {
    let Some(e) = env("create-on") else { return };
    let Some([soft, kry]) = e.needs("create-on", ["softhsm", "kryoptic"]) else {
        // The test is skipped only when neither reference is required. A run that requires both
        // (the check phase) fails here instead of passing with nothing created (review
        // references.rs F1).
        for require in ["CAKEYS_TEST_REQUIRE", "CAKEYS_KRYOPTIC_REQUIRE"] {
            assert!(
                std::env::var_os(require).is_none(),
                "create-on needs the softhsm and kryoptic references: {require} is set"
            );
        }
        return;
    };
    let body = format!(
        "[objects.born]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n\
         [specs.born]\nobject = \"born\"\nattributes = {{ CKA_SIGN = true }}\n\
         tokens.{} = {{ locator = {{ CKA_LABEL = \"xref-born\" }}, origin = \"create\" }}\n\
         tokens.{} = {{ locator = {{ CKA_LABEL = \"xref-born\" }}, origin = \"import\" }}\n",
        soft.name, kry.name
    );
    e.config(&body);
    let o = e.km(soft, &["create", "--spec", "born"]);
    assert_eq!(code(&o), 22, "{}", stderr(&o));
    assert!(stderr(&o).contains("origin = \"import\": camigrate brings its material here"), "{}", stderr(&o));
    assert_eq!(open_session(&soft.module, soft.token_label, "1234").labelled("xref-born").len(), 2, "the pair");
    assert_eq!(open_session(&kry.module, kry.token_label, "1234").labelled("xref-born"), []);
    assert_eq!(code(&e.km(kry, &["create", "--spec", "born", "--token", "kryoptic"])), 17);
    assert_eq!(open_session(&kry.module, kry.token_label, "1234").labelled("xref-born"), []);
}
