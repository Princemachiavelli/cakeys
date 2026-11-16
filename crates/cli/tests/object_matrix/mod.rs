//! The object matrix (docs/PLAN.md A4; docs/OPEN.md, "A matrix of what can be created, and at
//! what assurance"): what cakeys makes of objects it did not create. A fixed grid of objects is
//! created on a token straight through cryptoki, generated or imported as a legacy key would
//! arrive; each is declared exactly as it is (its usage bits, sensitivity, extractability,
//! per-use PIN and allowed mechanisms) and realised. The outcome per object — the mode, schemes
//! and binding recorded, or the exit code, or the token refusing to hold such an object — is
//! spec-coverage/objects/<token>.toml, generated and pinned:
//! `CAKEYS_UPDATE_OBJECTS=$PWD/spec-coverage/objects` rewrites it there
//! (`scripts/local-tests.sh -E 'test(object_matrix)'`).
//! What each refused row printed is in the test's directory, `report.txt`.
//!
//! Four families, in this order: generated keys and imported secret keys ([`Row`]); imported
//! private keys, by where their public half is ([`Import`]); certificates ([`Cert`]); data
//! objects ([`Data`]).
//!
//! Run by the reference suite (tests/reference/matrix.rs: `SoftHSM`, kryoptic) and on
//! tpm2-pkcs11 over a software TPM (tests/tpm2.rs), each with [`check`].
#![expect(unreachable_pub, reason = "its crate is a test binary: pub and pub(crate) say the same")]

use crate::common::*;
use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::object::{Attribute, CertificateType, KeyType, ObjectClass};
use cryptoki::session::Session;
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

/// The kinds of object the grid holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Aes,
    Des3,
    Generic,
    HmacSha256,
    Ec,
    Rsa,
    Ed25519,
}

impl Kind {
    fn name(self) -> &'static str {
        match self {
            Kind::Aes => "aes",
            Kind::Des3 => "des3",
            Kind::Generic => "generic",
            Kind::HmacSha256 => "hmac-sha256",
            Kind::Ec => "ec-p256",
            Kind::Rsa => "rsa-2048",
            Kind::Ed25519 => "ed25519",
        }
    }

    fn secret(self) -> bool {
        matches!(self, Kind::Aes | Kind::Des3 | Kind::Generic | Kind::HmacSha256)
    }

    /// The usage bits a row may set: for a secret key the ones a commitment uses, then the ones
    /// no commitment can (an unwrap-only or derive-only key); for a private key its operations.
    fn usage(self) -> &'static [&'static str] {
        match self {
            Kind::Aes => &["CKA_SIGN", "CKA_ENCRYPT", "CKA_DECRYPT", "CKA_WRAP"],
            Kind::Des3 => &["CKA_ENCRYPT", "CKA_DECRYPT"],
            Kind::Generic | Kind::HmacSha256 | Kind::Ed25519 => &["CKA_SIGN"],
            Kind::Ec => &["CKA_SIGN", "CKA_DERIVE", "CKA_UNWRAP"],
            Kind::Rsa => &["CKA_SIGN", "CKA_DECRYPT", "CKA_UNWRAP"],
        }
    }

    /// The `CKA_ALLOWED_MECHANISMS` a row may carry (besides none): one the identity uses, one
    /// it does not.
    fn allowed(self) -> &'static [&'static str] {
        match self {
            Kind::Aes => &["CKM_AES_CMAC", "CKM_AES_ECB", "CKM_AES_GCM"],
            Kind::Des3 => &["CKM_DES3_ECB", "CKM_DES3_CBC_PAD"],
            Kind::Generic | Kind::HmacSha256 => &["CKM_SHA256_HMAC", "CKM_SHA_1_HMAC"],
            Kind::Ec => &["CKM_ECDSA", "CKM_ECDH1_DERIVE"],
            Kind::Rsa => &["CKM_SHA256_RSA_PKCS", "CKM_RSA_PKCS", "CKM_RSA_PKCS_OAEP"],
            Kind::Ed25519 => &["CKM_EDDSA"],
        }
    }

    /// The keys.toml object of this kind.
    fn object(self) -> &'static str {
        match self {
            Kind::Aes => "class = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_AES\"\nvalueLen = 32",
            Kind::Des3 => "class = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_DES3\"",
            Kind::Generic => "class = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_GENERIC_SECRET\"\nvalueLen = 32",
            Kind::HmacSha256 => "class = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_SHA256_HMAC\"\nvalueLen = 32",
            Kind::Ec => "class = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"",
            Kind::Rsa => "class = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_RSA\"\nmodulusBits = 2048",
            Kind::Ed25519 => "class = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC_EDWARDS\"\ncurve = \"edwards25519\"",
        }
    }
}

/// How the object came to be on the token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Origin {
    /// `C_GenerateKey` or `C_GenerateKeyPair`: `CKA_LOCAL` true.
    Generated,
    /// `C_CreateObject` with a value: `CKA_LOCAL` false, as an imported legacy key.
    Imported,
}

/// One object of the grid.
#[derive(Clone, Debug)]
struct Row {
    kind: Kind,
    origin: Origin,
    /// The usage bits set; the kind's others are false.
    usage: Vec<&'static str>,
    extractable: bool,
    sensitive: bool,
    always_authenticate: bool,
    allowed: Option<&'static str>,
}

impl Row {
    /// The row's key in the table: every dimension, in a fixed order.
    fn key(&self) -> String {
        let origin = match self.origin {
            Origin::Generated => "generated",
            Origin::Imported => "imported",
        };
        let usage = if self.usage.is_empty() {
            "none".to_owned()
        } else {
            self.usage.iter().map(|u| u.trim_start_matches("CKA_")).collect::<Vec<_>>().join("+")
        };
        let mut key = format!(
            "{} {origin} usage={usage} {}extractable {}sensitive",
            self.kind.name(),
            if self.extractable { "" } else { "non-" },
            if self.sensitive { "" } else { "non-" },
        );
        if self.always_authenticate {
            key.push_str(" always-authenticate");
        }
        if let Some(m) = self.allowed {
            let _ = write!(key, " allowed={m}");
        }
        key
    }

    /// The spec's declared attributes: exactly what the object carries.
    fn attributes(&self) -> String {
        declared(self.kind, &self.usage, self.extractable, self.sensitive, self.always_authenticate, self.allowed)
    }

    fn binding(&self) -> &'static str {
        binding(self.kind, &self.usage)
    }
}

/// A key spec's declared attributes: the kind's usage bits as `usage` sets them, the protection,
/// the per-use PIN and the allowed mechanism.
fn declared(
    kind: Kind,
    usage: &[&str],
    extractable: bool,
    sensitive: bool,
    always_authenticate: bool,
    allowed: Option<&str>,
) -> String {
    let mut attrs: Vec<String> = kind.usage().iter().map(|u| format!("{u} = {}", usage.contains(u))).collect();
    attrs.push(format!("CKA_EXTRACTABLE = {extractable}"));
    attrs.push(format!("CKA_SENSITIVE = {sensitive}"));
    if always_authenticate {
        attrs.push("CKA_ALWAYS_AUTHENTICATE = true".into());
    }
    if let Some(m) = allowed {
        attrs.push(format!("CKA_ALLOWED_MECHANISMS = [\"{m}\"]"));
    }
    attrs.join(", ")
}

/// A private key's binding, as its spec's author would choose it from what the key may do:
/// signing first (the default), then deriving (EC) or decrypting (RSA), else the token's word
/// (DESIGN.md §3.6). Secret keys have none.
fn binding(kind: Kind, usage: &[&str]) -> &'static str {
    let may = |bit| usage.contains(&bit);
    match kind {
        _ if kind.secret() || may("CKA_SIGN") => "",
        Kind::Ec if may("CKA_DERIVE") => ", binding = \"pop-ecdh\"",
        Kind::Rsa if may("CKA_DECRYPT") => ", binding = \"pop-decrypt\"",
        _ => ", binding = \"token-asserted\"",
    }
}

/// Every subset of `bits`, in a fixed order.
fn subsets(bits: &[&'static str]) -> Vec<Vec<&'static str>> {
    (0..1u32 << bits.len())
        .map(|mask| bits.iter().enumerate().filter(|(i, _)| mask & (1 << i) != 0).map(|(_, b)| *b).collect())
        .collect()
}

/// Where an imported private key's public half is, if anywhere. Imports carry the private
/// material only (`pkcs11-tool --write-object --type privkey`, a PKCS#12 import, a migration
/// tool); the public half is whatever else the importer wrote under the same label.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PublicHalf {
    /// A public key object.
    Object,
    /// `CKA_PUBLIC_KEY_INFO` on the private key object itself.
    Info,
    /// Only a certificate (a PIV-style slot, a PKCS#12 import).
    Certificate,
    /// Nothing.
    Nothing,
}

impl PublicHalf {
    fn name(self) -> &'static str {
        match self {
            PublicHalf::Object => "object",
            PublicHalf::Info => "info",
            PublicHalf::Certificate => "certificate",
            PublicHalf::Nothing => "none",
        }
    }
}

/// An imported private key: `C_CreateObject` of fixed fixture material (`CKA_LOCAL` false).
#[derive(Clone, Debug)]
struct Import {
    kind: Kind,
    public: PublicHalf,
    usage: Vec<&'static str>,
    extractable: bool,
    sensitive: bool,
    allowed: Option<&'static str>,
}

impl Import {
    fn key(&self) -> String {
        let usage = if self.usage.is_empty() {
            "none".to_owned()
        } else {
            self.usage.iter().map(|u| u.trim_start_matches("CKA_")).collect::<Vec<_>>().join("+")
        };
        let mut key = format!(
            "{} imported public={} usage={usage} {}extractable {}sensitive",
            self.kind.name(),
            self.public.name(),
            if self.extractable { "" } else { "non-" },
            if self.sensitive { "" } else { "non-" },
        );
        if let Some(m) = self.allowed {
            let _ = write!(key, " allowed={m}");
        }
        key
    }
}

const ADOPT_CERT: &[u8] = include_bytes!("../fixtures/adopt-cert.der");

/// The certificates the grid holds: a fixture's DER, or a value no parser accepts.
const CERTS: &[(&str, &[u8])] = &[
    ("rsa-2048", ADOPT_CERT),
    ("ec-p256", include_bytes!("../fixtures/tpm-import-p256-cert.der")),
    ("ec-p384", include_bytes!("../fixtures/adopt-cert-p384.der")),
    ("ed25519", include_bytes!("../fixtures/adopt-cert-ed25519.der")),
    // Truncated: a damaged or non-DER value.
    ("malformed", ADOPT_CERT.split_at(100).0),
];

/// A certificate object, public or private, its `CKA_PRIVATE` declared in the spec or not.
#[derive(Clone, Debug)]
struct Cert {
    which: usize,
    private: bool,
    declared: bool,
}

/// A data object of `len` bytes, public or private, its `CKA_PRIVATE` declared or not.
#[derive(Clone, Debug)]
struct Data {
    len: usize,
    private: bool,
    declared: bool,
}

/// The `CKA_PRIVATE` part of a certificate's or data object's row key.
fn privacy(private: bool, declared: bool) -> String {
    format!("{}{}", if private { "private" } else { "public" }, if declared { "" } else { " undeclared" })
}

/// One object of the grid, of any family.
#[derive(Clone, Debug)]
enum Item {
    Key(Row),
    Import(Import),
    Cert(Cert),
    Data(Data),
}

impl Item {
    /// The row's key in the table.
    fn key(&self) -> String {
        match self {
            Item::Key(r) => r.key(),
            Item::Import(r) => r.key(),
            Item::Cert(c) => format!("certificate {} {}", CERTS[c.which].0, privacy(c.private, c.declared)),
            Item::Data(d) => format!("data {}B {}", d.len, privacy(d.private, d.declared)),
        }
    }

    /// The keys.toml object.
    fn object(&self) -> String {
        match self {
            Item::Key(Row { kind, .. }) | Item::Import(Import { kind, .. }) => kind.object().to_owned(),
            Item::Cert(_) => "class = \"CKO_CERTIFICATE\"\ncertificateType = \"CKC_X_509\"".to_owned(),
            Item::Data(_) => "class = \"CKO_DATA\"".to_owned(),
        }
    }

    /// The spec's declared attributes.
    fn attributes(&self) -> String {
        match self {
            Item::Key(r) => r.attributes(),
            Item::Import(r) => declared(r.kind, &r.usage, r.extractable, r.sensitive, false, r.allowed),
            Item::Cert(Cert { private, declared, .. }) | Item::Data(Data { private, declared, .. }) => {
                if *declared {
                    format!("CKA_PRIVATE = {private}")
                } else {
                    String::new()
                }
            }
        }
    }

    /// The rest of the spec's token entry: a private key's binding.
    fn binding(&self) -> &'static str {
        match self {
            Item::Key(r) => r.binding(),
            Item::Import(r) => binding(r.kind, &r.usage),
            Item::Cert(_) | Item::Data(_) => "",
        }
    }
}

/// The grid. Secret keys: every subset of the commitment bits, plus unwrap-only and derive-only
/// (the keys DESIGN.md §3.4 refuses); every extractable × sensitive; generated and imported.
/// Private keys: every subset of their operations, with and without a per-use PIN; generated.
/// Each also unrestricted and under each allowed-mechanism variant.
///
/// Then imported private keys: each place the public half can be, every subset of operations,
/// sensitive or not (a legacy import often is not), unrestricted or under each allowed variant.
/// Then certificates and data objects: public or private, the privacy declared or not.
fn grid() -> Vec<Item> {
    let mut items: Vec<Item> = keys().into_iter().map(Item::Key).collect();
    for kind in [Kind::Ec, Kind::Rsa, Kind::Ed25519] {
        for public in [PublicHalf::Object, PublicHalf::Info, PublicHalf::Certificate, PublicHalf::Nothing] {
            for usage in subsets(kind.usage()) {
                for (extractable, sensitive) in [(false, true), (true, false)] {
                    for allowed in std::iter::once(None).chain(kind.allowed().iter().copied().map(Some)) {
                        items.push(Item::Import(Import {
                            kind,
                            public,
                            usage: usage.clone(),
                            extractable,
                            sensitive,
                            allowed,
                        }));
                    }
                }
            }
        }
    }
    for which in 0..CERTS.len() {
        for private in [false, true] {
            for declared in [true, false] {
                items.push(Item::Cert(Cert { which, private, declared }));
            }
        }
    }
    for len in [0, 32, 4096] {
        for private in [false, true] {
            for declared in [true, false] {
                items.push(Item::Data(Data { len, private, declared }));
            }
        }
    }
    items
}

/// The first family: generated keys, and imported secret keys.
fn keys() -> Vec<Row> {
    let mut rows = Vec::new();
    for kind in [Kind::Aes, Kind::Des3, Kind::Generic, Kind::HmacSha256, Kind::Ec, Kind::Rsa, Kind::Ed25519] {
        let mut usages = subsets(kind.usage());
        if kind.secret() {
            usages.push(vec!["CKA_UNWRAP"]);
            usages.push(vec!["CKA_DERIVE"]);
        }
        let origins: &[Origin] =
            if kind.secret() { &[Origin::Generated, Origin::Imported] } else { &[Origin::Generated] };
        let protections: &[(bool, bool)] = if kind.secret() {
            &[(false, true), (true, true), (true, false), (false, false)]
        } else {
            &[(false, true)]
        };
        let authentications: &[bool] = if kind.secret() { &[false] } else { &[false, true] };
        let allowed: Vec<Option<&'static str>> =
            std::iter::once(None).chain(kind.allowed().iter().copied().map(Some)).collect();
        for &origin in origins {
            for usage in &usages {
                for &(extractable, sensitive) in protections {
                    for &always_authenticate in authentications {
                        for &allowed in &allowed {
                            rows.push(Row {
                                kind,
                                origin,
                                usage: usage.clone(),
                                extractable,
                                sensitive,
                                always_authenticate,
                                allowed,
                            });
                        }
                    }
                }
            }
        }
    }
    rows
}

/// The mechanism of a `CKM_` name the grid uses.
fn mechanism(name: &str) -> MechanismType {
    match name {
        "CKM_AES_CMAC" => MechanismType::AES_CMAC,
        "CKM_AES_ECB" => MechanismType::AES_ECB,
        "CKM_AES_GCM" => MechanismType::AES_GCM,
        "CKM_DES3_ECB" => MechanismType::DES3_ECB,
        "CKM_DES3_CBC_PAD" => MechanismType::DES3_CBC_PAD,
        "CKM_SHA256_HMAC" => MechanismType::SHA256_HMAC,
        "CKM_SHA_1_HMAC" => MechanismType::SHA1_HMAC,
        "CKM_ECDSA" => MechanismType::ECDSA,
        "CKM_ECDH1_DERIVE" => MechanismType::ECDH1_DERIVE,
        "CKM_SHA256_RSA_PKCS" => MechanismType::SHA256_RSA_PKCS,
        "CKM_RSA_PKCS" => MechanismType::RSA_PKCS,
        "CKM_RSA_PKCS_OAEP" => MechanismType::RSA_PKCS_OAEP,
        "CKM_EDDSA" => MechanismType::EDDSA,
        other => panic!("no mechanism {other} in the grid"),
    }
}

/// The attribute of a usage bit's name, set to `on`.
fn usage_attribute(name: &str, on: bool) -> Attribute {
    match name {
        "CKA_SIGN" => Attribute::Sign(on),
        "CKA_ENCRYPT" => Attribute::Encrypt(on),
        "CKA_DECRYPT" => Attribute::Decrypt(on),
        "CKA_WRAP" => Attribute::Wrap(on),
        "CKA_UNWRAP" => Attribute::Unwrap(on),
        "CKA_DERIVE" => Attribute::Derive(on),
        other => panic!("no usage bit {other} in the grid"),
    }
}

/// Every usage bit `kind` has, and the two a secret key's grid adds, set as `set` says.
fn usage_attributes(kind: Kind, set: &[&str]) -> Vec<Attribute> {
    let mut names: Vec<&str> = kind.usage().to_vec();
    if kind.secret() {
        names.extend(["CKA_UNWRAP", "CKA_DERIVE"]);
    }
    names.dedup();
    names.into_iter().map(|n| usage_attribute(n, set.contains(&n))).collect()
}

/// A failed call's return value's name.
fn failed(e: cryptoki::error::Error) -> String {
    match e {
        cryptoki::error::Error::Pkcs11(rv, _) => format!("{rv:?}"),
        other => other.to_string(),
    }
}

/// Create `item`'s object on the token, labelled `label`, or say why the token would not.
fn create_item(s: &Session, item: &Item, label: &str) -> Result<(), String> {
    match item {
        Item::Key(r) => create(s, r, label),
        Item::Import(r) => create_import(s, r, label),
        Item::Cert(c) => {
            let der = CERTS[c.which].1;
            // The subject from the intact certificate: the token requires one, and a parser need not
            // be the token's to accept the value.
            let cert = <x509_cert::Certificate as x509_cert::der::Decode>::from_der(ADOPT_CERT).unwrap();
            let subject = x509_cert::der::Encode::to_der(cert.tbs_certificate().subject()).unwrap();
            s.create_object(&[
                Attribute::Class(ObjectClass::CERTIFICATE),
                Attribute::CertificateType(CertificateType::X_509),
                Attribute::Token(true),
                Attribute::Private(c.private),
                Attribute::Label(label.as_bytes().to_vec()),
                Attribute::Subject(subject),
                Attribute::Value(der.to_vec()),
            ])
            .map(|_| ())
            .map_err(failed)
        }
        Item::Data(d) => {
            let value: Vec<u8> = (0..d.len).map(|i| u8::try_from((i * 31 + 7) % 251).unwrap()).collect();
            s.create_object(&[
                Attribute::Class(ObjectClass::DATA),
                Attribute::Token(true),
                Attribute::Private(d.private),
                Attribute::Label(label.as_bytes().to_vec()),
                Attribute::Application(b"cakeys object matrix".to_vec()),
                Attribute::Value(value),
            ])
            .map(|_| ())
            .map_err(failed)
        }
    }
}

/// The fixtures the imported private keys are made of.
const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

/// Create an imported private key and its public half, if the row has one.
fn create_import(s: &Session, row: &Import, label: &str) -> Result<(), String> {
    use cryptoki::object::ObjectClass as C;
    let (key_type, mut private, public, cert): (KeyType, Vec<Attribute>, Vec<Attribute>, Vec<u8>) = match row.kind {
        Kind::Ec => {
            let (params, scalar, point) = ec_fixture(&pem_der(&format!("{FIXTURES}/tpm-import-p256.pem")));
            (
                KeyType::EC,
                vec![Attribute::EcParams(params.clone()), Attribute::Value(scalar)],
                vec![Attribute::EcParams(params), Attribute::EcPoint(tlv(0x04, &point))],
                include_bytes!("../fixtures/tpm-import-p256-cert.der").to_vec(),
            )
        }
        Kind::Ed25519 => {
            let seed = ed25519_fixture(&pem_der(&format!("{FIXTURES}/matrix-ed25519.pem")));
            let cert = include_bytes!("../fixtures/matrix-ed25519-cert.der").to_vec();
            let parsed = <x509_cert::Certificate as x509_cert::der::Decode>::from_der(&cert).unwrap();
            let point = parsed.tbs_certificate().subject_public_key_info().subject_public_key.raw_bytes().to_vec();
            (
                KeyType::EC_EDWARDS,
                vec![Attribute::EcParams(ED25519_PARAMS.to_vec()), Attribute::Value(seed)],
                vec![Attribute::EcParams(ED25519_PARAMS.to_vec()), Attribute::EcPoint(tlv(0x04, &point))],
                cert,
            )
        }
        Kind::Rsa => {
            let k = rsa_fixture(&pem_der(&format!("{FIXTURES}/tpm-import-rsa2048.pem")));
            (
                KeyType::RSA,
                vec![
                    Attribute::Modulus(k[0].clone()),
                    Attribute::PublicExponent(k[1].clone()),
                    Attribute::PrivateExponent(k[2].clone()),
                    Attribute::Prime1(k[3].clone()),
                    Attribute::Prime2(k[4].clone()),
                    Attribute::Exponent1(k[5].clone()),
                    Attribute::Exponent2(k[6].clone()),
                    Attribute::Coefficient(k[7].clone()),
                ],
                vec![Attribute::Modulus(k[0].clone()), Attribute::PublicExponent(k[1].clone())],
                include_bytes!("../fixtures/tpm-import-rsa2048-cert.der").to_vec(),
            )
        }
        _ => unreachable!("only private keys are imported in this family"),
    };
    private.extend([
        Attribute::Class(C::PRIVATE_KEY),
        Attribute::KeyType(key_type),
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::Label(label.as_bytes().to_vec()),
        Attribute::Extractable(row.extractable),
        Attribute::Sensitive(row.sensitive),
    ]);
    private.extend(usage_attributes(row.kind, &row.usage));
    if let Some(m) = row.allowed {
        private.push(Attribute::AllowedMechanisms(vec![mechanism(m)]));
    }
    if row.public == PublicHalf::Info {
        let parsed = <x509_cert::Certificate as x509_cert::der::Decode>::from_der(&cert).unwrap();
        let spki = x509_cert::der::Encode::to_der(parsed.tbs_certificate().subject_public_key_info()).unwrap();
        private.push(Attribute::PublicKeyInfo(spki));
    }
    s.create_object(&private).map_err(failed)?;
    match row.public {
        PublicHalf::Object => {
            let mut template = vec![
                Attribute::Class(C::PUBLIC_KEY),
                Attribute::KeyType(key_type),
                Attribute::Token(true),
                Attribute::Label(label.as_bytes().to_vec()),
                Attribute::Verify(row.usage.contains(&"CKA_SIGN")),
            ];
            template.extend(public);
            s.create_object(&template).map(|_| ()).map_err(|e| format!("public key object: {}", failed(e)))
        }
        PublicHalf::Certificate => s
            .create_object(&cert_object(&cert, label.as_bytes(), None))
            .map(|_| ())
            .map_err(|e| format!("certificate: {}", failed(e))),
        PublicHalf::Info | PublicHalf::Nothing => Ok(()),
    }
}

/// Create `row`'s object on the token, labelled `label`, or say why the token would not
/// (the return value's name).
fn create(s: &Session, row: &Row, label: &str) -> Result<(), String> {
    let mut private = vec![
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::Label(label.as_bytes().to_vec()),
        Attribute::Extractable(row.extractable),
        Attribute::Sensitive(row.sensitive),
    ];
    private.extend(usage_attributes(row.kind, &row.usage));
    if row.always_authenticate {
        private.push(Attribute::AlwaysAuthenticate(true));
    }
    if let Some(m) = row.allowed {
        private.push(Attribute::AllowedMechanisms(vec![mechanism(m)]));
    }
    let (key_type, len, keygen) = match row.kind {
        Kind::Aes => (KeyType::AES, 32, Mechanism::AesKeyGen),
        Kind::Des3 => (KeyType::DES3, 24, Mechanism::Des3KeyGen),
        Kind::Generic => (KeyType::GENERIC_SECRET, 32, Mechanism::GenericSecretKeyGen),
        // PKCS#11 3.0's own generation for the type (SoftHSM 2.7 has none: not created there).
        Kind::HmacSha256 => (KeyType::SHA256_HMAC, 32, Mechanism::Sha256KeyGen),
        Kind::Ec | Kind::Rsa | Kind::Ed25519 => {
            let public = vec![
                Attribute::Token(true),
                Attribute::Label(label.as_bytes().to_vec()),
                Attribute::Verify(row.usage.contains(&"CKA_SIGN")),
            ];
            let (mechanism, public) = match row.kind {
                Kind::Ec => {
                    (Mechanism::EccKeyPairGen, [public, vec![Attribute::EcParams(P256_PARAMS.to_vec())]].concat())
                }
                Kind::Ed25519 => (
                    Mechanism::EccEdwardsKeyPairGen,
                    [public, vec![Attribute::EcParams(ED25519_PARAMS.to_vec())]].concat(),
                ),
                _ => (
                    Mechanism::RsaPkcsKeyPairGen,
                    [public, vec![Attribute::ModulusBits(2048.into()), Attribute::PublicExponent(vec![1, 0, 1])]]
                        .concat(),
                ),
            };
            return s.generate_key_pair(&mechanism, &public, &private).map(|_| ()).map_err(failed);
        }
    };
    let mut secret = vec![Attribute::Class(cryptoki::object::ObjectClass::SECRET_KEY), Attribute::KeyType(key_type)];
    secret.extend(private);
    match row.origin {
        Origin::Generated => {
            if row.kind != Kind::Des3 {
                secret.push(Attribute::ValueLen(len.into()));
            }
            s.generate_key(&keygen, &secret).map(|_| ()).map_err(failed)
        }
        Origin::Imported => {
            // The token's own randomness: a key nothing relies on.
            let value = s.generate_random_vec(u32::try_from(len).unwrap()).map_err(failed)?;
            secret.push(Attribute::Value(value));
            s.create_object(&secret).map(|_| ()).map_err(failed)
        }
    }
}

/// The DER `CKA_EC_PARAMS` of the grid's curves: the named curve's OID.
const P256_PARAMS: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const ED25519_PARAMS: &[u8] = &[0x06, 0x03, 0x2b, 0x65, 0x70];

/// What realising a row gave: what the lock recorded, or the exit code. With `immutables`, also
/// the provenance the lock pins (the immutables that are true): what tells an imported private
/// key from a generated one, whose identity is the same.
fn outcome(w: &Workdir, spec: &str, token: &str, immutables: bool) -> Result<String, (i32, String)> {
    let o = w.km(&["lock", "--spec", spec, "--token", token, "--update-lock"]);
    if code(&o) != 0 {
        return Err((code(&o), stderr(&o)));
    }
    let r = &w.lock()["realisations"][spec][token];
    let mut got = r["mode"].as_str().unwrap().to_owned();
    let schemes: Vec<&str> = r["schemes"].as_array().unwrap().iter().map(|s| s.as_str().unwrap()).collect();
    let _ = write!(got, " {}", schemes.join(","));
    if let Some(b) = r.get("binding").and_then(toml::Value::as_str) {
        let _ = write!(got, " {b}");
    }
    if immutables {
        // `none`: pinned, all false; `?`: the lock pins none at all.
        let shown = r.get("immutables").and_then(toml::Value::as_table).map_or_else(
            || "?".to_owned(),
            |pinned| {
                let set: Vec<String> = pinned
                    .iter()
                    .filter(|(_, v)| v.as_bool() == Some(true))
                    .map(|(k, _)| k.trim_start_matches("CKA_").to_lowercase().replace('_', "-"))
                    .collect();
                if set.is_empty() { "none".to_owned() } else { set.join(",") }
            },
        );
        let _ = write!(got, " immutables={shown}");
    }
    Ok(got)
}

/// A token the matrix runs on.
pub struct Target<'a> {
    /// The table's name: spec-coverage/objects/<name>.toml.
    pub name: &'a str,
    /// The keys.toml token the specs realise on, and the tokens header that defines it for a
    /// realisation's directory.
    pub token: &'a str,
    pub tokens: &'a (dyn Fn(&Path) -> String + Sync),
    /// A logged-in session on it, to create the grid's objects in.
    pub session: &'a dyn Fn() -> TestSession,
    /// Objects created per session. A module that keeps what it made loaded until it is
    /// finalized (tpm2-pkcs11, within the resource manager's limit per connection) needs a
    /// fresh one every few, or its later creations fail for want of room, not for what they are.
    pub batch: usize,
    /// The test's directory: `report.txt` goes there.
    pub dir: &'a Path,
    /// Realisations at once (a module that serialises its device gains nothing from more).
    pub workers: usize,
}

/// Create the grid on `t`, lock every object, and compare the table with the committed one
/// (or rewrite it, under `CAKEYS_UPDATE_OBJECTS`).
///
/// # Panics
///
/// When the table differs from the committed one.
pub fn check(t: &Target<'_>) {
    let rows = grid();
    // Create every object first, `t.batch` to a session. The old session is finalized before
    // the next opens: two contexts on one module in one process finalize under each other.
    let created: Vec<Result<(), String>> = {
        let mut s: Option<TestSession> = None;
        let mut created = Vec::with_capacity(rows.len());
        for (i, row) in rows.iter().enumerate() {
            if i % t.batch == 0 {
                drop(s.take());
            }
            let session = s.get_or_insert_with(t.session);
            created.push(create_item(session, row, &format!("m{i}")));
        }
        created
    };
    let results: Mutex<Vec<Option<String>>> = Mutex::new(vec![None; rows.len()]);
    let report: Mutex<Vec<(usize, String)>> = Mutex::new(Vec::new());
    let next = AtomicUsize::new(0);
    // What the workers need of `t`: its session opener is not theirs to share.
    let (token, tokens) = (t.token, t.tokens);
    std::thread::scope(|scope| {
        for _ in 0..t.workers {
            scope.spawn(|| {
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some(row) = rows.get(i) else { break };
                    let got = if let Err(rv) = &created[i] {
                        format!("not created: {rv}")
                    } else {
                        let w = Workdir::new(&format!("object-matrix-{i}"));
                        w.write_config(&format!(
                            "{}\n[objects.o]\n{}\n\n[specs.m]\nobject = \"o\"\nattributes = {{ {} }}\n\
                                 tokens.{} = {{ locator = {{ CKA_LABEL = \"m{i}\" }}, origin = \"adopt\"{} }}\n",
                            tokens(&w.dir),
                            row.object(),
                            row.attributes(),
                            token,
                            row.binding(),
                        ));
                        match outcome(&w, "m", token, matches!(row, Item::Import(_))) {
                            Ok(got) => got,
                            Err((code, said)) => {
                                report.lock().unwrap().push((i, said));
                                format!("exit {code}")
                            }
                        }
                    };
                    results.lock().unwrap()[i] = Some(got);
                }
            });
        }
    });
    let results = results.into_inner().unwrap();
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    let mut table = String::new();
    for (row, got) in rows.iter().zip(&results) {
        let got = got.as_deref().unwrap();
        let class = got.split_whitespace().next().unwrap();
        *counts.entry(if class == "not" { "not created" } else { class }).or_default() += 1;
        let _ = writeln!(table, "{:?} = {:?}", row.key(), got);
    }
    let mut text = format!(
        "# Generated by the object-matrix test (crates/cli/tests/object_matrix/mod.rs) on {}: what\n\
         # cakeys makes of objects it did not create. Never edit: CAKEYS_UPDATE_OBJECTS=<dir> rewrites it.\n\
         # Each row: the mode, schemes and binding recorded; or the exit code; or the token's refusal.\n\
         token = \"{}\"\n\n[summary]\n",
        t.name, t.name
    );
    for (k, n) in &counts {
        let _ = writeln!(text, "{k:?} = {n}");
    }
    let _ = write!(text, "\n[rows]\n{table}");
    let mut said = String::new();
    for (i, s) in report.into_inner().unwrap().into_iter().collect::<BTreeMap<_, _>>() {
        let _ = writeln!(said, "## {}\n{s}", rows[i].key());
    }
    std::fs::write(t.dir.join("report.txt"), said).unwrap();
    let file = format!("{}.toml", t.name);
    // The directory to rewrite the table in: the repository's, from wherever the test runs
    // (scripts/local-tests.sh runs a copy of the tree).
    if let Some(dir) = std::env::var_os("CAKEYS_UPDATE_OBJECTS") {
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(Path::new(&dir).join(&file), &text).unwrap();
        return;
    }
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../spec-coverage/objects").join(&file);
    let committed = std::fs::read_to_string(&path).unwrap_or_default();
    assert!(
        committed == text,
        "{} is not what the grid gives on this token (report: {}); regenerate with \
         CAKEYS_UPDATE_OBJECTS=$PWD/spec-coverage/objects",
        path.display(),
        t.dir.join("report.txt").display()
    );
}
