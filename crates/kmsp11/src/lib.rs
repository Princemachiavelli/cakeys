//! The libkmsp11 provider: Google Cloud KMS keys through PKCS#11 (`docs/CLOUD_HSM.md`). Every key
//! is bound at creation to one Cloud KMS algorithm (`CKA_KMS_ALGORITHM`), which fixes its curve
//! or size, its purpose and the mechanisms it serves, and libkmsp11 takes no other attribute and
//! no public template.
//!
//! The table (`keys.json`, from libkmsp11 1.9's `algorithm_details.cc` and `kmsp11.h`) holds
//! every algorithm. [`Kmsp11::generation`] chooses one for a key spec; its `probe` rows are
//! [`Kmsp11::bound_keys`], which the write probe generates, and they are shared with
//! `scripts/cloud/gcp/main.tf`, which pre-creates each with a short destroy-scheduled duration
//! and no version so the probe only adds versions (libkmsp11's
//! `experimental_create_multiple_versions`). A key libkmsp11 creates itself gets Cloud KMS's
//! 30-day default, and its label (the `CryptoKey` ID) can never be used again.

use cakeys_core::config::{AttrValue, Binding, Locator, ModuleInfo, ObjectCfg, SpecCfg};
use cakeys_core::types::{KeyType as Kt, ObjectClass as Class};
use cakeys_core::{KmError, Result};
use cakeys_pkcs11::{BoundKey, Generation, Provider};
use cakeys_profile::{KeyKind, On};
use cryptoki::mechanism::MechanismType;
use cryptoki::object::{Attribute, AttributeType};

/// `CKA_KMS_ALGORITHM` (kmsp11.h: `CKA_VENDOR_DEFINED | 0x1E100 | 0x01`), a `CK_ULONG`.
pub const CKA_KMS_ALGORITHM: u64 = 0x8001_E101;

/// What every bound key's label starts with.
pub const LABEL_PREFIX: &str = "caprobe-";

/// The mechanisms the table names, by their PKCS#11 names.
const MECHANISMS: [MechanismType; 21] = [
    MechanismType::ECC_KEY_PAIR_GEN,
    MechanismType::RSA_PKCS_KEY_PAIR_GEN,
    MechanismType::AES_KEY_GEN,
    MechanismType::GENERIC_SECRET_KEY_GEN,
    MechanismType::ECDSA,
    MechanismType::ECDSA_SHA256,
    MechanismType::ECDSA_SHA384,
    MechanismType::RSA_PKCS,
    MechanismType::SHA256_RSA_PKCS,
    MechanismType::SHA512_RSA_PKCS,
    MechanismType::RSA_PKCS_PSS,
    MechanismType::SHA256_RSA_PKCS_PSS,
    MechanismType::SHA512_RSA_PKCS_PSS,
    MechanismType::RSA_PKCS_OAEP,
    MechanismType::SHA1_HMAC,
    MechanismType::SHA224_HMAC,
    MechanismType::SHA256_HMAC,
    MechanismType::SHA384_HMAC,
    MechanismType::SHA512_HMAC,
    MechanismType::AES_CBC,
    MechanismType::AES_CTR,
];

fn mechanism(name: &str) -> MechanismType {
    // CKM_AES_CBC_PAD is served beside CKM_AES_CBC; cakeys only compares its name.
    if name == "CKM_AES_CBC_PAD" {
        return MechanismType::AES_CBC_PAD;
    }
    *MECHANISMS.iter().find(|m| m.to_string() == name).unwrap_or_else(|| panic!("keys.json: unknown mechanism {name}"))
}

/// One Cloud KMS algorithm of the table.
struct Row {
    algorithm: String,
    id: u64,
    purpose: String,
    kind: String,
    on: String,
    keygen: MechanismType,
    mechanisms: Vec<String>,
    probe: bool,
}

impl Row {
    fn template(&self, label: &str) -> Vec<Attribute> {
        vec![
            Attribute::Label(label.as_bytes().to_vec()),
            // A CK_ULONG: 64 bits on every platform this builds for (LP64).
            Attribute::VendorDefined((AttributeType::VendorDefined(CKA_KMS_ALGORITHM), self.id.to_ne_bytes().to_vec())),
        ]
    }

    fn signs(&self) -> bool {
        matches!(self.purpose.as_str(), "ASYMMETRIC_SIGN" | "MAC")
    }

    fn decrypts(&self) -> bool {
        matches!(self.purpose.as_str(), "ASYMMETRIC_DECRYPT" | "RAW_ENCRYPT_DECRYPT")
    }
}

/// The table, in its file's order: the first row of a kind, size and purpose is the default.
/// Parsed once; the file is this crate's own, so a row that does not read is a build-time bug
/// (`the_table_parses_and_its_probe_rows_are_the_nineteen`).
fn rows() -> &'static [Row] {
    static ROWS: std::sync::LazyLock<Vec<Row>> = std::sync::LazyLock::new(parse_rows);
    &ROWS
}

fn parse_rows() -> Vec<Row> {
    let table: serde_json::Value = serde_json::from_str(include_str!("keys.json")).expect("keys.json is valid JSON");
    let text = |v: &serde_json::Value, k: &str| v[k].as_str().expect("keys.json: a string field").to_owned();
    table
        .as_array()
        .expect("keys.json is an array")
        .iter()
        .map(|v| Row {
            algorithm: text(v, "algorithm"),
            id: v["id"].as_u64().expect("keys.json: id is a number"),
            purpose: text(v, "purpose"),
            kind: text(v, "kind"),
            on: text(v, "on"),
            keygen: mechanism(&text(v, "keygen")),
            mechanisms: v["mechanisms"]
                .as_array()
                .expect("keys.json: mechanisms is an array")
                .iter()
                .map(|m| {
                    let name = m.as_str().expect("keys.json: a mechanism name");
                    mechanism(name);
                    name.to_owned()
                })
                .collect(),
            probe: v["probe"].as_bool().expect("keys.json: probe is a boolean"),
        })
        .collect()
}

/// A Cloud KMS `CryptoKey` ID, what libkmsp11 takes as `CKA_LABEL` (session.cc).
fn is_crypto_key_id(s: &str) -> bool {
    (1..=63).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// What libkmsp11 reports on a key of `row` (object.cc), by attribute, for the private or secret
/// half and for the public half: a spec declaring anything else would fail cakeys' own check of
/// the key after creating it, so it is refused before.
fn reported(row: &Row, public: bool) -> Vec<(&'static str, bool)> {
    let (signs, decrypts) = (row.signs(), row.decrypts());
    let mut v = vec![
        ("CKA_TOKEN", true),
        ("CKA_PRIVATE", false),
        ("CKA_MODIFIABLE", false),
        ("CKA_COPYABLE", false),
        ("CKA_DERIVE", false),
    ];
    if public {
        v.extend([
            ("CKA_DESTROYABLE", false),
            ("CKA_ENCRYPT", decrypts),
            ("CKA_VERIFY", signs),
            ("CKA_VERIFY_RECOVER", false),
            ("CKA_WRAP", false),
            ("CKA_TRUSTED", false),
        ]);
        return v;
    }
    v.extend([
        ("CKA_DESTROYABLE", true),
        ("CKA_SENSITIVE", true),
        ("CKA_EXTRACTABLE", false),
        ("CKA_ALWAYS_SENSITIVE", true),
        ("CKA_NEVER_EXTRACTABLE", true),
        ("CKA_SIGN", signs),
        ("CKA_DECRYPT", decrypts),
        ("CKA_UNWRAP", false),
        ("CKA_WRAP_WITH_TRUSTED", false),
    ]);
    if row.kind == "CKK_AES" || row.kind.ends_with("_HMAC") {
        v.extend([("CKA_ENCRYPT", decrypts), ("CKA_VERIFY", signs), ("CKA_WRAP", false), ("CKA_TRUSTED", false)]);
    } else {
        v.extend([("CKA_SIGN_RECOVER", false), ("CKA_ALWAYS_AUTHENTICATE", false)]);
    }
    v
}

/// Refuse a declared attribute libkmsp11 would report otherwise, or not at all.
fn check_reported(row: &Row, declared: &std::collections::BTreeMap<String, AttrValue>, public: bool) -> Result<()> {
    let reported = reported(row, public);
    for (name, value) in declared {
        let AttrValue::Bool(want) = value else { continue };
        match reported.iter().find(|(n, _)| n == name) {
            Some((_, has)) if has == want => {}
            Some((_, has)) => {
                return Err(KmError::Unsupported(
                    format!(
                        "Cloud KMS {} keys report {name} = {has}{}, not {want}",
                        row.algorithm,
                        if public { " on the public key" } else { "" }
                    )
                    .into(),
                ));
            }
            None => {
                return Err(KmError::Unsupported(
                    format!(
                        "Cloud KMS keys do not report {name}{}: libkmsp11 could not show it as declared",
                        if public { " on the public key" } else { "" }
                    )
                    .into(),
                ));
            }
        }
    }
    Ok(())
}

/// The Cloud KMS algorithm for `object` as `spec` declares it, proven by `binding`, or why none
/// fits: everything libkmsp11 would make into a key cakeys could not then identify, show as
/// declared or prove is refused here, before a label is used up.
///
/// The row: the object's kind and size or curve, then the purpose (`CKA_SIGN` or `CKA_DECRYPT`,
/// never both: Cloud KMS keys serve one), then the spec's `CKA_ALLOWED_MECHANISMS`, which must
/// equal one algorithm's set; without it, the table's first row of that purpose (PKCS#1 v1.5 with
/// SHA-256 for RSA signing, OAEP with SHA-256 for decryption).
fn algorithm_for(object: &ObjectCfg, spec: &SpecCfg, binding: Option<Binding>) -> Result<&'static Row> {
    let kt = object.checked_key_type()?;
    let unsupported = |why: String| Err(KmError::Unsupported(why.into()));
    let on = match kt {
        Kt::Ec => object.curve.clone().unwrap_or_default(),
        Kt::Rsa => object.modulus_bits.unwrap_or_default().to_string(),
        Kt::Aes => {
            return unsupported(
                "Cloud KMS AES keys serve only GCM, CBC and CTR: cakeys identifies an AES key by CMAC, an \
                 ECB check value or key wrap, none of which they offer"
                    .into(),
            );
        }
        Kt::Sha1Hmac | Kt::Sha224Hmac | Kt::Sha256Hmac | Kt::Sha384Hmac | Kt::Sha512Hmac => {
            (object.value_len.unwrap_or_default() * 8).to_string()
        }
        Kt::Des3 => return unsupported("Cloud KMS has no Triple DES keys".into()),
        Kt::EcEdwards | Kt::GenericSecret => {
            return unsupported(format!(
                "Cloud KMS has no {} keys (HMAC keys are typed: CKK_SHA256_HMAC and the like)",
                kt.name()
            ));
        }
    };
    let (sign, decrypt) = (spec.flag("CKA_SIGN") == Some(true), spec.flag("CKA_DECRYPT") == Some(true));
    let purpose = match (kt, sign, decrypt) {
        (_, true, true) => {
            return unsupported(
                "Cloud KMS keys serve one purpose: CKA_SIGN and CKA_DECRYPT cannot both be true".into(),
            );
        }
        (Kt::Ec, _, true) => return unsupported("Cloud KMS EC keys only sign".into()),
        (Kt::Ec, _, false) | (Kt::Rsa, true, false) => "ASYMMETRIC_SIGN",
        (Kt::Rsa, false, true) => "ASYMMETRIC_DECRYPT",
        (Kt::Rsa, false, false) => {
            return unsupported(
                "a Cloud KMS RSA key is bound to signing or to decryption for good: declare CKA_SIGN = true \
                 or CKA_DECRYPT = true"
                    .into(),
            );
        }
        _ => "MAC",
    };
    let of_purpose = || rows().iter().filter(|r| r.kind == kt.name() && r.purpose == purpose);
    let candidates: Vec<&'static Row> = of_purpose().filter(|r| r.on == on).collect();
    if candidates.is_empty() {
        let offered: Vec<&str> = of_purpose().map(|r| r.on.as_str()).collect();
        return unsupported(format!(
            "Cloud KMS has no {} {purpose} key of {on} (offers: {})",
            kt.name(),
            if offered.is_empty() { "none".into() } else { offered.join(", ") }
        ));
    }
    let row = match spec.attributes.get("CKA_ALLOWED_MECHANISMS") {
        Some(AttrValue::Mechanisms(declared)) => {
            let fits = |r: &&Row| {
                let mut m = r.mechanisms.clone();
                m.sort();
                m == *declared
            };
            let names: Vec<String> =
                candidates.iter().map(|r| format!("{} [{}]", r.algorithm, r.mechanisms.join(", "))).collect();
            // A set two algorithms share (OAEP with SHA-256 or SHA-512 at 4096 bits) takes the
            // table's first, the SHA-256 one.
            candidates.into_iter().find(fits).ok_or_else(|| {
                KmError::Unsupported(
                    format!(
                        "no Cloud KMS algorithm serves exactly CKA_ALLOWED_MECHANISMS = [{}] (offered: {})",
                        declared.join(", "),
                        names.join("; ")
                    )
                    .into(),
                )
            })?
        }
        _ => candidates[0],
    };
    check_reported(row, &spec.attributes, false)?;
    check_reported(row, &spec.public_attributes, true)?;
    // The proof cakeys runs on the new key, which only that key's own mechanisms may serve. A
    // signature and a decryption are proven within them (`pop-sign` by whichever RSA signature
    // the key allows, `pop-decrypt` by OAEP with the key's hash: cakeys-pkcs11's possession
    // proofs); nothing here unwraps or derives.
    // To test on Cloud KMS: `create` of a PSS, a SHA-512 and an OAEP key with their pop-*
    // bindings (ISSUES.md B11); the proofs are written for these keys, the refusal that stood
    // here before them was never run against the change.
    match binding {
        Some(Binding::PopUnwrap) => {
            unsupported("Cloud KMS keys do not unwrap: binding = \"pop-unwrap\" cannot prove them".into())
        }
        Some(Binding::PopEcdh) => {
            unsupported("Cloud KMS keys do not derive: binding = \"pop-ecdh\" cannot prove them".into())
        }
        _ => Ok(row),
    }
}

/// libkmsp11, recognised by `C_GetInfo`'s manufacturer.
pub struct Kmsp11;

impl Provider for Kmsp11 {
    fn name(&self) -> &'static str {
        "kmsp11"
    }

    fn matches(&self, module: &ModuleInfo) -> bool {
        module.manufacturer.trim_end_matches([' ', '\0']) == "Google"
    }

    fn hint(&self) -> Option<&'static str> {
        Some(
            "Cloud KMS: a key libkmsp11 creates keeps its versions 30 days scheduled for destruction once \
             deleted, and its label (the CryptoKey ID) can never be used again, unless the key was \
             created beforehand with a shorter duration and libkmsp11 runs with \
             experimental_create_multiple_versions",
        )
    }

    fn generation(
        &self,
        object: &ObjectCfg,
        spec: &SpecCfg,
        loc: &Locator,
        binding: Option<Binding>,
    ) -> Result<Option<Generation>> {
        if !matches!(object.class, Class::PrivateKey | Class::SecretKey) {
            return Ok(None);
        }
        let label = match (&loc.label, &loc.id) {
            (Some(label), None) if is_crypto_key_id(label) => label,
            (_, Some(_)) => {
                return Err(KmError::Validation(
                    "Cloud KMS assigns CKA_ID (the CryptoKeyVersion's name): locate the key by CKA_LABEL alone".into(),
                ));
            }
            _ => {
                return Err(KmError::Validation(
                    "Cloud KMS keys are created under a CKA_LABEL that is a CryptoKey ID: 1 to 63 of \
                     [a-zA-Z0-9_-]"
                        .into(),
                ));
            }
        };
        let row = algorithm_for(object, spec, binding)?;
        Ok(Some(Generation { keygen: row.keygen, template: row.template(label) }))
    }

    fn bound_keys(&self) -> Vec<BoundKey> {
        rows()
            .iter()
            .filter(|r| r.probe)
            .map(|r| {
                let label = format!("{LABEL_PREFIX}{}", r.algorithm.to_lowercase().replace('_', "-"));
                let kind = KeyKind::from(r.kind.as_str());
                BoundKey {
                    template: r.template(&label),
                    keygen: r.keygen,
                    mechanisms: r.mechanisms.iter().map(|m| mechanism(m)).collect(),
                    name: r.algorithm.clone(),
                    label,
                    on: On::parse(&kind, &r.on),
                    kind,
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn object(kt: Kt, curve: Option<&str>, bits: Option<u64>, len: Option<u64>) -> ObjectCfg {
        let class = if matches!(kt, Kt::Ec | Kt::Rsa) { Class::PrivateKey } else { Class::SecretKey };
        let mut o = ObjectCfg::new(class, Some(kt));
        o.curve = curve.map(Into::into);
        o.modulus_bits = bits;
        o.value_len = len;
        o
    }

    fn spec(attrs: &[(&str, AttrValue)], public: &[(&str, AttrValue)]) -> SpecCfg {
        let map = |a: &[(&str, AttrValue)]| a.iter().map(|(n, v)| ((*n).to_owned(), v.clone())).collect();
        SpecCfg {
            object: "k".into(),
            attributes: map(attrs),
            public_attributes: map(public),
            migrate: cakeys_core::config::SpecMigrateCfg::default(),
            tokens: BTreeMap::new(),
        }
    }

    fn yes(name: &str) -> (&str, AttrValue) {
        (name, AttrValue::Bool(true))
    }

    fn pick(o: &ObjectCfg, s: &SpecCfg, b: Option<Binding>) -> std::result::Result<String, String> {
        algorithm_for(o, s, b).map(|r| r.algorithm.clone()).map_err(|e| e.to_string())
    }

    #[test]
    fn the_table_parses_and_its_probe_rows_are_the_nineteen() {
        let keys = Kmsp11.bound_keys();
        assert_eq!(rows().len(), 28);
        assert_eq!(keys.len(), 19);
        let mut labels: Vec<_> = keys.iter().map(|k| k.label.clone()).collect();
        for l in &labels {
            assert!(is_crypto_key_id(l), "{l}");
        }
        labels.sort();
        labels.dedup();
        assert_eq!(labels.len(), keys.len(), "two algorithms share a label");
        assert_eq!(keys[0].label, "caprobe-ec-sign-p256-sha256");
        assert_eq!(keys[0].keygen, MechanismType::ECC_KEY_PAIR_GEN);
    }

    #[test]
    fn only_google_is_libkmsp11() {
        let module = |m: &str| ModuleInfo {
            path: String::new(),
            hash: None,
            description: String::new(),
            manufacturer: m.into(),
            version: String::new(),
            cryptoki: String::new(),
        };
        assert!(Kmsp11.matches(&module("Google                          ")));
        assert!(!Kmsp11.matches(&module("SoftHSM")));
    }

    #[test]
    fn defaults_follow_the_purpose() {
        let sign = spec(&[yes("CKA_SIGN")], &[]);
        let pop = Some(Binding::PopSign);
        assert_eq!(pick(&object(Kt::Ec, Some("secp256r1"), None, None), &sign, pop), Ok("EC_SIGN_P256_SHA256".into()));
        assert_eq!(
            pick(&object(Kt::Ec, Some("secp384r1"), None, None), &spec(&[], &[]), pop),
            Ok("EC_SIGN_P384_SHA384".into())
        );
        assert_eq!(pick(&object(Kt::Rsa, None, Some(3072), None), &sign, pop), Ok("RSA_SIGN_PKCS1_3072_SHA256".into()));
        let decrypt = spec(&[yes("CKA_DECRYPT")], &[]);
        let asserted = Some(Binding::TokenAsserted);
        // At 4096 bits OAEP with SHA-256 and with SHA-512 serve the same set: the first, SHA-256.
        assert_eq!(
            pick(&object(Kt::Rsa, None, Some(4096), None), &decrypt, asserted),
            Ok("RSA_DECRYPT_OAEP_4096_SHA256".into())
        );
        assert_eq!(pick(&object(Kt::Sha256Hmac, None, None, Some(32)), &sign, None), Ok("HMAC_SHA256".into()));
    }

    #[test]
    fn allowed_mechanisms_choose_exactly() {
        let pss = spec(
            &[
                yes("CKA_SIGN"),
                (
                    "CKA_ALLOWED_MECHANISMS",
                    AttrValue::mechanisms(["CKM_RSA_PKCS_PSS".into(), "CKM_SHA256_RSA_PKCS_PSS".into()]),
                ),
            ],
            &[],
        );
        let rsa = object(Kt::Rsa, None, Some(2048), None);
        assert_eq!(pick(&rsa, &pss, Some(Binding::TokenAsserted)), Ok("RSA_SIGN_PSS_2048_SHA256".into()));
        // pop-sign proves an RSA key by a signature the key allows: a PSS key by PSS.
        assert_eq!(pick(&rsa, &pss, Some(Binding::PopSign)), Ok("RSA_SIGN_PSS_2048_SHA256".into()));
        let raw = spec(
            &[
                yes("CKA_SIGN"),
                (
                    "CKA_ALLOWED_MECHANISMS",
                    AttrValue::mechanisms([
                        "CKM_RSA_PKCS".into(),
                        "CKM_SHA256_RSA_PKCS".into(),
                        "CKM_SHA512_RSA_PKCS".into(),
                    ]),
                ),
            ],
            &[],
        );
        assert_eq!(pick(&rsa, &raw, Some(Binding::PopSign)), Ok("RSA_SIGN_RAW_PKCS1_2048".into()));
        let none =
            spec(&[yes("CKA_SIGN"), ("CKA_ALLOWED_MECHANISMS", AttrValue::mechanisms(["CKM_RSA_PKCS".into()]))], &[]);
        assert!(pick(&rsa, &none, None).unwrap_err().contains("serves exactly"));
    }

    #[test]
    fn what_could_not_be_proven_or_shown_is_refused_before_creating() {
        let rsa = object(Kt::Rsa, None, Some(2048), None);
        let ec = object(Kt::Ec, Some("secp256r1"), None, None);
        let refused = |o: &ObjectCfg, s: &SpecCfg, b: Option<Binding>, why: &str| {
            let e = pick(o, s, b).unwrap_err();
            assert!(e.contains(why), "{e}");
        };
        refused(&rsa, &spec(&[yes("CKA_SIGN"), yes("CKA_DECRYPT")], &[]), None, "one purpose");
        refused(&rsa, &spec(&[], &[]), None, "for good");
        refused(&ec, &spec(&[yes("CKA_DECRYPT")], &[]), None, "only sign");
        refused(&object(Kt::Ec, Some("secp521r1"), None, None), &spec(&[], &[]), None, "offers: secp256r1, secp384r1");
        refused(&object(Kt::Rsa, None, Some(1024), None), &spec(&[yes("CKA_SIGN")], &[]), None, "no CKK_RSA");
        // pop-decrypt is proven with the key's own OAEP hash; nothing unwraps.
        let decrypt = spec(&[yes("CKA_DECRYPT")], &[]);
        assert_eq!(pick(&rsa, &decrypt, Some(Binding::PopDecrypt)), Ok("RSA_DECRYPT_OAEP_2048_SHA256".into()));
        refused(&rsa, &decrypt, Some(Binding::PopUnwrap), "do not unwrap");
        refused(&ec, &spec(&[yes("CKA_DERIVE")], &[]), None, "CKA_DERIVE = false");
        refused(&ec, &spec(&[yes("CKA_SIGN"), yes("CKA_EXTRACTABLE")], &[]), None, "CKA_EXTRACTABLE = false");
        refused(&ec, &spec(&[yes("CKA_SIGN")], &[yes("CKA_PRIVATE")]), None, "on the public key");
        refused(&ec, &spec(&[yes("CKA_SIGN")], &[]), Some(Binding::PopEcdh), "do not derive");
        refused(&object(Kt::Aes, None, None, Some(32)), &spec(&[], &[]), None, "CMAC");
        refused(&object(Kt::GenericSecret, None, None, Some(32)), &spec(&[], &[]), None, "typed");
        refused(&object(Kt::Sha256Hmac, None, None, Some(16)), &spec(&[yes("CKA_SIGN")], &[]), None, "of 128");
    }

    #[test]
    fn keys_are_placed_by_a_crypto_key_id_label_alone() {
        let ec = object(Kt::Ec, Some("secp256r1"), None, None);
        let s = spec(&[yes("CKA_SIGN")], &[]);
        let at =
            |label: Option<&str>, id: Option<&str>| Locator { label: label.map(Into::into), id: id.map(Into::into) };
        let g = Kmsp11.generation(&ec, &s, &at(Some("signing-1"), None), Some(Binding::PopSign)).unwrap().unwrap();
        assert_eq!(g.keygen, MechanismType::ECC_KEY_PAIR_GEN);
        assert_eq!(g.template[0], Attribute::Label(b"signing-1".to_vec()));
        assert!(Kmsp11.generation(&ec, &s, &at(Some("a b"), None), None).is_err());
        assert!(Kmsp11.generation(&ec, &s, &at(Some("x"), Some("01")), None).is_err());
    }
}
