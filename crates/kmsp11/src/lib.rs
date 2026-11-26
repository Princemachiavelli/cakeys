//! The libkmsp11 provider, which manages Google Cloud KMS keys through PKCS#11
//! (`docs/CLOUD_HSM.md`). Every key is bound at creation to one Cloud KMS algorithm
//! (`CKA_KMS_ALGORITHM`). The algorithm fixes the key's curve or size, its purpose and the
//! mechanisms that it serves. libkmsp11 takes no other attribute and no public template.
//!
//! The table (`keys.json`, from libkmsp11 1.9's `algorithm_details.cc` and `kmsp11.h`) holds
//! every algorithm. [`Kmsp11::generation`] chooses one algorithm for a key spec. The table's
//! `probe` rows are the keys of [`Kmsp11::bound_keys`], which the write probe generates. These
//! rows are shared with `scripts/cloud/gcp/main.tf`, which creates each key in advance with a
//! short duration for scheduled destruction and with no version, so that the probe only adds
//! versions (libkmsp11's `experimental_create_multiple_versions`). A key that libkmsp11 creates
//! itself gets Cloud KMS's 30-day default, and its label (the `CryptoKey` ID) can never be used
//! again.

use cakeys_core::config::{AttrValue, Binding, Locator, ModuleInfo, Object, SpecCfg};
use cakeys_core::types::{KeyType as Kt, ObjectClass as Class};
use cakeys_core::{KmError, Result};
use cakeys_pkcs11::{BoundKey, Generation, Provider, Topic};
use cakeys_profile::{KeyKind, On};
use cryptoki::mechanism::MechanismType;
use cryptoki::object::{Attribute, AttributeType};

/// `CKA_KMS_ALGORITHM` (kmsp11.h: `CKA_VENDOR_DEFINED | 0x1E100 | 0x01`), a `CK_ULONG`.
pub const CKA_KMS_ALGORITHM: u64 = 0x8001_E101;

/// The prefix of every bound key's label. It is not the probe's `cakeys-probe-` prefix, because
/// these labels are the `CryptoKey` IDs that `scripts/cloud/gcp/main.tf` has already created.
/// Cloud KMS never deletes a key, so a rename would leave the old set of keys behind (review
/// 2026-11-23 D-17).
pub const LABEL_PREFIX: &str = "caprobe-";

/// The mechanisms that the table names, which are looked up by their PKCS#11 names.
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
    // libkmsp11 serves `CKM_AES_CBC_PAD` next to `CKM_AES_CBC`, and cakeys only compares the
    // name of `CKM_AES_CBC_PAD`.
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
            // The value is a `CK_ULONG`, which is 64 bits on every platform that this crate builds
            // for (LP64).
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

/// Returns the table in the order of its file. The first row for a kind, size and purpose is the
/// default. The table is parsed once. The file belongs to this crate, so a row that cannot be
/// parsed is a bug in the build, which the test
/// `the_table_parses_and_its_probe_rows_are_the_twenty_one` detects.
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

/// Returns whether `s` is a Cloud KMS `CryptoKey` ID, which is what libkmsp11 takes as
/// `CKA_LABEL` (session.cc).
fn is_crypto_key_id(s: &str) -> bool {
    (1..=63).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Returns what libkmsp11 reports for each attribute of a key of `row` (object.cc), for the
/// private or secret half or, when `public` is true, for the public half. A spec that declares
/// anything else would fail cakeys' own check of the key after the key is created, so such a
/// spec is refused before the creation.
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

/// Refuses a declared attribute that libkmsp11 would report with another value or would not
/// report at all. A key's `CKA_ALLOWED_MECHANISMS` is its algorithm's set of mechanisms. On the
/// private key, the declared set has already chosen the row ([`algorithm_for`]). On the public
/// key, the declared set must be that same set (kmsp11 lib.rs F2), and it is never skipped.
fn check_reported(row: &Row, declared: &std::collections::BTreeMap<String, AttrValue>, public: bool) -> Result<()> {
    let reported = reported(row, public);
    for (name, value) in declared {
        let want = match value {
            AttrValue::Bool(want) => want,
            AttrValue::Mechanisms(_) if !public && name == "CKA_ALLOWED_MECHANISMS" => continue,
            AttrValue::Mechanisms(declared) if name == "CKA_ALLOWED_MECHANISMS" => {
                let mut allowed = row.mechanisms.clone();
                allowed.sort();
                if *declared == allowed {
                    continue;
                }
                return Err(KmError::Unsupported(
                    format!(
                        "Cloud KMS {} keys allow [{}], on the public key as on the private: not \
                         CKA_ALLOWED_MECHANISMS = [{}]",
                        row.algorithm,
                        allowed.join(", "),
                        declared.join(", ")
                    )
                    .into(),
                ));
            }
            AttrValue::Mechanisms(_) => {
                return Err(KmError::Unsupported(
                    format!("Cloud KMS keys do not report {name}: libkmsp11 could not show it as declared").into(),
                ));
            }
        };
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

/// Returns the Cloud KMS algorithm for `object` as `spec` declares it and as `binding` proves
/// it, or an error that says why no algorithm fits. When libkmsp11 would make a key that cakeys
/// then could not identify, show as declared or prove, the request is refused here, before a
/// label is used up.
///
/// The row is chosen by the object's kind and size or curve, then by the purpose (`CKA_SIGN` or
/// `CKA_DECRYPT`, never both, because a Cloud KMS key serves one purpose), and then by the spec's
/// `CKA_ALLOWED_MECHANISMS`, which must equal one algorithm's set. Without
/// `CKA_ALLOWED_MECHANISMS`, the row is the table's first row of that purpose (PKCS#1 v1.5 with
/// SHA-256 for RSA signing, and OAEP with SHA-256 for decryption).
fn algorithm_for(object: Object<'_>, spec: &SpecCfg, binding: Option<Binding>) -> Result<&'static Row> {
    let kt = object.key_type().ok_or_else(|| KmError::Unsupported(format!("{} on Cloud KMS", object.class).into()))?;
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
            // When two algorithms share a set (OAEP with SHA-256 or with SHA-512 at 4096 bits),
            // the table's first algorithm, the SHA-256 one, is chosen.
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
    // cakeys runs the binding's proof on the new key, and only that key's own mechanisms may
    // serve the proof. A signature and a decryption are proven within those mechanisms
    // (`pop-sign` uses whichever RSA signature the key allows, and `pop-decrypt` uses OAEP with
    // the key's hash, in cakeys-pkcs11's possession proofs). No key here unwraps or derives.
    // Still to be tested on Cloud KMS: `create` of a PSS key, a SHA-512 key and an OAEP key with
    // their pop-* bindings (ISSUES.md B11). The proofs were written for these keys and replaced
    // the refusal that was here before, but this change has never run against Cloud KMS.
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

/// The libkmsp11 provider, which recognizes the module by the manufacturer in `C_GetInfo`.
pub struct Kmsp11;

impl Provider for Kmsp11 {
    fn name(&self) -> &'static str {
        "kmsp11"
    }

    fn matches(&self, module: &ModuleInfo) -> bool {
        module.manufacturer == "Google"
    }

    fn hint(&self, about: Topic) -> Option<&'static str> {
        // The hint describes what the creation of a key commits to, so only a refused generation
        // or creation carries it.
        matches!(about, Topic::Generate | Topic::Create).then_some(
            "Cloud KMS: a key libkmsp11 creates keeps its versions 30 days scheduled for destruction once \
             deleted, and its label (the CryptoKey ID) can never be used again, unless the key was \
             created beforehand with a shorter duration and libkmsp11 runs with \
             experimental_create_multiple_versions",
        )
    }

    fn generation(
        &self,
        object: Object<'_>,
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
                    // The table gives an AES key's size in bits, but a profile row counts the size
                    // in bytes.
                    on: match (&kind, r.on.parse::<u32>()) {
                        (KeyKind::Aes, Ok(bits)) => On::Bytes(bits / 8),
                        _ => On::parse(&kind, &r.on),
                    },
                    kind,
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cakeys_core::config::ObjectCfg;
    use std::collections::BTreeMap;

    /// The note about destruction concerns the creation of a key, so only a refused generation or
    /// creation carries it, and a missing mechanism never does (review 2026-11-23 B-9).
    #[test]
    fn the_hint_goes_only_where_it_applies() {
        assert!(Kmsp11.hint(Topic::Generate).is_some_and(|h| h.contains("30 days")));
        assert!(Kmsp11.hint(Topic::Create).is_some());
        assert_eq!(Kmsp11.hint(Topic::Mechanism), None);
    }

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
        Object::new(o).and_then(|o| algorithm_for(o, s, b)).map(|r| r.algorithm.clone()).map_err(|e| e.to_string())
    }

    #[test]
    fn the_table_parses_and_its_probe_rows_are_the_twenty_one() {
        let keys = Kmsp11.bound_keys();
        assert_eq!(rows().len(), 28);
        assert_eq!(keys.len(), 21);
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

    /// Every MAC row serves its key type's HMAC (libkmsp11's `algorithm_details.cc`), so a spec
    /// that declares that mechanism finds the row. Before the fix, `HMAC_SHA256` listed no
    /// mechanism, and `CKA_ALLOWED_MECHANISMS = ["CKM_SHA256_HMAC"]` matched no algorithm
    /// (exit 15).
    #[test]
    fn every_mac_row_serves_its_hmac() {
        let macs: Vec<&Row> = rows().iter().filter(|r| r.purpose == "MAC").collect();
        assert_eq!(macs.len(), 5);
        for r in macs {
            let hmac = r.kind.replacen("CKK_", "CKM_", 1);
            assert_eq!(r.mechanisms, [hmac], "{}", r.algorithm);
        }
        let declared = spec(
            &[yes("CKA_SIGN"), ("CKA_ALLOWED_MECHANISMS", AttrValue::mechanisms(["CKM_SHA256_HMAC".into()]))],
            &[],
        );
        assert_eq!(pick(&object(Kt::Sha256Hmac, None, None, Some(32)), &declared, None), Ok("HMAC_SHA256".into()));
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
        // `token::module_info` removes the padding (review 2026-11-23 B-26), so the manufacturer
        // is compared exactly.
        assert!(Kmsp11.matches(&module("Google")));
        assert!(!Kmsp11.matches(&module("Google LLC")));
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
        // At 4096 bits, OAEP with SHA-256 and OAEP with SHA-512 serve the same set, so the first
        // one, SHA-256, is chosen.
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
        // pop-sign proves an RSA key with a signature that the key allows, so it proves a PSS key
        // with PSS.
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
        // pop-decrypt is proven with the key's own OAEP hash, and no key unwraps.
        let decrypt = spec(&[yes("CKA_DECRYPT")], &[]);
        assert_eq!(pick(&rsa, &decrypt, Some(Binding::PopDecrypt)), Ok("RSA_DECRYPT_OAEP_2048_SHA256".into()));
        refused(&rsa, &decrypt, Some(Binding::PopUnwrap), "do not unwrap");
        refused(&ec, &spec(&[yes("CKA_DERIVE")], &[]), None, "CKA_DERIVE = false");
        refused(&ec, &spec(&[yes("CKA_SIGN"), yes("CKA_EXTRACTABLE")], &[]), None, "CKA_EXTRACTABLE = false");
        refused(&ec, &spec(&[yes("CKA_SIGN")], &[yes("CKA_PRIVATE")]), None, "on the public key");
        // The public key's allowed mechanisms are its algorithm's mechanisms, as the private
        // key's are (kmsp11 lib.rs F2). Another set is refused and is not skipped.
        let allowed =
            |names: &[&str]| ("CKA_ALLOWED_MECHANISMS", AttrValue::mechanisms(names.iter().map(|n| (*n).into())));
        let public = |names: &[&str]| spec(&[yes("CKA_SIGN")], &[allowed(names)]);
        assert_eq!(pick(&ec, &public(&["CKM_ECDSA_SHA256", "CKM_ECDSA"]), None), Ok("EC_SIGN_P256_SHA256".into()));
        refused(&ec, &public(&["CKM_ECDSA"]), None, "on the public key as on the private");
        let both = spec(&[yes("CKA_SIGN"), allowed(&["CKM_ECDSA", "CKM_ECDSA_SHA256"])], &[allowed(&["CKM_ECDSA"])]);
        refused(&ec, &both, None, "not CKA_ALLOWED_MECHANISMS = [CKM_ECDSA]");
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
        let g = Kmsp11
            .generation(Object::new(&ec).unwrap(), &s, &at(Some("signing-1"), None), Some(Binding::PopSign))
            .unwrap()
            .unwrap();
        assert_eq!(g.keygen, MechanismType::ECC_KEY_PAIR_GEN);
        assert_eq!(g.template[0], Attribute::Label(b"signing-1".to_vec()));
        assert!(Kmsp11.generation(Object::new(&ec).unwrap(), &s, &at(Some("a b"), None), None).is_err());
        assert!(Kmsp11.generation(Object::new(&ec).unwrap(), &s, &at(Some("x"), Some("01")), None).is_err());
    }
}
