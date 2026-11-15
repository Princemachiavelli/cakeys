//! The libkmsp11 provider: Google Cloud KMS keys through PKCS#11 (`docs/CLOUD_HSM.md`). Every key
//! is bound at creation to one Cloud KMS algorithm (`CKA_KMS_ALGORITHM`), which fixes its curve
//! or size, its purpose and the mechanisms it serves, and libkmsp11 takes no other attribute and
//! no public template. [`Kmsp11::bound_keys`] is that table, one key per algorithm.
//!
//! The table (`keys.json`, from libkmsp11 1.9's `algorithm_details.cc` and `kmsp11.h`) is shared
//! with `scripts/cloud/gcp/main.tf`, which pre-creates every key with a short destroy-scheduled
//! duration and no version; the probe only adds versions to them (libkmsp11's
//! `experimental_create_multiple_versions`). A label missing there would make libkmsp11 create
//! the key itself, with Cloud KMS's 30-day default.

use cakeys_core::config::ModuleInfo;
use cakeys_pkcs11::{BoundKey, Provider};
use cryptoki::mechanism::MechanismType;
use cryptoki::object::{Attribute, AttributeType};

/// `CKA_KMS_ALGORITHM` (kmsp11.h: `CKA_VENDOR_DEFINED | 0x1E100 | 0x01`), a `CK_ULONG`.
pub const CKA_KMS_ALGORITHM: u64 = 0x8001_E101;

/// What every bound key's label starts with.
pub const LABEL_PREFIX: &str = "caprobe-";

/// The mechanisms the table names, by their PKCS#11 names.
const MECHANISMS: [MechanismType; 14] = [
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
];

fn mechanism(name: &str) -> MechanismType {
    *MECHANISMS.iter().find(|m| m.to_string() == name).unwrap_or_else(|| panic!("keys.json: unknown mechanism {name}"))
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

    fn bound_keys(&self) -> Vec<BoundKey> {
        let table: serde_json::Value =
            serde_json::from_str(include_str!("keys.json")).expect("keys.json is valid JSON");
        let text = |v: &serde_json::Value, k: &str| v[k].as_str().expect("keys.json: a string field").to_owned();
        table
            .as_array()
            .expect("keys.json is an array")
            .iter()
            .map(|v| {
                let algorithm = text(v, "algorithm");
                let label = format!("{LABEL_PREFIX}{}", algorithm.to_lowercase().replace('_', "-"));
                let id = v["id"].as_u64().expect("keys.json: id is a number");
                BoundKey {
                    template: vec![
                        Attribute::Label(label.as_bytes().to_vec()),
                        // A CK_ULONG: 64 bits on every platform this builds for (LP64).
                        Attribute::VendorDefined((
                            AttributeType::VendorDefined(CKA_KMS_ALGORITHM),
                            id.to_ne_bytes().to_vec(),
                        )),
                    ],
                    name: algorithm,
                    label,
                    kind: text(v, "kind"),
                    on: text(v, "on"),
                    keygen: mechanism(&text(v, "keygen")),
                    mechanisms: v["mechanisms"]
                        .as_array()
                        .expect("keys.json: mechanisms is an array")
                        .iter()
                        .map(|m| mechanism(m.as_str().expect("keys.json: a mechanism name")))
                        .collect(),
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_table_parses_and_its_labels_are_cryptokey_ids() {
        let keys = Kmsp11.bound_keys();
        assert_eq!(keys.len(), 19);
        let mut labels: Vec<_> = keys.iter().map(|k| k.label.clone()).collect();
        for l in &labels {
            // Cloud KMS CryptoKey IDs: libkmsp11 refuses anything else (session.cc).
            assert!(l.len() <= 63 && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'), "{l}");
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
}
