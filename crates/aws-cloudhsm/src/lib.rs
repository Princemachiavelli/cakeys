//! The AWS `CloudHSM` provider: Client SDK 5's `libcloudhsm_pkcs11.so` (`docs/CLOUD_HSM.md`). What
//! it does without code is data, in the `aws-cloudhsm` profiles (a public key is always private,
//! the AES key wraps it lists but refuses, raw ECDH behind a client option). What needs code is
//! Ed25519, which a non-FIPS cluster makes and signs with, but not through the standard
//! mechanisms \[run\]:
//!
//! - it lists no `CKM_EC_EDWARDS_KEY_PAIR_GEN`, and generates an Ed25519 key with
//!   `CKM_EC_KEY_PAIR_GEN` given the Ed25519 OID in `CKA_EC_PARAMS`;
//! - the key reads `CKK_EC`, and its `CKA_EC_POINT` holds the whole `SubjectPublicKeyInfo`;
//! - it lists no `CKM_EDDSA`, and signs pure Ed25519 with the vendor `CKM_CLOUDHSM_EDDSA`
//!   (`0x80001057`), no parameters; the signature verifies as RFC 8032 Ed25519 on the host.
//!
//! The stand-ins are relied on only where the profile's `add` row says they work: `caprobe`
//! measures what [`Provider::stand_in`] covers, and a FIPS cluster, which refuses the generation
//! ("Ed25519 key generation not available"), records none.

use cakeys_core::config::ModuleInfo;
use cakeys_pkcs11::{Provider, Report};
use cryptoki::mechanism::vendor_defined::VendorDefinedMechanism;
use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::object::KeyType;
use std::borrow::Cow;

/// `CKM_CLOUDHSM_EDDSA`: pure `EdDSA`, no parameters (`CKM_VENDOR_DEFINED | 0x1057`).
pub const CKM_CLOUDHSM_EDDSA: u64 = 0x8000_1057;

/// `CKA_EC_PARAMS` of an Ed25519 key: the OID 1.3.101.112 (RFC 8410).
const ED25519_OID: [u8; 5] = [0x06, 0x03, 0x2b, 0x65, 0x70];

/// What precedes the 32-byte point in an Ed25519 `SubjectPublicKeyInfo` (RFC 8410).
const ED25519_SPKI_PREFIX: [u8; 12] = [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];

/// The AWS `CloudHSM` provider (see the crate's documentation).
pub struct AwsCloudHsm;

/// The point of an Ed25519 key whose `CKA_EC_POINT` is its whole SPKI; anything else as it is.
fn ed25519_point(raw: &[u8]) -> &[u8] {
    match raw.strip_prefix(&ED25519_SPKI_PREFIX[..]) {
        Some(point) if point.len() == 32 => point,
        _ => raw,
    }
}

impl Provider for AwsCloudHsm {
    fn name(&self) -> &'static str {
        "aws-cloudhsm"
    }

    fn matches(&self, module: &ModuleInfo) -> bool {
        module.manufacturer.trim_end_matches([' ', '\0']) == "CloudHSM"
    }

    /// An Ed25519 key's `CKA_EC_POINT` is its whole SPKI: the point is what follows the prefix.
    /// Its `CKA_KEY_TYPE` reads `CKK_EC`: the Ed25519 OID in `CKA_EC_PARAMS` says Edwards.
    fn repair<'a>(&self, report: Report<'a>) -> Report<'a> {
        match report {
            Report::EcPoint(raw) => Report::EcPoint(match raw {
                Cow::Borrowed(raw) => Cow::Borrowed(ed25519_point(raw)),
                Cow::Owned(raw) => Cow::Owned(ed25519_point(&raw).to_vec()),
            }),
            Report::KeyType { reported: KeyType::EC, ec_params: Some(p) } if p == ED25519_OID => {
                Report::KeyType { reported: KeyType::EC_EDWARDS, ec_params: Some(p) }
            }
            other => other,
        }
    }

    /// Ed25519 generation by `CKM_EC_KEY_PAIR_GEN` (the template's `CKA_EC_PARAMS` names the
    /// curve), and pure `EdDSA` by `CKM_CLOUDHSM_EDDSA`. Ed25519ctx, Ed25519ph and Ed448 carry
    /// parameters, which the vendor mechanism takes none of: no stand-in.
    fn stand_in(&self, m: &Mechanism) -> Option<Mechanism<'static>> {
        match m {
            Mechanism::EccEdwardsKeyPairGen => Some(Mechanism::EccKeyPairGen),
            // No `CK_EDDSA_PARAMS`: pure EdDSA (`Pure`, or `Ed25519` without a context).
            Mechanism::Eddsa(params) if params.inner().is_none() => {
                let vendor = MechanismType::new_vendor_defined(CKM_CLOUDHSM_EDDSA).ok()?;
                Some(Mechanism::VendorDefined(VendorDefinedMechanism::new::<()>(vendor, None)))
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cryptoki::mechanism::eddsa::{EddsaParams, EddsaSignatureScheme};

    /// The provider as cakeys holds it, with the repaired reads of `dyn Provider`.
    const P: &dyn Provider = &AwsCloudHsm;

    fn module(manufacturer: &str) -> ModuleInfo {
        ModuleInfo {
            path: "/x.so".into(),
            hash: None,
            description: "d".into(),
            manufacturer: manufacturer.into(),
            version: "5.18".into(),
            cryptoki: "2.40".into(),
        }
    }

    #[test]
    fn claims_cloudhsm_only() {
        assert!(AwsCloudHsm.matches(&module("CloudHSM")));
        assert!(AwsCloudHsm.matches(&module("CloudHSM                        ")));
        assert!(!AwsCloudHsm.matches(&module("SoftHSM")));
    }

    /// The SPKI `CloudHSM` puts in `CKA_EC_POINT` \[run\] gives up its point; anything else is kept.
    #[test]
    fn an_ed25519_spki_point_is_unpacked() {
        let point = [0x5f_u8; 32];
        let spki = [&ED25519_SPKI_PREFIX[..], &point].concat();
        assert_eq!(P.ec_point(&spki).as_ref(), &point);
        let sec1 = [0x04_u8; 65];
        assert_eq!(P.ec_point(&sec1).as_ref(), &sec1);
        assert_eq!(P.ec_point(&spki[..43]).as_ref(), &spki[..43], "a short one is not unpacked");
    }

    #[test]
    fn an_ec_key_on_the_ed25519_oid_is_edwards() {
        assert_eq!(P.key_type(KeyType::EC, Some(&ED25519_OID)), KeyType::EC_EDWARDS);
        let p256 = [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
        assert_eq!(P.key_type(KeyType::EC, Some(&p256)), KeyType::EC);
        assert_eq!(P.key_type(KeyType::RSA, None), KeyType::RSA);
    }

    #[test]
    fn pure_eddsa_and_edwards_generation_stand_in() {
        let keygen = AwsCloudHsm.stand_in(&Mechanism::EccEdwardsKeyPairGen).unwrap();
        assert_eq!(keygen.mechanism_type(), MechanismType::ECC_KEY_PAIR_GEN);
        let pure = AwsCloudHsm.stand_in(&Mechanism::Eddsa(EddsaParams::new(EddsaSignatureScheme::Pure))).unwrap();
        assert_eq!(pure.mechanism_type(), MechanismType::new_vendor_defined(CKM_CLOUDHSM_EDDSA).unwrap());
        let ctx = Mechanism::Eddsa(EddsaParams::new(EddsaSignatureScheme::Ed25519ctx(b"c")));
        assert!(AwsCloudHsm.stand_in(&ctx).is_none(), "a scheme with parameters has no stand-in");
        assert!(AwsCloudHsm.stand_in(&Mechanism::EccKeyPairGen).is_none());
        // What the probe measures, derived from the above.
        assert_eq!(P.stand_ins(), [MechanismType::ECC_EDWARDS_KEY_PAIR_GEN, MechanismType::EDDSA]);
    }
}
